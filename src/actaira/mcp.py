"""The MCP server: one tool, and nothing announced that does not run.

Design note D-256. This exists before the product does, and the reason is
distribution rather than function: directories list servers, not proxies, and
a server is the shape this reaches anybody in.

The note used to settle the other half differently, and the change is worth
recording rather than quietly making. Two unbuilt tools, `actaira_contract`
and `actaira_verdict`, were announced in `tools/list` and answered every call
with a state and the phase that would answer them, the same bytes whatever
they were asked. The argument was that a stub returning a plausible verdict is
the fail-open shape of this entire product, arriving through the one surface
other people's agents call directly, so the refusal had to be explicit.

That was right about the answer and wrong about the announcement. Phase S0
took contract and verdict out of the plan, and a refusal naming a phase that
no longer exists is worse than no tool at all: an agent reading `tools/list`
takes what it finds there as capability, and nothing further down can correct
a reading that already happened. The honest refusal was answering a question
nobody should have been invited to ask.

So the rule is structural now, and narrow: a tool is announced only if it
runs. The handler lives in the entry rather than in a branch below it, so a
tool cannot be added to this table and left unwired, and `tests/test_mcp.py`
calls every name the server lists.

`actaira_verify` is real, and is the existing offline verifier with nothing
added: no network, no anchors the caller did not supply, the same verdict the
command prints.

JSON-RPC over stdio, hand-rolled. One runtime dependency is the rule, and the
protocol needed here is a request, a response and a notification.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .attest import verify as verify_mod

PROTOCOL_VERSION = "2025-06-18"


def _text(payload: dict[str, Any], is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2, sort_keys=True)}],
        "isError": is_error,
    }


def _verify(arguments: dict[str, Any]) -> dict[str, Any]:
    path = arguments.get("path")
    if not isinstance(path, str) or not path:
        return _text(
            {"state": "usage_error", "detail": "actaira_verify needs a `path` to a package"},
            is_error=True,
        )
    result = verify_mod.verify_package(Path(path))
    payload = result.to_dict()
    # `state` said "verified" unconditionally, which is the one word a caller
    # reads off a field with that name. A tampered package came back
    # `{"state": "verified", "ok": false}` - the same shape of defect as a
    # stub returning a plausible verdict, arriving through the surface other
    # people's agents call directly. The field now says which of the two
    # happened, and nothing else in the payload moved.
    payload["state"] = "verified" if result.ok else "not_verified"
    # isError carries whether the CALL failed, and a package that does not
    # verify is a call that succeeded with bad news. A path that is not a
    # package is the other thing, and both end up false-with-reasons here, so
    # the flag follows the verdict and the reasons are always in the payload.
    return _text(payload, is_error=not result.ok)


TOOLS: dict[str, dict[str, Any]] = {
    "actaira_verify": {
        "description": (
            "Verify an Actaira attestation package offline and report its state. "
            "Nothing is scored."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "path to the package"}},
            "required": ["path"],
            "additionalProperties": True,
        },
        "run": _verify,
    },
}


def handle(message: dict[str, Any]) -> dict[str, Any] | None:
    """One JSON-RPC message in, one response out, or None for a notification."""
    identifier = message.get("id")
    method = message.get("method")

    if identifier is None:
        return None  # a notification: answering one desynchronises some clients

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": identifier,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "actaira", "version": __version__},
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": identifier,
            "result": {
                "tools": [
                    {
                        "name": name,
                        "description": tool["description"],
                        "inputSchema": tool["inputSchema"],
                    }
                    for name, tool in sorted(TOOLS.items())
                ]
            },
        }

    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        tool = TOOLS.get(name) if isinstance(name, str) else None
        if tool is None:
            return {
                "jsonrpc": "2.0",
                "id": identifier,
                "error": {"code": -32602, "message": f"no tool named {name!r}"},
            }
        arguments = params.get("arguments") or {}
        return {"jsonrpc": "2.0", "id": identifier, "result": tool["run"](arguments)}

    return {
        "jsonrpc": "2.0",
        "id": identifier,
        "error": {"code": -32601, "message": f"method {method!r} is not one this server answers"},
    }


def serve(reader: Any = None, writer: Any = None) -> int:
    """Read messages until stdin ends. stdout carries responses and nothing else."""
    reader = reader or sys.stdin
    writer = writer or sys.stdout
    for raw in reader:
        if not raw.strip():
            continue
        try:
            message = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(message, dict):
            continue
        response = handle(message)
        if response is None:
            continue
        writer.write(json.dumps(response) + "\n")
        writer.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    """The console script `.mcp.json` runs. It takes no arguments on purpose."""
    if argv:
        print("actaira-mcp takes no arguments: it speaks JSON-RPC on stdin.", file=sys.stderr)
        return 2
    return serve()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
