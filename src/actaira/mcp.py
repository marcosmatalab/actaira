"""The MCP server: three tools, and two of them saying they are not built.

Design note D-256. This exists before two thirds of it does, and the reason is
distribution rather than function: directories list servers, not proxies, and
a server is the shape this reaches anybody in. That argument is only honest if
the two unbuilt tools refuse to answer. A stub that returns a plausible
verdict is the fail-open shape of this entire product, arriving through the
one surface other people's agents call directly - so `actaira_verdict` and
`actaira_contract` return a state and the phase that will answer them, the
same bytes whatever they are asked, and never a value.

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
NOT_IMPLEMENTED = "not_implemented"

TOOLS: dict[str, dict[str, Any]] = {
    "actaira_contract": {
        "description": (
            "The contract derived from what an agent declared, and how wide it is. "
            "Not implemented yet: it arrives with the phase that derives a contract."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": True},
        "phase": "phase 2, which is where a contract is derived and its width is measured",
    },
    "actaira_verdict": {
        "description": (
            "Whether one session conforms to a contract, naming the event and the rule "
            "when it does not. Not implemented yet."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "additionalProperties": True,
        },
        "phase": "phase 2, which is where rules are evaluated against a trace",
    },
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
        "phase": "",
    },
}


def _text(payload: dict[str, Any], is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2, sort_keys=True)}],
        "isError": is_error,
    }


def _unbuilt(name: str) -> dict[str, Any]:
    """The same answer to every call, because it is not computing anything.

    A stub whose answer varies with its input is a stub pretending to work,
    and the first caller to see two different answers will reasonably assume
    one of them was derived from something.
    """
    return _text(
        {
            "state": NOT_IMPLEMENTED,
            "tool": name,
            "phase": TOOLS[name]["phase"],
            "detail": (
                "This tool is declared so that it can be refused by name. It returns no "
                "value: an invented one would be indistinguishable from a computed one."
            ),
        }
    )


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
        if name not in TOOLS:
            return {
                "jsonrpc": "2.0",
                "id": identifier,
                "error": {"code": -32602, "message": f"no tool named {name!r}"},
            }
        arguments = params.get("arguments") or {}
        result = _verify(arguments) if name == "actaira_verify" else _unbuilt(str(name))
        return {"jsonrpc": "2.0", "id": identifier, "result": result}

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
