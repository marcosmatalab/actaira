"""What every resolver calls to record one capability, and nothing else.

Seven functions and two constants, lifted out of `resolve.py` so that the six
per-vendor resolvers can live beside the readers they belong to without
importing the Claude Code resolver to reach them. `emit` is the only place a
`Capability` is constructed: it is where the merge row is looked up and where
the rule that names the row is attached, so a capability without a cited row
cannot be produced by accident.

The layering is the point. `merge` knows nothing; this knows `merge`; a vendor
resolver knows both; `resolve` knows all three and, through
`vendor_registry()`, the vendors. Nothing points back down, which is what makes
`tests/test_layering.py`'s answer about this package a short one.
"""
from __future__ import annotations

from typing import Any

from . import Capability, Resolution, Scope
from .claude_code import VENDOR
from .disk import Reading, digest_of
from .merge import row_for, rule_name

# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

UNPINNED = ("npx", "uvx", "bunx", "pnpm", "npm", "yarn")
REMOTE_TRANSPORTS = ("http", "streamable-http", "sse", "ws", "websocket")




def emit(
    found: list[Capability],
    *,
    name: str,
    scope: Scope,
    source: str,
    key: str,
    resolution: Resolution,
    condition: str | None = None,
    facts: dict[str, Any] | None = None,
    vendor: str = VENDOR,
) -> None:
    row = row_for(key, vendor)
    found.append(
        Capability(
            name=name,
            vendor=vendor,
            scope=scope,
            source=source,
            resolution=resolution,
            merge_rule=rule_name(row),
            condition=condition,
            facts=facts or {},
        )
    )




def referenced_target(command: str) -> str | None:
    from .disk import referenced_path

    return referenced_path(command)


def target_facts(reading: Reading, spoken: str | None) -> dict[str, Any]:
    if spoken is None:
        return {"target_unknown_because": "no path was recognised in the command"}
    facts = reading.scripts.get(spoken)
    return {"target_facts": facts} if facts else {}


def host_of(url: str) -> str:
    without = url.split("://", 1)[-1]
    return without.split("/", 1)[0].split("@")[-1].split(":")[0].lower()


def is_loopback(host: str) -> bool:
    """Whether a hook or server endpoint stays on this machine.

    `0.0.0.0` is in the list and the linter is right that it usually means
    "bind everywhere". It is not a bind address here: it is a DESTINATION
    somebody wrote in a settings file, and as a destination it resolves to the
    local host. Reporting it as remote would be a finding about a host nothing
    reaches.
    """
    return host in ("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0")  # noqa: S104




def looks_like_a_script(spoken: str) -> bool:
    from .disk import SCRIPT_SUFFIXES

    return spoken.lower().endswith(SCRIPT_SUFFIXES)


def is_pinned(launcher: str, arguments: list[str]) -> bool | None:
    """Whether an `npx`-style launch names a version. None when it is not one.

    `@` after the first character is the pin, so `@scope/name@1.2.3` is pinned
    and `@scope/name` is not. None rather than True for a launcher this rule
    does not cover: a plain `node server.js` is not an unpinned fetch, and
    answering False about it would be a finding about a fact nobody observed.
    """
    if launcher not in UNPINNED:
        return None
    for argument in arguments:
        if argument.startswith("-"):
            continue
        return "@" in argument[1:]
    return False


def server_facts(name: str, entry: dict[str, Any], *, with_content: bool) -> dict[str, Any]:
    """The facts every vendor's MCP server entry carries, in one place.

    One function and not five copies, because "unpinned" and "remote" mean the
    same thing in every vendor's file even though the surrounding key names
    differ - and five copies is five places for the reading to drift. What does
    NOT move here is the merge rule or the scope: those are per vendor, and they
    are supplied by the caller.
    """
    transport = entry.get("type") or ("http" if entry.get("url") or entry.get("httpUrl") else "stdio")
    facts: dict[str, Any] = {
        "server": name,
        "transport": str(transport),
        "pinned": None,
        "loopback": None,
    }
    if isinstance(entry.get("command"), str):
        launcher = entry["command"].replace("\\", "/").rsplit("/", 1)[-1]
        arguments = [item for item in (entry.get("args") or []) if isinstance(item, str)]
        facts["launcher"] = launcher
        facts["pinned"] = is_pinned(launcher, arguments)
        facts["args_sha256"] = digest_of(" ".join(arguments))
        if with_content:
            facts["args"] = arguments
    url = entry.get("url") if isinstance(entry.get("url"), str) else entry.get("httpUrl")
    if isinstance(url, str):
        facts["host"] = host_of(url)
        facts["loopback"] = is_loopback(facts["host"])
        facts["url_sha256"] = digest_of(url)
        if with_content:
            facts["url"] = url
    facts["remote"] = str(transport).lower() in REMOTE_TRANSPORTS
    return facts
