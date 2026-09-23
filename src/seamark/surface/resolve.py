"""The Claude Code resolver, and the union of the seven that is the surface.

What was here and is not: the citation table, which is `merge.py`, and the
functions that record a capability, which are `emit.py`. This file had grown to
two thousand and three lines holding all three jobs plus six other vendors'
resolvers, and the per-vendor readers were already in files of their own, so
the resolvers were the half that had not moved.

What stayed: Claude Code. `resolve` and its six helpers are the one vendor
whose resolver is not beside its reader, because `claude_code.py` is imported
by this module at module level and moving them there would make that import
circular. That is a reason and not a preference, and it is written here so the
asymmetry is visible rather than looking like an oversight.

Nothing here ever fuses two vendors' capabilities. If Cursor and Claude Code
configure the same MCP server, that is TWO capabilities with the same
`args_sha256`, each naming its own vendor, its own file and its own merge rule,
and the report says so rather than collapsing them into one row that belongs to
neither. Two vendors running the same command is two things that can be removed
independently and two approvals that expire independently.
"""
from __future__ import annotations

from typing import Any

from . import (
    REPOSITORY_SCOPES,
    Capability,
    NotRead,
    Resolution,
    Scope,
    Surface,
    Unresolved,
)
from .claude_code import STARTUP_EVENTS, VENDOR, hook_handlers
from .disk import Reading, digest_of
from .emit import (
    REMOTE_TRANSPORTS,
    emit,
    host_of,
    is_loopback,
    is_pinned,
    referenced_target,
    target_facts,
)
from .merge import (
    BYPASS_NEEDS_USER_SCOPE_FROM,
    parse_version,
    spell,
)


def _trust_state(reading: Reading, scope: Scope) -> tuple[Resolution, str | None]:
    """What workspace trust does to a capability from this scope.

    Only a repository scope waits. A value in the user or managed scope is the
    operator's own and the trust dialog is not about it, so it resolves.
    """
    if scope not in REPOSITORY_SCOPES:
        return Resolution.EFFECTIVE, None
    if reading.trusted is True:
        return Resolution.EFFECTIVE, None
    if reading.trusted is False:
        return Resolution.DECLARED, "the workspace trust dialog has not been accepted"
    return (
        Resolution.DECLARED,
        "waits for the workspace trust dialog; the trust state was not read "
        "(`seamark check --machine` reads it)",
    )


def _default_mode(
    reading: Reading, scope: Scope, mode: str, version: tuple[int, int, int] | None
) -> tuple[Resolution, str | None]:
    """The canonical declared-versus-effective case, and the only one with a threshold.

    `bypassPermissions` in a committed `.claude/settings.json` started every
    session with the prompts skipped until v2.1.257 and does nothing from
    v2.1.257. With no version, that is not a question this tool gets to answer:
    it names the threshold and returns INDETERMINATE.
    """
    if scope not in REPOSITORY_SCOPES:
        return Resolution.EFFECTIVE, None
    if mode == "auto":
        return (
            Resolution.DECLARED,
            "`auto` does not take effect from project or local settings at any version",
        )
    if mode != "bypassPermissions":
        return Resolution.EFFECTIVE, None
    if version is None:
        return (
            Resolution.INDETERMINATE,
            "the agent version is unknown: effective before {0}, not from {0}".format(
                spell(BYPASS_NEEDS_USER_SCOPE_FROM)
            ),
        )
    if version < BYPASS_NEEDS_USER_SCOPE_FROM:
        return (
            Resolution.EFFECTIVE,
            f"version {spell(version)} is before {spell(BYPASS_NEEDS_USER_SCOPE_FROM)}, where a repository file could still set it",
        )
    return (
        Resolution.DECLARED,
        f"does not take effect from project or local settings from version {spell(BYPASS_NEEDS_USER_SCOPE_FROM)}",
    )




def _hooks(
    reading: Reading,
    handle: Any,
    found: list[Capability],
    with_content: bool,
    unresolved: list[Unresolved] | None = None,
) -> None:
    from .claude_code import HANDLER_TYPES

    for event, handler in hook_handlers(handle.data):
        kind = handler.get("type")
        if not isinstance(kind, str):
            continue
        if kind not in HANDLER_TYPES:
            # D-290. The capability name is ours, never the file's. A handler
            # type this release does not know is a gap with the type named, not
            # a capability spelled by whoever wrote the settings file.
            if unresolved is not None:
                unresolved.append(
                    Unresolved(
                        subject=f"{event} hook in {handle.display}",
                        cause=(
                            f"handler type {kind!r} is not one this release reads; the "
                            "documented types are " + ", ".join(HANDLER_TYPES)
                        ),
                        source=handle.display,
                    )
                )
            continue
        facts: dict[str, Any] = {
            "event": event,
            "handler": kind,
            "at_startup": event in STARTUP_EVENTS,
        }
        matcher = handler.get("matcher")
        if isinstance(matcher, str):
            facts["matcher"] = matcher
        if kind == "command" and isinstance(handler.get("command"), str):
            command = handler["command"]
            facts["command_sha256"] = digest_of(command)
            spoken = referenced_target(command)
            facts["target"] = spoken
            facts.update(target_facts(reading, spoken))
            if with_content:
                facts["command"] = command
        if kind == "http" and isinstance(handler.get("url"), str):
            url = handler["url"]
            facts["url_sha256"] = digest_of(url)
            facts["host"] = host_of(url)
            facts["loopback"] = is_loopback(facts["host"])
            if with_content:
                facts["url"] = url
        if kind == "mcp_tool" and isinstance(handler.get("tool"), str):
            facts["tool_sha256"] = digest_of(handler["tool"])
        resolution, condition = Resolution.EFFECTIVE, None
        if handle.scope in REPOSITORY_SCOPES:
            # Not trust-gated: the documentation puts hooks in settings files in
            # the row that is Used before any trust step. This is the fact that
            # makes both 2026 worms work at all, so it is stated rather than
            # assumed.
            condition = "applies before any workspace trust step"
        emit(
            found,
            name={"command": "hook.command", "http": "hook.http",
                  "mcp_tool": "hook.mcp_tool"}[kind],
            scope=handle.scope,
            source=handle.display,
            key="hooks",
            resolution=resolution,
            condition=condition,
            facts=facts,
        )




def _permissions(handle: Any, reading: Reading, found: list[Capability],
                 version: tuple[int, int, int] | None) -> None:
    block = handle.data.get("permissions")
    if not isinstance(block, dict):
        return
    mode = block.get("defaultMode")
    if isinstance(mode, str):
        resolution, condition = _default_mode(reading, handle.scope, mode, version)
        emit(
            found,
            name="permissions.default_mode",
            scope=handle.scope,
            source=handle.display,
            key="permissions.defaultMode",
            resolution=resolution,
            condition=condition,
            facts={"mode": mode},
        )
    for entry in block.get("allow") or []:
        if not isinstance(entry, str):
            continue
        resolution, condition = _trust_state(reading, handle.scope)
        emit(
            found,
            name="permissions.allow",
            scope=handle.scope,
            source=handle.display,
            key="permissions.allow",
            resolution=resolution,
            condition=condition,
            facts={"rule": entry, "tool": entry.split("(", 1)[0]},
        )
    for entry in block.get("additionalDirectories") or []:
        if not isinstance(entry, str):
            continue
        resolution, condition = _trust_state(reading, handle.scope)
        from .disk import inside_tree

        emit(
            found,
            name="permissions.additional_directory",
            scope=handle.scope,
            source=handle.display,
            key="permissions.additionalDirectories",
            resolution=resolution,
            condition=condition,
            facts={"path": entry, "inside_tree": inside_tree(reading.root, entry)},
        )


def _helpers(handle: Any, found: list[Capability], with_content: bool) -> None:
    from .claude_code import COMMAND_KEYS

    for key in COMMAND_KEYS:
        value = handle.data.get(key)
        command = None
        if isinstance(value, str):
            command = value
        elif isinstance(value, dict) and isinstance(value.get("command"), str):
            command = value["command"]
        if command is None:
            continue
        facts: dict[str, Any] = {"key": key, "command_sha256": digest_of(command)}
        if with_content:
            facts["command"] = command
        emit(
            found,
            name="helper.command",
            scope=handle.scope,
            source=handle.display,
            key=key,
            resolution=Resolution.EFFECTIVE,
            condition=(
                "applies before any workspace trust step"
                if handle.scope in REPOSITORY_SCOPES
                else None
            ),
            facts=facts,
        )


def _managed_sandbox(reading: Reading) -> dict[str, frozenset[str] | None]:
    """What the managed scope already allows, so a widening can be named.

    `None` when no managed file was read at all, and that is the load-bearing
    case: without it, "this entry is not in the managed list" is indistinguishable
    from "we never looked at the managed list", and rules ACT-S013 and ACT-S014
    would fire on every repository that configures a sandbox. They return
    INDETERMINATE instead, because the fact they need is absent.
    """
    seen = [handle for handle in reading.settings if handle.scope is Scope.MANAGED]
    if not any(handle.ok for handle in seen):
        return {"excluded": None, "domains": None}
    excluded: set[str] = set()
    domains: set[str] = set()
    for handle in seen:
        if not handle.ok:
            continue
        block = handle.data.get("sandbox")
        if not isinstance(block, dict):
            continue
        excluded.update(
            item for item in (block.get("excludedCommands") or []) if isinstance(item, str)
        )
        network = block.get("network")
        if isinstance(network, dict):
            domains.update(
                item for item in (network.get("allowedDomains") or []) if isinstance(item, str)
            )
    return {"excluded": frozenset(excluded), "domains": frozenset(domains)}


def _widens(facts: dict[str, Any], entry: str, managed: frozenset[str] | None) -> None:
    """Record whether this entry widens the managed policy, or record nothing.

    Nothing, when no managed scope was read - and that is the whole point of
    writing it this way rather than storing `None`. A fact recorded as null is a
    fact somebody looked up and could not settle, and a clause testing it comes
    back False; a fact that is ABSENT comes back INDETERMINATE (D-275). The
    difference decides whether `check` reports "this repository does not widen
    the managed policy" about a machine whose managed policy it never opened,
    which would be an answer to a question nobody asked it.
    """
    if managed is None:
        return
    facts["widens_managed"] = entry not in managed


def _sandbox(
    handle: Any, found: list[Capability], managed: dict[str, frozenset[str] | None]
) -> None:
    block = handle.data.get("sandbox")
    if not isinstance(block, dict):
        return
    # One fact carried by both spellings of the same weakening, so one rule
    # covers both. Two rules would have been two identifiers for one statement,
    # and COMPATIBILITY.md promises an identifier means one thing forever.
    if block.get("enabled") is False:
        emit(
            found, name="sandbox.disabled", scope=handle.scope, source=handle.display,
            key="sandbox.enabled", resolution=Resolution.EFFECTIVE,
            facts={"enabled": False, "isolation_weakened": True},
        )
    if block.get("allowUnsandboxedCommands") is True:
        emit(
            found, name="sandbox.unsandboxed_allowed", scope=handle.scope,
            source=handle.display, key="sandbox.allowUnsandboxedCommands",
            resolution=Resolution.EFFECTIVE,
            facts={"allowUnsandboxedCommands": True, "isolation_weakened": True},
        )
    repository = handle.scope in REPOSITORY_SCOPES
    for entry in block.get("excludedCommands") or []:
        if isinstance(entry, str):
            facts: dict[str, Any] = {"command_sha256": digest_of(entry)}
            if repository:
                _widens(facts, entry, managed["excluded"])
            emit(
                found, name="sandbox.excluded_command", scope=handle.scope,
                source=handle.display, key="sandbox.excludedCommands",
                resolution=Resolution.EFFECTIVE, facts=facts,
            )
    network = block.get("network")
    if isinstance(network, dict):
        for entry in network.get("allowedDomains") or []:
            if isinstance(entry, str):
                facts = {"domain": entry, "wildcard": entry.startswith("*")}
                if repository:
                    _widens(facts, entry, managed["domains"])
                emit(
                    found, name="sandbox.network_domain", scope=handle.scope,
                    source=handle.display, key="sandbox.network.allowedDomains",
                    resolution=Resolution.EFFECTIVE, facts=facts,
                )


def _mcp(handle: Any, reading: Reading, found: list[Capability], with_content: bool) -> None:
    servers = handle.data.get("mcpServers")
    if not isinstance(servers, dict):
        return
    for name in sorted(servers):
        entry = servers[name]
        if not isinstance(entry, dict):
            continue
        transport = entry.get("type") or ("http" if entry.get("url") else "stdio")
        # `pinned` and `loopback` are always present, null when the question does
        # not apply to this server - a `node server.js` launch is not an unpinned
        # fetch, and a stdio server has no host. Null is an answer the reader
        # recorded; absent would mean nobody looked, and a rule treats those two
        # differently on purpose (D-275).
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
        if isinstance(entry.get("url"), str):
            facts["host"] = host_of(entry["url"])
            facts["loopback"] = is_loopback(facts["host"])
            facts["url_sha256"] = digest_of(entry["url"])
            if with_content:
                facts["url"] = entry["url"]
        facts["remote"] = str(transport).lower() in REMOTE_TRANSPORTS
        resolution, condition = _trust_state(reading, handle.scope)
        emit(
            found, name="mcp.server", scope=handle.scope, source=handle.display,
            key="enableAllProjectMcpServers", resolution=resolution, condition=condition,
            facts=facts,
        )




def _approvals(handle: Any, reading: Reading, found: list[Capability]) -> None:
    for key in ("enableAllProjectMcpServers", "enabledMcpjsonServers"):
        value = handle.data.get(key)
        if value in (None, False, []):
            continue
        resolution, condition = _trust_state(reading, handle.scope)
        emit(
            found, name="mcp.approval", scope=handle.scope, source=handle.display,
            key=key, resolution=resolution, condition=condition,
            facts={"key": key, "value": value if isinstance(value, bool) else list(value)},
        )


def resolve(
    reading: Reading,
    *,
    agent_version: str | None = None,
    with_content: bool = False,
) -> Surface:
    """Everything the reader saw, resolved into capabilities. A pure function.

    Pure over `reading` and `agent_version` and nothing else: no clock, no
    socket, and no disk beyond what the reader already put in `reading`. That is
    what lets the whole decision path be replayed from a fixture, which is what
    makes a golden corpus worth having.
    """
    version = parse_version(agent_version)
    found: list[Capability] = []
    unresolved: list[Unresolved] = list(reading.unresolved)
    managed = _managed_sandbox(reading)

    for handle in reading.settings:
        if not handle.ok:
            continue
        _hooks(reading, handle, found, with_content, unresolved)
        _permissions(handle, reading, found, version)
        _helpers(handle, found, with_content)
        _sandbox(handle, found, managed)
        _approvals(handle, reading, found)
        _mcp(handle, reading, found, with_content)

    for handle in reading.mcp_files:
        if handle.ok:
            _mcp(handle, reading, found, with_content)
            _hooks(reading, handle, found, with_content, unresolved)

    if version is None and any(
        item.resolution is Resolution.INDETERMINATE for item in found
    ):
        unresolved.append(
            Unresolved(
                subject="agent version",
                cause=(
                    "no --agent-version claude-code=X.Y.Z was given and nothing on disk "
                    "states it, so every rule whose answer depends on the version is "
                    "indeterminate (published limit 13)"
                ),
                source="--agent-version",
            )
        )

    return Surface(
        vendor=VENDOR,
        agent_version=spell(version) if version else None,
        capabilities=tuple(found),
        unresolved=tuple(unresolved),
        not_read=tuple(reading.not_read),
    )




# The capabilities this package emits ON PURPOSE with no rule naming them, and
# why each one.
#
# Design note D-292. `tests/test_capability_coverage.py` fails on any (vendor,
# capability) pair the resolvers can emit that no rule names and that is not
# here with a reason. The invariant it enforces is not "there are thirty-two
# rules" - the rule count is a budget, and fifteen or thirty-one would serve
# equally - it is that this tree must not EMIT something nobody names. A
# capability in a report that no rule can ever fire on is a line a reader cannot
# act on and cannot appeal, which is the shape of a tool that publishes noise.
#
# This is a list of exceptions, and `docs/PRINCIPLES.md` is right that a list satisfied by
# adding a line is kept by whoever declines to add one. Three things make this
# one cost something instead. A reason is required and is prose, so writing one
# means arguing it. A stale entry FAILS - an entry naming a capability nothing
# emits any more is a defect, not a leftover - so the list cannot silently
# outlive what it excuses. And the test plants a capability with no rule and
# requires the failure, so the guard cannot rot into a no-op.
#
# What is NOT an acceptable reason, stated so the next person has to look at it:
# "no rule yet". That is a rule somebody has not written, and it belongs in
# `docs/BACKLOG.md` with a phase, not here. Every entry below says why naming
# the capability would be wrong, not why it has not happened.
EMITTED_WITHOUT_A_RULE: dict[tuple[str, str], str] = {
    ("vscode", "settings.ignored_key"): (
        "This capability exists BECAUSE the vendor ignores the key. VS Code does not "
        "take an APPLICATION-scoped setting from a workspace file, so the repository "
        "has granted nothing and there is nothing for a rule to name. It is reported "
        "so a reader sees that somebody tried, which is a fact about intent that "
        "belongs in the surface and not in a finding."
    ),
    ("codex", "helper.command"): (
        "`notify` is on the list of keys the reference says a project-scoped config "
        "cannot override, so a repository that sets one has not set it - the "
        "capability is emitted DECLARED with that condition. In the user scope it is "
        "the operator's own command on their own machine. There is no scope in which "
        "a REPOSITORY grants this, which is the only thing a rule here could report."
    ),
    ("codex", "policy.managed_hooks_only"): (
        "A hardening, and the only one this tree reads. An administrator setting "
        "`allow_managed_hooks_only` in `requirements.toml` makes Codex skip user, "
        "project, session and plugin hooks. Naming it would be reporting somebody for "
        "locking their fleet down; it is emitted so the surface shows WHY a "
        "repository's hooks may not apply."
    ),
    ("gemini-cli", "helper.command"): (
        "No real violating configuration exists to test a rule against. `tools."
        "discoveryCommand` and `tools.callCommand` do run a command from a project "
        "file that overrides the user's, so a rule would be justified in principle - "
        "but five recorded searches on 2026-09-18 parsed 56 distinct public "
        "`.gemini/settings.json` files and not one set either key in the spelling the "
        "current schema publishes. the standard in `docs/PRINCIPLES.md` is that a rule arrives with a "
        "real violating case; writing one against a fixture we wrote ourselves would "
        "prove only that we can write the fixture. The capability is emitted, so "
        "nothing is hidden, and the rule waits for a case. The two repositories that "
        "DO set a tool command use the v1 flat spelling and come back INDETERMINATE "
        "(D-291), so they would not have exercised a rule either."
    ),
}




def vendor_registry() -> tuple[tuple[str, Any, Any], ...]:
    """(vendor, reader module, resolver), built on demand rather than at import.

    On demand because `cli.py` imports this module for `MERGE_TABLE` alone in
    some paths, and importing six readers to print a table is work nobody asked
    for. The tuple is rebuilt each call and is small; the cost is nothing beside
    the disk reads that follow it.
    """
    from . import claude_code as claude_code_mod
    from . import codex as codex_mod
    from . import cursor as cursor_mod
    from . import devcontainer as devcontainer_mod
    from . import gemini as gemini_mod
    from . import instructions as instructions_mod
    from . import vscode as vscode_mod

    return (
        (claude_code_mod.VENDOR, claude_code_mod, claude_code_surface),
        (codex_mod.VENDOR, codex_mod, codex_mod.codex_surface),
        (cursor_mod.VENDOR, cursor_mod, cursor_mod.cursor_surface),
        (devcontainer_mod.VENDOR, devcontainer_mod, devcontainer_mod.devcontainer_surface),
        (gemini_mod.VENDOR, gemini_mod, gemini_mod.gemini_surface),
        (instructions_mod.VENDOR, instructions_mod, instructions_mod.instructions_surface),
        (vscode_mod.VENDOR, vscode_mod, vscode_mod.vscode_surface),
    )


def claude_code_surface(reading: Any, *, agent_version: str | None = None,
                         with_content: bool = False) -> Surface:
    """`resolve` under the signature every other resolver has.

    An adapter and not a rename: `resolve` is phase S1's published entry point,
    `tests/test_surface.py` calls it by that name, and a registry that needed
    one vendor spelled differently from the other six is a registry with an
    exception in it.
    """
    return resolve(reading, agent_version=agent_version, with_content=with_content)


# The merge table is not here any more and is not re-exported either. A second
# name for one object is the shape `schemas/__init__.py` and `trace/provenance.py`
# were in when the reachability rule found them: a reader cannot tell which of
# the two is the definition, and a test ends up arbitrating between the copies.
# `cli.py`, `rules.py` and the suite read it from `merge`, which is where it is.
__all__ = [
    "EMITTED_WITHOUT_A_RULE",
    "NotRead",
    "claude_code_surface",
    "resolve",
    "vendor_registry",
]
