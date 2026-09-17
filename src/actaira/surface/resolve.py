"""The merge semantics, as a table of cited rows, and a pure function over it.

Design note D-273. Every merge decision is a ROW here, never an `if` somewhere
in the resolver. A row carries the key or family it governs, the rule, the URL
it came from, a digest of that page as retrieved, the date it was read, and the
sentence that says it. `tests/test_surface.py` fails on a row missing any of
those, and that test is itself exercised against a row with the citation removed
so it cannot be passing by never looking.

Rejected: citing "the Claude Code documentation" once at the top of the file.
The pages change independently, a rule that moved is indistinguishable from a
rule we misread, and the whole product claim is that a capability names the
documented rule that resolved it. One citation for thirteen rules is one
citation short of twelve.

Why a DIGEST and not a version number. These pages publish no version string and
no last-updated date - checked across all eight on the consultation date below.
So the honest anchor is the page as retrieved: sha256 over the markdown
`code.claude.com` served, plus the date. That is limit 14 applied to our own
sources rather than only to the user's - an approval over a page NAME is an
approval over whatever is at that name tomorrow. Where a page states an agent
version that governs a rule, `since` carries it as well, because that number is
the one the answer actually depends on.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
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
from .claude_code import STARTUP_EVENTS, VENDOR, Reading, digest_of, hook_handlers

# The date every row below was read. One constant, because they were read in one
# sitting and a per-row date that is always the same value is a field nobody
# maintains.
CONSULTED = "2026-09-17"

# The version from which `bypassPermissions` stopped taking effect from a
# repository file. It is the canonical declared-versus-effective case and the
# only threshold this release needs: before it, a committed `.claude/settings.json`
# could start a session with every prompt skipped.
BYPASS_NEEDS_USER_SCOPE_FROM = (2, 1, 257)


class Kind(StrEnum):
    """How one key combines across scopes."""

    PRECEDENCE = "highest scope that sets it wins"
    LIST_UNION = "the lists from every scope are combined"
    MANAGED_ONLY = "only a managed source may set it"
    STRICTEST_WINS = "the most restrictive value from any scope wins"
    NOT_FROM_REPOSITORY = "a repository file cannot set it"
    TRUST_GATED = "a repository file sets it, and it waits for workspace trust"
    NOT_TRUST_GATED = "a repository file sets it and it applies before any trust step"


@dataclass(frozen=True)
class MergeRow:
    """One documented merge rule, with the citation that makes it checkable."""

    keys: tuple[str, ...]
    kind: Kind
    url: str
    doc_sha256: str
    consulted: str
    quote: str
    since: str | None = None

    @property
    def cited(self) -> bool:
        """Whether this row may be used at all.

        Four fields and all four non-empty. A row that cannot say where it came
        from is an opinion about somebody else's software, which is the one
        thing CLAUDE.md's second negative forbids outright.
        """
        return bool(
            self.url.strip()
            and len(self.doc_sha256.strip()) == 64
            and self.consulted.strip()
            and self.quote.strip()
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "keys": list(self.keys),
            "rule": self.kind.value,
            "url": self.url,
            "doc_sha256": self.doc_sha256,
            "consulted": self.consulted,
            "quote": self.quote,
            "since": self.since,
        }


SETTINGS = "https://code.claude.com/docs/en/settings"
SETTINGS_REF = "https://code.claude.com/docs/en/settings-reference"
PERMISSIONS = "https://code.claude.com/docs/en/permissions"
PERMISSION_MODES = "https://code.claude.com/docs/en/permission-modes"
HOOKS = "https://code.claude.com/docs/en/hooks"
SANDBOXING = "https://code.claude.com/docs/en/sandboxing"
MANAGED = "https://code.claude.com/docs/en/managed-settings"
MCP = "https://code.claude.com/docs/en/mcp"

D_SETTINGS = "bc2cccf058099f4fd91436d73df0ef6a80533860a87e906048c9f1c44e9de7f6"
D_SETTINGS_REF = "8fdd564085ed6e40e0f4e1ba962c9cdc483b85c33fd2ef59806cfed4f081fc66"
D_PERMISSIONS = "eab3c45e44187c7be90a7566d21233835354237c9b41ac36906ea45114cc21cb"
D_PERMISSION_MODES = "77bbe7bccf66d50594d1c2209b209ee652d01c99580705917a88f24976d7eab2"
D_HOOKS = "e19530ebc7709e76ace04022835e8dc55c46247152f1e4b3449e84c6ebdcb5a4"
D_SANDBOXING = "f4aea577087c100af55310a11beb32fc079684124c00d34d487bd7c9be9419b6"
D_MANAGED = "da3cf2184feaba41349980bac68ce19f7df6fe7e01d11d9569c6f5bb05a8591d"
D_MCP = "67dccd0f48a35655d560f921f3974ed2a8c50fb999a9859439d3748dd8a48221"


MERGE_TABLE: tuple[MergeRow, ...] = (
    MergeRow(
        keys=("*",),
        kind=Kind.PRECEDENCE,
        url=SETTINGS,
        doc_sha256=D_SETTINGS,
        consulted=CONSULTED,
        quote=(
            "When the same key appears in more than one place, Claude Code uses the value "
            "from the highest level that sets it."
        ),
    ),
    MergeRow(
        keys=("permissions.allow", "permissions.ask", "permissions.deny"),
        kind=Kind.LIST_UNION,
        url=SETTINGS,
        doc_sha256=D_SETTINGS,
        consulted=CONSULTED,
        quote=(
            "When you set the same list key, such as `permissions.allow`, in more than one "
            "file, Claude Code combines the lists instead of picking one, so each file can "
            "add entries without removing another file's."
        ),
    ),
    MergeRow(
        keys=("hooks",),
        kind=Kind.LIST_UNION,
        url=HOOKS,
        doc_sha256=D_HOOKS,
        consulted=CONSULTED,
        quote=(
            "Hook entries merge across settings levels rather than replacing each other: "
            "user, project, and local settings add their own hooks without removing managed "
            "ones."
        ),
    ),
    MergeRow(
        keys=("hooks", "env", "apiKeyHelper", "statusLine", "awsAuthRefresh",
              "awsCredentialExport", "otelHeadersHelper", "fileSuggestion"),
        kind=Kind.NOT_TRUST_GATED,
        url=PERMISSIONS,
        doc_sha256=D_PERMISSIONS,
        consulted=CONSULTED,
        quote=(
            "Hooks in settings files, the `env` block and helper commands such as "
            "`apiKeyHelper` [...] Used. Workspace trust never gates a skill's "
            "`allowed-tools` in any session."
        ),
    ),
    MergeRow(
        keys=("permissions.defaultMode",),
        kind=Kind.NOT_FROM_REPOSITORY,
        url=SETTINGS_REF,
        doc_sha256=D_SETTINGS_REF,
        consulted=CONSULTED,
        quote=(
            "`auto` and `bypassPermissions` don't take effect from project or local "
            "settings, so set them in `~/.claude/settings.json` instead. Before v2.1.257, "
            "`bypassPermissions` took effect from any file."
        ),
        since="2.1.257",
    ),
    MergeRow(
        keys=("permissions.allow", "permissions.additionalDirectories"),
        kind=Kind.TRUST_GATED,
        url=PERMISSIONS,
        doc_sha256=D_PERMISSIONS,
        consulted=CONSULTED,
        quote=(
            "`permissions.allow` rules and `permissions.additionalDirectories` entries in a "
            "project's `.claude/settings.json` grant capability, so Claude Code applies them "
            "only after you accept the workspace trust dialog for that folder."
        ),
    ),
    MergeRow(
        keys=("enableAllProjectMcpServers", "enabledMcpjsonServers"),
        kind=Kind.TRUST_GATED,
        url=MCP,
        doc_sha256=D_MCP,
        consulted=CONSULTED,
        quote=(
            "A cloned repository can't approve its own servers: `enableAllProjectMcpServers` "
            "or `enabledMcpjsonServers` committed to the project's `.claude/settings.json` is "
            "ignored in an untrusted folder."
        ),
        since="2.1.196",
    ),
    MergeRow(
        keys=("extraKnownMarketplaces",),
        kind=Kind.TRUST_GATED,
        url=PERMISSIONS,
        doc_sha256=D_PERMISSIONS,
        consulted=CONSULTED,
        quote=(
            "Frontmatter hooks in a project subagent, a project `@skills-dir` plugin, and "
            "`extraKnownMarketplaces` entries from the repository [...] Not used, and no "
            "dialog is offered."
        ),
    ),
    MergeRow(
        keys=("allowManagedMcpServersOnly", "allowManagedHooksOnly",
              "allowManagedPermissionRulesOnly"),
        kind=Kind.MANAGED_ONLY,
        url=SETTINGS_REF,
        doc_sha256=D_SETTINGS_REF,
        consulted=CONSULTED,
        quote=(
            "Scope: Managed. (The settings index marks these keys Managed rather than "
            "`Any file`, so a repository file that sets one has not set it.)"
        ),
    ),
    MergeRow(
        keys=("disableClaudeAiConnectors", "isolatePeerMachines", "enableArtifact",
              "crossSessionInbound", "maxEffortLevel"),
        kind=Kind.STRICTEST_WINS,
        url=SETTINGS,
        doc_sha256=D_SETTINGS,
        consulted=CONSULTED,
        quote=(
            "For a few keys whose values restrict a session, Claude Code honors a "
            "restrictive value from a scope that otherwise couldn't override managed "
            "settings."
        ),
    ),
    MergeRow(
        keys=("sandbox.excludedCommands", "sandbox.filesystem.allowRead",
              "sandbox.filesystem.allowWrite"),
        kind=Kind.LIST_UNION,
        url=SANDBOXING,
        doc_sha256=D_SANDBOXING,
        consulted=CONSULTED,
        quote=(
            "For array keys such as `excludedCommands` and `allowRead`, Claude Code merges "
            "entries from every scope the session loads, so a developer can append entries "
            "that widen the policy. [...] `excludedCommands` has no equivalent managed-only "
            "lockdown."
        ),
    ),
    MergeRow(
        keys=("sandbox.network.allowedDomains",),
        kind=Kind.LIST_UNION,
        url=SANDBOXING,
        doc_sha256=D_SANDBOXING,
        consulted=CONSULTED,
        quote=(
            "Set `allowManagedReadPathsOnly` to `true` in managed settings so that only "
            "`allowRead` entries from managed settings are honored. [...] To lock network "
            "domains to the managed values the same way, set `allowManagedDomainsOnly`."
        ),
    ),
    MergeRow(
        keys=("sandbox.enabled", "sandbox.failIfUnavailable",
              "sandbox.allowUnsandboxedCommands"),
        kind=Kind.PRECEDENCE,
        url=SANDBOXING,
        doc_sha256=D_SANDBOXING,
        consulted=CONSULTED,
        quote=(
            "For boolean keys such as `enabled` and `failIfUnavailable`, Claude Code uses "
            "the managed value and ignores anything a developer sets locally."
        ),
    ),
    MergeRow(
        keys=("managed-settings.json",),
        kind=Kind.MANAGED_ONLY,
        url=MANAGED,
        doc_sha256=D_MANAGED,
        consulted=CONSULTED,
        quote=(
            "File-based: `managed-settings.json`, an optional `managed-settings.d/` "
            "directory, and `managed-mcp.json` in the system directory: "
            "`/Library/Application Support/ClaudeCode/` on macOS, `/etc/claude-code/` on "
            "Linux and WSL, and `C:\\Program Files\\ClaudeCode\\` on Windows."
        ),
    ),
)


def row_for(key: str) -> MergeRow:
    """The row that governs one key, falling back to the precedence ladder.

    Exact match before the fallback, and the fallback is a real documented row
    rather than a default: every capability names a rule that exists on a page.
    """
    for row in MERGE_TABLE:
        if key in row.keys and row.kind is not Kind.PRECEDENCE:
            return row
    for row in MERGE_TABLE:
        if key in row.keys:
            return row
    return MERGE_TABLE[0]


def rule_name(row: MergeRow) -> str:
    """A short stable handle for a row, printed beside every capability."""
    return "{}:{}".format(row.url.rsplit("/", 1)[-1], row.keys[0])


# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------

VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def parse_version(spoken: str | None) -> tuple[int, int, int] | None:
    """`2.1.257` -> (2, 1, 257). Anything else is None, which means unknown.

    Unknown is a first-class answer here and never a default to the newest
    plausible release. Published limit 13: the merge semantics depend on the
    agent's version, and resolving with the version that seems most likely is
    exactly the invention the third negative forbids.
    """
    if not spoken:
        return None
    found = VERSION.match(spoken.strip().lstrip("v"))
    if not found:
        return None
    return (int(found.group(1)), int(found.group(2)), int(found.group(3)))


def spell(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

UNPINNED = ("npx", "uvx", "bunx", "pnpm", "npm", "yarn")
REMOTE_TRANSPORTS = ("http", "streamable-http", "sse", "ws", "websocket")


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
        "(run with --machine to read it)",
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


def _emit(
    found: list[Capability],
    *,
    name: str,
    scope: Scope,
    source: str,
    key: str,
    resolution: Resolution,
    condition: str | None = None,
    facts: dict[str, Any] | None = None,
) -> None:
    row = row_for(key)
    found.append(
        Capability(
            name=name,
            vendor=VENDOR,
            scope=scope,
            source=source,
            resolution=resolution,
            merge_rule=rule_name(row),
            condition=condition,
            facts=facts or {},
        )
    )


def _hooks(reading: Reading, handle: Any, found: list[Capability], with_content: bool) -> None:
    for event, handler in hook_handlers(handle.data):
        kind = handler.get("type")
        if not isinstance(kind, str):
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
            facts.update(_target_facts(reading, spoken))
            if with_content:
                facts["command"] = command
        if kind == "http" and isinstance(handler.get("url"), str):
            url = handler["url"]
            facts["url_sha256"] = digest_of(url)
            facts["host"] = _host(url)
            facts["loopback"] = _is_loopback(facts["host"])
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
        _emit(
            found,
            name=f"hook.{kind}",
            scope=handle.scope,
            source=handle.display,
            key="hooks",
            resolution=resolution,
            condition=condition,
            facts=facts,
        )


def referenced_target(command: str) -> str | None:
    from .claude_code import referenced_path

    return referenced_path(command)


def _target_facts(reading: Reading, spoken: str | None) -> dict[str, Any]:
    if spoken is None:
        return {"target_unknown_because": "no path was recognised in the command"}
    facts = reading.scripts.get(spoken)
    return {"target_facts": facts} if facts else {}


def _host(url: str) -> str:
    without = url.split("://", 1)[-1]
    return without.split("/", 1)[0].split("@")[-1].split(":")[0].lower()


def _is_loopback(host: str) -> bool:
    """Whether a hook or server endpoint stays on this machine.

    `0.0.0.0` is in the list and the linter is right that it usually means
    "bind everywhere". It is not a bind address here: it is a DESTINATION
    somebody wrote in a settings file, and as a destination it resolves to the
    local host. Reporting it as remote would be a finding about a host nothing
    reaches.
    """
    return host in ("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0")  # noqa: S104


def _permissions(handle: Any, reading: Reading, found: list[Capability],
                 version: tuple[int, int, int] | None) -> None:
    block = handle.data.get("permissions")
    if not isinstance(block, dict):
        return
    mode = block.get("defaultMode")
    if isinstance(mode, str):
        resolution, condition = _default_mode(reading, handle.scope, mode, version)
        _emit(
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
        _emit(
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
        from .claude_code import inside_tree

        _emit(
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
        _emit(
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
        _emit(
            found, name="sandbox.disabled", scope=handle.scope, source=handle.display,
            key="sandbox.enabled", resolution=Resolution.EFFECTIVE,
            facts={"enabled": False, "isolation_weakened": True},
        )
    if block.get("allowUnsandboxedCommands") is True:
        _emit(
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
            _emit(
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
                _emit(
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
            facts["pinned"] = _pinned(launcher, arguments)
            facts["args_sha256"] = digest_of(" ".join(arguments))
            if with_content:
                facts["args"] = arguments
        if isinstance(entry.get("url"), str):
            facts["host"] = _host(entry["url"])
            facts["loopback"] = _is_loopback(facts["host"])
            facts["url_sha256"] = digest_of(entry["url"])
            if with_content:
                facts["url"] = entry["url"]
        facts["remote"] = str(transport).lower() in REMOTE_TRANSPORTS
        resolution, condition = _trust_state(reading, handle.scope)
        _emit(
            found, name="mcp.server", scope=handle.scope, source=handle.display,
            key="enableAllProjectMcpServers", resolution=resolution, condition=condition,
            facts=facts,
        )


def _pinned(launcher: str, arguments: list[str]) -> bool | None:
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


def _approvals(handle: Any, reading: Reading, found: list[Capability]) -> None:
    for key in ("enableAllProjectMcpServers", "enabledMcpjsonServers"):
        value = handle.data.get(key)
        if value in (None, False, []):
            continue
        resolution, condition = _trust_state(reading, handle.scope)
        _emit(
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
        _hooks(reading, handle, found, with_content)
        _permissions(handle, reading, found, version)
        _helpers(handle, found, with_content)
        _sandbox(handle, found, managed)
        _approvals(handle, reading, found)
        _mcp(handle, reading, found, with_content)

    for handle in reading.mcp_files:
        if handle.ok:
            _mcp(handle, reading, found, with_content)
            _hooks(reading, handle, found, with_content)

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


__all__ = [
    "BYPASS_NEEDS_USER_SCOPE_FROM",
    "CONSULTED",
    "Kind",
    "MERGE_TABLE",
    "MergeRow",
    "NotRead",
    "parse_version",
    "resolve",
    "row_for",
    "rule_name",
]
