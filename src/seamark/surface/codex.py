"""Read Codex CLI's TOML configuration, its hooks and its managed layers.

TOML, with `tomllib` from the standard library, the same reader the rule packs
use. Nothing is added to `pyproject.toml` for this.

Design note D-284. Codex is the vendor whose project scope has a documented
switch attached: "Project-local hooks load only when the project `.codex/` layer
is trusted", and `projects.<path>.trust_level` is what says whether it is.
So a hook committed to `.codex/` is DECLARED until that trust level is read, and
the trust level lives in the USER's config file - which `check` does not open
without `--machine`. That is the same shape as Claude Code's workspace trust and
it resolves the same way: a repository scope with no readable trust state is
declared, never effective, and never dismissed as absent.

The managed layer is where this vendor earns published limit 12 twice over. A
requirement can arrive as `/etc/codex/requirements.toml`, as a macOS MDM
preference under `com.openai.codex`, or "delivered in the cloud config bundle".
The first is a file. The second and third leave nothing on disk, so they are
reported as INDETERMINATE with the cause named rather than as absence - which
matters because `allow_managed_hooks_only` is exactly the kind of key an
administrator sets through one of them, and reporting "no managed policy" about
a machine that has one through MDM would be a wrong answer with no warning.
"""
from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from . import REPOSITORY_SCOPES, Capability, NotRead, Resolution, Scope, Surface, Unresolved
from .disk import (
    Reading,
    SettingsFile,
    digest_of,
    git_tracked,
    read_text,
    referenced_path,
    script_facts,
)
from .emit import emit, referenced_target, server_facts, target_facts
from .jsonc import JsoncError
from .jsonc import loads as jsonc_loads

VENDOR = "codex"

# Hook events that fire without the operator asking for anything. Same argument
# as `claude_code.STARTUP_EVENTS`: opening a session is not a decision to run
# code, and a detector written for one event is a detector for one attack.
STARTUP_EVENTS = ("SessionStart", "SessionEnd")

# Keys whose value is a command Codex runs. Each confirmed against the
# configuration reference's own description of the key, never by its name.
COMMAND_KEYS = ("notify",)

# The sandbox mode that turns the sandbox off, spelled as the reference spells
# it, and the approval policy that stops asking.
FULL_ACCESS = "danger-full-access"
NEVER_ASKS = "never"


def read_toml(scope: Scope, path: Path, display: str) -> SettingsFile:
    """One TOML file, or a stated cause. Never an empty table."""
    if not path.is_file():
        return SettingsFile(scope, path, display, problem="absent")
    text, problem = read_text(path)
    if text is None:
        return SettingsFile(scope, path, display, problem=problem)
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return SettingsFile(scope, path, display, problem=f"invalid TOML: {exc}")
    return SettingsFile(scope, path, display, data=parsed)


def managed_paths() -> tuple[Path, ...]:
    """`managed_config.toml` and `requirements.toml`, per operating system."""
    if os.name == "nt":
        program_data = Path(os.environ.get("ProgramData", "C:/ProgramData"))
        return (_codex_home() / "managed_config.toml", program_data / "OpenAI" / "Codex" / "requirements.toml")
    return (Path("/etc/codex/managed_config.toml"), Path("/etc/codex/requirements.toml"))


def _codex_home(home: Path | None = None) -> Path:
    configured = os.environ.get("CODEX_HOME")
    if configured:
        return Path(configured)
    base = home if home is not None else _home()
    return base / ".codex"


def _home() -> Path:
    try:
        return Path.home()
    except (RuntimeError, OSError):
        return Path(".")


def hook_handlers(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """(event, handler) for every hook in a `[hooks]` table or a `hooks.json`.

    Both spellings, because the documentation offers both: "Codex can also load
    lifecycle hooks from either `hooks.json` files or inline `[hooks]` tables in
    `config.toml` files." The two produce the same shape once parsed, so they
    are walked by one function and the finding does not depend on which file the
    author chose.

    Shape-tolerant at every level, for the reason `claude_code.hook_handlers`
    is: this document came from whoever opened the pull request.
    """
    found: list[tuple[str, dict[str, Any]]] = []
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return found
    for event, matchers in hooks.items():
        if not isinstance(matchers, list):
            continue
        for matcher in matchers:
            if not isinstance(matcher, dict):
                continue
            handlers = matcher.get("hooks")
            if not isinstance(handlers, list):
                continue
            for handler in handlers:
                if isinstance(handler, dict):
                    found.append((str(event), handler))
    return found


def hook_command(handler: dict[str, Any]) -> str | None:
    """The command a Codex hook runs, with its `args` kept out of the digest."""
    if handler.get("type") != "command":
        return None
    command = handler.get("command")
    return command if isinstance(command, str) else None


def trust_level(data: dict[str, Any], root: Path) -> str | None:
    """`projects.<path>.trust_level` for this root, or None if nothing says.

    Both the path as given and its resolved form are looked up, because a
    config file written on the machine names the directory the way the person
    typed it and `check` may have been handed either.
    """
    projects = data.get("projects")
    if not isinstance(projects, dict):
        return None
    for candidate in (str(root), str(root.resolve())):
        entry = projects.get(candidate)
        if isinstance(entry, dict) and isinstance(entry.get("trust_level"), str):
            return entry["trust_level"]
    return None


def read(root: Path, *, machine: bool = False, home: Path | None = None) -> Reading:
    """`.codex/` here, plus the user and managed layers when `--machine` says so."""
    root = Path(root)
    tracked, tracked_problem = git_tracked(root)
    settings: list[SettingsFile] = []
    unresolved: list[Unresolved] = []
    not_read: list[NotRead] = []

    settings.append(read_toml(Scope.PROJECT, root / ".codex" / "config.toml", ".codex/config.toml"))
    hooks_file = root / ".codex" / "hooks.json"
    if hooks_file.is_file():
        text, problem = read_text(hooks_file)
        if text is None:
            unresolved.append(Unresolved(".codex/hooks.json", problem or "unreadable", ".codex/hooks.json"))
        else:
            try:
                parsed = jsonc_loads(text)
            except JsoncError as exc:
                unresolved.append(
                    Unresolved(".codex/hooks.json", f"invalid JSON: {exc}", ".codex/hooks.json")
                )
            else:
                if isinstance(parsed, dict):
                    settings.append(
                        SettingsFile(
                            Scope.PROJECT, hooks_file, ".codex/hooks.json",
                            data={"hooks": parsed.get("hooks", parsed)},
                        )
                    )

    trusted: bool | None = None
    if machine:
        base = _codex_home(home)
        user = read_toml(Scope.USER, base / "config.toml", "~/.codex/config.toml")
        settings.append(user)
        if user.ok:
            assert user.data is not None
            level = trust_level(user.data, root)
            if level is not None:
                trusted = level == "trusted"
        for path in managed_paths():
            settings.append(read_toml(Scope.MANAGED, path, str(path)))
        not_read.append(
            NotRead(
                "the macOS MDM preference domain com.openai.codex and the cloud config bundle",
                "a managed requirement delivered by MDM or in the cloud bundle leaves no file, "
                "so a reader of files cannot see it (published limit 12)",
            )
        )
    else:
        not_read.append(
            NotRead(
                "~/.codex/config.toml and the managed layers",
                "not read without --machine, and the project trust_level that decides whether "
                "the .codex/ layer loads is in the first of them",
            )
        )

    for handle in settings:
        if handle.problem and handle.problem != "absent":
            unresolved.append(Unresolved(handle.display, handle.problem, handle.display))

    scripts: dict[str, dict[str, Any]] = {}
    for handle in settings:
        if not handle.ok:
            continue
        assert handle.data is not None
        commands = [
            command
            for _event, handler in hook_handlers(handle.data)
            if (command := hook_command(handler)) is not None
        ]
        notify = handle.data.get("notify")
        if isinstance(notify, list):
            parts = [item for item in notify if isinstance(item, str)]
            if parts:
                commands.append(" ".join(parts))
        elif isinstance(notify, str):
            commands.append(notify)
        for command in commands:
            spoken = referenced_path(command)
            if spoken is not None and spoken not in scripts:
                scripts[spoken] = script_facts(root, spoken, tracked, tracked_problem)

    return Reading(
        vendor=VENDOR,
        root=root,
        settings=tuple(settings),
        unresolved=tuple(unresolved),
        not_read=tuple(not_read),
        trusted=trusted,
        scripts=scripts,
    )


__all__ = [
    "COMMAND_KEYS",
    "FULL_ACCESS",
    "NEVER_ASKS",
    "STARTUP_EVENTS",
    "VENDOR",
    "hook_command",
    "hook_handlers",
    "managed_paths",
    "read",
    "read_toml",
    "trust_level",
]


# ---------------------------------------------------------------------------
# The resolver
# ---------------------------------------------------------------------------
#
# A pure function of what the reader above read. It touches no disk, no clock
# and no socket, which is what lets a fixture replay the whole decision path.
# It lived in `resolve.py` until the file reached two thousand lines holding
# seven vendors; it is beside its reader now, which is where the next person
# looking for it will look.




def _codex_trust(reading: Any, scope: Scope) -> tuple[Resolution, str | None]:
    """Codex's project layer waits on `projects.<path>.trust_level`.

    Same shape as Claude Code's workspace trust and a different mechanism, so it
    is written out rather than shared: the trust state lives in the user's own
    config file, and a run that did not open it says so instead of assuming.
    """
    if scope not in REPOSITORY_SCOPES:
        return Resolution.EFFECTIVE, None
    if reading.trusted is True:
        return Resolution.EFFECTIVE, None
    if reading.trusted is False:
        return Resolution.DECLARED, "this project's trust_level is `untrusted`, so the .codex/ layer is skipped"
    return (
        Resolution.DECLARED,
        "the project .codex/ layer loads only when trusted, and no trust_level was read "
        "(run with --machine to read ~/.codex/config.toml)",
    )


def codex_surface(reading: Any, *, agent_version: str | None = None,
        with_content: bool = False) -> Surface:
    """Codex CLI: hooks, MCP servers, `notify`, and the sandbox pair."""
    from .codex import STARTUP_EVENTS as STARTUP_EVENTS

    found: list[Capability] = []

    for handle in reading.settings:
        if not handle.ok:
            continue
        data = handle.data
        resolution, condition = _codex_trust(reading, handle.scope)

        for event, handler in hook_handlers(data):
            command = hook_command(handler)
            if command is None:
                continue
            facts: dict[str, Any] = {
                "event": event,
                "at_startup": event in STARTUP_EVENTS,
                "command_sha256": digest_of(command),
            }
            if isinstance(handler.get("matcher"), str):
                facts["matcher"] = handler["matcher"]
            if with_content:
                facts["command"] = command
            spoken = referenced_target(command)
            facts["target"] = spoken
            facts.update(target_facts(reading, spoken))
            emit(
                found, name="hook.command", scope=handle.scope, source=handle.display,
                key="hooks", resolution=resolution, condition=condition, facts=facts,
                vendor=reading.vendor,
            )

        notify = data.get("notify")
        command = None
        if isinstance(notify, list):
            parts = [item for item in notify if isinstance(item, str)]
            command = " ".join(parts) if parts else None
        elif isinstance(notify, str):
            command = notify
        if command is not None:
            facts = {"key": "notify", "command_sha256": digest_of(command)}
            if with_content:
                facts["command"] = command
            emit(
                found, name="helper.command", scope=handle.scope, source=handle.display,
                key="notify",
                # `notify` is on the list of keys a project file cannot set, so a
                # repository that sets one has declared something Codex ignores.
                resolution=(
                    Resolution.DECLARED if handle.scope in REPOSITORY_SCOPES
                    else Resolution.EFFECTIVE
                ),
                condition=(
                    "project-scoped config cannot override notification keys"
                    if handle.scope in REPOSITORY_SCOPES else None
                ),
                facts=facts, vendor=reading.vendor,
            )

        mode = data.get("sandbox_mode")
        if isinstance(mode, str):
            emit(
                found, name="sandbox.mode", scope=handle.scope, source=handle.display,
                key="sandbox_mode", resolution=Resolution.EFFECTIVE,
                facts={"mode": mode, "guardrail_removed": mode == FULL_ACCESS},
                vendor=reading.vendor,
            )
        policy = data.get("approval_policy")
        if isinstance(policy, str):
            emit(
                found, name="approval.policy", scope=handle.scope, source=handle.display,
                key="approval_policy", resolution=Resolution.EFFECTIVE,
                facts={"policy": policy, "guardrail_removed": policy == NEVER_ASKS},
                vendor=reading.vendor,
            )

        servers = data.get("mcp_servers")
        for name in sorted(servers) if isinstance(servers, dict) else []:
            entry = servers[name]
            if not isinstance(entry, dict):
                continue
            emit(
                found, name="mcp.server", scope=handle.scope, source=handle.display,
                key="mcp_servers", resolution=resolution, condition=condition,
                facts=server_facts(name, entry, with_content=with_content),
                vendor=reading.vendor,
            )

        if data.get("allow_managed_hooks_only") is True and handle.scope is Scope.MANAGED:
            emit(
                found, name="policy.managed_hooks_only", scope=handle.scope,
                source=handle.display, key="allow_managed_hooks_only",
                resolution=Resolution.EFFECTIVE,
                facts={"key": "allow_managed_hooks_only", "value": True},
                vendor=reading.vendor,
            )

    return Surface(
        vendor=reading.vendor,
        agent_version=None,
        capabilities=tuple(found),
        unresolved=tuple(reading.unresolved),
        not_read=tuple(reading.not_read),
    )
