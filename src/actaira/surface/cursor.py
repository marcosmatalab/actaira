"""Read Cursor's `hooks.json` and `mcp.json`, and name the scope that is not a file.

Design note D-285. Cursor publishes a four-level ladder - "Enterprise → Team →
Project → User" - and exactly one of those four levels has no path on disk. Team
hooks are "Configured in the web dashboard and synced to all team members
automatically". A reader of files cannot see them, and an empty answer about
them would read as "this machine has no team hooks", which is a claim nobody
made.

So the team level is NAMED on every run - in `not_read`, with the cause
"configured in the Cursor dashboard and synced without leaving a file" - and it
becomes INDETERMINATE exactly where this repository configures Cursor and a team
hook would therefore outrank what was read. That second half was got wrong
first: an unconditional gap is true of every repository on every machine, so
`check` exited 3 on a tree with nothing configured at all, and an exit code that
is always 3 spends the published meaning of 3 for no information. A constant is
not a gap.

This is the vendor the gate exercises published limit 12 against, because Claude
Code's equivalent is a registry key and an MDM profile - which a reader might
plausibly be extended to read one day - whereas a dashboard-synced hook is
outside the filesystem by design and always will be.

`beforeShellExecution` and the rest of the agent-operation hooks are read and
reported like any other capability. `sessionStart` and `workspaceOpen` are the
two that fire without anybody asking for anything, and `workspaceOpen` is the
one with no equivalent in the other vendors: it fires "when workspace opens or
on folder changes", which is the VS Code `folderOpen` shape arriving through a
different vendor's file.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from . import NotRead, Scope, Unresolved
from .disk import (
    Reading,
    SettingsFile,
    git_tracked,
    read_json,
    referenced_path,
    script_facts,
)

VENDOR = "cursor"

# The two events that fire without the operator asking for anything.
STARTUP_EVENTS = ("sessionStart", "workspaceOpen")

PROJECT_FILES = (
    ".cursor/hooks.json",
    ".cursor/mcp.json",
)


def enterprise_paths() -> tuple[Path, ...]:
    """The MDM-managed `hooks.json`, per operating system, as documented."""
    if sys.platform == "darwin":
        return (Path("/Library/Application Support/Cursor/hooks.json"),)
    if os.name == "nt":
        return (Path("C:/ProgramData/Cursor/hooks.json"),)
    return (Path("/etc/cursor/hooks.json"),)


def _home(home: Path | None = None) -> Path:
    if home is not None:
        return home
    try:
        return Path.home()
    except (RuntimeError, OSError):
        return Path(".")


def hook_entries(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """(event, entry) for every hook in a Cursor `hooks.json`.

    Cursor's shape is flatter than Claude Code's - `{"hooks": {"event": [{...}]}}`
    with no matcher level - so this is not the same walk under a different name.
    Every level is still checked before it is walked, for the same reason.
    """
    found: list[tuple[str, dict[str, Any]]] = []
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return found
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict):
                found.append((str(event), entry))
    return found


def hook_command(entry: dict[str, Any]) -> str | None:
    command = entry.get("command")
    return command if isinstance(command, str) else None


def read(root: Path, *, machine: bool = False, home: Path | None = None) -> Reading:
    """`.cursor/` here, the user's and the enterprise file under `--machine`.

    The team level is never read, on either path, because there is nothing to
    read. It is named in `not_read` always and raised to `unresolved` where it
    can outrank something here.
    """
    root = Path(root)
    tracked, tracked_problem = git_tracked(root)
    settings: list[SettingsFile] = []
    mcp_files: list[SettingsFile] = []
    unresolved: list[Unresolved] = []
    not_read: list[NotRead] = []

    settings.append(read_json(Scope.PROJECT, root / ".cursor" / "hooks.json", ".cursor/hooks.json"))
    mcp_files.append(read_json(Scope.PROJECT, root / ".cursor" / "mcp.json", ".cursor/mcp.json"))

    if machine:
        base = _home(home)
        settings.append(
            read_json(Scope.USER, base / ".cursor" / "hooks.json", "~/.cursor/hooks.json")
        )
        mcp_files.append(
            read_json(Scope.USER, base / ".cursor" / "mcp.json", "~/.cursor/mcp.json")
        )
        for path in enterprise_paths():
            settings.append(read_json(Scope.MANAGED, path, str(path)))
    else:
        not_read.append(
            NotRead(
                "~/.cursor/hooks.json, ~/.cursor/mcp.json and the enterprise hooks.json",
                "not read without --machine",
            )
        )

    # The level that is not a file. Named on every run, and INDETERMINATE only
    # when there is something here for it to outrank.
    #
    # Both halves matter and the second was got wrong first. An unconditional
    # `Unresolved` is true of every repository on every machine, so `check`
    # exited 3 on a tree with nothing configured at all - and an exit code that
    # is always 3 says nothing, which takes the published meaning of 3 with it.
    # A constant is not a gap. So the fact goes in `not_read`, where it is
    # published and costs nothing, and it becomes a gap exactly when this
    # repository carries Cursor configuration that a team hook would outrank -
    # which is when "what you see here may be overridden by something you
    # cannot see" is load-bearing rather than trivia.
    not_read.append(
        NotRead(
            "Cursor team hooks",
            "configured in the Cursor dashboard and synced to members without leaving a "
            "file, so a reader of files cannot see them (published limit 12). They sit "
            "above Project and User in the documented priority order",
        )
    )
    outrankable = any(
        handle.ok and handle.scope in (Scope.PROJECT, Scope.PROJECT_LOCAL)
        for handle in (*settings, *mcp_files)
    )
    if outrankable or machine:
        unresolved.append(
            Unresolved(
                subject="Cursor team hooks",
                cause=(
                    "this repository configures Cursor, and team hooks outrank Project and "
                    "User in the documented priority order. They are configured in the "
                    "dashboard and synced without leaving a file, so what is read here may "
                    "be overridden by something no reader of files can see "
                    "(published limit 12)"
                ),
                source="https://cursor.com/docs/agent/hooks",
            )
        )

    for handle in (*settings, *mcp_files):
        if handle.problem and handle.problem != "absent":
            unresolved.append(Unresolved(handle.display, handle.problem, handle.display))

    scripts: dict[str, dict[str, Any]] = {}
    for handle in settings:
        if not handle.ok:
            continue
        assert handle.data is not None
        for _event, entry in hook_entries(handle.data):
            command = hook_command(entry)
            if command is None:
                continue
            spoken = referenced_path(command)
            if spoken is not None and spoken not in scripts:
                scripts[spoken] = script_facts(root, spoken, tracked, tracked_problem)

    return Reading(
        vendor=VENDOR,
        root=root,
        settings=tuple(settings),
        mcp_files=tuple(mcp_files),
        unresolved=tuple(unresolved),
        not_read=tuple(not_read),
        scripts=scripts,
    )


__all__ = [
    "PROJECT_FILES",
    "STARTUP_EVENTS",
    "VENDOR",
    "enterprise_paths",
    "hook_command",
    "hook_entries",
    "read",
]
