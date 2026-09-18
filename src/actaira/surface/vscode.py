"""Read `.vscode/tasks.json` and `.vscode/settings.json`, and nothing else.

This is the half of both 2026 worms that phase S1 could name and not see. A task
with `"runOptions": {"runOn": "folderOpen"}` runs when the folder is opened, and
the keyv wave committed one alongside the Claude Code hook so that either half
alone was enough.

Design note D-282. VS Code is where DECLARED and EFFECTIVE come apart hardest,
and the reason is a setting that is not in this repository. A `folderOpen` task
is declared by the repository; whether it runs is decided by
`task.allowAutomaticTasks`, whose default is `off` and whose scope is
APPLICATION - so `.vscode/settings.json` CANNOT set it, and the value that
decides lives in the user's own settings file, which `check` does not open
without `--machine`. The three answers are therefore real:

    EFFECTIVE       a readable scope sets it to `on`
    DECLARED        a readable scope sets it to `off`, or nothing does and the
                    documented default `off` is what a read scope leaves
    INDETERMINATE   no scope we read says either way

Rejected: reporting the documented default `off` as the answer when nothing was
read. The default is what applies when NOBODY sets it, and "nobody set it" is
precisely what a reader that has not opened the user's settings file cannot
know. Answering `off` there is the third negative - a predicate with no
information returning False.

The reader does not decide any of that. It records which scopes were read, what
each said, and what the tasks declare; `resolve` is where the three answers are
produced, from those facts and the merge table alone.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from . import NotRead, Scope, Unresolved
from .disk import (
    MAX_BYTES,
    Reading,
    SettingsFile,
    git_tracked,
    read_text,
    referenced_path,
    script_facts,
)
from .jsonc import JsoncError
from .jsonc import loads as jsonc_loads

VENDOR = "vscode"

# The setting that decides whether a `folderOpen` task runs, and the two values
# the documentation gives it. APPLICATION scope: a workspace file cannot set it.
AUTOMATIC_TASKS = "task.allowAutomaticTasks"
ALLOWED = "on"
BLOCKED = "off"

PROJECT_FILES = (
    (Scope.PROJECT, ".vscode/tasks.json", "tasks"),
    (Scope.PROJECT, ".vscode/settings.json", "settings"),
)


def read_jsonc(scope: Scope, path: Path, display: str) -> SettingsFile:
    """One JSONC file. A comment is not a defect; anything else is a stated cause."""
    if not path.is_file():
        return SettingsFile(scope, path, display, problem="absent")
    text, problem = read_text(path)
    if text is None:
        return SettingsFile(scope, path, display, problem=problem)
    try:
        parsed = jsonc_loads(text)
    except JsoncError as exc:
        return SettingsFile(scope, path, display, problem=f"invalid JSONC: {exc}")
    if not isinstance(parsed, dict):
        return SettingsFile(
            scope, path, display,
            problem=f"top level is {type(parsed).__name__}, not an object",
        )
    return SettingsFile(scope, path, display, data=parsed)


def user_settings_dir(home: Path | None = None) -> Path:
    """Where VS Code keeps the user's own `settings.json`, per operating system.

    The three paths the settings documentation publishes. Read only under
    `--machine`: the case this command is built for is a pull request, and a
    pull request cannot change a developer's own settings file.
    """
    base = home if home is not None else _home()
    if sys.platform == "darwin":
        return base / "Library" / "Application Support" / "Code" / "User"
    if os.name == "nt":
        # `APPDATA` only when the caller did NOT name a base. A caller that
        # passes one is saying which home to read - a test, or an operator
        # pointing at a profile - and an environment variable that overruled it
        # would make the answer depend on the machine rather than the argument.
        roaming = (
            Path(os.environ["APPDATA"])
            if home is None and os.environ.get("APPDATA")
            else base / "AppData" / "Roaming"
        )
        return roaming / "Code" / "User"
    return base / ".config" / "Code" / "User"


def _home() -> Path:
    try:
        return Path.home()
    except (RuntimeError, OSError):
        return Path(".")


def tasks_in(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Every task entry in one `tasks.json`, shape-checked at every level.

    The document was written by whoever opened the pull request, so `tasks`
    holding a string and an entry holding null are both things this has to
    survive rather than raise on.
    """
    found = data.get("tasks")
    return [entry for entry in found if isinstance(entry, dict)] if isinstance(found, list) else []


def task_command(entry: dict[str, Any]) -> str | None:
    """The command string a task runs, in either documented spelling.

    `command` is a string, or a `{"value": ...}` object when the task quotes
    it. `args` are not folded in: they are recorded separately, and joining
    them here would produce a digest of a string nobody wrote.
    """
    command = entry.get("command")
    if isinstance(command, str):
        return command
    if isinstance(command, dict) and isinstance(command.get("value"), str):
        return command["value"]
    return None


def runs_on(entry: dict[str, Any]) -> str | None:
    """`runOptions.runOn`, or None when the task does not set it.

    None rather than the documented default `"default"`: the difference matters
    nowhere here, and recording a value nobody wrote as though they had is the
    habit that produces the answers this project exists to refuse.
    """
    options = entry.get("runOptions")
    if isinstance(options, dict) and isinstance(options.get("runOn"), str):
        return options["runOn"]
    return None


def read(root: Path, *, machine: bool = False, home: Path | None = None) -> Reading:
    """`.vscode/` here, plus the user's own settings when `--machine` says so."""
    root = Path(root)
    tracked, tracked_problem = git_tracked(root)
    settings: list[SettingsFile] = []
    unresolved: list[Unresolved] = []
    not_read: list[NotRead] = []

    for scope, relative, _kind in PROJECT_FILES:
        settings.append(read_jsonc(scope, root / relative, relative))

    if machine:
        base = user_settings_dir(home)
        settings.append(
            read_jsonc(Scope.USER, base / "settings.json", "<user>/Code/User/settings.json")
        )
        settings.append(
            read_jsonc(Scope.USER, base / "tasks.json", "<user>/Code/User/tasks.json")
        )
    else:
        not_read.append(
            NotRead(
                "the user's own VS Code settings.json",
                f"not read without --machine, and it is the only scope that can set "
                f"`{AUTOMATIC_TASKS}`",
            )
        )

    for handle in settings:
        if handle.problem and handle.problem != "absent":
            unresolved.append(Unresolved(handle.display, handle.problem, handle.display))

    # The four facts about every script a task points at. Same treatment as a
    # hook's target: existence, inside the tree, tracked by git, and a digest -
    # and never a fifth fact obtained by reading what the script does.
    scripts: dict[str, dict[str, Any]] = {}
    for handle in settings:
        if not handle.ok:
            continue
        assert handle.data is not None
        for entry in tasks_in(handle.data):
            command = task_command(entry)
            if command is None:
                continue
            spoken = referenced_path(command)
            if spoken is not None and spoken not in scripts:
                scripts[spoken] = script_facts(root, spoken, tracked, tracked_problem)

    return Reading(
        vendor=VENDOR,
        root=root,
        settings=tuple(settings),
        unresolved=tuple(unresolved),
        not_read=tuple(not_read),
        scripts=scripts,
    )


def automatic_tasks_setting(reading: Reading) -> tuple[str | None, str | None]:
    """The value that decides, and the file it came from - or (None, None).

    Highest-precedence scope first, which for VS Code is the reverse of Claude
    Code's ladder: "later scopes override earlier scopes", user before
    workspace. It is only ever answered from a scope this reader actually
    opened; a scope nobody read contributes nothing, which is what lets the
    third answer be INDETERMINATE rather than the documented default.

    A workspace file that sets the key is NOT an answer, because the key is
    APPLICATION-scoped and VS Code does not honour it there. That is recorded
    as its own capability rather than silently dropped: a repository that wrote
    it meant something by it.
    """
    for handle in reading.settings:
        if not handle.ok or handle.scope is not Scope.USER:
            continue
        assert handle.data is not None
        value = handle.data.get(AUTOMATIC_TASKS)
        if isinstance(value, str):
            return value, handle.display
    return None, None


def workspace_claims_automatic_tasks(reading: Reading) -> list[SettingsFile]:
    """Workspace files that set the application-scoped key, which VS Code ignores."""
    return [
        handle
        for handle in reading.settings
        if handle.ok
        and handle.scope in (Scope.PROJECT, Scope.PROJECT_LOCAL)
        and isinstance((handle.data or {}).get(AUTOMATIC_TASKS), str)
    ]


__all__ = [
    "ALLOWED",
    "AUTOMATIC_TASKS",
    "BLOCKED",
    "MAX_BYTES",
    "VENDOR",
    "automatic_tasks_setting",
    "read",
    "read_jsonc",
    "runs_on",
    "task_command",
    "tasks_in",
    "workspace_claims_automatic_tasks",
]
