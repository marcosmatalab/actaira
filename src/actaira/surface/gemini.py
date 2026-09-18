"""Read Gemini CLI's three `settings.json` scopes, whose ladder is not the others'.

Design note D-286. Gemini CLI's precedence is published as a seven-step list and
two of its steps invert what every other vendor here does: the PROJECT settings
file overrides the USER settings file, and the SYSTEM settings file overrides
both. Claude Code's ladder puts managed first and user above project; Gemini's
puts project above user and system above project.

That is exactly why "resolve across vendors" cannot mean "resolve with one
ladder and label the rows". A capability's scope means something different per
vendor, so each vendor's rows carry its own ladder with its own citation, and
the cross-vendor answer is a UNION of per-vendor answers rather than a merge.
Fusing them would produce a single confident precedence that no vendor
documents.

Strict JSON here, not JSONC. The configuration reference calls these files
`settings.json` and publishes no statement that comments are accepted, and this
package forgives a deviation only where a specification names it - the whole
argument of `jsonc.py`. A Gemini settings file with a comment therefore comes
back INDETERMINATE with "invalid JSON" as its cause, which is a true sentence
about a document we were not told how to read.

`mcpServers.<name>.trust` is the key this vendor is worth reading for on its
own: "Trust this server and bypass all tool call confirmations". It is a single
boolean in a project file that removes every prompt for one server's tools.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from . import NotRead, Scope, Unresolved
from .claude_code import (
    Reading,
    SettingsFile,
    git_tracked,
    read_json,
    referenced_path,
    script_facts,
)

VENDOR = "gemini-cli"

# Keys whose value Gemini CLI runs as a command, each taken from its own
# description in the configuration reference rather than from its name. The
# nested spelling is the one the current settings schema publishes.
COMMAND_KEYS = ("tools.discoveryCommand", "tools.callCommand")

# The v1 spelling of the same two keys, and the nested key each corresponds to.
#
# Design note D-291. Two public repositories set `toolDiscoveryCommand` at the
# top level of `.gemini/settings.json`, and this reader saw neither, so it
# reported nothing about a configured command - which is the one failure a
# configuration reader must not have. They are read now, and they resolve
# INDETERMINATE rather than EFFECTIVE: the current schema publishes only the
# nested names, whether this release of Gemini CLI still migrates the flat ones
# was not established from anything the vendor publishes, and the third negative
# says a predicate with no information answers INDETERMINATE and not either of
# the two convenient alternatives. Saying "it runs" would invent a migration;
# saying "it does not" would invent its removal.
LEGACY_COMMAND_KEYS = {
    "toolDiscoveryCommand": "tools.discoveryCommand",
    "toolCallCommand": "tools.callCommand",
}

# The approval mode that stops asking before an edit, spelled as documented.
# `plan` is NOT here: the reference calls it read-only mode, so it is more
# restrictive than the default rather than less, and a rule that fired on it
# would be reporting a repository for tightening its own configuration.
AUTO_EDIT = "auto_edit"


def system_paths() -> tuple[tuple[Path, str], ...]:
    """The system defaults file and the system settings file, per OS.

    Both, and in this order, because they sit at OPPOSITE ends of the published
    precedence list: system defaults are step 2, below the user's own file, and
    system settings are step 5, above the project's. A reader that collapsed
    them into "the system scope" would have one of the two in the wrong place.
    """
    if sys.platform == "darwin":
        base = Path("/Library/Application Support/GeminiCli")
    elif os.name == "nt":
        base = Path("C:/ProgramData/gemini-cli")
    else:
        base = Path("/etc/gemini-cli")
    defaults = Path(os.environ.get("GEMINI_CLI_SYSTEM_DEFAULTS_PATH") or base / "system-defaults.json")
    settings = Path(os.environ.get("GEMINI_CLI_SYSTEM_SETTINGS_PATH") or base / "settings.json")
    return ((defaults, "system-defaults"), (settings, "system-settings"))


def _home(home: Path | None = None) -> Path:
    if home is not None:
        return home
    try:
        return Path.home()
    except (RuntimeError, OSError):
        return Path(".")


def dig(data: dict[str, Any], path: str) -> Any:
    """`tools.discoveryCommand` out of a nested settings document, or None.

    Gemini's reference spells its keys with dots and stores them nested, so a
    flat `data.get("tools.discoveryCommand")` would find nothing in a real file.
    Both spellings are accepted: a file that uses the flat literal key is a file
    somebody wrote, and reporting nothing about it would be reporting absence.
    """
    if path in data:
        return data[path]
    node: Any = data
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def read(root: Path, *, machine: bool = False, home: Path | None = None) -> Reading:
    """`.gemini/settings.json` here, plus the user and system files under `--machine`."""
    root = Path(root)
    tracked, tracked_problem = git_tracked(root)
    settings: list[SettingsFile] = []
    unresolved: list[Unresolved] = []
    not_read: list[NotRead] = []

    settings.append(
        read_json(Scope.PROJECT, root / ".gemini" / "settings.json", ".gemini/settings.json")
    )

    if machine:
        base = _home(home)
        settings.append(
            read_json(Scope.USER, base / ".gemini" / "settings.json", "~/.gemini/settings.json")
        )
        for path, _which in system_paths():
            settings.append(read_json(Scope.MANAGED, path, str(path)))
    else:
        not_read.append(
            NotRead(
                "~/.gemini/settings.json and the two system settings files",
                "not read without --machine; the system settings file overrides the project's, "
                "so a capability read here may be overridden by one that was not",
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
        for key in (*COMMAND_KEYS, *LEGACY_COMMAND_KEYS):
            value = dig(handle.data, key)
            if not isinstance(value, str):
                continue
            spoken = referenced_path(value)
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


__all__ = [
    "AUTO_EDIT",
    "COMMAND_KEYS",
    "LEGACY_COMMAND_KEYS",
    "VENDOR",
    "dig",
    "read",
    "system_paths",
]
