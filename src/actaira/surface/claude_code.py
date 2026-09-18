"""Read what Claude Code's configuration files say, and nothing else.

The reader's whole contract is in the first sentence: it touches disk, and it
does not run anything, resolve anything or judge anything. Asking the audited
tool what it would do is trusting it, and running the script a hook points at
is being the vector, so neither happens here or anywhere downstream.

What is bounded and how is not here any more. The ceilings, the size-checked
reads, git's index, the four facts about a referenced script and the digest that
stands in for a literal are in `disk.py`, which is where the other six readers
import them from as well; design note D-271 moved with them. This module is the
Claude Code half: which files, in which scopes, and what its own documentation
calls them.

Rejected, and written down because it is the tempting shortcut: reading the
script a hook points at in order to classify it. That is judging what somebody
else's code does (the second negative) on evidence that does not support it (the
third), and it buys nothing a digest does not already buy - the digest is what
an approval is tied to, and the approval is the product.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from . import NotRead, Scope, Unresolved, miniyaml
from .disk import (
    MAX_DEPTH,
    MAX_FILES,
    Reading,
    SettingsFile,
    git_tracked,
    inside,
    read_json,
    read_text,
    referenced_path,
    script_facts,
)

VENDOR = "claude-code"

# What phase S1 reads in the project scope, highest precedence first. The order
# is the order the console prints them in, so two runs over one tree agree.
PROJECT_SETTINGS = (
    (Scope.PROJECT_LOCAL, ".claude/settings.local.json"),
    (Scope.PROJECT, ".claude/settings.json"),
)

# Seen and not read, each with a live reason. Phase S1's entries were the six
# vendors it deferred; phase S2 reads all of them, so what is left is what is
# still genuinely unread by ANY reader in this tree. A file in this list is
# reported, never skipped: silence reads as absence, and absence is the one
# thing a configuration reader must not imply.
#
# `.cursorrules` is the legacy spelling of Cursor's rules file. The rules pages
# document `.cursor/rules/*.mdc` and `AGENTS.md` and do not describe
# `.cursorrules`, so this release names it rather than guessing at a format the
# vendor no longer publishes.
NOT_READ_IN_S2 = (
    (".cursorrules", "the legacy Cursor rules file; the current documentation describes "
                     ".cursor/rules/ and AGENTS.md instead, so its format is not read here"),
    (".cursor/rules", "Cursor project rules carry instructions rather than capabilities; "
                      "the structural rules of this release read AGENTS.md and CLAUDE.md"),
    (".github/copilot-instructions.md", "no vendor read by this release documents loading it"),
)

# Settings keys that run a command, confirmed one by one against the "executes a
# command" column of the settings reference on the date in `resolve.CONSULTED`.
# A key is here because the documentation says it runs something, never because
# its name sounds as though it might.
COMMAND_KEYS = (
    "apiKeyHelper",
    "statusLine",
    "awsAuthRefresh",
    "awsCredentialExport",
    "otelHeadersHelper",
    "fileSuggestion",
)

# Hook events that fire without the operator asking for anything: opening a
# session is not a decision to run code. `SessionStart` is the one both worms
# used; the others are here because the same argument covers them, and a
# detector written for one event is a detector for one attack.
STARTUP_EVENTS = ("SessionStart", "Setup", "InstructionsLoaded", "ConfigChange")

# The handler types the hooks reference documents, and the only ones that may
# become a capability name.
#
# Design note D-290. `hook.{type}` used to be built from the `type` string in the
# file, so a settings file containing `"type": "totally-made-up"` produced the
# capability `hook.totally-made-up` - the audited repository choosing a name in
# Actaira's own vocabulary. Two things were wrong with that. A document's
# vocabulary has to be ours or it is not a contract, and no rule can ever name a
# capability whose spelling the input invents, so such a hook was reported and
# unrulable at the same time. An unknown type is now INDETERMINATE with the type
# it carried as its cause, which is the honest answer: something is configured
# there and this release does not know what it is.
HANDLER_TYPES = ("command", "http", "mcp_tool")






# ---------------------------------------------------------------------------
# Where the machine-scope files live
# ---------------------------------------------------------------------------


def managed_paths() -> tuple[Path, ...]:
    """The managed policy files, per operating system.

    Documented under "where each mechanism stores the policy". The MDM and
    registry mechanisms deliver the same keys through channels that leave no
    file, and this reader sees only files - which is published limit 12, and the
    reason a machine read reports the registry as not read rather than absent.
    """
    if sys.platform == "darwin":
        base = Path("/Library/Application Support/ClaudeCode")
    elif os.name == "nt":
        base = Path("C:/Program Files/ClaudeCode")
    else:
        base = Path("/etc/claude-code")
    return (base / "managed-settings.json", base / "managed-mcp.json")


def user_home(home: Path | None = None) -> Path:
    """`CLAUDE_CONFIG_DIR`'s parent, or the home directory, resolved when asked.

    Resolved when asked and not at import, for the reason D-240 gives about
    `default_key_path`: `Path.home()` raises where the environment names no home
    directory, and a module-level call takes `--help` down with it.
    """
    if home is not None:
        return home
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    if configured:
        return Path(configured).parent
    try:
        return Path.home()
    except (RuntimeError, OSError):
        return Path(".")



def hook_handlers(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """(event, handler) for every hook handler in one settings document.

    Shape-tolerant on purpose. This document was written by whoever sent the
    pull request, so every level is checked before it is walked: a `hooks` key
    holding a list, a matcher entry holding a string, a handler holding null.
    None of those is valid configuration and all of them are things a file on
    disk can contain, and a `TypeError` out of the reader is a crash where a
    finding belonged.
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


def command_strings(data: dict[str, Any]) -> list[str]:
    """Every string in this document that Claude Code would run as a command.

    The hook handlers' `command`, plus the six settings keys the reference marks
    as executing a command. Both shapes of those keys are accepted: the plain
    string and the `{"type": "command", "command": ...}` object.
    """
    found: list[str] = []
    for _event, handler in hook_handlers(data):
        if handler.get("type") == "command" and isinstance(handler.get("command"), str):
            found.append(handler["command"])
    for key in COMMAND_KEYS:
        value = data.get(key)
        if isinstance(value, str):
            found.append(value)
        elif isinstance(value, dict) and isinstance(value.get("command"), str):
            found.append(value["command"])
    return found


# ---------------------------------------------------------------------------
# The read itself
# ---------------------------------------------------------------------------


def frontmatter_files(root: Path) -> tuple[list[Path], list[NotRead]]:
    """Every skill and subagent definition under `.claude/`, bounded.

    Bounded by count and by depth, because the directory being walked belongs to
    whoever wrote the repository. The ceilings are reported when they bite, so a
    tree that was too big to walk says so instead of reporting what it managed.
    """
    found: list[Path] = []
    capped: list[NotRead] = []
    for folder in ("agents", "skills"):
        base = root / ".claude" / folder
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.md")):
            if len(path.relative_to(base).parts) > MAX_DEPTH:
                continue
            if not inside(root, path):
                capped.append(NotRead(path.name, "resolves outside the root"))
                continue
            if len(found) >= MAX_FILES:
                capped.append(
                    NotRead(
                        f".claude/{folder}/",
                        f"more than the {MAX_FILES}-file ceiling",
                    )
                )
                break
            found.append(path)
    return found, capped


def frontmatter_block(text: str) -> str | None:
    """The YAML between the opening `---` and the next one, or None.

    None when the file has no frontmatter at all, which is the ordinary case for
    a skill that is prose. A document that opens a block and never closes it is
    also None rather than an error: an unterminated `---` is not frontmatter, and
    reporting a gap about every markdown file that starts with a horizontal rule
    would bury the gaps that matter.
    """
    if not text.startswith("---"):
        return None
    rest = text[3:]
    if rest[:1] not in ("\n", "\r"):
        return None
    end = rest.find("\n---")
    return rest[:end] if end != -1 else None


def read(
    root: Path, *, machine: bool = False, home: Path | None = None
) -> Reading:
    """Every file this release reads, and a named gap for every one it does not.

    `machine` adds the two scopes that live outside the repository: the user's
    own settings and the managed policy. They are not read by default, because
    the common case is a pull request and a pull request cannot change them -
    and reading a developer's home directory to answer a question about a
    repository is a privacy cost with no answer attached.
    """
    root = Path(root)
    tracked, tracked_problem = git_tracked(root)
    settings: list[SettingsFile] = []
    mcp_files: list[SettingsFile] = []
    unresolved: list[Unresolved] = []
    not_read: list[NotRead] = []

    for scope, relative in PROJECT_SETTINGS:
        settings.append(read_json(scope, root / relative, relative))
    mcp_files.append(read_json(Scope.PROJECT, root / ".mcp.json", ".mcp.json"))

    if machine:
        base = user_home(home)
        settings.append(
            read_json(Scope.USER, base / ".claude" / "settings.json", "~/.claude/settings.json")
        )
        mcp_files.append(read_json(Scope.USER, base / ".claude.json", "~/.claude.json"))
        for path in managed_paths():
            settings.append(read_json(Scope.MANAGED, path, str(path)))
        not_read.append(
            NotRead(
                "MDM profile, HKLM and HKCU registry",
                "managed policy delivered without a file is invisible to a reader of files "
                "(published limit 12)",
            )
        )
    else:
        not_read.append(
            NotRead("~/.claude/settings.json and the managed policy", "not read without --machine")
        )

    # Only files that exist are worth a gap. An absent settings file is not a
    # gap: it is the ordinary case, and reporting it would bury the real ones.
    for handle in (*settings, *mcp_files):
        if handle.problem and handle.problem != "absent":
            unresolved.append(
                Unresolved(
                    subject=handle.display,
                    cause=handle.problem,
                    source=handle.display,
                )
            )

    # The four facts about every script any of those files points at.
    #
    # Both lists, which is the phase S1 defect this closes. A downloaded
    # plugin's `hooks/hooks.json` was appended to `mcp_files`, and this walk
    # only visited `settings` - so ACT-S003, ACT-S004 and ACT-S005 answered
    # INDETERMINATE about a plugin hook whose target was on disk all along.
    # Honest and incomplete is still incomplete.
    scripts: dict[str, dict[str, Any]] = {}

    def note_scripts(handles: list[SettingsFile]) -> None:
        for handle in handles:
            if not handle.ok:
                continue
            assert handle.data is not None
            for command in command_strings(handle.data):
                spoken = referenced_path(command)
                if spoken is None or spoken in scripts:
                    continue
                scripts[spoken] = script_facts(root, spoken, tracked, tracked_problem)

    note_scripts(settings)

    # Frontmatter. Phase S1 had no YAML reader and named every definition as a
    # gap; `miniyaml` reads the subset these files use, so a `hooks` block is
    # now PARSED and a document outside that subset is the only thing still
    # INDETERMINATE - with the construct that put it there as its cause.
    definitions, capped = frontmatter_files(root)
    not_read.extend(capped)
    for path in definitions:
        text, problem = read_text(path)
        display = path.relative_to(root).as_posix()
        if text is None:
            unresolved.append(Unresolved(display, problem or "unreadable", display))
            continue
        block = frontmatter_block(text)
        if block is None:
            continue
        try:
            parsed = miniyaml.loads(block)
        except miniyaml.YamlError as exc:
            unresolved.append(
                Unresolved(
                    subject=f"{display} frontmatter",
                    cause=f"frontmatter is outside the subset this release reads: {exc}",
                    source=display,
                )
            )
            continue
        if isinstance(parsed.get("hooks"), dict):
            settings.append(
                SettingsFile(
                    Scope.PROJECT, path, display, data={"hooks": parsed["hooks"]}
                )
            )

    # Plugins. What is on disk is read; what a marketplace would have to supply
    # is a gap, because a plugin that has not been downloaded is a capability
    # nobody can see and reporting it as absent would be an answer we do not have.
    for handle in settings:
        if not handle.ok:
            continue
        assert handle.data is not None
        enabled = handle.data.get("enabledPlugins")
        if not isinstance(enabled, dict):
            continue
        for name in sorted(enabled):
            local = root / ".claude" / "plugins" / str(name) / "hooks" / "hooks.json"
            if local.is_file():
                mcp_files.append(
                    read_json(handle.scope, local, local.relative_to(root).as_posix())
                )
            else:
                unresolved.append(
                    Unresolved(
                        subject=f"plugin {name}",
                        cause="enabled from a marketplace and not downloaded into this tree",
                        source=handle.display,
                    )
                )

    # Plugin hook files and any frontmatter block were appended above, after the
    # first pass, so they get a pass of their own rather than an ordering rule
    # somebody has to remember.
    note_scripts(settings)
    note_scripts(mcp_files)

    for relative, vendor in NOT_READ_IN_S2:
        if (root / relative).exists():
            not_read.append(NotRead(relative, vendor))

    trusted: bool | None = None
    if machine:
        claude_json = read_json(Scope.USER, user_home(home) / ".claude.json", "~/.claude.json")
        if claude_json.ok:
            assert claude_json.data is not None
            projects = claude_json.data.get("projects")
            if isinstance(projects, dict):
                entry = projects.get(str(root)) or projects.get(str(root.resolve()))
                if isinstance(entry, dict):
                    accepted = entry.get("hasTrustDialogAccepted")
                    trusted = accepted if isinstance(accepted, bool) else None

    return Reading(
        vendor=VENDOR,
        root=root,
        settings=tuple(settings),
        mcp_files=tuple(mcp_files),
        unresolved=tuple(unresolved),
        not_read=tuple(not_read),
        trusted=trusted,
        scripts=scripts,
    )
