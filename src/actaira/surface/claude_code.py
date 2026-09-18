"""Read what Claude Code's configuration files say, and nothing else.

The reader's whole contract is in the first sentence: it touches disk, and it
does not run anything, resolve anything or judge anything. Asking the audited
tool what it would do is trusting it, and running the script a hook points at
is being the vector, so neither happens here or anywhere downstream.

Design note D-271. Everything this module is defending against arrives the same
way: somebody else's repository, cloned by a developer who has not read it. So
every read is bounded before it is attempted - a byte ceiling, a file-count
ceiling, a directory depth ceiling - and every path is resolved and compared
against the root before it is opened. A reader that can be made to hang, to
exhaust memory or to open `/etc/shadow` by a file in the tree it is reading is a
worse defect than the one it was written to find. `SECURITY.md` names the test
that holds each of those down.

Rejected, and written down because it is the tempting shortcut: reading the
script a hook points at in order to classify it. That is judging what somebody
else's code does (the second negative) on evidence that does not support it (the
third), and it buys nothing a digest does not already buy - the digest is what
an approval is tied to, and the approval is the product.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import NotRead, Scope, Unresolved, miniyaml

# Ceilings, applied before a read rather than after. The numbers are generous
# for a real settings file and cheap for a hostile one; each is a deliberate
# refusal rather than a limit somebody will meet by accident.
MAX_BYTES = 4 * 1024 * 1024
MAX_FILES = 512
MAX_DEPTH = 8

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
# What a read produces
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SettingsFile:
    """One settings file, parsed or explicitly not parsed.

    `data is None` and `problem is not None` say one fact twice on purpose:
    every consumer has to handle the unparsed case, and a file that failed to
    parse must never reach a consumer as an empty mapping. A malformed
    `.claude/settings.json` read as `{}` would report "no hooks", which is the
    exact shape of the lie this project exists to refuse.
    """

    scope: Scope
    path: Path
    display: str
    data: dict[str, Any] | None = None
    problem: str | None = None

    @property
    def ok(self) -> bool:
        return self.data is not None


@dataclass(frozen=True)
class Reading:
    """Everything the reader saw, before anything has been resolved."""

    vendor: str
    root: Path
    settings: tuple[SettingsFile, ...] = ()
    mcp_files: tuple[SettingsFile, ...] = ()
    unresolved: tuple[Unresolved, ...] = ()
    not_read: tuple[NotRead, ...] = ()
    # None when nothing on disk said either way, which is the repo-only case.
    # Never guessed: the difference between "not trusted" and "unknown" is the
    # difference between a capability that is declared and one that is nothing.
    trusted: bool | None = None
    scripts: dict[str, dict[str, Any]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Bounded disk access
# ---------------------------------------------------------------------------


def read_text(path: Path) -> tuple[str | None, str | None]:
    """Text, or a cause. Size is checked before the bytes are asked for."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"cannot stat: {exc.strerror or exc}"
    if size > MAX_BYTES:
        return None, f"larger than the {MAX_BYTES}-byte ceiling ({size} bytes)"
    try:
        return path.read_text(encoding="utf-8"), None
    except UnicodeDecodeError:
        return None, "not valid UTF-8"
    except OSError as exc:
        return None, f"cannot read: {exc.strerror or exc}"


def read_json(scope: Scope, path: Path, display: str) -> SettingsFile:
    """Parse one JSON file. Invalid JSON is a stated cause, never an empty dict."""
    if not path.is_file():
        return SettingsFile(scope, path, display, problem="absent")
    text, problem = read_text(path)
    if text is None:
        return SettingsFile(scope, path, display, problem=problem)
    try:
        parsed = json.loads(text)
    except ValueError as exc:
        return SettingsFile(scope, path, display, problem=f"invalid JSON: {exc}")
    if not isinstance(parsed, dict):
        return SettingsFile(
            scope,
            path,
            display,
            problem=f"top level is {type(parsed).__name__}, not an object",
        )
    return SettingsFile(scope, path, display, data=parsed)


FOREIGN_ABSOLUTE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|//[^/])")


def absolute_anywhere(spoken: str) -> bool:
    """Whether this path is absolute on ANY platform, not just on this one.

    Design note D-279. `\\\\192.168.6.59\\config` and `C:/Users/x` are absolute
    paths that POSIX reads as relative, so on Linux `root / spoken` produced a
    path INSIDE the tree and `check` answered that a repository granting access
    to a file server was granting access to itself. It is the same answer being
    different on two machines, which is the property this repository defends
    everywhere else, and it was found by the gate running on WSL after passing
    on Windows.

    Rejected: `PureWindowsPath(spoken).is_absolute()` on every path. It calls
    `a/b` relative and `C:x` absolute correctly, but it also reads a plain POSIX
    path containing a backslash - legal in a filename - as a directory
    separator, so a repository could hide an escape in a file whose name
    contained one.
    """
    return bool(FOREIGN_ABSOLUTE.match(spoken))


def inside(root: Path, candidate: Path) -> bool:
    """Whether `candidate` is under `root` after both are fully resolved.

    Resolved on both sides, so a symlink in the tree pointing at `/etc` is
    outside and says so. `Path.resolve()` and not `os.path.abspath`: the latter
    normalises `..` textually and would call a symlinked escape inside.
    """
    try:
        base = root.resolve()
        return os.path.commonpath([base, candidate.resolve()]) == str(base)
    except (OSError, ValueError):  # different drives on Windows, or a bad path
        return False


def inside_tree(root: Path, spoken: str) -> bool:
    """`inside`, for a path as a repository spelled it. The one callers want."""
    if absolute_anywhere(spoken):
        return False
    return inside(root, (root / spoken).expanduser())


# ---------------------------------------------------------------------------
# Git's index, read rather than asked for
# ---------------------------------------------------------------------------


def git_tracked(root: Path) -> tuple[frozenset[str], str | None]:
    """The paths `.git/index` lists, parsed from the file.

    Rejected: `git ls-files`. It is a subprocess, and a reader that shells out
    to answer a question is one command away from being asked to shell out to
    answer a harder one. The index format is documented and stable, so it is
    read like any other file on disk.

    Version 4 path-compresses its entries and is not parsed here: it returns a
    cause, and every script's `git_tracked` fact becomes unknown rather than
    false. Saying "not tracked" about a file we could not look up is the third
    negative with a different subject.
    """
    index = root / ".git" / "index"
    if not index.is_file():
        return frozenset(), "no .git/index: this root is not a git working tree"
    try:
        blob = index.read_bytes()
    except OSError as exc:
        return frozenset(), f"cannot read .git/index: {exc.strerror or exc}"
    if len(blob) < 12 or blob[:4] != b"DIRC":
        return frozenset(), ".git/index is not in the DIRC format"
    version, count = struct.unpack(">II", blob[4:12])
    if version not in (2, 3):
        return frozenset(), f"git index version {version} is not read by this release"

    paths: set[str] = set()
    at = 12
    for _ in range(min(count, MAX_FILES * 64)):
        start = at
        at += 62  # the fixed entry header, up to and including the flags
        if at > len(blob):
            return frozenset(), ".git/index ends inside an entry"
        end = blob.find(b"\x00", at)
        if end == -1:
            return frozenset(), ".git/index ends inside a path"
        paths.add(blob[at:end].decode("utf-8", "replace"))
        at = end + 1
        at += (8 - ((at - start) % 8)) % 8  # entries are padded to a multiple of 8
    return frozenset(paths), None


# ---------------------------------------------------------------------------
# The four facts about a referenced script
# ---------------------------------------------------------------------------


def script_facts(
    root: Path, spoken: str, tracked: frozenset[str], tracked_problem: str | None
) -> dict[str, Any]:
    """Exists, inside the tree, tracked by git, and its sha256. Nothing else.

    Four facts and no fifth. The fifth would be what the script does, and
    reading it to find out is the line this tool does not cross - CLAUDE.md's
    second and third negatives, and the reason an approval is tied to the digest
    rather than to the path (published limit 14).
    """
    target = (root / spoken).expanduser()
    within = inside_tree(root, spoken)
    facts: dict[str, Any] = {
        "exists": target.is_file(),
        "inside_tree": within,
        "sha256": None,
        "git_tracked": None if tracked_problem else False,
    }
    if tracked_problem:
        facts["git_tracked_unknown_because"] = tracked_problem
    if not target.is_file():
        return facts
    if within and not tracked_problem:
        try:
            relative = target.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            relative = spoken
        facts["git_tracked"] = relative in tracked
    try:
        size = target.stat().st_size
    except OSError:
        return facts
    if size > MAX_BYTES:
        facts["sha256_unknown_because"] = f"larger than the {MAX_BYTES}-byte ceiling"
        return facts
    digest = hashlib.sha256()
    try:
        with target.open("rb") as handle:
            for block in iter(lambda: handle.read(65536), b""):
                digest.update(block)
    except OSError as exc:
        facts["sha256_unknown_because"] = f"cannot read: {exc.strerror or exc}"
        return facts
    facts["sha256"] = digest.hexdigest()
    return facts


def digest_of(text: str) -> str:
    """The digest that stands in for a literal when `--with-content` is off.

    A command line, an HTTP endpoint and a header value can each carry a secret,
    and a report is pasted into CI logs. So what travels by default is the shape
    and the digest, which is what `watch` and `scan` already do with somebody's
    conversation (D-263). Unsalted here, deliberately: this digest exists to be
    COMPARED between two runs and between two machines, which is what `diff` and
    an expiring approval are made of, and a per-run salt would make every such
    comparison impossible while hiding nothing a repository has not published.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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


# ---------------------------------------------------------------------------
# Finding the script a command string refers to
# ---------------------------------------------------------------------------

SCRIPT_SUFFIXES = (".mjs", ".js", ".cjs", ".ts", ".py", ".sh", ".bash", ".ps1", ".rb", ".pl")


def referenced_path(command: str) -> str | None:
    """The path a hook command appears to refer to, or None if none is recognised.

    Design note D-272. This is a PARSE, not a verdict: it looks for a token that
    is shaped like a path, and it never decides what running it would do. When
    it recognises nothing it returns None, and the rule that wanted a target
    then answers INDETERMINATE rather than guessing - so an unusual command
    shape costs a stated gap, never a wrong finding in either direction.

    Rejected: a shell parser. `node .vscode/setup.mjs` and `sh -c "$(curl ...)"`
    are both one token away from each other under any parser simple enough to
    be correct, and a parser complex enough to tell them apart is a second
    implementation of a shell inside a tool whose whole promise is that it never
    runs one.
    """
    for token in command.replace("\\", "/").split():
        if token.startswith("-"):
            continue
        if "/" in token or token.lower().endswith(SCRIPT_SUFFIXES):
            return token.strip("'\"")
    return None


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
