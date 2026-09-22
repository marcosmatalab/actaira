"""Bounded access to a tree somebody else wrote, and the shapes a read produces.

Design note D-300. Every reader in this package needs the same seven things and needs them to
behave identically: a size-checked text read, a JSON read that reports a parse
failure as a cause rather than as an empty mapping, the resolve-and-compare that
decides whether a path is inside the root, git's index, the four facts about a
referenced script, and the digest that stands in for a literal. They were
written first, inside `claude_code.py`, and six readers for other vendors then
imported them from a module named after a manufacturer that is not theirs.

This is that move and nothing else: no behaviour changed, no name changed, and
the phase S4 readers for the machine scope import from here rather than making
the miscount ten instead of six.

Design note D-271 lives here now, because this is where it is implemented.
Everything this module defends against arrives the same way: somebody else's
repository, cloned by a developer who has not read it. So every read is bounded
before it is attempted - a byte ceiling, a file-count ceiling, a directory depth
ceiling - and every path is resolved and compared against the root before it is
opened. A reader that can be made to hang, to exhaust memory or to open
`/etc/shadow` by a file in the tree it is reading is a worse defect than the one
it was written to find. `SECURITY.md` names the test that holds each of those
down.

Rejected: leaving them where they were and re-exporting under a new name. A
re-export is two names for one function, and the second one is the one that
stops being updated.

Nothing here runs anything it reads. `script_facts` records four facts about a
script and never a fifth, and the fifth would be what the script does.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import NotRead, Scope, Unresolved

# Ceilings, applied before a read rather than after. The numbers are generous
# for a real settings file and cheap for a hostile one; each is a deliberate
# refusal rather than a limit somebody will meet by accident.
MAX_BYTES = 4 * 1024 * 1024
MAX_FILES = 512
MAX_DEPTH = 8

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
    reading it to find out is the line this tool does not cross - the second
    and third negatives, and the reason an approval is tied to the digest
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
