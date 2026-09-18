"""AGENTS.md, CLAUDE.md and GEMINI.md, read for structure and never for meaning.

Design note D-287. These files are free text that several vendors load into a
model's context at session start, so the temptation is to classify what they
SAY. That is judging intention on evidence that cannot support it - CLAUDE.md's
second and third negatives together - and it is also a losing game: a list of
suspicious phrases is a list somebody rewords.

So this module answers three questions that a machine can answer the same way
twice, and no fourth:

1. Does an import resolve outside the repository tree? Both vendors that
   document `@path` imports say the path may be absolute or relative, and Claude
   Code documents what happens when one leaves the working directory: an
   approval dialog the first time. That is a capability with a condition, and
   both are structural facts about a path.
2. Does a line contain, literally, a download piped into an interpreter? This is
   a LITERAL match on two token families in one line - `curl` or `wget`, and
   `sh`, `bash`, `zsh` or `python` after a pipe. It is not a judgement about
   what the line is for. A line that contains it contains it.
3. Does the file name a script by path? Same treatment as a hook's target, and
   the same four facts: exists, inside the tree, tracked, digest.

The rule that fires on the second is named "the instructions file contains a
literal remote-execution command", never "the instructions file is malicious".
The difference is the whole of the second negative, and `test_surface_instructions`
asserts it by putting "ignore all previous instructions" in a fixture and
requiring that nothing fires.

Code spans and fenced code blocks are skipped for imports, because Claude Code
documents that they are: "Import parsing skips Markdown code spans and fenced
code blocks." An `@README` inside backticks is documentation about an import,
not one. They are NOT skipped for the literal download match: a fenced block is
how a person is told to run something, and the question there is whether the
string is present, not whether the vendor would expand it.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import NotRead, Scope, Unresolved
from .claude_code import (
    MAX_FILES,
    Reading,
    SettingsFile,
    absolute_anywhere,
    git_tracked,
    inside_tree,
    read_text,
    script_facts,
)

VENDOR = "instructions"

# The instruction files this release reads, and the vendor that documents each.
# `CLAUDE.md` is here as well as in phase S1's not-read list: S1 named it and
# did not open it, and this is the release that does.
WELL_KNOWN = {
    "AGENTS.md": "codex",
    "CLAUDE.md": "claude-code",
    "CLAUDE.local.md": "claude-code",
    "GEMINI.md": "gemini-cli",
}

# `@path`, as both vendors document it. Anchored at a line start or whitespace
# so an email address and a `user@host` in prose are not imports, and stopped
# before trailing punctuation so `@docs/x.md.` imports `docs/x.md`.
IMPORT = re.compile(r"(?:^|(?<=\s))@(?P<path>[^\s`]+?)(?=[.,;:!?)\]]*(?:\s|$))")

# A download piped into an interpreter, matched on ONE line as two literal
# token families either side of a pipe. Deliberately not a shell parser: this
# is a presence test, and D-272 already argued why writing a shell to be sure
# is the wrong trade for a tool that never runs one.
FETCHERS = ("curl", "wget")
INTERPRETERS = ("sh", "bash", "zsh", "dash", "python", "python3", "node", "ruby", "perl")
PIPED = re.compile(
    r"\b(?:{fetch})\b[^|\n]*\|\s*(?:\S*/)?(?:sudo\s+)?\b(?:{run})\b".format(
        fetch="|".join(FETCHERS), run="|".join(INTERPRETERS)
    )
)

FENCE = re.compile(r"^\s*(?:```|~~~)")
CODE_SPAN = re.compile(r"`[^`]*`")


def strip_code(text: str) -> str:
    """The document with fenced blocks and code spans blanked, newlines kept.

    Blanked rather than deleted so a line number computed over the result is
    the line number in the file, which is what a person opens the file at.
    """
    out: list[str] = []
    fenced = False
    for line in text.splitlines():
        if FENCE.match(line):
            fenced = not fenced
            out.append("")
            continue
        out.append("" if fenced else CODE_SPAN.sub(lambda m: " " * len(m.group(0)), line))
    return "\n".join(out)


def imports(text: str) -> list[str]:
    """Every `@path` this document imports, code spans and fences skipped."""
    return [matched.group("path") for matched in IMPORT.finditer(strip_code(text))]


def piped_downloads(text: str) -> list[int]:
    """The 1-based line numbers carrying a literal download into an interpreter.

    Over the WHOLE document, fences included. The question this answers is
    whether the string is present for a reader - human or model - to follow,
    and a fenced block is the usual way one is presented.
    """
    return [
        number
        for number, line in enumerate(text.splitlines(), start=1)
        if PIPED.search(line)
    ]


def outside_tree(root: Path, spoken: str) -> bool:
    """Whether an import leaves the repository, on any platform's spelling.

    `~/` is outside by definition and is the spelling Claude Code's own
    documentation uses for the case, so it is answered before the path is
    joined to anything.
    """
    if spoken.startswith("~"):
        return True
    if absolute_anywhere(spoken):
        return True
    return not inside_tree(root, spoken)


def read(root: Path, *, machine: bool = False, home: Path | None = None) -> Reading:
    """Every well-known instruction file at the root of the tree.

    The root only. Claude Code loads CLAUDE.md from every directory above the
    working directory and on demand from those below it, and both of those are
    outside what a reader handed one repository can see: the first is the
    developer's own filesystem, the second depends on which files the agent
    happens to open. Both are named in `not_read` rather than half-walked.
    """
    root = Path(root)
    tracked, tracked_problem = git_tracked(root)
    settings: list[SettingsFile] = []
    unresolved: list[Unresolved] = []
    not_read: list[NotRead] = [
        NotRead(
            "instruction files above and below the repository root",
            "files in parent directories are on the developer's own filesystem, and files in "
            "subdirectories load on demand depending on what the agent opens; this release "
            "reads the root",
        )
    ]
    scripts: dict[str, dict[str, Any]] = {}
    seen = 0

    for name in sorted(WELL_KNOWN):
        path = root / name
        if not path.is_file():
            continue
        if seen >= MAX_FILES:
            not_read.append(NotRead(name, f"more than the {MAX_FILES}-file ceiling"))
            continue
        seen += 1
        text, problem = read_text(path)
        if text is None:
            unresolved.append(Unresolved(name, problem or "unreadable", name))
            continue
        found = imports(text)
        settings.append(
            SettingsFile(
                Scope.PROJECT,
                path,
                name,
                data={
                    "file": name,
                    "documented_by": WELL_KNOWN[name],
                    "imports": found,
                    "piped_download_lines": piped_downloads(text),
                },
            )
        )
        for spoken in found:
            if spoken not in scripts:
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
    "FETCHERS",
    "INTERPRETERS",
    "VENDOR",
    "WELL_KNOWN",
    "imports",
    "outside_tree",
    "piped_downloads",
    "read",
    "strip_code",
]
