#!/usr/bin/env python3
"""Point every design-note row at the line that actually argues it.

Design note D-237. `docs/DESIGN.md` maps each note to a `file:line`, and both
READMEs say "every note names the file and line that implements it". The test
deliberately checked the file and not the line, on the reasonable grounds that
a row three lines off is still a working reference. By 2.2.0 fifteen rows were
between 28 and 412 lines off, several landing on a blank line or a closing
bracket, and D-92 pointed at `if args.dsse:` inside `attest` while the note it
names is in `_run_discover`. At that distance the reference is not stale, it
is wrong, and the README's sentence is a claim the file does not keep.

The line is derivable, so it is derived. Every note is argued in a docstring or
a comment that names it, so this finds the first mention of `D-nn` in the file
the row already names and rewrites the number. It never changes the file, the
id or the prose: a row pointing at the wrong *file* is a decision somebody has
to make, and `tests/test_design_notes.py` already fails on one.

    make design-notes      rewrite the line numbers
    make design-notes CHECK=1   fail instead of rewriting, which is what the gate runs
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs" / "DESIGN.md"

ROW = re.compile(r"^\| (D-\d+[a-z]?) \| ([^|]+) \| `([^`:]+):(\d+)` \|$", re.MULTILINE)


def first_mention(relative: str, note: str) -> int | None:
    """The line where this note is argued, which is where it is first named.

    Word-boundary matched so `D-23` does not find `D-230`, and the file is
    read as text because a note can be argued in a comment, a docstring or a
    module header and all three are just lines.
    """
    path = ROOT / relative
    if not path.is_file():
        return None
    pattern = re.compile(rf"\b{re.escape(note)}\b")
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if pattern.search(line):
            return number
    return None


def main() -> int:
    checking = "--check" in sys.argv
    text = DESIGN.read_text(encoding="utf-8")
    moved: list[str] = []
    unfound: list[str] = []

    def rewrite(match: re.Match[str]) -> str:
        note, prose, relative, stated = match.groups()
        found = first_mention(relative, note)
        if found is None:
            unfound.append(f"{note}: {relative} never names it")
            return match.group(0)
        if str(found) != stated:
            moved.append(f"{note}: {relative}:{stated} -> :{found}")
        return f"| {note} | {prose} | `{relative}:{found}` |"

    rewritten = ROW.sub(rewrite, text)

    if unfound:
        print("\n".join("  " + item for item in unfound), file=sys.stderr)
        print("A row whose file does not argue its note is a decision, not a line number.",
              file=sys.stderr)
        return 1

    if checking:
        if moved:
            print(f"{len(moved)} design-note row(s) point at the wrong line:", file=sys.stderr)
            print("\n".join("  " + item for item in moved), file=sys.stderr)
            print("Run `make design-notes`.", file=sys.stderr)
            return 1
        print(f"{len(ROW.findall(text))} design notes, each pointing at the line that argues it")
        return 0

    if rewritten != text:
        DESIGN.write_text(rewritten, encoding="utf-8", newline="\n")
    print(f"{len(ROW.findall(text))} design notes, {len(moved)} line number(s) corrected")
    for item in moved:
        print("  " + item)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
