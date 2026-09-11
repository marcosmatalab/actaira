"""The design-note table has to point at code that exists.

`docs/DESIGN.md` opens with a table mapping each note to the file and line
that carries it, and that table is how a reviewer gets from an argument to the
code it decided. It went stale once already: eight notes, D-29 to D-36, were
written into the modules while the table still stopped at D-28, so a reader
following the table would have concluded the governance layer had no recorded
reasoning at all.

Two checks, and they are the two ways this can rot: a table row pointing at a
file or a note that is not there, and a note in the code that the table never
lists. Line numbers are deliberately not asserted, because a row whose line
has moved by three is still a working reference and a test that failed on it
would be noise on every edit.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from conftest import REPO_ROOT

ROOT = Path(REPO_ROOT)
DESIGN = (ROOT / "docs" / "DESIGN.md").read_text(encoding="utf-8")

TABLE_ROW = re.compile(r"^\| (D-\d+[a-z]?) \| [^|]+ \| `([^`:]+):(\d+)` \|$", re.MULTILINE)
ROWS = TABLE_ROW.findall(DESIGN)

SOURCE_DIRECTORIES = ("src", "evals", "fuzz", "scripts")
NOTE_IN_CODE = re.compile(r"[Dd]esign note (?:\(see docs/DESIGN\.md, )?(D-\d+[a-z]?)")


def source_files() -> list[Path]:
    files: list[Path] = []
    for directory in SOURCE_DIRECTORIES:
        files.extend(sorted((ROOT / directory).rglob("*.py")))
    return [path for path in files if "__pycache__" not in path.parts]


def notes_in_code() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for path in source_files():
        for note in NOTE_IN_CODE.findall(path.read_text(encoding="utf-8")):
            found.setdefault(note, []).append(str(path.relative_to(ROOT)))
    return found


def test_the_table_is_not_empty():
    assert len(ROWS) >= 30, "the design-note table is how a reviewer navigates this repository"


@pytest.mark.parametrize("note, relative, line", ROWS, ids=lambda item: str(item))
def test_every_row_points_at_a_file_that_carries_its_note(note, relative, line):
    path = ROOT / relative
    assert path.exists(), f"{note} points at a missing file: {relative}"
    assert note in path.read_text(encoding="utf-8"), (
        f"{note} points at {relative}, which does not mention it"
    )


def test_every_note_written_in_the_code_is_listed_in_the_table():
    listed = {note for note, _relative, _line in ROWS}
    written = set(notes_in_code())
    missing = sorted(written - listed)
    assert not missing, (
        f"these notes exist in the code and not in the table: {missing}. "
        "A reader following the table would conclude they were never argued."
    )


def test_no_two_rows_claim_the_same_identifier():
    identifiers = [note for note, _relative, _line in ROWS]
    assert len(identifiers) == len(set(identifiers))
