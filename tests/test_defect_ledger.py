"""The defect ledger has to describe this repository, not a past one.

`docs/defects.json` carries the central claim of this project: that every
defect in it was found by a mechanism that can fail, and that each one is held
down by a test. A claim like that decays quietly. A test gets renamed in a
refactor, the ledger keeps naming it, the README keeps printing a total, and
the whole argument becomes a number somebody typed once.

So the ledger is data and this file checks it: every field present, every id
unique, and above all every test it names actually defined in the file it says
it is in. `scripts/figures.py` makes the same check against what pytest
collects, which is stricter (it would catch a test excluded by a marker) but
runs only under `make figures`. This one runs on every commit.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from conftest import REPO_ROOT

LEDGER_PATH = Path(REPO_ROOT) / "docs" / "defects.json"
LEDGER = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
DEFECTS = LEDGER["defects"]


def defined_test_names(relative: str) -> set[str]:
    """Function names defined at module level in a test file, via ast.

    Parsing rather than importing: importing a test module to check that it
    defines a name would run its module-level fixtures and collection, which
    is a lot of machinery for a question about text.
    """
    tree = ast.parse((Path(REPO_ROOT) / relative).read_text(encoding="utf-8"))
    return {
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }


def test_the_ledger_is_not_empty():
    assert len(DEFECTS) >= 30, "the ledger is the argument; an empty one makes no argument"


@pytest.mark.parametrize("defect", DEFECTS, ids=lambda item: item["id"])
def test_every_defect_states_what_broke_and_what_found_it(defect):
    for field in ("id", "title", "effect", "found_by", "counts_as", "shipped_defect"):
        assert field in defect, f"{defect.get('id', '?')} is missing {field}"
    assert defect["found_by"] in LEDGER["found_by_meanings"], (
        f"{defect['id']} names a mechanism the ledger does not define"
    )
    assert isinstance(defect["counts_as"], int) and defect["counts_as"] >= 1


@pytest.mark.parametrize("defect", DEFECTS, ids=lambda item: item["id"])
def test_every_defect_is_pinned_or_says_why_not(defect):
    """A defect with no regression test is a defect waiting to come back.

    A note is accepted in place of a test, and exactly one entry still uses
    that door: DEF-58, a lint failure whose regression test is ruff. `make
    lint` runs on every commit and is one of the steps in `make all`, so the
    pin is real; writing a unit test to assert that a `noqa` sits on the right
    line would be a second, weaker copy of what the linter already does.
    """
    assert defect.get("pinned_by") or defect.get("pinned_note"), (
        f"{defect['id']} names neither a regression test nor a reason it has none"
    )


@pytest.mark.parametrize("defect", DEFECTS, ids=lambda item: item["id"])
def test_every_test_the_ledger_names_exists(defect):
    for node in defect.get("pinned_by") or []:
        relative, _, name = node.partition("::")
        assert (Path(REPO_ROOT) / relative).exists(), f"{defect['id']} names a missing file: {relative}"
        assert name in defined_test_names(relative), (
            f"{defect['id']} names {node}, which is not defined in {relative}. "
            "Either the test was renamed and the ledger was not, or the defect lost its pin."
        )


def test_defect_identifiers_are_unique():
    ids = [defect["id"] for defect in DEFECTS]
    assert len(ids) == len(set(ids))


def test_the_shipped_and_unshipped_split_is_explained():
    """Two entries are not defects in the tool. Both have to say which they are.

    Counting a fault in the measuring apparatus as a fault in the tool would
    inflate the headline number in the direction that flatters the author,
    which is exactly the error the benchmark denominator was.
    """
    for defect in DEFECTS:
        if not defect["shipped_defect"]:
            assert defect.get("not_shipped_because"), (
                f"{defect['id']} is excluded from the shipped count without saying why"
            )
