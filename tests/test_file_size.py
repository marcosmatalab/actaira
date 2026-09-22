"""No file in `src/` over nine hundred lines, and the three that are.

The closing plan set "no file over 900 lines" as a criterion of its structural
phase. `surface/resolve.py` was the file it was written about and it went from
2,023 lines to 592. Three files are still over the cap and stay over it, and
that is a decision rather than an omission: the alternative was splitting two
modules the plan's own change inventory never names and one it explicitly
protects, at the end of a piece of work, with no test asking for the split.

A criterion that is not met and not watched is the thing this repository
refuses everywhere else - a number in a document with nothing behind it. So
the criterion becomes a measured rule, and the three files become an
ALLOWLIST with a ceiling each, in the shape `tests/test_layering.py` uses and
for the same reason: an allowlist fails on the case nobody thought of.

It is a RATCHET and it fails in both directions, like `make types`:

  * a file over the cap that is not in the table fails;
  * a file in the table that has grown past the size recorded here fails, so
    "already exempt" never becomes room to grow;
  * a file in the table that is now under the cap fails, because a stale
    exemption is how an exclusion list becomes a place things go to hide;
  * a table entry naming a path that is not in the tree fails, rather than
    quietly guarding nothing (work rule 11).

`docs/ENGINEERING.md` carries the trade-off in prose. This file carries it
where it can fail.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from conftest import SRC_DIR
from test_reachability import MODULES

# The cap the plan set, and the number `make all` holds the tree to.
CAP = 900

# path -> (the size it is allowed to be, why it is over the cap).
#
# The ceiling is the file's size when this table was written, not a round
# number above it. A round ceiling is an allowance; this one is a record of
# what was there, so the first line added over it is red.
ALLOWED: dict[str, tuple[int, str]] = {
    "src/seamark/attest/timestamp.py": (
        1129,
        "RFC 3161 end to end: the ASN.1 for the request, the parse of the "
        "response, the exchange with the authority and the verification of "
        "what came back. Splitting the codec from the verifier that uses it "
        "puts one wire format in two files, which is the two-definitions "
        "shape work rule 10 refuses.",
    ),
    "src/seamark/cli.py": (
        1086,
        "The parser and the seven command bodies. It is the top of the import "
        "graph, the one file where a reader expects to find everything the "
        "tool can do, and a split would move the parser away from the "
        "commands it builds. The change inventory of the closing plan does "
        "not name it, so splitting it here would be work nobody asked for at "
        "the end of a phase.",
    ),
    "src/seamark/attest/verify.py": (
        976,
        "Protected by the plan that set the cap: §3.5 names "
        "`verify_package` and says this file is not touched. Every signature "
        "path in the package ends here, and it is the last place to go "
        "rearranging at the close of a release.",
    ),
}


def lines_in(text: str) -> int:
    """Lines as `wc -l` counts them, which is what the acceptance script runs.

    Two readers of one property share a definition or they cancel. A file
    whose last line has no newline is counted the same way here and there.
    """
    return text.count("\n")


def sizes() -> dict[str, int]:
    return {
        str(path.relative_to(SRC_DIR.parent)).replace("\\", "/"):
            lines_in(path.read_text(encoding="utf-8"))
        for path in MODULES.values()
    }


def violations(measured: dict[str, int], allowed: dict[str, tuple[int, str]]) -> list[str]:
    """Every way the tree and the table can disagree. A pure function, so the
    twins can plant a file that is not on disk and a table that is not the
    one above."""
    problems: list[str] = []
    for path, count in sorted(measured.items()):
        if path in allowed:
            continue
        if count > CAP:
            problems.append(
                f"{path} is {count} lines and the cap is {CAP}. Split it, or add it to "
                "ALLOWED with the size it is and the reason it stays."
            )
    for path, (ceiling, reason) in sorted(allowed.items()):
        if not reason.strip():
            problems.append(f"{path} is allowed over the cap and states no reason")
        if path not in measured:
            problems.append(
                f"ALLOWED names {path}, which is not a module in src/. An exemption for "
                "a file that is not there guards nothing."
            )
            continue
        count = measured[path]
        if count > ceiling:
            problems.append(
                f"{path} is {count} lines and was {ceiling} when it was allowed over the "
                f"cap of {CAP}. Being on this list is not room to grow."
            )
        if count <= CAP:
            problems.append(
                f"{path} is {count} lines, which is inside the cap of {CAP}. Take it out "
                "of ALLOWED: a stale exemption is where the next one hides."
            )
    return problems


def test_the_reader_sees_the_tree():
    """Work rule 11, and work rule 10 in the same assertion.

    The file list comes from `test_reachability.MODULES` rather than from a
    second walk of `src/`, so the two checks cannot end up reading different
    trees. This asserts that the walk the acceptance script performs -
    `find src -name '*.py'` - finds exactly the same files.
    """
    measured = sizes()
    assert len(measured) > 30, f"only {len(measured)} files were read; the reader found nothing"
    on_disk = {
        str(path.relative_to(SRC_DIR.parent)).replace("\\", "/")
        for path in SRC_DIR.rglob("*.py")
        if "__pycache__" not in path.parts and ".egg-info" not in str(path)
    }
    assert on_disk == set(measured), (
        "the module reader and a plain walk of src/ disagree about what is in the tree: "
        f"{sorted(on_disk ^ set(measured))}"
    )


def test_no_file_in_src_is_over_the_cap_unless_the_table_says_so():
    assert not violations(sizes(), ALLOWED), "\n".join(violations(sizes(), ALLOWED))


@pytest.mark.parametrize("dropped", sorted(ALLOWED))
def test_removing_an_entry_from_the_allowlist_fails(dropped):
    """The negative proof, one per entry: take a file off the list and the
    rule has to refuse the tree.

    This is the twin work rule 9 asks for. A cap that has never been seen
    stopping anything is a cap nobody has tested, and each of these three
    files is over it right now, so the failure is the real one rather than a
    plant.
    """
    without = {path: row for path, row in ALLOWED.items() if path != dropped}
    problems = violations(sizes(), without)
    assert any(dropped in problem and "the cap is" in problem for problem in problems), (
        f"{dropped} is over the cap and the rule said nothing when it was taken off the "
        f"allowlist: {problems}"
    )


@pytest.mark.parametrize(
    ("measured", "allowed", "expected"),
    [
        # A new file over the cap that nobody added to the table.
        ({"src/seamark/report/pdf.py": 1200}, {}, "Split it"),
        # An allowed file that grew after being allowed.
        (
            {"src/seamark/cli.py": 1400},
            {"src/seamark/cli.py": (1086, "as above")},
            "not room to grow",
        ),
        # An allowed file that was split and left on the list.
        (
            {"src/seamark/cli.py": 300},
            {"src/seamark/cli.py": (1086, "as above")},
            "Take it out",
        ),
        # A table entry for a file that is not in the tree.
        ({}, {"src/seamark/web/app.py": (1000, "as above")}, "guards nothing"),
        # An exemption with no reason written next to it.
        (
            {"src/seamark/cli.py": 1000},
            {"src/seamark/cli.py": (1086, "   ")},
            "states no reason",
        ),
    ],
)
def test_the_rule_refuses_each_way_it_can_be_broken(measured, allowed, expected):
    problems = violations(measured, allowed)
    assert any(expected in problem for problem in problems), (
        f"planted {measured} against {allowed} and got {problems}"
    )


def test_the_rule_is_not_vacuous():
    """A cap so high that nothing can reach it is a green tick with nothing
    behind it."""
    assert violations({"src/seamark/model.py": CAP + 1}, {}), (
        f"a file one line over {CAP} passed the cap"
    )
    assert not violations({"src/seamark/model.py": CAP}, {}), (
        f"a file of exactly {CAP} lines was refused; the cap is inclusive"
    )


def test_the_three_allowed_files_are_the_ones_the_documentation_names():
    """`docs/ENGINEERING.md` argues the exception in prose, and prose about a
    list is the second copy that goes stale first."""
    page = (Path(SRC_DIR).parent / "docs" / "ENGINEERING.md").read_text(encoding="utf-8")
    for path in ALLOWED:
        assert path in page, (
            f"{path} is allowed over the {CAP}-line cap and docs/ENGINEERING.md does not "
            "name it. An exception nobody can read about is an exception nobody agreed to."
        )
    named = {
        line.split("`")[1]
        for line in page.splitlines()
        if line.startswith("| `src/seamark/") and "`" in line
    }
    assert named == set(ALLOWED), (
        "the table in docs/ENGINEERING.md and the table in this file name different "
        f"files: {sorted(named ^ set(ALLOWED))}"
    )
