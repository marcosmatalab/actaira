#!/usr/bin/env python3
"""The two coverage numbers the READMEs state, each from where it is defined.

`README.md` said "the floor is 88 and the tree measures 90" and both numbers
were typed. A figure with no command behind it is the one thing the rest of
this repository does not allow itself, and coverage is the worst place for it:
it is the number that most looks like evidence and most easily stops being
true, because nothing about a coverage drop makes a build red until somebody
crosses the floor.

So:

  the floor     is defined once, by `COVERAGE_FLOOR` in the `Makefile`, which
                is the thing that enforces it. This module reads that line
                rather than carrying a second copy of the number, and CI asks
                for it here too (work rule 10).
  the measured  comes from the coverage data file the suite leaves behind,
  percentage    through `coverage json`, so it is coverage's own rounding and
                the same digits `coverage report` prints.

`scripts/figures.py` calls both and writes the result into `figures.json`,
where `figures_contract.py` turns them into figures the two READMEs are held
to like every other number on the page.

    python scripts/coverage_figure.py            print the measured percentage
    python scripts/coverage_figure.py --floor    print the floor
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_FILE = ROOT / ".coverage"


class NotMeasuredError(Exception):
    """No coverage data in this tree. Not the same thing as bad coverage."""


def floor_in(makefile: str) -> int:
    """The floor a Makefile enforces. Pure, so a twin can plant one without one.

    Raises rather than defaulting. A default here would be a third copy of
    the number that agrees with the other two until the day somebody changes
    one of them, and the failure would be a README quoting a floor nothing
    holds.
    """
    for line in makefile.splitlines():
        if line.startswith("COVERAGE_FLOOR"):
            _, _, value = line.partition("=")
            return int(value.strip())
    raise SystemExit(
        "the Makefile defines no COVERAGE_FLOOR, so the floor the README states is "
        "not enforced by anything"
    )


def floor() -> int:
    """The floor `make test-cov` enforces, read from the Makefile that enforces it."""
    return floor_in((ROOT / "Makefile").read_text(encoding="utf-8"))


def measured() -> dict[str, str | int]:
    """The percentage, as `coverage report` would print it.

    `percent_covered_display` and not the float: the published figure is the
    integer a reader sees in the terminal, and publishing the float would put
    a number in the README that moves when one defensive branch changes and
    says nothing anybody could act on. The statement and miss counts are
    deliberately NOT published for the same reason - they differ by a line or
    two between interpreters, and CI compares this file byte for byte.
    """
    if not DATA_FILE.is_file():
        raise NotMeasuredError(f"{DATA_FILE.name} is not here. Run `make test-cov`.")
    with tempfile.TemporaryDirectory() as directory:
        destination = Path(directory) / "coverage.json"
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-m", "coverage", "json", "-o", str(destination), "--quiet"],
            cwd=ROOT, capture_output=True, text=True, timeout=300,
        )
        if completed.returncode != 0 or not destination.is_file():
            # Loud, and NOT NotMeasuredError. A data file that is here and cannot be
            # read is a broken measurement, and the difference between that and
            # an absent one is the difference between a figure this tree cannot
            # check and a figure that is wrong.
            raise SystemExit(
                "there is a .coverage data file and `coverage json` could not read it, "
                "so the published coverage figure cannot be re-measured here:\n"
                + (completed.stderr or completed.stdout).strip()
            )
        totals = json.loads(destination.read_text(encoding="utf-8"))["totals"]
    return {"percent": totals["percent_covered_display"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--floor", action="store_true",
                        help="print the floor from the Makefile instead")
    arguments = parser.parse_args()
    if arguments.floor:
        print(floor())
        return 0
    try:
        print(measured()["percent"])
    except NotMeasuredError as absent:
        raise SystemExit(str(absent)) from absent
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
