"""Write the measured figures into both READMEs, rather than asking a human to.

Design note D-181, and D-230 for what changed in 2.2.0. `make release-check`
compares the figures in the READMEs with the ones the code and the harnesses
report, and fails when they differ. That check is correct and it was, on its
own, a treadmill: adding a test changes the count, so every commit that added
a test failed the gate until somebody edited two markdown files by hand, in
two different thousands separators.

A gate whose only remedy is a manual edit gets routed around. So the numbers
are written here, by the same command that measures them, and the gate becomes
what it should be: a check that nobody committed a README written against a
different tree.

What D-230 changed is the scope. This script used to know five figures and
`release_check.py` used to know one of them, each with its own copy of what a
figure was, and everything outside that overlap was typed by hand. By 2.2.0
that had produced a README stating "sixty-six defects across 11 mechanisms"
three lines below a synced line saying 109. The table now lives in
`scripts/figures_contract.py`, both scripts import it, and it covers every
figure the prose is allowed to state.

Only figures that already appear in the file are replaced. This does not
insert prose, and a README that stops mentioning a figure simply stops having
it updated - a script that wrote sentences into a document would be a worse
problem than the one it solved.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from figures_contract import ROOT, SEPARATORS, figures  # noqa: E402


def main() -> int:
    try:
        table = figures()
    except (FileNotFoundError, ValueError) as problem:
        print(problem, file=sys.stderr)
        return 1

    # DEF-122 removed a second writer from this function. The defect ledger's
    # sentence used to be rewritten whole, by a regex of its own, on the ground
    # that two of its figures "never appear on their own". That regex emitted
    # `**137**, all fixed, **17**` - and markup between a figure and its noun is
    # exactly what makes every pattern in the table stop matching. So one
    # mechanism wrote the sentence into a shape the other could not read, the
    # loop below silently wrote nothing there, and the gate silently compared
    # nothing. Both ledger figures have rows in the table now, `defects_pinned`
    # included, and this function has one way of writing a number.
    changed: list[str] = []
    written = 0
    for name in SEPARATORS:
        path = ROOT / name
        before = path.read_text(encoding="utf-8")
        text = before
        for figure in table:
            pattern = figure.patterns.get(name)
            if pattern is None:
                continue
            text, count = re.subn(pattern, figure.rendered(name), text)
            written += count
        if text != before:
            path.write_text(text, encoding="utf-8", newline="\n")
            changed.append(name)

    print(f"{len(table)} figures, {written} occurrences written")
    print(f"  {'updated ' + ', '.join(changed) if changed else 'every guarded page already current'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
