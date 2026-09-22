#!/usr/bin/env python3
"""The commit bodies, held to the cap and to the vocabulary, forever.

    python scripts/history_check.py              this branch
    python scripts/history_check.py --branch X   another one

Phase 6 of the closing plan cleaned the history once: forty-five bodies came
down under fifteen lines and the phase scaffolding came out of them. A cleanup
with nothing behind it is a cleanup that lasts until the next sprint, which is
exactly how the bodies got that way the first time, so the criterion of that
phase is a command now and it runs in CI on the job that already fetches the
whole history.

WHAT IT MEASURES, and this is the part worth reading. It measures the body each
commit WILL carry, not the one it carries today:
`.github/history-rewrite/messages.json` maps a commit to the message the replay
will give it, so a commit still on the list is measured by its rewritten body.
That is the same definition `replay.py` uses to refuse to build a history that
would break the cap, imported from here rather than written twice - two checks
over one property share their definition or they cancel.

The consequence is that this is green before the rewrite and green after it,
and red the moment somebody writes a body the rewrite would not have allowed.
The summary line says how many commits are still taking their message from the
map, so "the rewrite has not been applied yet" is a fact on the page rather
than something a reader has to infer from a green tick.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAP = ROOT / ".github" / "history-rewrite" / "messages.json"

# The cap as the acceptance script measures it, with `wc -l` over
# `git log --format=%B`: the message's own lines plus the newline the format
# adds. Fourteen lines of text, therefore.
MAX_LINES = 15

# The vocabulary phase 6 removes, in the spelling its criterion greps for. It
# is a list of words this project used to write in commit messages while
# working through a plan, and none of them means anything to somebody reading
# `git log` afterwards.
FORBIDDEN = ("work rule", "budget", "adversarial pass", "a later session")


def problems_in(bodies: dict[str, str]) -> list[str]:
    """Every body that is too long or carries the scaffolding. Pure."""
    problems: list[str] = []
    for sha, message in sorted(bodies.items()):
        lines = message.rstrip("\n").split("\n")
        if len(lines) + 1 > MAX_LINES:
            problems.append(f"{sha}: {len(lines) + 1} lines, the cap is {MAX_LINES}")
        for word in FORBIDDEN:
            if word in message.lower():
                problems.append(
                    f"{sha}: says {word!r}, which is the vocabulary a reader of "
                    "`git log` gets nothing from"
                )
    return problems


def git(*arguments: str) -> str:
    return subprocess.run(  # noqa: S603 - a fixed argv, no shell
        ["git", *arguments],  # noqa: S607 - git from PATH, as every other script here
        cwd=ROOT, capture_output=True, check=True,
    ).stdout.decode("utf-8")


def rewritten() -> dict[str, str]:
    """The map, or an empty one once it has been applied and removed."""
    if not MAP.is_file():
        return {}
    return json.loads(MAP.read_text(encoding="utf-8"))


def resulting_bodies(branch: str) -> tuple[dict[str, str], int]:
    """(sha -> the body this commit will carry, how many came from the map)."""
    planned = rewritten()
    bodies: dict[str, str] = {}
    from_the_map = 0
    for sha in git("rev-list", branch).split():
        short = sha[:8]
        if short in planned:
            bodies[short] = planned[short]
            from_the_map += 1
        else:
            bodies[short] = git("log", "-1", "--format=%B", sha).rstrip("\n")
    return bodies, from_the_map


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--branch", default="HEAD")
    arguments = parser.parse_args()

    top = subprocess.run(  # noqa: S603 - a fixed argv, no shell
        ["git", "rev-parse", "--show-toplevel"],  # noqa: S607 - git from PATH
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    if top.returncode != 0 or Path(top.stdout.strip()).resolve() != ROOT.resolve():
        # Loud, not a skip. An unpacked sdist has no history to check, and the
        # honest answer is that this ran nowhere rather than that it passed.
        print("this tree is not the root of its own git repository, so there is no "
              "history here to check", file=sys.stderr)
        return 1

    bodies, from_the_map = resulting_bodies(arguments.branch)
    if not bodies:
        print(f"no commits were read on {arguments.branch}, so nothing was checked",
              file=sys.stderr)
        return 1

    problems = problems_in(bodies)
    if problems:
        print(f"{len(problems)} commit message(s) the history should not carry:")
        for line in problems:
            print(f"  {line}")
        print("\nThe cap and the words are the criterion of phase 6, in "
              "docs/ENGINEERING.md. A body over the cap belongs in docs/DESIGN.md, "
              "docs/defects.json or CHANGELOG.md, which is where a reader can find it "
              "without running `git log`.")
        return 1

    pending = (f", {from_the_map} of them still taking it from "
               f"{MAP.relative_to(ROOT).as_posix()}, so the rewrite has not been applied yet"
               if from_the_map else ", none of them from a rewrite map")
    print(f"{len(bodies)} commit messages, each within {MAX_LINES} lines and free of "
          f"the scaffolding vocabulary{pending}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
