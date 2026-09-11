#!/usr/bin/env python3
"""Static type checking over `src/`, as a ratchet rather than an ultimatum.

Design note D-242. **The list is empty: all 95 modules under `src/actaira`
type-check with no errors.** The machinery below stays, because the list being
empty is a fact about today and the ratchet is what keeps it true.

It was not always empty. It held 16 modules reporting 48 errors between them,
and the argument for keeping them exempt was that most were the friction a
checker has with code written to be read rather than to be checked. Working
through them showed that argument was half right and half an excuse:

  * Some were the checker being pedantic, and the fix was to say what the code
    already meant. `_HASHES` holds hash constructors, so it says
    `Callable[[], HashAlgorithm]` rather than letting inference land on an
    abstract base. `_verdict` reads its sequences and never owns them, so they
    are `Sequence`.
  * Some were a declared type that was simply **wrong**. The message catalogue
    was annotated `dict[str, dict[str, str]]` while every three-level read in
    the tree contradicted it. Eleven of the 48 errors were that one lie, and
    the checker was right about all eleven.
  * Two were **bugs waiting for an input nobody had sent yet**. A certificate
    whose `signature_hash_algorithm` is None reached a verify call that cannot
    take None; the answer is now the same "not verified" the unknown-key
    branch already gave. And a list append chose its target with a conditional
    expression, so a falsy-but-present document would have been filed as
    missing.
  * The rest were one name doing two jobs in one function: a loop variable
    reused across loops over different types, a `result` that was a
    VerifyResult in one branch and a PackageResult in another.

None of that was fixed with `# type: ignore`. There is not one in the tree.
That distinction is the whole point: silencing a checker and satisfying it
look identical in a green build and are opposites.

The gate fails in both directions, and that is what makes it a ratchet:

  * A module NOT on the list must have no errors. With the list empty, that is
    every module in `src/actaira`.
  * A module ON the list must still have errors. A module cleaned up and left
    on the list is a stale exemption, and a stale exemption is how an
    exclusion list becomes a place things go to hide.

The list only ever shrinks. Adding to it is a decision somebody has to argue
for in a review, which is the point, and there is now nothing to argue from.

Needs mypy, which is in the `types` extra rather than in `dev`: the close gate
(`make all`) must not be able to break because a third-party checker changed
what it reports between two versions.

    python3 scripts/type_check.py        check
    python3 scripts/type_check.py --list report what each module says, and stop
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Empty, and the gate above is what keeps it that way: a module that grows an
# error is a module that was not on this list, which fails. Putting one back
# means writing down which module, and why, where a reviewer will read it.
KNOWN_UNCLEAN: dict[str, str] = {}

ERROR = re.compile(r"^(?P<file>[^:]+):\d+: error:", re.MULTILINE)


def run_mypy() -> str:
    command = [sys.executable, "-m", "mypy", "src/actaira", "--ignore-missing-imports"]
    try:
        run = subprocess.run(  # noqa: S603 - a fixed argv, no shell
            command, cwd=ROOT, capture_output=True, text=True, timeout=900,
        )
    except FileNotFoundError:  # pragma: no cover - environment
        raise SystemExit("python is not on PATH, which cannot be true here") from None
    if "No module named mypy" in run.stderr:
        raise SystemExit(
            'mypy is not installed. It is in the `types` extra, deliberately:\n'
            '    python -m pip install -e ".[types]"'
        )
    return run.stdout


def files_with_errors(output: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for match in ERROR.finditer(output):
        name = match.group("file").replace("\\", "/")
        counts[name] = counts.get(name, 0) + 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Type-check src/ against the known-unclean list")
    parser.add_argument("--list", action="store_true", help="print what each module reports and stop")
    arguments = parser.parse_args()

    counts = files_with_errors(run_mypy())

    if arguments.list:
        names = sorted(set(counts) | set(KNOWN_UNCLEAN))
        if not names:
            print("  no module under src/actaira reports a type error")
            return 0
        for name in names:
            state = "known" if name in KNOWN_UNCLEAN else "NEW"
            print(f"  {counts.get(name, 0):>3} {state:<5} {name}")
        return 0

    problems: list[str] = []

    regressed = sorted(name for name in counts if name not in KNOWN_UNCLEAN)
    for name in regressed:
        problems.append(
            f"{name}: {counts[name]} type error(s) in a module that had none. "
            "Fix them, or argue the exemption into KNOWN_UNCLEAN."
        )

    cleaned = sorted(name for name in KNOWN_UNCLEAN if name not in counts)
    for name in cleaned:
        problems.append(
            f"{name}: no type errors any more, and it is still on the known-unclean "
            "list. Remove the entry so the module is protected from now on."
        )

    if problems:
        print("type-check\n")
        for problem in problems:
            print(f"  FAIL  {problem}")
        print(f"\n{len(problems)} problem(s).")
        return 1

    protected = 0
    for path in (ROOT / "src" / "actaira").rglob("*.py"):
        relative = path.relative_to(ROOT).as_posix()
        if relative not in KNOWN_UNCLEAN:
            protected += 1
    if KNOWN_UNCLEAN:
        print(
            f"type-check: {protected} module(s) clean and held there, "
            f"{len(KNOWN_UNCLEAN)} on the known-unclean list and still unclean"
        )
    else:
        print(
            f"type-check: {protected} module(s), all clean, none exempt, "
            "and no `# type: ignore` anywhere in src/"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
