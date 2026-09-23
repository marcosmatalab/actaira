#!/usr/bin/env python3
"""Build the wheel and the sdist into `dist/`, then check what went into them.

Design note D-239. The two distribution files used to be built in the root of
the tree and left there, beside the source, where the next archive of the
folder swept them up: a delivered copy of this repository carried a wheel and
a tarball of itself. The build is not the problem, the place is - so this one
cleans first, writes only into `dist/`, and then opens both artifacts and
asserts what is inside them.

The assertions are the reason this is a script and not a Makefile line. A
package is the one artifact whose contents nobody looks at, and three of the
things that must never be in one are things this repository deliberately
generates: `evals/corpus/build.py`, which writes working gadget pickles; the
fuzz corpus; and the temporary captures. `MANIFEST.in` already excludes them,
and an exclusion that nothing checks is how they get back in.

    python3 scripts/build_package.py            build and check
    python3 scripts/build_package.py --install  also install the wheel into a
                                                throwaway venv and run the CLI
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

def required() -> tuple[str, ...]:
    """Everything a working install needs that is not a `.py` file.

    Read off `src/` rather than typed. The failure these guard against is
    always the same shape: the tool imports, runs, and then cannot find a
    schema, a translation or a demo session.

    It WAS typed, and it named `seamark/web/static/index.html`, two more files
    beside it, a cassette and `report-v1.json` - all of which went to tag
    v2.3.0 with the scanner. So `make package` failed on every run from the
    pivot onwards, and nothing said so because `make package` is deliberately
    not in `make all`: a packaging tool must not be able to break an install.
    That argument is still right and it left this script unread for a release.

    The rule now is the simple one: a non-Python file that is inside the
    package directory is a file the package ships. Rejected: extending the
    literal list, which is how it came to describe a tree that is not there.
    """
    package = ROOT / "src" / "seamark"
    found = tuple(sorted(
        path.relative_to(ROOT / "src").as_posix()
        for path in package.rglob("*")
        if path.is_file() and path.suffix != ".py" and "__pycache__" not in path.parts
    ))
    if not found:
        raise SystemExit(
            "no data file was found under src/seamark, so this build would be checked "
            "against nothing. Work rule 11: a check that finds nothing has not passed."
        )
    return found

# What must never ship. The first two are the point: a distributed artifact is
# not where a generator of working gadget pickles belongs, and the fuzz corpus
# is raw malformed input with no reason to travel.
FORBIDDEN_SUBSTRINGS = (
    "evals/corpus/build.py",
    "fuzz/corpus/",
    ".screenshots/",
    ".venv/",
    "site-data.json",
)
FORBIDDEN_PREFIXES = ("tests/", "evals/", "fuzz/", ".github/", ".screenshots/", ".env")


class PackagingError(Exception):
    """Something is in a distribution that should not be, or missing from one."""


def clean() -> None:
    for directory in (DIST, ROOT / "build"):
        shutil.rmtree(directory, ignore_errors=True)
    for parent in (ROOT, ROOT / "src"):
        for egg in parent.glob("*.egg-info"):
            shutil.rmtree(egg, ignore_errors=True)
    for path in sorted(ROOT.glob("*.whl")) + sorted(ROOT.glob("*.tar.gz")):
        path.unlink()
        print(f"removed {path.name} from the root of the tree")


def build() -> tuple[Path, Path]:
    run = subprocess.run(  # noqa: S603 - a fixed argv, no shell
        [sys.executable, "-m", "build", "--outdir", str(DIST)],
        cwd=ROOT, capture_output=True, text=True,
    )
    if run.returncode != 0:
        # `build` is not in the dev extra, on the same argument every other
        # optional tool here is kept out of it: a packaging tool must not be
        # able to break an install of the package.
        raise PackagingError(
            "python -m build failed. Install it with `pip install build`.\n"
            + run.stdout + run.stderr
        )
    wheels = sorted(DIST.glob("*.whl"))
    sdists = sorted(DIST.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise PackagingError(
            f"expected one wheel and one sdist in dist/, found {wheels} and {sdists}"
        )
    return wheels[0], sdists[0]


def members(path: Path) -> list[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as handle:
            return handle.namelist()
    with tarfile.open(path) as handle:
        # The sdist's top-level directory is `seamark-<version>/`; strip it so
        # the rules below read the same for both artifacts.
        return [name.split("/", 1)[1] for name in handle.getnames() if "/" in name]


def check(path: Path, *, require_resources: bool) -> list[str]:
    names = members(path)
    problems = []

    for name in names:
        for fragment in FORBIDDEN_SUBSTRINGS:
            if fragment in name:
                problems.append(f"{path.name} contains {name} (matches {fragment!r})")
        for prefix in FORBIDDEN_PREFIXES:
            if name.startswith(prefix):
                problems.append(f"{path.name} contains {name} (under {prefix!r})")

    if require_resources:
        for needed in required():
            if needed not in names:
                problems.append(
                    f"{path.name} is missing {needed}, which the tool reads at run time"
                )

    return problems


def sha256sums(paths: list[Path]) -> Path:
    """Two builds of the same source, compared without trusting either."""
    target = DIST / "SHA256SUMS"
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
        for path in sorted(paths, key=lambda item: item.name)
    ]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return target


# What a clean install is asked to run, and the rule its data probe reads. Named
# here so `tests/test_package_contents.py` can hold them against the parser and
# the packs offline: the install needs a network, and a list only the install
# ever read still named `schema` and a scanner rule a phase after both left.
SMOKE = (["--version"], ["--help"], ["scan", "--demo"])
PROBE_RULE = "ACT-S001"


def install_and_run(wheel: Path) -> None:
    """The check no inspection of the archive can make: does it work.

    A wheel whose contents are right and whose entry point is wrong installs
    cleanly and then has no `seamark` command, and nothing above would notice.
    """
    with tempfile.TemporaryDirectory(prefix="seamark-wheel-") as scratch:
        env = Path(scratch) / "venv"
        subprocess.run(  # noqa: S603 - a fixed argv, no shell
            [sys.executable, "-m", "venv", str(env)], check=True, capture_output=True,
        )
        scripts = env / "Scripts" if (env / "Scripts").exists() else env / "bin"
        python = next(
            candidate for candidate in (scripts / "python.exe", scripts / "python")
            if candidate.exists()
        )
        subprocess.run(  # noqa: S603 - a fixed argv, no shell
            [str(python), "-m", "pip", "install", "--quiet", str(wheel)],
            check=True, capture_output=True,
        )
        for argv in SMOKE:
            run = subprocess.run(  # noqa: S603 - a fixed argv, no shell
                [str(python), "-m", "seamark", *argv],
                capture_output=True, text=True, timeout=180,
            )
            if run.returncode != 0:
                raise PackagingError(
                    f"`seamark {' '.join(argv)}` exited {run.returncode} from a clean install "
                    f"of {wheel.name}:\n{run.stdout}{run.stderr}"
                )
            print(f"  clean install: seamark {' '.join(argv)} -> exit 0")

        # The resources, read the way the tool reads them rather than listed.
        probe = (
            "from seamark.i18n.catalog import Catalog;"
            "from seamark import schemas;"
            "from seamark.surface import rules;"
            f"Catalog('es').rule('{PROBE_RULE}');"
            "assert schemas.names();"
            f"assert '{PROBE_RULE}' in {{rule.id for rule in rules.load()}};"
            "print('  clean install: catalogue, schemas and rule packs all load')"
        )
        run = subprocess.run(  # noqa: S603 - a fixed argv, no shell
            [str(python), "-c", probe], capture_output=True, text=True, timeout=180,
        )
        if run.returncode != 0:
            raise PackagingError(
                f"the installed wheel cannot read its own data:\n{run.stdout}{run.stderr}"
            )
        print(run.stdout.rstrip())


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and check the distribution artifacts")
    parser.add_argument(
        "--install", action="store_true",
        help="also install the wheel into a throwaway venv and run the CLI from it",
    )
    arguments = parser.parse_args()

    try:
        clean()
        wheel, sdist = build()
        print(f"built {wheel.relative_to(ROOT)}")
        print(f"built {sdist.relative_to(ROOT)}")

        problems = check(wheel, require_resources=True) + check(sdist, require_resources=False)
        if problems:
            raise PackagingError(
                "\n  ".join(["the distribution is not what it should be:", *problems])
            )
        print(f"  wheel: {len(members(wheel))} entries, every runtime resource present")
        print(f"  sdist: {len(members(sdist))} entries, no tests, evals, fuzz corpus or corpus builder")

        sums = sha256sums([wheel, sdist])
        print(f"wrote {sums.relative_to(ROOT)}")

        if arguments.install:
            install_and_run(wheel)
    except PackagingError as problem:
        print(f"\nFAIL  {problem}", file=sys.stderr)
        return 1
    print("\ndist/ holds the wheel, the sdist and their digests, and nothing else was written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
