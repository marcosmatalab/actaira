#!/usr/bin/env python3
"""Build the keyv repository in a temporary directory and diff it. One command.

    python3 scripts/demo_keyv.py

Two commits in a throwaway git repository: a clean one, and the same tree with
the 4 August 2026 keyv wave's configuration reconstructed on top of it. Then
`actaira diff` between them, which is the block both READMEs print.

WHY A SCRIPT AND NOT A FIXTURE. The `diff` half of this product needs two
MOMENTS, and a moment is a commit. A fixture directory has one. This is the
smallest thing that makes the second one exist, and it makes it somewhere that
is not the reader's repository - `tempfile.mkdtemp`, removed on the way out.

WHAT IS IN THE SECOND COMMIT, precisely. It is
`tests/fixtures/surface/keyv-august/`, copied. That directory is a
RECONSTRUCTION from the sentences Snyk, Aikido and Wiz published about the wave,
its provenance file says which sentence each fragment comes from and what it does
NOT claim, and both `setup.mjs` files in it are comments only - an inert stub.
A security repository that shipped the worm's payload in order to demonstrate
catching the worm would be the worm. `tests/test_surface_rules.py` asserts the
stubs are inert, so this script cannot quietly start distributing something else.

Nothing here is executed. `git` is asked to make two commits and Actaira is
asked to read two trees; the `setup.mjs` the hook points at is hashed and never
run, which is what `check` and `diff` both promise and what this demo is about.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess  # noqa: S404 - git, argv as a list, in a directory this script made
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "surface" / "keyv-august"

# The commit this demo is built on. A fixed identity and a fixed date, so two
# runs on two machines produce the same two commits - which is the property
# `tests/test_readme_parity.py` needs in order to compare this output with the
# block on a page, and the property a demo of a change-detection tool should
# have anyway.
WHEN = "2026-08-04T00:00:00+00:00"
ENVIRONMENT = {
    "GIT_AUTHOR_NAME": "actaira demo",
    "GIT_AUTHOR_EMAIL": "demo@actaira.invalid",
    "GIT_COMMITTER_NAME": "actaira demo",
    "GIT_COMMITTER_EMAIL": "demo@actaira.invalid",
    "GIT_AUTHOR_DATE": WHEN,
    "GIT_COMMITTER_DATE": WHEN,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
}


def git(where: Path, *arguments: str) -> None:
    # S603/S607: a fixed argv, a list, never a shell, and `git` from PATH - the
    # same way `surface/diff.py` runs it, in a directory this script made.
    subprocess.run(  # noqa: S603
        ["git", "-C", str(where), *arguments],  # noqa: S607
        check=True,
        capture_output=True,
        env={**os.environ, **ENVIRONMENT},
    )


def build(where: Path) -> None:
    """A clean commit, then the reconstructed wave on top of it."""
    where.mkdir(parents=True, exist_ok=True)
    git(where, "init", "-q", "-b", "main")
    (where / "README.md").write_text("# a repository\n", encoding="utf-8")
    (where / "package.json").write_text('{\n  "name": "a-repository"\n}\n', encoding="utf-8")
    git(where, "add", "-A")
    git(where, "commit", "-q", "-m", "a repository before anything happened to it")

    for source in sorted(FIXTURE.rglob("*")):
        if source.is_dir():
            continue
        target = where / source.relative_to(FIXTURE)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Copied through a newline normalisation rather than byte for byte, and
        # this is not tidiness. A capability's digest covers the sha256 of the
        # script a hook names, so a checkout whose files arrived with CRLF - which
        # is every default `git clone` on Windows - would make this demo print a
        # different digest from the same demo on Linux. The two READMEs show that
        # digest, `tests/test_readme_parity.py` compares the page against the
        # command, and the gate runs in WSL: without this, the block would be
        # right on one platform and wrong on the other with nothing to say why.
        target.write_bytes(source.read_bytes().replace(b"\r\n", b"\n"))
    git(where, "add", "-A")
    git(where, "commit", "-q", "-m", "the keyv wave, reconstructed from the published reports")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--keep", action="store_true",
                        help="leave the repository on disk and print where it is")
    parser.add_argument("--lang", choices=("en", "es"), default="en")
    arguments = parser.parse_args(argv)

    sys.path.insert(0, str(ROOT / "src"))
    from actaira import cli

    where = Path(tempfile.mkdtemp(prefix="actaira-demo-"))
    try:
        build(where)
        # Through `cli.main`, so what this prints is what the command prints -
        # not a second rendering that could drift from it.
        code = cli.main([
            "--lang", arguments.lang, "diff", "--repo", str(where), "--", "HEAD~1", "HEAD",
        ])
    finally:
        if arguments.keep:
            print(f"\nthe repository is at {where}", file=sys.stderr)
        else:
            shutil.rmtree(where, ignore_errors=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
