"""A fixture that only exists on the machine that wrote it is not a fixture.

This file exists because of one incident, and it is worth stating plainly: phase
S1's fixtures for the two 2026 npm worms carry a `.vscode/tasks.json`, because
that file is HALF OF THE ATTACK and the whole point of the report's "not read in
this release" list is that the half `check` cannot see is named rather than
omitted. `.gitignore` excluded `.vscode/` everywhere, `git add -A` skipped both
files without a word, and the suite went green on the machine that had them and
red on the first clean clone - which is CI.

Nothing in the suite could have caught that, because every test in it reads the
WORKING DIRECTORY, and the working directory is not what anybody else gets. So
the invariant is asserted here directly: everything under `tests/fixtures/` is in
git's index. A test that reads a file git will not hand to anybody else is a test
about this laptop.

Two independent readings, on purpose:

* the index itself, parsed by `surface.claude_code.git_tracked` - the same reader
  `check` uses to answer whether a hook's script is tracked, so this dogfoods it;
* `git check-ignore`, which is the authority on WHY a file is missing, used to
  make the failure message name the pattern rather than leave somebody grepping.

The first is the assertion. The second only enriches it, so the suite does not
depend on a subprocess to hold the line.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from actaira.surface.claude_code import git_tracked
from conftest import REPO_ROOT

FIXTURES = Path(REPO_ROOT) / "tests" / "fixtures"


def fixture_files() -> list[Path]:
    return sorted(
        path
        for path in FIXTURES.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    )


TRACKED, INDEX_PROBLEM = git_tracked(Path(REPO_ROOT))


def why_ignored(path: Path) -> str:
    """The `.gitignore` line that excludes this path, for the failure message."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "check-ignore", "-v", "--", str(path)],  # noqa: S607 - the developer's PATH
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - no git on PATH
        return "git check-ignore could not be run"
    return result.stdout.strip() or "not ignored; it was simply never added"


@pytest.mark.skipif(
    INDEX_PROBLEM is not None, reason=f"not a git working tree: {INDEX_PROBLEM}"
)
def test_the_walk_finds_the_fixtures_it_is_supposed_to_guard():
    """The non-vacuity guard. An empty walk would make the rule below pass over
    nothing, which is the failure mode this repository keeps meeting."""
    found = fixture_files()

    assert len(found) > 20, f"only {len(found)} fixture files found; the walk is not walking"
    assert TRACKED, "the git index parsed to an empty set; the reading is wrong"
    names = {path.name for path in found}
    assert "tasks.json" in names, (
        "the walk does not see `.vscode/tasks.json`, which is the file whose absence "
        "this whole test exists about"
    )


@pytest.mark.skipif(
    INDEX_PROBLEM is not None, reason=f"not a git working tree: {INDEX_PROBLEM}"
)
@pytest.mark.parametrize(
    "relative",
    [path.relative_to(REPO_ROOT).as_posix() for path in fixture_files()],
)
def test_every_fixture_file_is_in_the_index(relative):
    """The rule. One case per file, so the failure names the file."""
    assert relative in TRACKED, (
        f"{relative} is on this disk and not in git's index, so a clone does not have it "
        f"and every test that reads it is a test about this machine.\n"
        f"  {why_ignored(Path(REPO_ROOT) / relative)}\n"
        "Add it. If a `.gitignore` pattern excludes it, un-ignore the directory AND its "
        "contents, in that order: git will not re-include a file whose parent directory "
        "is excluded."
    )


@pytest.mark.skipif(
    INDEX_PROBLEM is not None, reason=f"not a git working tree: {INDEX_PROBLEM}"
)
def test_the_rule_bites_on_a_planted_ignored_file(tmp_path):
    """The guard on the guard, planted the way the real defect arrived.

    A file under `tests/fixtures/` that `.gitignore` excludes. Both halves are
    asserted: that the walk SEES it, and that the index does NOT have it - which
    is exactly the pair of facts that was true of `.vscode/tasks.json` and that
    nothing in the suite was asking about.

    Planted under a name `.gitignore` already excludes, rather than by editing
    `.gitignore` from a test. Editing the ignore file mid-suite would leave the
    developer's tree changed if the test failed halfway, and a test that can do
    that is a worse problem than the one it checks for.
    """
    planted = FIXTURES / "surface" / ".vscode-planted" / "ignored.swp"
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_text("planted by the suite\n", encoding="utf-8")
    try:
        assert planted.is_file()
        assert planted in fixture_files(), "the walk does not reach the planted file"

        relative = planted.relative_to(REPO_ROOT).as_posix()
        assert relative not in TRACKED, "the plant is tracked; it cannot demonstrate anything"

        # And the message a reader would get names the pattern rather than
        # leaving them to grep for it.
        assert ".gitignore" in why_ignored(planted), (
            "the plant is untracked for some reason other than being ignored, so this "
            "does not exercise the case the real defect was"
        )
    finally:
        planted.unlink()
        planted.parent.rmdir()
