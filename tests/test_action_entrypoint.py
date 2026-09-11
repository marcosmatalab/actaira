"""The composite action's entrypoint, which nothing tested.

`.github/actions/actaira-scan/entrypoint.sh` is an integration definition
shipped in this tree, not a service running anywhere - but it is a shell
script that takes attacker-influenced strings and writes them into
`GITHUB_OUTPUT`, and `SECURITY.md` puts exactly that in the threat model. It
had no test of any kind.

Two properties matter and one is a vulnerability class:

  * **Output injection.** `GITHUB_OUTPUT` is a `key=value` file, one line per
    output. A newline inside a value writes a line the script never emitted,
    so an input carrying `x` + newline + `should-fail=false` sets the output
    the action's own "fail the job" step reads. Only `path` was flattened;
    `sarif-file` reached the writer untouched, on both the normal path and the
    early exit.

  * **Exit codes.** The script always exits 0 on purpose - the verdict travels
    in the outputs so the SARIF upload is not skipped - and every code the CLI
    can return has to arrive as the right `verdict` and the right
    `should-fail`. A `usage` that reported `should-fail=false` would be a scan
    that never ran, reported as a job that passed.

The script is bash and the CLI it calls is on `PATH`, so these run it for real
with `actaira` shimmed to a script that exits with the code under test. Where
bash is not available the module is skipped, naming that rather than passing.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import REPO_ROOT

ENTRYPOINT = Path(REPO_ROOT) / ".github" / "actions" / "actaira-scan" / "entrypoint.sh"

BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(
    BASH is None, reason="the action entrypoint is a bash script and this host has no bash"
)


def run(tmp_path, *, inputs: dict[str, str], cli_exit: int = 0, cli_stdout: str = "",
        sarif_bytes: bytes | None = b"{}") -> tuple[dict[str, str], str, int]:
    """Run the entrypoint with a shimmed `actaira` and read back its outputs."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir(parents=True, exist_ok=True)

    # The shim writes the SARIF file the real CLI would write, prints what the
    # real CLI would print, and exits with the code under test.
    #
    # `cli_stdout` goes through a file rather than through a quoted `printf`
    # argument, so a newline in it is a real newline in the log. Embedding it
    # in the script made it the two characters backslash-n, which meant the
    # injection test was asserting against a log that had no newline in it -
    # a test that passes because it never reproduces the case.
    sarif_target = inputs.get("ACTAIRA_SARIF_FILE", "actaira.sarif")
    stdout_file = tmp_path / "cli-stdout.txt"
    stdout_file.write_text(cli_stdout + "\n", encoding="utf-8", newline="\n")
    body = ["#!/usr/bin/env bash", f"cat {str(stdout_file)!r}"]
    if sarif_bytes is not None:
        body.append(f'printf "%s" {sarif_bytes.decode()!r} > {sarif_target!r}')
    body.append(f"exit {cli_exit}")
    shim = shim_dir / "actaira"
    shim.write_text("\n".join(body) + "\n", encoding="utf-8", newline="\n")
    shim.chmod(0o755)

    outputs = tmp_path / "github_output"
    outputs.write_text("", encoding="utf-8", newline="\n")

    environment = {
        "PATH": os.pathsep.join([str(shim_dir), os.environ.get("PATH", "")]),
        "GITHUB_OUTPUT": str(outputs),
        **inputs,
    }
    completed = subprocess.run(  # noqa: S603 - a fixed argv, no shell
        [BASH, str(ENTRYPOINT)], cwd=workspace, env=environment,
        capture_output=True, text=True, timeout=120,
    )
    parsed: dict[str, str] = {}
    for line in outputs.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            parsed[key] = value
    return parsed, completed.stdout + completed.stderr, completed.returncode


@pytest.fixture
def scannable(tmp_path):
    """A path the script will accept, prepared in every workspace a test may use.

    A test that needs two isolated runs uses `tmp_path / "a"` and
    `tmp_path / "b"`, because one run's SARIF report left in the other's
    directory would make the second look like it wrote one.
    """
    for root in (tmp_path, tmp_path / "a", tmp_path / "b"):
        workspace = root / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "models").mkdir(exist_ok=True)
        (workspace / "models" / "clean.bin").write_bytes(b"\x00" * 16)
    return "models"


# ---------------------------------------------------------------------------
# Output injection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("variable", ["ACTAIRA_PATH", "ACTAIRA_SARIF_FILE"])
def test_a_newline_in_an_input_cannot_write_an_output_the_script_never_emitted(tmp_path, variable):
    """The vulnerability. `sarif-file` was the one that reached the writer
    unflattened, and `should-fail` is the output worth forging: the action's
    last step reads it to decide whether the job fails."""
    hostile = "models\nshould-fail=false\nverdict=pass"
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    (workspace / "models").mkdir()

    inputs = {"ACTAIRA_PATH": "models", "ACTAIRA_SARIF_FILE": "actaira.sarif"}
    inputs[variable] = hostile

    outputs, _log, code = run(tmp_path, inputs=inputs, cli_exit=1)

    assert code == 0, "the script always exits 0; the verdict travels in the outputs"
    # Whatever the run decided, it decided it once. The forged pair must not be
    # what a consumer reads.
    assert outputs["should-fail"] == "true", (
        "an input newline set should-fail=false: the job would have passed on a "
        "scan that failed"
    )
    for key, value in outputs.items():
        assert "\n" not in value and "\r" not in value, f"{key} still carries a newline"


def test_a_newline_in_a_scanned_file_name_cannot_forge_an_output(tmp_path, scannable):
    """The log is attacker-controlled: it contains the names of the files being
    scanned, and this tool's whole premise is that those files are hostile."""
    outputs, _log, _code = run(
        tmp_path,
        inputs={"ACTAIRA_PATH": scannable},
        cli_exit=0,
        cli_stdout="1 artifact(s): 1 passed\nshould-fail=false\nexit-code=99",
    )

    assert outputs["should-fail"] == "false", "this run genuinely passed"
    assert outputs["exit-code"] == "0", "the forged exit code did not become the real one"
    # Read back the way a consumer reads it. Two lines for one key would mean
    # the log wrote its own; the parser keeps the last, which is the forged one.
    assert "should-fail=false" not in outputs["summary"]
    assert "\n" not in outputs["summary"]


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("cli_exit", "verdict", "should_fail"),
    [(0, "pass", "false"), (1, "fail", "true"), (2, "usage", "true"), (3, "inconclusive", "true")],
)
def test_every_cli_exit_code_reaches_the_outputs_as_itself(tmp_path, scannable, cli_exit, verdict, should_fail):
    """Exit code 3 is the one that matters: an artifact that could not be read
    is not a passing job, and the doctrine of the whole repository is that it
    never becomes one by default."""
    outputs, _log, code = run(tmp_path, inputs={"ACTAIRA_PATH": scannable}, cli_exit=cli_exit)

    assert code == 0
    assert outputs["exit-code"] == str(cli_exit)
    assert outputs["verdict"] == verdict
    assert outputs["should-fail"] == should_fail


def test_a_path_that_is_not_there_is_a_usage_failure_and_not_a_pass(tmp_path):
    """A scan pointed at a path that does not exist has proved nothing about
    the repository, so it must not report success."""
    outputs, log, code = run(tmp_path, inputs={"ACTAIRA_PATH": "no/such/place"})

    assert code == 0
    assert outputs["exit-code"] == "2"
    assert outputs["verdict"] == "usage"
    assert outputs["should-fail"] == "true"
    assert outputs["sarif-written"] == "false"
    assert "nothing to scan" in log


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("ACTAIRA_POLICY", "permissive"),
        ("ACTAIRA_FAIL_ON", "catastrophic"),
        ("ACTAIRA_ALLOW_INCONCLUSIVE", "yes"),
        # Not an empty string: bash's ${VAR:-default} already turns that into
        # the default. A value that is *only* a newline is the reachable case -
        # non-empty going in, empty after the flattening that stops output
        # injection - and `--out ""` would then report sarif-written=false for
        # a run that did produce findings.
        ("ACTAIRA_SARIF_FILE", "\n"),
    ],
)
def test_an_input_outside_its_closed_set_fails_the_job_rather_than_scanning_anyway(
    tmp_path, scannable, variable, value
):
    """A typo in a workflow must not silently scan under a different policy
    than the one that was asked for, and must not come back green."""
    inputs = {"ACTAIRA_PATH": scannable, variable: value}

    outputs, log, code = run(tmp_path, inputs=inputs)

    assert code == 0
    assert outputs["verdict"] == "usage", f"{variable}={value!r} was accepted"
    assert outputs["should-fail"] == "true"
    assert "::error" in log


def test_a_path_with_spaces_is_scanned_rather_than_word_split(tmp_path):
    """The argv is an array for this reason, and it is worth an assertion: a
    repository with `my models/` in it is ordinary, and the failure would be
    silent - a scan of a path that does not exist, reported as usage."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    (workspace / "my models").mkdir()

    outputs, _log, _code = run(
        tmp_path, inputs={"ACTAIRA_PATH": "my models"}, cli_exit=0,
        cli_stdout="1 artifact(s): 1 passed",
    )

    assert outputs["verdict"] == "pass"
    assert outputs["exit-code"] == "0"


def test_the_sarif_flag_reports_what_was_written_and_not_what_was_asked_for(tmp_path, scannable):
    """`sarif-written` gates the upload step. A run whose CLI produced no
    report must say so, or the upload step fails on a file that is not there."""
    written, _log, _code = run(tmp_path / "a", inputs={"ACTAIRA_PATH": scannable}, cli_exit=1)
    missing, _log2, _code2 = run(
        tmp_path / "b", inputs={"ACTAIRA_PATH": scannable}, cli_exit=1, sarif_bytes=None
    )

    assert written["sarif-written"] == "true"
    assert missing["sarif-written"] == "false"
    assert missing["sarif-file"] == "actaira.sarif", "the path is still reported"
