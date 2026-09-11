"""The comparison harness, tested as carefully as the thing it compares.

Design note D-24, put under test. `evals/benchmark.py` makes public claims
about picklescan, modelscan and fickling: how much each one caught, how often
each one cried wolf, and whether any of them beat Actaira. Those numbers are
only worth printing if the machinery that produces them has been shown to
work, and in particular shown to be capable of producing an unflattering
answer. A "no other tool beats us" line is evidence only if the code that
computes it would say otherwise when it is false.

Four mechanisms are load-bearing and each is pinned below:

  * a format a tool never claimed to support is recorded as declined, never
    as a miss. Counting an ONNX file against picklescan would be a lie in the
    direction that flatters this project.
  * a tool that crashes is recorded as an error, not as a clean result. The
    difference is the whole value of the table: "said nothing" and "said this
    is fine" are opposite claims.
  * declines are reported as coverage, separately from detection.
  * `losses` is computed for real, so an artifact another tool catches and
    Actaira misses is named.

Every rival is guarded by `pytest.importorskip`, so this file stays green on a
machine that has none of them installed - the same rule the rest of the suite
follows for torch.
"""
from __future__ import annotations

import json
import pickle
import subprocess
from pathlib import Path

import pytest

from conftest import REPO_ROOT, _load_module_by_path, corpus_build

benchmark = _load_module_by_path("actaira_benchmark", REPO_ROOT / "evals" / "benchmark.py")

GADGET = corpus_build.craft_reduce("posix", "system", ("id",), 2)
BENIGN_PICKLE = pickle.dumps({"encoder.weight": [0.0, 1.0]}, protocol=2)
SAFETENSORS = corpus_build.build_safetensors(
    {"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}}, b"\x00" * 64
)
CUSTOM_ONNX = corpus_build.build_onnx("com.acme.kernels", "AcmeOp")


def write_corpus(directory: Path, entries: list[tuple[str, str, str, bytes]]) -> Path:
    """Write a corpus directory in the shape `benchmark.run` reads.

    `run` takes its entries from `cases.json`, so a test corpus has to carry
    one. Building it here rather than reusing `evals/artifacts` keeps these
    tests to a handful of artifacts chosen for the property under test, and
    keeps them from breaking every time a case is added to the real corpus.
    """
    directory.mkdir(parents=True, exist_ok=True)
    for name, _family, _label, payload in entries:
        (directory / name).write_bytes(payload)
    (directory / "cases.json").write_text(
        json.dumps([{"name": name, "family": family, "label": label} for name, family, label, _ in entries]),
        encoding="utf-8",
    )
    return directory


def _never_run(path: Path, fmt: str) -> benchmark.ToolResult:
    """Adapter for a Tool handed to `_score`, which must never invoke one."""
    raise AssertionError("the scoreboard must score recorded results, not re-run tools")


def tool(name: str, supported: set[str]) -> benchmark.Tool:
    return benchmark.Tool(name, "0.0-test", _never_run, supported)


def result(flagged: bool | None, **kwargs) -> benchmark.ToolResult:
    return benchmark.ToolResult(flagged=flagged, **kwargs)


# ---------------------------------------------------------------------------
# Declining an unsupported format
# ---------------------------------------------------------------------------

def test_an_artifact_outside_a_tools_declared_formats_is_declined_not_missed(tmp_path):
    """Fairness rule 3, end to end through `run`.

    A pickle scanner asked about an ONNX graph has no opinion, and recording
    that as `flagged=False` would put it in the table as a miss. The corpus
    here deliberately mixes three formats so that at least one row lands
    outside each rival's declared set, and every such row is checked: the
    result must be `None` and must say why.
    """
    supported = {entry.name: entry.supported for entry in benchmark.discover_tools()}
    if not [name for name in supported if not name.startswith("actaira")]:
        pytest.skip("no rival scanner installed; every tool present reads every format")

    corpus = write_corpus(
        tmp_path / "corpus",
        [
            ("gadget.pkl", "classic", "malicious", GADGET),
            ("weights.safetensors", "structural", "malicious", SAFETENSORS),
            ("graph.onnx", "onnx", "malicious", CUSTOM_ONNX),
        ],
    )

    summary = benchmark.run(corpus, [])

    declined = 0
    for row in summary["rows"]:
        for name, recorded in row["results"].items():
            if row["detected_format"] in supported[name]:
                continue
            declined += 1
            assert recorded["flagged"] is None, (
                f"{name} was scored on {row['name']} ({row['detected_format']}), "
                "a format it does not claim to read"
            )
            assert recorded["detail"] == "format not supported"
    assert declined, "this corpus must contain a row outside some tool's declared formats"


@pytest.mark.parametrize(
    "adapter_name, module_name",
    [("_picklescan", "picklescan"), ("_modelscan", "modelscan")],
)
def test_the_declaration_of_supported_formats_is_what_produces_the_decline(tmp_path, adapter_name, module_name):
    """Negative control for the test above: the decline is not free.

    Called directly, on a format outside its scope, neither rival declines.
    Both answer, and today both answer `False` - which the table would read as
    "did not detect this malicious file". The `supported` set on each Tool is
    the only thing standing between that answer and a fabricated miss, so
    deleting it would silently change the published numbers rather than break
    anything. This test exists so that it breaks something.
    """
    pytest.importorskip(module_name, reason="rival tools are optional")
    path = tmp_path / "weights.safetensors"
    path.write_bytes(SAFETENSORS)

    answered = getattr(benchmark, adapter_name)(path, "safetensors")

    assert answered.flagged is not None, (
        f"{module_name} declines this format by itself; if that ever becomes true the "
        "premise of the format gate should be revisited, not the gate removed"
    )
    assert "safetensors" not in {entry.name: entry.supported for entry in benchmark.discover_tools()}[module_name]


# ---------------------------------------------------------------------------
# A tool that fails must not read as a tool that approved
# ---------------------------------------------------------------------------

class _ExplodingModelScan:
    def scan(self, _path: str) -> dict:
        raise RuntimeError("scanner exploded")


def _break_picklescan(monkeypatch):
    scanner = pytest.importorskip("picklescan.scanner", reason="rival tools are optional")

    def boom(_path):
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr(scanner, "scan_file_path", boom)
    return benchmark._picklescan


def _break_modelscan(monkeypatch):
    modelscan_module = pytest.importorskip("modelscan.modelscan", reason="rival tools are optional")
    monkeypatch.setattr(modelscan_module, "ModelScan", _ExplodingModelScan)
    return benchmark._modelscan


@pytest.mark.parametrize("install_failure", [_break_picklescan, _break_modelscan], ids=["picklescan", "modelscan"])
def test_an_adapter_whose_tool_raises_records_an_error_not_a_clean_result(tmp_path, monkeypatch, install_failure):
    """A crash is not a verdict.

    If an adapter let an exception become `flagged=False`, a rival that failed
    to install its own parser would appear in the table as a scanner that
    looked at every artifact and approved all of them - the single most
    flattering-to-us failure mode this harness has. The adapter has to convert
    the exception into a decline that carries the exception's type and text,
    so the run is auditable afterwards.

    Note the asymmetry this does not cover: `_picklescan` and `_modelscan`
    catch `Exception`, while `_fickling` catches only `TimeoutExpired`, and
    `run` itself wraps no adapter call at all. Anything a subprocess launch
    raises therefore aborts the whole benchmark rather than being recorded.
    A crashed run is loud, so that is a lesser problem than a silent one, but
    it is not the same contract for all three adapters.
    """
    adapter = install_failure(monkeypatch)
    path = tmp_path / "gadget.pkl"
    path.write_bytes(GADGET)

    recorded = adapter(path, "pickle")

    assert recorded.flagged is None, "a crashed tool has no opinion and must not be scored as one"
    assert recorded.error == "RuntimeError: scanner exploded"
    assert recorded.seconds >= 0.0


# ---------------------------------------------------------------------------
# A detection is read before an error
#
# `scan_err` was tested first, so a picklescan run that both found something
# and hit a member it could not open was recorded as "declined". A decline
# drops the artifact out of the detection denominator, so every one of these
# moved the comparison in this project's favour - the one direction fairness
# rule 2 forbids a vendor-written benchmark from being wrong in.
# ---------------------------------------------------------------------------

class _PicklescanResult:
    """The shape `scan_file_path` returns, with only the fields read here."""

    def __init__(self, *, issues_count: int, infected_files: int, scan_err: bool) -> None:
        self.issues_count = issues_count
        self.infected_files = infected_files
        self.scan_err = scan_err
        self.globals = [_Global("posix", "system")] if issues_count else []


class _Global:
    def __init__(self, module: str, name: str) -> None:
        self.module, self.name, self.safety = module, name, "Dangerous"


@pytest.mark.parametrize(
    "issues, infected, scan_err, expected_flagged, expected_error",
    [
        (1, 1, True, True, None),    # found something AND hit an unreadable member
        (1, 0, True, True, None),    # an issue with no infected file, still a detection
        (0, 1, True, True, None),    # an infected file with no issue row
        (0, 0, True, None, "scan_err"),  # nothing found and it could not read: a decline
        (1, 1, False, True, None),   # the ordinary detection
        (0, 0, False, False, None),  # the ordinary clean answer
    ],
    ids=["found-and-errored", "issue-only", "infected-only", "errored-only", "found", "clean"],
)
def test_a_real_detection_counts_even_when_the_scan_also_reported_an_error(
    tmp_path, monkeypatch, issues, infected, scan_err, expected_flagged, expected_error
):
    scanner = pytest.importorskip("picklescan.scanner", reason="rival tools are optional")
    monkeypatch.setattr(
        scanner, "scan_file_path",
        lambda _path: _PicklescanResult(issues_count=issues, infected_files=infected, scan_err=scan_err),
    )
    path = tmp_path / "gadget.pkl"
    path.write_bytes(GADGET)

    recorded = benchmark._picklescan(path, "pickle")

    assert recorded.flagged is expected_flagged
    assert recorded.error == expected_error


def test_a_declined_picklescan_result_still_leaves_the_artifact_out_of_the_denominator(tmp_path, monkeypatch):
    """The other half: the decline path is not being removed, only made to
    stop swallowing detections."""
    scanner = pytest.importorskip("picklescan.scanner", reason="rival tools are optional")
    monkeypatch.setattr(
        scanner, "scan_file_path",
        lambda _path: _PicklescanResult(issues_count=0, infected_files=0, scan_err=True),
    )
    path = tmp_path / "gadget.pkl"
    path.write_bytes(GADGET)

    assert benchmark._picklescan(path, "pickle").flagged is None


@pytest.mark.parametrize(
    "returncode, expected_flagged, expected_error",
    [(0, False, None), (1, True, None), (2, None, "exit 2")],
    ids=["considered-safe", "considered-unsafe", "could-not-parse"],
)
def test_fickling_exit_codes_separate_unsafe_from_unreadable(
    tmp_path, monkeypatch, returncode, expected_flagged, expected_error
):
    """fickling is run as a subprocess, so its verdict is an exit status.

    Exit 1 means "unsafe" and exit 0 means "not unsafe", but anything above 1
    means fickling could not parse the file at all - which is what it returns
    for a torch zip container, four of which are in the published corpus.
    Collapsing `> 1` into `!= 1` would score those four as misses against a
    tool that never claimed to read them, and would make Actaira's margin over
    fickling look four artifacts wider than it is.
    """
    pytest.importorskip("fickling", reason="rival tools are optional")
    path = tmp_path / "gadget.pkl"
    path.write_bytes(GADGET)

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(args=["fickling"], returncode=returncode, stdout="", stderr="")

    monkeypatch.setattr(benchmark.subprocess, "run", fake_run)

    recorded = benchmark._fickling(path, "pickle")

    assert recorded.flagged is expected_flagged
    assert recorded.error == expected_error


def test_a_fickling_run_that_times_out_is_declined_rather_than_cleared(tmp_path, monkeypatch):
    """The timeout path, which is the failure a subprocess adapter actually
    meets: a pickle crafted to make the analysis spin. Sixty seconds of
    nothing is not evidence that the file is safe."""
    pytest.importorskip("fickling", reason="rival tools are optional")
    path = tmp_path / "gadget.pkl"
    path.write_bytes(GADGET)

    def fake_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["fickling"], timeout=60)

    monkeypatch.setattr(benchmark.subprocess, "run", fake_run)

    recorded = benchmark._fickling(path, "pickle")

    assert recorded.flagged is None
    assert recorded.error == "timeout"


# ---------------------------------------------------------------------------
# Discovery: a tool that is not installed must be absent, not silent
# ---------------------------------------------------------------------------

def test_a_rival_that_is_not_installed_is_left_out_of_the_table(monkeypatch):
    """An absent tool must produce no column, not a column of clean rows.

    `discover_tools` appends a rival only when its module imports. With that
    check forced to fail, only the two Actaira configurations remain. The
    alternative - listing a tool that was never run - would fill its row with
    `flagged=False` and print a scanner that missed everything.
    """
    monkeypatch.setattr(benchmark, "_importable", lambda module: False)

    assert [entry.name for entry in benchmark.discover_tools()] == ["actaira (strict)", "actaira (known-bad)"]


@pytest.mark.parametrize("module_name", ["picklescan", "modelscan", "fickling"])
def test_an_installed_rival_is_discovered_with_the_version_it_will_be_credited_with(module_name):
    """The table prints a version next to every tool, and a comparison against
    an unnamed version is not reproducible. `_version` falls back to "?" when
    the distribution cannot be found, which is exactly the case a reader
    cannot check, so it must not survive into a published row."""
    pytest.importorskip(module_name, reason="rival tools are optional")

    discovered = {entry.name: entry.version for entry in benchmark.discover_tools()}

    assert module_name in discovered
    assert discovered[module_name] != "?"
    assert discovered[module_name][0].isdigit()


# ---------------------------------------------------------------------------
# The scoreboard
# ---------------------------------------------------------------------------

ACTAIRA = "actaira (strict)"


def _rows_with_one_decline() -> list[benchmark.Row]:
    """Two malicious artifacts: one the rival reads and catches, one it declines."""
    return [
        benchmark.Row(
            "gadget.pkl", "classic", "malicious", "pickle",
            {ACTAIRA: result(True), "rival": result(True)},
        ),
        benchmark.Row(
            "weights.safetensors", "structural", "malicious", "safetensors",
            {ACTAIRA: result(True), "rival": result(None, detail="format not supported")},
        ),
    ]


def test_the_scoreboard_reports_a_decline_as_coverage_and_not_as_a_detection():
    """Declines are counted, and they are never counted as catches.

    The half of fairness rule 3 that the code does implement: breadth is
    visible as its own column, so a tool that reads one format out of six
    cannot look equal to one that reads all six.
    """
    board = benchmark._score(_rows_with_one_decline(), [tool(ACTAIRA, benchmark.ACTAIRA_FORMATS), tool("rival", benchmark.PICKLE_FORMATS)])
    rival = board["whole_corpus"]["rival"]

    assert rival["declined"] == 1
    assert rival["malicious_caught"] == 1, "a declined artifact is not a catch either"
    assert board["whole_corpus"][ACTAIRA]["declined"] == 0
    assert board["whole_corpus"][ACTAIRA]["malicious_caught"] == 2


def test_a_declined_artifact_is_not_in_the_detection_denominator():
    """Fairness rule 3: a tool is scored only on the formats it claims.

    The rival below reads one of the two malicious artifacts and catches it.
    Its detection score is therefore 1/1, not 1/2: the artifact it declined
    belongs in the coverage column, which the test above pins, and nowhere
    else. Scoring it as a miss penalises a tool for the honest answer and
    inflates the margin the benchmark reports in this project's favour.

    This is the test that found the defect it now guards. `_score` used to
    build `malicious_total` from every malicious row in the subset, declined
    ones included, which contradicted the module docstring's own fairness rule
    3 and flattered Actaira on every published row: fickling appeared as 32/36
    head to head when 4 of those 36 were torch zip containers it had returned
    "could not parse" for, so its real score on what it reads was 32/32.
    `evals/benchmark.py:263` now drops the declined rows before counting, and
    `malicious_in_scope` keeps the wider figure visible next to it.
    """
    board = benchmark._score(_rows_with_one_decline(), [tool(ACTAIRA, benchmark.ACTAIRA_FORMATS), tool("rival", benchmark.PICKLE_FORMATS)])

    assert board["whole_corpus"]["rival"]["malicious_total"] == 1
    assert board["whole_corpus"]["rival"]["malicious_in_scope"] == 2, (
        "the artifact the rival declined is still visible, it is just not in the denominator"
    )


def test_losses_names_the_artifact_a_rival_catches_and_actaira_does_not(tmp_path, monkeypatch):
    """The claim "no other tool beats us", made falsifiable.

    A fake tool is inserted that flags everything, and the corpus is built so
    that the three interesting cases are all present at once:

      * `quiet.pkl` - labelled malicious, and Actaira passes it. This is a
        loss and must be named.
      * `loud.pkl` - malicious and caught by both. Not a loss: a tool merely
        agreeing with Actaira must not appear.
      * `clean.pkl` - flagged by the fake tool but labelled benign. Not a
        loss either: that is the fake tool's false alarm, and folding false
        alarms into the loss list would make the column meaningless in the
        opposite direction.

    Without this test, an empty `losses` list would be indistinguishable from
    a `losses` list that is always empty.
    """
    corpus = write_corpus(
        tmp_path / "corpus",
        [
            ("quiet.pkl", "gadget-unknown", "malicious", BENIGN_PICKLE),
            ("loud.pkl", "classic", "malicious", GADGET),
            ("clean.pkl", "benign", "benign", BENIGN_PICKLE),
        ],
    )

    def flags_everything(path: Path, fmt: str) -> benchmark.ToolResult:
        return benchmark.ToolResult(flagged=True, detail="oracle")

    monkeypatch.setattr(
        benchmark,
        "discover_tools",
        lambda: [
            benchmark.Tool(ACTAIRA, "0.0-test", benchmark._actaira("strict"), benchmark.ACTAIRA_FORMATS),
            benchmark.Tool("oracle", "0.0-test", flags_everything, benchmark.PICKLE_FORMATS),
        ],
    )

    summary = benchmark.run(corpus, [])
    recorded = {row["name"]: row["results"] for row in summary["rows"]}

    # The premise, asserted rather than assumed: the three rows really do have
    # the shapes the loss list is being tested against.
    assert recorded["quiet.pkl"][ACTAIRA]["flagged"] is False
    assert recorded["loud.pkl"][ACTAIRA]["flagged"] is True
    assert recorded["clean.pkl"]["oracle"]["flagged"] is True

    assert summary["scoreboard"]["losses"] == {"oracle": ["quiet.pkl"]}


def test_losses_is_empty_only_when_no_rival_actually_wins(tmp_path, monkeypatch):
    """Negative control for the test above, and the one the README leans on.

    Same corpus, same pipeline, a rival that catches nothing Actaira misses.
    The list has to come back empty - and the key has to be present, because
    `render` prints "none" for a tool it can see and prints nothing at all for
    a tool it cannot.
    """
    corpus = write_corpus(
        tmp_path / "corpus",
        [
            ("quiet.pkl", "gadget-unknown", "malicious", BENIGN_PICKLE),
            ("loud.pkl", "classic", "malicious", GADGET),
        ],
    )

    def flags_nothing(path: Path, fmt: str) -> benchmark.ToolResult:
        return benchmark.ToolResult(flagged=False, detail="")

    monkeypatch.setattr(
        benchmark,
        "discover_tools",
        lambda: [
            benchmark.Tool(ACTAIRA, "0.0-test", benchmark._actaira("strict"), benchmark.ACTAIRA_FORMATS),
            benchmark.Tool("timid", "0.0-test", flags_nothing, benchmark.PICKLE_FORMATS),
        ],
    )

    summary = benchmark.run(corpus, [])

    assert summary["scoreboard"]["losses"] == {"timid": []}
    assert "timid" in summary["scoreboard"]["by_family"]["gadget-unknown"]


def test_the_rendered_report_names_the_losses_it_found(tmp_path, monkeypatch):
    """The number has to reach the page a reader sees.

    `render` is what produces the text pasted into the README, so a loss that
    is computed correctly and then dropped on the way to the table would be
    invisible in exactly the place it matters. The rendered output must carry
    the artifact's name under the losses heading.
    """
    corpus = write_corpus(
        tmp_path / "corpus", [("quiet.pkl", "gadget-unknown", "malicious", BENIGN_PICKLE)]
    )

    monkeypatch.setattr(
        benchmark,
        "discover_tools",
        lambda: [
            benchmark.Tool(ACTAIRA, "0.0-test", benchmark._actaira("strict"), benchmark.ACTAIRA_FORMATS),
            benchmark.Tool("oracle", "0.0-test", lambda path, fmt: benchmark.ToolResult(flagged=True), benchmark.PICKLE_FORMATS),
        ],
    )

    text = benchmark.render(benchmark.run(corpus, []))

    heading = "artifacts another tool catches that actaira (strict) does not:"
    assert heading in text
    tail = text.split(heading, 1)[1]
    assert "quiet.pkl" in tail.splitlines()[1]
