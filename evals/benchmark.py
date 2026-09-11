"""Compare Actaira with the other scanners in this space, on the same corpus.

Design note D-24. A tool that only reports its own numbers is asking to be
taken on faith. This harness runs Actaira, picklescan, Protect AI's modelscan
and Trail of Bits' fickling over identical artifacts and prints what each one
said.

Fairness rules, because a rigged benchmark is worth less than none:

  1. Same artifacts, same order, same machine, same run.
  2. The question asked of every tool is the one a user actually asks: does
     this tool tell me the artifact is dangerous, yes or no? Not "did it fire
     my rule", which only Actaira has.
  3. A tool is only scored on formats it claims to support. Coverage is
     reported separately, as a count of artifacts each tool declined or could
     not read, so breadth is visible without being smuggled into accuracy.
  4. Every tool runs with its default configuration. Actaira's default is
     `--policy strict`; its denylist mode is reported as a separate column so
     the comparison shows what the policy choice buys rather than hiding it.
  5. Losses are printed. If another tool catches something Actaira misses,
     that artifact is named in the output.

The corpus is not neutral: it was built while developing Actaira, so it
contains the gadget shapes Actaira was designed around. That is stated in the
report rather than argued away. The `gadget-unknown` family is the part that
matters most, because those are documented execution paths chosen for being
absent from published denylists, and no tool here had them as a target.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from actaira.inspect import inspect_artifact  # noqa: E402
from actaira.model import Severity, Verdict  # noqa: E402

# Formats each tool documents support for. Anything outside this set is
# recorded as "declined", never as a miss.
PICKLE_FORMATS = {"pickle", "pytorch-zip", "zip", "npy"}
ACTAIRA_FORMATS = PICKLE_FORMATS | {"safetensors", "onnx", "gguf", "hdf5", "unknown", "empty"}
MODELSCAN_FORMATS = PICKLE_FORMATS | {"hdf5"}


@dataclass
class ToolResult:
    flagged: bool | None  # None = declined or unsupported
    detail: str = ""
    error: str | None = None
    seconds: float = 0.0


@dataclass
class Tool:
    name: str
    version: str
    run: Callable[[Path, str], ToolResult]
    supported: set[str]
    note: str = ""


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------

def _actaira(policy: str) -> Callable[[Path, str], ToolResult]:
    def run(path: Path, fmt: str) -> ToolResult:
        started = time.perf_counter()
        report = inspect_artifact(path, scan_policy=policy, fail_on=Severity.HIGH)
        elapsed = time.perf_counter() - started
        return ToolResult(
            flagged=report.verdict is Verdict.FAIL,
            detail=",".join(sorted({finding.rule_id for finding in report.findings})),
            seconds=elapsed,
        )

    return run


def _picklescan(path: Path, fmt: str) -> ToolResult:
    from picklescan.scanner import scan_file_path

    started = time.perf_counter()
    try:
        result = scan_file_path(str(path))
    except Exception as exc:
        return ToolResult(flagged=None, error=f"{type(exc).__name__}: {exc}",
                          seconds=time.perf_counter() - started)
    elapsed = time.perf_counter() - started
    dangerous = [g for g in result.globals if str(getattr(g, "safety", "")).lower().endswith("dangerous")]
    flagged = result.issues_count > 0 or result.infected_files > 0
    # A detection is read before an error, and the order is the whole of the
    # fix. picklescan sets `scan_err` on artifacts it also flags - a member it
    # could not open inside an archive whose other member held the gadget -
    # and testing `scan_err` first turned every one of those into "declined to
    # answer", which drops the artifact out of the denominator. The tool was
    # being denied credit for real detections and the comparison moved in
    # Actaira's favour every time, which is the one direction a benchmark
    # written by the vendor must never be wrong in (fairness rule 2).
    if flagged:
        return ToolResult(flagged=True, detail=",".join(sorted(f"{g.module}.{g.name}" for g in dangerous)),
                          seconds=elapsed)
    if getattr(result, "scan_err", False):
        return ToolResult(flagged=None, error="scan_err", seconds=elapsed)
    return ToolResult(flagged=False, detail="", seconds=elapsed)


def _modelscan(path: Path, fmt: str) -> ToolResult:
    from modelscan.modelscan import ModelScan

    started = time.perf_counter()
    try:
        scanner = ModelScan()
        result = scanner.scan(str(path))
    except Exception as exc:
        return ToolResult(flagged=None, error=f"{type(exc).__name__}: {exc}",
                          seconds=time.perf_counter() - started)
    elapsed = time.perf_counter() - started
    summary = result.get("summary", {})
    issues = result.get("issues", [])
    total = summary.get("total_issues", len(issues))
    return ToolResult(
        flagged=bool(total),
        detail=",".join(sorted({issue.get("operator", "?") for issue in issues})),
        seconds=elapsed,
    )


def _fickling(path: Path, fmt: str) -> ToolResult:
    started = time.perf_counter()
    try:
        # S603: fairness rule 4 says every tool runs with its default
        # configuration, and fickling's is a command line. The argument vector is
        # this interpreter plus a corpus path, never a shell string.
        completed = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "fickling", "--check-safety", str(path)],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(flagged=None, error="timeout", seconds=time.perf_counter() - started)
    elapsed = time.perf_counter() - started
    # fickling exits 1 when it considers the file unsafe, 0 when it does not,
    # and >1 when it could not parse the file at all.
    if completed.returncode > 1:
        return ToolResult(flagged=None, error=f"exit {completed.returncode}", seconds=elapsed)
    return ToolResult(
        flagged=completed.returncode == 1,
        detail=(completed.stdout or completed.stderr).strip().splitlines()[:1] and
               (completed.stdout or completed.stderr).strip().splitlines()[0][:80] or "",
        seconds=elapsed,
    )


def discover_tools() -> list[Tool]:
    tools = [
        Tool("actaira (strict)", _version("actaira"), _actaira("strict"), ACTAIRA_FORMATS,
             "allowlist policy, the default"),
        Tool("actaira (known-bad)", _version("actaira"), _actaira("known-bad"), ACTAIRA_FORMATS,
             "denylist policy, for comparison"),
    ]
    if _importable("picklescan"):
        tools.append(Tool("picklescan", _version("picklescan"), _picklescan, PICKLE_FORMATS,
                          "denylist of dangerous globals"))
    if _importable("modelscan"):
        tools.append(Tool("modelscan", _version("modelscan"), _modelscan, MODELSCAN_FORMATS,
                          "Protect AI, denylist of unsafe operators"))
    if _importable("fickling"):
        tools.append(Tool("fickling", _version("fickling"), _fickling, PICKLE_FORMATS,
                          "Trail of Bits, AST analysis of the pickle program"))
    return tools


def _importable(module: str) -> bool:
    try:
        __import__(module)
        return True
    except Exception:
        return False


def _version(module: str) -> str:
    try:
        from importlib.metadata import version

        return version(module)
    except Exception:
        return "?"


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

@dataclass
class Row:
    name: str
    family: str
    label: str
    detected_format: str
    results: dict[str, ToolResult] = field(default_factory=dict)


def run(corpus_dir: Path, extra_dirs: list[Path]) -> dict[str, Any]:
    cases = json.loads((corpus_dir / "cases.json").read_text(encoding="utf-8"))
    entries = [(corpus_dir / case["name"], case["family"], case["label"]) for case in cases]

    for extra in extra_dirs:
        manifest = extra / "real_cases.json"
        if not manifest.exists():
            continue
        for case in json.loads(manifest.read_text(encoding="utf-8")):
            entries.append((extra / case["name"], "real", case["label"]))

    tools = discover_tools()
    rows: list[Row] = []
    for path, family, label in entries:
        if not path.exists():
            continue
        detected = inspect_artifact(path).detected_format
        row = Row(name=path.name, family=family, label=label, detected_format=detected)
        for tool in tools:
            if detected not in tool.supported:
                row.results[tool.name] = ToolResult(flagged=None, detail="format not supported")
            else:
                row.results[tool.name] = tool.run(path, detected)
        rows.append(row)

    return {
        "tools": [{"name": t.name, "version": t.version, "note": t.note} for t in tools],
        "python": sys.version.split()[0],
        "rows": [
            {
                "name": r.name, "family": r.family, "label": r.label,
                "detected_format": r.detected_format,
                "results": {
                    name: {"flagged": res.flagged, "detail": res.detail,
                           "error": res.error, "ms": round(res.seconds * 1000, 3)}
                    for name, res in r.results.items()
                },
            }
            for r in rows
        ],
        "scoreboard": _score(rows, tools),
    }


def _score(rows: list[Row], tools: list[Tool]) -> dict[str, Any]:
    """Two scoreboards: head to head on pickles, then whole-corpus coverage."""
    head_to_head = [row for row in rows if row.detected_format in PICKLE_FORMATS]
    board: dict[str, Any] = {"head_to_head_pickle": {}, "whole_corpus": {}, "losses": {}}

    for tool in tools:
        for scope, subset in (("head_to_head_pickle", head_to_head), ("whole_corpus", rows)):
            # Declined artifacts leave the denominator. Counting a format a
            # tool never claimed to read as a miss is the oldest trick in
            # benchmarking, and this harness was doing it: fickling showed as
            # 32/36 when 4 of those were torch containers it could not parse,
            # so its real score on what it reads is 32/32. The error flattered
            # Actaira every time, which is exactly why it survived a reading.
            # Caught by tests/test_benchmark.py, written to check the harness
            # rather than the tools.
            answered = [r for r in subset if r.results[tool.name].flagged is not None]
            malicious = [r for r in answered if r.label == "malicious"]
            benign = [r for r in answered if r.label == "benign"]
            caught = [r for r in malicious if r.results[tool.name].flagged is True]
            declined = [r for r in subset if r.results[tool.name].flagged is None]
            false_alarms = [r for r in benign if r.results[tool.name].flagged is True]
            timings = [r.results[tool.name].seconds for r in subset if r.results[tool.name].flagged is not None]
            board[scope][tool.name] = {
                "malicious_in_scope": sum(1 for r in subset if r.label == "malicious"),
                "malicious_total": len(malicious),
                "malicious_caught": len(caught),
                "benign_total": len(benign),
                "false_alarms": len(false_alarms),
                "false_alarm_cases": sorted(r.name for r in false_alarms),
                "declined": len(declined),
                "median_ms": round(sorted(timings)[len(timings) // 2] * 1000, 3) if timings else None,
            }

    # Per family, because the aggregate hides the interesting part: every
    # tool here catches the textbook `os.system` gadget, and the question
    # worth asking is what happens on the ones nobody put on a list.
    board["by_family"] = {}
    families = sorted({row.family for row in rows if row.label == "malicious"})
    for family in families:
        subset = [r for r in rows if r.family == family and r.label == "malicious"]
        board["by_family"][family] = {
            tool.name: {
                "caught": sum(1 for r in subset if r.results[tool.name].flagged is True),
                "declined": sum(1 for r in subset if r.results[tool.name].flagged is None),
                "total": sum(1 for r in subset if r.results[tool.name].flagged is not None),
                "in_family": len(subset),
            }
            for tool in tools
        }

    # Where another tool wins. Printed even when the list is empty, because an
    # empty list is only meaningful if the reader knows it was checked.
    actaira = "actaira (strict)"
    for tool in tools:
        if tool.name.startswith("actaira"):
            continue
        wins = sorted(
            row.name for row in rows
            if row.label == "malicious"
            and row.results[tool.name].flagged is True
            and row.results[actaira].flagged is not True
        )
        board["losses"][tool.name] = wins
    return board


def render(summary: dict[str, Any]) -> str:
    lines: list[str] = ["tools under test:"]
    for tool in summary["tools"]:
        lines.append(f"  {tool['name']:22} {tool['version']:12} {tool['note']}")
    lines.append("")
    for scope, title in (
        ("head_to_head_pickle", "head to head, pickle-family artifacts only"),
        ("whole_corpus", "whole corpus, including formats some tools do not read"),
    ):
        lines.append(title)
        lines.append("  caught and false alarms are over the artifacts each tool actually read;")
        lines.append("  declined counts the ones it did not, and is where coverage lives.")
        lines.append(f"  {'tool':22} {'caught':>12}  {'false alarms':>13}  {'declined':>9}  {'median':>8}")
        for name, row in summary["scoreboard"][scope].items():
            caught = f"{row['malicious_caught']}/{row['malicious_total']}"
            alarms = f"{row['false_alarms']}/{row['benign_total']}"
            median = f"{row['median_ms']} ms" if row["median_ms"] is not None else "n/a"
            lines.append(f"  {name:22} {caught:>12}  {alarms:>13}  {row['declined']:>9}  {median:>8}")
        lines.append("")
    lines.append("detection by gadget family, malicious artifacts only")
    families = summary["scoreboard"].get("by_family", {})
    if families:
        tool_names = list(next(iter(families.values())).keys())
        header = "  " + f"{'family':18}" + "".join(f"{name[:18]:>20}" for name in tool_names)
        lines.append(header)
        for family, scores in families.items():
            cells = "".join(
                f"{str(scores[name]['caught']) + '/' + str(scores[name]['total']):>20}"
                for name in tool_names
            )
            lines.append(f"  {family:18}{cells}")
    lines.append("")

    lines.append("false alarms, named:")
    for scope in ("head_to_head_pickle",):
        for name, row in summary["scoreboard"][scope].items():
            if row["false_alarm_cases"]:
                lines.append(f"  {name:22} {', '.join(row['false_alarm_cases'])}")
    lines.append("")
    lines.append("artifacts another tool catches that actaira (strict) does not:")
    for name, wins in summary["scoreboard"]["losses"].items():
        lines.append(f"  {name:22} {wins if wins else 'none'}")
    lines.append("")
    lines.append(READING_NOTES)
    return "\n".join(lines)


READING_NOTES = """how to read this
  Every tool here is competent and none of them is doing a bad job. They
  answer different questions, and the table only makes sense with that said.

  fickling asks "can this pickle execute anything at all", which is a
  legitimate and more conservative question than "is this pickle malicious".
  That is why it flags ordinary state_dicts: a state_dict does contain a
  REDUCE. Read its false-alarm column as the cost of a stricter question,
  not as a defect. Its per-file cost here also includes process startup,
  since it is invoked as a subprocess the way a user would.

  picklescan and modelscan are denylist scanners and behave exactly as
  documented: they catch the gadgets on their lists and pass the ones that
  are not. The `gadget-unknown` row is where that shows.

  actaira (strict) has one false alarm, `real_full_module.pt`, and it is
  worth naming: that artifact is `torch.save(model)` on a whole nn.Module,
  which stores an import of the user's own class. Actaira reports it on
  purpose, because loading it imports user code. By the corpus label it is a
  benign file, so it is counted as a false alarm here rather than explained
  away. A reviewer can decide which of the two readings they prefer.

  The corpus was built while developing Actaira, so it contains the shapes
  Actaira was designed around. Treat the aggregate as a description of this
  corpus, not as a general ranking."""


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare Actaira with other model artifact scanners")
    parser.add_argument("--corpus", type=Path, default=ROOT / "evals" / "artifacts")
    parser.add_argument("--real", type=Path, default=ROOT / "evals" / "real")
    parser.add_argument("--json-out", type=Path, default=ROOT / "evals" / "benchmark.json")
    args = parser.parse_args()

    if not (args.corpus / "cases.json").exists():
        sys.path.insert(0, str(ROOT / "evals"))
        from corpus.build import build  # type: ignore

        build(args.corpus)

    summary = run(args.corpus, [args.real])
    args.json_out.write_text(json.dumps(summary, indent=2), encoding="utf-8", newline="\n")
    print(render(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
