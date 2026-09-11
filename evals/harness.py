"""Evaluation harness. Every number published about Actaira is produced here.

Design note D-20. What this measures and what it refuses to measure:

  MEASURED  detection over a closed, hand-built corpus, per policy; false
            positives on the benign half; determinism across repeated runs;
            tamper detection on the attestation package.
  NOT MEASURED  performance against real-world malware, or any estimate of
            it. The corpus is closed and finite, so the right statistic is a
            count, not a rate with a confidence interval. Reporting "97.3%
            detection" from 51 fixed cases would dress a count as an
            estimate of a population that was never sampled.

Detection is decided by the verdict, not by whether a specific rule fired,
because a tool that flags the right file for the wrong reason still stops
the file. Rule-level expectations are checked separately and reported as
their own count.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from actaira.attest import chain, package, signing  # noqa: E402
from actaira.attest.verify import verify_package  # noqa: E402
from actaira.inspect import inspect_artifact  # noqa: E402
from actaira.model import Severity, Verdict  # noqa: E402

POLICIES = ("strict", "known-bad")


@dataclass
class CaseOutcome:
    name: str
    family: str
    label: str
    expected: str
    observed: dict[str, str] = field(default_factory=dict)
    rules: dict[str, list[str]] = field(default_factory=dict)
    expectation_ok: bool = True
    problems: list[str] = field(default_factory=list)
    duration_ms: float = 0.0


def run(corpus_dir: Path) -> dict[str, Any]:
    cases = json.loads((corpus_dir / "cases.json").read_text(encoding="utf-8"))
    outcomes: list[CaseOutcome] = []

    for case in cases:
        path = corpus_dir / case["name"]
        outcome = CaseOutcome(
            name=case["name"], family=case["family"], label=case["label"], expected=case["expect_verdict"]
        )
        for policy in POLICIES:
            started = time.perf_counter()
            report = inspect_artifact(path, scan_policy=policy, fail_on=Severity.HIGH)
            elapsed = (time.perf_counter() - started) * 1000
            if policy == "strict":
                outcome.duration_ms = elapsed
            outcome.observed[policy] = report.verdict.value
            outcome.rules[policy] = sorted({finding.rule_id for finding in report.findings})

        # Expectations are stated against the default policy only.
        strict_rules = set(outcome.rules["strict"])
        if outcome.observed["strict"] != outcome.expected:
            outcome.expectation_ok = False
            outcome.problems.append(f"verdict {outcome.observed['strict']}, expected {outcome.expected}")
        missing = [rule for rule in case.get("expect_rules", []) if rule not in strict_rules]
        if missing:
            outcome.expectation_ok = False
            outcome.problems.append(f"missing expected rules: {missing}")
        forbidden = [rule for rule in case.get("forbid_rules", []) if rule in strict_rules]
        if forbidden:
            outcome.expectation_ok = False
            outcome.problems.append(f"rules that must not fire did: {forbidden}")
        outcomes.append(outcome)

    summary = {
        "corpus": {
            "cases": len(outcomes),
            "benign": sum(1 for o in outcomes if o.label == "benign"),
            "malicious": sum(1 for o in outcomes if o.label == "malicious"),
            "hostile_but_inconclusive": sum(
                1 for o in outcomes if o.label == "hostile-but-inconclusive"
            ),
            "families": sorted({o.family for o in outcomes}),
        },
        "expectations": {
            "checked": len(outcomes),
            "met": sum(1 for o in outcomes if o.expectation_ok),
            "failed": [
                {"case": o.name, "problems": o.problems} for o in outcomes if not o.expectation_ok
            ],
        },
        "policy_comparison": _policy_table(outcomes),
        "timing_ms": _timing(outcomes),
        "determinism": _determinism(corpus_dir, cases),
        "tamper_detection": _tamper(corpus_dir, cases),
        "cases": [
            {
                "name": o.name, "family": o.family, "label": o.label,
                "expected": o.expected, "observed": o.observed, "rules": o.rules,
                "ok": o.expectation_ok, "problems": o.problems,
            }
            for o in outcomes
        ],
    }
    return summary


def _policy_table(outcomes: list[CaseOutcome]) -> dict[str, Any]:
    """Counts, not rates. The corpus is closed, so a count is the honest unit."""
    table: dict[str, Any] = {}
    malicious = [o for o in outcomes if o.label == "malicious"]
    benign = [o for o in outcomes if o.label == "benign"]
    for policy in POLICIES:
        caught = [o for o in malicious if o.observed[policy] == Verdict.FAIL.value]
        missed = [o for o in malicious if o.observed[policy] != Verdict.FAIL.value]
        false_fail = [o for o in benign if o.observed[policy] == Verdict.FAIL.value]
        table[policy] = {
            "malicious_total": len(malicious),
            "malicious_caught": len(caught),
            "malicious_missed": len(missed),
            "missed_cases": sorted(o.name for o in missed),
            "benign_total": len(benign),
            "benign_wrongly_failed": len(false_fail),
            "benign_wrongly_failed_cases": sorted(o.name for o in false_fail),
        }
    # The third group, measured against what it is supposed to produce rather
    # than against FAIL. An artifact whose honest verdict is INCONCLUSIVE is
    # not a detection case, and putting it in a detection denominator measures
    # the wrong thing in whichever direction it is counted.
    inconclusive_by_design = [o for o in outcomes if o.label == "hostile-but-inconclusive"]
    table["hostile_but_inconclusive"] = {
        "total": len(inconclusive_by_design),
        "reported_as_inconclusive": sum(
            1 for o in inconclusive_by_design
            if o.observed["strict"] == Verdict.INCONCLUSIVE.value
        ),
        "cases": sorted(o.name for o in inconclusive_by_design),
    }
    only_strict = sorted(
        o.name for o in malicious
        if o.observed["strict"] == Verdict.FAIL.value and o.observed["known-bad"] != Verdict.FAIL.value
    )
    table["caught_only_by_strict"] = {"count": len(only_strict), "cases": only_strict}
    return table


def _timing(outcomes: list[CaseOutcome]) -> dict[str, float]:
    values = [o.duration_ms for o in outcomes]
    return {
        "n": len(values),
        "median_ms": round(statistics.median(values), 3),
        "max_ms": round(max(values), 3),
        "total_ms": round(sum(values), 1),
    }


def _determinism(corpus_dir: Path, cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Two passes must produce byte-identical reports.

    Non-determinism here would make the attestation worthless: the same
    artifact must always hash to the same payload.
    """
    mismatches: list[str] = []
    for case in cases:
        path = corpus_dir / case["name"]
        first = json.dumps(inspect_artifact(path).to_dict(), sort_keys=True)
        second = json.dumps(inspect_artifact(path).to_dict(), sort_keys=True)
        if first != second:
            mismatches.append(case["name"])
    return {"cases": len(cases), "identical": len(cases) - len(mismatches), "mismatches": mismatches}


def _tamper(corpus_dir: Path, cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Negative control for the attestation layer.

    For every artifact: attest it, then flip one byte and re-attest. The
    subject digest must change, and the original package must stop verifying
    when its entries are edited. A signing layer that passes this trivially
    is not being tested, so the check also asserts the positive case.
    """
    keypair = signing.generate()
    digest_changed = 0
    digest_unchanged: list[str] = []
    tamper_caught = 0
    tamper_missed: list[str] = []
    positive_ok = 0

    workdir = corpus_dir.parent / "_tamper"
    workdir.mkdir(exist_ok=True)

    for case in cases:
        path = corpus_dir / case["name"]
        original = path.read_bytes()
        if not original:
            continue

        report = inspect_artifact(path)
        entries: list[chain.Entry] = []
        chain.append(entries, report.sha256, report.to_dict())
        pkg_path = workdir / f"{case['name']}.zip"
        package.write_package(pkg_path, entries, keypair)

        if verify_package(pkg_path).ok:
            positive_ok += 1

        # flip one byte in the middle of the artifact
        mutated = bytearray(original)
        index = len(mutated) // 2
        mutated[index] ^= 0xFF
        mutated_path = workdir / case["name"]
        mutated_path.write_bytes(bytes(mutated))
        if hashlib.sha256(bytes(mutated)).hexdigest() != report.sha256:
            digest_changed += 1
        else:
            digest_unchanged.append(case["name"])

        # edit the signed package itself and confirm verification fails
        if _tampered_package_rejected(pkg_path):
            tamper_caught += 1
        else:
            tamper_missed.append(case["name"])

        pkg_path.unlink(missing_ok=True)
        mutated_path.unlink(missing_ok=True)

    try:
        workdir.rmdir()
    except OSError:
        pass

    return {
        "artifacts_tested": digest_changed + len(digest_unchanged),
        "subject_digest_changed": digest_changed,
        "subject_digest_unchanged": digest_unchanged,
        "packages_verified_before_tampering": positive_ok,
        "tampered_packages_rejected": tamper_caught,
        "tampered_packages_accepted": tamper_missed,
    }


def tampered_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """The edit an attacker would want, and one that is never a no-op.

    DEF-03. Setting the verdict to a constant was wrong: for an artifact
    already recorded as `pass`, the "tampered" package came out byte-identical
    to the original, so the tamper check passed vacuously on 8 of 50 cases
    while reporting 50/50. Flipping to the opposite value is what makes the
    mutation a mutation, whatever the starting verdict was.

    It is a named function rather than four lines inside the zip round trip so
    that the property, "this always changes something", is testable without
    signing anything. `tests/test_eval_harness.py` is what holds it down.
    """
    payload = entry["payload"]
    payload["verdict"] = "fail" if payload.get("verdict") == "pass" else "pass"
    payload["findings"] = []
    return entry


def _tampered_package_rejected(pkg_path: Path) -> bool:
    """Rewrite one entry inside the signed zip and re-verify."""
    import zipfile

    with zipfile.ZipFile(pkg_path) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    entries_raw = members["entries.jsonl"].decode("utf-8").splitlines()
    if not entries_raw:
        return False
    entry = tampered_entry(json.loads(entries_raw[0]))
    entries_raw[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    members["entries.jsonl"] = ("\n".join(entries_raw) + "\n").encode("utf-8")

    tampered = pkg_path.with_suffix(".tampered.zip")
    with zipfile.ZipFile(tampered, "w") as archive:
        for name, blob in members.items():
            archive.writestr(name, blob)
    result = verify_package(tampered)
    tampered.unlink(missing_ok=True)
    return not result.ok


def render(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    corpus = summary["corpus"]
    lines.append(f"corpus: {corpus['cases']} cases ({corpus['benign']} benign, {corpus['malicious']} malicious)")
    expectations = summary["expectations"]
    lines.append(f"expectations met: {expectations['met']}/{expectations['checked']}")
    for failure in expectations["failed"]:
        lines.append(f"  FAIL {failure['case']}: {'; '.join(failure['problems'])}")
    lines.append("")
    lines.append("policy comparison (counts over the closed corpus, not rates)")
    for policy in POLICIES:
        row = summary["policy_comparison"][policy]
        lines.append(
            f"  {policy:10} caught {row['malicious_caught']}/{row['malicious_total']} malicious"
            f"   false failures on benign: {row['benign_wrongly_failed']}/{row['benign_total']}"
        )
        if row["missed_cases"]:
            lines.append(f"             missed: {', '.join(row['missed_cases'])}")
    only = summary["policy_comparison"]["caught_only_by_strict"]
    lines.append(f"  caught only by the allowlist policy: {only['count']}")
    uncertain = summary["policy_comparison"]["hostile_but_inconclusive"]
    if uncertain["total"]:
        lines.append(
            f"  hostile but inconclusive by design: "
            f"{uncertain['reported_as_inconclusive']}/{uncertain['total']} reported as inconclusive"
        )
    lines.append("")
    determinism = summary["determinism"]
    lines.append(f"determinism: {determinism['identical']}/{determinism['cases']} identical across two runs")
    tamper = summary["tamper_detection"]
    lines.append(
        f"attestation: {tamper['packages_verified_before_tampering']} packages verified before tampering, "
        f"{tamper['tampered_packages_rejected']}/{tamper['artifacts_tested']} rejected after one edited entry"
    )
    lines.append(f"subject digest changed by a single flipped byte: {tamper['subject_digest_changed']}/{tamper['artifacts_tested']}")
    timing = summary["timing_ms"]
    lines.append(f"timing: median {timing['median_ms']} ms per artifact, max {timing['max_ms']} ms")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Actaira evaluation harness")
    parser.add_argument("--corpus", type=Path, default=ROOT / "evals" / "artifacts")
    parser.add_argument("--json-out", type=Path, default=ROOT / "evals" / "results.json")
    args = parser.parse_args()

    if not (args.corpus / "cases.json").exists():
        from corpus.build import build  # type: ignore
        build(args.corpus)

    summary = run(args.corpus)
    args.json_out.write_text(json.dumps(summary, indent=2), encoding="utf-8", newline="\n")
    print(render(summary))

    # The positive control is part of the gate, not decoration. It was printed
    # and never asserted, so a signing layer that verified nothing at all -
    # `positive_ok == 0`, every package failing before it was ever tampered
    # with - still exited 0, because "no tampered package was accepted" is
    # trivially true when no package is accepted either.
    tamper = summary["tamper_detection"]
    ok = (
        summary["expectations"]["met"] == summary["expectations"]["checked"]
        and not summary["determinism"]["mismatches"]
        and not tamper["tampered_packages_accepted"]
        and tamper["packages_verified_before_tampering"] == tamper["artifacts_tested"]
        and tamper["tampered_packages_rejected"] == tamper["artifacts_tested"]
        and tamper["subject_digest_changed"] == tamper["artifacts_tested"]
        and tamper["artifacts_tested"] > 0
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
