"""Orchestrator: one artifact in, one ArtifactReport out.

Design note D-10. Verdict rules, in one place so they can be argued with:

  FAIL          at least one CRITICAL or HIGH finding.
  INCONCLUSIVE  the artifact could not be fully read, or the format is
                unknown, and nothing worse was found.
  PASS          fully read, nothing above MEDIUM.

MEDIUM and below do not fail an artifact because they describe hygiene
(extension mismatch, unusual dtype) rather than a path to execution. That
threshold is a policy choice, exposed as `--fail-on` rather than baked in,
and the eval harness measures both settings.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from .coverage import (
    REASON_INSPECTOR_CRASHED,
    REASON_NOT_APPLICABLE_TO_FORMAT,
    REASON_READ_IN_FULL,
    Coverage,
    CoverageState,
    Surface,
    SurfaceCoverage,
    apply_findings,
    baseline,
    classified_rules,
)
from .formats import archive, detect, gguf, keras_h5, npy, onnx, safetensors
from .formats.pickle_scan import scan_pickle_bytes
from .io_budget import MAX_PICKLE_BYTES, read_at_most
from .model import ArtifactReport, Finding, Severity, Verdict

READ_CHUNK = 1024 * 1024

# Rule ids that ARE the report's own admission that part of the artifact was
# never read: a header that did not parse, a member that would not open, a
# budget that cut the scan short.
#
# This set exists because the same bug was fixed three times and shipped a
# fourth. Each branch of `inspect_artifact` derived `fully_read` for itself,
# and each new branch forgot: the zip branch let a member it could not
# decompress reach PASS, the ONNX branch let an over-budget file reach PASS,
# and fuzzing then found the safetensors and NumPy branches doing it too,
# plus a pickle inside a zip whose parse error nobody propagated. Deriving
# the condition from the findings, in one place, makes "I could not read
# this" a property of what was reported rather than of which branch ran, so
# a new rule has to be classified here to be forgotten.
#
# Superseded by `coverage.py` and kept as a derived value. Design note D-104.
# The set below is now the subset of classified rules whose effect is an
# in-scope surface that is not COMPLETE, computed rather than maintained, so
# a rule cannot be classified in one place and forgotten in the other.
LEGACY_UNREAD_RULE_IDS: frozenset[str] = frozenset(
    {
        "ACT-FMT-001",  # format not recognised
        "ACT-FMT-003",  # zero bytes
        "ACT-PKL-006",  # pickle stream did not disassemble
        "ACT-PKL-008",  # opcode budget hit, the rest of the stream is unread
        "ACT-PKL-013",  # concatenated-stream budget hit, the tail is unread
        "ACT-ZIP-003",  # member could not be read
        "ACT-ZIP-004",  # member budget hit
        "ACT-ZIP-005",  # archive would not open
        "ACT-ZIP-006",  # member over the size cap, not inspected
        "ACT-ZIP-007",  # member the name gate never opened
        "ACT-ONX-003",  # protobuf did not decode
        "ACT-ONX-004",  # over the size budget, never parsed
        "ACT-GGF-001",  # malformed gguf
        "ACT-GGF-003",  # counts over budget, parsing abandoned
        "ACT-GGF-004",  # fewer tensors parsed than declared
        "ACT-NPY-002",  # malformed npy
        "ACT-H5-003",   # model_config not located or not parseable
        "ACT-H5-004",   # not an HDF5 file after all
        "ACT-STF-001",  # header length outside the budget, never parsed
        "ACT-STF-002",  # header length past the end of the file
        "ACT-STF-007",  # malformed safetensors header or entry
    }
)


class _OverBudgetError(Exception):
    """Internal: this parser will not hold a file this large."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(READ_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def inspect_artifact(path: Path, scan_policy: str = "strict", fail_on: Severity = Severity.HIGH) -> ArtifactReport:
    path = Path(path)
    detected, confidence = detect.sniff(path)
    report = ArtifactReport(
        path=str(path),
        size_bytes=path.stat().st_size,
        sha256=sha256_file(path),
        detected_format=detected,
        format_confidence=confidence,
        verdict=Verdict.INCONCLUSIVE,
    )

    mismatch = detect.extension_mismatch(path, detected)
    if mismatch is not None:
        report.findings.append(mismatch)

    fully_read = True

    try:
        if detected == "pickle":
            # D-160. This was `path.read_bytes()` with no ceiling, so a 4 GB
            # `.pkl` allocated 4 GB inside a CI job. Every other parser had a
            # budget; the one that reads the format this tool exists for did
            # not. Over the budget nothing is scanned and the report says so,
            # which is the honest answer: the file was not read.
            blob, over_budget = read_at_most(path, MAX_PICKLE_BYTES)
            if over_budget:
                report.findings.append(
                    Finding(
                        rule_id="ACT-PKL-014",
                        severity=Severity.MEDIUM,
                        location=path.name,
                        evidence={"size_bytes": report.size_bytes, "limit_bytes": MAX_PICKLE_BYTES},
                    )
                )
                raise _OverBudgetError
            result = scan_pickle_bytes(blob, path.name, scan_policy)
            report.findings.extend(result.findings)
            report.imported_callables = sorted(result.imported_callables)
            report.metadata["pickle_protocol"] = result.protocol
            if result.container:
                report.metadata["container"] = result.container
            report.metadata["opcode_count"] = result.opcode_count
            fully_read = not result.truncated

        elif detected in ("zip", "pytorch-zip"):
            findings, metadata, imported = archive.inspect(path, scan_policy)
            report.findings.extend(findings)
            report.metadata.update(metadata)
            report.imported_callables = sorted(imported)
            if metadata.get("pickle_members"):
                report.detected_format = "pytorch-zip"
            # An archive that hit the member budget, failed to open, or had a
            # member it could not read was NOT fully inspected. Without this
            # the branch fell through to PASS, which is precisely the silent
            # pass D-04 forbids. Found by tests/test_formats.py, not by review:
            # a 600-shard checkpoint is a normal layout, so the gadget in
            # member 520 was never even scanned.
            fully_read = not any(
                finding.rule_id in ("ACT-ZIP-003", "ACT-ZIP-004", "ACT-ZIP-005")
                for finding in findings
            )

        elif detected == "safetensors":
            findings, tensors, metadata = safetensors.inspect(path)
            report.findings.extend(findings)
            report.tensors = tensors
            report.metadata.update(metadata)

        elif detected == "onnx":
            findings, tensors, metadata = onnx.inspect(path)
            report.findings.extend(findings)
            report.tensors = tensors
            report.metadata.update(metadata)
            # ACT-ONX-004 (over the size budget) counts as unread too: the
            # file was never parsed. Keying this on ACT-ONX-003 alone was the
            # same shape of bug as the zip branch, one inspector over.
            fully_read = not any(f.rule_id in ("ACT-ONX-003", "ACT-ONX-004") for f in findings)

        elif detected == "gguf":
            findings, tensors, metadata = gguf.inspect(path)
            report.findings.extend(findings)
            report.tensors = tensors
            report.metadata.update(metadata)
            fully_read = not any(f.rule_id in ("ACT-GGF-001", "ACT-GGF-004") for f in findings)

        elif detected == "npy":
            findings, tensors, metadata, imported = npy.inspect(path, scan_policy)
            report.findings.extend(findings)
            report.tensors = tensors
            report.metadata.update(metadata)
            report.imported_callables = sorted(imported)

        elif detected == "hdf5":
            findings, metadata, config_read = keras_h5.inspect(path)
            report.findings.extend(findings)
            report.metadata.update(metadata)
            fully_read = config_read

        elif detected == "empty":
            report.findings.append(
                Finding(rule_id="ACT-FMT-003", severity=Severity.LOW, location=path.name, evidence={"size_bytes": 0})
            )
            fully_read = False

        else:
            report.findings.append(
                Finding(
                    rule_id="ACT-FMT-001",
                    severity=Severity.MEDIUM,
                    location=path.name,
                    evidence={"reason": "format_not_recognised", "consequence": "inconclusive"},
                )
            )
            fully_read = False

    except _OverBudgetError:
        # Not an inspector error: nothing went wrong, the file is simply
        # larger than this parser will hold. The finding above carries the
        # numbers and the coverage table turns it into a gap, so the verdict
        # is INCONCLUSIVE rather than a traceback.
        fully_read = False

    except Exception as exc:  # an inspector crash must never become a PASS
        report.inspector_errors.append(f"{type(exc).__name__}: {exc}")
        fully_read = False

    # The branches above each know something extra about their own inspector
    # (a pickle's `truncated` flag, whether the Keras config was located).
    # This is the floor under all of them: whatever the branch concluded, an
    # artifact whose own findings say it was not read is not fully read.
    if any(finding.rule_id in UNREAD_RULE_IDS for finding in report.findings):
        fully_read = False

    coverage = build_coverage(report, branch_complete=fully_read)
    report.coverage = coverage
    report.verdict = decide_verdict(report, coverage, fail_on)
    # `fully_read` is derived now, not decided. Design note D-104: every
    # consumer written against the old contract - SARIF properties, the JUnit
    # properties block, the governance assessor, the web UI - keeps reading a
    # boolean at the same key.
    #
    # Its meaning narrowed, and saying otherwise would be the kind of claim
    # this repository exists to refuse. Before the coverage model it answered
    # two questions at once, "did every parser finish" and "was the whole file
    # examined", and the second was never true of any checkpoint. It now
    # answers only the first, over the surfaces this tool undertook to read.
    # A benign torch zip was False and is True, and that is the correction
    # rather than a regression: see the coverage matrix for what was and was
    # not looked at, which is the field that carries the real answer.
    report.metadata["fully_read"] = all(
        entry.state is CoverageState.COMPLETE for entry in coverage.in_scope()
    ) and not report.inspector_errors
    return report


def build_coverage(report: ArtifactReport, branch_complete: bool) -> Coverage:
    """Turn one artifact's findings into a per-surface coverage matrix.

    `branch_complete` is what the inspector branch itself concluded - a
    pickle's `truncated` flag, whether the Keras config was located - for the
    cases a rule id does not capture. It can only lower a surface, never
    raise one, because `Coverage.set` keeps the worst state seen.
    """
    coverage = baseline()
    scope = _SURFACES_IN_SCOPE.get(report.detected_format, _DEFAULT_SCOPE)
    for surface in scope:
        coverage.set(
            SurfaceCoverage(surface=surface, state=CoverageState.COMPLETE, reason=REASON_READ_IN_FULL)
        )
    apply_findings(coverage, (finding.rule_id for finding in report.findings))
    if not branch_complete:
        for surface in scope:
            coverage.set(
                SurfaceCoverage(
                    surface=surface,
                    state=CoverageState.PARTIAL,
                    reason=REASON_NOT_APPLICABLE_TO_FORMAT,
                )
            )
    if report.inspector_errors:
        # An inspector that raised knows nothing about anything it was asked
        # to read. Every in-scope surface fails, not just the one the
        # traceback happened to be in.
        for surface in scope:
            coverage.set(
                SurfaceCoverage(
                    surface=surface,
                    state=CoverageState.FAILED,
                    reason=REASON_INSPECTOR_CRASHED,
                    detail={"errors": list(report.inspector_errors)},
                )
            )
    return coverage


def decide_verdict(report: ArtifactReport, coverage: Coverage, fail_on: Severity) -> Verdict:
    """PASS, FAIL or INCONCLUSIVE, decided from coverage rather than a boolean.

    Design note D-105. The rule that changed: a surface marked NOT_ASSESSED
    cannot make a verdict inconclusive. It never could, in principle - the
    tool has always declined to read raw weights - but the old boolean had no
    way to say so, and every checkpoint paid for it with an exit code of 3.

    What still makes a verdict inconclusive is a surface that WAS in scope
    and was not read: a header that would not parse, a member that would not
    decompress, an inspector that raised. Those are the cases where the tool
    tried and could not, and reporting them as success is the thing D-04
    forbids.
    """
    worst = report.max_severity
    if worst is not None and worst.rank >= fail_on.rank:
        return Verdict.FAIL
    if report.inspector_errors:
        return Verdict.INCONCLUSIVE
    weakest = coverage.weakest_in_scope()
    if weakest is None:
        # Nothing was in scope at all, so nothing was established.
        return Verdict.INCONCLUSIVE
    if weakest.state is not CoverageState.COMPLETE:
        return Verdict.INCONCLUSIVE
    return Verdict.PASS


# Which surfaces each format's inspector undertakes to read in full.
#
# A safetensors file has no load-time execution surface at all - that is the
# entire point of the format - so claiming COMPLETE coverage of one would be
# claiming to have checked something that does not exist. The distinction
# matters to a policy: "execution surface COMPLETE" from a safetensors file
# and from a pickle are different statements, and only the second is evidence
# that a scanner looked at code.
_SURFACES_IN_SCOPE: dict[str, tuple[Surface, ...]] = {
    "pickle": (Surface.LOAD_TIME_EXECUTION,),
    "zip": (Surface.LOAD_TIME_EXECUTION, Surface.ARCHIVE_STRUCTURE),
    "pytorch-zip": (Surface.LOAD_TIME_EXECUTION, Surface.ARCHIVE_STRUCTURE),
    "safetensors": (Surface.ARTIFACT_METADATA,),
    "onnx": (Surface.ARTIFACT_METADATA,),
    "gguf": (Surface.ARTIFACT_METADATA,),
    "npy": (Surface.LOAD_TIME_EXECUTION, Surface.ARTIFACT_METADATA),
    "hdf5": (Surface.LOAD_TIME_EXECUTION, Surface.ARTIFACT_METADATA),
    "empty": (Surface.LOAD_TIME_EXECUTION,),
    "unknown": (Surface.LOAD_TIME_EXECUTION,),
}
_DEFAULT_SCOPE: tuple[Surface, ...] = (Surface.LOAD_TIME_EXECUTION,)


def _derive_legacy_unread_rules() -> frozenset[str]:
    """The old flat set, computed from the coverage table.

    Kept so `UNREAD_RULE_IDS` still exists for anything importing it, and so
    a test can assert the two definitions agree rather than trusting that
    somebody updated both.
    """
    from .coverage import rule_effect

    derived = set()
    for rule_id in classified_rules():
        effect = rule_effect(rule_id)
        if effect is None:
            continue
        _, state, _ = effect
        if state.in_scope and state is not CoverageState.COMPLETE:
            derived.add(rule_id)
    return frozenset(derived)


UNREAD_RULE_IDS: frozenset[str] = _derive_legacy_unread_rules()
