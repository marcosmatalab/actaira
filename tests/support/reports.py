"""Build an `ArtifactReport` directly, without an inspector.

Half the suite used `inspect_artifact` as a fixture factory: write a file,
inspect it, then test the receipt, the subject, the schema or the package
built from the result. The subject of those tests was never inspection, and
`actaira.inspect` went to archive/model-scanner with the scanner.

`ArtifactReport` was already designed for this - its docstring says its fields
are defaulted "so a report constructed by a test or a third party stays
constructible". Rejected: a fake inspector that re-derives verdicts from
findings, which would make the suite assert on a reimplementation of deleted
code rather than on the module under test.

`verdict` is passed, never computed here, for the same reason: a helper that
decided PASS or FAIL would be the decision logic these tests exist to check.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from actaira.coverage import (
    REASON_FORMAT_UNKNOWN,
    REASON_READ_IN_FULL,
    Coverage,
    CoverageState,
    Surface,
    SurfaceCoverage,
    baseline,
)
from actaira.model import ArtifactReport, Finding, Severity, Verdict

# Deterministic filler. The attestation layer hashes and packages bytes without
# reading them, so what these bytes mean is exactly nothing, and saying so here
# is cheaper than a test wondering whether the content mattered.
FILLER = b"\x00" * 64


def finding(rule_id: str, severity: Severity = Severity.HIGH, location: str = "", **evidence: Any) -> Finding:
    return Finding(rule_id=rule_id, severity=severity, location=location, evidence=dict(evidence))


# The three surfaces a static pass ever claimed. `baseline()` already pins the
# other three to NOT_ASSESSED with the reason each one is out of scope.
STATIC_SURFACES = (Surface.LOAD_TIME_EXECUTION, Surface.ARCHIVE_STRUCTURE, Surface.ARTIFACT_METADATA)


def full_coverage(*, state: CoverageState = CoverageState.COMPLETE, reason: str = REASON_READ_IN_FULL) -> Coverage:
    """Every in-scope surface at one state, for tests that only need "not a gap".

    `reason` is a key the catalogue translates and `coverage/v1` requires it to
    be non-empty, so it is defaulted rather than left blank.
    """
    coverage = baseline()
    for surface in STATIC_SURFACES:
        coverage.set(SurfaceCoverage(surface=surface, state=state, reason=reason))
    return coverage


def make_report(
    path: str | Path,
    *,
    payload: bytes | None = None,
    sha256: str | None = None,
    size_bytes: int | None = None,
    detected_format: str = "safetensors",
    format_confidence: str = "magic",
    verdict: Verdict = Verdict.PASS,
    findings: list[Finding] | None = None,
    metadata: dict[str, Any] | None = None,
    imported_callables: list[str] | None = None,
    inspector_errors: list[str] | None = None,
    coverage: Coverage | None = None,
) -> ArtifactReport:
    """A report about `path`. Nothing is read from disk unless `payload` is None."""
    target = Path(path)
    if payload is None and sha256 is None and target.exists():
        payload = target.read_bytes()
    body = FILLER if payload is None else payload
    return ArtifactReport(
        path=str(path),
        size_bytes=len(body) if size_bytes is None else size_bytes,
        sha256=hashlib.sha256(body).hexdigest() if sha256 is None else sha256,
        detected_format=detected_format,
        format_confidence=format_confidence,
        verdict=verdict,
        findings=list(findings or []),
        metadata=dict(metadata or {"fully_read": True}),
        imported_callables=list(imported_callables or []),
        inspector_errors=list(inspector_errors or []),
        coverage=coverage if coverage is not None else full_coverage(),
    )


def write_report(path: str | Path, *, payload: bytes | None = None, **kwargs: Any) -> ArtifactReport:
    """Write the bytes to disk and describe them. What most call sites want."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    body = FILLER if payload is None else payload
    target.write_bytes(body)
    return make_report(target, payload=body, **kwargs)


# The shape the archived corpus produced for its one gadget pickle, written out
# because the report writers under test translate rule ids and rank severities
# and a test that supplies only one finding cannot exercise either. Two rules,
# two severities, one with evidence: that is the whole reason this pair exists.
GADGET_FINDINGS = (
    ("ACT-PKL-002", Severity.CRITICAL, {"callable": "posix.system"}),
    ("ACT-PKL-008", Severity.INFO, {"opcode": "REDUCE"}),
)


def write_flagged_report(
    path: str | Path,
    *rule_ids: str,
    severity: Severity = Severity.CRITICAL,
    location: str | None = None,
    **kwargs: Any,
) -> ArtifactReport:
    """The other half of every pair: one clean artifact and one that is not.

    With no rule ids this is the gadget pickle. With them it is exactly the
    findings named, all at `severity`, for a test about one specific rule.
    `location` is where inside the artifact the finding sits - a zip member
    name, or the file's own name when the artifact is not an archive.
    """
    where = str(path) if location is None else location
    if rule_ids:
        findings = [finding(rule_id, severity=severity, location=where) for rule_id in rule_ids]
    else:
        findings = [
            finding(rule_id, severity=rule_severity, location=where, **evidence)
            for rule_id, rule_severity, evidence in GADGET_FINDINGS
        ]
    kwargs.setdefault("verdict", Verdict.FAIL)
    kwargs.setdefault("detected_format", "pickle")
    kwargs.setdefault("imported_callables", ["posix.system"])
    return write_report(path, findings=findings, **kwargs)


def write_unread_report(path: str | Path, **kwargs: Any) -> ArtifactReport:
    """The third verdict: nothing identified the bytes, so nothing is claimed."""
    kwargs.setdefault("payload", b"\x11\x22\x33\x44 not a known format")
    kwargs.setdefault("detected_format", "unknown")
    kwargs.setdefault("format_confidence", "unknown")
    kwargs.setdefault("verdict", Verdict.INCONCLUSIVE)
    kwargs.setdefault("metadata", {"fully_read": False})
    kwargs.setdefault(
        "coverage",
        full_coverage(state=CoverageState.FAILED, reason=REASON_FORMAT_UNKNOWN),
    )
    kwargs.setdefault("findings", [finding("ACT-FMT-001", severity=Severity.MEDIUM, location=str(path))])
    return write_report(path, **kwargs)


__all__ = [
    "FILLER",
    "STATIC_SURFACES",
    "Surface",
    "finding",
    "full_coverage",
    "make_report",
    "GADGET_FINDINGS",
    "write_flagged_report",
    "write_unread_report",
    "write_report",
]
