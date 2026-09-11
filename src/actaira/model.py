"""Core data model shared by every inspector.

Design note (see docs/DESIGN.md, D-01): every inspector returns the same
`Finding` shape so that the report, the ML-BOM and the attestation can be
built without knowing which format produced the data. The alternative
(format-specific report objects) was rejected because it pushes format
knowledge into the signing layer, which must stay format-agnostic to keep
the attestation reproducible.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from .coverage import Coverage


class Severity(str, Enum):
    """Ordered severity. Comparison uses `rank`, never string order."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Verdict(str, Enum):
    """Outcome of an inspection.

    `INCONCLUSIVE` is a first-class result, not an error. Design note D-04:
    an inspector that cannot parse an artifact must say so instead of
    returning PASS, because a silent PASS on an unparsed file is exactly the
    failure mode that makes a supply-chain tool worthless.
    """

    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Finding:
    """One observation about an artifact.

    `rule_id` is stable across versions and is what the eval harness asserts
    on. Human-readable text lives in the i18n catalogue, never here, so that
    changing wording can never change a test outcome (D-07).
    """

    rule_id: str
    severity: Severity
    location: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "location": self.location,
            "evidence": self.evidence,
        }


@dataclass
class TensorInfo:
    name: str
    dtype: str
    shape: list[int]
    n_elements: int


@dataclass
class ArtifactReport:
    """Everything known about one artifact after static inspection."""

    path: str
    size_bytes: int
    sha256: str
    detected_format: str
    format_confidence: str  # "magic" | "structure" | "extension" | "unknown"
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)
    tensors: list[TensorInfo] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    imported_callables: list[str] = field(default_factory=list)
    inspector_errors: list[str] = field(default_factory=list)
    # What was actually looked at, surface by surface. Design note D-100.
    # Defaulted rather than required so a report constructed by a test or a
    # third party stays constructible; `inspect_artifact` always sets it.
    coverage: Coverage = field(default_factory=Coverage)

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "detected_format": self.detected_format,
            "format_confidence": self.format_confidence,
            "verdict": self.verdict.value,
            "max_severity": self.max_severity.value if self.max_severity else None,
            "findings": [f.to_dict() for f in self.findings],
            "tensors": [asdict(t) for t in self.tensors],
            "metadata": self.metadata,
            "imported_callables": sorted(self.imported_callables),
            "inspector_errors": self.inspector_errors,
            "coverage": self.coverage.to_dict(),
        }


def artifact_name(path: str) -> str:
    """The last path segment of a report path, whichever separator wrote it.

    Design note D-238. This operation was spelled three ways in this
    repository. `Path(p).name` is correct only when the path was written by
    the platform reading it. `p.rsplit("/", 1)[-1]` is correct only on POSIX,
    and six documents were built with it: the ML-BOM component name, the
    receipt's artifact rows, the governance dossier's `artifacts_not_fully_read`,
    the assessed-artifact list, the bundle location and the CLI's summary
    line. On Windows every one of those carried the producer's absolute path
    instead of a filename - a `C:\\Users\\someone\\models\\clean.pkl` inside
    a signed receipt - which is a document that leaks where it was made and
    that cannot be compared with the same document produced anywhere else.

    Both separators are cut, deliberately, and not by `os.path.basename`: a
    report can be read on a different platform from the one that wrote it, and
    a document that means something different depending on who opens it is not
    a contract.
    """
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def canonical_json(payload: Any) -> bytes:
    """Canonical JSON used everywhere a hash is computed.

    Design note D-03: sorted keys, compact separators, UTF-8, no NaN. Two
    runs over the same artifact must produce byte-identical output or the
    hash chain is meaningless. `allow_nan=False` matters: NaN would serialise
    to a non-standard token and break third-party verifiers.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
