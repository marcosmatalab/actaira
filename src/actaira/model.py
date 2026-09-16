"""The shapes that survive the scanner, and the one every hash is taken over.

`canonical_json` is why this module is still reached: `attest/chain.py`,
`attest/package.py`, `attest/verify.py` and `trace/redact.py` all hash through
it, and two runs over the same facts have to produce the same bytes or every
signature in the tree is decoration (D-03).

`Severity`, `Verdict` and `Finding` are the reporting vocabulary (D-01, D-04).
Phase A left them with no caller in `src/`: the rule packages that will raise a
`Finding` are phase B's, and nothing between here and there produces one. They
are kept rather than deleted because they are the shape phase B is written
against, and `docs/BACKLOG.md` records that they are currently unreached so the
next reader does not mistake "present" for "used".

What left with the scanner, and why, since a reader looking for it should not
have to use `git log`: `ArtifactReport` and `TensorInfo` described a file that
had been statically inspected - format, tensors, imported callables, coverage
per surface. Nothing in this tree inspects a file. They anchored `coverage.py`
(329 lines) and the writing half of `attest/dsse.py`, and all of it went in
phase A. `artifact_name` went with them: it existed because six
scanner-era documents spelled "the last path segment" three ways, and none of
those six documents exists now. Recover any of it from
`archive/model-scanner:src/actaira/model.py`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


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
