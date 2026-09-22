"""The shapes that survive the scanner, and the one every hash is taken over.

`canonical_json` is why this module is still reached: `attest/chain.py`,
`attest/package.py`, `attest/verify.py` and `trace/redact.py` all hash through
it, and two runs over the same facts have to produce the same bytes or every
signature in the tree is decoration (D-03).

`Finding` is the reporting vocabulary (D-01), and phase S1 is where it acquired
the caller phase A kept it for: `surface/rules.py` raises one per rule that
fires. Two of its three companions did not survive that meeting.

`Severity` is gone. It was a five-member enum whose only reason to be an enum
rather than a string was `rank`, and `rank` exists to ORDER severities - which
is the fold the first negative forbids, sitting inside the package as a
finished implementation waiting for a caller. A rule pack's severity is a label
its author wrote, it is published verbatim beside that author's name, and the
set of labels belongs to whoever writes the pack rather than to us. So the field
is a `str` and the enum is in the history.

`Verdict` is gone too, and it is the cleaner deletion: PASS, FAIL and
INCONCLUSIVE are conformance vocabulary, and the conformance product left in
phase S0. What replaced INCONCLUSIVE is `surface.Resolution.INDETERMINATE`,
which says something different and says it about a capability rather than about
an inspection. Recover either from `v2.3.0:src/actaira/model.py`.

What left with the scanner, and why, since a reader looking for it should not
have to use `git log`: `ArtifactReport` and `TensorInfo` described a file that
had been statically inspected - format, tensors, imported callables, coverage
per surface. Nothing in this tree inspects a file. They anchored `coverage.py`
(329 lines) and the writing half of `attest/dsse.py`, and all of it went in
phase A. `artifact_name` went with them: it existed because six
scanner-era documents spelled "the last path segment" three ways, and none of
those six documents exists now. Recover any of it from
`v2.3.0:src/actaira/model.py`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Finding:
    """One observation, and the four fields that say whose observation it is.

    `rule_id` is stable across versions and is what a suppression file keys on.
    Human-readable text lives in the i18n catalogue, never here, so that
    changing wording can never change a test outcome (D-07).

    `rule_version`, `author` and `pack` are not decoration and not metadata:
    the second negative says Actaira never judges, only cites, so a
    finding that did not name who wrote the rule it came from would be Actaira
    holding the opinion. They travel as siblings of `severity` for the same
    reason - a severity standing on its own is one somebody computed, and
    `tests/test_no_aggregate.py` fails on one that does.
    """

    rule_id: str
    rule_version: str
    author: str
    pack: str
    severity: str
    location: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "author": self.author,
            "pack": self.pack,
            "severity": self.severity,
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
