"""Evidence with an identity, a lifetime, and a reason it stopped counting.

Design note D-223. `evidence_max_age_days` existed in 2.1 as a predicate over a
date the caller passed in, which is enough to ask "was this observed recently"
and cannot answer any of the questions that follow it: which observation was
this, what replaced it, what stopped being true when the model changed, and
which decisions rested on something that has since been revoked.

Those need evidence to be an object rather than a timestamp, so it is one. The
five states are the ones that actually occur, and keeping them apart matters
because they call for different actions:

  VALID       still stands for exactly the subject it was taken about
  STALE       older than the freshness the policy requires - re-observe
  SUPERSEDED  a later observation of the same claim about the same subject
  REVOKED     the key, source or attestation behind it was withdrawn
  UNTRUSTED   intact, and this environment's trust policy does not accept it

STALE and SUPERSEDED are the pair most tools merge, and merging them loses the
distinction between "nobody has looked lately" and "somebody looked and this is
not the current answer". REVOKED and UNTRUSTED are the other pair: the first is
a fact about the world, the second is a decision made here, and D-170's
separation of signature from trust runs all the way through to here.

The rule that shapes the transitions: evidence is superseded by the digest it
was taken about, never by its subject's name. A new scan of a model that did
not change supersedes nothing, and a scan of a model that did change supersedes
only the evidence bound to the old digest - so evidence about a sibling
artifact that nobody touched stays valid, which is the difference between an
invalidation an operator can act on and a wall of red.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from .. import __version__

SCHEMA_VERSION = "evidence-record/v1"


class EvidenceState(str, Enum):
    VALID = "valid"
    STALE = "stale"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"
    UNTRUSTED = "untrusted"

    @property
    def counts(self) -> bool:
        """Whether a decision may rest on evidence in this state.

        Only VALID does. The other four are not degrees of confidence; they
        are four different reasons the evidence has stopped answering the
        question, and a policy that accepted "stale" as nearly-valid would be
        a policy with no freshness requirement.
        """
        return self is EvidenceState.VALID


# What a piece of evidence is about. Kept as a closed list so a dashboard can
# group by it and `release_check.py` can assert every member is translated.
KINDS = (
    "artifact_scan",
    "bundle",
    "agent_assessment",
    "policy_decision",
    "governance",
    "attestation",
    "source_snapshot",
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class EvidenceRecord:
    """One observation, identified by what it says rather than when it ran."""

    subject_id: str
    kind: str
    subject_digest: str = ""
    collector: str = "actaira-core"
    collector_version: str = __version__
    observed_at: str = field(default_factory=_now)
    valid_until: str | None = None
    state: EvidenceState = EvidenceState.VALID
    supersedes: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    trust: dict[str, Any] = field(default_factory=dict)

    @property
    def digest(self) -> str:
        """Over what the evidence says, not over when it was taken.

        Two identical observations of an unchanged subject have one digest,
        which is what makes re-running `watch` idempotent: the second run
        recognises the record it already has instead of writing a second one
        that supersedes the first for no reason.
        """
        body = {
            "subject_id": self.subject_id,
            "subject_digest": self.subject_digest,
            "kind": self.kind,
            "collector": self.collector,
            "collector_version": self.collector_version,
            "payload": self.payload,
        }
        blob = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()

    @property
    def evidence_id(self) -> str:
        return "ev_" + self.digest.split(":", 1)[1][:32]

    def age_days(self, on: datetime | None = None) -> int:
        moment = on or datetime.now(UTC)
        try:
            taken = datetime.fromisoformat(self.observed_at)
        except ValueError:  # pragma: no cover - only on a hand-edited store
            return 0
        if taken.tzinfo is None:
            taken = taken.replace(tzinfo=UTC)
        return (moment - taken).days

    def to_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "evidence_id": self.evidence_id,
            "subject": self.subject_id,
            "subject_digest": self.subject_digest,
            "kind": self.kind,
            "collector": self.collector,
            "collector_version": self.collector_version,
            "observed_at": self.observed_at,
            "valid_until": self.valid_until,
            "state": self.state.value,
            "supersedes": self.supersedes,
            "digest": self.digest,
        }
        if self.payload:
            document["payload"] = self.payload
        if self.trust:
            document["trust"] = self.trust
        return document


def for_subject(
    subject_id: str,
    kind: str,
    *,
    subject_digest: str = "",
    payload: dict[str, Any] | None = None,
    valid_for_days: int | None = None,
    trust: dict[str, Any] | None = None,
) -> EvidenceRecord:
    if kind not in KINDS:
        raise ValueError(f"{kind!r} is not an evidence kind. Known: {', '.join(KINDS)}")
    valid_until = None
    if valid_for_days is not None:
        valid_until = (datetime.now(UTC) + timedelta(days=valid_for_days)).isoformat()
    return EvidenceRecord(
        subject_id=subject_id,
        kind=kind,
        subject_digest=subject_digest,
        payload=payload or {},
        valid_until=valid_until,
        trust=trust or {},
    )


def supersede(
    store: Any, subject_id: str, new_digest: str, *, connection: Any = None
) -> list[str]:
    """Mark evidence about an earlier digest of this subject as superseded.

    Bound to the digest, not to the name, and that is the whole rule. A
    re-observation of a model that did not change supersedes nothing; one of a
    model that did supersedes only the records taken about the bytes that are
    gone. Evidence about a sibling artifact nobody touched stays VALID, which
    is the difference between an invalidation somebody acts on and a page of
    red nobody reads.

    Returns the ids it changed, so `watch` can report a number it can defend.
    """
    changed: list[str] = []
    for row in store.evidence_for(subject_id):
        if row["state"] != EvidenceState.VALID.value:
            continue
        if row["subject_digest"] and row["subject_digest"] == new_digest:
            continue
        store.set_evidence_state(row["evidence_id"], EvidenceState.SUPERSEDED.value, connection)
        changed.append(row["evidence_id"])
    return changed


def expire(store: Any, *, max_age_days: int, on: datetime | None = None) -> list[str]:
    """Move VALID evidence past its own `valid_until`, or past a limit, to STALE.

    Two clocks, and the record's own wins. A collector that said how long its
    observation is good for knows something this function does not - a
    signature valid until a certificate expires, a scan of a source that
    publishes weekly - and a global limit that overrode it would be a worse
    answer imposed on a better one.
    """
    moment = on or datetime.now(UTC)
    changed: list[str] = []
    for row in store.all_evidence(EvidenceState.VALID.value):
        expiry = _moment(row["valid_until"])
        if expiry is not None:
            stale = expiry < moment
        else:
            taken = _moment(row["observed_at"])
            if taken is None:
                # A timestamp nothing can read is not evidence of freshness.
                # Falling through to the limit would compare against a date
                # this process invented.
                continue
            stale = (moment - taken).days > max_age_days
        if stale:
            store.set_evidence_state(row["evidence_id"], EvidenceState.STALE.value)
            changed.append(row["evidence_id"])
    return changed


def _moment(raw: Any) -> datetime | None:
    """Parse a stored timestamp, always aware, or None when it will not read.

    Defect DEF-91. `EvidenceRecord.valid_until` is a public field with no
    validation, and a naive value - `2026-01-01T00:00:00`, which is what a
    person writing one by hand produces - made the comparison raise
    `TypeError: can't compare offset-naive and offset-aware datetimes` and took
    `actaira watch --max-age-days N` down with a traceback. The old `except
    ValueError` did not catch it, because the parse succeeded and the
    comparison was the thing that failed.

    A value with no zone is read as UTC, which is what every timestamp this
    module writes is, and what a person writing one by hand means.
    """
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
