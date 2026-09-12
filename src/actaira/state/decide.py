"""Whether a decision that was made still describes the thing in front of you.

Design note D-245. A policy decision is a historical fact: on a date, under a
policy with a digest, from named inputs, this tool answered ALLOW, DENY or
REVIEW. That fact never changes, and nothing in this module writes to the
`decisions` table. An ALLOW recorded in March is still an ALLOW in September
even when every artifact it was about has been replaced, because what was
decided and what is true now are two different questions and a tool that
overwrites the first with the second destroys the only record of what was
approved.

The second question is the one this module answers, and it has its own
three-valued vocabulary kept deliberately distinct from the decision's:

  CURRENT                 every input this decision recorded still describes
                          the subject it described then
  REQUIRES_REASSESSMENT   at least one input demonstrably no longer does, and
                          the store can say which and why
  UNDETERMINED            the store cannot tell - because the decision
                          recorded no dependencies, or because an input names
                          something this workspace does not hold

Three properties are load-bearing.

**REQUIRES_REASSESSMENT is never reached by inference.** It needs a row: an
evidence record whose state is not VALID, or a subject whose recorded digest
differs from the one the decision named. "The model changed recently" is not a
reason; `{"reason": "evidence_superseded", "evidence_id": "ev_...",
"was": "sha256:OLD", "now": "sha256:NEW"}` is. Every reason this module
produces is a mapping a caller can act on without reading prose, which is what
§18 of the specification asks for and what a score would destroy.

**An old decision is UNDETERMINED, not CURRENT.** Decisions written before
schema version 3 carry no dependency rows. Reading "no inputs" as "nothing it
depended on has changed" would mark exactly the decisions this release knows
least about as the ones needing no attention.

**Absence is not falsehood, one level down as well.** An input naming an
evidence record this store does not hold contributes an undetermined reason,
never a reassessment: a record that was never here is not a record that was
withdrawn.

This is not a second policy engine. It produces no verdict about the subject,
no severity and no number. It answers one question about one stored row.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .evidence import EvidenceState

# What a decision's applicability to present reality is. Distinct strings from
# `Decision` on purpose: a reader who confuses "allow" with "current" has
# confused what was decided with whether it still applies, and identical
# vocabularies are how that confusion gets made.
CURRENT = "current"
REQUIRES_REASSESSMENT = "requires_reassessment"
UNDETERMINED = "undetermined"

VALIDITIES = (CURRENT, REQUIRES_REASSESSMENT, UNDETERMINED)

# The two kinds of thing a decision can rest on. `subject` says it was made
# about this asset at this digest; `evidence` says it read this record. They
# are separate because they stop describing reality for different reasons and
# a reader has to be able to tell which happened.
ROLE_SUBJECT = "subject"
ROLE_EVIDENCE = "evidence"
ROLES = (ROLE_EVIDENCE, ROLE_SUBJECT)


@dataclass(frozen=True)
class DecisionInput:
    """One thing a decision rested on, as it was at the moment it was made."""

    role: str
    ref: str
    subject_id: str = ""
    subject_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "ref": self.ref,
            "subject_id": self.subject_id,
            "subject_digest": self.subject_digest,
        }


def subject_input(subject_id: str, subject_digest: str) -> DecisionInput:
    return DecisionInput(
        role=ROLE_SUBJECT, ref=subject_id, subject_id=subject_id, subject_digest=subject_digest
    )


def evidence_input(evidence_id: str, subject_id: str, subject_digest: str) -> DecisionInput:
    return DecisionInput(
        role=ROLE_EVIDENCE, ref=evidence_id, subject_id=subject_id, subject_digest=subject_digest
    )


@dataclass
class Validity:
    """One stored decision, what it said, and whether that still applies."""

    decision_id: str
    decision: str
    policy_digest: str
    decided_on: str
    status: str
    reasons: list[dict[str, Any]] = field(default_factory=list)
    inputs: int = 0

    @property
    def stands(self) -> bool:
        """Whether nothing about this decision needs a second look.

        Only CURRENT does. UNDETERMINED is not a softer yes: it is the answer
        that says this store cannot support either conclusion, and a caller
        that treated it as a pass would have turned a gap into an assurance.
        """
        return self.status == CURRENT

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            # The historical answer, unchanged and named as historical, so a
            # reader is never invited to think this module rewrote it.
            "decision": self.decision,
            "policy_digest": self.policy_digest,
            "decided_on": self.decided_on,
            "validity": self.status,
            "inputs": self.inputs,
            "reasons": list(self.reasons),
        }


def validity(store: Any, decision_row: dict[str, Any]) -> Validity:
    """Read one decision's recorded inputs and say whether they still hold.

    Reads only. Every branch that could conclude REQUIRES_REASSESSMENT has to
    produce the row it concluded it from, and every branch that cannot produce
    one concludes UNDETERMINED instead.
    """
    decision_id = str(decision_row["decision_id"])
    inputs = store.decision_inputs(decision_id)
    result = Validity(
        decision_id=decision_id,
        decision=str(decision_row["decision"]),
        policy_digest=str(decision_row["policy_digest"]),
        decided_on=str(decision_row["observed_at"]),
        status=UNDETERMINED,
        inputs=len(inputs),
    )

    if not inputs:
        result.reasons.append(
            {
                "reason": "no_recorded_inputs",
                "detail": "this decision was filed before the store recorded what a decision "
                "depended on, so nothing here can say whether its inputs still describe "
                "the subject",
            }
        )
        return result

    reassess: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    for row in inputs:
        verdict, reason = _check(store, row)
        if verdict == REQUIRES_REASSESSMENT:
            reassess.append(reason)
        elif verdict == UNDETERMINED:
            unknown.append(reason)

    # Order matters and this is the whole precedence rule. A single proven
    # input that no longer describes reality settles it, whatever else is
    # unknown: the decision needs a second look and this module can say why.
    # Only when nothing is proven do the gaps decide, and a gap is never a
    # pass.
    if reassess:
        result.status = REQUIRES_REASSESSMENT
        result.reasons = reassess + unknown
    elif unknown:
        result.status = UNDETERMINED
        result.reasons = unknown
    else:
        result.status = CURRENT
    return result


def _check(store: Any, row: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    role = str(row["role"])
    ref = str(row["ref"])
    if role == ROLE_EVIDENCE:
        return _check_evidence(store, ref, row)
    if role == ROLE_SUBJECT:
        return _check_subject(store, ref, row)
    # A role this release does not know was written by one that did. Refusing
    # to guess what it meant is the same rule the store applies to a newer
    # schema version.
    return UNDETERMINED, {
        "reason": "unknown_input_role",
        "role": role,
        "ref": ref,
        "detail": "this input was recorded by a release that knew a kind of dependency "
        "this one does not",
    }


def _check_evidence(store: Any, ref: str, row: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    record = store.evidence(ref)
    if record is None:
        return UNDETERMINED, {
            "reason": "evidence_not_in_store",
            "evidence_id": ref,
            "subject": row["subject_id"],
            "detail": "this decision named an evidence record this workspace does not hold. "
            "A record that was never here is not a record that was withdrawn",
        }
    state = str(record["state"])
    if state == EvidenceState.VALID.value:
        return CURRENT, {}
    # The four states are four different things and the reason says which,
    # because "stale" asks somebody to re-observe and "revoked" asks somebody
    # to stop relying on a signer. See D-223.
    reason: dict[str, Any] = {
        "reason": "evidence_" + state,
        "evidence_id": ref,
        "state": state,
        "subject": record["subject_id"],
        "was": record["subject_digest"] or None,
    }
    current = _recorded_digest(store, str(record["subject_id"]))
    if current is not None:
        reason["now"] = current
    return REQUIRES_REASSESSMENT, reason


def _check_subject(store: Any, ref: str, row: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    was = str(row["subject_digest"] or "")
    if not was:
        return UNDETERMINED, {
            "reason": "subject_digest_not_recorded",
            "subject": ref,
            "detail": "the decision named this subject without a digest, so there is nothing "
            "to compare the current one against",
        }
    asset = store.asset(ref)
    if asset is None:
        return UNDETERMINED, {
            "reason": "subject_not_in_store",
            "subject": ref,
            "was": was,
            "detail": "this workspace holds no asset by that id, so it cannot say whether the "
            "subject still has the digest this decision was made about",
        }
    now = str(asset["digest"] or "")
    if not now:
        return UNDETERMINED, {
            "reason": "subject_digest_unknown",
            "subject": ref,
            "was": was,
            "detail": "the asset is recorded and carries no digest, so the two cannot be "
            "compared",
        }
    if now == was:
        return CURRENT, {}
    return REQUIRES_REASSESSMENT, {
        "reason": "subject_digest_changed",
        "subject": ref,
        "was": was,
        "now": now,
    }


def _recorded_digest(store: Any, subject_id: str) -> str | None:
    asset = store.asset(subject_id)
    if asset is None:
        return None
    return str(asset["digest"]) or None


def review(store: Any) -> list[Validity]:
    """Every stored decision with its current applicability, oldest first.

    The order the store returns them in, which is the order they were made.
    Sorting by status would put the interesting ones first and make two runs
    over the same store print different sequences the moment one record
    changed state.
    """
    return [validity(store, row) for row in store.decisions()]


def counts(rows: list[Validity]) -> dict[str, int]:
    """How many decisions are in each validity, every value present.

    Every key appears even at zero. A summary whose absent keys mean zero is
    one where a reader cannot tell "none require reassessment" from "this
    build forgot to compute it".
    """
    tally = dict.fromkeys(VALIDITIES, 0)
    for row in rows:
        tally[row.status] = tally.get(row.status, 0) + 1
    return tally
