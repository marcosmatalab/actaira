"""Map technical evidence to obligations. No score, by construction.

Design note D-31. The output of this module is a list of obligations with,
for each, what the supplied evidence contributes and what it does not. There
is no aggregate, no percentage and no traffic light over the set, and that
is a design decision rather than an omission.

The reason is specific and comes from having audited a compliance platform
that did the opposite. A percentage over a set of obligations requires two
things that do not exist: a weighting between obligations of different
kinds, and a way to tell "evidence exists" from "evidence is adequate". Both
have to be invented, and once invented the number is presented to auditors as
though it were measured. So this module reports coverage per obligation and
refuses to add them up.

What it does compute is a `gaps` list: obligations that apply on the date
given, whose evidence Actaira does not provide. That list gets longer as the
catalogue grows, which is the correct direction for an honest tool.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any

from ..model import ArtifactReport, Verdict, artifact_name
from .catalog import ALL_OBLIGATIONS, Coverage, Obligation, Role


@dataclass
class EvidenceItem:
    """One thing the evidence set actually contains."""

    kind: str  # artifact_inspection | ml_bom | attestation | consistency_proof | time_anchor
    subject: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "subject": self.subject, "detail": self.detail}


@dataclass
class ObligationAssessment:
    obligation: Obligation
    applicable: bool
    evidence: list[EvidenceItem] = field(default_factory=list)

    @property
    def state(self) -> str:
        if not self.applicable:
            return "not_yet_applicable"
        if self.obligation.coverage is Coverage.NOT_COVERED:
            return "outside_this_tool"
        if not self.evidence:
            return "no_evidence_supplied"
        return f"evidence_{self.obligation.coverage.value}"

    def to_dict(self) -> dict[str, Any]:
        payload = self.obligation.to_dict()
        payload.update(
            {
                "applicable": self.applicable,
                "state": self.state,
                "evidence": [item.to_dict() for item in self.evidence],
                "evidence_count": len(self.evidence),
            }
        )
        return payload


@dataclass
class Assessment:
    on: date
    role: Role
    assessments: list[ObligationAssessment] = field(default_factory=list)
    artifacts: int = 0
    disclaimer: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessed_on": self.on.isoformat(),
            "role": self.role.value,
            "artifacts": self.artifacts,
            "obligations": [item.to_dict() for item in self.assessments],
            "counts_not_a_score": {
                "applicable": sum(1 for a in self.assessments if a.applicable),
                "with_evidence": sum(1 for a in self.assessments if a.applicable and a.evidence),
                "outside_this_tool": sum(
                    1 for a in self.assessments
                    if a.applicable and a.obligation.coverage is Coverage.NOT_COVERED
                ),
            },
            "disclaimer": self.disclaimer,
        }


DISCLAIMER = (
    "This is a record of technical evidence, not a compliance opinion. It states "
    "which obligations the supplied evidence touches and, for each, what that "
    "evidence does not establish. It contains no score, because a percentage over "
    "obligations of different kinds would have to be invented. Whether an "
    "organisation complies is a legal question about a system in its context, and "
    "no tool that reads model files can answer it."
)


def assess(
    reports: list[ArtifactReport],
    on: date,
    role: Role = Role.PROVIDER,
    has_attestation: bool = False,
    has_consistency_proof: bool = False,
    has_time_anchor: bool = False,
    has_bom: bool = False,
) -> Assessment:
    """Build the evidence map for a set of inspected artifacts."""
    evidence = _collect(reports, has_attestation, has_consistency_proof, has_time_anchor, has_bom)
    result = Assessment(on=on, role=role, artifacts=len(reports), disclaimer=DISCLAIMER)

    for obligation in ALL_OBLIGATIONS:
        if not _binds(obligation, role):
            continue
        applicable = obligation.applies_from <= on
        matched = [item for item in evidence if item.kind in _EVIDENCE_FOR.get(obligation.id, ())]
        result.assessments.append(ObligationAssessment(obligation, applicable, matched))

    result.assessments.sort(
        key=lambda item: (not item.applicable, item.obligation.applies_from, item.obligation.id)
    )
    return result


# Which kinds of evidence bear on which obligation. Deliberately sparse: an
# obligation absent from this map gets no evidence, which is the correct
# outcome for most of the regulation.
#
# AIA-12 used to be in here, drawing the ledger, the consistency proof and the
# time anchor. It is gone because Art. 12 asks the high-risk *system* to be
# able to record its own events, and a ledger of this tool's inspections is
# not that. Those three kinds now land only on AIA-15, whose entry claims
# "a verifiable record of which artifact was deployed": that is what an
# append-only ledger with a consistency proof and a time anchor actually is.
_EVIDENCE_FOR: dict[str, tuple[str, ...]] = {
    "AIA-53-1a": ("artifact_inspection", "ml_bom"),
    "AIA-53-1b": ("ml_bom", "attestation", "artifact_inspection"),
    "AIA-55": ("artifact_inspection", "attestation"),
    "AIA-50-2": ("artifact_inspection", "attestation"),
    "AIA-11": ("artifact_inspection", "ml_bom"),
    "AIA-15": ("artifact_inspection", "attestation", "consistency_proof", "time_anchor"),
}


def _binds(obligation: Obligation, role: Role) -> bool:
    """Whether `obligation` binds someone acting in `role`.

    One inheritance, and it is the only one the Regulation supports. A
    provider of a general-purpose AI model with systemic risk is still a
    provider of a general-purpose AI model, so Art. 55 is additional to
    Art. 52 to 54 rather than a substitute for them.

    There used to be a second: PROVIDER_GPAI inherited the PROVIDER rows, on
    the reasoning that a GPAI provider placing a system on the market is a
    provider. The premise is true and the inference is not. Art. 3(63) defines
    the provider of a general-purpose AI *model* and Art. 3(3) the provider of
    an AI *system*; Chapter IV binds the second. Publishing weights does not
    place a system on the market, so the rule handed Art. 50(1) and 50(2) to
    people who may owe neither. Someone who is both declares both.
    """
    if obligation.role is Role.ANY or role is Role.ANY:
        return True
    if obligation.role is role:
        return True
    return (
        role is Role.PROVIDER_GPAI_SYSTEMIC
        and obligation.role is Role.PROVIDER_GPAI
    )


def _was_read(report: ArtifactReport) -> bool:
    """Whether anything observed in this artifact can be used as evidence.

    One predicate, used both to build the evidence list and to build
    `unread_artifacts`, so the two can never disagree about the same file.
    An artifact the inspector could not read through is not weak evidence,
    it is evidence about nothing.
    """
    return report.verdict is not Verdict.INCONCLUSIVE and bool(report.metadata.get("fully_read", False))


def _collect(
    reports: list[ArtifactReport],
    has_attestation: bool,
    has_consistency_proof: bool,
    has_time_anchor: bool,
    has_bom: bool,
) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    # Only artifacts that were read through become evidence. An inconclusive
    # or truncated read used to produce an `artifact_inspection` item carrying
    # `fully_read: false`, which counted as evidence for every obligation the
    # map points at it: exactly the quiet promotion of an unread file to a
    # supporting document that `unread_artifacts` exists to prevent.
    readable = [report for report in reports if _was_read(report)]
    for report in readable:
        items.append(
            EvidenceItem(
                kind="artifact_inspection",
                subject=report.sha256,
                detail={
                    "path": artifact_name(report.path),
                    "format": report.detected_format,
                    "verdict": report.verdict.value,
                    "fully_read": True,
                    "tensors": len(report.tensors),
                    "parameters_observed": report.metadata.get("total_parameters"),
                },
            )
        )
    if has_bom and readable:
        items.append(EvidenceItem(kind="ml_bom", subject="cyclonedx-1.6", detail={"components": len(readable)}))
    if has_attestation:
        items.append(EvidenceItem(kind="attestation", subject="ed25519", detail={}))
    if has_consistency_proof:
        items.append(EvidenceItem(kind="consistency_proof", subject="rfc6962", detail={}))
    if has_time_anchor:
        items.append(EvidenceItem(kind="time_anchor", subject="rfc3161", detail={}))
    return items


def gaps(assessment: Assessment) -> list[Obligation]:
    """Applicable obligations this evidence does not address."""
    return [
        item.obligation
        for item in assessment.assessments
        if item.applicable and not item.evidence
    ]


def unread_artifacts(reports: list[ArtifactReport]) -> list[str]:
    """Artifacts that could not be fully read.

    Surfaced in the governance layer because evidence derived from an
    artifact the tool could not read is evidence about nothing, and an
    inconclusive result must not quietly become a supporting document.
    """
    return [artifact_name(report.path) for report in reports if not _was_read(report)]
