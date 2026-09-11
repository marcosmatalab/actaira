"""Signed evidence dossier: the assessment, bound to the artifacts it describes.

Design note D-32. An assessment that is not bound to the artifacts it was
computed from is a document about nothing: change a model file and the
document still says what it said. So the dossier is written into the same
attestation package as the inspections, its own entry in the same hash
chain, covered by the same signature and the same optional time anchor.

Consequence, and it is the point: a reader who verifies the package gets the
inspection reports and the governance mapping as one indivisible object. They
cannot be handed a favourable assessment that quietly refers to a different
set of files, because the assessment entry records the subject digest of
every artifact it drew on and the verifier recomputes them.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

from .. import __version__
from ..attest import chain, package, signing
from ..bom.cyclonedx import build_bom
from ..model import ArtifactReport
from .assess import assess, gaps, unread_artifacts
from .catalog import Role

DOSSIER_KIND = "governance.evidence.v1"


def build_dossier(
    reports: list[ArtifactReport],
    on: date,
    role: Role,
    has_attestation: bool = True,
    has_consistency_proof: bool = False,
    has_time_anchor: bool = False,
) -> dict[str, Any]:
    assessment = assess(
        reports,
        on=on,
        role=role,
        has_attestation=has_attestation,
        has_consistency_proof=has_consistency_proof,
        has_time_anchor=has_time_anchor,
        has_bom=True,
    )
    return {
        "kind": DOSSIER_KIND,
        "tool": "actaira",
        "tool_version": __version__,
        "framework": "Regulation (EU) 2024/1689",
        "subjects": sorted(report.sha256 for report in reports),
        "assessment": assessment.to_dict(),
        "gaps_this_evidence_does_not_address": [
            {"id": item.id, "article": item.article, "title": item.title}
            for item in gaps(assessment)
        ],
        "artifacts_not_fully_read": unread_artifacts(reports),
    }


def write_evidence_package(
    out_path: Path,
    reports: list[ArtifactReport],
    keypair: signing.KeyPair,
    on: date,
    role: Role,
    previous_entries: list[chain.Entry] | None = None,
    tsa_url: str | None = None,
) -> tuple[package.PackageResult, dict[str, Any]]:
    """One inspection entry per artifact, then one dossier entry over all of them."""
    entries: list[chain.Entry] = list(previous_entries or [])
    boms: dict[str, dict[str, Any]] = {}
    for report in reports:
        chain.append(entries, report.sha256, report.to_dict())
        boms[report.sha256] = build_bom([report])

    dossier = build_dossier(
        reports,
        on=on,
        role=role,
        has_attestation=True,
        has_consistency_proof=bool(previous_entries),
        has_time_anchor=bool(tsa_url),
    )
    # The dossier's subject is the digest of the set it covers, so the entry
    # cannot be lifted out and reattached to a different collection.
    chain.append(entries, _subject_digest(reports), dossier)

    kwargs: dict[str, Any] = {}
    if tsa_url:
        kwargs["tsa_url"] = tsa_url
    result = package.write_package(out_path, entries, keypair, boms, **kwargs)
    return result, dossier


def _subject_digest(reports: list[ArtifactReport]) -> str:
    import hashlib

    digest = hashlib.sha256()
    for sha in sorted(report.sha256 for report in reports):
        digest.update(bytes.fromhex(sha))
    return digest.hexdigest()
