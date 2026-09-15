"""The assurance receipt: a signed statement of what was observed, and when.

Design note D-120. This is the one output of this tool that is meant to leave
the organisation that produced it. A scan report is for the person running the
scan; an attestation package is for an auditor with the artifacts to hand. A
receipt is for the party on the other side of a supply relationship, who has
neither, and who needs to answer one question: at that moment, under that
policy, what had actually been established about this thing?

Four properties make that answerable, and all four are refusals as much as
features.

It is not a certification. Nothing here says an artifact is safe, compliant or
approved. It says what was looked at, what was found, which surfaces were
covered, which policy was applied and what that policy decided. A reader who
disagrees with the policy can say so, because the policy's digest is in the
document.

It is not a score. There is no percentage and no grade. Counts of findings by
severity are counts, and coverage states are states; neither is combined into
a number, because the moment a number exists somebody tunes the threshold
instead of fixing the artifact.

It is verifiable without this tool's cooperation. The signature covers the
canonical JSON of the whole document minus the signature block, which is a
transformation a third party can implement in twenty lines. `actaira receipt
verify` is a convenience, not a dependency.

It says what it does not know. `not_assessed` surfaces are printed, not
omitted; an unevaluable policy condition is carried through as REVIEW; a
signature that verified against a key nobody vouched for is reported as
verified and untrusted, separately. A receipt that only listed good news would
be a marketing document with a signature on it.
"""
from __future__ import annotations

import base64
import hashlib
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from . import __version__
from .attest.signing import KeyPair, fingerprint_of, public_from_b64
from .attest.signing import verify as verify_signature
from .coverage import Coverage, CoverageState, Surface
from .model import ArtifactReport, Severity, artifact_name, canonical_json

SCHEMA_VERSION = "assurance-receipt/v2"

# v1 stays readable forever. `docs/COMPATIBILITY.md` promises it, and the
# promise is the whole point of publishing a contract: a receipt issued by
# 2.1.0 is not wrong, it is old, and a verifier that refused it would make an
# upgrade of this tool break every artifact the previous one signed.
#
# The asymmetry is deliberate and it runs one way only. This release reads v1
# and v2 and writes v2. Nothing may emit v1 again - a producer that can still
# write the old shape will, in some branch nobody exercised, and the consumer
# on the other end will read the old meaning out of a new document.
LEGACY_SCHEMA_VERSIONS = ("assurance-receipt/v1",)
READABLE_SCHEMA_VERSIONS = (*LEGACY_SCHEMA_VERSIONS, SCHEMA_VERSION)
SIGNATURE_KEY = "signature"


def subject_id(report: ArtifactReport) -> str:
    return f"sha256:{report.sha256}"


def merge_coverage(reports: list[ArtifactReport]) -> Coverage:
    """The coverage of a set, which is the weakest coverage in it.

    A release is every artifact in it. Reporting the best surface state across
    a set, or the mean of them, would let one unreadable file hide behind
    nine clean ones - and the unreadable file is the one the reader needs to
    know about. `Coverage.set` already keeps the worst per surface, so folding
    every report into one matrix gives exactly that.
    """
    merged = Coverage()
    for report in reports:
        for entry in report.coverage.ordered():
            merged.set(entry)
    return merged


def _severity_counts(reports: list[ArtifactReport]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for report in reports:
        for finding in report.findings:
            counter[finding.severity.value] += 1
    # Every severity appears, including the zeroes. A document that omitted
    # "critical": 0 would read differently from one that stated it, and the
    # difference between "none found" and "not reported" is the whole point.
    return {severity.value: counter.get(severity.value, 0) for severity in Severity}


def build(
    reports: list[ArtifactReport],
    *,
    observed_at: datetime,
    policy_decision: dict[str, Any] | None = None,
    attestation: dict[str, Any] | None = None,
    governance: dict[str, Any] | None = None,
    system: str = "",
    subjects: list[Any] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    snapshots: list[dict[str, Any]] | None = None,
    graph: dict[str, Any] | None = None,
    trust: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble an unsigned receipt from what a run established.

    Design note D-228. v1 was a document about a list of `ArtifactReport`s. It
    could carry a policy decision and the name of a system, and it could not
    say what that system was made of: no bundle, no agent, no relations, no
    evidence, no record of which revision of which source the bytes came from.
    The signature was sound and the scope was narrow, so "this system was
    assured" had to be assembled by a person out of several receipts and a
    wiki page.

    v2 keeps every v1 field and adds `typed_subjects`, which is the list of
    `SubjectRef`-shaped entries the policy layer decided over, plus references
    to the evidence, snapshots and graph behind them. Everything added is
    inside the signature, so mutating a graph or an evidence reference breaks
    it exactly like mutating a finding does.

    `reports` stays first and stays positional: every 2.1 caller passes it and
    keeps working, and `subjects` is what a caller with bundles and agents
    uses instead.
    """
    merged = merge_coverage(reports)
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": "actaira",
        "tool_version": __version__,
        "observed_at": observed_at.isoformat(timespec="seconds"),
        "subjects": [
            {
                "id": subject_id(report),
                "name": artifact_name(report.path),
                "format": report.detected_format,
                "format_confidence": report.format_confidence,
                "size_bytes": report.size_bytes,
                "verdict": report.verdict.value,
                "coverage": report.coverage.to_dict(),
                "findings": sorted(
                    {finding.rule_id for finding in report.findings}
                ),
                "imported_callables": sorted(report.imported_callables),
            }
            for report in reports
        ],
        "coverage": merged.to_dict(),
        "findings_by_severity": _severity_counts(reports),
        "supply_chain": _supply_chain(attestation),
    }
    if system:
        document["system"] = system
    if subjects:
        document["typed_subjects"] = _typed_subjects(subjects)
    if evidence:
        # Referenced by id and digest rather than embedded. The store holds the
        # records; a receipt that inlined them would be a second copy that can
        # disagree with the first, and the reference is what a verifier needs
        # to ask "is this still valid" - a question a snapshot of the record
        # cannot answer.
        document["evidence"] = sorted(
            (
                {
                    "evidence_id": item["evidence_id"],
                    "kind": item.get("kind", ""),
                    "state": item.get("state", ""),
                    "digest": item.get("digest", ""),
                    "observed_at": item.get("observed_at", ""),
                }
                for item in evidence
            ),
            key=lambda row: row["evidence_id"],
        )
    if snapshots:
        document["snapshots"] = sorted(
            (
                {
                    "source": item.get("source", ""),
                    "revision": item.get("revision", ""),
                    "snapshot_digest": item.get("snapshot_digest", ""),
                    "listing_complete": item.get("listing_complete"),
                }
                for item in snapshots
            ),
            key=lambda row: (row["source"], row["snapshot_digest"]),
        )
    if graph is not None:
        document["graph"] = {
            "nodes": len(graph.get("nodes", [])),
            "edges": len(graph.get("edges", [])),
            "digest": _digest_of(graph),
        }
    if trust is not None:
        document["trust"] = trust
    if policy_decision is not None:
        document["policy_decision"] = policy_decision
    if governance is not None:
        document["governance"] = governance
    document["states_what_it_does_not_cover"] = _not_covered(merged)
    return document


def _digest_of(payload: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(payload)).hexdigest()


def _typed_subjects(subjects: list[Any]) -> list[dict[str, Any]]:
    """One entry per subject the decision was about, whatever kind it is.

    Per-subject provenance is here rather than at the top of the document
    because a receipt over four subjects from three sources has three
    provenances, and a single top-level `source` field would have to pick one
    - which is how a receipt ends up naming a registry that served one of its
    subjects and implying it served them all.
    """
    rows: list[dict[str, Any]] = []
    for claims in subjects:
        reference = getattr(claims, "ref", None)
        if reference is None:
            # Defect DEF-93: this used to `continue`, so a receipt over four
            # subjects could list three and say nothing about the fourth. A
            # document that quietly covers less than it was asked to is the
            # failure mode this whole file exists to rule out.
            raise ValueError(
                "a receipt subject has no reference, so nothing identifies what it is about. "
                "Build claims with one of the `subject.for_*` helpers."
            )
        entry: dict[str, Any] = {**reference.to_dict()}
        if getattr(claims, "provenance", None):
            entry["provenance"] = dict(claims.provenance)
        bundle = getattr(claims, "bundle", None)
        if bundle is not None:
            identity = bundle.content_identity()
            # The field that stops a receipt from claiming "the same model" on
            # a repository nobody hashed. See D-200.
            entry["content_identity"] = {
                "state": identity["state"],
                "digest": identity["digest"],
                "binding_source": identity["binding_source"],
            }
            entry["findings"] = sorted({finding.rule_id for finding in bundle.findings})
        agent = getattr(claims, "agent", None)
        if agent is not None:
            from .conformance import assess

            entry["effects"] = sorted(effect.value for effect in agent.effects)
            entry["findings"] = sorted({finding.rule_id for finding in assess(agent)})
            entry["open_attack_paths"] = sum(
                1 for path in getattr(claims, "attack_paths", []) if not path.get("broken")
            )
        if getattr(claims, "relations", None):
            entry["relations"] = len(claims.relations)
        if getattr(claims, "evidence", None):
            entry["evidence"] = sorted(
                str(item.get("evidence_id", "")) for item in claims.evidence
            )
        rows.append(entry)
    return sorted(rows, key=lambda row: (row["kind"], row["id"]))


def _supply_chain(attestation: dict[str, Any] | None) -> dict[str, Any]:
    """The two questions, kept apart.

    `signature_verified` says the bytes were not altered since signing.
    `signer_trusted` says the key belongs to somebody this environment
    accepts. A receipt that merged them into one "signed: true" would let a
    self-signed package read exactly like one signed by a known publisher,
    which is the confusion this whole layer exists to prevent. When no trust
    decision was made, the field says so rather than defaulting either way.
    """
    if attestation is None:
        return {
            "attestation": "none",
            "signature_verified": None,
            "signer_trusted": None,
            "note": "this run was not given an attestation package, so nothing is claimed about provenance",
        }
    payload: dict[str, Any] = {
        "attestation": "present",
        "signature_verified": bool(attestation.get("signature_verified")),
        "signer_trusted": attestation.get("signer_trusted"),
    }
    if payload["signer_trusted"] is None:
        payload["note"] = "no trust anchor was supplied, so the signer is verified but not vouched for"
    if attestation.get("time_anchor_trust"):
        payload["time_anchor_trust"] = attestation["time_anchor_trust"]
    return payload


def _not_covered(merged: Coverage) -> list[dict[str, str]]:
    """The explicit list of what this receipt is silent about.

    Printed rather than omitted. A document that listed only the surfaces it
    covered would let a reader assume the rest were fine, and the most common
    way an assurance artifact misleads is by being read as exhaustive.
    """
    rows = []
    for surface in Surface:
        state = merged.state(surface)
        if state is CoverageState.COMPLETE:
            continue
        rows.append({"surface": surface.value, "state": state.value, "reason": merged.reason(surface)})
    return rows


# --------------------------------------------------------------------------
# Signing and verifying
# --------------------------------------------------------------------------


# Domain separation for the receipt signature. The same default key signs the
# package manifest and this, and Ed25519 over a bare 32-byte digest carries no
# statement of which one it meant. `dsse.pae` already refuses that class of
# confusion; this signer did not. Rejected: relying on the two digests being
# over different document shapes, which is an argument about content, not about
# what the signature says. The trailing NUL cannot occur in the label.
RECEIPT_SIGNING_CONTEXT = b"actaira.receipt/receipt-sha256/v1\x00"
SIGNATURE_SUBJECT_NOTE = (
    "RECEIPT_SIGNING_CONTEXT || sha256 of the canonical JSON of this document "
    "without its signature block"
)


def signing_subject(document: dict[str, Any]) -> bytes:
    """The exact bytes hashed into a signature: the document without its signature.

    Twenty lines for a third party to reimplement, which is the requirement.
    `canonical_json` is sorted keys, compact separators, UTF-8, no NaN - the
    same transformation every other hash in this repository uses, documented
    in D-03 so that a verifier does not have to read this module to write
    their own.
    """
    return canonical_json({key: value for key, value in document.items() if key != SIGNATURE_KEY})


def signed_bytes(receipt_sha256: str) -> bytes:
    """What the key actually signs, context included. The other half of the pair."""
    return RECEIPT_SIGNING_CONTEXT + bytes.fromhex(receipt_sha256)


def sign(document: dict[str, Any], keypair: KeyPair) -> dict[str, Any]:
    subject = signing_subject(document)
    digest = hashlib.sha256(subject).hexdigest()
    signed = dict(document)
    signed[SIGNATURE_KEY] = {
        "algorithm": "ed25519",
        "over": SIGNATURE_SUBJECT_NOTE,
        "receipt_sha256": digest,
        "key_id": keypair.key_id,
        "public_key_b64": keypair.public_b64,
        "fingerprint_sha256": keypair.fingerprint,
        "value_b64": base64.b64encode(keypair.sign(signed_bytes(digest))).decode("ascii"),
    }
    return signed


@dataclass
class ReceiptVerification:
    """What a verifier can say, with the two questions kept apart."""

    ok: bool = True
    signature_verified: bool = False
    signer_trusted: bool | None = None
    receipt_sha256: str = ""
    key_fingerprint: str = ""
    schema_version: str = ""
    problems: list[str] = field(default_factory=list)
    subjects: list[str] = field(default_factory=list)
    decision: str | None = None

    def fail(self, problem: str) -> None:
        self.ok = False
        self.problems.append(problem)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "signature_verified": self.signature_verified,
            "signer_trusted": self.signer_trusted,
            "receipt_sha256": self.receipt_sha256,
            "key_fingerprint_sha256": self.key_fingerprint,
            "schema_version": self.schema_version,
            "subjects": self.subjects,
            "decision": self.decision,
            "problems": self.problems,
        }


def verify(
    document: dict[str, Any],
    *,
    trusted_fingerprints: set[str] | None = None,
) -> ReceiptVerification:
    """Check a receipt offline, with nothing but the document and a keyring.

    No network, no filesystem, no clock. The clock matters: a verifier that
    rejected a receipt for being old would be making a policy decision on the
    reader's behalf, and freshness is a property of the question being asked,
    not of the document.
    """
    result = ReceiptVerification()
    result.schema_version = str(document.get("schema_version", ""))
    if result.schema_version not in READABLE_SCHEMA_VERSIONS:
        # Refused, not best-effort. A receipt from a version this reader does
        # not know may mean something different by a field it thinks it
        # understands, and a partial check reported as a pass is worse than no
        # check. The published versions are accepted forever; an unpublished
        # one is not accepted at all.
        result.fail(
            f"this verifier understands {', '.join(READABLE_SCHEMA_VERSIONS)}, the document says "
            f"{result.schema_version or 'nothing'}"
        )
        return result

    block = document.get(SIGNATURE_KEY)
    if not isinstance(block, dict):
        result.fail("the receipt carries no signature block")
        return result

    recomputed = hashlib.sha256(signing_subject(document)).hexdigest()
    result.receipt_sha256 = recomputed
    stated = str(block.get("receipt_sha256", ""))
    if stated != recomputed:
        # The document was edited after signing. Reported before the signature
        # check so the reader learns which of the two failed.
        result.fail(f"the receipt's contents do not match its stated digest ({stated or 'absent'})")

    try:
        public = public_from_b64(str(block.get("public_key_b64", "")))
    except Exception as exc:
        result.fail(f"the embedded public key does not load: {type(exc).__name__}")
        return result

    fingerprint = fingerprint_of(public)
    result.key_fingerprint = fingerprint
    stated_fingerprint = str(block.get("fingerprint_sha256", ""))
    if stated_fingerprint and stated_fingerprint != fingerprint:
        result.fail("the signature block's fingerprint is not the fingerprint of the key it carries")

    try:
        signature = base64.b64decode(str(block.get("value_b64", "")), validate=True)
    except Exception:
        result.fail("the signature is not valid base64")
        return result

    result.signature_verified = verify_signature(public, signature, signed_bytes(recomputed))
    if not result.signature_verified:
        result.fail("the signature does not verify over this document")

    if trusted_fingerprints is not None:
        # Separate from the signature check, and only answered when the caller
        # supplied anchors. "I have no opinion about this key" is a third
        # state, and collapsing it into False would make an unchecked receipt
        # indistinguishable from a rejected one.
        result.signer_trusted = fingerprint in trusted_fingerprints
        if not result.signer_trusted:
            result.fail(f"the signing key {fingerprint[:16]} is not in the supplied trust anchors")

    result.subjects = [str(item.get("id", "")) for item in document.get("subjects", [])]
    decision = document.get("policy_decision")
    if isinstance(decision, dict):
        result.decision = str(decision.get("decision", ""))
    return result


def subject_digests_match(document: dict[str, Any], reports: list[ArtifactReport]) -> list[str]:
    """Which subjects in the receipt are not the artifacts in front of us.

    Optional, and separate from `verify`, because a receipt is verifiable
    without the artifacts and usually read without them. When they are to
    hand this is the check that closes the loop: a valid signature over a
    document about different files is a valid signature about nothing.
    """
    stated = {str(item.get("id", "")) for item in document.get("subjects", [])}
    present = {subject_id(report) for report in reports}
    problems = []
    for missing in sorted(stated - present):
        problems.append(f"the receipt names {missing}, which is not among the artifacts supplied")
    for extra in sorted(present - stated):
        problems.append(f"{extra} was supplied but the receipt does not mention it")
    return problems


def observed_on(document: dict[str, Any]) -> date | None:
    raw = str(document.get("observed_at", ""))
    try:
        return datetime.fromisoformat(raw).date()
    except ValueError:
        return None
