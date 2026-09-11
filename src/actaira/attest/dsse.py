"""DSSE envelopes and in-toto statements, so an Actaira report can be read by
tools that never heard of Actaira.

Design note D-50, and the reason this module exists at all.

There is now an emerging standard for signing model artifacts. OpenSSF Model
Signing (OMS) is built on DSSE envelopes carrying in-toto statements, and
`sigstore/model-transparency` is its reference implementation. Actaira's own
package format (D-14) predates that and is better at some things than the
standard is: it carries a hash chain, a Merkle root, an optional RFC 3161
anchor and an ML-BOM, none of which a bare DSSE envelope has. What it is not
is *speakable*. A verifier that already knows how to check a DSSE envelope
cannot check an Actaira zip, and the cost of that is not theoretical: it is
the difference between being a step in someone's existing pipeline and being
a tool they have to adopt wholesale.

So the zip stays, and this module adds a second, smaller mouth that speaks
the standard. The two are not alternatives, and the rejected alternative was
to replace the package with an envelope: an envelope has nowhere to put a
consistency proof between two runs, and D-25's argument for append-only
evidence would have been thrown away to gain interoperability.

The complementarity worth stating plainly, because it is the whole reason a
model signature and an Actaira report are different objects: OMS and
`model-transparency` sign and verify integrity. They do not look inside the
artifact - the project says so itself - so a signed model is a model whose
publisher is known, not a model that is safe. Actaira never says who signed
anything; it says what is inside. "Signed by X" and "contains a pickle that
calls `posix.system`" are both true of the same file, and a supply chain
needs both sentences. Emitting the second one in the envelope format the
first one already uses is the cheapest way to put them side by side.

Design note D-51, on Pre-Authentication Encoding and a failure class it
removes for free.

DSSE does not sign the payload. It signs

    PAE(payloadType, payload) =
        "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload

where SP is a single 0x20 byte and LEN is the ASCII decimal *byte* length.
The length prefixes are what make the encoding injective: without them,
("ab", "c") and ("a", "bc") would produce the same signed bytes, and an
attacker who can pick both fields could move a byte across the boundary and
keep the signature valid. With them, every (type, payload) pair has exactly
one encoding, so a signature over one pair cannot be replayed as a signature
over another. The concrete attack the type field's presence stops is a
signature made over a JSON document being presented as a signature over the
same bytes read as some other media type, where a different parser reaches a
different meaning. `tests/test_dsse.py` runs both of those.

The collateral benefit, which is the part that argues for the format rather
than merely implementing it: in DSSE the payload lives *inside* the signed
envelope. There is no such thing as a file sitting next to the signature
that the signature was supposed to cover and does not. Actaira's own package
manages that with care - the manifest lists every member with its digest, and
`UNDECLARED_BY_CONSTRUCTION` names the three that cannot be listed - but
"with care" is exactly the property that decays: a fourth member added by a
future writer and forgotten in the manifest is a file dangling outside the
signature, and nothing about a zip makes that shape impossible. In an
envelope it is not a rule that has to be maintained, it is unrepresentable.
What the envelope gives up in exchange is everything the package holds that
is not one payload: the chain, the root, the token, the BOM documents. That
is a real loss and the reason both exist.

The predicate schema, `https://actaira.dev/predicates/inspection/v1`
--------------------------------------------------------------------
The `subject` of the statement is the artifacts, named and digested per
in-toto. The `predicate` is the inspection, and every field in it comes from
bytes that were parsed, on the same rule the ML-BOM obeys (D-16):

    tool          {"name": "actaira", "version": "1.0.0"}
    policy        {"import_policy": "strict" | "known-bad",
                   "fail_on": "critical" | "high" | "medium" | "low"}
                  The settings the verdicts below were computed under. A
                  verdict without its policy is not reproducible, and this
                  predicate has to be reproducible or it is decoration.
    verdict       "pass" | "fail" | "inconclusive": the worst verdict over
                  the subjects, worst-first (fail, then inconclusive). Never
                  a score, never a ratio. See D-41.
    inspected_at  RFC 3339 UTC. Says when this statement was written and
                  nothing more; on its own it is an unanchored claim about
                  time, exactly as D-13 says of a chain entry.
    artifacts     one row per subject, joined to it by `sha256`:
                  {name, path, sha256, format, format_confidence, verdict,
                   fully_read, max_severity | null, rules_fired: [id, ...]}
                  `fully_read: false` is the row saying part of the artifact
                  was never read, so a reader can tell "clean" from "not
                  looked at" without opening the findings.
    rules_fired   the union over all artifacts, aggregated as
                  [{rule_id, severity, count}, ...] sorted by rule_id. Rule
                  identifiers are the stable interface (D-07); the prose for
                  them is in the message catalogue and deliberately not here,
                  so a wording change cannot alter a signed document.

A consumer that does not know this predicate type still gets a valid in-toto
statement over subjects it can verify digests against, which is the point of
putting the artifact identity in `subject` rather than only in the predicate.
"""
from __future__ import annotations

import base64
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .. import __version__
from ..model import ArtifactReport, Severity, Verdict
from . import signing
from .signing import KeyPair

# The media type in-toto registers for a v1 statement. It is signed as part
# of the PAE preimage, so it is not a hint: changing it invalidates every
# signature over the envelope.
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://actaira.dev/predicates/inspection/v1"

DSSE_HEADER = b"DSSEv1"
SP = b" "

# Verdicts, worst first. The order is the aggregation rule for a statement
# covering several artifacts and it is written once, here, so that a reader
# does not have to reconstruct it from a chain of comparisons.
VERDICT_ORDER: tuple[Verdict, ...] = (Verdict.FAIL, Verdict.INCONCLUSIVE, Verdict.PASS)


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding, exactly as the specification writes it.

    Both lengths are byte lengths of the UTF-8 encoding, not character
    counts. That distinction is the one an implementation gets wrong when it
    is written against an ASCII example and then handed a payload with an
    accent in it, so `tests/test_dsse.py` carries a multibyte vector whose
    expected length was counted by hand.
    """
    type_bytes = payload_type.encode("utf-8")
    return SP.join(
        [
            DSSE_HEADER,
            str(len(type_bytes)).encode("ascii"),
            type_bytes,
            str(len(payload)).encode("ascii"),
            payload,
        ]
    )


@dataclass(frozen=True)
class Signature:
    """One signature over an envelope's PAE.

    `keyid` is advisory in DSSE: it tells a verifier which key to try and it
    is not itself authenticated (it lives outside the PAE preimage). This
    module therefore never *decides* anything from it, and reports a keyid
    that disagrees with the key that actually verified as a problem rather
    than as a reason to accept or reject. Treating an unauthenticated hint as
    an identity is how a verifier ends up trusting a field an attacker writes.
    """

    sig: bytes
    keyid: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"keyid": self.keyid, "sig": base64.b64encode(self.sig).decode("ascii")}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Signature:
        return cls(sig=base64.b64decode(str(raw.get("sig", ""))), keyid=str(raw.get("keyid", "")))


@dataclass(frozen=True)
class Envelope:
    """A DSSE envelope: the payload, its type, and the signatures over both.

    Frozen, and `signed()` returns a new envelope rather than mutating this
    one, because an envelope is the signed object: an API that lets a caller
    edit the payload of an already-signed envelope in place invites exactly
    the state where the bytes and the signature disagree and nothing said so.
    """

    payload: bytes
    payload_type: str = PAYLOAD_TYPE
    signatures: tuple[Signature, ...] = ()

    def pae(self) -> bytes:
        return pae(self.payload_type, self.payload)

    def signed(self, keypair: KeyPair) -> Envelope:
        """This envelope with one more signature on it.

        DSSE allows n signatures over one payload, and adding rather than
        replacing is what makes co-signing possible. Unlike the package
        format's decision in D-14 (one signature over a manifest that covers
        everything), n signatures here are n signatures over *the same*
        preimage, so there is no subset of the evidence a verifier can check
        while skipping the rest.
        """
        signature = Signature(sig=keypair.sign(self.pae()), keyid=keypair.key_id)
        return Envelope(
            payload=self.payload,
            payload_type=self.payload_type,
            signatures=(*self.signatures, signature),
        )

    def statement(self) -> dict[str, Any]:
        """The payload parsed as JSON. Raises if it is not an object."""
        parsed = json.loads(self.payload.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("payload is not a JSON object")
        return parsed

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": base64.b64encode(self.payload).decode("ascii"),
            "payloadType": self.payload_type,
            "signatures": [signature.to_dict() for signature in self.signatures],
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Envelope:
        """Rebuild an envelope from its JSON form.

        A missing payload or payloadType raises, because those two fields are
        the signed preimage and an envelope without them is not a damaged
        envelope, it is not an envelope. A missing `signatures` array is
        tolerated and becomes zero signatures, which `verify_envelope`
        reports as unsigned: that is a verification result the caller should
        see next to the others, not an exception it has to special-case.
        """
        if "payload" not in raw or "payloadType" not in raw:
            raise ValueError("not a DSSE envelope: payload and payloadType are required")
        raw_signatures = raw.get("signatures") or []
        if not isinstance(raw_signatures, list):
            raise ValueError("signatures must be an array")
        return cls(
            payload=base64.b64decode(str(raw["payload"])),
            payload_type=str(raw["payloadType"]),
            signatures=tuple(Signature.from_dict(row) for row in raw_signatures),
        )

    @classmethod
    def from_json(cls, text: str | bytes) -> Envelope:
        return cls.from_dict(json.loads(text))


def in_toto_statement(
    subjects: Sequence[dict[str, Any]],
    predicate: dict[str, Any],
    predicate_type: str = PREDICATE_TYPE,
) -> dict[str, Any]:
    """An in-toto v1 statement. Four fields, in the order the spec names them."""
    return {
        "_type": STATEMENT_TYPE,
        "subject": [dict(subject) for subject in subjects],
        "predicateType": predicate_type,
        "predicate": predicate,
    }


def subject_of(report: ArtifactReport) -> dict[str, Any]:
    """The in-toto subject for one artifact: a name and a digest.

    `name` is the file's base name rather than the path it happened to have
    on the machine that ran the scan. An in-toto subject name is meant to be
    an identifier a consumer can match against its own copy, and a consumer's
    copy is not at `/home/ci/work/42/model.safetensors`. The full path is not
    dropped: it goes in the predicate row, labelled `path`, where it reads as
    provenance rather than as identity.
    """
    return {
        "name": PurePosixPath(report.path.replace("\\", "/")).name or report.path,
        "digest": {"sha256": report.sha256},
    }


def worst_verdict(reports: Sequence[ArtifactReport]) -> Verdict:
    """The worst verdict over a set of reports, or INCONCLUSIVE for none.

    Empty means nothing was inspected, and the answer to "what did you find
    in nothing" is not "pass". D-04, one layer up.
    """
    for verdict in VERDICT_ORDER:
        if any(report.verdict is verdict for report in reports):
            return verdict
    return Verdict.INCONCLUSIVE


def inspection_predicate(
    reports: Sequence[ArtifactReport],
    scan_policy: str = "strict",
    fail_on: Severity = Severity.HIGH,
    inspected_at: str | None = None,
) -> dict[str, Any]:
    """The `predicate` body. Schema documented in the module docstring.

    `inspected_at` is injectable so that a caller which needs a byte-stable
    document (a test, a reproducible build) can supply the moment instead of
    reading the clock. Nothing else in here varies between two runs over the
    same bytes under the same policy, which is the property that makes the
    signature worth anything.
    """
    rows = [_artifact_row(report) for report in reports]
    return {
        "tool": {"name": "actaira", "version": __version__},
        "policy": {"import_policy": scan_policy, "fail_on": fail_on.value},
        "verdict": worst_verdict(reports).value,
        "inspected_at": inspected_at or datetime.now(UTC).isoformat(timespec="seconds"),
        "artifacts": rows,
        "rules_fired": _aggregate_rules(reports),
    }


def _artifact_row(report: ArtifactReport) -> dict[str, Any]:
    return {
        "name": subject_of(report)["name"],
        "path": report.path,
        "sha256": report.sha256,
        "format": report.detected_format,
        "format_confidence": report.format_confidence,
        "verdict": report.verdict.value,
        "fully_read": bool(report.metadata.get("fully_read", False)),
        "max_severity": report.max_severity.value if report.max_severity else None,
        "rules_fired": sorted({finding.rule_id for finding in report.findings}),
    }


def _aggregate_rules(reports: Sequence[ArtifactReport]) -> list[dict[str, Any]]:
    """Counts per rule, sorted. A count of firings, never a score (D-41)."""
    tally: dict[str, dict[str, Any]] = {}
    for report in reports:
        for finding in report.findings:
            row = tally.setdefault(
                finding.rule_id,
                {"rule_id": finding.rule_id, "severity": finding.severity.value, "count": 0},
            )
            # A rule can fire at different severities in different inspectors;
            # the worst one is kept so the row cannot understate the artifact.
            if Severity(row["severity"]).rank < finding.severity.rank:
                row["severity"] = finding.severity.value
            row["count"] += 1
    return [tally[rule_id] for rule_id in sorted(tally)]


def to_envelope(
    reports: Sequence[ArtifactReport],
    keypair: KeyPair | None = None,
    scan_policy: str = "strict",
    fail_on: Severity = Severity.HIGH,
    inspected_at: str | None = None,
) -> Envelope:
    """Inspection reports in, one signed DSSE envelope out.

    `keypair` is optional and its absence produces an envelope with zero
    signatures. That is a legitimate DSSE object (the format allows it) and
    `verify_envelope` refuses it loudly, which is the behaviour wanted for a
    document that is going to be handed to a co-signer before anyone verifies
    it. What is not offered is a way to produce a *partially* signed envelope,
    because there is no such thing here: every signature covers the whole
    preimage.
    """
    statement = in_toto_statement(
        subjects=[subject_of(report) for report in reports],
        predicate=inspection_predicate(
            reports,
            scan_policy=scan_policy,
            fail_on=fail_on,
            inspected_at=inspected_at,
        ),
    )
    # Sorted keys and compact separators for the same reason canonical_json
    # exists (D-03): the payload is base64-encoded into the envelope and
    # hashed by whoever verifies it, so two runs over the same facts must
    # produce the same bytes. `ensure_ascii=False` keeps a non-ASCII file
    # name readable in the document rather than escaped, and the PAE length
    # prefix is computed over the encoded bytes, which is where a UTF-8
    # payload gets its length right or wrong.
    payload = json.dumps(
        statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    envelope = Envelope(payload=payload, payload_type=PAYLOAD_TYPE)
    return envelope.signed(keypair) if keypair is not None else envelope


def verify_envelope(envelope: Envelope, public_key: Ed25519PublicKey) -> tuple[bool, list[str]]:
    """Check an envelope against one key. Returns (ok, problems).

    Every problem found is reported, not just the first, for the reason
    `verify_package` gives one layer up: a verifier that stops at the first
    failure teaches its user to fix one thing and re-run, and the second
    failure is then discovered by whoever is holding the package next.

    The checks, in the order they are listed in the output:

      1. at least one signature exists;
      2. `payloadType` is the in-toto media type. Checked explicitly even
         though the PAE covers it, because a verifier that only checks the
         signature will happily authenticate an attacker's media type as long
         as the attacker also signed it;
      3. some signature verifies over PAE(payloadType, payload);
      4. the keyid of a signature that verified agrees with the key that
         verified it - an inconsistency, reported, never used to decide;
      5. the payload is JSON, is an in-toto v1 statement, carries at least
         one subject, and every subject has a well-formed sha256 digest;
      6. the predicate type is Actaira's. A foreign predicate is a valid
         in-toto statement and this function still calls it a problem,
         because its contract is "is this an Actaira inspection statement I
         can trust", and answering yes for a document whose meaning is
         defined elsewhere is the failure this whole module is arguing
         against.
    """
    problems: list[str] = []

    if not envelope.signatures:
        problems.append("envelope carries no signatures")
    if envelope.payload_type != PAYLOAD_TYPE:
        problems.append(f"payloadType is {envelope.payload_type!r}, expected {PAYLOAD_TYPE!r}")

    preimage = envelope.pae()
    key_id = signing.fingerprint_of(public_key)[:16]
    verified = [
        index
        for index, signature in enumerate(envelope.signatures)
        if signing.verify(public_key, signature.sig, preimage)
    ]
    if envelope.signatures and not verified:
        problems.append(
            f"no signature verifies over PAE({envelope.payload_type!r}, {len(envelope.payload)} bytes) "
            f"with key {key_id}"
        )
    for index in verified:
        declared = envelope.signatures[index].keyid
        if declared and declared != key_id:
            problems.append(
                f"signature[{index}] verifies with key {key_id} but declares keyid {declared!r}"
            )

    problems.extend(_statement_problems(envelope))
    return (not problems), problems


def _statement_problems(envelope: Envelope) -> list[str]:
    """Shape checks on the payload, separate from the cryptography.

    Split out because they answer a different question and a reader has to be
    able to tell them apart: a signature failure means the bytes are not what
    was signed, a shape failure means the signed bytes do not say what this
    verifier knows how to read. Only the first is an attack.
    """
    problems: list[str] = []
    try:
        statement = envelope.statement()
    except (UnicodeDecodeError, ValueError) as exc:
        return [f"payload is not a JSON object: {type(exc).__name__}: {exc}"]

    if statement.get("_type") != STATEMENT_TYPE:
        problems.append(f"_type is {statement.get('_type')!r}, expected {STATEMENT_TYPE!r}")
    if statement.get("predicateType") != PREDICATE_TYPE:
        problems.append(
            f"predicateType is {statement.get('predicateType')!r}, expected {PREDICATE_TYPE!r}"
        )
    if not isinstance(statement.get("predicate"), dict):
        problems.append("predicate is missing or is not an object")

    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        problems.append("statement carries no subject")
        return problems
    for index, subject in enumerate(subjects):
        if not isinstance(subject, dict):
            problems.append(f"subject[{index}] is not an object")
            continue
        if not subject.get("name"):
            problems.append(f"subject[{index}] has no name")
        digest = subject.get("digest")
        sha256 = digest.get("sha256") if isinstance(digest, dict) else None
        if not isinstance(sha256, str) or len(sha256) != 64:
            problems.append(f"subject[{index}] has no well-formed sha256 digest")
    return problems
