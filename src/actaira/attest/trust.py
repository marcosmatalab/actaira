"""Chain validation for time-stamp tokens, against anchors you supplied.

Design note D-170. Until this module existed the tool checked a token's own
signature against the certificate the token carried, which establishes that
the token is internally consistent and nothing else. A token is a certificate
plus a signature; anyone can make both. `tsa_chain` therefore stayed
`not_verified` and the reports said so out loud, which was honest and left a
real question unanswered: is this authority one this environment accepts?

The answer requires anchors, and the anchors have to come from the person
verifying. Shipping a bundle of "trusted" TSA roots would be this project
deciding on their behalf, with a list that goes stale the first time a root
rotates and that nobody would ever audit. So the store is an argument, and
with no store the answer is `unknown` - a third state, not a failure, exactly
as it is for a signing key nobody vouched for.

What is checked, stated precisely because the value of the answer depends on
knowing its limits:

* every signature in the path, leaf to anchor;
* every certificate's validity window, evaluated at the token's genTime
  rather than at the verifier's clock - a token issued in 2024 by a
  certificate that expired in 2025 was valid when it was issued, and judging
  it against today would reject every token the moment its TSA rotated;
* `basicConstraints` CA on every issuer, and the path length constraint;
* `keyUsage` keyCertSign on every issuer;
* `extendedKeyUsage` id-kp-timeStamping on the leaf.

What is NOT checked, and none of it is a detail:

* revocation. No CRL and no OCSP, because both are network calls and this
  tool verifies offline. A revoked certificate validates here.
* name constraints and policy constraints.
* anything about whether the anchor deserves to be an anchor.

`ChainResult.limits` carries that list into every report, so it travels with
the answer rather than living only here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

TRUSTED = "trusted"
UNTRUSTED = "untrusted"
UNKNOWN = "unknown"

# What a caller is buying, in the answer itself. A verifier who reads
# "trusted" without this list is reading a stronger claim than was made.
LIMITS = (
    "revocation is not checked: no CRL and no OCSP, because both are network calls",
    "name constraints and policy constraints are not evaluated",
    "the anchors are whatever the caller supplied; nothing here judges them",
)

MAX_PATH_LENGTH = 8


@dataclass
class TrustStore:
    """Anchors the caller supplied, indexed by public-key fingerprint.

    Indexed by SPKI rather than by subject name, because a name is a label
    and a key is an identity. Two certificates with the same subject and
    different keys are different anchors, and a store keyed by name would let
    the second impersonate the first.
    """

    anchors: dict[str, x509.Certificate] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.anchors)

    def __bool__(self) -> bool:
        return bool(self.anchors)

    def add(self, certificate: x509.Certificate) -> str:
        fingerprint = spki_fingerprint(certificate)
        self.anchors[fingerprint] = certificate
        return fingerprint

    def contains(self, certificate: x509.Certificate) -> bool:
        return spki_fingerprint(certificate) in self.anchors

    def describe(self) -> list[dict[str, str]]:
        return sorted(
            (
                {"subject": certificate.subject.rfc4514_string(), "spki_sha256": fingerprint}
                for fingerprint, certificate in self.anchors.items()
            ),
            key=lambda row: row["spki_sha256"],
        )


def spki_fingerprint(certificate: x509.Certificate) -> str:
    """SHA-256 over the DER SubjectPublicKeyInfo."""
    import hashlib

    der = certificate.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def load_store(path: Path) -> TrustStore:
    """Load anchors from a PEM file or a directory of PEM files.

    PEM because it is what a certificate arrives as, what an organisation's
    internal CA publishes, and what a reviewer can open in a text editor to
    see what they are being asked to trust.
    """
    path = Path(path)
    store = TrustStore()
    files = sorted(path.glob("*.pem")) + sorted(path.glob("*.crt")) if path.is_dir() else [path]
    for candidate in files:
        blob = candidate.read_bytes()
        try:
            certificates = x509.load_pem_x509_certificates(blob)
        except Exception:
            try:
                certificates = [x509.load_der_x509_certificate(blob)]
            except Exception as exc:
                raise ValueError(f"{candidate} holds no certificate this tool can read: {exc}") from exc
        for certificate in certificates:
            store.add(certificate)
    if not store:
        raise ValueError(f"{path} holds no certificates")
    return store


@dataclass
class ChainResult:
    """The trust answer, with the path that produced it and what it omits."""

    state: str = UNKNOWN
    anchor: str = ""
    anchor_spki: str = ""
    path: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    checked_at: str = ""
    limits: tuple[str, ...] = LIMITS

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "anchor": self.anchor,
            "anchor_spki_sha256": self.anchor_spki,
            "path": list(self.path),
            "checked_at": self.checked_at,
            "problems": list(self.problems),
            "does_not_check": list(self.limits),
        }


def evaluate(
    leaf: x509.Certificate | None,
    candidates: list[x509.Certificate],
    store: TrustStore | None,
    at_time: datetime | None,
) -> ChainResult:
    """Walk from `leaf` to an anchor in `store`, or say why it could not.

    `at_time` is the token's genTime, not the verifier's clock. A token issued
    in 2024 under a certificate that expired in 2025 was valid when it was
    issued; judging it against today would reject every token the moment its
    TSA rotated, which would make the check useless in exactly the situation
    it exists for.
    """
    result = ChainResult()
    if store is None or not store:
        result.problems.append("no trust anchors were supplied, so nothing was concluded")
        return result
    if leaf is None:
        result.state = UNTRUSTED
        result.problems.append("the token carries no signer certificate to build a path from")
        return result

    moment = (at_time or datetime.now(UTC)).astimezone(UTC)
    result.checked_at = moment.isoformat(timespec="seconds")

    if not _has_timestamping_eku(leaf):
        # Refused at the leaf rather than folded into the path walk. A
        # certificate without id-kp-timeStamping is not a time-stamping
        # authority, however impeccable its issuer, and accepting one would
        # let any certificate under a trusted root stamp time.
        result.state = UNTRUSTED
        result.problems.append(
            "the signer certificate does not carry extendedKeyUsage id-kp-timeStamping"
        )
        return result

    pool = {spki_fingerprint(item): item for item in candidates}
    chain = [leaf]
    current = leaf
    # Cross-signed certificates make cycles reachable without anyone acting
    # in bad faith, and a hostile bundle can construct one deliberately. The
    # path-length cap would stop it either way; this stops it with an
    # accurate reason.
    seen = {spki_fingerprint(leaf)}

    for depth in range(MAX_PATH_LENGTH):
        if not _valid_at(current, moment):
            result.state = UNTRUSTED
            result.problems.append(
                f"{current.subject.rfc4514_string()} was not valid at {result.checked_at}"
            )
            return result
        if store.contains(current):
            result.state = TRUSTED
            result.anchor = current.subject.rfc4514_string()
            result.anchor_spki = spki_fingerprint(current)
            result.path = [item.subject.rfc4514_string() for item in chain]
            return result

        issuer = _find_issuer(current, list(pool.values()) + list(store.anchors.values()))
        if issuer is None:
            result.state = UNTRUSTED
            result.problems.append(
                f"no issuer for {current.subject.rfc4514_string()} is in the token or the trust store"
            )
            return result
        if not _signature_ok(current, issuer):
            result.state = UNTRUSTED
            result.problems.append(
                f"{current.subject.rfc4514_string()} is not signed by "
                f"{issuer.subject.rfc4514_string()}"
            )
            return result
        problem = _issuer_may_issue(issuer, depth)
        if problem:
            result.state = UNTRUSTED
            result.problems.append(problem)
            return result
        fingerprint = spki_fingerprint(issuer)
        if fingerprint in seen:
            result.state = UNTRUSTED
            result.problems.append(
                f"the certificate path loops at {issuer.subject.rfc4514_string()}"
            )
            return result
        seen.add(fingerprint)
        chain.append(issuer)
        current = issuer

    result.state = UNTRUSTED
    result.problems.append(f"the certificate path is longer than {MAX_PATH_LENGTH}")
    return result


def _valid_at(certificate: x509.Certificate, moment: datetime) -> bool:
    return certificate.not_valid_before_utc <= moment <= certificate.not_valid_after_utc


def _has_timestamping_eku(certificate: x509.Certificate) -> bool:
    try:
        usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False
    return x509.oid.ExtendedKeyUsageOID.TIME_STAMPING in usages


def _find_issuer(
    certificate: x509.Certificate, candidates: list[x509.Certificate]
) -> x509.Certificate | None:
    """The first candidate whose subject is this certificate's issuer.

    Self-signed certificates are excluded when they are the certificate
    itself, so a self-signed leaf does not become its own issuer and loop.
    """
    for candidate in candidates:
        if candidate.subject != certificate.issuer:
            continue
        if candidate.fingerprint(hashes.SHA256()) == certificate.fingerprint(hashes.SHA256()):
            continue
        return candidate
    # No fallback to "itself" for a self-signed certificate. The walk already
    # checked the store before looking for an issuer, so a self-signed
    # certificate that is not an anchor has nowhere to go - and returning it
    # as its own issuer made the walk loop on it until the path-length cap,
    # which reported "the path is longer than 8" for what is really "this
    # root is not one of yours". A wrong reason is worse than a wrong answer:
    # it sends the reader to the wrong fix.
    return None


def _issuer_may_issue(issuer: x509.Certificate, depth: int) -> str | None:
    try:
        constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return f"{issuer.subject.rfc4514_string()} has no basicConstraints, so it is not a CA"
    if not constraints.ca:
        return f"{issuer.subject.rfc4514_string()} is not a CA certificate"
    if constraints.path_length is not None and constraints.path_length < depth:
        return (
            f"{issuer.subject.rfc4514_string()} sets pathLenConstraint "
            f"{constraints.path_length}, which this path exceeds"
        )
    try:
        usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return None  # keyUsage is optional; basicConstraints already said CA
    if not usage.key_cert_sign:
        return f"{issuer.subject.rfc4514_string()} does not carry keyUsage keyCertSign"
    return None


def _signature_ok(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
    public = issuer.public_key()
    algorithm = certificate.signature_hash_algorithm
    try:
        if isinstance(public, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            # Both need the digest the certificate was signed with, and
            # `signature_hash_algorithm` is None for the algorithms that carry
            # their own (Ed25519, and RSASSA-PSS with parameters this build
            # cannot read). Reaching the verify call with None raises inside
            # cryptography, so it gets the same answer as an unknown key type:
            # a signature nobody checked is not a signature that passed.
            if algorithm is None:
                return False
            if isinstance(public, rsa.RSAPublicKey):
                public.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    algorithm,
                )
            else:
                public.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    ec.ECDSA(algorithm),
                )
        else:
            # An algorithm this build cannot check is not a pass. Saying
            # "trusted" about a signature nobody verified is the failure this
            # whole module exists to avoid.
            return False
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True
