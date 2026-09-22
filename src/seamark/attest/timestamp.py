"""RFC 3161 time-stamping, written against the bytes rather than a library.

Design note D-27. A hash chain proves ordering. It does not prove freshness:
whoever holds the signing key can rebuild the whole log today and date it
yesterday, and every internal check still passes (D-13). A time-stamp token
from a third party closes exactly that hole and nothing else, so it is
optional, it is never required, and what it proves is stated narrowly.

**Decided.** Speak RFC 3161 directly: build the `TimeStampReq` as DER by
hand, POST it as `application/timestamp-query`, and parse and check the
`TimeStampResp` here. No new dependency; `cryptography` is still the only
one, and it is used for what it is good at (X.509 and signature primitives),
not for ASN.1 parsing it does not expose.

**Why.** The alternatives are `rfc3161ng`/`asn1crypto`, or shelling out to
`openssl ts`. Both were rejected. A tool whose subject is supply-chain
provenance does not answer "why is this dependency here?" with "to check a
timestamp"; and a subprocess makes the check depend on which OpenSSL happens
to be on the machine, which is the opposite of an offline, reproducible
verifier. The DER involved is small and completely specified: a request is
four fields, a response is a status plus a CMS `SignedData` whose payload is
a nine-field `TSTInfo`.

**What is given up.** The parser here is deliberately narrow. It reads
definite-length DER only, refuses high-tag-number forms, and knows the
handful of algorithms a TSA actually uses. A conforming-but-exotic token is
reported as unparsed rather than guessed at, which is the safe direction: an
unread token must never read as a verified one.

**What a verified token proves, and what it does not.** Three separate
claims, kept separate on purpose, the same way D-15 keeps integrity and
identity apart:

  imprint   the token was issued over *this* digest. Checked here, offline,
            always. Failing it is a hard failure.
  signature the token was signed by the certificate the token itself
            carries. Checked here, offline, when the algorithms are ones
            this module knows. That is `embedded_cert_only`: it proves the
            token was not edited after issuance, and nothing about who the
            issuer is.
  chain     the signer's certificate chains to a timestamping root the
            verifier trusts. NOT checked. Seamark ships no trust store, and
            a verifier that pretends to validate a chain against nothing is
            worse than one that says it did not. The state is reported as
            `tsa_chain: "not_verified"` with a warning, exactly as an
            unanchored signing key is reported as `embedded_key_only`.

Never say verified about something that was not.
"""
from __future__ import annotations

import secrets
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from . import trust as trust_mod

# ---------------------------------------------------------------------------
# Object identifiers, spelled out so a reader can check them against the RFC
# ---------------------------------------------------------------------------

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"          # RFC 5652 id-signedData
OID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4"     # RFC 3161 id-ct-TSTInfo
OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3"    # RFC 5652 id-contentType
OID_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"  # RFC 5652 id-messageDigest
OID_KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"        # RFC 5280 id-kp-timeStamping

# messageImprint and signature digests
OID_SHA1 = "1.3.14.3.2.26"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"

DIGEST_OIDS = {"sha1": OID_SHA1, "sha256": OID_SHA256, "sha384": OID_SHA384, "sha512": OID_SHA512}
DIGEST_NAMES = {oid: name for name, oid in DIGEST_OIDS.items()}

# What `--tsa-url` is allowed to ask for. SHA-1 is readable (a token issued
# years ago may carry it) but never requested.
REQUESTABLE = ("sha256", "sha384", "sha512")
DIGEST_SIZES = {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}

# Signature algorithms. The value is (family, fixed digest or None); None
# means the digest comes from the SignerInfo digestAlgorithm, which is how
# CMS carries plain rsaEncryption.
_SIGNATURE_ALGORITHMS: dict[str, tuple[str, str | None]] = {
    "1.2.840.113549.1.1.1": ("rsa", None),           # rsaEncryption
    "1.2.840.113549.1.1.11": ("rsa", "sha256"),      # sha256WithRSAEncryption
    "1.2.840.113549.1.1.12": ("rsa", "sha384"),
    "1.2.840.113549.1.1.13": ("rsa", "sha512"),
    "1.2.840.10045.2.1": ("ecdsa", None),            # id-ecPublicKey
    "1.2.840.10045.4.3.2": ("ecdsa", "sha256"),      # ecdsa-with-SHA256
    "1.2.840.10045.4.3.3": ("ecdsa", "sha384"),
    "1.2.840.10045.4.3.4": ("ecdsa", "sha512"),
    "1.3.101.112": ("ed25519", None),                # id-Ed25519
}

# The three digests this verifier accepts, as constructors. Annotated as
# callables rather than left to inference: the join of three concrete
# classes is `type[HashAlgorithm]`, and HashAlgorithm is abstract, so a
# checker reading `hash_class()` sees an abstract class being instantiated.
# What the table actually holds is "something that returns a hash", and
# saying so is both true and checkable.
_HASHES: dict[str, Callable[[], hashes.HashAlgorithm]] = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}

# A token is a few kilobytes. Anything past this is a hostile or broken
# responder, and reading it into memory is the responder's decision, not ours.
MAX_RESPONSE_BYTES = 1 << 20

CONTENT_TYPE_QUERY = "application/timestamp-query"
CONTENT_TYPE_REPLY = "application/timestamp-reply"

# RFC 3161 section 2.4.2
PKI_STATUS = {
    0: "granted",
    1: "grantedWithMods",
    2: "rejection",
    3: "waiting",
    4: "revocationWarning",
    5: "revocationNotification",
}
GRANTED_STATUSES = (0, 1)

# RFC 3161 PKIFailureInfo, by bit position.
FAILURE_INFO = {
    0: "badAlg", 2: "badRequest", 5: "badDataFormat", 14: "timeNotAvailable",
    15: "unacceptedPolicy", 16: "unacceptedExtension", 17: "addInfoNotAvailable",
    25: "systemFailure",
}

# Attribute types rendered by short name in a distinguished name; anything
# else is printed as its dotted OID rather than silently dropped.
_NAME_ATTRIBUTES = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "DC",
}


class TimestampError(ValueError):
    """A time-stamp request, response or token that could not be handled."""


class TokenTamperedError(TimestampError):
    """The token contradicts itself: it was edited after it was signed.

    Kept apart from `TimestampError` because the two must not be reported
    the same way. "I could not check this" and "I checked it and it is
    wrong" are opposite claims, and collapsing the second into the first is
    how a tampered token comes to be described as merely unverified.
    """


# ---------------------------------------------------------------------------
# DER, written out. Encoder first, then reader.
# ---------------------------------------------------------------------------

TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_BOOLEAN = 0x01
TAG_SEQUENCE = 0x30
TAG_SET = 0x31
TAG_GENERALIZED_TIME = 0x18


def _encode_length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    body = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(body)) + body


def _der_integer(value: int) -> bytes:
    if value < 0:
        raise TimestampError("negative integers are not produced by this encoder")
    if value == 0:
        return _tlv(TAG_INTEGER, b"\x00")
    # Minimal two's-complement encoding of a positive integer: one more byte
    # than the magnitude needs whenever the top bit would otherwise be set.
    width = (value.bit_length() // 8) + 1
    return _tlv(TAG_INTEGER, value.to_bytes(width, "big"))


def _der_oid(dotted: str) -> bytes:
    try:
        parts = [int(piece) for piece in dotted.split(".")]
    except ValueError as exc:
        raise TimestampError(f"not an object identifier: {dotted!r}") from exc
    if len(parts) < 2 or parts[0] > 2 or any(part < 0 for part in parts):
        raise TimestampError(f"not an object identifier: {dotted!r}")
    if parts[0] < 2 and parts[1] >= 40:
        raise TimestampError(f"second arc out of range: {dotted!r}")
    body = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = bytearray([part & 0x7F])
        part >>= 7
        while part:
            chunk.append((part & 0x7F) | 0x80)
            part >>= 7
        body.extend(reversed(chunk))
    return _tlv(TAG_OID, bytes(body))


def _der_algorithm(oid: str) -> bytes:
    """AlgorithmIdentifier with an explicit NULL parameter.

    RFC 4055 allows the parameter to be absent for the SHA-2 family and
    `openssl ts -query` writes the NULL. Interoperability beats purity here:
    the request this module produces is byte-identical to OpenSSL's, which
    `tests/test_timestamp.py` asserts against a captured `.tsq`.
    """
    return _tlv(TAG_SEQUENCE, _der_oid(oid) + _tlv(TAG_NULL, b""))


@dataclass(frozen=True)
class Tlv:
    """One DER element: its tag, its contents, and the exact bytes it came in.

    `raw` matters: re-encoding a parsed structure to hash it is how CMS
    signatures are forged in practice, so anything that gets hashed is hashed
    over the bytes as they arrived, never over a re-encoding.
    """
    tag: int
    body: bytes
    raw: bytes

def read_tlv(data: bytes, offset: int = 0) -> tuple[Tlv, int]:
    if offset + 2 > len(data):
        raise TimestampError("truncated DER: no room for a tag and a length")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise TimestampError("high-tag-number form is not accepted")
    first = data[offset + 1]
    cursor = offset + 2
    if first == 0x80:
        raise TimestampError("indefinite length is not DER")
    if first < 0x80:
        size = first
    else:
        count = first & 0x7F
        if count > 8:
            raise TimestampError("length field is implausibly wide")
        if cursor + count > len(data):
            raise TimestampError("truncated DER: length field runs past the end")
        chunk = data[cursor:cursor + count]
        if chunk[0] == 0:
            raise TimestampError("non-minimal length encoding is not DER")
        size = int.from_bytes(chunk, "big")
        if size < 0x80:
            raise TimestampError("long-form length used for a short value")
        cursor += count
    end = cursor + size
    if end > len(data):
        raise TimestampError(f"truncated DER: element claims {size} bytes, {len(data) - cursor} remain")
    return Tlv(tag=tag, body=data[cursor:end], raw=data[offset:end]), end


def read_all(data: bytes) -> list[Tlv]:
    """Every element in a buffer, with nothing left over."""
    items: list[Tlv] = []
    offset = 0
    while offset < len(data):
        item, offset = read_tlv(data, offset)
        items.append(item)
    return items


def read_one(data: bytes, expected_tag: int | None = None, what: str = "element") -> Tlv:
    item, offset = read_tlv(data, 0)
    if offset != len(data):
        raise TimestampError(f"{len(data) - offset} trailing bytes after the {what}")
    if expected_tag is not None and item.tag != expected_tag:
        raise TimestampError(f"{what}: expected tag 0x{expected_tag:02x}, found 0x{item.tag:02x}")
    return item


def _expect(item: Tlv, tag: int, what: str) -> Tlv:
    if item.tag != tag:
        raise TimestampError(f"{what}: expected tag 0x{tag:02x}, found 0x{item.tag:02x}")
    return item


def decode_oid(item: Tlv) -> str:
    _expect(item, TAG_OID, "object identifier")
    body = item.body
    if not body:
        raise TimestampError("empty object identifier")
    first = body[0]
    arcs = [min(first // 40, 2)]
    arcs.append(first - arcs[0] * 40)
    value = 0
    started = False
    for index, byte in enumerate(body[1:], start=1):
        if not started and byte == 0x80:
            raise TimestampError("non-minimal arc encoding in an object identifier")
        started = True
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
            started = False
        elif index == len(body) - 1:
            raise TimestampError("object identifier ends mid-arc")
    return ".".join(str(arc) for arc in arcs)


def decode_integer(item: Tlv) -> int:
    _expect(item, TAG_INTEGER, "integer")
    if not item.body:
        raise TimestampError("empty integer")
    return int.from_bytes(item.body, "big", signed=True)


def decode_boolean(item: Tlv) -> bool:
    _expect(item, TAG_BOOLEAN, "boolean")
    if len(item.body) != 1:
        raise TimestampError("boolean is not one byte")
    return item.body[0] != 0


def decode_generalized_time(item: Tlv) -> datetime:
    """RFC 3161 requires GeneralizedTime in UTC, with the Z, and no offset."""
    _expect(item, TAG_GENERALIZED_TIME, "genTime")
    try:
        text = item.body.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TimestampError("genTime is not ASCII") from exc
    if not text.endswith("Z"):
        raise TimestampError(f"genTime is not UTC: {text!r}")
    stem = text[:-1]
    fraction = 0
    if "." in stem:
        stem, digits = stem.split(".", 1)
        if not digits.isdigit():
            raise TimestampError(f"genTime has a malformed fraction: {text!r}")
        fraction = int(round(float("0." + digits) * 1_000_000))
    if len(stem) != 14 or not stem.isdigit():
        raise TimestampError(f"genTime is not YYYYMMDDHHMMSS: {text!r}")
    try:
        moment = datetime.strptime(stem, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    except ValueError as exc:
        raise TimestampError(f"genTime is not a real instant: {text!r}") from exc
    return moment.replace(microsecond=min(fraction, 999_999))


def _decode_directory_string(item: Tlv) -> str:
    if item.tag in (0x0C, 0x13, 0x16, 0x14):  # UTF8, Printable, IA5, Teletex
        return item.body.decode("utf-8", errors="replace")
    if item.tag == 0x1E:  # BMPString
        return item.body.decode("utf-16-be", errors="replace")
    return item.body.hex()


def render_name(der: bytes) -> str:
    """An RDNSequence as RFC 4514 renders it: most specific attribute first.

    The same shape `cryptography` produces for a certificate subject, so the
    name read out of a TSTInfo and the name read off the signer certificate
    can be compared as strings. `tests/test_timestamp.py` asserts that they
    agree on a token written by OpenSSL, which is what keeps this honest.
    """
    sequence = read_one(der, TAG_SEQUENCE, "RDNSequence")
    pieces: list[str] = []
    for rdn in read_all(sequence.body):
        _expect(rdn, TAG_SET, "relative distinguished name")
        for attribute in read_all(rdn.body):
            _expect(attribute, TAG_SEQUENCE, "attribute type and value")
            parts = read_all(attribute.body)
            if len(parts) != 2:
                raise TimestampError("attribute is not a type/value pair")
            oid = decode_oid(parts[0])
            label = _NAME_ATTRIBUTES.get(oid, oid)
            pieces.append(f"{label}={_decode_directory_string(parts[1])}")
    return ",".join(reversed(pieces))


# ---------------------------------------------------------------------------
# The request
# ---------------------------------------------------------------------------

def build_request(
    digest: bytes,
    *,
    hash_algorithm: str = "sha256",
    nonce: int | None = None,
    cert_req: bool = True,
    policy: str | None = None,
) -> bytes:
    """A DER `TimeStampReq` over `digest` (RFC 3161 section 2.4.1).

        TimeStampReq ::= SEQUENCE {
            version         INTEGER { v1(1) },
            messageImprint  MessageImprint,
            reqPolicy       TSAPolicyId OPTIONAL,
            nonce           INTEGER OPTIONAL,
            certReq         BOOLEAN DEFAULT FALSE,
            extensions      [0] IMPLICIT Extensions OPTIONAL }

    `certReq` defaults to TRUE here and not to the ASN.1 default: without the
    signer certificate in the reply there is nothing to check the token's own
    signature against, and this module would have to report `not_verified`
    for every token it ever saw.
    """
    if hash_algorithm not in REQUESTABLE:
        raise TimestampError(f"unsupported request hash algorithm: {hash_algorithm}")
    if len(digest) != DIGEST_SIZES[hash_algorithm]:
        raise TimestampError(
            f"{hash_algorithm} digest must be {DIGEST_SIZES[hash_algorithm]} bytes, got {len(digest)}"
        )
    imprint = _tlv(
        TAG_SEQUENCE,
        _der_algorithm(DIGEST_OIDS[hash_algorithm]) + _tlv(TAG_OCTET_STRING, digest),
    )
    body = _der_integer(1) + imprint
    if policy is not None:
        body += _der_oid(policy)
    if nonce is not None:
        body += _der_integer(nonce)
    if cert_req:
        # DEFAULT FALSE, so TRUE is encoded and FALSE is omitted.
        body += _tlv(TAG_BOOLEAN, b"\xff")
    return _tlv(TAG_SEQUENCE, body)


def make_nonce() -> int:
    """A 64-bit nonce, so a replayed reply is detectable.

    Positive on purpose: a nonce whose top bit is set encodes with a leading
    zero byte and some TSAs echo it back re-encoded, which turns a perfectly
    good token into a spurious mismatch.
    """
    return secrets.randbits(63) | 1


def post_request(url: str, request_der: bytes, timeout: float = 10.0) -> bytes:
    """POST a `TimeStampReq` and return the raw `TimeStampResp` bytes.

    The only place in Seamark that opens a network connection, which is why
    it is one function, reached only from `attest --tsa-url`, and why the
    scheme is checked before the URL reaches urllib: `file://` and friends
    would turn a TSA URL into a local file read.
    """
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise TimestampError(f"a TSA URL must be http or https, not {scheme or 'a bare path'}")
    request = urllib.request.Request(  # noqa: S310 - scheme checked on the line above
        url,
        data=request_der,
        method="POST",
        headers={
            "Content-Type": CONTENT_TYPE_QUERY,
            "Accept": CONTENT_TYPE_REPLY,
            "Content-Length": str(len(request_der)),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - as above
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:  # a TSA may answer 4xx with a DER rejection
        payload = exc.read(MAX_RESPONSE_BYTES + 1) if exc.fp is not None else b""
        if not payload:
            raise TimestampError(f"the TSA answered HTTP {exc.code} with no body") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise TimestampError(f"could not reach the TSA: {exc}") from exc
    if len(payload) > MAX_RESPONSE_BYTES:
        raise TimestampError(f"the TSA answered with more than {MAX_RESPONSE_BYTES} bytes")
    if not payload:
        raise TimestampError("the TSA answered with an empty body")
    return payload


# ---------------------------------------------------------------------------
# The response and the token it carries
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Response:
    status: int
    status_name: str
    status_text: str
    failure_info: list[str]
    token: bytes | None

    @property
    def granted(self) -> bool:
        return self.status in GRANTED_STATUSES and self.token is not None


def parse_response(der: bytes) -> Response:
    """RFC 3161 section 2.4.2.

        TimeStampResp ::= SEQUENCE {
            status          PKIStatusInfo,
            timeStampToken  TimeStampToken OPTIONAL }
        PKIStatusInfo ::= SEQUENCE {
            status          PKIStatus,
            statusString    PKIFreeText OPTIONAL,
            failInfo        PKIFailureInfo OPTIONAL }
    """
    outer = read_one(der, TAG_SEQUENCE, "TimeStampResp")
    items = read_all(outer.body)
    if not items:
        raise TimestampError("TimeStampResp is empty")
    status_info = read_all(_expect(items[0], TAG_SEQUENCE, "PKIStatusInfo").body)
    if not status_info:
        raise TimestampError("PKIStatusInfo is empty")
    status = decode_integer(status_info[0])
    text_parts: list[str] = []
    failures: list[str] = []
    for extra in status_info[1:]:
        if extra.tag == TAG_SEQUENCE:  # PKIFreeText ::= SEQUENCE OF UTF8String
            text_parts.extend(part.body.decode("utf-8", errors="replace") for part in read_all(extra.body))
        elif extra.tag == TAG_BIT_STRING:
            failures = _decode_failure_info(extra)
    token = None
    if len(items) > 1:
        token = _expect(items[1], TAG_SEQUENCE, "TimeStampToken").raw
    return Response(
        status=status,
        status_name=PKI_STATUS.get(status, f"unknown({status})"),
        status_text="; ".join(text_parts),
        failure_info=failures,
        token=token,
    )


def _decode_failure_info(item: Tlv) -> list[str]:
    if len(item.body) < 1:
        return []
    unused = item.body[0]
    bits = item.body[1:]
    names: list[str] = []
    total = len(bits) * 8 - (unused if 0 <= unused < 8 else 0)
    for position in range(max(total, 0)):
        if bits[position // 8] & (0x80 >> (position % 8)):
            names.append(FAILURE_INFO.get(position, f"bit{position}"))
    return names


@dataclass(frozen=True)
class TokenInfo:
    """The TSTInfo fields a verifier acts on, plus who signed it."""
    version: int
    policy: str
    hash_algorithm: str
    message_imprint: bytes
    serial_number: int
    gen_time: datetime
    accuracy_seconds: float | None
    ordering: bool
    nonce: int | None
    tsa_name: str | None
    signer_subject: str | None
    signer_issuer: str | None

    @property
    def gen_time_iso(self) -> str:
        return self.gen_time.isoformat(timespec="seconds").replace("+00:00", "Z")

    def to_dict(self) -> dict[str, Any]:
        return {
            "gen_time": self.gen_time_iso,
            "serial_number": str(self.serial_number),
            "policy": self.policy,
            "hash_algorithm": self.hash_algorithm,
            "message_imprint_sha256_hex": self.message_imprint.hex(),
            "accuracy_seconds": self.accuracy_seconds,
            "nonce": str(self.nonce) if self.nonce is not None else None,
            "tsa_name": self.tsa_name,
            "signer_subject": self.signer_subject,
            "signer_issuer": self.signer_issuer,
        }


@dataclass
class _SignedData:
    econtent_type: str
    econtent: bytes
    certificates: list[x509.Certificate]
    signer_infos: list[Tlv]


def _load_certificate(candidate: Tlv) -> x509.Certificate | None:
    """One member of a CertificateSet, or None.

    A set may hold attribute certificates and other CHOICE members that are
    not X.509 certificates, and a token may carry one certificate this
    version of `cryptography` refuses to parse. Neither is a reason to give
    up on the token: the signer is looked up by name below, and if the
    certificate it needs is the unreadable one the result is
    `not_verified`, which is the honest answer.
    """
    if candidate.tag != TAG_SEQUENCE:
        return None
    try:
        return x509.load_der_x509_certificate(candidate.raw)
    except Exception:  # noqa: BLE001 - see the docstring
        return None


def _parse_signed_data(token_der: bytes) -> _SignedData:
    """ContentInfo -> SignedData (RFC 5652 sections 3 and 5.1)."""
    content_info = read_all(read_one(token_der, TAG_SEQUENCE, "ContentInfo").body)
    if len(content_info) != 2:
        raise TimestampError("ContentInfo does not hold a type and a content")
    if decode_oid(content_info[0]) != OID_SIGNED_DATA:
        raise TimestampError("the time-stamp token is not a CMS SignedData")
    signed_data = read_one(_expect(content_info[1], 0xA0, "content [0]").body, TAG_SEQUENCE, "SignedData")
    items = read_all(signed_data.body)
    if len(items) < 4:
        raise TimestampError("SignedData is missing fields")
    encap = read_all(_expect(items[2], TAG_SEQUENCE, "EncapsulatedContentInfo").body)
    if not encap:
        raise TimestampError("EncapsulatedContentInfo is empty")
    econtent_type = decode_oid(encap[0])
    if len(encap) < 2:
        raise TimestampError("the token carries no eContent; it is a detached signature")
    econtent = read_one(_expect(encap[1], 0xA0, "eContent [0]").body, TAG_OCTET_STRING, "eContent").body

    certificates: list[x509.Certificate] = []
    signer_infos: list[Tlv] = []
    for item in items[3:]:
        if item.tag == 0xA0:  # [0] IMPLICIT CertificateSet
            certificates = [
                certificate
                for certificate in (_load_certificate(candidate) for candidate in read_all(item.body))
                if certificate is not None
            ]
        elif item.tag == TAG_SET:
            signer_infos = [_expect(info, TAG_SEQUENCE, "SignerInfo") for info in read_all(item.body)]
    if not signer_infos:
        raise TimestampError("SignedData carries no SignerInfo")
    return _SignedData(econtent_type, econtent, certificates, signer_infos)


def _parse_tst_info(der: bytes) -> dict[str, Any]:
    """TSTInfo, RFC 3161 section 2.4.2."""
    items = read_all(read_one(der, TAG_SEQUENCE, "TSTInfo").body)
    if len(items) < 5:
        raise TimestampError("TSTInfo is missing required fields")
    version = decode_integer(items[0])
    policy = decode_oid(items[1])
    imprint = read_all(_expect(items[2], TAG_SEQUENCE, "messageImprint").body)
    if len(imprint) != 2:
        raise TimestampError("messageImprint is not an algorithm and a digest")
    algorithm_oid = decode_oid(read_all(_expect(imprint[0], TAG_SEQUENCE, "hashAlgorithm").body)[0])
    digest = _expect(imprint[1], TAG_OCTET_STRING, "hashedMessage").body
    serial = decode_integer(items[3])
    gen_time = decode_generalized_time(items[4])

    accuracy: float | None = None
    ordering = False
    nonce: int | None = None
    tsa_name: str | None = None
    for item in items[5:]:
        if item.tag == TAG_SEQUENCE:
            accuracy = _decode_accuracy(item)
        elif item.tag == TAG_BOOLEAN:
            ordering = decode_boolean(item)
        elif item.tag == TAG_INTEGER:
            nonce = decode_integer(item)
        elif item.tag == 0xA0:  # [0] EXPLICIT GeneralName
            tsa_name = _decode_general_name(item)
    return {
        "version": version,
        "policy": policy,
        "hash_algorithm": DIGEST_NAMES.get(algorithm_oid, algorithm_oid),
        "message_imprint": digest,
        "serial_number": serial,
        "gen_time": gen_time,
        "accuracy_seconds": accuracy,
        "ordering": ordering,
        "nonce": nonce,
        "tsa_name": tsa_name,
    }


def _decode_accuracy(item: Tlv) -> float | None:
    total = 0.0
    for part in read_all(item.body):
        if part.tag == TAG_INTEGER:
            total += float(decode_integer(part))
        elif part.tag == 0x80:  # [0] IMPLICIT millis
            total += int.from_bytes(part.body, "big") / 1_000
        elif part.tag == 0x81:  # [1] IMPLICIT micros
            total += int.from_bytes(part.body, "big") / 1_000_000
    return total or None


def _decode_general_name(item: Tlv) -> str | None:
    inner = read_all(item.body)
    if not inner:
        return None
    choice = inner[0]
    if choice.tag == 0xA4:  # [4] EXPLICIT directoryName, because Name is a CHOICE
        return render_name(choice.body)
    if choice.tag == 0x86:  # [6] uniformResourceIdentifier
        return choice.body.decode("ascii", errors="replace")
    if choice.tag == 0x82:  # [2] dNSName
        return choice.body.decode("ascii", errors="replace")
    return None


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

@dataclass
class TokenVerification:
    """What was checked, what was not, and why. Never a bare boolean."""
    ok: bool = False
    imprint_matches: bool = False
    nonce_matches: bool | None = None
    signature_state: str = "not_verified"  # embedded_cert_only | not_verified | invalid
    # trusted | untrusted | unknown. "unknown" is the answer with no anchors
    # supplied, and it is the default: a chain nobody checked must never read
    # as one that passed.
    tsa_chain: str = "unknown"
    chain: dict[str, Any] = field(default_factory=dict)
    signer_eku_timestamping: bool | None = None
    signer_cert_covers_gen_time: bool | None = None
    info: TokenInfo | None = None
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "imprint_matches": self.imprint_matches,
            "nonce_matches": self.nonce_matches,
            "signature_state": self.signature_state,
            "tsa_chain": self.tsa_chain,
            "chain": self.chain,
            "signer_eku_timestamping": self.signer_eku_timestamping,
            "signer_cert_covers_gen_time": self.signer_cert_covers_gen_time,
            "problems": list(self.problems),
            "warnings": list(self.warnings),
            "token": self.info.to_dict() if self.info else None,
        }


def parse_token(token_der: bytes) -> TokenInfo:
    """Read a token without judging it. Raises `TimestampError` if unreadable."""
    signed = _parse_signed_data(token_der)
    if signed.econtent_type != OID_CT_TST_INFO:
        raise TimestampError(f"the token's content is {signed.econtent_type}, not id-ct-TSTInfo")
    fields = _parse_tst_info(signed.econtent)
    signer = _match_signer(signed)
    subject = issuer = None
    if signer is not None:
        subject = signer.subject.rfc4514_string()
        issuer = signer.issuer.rfc4514_string()
    return TokenInfo(
        version=fields["version"],
        policy=fields["policy"],
        hash_algorithm=fields["hash_algorithm"],
        message_imprint=fields["message_imprint"],
        serial_number=fields["serial_number"],
        gen_time=fields["gen_time"],
        accuracy_seconds=fields["accuracy_seconds"],
        ordering=fields["ordering"],
        nonce=fields["nonce"],
        tsa_name=fields["tsa_name"] or subject,
        signer_subject=subject,
        signer_issuer=issuer,
    )


def verify_token(
    token_der: bytes,
    expected_digest: bytes,
    *,
    hash_algorithm: str = "sha256",
    expected_nonce: int | None = None,
    trust_store: trust_mod.TrustStore | None = None,
) -> TokenVerification:
    """Check a token against the digest it is supposed to cover.

    Offline and total: any malformed input comes back as a failed result with
    a reason, never as an exception. `ok` means the imprint matched and the
    token parsed; it never means the TSA is trusted, which is what
    `tsa_chain` is for.
    """
    result = TokenVerification()
    try:
        signed = _parse_signed_data(token_der)
        if signed.econtent_type != OID_CT_TST_INFO:
            raise TimestampError(f"the token's content is {signed.econtent_type}, not id-ct-TSTInfo")
        info = parse_token(token_der)
    except TimestampError as exc:
        result.problems.append(f"time-stamp token could not be read: {exc}")
        return result
    except Exception as exc:  # noqa: BLE001 - an unreadable token is a result, not a crash
        result.problems.append(f"time-stamp token could not be read: {type(exc).__name__}: {exc}")
        return result
    result.info = info

    if info.version != 1:
        result.warnings.append(f"the token declares TSTInfo version {info.version}, not 1")
    if info.hash_algorithm != hash_algorithm:
        result.problems.append(
            f"the token was issued over a {info.hash_algorithm} imprint, the manifest is hashed with {hash_algorithm}"
        )
    result.imprint_matches = info.message_imprint == expected_digest
    if not result.imprint_matches:
        result.problems.append(
            "the time-stamp token was issued over a different digest: it does not "
            f"cover this manifest (token {info.message_imprint.hex()[:16]}..., "
            f"expected {expected_digest.hex()[:16]}...)"
        )
    if expected_nonce is not None:
        result.nonce_matches = info.nonce == expected_nonce
        if not result.nonce_matches:
            result.problems.append("the token's nonce does not match the one this request sent")

    _check_signature(signed, result)
    _check_signer_certificate(signed, info, result)

    # D-170. The signer check above establishes that the token is internally
    # consistent: its signature verifies against the certificate it carries.
    # Whether that certificate belongs to an authority this environment
    # accepts is a different question, and it has no answer without anchors
    # the caller supplied. With none, `tsa_chain` stays "unknown" - a third
    # state, not a failure - exactly as a signing key nobody vouched for is
    # reported as embedded_key_only rather than rejected.
    chain = trust_mod.evaluate(
        _match_signer(signed),
        list(signed.certificates),
        trust_store,
        info.gen_time,
    )
    result.tsa_chain = chain.state
    result.chain = chain.to_dict()
    if chain.state == trust_mod.UNTRUSTED:
        result.problems.extend(chain.problems)
    elif chain.state == trust_mod.UNKNOWN:
        result.warnings.append(
            "TSA CHAIN NOT CHECKED: no trust anchors were supplied, so the authority that "
            "issued this token is unknown. The token is internally consistent; that is all."
        )

    if chain.state != trust_mod.TRUSTED:
        # Unconditional until D-170. That was correct while no chain was ever
        # checked and became a lie the moment one could be: a package verified
        # against anchors the caller supplied would have carried a warning
        # saying nothing checked the chain, which is the exact confusion this
        # whole module is written to avoid.
        result.warnings.append(
            "TSA CERTIFICATE CHAIN NOT VERIFIED: the token was checked against the "
            "certificate it carries. Seamark ships no trust store, so nothing here "
            "says that certificate belongs to a timestamp authority you accept. "
            "Pass --tsa-trust-store with anchors you have chosen."
        )
    # `not_verified` is not a milder shade of "checked". It is the state the
    # module reaches when there was no certificate to check against, when the
    # algorithms are ones this verifier does not implement, or when the broad
    # `except` clauses in `_check_signature` swallowed something on the way.
    # Treating it as equivalent to `embedded_cert_only` made an unchecked
    # token indistinguishable from a checked one at the only place a caller
    # looks, which is exactly the "never say verified about something that
    # was not" rule this module opens with. So `ok` now requires the positive
    # state, and the reason is written into `problems` rather than left in a
    # warning a caller may not read.
    if result.signature_state == "not_verified":
        result.problems.append(
            "the time-stamp token's own signature was NOT checked, so nothing here "
            "says the token was issued by the certificate it carries or that it was "
            "not edited afterwards"
        )
    result.ok = (
        result.imprint_matches
        and result.signature_state == "embedded_cert_only"
        and not result.problems
    )
    return result


def _check_signature(signed: _SignedData, result: TokenVerification) -> None:
    """The CMS signature over the token's own content, against its own cert."""
    try:
        items = read_all(signed.signer_infos[0].body)
        if len(items) < 5:
            raise TimestampError("SignerInfo is missing fields")
        digest_algorithm = decode_oid(read_all(_expect(items[2], TAG_SEQUENCE, "digestAlgorithm").body)[0])
        cursor = 3
        signed_attrs = None
        if items[cursor].tag == 0xA0:
            signed_attrs = items[cursor]
            cursor += 1
        signature_algorithm = decode_oid(read_all(_expect(items[cursor], TAG_SEQUENCE, "signatureAlgorithm").body)[0])
        cursor += 1
        signature = _expect(items[cursor], TAG_OCTET_STRING, "signature").body

        digest_name = DIGEST_NAMES.get(digest_algorithm, digest_algorithm)
        if digest_name not in _HASHES:
            result.warnings.append(
                f"token signature not checked: it is digested with {digest_name}, "
                "which this verifier does not accept"
            )
            return
        hash_class = _HASHES[digest_name]

        if signed_attrs is None:
            signed_bytes = signed.econtent
        else:
            _verify_signed_attributes(signed_attrs, signed, hash_class)
            # RFC 5652 section 5.4: the signature is over the DER SET OF, not
            # over the [0] IMPLICIT tag the attributes actually arrived with.
            signed_bytes = _tlv(TAG_SET, signed_attrs.body)

        certificate = _match_signer(signed)
        if certificate is None:
            result.warnings.append(
                "token signature not checked: the token carries no certificate for its signer, "
                "so there is nothing to check it against"
            )
            return
        family, fixed_digest = _SIGNATURE_ALGORITHMS.get(signature_algorithm, ("", None))
        if fixed_digest is not None and fixed_digest != digest_name:
            raise TimestampError(
                f"signatureAlgorithm says {fixed_digest} and digestAlgorithm says {digest_name}"
            )
        public_key = certificate.public_key()
        if family == "rsa" and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, signed_bytes, padding.PKCS1v15(), hash_class())
        elif family == "ecdsa" and isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, signed_bytes, ec.ECDSA(hash_class()))
        elif family == "ed25519" and isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, signed_bytes)
        else:
            result.warnings.append(
                f"token signature not checked: signature algorithm {signature_algorithm} "
                "is not one this verifier implements"
            )
            return
    except InvalidSignature:
        result.signature_state = "invalid"
        result.problems.append(
            "the time-stamp token's own signature does not verify against the certificate it carries"
        )
        return
    except TokenTamperedError as exc:
        result.signature_state = "invalid"
        result.problems.append(f"the time-stamp token contradicts itself: {exc}")
        return
    except (TimestampError, UnsupportedAlgorithm) as exc:
        result.warnings.append(f"token signature not checked: {exc}")
        return
    except Exception as exc:  # noqa: BLE001 - as everywhere here, a result rather than a crash
        result.warnings.append(f"token signature not checked: {type(exc).__name__}: {exc}")
        return
    result.signature_state = "embedded_cert_only"


def _verify_signed_attributes(
    signed_attrs: Tlv, signed: _SignedData, hash_class: Callable[[], hashes.HashAlgorithm]
) -> None:
    """message-digest and content-type, the two attributes that bind the
    signature to the payload. Without this check a signature over a valid
    attribute set could be lifted onto any other TSTInfo."""
    digest_value: bytes | None = None
    content_type: str | None = None
    for attribute in read_all(signed_attrs.body):
        parts = read_all(_expect(attribute, TAG_SEQUENCE, "SignedAttribute").body)
        if len(parts) != 2:
            continue
        oid = decode_oid(parts[0])
        values = read_all(_expect(parts[1], TAG_SET, "attribute values").body)
        if not values:
            continue
        if oid == OID_ATTR_MESSAGE_DIGEST:
            digest_value = _expect(values[0], TAG_OCTET_STRING, "messageDigest").body
        elif oid == OID_ATTR_CONTENT_TYPE:
            content_type = decode_oid(values[0])
    if content_type is not None and content_type != OID_CT_TST_INFO:
        raise TokenTamperedError(f"the signed content-type attribute says {content_type}, not id-ct-TSTInfo")
    if digest_value is None:
        raise TimestampError("the signed attributes carry no message-digest")
    digest = hashes.Hash(hash_class())
    digest.update(signed.econtent)
    if digest.finalize() != digest_value:
        raise TokenTamperedError("the signed message-digest attribute does not match the TSTInfo the token carries")


def _match_signer(signed: _SignedData) -> x509.Certificate | None:
    """The certificate the SignerInfo names, by issuer and serial or by key id.

    No fallback to "the only certificate present": a token that names a
    signer it does not carry has not been checked, and guessing would turn
    that into a green tick.
    """
    try:
        items = read_all(signed.signer_infos[0].body)
        sid = items[1]
        if sid.tag == TAG_SEQUENCE:  # issuerAndSerialNumber
            parts = read_all(sid.body)
            if len(parts) != 2:
                return None
            issuer_der = parts[0].raw
            serial = decode_integer(parts[1])
            for certificate in signed.certificates:
                if certificate.serial_number == serial and certificate.issuer.public_bytes() == issuer_der:
                    return certificate
            return None
        if sid.tag == 0x80:  # [0] IMPLICIT subjectKeyIdentifier
            wanted = sid.body
            for certificate in signed.certificates:
                try:
                    extension = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
                except x509.ExtensionNotFound:
                    continue
                if extension.value.digest == wanted:
                    return certificate
            return None
    except (TimestampError, ValueError):
        return None
    return None


def _check_signer_certificate(signed: _SignedData, info: TokenInfo, result: TokenVerification) -> None:
    """Two properties of the signer certificate that are checkable offline.

    RFC 3161 section 2.3 requires the TSA certificate to carry the
    timeStamping extended key usage and only that one. A certificate without
    it was not issued for this job, whoever signed it.
    """
    certificate = _match_signer(signed)
    if certificate is None:
        return
    try:
        usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        result.signer_eku_timestamping = any(
            usage.dotted_string == OID_KP_TIME_STAMPING for usage in usages
        )
    except x509.ExtensionNotFound:
        result.signer_eku_timestamping = False
    except Exception:  # noqa: BLE001 - a malformed extension is "not established", not a crash
        result.signer_eku_timestamping = None
    if result.signer_eku_timestamping is False:
        result.warnings.append(
            "the token's signer certificate does not carry the timeStamping extended "
            "key usage that RFC 3161 requires of a TSA"
        )
    try:
        covers = certificate.not_valid_before_utc <= info.gen_time <= certificate.not_valid_after_utc
        result.signer_cert_covers_gen_time = covers
        if not covers:
            result.warnings.append(
                "the token's genTime falls outside the validity window of the certificate that signed it"
            )
    except Exception:  # noqa: BLE001
        result.signer_cert_covers_gen_time = None


# ---------------------------------------------------------------------------
# One call, for the CLI
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StampResult:
    token: bytes
    info: TokenInfo
    verification: TokenVerification
    tsa_url: str


def stamp(
    url: str,
    digest: bytes,
    *,
    hash_algorithm: str = "sha256",
    timeout: float = 10.0,
) -> StampResult:
    """Ask `url` to time-stamp `digest`, and check the answer before keeping it.

    A token that does not verify against the digest we asked about is not
    written to the package: keeping it would put a claim in the manifest that
    the package itself contradicts.
    """
    nonce = make_nonce()
    request = build_request(digest, hash_algorithm=hash_algorithm, nonce=nonce, cert_req=True)
    payload = post_request(url, request, timeout=timeout)
    try:
        response = parse_response(payload)
    except TimestampError as exc:
        # Worth the extra sentence: the usual cause is a proxy or a captive
        # portal answering instead of the TSA, and "truncated DER" on its own
        # sends the reader looking for a bug in the parser.
        raise TimestampError(
            f"{url} answered with something that is not a TimeStampResp ({exc}). "
            f"First bytes: {payload[:48]!r}"
        ) from exc
    if not response.granted:
        detail = response.status_text or ", ".join(response.failure_info) or "no reason given"
        raise TimestampError(f"the TSA refused the request ({response.status_name}): {detail}")
    assert response.token is not None
    verification = verify_token(
        response.token, digest, hash_algorithm=hash_algorithm, expected_nonce=nonce
    )
    if not verification.ok or verification.info is None:
        raise TimestampError(
            "the TSA answered with a token this verifier does not accept: "
            + "; ".join(verification.problems)
        )
    return StampResult(
        token=response.token, info=verification.info, verification=verification, tsa_url=url
    )


