"""A timestamp authority the test suite runs itself.

The RFC 3161 tests need two different kinds of input and this file is the
second kind.

The first kind lives in `tests/fixtures/rfc3161/`: real responses written by
OpenSSL, so that the parser is checked against bytes this project did not
produce. Those are fixed, which is exactly what makes them useless for the
end-to-end path: a captured token is over a captured digest, and the manifest
of a package built during a test hashes to something new every run.

So this file issues tokens over any digest asked of it. It is a second
implementation on purpose - its DER encoder is written here rather than
imported from `actaira.attest.timestamp`, because a test that encodes with
the code under test and then decodes with the code under test proves only
that the code agrees with itself. And it signs with ECDSA P-256, where the
OpenSSL fixtures sign with RSA, so the two together cover both branches of
the verifier's signature handling.

`test_timestamp.py` also hands what this file produces back to OpenSSL when
OpenSSL is installed, which is what keeps the second implementation honest.
"""
from __future__ import annotations

import http.server
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
# RFC 5035. A TSA that answers certReq must bind the certificate it wants to
# be checked against into the signed attributes; OpenSSL refuses a token
# without it, which is how this fixture came to have one.
OID_ATTR_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"
DEFAULT_POLICY = "1.3.6.1.4.1.99999.2.1"


# ---------------------------------------------------------------------------
# DER, written independently of src/actaira/attest/timestamp.py
# ---------------------------------------------------------------------------

def der(tag: int, body: bytes) -> bytes:
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    size = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + body


def integer(value: int) -> bytes:
    width = 1 if value == 0 else (value.bit_length() // 8) + 1
    return der(0x02, value.to_bytes(width, "big"))


def oid(dotted: str) -> bytes:
    arcs = [int(part) for part in dotted.split(".")]
    body = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        piece = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            piece.append((arc & 0x7F) | 0x80)
            arc >>= 7
        body.extend(reversed(piece))
    return der(0x06, bytes(body))


def octets(payload: bytes) -> bytes:
    return der(0x04, payload)


def sequence(*parts: bytes) -> bytes:
    return der(0x30, b"".join(parts))


def der_set(*parts: bytes) -> bytes:
    # DER orders the members of a SET OF by their encoding.
    return der(0x31, b"".join(sorted(parts)))


def algorithm(dotted: str, null_parameter: bool = True) -> bytes:
    return sequence(oid(dotted) + (der(0x05, b"") if null_parameter else b""))


def generalized_time(moment: datetime) -> bytes:
    return der(0x18, moment.astimezone(UTC).strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """(tag, body, next offset). Enough to read a TimeStampReq, no more."""
    tag = data[offset]
    first = data[offset + 1]
    if first < 0x80:
        size, start = first, offset + 2
    else:
        count = first & 0x7F
        size = int.from_bytes(data[offset + 2:offset + 2 + count], "big")
        start = offset + 2 + count
    return tag, data[start:start + size], start + size


def read_children(body: bytes) -> list[tuple[int, bytes]]:
    items: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(body):
        tag, contents, offset = read_tlv(body, offset)
        items.append((tag, contents))
    return items


@dataclass
class ParsedQuery:
    digest: bytes
    nonce: int | None
    cert_req: bool


def parse_query(request_der: bytes) -> ParsedQuery:
    _, body, _ = read_tlv(request_der)
    items = read_children(body)
    imprint = read_children(items[1][1])
    digest = imprint[1][1]
    nonce = None
    cert_req = False
    for tag, contents in items[2:]:
        if tag == 0x02:
            nonce = int.from_bytes(contents, "big")
        elif tag == 0x01:
            cert_req = contents != b"\x00"
    return ParsedQuery(digest=digest, nonce=nonce, cert_req=cert_req)


# ---------------------------------------------------------------------------
# The authority
# ---------------------------------------------------------------------------

class FixtureTSA:
    """A two-certificate chain and a serial counter. No state on disk."""

    def __init__(self, *, name: str = "Actaira Test TSA", eku_timestamping: bool = True) -> None:
        self.serial = 0
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.tsa_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)

        root_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Actaira Test Fixtures"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{name} Root"),
        ])
        self.root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_name)
            .issuer_name(root_name)
            .public_key(self.root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True,
                    crl_sign=True, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.root_key, hashes.SHA256())
        )

        leaf_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Actaira Test Fixtures"),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ])
        builder = (
            x509.CertificateBuilder()
            .subject_name(leaf_name)
            .issuer_name(root_name)
            .public_key(self.tsa_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.tsa_key.public_key()), critical=False)
        )
        if eku_timestamping:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
            )
        self.tsa_cert = builder.sign(self.root_key, hashes.SHA256())

    # -- pieces ------------------------------------------------------------
    @property
    def tsa_cert_der(self) -> bytes:
        return self.tsa_cert.public_bytes(serialization.Encoding.DER)

    @property
    def root_cert_pem(self) -> bytes:
        return self.root_cert.public_bytes(serialization.Encoding.PEM)

    @property
    def tsa_cert_pem(self) -> bytes:
        return self.tsa_cert.public_bytes(serialization.Encoding.PEM)

    def tst_info(
        self,
        digest: bytes,
        *,
        nonce: int | None,
        gen_time: datetime,
        serial: int,
        policy: str = DEFAULT_POLICY,
        name_in_token: bool = True,
    ) -> bytes:
        imprint = sequence(algorithm(OID_SHA256) + octets(digest))
        body = integer(1) + oid(policy) + imprint + integer(serial) + generalized_time(gen_time)
        body += sequence(integer(1))  # accuracy: one second
        if nonce is not None:
            body += integer(nonce)
        if name_in_token:
            # [0] EXPLICIT GeneralName, whose directoryName choice is [4] EXPLICIT
            body += der(0xA0, der(0xA4, self.tsa_cert.subject.public_bytes()))
        return sequence(body)

    def token(self, tst_info: bytes, *, include_certificate: bool = True) -> bytes:
        content_digest = hashes.Hash(hashes.SHA256())
        content_digest.update(tst_info)
        certificate_digest = hashes.Hash(hashes.SHA256())
        certificate_digest.update(self.tsa_cert_der)
        # ESSCertIDv2 with the default hashAlgorithm, so SHA-256 and no
        # AlgorithmIdentifier on the wire: SEQUENCE { SEQUENCE { SEQUENCE {
        # OCTET STRING certHash } } }
        ess = sequence(sequence(sequence(octets(certificate_digest.finalize()))))
        signed_attributes = [
            sequence(oid(OID_ATTR_CONTENT_TYPE) + der_set(oid(OID_CT_TST_INFO))),
            sequence(oid(OID_ATTR_MESSAGE_DIGEST) + der_set(octets(content_digest.finalize()))),
            sequence(oid(OID_ATTR_SIGNING_CERTIFICATE_V2) + der_set(ess)),
        ]
        attributes_body = b"".join(sorted(signed_attributes))
        signature = self.tsa_key.sign(der(0x31, attributes_body), ec.ECDSA(hashes.SHA256()))

        signer_info = sequence(
            integer(1)
            + sequence(self.tsa_cert.issuer.public_bytes() + integer(self.tsa_cert.serial_number))
            + algorithm(OID_SHA256)
            + der(0xA0, attributes_body)
            + algorithm(OID_ECDSA_SHA256, null_parameter=False)
            + octets(signature)
        )
        encap = sequence(oid(OID_CT_TST_INFO) + der(0xA0, octets(tst_info)))
        pieces = integer(3) + der_set(algorithm(OID_SHA256)) + encap
        if include_certificate:
            pieces += der(0xA0, self.tsa_cert_der + self.root_cert.public_bytes(serialization.Encoding.DER))
        pieces += der_set(signer_info)
        return sequence(oid(OID_SIGNED_DATA) + der(0xA0, sequence(pieces)))

    def respond(
        self,
        request_der: bytes,
        *,
        gen_time: datetime | None = None,
        status: int = 0,
        echo_nonce: bool = True,
        include_certificate: bool | None = None,
        name_in_token: bool = True,
    ) -> bytes:
        query = parse_query(request_der)
        if status != 0:
            return sequence(
                sequence(
                    integer(status)
                    + sequence(der(0x0C, b"the fixture authority refused this request"))
                    + der(0x03, b"\x01\x02")
                )
            )
        self.serial += 1
        info = self.tst_info(
            query.digest,
            nonce=query.nonce if echo_nonce else None,
            gen_time=gen_time or datetime.now(UTC),
            serial=self.serial,
            name_in_token=name_in_token,
        )
        carry = query.cert_req if include_certificate is None else include_certificate
        return sequence(sequence(integer(0)) + self.token(info, include_certificate=carry))


# ---------------------------------------------------------------------------
# The same authority, over HTTP on the loopback interface
# ---------------------------------------------------------------------------

@contextmanager
def serving(authority: FixtureTSA, **response_options):
    """A TSA on 127.0.0.1 for the length of the `with` block.

    Loopback only, an ephemeral port, and no keep-alive: this exists to
    exercise `post_request` against a socket, not to be a server.
    """
    state = {"requests": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - the name http.server dispatches on
            state["requests"] += 1
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            state["content_type"] = self.headers.get("Content-Type", "")
            state["accept"] = self.headers.get("Accept", "")
            if self.path.endswith("/http-error"):
                self.send_response(500)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"the fixture authority is out of order")
                return
            if self.path.endswith("/not-der"):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Host not in allowlist: tsa.example.com")
                return
            if self.path.endswith("/flood"):
                payload = b"\x00" * (2 << 20)
            else:
                payload = authority.respond(body, **response_options)
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args) -> None:  # keep the test output readable
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/tsr", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
