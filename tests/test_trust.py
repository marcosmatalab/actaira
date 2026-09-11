"""Chain validation: the three states, and what each one is worth.

Design note D-170. The claim being tested is narrow and it has to stay narrow:
with anchors the caller supplied, a path was built and every signature on it
verified. Without anchors, nothing was concluded. The failure this file exists
to prevent is the middle state quietly reading as the first.

Inputs come from two places that are not this module. The RSA fixtures in
`tests/fixtures/rfc3161/` were issued by OpenSSL, root and leaf both, so the
path being walked is one OpenSSL built. `tests/tsa.py` issues ECDSA chains at
test time, so both signature branches of the walker are exercised by
certificates this module did not create.
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import tsa
from actaira.attest import timestamp as ts
from actaira.attest import trust
from conftest import REPO_ROOT

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "rfc3161"
SUBJECT_DIGEST = hashlib.sha256((FIXTURES / "subject.bin").read_bytes()).digest()


@pytest.fixture(scope="module")
def openssl_token() -> bytes:
    return ts.parse_response((FIXTURES / "granted.tsr").read_bytes()).token


@pytest.fixture(scope="module")
def openssl_root() -> trust.TrustStore:
    return trust.load_store(FIXTURES / "ca.crt")


@pytest.fixture(scope="module")
def authority() -> tsa.FixtureTSA:
    return tsa.FixtureTSA()


def issue(authority: tsa.FixtureTSA, digest: bytes) -> bytes:
    """A token over `digest`, from the fixture authority."""
    response = authority.respond(ts.build_request(digest, nonce=None, cert_req=True))
    return ts.parse_response(response).token


def store_of(*certificates: x509.Certificate) -> trust.TrustStore:
    store = trust.TrustStore()
    for certificate in certificates:
        store.add(certificate)
    return store


# --------------------------------------------------------------------------
# The three states
# --------------------------------------------------------------------------


def test_a_token_whose_root_is_an_anchor_is_trusted(openssl_token, openssl_root):
    """The positive case, over a chain OpenSSL issued rather than one this
    test built, so the walker is agreeing with another implementation."""
    result = ts.verify_token(openssl_token, SUBJECT_DIGEST, trust_store=openssl_root)

    assert result.tsa_chain == trust.TRUSTED
    assert result.chain["anchor"].startswith("CN=Actaira Fixture Root CA")
    assert result.chain["path"], "a trusted answer names the path it walked"
    assert not any("NOT VERIFIED" in warning for warning in result.warnings)


def test_with_no_store_the_chain_is_unknown_and_nothing_is_concluded(openssl_token):
    """The third state. Not a failure, and it must never read as the first:
    a signing key nobody vouched for is reported the same way."""
    result = ts.verify_token(openssl_token, SUBJECT_DIGEST)

    assert result.tsa_chain == trust.UNKNOWN
    assert result.ok, "an unknown chain does not make a token invalid"
    assert "no trust anchors" in " ".join(result.chain["problems"])


def test_a_root_that_is_not_the_issuer_makes_the_chain_untrusted(openssl_token, authority):
    """The negative control that decides whether the positive test means
    anything. A store containing some other CA must not satisfy the walk."""
    result = ts.verify_token(openssl_token, SUBJECT_DIGEST, trust_store=store_of(authority.root_cert))

    assert result.tsa_chain == trust.UNTRUSTED
    assert any("no issuer" in problem for problem in result.chain["problems"])


def test_an_ecdsa_chain_is_walked_as_well_as_an_rsa_one(authority):
    """The fixtures are RSA; `tests/tsa.py` signs with ECDSA. Both branches of
    the signature check need a real certificate through them, because a
    branch nothing exercises is a branch that is wrong."""
    digest = hashlib.sha256(b"anything").digest()
    token = issue(authority, digest)

    trusted = ts.verify_token(token, digest, trust_store=store_of(authority.root_cert))
    stranger = ts.verify_token(token, digest, trust_store=trust.load_store(FIXTURES / "ca.crt"))

    assert trusted.tsa_chain == trust.TRUSTED
    assert stranger.tsa_chain == trust.UNTRUSTED


# --------------------------------------------------------------------------
# What makes a path fail
# --------------------------------------------------------------------------


def test_a_signer_without_the_timestamping_usage_is_untrusted_under_any_root():
    """Refused at the leaf rather than folded into the walk. A certificate
    with no id-kp-timeStamping is not a time-stamping authority however
    impeccable its issuer, and accepting one would let any certificate under
    a trusted root stamp time."""
    authority = tsa.FixtureTSA(eku_timestamping=False)
    digest = hashlib.sha256(b"anything").digest()
    token = issue(authority, digest)

    result = ts.verify_token(token, digest, trust_store=store_of(authority.root_cert))

    assert result.tsa_chain == trust.UNTRUSTED
    assert any("timeStamping" in problem for problem in result.chain["problems"])


def test_the_chain_is_judged_at_the_token_s_gen_time_not_today(authority):
    """A token issued in 2024 under a certificate that expired in 2025 was
    valid when it was issued. Judging it against the verifier's clock would
    reject every token the moment its TSA rotated - which is precisely the
    situation the check exists for."""
    leaf = authority.tsa_cert
    store = store_of(authority.root_cert)

    at_issue = trust.evaluate(leaf, [leaf, authority.root_cert], store, leaf.not_valid_before_utc + timedelta(days=1))
    long_after = trust.evaluate(
        leaf, [leaf, authority.root_cert], store, leaf.not_valid_after_utc + timedelta(days=365)
    )

    assert at_issue.state == trust.TRUSTED
    assert long_after.state == trust.UNTRUSTED
    assert any("not valid at" in problem for problem in long_after.problems)


def test_an_issuer_that_is_not_a_ca_cannot_issue():
    """basicConstraints is the whole of what separates a leaf from a CA. A
    walker that skipped it would let any certificate signed by a trusted TSA
    become an issuer."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Not A CA")])
    now = datetime.now(UTC)

    # A self-signed certificate that does not claim to be a CA.
    pretend_root = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Leaf")]))
        .issuer_name(name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
        )
        .sign(root_key, hashes.SHA256())
    )

    result = trust.evaluate(leaf, [leaf, pretend_root], store_of(pretend_root), now)

    assert result.state == trust.UNTRUSTED
    assert any("not a CA" in problem for problem in result.problems)


def test_a_forged_leaf_under_a_real_issuer_name_does_not_verify(authority):
    """The attack the signature check exists for: take a trusted root's name,
    issue yourself a leaf, and hope nobody checks who actually signed it."""
    forger = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    forged = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Forged TSA")]))
        .issuer_name(authority.root_cert.subject)  # claims the real root
        .public_key(forger.public_key())
        .serial_number(99)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
        )
        .sign(forger, hashes.SHA256())  # signed by itself, not by the root
    )

    result = trust.evaluate(forged, [forged, authority.root_cert], store_of(authority.root_cert), now)

    assert result.state == trust.UNTRUSTED
    assert any("not signed by" in problem for problem in result.problems)


# --------------------------------------------------------------------------
# The store itself
# --------------------------------------------------------------------------


def test_the_store_is_keyed_by_public_key_not_by_name(authority):
    """A name is a label and a key is an identity. Two certificates with the
    same subject and different keys are different anchors, and a store keyed
    by name would let the second impersonate the first."""
    other = tsa.FixtureTSA()

    store = store_of(authority.root_cert)

    assert store.contains(authority.root_cert)
    assert not store.contains(other.root_cert)


def test_a_store_that_holds_no_certificate_is_an_error_not_an_empty_store(tmp_path):
    """An empty store that loaded successfully would answer `unknown` for
    every token, which reads exactly like having supplied no store at all -
    so a typo in a path would silently disable the check the caller asked
    for."""
    empty = tmp_path / "anchors.pem"
    empty.write_text("# nothing here\n", encoding="utf-8")

    with pytest.raises(ValueError):
        trust.load_store(empty)


def test_a_directory_of_pem_files_loads_as_one_store(tmp_path, authority):
    for index, certificate in enumerate((authority.root_cert, tsa.FixtureTSA().root_cert)):
        (tmp_path / f"anchor{index}.pem").write_bytes(
            certificate.public_bytes(serialization.Encoding.PEM)
        )

    store = trust.load_store(tmp_path)

    assert len(store) == 2
    assert store.contains(authority.root_cert)


def test_every_answer_carries_what_it_does_not_check(openssl_token, openssl_root):
    """The limits travel with the answer rather than living only in a
    docstring. A verifier who reads "trusted" without them is reading a
    stronger claim than was made - revocation above all."""
    result = ts.verify_token(openssl_token, SUBJECT_DIGEST, trust_store=openssl_root)

    limits = " ".join(result.chain["does_not_check"])

    assert "revocation" in limits
    assert "CRL" in limits and "OCSP" in limits


def test_a_trust_store_that_cannot_be_read_fails_the_verification(tmp_path):
    """Named and unreadable is a usage error. Falling back to checking
    nothing would silently verify without the anchors somebody asked for,
    which is the shape of failure this module exists to prevent."""
    from actaira.attest import verify as verify_mod

    missing = tmp_path / "not-here.pem"
    package = tmp_path / "package.zip"
    package.write_bytes(b"not a package")

    result = verify_mod.verify_package(package, tsa_trust_store=missing)

    assert not result.ok
