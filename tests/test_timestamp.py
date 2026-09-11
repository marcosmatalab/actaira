"""RFC 3161, checked against two implementations that are not this one.

Design note D-27 says the time anchor is optional, that what it proves is
narrow, and that nothing may be called verified unless it was. This file is
where those three claims are held to account, and it takes its inputs from
outside the module under test on purpose:

  * `tests/fixtures/rfc3161/` holds responses written by OpenSSL. The parser
    is asserted against bytes this project did not produce, and the request
    encoder is compared byte for byte with OpenSSL's own `.tsq`.
  * `tests/tsa.py` is a second implementation, written independently in the
    test tree, that issues tokens over any digest. It exists because the
    end-to-end path needs a token over a manifest that only exists during the
    test, and it signs with ECDSA where the fixtures use RSA, so both
    branches of the signature check are exercised.
  * when OpenSSL is installed, it is asked to verify what `tests/tsa.py`
    issues, which is what stops the second implementation from drifting into
    agreeing only with the first.

Nothing here touches the network. The only socket in the file is a loopback
server the test starts and stops itself.
"""
from __future__ import annotations

import hashlib
import random
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import tsa
from actaira.attest import timestamp as ts
from conftest import REPO_ROOT

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "rfc3161"
SUBJECT = (FIXTURES / "subject.bin").read_bytes()
OTHER = (FIXTURES / "other.bin").read_bytes()
SUBJECT_DIGEST = hashlib.sha256(SUBJECT).digest()
OPENSSL = shutil.which("openssl")


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


@pytest.fixture(scope="module")
def authority() -> tsa.FixtureTSA:
    return tsa.FixtureTSA()


# ---------------------------------------------------------------------------
# The request, byte for byte against OpenSSL
# ---------------------------------------------------------------------------

def test_the_request_is_the_one_openssl_writes():
    """`openssl ts -query -data subject.bin -sha256 -cert -no_nonce`.

    Byte equality, not "parses the same": a hand-written DER encoder that is
    merely self-consistent is the failure mode this test exists to catch.
    """
    assert ts.build_request(SUBJECT_DIGEST, nonce=None, cert_req=True) == fixture("query_cert_nononce.tsq")


def test_certreq_false_is_omitted_because_it_is_the_asn1_default():
    assert ts.build_request(SUBJECT_DIGEST, nonce=None, cert_req=False) == fixture("query_nocert_nononce.tsq")


def test_the_two_requests_differ_only_by_the_certreq_flag():
    """A control for the two assertions above: they must not be comparing the
    same bytes to themselves."""
    with_flag = fixture("query_cert_nononce.tsq")
    without = fixture("query_nocert_nononce.tsq")

    assert with_flag != without
    assert len(with_flag) == len(without) + 3
    assert with_flag.endswith(b"\x01\x01\xff")


def test_a_digest_of_the_wrong_length_for_its_algorithm_is_refused():
    with pytest.raises(ts.TimestampError):
        ts.build_request(b"\x00" * 31, hash_algorithm="sha256")


def test_sha1_can_be_read_but_never_requested():
    assert ts.DIGEST_NAMES[ts.OID_SHA1] == "sha1"
    with pytest.raises(ts.TimestampError):
        ts.build_request(b"\x00" * 20, hash_algorithm="sha1")


def test_a_nonce_with_its_top_bit_set_still_encodes_as_a_positive_integer():
    request = ts.build_request(SUBJECT_DIGEST, nonce=0x8000000000000001, cert_req=False)
    parsed = tsa.parse_query(request)

    assert parsed.nonce == 0x8000000000000001


@pytest.mark.parametrize("value,encoded", [(0, b"\x02\x01\x00"), (127, b"\x02\x01\x7f"),
                                           (128, b"\x02\x02\x00\x80"), (256, b"\x02\x02\x01\x00")])
def test_integers_use_the_minimal_signed_form(value, encoded):
    assert ts._der_integer(value) == encoded


def test_object_identifiers_round_trip_through_both_directions():
    for dotted in (ts.OID_SHA256, ts.OID_CT_TST_INFO, ts.OID_KP_TIME_STAMPING, "1.2.840.113549.1.1.11"):
        assert ts.decode_oid(ts.read_one(ts._der_oid(dotted), 0x06)) == dotted


# ---------------------------------------------------------------------------
# Parsing what OpenSSL answered
# ---------------------------------------------------------------------------

def test_a_captured_granted_response_carries_a_token():
    response = ts.parse_response(fixture("granted.tsr"))

    assert (response.status, response.status_name) == (0, "granted")
    assert response.granted
    assert response.token is not None


def test_a_captured_rejection_carries_its_reason_and_no_token():
    """The negative control for the test above. A rejection that parsed as a
    grant would be the worst possible failure of this module."""
    response = ts.parse_response(fixture("rejection.tsr"))

    assert response.status == 2
    assert response.status_name == "rejection"
    assert response.token is None
    assert not response.granted
    assert "policy" in response.status_text.lower()
    assert "unacceptedPolicy" in response.failure_info


def test_the_captured_token_verifies_over_the_document_it_covers():
    response = ts.parse_response(fixture("granted.tsr"))

    result = ts.verify_token(response.token, SUBJECT_DIGEST)

    assert result.ok
    assert result.imprint_matches
    assert result.signature_state == "embedded_cert_only"
    assert result.info.hash_algorithm == "sha256"
    assert result.info.gen_time.tzinfo is not None


def test_with_no_anchors_the_chain_is_unknown_and_says_so_out_loud():
    """The whole point of D-27's third claim, now with a name for the third
    state. `ok` must never be read as "the authority is trusted", and with no
    anchors supplied the honest answer is neither trusted nor untrusted."""
    result = ts.verify_token(ts.parse_response(fixture("granted.tsr")).token, SUBJECT_DIGEST)

    assert result.ok
    assert result.tsa_chain == "unknown"
    assert any("NOT CHECKED" in warning for warning in result.warnings)
    assert result.chain["does_not_check"], "the answer travels with its limits"


def test_the_name_read_out_of_the_token_matches_the_signer_certificate():
    """`render_name` parses an RDNSequence by hand. This pins it against the
    name `cryptography` renders for the same certificate."""
    result = ts.verify_token(ts.parse_response(fixture("granted.tsr")).token, SUBJECT_DIGEST)

    assert result.info.tsa_name == result.info.signer_subject
    assert result.info.tsa_name.startswith("CN=Actaira Fixture TSA")
    assert result.info.signer_issuer.startswith("CN=Actaira Fixture Root CA")


def test_the_signer_certificate_is_checked_for_the_timestamping_key_usage():
    result = ts.verify_token(ts.parse_response(fixture("granted.tsr")).token, SUBJECT_DIGEST)

    assert result.signer_eku_timestamping is True
    assert result.signer_cert_covers_gen_time is True


def test_a_token_over_another_document_does_not_verify_against_this_one():
    response = ts.parse_response(fixture("granted_other_subject.tsr"))

    result = ts.verify_token(response.token, SUBJECT_DIGEST)

    assert not result.ok
    assert not result.imprint_matches
    assert any("different digest" in problem for problem in result.problems)
    # and it does verify against the document it was actually issued over
    assert ts.verify_token(response.token, hashlib.sha256(OTHER).digest()).ok


def test_a_token_with_no_certificate_is_unchecked_rather_than_verified():
    """`not_verified` and `embedded_cert_only` are different answers and the
    difference is the reason this module exists."""
    response = ts.parse_response(fixture("granted_no_cert.tsr"))

    result = ts.verify_token(response.token, SUBJECT_DIGEST)

    assert result.imprint_matches
    assert result.signature_state == "not_verified"
    assert any("no certificate" in warning for warning in result.warnings)
    assert result.signer_eku_timestamping is None


# ---------------------------------------------------------------------------
# Tampering
# ---------------------------------------------------------------------------

def test_flipping_a_byte_of_the_imprint_is_caught():
    token = bytearray(ts.parse_response(fixture("granted.tsr")).token)
    token[token.index(SUBJECT_DIGEST) + 5] ^= 0xFF

    result = ts.verify_token(bytes(token), SUBJECT_DIGEST)

    assert not result.ok
    assert not result.imprint_matches
    assert result.signature_state == "invalid"


def test_flipping_a_byte_of_the_signature_is_caught_as_invalid_not_as_unchecked():
    token = bytearray(ts.parse_response(fixture("granted.tsr")).token)
    token[-10] ^= 0xFF

    result = ts.verify_token(bytes(token), SUBJECT_DIGEST)

    assert not result.ok
    assert result.imprint_matches, "the imprint is untouched; only the signature moved"
    assert result.signature_state == "invalid"


def test_swapping_the_payload_under_a_good_signature_is_caught(authority):
    """The lift attack: keep a valid signature over a valid attribute set and
    put a different TSTInfo underneath it. Only the message-digest attribute
    stands between that and a forged timestamp."""
    moment = datetime.now(UTC)
    mine = authority.tst_info(SUBJECT_DIGEST, nonce=1, gen_time=moment, serial=7)
    theirs = authority.tst_info(hashlib.sha256(OTHER).digest(), nonce=1, gen_time=moment, serial=7)
    token = authority.token(mine)
    assert len(mine) == len(theirs), "the splice below assumes equal lengths"
    spliced = token.replace(mine, theirs)
    assert spliced != token

    result = ts.verify_token(spliced, hashlib.sha256(OTHER).digest())

    assert not result.ok
    assert result.imprint_matches, "the swapped payload does cover the other document"
    assert result.signature_state == "invalid"
    assert any("contradicts itself" in problem for problem in result.problems)


def test_arbitrary_bytes_are_rejected_without_raising():
    """The property the fuzz targets assert for artifacts, applied here: a
    verifier that raises on hostile input is a verifier that can be turned
    into a crash by whoever supplies the token."""
    rng = random.Random(20260910)  # noqa: S311 - fuzzing a parser, not making keys
    for _ in range(400):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 96)))
        result = ts.verify_token(blob, SUBJECT_DIGEST)
        assert result.ok is False
        assert result.problems


def test_a_truncated_real_token_is_rejected_without_raising():
    token = ts.parse_response(fixture("granted.tsr")).token
    for cut in (1, 10, 100, len(token) // 2, len(token) - 1):
        assert ts.verify_token(token[:cut], SUBJECT_DIGEST).ok is False


# ---------------------------------------------------------------------------
# The DER reader is strict on purpose
# ---------------------------------------------------------------------------

def test_indefinite_length_is_refused():
    with pytest.raises(ts.TimestampError, match="indefinite"):
        ts.read_tlv(b"\x30\x80\x00\x00")


def test_a_non_minimal_length_is_refused():
    with pytest.raises(ts.TimestampError, match="non-minimal|short value"):
        ts.read_tlv(b"\x04\x81\x01\x41")


def test_high_tag_number_form_is_refused():
    with pytest.raises(ts.TimestampError, match="high-tag"):
        ts.read_tlv(b"\x1f\x81\x00\x01\x41")


def test_a_length_that_runs_past_the_end_is_refused():
    with pytest.raises(ts.TimestampError, match="truncated"):
        ts.read_tlv(b"\x04\x10\x41\x42")


def test_trailing_bytes_after_a_complete_element_are_refused():
    with pytest.raises(ts.TimestampError, match="trailing"):
        ts.read_one(b"\x04\x01\x41\x00\x00")


def test_a_generalized_time_without_a_zone_is_refused():
    with pytest.raises(ts.TimestampError, match="not UTC"):
        ts.decode_generalized_time(ts.Tlv(tag=0x18, body=b"20260910105435", raw=b""))


def test_a_generalized_time_that_is_not_a_real_instant_is_refused():
    with pytest.raises(ts.TimestampError):
        ts.decode_generalized_time(ts.Tlv(tag=0x18, body=b"20261340105435Z", raw=b""))


def test_a_generalized_time_with_a_fraction_keeps_the_second():
    moment = ts.decode_generalized_time(ts.Tlv(tag=0x18, body=b"20260910105435.5Z", raw=b""))

    assert (moment.year, moment.month, moment.day, moment.second) == (2026, 9, 10, 35)
    assert moment.microsecond == 500_000


# ---------------------------------------------------------------------------
# The transport, over loopback
# ---------------------------------------------------------------------------

def test_post_request_sends_a_timestamp_query_and_returns_the_reply(authority):
    with tsa.serving(authority) as (url, state):
        raw = ts.post_request(url, ts.build_request(SUBJECT_DIGEST, nonce=42))

    assert state["content_type"] == ts.CONTENT_TYPE_QUERY
    assert state["accept"] == ts.CONTENT_TYPE_REPLY
    assert ts.parse_response(raw).granted


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.invalid/tsr", "/tmp/not-a-url"])
def test_a_url_that_is_not_http_is_refused_before_a_socket_is_opened(url):
    """urllib will happily open `file://`. A TSA URL that reads a local file
    would turn a timestamp request into an exfiltration primitive."""
    with pytest.raises(ts.TimestampError, match="http"):
        ts.post_request(url, b"\x00")


def test_a_reply_larger_than_the_budget_is_refused(authority):
    with tsa.serving(authority) as (url, _):
        with pytest.raises(ts.TimestampError, match="more than"):
            ts.post_request(url.replace("/tsr", "/flood"), ts.build_request(SUBJECT_DIGEST))


def test_an_http_error_body_that_is_not_a_response_is_reported(authority):
    with tsa.serving(authority) as (url, _):
        with pytest.raises(ts.TimestampError):
            ts.stamp(url.replace("/tsr", "/http-error"), SUBJECT_DIGEST)


def test_a_reply_that_is_not_der_names_what_came_back(authority):
    """What a proxy or a captive portal actually does: answer 200 with prose.
    The message has to point at the answer, not at the parser."""
    with tsa.serving(authority) as (url, _):
        with pytest.raises(ts.TimestampError, match="not a TimeStampResp"):
            ts.stamp(url.replace("/tsr", "/not-der"), SUBJECT_DIGEST)


def test_an_unreachable_authority_is_an_error_not_a_silent_skip():
    with pytest.raises(ts.TimestampError, match="could not reach"):
        ts.post_request("http://127.0.0.1:1/tsr", b"\x00", timeout=2.0)


# ---------------------------------------------------------------------------
# stamp(): request, check, keep or refuse
# ---------------------------------------------------------------------------

def test_stamp_returns_a_token_that_covers_the_digest_it_asked_about(authority):
    digest = hashlib.sha256(b"a manifest that only exists in this test").digest()

    with tsa.serving(authority) as (url, _):
        result = ts.stamp(url, digest)

    assert result.info.message_imprint == digest
    assert result.verification.ok
    assert result.tsa_url == url
    assert ts.verify_token(result.token, digest).ok


def test_stamp_refuses_a_reply_whose_nonce_does_not_come_back(authority):
    """Replay protection. Without it, an intermediary could answer with a
    token it was given for some other request."""
    with tsa.serving(authority, echo_nonce=False) as (url, _):
        with pytest.raises(ts.TimestampError):
            ts.stamp(url, SUBJECT_DIGEST)


def test_stamp_refuses_a_rejection_rather_than_writing_an_empty_anchor(authority):
    with tsa.serving(authority, status=2) as (url, _):
        with pytest.raises(ts.TimestampError, match="refused"):
            ts.stamp(url, SUBJECT_DIGEST)


def test_an_authority_whose_certificate_is_not_for_timestamping_is_flagged():
    crooked = tsa.FixtureTSA(name="Actaira Not A TSA", eku_timestamping=False)
    digest = hashlib.sha256(b"anything").digest()
    response = crooked.respond(ts.build_request(digest, nonce=5))

    result = ts.verify_token(ts.parse_response(response).token, digest, expected_nonce=5)

    assert result.signature_state == "embedded_cert_only"
    assert result.signer_eku_timestamping is False
    assert any("timeStamping" in warning for warning in result.warnings)


def test_a_token_dated_outside_its_signer_certificate_is_flagged(authority):
    digest = hashlib.sha256(b"a token from the future").digest()
    response = authority.respond(
        ts.build_request(digest, nonce=7), gen_time=datetime.now(UTC) + timedelta(days=4000)
    )

    result = ts.verify_token(ts.parse_response(response).token, digest, expected_nonce=7)

    assert result.signer_cert_covers_gen_time is False
    assert any("validity window" in warning for warning in result.warnings)


# ---------------------------------------------------------------------------
# The second implementation, checked by a third
# ---------------------------------------------------------------------------

@pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed")
def test_openssl_accepts_the_tokens_the_fixture_authority_issues(authority, tmp_path: Path):
    """`tests/tsa.py` is only useful as an independent implementation if it is
    right. OpenSSL says whether it is."""
    digest = hashlib.sha256(b"checked by a third implementation").digest()
    response = authority.respond(ts.build_request(digest, nonce=11))
    (tmp_path / "reply.tsr").write_bytes(response)
    (tmp_path / "root.pem").write_bytes(authority.root_cert_pem)

    completed = subprocess.run(
        [OPENSSL, "ts", "-verify", "-digest", digest.hex(),
         "-in", str(tmp_path / "reply.tsr"), "-CAfile", str(tmp_path / "root.pem")],
        capture_output=True, text=True, timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    assert "Verification: OK" in completed.stdout


@pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed")
def test_openssl_rejects_a_token_the_fixture_authority_did_not_issue(authority, tmp_path: Path):
    """Control for the test above: OpenSSL must be capable of saying no here."""
    digest = hashlib.sha256(b"checked by a third implementation").digest()
    response = bytearray(authority.respond(ts.build_request(digest, nonce=11)))
    response[-5] ^= 0xFF
    (tmp_path / "reply.tsr").write_bytes(bytes(response))
    (tmp_path / "root.pem").write_bytes(authority.root_cert_pem)

    completed = subprocess.run(
        [OPENSSL, "ts", "-verify", "-digest", digest.hex(),
         "-in", str(tmp_path / "reply.tsr"), "-CAfile", str(tmp_path / "root.pem")],
        capture_output=True, text=True, timeout=60,
    )

    assert completed.returncode != 0
