"""DSSE envelopes and in-toto statements.

The tests that matter here are the ones about Pre-Authentication Encoding,
because PAE is the part of DSSE that people re-implement from an example and
get subtly wrong. Every vector below was computed by hand from the text of
the specification rather than from this repository's own output: a test that
asserts `pae(...) == pae(...)` proves the function is consistent with itself,
which is exactly the property a wrong implementation also has.
"""
from __future__ import annotations

import base64
import json

import pytest

from actaira.attest import signing
from actaira.attest.dsse import (
    PAYLOAD_TYPE,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    Envelope,
    inspection_predicate,
    pae,
    to_envelope,
    verify_envelope,
)
from actaira.model import Severity, Verdict
from support.reports import write_flagged_report, write_report, write_unread_report


@pytest.fixture
def reports(tmp_path):
    """One clean artifact and one with a gadget, so the predicate has both."""
    return [
        write_report(tmp_path / "clean.safetensors"),
        write_flagged_report(tmp_path / "checkpoint.pkl"),
    ]


# ---------------------------------------------------------------------------
# PAE, against the specification rather than against ourselves
# ---------------------------------------------------------------------------

def test_pae_matches_the_vector_written_in_the_dsse_specification():
    """PAE("http://example.com/HelloWorld", "hello world").

    Counted by hand: the type is 29 bytes (7 for "http://", 11 for
    "example.com", 1 for "/", 10 for "HelloWorld") and the payload is 11.
    """
    assert pae("http://example.com/HelloWorld", b"hello world") == (
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    )


def test_pae_of_two_empty_strings_still_carries_both_lengths():
    """The degenerate case, where an implementation that joins on spaces
    without emitting the empty fields produces something shorter."""
    assert pae("", b"") == b"DSSEv1 0  0 "


def test_pae_lengths_are_byte_counts_and_not_character_counts():
    """"café" is four characters and five bytes. An implementation written
    against ASCII examples emits 4 here, and every signature it makes is over
    a preimage no conforming verifier will reconstruct."""
    assert pae("application/vnd.in-toto+json", "café".encode()) == (
        b"DSSEv1 28 application/vnd.in-toto+json 5 caf\xc3\xa9"
    )


def test_pae_is_injective_across_the_type_payload_boundary():
    """The reason the length prefixes exist. Without them both of these
    encode to the same bytes and a signature over one is a signature over the
    other."""
    assert pae("ab", b"c") != pae("a", b"bc")
    assert pae("", b"a b") != pae("a", b"b")


def test_the_header_is_the_literal_dssev1():
    assert pae("x", b"y").startswith(b"DSSEv1 ")


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------

def test_a_signed_envelope_verifies_against_its_key(reports, keypair):
    envelope = to_envelope(reports, keypair)

    ok, problems = verify_envelope(envelope, keypair.public)

    assert ok, problems
    assert problems == []


def test_the_signature_is_over_the_pae_and_not_over_the_payload(reports, keypair):
    """Stated as a test because it is the whole difference between DSSE and
    "we base64ed a JSON document and signed it"."""
    envelope = to_envelope(reports, keypair)
    signature = envelope.signatures[0].sig

    assert signing.verify(keypair.public, signature, envelope.pae())
    assert not signing.verify(keypair.public, signature, envelope.payload)


def test_an_unsigned_envelope_is_reported_as_unsigned_rather_than_accepted(reports, keypair):
    envelope = to_envelope(reports)

    ok, problems = verify_envelope(envelope, keypair.public)

    assert not ok
    assert any("no signatures" in problem for problem in problems)


def test_a_second_signature_is_added_and_both_verify(reports, keypair, tmp_path):
    """DSSE allows n signatures over one preimage. Co-signing must not
    invalidate the first signature, and neither signature may cover a subset
    of the document."""
    other, _created = signing.load_or_create(tmp_path / "second" / "key.pem")
    envelope = to_envelope(reports, keypair).signed(other)

    assert len(envelope.signatures) == 2
    assert verify_envelope(envelope, keypair.public)[0]
    assert verify_envelope(envelope, other.public)[0]


def test_a_different_key_does_not_verify(reports, keypair, tmp_path):
    stranger, _created = signing.load_or_create(tmp_path / "stranger" / "key.pem")
    envelope = to_envelope(reports, keypair)

    ok, problems = verify_envelope(envelope, stranger.public)

    assert not ok
    assert any("no signature verifies" in problem for problem in problems)


# ---------------------------------------------------------------------------
# Tampering
# ---------------------------------------------------------------------------

def test_an_altered_payload_is_rejected(reports, keypair):
    envelope = to_envelope(reports, keypair)
    statement = envelope.statement()
    statement["predicate"]["verdict"] = Verdict.PASS.value  # it was "fail"
    forged = Envelope(
        payload=json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        payload_type=envelope.payload_type,
        signatures=envelope.signatures,
    )

    ok, problems = verify_envelope(forged, keypair.public)

    assert not ok
    assert any("no signature verifies" in problem for problem in problems)


def test_an_altered_payload_type_is_rejected(reports, keypair):
    """This is the attack PAE exists to stop: the same bytes, re-labelled so
    that a consumer picks a different parser and reaches a different meaning.
    The type is inside the signed preimage, so the signature breaks, and the
    explicit media-type check catches the case where the attacker re-signs."""
    envelope = to_envelope(reports, keypair)
    relabelled = Envelope(
        payload=envelope.payload,
        payload_type="application/x-attacker-chosen",
        signatures=envelope.signatures,
    )

    ok, problems = verify_envelope(relabelled, keypair.public)

    assert not ok
    assert any("payloadType" in problem for problem in problems)
    assert any("no signature verifies" in problem for problem in problems)


def test_a_relabelled_and_resigned_envelope_is_still_refused(reports, keypair):
    """The attacker holds a key of their own, so the signature is valid. What
    they cannot do is make the document mean what the media type says."""
    envelope = to_envelope(reports)
    relabelled = Envelope(
        payload=envelope.payload, payload_type="text/plain"
    ).signed(keypair)

    ok, problems = verify_envelope(relabelled, keypair.public)

    assert not ok
    assert [problem for problem in problems if "payloadType" in problem]


def test_a_keyid_that_disagrees_with_the_key_that_signed_is_reported(reports, keypair):
    """The keyid is outside the PAE preimage, so an attacker can rewrite it
    without breaking anything. It must never be used to decide, and a
    disagreement must not pass unremarked."""
    envelope = to_envelope(reports, keypair)
    lying = Envelope(
        payload=envelope.payload,
        payload_type=envelope.payload_type,
        signatures=(
            type(envelope.signatures[0])(sig=envelope.signatures[0].sig, keyid="0" * 16),
        ),
    )

    ok, problems = verify_envelope(lying, keypair.public)

    assert not ok
    assert any("declares keyid" in problem for problem in problems)


def test_a_foreign_predicate_type_is_not_accepted_as_an_actaira_statement(keypair):
    envelope = to_envelope([], keypair)
    statement = envelope.statement()
    statement["predicateType"] = "https://slsa.dev/provenance/v1"
    forged = Envelope(
        payload=json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        payload_type=PAYLOAD_TYPE,
    ).signed(keypair)

    ok, problems = verify_envelope(forged, keypair.public)

    assert not ok
    assert any("predicateType" in problem for problem in problems)


def test_every_problem_is_reported_and_not_only_the_first(keypair):
    """A verifier that stops at the first failure teaches its user to fix one
    thing and re-run."""
    broken = Envelope(payload=b"not json at all", payload_type="text/plain")

    ok, problems = verify_envelope(broken, keypair.public)

    assert not ok
    assert len(problems) >= 3


# ---------------------------------------------------------------------------
# The in-toto statement
# ---------------------------------------------------------------------------

def test_the_statement_round_trips_through_its_json_form(reports, keypair):
    envelope = to_envelope(reports, keypair)

    restored = Envelope.from_json(envelope.to_json())

    assert restored == envelope
    assert restored.statement() == envelope.statement()
    assert verify_envelope(restored, keypair.public)[0]


def test_the_envelope_json_uses_the_field_names_the_specification_names(reports, keypair):
    document = json.loads(to_envelope(reports, keypair).to_json())

    assert set(document) == {"payload", "payloadType", "signatures"}
    assert document["payloadType"] == PAYLOAD_TYPE
    assert set(document["signatures"][0]) == {"keyid", "sig"}
    # The payload is inside the envelope, base64-encoded, which is the
    # property that makes a file dangling outside the signature impossible.
    assert base64.b64decode(document["payload"]) == to_envelope(reports).payload


def test_the_statement_is_in_toto_v1_with_a_subject_per_artifact(reports):
    statement = to_envelope(reports).statement()

    assert statement["_type"] == STATEMENT_TYPE
    assert statement["predicateType"] == PREDICATE_TYPE
    assert [subject["name"] for subject in statement["subject"]] == [
        "clean.safetensors",
        "checkpoint.pkl",
    ]
    assert [subject["digest"]["sha256"] for subject in statement["subject"]] == [
        report.sha256 for report in reports
    ]


def test_the_subject_name_is_not_the_local_path(reports):
    """An in-toto subject name is meant to be matchable against a consumer's
    own copy, and the consumer's copy is not under this machine's tmp_path."""
    statement = to_envelope(reports).statement()

    for subject in statement["subject"]:
        assert "/" not in subject["name"]


def test_the_predicate_carries_the_verdict_the_policy_and_the_rules(reports):
    predicate = to_envelope(reports).statement()["predicate"]

    assert predicate["tool"]["name"] == "actaira"
    assert predicate["policy"] == {"import_policy": "strict", "fail_on": "high"}
    assert predicate["verdict"] == "fail"  # the gadget artifact decides it
    assert "ACT-PKL-002" in {row["rule_id"] for row in predicate["rules_fired"]}
    assert {row["name"] for row in predicate["artifacts"]} == {
        "clean.safetensors",
        "checkpoint.pkl",
    }


def test_the_predicate_says_which_artifacts_were_not_fully_read(tmp_path):
    """"Clean" and "not looked at" have to be distinguishable without opening
    the findings. D-04, carried into the envelope."""
    predicate = to_envelope([write_unread_report(tmp_path / "broken.gguf")]).statement()["predicate"]

    assert predicate["artifacts"][0]["fully_read"] is False
    assert predicate["verdict"] == "inconclusive"


def test_an_empty_report_set_is_inconclusive_and_never_a_pass():
    assert inspection_predicate([])["verdict"] == "inconclusive"


def test_the_predicate_is_byte_identical_across_two_runs_over_the_same_bytes(reports):
    """A signed document that changes between runs cannot be compared, and a
    signature over it proves only that somebody signed something."""
    first = to_envelope(reports, inspected_at="2026-09-10T00:00:00+00:00").payload
    second = to_envelope(reports, inspected_at="2026-09-10T00:00:00+00:00").payload

    assert first == second


def test_the_policy_the_verdict_was_computed_under_is_recorded(reports):
    predicate = inspection_predicate(reports, scan_policy="known-bad", fail_on=Severity.CRITICAL)

    assert predicate["policy"] == {"import_policy": "known-bad", "fail_on": "critical"}


def test_an_envelope_without_a_payload_type_is_refused_at_load():
    with pytest.raises(ValueError, match="payloadType"):
        Envelope.from_dict({"payload": "e30=", "signatures": []})


def test_a_missing_signatures_array_loads_as_unsigned_rather_than_raising():
    """A verification result the caller should see next to the others, not an
    exception it has to special-case."""
    envelope = Envelope.from_dict({"payload": "e30=", "payloadType": PAYLOAD_TYPE})

    assert envelope.signatures == ()


# --------------------------------------------------------------------------
# DEF-96: the envelope reaches a package, and the package reads it back
# --------------------------------------------------------------------------


def _package_with_envelope(tmp_path, reports, keypair, *, dsse=True):
    """A package, with or without the DSSE member. What `attest --dsse` wrote.

    The command that assembled this went to archive/model-scanner; the
    assembly did not. Writing it out here keeps the property under test -
    an envelope is an ordinary package member, covered by the manifest and
    by its own signature - attached to the code that still implements it.
    """
    from actaira.attest import chain, package

    entries: list[chain.Entry] = []
    for report in reports:
        chain.append(entries, report.sha256, report.to_dict(), timestamp="2026-01-01T00:00:00")
    envelope = to_envelope(reports, keypair).to_json().encode("utf-8") if dsse else None
    out = tmp_path / "attestation.zip"
    package.write_package(out, entries, keypair, envelope=envelope)
    return out


def test_a_package_can_carry_a_signed_envelope(tmp_path, reports, keypair):
    """The defect, as the behaviour that was missing.

    `attest/dsse.py` shipped in 2.0 with 27 tests and nothing ever called it.
    The README advertised `actaira attest --dsse` and `grep -n dsse cli.py`
    returned nothing - the flag had never existed in any commit, so the
    command exited 2 with `unrecognized arguments`. Five hundred lines of
    tested code no user can reach is not interoperability, it is a claim.
    """
    import zipfile

    from actaira.attest.package import DSSE_NAME

    out = _package_with_envelope(tmp_path, reports, keypair)

    with zipfile.ZipFile(out) as archive:
        assert DSSE_NAME in archive.namelist()
        envelope = Envelope.from_json(archive.read(DSSE_NAME).decode("utf-8"))
    assert envelope.signatures, "the envelope is signed with the package's own key"
    assert envelope.statement()["_type"] == STATEMENT_TYPE


def test_a_package_without_one_carries_no_envelope(tmp_path, reports, keypair):
    """Off by default: an existing package format does not change shape
    because a new option exists."""
    import zipfile

    from actaira.attest.package import DSSE_NAME

    out = _package_with_envelope(tmp_path, reports, keypair, dsse=False)

    with zipfile.ZipFile(out) as archive:
        assert DSSE_NAME not in archive.namelist()


def test_verify_checks_the_envelope_it_finds(tmp_path, reports, keypair):
    """Writing it without reading it back would repeat the same shape one
    layer along: a document in the package that no code in the package has
    ever checked."""
    from actaira.attest import verify as verify_mod

    out = _package_with_envelope(tmp_path, reports, keypair)

    result = verify_mod.verify_package(out)

    assert result.ok, result.problems
    assert result.checks["dsse_envelope_valid"] is True


def test_an_edited_envelope_is_caught_twice(tmp_path, reports, keypair):
    """Once by the manifest digest, because it is an ordinary member, and
    once by its own signature. That is the structural property this module
    argues for: nothing hangs outside a signature."""
    import zipfile

    from actaira.attest import verify as verify_mod
    from actaira.attest.package import DSSE_NAME

    out = _package_with_envelope(tmp_path, reports, keypair)

    with zipfile.ZipFile(out) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    document = json.loads(members[DSSE_NAME])
    document["payload"] = base64.b64encode(b'{"tampered": true}').decode("ascii")
    members[DSSE_NAME] = json.dumps(document).encode("utf-8")
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(tampered, "w") as archive:
        for name, blob in sorted(members.items()):
            archive.writestr(name, blob)

    result = verify_mod.verify_package(tampered)

    assert not result.ok
    assert any("files" in problem or DSSE_NAME in problem for problem in result.problems)
