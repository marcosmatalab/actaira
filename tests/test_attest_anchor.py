"""The time anchor at the package boundary, D-27 and D-27b.

`test_timestamp.py` checks that a token can be built, read and disbelieved.
This file checks the thing that actually matters to a user: that an anchored
package says what it means, that the token in it covers the manifest beside
it, and that every way of making those two disagree is caught.

The authority is `tests/tsa.py`, running on loopback or called directly. No
test here reaches the network, and none of them would pass if it did: the
manifests they stamp exist only for the length of the test.
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

import tsa
from actaira.attest import chain, package, signing
from actaira.attest import timestamp as ts
from actaira.attest import verify as verify_mod
from actaira.inspect import inspect_artifact
from actaira.model import canonical_json
from conftest import corpus_build


@pytest.fixture(scope="module")
def authority() -> tsa.FixtureTSA:
    return tsa.FixtureTSA()


@pytest.fixture
def stamper(authority):
    """A `stamp_fn` for `write_package` that answers from the fixture
    authority in-process. The socket is exercised separately, at the CLI."""

    def stamp(url: str, digest: bytes, timeout: float = 10.0) -> ts.StampResult:
        nonce = ts.make_nonce()
        request = ts.build_request(digest, nonce=nonce, cert_req=True)
        response = ts.parse_response(authority.respond(request))
        verification = ts.verify_token(response.token, digest, expected_nonce=nonce)
        assert verification.ok, verification.problems
        return ts.StampResult(
            token=response.token, info=verification.info, verification=verification, tsa_url=url
        )

    return stamp


@pytest.fixture
def entries(tmp_path: Path) -> list[chain.Entry]:
    artifact = tmp_path / "clean.safetensors"
    artifact.write_bytes(
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}}, b"\x00" * 64
        )
    )
    report = inspect_artifact(artifact)
    built: list[chain.Entry] = []
    chain.append(built, report.sha256, report.to_dict())
    return built


TSA_URL = "https://tsa.example.invalid/tsr"


def anchored(tmp_path: Path, entries, keypair, stamper, name: str = "anchored.zip"):
    return package.write_package(
        tmp_path / name, entries, keypair, tsa_url=TSA_URL, stamp_fn=stamper
    )


def read_members(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as handle:
        return {name: handle.read(name) for name in handle.namelist()}


def write_members(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as handle:
        for name, payload in sorted(members.items()):
            handle.writestr(name, payload)
    return path


def resign(members: dict[str, bytes], manifest: dict, keypair) -> dict[str, bytes]:
    """What an attacker who holds the signing key would do after editing."""
    import base64

    for row in manifest["files"]:
        blob = members[row["path"]]
        row["sha256"] = hashlib.sha256(blob).hexdigest()
        row["bytes"] = len(blob)
    blob = canonical_json(manifest)
    members["manifest.json"] = blob
    members["manifest.sig"] = json.dumps(
        {
            "algorithm": "ed25519",
            "over": "sha256(manifest.json)",
            "key_id": keypair.key_id,
            "signature_b64": base64.b64encode(keypair.sign(hashlib.sha256(blob).digest())).decode("ascii"),
        },
        indent=2,
    ).encode("utf-8")
    return members


# ---------------------------------------------------------------------------
# Optional means optional
# ---------------------------------------------------------------------------

def test_without_a_tsa_url_nothing_changes(tmp_path, entries, keypair):
    result = package.write_package(tmp_path / "plain.zip", entries, keypair)

    assert result.time_anchor == "none"
    assert result.timestamp is None
    assert package.TIMESTAMP_NAME not in read_members(result.path)

    verified = verify_mod.verify_package(result.path)
    assert verified.ok
    assert verified.time_anchor == "none"
    assert verified.time_evidence == "self_asserted"
    assert "timestamp_matches_manifest" not in verified.checks
    assert any("NO TIME ANCHOR" in warning for warning in verified.warnings)


def test_an_anchored_package_says_so_and_carries_the_token(tmp_path, entries, keypair, stamper):
    result = anchored(tmp_path, entries, keypair, stamper)
    members = read_members(result.path)

    assert result.time_anchor == "rfc3161"
    assert package.TIMESTAMP_NAME in members
    manifest = json.loads(members["manifest.json"])
    assert manifest["time_anchor"] == "rfc3161"
    assert manifest["timestamp"]["tsa_url"] == TSA_URL
    assert manifest["timestamp"]["gen_time"] == result.timestamp.gen_time_iso
    assert manifest["timestamp"]["over"] == package.TIMESTAMP_SUBJECT_NOTE


def test_the_stamped_digest_is_the_pending_form_of_this_very_manifest(tmp_path, entries, keypair, stamper):
    """D-27b, asserted rather than described: the bytes the TSA saw are
    recoverable from the finished manifest."""
    result = anchored(tmp_path, entries, keypair, stamper)
    members = read_members(result.path)
    manifest = json.loads(members["manifest.json"])

    subject = package.timestamp_subject(manifest)
    info = ts.parse_token(members[package.TIMESTAMP_NAME])

    assert info.message_imprint == hashlib.sha256(subject).digest()
    assert json.loads(subject)["time_anchor"] == "pending"
    assert "timestamp" not in json.loads(subject)


def test_the_token_is_not_listed_in_files_and_cannot_be(tmp_path, entries, keypair, stamper):
    """It is written after the manifest is hashed, like the signature. The
    verifier must exempt exactly those three members and no others."""
    result = anchored(tmp_path, entries, keypair, stamper)
    manifest = json.loads(read_members(result.path)["manifest.json"])

    declared = {row["path"] for row in manifest["files"]}
    assert package.TIMESTAMP_NAME not in declared
    assert declared == {"entries.jsonl", "keyring.json"}


def test_an_anchored_package_verifies_and_reports_the_gen_time(tmp_path, entries, keypair, stamper):
    result = anchored(tmp_path, entries, keypair, stamper)

    verified = verify_mod.verify_package(result.path)

    assert verified.ok
    assert verified.checks["timestamp_matches_manifest"] is True
    assert verified.time_anchor == "rfc3161"
    assert verified.time_evidence == "rfc3161"
    assert verified.timestamp["token"]["gen_time"] == result.timestamp.gen_time_iso
    assert not any("NO TIME ANCHOR" in warning for warning in verified.warnings)


def test_the_chain_of_the_authority_is_still_reported_as_unverified(tmp_path, entries, keypair, stamper):
    """An anchored package must not read as a fully trusted one. The TSA's
    certificate was never checked against anything."""
    result = anchored(tmp_path, entries, keypair, stamper)

    verified = verify_mod.verify_package(result.path)

    assert verified.timestamp["tsa_chain"] == "unknown"
    assert any("CHAIN NOT VERIFIED" in warning for warning in verified.warnings)


# ---------------------------------------------------------------------------
# Every way of making the manifest and the token disagree
# ---------------------------------------------------------------------------

def test_editing_the_manifest_breaks_the_anchor_even_when_it_is_re_signed(
    tmp_path, entries, keypair, stamper
):
    """The reason the anchor is worth having. Whoever holds the signing key
    can re-sign anything; they cannot re-date it."""
    result = anchored(tmp_path, entries, keypair, stamper)
    members = read_members(result.path)
    manifest = json.loads(members["manifest.json"])
    manifest["created"] = "2019-01-01T00:00:00+00:00"
    write_members(tmp_path / "backdated.zip", resign(members, manifest, keypair))

    verified = verify_mod.verify_package(tmp_path / "backdated.zip")

    assert verified.checks["signature_valid"] is True, "the attacker re-signed it correctly"
    assert verified.checks["timestamp_matches_manifest"] is False
    assert verified.ok is False
    assert any("different digest" in problem for problem in verified.problems)


def test_a_token_issued_over_something_else_is_caught(tmp_path, entries, keypair, stamper, authority):
    result = anchored(tmp_path, entries, keypair, stamper)
    members = read_members(result.path)
    elsewhere = authority.respond(ts.build_request(hashlib.sha256(b"another package").digest()))
    members[package.TIMESTAMP_NAME] = ts.parse_response(elsewhere).token
    write_members(tmp_path / "swapped.zip", members)

    verified = verify_mod.verify_package(tmp_path / "swapped.zip")

    assert verified.ok is False
    assert verified.checks["timestamp_matches_manifest"] is False


def test_removing_the_token_from_a_package_that_claims_one_is_caught(tmp_path, entries, keypair, stamper):
    result = anchored(tmp_path, entries, keypair, stamper)
    members = read_members(result.path)
    del members[package.TIMESTAMP_NAME]
    write_members(tmp_path / "stripped.zip", members)

    verified = verify_mod.verify_package(tmp_path / "stripped.zip")

    assert verified.ok is False
    assert any("carries no manifest.tsr" in problem for problem in verified.problems)


def test_a_token_smuggled_into_an_unanchored_package_is_caught(tmp_path, entries, keypair, authority):
    plain = package.write_package(tmp_path / "plain.zip", entries, keypair)
    members = read_members(plain.path)
    response = authority.respond(ts.build_request(hashlib.sha256(b"anything at all").digest()))
    members[package.TIMESTAMP_NAME] = ts.parse_response(response).token
    write_members(tmp_path / "smuggled.zip", members)

    verified = verify_mod.verify_package(tmp_path / "smuggled.zip")

    assert verified.ok is False
    assert any("declares no time anchor" in problem for problem in verified.problems)


def test_a_manifest_that_advertises_a_gen_time_the_token_does_not_carry_is_caught(
    tmp_path, entries, keypair, stamper
):
    """The manifest is signed and the token is not covered by that signature,
    so the two are cross-checked in both directions."""
    result = anchored(tmp_path, entries, keypair, stamper)
    members = read_members(result.path)
    manifest = json.loads(members["manifest.json"])
    manifest["timestamp"]["gen_time"] = "2031-05-05T00:00:00Z"
    write_members(tmp_path / "misdated.zip", resign(members, manifest, keypair))

    verified = verify_mod.verify_package(tmp_path / "misdated.zip")

    assert verified.ok is False
    assert any("advertises a genTime" in problem for problem in verified.problems)


def test_a_manifest_declaring_an_anchor_this_version_does_not_know_is_refused(
    tmp_path, entries, keypair
):
    plain = package.write_package(tmp_path / "plain.zip", entries, keypair)
    members = read_members(plain.path)
    manifest = json.loads(members["manifest.json"])
    manifest["time_anchor"] = "roughtime"
    write_members(tmp_path / "unknown.zip", resign(members, manifest, keypair))

    verified = verify_mod.verify_package(tmp_path / "unknown.zip")

    assert verified.ok is False
    assert any("unknown time anchor" in problem for problem in verified.problems)


def test_an_extension_of_an_anchored_package_keeps_verifying(tmp_path, entries, keypair, stamper):
    """`--continue` and `--extends` must still work with an anchor present:
    each package carries its own token over its own manifest."""
    first = anchored(tmp_path, entries, keypair, stamper, name="first.zip")
    more = list(entries)
    chain.append(more, "b" * 64, {"note": "a second entry"})
    second = anchored(tmp_path, more, keypair, stamper, name="second.zip")

    ok, problems = verify_mod.verify_extends(first.path, second.path)

    assert ok, problems
    assert verify_mod.verify_package(second.path).time_evidence == "rfc3161"


# ---------------------------------------------------------------------------
# Through the command line, over a socket
# ---------------------------------------------------------------------------

def test_the_cli_anchors_a_package_against_a_live_authority(tmp_path, capsys, authority):
    from actaira import cli

    artifact = tmp_path / "clean.safetensors"
    artifact.write_bytes(
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}, b"\x00" * 16
        )
    )
    out = tmp_path / "cli.zip"
    with tsa.serving(authority) as (url, state):
        code = cli.main([
            "attest", str(artifact), "--out", str(out),
            "--key", str(tmp_path / "keys" / "signing-key.pem"), "--tsa-url", url,
        ])

    assert code == cli.EXIT_OK
    assert state["requests"] == 1
    printed = capsys.readouterr().out
    assert "time_anchor  rfc3161" in printed
    assert "Time-stamped by" in printed

    assert cli.main(["verify", str(out)]) == cli.EXIT_OK
    verify_output = capsys.readouterr().out
    assert "Time anchor: rfc3161 (rfc3161)" in verify_output
    assert "gen_time" in verify_output
    assert "tsa_chain unknown" in verify_output


def test_the_cli_writes_no_package_at_all_when_the_authority_refuses(tmp_path, capsys, authority):
    """A downgrade to an unanchored package would be the worst outcome: the
    caller asked for an anchor and would get a package that quietly lacks one."""
    from actaira import cli

    artifact = tmp_path / "clean.safetensors"
    artifact.write_bytes(
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}, b"\x00" * 16
        )
    )
    out = tmp_path / "refused.zip"
    with tsa.serving(authority, status=2) as (url, _):
        code = cli.main([
            "attest", str(artifact), "--out", str(out),
            "--key", str(tmp_path / "keys" / "signing-key.pem"), "--tsa-url", url,
        ])

    assert code == cli.EXIT_USAGE
    assert not out.exists()
    assert "timestamp authority" in capsys.readouterr().err


def test_the_json_verify_output_carries_the_anchor_for_a_machine_to_read(
    tmp_path, entries, keypair, stamper
):
    result = anchored(tmp_path, entries, keypair, stamper)

    document = verify_mod.verify_package(result.path).to_dict()

    assert document["time_anchor"] == "rfc3161"
    assert document["time_evidence"] == "rfc3161"
    assert document["timestamp"]["tsa_chain"] == "unknown"
    assert document["timestamp"]["token"]["tsa_name"].startswith("CN=Actaira Test TSA")
    assert json.dumps(document), "the verify document must stay JSON-serialisable"


def test_a_stamp_that_predates_the_signing_key_is_refused(tmp_path, entries, keypair, authority):
    """Two mechanisms meeting, D-27 and D-28. The token is genuine and covers
    this manifest; it says the package was signed in 2020, and the key that
    signed it did not exist until today. Believing both is impossible, so the
    package fails rather than being reported as anchored.

    Actaira does not otherwise second-guess a TSA's clock. It reports the
    genTime and lets the reader judge it - but a genTime that contradicts the
    package's own keyring is a contradiction inside the package.
    """
    old = datetime(2020, 1, 1, tzinfo=UTC)

    def stamp(url: str, digest: bytes, timeout: float = 10.0) -> ts.StampResult:
        response = ts.parse_response(authority.respond(ts.build_request(digest), gen_time=old))
        verification = ts.verify_token(response.token, digest)
        return ts.StampResult(response.token, verification.info, verification, url)

    result = package.write_package(
        tmp_path / "old.zip", entries, keypair, tsa_url=TSA_URL, stamp_fn=stamp
    )

    verified = verify_mod.verify_package(result.path)

    assert verified.checks["timestamp_matches_manifest"] is True, "the token itself is fine"
    assert verified.key_state == "before_validity"
    assert verified.ok is False
    assert verified.timestamp["token"]["gen_time"].startswith("2020-01-01")
    assert any("before key" in problem for problem in verified.problems)


def test_the_signing_key_is_carried_with_its_status(tmp_path, entries, keypair, stamper):
    result = anchored(tmp_path, entries, keypair, stamper)
    ring = json.loads(read_members(result.path)["keyring.json"])

    assert [row["status"] for row in ring["keys"]] == ["active"]
    assert ring["keys"][0]["fingerprint_sha256"] == keypair.fingerprint
    assert "private_key_path" not in ring["keys"][0], "the package must not leak local paths"


def test_signing_generates_a_distinct_key_per_test(keypair):
    """A guard on the fixture, not on the code: several files now depend on
    `keypair` being fresh, and a cached one would make retirement tests lie."""
    assert keypair.key_id != signing.generate().key_id


# ---------------------------------------------------------------------------
# The token is covered by the signature, and the manifest has to describe it
#
# Three holes found by an external adversarial audit, all of them variations
# of the same mistake: the token was checked against what the manifest *said*
# rather than against what the manifest *committed to*.
# ---------------------------------------------------------------------------

def subject_digest_of(members: dict[str, bytes]) -> bytes:
    """The digest the TSA was asked to stamp, recovered from a written package."""
    manifest = json.loads(members["manifest.json"])
    return hashlib.sha256(package.timestamp_subject(manifest)).digest()


def mint(authority: tsa.FixtureTSA, digest: bytes, *, serial: int, gen_time: datetime) -> bytes:
    """A token over `digest`, with a serial and a genTime of the caller's choosing.

    This is what any timestamp authority can do, which is the point: Actaira
    ships no trust store, so `tsa_chain` is never verified and a token from an
    authority nobody has heard of parses exactly like one from a real TSA.
    The only thing that can tell them apart is a commitment to the token's own
    bytes.
    """
    info = authority.tst_info(digest, nonce=None, gen_time=gen_time, serial=serial)
    return authority.token(info)


def test_a_token_whose_signature_was_never_checked_is_not_a_verified_token(
    tmp_path, entries, keypair, authority
):
    """`not_verified` used to be `ok`. A token carrying no certificate has had
    its imprint checked and nothing else: it says which digest it covers, and
    nothing at all about who issued it or whether it was edited afterwards."""

    def stamp(url: str, digest: bytes, timeout: float = 10.0) -> ts.StampResult:
        response = ts.parse_response(
            authority.respond(ts.build_request(digest), include_certificate=False)
        )
        return ts.StampResult(response.token, ts.parse_token(response.token), None, url)

    result = package.write_package(
        tmp_path / "unchecked.zip", entries, keypair, tsa_url=TSA_URL, stamp_fn=stamp
    )

    verified = verify_mod.verify_package(result.path)

    assert verified.timestamp["signature_state"] == "not_verified"
    assert verified.timestamp["ok"] is False, "an unchecked signature is not a checked one"
    assert verified.checks["timestamp_matches_manifest"] is False
    assert verified.ok is False
    assert any("was NOT checked" in problem for problem in verified.problems)


def test_the_token_file_cannot_be_swapped_for_another_token_over_the_same_manifest(
    tmp_path, entries, keypair, stamper
):
    """`manifest.tsr` is not in `files` and cannot be, so before `token_sha256`
    it was covered by nothing at all.

    The swap needs no signing key: a second authority mints a token over the
    same imprint, carrying the very genTime and serial the manifest
    advertises, and the manifest is left untouched. Every cross-check the
    verifier had - imprint, genTime, serial - agreed, because they were all
    checks against values the attacker could choose to match.
    """
    result = anchored(tmp_path, entries, keypair, stamper)
    members = read_members(result.path)
    manifest = json.loads(members["manifest.json"])

    rogue = tsa.FixtureTSA(name="Somebody Else's TSA")
    forged = mint(
        rogue,
        subject_digest_of(members),
        serial=int(manifest["timestamp"]["serial_number"]),
        gen_time=datetime.fromisoformat(manifest["timestamp"]["gen_time"].replace("Z", "+00:00")),
    )
    assert forged != members[package.TIMESTAMP_NAME]
    assert ts.verify_token(forged, subject_digest_of(members)).ok, "the forgery is a real token"

    members[package.TIMESTAMP_NAME] = forged
    write_members(tmp_path / "swapped.zip", members)

    verified = verify_mod.verify_package(tmp_path / "swapped.zip")

    assert verified.ok is False
    assert verified.checks["timestamp_matches_manifest"] is False
    assert any("not the token this manifest was signed over" in p for p in verified.problems)


def test_the_swap_is_caught_by_the_digest_and_not_by_the_signature(tmp_path, entries, keypair, stamper):
    """The other half of the test above: everything else about the swapped
    package still verifies, so the digest is doing the work."""
    result = anchored(tmp_path, entries, keypair, stamper)
    members = read_members(result.path)
    manifest = json.loads(members["manifest.json"])
    rogue = tsa.FixtureTSA(name="Somebody Else's TSA")
    members[package.TIMESTAMP_NAME] = mint(
        rogue,
        subject_digest_of(members),
        serial=int(manifest["timestamp"]["serial_number"]),
        gen_time=datetime.fromisoformat(manifest["timestamp"]["gen_time"].replace("Z", "+00:00")),
    )
    write_members(tmp_path / "swapped.zip", members)

    verified = verify_mod.verify_package(tmp_path / "swapped.zip")

    assert verified.checks["signature_valid"] is True
    assert verified.checks["files_match_manifest"] is True
    assert not any("different digest" in problem for problem in verified.problems), (
        "the forged token covers the right manifest; only its bytes differ"
    )


def test_an_rfc3161_manifest_with_no_timestamp_block_is_refused(
    tmp_path, entries, keypair, authority, stamper
):
    """`time_anchor: rfc3161` with no `timestamp` block used to compare every
    field against itself.

    `timestamp_subject` strips the block, so removing it leaves the stamped
    subject untouched: a token over the correct manifest, issued in 1999, was
    accepted and reported as third-party time evidence.
    """
    result = anchored(tmp_path, entries, keypair, stamper)
    members = read_members(result.path)
    manifest = json.loads(members["manifest.json"])
    ancient = datetime(1999, 12, 31, 23, 59, 59, tzinfo=UTC)
    members[package.TIMESTAMP_NAME] = mint(
        authority, subject_digest_of(members), serial=4321, gen_time=ancient
    )
    del manifest["timestamp"]
    write_members(tmp_path / "blockless.zip", resign(members, manifest, keypair))

    verified = verify_mod.verify_package(tmp_path / "blockless.zip")

    assert verified.ok is False
    assert verified.checks["timestamp_matches_manifest"] is False
    assert verified.time_evidence != "rfc3161"
    assert any("carries no `timestamp` block" in problem for problem in verified.problems)


@pytest.mark.parametrize("dropped", ["gen_time", "serial_number", "token_sha256"])
def test_every_field_the_timestamp_block_advertises_is_required(
    tmp_path, entries, keypair, stamper, dropped
):
    """A field that is absent is not a field that agrees. Each one was a
    permissive default before: `get(name, actual) == actual`."""
    result = anchored(tmp_path, entries, keypair, stamper)
    members = read_members(result.path)
    manifest = json.loads(members["manifest.json"])
    del manifest["timestamp"][dropped]
    write_members(tmp_path / "partial.zip", resign(members, manifest, keypair))

    verified = verify_mod.verify_package(tmp_path / "partial.zip")

    assert verified.ok is False
    assert verified.checks["timestamp_matches_manifest"] is False
    assert any(dropped in problem for problem in verified.problems)


def test_the_declared_token_digest_is_the_digest_of_the_token_that_was_written(
    tmp_path, entries, keypair, stamper
):
    """The positive control: the writer and the reader agree on a real package."""
    result = anchored(tmp_path, entries, keypair, stamper)
    members = read_members(result.path)
    manifest = json.loads(members["manifest.json"])

    assert manifest["timestamp"][package.TIMESTAMP_TOKEN_DIGEST_KEY] == hashlib.sha256(
        members[package.TIMESTAMP_NAME]
    ).hexdigest()
    assert manifest["timestamp"]["token_bytes"] == len(members[package.TIMESTAMP_NAME])
    assert verify_mod.verify_package(result.path).checks["timestamp_matches_manifest"] is True
