"""The attestation package, end to end, and four ways of forging one.

Design note D-15 splits verification into integrity ("are these the bytes that
were signed?") and identity ("is this a key I trust?"). The tests are arranged
along that split, because the whole value of the package is that it refuses to
blur the two.
"""
from __future__ import annotations

import base64
import hashlib
import json
import warnings
import zipfile
from pathlib import Path

import pytest

from actaira.attest import chain, package, signing
from actaira.attest import verify as verify_mod
from actaira.model import canonical_json
from support.reports import write_record

INTEGRITY_CHECKS = (
    "files_match_manifest",
    "chain_intact",
    "head_matches",
    "merkle_root_matches",
    "signature_valid",
)


@pytest.fixture
def artifacts(tmp_path: Path) -> list[Path]:
    """One clean artifact and one that fails, so the attested payload has
    something worth lying about."""
    return [
        write_record(tmp_path / "clean.safetensors", payload=b"clean bytes",
                     verdict="pass", findings=[]),
        write_record(tmp_path / "gadget.pkl", payload=b"other bytes",
                     verdict="fail", findings=["ACT-PKL-001"]),
    ]


@pytest.fixture
def attested(tmp_path: Path, artifacts: list[Path], keypair):
    """Inspect, attest, and hand back everything a verifier would be given."""
    reports = list(artifacts)
    # Two distinct subjects is the whole requirement: the manifest, the chain
    # and the Merkle root are what is under test, and none of them reads inside
    # a payload. Asserting a verdict here would be asserting on the suite's own
    # fixture, which phase A removed the means to compute anyway.
    assert len({report.sha256 for report in reports}) == 2

    entries: list[chain.Entry] = []
    boms: dict[str, dict] = {}
    for report in reports:
        chain.append(entries, report.sha256, report.to_dict())
        # Any JSON document. The packaging layer stores a BOM by digest and
        # never reads inside it; the CycloneDX writer that used to fill this in
        # is on archive/model-scanner. What is under test is the manifest's
        # coverage of the member, not the member's schema.
        boms[report.sha256] = {"subject": report.sha256, "verdict": report.to_dict()["verdict"]}

    result = package.write_package(tmp_path / "attestation.zip", entries, keypair, boms)
    return result, reports, keypair


def trust_file(tmp_path: Path, fingerprint: str, name: str = "trusted.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"keys": [{"fingerprint_sha256": fingerprint}]}), encoding="utf-8")
    return path


def read_members(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as handle:
        return {name: handle.read(name) for name in handle.namelist()}


def write_members(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as handle:
        for name, payload in sorted(members.items()):
            handle.writestr(name, payload)
    return path


def resign(members: dict[str, bytes], keypair) -> dict[str, bytes]:
    """Rebuild manifest file hashes and sign again: what an attacker with a key
    of their own would do after editing a package."""
    manifest = json.loads(members["manifest.json"])
    for row in manifest["files"]:
        blob = members[row["path"]]
        row["sha256"] = hashlib.sha256(blob).hexdigest()
        row["bytes"] = len(blob)
    manifest["signing_key_id"] = keypair.key_id
    manifest["signing_key_fingerprint_sha256"] = keypair.fingerprint
    manifest_blob = canonical_json(manifest)
    members["manifest.json"] = manifest_blob
    members["manifest.sig"] = json.dumps(
        {
            "algorithm": "ed25519",
            "over": package.SIGNATURE_SUBJECT_NOTE,
            "key_id": keypair.key_id,
            "signature_b64": base64.b64encode(
                keypair.sign(package.manifest_signing_subject(manifest_blob))
            ).decode("ascii"),
        },
        indent=2,
    ).encode("utf-8")
    return members


# ---------------------------------------------------------------------------
# The honest cycle
# ---------------------------------------------------------------------------

def test_a_freshly_written_package_verifies_with_integrity_only(attested):
    result_written, reports, _keypair = attested

    result = verify_mod.verify_package(result_written.path)

    assert result.ok is True
    assert all(result.checks[name] for name in INTEGRITY_CHECKS)
    assert result.entry_count == len(reports)
    assert result.problems == []

    # Identity was not checked, and the result says so instead of showing a
    # green tick: this is the claim D-15 is built around.
    assert result.trust_state == "embedded_key_only"
    assert result.checks["key_trusted"] is False
    assert any("IDENTITY NOT VERIFIED" in warning for warning in result.warnings)
    assert any("NO TIME ANCHOR" in warning for warning in result.warnings)


def test_the_package_carries_what_a_reviewer_needs_offline(attested):
    result_written, reports, keypair = attested
    members = read_members(result_written.path)

    assert set(members) == {
        "manifest.json",
        "manifest.sig",
        "entries.jsonl",
        "keyring.json",
    } | {f"bom/{report.sha256}.cdx.json" for report in reports}

    entries = [json.loads(line) for line in members["entries.jsonl"].splitlines() if line.strip()]
    assert [entry["subject_sha256"] for entry in entries] == [r.sha256 for r in reports]
    assert entries[-1]["entry_hash"] == result_written.head_hash
    assert json.loads(members["keyring.json"])["keys"][0]["fingerprint_sha256"] == keypair.fingerprint


def test_require_trust_without_anchors_fails(attested):
    """`--require-trust` is the setting that turns "I checked the key it gave
    me" into "I checked a key I already had"."""
    result_written, _reports, _keypair = attested

    result = verify_mod.verify_package(result_written.path, require_trust=True)

    assert result.ok is False
    assert result.trust_state == "embedded_key_only"
    assert all(result.checks[name] for name in INTEGRITY_CHECKS), (
        "integrity still holds; only the identity requirement failed"
    )
    assert "--require-trust was set and the signing key is not trusted" in result.problems


def test_the_right_fingerprint_in_a_keyring_makes_it_trusted(tmp_path, attested):
    result_written, _reports, keypair = attested
    keyring = trust_file(tmp_path, keypair.fingerprint)

    result = verify_mod.verify_package(
        result_written.path, trusted_keyring=keyring, require_trust=True
    )

    assert result.ok is True
    assert result.trust_state == "trusted"
    assert result.checks["key_trusted"] is True
    assert result.problems == []


def test_a_raw_public_key_anchor_works_the_same_way(attested):
    result_written, _reports, keypair = attested

    result = verify_mod.verify_package(
        result_written.path, trusted_pubkey_b64=keypair.public_b64, require_trust=True
    )

    assert result.trust_state == "trusted"
    assert result.ok is True


# ---------------------------------------------------------------------------
# A trust anchor that will not load is a refusal, not a shrug
#
# Every one of these produced an empty anchor set, which fell through to the
# `embedded_key_only` branch: OK, exit 0, and the caller's assertion about
# whose signatures they accept discarded without a word - along with every
# revocation the keyring carried.
# ---------------------------------------------------------------------------

BROKEN_KEYRINGS = {
    "misspelled_keys": ({"key": [{"fingerprint_sha256": "ab" * 32}]}, "no `keys` list"),
    "keys_is_a_string": ({"keys": "abcdef"}, "`keys` is a str, not a list"),
    "keys_is_empty": ({"keys": []}, "anchors nothing"),
    "keys_holds_strings": ({"keys": ["ab" * 32]}, "is not an object"),
    "row_names_nothing": ({"keys": [{"key_id": "k1", "status": "active"}]},
                          "neither fingerprint_sha256 nor public_key_b64"),
    "not_an_object": ([{"fingerprint_sha256": "ab" * 32}], "not a keyring object"),
}


@pytest.mark.parametrize("shape", sorted(BROKEN_KEYRINGS))
def test_a_keyring_that_yields_no_anchors_fails_and_says_why(tmp_path, attested, shape):
    payload, expected = BROKEN_KEYRINGS[shape]
    result, _reports, _keypair = attested
    ring = tmp_path / f"{shape}.json"
    ring.write_text(json.dumps(payload), encoding="utf-8")

    verified = verify_mod.verify_package(result.path, trusted_keyring=ring)

    assert verified.ok is False
    assert verified.trust_state == "untrusted"
    assert any(expected in problem for problem in verified.problems), verified.problems
    assert any("none could be loaded" in problem for problem in verified.problems)


def test_a_keyring_that_is_not_json_at_all_is_a_problem(tmp_path, attested):
    result, _reports, _keypair = attested
    ring = tmp_path / "broken.json"
    ring.write_bytes(b"\x00\x01 this is not json")

    verified = verify_mod.verify_package(result.path, trusted_keyring=ring)

    assert verified.ok is False
    assert any("not valid JSON" in problem for problem in verified.problems)


def test_a_keyring_that_does_not_exist_is_a_problem(tmp_path, attested):
    result, _reports, _keypair = attested

    verified = verify_mod.verify_package(result.path, trusted_keyring=tmp_path / "absent.json")

    assert verified.ok is False
    assert any("could not be read" in problem for problem in verified.problems)


@pytest.mark.parametrize("value", ["", "   ", "not base64 at all", "AAAA"])
def test_a_pubkey_that_is_not_a_key_fails_instead_of_raising(attested, value):
    """`--pubkey ""` was falsy, so it was treated as no anchor at all;
    anything else unparseable propagated a ValueError out of the verifier."""
    result, _reports, _keypair = attested

    verified = verify_mod.verify_package(result.path, trusted_pubkey_b64=value)

    assert verified.ok is False
    assert verified.trust_state == "untrusted"
    assert any("--pubkey" in problem for problem in verified.problems), verified.problems


def test_one_unusable_row_does_not_discard_the_rest_of_the_keyring(tmp_path, attested):
    """The refusal is about ending with no anchors, not about a perfect file:
    a keyring that names the signing key alongside a row nobody can read is
    still a keyring that names the signing key."""
    result, _reports, keypair = attested
    ring = tmp_path / "mixed.json"
    ring.write_text(
        json.dumps({"keys": [{"note": "row with nothing in it"},
                             {"fingerprint_sha256": keypair.fingerprint}]}),
        encoding="utf-8",
    )

    verified = verify_mod.verify_package(result.path, trusted_keyring=ring, require_trust=True)

    assert verified.trust_state == "trusted"
    assert any("keys[0]" in problem for problem in verified.problems), "the bad row is still named"


def test_a_well_formed_keyring_is_unaffected(tmp_path, attested):
    """Negative control for the six above: the shape check has to accept the
    shape the tool itself writes."""
    result, _reports, keypair = attested

    verified = verify_mod.verify_package(
        result.path, trusted_keyring=trust_file(tmp_path, keypair.fingerprint), require_trust=True
    )

    assert verified.ok is True, verified.problems
    assert verified.trust_state == "trusted"


def test_someone_elses_fingerprint_leaves_it_untrusted(tmp_path, attested):
    result_written, _reports, _keypair = attested
    stranger = signing.generate()
    keyring = trust_file(tmp_path, stranger.fingerprint, "stranger.json")

    result = verify_mod.verify_package(result_written.path, trusted_keyring=keyring)

    assert result.trust_state == "untrusted"
    assert result.checks["key_trusted"] is False
    assert any("not in the supplied trust anchors" in problem for problem in result.problems)
    # The two answers stay separate in the report: every integrity check still
    # passes, because who signed a package says nothing about whether its bytes
    # were edited.
    assert all(result.checks[name] for name in INTEGRITY_CHECKS)
    # But `ok` is False. Supplying anchors is an assertion about who you accept,
    # so once given they are binding: ok=True next to "this key is not one of
    # yours" is a contradiction a CI job would act on. Not supplying anchors at
    # all remains the permissive default and reports `embedded_key_only`.
    assert result.ok is False
    assert (
        verify_mod.verify_package(
            result_written.path, trusted_keyring=keyring, require_trust=True
        ).ok
        is False
    )


# ---------------------------------------------------------------------------
# Four forgeries
# ---------------------------------------------------------------------------

def test_editing_an_attested_entry_is_caught(tmp_path, attested):
    """Turn the failing artifact's verdict into a pass, the way a publisher
    who wanted a clean report would."""
    result_written, _reports, _keypair = attested
    members = read_members(result_written.path)
    original = members["entries.jsonl"]

    lines = original.splitlines()
    entry = json.loads(lines[1])
    assert entry["payload"]["verdict"] == "fail"
    entry["payload"]["verdict"] = "pass"
    entry["payload"]["findings"] = []
    members["entries.jsonl"] = lines[0] + b"\n" + canonical_json(entry) + b"\n"
    assert members["entries.jsonl"] != original, "the tamper did not change anything"

    result = verify_mod.verify_package(write_members(tmp_path / "edited.zip", members))

    assert result.ok is False
    assert result.checks["files_match_manifest"] is False
    assert "entries.jsonl: sha256 mismatch" in result.problems
    # Three independent checks catch it, and the chain names the entry.
    assert result.checks["chain_intact"] is False
    assert "entry[1]: payload_hash does not match payload" in result.problems
    assert result.checks["merkle_root_matches"] is False
    # The manifest itself was not touched, so its signature still verifies:
    # forging content is not the same as forging the signature.
    assert result.checks["signature_valid"] is True


def test_editing_a_hash_in_the_manifest_is_caught(tmp_path, attested):
    """The manifest is the signed document, so rewriting one row in it breaks
    the signature as well as the file it lies about."""
    result_written, _reports, _keypair = attested
    members = read_members(result_written.path)

    manifest = json.loads(members["manifest.json"])
    row = next(row for row in manifest["files"] if row["path"] == "entries.jsonl")
    row["sha256"] = "0" * 64
    members["manifest.json"] = canonical_json(manifest)

    result = verify_mod.verify_package(write_members(tmp_path / "manifest.zip", members))

    assert result.ok is False
    assert result.checks["signature_valid"] is False
    assert "signature does not verify against any key in the package keyring" in result.problems
    assert result.checks["files_match_manifest"] is False
    assert "entries.jsonl: sha256 mismatch" in result.problems
    assert result.trust_state == "untrusted", "no key signed this manifest"


def test_a_file_nobody_declared_is_caught(tmp_path, attested):
    """The manifest is a closed list, not a minimum. An extra member is how a
    payload rides along inside an otherwise valid package."""
    result_written, _reports, keypair = attested
    members = read_members(result_written.path)
    members["bom/extra.cdx.json"] = b'{"smuggled": true}'

    result = verify_mod.verify_package(
        write_members(tmp_path / "extra.zip", members),
        trusted_keyring=trust_file(tmp_path, keypair.fingerprint),
    )

    assert result.ok is False
    assert result.checks["files_match_manifest"] is False
    assert "bom/extra.cdx.json: present in package but not covered by the manifest" in result.problems
    # Everything else still holds, which is what makes this failure readable.
    assert result.checks["chain_intact"] is True
    assert result.checks["merkle_root_matches"] is True
    assert result.checks["signature_valid"] is True
    assert result.trust_state == "trusted"


def test_two_members_under_one_name_are_refused(tmp_path, attested):
    """A zip may carry the same name twice, and `read` returns the last one.

    So a package could hide an unsigned member behind a name the manifest
    covers: every hash the verifier checked matched, because it checked the
    copy the reader was given, and nothing showed as undeclared, because the
    name was declared. Found by a hostile review of the verifier, not by the
    test suite, which is why this test exists rather than being assumed.
    """
    result_written, _reports, keypair = attested
    members = read_members(result_written.path)
    duplicated = "entries.jsonl"
    path = tmp_path / "duplicate.zip"
    with warnings.catch_warnings():
        # zipfile warns about the duplicate name. Writing one on purpose is
        # the point of the test, so the warning is the expected behaviour of
        # the fixture rather than something to fix.
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as handle:
            for name, payload in sorted(members.items()):
                handle.writestr(name, payload)
            handle.writestr(duplicated, b'{"smuggled": true}\n')

    result = verify_mod.verify_package(
        path, trusted_keyring=trust_file(tmp_path, keypair.fingerprint)
    )

    assert result.ok is False
    assert any("duplicate member names" in problem for problem in result.problems)
    assert any(duplicated in problem for problem in result.problems)


def test_swapping_the_keyring_and_re_signing_passes_integrity_and_fails_identity(
    tmp_path, attested
):
    """The attack the whole design exists for.

    An attacker who rewrites the package also replaces the key it carries, so
    every internal check passes. Only an anchor the verifier already held can
    tell the difference, which is why integrity alone is reported as
    `embedded_key_only` rather than as success.
    """
    result_written, _reports, keypair = attested
    members = read_members(result_written.path)
    attacker = signing.generate()

    lines = members["entries.jsonl"].splitlines()
    entry = json.loads(lines[1])
    entry["payload"]["verdict"] = "pass"
    entry["payload"]["findings"] = []
    entry["payload_hash"] = chain.compute_payload_hash(entry["payload"])
    entry["entry_hash"] = chain.compute_entry_hash(
        entry["prev_hash"],
        entry["payload_hash"],
        entry["timestamp"],
        entry["subject_sha256"],
        entry["index"],
    )
    members["entries.jsonl"] = lines[0] + b"\n" + canonical_json(entry) + b"\n"

    forged_entries = [
        json.loads(line) for line in members["entries.jsonl"].splitlines() if line.strip()
    ]
    manifest = json.loads(members["manifest.json"])
    manifest["head_hash"] = forged_entries[-1]["entry_hash"]
    from actaira.attest import merkle

    manifest["merkle_root"] = merkle.build_root(
        [merkle.leaf_hash(canonical_json(item)) for item in forged_entries]
    ).hex()
    members["manifest.json"] = canonical_json(manifest)
    members["keyring.json"] = canonical_json(
        {
            "keys": [
                {
                    "key_id": attacker.key_id,
                    "algorithm": "ed25519",
                    "public_key_b64": attacker.public_b64,
                    "fingerprint_sha256": attacker.fingerprint,
                }
            ]
        }
    )
    members = resign(members, attacker)
    forged = write_members(tmp_path / "forged.zip", members)

    # Without an anchor, the forgery is internally perfect...
    naive = verify_mod.verify_package(forged)
    assert all(naive.checks[name] for name in INTEGRITY_CHECKS)
    assert naive.trust_state == "embedded_key_only"
    assert naive.ok is True

    # ...and the anchor is the only thing that catches it.
    checked = verify_mod.verify_package(
        forged,
        trusted_keyring=trust_file(tmp_path, keypair.fingerprint),
        require_trust=True,
    )
    assert checked.ok is False
    assert checked.trust_state == "untrusted"
    assert checked.checks["key_trusted"] is False
    assert any("not in the supplied trust anchors" in problem for problem in checked.problems)
    # The original package, verified with the same anchor, passes: the anchor
    # is not just rejecting everything.
    assert verify_mod.verify_package(
        result_written.path,
        trusted_keyring=trust_file(tmp_path, keypair.fingerprint),
        require_trust=True,
    ).ok is True


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------

def test_a_package_missing_a_required_member_is_refused(tmp_path, attested):
    result_written, _reports, _keypair = attested
    members = read_members(result_written.path)
    del members["keyring.json"]

    result = verify_mod.verify_package(write_members(tmp_path / "nokeyring.zip", members))

    assert result.ok is False
    assert "missing required member: keyring.json" in result.problems


def test_something_that_is_not_a_zip_is_refused_without_raising(tmp_path):
    path = tmp_path / "not-a-package.zip"
    path.write_bytes(b"this is not a zip file")

    result = verify_mod.verify_package(path)

    assert result.ok is False
    assert result.problems and "not a readable zip" in result.problems[0]


# ---------------------------------------------------------------------------
# Hostile input: a verdict, never a traceback
# ---------------------------------------------------------------------------
#
# CLAUDE.md, code rules: a format error is caught at load time and is a message,
# not a traceback. `_read_member` already obeyed that and the three readers
# after it did not. Each of these came out of `verify_package` as an exception,
# so `actaira verify` printed a Python stack to stderr on a package anyone can
# build. One test per input, because they fail through three different types.


def _forged(tmp_path: Path, attested, name: str, **replacements: bytes) -> Path:
    result_written, _reports, _keypair = attested
    members = read_members(result_written.path)
    members.update(replacements)
    return write_members(tmp_path / name, members)


def test_a_payload_carrying_a_nan_token_is_a_verdict(tmp_path, attested):
    """`json.loads` accepts the bare token `NaN`; `canonical_json` is
    `allow_nan=False` and is called by `verify_chain` and by `leaf_hash`,
    outside any `try`. The result was `ValueError: Out of range float values`."""
    result_written, _reports, _keypair = attested
    line = json.loads(read_members(result_written.path)["entries.jsonl"].splitlines()[0])
    line["payload"] = {"claim": "observed"}
    blob = json.dumps(line).replace('"observed"', "NaN").encode("utf-8") + b"\n"

    result = verify_mod.verify_package(_forged(tmp_path, attested, "nan.zip", **{"entries.jsonl": blob}))

    assert result.ok is False
    assert any("NaN" in problem for problem in result.problems), result.problems


def test_a_manifest_file_row_without_a_path_is_a_verdict(tmp_path, attested):
    """`{row["path"]: row for row in ...}` raised `KeyError: 'path'`."""
    result_written, _reports, _keypair = attested
    manifest = json.loads(read_members(result_written.path)["manifest.json"])
    manifest["files"] = [{"sha256": "0" * 64}]
    blob = json.dumps(manifest).encode("utf-8")

    result = verify_mod.verify_package(
        _forged(tmp_path, attested, "nopath.zip", **{"manifest.json": blob})
    )

    assert result.ok is False
    assert result.checks["files_match_manifest"] is False
    assert any("declares no `path`" in problem for problem in result.problems), result.problems


def test_a_manifest_whose_files_is_not_a_list_is_a_verdict(tmp_path, attested):
    """The same line raised `TypeError: string indices must be integers`."""
    result_written, _reports, _keypair = attested
    manifest = json.loads(read_members(result_written.path)["manifest.json"])
    manifest["files"] = "entries.jsonl"
    blob = json.dumps(manifest).encode("utf-8")

    result = verify_mod.verify_package(
        _forged(tmp_path, attested, "filesstr.zip", **{"manifest.json": blob})
    )

    assert result.ok is False
    assert result.checks["files_match_manifest"] is False
    assert any("not a list of members" in problem for problem in result.problems), result.problems


def test_no_hostile_package_in_this_file_reaches_the_caller_as_an_exception(tmp_path, attested):
    """The property behind the three above, over a handful more shapes. A
    verifier that crashes has not refused the package: it has told a CI job
    that Actaira is broken, which is where the operator looks next."""
    result_written, _reports, _keypair = attested
    original = read_members(result_written.path)
    manifest = json.loads(original["manifest.json"])

    shapes = {
        "manifest is a list": {"manifest.json": b"[]"},
        "manifest files rows are strings": {
            "manifest.json": json.dumps({**manifest, "files": ["entries.jsonl"]}).encode("utf-8")
        },
        "entries line is not an object": {"entries.jsonl": b'"just a string"\n'},
        "entries carry Infinity": {"entries.jsonl": b'{"index": Infinity}\n'},
        "manifest head_hash is an object": {
            "manifest.json": json.dumps({**manifest, "head_hash": {}}).encode("utf-8")
        },
    }
    for label, replacement in shapes.items():
        result = verify_mod.verify_package(
            _forged(tmp_path, attested, f"{label.replace(' ', '-')}.zip", **replacement)
        )
        assert result.ok is False, label
        assert result.problems, label
