"""Key rotation, retirement and revocation, D-28.

The four cases the design turns on, and the file is arranged around them:

    active key                    verifies
    retired key, inside window    verifies, and says the key is retired
    retired key, outside window   refused
    revoked key                   refused, at any moment whatsoever

The moment a signature is judged against is either a third party's (an RFC
3161 genTime, D-27) or the package's own (`created`, and the entry
timestamps under it). Both are tested, because the difference between them
is the difference between evidence and a claim, and the verifier is required
to say which one it used.
"""
from __future__ import annotations

import json
import os
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import tsa
from actaira import cli
from actaira.attest import chain, keyring, package, signing
from actaira.attest import timestamp as ts
from actaira.attest import verify as verify_mod
from actaira.inspect import inspect_artifact
from conftest import POSIX_MODE_BITS, corpus_build, requires_posix_modes

NOW = datetime.now(UTC)


def iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


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


def ring_with(keypair, **fields) -> keyring.Keyring:
    """A keyring whose only key is this one, in whatever state the test needs."""
    record = keyring.KeyRecord.from_keypair(keypair)
    for name, value in fields.items():
        setattr(record, name, value)
    return keyring.Keyring(keys=[record])


def sign_package(tmp_path: Path, entries, keypair, ring, name="package.zip", **kwargs):
    return package.write_package(tmp_path / name, entries, keypair, keyring=ring, **kwargs)


# ---------------------------------------------------------------------------
# The rule itself, in isolation
# ---------------------------------------------------------------------------

def test_an_active_key_inside_its_window_is_accepted():
    record = keyring.KeyRecord("k", "b64", "f" * 64, not_before=iso(NOW - timedelta(days=1)))

    verdict = keyring.evaluate(record, NOW)

    assert verdict.accepted
    assert verdict.state == "active"


def test_a_retired_key_is_accepted_inside_the_window_it_was_valid_for():
    record = keyring.KeyRecord(
        "k", "b64", "f" * 64, status=keyring.RETIRED,
        not_before=iso(NOW - timedelta(days=30)), not_after=iso(NOW - timedelta(days=10)),
    )

    verdict = keyring.evaluate(record, NOW - timedelta(days=20))

    assert verdict.accepted
    assert verdict.state == "retired_within_validity"


def test_a_retired_key_is_refused_after_its_window_closed():
    record = keyring.KeyRecord(
        "k", "b64", "f" * 64, status=keyring.RETIRED,
        not_before=iso(NOW - timedelta(days=30)), not_after=iso(NOW - timedelta(days=10)),
    )

    verdict = keyring.evaluate(record, NOW)

    assert not verdict.accepted
    assert verdict.state == "retired_outside_validity"
    assert "stopped being valid" in verdict.detail


def test_a_revoked_key_is_refused_even_inside_its_window():
    """Revocation is not an expiry. A key that was in the wrong hands taints
    what it signed before anyone noticed, which is the whole difference from
    retirement."""
    record = keyring.KeyRecord(
        "k", "b64", "f" * 64, status=keyring.REVOKED,
        not_before=iso(NOW - timedelta(days=30)), not_after=iso(NOW + timedelta(days=30)),
        revoked_at=iso(NOW),
    )

    for moment in (NOW - timedelta(days=20), NOW, NOW + timedelta(days=20)):
        verdict = keyring.evaluate(record, moment)
        assert not verdict.accepted
        assert verdict.state == "revoked"


def test_a_key_with_no_window_at_all_is_unconstrained():
    """Keys made before 1.0.0 have no dates. Refusing them would break every
    package written by an earlier version, which is not what rotation is for."""
    verdict = keyring.evaluate(keyring.KeyRecord("k", "b64", "f" * 64), NOW)

    assert verdict.accepted
    assert verdict.state == "unconstrained"


def test_a_key_with_a_window_and_no_evidence_of_when_is_refused():
    record = keyring.KeyRecord("k", "b64", "f" * 64, not_before=iso(NOW))

    verdict = keyring.evaluate(record, None)

    assert not verdict.accepted
    assert verdict.state == "no_time_evidence"


def test_an_unrecognised_status_is_refused_rather_than_treated_as_active():
    """The safe direction. A status this version does not know must not
    default to the most permissive one."""
    record = keyring.KeyRecord("k", "b64", "f" * 64, status="probably-fine")

    verdict = keyring.evaluate(record, NOW)

    assert not verdict.accepted
    assert verdict.state == "unknown_status"


def test_a_signature_predating_the_key_is_refused():
    record = keyring.KeyRecord("k", "b64", "f" * 64, not_before=iso(NOW))

    verdict = keyring.evaluate(record, NOW - timedelta(days=1))

    assert not verdict.accepted
    assert verdict.state == "before_validity"


# ---------------------------------------------------------------------------
# The same four cases, through a real package
# ---------------------------------------------------------------------------

def test_a_package_signed_by_an_active_key_verifies(tmp_path, entries, keypair):
    result = sign_package(tmp_path, entries, keypair, ring_with(keypair))

    verified = verify_mod.verify_package(result.path)

    assert verified.ok
    assert verified.key_state == "active"
    assert verified.checks["signing_key_in_validity"] is True


def test_a_package_signed_inside_a_retired_keys_window_verifies_with_a_warning(
    tmp_path, entries, keypair
):
    ring = ring_with(
        keypair,
        status=keyring.RETIRED,
        not_before=iso(NOW - timedelta(days=10)),
        not_after=iso(NOW + timedelta(days=10)),
        retired_at=iso(NOW + timedelta(days=10)),
    )

    verified = verify_mod.verify_package(sign_package(tmp_path, entries, keypair, ring).path)

    assert verified.ok
    assert verified.key_state == "retired_within_validity"
    assert any("RETIRED KEY" in warning for warning in verified.warnings)
    assert any("whoever holds the key chose" in warning for warning in verified.warnings), \
        "with no anchor, the verifier must say the dating is the signer's own"


def test_a_package_signed_after_a_retired_keys_window_is_refused(tmp_path, entries, keypair):
    ring = ring_with(
        keypair,
        status=keyring.RETIRED,
        not_before=iso(NOW - timedelta(days=30)),
        not_after=iso(NOW - timedelta(days=10)),
    )

    verified = verify_mod.verify_package(sign_package(tmp_path, entries, keypair, ring).path)

    assert verified.ok is False
    assert verified.key_state == "retired_outside_validity"
    assert verified.checks["signing_key_in_validity"] is False
    assert verified.checks["signature_valid"] is True, "the bytes are intact; the key was not allowed"


def test_a_package_signed_by_a_revoked_key_is_refused(tmp_path, entries, keypair):
    ring = ring_with(keypair, status=keyring.REVOKED, revoked_at=iso(NOW))

    verified = verify_mod.verify_package(sign_package(tmp_path, entries, keypair, ring).path)

    assert verified.ok is False
    assert verified.key_state == "revoked"
    assert any("revoked" in problem for problem in verified.problems)


# ---------------------------------------------------------------------------
# Which clock decides
# ---------------------------------------------------------------------------

def test_a_time_stamp_can_place_a_signature_inside_a_window_the_package_falls_outside(
    tmp_path, entries, keypair
):
    """The case D-27 and D-28 were both written for: a retired key, a window
    that closed long ago, and a third party's word that the signing happened
    while it was open. Without the anchor this package is refused; with it,
    it verifies, and the verifier reports which of the two it used."""
    authority = tsa.FixtureTSA()
    stamped_at = datetime(2024, 6, 1, tzinfo=UTC)

    def stamp(url: str, digest: bytes, timeout: float = 10.0) -> ts.StampResult:
        response = ts.parse_response(authority.respond(ts.build_request(digest), gen_time=stamped_at))
        verification = ts.verify_token(response.token, digest)
        return ts.StampResult(response.token, verification.info, verification, url)

    ring = ring_with(
        keypair,
        status=keyring.RETIRED,
        not_before=iso(datetime(2024, 1, 1, tzinfo=UTC)),
        not_after=iso(datetime(2024, 12, 31, tzinfo=UTC)),
    )
    without = sign_package(tmp_path, entries, keypair, ring, name="unanchored.zip")
    with_anchor = sign_package(
        tmp_path, entries, keypair, ring, name="anchored.zip",
        tsa_url="https://tsa.example.invalid/tsr", stamp_fn=stamp,
    )

    unanchored = verify_mod.verify_package(without.path)
    anchored = verify_mod.verify_package(with_anchor.path)

    assert unanchored.ok is False
    assert unanchored.time_evidence == "self_asserted"
    assert unanchored.key_state == "retired_outside_validity"

    assert anchored.ok is True
    assert anchored.time_evidence == "rfc3161"
    assert anchored.key_state == "retired_within_validity"
    assert any("RFC 3161 time-stamp" in warning for warning in anchored.warnings)


def test_a_revoked_key_is_not_rescued_by_a_time_stamp(tmp_path, entries, keypair):
    """The control for the test above. If an anchor could rescue a revoked
    key, revocation would mean nothing."""
    authority = tsa.FixtureTSA()

    def stamp(url: str, digest: bytes, timeout: float = 10.0) -> ts.StampResult:
        response = ts.parse_response(
            authority.respond(ts.build_request(digest), gen_time=datetime(2024, 6, 1, tzinfo=UTC))
        )
        verification = ts.verify_token(response.token, digest)
        return ts.StampResult(response.token, verification.info, verification, url)

    ring = ring_with(
        keypair,
        status=keyring.REVOKED,
        not_before=iso(datetime(2024, 1, 1, tzinfo=UTC)),
        not_after=iso(datetime(2024, 12, 31, tzinfo=UTC)),
        revoked_at=iso(datetime(2025, 1, 1, tzinfo=UTC)),
    )

    verified = verify_mod.verify_package(
        sign_package(tmp_path, entries, keypair, ring,
                     tsa_url="https://tsa.example.invalid/tsr", stamp_fn=stamp).path
    )

    assert verified.ok is False
    assert verified.key_state == "revoked"


# ---------------------------------------------------------------------------
# Where the status comes from
# ---------------------------------------------------------------------------

def test_a_keyring_the_verifier_supplies_overrides_the_one_in_the_package(
    tmp_path, entries, keypair
):
    """A package rewritten by an attacker rewrites its own keyring too. The
    only revocation worth anything is the one the verifier already held."""
    result = sign_package(tmp_path, entries, keypair, ring_with(keypair))
    trusted = tmp_path / "trusted.json"
    trusted.write_text(json.dumps({
        "keys": [{
            "key_id": keypair.key_id,
            "public_key_b64": keypair.public_b64,
            "fingerprint_sha256": keypair.fingerprint,
            "status": "revoked",
            "revoked_at": iso(NOW),
        }]
    }), encoding="utf-8")

    optimistic = verify_mod.verify_package(result.path)
    honest = verify_mod.verify_package(result.path, trusted_keyring=trusted)

    assert optimistic.ok is True
    assert optimistic.key_status_source == "package"
    assert honest.ok is False
    assert honest.key_state == "revoked"
    assert honest.key_status_source == "trusted_keyring"


def test_a_package_that_admits_its_own_key_is_revoked_is_still_refused(tmp_path, entries, keypair):
    """The embedded copy can only make the verdict stricter, and it does. A
    package telling the truth against its own interest is worth believing."""
    ring = ring_with(keypair, status=keyring.REVOKED, revoked_at=iso(NOW))

    verified = verify_mod.verify_package(sign_package(tmp_path, entries, keypair, ring).path)

    assert verified.ok is False
    assert verified.key_status_source == "package"


def test_a_package_written_before_keyrings_existed_still_verifies(tmp_path, entries, keypair):
    """A 0.2.0 keyring row: four fields, no status and no dates."""
    ring = keyring.Keyring(keys=[keyring.KeyRecord.from_dict({
        "key_id": keypair.key_id,
        "algorithm": "ed25519",
        "public_key_b64": keypair.public_b64,
        "fingerprint_sha256": keypair.fingerprint,
    })])

    verified = verify_mod.verify_package(sign_package(tmp_path, entries, keypair, ring).path)

    assert verified.ok
    assert verified.key_state == "unconstrained"


# ---------------------------------------------------------------------------
# Rotation on disk
# ---------------------------------------------------------------------------

def test_rotation_retires_the_old_key_and_keeps_it(tmp_path):
    key_path = tmp_path / "signing-key.pem"
    before = keyring.load_local(key_path)

    rotation = keyring.rotate(key_path)

    assert rotation.retired.key_id == before.keypair.key_id
    assert rotation.retired.status == keyring.RETIRED
    assert rotation.fresh.key_id != before.keypair.key_id
    assert rotation.fresh.status == keyring.ACTIVE
    assert {record.key_id for record in rotation.keyring.keys} == {
        rotation.retired.key_id, rotation.fresh.key_id
    }
    assert rotation.keyring.active().key_id == rotation.fresh.key_id


def test_rotation_archives_the_old_private_key_rather_than_deleting_it(tmp_path):
    key_path = tmp_path / "signing-key.pem"
    original = keyring.load_local(key_path).keypair

    rotation = keyring.rotate(key_path)

    assert rotation.archived_key_path.exists()
    assert rotation.archived_key_path.name == f"signing-key-{original.key_id}.pem"
    if POSIX_MODE_BITS:
        assert oct(rotation.archived_key_path.stat().st_mode & 0o777) == "0o600"
    recovered, created = signing.load_or_create(rotation.archived_key_path)
    assert created is False
    assert recovered.key_id == original.key_id
    assert signing.load_or_create(key_path)[0].key_id == rotation.fresh.key_id


def test_the_retired_keys_window_closes_exactly_when_the_new_one_opens(tmp_path):
    """No gap and no overlap: a signature made at the instant of rotation must
    fall inside exactly one of the two windows, not neither."""
    rotation = keyring.rotate(tmp_path / "signing-key.pem")

    assert rotation.retired.not_after == rotation.fresh.not_before
    moment = keyring.parse_moment(rotation.fresh.not_before)
    assert keyring.evaluate(rotation.retired, moment).accepted
    assert keyring.evaluate(rotation.fresh, moment).accepted


def test_a_package_signed_before_rotation_still_verifies_afterwards(tmp_path, entries):
    """The failure this whole note exists to fix: before 1.0.0, rotating the
    key invalidated the history."""
    key_path = tmp_path / "signing-key.pem"
    local = keyring.load_local(key_path)
    old = package.write_package(
        tmp_path / "before.zip", entries, local.keypair, keyring=local.keyring
    )
    assert verify_mod.verify_package(old.path).ok

    rotation = keyring.rotate(key_path)
    published = tmp_path / "published-keyring.json"
    published.write_text(json.dumps(rotation.keyring.to_dict()), encoding="utf-8")

    verified = verify_mod.verify_package(old.path, trusted_keyring=published)

    assert verified.ok
    assert verified.trust_state == "trusted"
    assert verified.key_state == "retired_within_validity"


def test_revoking_a_key_marks_it_and_leaves_the_others_alone(tmp_path):
    key_path = tmp_path / "signing-key.pem"
    rotation = keyring.rotate(key_path)

    record = keyring.revoke(key_path, rotation.retired.key_id)

    assert record.status == keyring.REVOKED
    reloaded = keyring.Keyring.load(rotation.keyring_path)
    assert reloaded.find(rotation.retired.key_id).status == keyring.REVOKED
    assert reloaded.find(rotation.fresh.key_id).status == keyring.ACTIVE


def test_revoking_a_key_that_is_not_there_is_an_error_not_a_silent_no_op(tmp_path):
    key_path = tmp_path / "signing-key.pem"
    keyring.load_local(key_path)

    with pytest.raises(ValueError, match="no key"):
        keyring.revoke(key_path, "0123456789abcdef")


def test_retiring_a_revoked_key_is_refused(tmp_path):
    """Retirement is weaker than revocation, so it must not be reachable from
    it: that would launder a revoked key back into acceptability."""
    key_path = tmp_path / "signing-key.pem"
    local = keyring.load_local(key_path)
    local.keyring.revoke(local.keypair.key_id)

    with pytest.raises(ValueError, match="revoked"):
        local.keyring.retire(local.keypair.key_id)


@requires_posix_modes
def test_the_keyring_file_is_not_world_readable(tmp_path):
    """It holds no secret, but it does hold the path of every private key on
    the machine."""
    local = keyring.load_local(tmp_path / "signing-key.pem")

    assert oct(local.path.stat().st_mode & 0o777) == "0o600"
    assert json.loads(local.path.read_text())["keys"][0]["private_key_path"].endswith("signing-key.pem")


def test_both_key_files_are_created_restricted_rather_than_restricted_afterwards(tmp_path, monkeypatch):
    """The half of the permission claim that is observable on every platform.

    A kernel that ignores the mode argument is the host's decision and is
    recorded in `SECURITY.md`. What is Actaira's decision, everywhere, is
    *when* it asks: the mode goes to `os.open` together with `O_CREAT`, before
    any key material is written, rather than to a `chmod` afterwards. The
    difference is a window in which the file exists, is readable by everyone,
    and already holds a private key.

    So this asserts the argument rather than the resulting bits, which keeps
    the claim under test where `test_the_keyring_file_is_not_world_readable`
    cannot run at all.
    """
    opened: list[tuple[int, int]] = []
    real_open = os.open

    def recording_open(path, flags, mode=0o777, *args, **kwargs):
        opened.append((flags, mode))
        return real_open(path, flags, mode, *args, **kwargs)

    monkeypatch.setattr(os, "open", recording_open)
    keyring.load_local(tmp_path / "signing-key.pem")

    creating = [mode for flags, mode in opened if flags & os.O_CREAT]
    assert creating, "neither the private key nor the keyring was created through os.open"
    for mode in creating:
        assert mode == 0o600, (
            f"a key file was created with mode {oct(mode)}; the restriction has to be "
            "part of the create, not a chmod after the bytes are already on disk"
        )


def test_a_key_that_predates_the_keyring_is_adopted_without_inventing_a_date(tmp_path):
    """Stamping today's date on a key made last year would be a fabricated
    fact in the one field a verifier uses to date a signature."""
    key_path = tmp_path / "signing-key.pem"
    keypair, _ = signing.load_or_create(key_path)

    local = keyring.load_local(key_path)
    record = local.keyring.find(keypair.key_id)

    assert record.not_before is None
    assert record.created is None
    assert "predates the keyring" in record.note
    assert keyring.evaluate(record, NOW).state == "unconstrained"


def test_the_package_copy_of_the_keyring_carries_no_private_paths(tmp_path, entries):
    local = keyring.load_local(tmp_path / "signing-key.pem")
    result = package.write_package(tmp_path / "p.zip", entries, local.keypair, keyring=local.keyring)

    with zipfile.ZipFile(result.path) as archive:
        ring = json.loads(archive.read("keyring.json"))

    assert ring["keys"]
    assert all("private_key_path" not in row for row in ring["keys"])


# ---------------------------------------------------------------------------
# Through the command line
# ---------------------------------------------------------------------------

def test_keygen_prints_the_keyring_it_created(tmp_path, capsys):
    key_path = tmp_path / "signing-key.pem"

    assert cli.main(["keygen", "--key", str(key_path)]) == cli.EXIT_OK

    printed = capsys.readouterr().out
    assert "fingerprint " in printed
    assert "Keyring:" in printed
    assert "active" in printed


def test_keygen_rotate_reports_both_keys(tmp_path, capsys):
    key_path = tmp_path / "signing-key.pem"
    cli.main(["keygen", "--key", str(key_path)])
    first = capsys.readouterr().out.splitlines()[1].split()[1]

    assert cli.main(["keygen", "--key", str(key_path), "--rotate"]) == cli.EXIT_OK

    printed = capsys.readouterr().out
    assert "retired" in printed
    assert first in printed, "the retired key stays visible in the keyring"
    assert "not deleted" in printed


def test_keygen_revoke_marks_the_key(tmp_path, capsys):
    key_path = tmp_path / "signing-key.pem"
    cli.main(["keygen", "--key", str(key_path)])
    key_id = capsys.readouterr().out.splitlines()[1].split()[1]

    assert cli.main(["keygen", "--key", str(key_path), "--revoke", key_id]) == cli.EXIT_OK

    assert "revoked" in capsys.readouterr().out
    assert keyring.Keyring.load(keyring.keyring_path_for(key_path)).find(key_id).status == "revoked"


def test_keygen_revoking_an_unknown_key_is_a_usage_error(tmp_path, capsys):
    key_path = tmp_path / "signing-key.pem"
    cli.main(["keygen", "--key", str(key_path)])
    capsys.readouterr()

    assert cli.main(["keygen", "--key", str(key_path), "--revoke", "deadbeefdeadbeef"]) == cli.EXIT_USAGE
    assert "no key" in capsys.readouterr().err


def test_rotate_and_revoke_together_are_a_usage_error(tmp_path, capsys):
    assert cli.main([
        "keygen", "--key", str(tmp_path / "k.pem"), "--rotate", "--revoke", "abc"
    ]) == cli.EXIT_USAGE
    assert "two different things" in capsys.readouterr().err


def test_attest_signs_with_the_active_key_after_a_rotation(tmp_path, capsys):
    artifact = tmp_path / "clean.safetensors"
    artifact.write_bytes(
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}, b"\x00" * 16
        )
    )
    key_path = tmp_path / "signing-key.pem"
    rotation = keyring.rotate(key_path)
    capsys.readouterr()

    assert cli.main(["attest", str(artifact), "--out", str(tmp_path / "a.zip"), "--key", str(key_path)]) == cli.EXIT_OK

    printed = capsys.readouterr().out
    assert f"key_id       {rotation.fresh.key_id}" in printed
    verified = verify_mod.verify_package(tmp_path / "a.zip")
    assert verified.ok
    assert verified.manifest["signing_key_id"] == rotation.fresh.key_id
    assert verified.key_state == "active"

    # The package carries the retired key as well, so a verifier reading only
    # this package can still date what the previous key signed.
    with zipfile.ZipFile(tmp_path / "a.zip") as archive:
        ring = json.loads(archive.read("keyring.json"))
    assert {row["key_id"]: row["status"] for row in ring["keys"]} == {
        rotation.retired.key_id: "retired",
        rotation.fresh.key_id: "active",
    }
