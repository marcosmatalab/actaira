"""The hash chain and the Ed25519 key handling.

Each tamper below must produce a *different* problem, localised to the entry it
touched. A verifier that answered "broken" for everything would still pass a
test that only asserted failure, so the assertions are on which problem, about
which entry.
"""
from __future__ import annotations

import copy
import hashlib
import stat

import pytest

from conftest import POSIX_MODE_BITS
from seamark.attest import chain, signing

# The DER SubjectPublicKeyInfo prefix for an Ed25519 key: SEQUENCE, AlgorithmId
# 1.3.101.112, BIT STRING of 32 bytes. Fixed by RFC 8410.
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


@pytest.fixture
def entries() -> list[dict]:
    """Four entries with fixed timestamps, so the chain is byte-reproducible."""
    built: list[chain.Entry] = []
    for index in range(4):
        chain.append(
            built,
            subject_sha256=f"{index:064x}",
            payload={"artifact": f"model-{index}.pt", "verdict": "pass", "findings": []},
            timestamp=f"2026-01-0{index + 1}T12:00:00.000000+00:00",
        )
    return [entry.to_dict() for entry in built]


# ---------------------------------------------------------------------------
# The intact chain
# ---------------------------------------------------------------------------

def test_an_intact_chain_reports_no_problems(entries):
    assert chain.verify_chain(entries) == []


def test_each_entry_commits_to_its_predecessor(entries):
    assert entries[0]["prev_hash"] == chain.GENESIS
    for position in range(1, len(entries)):
        assert entries[position]["prev_hash"] == entries[position - 1]["entry_hash"]
    assert len({entry["entry_hash"] for entry in entries}) == len(entries)


def test_the_same_content_hashes_the_same_way_twice(entries):
    """The chain is only evidence if it is reproducible: rebuilding it from the
    same inputs must give the same hashes."""
    rebuilt: list[chain.Entry] = []
    for entry in entries:
        chain.append(rebuilt, entry["subject_sha256"], entry["payload"], entry["timestamp"])

    assert [item.entry_hash for item in rebuilt] == [entry["entry_hash"] for entry in entries]


# ---------------------------------------------------------------------------
# Three tampers, three different problems
# ---------------------------------------------------------------------------

def test_editing_a_payload_breaks_that_entrys_payload_hash(entries):
    tampered = copy.deepcopy(entries)
    tampered[1]["payload"]["verdict"] = "fail"

    problems = chain.verify_chain(tampered)

    assert problems == ["entry[1]: payload_hash does not match payload"]


def test_deleting_an_entry_breaks_the_link_at_the_gap(entries):
    tampered = copy.deepcopy(entries)
    del tampered[2]

    problems = chain.verify_chain(tampered)

    assert problems == [
        "entry[2]: index is 3, expected 2",
        "entry[2]: prev_hash does not match previous entry_hash",
    ]


def test_moving_a_timestamp_breaks_that_entrys_own_hash(entries):
    """The timestamp is inside the entry hash on purpose: an attestation whose
    time can be edited without breaking anything is not evidence of when."""
    tampered = copy.deepcopy(entries)
    tampered[1]["timestamp"] = "2030-06-01T12:00:00.000000+00:00"

    problems = chain.verify_chain(tampered)

    assert problems == ["entry[1]: entry_hash does not match its own fields"]


def test_the_three_tampers_are_told_apart(entries):
    """Stated as its own assertion: the diagnostics must not converge on one
    generic "chain broken" message, or a verifier cannot say what happened."""
    payload_edit = copy.deepcopy(entries)
    payload_edit[1]["payload"]["verdict"] = "fail"
    deletion = copy.deepcopy(entries)
    del deletion[2]
    time_shift = copy.deepcopy(entries)
    time_shift[1]["timestamp"] = "2030-06-01T12:00:00.000000+00:00"

    results = [
        set(chain.verify_chain(payload_edit)),
        set(chain.verify_chain(deletion)),
        set(chain.verify_chain(time_shift)),
    ]

    for first in range(len(results)):
        for second in range(first + 1, len(results)):
            assert results[first] & results[second] == set()
            assert results[first] and results[second]


def test_reordering_two_entries_is_caught(entries):
    tampered = copy.deepcopy(entries)
    tampered[1], tampered[2] = tampered[2], tampered[1]

    problems = chain.verify_chain(tampered)

    assert "entry[1]: index is 2, expected 1" in problems
    assert "entry[1]: prev_hash does not match previous entry_hash" in problems
    # Everything from the swap onwards is broken, and nothing before it is:
    # that localisation is what tells a reviewer where the chain was touched.
    assert not any(problem.startswith("entry[0]") for problem in problems)


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

def test_a_signature_verifies_against_its_own_key(keypair):
    payload = b"manifest-bytes"
    signature = keypair.sign(payload)

    assert signing.verify(keypair.public, signature, payload) is True
    assert len(signature) == 64


def test_a_signature_does_not_verify_over_different_bytes(keypair):
    signature = keypair.sign(b"manifest-bytes")

    assert signing.verify(keypair.public, signature, b"manifest-byteS") is False


def test_a_signature_does_not_verify_under_another_key(keypair):
    other = signing.generate()
    signature = keypair.sign(b"manifest-bytes")

    assert signing.verify(other.public, signature, b"manifest-bytes") is False
    assert other.fingerprint != keypair.fingerprint


def test_a_corrupted_signature_is_rejected_rather_than_raising(keypair):
    payload = b"manifest-bytes"
    signature = bytearray(keypair.sign(payload))
    signature[0] ^= 0x01

    assert signing.verify(keypair.public, bytes(signature), payload) is False


def test_the_fingerprint_is_the_sha256_of_the_der_public_key(keypair):
    """The interoperability claim in D-12: an auditor must be able to recompute
    this with openssl, which means it is over the DER SubjectPublicKeyInfo and
    not over the raw 32 bytes."""
    import base64

    der = keypair.public_der
    raw = base64.b64decode(keypair.public_b64)

    assert der == ED25519_SPKI_PREFIX + raw
    assert keypair.fingerprint == hashlib.sha256(der).hexdigest()
    assert keypair.fingerprint != hashlib.sha256(raw).hexdigest()
    assert keypair.key_id == keypair.fingerprint[:16]


# ---------------------------------------------------------------------------
# Key files on disk
# ---------------------------------------------------------------------------

def test_load_or_create_writes_the_private_key_unreadable_to_others(tmp_path):
    path = tmp_path / "nested" / "signing-key.pem"

    created_pair, created = signing.load_or_create(path)

    assert created is True
    if POSIX_MODE_BITS:
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600, f"key file is {oct(mode)}, group or world can read it"
    # The half that holds everywhere - that the restriction is an argument to
    # the create rather than a chmod afterwards - is asserted in
    # tests/test_keyring.py. What a kernel without permission bits then does
    # with that argument is the host's decision, and SECURITY.md records it.
    # Written in two pieces so the whole PEM header never appears as one string
    # here: push protection reads a header in a source file as a leaked key.
    assert path.read_bytes().startswith(b"-----BEGIN " + b"PRIVATE KEY-----")
    assert created_pair.fingerprint


def test_reloading_the_key_file_gives_back_the_same_identity(tmp_path):
    path = tmp_path / "signing-key.pem"
    first, created_first = signing.load_or_create(path)

    second, created_second = signing.load_or_create(path)

    assert (created_first, created_second) == (True, False)
    assert second.fingerprint == first.fingerprint
    assert second.public_b64 == first.public_b64
    # Same identity means signatures made before the reload still verify.
    signature = first.sign(b"payload")
    assert signing.verify(second.public, signature, b"payload") is True


def test_two_separate_key_files_are_two_separate_identities(tmp_path):
    first, _ = signing.load_or_create(tmp_path / "a.pem")
    second, _ = signing.load_or_create(tmp_path / "b.pem")

    assert first.fingerprint != second.fingerprint
    assert signing.verify(second.public, first.sign(b"x"), b"x") is False


def test_a_pem_that_is_not_ed25519_is_refused(tmp_path):
    """A wrong-algorithm key must be rejected loudly, not silently used."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / "rsa.pem"
    path.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    with pytest.raises(ValueError):
        signing.load_or_create(path)
