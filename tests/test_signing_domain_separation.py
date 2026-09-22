"""One key signs two things. Each has to say which one it meant.

Ed25519 over a bare 32-byte digest carries no statement of context. Actaira
signs the package manifest and DSSE envelopes, and by default both use the
same key in ~/.actaira. `dsse.py` argues at length
for PAE precisely because that removes a class of cross-protocol confusion for
free; the package manifest signed 32 raw bytes and made no such statement, so
a signature produced in one role was bytes that verified in the other.

Three signers until phase A: the assurance receipt was the third, and it left
with `receipt.py` because no command reached it. Its two tests went with it.
The property is unchanged and is not weaker for having one fewer signer - it
is about whether a preimage names its role, and two roles that collide are
exactly as bad as three. Recover the receipt half from
`v2.3.0:tests/test_signing_domain_separation.py`.

One test per signer, plus the pair test that is the actual property: the
preimages over the same digest are different byte strings.
"""
from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from pathlib import Path

from actaira.attest import chain, package, signing
from actaira.model import canonical_json

DIGEST = hashlib.sha256(b"the same thirty-two bytes either way").digest()


# ---------------------------------------------------------------------------
# The package manifest
# ---------------------------------------------------------------------------


def test_manifest_signature_is_not_over_the_bare_digest() -> None:
    """What the key signs is the context plus the digest, never the digest alone."""
    blob = canonical_json({"schema_version": "x", "files": []})
    subject = package.manifest_signing_subject(blob)

    assert subject != hashlib.sha256(blob).digest(), "the bare digest is the defect"
    assert subject.startswith(package.MANIFEST_SIGNING_CONTEXT)
    assert subject == package.MANIFEST_SIGNING_CONTEXT + hashlib.sha256(blob).digest()


def test_a_manifest_signature_over_the_bare_digest_is_refused(tmp_path: Path, keypair) -> None:
    """The end-to-end half: forge the pre-fix signature, watch verification fail."""
    manifest_blob = canonical_json({"schema_version": "x", "files": []})
    forged = keypair.sign(hashlib.sha256(manifest_blob).digest())

    assert not signing.verify(
        keypair.private.public_key(), forged, package.manifest_signing_subject(manifest_blob)
    )
    assert signing.verify(
        keypair.private.public_key(), keypair.sign(package.manifest_signing_subject(manifest_blob)),
        package.manifest_signing_subject(manifest_blob),
    )


def test_the_manifest_says_what_its_signature_covers(tmp_path: Path, keypair) -> None:
    """A verifier reimplementing this reads the recipe out of the package."""
    entries: list[chain.Entry] = []
    chain.append(entries, "c" * 64, {"claim": "observed"}, timestamp="2026-01-01T00:00:00")
    out = tmp_path / "attestation.zip"
    package.write_package(out, entries, keypair)

    with zipfile.ZipFile(out) as archive:
        signature_doc = json.loads(archive.read(package.SIGNATURE_NAME))
        manifest_blob = archive.read(package.MANIFEST_NAME)

    assert signature_doc["over"] == package.SIGNATURE_SUBJECT_NOTE
    assert "MANIFEST_SIGNING_CONTEXT" in signature_doc["over"]
    assert signing.verify(
        keypair.private.public_key(),
        base64.b64decode(signature_doc["signature_b64"]),
        package.manifest_signing_subject(manifest_blob),
    )


# ---------------------------------------------------------------------------
# The receipt
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# The property the two constants exist for
# ---------------------------------------------------------------------------


def test_the_two_contexts_produce_two_different_preimages() -> None:
    """A shared "actaira" prefix would separate us from other tools, not these
    signers from each other. This is the assertion that catches that."""
    from actaira.attest import dsse

    manifest = package.MANIFEST_SIGNING_CONTEXT + DIGEST
    envelope = dsse.pae(dsse.PAYLOAD_TYPE, DIGEST)

    assert len({manifest, envelope, DIGEST}) == 3
    label = package.MANIFEST_SIGNING_CONTEXT
    assert label.endswith(b"\x00"), "the label needs a terminator that cannot occur in it"
    assert b"\x00" not in label[:-1]
