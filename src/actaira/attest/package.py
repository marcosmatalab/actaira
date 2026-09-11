"""Build a portable, offline-verifiable attestation package.

Design note D-14. The package is a plain zip so that a third party can open
it with tools they already have, and every artifact inside is either text or
JSON so that a reviewer can read it without running Actaira at all. The
signature covers the manifest, and the manifest covers every other file by
SHA-256, so one signature check plus n hash checks authenticates the whole
package. Signing each file separately was rejected: n signatures is n
opportunities for a verifier to check some and not others.

Design note D-27b, the ordering problem an optional time anchor creates. A
time-stamp token is issued over a digest, and the only digest worth stamping
here is the manifest's. But the manifest has to record what the TSA said -
the authority, the genTime - or a reader would have to open a DER blob to
learn when the package claims to be from. Those two requirements chase each
other around: hashing the manifest requires the timestamp, writing the
timestamp into the manifest changes the hash.

The knot is cut by stamping a manifest with the anchor field held at
`"pending"`, and then completing it:

    subject = canonical_json(manifest | {"time_anchor": "pending"} - "timestamp")
    token   = TSA(sha256(subject))
    manifest["time_anchor"] = "rfc3161"
    manifest["timestamp"]   = {gen_time, serial, tsa, url, over,
                               token_sha256: sha256(token)}

`timestamp_subject()` below is that transformation, and the verifier applies
the same one to recover the exact bytes the TSA saw. Nothing is lost by
stamping the pending form: it already commits to the Merkle root, the head
hash, every file digest and the signing key. And the completed manifest is
what the Ed25519 signature covers, so everything written into it afterwards
is covered too - including `token_sha256`, the digest of the finished token,
which is what puts `manifest.tsr` itself under the signature. Without it the
token was the one member of the package covered by nothing: `files` cannot
list it, and the genTime and serial the manifest advertises are values a
second real token from the same authority can also carry. With it, a swapped
`manifest.tsr` fails against the manifest, and a swapped manifest fails
against the signature.
"""
from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import __version__
from ..model import canonical_json
from . import merkle, timestamp
from .chain import Entry
from .keyring import Keyring, single_key_ring
from .signing import KeyPair

PACKAGE_FORMAT_VERSION = 2
ENTRIES_NAME = "entries.jsonl"
MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.sig"
KEYRING_NAME = "keyring.json"
TIMESTAMP_NAME = "manifest.tsr"
# The in-toto Statement, in a DSSE envelope, for consumers that speak the
# supply-chain standards rather than this package format. Written as an
# ordinary member, so it is listed in `manifest.files` with its digest and is
# therefore covered by the manifest signature exactly like the BOMs are -
# which is the structural property `dsse.py` argues for: nothing hangs outside
# the signature.
DSSE_NAME = "statement.dsse.json"

TIME_ANCHOR_NONE = "none"
TIME_ANCHOR_RFC3161 = "rfc3161"
TIME_ANCHOR_PENDING = "pending"

# Written into the manifest so a reader knows exactly which bytes were
# stamped, without having to find this file.
TIMESTAMP_SUBJECT_NOTE = 'sha256(manifest.json with time_anchor="pending" and no timestamp block)'

# Members that are not listed in `files` because they cannot be: the manifest
# is the list and the signature is over the manifest. Everything else in the
# zip must be declared.
#
# `manifest.tsr` used to be on this list too, and that was a hole. The token
# is issued over the manifest's *pending* form, so it cannot appear in
# `files` - hashing it there would change the very bytes it commits to. But
# "cannot be in `files`" was read as "cannot be covered at all", and the
# token ended up outside both the file list and the Ed25519 signature: anyone
# could swap `manifest.tsr` for another token and the package still verified,
# because the only things checked against it were the genTime and the serial
# the manifest advertises, which an attacker holding a real token from the
# same TSA can satisfy. The fix costs nothing and closes it: the digest of
# the finished token goes into the manifest's `timestamp` block, which is not
# part of the stamped subject (`timestamp_subject` strips it) but *is* part
# of the signed manifest. The knot stays cut and the token is now covered.
UNDECLARED_BY_CONSTRUCTION = (MANIFEST_NAME, SIGNATURE_NAME, TIMESTAMP_NAME)

# The key under `timestamp` that carries that digest, named here because the
# verifier reads it and the writer writes it and neither should spell it out.
# noqa: S105 below - "token" here is an RFC 3161 time-stamp token, and the
# value is the name of a JSON field, not a credential.
TIMESTAMP_TOKEN_DIGEST_KEY = "token_sha256"  # noqa: S105


def timestamp_subject(manifest: dict[str, Any]) -> bytes:
    """The exact bytes a TSA was asked to stamp, recovered from a manifest.

    Used by the writer before the token exists and by the verifier after it
    does. Sharing this one function between them is the same concession D-15
    already makes for the hash helpers: it is a serialisation rule, not a
    judgement, and having two copies of a serialisation rule is how the two
    sides drift apart.
    """
    core = {name: value for name, value in manifest.items() if name != "timestamp"}
    core["time_anchor"] = TIME_ANCHOR_PENDING
    return canonical_json(core)


@dataclass
class PackageResult:
    path: Path
    head_hash: str
    merkle_root: str
    entry_count: int
    key_id: str
    fingerprint: str
    time_anchor: str = TIME_ANCHOR_NONE
    timestamp: timestamp.TokenInfo | None = None


def write_package(
    out_path: Path,
    entries: list[Entry],
    keypair: KeyPair,
    boms: dict[str, dict[str, Any]] | None = None,
    keyring: Keyring | None = None,
    envelope: bytes | None = None,
    tsa_url: str | None = None,
    tsa_timeout: float = 10.0,
    stamp_fn: Callable[..., timestamp.StampResult] | None = None,
) -> PackageResult:
    """Write the package, optionally anchored in time.

    `stamp_fn` exists so the timestamping path can be exercised without a
    network: the test suite passes a function backed by a TSA it runs itself.
    It is resolved at call time rather than bound as a default argument, so a
    caller can substitute it without reaching into this module's globals. The
    default is the real thing, and no other code path here opens a socket.
    """
    out_path = Path(out_path)
    boms = boms or {}

    entries_blob = b"".join(canonical_json(entry.to_dict()) + b"\n" for entry in entries)
    leaves = [merkle.leaf_hash(canonical_json(entry.to_dict())) for entry in entries]
    root = merkle.build_root(leaves).hex()
    head = entries[-1].entry_hash if entries else "0" * 64

    members: dict[str, bytes] = {ENTRIES_NAME: entries_blob}
    for subject_sha, document in boms.items():
        members[f"bom/{subject_sha}.cdx.json"] = canonical_json(document)

    if envelope is not None:
        # Defect DEF-96. `attest/dsse.py` has existed and been tested since
        # 2.0 and nothing ever called it: the README advertised `--dsse` and
        # the flag had never been implemented in any commit. A 500-line module
        # no user can reach is not interoperability, it is a claim.
        members[DSSE_NAME] = envelope

    ring = keyring or single_key_ring(keypair)
    members[KEYRING_NAME] = canonical_json(ring.to_dict(include_private=False))

    manifest: dict[str, Any] = {
        "format_version": PACKAGE_FORMAT_VERSION,
        "tool": "actaira",
        "tool_version": __version__,
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "entry_count": len(entries),
        "head_hash": head,
        "merkle_root": root,
        "merkle_scheme": "rfc6962",
        "signing_key_id": keypair.key_id,
        "signing_key_fingerprint_sha256": keypair.fingerprint,
        "time_anchor": TIME_ANCHOR_NONE,
        "files": sorted(
            (
                {
                    "path": name,
                    "sha256": hashlib.sha256(blob).hexdigest(),
                    "bytes": len(blob),
                }
                for name, blob in members.items()
            ),
            key=lambda row: row["path"],
        ),
    }

    token: bytes | None = None
    stamped: timestamp.TokenInfo | None = None
    if tsa_url:
        subject = timestamp_subject(manifest)
        stamper = stamp_fn or timestamp.stamp
        result = stamper(tsa_url, hashlib.sha256(subject).digest(), timeout=tsa_timeout)
        token = result.token
        stamped = result.info
        manifest["time_anchor"] = TIME_ANCHOR_RFC3161
        manifest["timestamp"] = {
            "tsa_url": tsa_url,
            "over": TIMESTAMP_SUBJECT_NOTE,
            "hash_algorithm": "sha256",
            "token_file": TIMESTAMP_NAME,
            # The token's own digest, so the signature covers the bytes of the
            # token and not merely a description of them. Written last, over
            # the finished DER, and read back by `verify._check_timestamp`.
            TIMESTAMP_TOKEN_DIGEST_KEY: hashlib.sha256(token).hexdigest(),
            "token_bytes": len(token),
            "gen_time": stamped.gen_time_iso,
            "serial_number": str(stamped.serial_number),
            "policy": stamped.policy,
            "tsa_name": stamped.tsa_name,
        }

    manifest_blob = canonical_json(manifest)
    signature = keypair.sign(hashlib.sha256(manifest_blob).digest())

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, blob in sorted(members.items()):
            archive.writestr(name, blob)
        archive.writestr(MANIFEST_NAME, manifest_blob)
        archive.writestr(
            SIGNATURE_NAME,
            json.dumps(
                {
                    "algorithm": "ed25519",
                    "over": "sha256(manifest.json)",
                    "key_id": keypair.key_id,
                    "signature_b64": base64.b64encode(signature).decode("ascii"),
                },
                indent=2,
            ),
        )
        if token is not None:
            archive.writestr(TIMESTAMP_NAME, token)

    return PackageResult(
        path=out_path,
        head_hash=head,
        merkle_root=root,
        entry_count=len(entries),
        key_id=keypair.key_id,
        fingerprint=keypair.fingerprint,
        time_anchor=manifest["time_anchor"],
        timestamp=stamped,
    )
