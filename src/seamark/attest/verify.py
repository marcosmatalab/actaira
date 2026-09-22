"""Offline verification of an attestation package.

Design note D-15, the decision that gives this tool its reason to exist.

Verification answers two different questions and refuses to blur them:

  integrity  do the bytes match what the manifest says, is the chain
             self-consistent, does the Merkle root recompute, and does the
             signature check out against the key in the package?
  identity   is the signing key one the verifier already trusts?

A package always carries its own public key, so integrity can always be
checked. That proves the package was not edited after signing; it proves
nothing about who signed it, because an attacker who rewrites the package
also replaces the embedded key. Tools that print a green tick for this case
are lying by omission.

So: integrity-only verification returns `trust_state = "embedded_key_only"`
and a loud warning. `--require-trust` turns that state into a failure. The
verifier here shares no code path with the writer beyond the hash helpers,
so a bug in package writing cannot be cancelled out by the same bug in
reading.
"""
from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..model import canonical_json
from . import keyring as keyring_mod
from . import merkle, signing, timestamp, trust
from .chain import verify_chain
from .package import (
    DSSE_NAME,
    ENTRIES_NAME,
    KEYRING_NAME,
    MANIFEST_NAME,
    SIGNATURE_NAME,
    TIME_ANCHOR_NONE,
    TIME_ANCHOR_RFC3161,
    TIMESTAMP_NAME,
    TIMESTAMP_TOKEN_DIGEST_KEY,
    UNDECLARED_BY_CONSTRUCTION,
    manifest_signing_subject,
    timestamp_subject,
)

# Checks that must be recorded on every package, whatever shape it is in. A
# name here that is missing from `result.checks` fails the package: a check that
# did not run is not a check that passed.
REQUIRED_CHECKS = (
    "files_match_manifest",
    "chain_intact",
    "head_matches",
    "merkle_root_matches",
    "signature_valid",
)

# Checks only some packages reach - a DSSE envelope, a keyring record, a TSA
# trust store the caller asked for, a time anchor.
# Recorded whenever they apply, and a False one fails exactly like a required
# one. The distinction that matters is between a check that does not apply and
# one that applies and did not run: the first is a package with nothing to
# check, the second is the hole this whole tally was rewritten to close, so
# every branch where one applies records it rather than returning past it.
# `_check_timestamp` is where that went wrong and it is audited by
# `test_the_timestamp_check_is_recorded_whenever_it_applies`.
CONDITIONAL_CHECKS = (
    "dsse_envelope_valid",
    "sealed_document_is_a_contract_this_tool_knows",
    "signing_key_in_validity",
    "timestamp_matches_manifest",
    "tsa_trust_store_loaded",
)

FAILING_CHECKS = REQUIRED_CHECKS + CONDITIONAL_CHECKS

# The only checks a False value does NOT fail, one line of why each. The list
# is short because it is the whole of the exception: everything else fails.
#
# `key_trusted` is an advisory and not a failure because D-15 keeps integrity
# and identity apart: a package always carries its own key, so integrity is
# always answerable, and "nobody vouched for this key" is the honest default
# rather than a defect in the package. Rejected: moving it to FAILING_CHECKS,
# which would fail every package verified without anchors and collapse the two
# questions the module exists to keep separate; `--require-trust` is how a
# caller asks for the strict reading, and it already fails the run.
ADVISORY_CHECKS = {
    "key_trusted": (
        "identity is a separate question from integrity (D-15). With no anchors "
        "the answer is `embedded_key_only`, which is the documented default, and "
        "only --require-trust turns it into a failure."
    ),
}

# What a check prints. Three markers, because two of them made the screen
# contradict itself: a healthy package verified without anchors showed
# `[FAIL] the signing key is one you already trust` above `Result: OK`, which
# is the correct verdict rendered in the word for the opposite one.
MARK_PASSED = "ok"
MARK_FAILED = "FAIL"
MARK_ADVISORY = "--"


def check_mark(name: str, passed: bool) -> str:
    """The marker one check prints, derived from its classification.

    Here rather than at the print site on purpose. A caller choosing the word
    is a caller who can print `[--]` next to a check that fails the package,
    and the marker has to be a function of the lists above or it is decoration.
    """
    if passed:
        return MARK_PASSED
    return MARK_ADVISORY if name in ADVISORY_CHECKS else MARK_FAILED

# Kept so a 2.x embedder importing this name still imports something true: it
# is the subset of REQUIRED_CHECKS that is about the package's bytes.
INTEGRITY_CHECKS = REQUIRED_CHECKS[:5]

# `ZipFile.read` decompresses without any limit at all, so a 1.4 MiB package
# whose `entries.jsonl` expands to three gigabytes made the verifier allocate
# three gigabytes: a denial of service against the machine doing the
# verifying, reachable from `POST /api/verify` with a file anyone can build.
# The archive inspector already learned this (`formats/archive._read_bounded`)
# and the attestation reader had not. Every member is read through
# `_read_member` now, capped, and a member over the cap is a verification
# problem rather than an allocation: a package this tool cannot read without
# exhausting memory is a package it must refuse, not one it dies on.
#
# 64 MiB is far above anything the writer produces - the largest member is
# `entries.jsonl`, roughly 3 KiB per inspected artifact - and small enough
# that a directory full of hostile packages cannot exhaust a laptop.
MAX_MEMBER_BYTES = 64 * 1024 * 1024
HASH_CHUNK = 1024 * 1024

@dataclass
class VerifyResult:
    ok: bool = False
    trust_state: str = "unverified"  # trusted | embedded_key_only | untrusted
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checks: dict[str, bool] = field(default_factory=dict)
    manifest: dict[str, Any] = field(default_factory=dict)
    entry_count: int = 0
    # When the package claims to have been signed, and how good that claim is.
    time_anchor: str = TIME_ANCHOR_NONE      # none | rfc3161
    time_evidence: str = "none"              # rfc3161 | self_asserted | none
    timestamp: dict[str, Any] | None = None
    # The signing key's standing at that moment, and where that verdict came
    # from: a keyring the verifier supplied, or the one the package carries.
    key_state: str = "unknown"
    key_status_source: str = "none"          # trusted_keyring | package | none
    # Which published contracts the entries in this package declare, in the
    # order they appear. Empty for a 2.x package, whose entries carry a payload
    # with no `schema_version` at all - which is not a defect in it and does not
    # make it fail. `seamark seal` is the first writer in this tree that puts a
    # versioned document into a chain, and a verifier that could not say WHAT it
    # had just verified would be checking bytes and reporting nothing about them.
    documents: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "trust_state": self.trust_state,
            "checks": self.checks,
            "problems": self.problems,
            "warnings": self.warnings,
            "entry_count": self.entry_count,
            "time_anchor": self.time_anchor,
            "time_evidence": self.time_evidence,
            "timestamp": self.timestamp,
            "key_state": self.key_state,
            "key_status_source": self.key_status_source,
            "documents": self.documents,
            "manifest": self.manifest,
        }


def verify_extends(
    older_package: Path,
    newer_package: Path,
) -> tuple[bool, list[str]]:
    """Check that `newer_package` is an append-only extension of `older_package`.

    Design note D-25b. This is the question a hash chain alone cannot answer.
    Whoever holds the signing key can publish a chain today and a different
    chain tomorrow, both internally consistent, with an entry quietly
    rewritten; every inclusion proof against the newer one still verifies.
    Comparing two roots with an RFC 6962 consistency proof is what turns
    "append-only" from a promise into something the holder of the old root
    can check for themselves.

    Both packages are verified for integrity first, because a consistency
    proof over a forged package proves nothing.
    """
    problems: list[str] = []
    older = verify_package(older_package)
    newer = verify_package(newer_package)
    if not older.ok:
        problems.append(f"older package does not verify: {older.problems[:1]}")
    if not newer.ok:
        problems.append(f"newer package does not verify: {newer.problems[:1]}")
    if problems:
        return False, problems

    old_entries = _read_entries(older_package)
    new_entries = _read_entries(newer_package)
    if len(new_entries) < len(old_entries):
        return False, [f"newer package has {len(new_entries)} entries, older has {len(old_entries)}"]

    old_leaves = [merkle.leaf_hash(canonical_json(entry)) for entry in old_entries]
    new_leaves = [merkle.leaf_hash(canonical_json(entry)) for entry in new_entries]
    proof = merkle.build_consistency_proof(new_leaves, len(old_leaves))
    ok = merkle.verify_consistency(
        merkle.build_root(old_leaves), len(old_leaves),
        merkle.build_root(new_leaves), len(new_leaves),
        proof,
    )
    if not ok:
        problems.append(
            "the newer log is not an extension of the older one: an entry was "
            "rewritten or removed, not merely appended"
        )
    return ok, problems


def _read_entries(package_path: Path) -> list[dict[str, Any]]:
    with zipfile.ZipFile(package_path) as archive:
        blob = _read_member_or_raise(archive, ENTRIES_NAME)
        return [strict_json(line) for line in blob.splitlines() if line.strip()]


class MemberTooLargeError(Exception):
    """A package member that will not be decompressed at any price."""


def _read_member_or_raise(archive: zipfile.ZipFile, name: str) -> bytes:
    """Read one member with a hard cap on the decompressed size.

    Reading one byte past the cap is enough to detect the overflow without
    materialising it, the same trick `formats/archive._read_bounded` uses.
    """
    with archive.open(name) as handle:
        payload = handle.read(MAX_MEMBER_BYTES + 1)
    if len(payload) > MAX_MEMBER_BYTES:
        raise MemberTooLargeError(
            f"{name} decompresses to more than {MAX_MEMBER_BYTES // (1024 * 1024)} MiB; "
            "refusing to read it"
        )
    return payload


def _read_member(archive: zipfile.ZipFile, name: str, result: VerifyResult) -> bytes | None:
    """The same read, as a verification problem instead of an exception."""
    try:
        return _read_member_or_raise(archive, name)
    except MemberTooLargeError as exc:
        result.problems.append(str(exc))
        return None
    except Exception as exc:  # noqa: BLE001 - an unreadable member is a verdict, not a crash
        result.problems.append(f"{name} could not be read: {type(exc).__name__}: {exc}")
        return None


def _hash_member(archive: zipfile.ZipFile, name: str) -> str | None:
    """sha256 of a member, streamed, so a declared file cannot be a bomb either.

    None means the member is over the cap or would not decompress; the caller
    turns that into a mismatch, because a file whose digest cannot be computed
    has not matched the manifest.
    """
    digest = hashlib.sha256()
    seen = 0
    try:
        with archive.open(name) as handle:
            while True:
                chunk = handle.read(HASH_CHUNK)
                if not chunk:
                    break
                seen += len(chunk)
                if seen > MAX_MEMBER_BYTES:
                    return None
                digest.update(chunk)
    except Exception:  # noqa: BLE001 - same reason as above
        return None
    return digest.hexdigest()


def strict_json(blob: bytes | str) -> Any:
    """`json.loads`, minus the three tokens `canonical_json` cannot write back.

    `json.loads` accepts `NaN`, `Infinity` and `-Infinity`; `canonical_json` is
    `allow_nan=False`. So a payload carrying one loaded here, travelled as far
    as `verify_chain` and `merkle.leaf_hash`, and came out of the verifier as a
    `ValueError` traceback. Refused at the point of reading instead: a format
    error is a message at load time, not a crash at evaluation time.
    """

    def refuse(token: str) -> Any:
        raise ValueError(f"{token} is not a number this verifier reads")

    return json.loads(blob, parse_constant=refuse)


def _declared_files(manifest: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """The manifest's `files` list, checked for shape before it is indexed.

    `{row["path"]: row for row in manifest.get("files", [])}` raised `KeyError`
    on a row without a path and `TypeError` on a `files` that was a string. A
    manifest is a document somebody else wrote, so its shape is a verdict.
    """
    rows = manifest.get("files", [])
    if not isinstance(rows, list):
        return {}, [f"manifest `files` is a {type(rows).__name__}, not a list of members"]

    declared: dict[str, dict[str, Any]] = {}
    problems: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            problems.append(f"manifest files[{index}] is a {type(row).__name__}, not an object")
            continue
        path = row.get("path")
        if not isinstance(path, str) or not path:
            problems.append(f"manifest files[{index}] declares no `path`, so it names no member")
            continue
        if path in declared:
            problems.append(f"manifest files[{index}] declares {path} a second time")
            continue
        declared[path] = row
    return declared, problems


def settle(result: VerifyResult) -> None:
    """Turn the checks recorded into a verdict. Failure is the default.

    This was an allow-list: `INTEGRITY_CHECKS` plus three
    names read through `result.checks.get(name, True)`. A check that was False
    and not on the list counted for nothing - `dsse_envelope_valid` printed
    [FAIL] beside `Result: OK` - and a check that never ran counted as a pass,
    which is how an unreadable TSA trust store skipped the whole RFC 3161
    check. Rejected: adding those two names to the list, which fixes two
    packages and leaves the shape that produced both of them in place.
    """
    missing = [name for name in REQUIRED_CHECKS if name not in result.checks]
    for name in missing:
        result.problems.append(f"{name} was never established, so it cannot be read as passed")
    failed = [
        name
        for name, passed in sorted(result.checks.items())
        if not passed and name not in ADVISORY_CHECKS
    ]
    result.ok = not missing and not failed


def verify_package(
    package_path: Path,
    trusted_keyring: Path | None = None,
    trusted_pubkey_b64: str | None = None,
    require_trust: bool = False,
    tsa_trust_store: Path | None = None,
) -> VerifyResult:
    result = VerifyResult()
    package_path = Path(package_path)

    try:
        archive = zipfile.ZipFile(package_path)
    except Exception as exc:
        result.problems.append(f"package is not a readable zip: {type(exc).__name__}: {exc}")
        return result

    with archive:
        raw_names = archive.namelist()
        names = set(raw_names)
        # A zip may carry two members with the same name. `read` returns the
        # last one, so a package could hide an unsigned member behind a name
        # the manifest covers: every hash matched and nothing showed as
        # undeclared. Found by a hostile review, not by the test suite.
        if len(raw_names) != len(names):
            duplicates = sorted({name for name in raw_names if raw_names.count(name) > 1})
            result.problems.append(f"package contains duplicate member names: {duplicates}")
        for required in (MANIFEST_NAME, SIGNATURE_NAME, ENTRIES_NAME, KEYRING_NAME):
            if required not in names:
                result.problems.append(f"missing required member: {required}")
        if result.problems:
            return result

        manifest_blob = _read_member(archive, MANIFEST_NAME, result)
        if manifest_blob is None:
            return result
        try:
            manifest = strict_json(manifest_blob)
        except Exception as exc:
            result.problems.append(f"manifest.json is not valid JSON: {exc}")
            return result
        if not isinstance(manifest, dict):
            result.problems.append(
                f"manifest.json is a {type(manifest).__name__}, not a manifest object"
            )
            return result
        result.manifest = manifest

        # 1. every declared file hashes to what the manifest says
        declared, shape_problems = _declared_files(manifest)
        result.problems.extend(shape_problems)
        files_ok = not shape_problems
        for path, row in declared.items():
            if path not in names:
                result.problems.append(f"manifest lists {path}, not present in package")
                files_ok = False
                continue
            actual = _hash_member(archive, path)
            if actual is None:
                result.problems.append(
                    f"{path}: could not be read within the member size cap, so its digest "
                    "was never checked"
                )
                files_ok = False
            elif actual != row.get("sha256"):
                result.problems.append(f"{path}: sha256 mismatch")
                files_ok = False
        undeclared = names - set(declared) - set(UNDECLARED_BY_CONSTRUCTION)
        for path in sorted(undeclared):
            result.problems.append(f"{path}: present in package but not covered by the manifest")
            files_ok = False
        if len(raw_names) != len(names):
            files_ok = False
        result.checks["files_match_manifest"] = files_ok

        # 2. the chain is self-consistent
        entries_blob = _read_member(archive, ENTRIES_NAME, result)
        if entries_blob is None:
            return result
        try:
            entries = [strict_json(line) for line in entries_blob.splitlines() if line.strip()]
        except ValueError as exc:
            result.problems.append(f"{ENTRIES_NAME} is not valid JSON lines: {exc}")
            return result
        if not all(isinstance(entry, dict) for entry in entries):
            result.problems.append(f"{ENTRIES_NAME} holds a line that is not a chain entry object")
            return result
        result.entry_count = len(entries)
        chain_problems = verify_chain(entries)
        result.problems.extend(chain_problems)
        result.checks["chain_intact"] = not chain_problems

        # 3. head and Merkle root recompute from the entries themselves
        head_ok = (entries[-1]["entry_hash"] if entries else "0" * 64) == manifest.get("head_hash")
        if not head_ok:
            result.problems.append("head_hash in manifest does not match the last entry")
        result.checks["head_matches"] = head_ok

        leaves = [merkle.leaf_hash(canonical_json(entry)) for entry in entries]
        root_ok = merkle.build_root(leaves).hex() == manifest.get("merkle_root")
        if not root_ok:
            result.problems.append("merkle_root in manifest does not match the entries")
        result.checks["merkle_root_matches"] = root_ok

        # 4. signature over the manifest
        signature_blob = _read_member(archive, SIGNATURE_NAME, result)
        keyring_blob = _read_member(archive, KEYRING_NAME, result)
        if signature_blob is None or keyring_blob is None:
            return result
        try:
            signature_doc = json.loads(signature_blob)
            signature = base64.b64decode(signature_doc.get("signature_b64", ""))
            keyring = json.loads(keyring_blob)
        except Exception as exc:  # noqa: BLE001 - a malformed signature block is a verdict
            result.problems.append(f"the signature block could not be read: {type(exc).__name__}: {exc}")
            return result
        embedded = keyring.get("keys", []) if isinstance(keyring, dict) else []
        signature_ok = False
        signing_fingerprint = None
        signing_row: dict[str, Any] | None = None
        signing_public = None
        for key_row in embedded:
            try:
                public = signing.public_from_b64(key_row["public_key_b64"])
            except Exception:
                continue
            if signing.verify(public, signature, manifest_signing_subject(manifest_blob)):
                signature_ok = True
                signing_fingerprint = signing.fingerprint_of(public)
                signing_row = key_row if isinstance(key_row, dict) else None
                signing_public = public
                break
        if not signature_ok:
            result.problems.append("signature does not verify against any key in the package keyring")
        result.checks["signature_valid"] = signature_ok

        # 4b. the DSSE envelope, when the package carries one. Its bytes are
        # already covered by `files_match_manifest` - it is an ordinary member
        # with a digest in the manifest - so this checks the OTHER property:
        # that its own signature verifies over its own payload. A package
        # whose envelope was signed by a different key than the manifest is a
        # package that says two things, and a consumer reaching for the
        # envelope rather than for the chain has to be told.
        if DSSE_NAME in names:
            _check_envelope(archive, result, signing_public)

        # 4c. what the entries actually say. A package whose payload declares a
        # contract this tool publishes is checked against that contract's
        # required fields; one that declares a version this tool does not know
        # is a failure, not a shrug, because the alternative is reporting OK
        # about a document whose meaning we guessed. A payload that declares no
        # version at all is a 2.x entry and records nothing.
        _check_documents(entries, result)

        # 5. the time anchor, if the manifest claims one
        stamp = _check_timestamp(archive, names, manifest, result, tsa_trust_store)
        moment, result.time_evidence = _signing_moment(manifest, entries, stamp)

        # 6. the standing of the signing key at that moment
        trusted_records = _load_trusted_records(trusted_keyring)
        _check_key_validity(signing_row, signing_fingerprint, trusted_records, moment, result)

        # 7. identity, kept strictly separate from integrity
        anchors = _load_anchors(trusted_keyring, trusted_pubkey_b64)
        result.problems.extend(anchors.problems)
        if signing_fingerprint is None:
            result.trust_state = "untrusted"
        elif anchors.fingerprints:
            if signing_fingerprint in anchors.fingerprints:
                result.trust_state = "trusted"
            else:
                result.trust_state = "untrusted"
                result.problems.append(
                    f"signing key {signing_fingerprint[:16]} is not in the supplied trust anchors"
                )
        elif anchors.requested:
            # Asking for anchors and getting none is not the same as not
            # asking. A keyring with a typo in it ({"key": [...]}), a keyring
            # whose `keys` is a string, or `--pubkey ""` all produced an empty
            # set, which fell through to `embedded_key_only` and printed OK
            # with exit 0 - the caller's assertion about who they accept was
            # discarded in silence, and with it every revocation that keyring
            # carried. An anchor source that yields nothing usable is a
            # failure of the request, not an absence of one.
            result.trust_state = "untrusted"
            result.problems.append(
                "trust anchors were supplied but none could be loaded, so identity "
                "was not checked against anything"
            )
        else:
            result.trust_state = "embedded_key_only"
            result.warnings.append(
                "INTEGRITY VERIFIED, IDENTITY NOT VERIFIED: the package was checked "
                "against the public key it carries. Supply --trusted-keyring or "
                "--pubkey to bind it to a key you already trust."
            )
        result.checks["key_trusted"] = result.trust_state == "trusted"

    settle(result)
    # Supplying trust anchors is an assertion about who you accept. Returning
    # ok=True alongside "this key is not one of yours" is a contradiction a
    # caller will act on, so anchors are binding once given. Not requiring
    # them at all stays the default, and that case is `embedded_key_only`.
    if result.trust_state == "untrusted":
        result.ok = False
    if require_trust and result.trust_state != "trusted":
        result.ok = False
        result.problems.append("--require-trust was set and the signing key is not trusted")
    return result


def _check_documents(entries: list[dict[str, Any]], result: VerifyResult) -> None:
    """Name every published contract this package's entries declare, and check it.

    The check is deliberately narrow: the version is one this release publishes,
    and the document carries the fields that version says are required. It is
    not a full schema validation - `jsonschema` is a test dependency and this
    tool installs with `cryptography` alone - and saying so here is better than
    a reader assuming the stricter thing from the name.
    """
    from ..schemas import VERSIONS, load, stem

    declared = {version for version in VERSIONS.values()}
    ok = True
    for index, entry in enumerate(entries):
        payload = entry.get("payload")
        if not isinstance(payload, dict):
            continue
        version = payload.get("schema_version")
        if not isinstance(version, str):
            continue
        result.documents.append(version)
        if version not in declared:
            result.problems.append(
                f"entry {index} declares {version}, which this release does not publish, "
                "so what its fields mean here is a guess"
            )
            ok = False
            continue
        try:
            schema = load(stem(version))
        except KeyError:  # pragma: no cover - VERSIONS and the files agree, by test
            continue
        missing = [
            name for name in schema.get("required", []) if name not in payload
        ]
        if missing:
            result.problems.append(
                f"entry {index} declares {version} and is missing {', '.join(missing)}"
            )
            ok = False
    if result.documents:
        result.checks["sealed_document_is_a_contract_this_tool_knows"] = ok


@dataclass
class _Anchors:
    """The trust anchors a caller supplied, and what went wrong loading them.

    `requested` is deliberately separate from `fingerprints`: it records that
    the caller made an assertion about identity at all, which is the thing an
    empty set cannot tell you apart from silence.
    """
    fingerprints: set[str] = field(default_factory=set)
    problems: list[str] = field(default_factory=list)
    requested: bool = False


def _load_anchors(trusted_keyring: Path | None, trusted_pubkey_b64: str | None) -> _Anchors:
    """Every anchor the caller supplied, and a reason for every one that failed.

    Nothing here raises. A bad `--pubkey` used to propagate a `ValueError` out
    of `verify_package`; a bad keyring used to be discarded without a word.
    Both are now problems with a sentence saying which input was wrong and
    why, because the caller has to be able to fix it.
    """
    anchors = _Anchors(requested=trusted_keyring is not None or trusted_pubkey_b64 is not None)

    if trusted_pubkey_b64 is not None:
        if not trusted_pubkey_b64.strip():
            anchors.problems.append("--pubkey was given but is empty")
        else:
            try:
                anchors.fingerprints.add(
                    signing.fingerprint_of(signing.public_from_b64(trusted_pubkey_b64))
                )
            except Exception as exc:  # noqa: BLE001 - any decoding failure is one message
                anchors.problems.append(
                    f"--pubkey is not a base64 raw Ed25519 public key: {type(exc).__name__}: {exc}"
                )

    if trusted_keyring is not None:
        anchors.problems.extend(_anchors_from_keyring(Path(trusted_keyring), anchors.fingerprints))
    return anchors


def _anchors_from_keyring(path: Path, into: set[str]) -> list[str]:
    """Read a keyring file and add every usable fingerprint to `into`.

    The shape is checked rather than assumed. `payload.get("keys", [])` on
    `{"key": [...]}` returns an empty list, on `{"keys": "x"}` returns a
    string that iterates into characters, and on a list of strings raises
    inside the loop - three different ways for a keyring the caller believes
    in to contribute nothing, all of which used to look identical to "no
    keyring was supplied".
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return [f"--trusted-keyring {path} could not be read: {type(exc).__name__}: {exc}"]
    except ValueError as exc:
        return [f"--trusted-keyring {path} is not valid JSON: {exc}"]

    if not isinstance(payload, dict):
        return [f"--trusted-keyring {path} is a {type(payload).__name__}, not a keyring object"]
    if "keys" not in payload:
        return [
            f"--trusted-keyring {path} has no `keys` list "
            f"(top-level names present: {sorted(map(str, payload))})"
        ]
    rows = payload["keys"]
    if not isinstance(rows, list):
        return [f"--trusted-keyring {path}: `keys` is a {type(rows).__name__}, not a list"]
    if not rows:
        return [f"--trusted-keyring {path}: `keys` is empty, so it anchors nothing"]

    problems: list[str] = []
    for index, key_row in enumerate(rows):
        if not isinstance(key_row, dict):
            problems.append(f"--trusted-keyring {path}: keys[{index}] is not an object")
            continue
        if "fingerprint_sha256" in key_row:
            into.add(str(key_row["fingerprint_sha256"]))
        elif "public_key_b64" in key_row:
            try:
                into.add(signing.fingerprint_of(signing.public_from_b64(key_row["public_key_b64"])))
            except Exception as exc:  # noqa: BLE001 - one message per unusable row
                problems.append(
                    f"--trusted-keyring {path}: keys[{index}] carries an unreadable "
                    f"public_key_b64: {type(exc).__name__}: {exc}"
                )
        else:
            problems.append(
                f"--trusted-keyring {path}: keys[{index}] has neither fingerprint_sha256 "
                "nor public_key_b64"
            )
    return problems


def _check_envelope(archive: zipfile.ZipFile, result: VerifyResult, public: Any) -> None:
    """Verify the in-toto Statement this package carries, if it carries one.

    Defect DEF-96. The envelope format has been implemented and tested since
    2.0 and nothing produced or read one, because `--dsse` was advertised and
    never existed. Writing it without reading it back would repeat the same
    shape one layer along: a document in the package that no code in the
    package has ever checked.
    """
    from . import dsse

    blob = _read_member(archive, DSSE_NAME, result)
    if blob is None:
        return
    try:
        envelope = dsse.Envelope.from_json(blob.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - any parse failure is one problem
        result.problems.append(f"{DSSE_NAME} is not a DSSE envelope: {type(exc).__name__}: {exc}")
        result.checks["dsse_envelope_valid"] = False
        return
    if public is None:
        result.checks["dsse_envelope_valid"] = False
        result.problems.append(
            f"{DSSE_NAME} is present and no key in this package verified the manifest, so nothing "
            "can be said about it"
        )
        return
    ok, problems = dsse.verify_envelope(envelope, public)
    result.checks["dsse_envelope_valid"] = ok
    for problem in problems:
        result.problems.append(f"{DSSE_NAME}: {problem}")


def _check_timestamp(
    archive: zipfile.ZipFile,
    names: set[str],
    manifest: dict[str, Any],
    result: VerifyResult,
    tsa_trust_store: Path | None = None,
) -> timestamp.TokenVerification | None:
    """The RFC 3161 side of verification, D-27.

    Three things are checked and one is refused. The imprint must cover this
    exact manifest; the genTime and serial the manifest advertises must be
    the ones the token actually carries, or the manifest is describing some
    other token; and the token's own signature is checked against the
    certificate it carries. What is refused is any claim about the TSA's
    identity: no trust store ships with Seamark, so `tsa_chain` stays
    `not_verified` and says so out loud.
    """
    declared = str(manifest.get("time_anchor", TIME_ANCHOR_NONE))
    result.time_anchor = declared
    token = _read_member(archive, TIMESTAMP_NAME, result) if TIMESTAMP_NAME in names else None

    if declared == TIME_ANCHOR_NONE:
        if token is not None:
            result.problems.append(
                f"{TIMESTAMP_NAME} is present but the manifest declares no time anchor"
            )
            result.checks["timestamp_matches_manifest"] = False
        else:
            # No anchor claimed and no token carried, so there is nothing for a
            # token to agree with and the check does not apply. Deliberately
            # NOT recorded as True: this check's name says an RFC 3161 stamp
            # covers this manifest, and writing True where no stamp exists
            # would be claiming the unobserved. The warning is the answer here,
            # and `time_anchor` / `time_evidence` already carry it to --json.
            result.warnings.append(
                "NO TIME ANCHOR: the chain proves ordering, not when anything happened."
            )
        return None

    if declared != TIME_ANCHOR_RFC3161:
        result.problems.append(f"the manifest declares an unknown time anchor: {declared!r}")
        result.checks["timestamp_matches_manifest"] = False
        return None

    if token is None:
        result.problems.append(
            f"the manifest declares an RFC 3161 time anchor but the package carries no {TIMESTAMP_NAME}"
        )
        result.checks["timestamp_matches_manifest"] = False
        return None

    subject = hashlib.sha256(timestamp_subject(manifest)).digest()
    store = None
    if tsa_trust_store is not None:
        try:
            store = trust.load_store(tsa_trust_store)
        except (OSError, ValueError) as exc:
            # A trust store the caller named and this process cannot read is
            # a usage error, not a reason to fall back to checking nothing.
            # Silently verifying without the anchors somebody asked for is the
            # shape of failure this module exists to prevent - and it happened
            # anyway, because returning here left `timestamp_matches_manifest`
            # unrecorded and the old tally read an absent check as a pass. Both
            # are written down now: the store is its own hard failure, and the
            # timestamp it was going to check stays unestablished.
            result.problems.append(f"the TSA trust store could not be loaded: {exc}")
            result.checks["tsa_trust_store_loaded"] = False
            result.checks["timestamp_matches_manifest"] = False
            return None
        result.checks["tsa_trust_store_loaded"] = True
    stamp = timestamp.verify_token(token, subject, trust_store=store)
    result.problems.extend(stamp.problems)
    result.warnings.extend(stamp.warnings)
    result.timestamp = stamp.to_dict()

    declared_block = manifest.get("timestamp")
    consistent = True

    # A manifest that says `time_anchor: rfc3161` and carries no `timestamp`
    # block is not a manifest with fewer optional fields, it is a manifest
    # that declares an anchor and then describes no token. The comparisons
    # below used to default to whatever the token said - `get("gen_time")`
    # against `(None, actual)` and `get("serial_number", actual)` - so a
    # missing block made both of them compare a value with itself and pass. A
    # token issued in 1999, over the right digest, went through. There is no
    # permissive default here any more: the block is required, and so is each
    # field it is supposed to advertise.
    if not isinstance(declared_block, dict) or not declared_block:
        result.problems.append(
            "the manifest declares an RFC 3161 time anchor and carries no `timestamp` "
            "block, so there is nothing in the signed manifest for the token to agree with"
        )
        result.checks["timestamp_matches_manifest"] = False
        return None

    if stamp.info is not None:
        advertised = (
            ("gen_time", "genTime", declared_block.get("gen_time"), stamp.info.gen_time_iso),
            ("serial_number", "time-stamp serial", declared_block.get("serial_number"),
             str(stamp.info.serial_number)),
        )
        for field_name, label, claimed, actual in advertised:
            if claimed is None:
                result.problems.append(
                    f"the manifest's timestamp block does not advertise {field_name}, so the "
                    f"token's own {label} is unchecked"
                )
                consistent = False
            elif str(claimed) != actual:
                result.problems.append(
                    f"the manifest advertises a {label} the token does not carry: "
                    f"{claimed} against {actual}"
                )
                consistent = False

    # And the token's own bytes. `manifest.tsr` cannot be listed in `files`
    # (D-27b), so before this check it was the one member covered by neither
    # the file list nor the signature: swapping in another genuine token from
    # the same authority, with the genTime and serial the manifest advertises,
    # left every other check green.
    claimed_digest = declared_block.get(TIMESTAMP_TOKEN_DIGEST_KEY)
    actual_digest = hashlib.sha256(token).hexdigest()
    if claimed_digest is None:
        result.problems.append(
            f"the manifest's timestamp block does not declare {TIMESTAMP_TOKEN_DIGEST_KEY}, "
            f"so {TIMESTAMP_NAME} is covered by no signature and could be any token"
        )
        consistent = False
    elif str(claimed_digest) != actual_digest:
        result.problems.append(
            f"{TIMESTAMP_NAME} is not the token this manifest was signed over: "
            f"the manifest declares {str(claimed_digest)[:16]}..., the file hashes to "
            f"{actual_digest[:16]}..."
        )
        consistent = False

    result.checks["timestamp_matches_manifest"] = stamp.ok and consistent
    return stamp if stamp.ok and consistent else None


def _signing_moment(
    manifest: dict[str, Any],
    entries: list[dict[str, Any]],
    stamp: timestamp.TokenVerification | None,
) -> tuple[datetime | None, str]:
    """When this package was signed, and how much that answer is worth.

    `rfc3161` is a third party's word. `self_asserted` is the package's own
    `created` field, or the last entry's timestamp: both are covered by the
    signature and by the Merkle root, so they cannot be edited after the
    fact - but whoever holds the signing key chose them in the first place,
    which is exactly the gap D-13 describes and D-27 exists to close.
    """
    if stamp is not None and stamp.ok and stamp.info is not None:
        return stamp.info.gen_time, "rfc3161"
    moment = keyring_mod.parse_moment(manifest.get("created"))
    if moment is None and entries:
        moment = keyring_mod.parse_moment(str(entries[-1].get("timestamp", "")))
    return moment, "self_asserted" if moment is not None else "none"


def _check_key_validity(
    signing_row: dict[str, Any] | None,
    signing_fingerprint: str | None,
    trusted_records: dict[str, keyring_mod.KeyRecord],
    moment: datetime | None,
    result: VerifyResult,
) -> None:
    """Was this key allowed to sign, then? D-28.

    Both records are read and the stricter one decides. An attacker who
    rewrites a package rewrites its keyring too, so the embedded copy can only
    ever be believed against its own interest - which is exactly what a
    confessed `revoked` is. Rejected: the verifier's record winning outright,
    which is what this did, and which made naming the fingerprint in
    `--trusted-keyring` discard the package's own confession and return OK.
    """
    if signing_fingerprint is None:
        result.key_state = "unknown"
        return

    # Ordered: the verifier's record is consulted first, so it is the one that
    # names the source when the two agree.
    candidates: list[tuple[str, keyring_mod.KeyRecord]] = []
    trusted = trusted_records.get(signing_fingerprint)
    if trusted is not None:
        candidates.append(("trusted_keyring", trusted))
    if signing_row is not None:
        candidates.append(("package", keyring_mod.KeyRecord.from_dict(signing_row)))
    if not candidates:
        result.key_state = "unknown"
        return

    verdicts = [(source, keyring_mod.evaluate(record, moment)) for source, record in candidates]
    refusals = [pair for pair in verdicts if not pair[1].accepted]
    source, verdict = refusals[0] if refusals else verdicts[0]
    result.key_status_source = source
    result.key_state = verdict.state
    result.checks["signing_key_in_validity"] = verdict.accepted
    if not verdict.accepted:
        result.problems.append(verdict.detail)
        return
    if verdict.state == "retired_within_validity":
        result.warnings.append(
            f"SIGNED BY A RETIRED KEY: {verdict.detail}, according to "
            + (
                "the RFC 3161 time-stamp."
                if result.time_evidence == "rfc3161"
                else "the package's own timestamps, which whoever holds the key chose. "
                "Anchor the package with --tsa-url to make that datable by a third party."
            )
        )


def _load_trusted_records(trusted_keyring: Path | None) -> dict[str, keyring_mod.KeyRecord]:
    """Keys the verifier supplied, indexed by fingerprint."""
    if trusted_keyring is None:
        return {}
    try:
        payload = json.loads(Path(trusted_keyring).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    records: dict[str, keyring_mod.KeyRecord] = {}
    if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
        # The shape is reported by `_load_anchors`, which fails the whole
        # verification for it. Here it is only a reason to read nothing:
        # duplicating the message would print it twice.
        return records
    for row in payload["keys"]:
        if not isinstance(row, dict):
            continue
        record = keyring_mod.KeyRecord.from_dict(row)
        if record.fingerprint_sha256:
            records[record.fingerprint_sha256] = record
    return records
