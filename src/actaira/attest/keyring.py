"""Several signing keys, with validity windows and a status.

Design note D-28. Until 1.0.0 a keyring held exactly one key, so rotating it
invalidated everything ever signed: the new package carried the new key, the
old packages carried the old one, and a verifier holding the current
fingerprint as a trust anchor rejected all of the history. That is not key
rotation, it is key replacement, and it punishes the one operational habit
this project should be encouraging.

**Decided.** A keyring is a list of keys. Each carries a status - `active`,
`retired` or `revoked` - and the window it was allowed to sign in
(`not_before`, `not_after`). `actaira keygen --rotate` retires the current
key and generates a new one *beside* it, keeping the old public key in the
ring. A verifier accepts a signature from a retired key when the moment the
package was signed falls inside that key's window, and refuses one from a
revoked key at any moment whatsoever.

**Why the two states differ.** Retirement is routine: the key stopped being
used, and what it signed before it stopped is still good. Revocation is the
claim that the key was in the wrong hands, and the honest reading of that is
that nothing it ever signed can be relied on, including things it signed
before anybody noticed. Collapsing the two into one flag would force a
choice between never being able to rotate and never being able to revoke.

**Where the truth lives.** A package carries a copy of the keyring so it can
be checked offline, and that copy is *not* authoritative about status: an
attacker who rewrites a package rewrites the keyring inside it, marking
their key active with a window that suits them. Status is only binding when
it comes from the keyring the verifier supplies with `--trusted-keyring`,
which is the same argument D-15 makes about identity. The embedded copy is
still used when there is no trust anchor, because "the package says this key
was revoked" is worth acting on even from an untrusted source: it can only
ever make the verdict stricter.

**What is given up.** There is no revocation distribution, no CRL and no
expiry that the tool enforces on its own. Publishing a keyring is the
operator's job. And a validity window is only as good as the evidence for
when signing happened, which is why this note only became worth writing once
D-27 put a real time anchor in the package.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .signing import KeyPair, fingerprint_of, load_or_create, public_from_b64

KEYRING_VERSION = 1
KEYRING_FILENAME = "keyring.json"

ACTIVE = "active"
RETIRED = "retired"
REVOKED = "revoked"
STATUSES = (ACTIVE, RETIRED, REVOKED)


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def parse_moment(value: str | None) -> datetime | None:
    """An ISO-8601 instant, or None if it is missing or unreadable.

    Unreadable is deliberately not an exception: these strings come out of a
    package written by somebody else, and a malformed date must degrade the
    evidence rather than crash the verifier.
    """
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


@dataclass
class KeyRecord:
    key_id: str
    public_key_b64: str
    fingerprint_sha256: str
    algorithm: str = "ed25519"
    status: str = ACTIVE
    not_before: str | None = None
    not_after: str | None = None
    created: str | None = None
    retired_at: str | None = None
    revoked_at: str | None = None
    note: str | None = None
    private_key_path: str | None = None

    @classmethod
    def from_keypair(cls, keypair: KeyPair, *, not_before: str | None = None, **extra: Any) -> KeyRecord:
        stamp = not_before or now_iso()
        return cls(
            key_id=keypair.key_id,
            public_key_b64=keypair.public_b64,
            fingerprint_sha256=keypair.fingerprint,
            not_before=stamp,
            created=stamp,
            **extra,
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> KeyRecord:
        """Tolerant on the way in, strict on the way out.

        A row from someone else's keyring may be missing anything. What it
        cannot do is become more permissive by being malformed: a row with no
        public key is unusable, and an unrecognised status is preserved
        verbatim so that `evaluate` refuses it rather than defaulting it to
        `active`.
        """
        public = str(raw.get("public_key_b64", ""))
        fingerprint = str(raw.get("fingerprint_sha256", "") or "")
        if not fingerprint and public:
            try:
                fingerprint = fingerprint_of(public_from_b64(public))
            except Exception:  # noqa: BLE001 - an unreadable key stays unusable, it does not raise here
                fingerprint = ""
        return cls(
            key_id=str(raw.get("key_id", fingerprint[:16])),
            public_key_b64=public,
            fingerprint_sha256=fingerprint,
            algorithm=str(raw.get("algorithm", "ed25519")),
            status=str(raw.get("status", ACTIVE)),
            not_before=_optional_str(raw.get("not_before")),
            not_after=_optional_str(raw.get("not_after")),
            created=_optional_str(raw.get("created")),
            retired_at=_optional_str(raw.get("retired_at")),
            revoked_at=_optional_str(raw.get("revoked_at")),
            note=_optional_str(raw.get("note")),
            private_key_path=_optional_str(raw.get("private_key_path")),
        )

    def to_dict(self, include_private: bool = False) -> dict[str, Any]:
        row: dict[str, Any] = {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key_b64": self.public_key_b64,
            "fingerprint_sha256": self.fingerprint_sha256,
            "status": self.status,
        }
        for name in ("not_before", "not_after", "created", "retired_at", "revoked_at", "note"):
            value = getattr(self, name)
            if value is not None:
                row[name] = value
        if include_private and self.private_key_path:
            row["private_key_path"] = self.private_key_path
        return row


def _optional_str(value: Any) -> str | None:
    return None if value is None else str(value)


@dataclass(frozen=True)
class Validity:
    """The answer to "could this key have signed this, then?", with its reason."""
    accepted: bool
    state: str
    detail: str = ""


def evaluate(record: KeyRecord, moment: datetime | None) -> Validity:
    """Decide a key record against an instant.

    `moment` is when the signature is believed to have been made. None means
    no evidence at all was available, which is not the same as evidence that
    it was in range: a key with a window and no moment to check it against is
    refused unless the record places no bounds on it.
    """
    if record.status == REVOKED:
        when = f" (revoked {record.revoked_at})" if record.revoked_at else ""
        return Validity(False, "revoked", f"key {record.key_id} is revoked{when}")
    if record.status not in STATUSES:
        return Validity(False, "unknown_status", f"key {record.key_id} carries an unrecognised status {record.status!r}")

    start = parse_moment(record.not_before)
    end = parse_moment(record.not_after)
    if start is None and end is None:
        return Validity(True, "unconstrained", f"key {record.key_id} declares no validity window")
    if moment is None:
        return Validity(
            False,
            "no_time_evidence",
            f"key {record.key_id} has a validity window but the package offers no evidence of when it was signed",
        )
    if start is not None and moment < start:
        return Validity(
            False,
            "before_validity",
            f"the package was signed at {moment.isoformat()}, before key {record.key_id} became valid at {record.not_before}",
        )
    if end is not None and moment > end:
        state = "retired_outside_validity" if record.status == RETIRED else "outside_validity"
        return Validity(
            False,
            state,
            f"the package was signed at {moment.isoformat()}, after key {record.key_id} stopped being valid at {record.not_after}",
        )
    if record.status == RETIRED:
        return Validity(
            True,
            "retired_within_validity",
            f"key {record.key_id} is retired, and the package was signed inside the window it was valid for",
        )
    return Validity(True, "active", f"key {record.key_id} is active")


@dataclass
class Keyring:
    keys: list[KeyRecord] = field(default_factory=list)
    version: int = KEYRING_VERSION

    # -- lookup ------------------------------------------------------------
    def active(self) -> KeyRecord | None:
        for record in self.keys:
            if record.status == ACTIVE:
                return record
        return None

    def find(self, key_id: str) -> KeyRecord | None:
        for record in self.keys:
            if record.key_id == key_id:
                return record
        return None

    # -- mutation ----------------------------------------------------------
    def add(self, record: KeyRecord) -> KeyRecord:
        if self.find(record.key_id) is not None:
            raise ValueError(f"key {record.key_id} is already in the keyring")
        self.keys.append(record)
        return record

    def retire(self, key_id: str, when: str | None = None) -> KeyRecord:
        record = self._require(key_id)
        if record.status == REVOKED:
            raise ValueError(f"key {key_id} is revoked; retiring it would weaken that")
        stamp = when or now_iso()
        record.status = RETIRED
        record.retired_at = stamp
        record.not_after = stamp
        return record

    def revoke(self, key_id: str, when: str | None = None) -> KeyRecord:
        record = self._require(key_id)
        stamp = when or now_iso()
        record.status = REVOKED
        record.revoked_at = stamp
        if record.not_after is None:
            record.not_after = stamp
        return record

    def _require(self, key_id: str) -> KeyRecord:
        record = self.find(key_id)
        if record is None:
            raise ValueError(f"no key {key_id} in this keyring")
        return record

    # -- serialisation -----------------------------------------------------
    def to_dict(self, include_private: bool = False) -> dict[str, Any]:
        return {
            "version": self.version,
            "keys": [record.to_dict(include_private=include_private) for record in self.keys],
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Keyring:
        rows = raw.get("keys", [])
        return cls(
            keys=[KeyRecord.from_dict(row) for row in rows if isinstance(row, dict)],
            version=int(raw.get("version", KEYRING_VERSION)),
        )

    @classmethod
    def load(cls, path: Path) -> Keyring:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def save(self, path: Path) -> Path:
        """Write the keyring, private key paths included.

        Mode 0600: the file holds no secret, but it does hold the paths of
        every private key on this machine, and the list of what to steal is
        worth as little publicity as the keys themselves.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        blob = json.dumps(self.to_dict(include_private=True), indent=2, sort_keys=True) + "\n"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(blob)
        return path


def keyring_path_for(key_path: Path) -> Path:
    return Path(key_path).parent / KEYRING_FILENAME


# ---------------------------------------------------------------------------
# The local keyring: the one beside the private key on this machine
# ---------------------------------------------------------------------------

@dataclass
class LocalKeyring:
    keypair: KeyPair
    keyring: Keyring
    path: Path
    created_key: bool = False


def load_local(key_path: Path) -> LocalKeyring:
    """The signing key and the keyring that sits beside it, creating both.

    A key that predates the keyring (anything made before 1.0.0) is adopted
    with no `not_before`, and says so in its note. Stamping it with today's
    date would be an invented fact, and inventing the one field a verifier
    uses to date a signature is exactly the wrong place to guess.
    """
    key_path = Path(key_path)
    keypair, created = load_or_create(key_path)
    path = keyring_path_for(key_path)
    keyring = Keyring.load(path) if path.exists() else Keyring()

    record = keyring.find(keypair.key_id)
    if record is None:
        if created:
            record = KeyRecord.from_keypair(keypair)
        else:
            record = KeyRecord(
                key_id=keypair.key_id,
                public_key_b64=keypair.public_b64,
                fingerprint_sha256=keypair.fingerprint,
                not_before=None,
                created=None,
                note=f"adopted into the keyring on {now_iso()}; this key predates the keyring, so no start of validity is claimed",
            )
        record.private_key_path = str(key_path)
        keyring.add(record)
        keyring.save(path)
    elif record.private_key_path != str(key_path):
        record.private_key_path = str(key_path)
        keyring.save(path)
    return LocalKeyring(keypair=keypair, keyring=keyring, path=path, created_key=created)


@dataclass
class Rotation:
    retired: KeyRecord | None
    fresh: KeyRecord
    archived_key_path: Path | None
    keyring: Keyring
    keyring_path: Path
    keypair: KeyPair


def rotate(key_path: Path, when: str | None = None) -> Rotation:
    """Retire the current key and put a new one in its place.

    The old private key is moved next to the new one as
    `signing-key-<key_id>.pem` rather than deleted. Deleting it would make
    the retirement irreversible in the wrong way: re-signing an old package
    to correct a mistake becomes impossible, while the risk that made you
    rotate is unchanged, because whoever had a copy still has it.
    """
    key_path = Path(key_path)
    stamp = when or now_iso()
    local = load_local(key_path)
    keyring = local.keyring

    retired_record: KeyRecord | None = None
    archived: Path | None = None
    if key_path.exists():
        retired_record = keyring.find(local.keypair.key_id)
        if retired_record is not None and retired_record.status == ACTIVE:
            keyring.retire(retired_record.key_id, stamp)
        archived = key_path.with_name(f"{key_path.stem}-{local.keypair.key_id}{key_path.suffix}")
        if not archived.exists():
            key_path.replace(archived)
            os.chmod(archived, 0o600)
        else:
            key_path.unlink()
        if retired_record is not None:
            retired_record.private_key_path = str(archived)

    fresh_pair, created = load_or_create(key_path)
    if not created:  # pragma: no cover - the path was just cleared above
        raise RuntimeError(f"{key_path} still exists; refusing to overwrite a private key")
    fresh_record = KeyRecord.from_keypair(fresh_pair, not_before=stamp)
    fresh_record.private_key_path = str(key_path)
    keyring.add(fresh_record)
    keyring.save(local.path)
    return Rotation(
        retired=retired_record,
        fresh=fresh_record,
        archived_key_path=archived,
        keyring=keyring,
        keyring_path=local.path,
        keypair=fresh_pair,
    )


def revoke(key_path: Path, key_id: str, when: str | None = None) -> KeyRecord:
    """Mark a key revoked in the local keyring.

    Nothing here distributes that fact. A verifier learns about it by being
    given this keyring with `--trusted-keyring`, or by reading a package
    signed after the revocation, and the docstring at the top of this module
    says why only the first of those two is binding.
    """
    local = load_local(key_path)
    record = local.keyring.revoke(key_id, when)
    local.keyring.save(local.path)
    return record


def single_key_ring(keypair: KeyPair) -> Keyring:
    """The keyring a package gets when the signer has no keyring at all.

    Kept so that `write_package` can still be called with nothing but a key
    pair, which is what the older tests and any embedding code do.
    """
    return Keyring(keys=[KeyRecord.from_keypair(keypair)])


__all__ = [
    "ACTIVE",
    "KEYRING_FILENAME",
    "KEYRING_VERSION",
    "RETIRED",
    "REVOKED",
    "STATUSES",
    "KeyRecord",
    "Keyring",
    "LocalKeyring",
    "Rotation",
    "Validity",
    "evaluate",
    "keyring_path_for",
    "load_local",
    "now_iso",
    "parse_moment",
    "revoke",
    "rotate",
    "single_key_ring",
]
