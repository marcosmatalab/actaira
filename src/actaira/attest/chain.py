"""Hash-linked attestation entries.

Design note D-13. Each entry commits to its predecessor, so removing or
reordering an entry breaks every hash after it. The entry hash covers the
previous hash, the payload hash, the timestamp and the subject digest; the
timestamp is inside the hash on purpose, because an attestation whose time
can be edited without breaking the chain is not evidence of when anything
happened.

What this does NOT prove, stated here rather than left to be discovered:
a hash chain proves internal consistency, not freshness. Whoever holds the
signing key can rebuild the whole chain with different content. Proving that
an entry existed at a point in time needs a third party, and since 1.0.0 one
can be asked: `attest --tsa-url` anchors the manifest per RFC 3161 (D-27).
Without it the report says `time_anchor: none` rather than implying otherwise.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..model import canonical_json

GENESIS = "0" * 64
# 2 is the length-prefixed preimage. Version 1 joined the fields with "|" and
# is not accepted by anything here any more: see `compute_entry_hash`.
ENTRY_VERSION = 2

# Separator-free framing, the same construction `dsse.pae` uses. Every field is
# preceded by its own byte length, so no content a field carries can be read as
# a field boundary. The spaces are decoration, not delimiters.
ENTRY_HEADER = b"actaira chain entry v2"
SP = b" "


@dataclass
class Entry:
    index: int
    timestamp: str
    subject_sha256: str
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str = ""
    payload_hash: str = field(default="")

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": ENTRY_VERSION,
            "index": self.index,
            "timestamp": self.timestamp,
            "subject_sha256": self.subject_sha256,
            "payload": self.payload,
            "payload_hash": self.payload_hash,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


def compute_payload_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def entry_pae(prev_hash: str, payload_hash: str, timestamp: str, subject: str, index: int) -> bytes:
    """The preimage one entry hash is taken over, length-prefixed per field.

    Rejected: joining with "|" and asserting the separator cannot occur,
    which is what version 1 did. Nothing enforced that assertion - `verify_chain`
    calls `str()` on `timestamp` and `subject_sha256` and checks neither - so
    a subject of "deadbeef|" + digest collided with a timestamp of
    "...|deadbeef" and the verifier accepted both. A length prefix removes the
    question instead of answering it. See `tests/test_chain_domain_separation.py`.
    """
    fields = [
        str(ENTRY_VERSION).encode("utf-8"),
        str(index).encode("utf-8"),
        prev_hash.encode("utf-8"),
        payload_hash.encode("utf-8"),
        timestamp.encode("utf-8"),
        subject.encode("utf-8"),
    ]
    parts = [ENTRY_HEADER, str(len(fields)).encode("ascii")]
    for field_bytes in fields:
        parts.append(str(len(field_bytes)).encode("ascii"))
        parts.append(field_bytes)
    return SP.join(parts)


def compute_entry_hash(prev_hash: str, payload_hash: str, timestamp: str, subject: str, index: int) -> str:
    return hashlib.sha256(entry_pae(prev_hash, payload_hash, timestamp, subject, index)).hexdigest()


def append(entries: list[Entry], subject_sha256: str, payload: dict[str, Any], timestamp: str | None = None) -> Entry:
    prev = entries[-1].entry_hash if entries else GENESIS
    index = len(entries)
    stamp = timestamp or datetime.now(UTC).isoformat(timespec="microseconds")
    payload_hash = compute_payload_hash(payload)
    entry = Entry(
        index=index,
        timestamp=stamp,
        subject_sha256=subject_sha256,
        payload=payload,
        prev_hash=prev,
        payload_hash=payload_hash,
        entry_hash=compute_entry_hash(prev, payload_hash, stamp, subject_sha256, index),
    )
    entries.append(entry)
    return entry


def verify_chain(entries: list[dict[str, Any]]) -> list[str]:
    """Return a list of problems. Empty list means the chain is intact."""
    problems: list[str] = []
    expected_prev = GENESIS
    for position, raw in enumerate(entries):
        index = raw.get("index")
        if index != position:
            problems.append(f"entry[{position}]: index is {index}, expected {position}")
        if raw.get("prev_hash") != expected_prev:
            problems.append(f"entry[{position}]: prev_hash does not match previous entry_hash")
        recomputed_payload = compute_payload_hash(raw.get("payload", {}))
        if recomputed_payload != raw.get("payload_hash"):
            problems.append(f"entry[{position}]: payload_hash does not match payload")
        recomputed_entry = compute_entry_hash(
            str(raw.get("prev_hash")),
            str(raw.get("payload_hash")),
            str(raw.get("timestamp")),
            str(raw.get("subject_sha256")),
            int(raw.get("index", position)),
        )
        if recomputed_entry != raw.get("entry_hash"):
            problems.append(f"entry[{position}]: entry_hash does not match its own fields")
        expected_prev = str(raw.get("entry_hash"))
    return problems


def load_entries(raw_entries: list[dict[str, Any]]) -> list[Entry]:
    """Rebuild Entry objects from a package's entries.jsonl.

    Design note D-26. Without this, every `actaira attest` produced a fresh
    chain from genesis, so two runs over overlapping artifacts shared no
    history and a consistency proof between them always failed. That is not a
    verifier bug, it is the append-only property being absent: a log you
    restart is not a log. `attest --continue` resumes the previous chain and
    appends, which is what makes `verify --extends` mean anything.

    The entries are rebuilt, never re-derived: hashes are taken from the file
    as written so that resuming cannot silently rewrite history. `verify_chain`
    is expected to run over the result before it is trusted.
    """
    entries: list[Entry] = []
    for raw in raw_entries:
        entries.append(
            Entry(
                index=int(raw["index"]),
                timestamp=str(raw["timestamp"]),
                subject_sha256=str(raw["subject_sha256"]),
                payload=raw.get("payload", {}),
                prev_hash=str(raw["prev_hash"]),
                entry_hash=str(raw["entry_hash"]),
                payload_hash=str(raw["payload_hash"]),
            )
        )
    return entries
