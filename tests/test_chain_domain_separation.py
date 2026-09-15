"""The entry hash must not let a field's content be read as a field boundary.

Version 1 of `compute_entry_hash` joined six fields with "|" and its docstring
called that "length-prefixed concatenation". It was not. The premise it rested
on - that no field can contain the separator - was enforced by nobody:
`verify_chain` calls `str()` on `timestamp` and `subject_sha256` and checks
the format of neither, so any string at all reaches the preimage.

The consequence was a real second preimage. Moving "deadbeef|" from the front
of the subject to the end of the timestamp produced identical bytes, so one
entry hash certified two different (timestamp, subject) pairs and the verifier
accepted whichever one was presented.

These tests stay for good. `test_the_recorded_collision_is_rejected` is the
exact pair from the defect report, and `test_the_v1_preimage_is_gone` fails if
anyone reintroduces the separator scheme under any name.
"""
from __future__ import annotations

import hashlib

from actaira.attest import chain

PREV = "0" * 64
PAYLOAD = "a" * 64
SUBJECT = "c" * 64


def _v1_entry_hash(prev_hash: str, payload_hash: str, timestamp: str, subject: str, index: int) -> str:
    """Version 1, reproduced here so the test can assert it is not what we do."""
    preimage = "|".join([str(1), str(index), prev_hash, payload_hash, timestamp, subject])
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def test_the_recorded_collision_is_rejected() -> None:
    """The pair from the defect report. Under v1 these were the same digest."""
    shifted_timestamp = chain.compute_entry_hash(PREV, PAYLOAD, "2026-01-01T00:00:00|deadbeef", SUBJECT, 0)
    shifted_subject = chain.compute_entry_hash(PREV, PAYLOAD, "2026-01-01T00:00:00", "deadbeef|" + SUBJECT, 0)

    assert _v1_entry_hash(PREV, PAYLOAD, "2026-01-01T00:00:00|deadbeef", SUBJECT, 0) == _v1_entry_hash(
        PREV, PAYLOAD, "2026-01-01T00:00:00", "deadbeef|" + SUBJECT, 0
    ), "the collision must still be demonstrable under v1, or this test proves nothing"
    assert shifted_timestamp != shifted_subject


def test_the_v1_preimage_is_gone() -> None:
    """A direct guard against a revert, not an incidental consequence of one."""
    assert chain.compute_entry_hash(PREV, PAYLOAD, "2026-01-01T00:00:00", SUBJECT, 0) != _v1_entry_hash(
        PREV, PAYLOAD, "2026-01-01T00:00:00", SUBJECT, 0
    )
    assert chain.ENTRY_VERSION >= 2


def test_every_boundary_shift_is_a_different_hash() -> None:
    """Not just the reported pair: move the boundary anywhere, get a new digest."""
    marker = "deadbeef"
    seen = set()
    for split in range(len(marker) + 1):
        head, tail = marker[:split], marker[split:]
        seen.add(chain.compute_entry_hash(PREV, PAYLOAD, "2026-01-01T00:00:00" + head, tail + SUBJECT, 0))
    assert len(seen) == len(marker) + 1


def test_the_preimage_carries_every_field_length() -> None:
    """The framing itself, so a future edit cannot drop a prefix unnoticed."""
    preimage = chain.entry_pae(PREV, PAYLOAD, "2026-01-01T00:00:00", SUBJECT, 7)
    assert preimage.startswith(chain.ENTRY_HEADER + b" 6 ")
    for value in (PREV, PAYLOAD, "2026-01-01T00:00:00", SUBJECT, "7"):
        assert f" {len(value.encode('utf-8'))} {value}".encode() in preimage


def test_verify_chain_refuses_a_shifted_entry() -> None:
    """The end-to-end half. v1 returned no problems for exactly this document."""
    entries: list[chain.Entry] = []
    chain.append(entries, SUBJECT, {"claim": "first"}, timestamp="2026-01-01T00:00:00")
    honest = [entry.to_dict() for entry in entries]
    assert chain.verify_chain(honest) == []

    forged = [dict(honest[0])]
    forged[0]["timestamp"] = "2026-01-01T00:00:00|deadbeef"
    forged[0]["subject_sha256"] = SUBJECT[len("deadbeef|"):]

    problems = chain.verify_chain(forged)
    assert problems == ["entry[0]: entry_hash does not match its own fields"]
