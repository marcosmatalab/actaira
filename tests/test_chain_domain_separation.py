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

import pytest

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


# ---------------------------------------------------------------------------
# The field that says how to read the other five
# ---------------------------------------------------------------------------


def _honest_entry() -> dict:
    entries: list[chain.Entry] = []
    chain.append(entries, SUBJECT, {"claim": "first"}, timestamp="2026-01-01T00:00:00")
    return entries[0].to_dict()


def test_the_version_a_document_declares_is_inside_its_own_hash() -> None:
    """`entry_pae` encoded this module's constant instead of the entry's field,
    so `version` was the one field the hash did not bind."""
    honest = _honest_entry()

    assert chain.compute_entry_hash(
        honest["prev_hash"], honest["payload_hash"], honest["timestamp"],
        honest["subject_sha256"], honest["index"], version="1",
    ) != honest["entry_hash"]
    assert chain.compute_entry_hash(
        honest["prev_hash"], honest["payload_hash"], honest["timestamp"],
        honest["subject_sha256"], honest["index"], version=str(chain.ENTRY_VERSION),
    ) == honest["entry_hash"]


@pytest.mark.parametrize("declared", [1, 99, "2", None, 2.0, True])
def test_verify_chain_refuses_any_version_it_does_not_read(declared) -> None:
    """Both halves. An entry relabelled in place no longer matches its own
    hash, and one relabelled and rehashed is refused for the label itself:
    a v1 entry read under the v2 rule is bytes read under a rule they were not
    written under, whether or not the arithmetic happens to work out."""
    forged = dict(_honest_entry())
    forged["version"] = declared

    problems = chain.verify_chain([forged])

    assert any("version" in problem for problem in problems), problems
    assert not chain.verify_chain([_honest_entry()])


def test_an_entry_relabelled_and_rehashed_is_still_refused() -> None:
    """The interesting half on its own: the attacker recomputes the hash under
    the version they claim, so only the version check stands between them and
    a chain this verifier reads by the wrong rule."""
    honest = _honest_entry()
    forged = dict(honest)
    forged["version"] = 1
    forged["entry_hash"] = chain.compute_entry_hash(
        honest["prev_hash"], honest["payload_hash"], honest["timestamp"],
        honest["subject_sha256"], honest["index"], version="1",
    )

    problems = chain.verify_chain([forged])

    assert problems == [
        f"entry[0]: version is 1, this verifier reads only {chain.ENTRY_VERSION}"
    ]


def test_an_unreadable_index_is_a_problem_and_not_a_traceback() -> None:
    """`int(raw.get("index", position))` raised on a hostile entry. Every other
    field reaches the preimage through `str()`; this one now does too."""
    forged = dict(_honest_entry())
    forged["index"] = "not-a-number"

    problems = chain.verify_chain([forged])

    assert any("index" in problem for problem in problems)
    assert any("entry_hash" in problem for problem in problems)


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
