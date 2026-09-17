"""Attestation inputs built by the suite, not by the tool under test.

Phase A removed the model scanner's report shape. `ArtifactReport` described a
statically inspected file - format, tensors, imported callables, coverage per
surface - and nothing in this tree inspects a file, so it went, and this module
went with its old contents.

What the tests that used it were ever about is unchanged. `chain.append` takes a
digest and a payload mapping; `write_package` takes entries. Neither has ever
cared that the mapping came from an inspection, so the suite supplies one.

The DSSE half is the part worth arguing. `to_envelope` used to build the
envelope these tests verify, and testing `verify_envelope` against the tree's
own writer is the shape D-15 warns about at the top of `attest/verify.py`: a
bug in the writer cancels the same bug in the reader and both tests pass. The
writer here is the specification's shape typed out again, so the two halves
have no code in common. Rejected: importing the archived `to_envelope` from
`archive/model-scanner`, which would restore exactly the shared path.

Nothing here computes a verdict, a severity or a fold over either. A helper
that decided PASS or FAIL would be the decision logic these tests exist to
check, and a helper that folded two severities into a worst one would be the
first negative, reintroduced in the suite that is supposed to forbid it.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from actaira.attest.dsse import PAYLOAD_TYPE, PREDICATE_TYPE, STATEMENT_TYPE, Envelope
from actaira.attest.signing import KeyPair

# Deterministic filler. The attestation layer hashes and packages bytes without
# reading them, so what these bytes mean is exactly nothing, and saying so here
# is cheaper than a test wondering whether the content mattered.
FILLER = b"\x00" * 64


class Record:
    """One thing filed in a chain: a digest, and a mapping describing it.

    A class rather than a tuple because the call sites read `record.sha256` and
    `record.to_dict()`, which is what they read when this was an
    `ArtifactReport`, and the subject of those tests was never the report.
    """

    def __init__(self, path: str | Path, payload: dict[str, Any], sha256: str) -> None:
        self.path = str(path)
        self.sha256 = sha256
        self._payload = payload

    def to_dict(self) -> dict[str, Any]:
        return dict(self._payload)


def record(
    path: str | Path,
    *,
    payload: bytes | None = None,
    sha256: str | None = None,
    note: str = "filed by the test suite",
    **extra: Any,
) -> Record:
    """Describe `path`. Nothing is read from disk unless `payload` is None."""
    target = Path(path)
    if payload is None and sha256 is None and target.exists():
        payload = target.read_bytes()
    body = FILLER if payload is None else payload
    digest = hashlib.sha256(body).hexdigest() if sha256 is None else sha256
    return Record(path, {"name": target.name, "sha256": digest, "note": note, **extra}, digest)


def write_record(path: str | Path, *, payload: bytes | None = None, **kwargs: Any) -> Record:
    """Write the bytes to disk and describe them. What most call sites want."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    body = FILLER if payload is None else payload
    target.write_bytes(body)
    return record(target, payload=body, **kwargs)


def statement(
    records: list[Record],
    *,
    predicate: dict[str, Any] | None = None,
    predicate_type: str = PREDICATE_TYPE,
    statement_type: str = STATEMENT_TYPE,
) -> dict[str, Any]:
    """An in-toto v1 statement over these records, typed out from the spec."""
    return {
        "_type": statement_type,
        "subject": [{"name": Path(item.path).name, "digest": {"sha256": item.sha256}}
                    for item in records],
        "predicateType": predicate_type,
        "predicate": {"note": "written by the test suite"} if predicate is None else predicate,
    }


def envelope(
    records: list[Record],
    keypair: KeyPair | None = None,
    *,
    payload_type: str = PAYLOAD_TYPE,
    **kwargs: Any,
) -> Envelope:
    """A DSSE envelope over an in-toto statement. Unsigned when no keypair.

    An unsigned envelope is a legitimate DSSE object and `verify_envelope`
    refuses it loudly, which is the behaviour these tests pin.
    """
    blob = json.dumps(
        statement(records, **kwargs),
        sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")
    built = Envelope(payload=blob, payload_type=payload_type)
    return built.signed(keypair) if keypair is not None else built


def envelope_bytes(records: list[Record], keypair: KeyPair | None = None, **kwargs: Any) -> bytes:
    return envelope(records, keypair, **kwargs).to_json().encode("utf-8")


def payload_of(built: Envelope) -> dict[str, Any]:
    """The statement inside an envelope, for a test asserting on its shape."""
    return json.loads(base64.b64decode(built.to_dict()["payload"]))


__all__ = [
    "FILLER",
    "Record",
    "envelope",
    "envelope_bytes",
    "payload_of",
    "record",
    "statement",
    "write_record",
]


# ---------------------------------------------------------------------------
# Every document this tree emits
# ---------------------------------------------------------------------------
#
# Phase A turned three `xfail(strict=True)` markers about the first negative
# into properties over emitted documents. A property like "no emitted document
# carries a fold over severities" is only worth as much as this enumeration: if
# it returns nothing, every test built on it passes without looking at anything,
# which is the failure mode the enumeration itself has to be guarded against.
# So callers assert it is non-empty, and `test_no_aggregate.py` additionally
# asserts that it names every emitter the tree has.


def emitted_documents(tmp_path: Path) -> list[tuple[str, dict[str, Any]]]:
    """(name, document) for every document an Actaira command can write today.

    Three: the demo trace `actaira scan --demo` prints, a `watch` trace assembled
    from a recorded session, and the `surface/v1` document `actaira check`
    writes. When a command that emits a fourth arrives, it is added here and
    every property over this list starts covering it with no edit at the call
    sites.

    The `check` document is built over a configuration that DOES fire rules,
    which is the only version of it worth walking: `surface/v1` is the first
    document this tree emits that carries a `severity` at all, so a surface with
    no findings would leave the attribution property asserting nothing. The
    fixture is one of the two reconstructed worms, so the walk runs over a
    document with real findings, real authors and real severities in it.
    """
    from actaira.proxy import Recorder
    from actaira.proxy.session import WatchSession
    from actaira.surface import claude_code, document, resolve, rules
    from actaira.trace.claude_code import demo_trace

    session = WatchSession(tmp_path / "records", "s")
    recorder = Recorder(
        session_id=session.session_id,
        record_path=session.record_dir / "srv.jsonl",
        salt=session.salt,
        run_id=session.run_id,
    )
    recorder.call("read_file", {"path": "x"}, at="2026-01-01T00:00:00.000Z", call_id="1")
    recorder.close()

    worm = Path(__file__).resolve().parents[1] / "fixtures" / "surface" / "mini-shai-hulud"
    surface = resolve.resolve(claude_code.read(worm))
    findings, gaps = rules.evaluate(surface, rules.load())
    assert findings, "the check fixture fires no rule, so the severity walk would be vacuous"

    return [
        ("scan --demo", demo_trace().to_dict()),
        ("watch", session.assemble(child_returncode=0).to_dict()),
        (
            "check",
            document(
                root=str(worm),
                surfaces=(surface,),
                findings=findings,
                gaps=tuple([*surface.unresolved, *gaps]),
                machine=False,
                merge_rules=resolve.MERGE_TABLE,
            ),
        ),
    ]


def every_string(node: Any, trail: str = "") -> list[tuple[str, str]]:
    """(path, text) for every key and every string value anywhere in a document.

    Keys as well as values: a fold published as the KEY `max_severity` is the
    defect these properties are about, and a walk over values alone would miss
    it entirely.
    """
    out: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            out.append((f"{trail}.{key}", str(key)))
            out.extend(every_string(value, f"{trail}.{key}"))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            out.extend(every_string(item, f"{trail}[{index}]"))
    elif isinstance(node, str):
        out.append((trail, node))
    return out
