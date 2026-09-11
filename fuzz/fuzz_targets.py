#!/usr/bin/env python3
"""Fuzz targets for every hand-written parser in Actaira.

The property under test is the one the product promises, stated in four
parts. For any byte sequence at all, `inspect_artifact` must:

  (a) terminate,
  (b) never raise an uncaught exception,
  (c) never consume memory without bound,
  (d) never return `Verdict.PASS` for an artifact it could not fully read.

Each part is an oracle here, not a comment:

  (a) a per-case SIGALRM plus a parent-side watchdog for the C-level loops a
      Python signal cannot interrupt (big-integer arithmetic, mostly),
  (b) any exception escaping a target,
  (c) `RLIMIT_AS` in the worker process, so an allocation the parser should
      never have attempted surfaces as `MemoryError` instead of as a machine
      that swaps; plus an RSS high-water check for allocations that succeed,
  (d) the report's coverage claim is measured against the artifact on disk:
      the size it reports against the size of the file, and, for an archive,
      every member name against a second independent listing of the zip. A
      report claiming `fully_read` while some of the file is accounted for
      nowhere is caught by what is in the file, not by what the report
      concluded. `PASS` is separately cross-checked against
      `metadata["fully_read"]`, `inspector_errors` and `UNREAD_RULE_IDS`,
      which catches a report that contradicts itself - that half used to be
      the whole oracle, and it was circular: it re-derived `PASS` from the
      same boolean `PASS` came from.

A fifth check rides along with (b): the report must survive
`canonical_json(report.to_dict())`. That is not an extra requirement invented
for the fuzzer, it is the only thing the CLI, the ML-BOM and the attestation
ever do with a report, so a report that cannot be serialised is an uncaught
exception in `actaira scan --json` one function call later.

Two engines
-----------
`--engine atheris` uses libFuzzer through Atheris when it is installed: real
coverage-guided mutation, with `-timeout` and `-rss_limit_mb` enforcing (a)
and (c) natively.

`--engine builtin` (the default when Atheris is missing, and what `make fuzz`
runs so CI needs no extra dependency) is a small coverage-guided mutation
fuzzer written here: valid seeds generated from `evals/corpus/build.py`,
deterministic mutation from a fixed seed, and a `sys.settrace` line-coverage
signal that decides which inputs are worth keeping as parents.

Reproducibility
---------------
`--seed` and `--iters` fully determine a builtin run: same command, same
sequence of inputs, same corpus, same findings. Individual failures are also
saved as raw bytes under the run's `crashes/` directory and can be replayed
on their own with `replay`, which is what the regression tests use.

Usage
-----
    python3 fuzz/fuzz_targets.py list
    python3 fuzz/fuzz_targets.py run --target all --seed 1 --iters 50000
    python3 fuzz/fuzz_targets.py replay --target npy --input fuzz/corpus/x.bin
    python3 fuzz/fuzz_targets.py reduce --target npy --input crash.bin
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import pickle
import random
import signal
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

FUZZ_DIR = Path(__file__).resolve().parent
REPO_ROOT = FUZZ_DIR.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from actaira.formats import archive, detect, gguf, keras_h5, npy, onnx, safetensors  # noqa: E402
from actaira.formats.pickle_scan import scan_pickle_bytes  # noqa: E402
from actaira.inspect import UNREAD_RULE_IDS, inspect_artifact  # noqa: E402
from actaira.model import Verdict, canonical_json  # noqa: E402

# ---------------------------------------------------------------------------
# What this platform can and cannot enforce
# ---------------------------------------------------------------------------

# `resource` and `SIGALRM` are POSIX. They used to be imported unconditionally
# at module scope, which meant this file could not even be imported on Windows
# - and `tests/test_fuzz_regressions.py` imports it, so the whole suite failed
# to collect there: 41 tests silently absent and a release gate comparing the
# figure in docs against a smaller number it could not explain.
#
# The fix is not to pretend the oracles still hold. Two of the four promises
# are enforced by these two facilities, and a fuzzer that loses them and says
# nothing is a fuzzer reporting "no findings" from a weaker instrument than the
# one the figure was measured with. So the capability is detected once, here,
# the run degrades explicitly, and every summary carries the list of oracles
# this platform could not enforce - into `summary.json`, into the printed
# banner, and into anything that reads either.
try:  # pragma: no cover - the branch taken depends on the platform
    import resource
except ImportError:  # pragma: no cover - Windows
    resource = None  # type: ignore[assignment]

HAVE_RLIMIT = resource is not None and hasattr(resource, "RLIMIT_AS")
HAVE_RUSAGE = resource is not None and hasattr(resource, "getrusage")
HAVE_ALARM = hasattr(signal, "SIGALRM") and hasattr(signal, "setitimer")


def unenforced_oracles() -> list[str]:
    """The promises this platform cannot hold the parser to, named one by one.

    Empty on POSIX. A non-empty list does not make a run useless - oracles (b)
    and (d) are pure Python and still hold, and the parent-side watchdog still
    catches a worker that stops making progress - but it does make the run a
    weaker measurement, and the difference belongs in the output rather than in
    a reader's assumptions.
    """
    missing: list[str] = []
    if not HAVE_RLIMIT:
        missing.append(
            "(c) bounded memory: RLIMIT_AS is POSIX-only, so an unbounded allocation "
            "surfaces as this machine swapping rather than as MemoryError"
        )
    if not HAVE_RUSAGE:
        missing.append(
            "(c) peak RSS: getrusage is POSIX-only, so an allocation that succeeds is "
            "not measured"
        )
    if not HAVE_ALARM:
        missing.append(
            "(a) per-case termination: SIGALRM is POSIX-only, so a hang is caught by "
            "the parent watchdog after the whole worker stalls, not per case"
        )
    return missing


# ---------------------------------------------------------------------------
# The oracle
# ---------------------------------------------------------------------------

# `UNREAD_RULE_IDS` is imported from `actaira.inspect`, not copied.
#
# It used to be copied, and the copy drifted: it was missing ACT-PKL-013, the
# concatenated-stream budget, which is the rule DEF-33 was fixed to emit. A
# fuzzer holding a subset of the production list cannot detect a PASS next to
# a rule it has never heard of, and a divergence in the direction that hides
# failures is the only direction that matters. One list, in the module that
# decides the verdict; this file asks that module what it thinks.

class CaseTimeout(BaseException):
    """Raised by SIGALRM inside a case.

    Derived from `BaseException` on purpose: every inspector in this project
    has a deliberate `except Exception` at its boundary, and a timeout that
    those handlers could swallow would be reported as a finding instead of as
    the hang it is.
    """


class PropertyViolationError(Exception):
    """One input broke one of the four promises."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind = kind
        self.detail = detail


def _check_coverage_claim(report: Any, path: Path) -> None:
    """Oracle (d), measured against the file rather than against the verdict.

    The old form of this oracle was circular. It asked "if the verdict is
    PASS, is `fully_read` True?" - and `fully_read` is the boolean
    `decide_verdict` derived PASS from in the first place, so the answer was
    yes by construction. It could only ever catch a branch that set one and
    not the other, and that branch does not exist: `inspect_artifact` derives
    both from the same variable, three lines apart.

    What follows measures the claim instead. `fully_read: True` is a statement
    about the artifact on disk, so it is checked against the artifact on disk:
    the size the report gives, and - for an archive, where "how much was read"
    is a countable thing - every member name, listed here by a second,
    independent open. A report that claims to have read an archive end to end
    while never accounting for six of its members is caught whatever verdict
    it carries, and it is caught because of what is in the zip, not because of
    what the report concluded.
    """
    real_size = path.stat().st_size
    if report.size_bytes != real_size:
        raise PropertyViolationError(
            "coverage",
            f"the report describes {report.size_bytes} bytes and the file is {real_size}",
        )
    if report.metadata.get("fully_read") is not True:
        return

    if report.detected_format not in ("zip", "pytorch-zip"):
        return
    try:
        with zipfile.ZipFile(path) as handle:
            present = [info.filename for info in handle.infolist()]
    except Exception:
        raise PropertyViolationError(
            "coverage", "claimed fully_read for an archive that will not open"
        ) from None
    accounted = set(report.metadata.get("pickle_members") or [])
    accounted |= set(report.metadata.get("members_not_inspected") or [])
    missing = sorted(set(present) - accounted)
    if missing:
        raise PropertyViolationError(
            "coverage",
            f"claimed fully_read while {len(missing)} member(s) are accounted for nowhere "
            f"in the report: {missing[:5]}",
        )


def _check_report(report: Any, path: Path) -> None:
    """Oracles (b, tail) and (d) on a finished `ArtifactReport`."""
    try:
        payload = report.to_dict()
        canonical_json(payload)
    except Exception as exc:
        raise PropertyViolationError(
            "unserialisable", f"canonical_json(report.to_dict()) raised {type(exc).__name__}: {exc}"
        ) from exc

    for entry in report.inspector_errors:
        if entry.startswith("MemoryError"):
            raise PropertyViolationError("memory", f"inspector attempted an unbounded allocation: {entry}")

    _check_coverage_claim(report, path)

    if report.verdict is not Verdict.PASS:
        return

    # These three remain, and they are consistency checks on the report rather
    # than the coverage oracle: a report that contradicts itself is worth
    # catching cheaply, but `_check_coverage_claim` above is the one that can
    # fail without the report first admitting something.
    if report.inspector_errors:
        raise PropertyViolationError("unsound-pass", f"PASS with inspector_errors={report.inspector_errors}")
    if report.metadata.get("fully_read") is not True:
        raise PropertyViolationError("unsound-pass", "PASS with metadata['fully_read'] not True")
    unread = sorted({f.rule_id for f in report.findings} & UNREAD_RULE_IDS)
    if unread:
        raise PropertyViolationError("unsound-pass", f"PASS while reporting {unread}, which mean the file was not read")


def _check_parts(findings: Iterable[Any], tensors: Iterable[Any], metadata: Any) -> None:
    """Oracle (b, tail) for a bare inspector that returns parts, not a report.

    Every part ends up inside the report, so each must be serialisable on its
    own; catching it here says which inspector produced the value.
    """
    from dataclasses import asdict

    payload = {
        "findings": [f.to_dict() for f in findings],
        "tensors": [asdict(t) for t in tensors],
        "metadata": metadata,
    }
    try:
        canonical_json(payload)
    except Exception as exc:
        raise PropertyViolationError(
            "unserialisable", f"inspector output is not canonical-JSON serialisable: {type(exc).__name__}: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


def _target_inspect(path: Path, data: bytes) -> None:
    _check_report(inspect_artifact(path), path)


def _target_detect(path: Path, data: bytes) -> None:
    detected, confidence = detect.sniff(path)
    if not isinstance(detected, str) or not isinstance(confidence, str):
        raise PropertyViolationError("crash", f"sniff returned {detected!r}, {confidence!r}")
    detect.extension_mismatch(path, detected)


def _target_pickle(path: Path, data: bytes) -> None:
    result = scan_pickle_bytes(data, "fuzz")
    _check_parts(result.findings, [], {"protocol": result.protocol, "opcodes": result.opcode_count})


def _target_onnx(path: Path, data: bytes) -> None:
    _check_parts(*onnx.inspect(path))


def _target_gguf(path: Path, data: bytes) -> None:
    _check_parts(*gguf.inspect(path))


def _target_safetensors(path: Path, data: bytes) -> None:
    _check_parts(*safetensors.inspect(path))


def _target_npy(path: Path, data: bytes) -> None:
    findings, tensors, metadata, _imported = npy.inspect(path)
    _check_parts(findings, tensors, metadata)


def _target_keras_h5(path: Path, data: bytes) -> None:
    findings, metadata, _read = keras_h5.inspect(path)
    _check_parts(findings, [], metadata)


def _target_archive(path: Path, data: bytes) -> None:
    findings, metadata, _imported = archive.inspect(path)
    _check_parts(findings, [], metadata)


TARGETS: dict[str, Callable[[Path, bytes], None]] = {
    "inspect": _target_inspect,
    "detect": _target_detect,
    "pickle": _target_pickle,
    "onnx": _target_onnx,
    "gguf": _target_gguf,
    "safetensors": _target_safetensors,
    "npy": _target_npy,
    "keras_h5": _target_keras_h5,
    "archive": _target_archive,
}


# ---------------------------------------------------------------------------
# Seed corpus, generated from the eval corpus builder
# ---------------------------------------------------------------------------


def _load_corpus_builder() -> Any:
    """Load `evals/corpus/build.py` by path, the way `tests/conftest.py` does."""
    path = REPO_ROOT / "evals" / "corpus" / "build.py"
    spec = importlib.util.spec_from_file_location("actaira_fuzz_corpus_build", path)
    if spec is None or spec.loader is None:  # pragma: no cover - environment error
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _zip_bytes(entries: list[tuple[str, bytes]], compression: int = zipfile.ZIP_STORED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as handle:
        for name, payload in entries:
            handle.writestr(name, payload)
    return buffer.getvalue()


def seed_corpus() -> dict[str, list[bytes]]:
    """Valid (and deliberately near-valid) starting points, per format family.

    Mutation only finds what it can reach, so the seeds have to already be
    the shapes the parsers accept: every branch a mutator can flip into
    existence starts from one of these.
    """
    build = _load_corpus_builder()
    seeds: dict[str, list[bytes]] = {}

    state_dict = {"w": [1.0, 2.0], "cfg": {"hidden": 8, "labels": ["a", "b"]}}
    seeds["pickle"] = [
        *(pickle.dumps(state_dict, protocol=p) for p in range(0, 6)),
        build.craft_reduce("posix", "system", ("id",), 2),
        build.craft_reduce("pydoc", "pipepager", ("x", "sh -c id"), 4),
        build.craft_extension(),
        build.craft_persid(),
        b"I1\n0cposix\nsystem\n(S'id'\ntR.",
        pickle.dumps({"a": 1}, protocol=2) + pickle.dumps({"b": 2}, protocol=2),
        b".",
        b"\x80\x05.",
    ]

    seeds["onnx"] = [
        build.build_onnx(),
        build.build_onnx(domain="ai.onnx.contrib", op_type="PyOp"),
        build.build_onnx(domain="com.acme.kernels", op_type="AcmeOp"),
        # A ModelProto carrying one initializer, so the TensorProto reader is
        # reachable by mutation instead of only by luck.
        b"\x08\x01"
        + build._field_bytes(  # noqa: SLF001 - the corpus builder is the reference encoder
            7,
            build._field_bytes(5, build._field_varint(2, 1) + build._field_varint(1, 4) + build._field_bytes(8, b"w")),
        ),
    ]

    seeds["gguf"] = [
        build.build_gguf(1),
        build.build_gguf(2),
        build.build_gguf(1, declared_tensor_count=4),
        build.build_gguf(1, version=1),
        # A key/value block holding one of every scalar type plus an array,
        # which is the part of the reader mutation should be aiming at.
        b"GGUF"
        + struct.pack("<I", 3)
        + struct.pack("<Q", 0)
        + struct.pack("<Q", 3)
        + struct.pack("<Q", 1) + b"a" + struct.pack("<I", 6) + struct.pack("<f", 1.5)
        + struct.pack("<Q", 1) + b"b" + struct.pack("<I", 12) + struct.pack("<d", 2.5)
        + struct.pack("<Q", 1) + b"c" + struct.pack("<I", 9) + struct.pack("<I", 4) + struct.pack("<Q", 3)
        + struct.pack("<I", 1) + struct.pack("<I", 2) + struct.pack("<I", 3),
    ]

    seeds["safetensors"] = [
        build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]},
             "b": {"dtype": "F32", "shape": [4], "data_offsets": [64, 80]}},
            b"\x00" * 80,
        ),
        build.build_safetensors({"w": {"dtype": "F32", "shape": [4], "data_offsets": [0, 99999]}}, b"\x00" * 16),
        build.build_safetensors(
            {"__metadata__": {"format": "pt"}, "a": {"dtype": "BOOL", "shape": [3], "data_offsets": [0, 1]}},
            b"\x00" * 8,
        ),
        build.build_safetensors({}, b""),
    ]

    npy_seeds: list[bytes] = []
    # numpy is a dev extra, so its writer is used when it is there and the
    # hand-built headers below cover the format when it is not.
    numpy = importlib.util.find_spec("numpy")
    if numpy is not None:
        import numpy as np

        for array, allow in ((np.zeros((4, 4), dtype=np.float32), False),
                             (np.array([{"a": 1}], dtype=object), True)):
            buffer = io.BytesIO()
            np.save(buffer, array, allow_pickle=allow)
            npy_seeds.append(buffer.getvalue())
    header = b"{'descr': '<f4', 'fortran_order': False, 'shape': (2, 2), }"
    padded = header + b" " * ((64 - (10 + len(header)) % 64) % 64) + b"\n"
    npy_seeds.append(b"\x93NUMPY\x01\x00" + struct.pack("<H", len(padded)) + padded + b"\x00" * 16)
    npy_seeds.append(b"\x93NUMPY\x02\x00" + struct.pack("<I", len(padded)) + padded + b"\x00" * 16)
    seeds["npy"] = npy_seeds

    seeds["keras_h5"] = [
        build.build_keras_h5(["Dense", "Dropout"]),
        build.build_keras_h5(["Dense", "Lambda"]),
        build.build_keras_h5(["AcmeCustomLayer"]),
        b"\x89HDF\r\n\x1a\n" + b"\x00" * 16,
    ]

    good_pickle = pickle.dumps(state_dict, protocol=2)
    seeds["archive"] = [
        _zip_bytes([("archive/data.pkl", good_pickle), ("archive/data/0", b"\x00" * 64),
                    ("archive/version", b"3\n")]),
        _zip_bytes([("archive/data.pkl", build.craft_reduce("posix", "system", ("id",), 2))]),
        _zip_bytes([("../../../tmp/escape.txt", b"x"), ("archive/data.pkl", good_pickle)]),
        _zip_bytes([("pad.bin", b"\x00" * 400_000), ("archive/data.pkl", good_pickle)], zipfile.ZIP_DEFLATED),
        _zip_bytes([("model.bin", good_pickle), ("weights.pt", b"\x00" * 32)]),
        _zip_bytes([(f"shard{index}.pkl", good_pickle) for index in range(6)]),
        b"PK\x05\x06" + b"\x00" * 18,
    ]

    return seeds


def seeds_for(target: str) -> list[bytes]:
    """Seeds a given target should start from, deduplicated, order stable."""
    pools = seed_corpus()
    if target in pools:
        chosen = list(pools[target])
    else:
        chosen = [payload for _family, payloads in sorted(pools.items()) for payload in payloads]
    # A handful of degenerate inputs every target should survive.
    chosen.extend([b"", b"\x00", b"\xff" * 16, b"{}", b"PK\x03\x04", b"\x89HDF\r\n\x1a\n"])
    seen: set[bytes] = set()
    unique: list[bytes] = []
    for payload in chosen:
        if payload not in seen:
            seen.add(payload)
            unique.append(payload)
    return unique


# ---------------------------------------------------------------------------
# Mutation
# ---------------------------------------------------------------------------

# Values a hand-written binary parser is most likely to mishandle when it
# reads a length or a count: zero, one past a signed boundary, and every
# all-ones width. Substituting these into length fields is the single most
# productive mutator against this codebase, which is full of `read(n)` where
# `n` came off the wire.
_EXTREME_INTS: tuple[int, ...] = (
    0, 1, 2, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF,
    0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
)
_INTERESTING_BYTES = bytes([0x00, 0x01, 0x08, 0x0A, 0x20, 0x2E, 0x5B, 0x7B, 0x80, 0xFF])
_MAGICS: tuple[bytes, ...] = (
    b"\x93NUMPY", b"GGUF", b"PK\x03\x04", b"\x89HDF\r\n\x1a\n", b"\x80\x04", b"\x08",
)

MAX_INPUT_BYTES = 65_536


def _mutate(data: bytes, rng: random.Random, corpus: list[bytes]) -> bytes:
    """One deterministic mutation. `rng` is the only source of randomness."""
    buffer = bytearray(data)
    operator = rng.randrange(13)

    if not buffer and operator not in (5, 11, 12):
        operator = 5

    if operator == 0:  # bit flips
        for _ in range(rng.randint(1, 8)):
            index = rng.randrange(len(buffer))
            buffer[index] ^= 1 << rng.randrange(8)
    elif operator == 1:  # random byte overwrite
        for _ in range(rng.randint(1, 6)):
            buffer[rng.randrange(len(buffer))] = rng.randrange(256)
    elif operator == 2:  # interesting byte overwrite
        for _ in range(rng.randint(1, 6)):
            buffer[rng.randrange(len(buffer))] = rng.choice(_INTERESTING_BYTES)
    elif operator == 3:  # truncate
        buffer = buffer[: rng.randrange(len(buffer))]
    elif operator == 4:  # extend
        filler = rng.choice([b"\x00", b"\xff", b".", bytes([rng.randrange(256)])])
        buffer.extend(filler * rng.randint(1, 64))
    elif operator == 5:  # insert a run of bytes
        index = rng.randrange(len(buffer) + 1)
        blob = bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
        buffer[index:index] = blob
    elif operator == 6:  # delete a chunk
        index = rng.randrange(len(buffer))
        buffer[index : index + rng.randint(1, 32)] = b""
    elif operator == 7:  # extreme value into a length/count field
        width = rng.choice((1, 2, 4, 8))
        order: Any = rng.choice(("little", "big"))
        if len(buffer) >= width:
            index = rng.randrange(len(buffer) - width + 1)
            value = rng.choice(_EXTREME_INTS) & ((1 << (8 * width)) - 1)
            buffer[index : index + width] = value.to_bytes(width, order)
    elif operator == 8:  # duplicate a chunk in place
        index = rng.randrange(len(buffer))
        chunk = bytes(buffer[index : index + rng.randint(1, 64)])
        times = rng.randint(2, 8)
        buffer[index:index] = chunk * times
    elif operator == 9:  # repeat the whole input: finds superlinear scanners
        buffer = bytearray(bytes(buffer) * rng.randint(2, 6))
    elif operator == 10:  # splice with another corpus entry
        other = corpus[rng.randrange(len(corpus))]
        if other:
            cut_a = rng.randrange(len(buffer) + 1)
            cut_b = rng.randrange(len(other) + 1)
            buffer = bytearray(bytes(buffer[:cut_a]) + other[cut_b:])
    elif operator == 11:  # prepend a magic so detection routes somewhere new
        buffer[0:0] = rng.choice(_MAGICS)
    else:  # 12: overwrite the head with a magic, keeping the tail
        magic = rng.choice(_MAGICS)
        buffer[0 : len(magic)] = magic

    if len(buffer) > MAX_INPUT_BYTES:
        buffer = buffer[:MAX_INPUT_BYTES]
    return bytes(buffer)


# ---------------------------------------------------------------------------
# Coverage feedback
# ---------------------------------------------------------------------------


class _Coverage:
    """Line coverage over `src/actaira` only, via `sys.settrace`.

    Deliberately coarse: the point is a signal for "this input reached
    somewhere new", not a report. Frames outside the package get `None` back
    from the call hook, so they are never traced line by line and the cost
    stays near the parsers themselves.
    """

    __slots__ = ("seen", "current", "prefix", "enabled")

    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.seen: set[tuple[str, int]] = set()
        self.current: set[tuple[str, int]] = set()
        self.enabled = True

    def _line(self, frame: Any, event: str, arg: Any) -> Any:
        if event == "line":
            self.current.add((frame.f_code.co_filename, frame.f_lineno))
        return self._line

    def _call(self, frame: Any, event: str, arg: Any) -> Any:
        if frame.f_code.co_filename.startswith(self.prefix):
            self.current.add((frame.f_code.co_filename, frame.f_lineno))
            return self._line
        return None

    def start(self) -> None:
        self.current = set()
        sys.settrace(self._call)

    def stop(self) -> bool:
        """Stop tracing; True when this case reached a line never seen before."""
        sys.settrace(None)
        fresh = not self.current <= self.seen
        self.seen |= self.current
        return fresh


# ---------------------------------------------------------------------------
# Executing one case
# ---------------------------------------------------------------------------


@dataclass
class CaseResult:
    kind: str | None = None
    detail: str = ""
    seconds: float = 0.0
    new_coverage: bool = False


def run_case(
    target: str,
    data: bytes,
    scratch: Path,
    timeout: float,
    coverage: _Coverage | None = None,
) -> CaseResult:
    """Execute one input against one target and apply the oracle."""
    function = TARGETS[target]
    scratch.write_bytes(data)
    result = CaseResult()

    # The per-case alarm, where the platform has one. Where it does not, the
    # case still runs and the parent-side watchdog is what notices a stall;
    # `unenforced_oracles()` is what says so out loud.
    previous = signal.getsignal(signal.SIGALRM) if HAVE_ALARM else None

    def _fire(_signum: int, _frame: Any) -> None:
        raise CaseTimeout(f"exceeded {timeout}s")

    if HAVE_ALARM:
        signal.signal(signal.SIGALRM, _fire)
        signal.setitimer(signal.ITIMER_REAL, timeout)
    started = time.perf_counter()
    if coverage is not None:
        coverage.start()
    try:
        function(scratch, data)
    except CaseTimeout as exc:
        result.kind, result.detail = "hang", str(exc)
    except PropertyViolationError as exc:
        result.kind, result.detail = exc.kind, exc.detail
    except MemoryError as exc:
        result.kind, result.detail = "memory", f"MemoryError: {exc}"
    except RecursionError as exc:
        result.kind, result.detail = "crash", f"RecursionError: {exc}"
    except Exception as exc:
        result.kind, result.detail = "crash", f"{type(exc).__name__}: {exc}"
    finally:
        if coverage is not None:
            result.new_coverage = coverage.stop()
        if HAVE_ALARM:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        result.seconds = time.perf_counter() - started
    return result


# ---------------------------------------------------------------------------
# Reduction
# ---------------------------------------------------------------------------


def reduce_case(
    target: str,
    data: bytes,
    kind: str,
    scratch: Path,
    timeout: float,
    budget: int = 2000,
    deadline_seconds: float = 25.0,
    heartbeat: Callable[[int], None] | None = None,
) -> bytes:
    """Delta-debug an input down while it keeps failing the same way.

    A regression test is only worth reading if the input in it is small
    enough to explain itself, so this runs before anything is written to
    `fuzz/corpus/`.

    Reduction is capped in both attempts and wall clock: a hang reproducer
    costs one full timeout per attempt, and spending ten minutes shrinking a
    24-byte input is not a good trade against finding the next bug. The
    `heartbeat` callback exists so the parent watchdog can tell a long
    reduction apart from a wedged worker.
    """
    best = data
    attempts = 0
    started = time.monotonic()

    def exhausted() -> bool:
        return attempts >= budget or time.monotonic() - started > deadline_seconds

    def still_fails(candidate: bytes) -> bool:
        nonlocal attempts
        attempts += 1
        if heartbeat is not None:
            heartbeat(attempts)
        return run_case(target, candidate, scratch, timeout).kind == kind

    chunk = max(1, len(best) // 2)
    while chunk >= 1 and not exhausted():
        index = 0
        shrunk = False
        while index < len(best) and not exhausted():
            candidate = best[:index] + best[index + chunk :]
            if candidate != best and still_fails(candidate):
                best = candidate
                shrunk = True
            else:
                index += chunk
        if not shrunk:
            if chunk == 1:
                break
            chunk //= 2
    # Final pass: flatten remaining bytes towards zero, which usually turns a
    # random-looking blob into something a reader can see the shape of.
    for index in range(len(best)):
        if exhausted():
            break
        if best[index] == 0:
            continue
        candidate = best[:index] + b"\x00" + best[index + 1 :]
        if still_fails(candidate):
            best = candidate
    return best


def failure_class(kind: str, detail: str) -> str:
    """Collapse one failure to its class, so each bug is reduced once.

    Digits are erased because the same bug reports a different offset, index
    or byte count on every input it is found with, and reducing the same bug
    two hundred times is how a fuzzing run spends its whole budget on the
    first thing it finds.
    """
    head = detail.split(":")[0]
    normalised = "".join("#" if character.isdigit() else character for character in head)
    return f"{kind}|{normalised[:80]}"


# ---------------------------------------------------------------------------
# The builtin engine (worker side)
# ---------------------------------------------------------------------------


@dataclass
class RunConfig:
    target: str
    seed: int
    iters: int
    timeout: float
    memory_mb: int
    out_dir: Path
    quiet: bool = False
    skip_hashes: set[str] = field(default_factory=set)
    start_index: int = 0


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _peak_rss_kib() -> int:
    """Peak resident set of this process in KiB, or 0 where it cannot be read.

    Returning 0 on a platform without `getrusage` keeps the high-water check
    arithmetic valid (0 - 0 never exceeds the threshold) instead of guessing a
    number. The guess is the dangerous option: an invented baseline would turn
    the memory oracle into one that reports nothing and looks like one that
    reported nothing found. What this platform cannot measure is named in
    `unenforced_oracles()` instead.
    """
    if not HAVE_RUSAGE:
        return 0
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


def _worker(config: RunConfig) -> int:
    """Run cases `start_index .. iters` in this process, under RLIMIT_AS.

    Every case is written to `state/current.bin` before it runs so that the
    parent can name the input that killed the worker, which is the only way
    to catch a hang inside a C-level loop no Python signal can interrupt.
    """
    if HAVE_RLIMIT:
        limit = config.memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    sys.setrecursionlimit(3000)

    state_dir = config.out_dir / "state"
    crash_dir = config.out_dir / "crashes"
    state_dir.mkdir(parents=True, exist_ok=True)
    crash_dir.mkdir(parents=True, exist_ok=True)
    current_bin = state_dir / "current.bin"
    current_json = state_dir / "current.json"
    findings_path = config.out_dir / "findings.jsonl"

    scratch_dir = Path(tempfile.mkdtemp(prefix="actaira-fuzz-"))
    scratch = scratch_dir / f"case_{config.target}.bin"

    corpus = seeds_for(config.target)
    # Anything already saved as interesting from an earlier chunk of this run.
    saved = sorted((config.out_dir / "queue").glob("*.bin")) if (config.out_dir / "queue").exists() else []
    corpus.extend(path.read_bytes() for path in saved)
    (config.out_dir / "queue").mkdir(parents=True, exist_ok=True)

    coverage = _Coverage(str(SRC_DIR))
    # Prime coverage on the seeds so "new coverage" means new relative to the
    # valid inputs, not relative to nothing.
    for payload in list(corpus):
        run_case(config.target, payload, scratch, config.timeout, coverage)

    baseline_rss = _peak_rss_kib()
    # Failure classes already reduced and reported, persisted so that a worker
    # restarted past a hard failure does not spend its budget re-reducing what
    # the previous worker already wrote down.
    classes_path = state_dir / "classes.json"
    seen_reports: set[str] = set(json.loads(classes_path.read_text())) if classes_path.exists() else set()
    executed = 0
    started = time.perf_counter()

    for index in range(config.start_index, config.iters):
        rng = random.Random(config.seed * 1_000_003 + index)  # noqa: S311 - fuzzing, not crypto
        parent = corpus[rng.randrange(len(corpus))]
        data = _mutate(parent, rng, corpus)
        if _digest(data) in config.skip_hashes:
            continue

        def _progress(phase: str, index: int = index, sha: str = _digest(data), step: int = 0) -> None:
            current_json.write_text(
                json.dumps({"index": index, "sha": sha, "target": config.target, "phase": phase, "step": step})
            )

        current_bin.write_bytes(data)
        _progress("execute")

        result = run_case(config.target, data, scratch, config.timeout, coverage)
        executed += 1

        rss = _peak_rss_kib()
        if result.kind is None and rss - baseline_rss > 256 * 1024:
            result.kind = "memory"
            result.detail = f"peak RSS grew by {(rss - baseline_rss) // 1024} MiB on one case"
        baseline_rss = max(baseline_rss, rss)

        if result.kind is not None:
            key = failure_class(result.kind, result.detail)
            if key not in seen_reports:
                seen_reports.add(key)
                classes_path.write_text(json.dumps(sorted(seen_reports)))
                minimal = reduce_case(
                    config.target,
                    data,
                    result.kind,
                    scratch,
                    config.timeout,
                    heartbeat=lambda step: _progress("reduce", step=step),
                )
                name = f"{config.target}-{result.kind}-{_digest(minimal)}.bin"
                (crash_dir / name).write_bytes(minimal)
                record = {
                    "target": config.target,
                    "kind": result.kind,
                    "detail": result.detail,
                    "index": index,
                    "input_sha256": hashlib.sha256(minimal).hexdigest(),
                    "input_bytes": len(minimal),
                    "input_hex": minimal[:512].hex(),
                    "file": str(crash_dir / name),
                }
                with findings_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, sort_keys=True) + "\n")
                if not config.quiet:
                    print(f"  ! {result.kind:<14} {result.detail[:96]}  -> {name}", flush=True)
        elif result.new_coverage and len(data) <= 4096:
            (config.out_dir / "queue" / f"{_digest(data)}.bin").write_bytes(data)
            corpus.append(data)

    elapsed = time.perf_counter() - started
    summary = {
        "target": config.target,
        "executed": executed,
        "seconds": round(elapsed, 2),
        "corpus": len(corpus),
    }
    (config.out_dir / "state" / "worker.json").write_text(json.dumps(summary))
    if not config.quiet:
        rate = executed / elapsed if elapsed else 0.0
        print(f"  {config.target}: {executed} cases in {elapsed:.1f}s ({rate:.0f}/s), corpus {len(corpus)}", flush=True)
    return 0


# ---------------------------------------------------------------------------
# The builtin engine (parent side, with the watchdog)
# ---------------------------------------------------------------------------


def run_builtin(config: RunConfig) -> dict[str, Any]:
    """Drive one worker per target, restarting it past any input that kills it.

    A worker that dies takes its own report with it, so the parent reads
    `state/current.bin`, records that input as a hard failure, and restarts
    the worker at the next index with that input's hash on the skip list.
    """
    config.out_dir.mkdir(parents=True, exist_ok=True)
    (config.out_dir / "state").mkdir(parents=True, exist_ok=True)
    findings_path = config.out_dir / "findings.jsonl"
    # A run is defined by its seed and its iteration count, so it starts from
    # nothing: leftover state from a previous run would make the same command
    # produce a different corpus.
    for stale in (findings_path, config.out_dir / "state" / "classes.json"):
        if stale.exists():
            stale.unlink()
    for stale_file in (config.out_dir / "queue").glob("*.bin"):
        stale_file.unlink()

    skip: set[str] = set()
    start = 0
    hard_failures: list[dict[str, Any]] = []
    watchdog = max(config.timeout * 4, 30.0)
    # What the workers actually ran, as opposed to what was asked for. The
    # worker has always written this to `state/worker.json` and nobody read
    # it, so the summary published `config.iters` - the number on the command
    # line - as though it were the number of cases executed. A run that died
    # after 12 cases reported the full figure with zero findings, and
    # `scripts/figures.py` put that number in the README.
    worker_state = config.out_dir / "state" / "worker.json"
    worker_state.unlink(missing_ok=True)
    executed = 0

    while start < config.iters:
        command = [
            sys.executable, str(Path(__file__).resolve()), "_exec",
            "--target", config.target,
            "--seed", str(config.seed),
            "--iters", str(config.iters),
            "--start-index", str(start),
            "--timeout", str(config.timeout),
            "--memory-mb", str(config.memory_mb),
            "--out", str(config.out_dir),
        ]
        if skip:
            command += ["--skip", ",".join(sorted(skip))]
        process = subprocess.Popen(command, stdout=None, stderr=None)  # noqa: S603 - fixed argv, no shell
        last_state = ""
        last_change = time.monotonic()
        current_json = config.out_dir / "state" / "current.json"
        while process.poll() is None:
            time.sleep(0.25)
            try:
                state = current_json.read_text()
            except OSError:
                state = last_state
            if state != last_state:
                last_state, last_change = state, time.monotonic()
            elif time.monotonic() - last_change > watchdog:
                process.kill()
                process.wait()
                break

        executed += _executed_by_worker(worker_state)

        if process.returncode == 0:
            break

        # The worker is gone. Whatever it was holding is the culprit.
        try:
            state = json.loads((config.out_dir / "state" / "current.json").read_text())
            payload = (config.out_dir / "state" / "current.bin").read_bytes()
        except Exception as exc:
            # The worker died and took its own state with it. This used to be
            # a bare `break`, which left the run looking complete: the summary
            # published the full iteration count, zero findings, and exit 0.
            # A fuzzer that cannot say what killed it has still been killed,
            # and that is a hard failure, recorded where the exit code can see
            # it.
            record = {
                "target": config.target,
                "kind": "worker-lost",
                "detail": (
                    f"worker exited with returncode={process.returncode} and its state could "
                    f"not be read ({type(exc).__name__}: {exc}); the run is incomplete"
                ),
                "index": start,
                "input_sha256": "",
                "input_bytes": 0,
                "input_hex": "",
                "file": "",
            }
            with findings_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
            hard_failures.append(record)
            print(f"  !! worker died at case {start} and left no state; run is incomplete", flush=True)
            break
        kind = "hang" if process.returncode is None or process.returncode < 0 else "crash"
        digest = _digest(payload)
        skip.add(digest)
        record = {
            "target": config.target,
            "kind": kind,
            "detail": f"worker died (returncode={process.returncode}) on case {state['index']}",
            "index": state["index"],
            "input_sha256": hashlib.sha256(payload).hexdigest(),
            "input_bytes": len(payload),
            "input_hex": payload[:512].hex(),
            "file": str(config.out_dir / "crashes" / f"{config.target}-{kind}-{digest}.bin"),
        }
        (config.out_dir / "crashes").mkdir(parents=True, exist_ok=True)
        Path(record["file"]).write_bytes(payload)
        with findings_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        hard_failures.append(record)
        print(f"  !! worker died on case {state['index']} ({kind}); restarting past it", flush=True)
        start = int(state["index"]) + 1

    findings = _read_findings(findings_path)
    return {
        "target": config.target,
        # `iters` is the budget the caller asked for; `executed` is what ran.
        # Both are published because they are different numbers and every
        # consumer wants the second one.
        "iters": config.iters,
        "executed": executed,
        "seed": config.seed,
        "findings": findings,
        "hard_failures": hard_failures,
        # Empty on POSIX. Non-empty means this run held the parser to fewer
        # than four promises, and every consumer of this summary is entitled
        # to know which before reading "0 violations" as a result.
        "unenforced_oracles": unenforced_oracles(),
    }


def _executed_by_worker(worker_state: Path) -> int:
    """The case count one worker wrote before it exited, then forgotten.

    Read and removed after every worker, so a restarted worker's count adds to
    the total instead of replacing it, and a worker that died without writing
    the file contributes nothing rather than the previous worker's figure.
    """
    try:
        count = int(json.loads(worker_state.read_text()).get("executed", 0))
    except Exception:
        return 0
    finally:
        worker_state.unlink(missing_ok=True)
    return max(count, 0)


def _read_findings(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


# ---------------------------------------------------------------------------
# The Atheris engine
# ---------------------------------------------------------------------------


def run_atheris(config: RunConfig) -> int:
    """Coverage-guided fuzzing through libFuzzer, when Atheris is installed.

    `instrument_all` rewrites the bytecode of everything already imported so
    libFuzzer gets real edge coverage out of the parsers. It is slow to start
    (a few seconds) and it has to happen before `Setup`.
    """
    import atheris

    atheris.instrument_all()

    scratch_dir = Path(tempfile.mkdtemp(prefix="actaira-atheris-"))
    scratch = scratch_dir / f"case_{config.target}.bin"
    corpus_dir = config.out_dir / "atheris-corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)
    for payload in seeds_for(config.target):
        (corpus_dir / f"{_digest(payload)}.bin").write_bytes(payload)

    function = TARGETS[config.target]

    def one_input(data: bytes) -> None:
        scratch.write_bytes(data)
        function(scratch, data)

    argv = [
        sys.argv[0],
        f"-runs={config.iters}",
        f"-seed={config.seed}",
        f"-timeout={int(config.timeout)}",
        f"-rss_limit_mb={config.memory_mb}",
        f"-max_len={MAX_INPUT_BYTES}",
        f"-artifact_prefix={config.out_dir}/",
        str(corpus_dir),
    ]
    atheris.Setup(argv, one_input)
    atheris.Fuzz()
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cmd_run(args: argparse.Namespace) -> int:
    targets = sorted(TARGETS) if args.target == "all" else [args.target]
    out_root = Path(args.out).resolve()
    summaries = []
    total_violations = 0
    started = time.perf_counter()

    missing = unenforced_oracles()
    if missing:
        print(
            "  !! this platform cannot enforce every oracle; the run is a weaker "
            "measurement than the figure in docs/FIGURES.md:",
            flush=True,
        )
        for line in missing:
            print(f"     - {line}", flush=True)

    for target in targets:
        config = RunConfig(
            target=target,
            seed=args.seed,
            iters=args.iters,
            timeout=args.timeout,
            memory_mb=args.memory_mb,
            out_dir=out_root / target,
        )
        print(f"[{target}] engine={args.engine} seed={args.seed} iters={args.iters}", flush=True)
        if args.engine == "atheris":
            # libFuzzer owns the loop and reports its own failures, writing
            # any crashing input under --out. There is nothing to summarise
            # here that it has not already printed.
            run_atheris(config)
            continue
        summary = run_builtin(config)
        total_violations += len(summary["findings"])
        summaries.append(summary)

    elapsed = time.perf_counter() - started
    executed = sum(summary["executed"] for summary in summaries)
    report = {
        "seed": args.seed,
        "iters_per_target": args.iters,
        "cases_executed": executed,
        "targets": summaries,
        "unique_violations": total_violations,
        "seconds": round(elapsed, 1),
        "unenforced_oracles": missing,
    }
    (out_root / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True))
    print(f"\n{len(targets)} target(s), {args.iters} cases each requested, {executed} executed, "
          f"{elapsed:.1f}s, {total_violations} property violation(s)")
    if missing:
        print(f"  !! {len(missing)} oracle(s) unenforced on this platform; see summary.json")
    for summary in summaries:
        for finding in summary["findings"]:
            print(f"  {summary['target']:<12} {finding['kind']:<14} {finding['detail'][:100]}")
    return 1 if total_violations else 0


def _cmd_exec(args: argparse.Namespace) -> int:
    config = RunConfig(
        target=args.target,
        seed=args.seed,
        iters=args.iters,
        timeout=args.timeout,
        memory_mb=args.memory_mb,
        out_dir=Path(args.out),
        start_index=args.start_index,
        skip_hashes=set(args.skip.split(",")) if args.skip else set(),
    )
    return _worker(config)


def _cmd_replay(args: argparse.Namespace) -> int:
    data = Path(args.input).read_bytes()
    scratch_dir = Path(tempfile.mkdtemp(prefix="actaira-replay-"))
    result = run_case(args.target, data, scratch_dir / "case.bin", args.timeout)
    if result.kind is None:
        print(f"{args.input}: no violation ({result.seconds * 1000:.1f} ms)")
        return 0
    print(f"{args.input}: {result.kind}: {result.detail}")
    return 1


def _cmd_reduce(args: argparse.Namespace) -> int:
    data = Path(args.input).read_bytes()
    scratch_dir = Path(tempfile.mkdtemp(prefix="actaira-reduce-"))
    scratch = scratch_dir / "case.bin"
    first = run_case(args.target, data, scratch, args.timeout)
    if first.kind is None:
        print("input does not fail; nothing to reduce")
        return 1
    minimal = reduce_case(args.target, data, first.kind, scratch, args.timeout)
    destination = Path(args.output) if args.output else Path(args.input).with_suffix(".min.bin")
    destination.write_bytes(minimal)
    print(f"{len(data)} -> {len(minimal)} bytes, kind={first.kind}, written to {destination}")
    print(f"  hex: {minimal[:256].hex()}")
    return 0


def _cmd_list(_args: argparse.Namespace) -> int:
    pools = seed_corpus()
    for name in sorted(TARGETS):
        count = len(seeds_for(name))
        print(f"{name:<14} seeds={count:<4} family_seeds={len(pools.get(name, []))}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(target_parser: argparse.ArgumentParser) -> None:
        target_parser.add_argument("--target", default="all", choices=[*sorted(TARGETS), "all"])
        target_parser.add_argument("--seed", type=int, default=1)
        target_parser.add_argument("--iters", type=int, default=50_000)
        target_parser.add_argument("--timeout", type=float, default=10.0)
        target_parser.add_argument("--memory-mb", type=int, default=1024)
        target_parser.add_argument("--out", default=str(FUZZ_DIR / "runs" / "latest"))

    run_parser = sub.add_parser("run", help="fuzz one or every target")
    add_common(run_parser)
    run_parser.add_argument("--engine", default="builtin", choices=("builtin", "atheris"))
    run_parser.set_defaults(func=_cmd_run)

    exec_parser = sub.add_parser("_exec", help=argparse.SUPPRESS)
    add_common(exec_parser)
    exec_parser.add_argument("--start-index", type=int, default=0)
    exec_parser.add_argument("--skip", default="")
    exec_parser.set_defaults(func=_cmd_exec)

    replay_parser = sub.add_parser("replay", help="run one saved input against one target")
    replay_parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    replay_parser.add_argument("--input", required=True)
    replay_parser.add_argument("--timeout", type=float, default=10.0)
    replay_parser.set_defaults(func=_cmd_replay)

    reduce_parser = sub.add_parser("reduce", help="shrink a failing input while it keeps failing")
    reduce_parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    reduce_parser.add_argument("--input", required=True)
    reduce_parser.add_argument("--output", default=None)
    reduce_parser.add_argument("--timeout", type=float, default=10.0)
    reduce_parser.set_defaults(func=_cmd_reduce)

    list_parser = sub.add_parser("list", help="list targets and seed counts")
    list_parser.set_defaults(func=_cmd_list)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
