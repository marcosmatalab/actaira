"""NumPy .npy inspector.

`.npy` is usually inert, with one exception that matters: an array with
dtype `object` stores its elements as a pickle, so `numpy.load` on such a
file executes code unless `allow_pickle=False`. Detecting that case is the
whole job here.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from ..model import Finding, Severity, TensorInfo
from .pickle_scan import scan_pickle_bytes
from .shape import ShapeOutOfRangeError, element_count

MAGIC = b"\x93NUMPY"


def inspect(path: Path, scan_policy: str = "strict") -> tuple[list[Finding], list[TensorInfo], dict[str, Any], set[str]]:
    findings: list[Finding] = []
    tensors: list[TensorInfo] = []
    metadata: dict[str, Any] = {}
    imported: set[str] = set()
    file_size = path.stat().st_size

    with path.open("rb") as handle:
        if handle.read(6) != MAGIC:
            findings.append(_malformed(path, "bad_magic"))
            return findings, tensors, metadata, imported
        # Six bytes of magic followed by nothing is a real file to hand this
        # tool, and `handle.read(1)[0]` raised IndexError on it. Reading the
        # version as a block and checking the length is the only way a reader
        # of a truncated file reports the truncation instead of crashing.
        version = handle.read(2)
        if len(version) < 2:
            findings.append(_malformed(path, "version_truncated"))
            return findings, tensors, metadata, imported
        major = version[0]
        length_bytes = 2 if major == 1 else 4
        raw = handle.read(length_bytes)
        if len(raw) < length_bytes:
            findings.append(_malformed(path, "header_length_truncated"))
            return findings, tensors, metadata, imported
        header_len = int.from_bytes(raw, "little")
        # `header_len` is four attacker-chosen bytes for version 2 and 3, and
        # `read()` allocates its argument up front, so passing it straight
        # through turned a twelve-byte file into a 4 GiB allocation. The file
        # cannot hold more header than it has bytes left, so a declared
        # length past the end is already the malformed case below - decide it
        # from the size on disk, before allocating anything.
        remaining = max(0, file_size - handle.tell())
        if header_len > remaining:
            findings.append(_malformed(path, "header_truncated"))
            return findings, tensors, metadata, imported
        header_raw = handle.read(header_len)
        if len(header_raw) < header_len:  # pragma: no cover - the size check covers it
            findings.append(_malformed(path, "header_truncated"))
            return findings, tensors, metadata, imported
        body_offset = handle.tell()

        try:
            # literal_eval, never eval: the header is attacker-controlled text.
            header = ast.literal_eval(header_raw.decode("latin1").strip())
        except Exception as exc:
            findings.append(_malformed(path, f"{type(exc).__name__}: {exc}"))
            return findings, tensors, metadata, imported

        # `literal_eval` returns whatever the header said, which is any Python
        # literal at all. A header of `1` gave `header.get` an int, a shape of
        # `5` gave `list()` an int, and a dimension of `'a'` gave `int()` a
        # string: three uncaught exceptions from three one-byte edits.
        if not isinstance(header, dict):
            findings.append(_malformed(path, f"header_not_a_dict:{type(header).__name__}"))
            return findings, tensors, metadata, imported
        raw_shape = header.get("shape", ())
        if not isinstance(raw_shape, (tuple, list)):
            findings.append(_malformed(path, f"shape_not_a_sequence:{type(raw_shape).__name__}"))
            return findings, tensors, metadata, imported

        descr = str(header.get("descr", "?"))
        shape = list(raw_shape)
        metadata["descr"] = descr
        metadata["fortran_order"] = bool(header.get("fortran_order", False))
        try:
            n_elements = element_count(shape)
        except ShapeOutOfRangeError as exc:
            findings.append(_malformed(path, f"bad_shape:{exc}"))
            return findings, tensors, metadata, imported
        tensors.append(TensorInfo(name="array", dtype=descr, shape=shape, n_elements=n_elements))

        if "O" in descr:
            findings.append(
                Finding(
                    rule_id="ACT-NPY-001",
                    severity=Severity.CRITICAL,
                    location=path.name,
                    evidence={"descr": descr, "reason": "object_dtype_stores_a_pickle"},
                )
            )
            handle.seek(body_offset)
            payload = handle.read()
            if payload:
                result = scan_pickle_bytes(payload, f"{path.name}#body", scan_policy)
                findings.extend(result.findings)
                imported |= result.imported_callables

    return findings, tensors, metadata, imported


def _malformed(path: Path, reason: str) -> Finding:
    return Finding(rule_id="ACT-NPY-002", severity=Severity.MEDIUM, location=path.name, evidence={"reason": reason})
