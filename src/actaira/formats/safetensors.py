"""safetensors inspector.

The format is a u64 little-endian header length, a JSON header, then a raw
tensor buffer. It cannot execute code, which is the whole point of the
format, so inspection here is about structural integrity rather than
gadgets: a header that lies about where tensors live is how a reader gets
walked out of bounds, and it is also how two files with the same declared
shapes can hold different weights.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..model import Finding, Severity, TensorInfo
from .shape import ShapeOutOfRangeError, element_count

# Bound on header size. The largest legitimate header measured in the corpus
# is under 1 MiB; 64 MiB leaves three orders of magnitude of headroom while
# still refusing a header that claims to be the whole disk.
MAX_HEADER_BYTES = 64 * 1024 * 1024

_DTYPE_BITS: dict[str, int] = {
    "BOOL": 1, "U8": 8, "I8": 8, "F8_E5M2": 8, "F8_E4M3": 8,
    "I16": 16, "U16": 16, "F16": 16, "BF16": 16,
    "I32": 32, "U32": 32, "F32": 32,
    "I64": 64, "U64": 64, "F64": 64,
}


def inspect(path: Path) -> tuple[list[Finding], list[TensorInfo], dict[str, Any]]:
    findings: list[Finding] = []
    tensors: list[TensorInfo] = []
    metadata: dict[str, Any] = {}
    file_size = path.stat().st_size

    with path.open("rb") as handle:
        raw_len = handle.read(8)
        if len(raw_len) < 8:
            findings.append(_malformed(path, "header_length_truncated"))
            return findings, tensors, metadata
        header_len = int.from_bytes(raw_len, "little")

        if header_len == 0 or header_len > MAX_HEADER_BYTES:
            findings.append(
                Finding(
                    rule_id="ACT-STF-001",
                    severity=Severity.HIGH,
                    location=path.name,
                    evidence={"declared_header_bytes": header_len, "limit": MAX_HEADER_BYTES},
                )
            )
            return findings, tensors, metadata
        if 8 + header_len > file_size:
            findings.append(
                Finding(
                    rule_id="ACT-STF-002",
                    severity=Severity.HIGH,
                    location=path.name,
                    evidence={"declared_header_bytes": header_len, "file_bytes": file_size},
                )
            )
            return findings, tensors, metadata

        try:
            header = json.loads(handle.read(header_len).decode("utf-8"))
        except Exception as exc:
            findings.append(_malformed(path, f"{type(exc).__name__}: {exc}"))
            return findings, tensors, metadata

    if not isinstance(header, dict):
        findings.append(_malformed(path, "header_not_object"))
        return findings, tensors, metadata

    metadata["__metadata__"] = header.get("__metadata__", {})
    data_region = file_size - 8 - header_len
    spans: list[tuple[int, int, str]] = []

    for name, spec in header.items():
        if name == "__metadata__":
            continue
        if not isinstance(spec, dict):
            findings.append(_malformed(path, f"entry_not_object:{name}"))
            continue
        dtype = str(spec.get("dtype", "?"))
        shape = spec.get("shape", [])
        offsets = spec.get("data_offsets", [])
        if not isinstance(shape, list) or not all(isinstance(d, int) and d >= 0 for d in shape):
            findings.append(_malformed(path, f"bad_shape:{name}"))
            continue
        if not (isinstance(offsets, list) and len(offsets) == 2 and all(isinstance(o, int) for o in offsets)):
            findings.append(_malformed(path, f"bad_offsets:{name}"))
            continue

        start, end = offsets
        # JSON integers have no width, so `shape` could ask for a product of
        # any size at all. A five-kilobyte header holding a few hundred
        # twenty-digit dimensions built an integer too wide for CPython to
        # render as a string (4300 digits, `sys.set_int_max_str_digits`), so
        # `json.dumps` on the finished report raised ValueError and every
        # consumer of that report - `--json`, the ML-BOM, the attestation -
        # died on a file this inspector had already "read". `element_count`
        # holds each dimension to the 64 bits the format stores it in.
        try:
            n_elements = element_count(shape)
        except ShapeOutOfRangeError as exc:
            findings.append(_malformed(path, f"bad_shape:{name}:{exc}"))
            continue
        tensors.append(TensorInfo(name=name, dtype=dtype, shape=shape, n_elements=n_elements))

        if start < 0 or end < start or end > data_region:
            findings.append(
                Finding(
                    rule_id="ACT-STF-003",
                    severity=Severity.CRITICAL,
                    location=f"{path.name}#{name}",
                    evidence={"data_offsets": [start, end], "data_region_bytes": data_region},
                )
            )
            continue

        bits = _DTYPE_BITS.get(dtype)
        if bits is None:
            findings.append(
                Finding(
                    rule_id="ACT-STF-005",
                    severity=Severity.MEDIUM,
                    location=f"{path.name}#{name}",
                    evidence={"dtype": dtype},
                )
            )
        else:
            expected = (n_elements * bits + 7) // 8
            if expected != end - start:
                findings.append(
                    Finding(
                        rule_id="ACT-STF-004",
                        severity=Severity.HIGH,
                        location=f"{path.name}#{name}",
                        evidence={
                            "declared_bytes": end - start,
                            "expected_bytes": expected,
                            "dtype": dtype,
                            "shape": shape,
                        },
                    )
                )
        spans.append((start, end, name))

    _check_overlap(path, spans, findings)
    metadata["tensor_count"] = len(tensors)
    metadata["total_parameters"] = sum(t.n_elements for t in tensors)
    return findings, tensors, metadata


def _check_overlap(path: Path, spans: list[tuple[int, int, str]], findings: list[Finding]) -> None:
    """Two tensors sharing bytes means the header is not a faithful map."""
    for (a_start, a_end, a_name), (b_start, b_end, b_name) in _pairs(sorted(spans)):
        if a_end > b_start:
            findings.append(
                Finding(
                    rule_id="ACT-STF-006",
                    severity=Severity.HIGH,
                    location=path.name,
                    evidence={"tensors": [a_name, b_name], "a": [a_start, a_end], "b": [b_start, b_end]},
                )
            )


def _pairs(items: list[tuple[int, int, str]]):
    for index in range(len(items) - 1):
        yield items[index], items[index + 1]


def _malformed(path: Path, reason: str) -> Finding:
    return Finding(
        rule_id="ACT-STF-007",
        severity=Severity.MEDIUM,
        location=path.name,
        evidence={"reason": reason},
    )
