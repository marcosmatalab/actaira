"""GGUF inspector (llama.cpp family).

GGUF is a self-describing container: magic, version, tensor count, then a
key-value metadata block, then tensor descriptors. It executes nothing, so
inspection is about provenance (architecture, quantisation, declared name)
and about the counts being internally consistent with the file that carries
them, which is what catches a truncated or doctored download.
"""
from __future__ import annotations

import math
import struct
from pathlib import Path
from typing import Any

from ..io_budget import MAX_GGUF_HEADER_BYTES, read_at_most
from ..model import Finding, Severity, TensorInfo
from .shape import ShapeOutOfRangeError, element_count

MAGIC = b"GGUF"
MAX_KV = 4096
MAX_TENSORS = 100_000
MAX_STRING = 1 << 20
# Arrays may hold arrays, so the reader recurses. Eight levels is more nesting
# than any real GGUF metadata block uses, and the bound is what stops twelve
# bytes per level of a hostile file from becoming a RecursionError.
MAX_ARRAY_DEPTH = 8

(T_UINT8, T_INT8, T_UINT16, T_INT16, T_UINT32, T_INT32, T_FLOAT32, T_BOOL,
 T_STRING, T_ARRAY, T_UINT64, T_INT64, T_FLOAT64) = range(13)

_SCALAR = {
    T_UINT8: ("<B", 1), T_INT8: ("<b", 1), T_UINT16: ("<H", 2), T_INT16: ("<h", 2),
    T_UINT32: ("<I", 4), T_INT32: ("<i", 4), T_FLOAT32: ("<f", 4), T_BOOL: ("<?", 1),
    T_UINT64: ("<Q", 8), T_INT64: ("<q", 8), T_FLOAT64: ("<d", 8),
}


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        # Set when a read ran off the end of the buffer. The caller uses it to
        # tell "the header did not fit in the budget" from "the file is
        # corrupt": the two raise identically and mean opposite things.
        self.exhausted = False

    def take(self, count: int) -> bytes:
        if self.pos + count > len(self.data):
            self.exhausted = True
            raise ValueError("truncated gguf")
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def string(self) -> str:
        length = self.u64()
        if length > MAX_STRING:
            raise ValueError(f"gguf string too long: {length}")
        return self.take(length).decode("utf-8", errors="replace")

    def value(self, value_type: int, depth: int = 0) -> Any:
        if value_type in _SCALAR:
            fmt, size = _SCALAR[value_type]
            decoded = struct.unpack(fmt, self.take(size))[0]
            # A float32 or float64 key/value is four or eight arbitrary bytes,
            # and roughly one exponent pattern in 256 of them is NaN or an
            # infinity. Those are not JSON: `canonical_json` sets
            # `allow_nan=False` on purpose, so a single flipped byte in a
            # metadata float produced a report that could not be serialised
            # and an `actaira scan --json` that raised ValueError. A file
            # whose metadata cannot be written down is a malformed file, and
            # is reported as one rather than being coerced into a token no
            # verifier would accept.
            if isinstance(decoded, float) and not math.isfinite(decoded):
                raise ValueError(f"non-finite float in gguf metadata: {decoded!r}")
            return decoded
        if value_type == T_STRING:
            return self.string()
        if value_type == T_ARRAY:
            if depth >= MAX_ARRAY_DEPTH:
                raise ValueError(f"gguf array nested deeper than {MAX_ARRAY_DEPTH}")
            item_type = self.u32()
            count = self.u64()
            if count > MAX_KV * 64:
                raise ValueError(f"gguf array too long: {count}")
            return [self.value(item_type, depth + 1) for _ in range(count)]
        raise ValueError(f"unknown gguf value type {value_type}")


def inspect(path: Path) -> tuple[list[Finding], list[TensorInfo], dict[str, Any]]:
    findings: list[Finding] = []
    tensors: list[TensorInfo] = []
    metadata: dict[str, Any] = {}

    # D-160. This read the whole file, and a GGUF is the largest artifact this
    # tool meets: a quantised 70B is tens of gigabytes. Everything this module
    # has anything to say about - the magic, the key-value metadata, the
    # tensor descriptors - sits at the head, and the rest is tensor data,
    # which is out of scope by design. Reading a prefix is not a compromise.
    header, truncated = read_at_most(path, MAX_GGUF_HEADER_BYTES)
    reader = _Reader(header)

    try:
        if reader.take(4) != MAGIC:
            findings.append(_malformed(path, "bad_magic"))
            return findings, tensors, metadata
        version = reader.u32()
        tensor_count = reader.u64()
        kv_count = reader.u64()
        metadata["gguf_version"] = version
        metadata["declared_tensor_count"] = tensor_count

        if version not in (1, 2, 3):
            findings.append(
                Finding(
                    rule_id="ACT-GGF-002",
                    severity=Severity.MEDIUM,
                    location=path.name,
                    evidence={"version": version, "known": [1, 2, 3]},
                )
            )
        if kv_count > MAX_KV or tensor_count > MAX_TENSORS:
            findings.append(
                Finding(
                    rule_id="ACT-GGF-003",
                    severity=Severity.HIGH,
                    location=path.name,
                    evidence={"kv_count": kv_count, "tensor_count": tensor_count},
                )
            )
            return findings, tensors, metadata

        kv: dict[str, Any] = {}
        for _ in range(kv_count):
            key = reader.string()
            value_type = reader.u32()
            value = reader.value(value_type)
            if isinstance(value, list) and len(value) > 16:
                value = {"array_length": len(value), "sample": value[:4]}
            kv[key] = value
        metadata["kv"] = kv

        # The tensor loop keeps what it managed to parse instead of aborting.
        # Before this, the loop ran exactly `tensor_count` times or raised, so
        # `len(tensors)` always equalled the declared count and ACT-GGF-004
        # was unreachable: a rule with catalogue entries in two languages that
        # could never fire. Found by reading the code against its own docs.
        truncated_at: int | None = None
        for index in range(tensor_count):
            try:
                name = reader.string()
                n_dims = reader.u32()
                if n_dims > 8:
                    raise ValueError(f"implausible tensor rank {n_dims}")
                shape = [reader.u64() for _ in range(n_dims)]
                ggml_type = reader.u32()
                reader.u64()  # offset
            except Exception:
                truncated_at = index
                break
            try:
                count = element_count(shape)
            except ShapeOutOfRangeError:
                truncated_at = index
                break
            tensors.append(TensorInfo(name=name, dtype=f"ggml_type_{ggml_type}", shape=shape, n_elements=count))

        if truncated_at is not None:
            # Running out of bytes at the budget and running out because the
            # file is corrupt produce the same exception and are not the same
            # statement. Calling the first "malformed" would report a
            # perfectly good 40 GB model as damaged, which is the failure mode
            # that gets a scanner removed from a pipeline.
            findings.append(
                _over_budget(path, truncated_at)
                if truncated and reader.exhausted
                else _malformed(path, f"tensor_descriptor_truncated_at_index_{truncated_at}")
            )

    except Exception as exc:
        if truncated and reader.exhausted:
            findings.append(_over_budget(path, None))
            return findings, tensors, metadata
        findings.append(_malformed(path, f"{type(exc).__name__}: {exc}"))
        return findings, tensors, metadata

    metadata["tensor_count"] = len(tensors)
    metadata["total_parameters"] = sum(t.n_elements for t in tensors)
    if len(tensors) != metadata["declared_tensor_count"]:
        findings.append(
            Finding(
                rule_id="ACT-GGF-004",
                severity=Severity.HIGH,
                location=path.name,
                evidence={"declared": metadata["declared_tensor_count"], "parsed": len(tensors)},
            )
        )
    return findings, tensors, metadata


def _over_budget(path: Path, index: int | None) -> Finding:
    """The header did not fit in the prefix this parser reads.

    ACT-GGF-003 rather than a new rule: it already means "this file's counts
    put it past what the parser will do", and a reader who meets it learns the
    same thing either way - the descriptors were not all read, so the tensor
    list is partial and the artifact is inconclusive.
    """
    evidence: dict[str, Any] = {
        "limit_bytes": MAX_GGUF_HEADER_BYTES,
        "reason": "the tensor descriptors extend past the header budget",
    }
    if index is not None:
        evidence["parsed_descriptors"] = index
    return Finding(rule_id="ACT-GGF-003", severity=Severity.HIGH, location=path.name, evidence=evidence)


def _malformed(path: Path, reason: str) -> Finding:
    return Finding(rule_id="ACT-GGF-001", severity=Severity.MEDIUM, location=path.name, evidence={"reason": reason})
