"""ONNX inspector: a minimal protobuf reader, no onnx dependency.

Design note D-08. The `onnx` package would parse this in three lines, but it
brings protobuf and a large native surface, and this project's claim is that
you can inspect an artifact without installing the ecosystem that loads it.
So the wire format is decoded directly: field number, wire type, payload.
Only the fields that matter for provenance and risk are decoded, and
anything unrecognised is skipped by length, which is what makes the reader
robust against fields it has never seen.

Risk model for ONNX: the graph itself is data, but operators outside the
standard domains resolve to custom native or Python kernels at session
creation, so a non-standard opset domain is the thing to surface.
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..model import Finding, Severity, TensorInfo
from .shape import MAX_RANK, ShapeOutOfRangeError, element_count

# Domains that ship with a standard ONNX Runtime install.
STANDARD_DOMAINS = {"", "ai.onnx", "ai.onnx.ml", "ai.onnx.training", "ai.onnx.preview.training"}
# Domains documented to execute user-supplied Python at inference time.
PYTHON_EXECUTING_DOMAINS = {"ai.onnx.contrib", "com.microsoft.pyop", "pyop"}

MAX_BYTES = 512 * 1024 * 1024
MAX_NODES = 200_000


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated varint")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 70:
            raise ValueError("varint too long")


def _iter_fields(data: bytes, start: int = 0, end: int | None = None) -> Iterator[tuple[int, int, Any]]:
    """Yield (field_number, wire_type, payload) for one protobuf message."""
    pos = start
    limit = len(data) if end is None else end
    while pos < limit:
        key, pos = _read_varint(data, pos)
        field_number, wire_type = key >> 3, key & 0x07
        if wire_type == 0:
            value, pos = _read_varint(data, pos)
            yield field_number, wire_type, value
        elif wire_type == 1:
            fixed64, pos = data[pos : pos + 8], pos + 8
            yield field_number, wire_type, fixed64
        elif wire_type == 2:
            length, pos = _read_varint(data, pos)
            if pos + length > limit:
                raise ValueError("length-delimited field exceeds message")
            yield field_number, wire_type, data[pos : pos + length]
            pos += length
        elif wire_type == 5:
            fixed32, pos = data[pos : pos + 4], pos + 4
            yield field_number, wire_type, fixed32
        else:
            raise ValueError(f"unsupported wire type {wire_type}")


def inspect(path: Path) -> tuple[list[Finding], list[TensorInfo], dict[str, Any]]:
    findings: list[Finding] = []
    tensors: list[TensorInfo] = []
    metadata: dict[str, Any] = {}

    size = path.stat().st_size
    if size > MAX_BYTES:
        findings.append(
            Finding(
                rule_id="ACT-ONX-004",
                severity=Severity.MEDIUM,
                location=path.name,
                evidence={"size_bytes": size, "limit": MAX_BYTES},
            )
        )
        return findings, tensors, metadata

    data = path.read_bytes()
    domains: set[str] = set()
    op_types: dict[str, int] = {}
    graph_payload: bytes | None = None

    try:
        for field_number, wire, payload in _iter_fields(data):
            if field_number == 1:
                metadata["ir_version"] = _varint(payload, wire, "ir_version")
            elif field_number == 2:
                metadata["producer_name"] = _utf8(payload)
            elif field_number == 3:
                metadata["producer_version"] = _utf8(payload)
            elif field_number == 4:
                metadata["domain"] = _utf8(payload)
            elif field_number == 5:
                metadata["model_version"] = _varint(payload, wire, "model_version")
            elif field_number == 7:
                graph_payload = _bytes(payload, "graph")
            elif field_number == 8:  # opset_import
                domains.add(_read_opset_domain(_bytes(payload, "opset_import")))
    except Exception as exc:
        findings.append(
            Finding(
                rule_id="ACT-ONX-003",
                severity=Severity.MEDIUM,
                location=path.name,
                evidence={"error": f"{type(exc).__name__}: {exc}"},
            )
        )
        return findings, tensors, metadata

    if graph_payload is not None:
        try:
            _read_graph(graph_payload, op_types, tensors)
        except Exception as exc:
            findings.append(
                Finding(
                    rule_id="ACT-ONX-003",
                    severity=Severity.MEDIUM,
                    location=f"{path.name}#graph",
                    evidence={"error": f"{type(exc).__name__}: {exc}"},
                )
            )

    metadata["opset_domains"] = sorted(domains)
    metadata["node_count"] = sum(op_types.values())
    metadata["op_types"] = dict(sorted(op_types.items(), key=lambda kv: -kv[1])[:32])
    metadata["initializer_count"] = len(tensors)

    for domain in sorted(domains):
        if domain in PYTHON_EXECUTING_DOMAINS:
            findings.append(
                Finding(
                    rule_id="ACT-ONX-001",
                    severity=Severity.CRITICAL,
                    location=path.name,
                    evidence={"domain": domain, "reason": "domain_executes_user_python"},
                )
            )
        elif domain not in STANDARD_DOMAINS:
            findings.append(
                Finding(
                    rule_id="ACT-ONX-002",
                    severity=Severity.HIGH,
                    location=path.name,
                    evidence={"domain": domain, "reason": "custom_operator_domain"},
                )
            )
    return findings, tensors, metadata


def _read_opset_domain(payload: bytes) -> str:
    for field_number, _wire, value in _iter_fields(payload):
        if field_number == 1:
            return _utf8(value)
    return ""


_ELEM_TYPE = {
    1: "F32", 2: "U8", 3: "I8", 4: "U16", 5: "I16", 6: "I32", 7: "I64",
    9: "BOOL", 10: "F16", 11: "F64", 12: "U32", 13: "U64", 16: "BF16",
}


def _read_graph(payload: bytes, op_types: dict[str, int], tensors: list[TensorInfo]) -> None:
    for field_number, _wire, value in _iter_fields(payload):
        if field_number == 1:  # node
            if sum(op_types.values()) >= MAX_NODES:
                continue
            op_type, domain = _read_node(_bytes(value, "node"))
            key = f"{domain}::{op_type}" if domain else op_type
            op_types[key] = op_types.get(key, 0) + 1
        elif field_number == 5:  # initializer (TensorProto)
            tensors.append(_read_tensor(_bytes(value, "initializer")))


def _read_node(payload: bytes) -> tuple[str, str]:
    op_type = ""
    domain = ""
    for field_number, _wire, value in _iter_fields(payload):
        if field_number == 4:
            op_type = _utf8(value)
        elif field_number == 7:
            domain = _utf8(value)
    return op_type, domain


def _read_tensor(payload: bytes) -> TensorInfo:
    """Decode one TensorProto far enough to describe it.

    `dims` is int64 in the schema and this reader now holds it to that, via
    `shape.element_count`. Before, a packed `dims` field of ten-byte varints
    was multiplied out as-is: 200 KiB of them produced a 1.4-million-bit
    integer in 1.5 seconds, growing with the square of the input, and the
    number could not even be printed into the report afterwards. A shape that
    large is not a tensor, so the whole graph is reported as unreadable
    rather than described with a number nobody can serialise.
    """
    dims: list[int] = []
    name = ""
    elem_type = 0
    for field_number, wire, value in _iter_fields(payload):
        if field_number == 1 and wire == 0:
            dims.append(int(value))
        elif field_number == 1 and wire == 2:
            # packed dims
            pos = 0
            while pos < len(value):
                if len(dims) > MAX_RANK:
                    raise ShapeOutOfRangeError(f"packed dims above the rank limit of {MAX_RANK}")
                dim, pos = _read_varint(value, pos)
                dims.append(dim)
        elif field_number == 2 and wire == 0:
            elem_type = int(value)
        elif field_number == 8:
            name = _utf8(value)
    count = element_count(dims)
    return TensorInfo(name=name or "<unnamed>", dtype=_ELEM_TYPE.get(elem_type, f"type_{elem_type}"), shape=dims, n_elements=count)


def _utf8(payload: Any) -> str:
    """Decode a length-delimited field, refusing anything that is not one.

    Every caller here reads a protobuf `string`, which is wire type 2. A file
    that declares the same field number with wire type 0 hands this function
    an `int`, and the versions of these helpers that did not check put that
    `int` - or, for wire types 1 and 5, a raw `bytes` slice - straight into
    the report. `bytes` is not JSON, so the report could not be serialised and
    `actaira scan --json` died on a five-byte file. Wire-type confusion is
    decided here, once, where the payload arrives.
    """
    return _bytes(payload, "string").decode("utf-8", errors="replace")


def _bytes(payload: Any, field: str) -> bytes:
    if not isinstance(payload, bytes):
        raise ValueError(f"field {field} is not length-delimited")
    return payload


def _varint(payload: Any, wire: int, field: str) -> int:
    if wire != 0 or not isinstance(payload, int):
        raise ValueError(f"field {field} is not a varint")
    return payload
