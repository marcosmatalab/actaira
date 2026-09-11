"""Format detection by content, never by extension.

Design note D-06. An attacker controls the file name, so `.safetensors` is a
claim, not a fact. Every inspector is selected from the bytes on disk. The
detected format and the extension are compared, and a mismatch is itself a
finding (ACT-FMT-002), because renaming a pickle to `.safetensors` to slip
past an extension-based filter is a real technique.
"""
from __future__ import annotations

import pickletools
from pathlib import Path

from ..model import Finding, Severity

MAGIC_HDF5 = b"\x89HDF\r\n\x1a\n"
MAGIC_NPY = b"\x93NUMPY"
MAGIC_GGUF = b"GGUF"
MAGIC_ZIP = b"PK\x03\x04"
MAGIC_ZIP_EMPTY = b"PK\x05\x06"

# Every byte that is a valid pickle opcode, derived from the standard library
# rather than hand-listed.
#
# This used to be a hand-written set of seven "common" first bytes. A hostile
# review defeated it in one line: a protocol 0 stream starting with INT ("I")
# was not recognised as a pickle, so a gadget rode through as an unknown
# format. Any hand-written subset of an opcode table is a guess about what an
# attacker will choose; the table itself is not.
PICKLE_OPCODE_BYTES = frozenset(opcode.code.encode("latin1")[0] for opcode in pickletools.opcodes)
STOP_OPCODE = ord(".")

_EXTENSION_EXPECTATION: dict[str, tuple[str, ...]] = {
    ".safetensors": ("safetensors",),
    ".onnx": ("onnx",),
    ".gguf": ("gguf",),
    ".ggml": ("gguf",),
    ".npy": ("npy",),
    ".npz": ("zip",),
    ".h5": ("hdf5",),
    ".hdf5": ("hdf5",),
    ".keras": ("zip", "hdf5"),
    ".pt": ("pytorch-zip", "pickle", "zip"),
    ".pth": ("pytorch-zip", "pickle", "zip"),
    ".bin": ("pytorch-zip", "pickle", "zip", "unknown"),
    ".ckpt": ("pytorch-zip", "pickle", "zip"),
    ".pkl": ("pickle",),
    ".pickle": ("pickle",),
    ".joblib": ("pickle", "zip"),
    ".model": ("unknown", "pickle", "zip"),
}


def sniff(path: Path) -> tuple[str, str]:
    """Return (format_id, confidence).

    confidence is "magic" when a documented magic number matched,
    "structure" when the format was inferred from a parseable structure, and
    "unknown" when nothing matched.
    """
    with path.open("rb") as handle:
        head = handle.read(64)

    if not head:
        return "empty", "magic"
    if head.startswith(MAGIC_HDF5):
        return "hdf5", "magic"
    if head.startswith(MAGIC_NPY):
        return "npy", "magic"
    if head.startswith(MAGIC_GGUF):
        return "gguf", "magic"
    if head.startswith(MAGIC_ZIP) or head.startswith(MAGIC_ZIP_EMPTY):
        return "zip", "magic"
    if _looks_like_safetensors(path, head):
        return "safetensors", "structure"
    if _looks_like_onnx(head):
        return "onnx", "structure"
    if _looks_like_pickle(path, head):
        return "pickle", "structure"
    return "unknown", "unknown"


def _looks_like_safetensors(path: Path, head: bytes) -> bool:
    """A safetensors file starts with a u64 LE header length then JSON."""
    if len(head) < 9:
        return False
    header_len = int.from_bytes(head[:8], "little")
    file_size = path.stat().st_size
    if header_len == 0 or header_len > file_size - 8:
        return False
    # The byte right after the length must open a JSON object.
    return head[8:9] == b"{"


def _looks_like_pickle(path: Path, head: bytes) -> bool:
    """A pickle starts with a valid opcode and ends with STOP.

    Checking both ends keeps arbitrary binaries out (many start with a byte
    that happens to be an opcode) while accepting every protocol, including
    the protocol 0 streams the previous heuristic missed. A file that starts
    with PROTO is accepted on that alone, since 0x80 is not a plausible first
    byte for the other formats this tool knows.
    """
    if not head:
        return False
    if head[0] == 0x80:  # PROTO, protocols 2 to 5
        return True
    if head[0] not in PICKLE_OPCODE_BYTES:
        return False
    try:
        with path.open("rb") as handle:
            handle.seek(max(0, path.stat().st_size - 1))
            return handle.read(1) == b"."
    except OSError:
        return False


def _looks_like_onnx(head: bytes) -> bool:
    """ONNX is a protobuf ModelProto; field 1 (ir_version) is a varint.

    A protobuf stream starting with tag 0x08 (field 1, varint) is the usual
    shape. This is structural inference, not a magic number, so callers get
    confidence "structure" and the parser is expected to confirm.
    """
    return len(head) >= 2 and head[0] == 0x08


def extension_mismatch(path: Path, detected: str) -> Finding | None:
    """Finding when the file name claims a format the bytes contradict."""
    suffix = path.suffix.lower()
    expected = _EXTENSION_EXPECTATION.get(suffix)
    if expected is None:
        return None
    if detected in expected:
        return None
    # pytorch-zip is a refinement of zip; do not flag the generic case.
    if detected == "pytorch-zip" and "zip" in expected:
        return None
    return Finding(
        rule_id="ACT-FMT-002",
        severity=Severity.MEDIUM,
        location=path.name,
        evidence={"extension": suffix, "expected": list(expected), "detected": detected},
    )
