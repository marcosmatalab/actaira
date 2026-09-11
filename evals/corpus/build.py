"""Build the evaluation corpus. Deterministic, no network, no ML frameworks.

Design note D-19. Every artifact here is generated from code in this file,
so the corpus is reproducible byte-for-byte on any machine and its SHA-256
values can be published. Downloading real models from a hub was rejected for
three reasons: it makes the eval non-reproducible, it makes CI depend on a
third party, and it would mean committing malware to a public repository.

Honesty about what this buys and what it does not:
  - The benign half exercises real serialisers (pickle protocols 0-5 via
    CPython, numpy's own writer), so false positives there are meaningful.
  - The malicious half is hand-crafted from documented gadget shapes. It
    measures detector coverage against those shapes. It does NOT measure
    performance against real-world malware, which no synthetic corpus can.
    The eval report states this rather than implying a broader claim.
"""
from __future__ import annotations

import io
import json
import pickle
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np


@dataclass
class Case:
    """One corpus artifact and what the tool is expected to say about it."""

    name: str
    family: str  # benign | gadget-known | gadget-unknown | structural | format
    # benign | malicious | hostile-but-inconclusive
    #
    # The third label exists because the detection denominator has to mean one
    # thing. `unreadable_member.pt` is hostile - a member deliberately made
    # undecompressable so its content is unknown - and the correct answer to it
    # is INCONCLUSIVE, not FAIL. Counting it as a missed detection would
    # permanently depress a figure that measures something else, and counting
    # it as caught would inflate one. It is measured separately, against the
    # verdict it is supposed to produce.
    label: str
    expect_verdict: str  # pass | fail | inconclusive
    expect_rules: list[str] = field(default_factory=list)
    forbid_rules: list[str] = field(default_factory=list)
    note: str = ""


# ---------------------------------------------------------------------------
# Hand-crafted pickle streams
#
# Built from raw opcodes rather than by pickling a live object, so the corpus
# can reference callables without importing them and works identically on
# every platform. `os.system` pickles as `posix.system` on Linux and
# `nt.system` on Windows; crafting the bytes removes that variance.
# ---------------------------------------------------------------------------

def craft_reduce(module: str, name: str, args: tuple, protocol: int = 2) -> bytes:
    """A pickle that imports `module.name` and calls it with `args`."""
    if protocol <= 2:
        head = b"\x80\x02"
        global_op = b"c" + module.encode() + b"\n" + name.encode() + b"\n"
    else:
        head = b"\x80\x04"
        global_op = (
            b"\x8c" + bytes([len(module)]) + module.encode()
            + b"\x8c" + bytes([len(name)]) + name.encode()
            + b"\x93"
        )
    argument_blob = pickle.dumps(args, protocol=2)[2:-1]  # strip PROTO and STOP
    return head + global_op + argument_blob + b"R."


def craft_extension(code: int = 240) -> bytes:
    """A pickle that resolves a callable through the copyreg extension registry."""
    return b"\x80\x02" + b"\x82" + bytes([code]) + b")R."


def craft_persid() -> bytes:
    return b"\x80\x02" + b"X\x03\x00\x00\x00abc" + b"Q" + b"."


# ---------------------------------------------------------------------------
# Minimal protobuf writer, for ONNX cases
# ---------------------------------------------------------------------------

def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _field_varint(number: int, value: int) -> bytes:
    return _varint(number << 3 | 0) + _varint(value)


def _field_bytes(number: int, payload: bytes) -> bytes:
    return _varint(number << 3 | 2) + _varint(len(payload)) + payload


def build_onnx(domain: str = "", op_type: str = "Relu") -> bytes:
    node = _field_bytes(4, op_type.encode())
    if domain:
        node += _field_bytes(7, domain.encode())
    graph = _field_bytes(1, node) + _field_bytes(2, b"main_graph")
    opset = _field_bytes(1, domain.encode()) if domain else _field_bytes(1, b"")
    opset += _field_varint(2, 17)
    return (
        _field_varint(1, 9)
        + _field_bytes(2, b"actaira-corpus")
        + _field_bytes(3, b"1.0")
        + _field_bytes(7, graph)
        + _field_bytes(8, opset)
    )


def build_gguf(tensor_count: int = 1, declared_tensor_count: int | None = None, version: int = 3) -> bytes:
    def gstr(value: str) -> bytes:
        raw = value.encode()
        return struct.pack("<Q", len(raw)) + raw

    declared = tensor_count if declared_tensor_count is None else declared_tensor_count
    out = b"GGUF" + struct.pack("<I", version) + struct.pack("<Q", declared) + struct.pack("<Q", 2)
    out += gstr("general.architecture") + struct.pack("<I", 8) + gstr("llama")
    out += gstr("general.name") + struct.pack("<I", 8) + gstr("corpus-tiny")
    for index in range(tensor_count):
        out += gstr(f"blk.{index}.weight") + struct.pack("<I", 2)
        out += struct.pack("<Q", 8) + struct.pack("<Q", 8)
        out += struct.pack("<I", 0) + struct.pack("<Q", index * 64)
    return out


def build_safetensors(header: dict[str, Any], payload: bytes) -> bytes:
    blob = json.dumps(header).encode()
    return struct.pack("<Q", len(blob)) + blob + payload


def build_keras_h5(class_names: list[str]) -> bytes:
    """Synthetic HDF5-with-Keras-config.

    Carries the real HDF5 magic and a real Keras `model_config` blob, which
    is exactly the surface `keras_h5.inspect` reads. It is NOT a valid HDF5
    file, and the eval report says so: this case measures the Lambda
    detector, not HDF5 parsing, which this tool does not claim to do.
    """
    config = {
        "class_name": "Sequential",
        "keras_version": "2.15.0",
        "config": {"layers": [{"class_name": name, "config": {"name": name.lower()}} for name in class_names]},
    }
    blob = json.dumps(config).encode()
    return b"\x89HDF\r\n\x1a\n" + b"\x00" * 64 + blob + b"\x00" * 32


# ---------------------------------------------------------------------------
# The corpus
# ---------------------------------------------------------------------------

def _state_dict() -> dict[str, Any]:
    return {
        "encoder.weight": np.zeros((8, 8), dtype=np.float32),
        "encoder.bias": np.zeros(8, dtype=np.float32),
        "config": {"hidden": 8, "layers": 2, "labels": ["a", "b"]},
    }


def build(out_dir: Path) -> list[Case]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cases: list[Case] = []

    def write(name: str, payload: bytes, **kwargs: Any) -> None:
        (out_dir / name).write_bytes(payload)
        cases.append(Case(name=name, **kwargs))

    # -- benign: every pickle protocol, through CPython's own pickler --------
    for protocol in range(0, 6):
        write(
            f"benign_state_dict_p{protocol}.pkl",
            pickle.dumps(_state_dict(), protocol=protocol),
            family="benign",
            label="benign",
            expect_verdict="pass",
            forbid_rules=["ACT-PKL-001", "ACT-PKL-002", "ACT-PKL-009"],
            note=f"numpy state_dict, pickle protocol {protocol}",
        )

    # -- benign: a realistic PyTorch checkpoint layout -----------------------
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("archive/data.pkl", pickle.dumps(_state_dict(), protocol=2))
        archive.writestr("archive/data/0", b"\x00" * 256)
        archive.writestr("archive/version", b"3\n")
    write(
        "benign_checkpoint.pt", buffer.getvalue(),
        # PASS, with ACT-ZIP-007 still firing. `archive/data/0` and
        # `archive/version` had their heads read and were classified by content
        # as data, so the load-time execution surface really was covered end to
        # end; what was declined is the rest of blobs already shown not to be
        # code, and that limits raw tensor content, which was never in scope.
        #
        # This expectation used to be INCONCLUSIVE, and that was the honest
        # answer while one boolean had to mean both "every parser finished" and
        # "the whole file was examined". It also meant every clean checkpoint
        # in existence exited 3. See design notes D-100 to D-105.
        family="benign", label="benign", expect_verdict="pass",
        expect_rules=["ACT-ZIP-007"],
        forbid_rules=["ACT-PKL-001", "ACT-PKL-002", "ACT-ZIP-001"],
        note="zip checkpoint holding a clean state_dict; the storage blobs are not opened",
    )

    # -- benign: other formats ----------------------------------------------
    write(
        "benign_model.safetensors",
        build_safetensors({"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]},
                           "b": {"dtype": "F32", "shape": [4], "data_offsets": [64, 80]}},
                          b"\x00" * 80),
        family="benign", label="benign", expect_verdict="pass",
        forbid_rules=["ACT-STF-003", "ACT-STF-004", "ACT-STF-006"],
        note="two well-formed tensors",
    )
    write("benign_model.onnx", build_onnx(), family="benign", label="benign",
          expect_verdict="pass", forbid_rules=["ACT-ONX-001", "ACT-ONX-002"],
          note="standard opset domain")
    write("benign_model.gguf", build_gguf(2), family="benign", label="benign",
          expect_verdict="pass", forbid_rules=["ACT-GGF-001", "ACT-GGF-004"],
          note="two tensors, counts consistent")
    buffer = io.BytesIO()
    np.save(buffer, np.zeros((4, 4), dtype=np.float32))
    write("benign_array.npy", buffer.getvalue(), family="benign", label="benign",
          expect_verdict="pass", forbid_rules=["ACT-NPY-001"], note="concrete dtype")
    write("benign_model.h5", build_keras_h5(["Dense", "Dropout", "Dense"]),
          family="benign", label="benign", expect_verdict="pass",
          forbid_rules=["ACT-H5-001", "ACT-H5-002"], note="synthetic; known layer classes only")

    # -- malicious: gadgets a denylist already knows -------------------------
    known_gadgets = [
        ("posix", "system", ("id",)),
        ("os", "system", ("id",)),
        ("subprocess", "Popen", (["/bin/sh", "-c", "id"],)),
        ("builtins", "eval", ("__import__('os').system('id')",)),
        ("builtins", "exec", ("import os",)),
        ("builtins", "__import__", ("os",)),
        ("operator", "attrgetter", ("system",)),
    ]
    for module, name, args in known_gadgets:
        for protocol in (2, 4):
            write(
                f"gadget_known_{module.replace('.', '_')}_{name}_p{protocol}.pkl",
                craft_reduce(module, name, args, protocol),
                family="gadget-known", label="malicious", expect_verdict="fail",
                expect_rules=["ACT-PKL-002"],
                note=f"{module}.{name} via REDUCE, protocol {protocol}",
            )

    # -- malicious: gadgets a denylist does NOT know ------------------------
    # Each is a documented execution path that no published denylist of this
    # size enumerates. They are the reason the default policy is an allowlist.
    unknown_gadgets = [
        ("pydoc", "pipepager", ("x", "sh -c id")),
        ("logging.config", "fileConfig", ("/tmp/x.ini",)),
        ("zipimport", "zipimporter", ("/tmp/payload.zip",)),
        ("numpy.testing._private.utils", "runstring", ("import os", {})),
        ("torch.utils.cpp_extension", "load", ("m", ["/tmp/x.cpp"])),
        ("xml.sax", "make_parser", ()),
        ("venv", "create", ("/tmp/v",)),
        ("bdb", "Bdb", ()),  # note: bdb IS on the denylist, so this one is expected as ACT-PKL-002
        ("vendorlib.tasks", "run_shell", ("id",)),
    ]
    # `bdb` happens to be on Actaira's denylist already, so it is expected to
    # fire ACT-PKL-002 rather than ACT-PKL-001. Encoding that here instead of
    # relaxing the assertion keeps the eval honest about which rule fired.
    denylisted_anyway = {"bdb"}
    for module, name, args in unknown_gadgets:
        rule = "ACT-PKL-002" if module.split(".")[0] in denylisted_anyway else "ACT-PKL-001"
        write(
            f"gadget_unknown_{module.replace('.', '_')}_{name}.pkl",
            craft_reduce(module, name, args, 4),
            family="gadget-unknown", label="malicious", expect_verdict="fail",
            expect_rules=[rule],
            note=f"{module}.{name}: execution path outside any denylist of this size",
        )

    # -- malicious: opcode-level tricks -------------------------------------
    write("gadget_extension_registry.pkl", craft_extension(),
          family="gadget-known", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-PKL-004"], note="callable resolved by extension code, no name in the stream")
    write("gadget_nested_torch_load.pkl", craft_reduce("torch", "load", ("payload.pt",), 4),
          family="gadget-known", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-PKL-007"], note="re-enters the unpickler on attacker data")

    # -- malicious: format and container abuse ------------------------------
    write("trojan_renamed.safetensors", craft_reduce("posix", "system", ("id",), 2),
          family="format", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-FMT-002", "ACT-PKL-002"],
          note="pickle wearing a safetensors extension")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("archive/data.pkl", craft_reduce("posix", "system", ("id",), 2))
        archive.writestr("archive/data/0", b"\x00" * 64)
    write("trojan_checkpoint.pt", buffer.getvalue(),
          family="gadget-known", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-PKL-002"], note="gadget one level down, inside the zip")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../../../../tmp/actaira_escape.txt", b"escaped")
        archive.writestr("archive/data.pkl", pickle.dumps({"w": [1]}, protocol=2))
    write("traversal_checkpoint.pt", buffer.getvalue(),
          family="structural", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-ZIP-001"], note="member escapes the extraction root")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("pad.bin", b"\x00" * 8_000_000)
        archive.writestr("archive/data.pkl", pickle.dumps({"w": [1]}, protocol=2))
    write("bomb_checkpoint.pt", buffer.getvalue(),
          family="structural", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-ZIP-002"], note="high expansion ratio member")

    # The name-gate evasion. `archive/data/0` is what a PyTorch checkpoint
    # calls a raw storage blob, so every version of this tool up to 2.0.0
    # never opened it. The clean `data.pkl` beside it is the decoy: a
    # name-based scanner opens that one, finds nothing, and the artifact
    # comes back with no pickle findings at all.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("archive/data.pkl", pickle.dumps({"w": [1]}, protocol=2))
        archive.writestr("archive/data/0", craft_reduce("posix", "system", ("id",), 2))
        archive.writestr("archive/version", b"3\n")
    write("storage_named_gadget.pt", buffer.getvalue(),
          family="structural", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-ZIP-008", "ACT-PKL-002"],
          note="a pickle under a raw-storage member name, found by content")

    # A member whose local header claims deflate over bytes that are not a
    # deflate stream. Its head cannot be decompressed, so its content is
    # unknown - which is not the same as being tensor data, and must not be
    # filed with it.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("archive/data.pkl", pickle.dumps({"w": [1]}, protocol=2))
        archive.writestr("archive/data/0", b"\x00" * 64)
    raw = bytearray(buffer.getvalue())
    # Flip the stored member's compression method to deflate without
    # deflating it, in both the local header and the central directory.
    marker = b"archive/data/0"
    for index in range(len(raw) - len(marker)):
        if raw[index:index + len(marker)] != marker:
            continue
        # The compression-method field sits 22 bytes before the local file
        # name in a local header, and 20 before it in a central directory
        # entry. Patch whichever signature precedes this occurrence.
        for back, signature in ((30, b"PK\x03\x04"), (46, b"PK\x01\x02")):
            start = index - back
            if start >= 0 and raw[start:start + 4] == signature:
                offset = start + (8 if signature == b"PK\x03\x04" else 10)
                raw[offset:offset + 2] = (8).to_bytes(2, "little")
    write("unreadable_member.pt", bytes(raw),
          family="structural", label="hostile-but-inconclusive", expect_verdict="inconclusive",
          expect_rules=["ACT-ZIP-009"],
          note="a member whose head will not decompress, so its content is unknown")

    buffer = io.BytesIO()
    np.save(buffer, np.array([{"a": 1}], dtype=object), allow_pickle=True)
    write("object_array.npy", buffer.getvalue(),
          family="format", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-NPY-001"], note="object dtype smuggles a pickle")

    write("oob_offsets.safetensors",
          build_safetensors({"w": {"dtype": "F32", "shape": [4], "data_offsets": [0, 99999]}}, b"\x00" * 16),
          family="structural", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-STF-003"], note="offsets outside the data region")
    write("overlap.safetensors",
          build_safetensors({"a": {"dtype": "U8", "shape": [8], "data_offsets": [0, 8]},
                             "b": {"dtype": "U8", "shape": [8], "data_offsets": [4, 12]}}, b"\x00" * 12),
          family="structural", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-STF-006"], note="two tensors share bytes")
    write("custom_domain.onnx", build_onnx(domain="ai.onnx.contrib", op_type="PyOp"),
          family="format", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-ONX-001"], note="domain that executes user Python")
    write("vendor_domain.onnx", build_onnx(domain="com.acme.kernels", op_type="AcmeOp"),
          family="format", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-ONX-002"], note="custom operator domain")
    write("lambda_model.h5", build_keras_h5(["Dense", "Lambda"]),
          family="format", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-H5-001"], note="synthetic; Lambda body runs on load")
    write("count_mismatch.gguf", build_gguf(1, declared_tensor_count=4),
          family="structural", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-GGF-001", "ACT-GGF-004"],
          note="declares four tensors, carries one: the header is not a faithful map of the file")

    # -- regression cases: every bypass a hostile review found ---------------
    # Each of these passed cleanly at some point during development. They stay
    # in the corpus so that a refactor which reopens the hole fails the eval
    # instead of being found again by someone else.
    protocol0_gadget = b"I1\n0" + b"cposix\nsystem\n" + b"(S'id'\ntR."
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("archive/data.pkl", protocol0_gadget)
        archive.writestr("archive/data/0", b"\x00" * 64)
    write("regression_proto0_in_zip.pt", buffer.getvalue(),
          family="gadget-known", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-PKL-002"],
          note="protocol 0 stream inside a checkpoint: defeated the old seven-byte first-byte gate")
    write("regression_proto0_gadget.pkl", protocol0_gadget,
          family="gadget-known", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-PKL-002"],
          note="the same stream loose on disk: was not even recognised as a pickle")
    write("regression_torch_load_inline.pkl",
          craft_reduce("torch.utils.cpp_extension", "load_inline", ("m", "int main(){}"), 4),
          family="gadget-unknown", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-PKL-001"],
          note="sibling of an exception in the old torch.* prefix: compiles and runs C++ on load")
    write("regression_torch_native.pkl", craft_reduce("torch._C", "_TensorBase", (), 4),
          family="gadget-unknown", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-PKL-001"],
          note="the whole pybind11 native module was reachable through the old prefix")
    write("regression_concatenated.pkl",
          pickle.dumps({"w": [1.0, 2.0]}, protocol=2) + craft_reduce("posix", "system", ("id",), 2),
          family="gadget-known", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-PKL-010", "ACT-PKL-002"],
          note="gadget concatenated after the first STOP: the scanner used to stop there")

    inner_gadget = craft_reduce("posix", "system", ("echo PWNED",), 4)
    write("regression_nested_loader.pt",
          craft_reduce("torch.storage", "_load_from_bytes", (inner_gadget,), 4),
          family="gadget-known", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-PKL-011", "ACT-PKL-002"],
          note="gadget wrapped in the operand of an allowlisted callable whose body is "
               "torch.load(BytesIO(b), weights_only=False): passed with exit 0 under both policies")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("archive/version", "3")
        archive.writestr("archive/weights.bin", craft_reduce("posix", "system", ("id",), 4) + b"\x00")
    write("regression_ambiguous_member_tail.pt", buffer.getvalue(),
          family="gadget-known", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-PKL-002"],
          note="one byte appended after STOP made an ambiguously named member fail the tail "
               "check and be dropped with no rule at all, leaving fully_read True")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("archive/version", "3")
        archive.writestr("archive/weights.bin", struct.pack("<256f", *([0.5] * 256)))
    write("regression_stream_budget.pt",
          pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2)
          + pickle.dumps(1, protocol=2) * 8
          + craft_reduce("posix", "system", ("id",), 2),
          family="gadget-known", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-PKL-013"],
          note="legacy magic to suppress the concatenation finding, eight fillers to exhaust "
               "the stream budget, gadget as stream nine: 115 bytes, empty findings, PASS exit 0")
    write("regression_inst_gadget.pkl", b"(S'echo PWNED'\nios\nsystem\n.",
          family="gadget-known", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-PKL-002"],
          note="INST imports by name exactly as GLOBAL does and was counted but never judged: "
               "27 bytes running a denylisted callable, PASS under both policies")
    write("regression_unmeasurable_tail.pt",
          pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2)
          + b"I\x00\n."
          + craft_reduce("os", "system", ("id",), 0),
          family="gadget-known", label="malicious", expect_verdict="fail",
          expect_rules=["ACT-PKL-013"],
          note="real pickle reads I\\x00\\n. as 0 then STOP where pickletools raises, so the "
               "walker could not measure the stream and gave up in silence behind the legacy "
               "exemption, leaving the gadget unread at a clean PASS")
    write("negative_ambiguous_blob.pt", buffer.getvalue(),
          family="structural", label="benign", expect_verdict="pass",
          expect_rules=["ACT-ZIP-007"],
          forbid_rules=["ACT-PKL-006"],
          note="negative control for the case above: a raw float blob under an ambiguous name "
               "must stay quiet, or the fix would trade a bypass for noise on every checkpoint. "
               "ACT-ZIP-007 names `archive/version`, which the name gate never opens, and is a "
               "statement of scope rather than a finding against the blob")

    # -- inconclusive by design ---------------------------------------------
    write("truncated.pkl", pickle.dumps(_state_dict(), protocol=4)[:64],
          family="structural", label="benign", expect_verdict="inconclusive",
          expect_rules=["ACT-PKL-006"], note="a partially read artifact must never read as PASS")
    write("mystery.model", b"\x11\x22\x33\x44 not a known format",
          family="format", label="benign", expect_verdict="inconclusive",
          expect_rules=["ACT-FMT-001"], note="unknown format is reported, not assumed safe")
    write("empty.pkl", b"", family="format", label="benign",
          expect_verdict="inconclusive", expect_rules=["ACT-FMT-003"], note="zero bytes")

    (out_dir / "cases.json").write_text(
        json.dumps([case.__dict__ for case in cases], indent=2, ensure_ascii=False),
        encoding="utf-8", newline="\n"
    )
    return cases


if __name__ == "__main__":
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("evals/artifacts")
    built = build(target)
    print(f"{len(built)} cases written to {target}")
