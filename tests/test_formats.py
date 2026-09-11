"""Format detection and the per-format structural inspectors.

Every case is paired: the inspector fires on the artifact that earns it, and
stays silent on the well-formed artifact next to it.
"""
from __future__ import annotations

import io
import pickle
import struct
import zipfile

import numpy as np
import pytest

from actaira.coverage import CoverageState, Surface
from actaira.formats import archive, detect, gguf, keras_h5, npy, onnx, safetensors
from actaira.inspect import inspect_artifact
from actaira.model import Severity, Verdict
from conftest import corpus_build


def rule_ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}


# ACT-ZIP-007 is a statement of scope, not a finding about the artifact: it
# fires on every archive that carries a member the name gate does not open,
# which is very nearly every archive. The tests below are about what else was
# found, so they subtract it and say so rather than listing it eight times.
SCOPE_RULES = {"ACT-ZIP-007"}


def findings_about_the_artifact(findings) -> set[str]:
    return rule_ids(findings) - SCOPE_RULES


def report_rules(report) -> set[str]:
    return {finding.rule_id for finding in report.findings}


def zip_bytes(entries, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as handle:
        for name, payload in entries:
            handle.writestr(name, payload)
    return buffer.getvalue()


CLEAN_STATE_DICT = pickle.dumps({"w": [1.0, 2.0]}, protocol=2)


# ---------------------------------------------------------------------------
# Detection reads bytes, not names
# ---------------------------------------------------------------------------

def test_a_pickle_renamed_to_safetensors_is_detected_as_a_pickle(write_artifact):
    payload = corpus_build.craft_reduce("posix", "system", ("id",), 2)
    disguised = write_artifact("model.safetensors", payload)

    assert detect.sniff(disguised) == ("pickle", "structure")

    report = inspect_artifact(disguised)
    assert "ACT-FMT-002" in report_rules(report)
    assert "ACT-PKL-002" in report_rules(report), "the disguise must not stop the pickle scan"
    assert report.verdict is Verdict.FAIL

    mismatch = next(f for f in report.findings if f.rule_id == "ACT-FMT-002")
    assert mismatch.evidence == {
        "extension": ".safetensors",
        "expected": ["safetensors"],
        "detected": "pickle",
    }


def test_the_same_bytes_under_an_honest_name_raise_no_mismatch(write_artifact):
    """Negative control: ACT-FMT-002 is about the lie, not about the content."""
    honest = write_artifact("model.pkl", corpus_build.craft_reduce("posix", "system", ("id",), 2))

    report = inspect_artifact(honest)

    assert "ACT-FMT-002" not in report_rules(report)
    assert "ACT-PKL-002" in report_rules(report)


def test_a_real_safetensors_file_is_not_flagged_for_its_extension(write_artifact):
    clean = write_artifact(
        "model.safetensors",
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}}, b"\x00" * 64
        ),
    )

    assert detect.sniff(clean) == ("safetensors", "structure")
    assert inspect_artifact(clean).verdict is Verdict.PASS


# ---------------------------------------------------------------------------
# safetensors: the header is a map, and a map can lie
# ---------------------------------------------------------------------------

def test_well_formed_safetensors_produces_no_findings(write_artifact):
    path = write_artifact(
        "good.safetensors",
        corpus_build.build_safetensors(
            {
                "w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]},
                "b": {"dtype": "F32", "shape": [4], "data_offsets": [64, 80]},
            },
            b"\x00" * 80,
        ),
    )

    findings, tensors, metadata = safetensors.inspect(path)

    assert findings == []
    assert [(t.name, t.dtype, t.shape, t.n_elements) for t in tensors] == [
        ("w", "F32", [4, 4], 16),
        ("b", "F32", [4], 4),
    ]
    assert metadata["total_parameters"] == 20


def test_offsets_outside_the_data_region_are_critical(write_artifact):
    path = write_artifact(
        "oob.safetensors",
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [4], "data_offsets": [0, 99999]}}, b"\x00" * 16
        ),
    )

    findings, _tensors, _metadata = safetensors.inspect(path)

    assert [f.rule_id for f in findings] == ["ACT-STF-003"]
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].evidence["data_offsets"] == [0, 99999]
    assert findings[0].evidence["data_region_bytes"] == 16
    assert inspect_artifact(path).verdict is Verdict.FAIL


def test_a_span_that_does_not_match_dtype_and_shape_is_flagged(write_artifact):
    """4x4 float32 is 64 bytes. A header claiming 32 is describing something
    other than what it says it is."""
    path = write_artifact(
        "size.safetensors",
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 32]}}, b"\x00" * 64
        ),
    )

    findings, _tensors, _metadata = safetensors.inspect(path)

    assert [f.rule_id for f in findings] == ["ACT-STF-004"]
    assert findings[0].evidence["declared_bytes"] == 32
    assert findings[0].evidence["expected_bytes"] == 64


def test_two_tensors_sharing_bytes_are_flagged(write_artifact):
    path = write_artifact(
        "overlap.safetensors",
        corpus_build.build_safetensors(
            {
                "a": {"dtype": "U8", "shape": [8], "data_offsets": [0, 8]},
                "b": {"dtype": "U8", "shape": [8], "data_offsets": [4, 12]},
            },
            b"\x00" * 12,
        ),
    )

    findings, _tensors, _metadata = safetensors.inspect(path)

    assert [f.rule_id for f in findings] == ["ACT-STF-006"]
    assert findings[0].evidence["tensors"] == ["a", "b"]


def test_adjacent_tensors_are_not_mistaken_for_overlapping_ones(write_artifact):
    """Negative control for the overlap check: `end == next start` is how a
    correct file is packed, and an off-by-one here would flag every file."""
    path = write_artifact(
        "adjacent.safetensors",
        corpus_build.build_safetensors(
            {
                "a": {"dtype": "U8", "shape": [8], "data_offsets": [0, 8]},
                "b": {"dtype": "U8", "shape": [8], "data_offsets": [8, 16]},
            },
            b"\x00" * 16,
        ),
    )

    assert safetensors.inspect(path)[0] == []


@pytest.mark.parametrize(
    "declared_header_bytes, payload, expected_rule",
    [
        (1 << 40, b"{}" + b"\x00" * 10, "ACT-STF-001"),   # header larger than any disk
        (0, b"{}" + b"\x00" * 10, "ACT-STF-001"),         # header of nothing
        (500, b'{"a":1}', "ACT-STF-002"),                 # header longer than the file
    ],
)
def test_an_impossible_header_length_is_refused_before_it_is_read(
    write_artifact, declared_header_bytes, payload, expected_rule
):
    """The declared length is read from attacker bytes, so it is checked before
    it is used to size a read."""
    path = write_artifact(
        "header.safetensors", struct.pack("<Q", declared_header_bytes) + payload
    )

    findings, tensors, _metadata = safetensors.inspect(path)

    assert [f.rule_id for f in findings] == [expected_rule]
    assert tensors == [], "nothing may be reported as parsed out of a header that was refused"
    # End to end, such a file does not even sniff as safetensors, and a file
    # that cannot be read must never reach PASS.
    assert detect.sniff(path)[0] != "safetensors"
    assert inspect_artifact(path).verdict is Verdict.INCONCLUSIVE


# ---------------------------------------------------------------------------
# zip containers
# ---------------------------------------------------------------------------

def test_member_escaping_the_extraction_root_is_flagged(write_artifact):
    path = write_artifact(
        "traversal.pt",
        zip_bytes([("../../etc/cron.d/x", b"escaped"), ("archive/data.pkl", CLEAN_STATE_DICT)]),
    )

    findings, metadata, _imported = archive.inspect(path)

    assert findings_about_the_artifact(findings) == {"ACT-ZIP-001"}
    assert findings[0].evidence["member"] == "../../etc/cron.d/x"
    assert metadata["pickle_members"] == ["archive/data.pkl"]
    assert inspect_artifact(path).verdict is Verdict.FAIL


@pytest.mark.parametrize(
    "member", ["/absolute/path", "C:/windows/system32/x", "dir/../../escape", "a\\..\\..\\escape"]
)
def test_traversal_shapes_are_all_caught(write_artifact, member):
    path = write_artifact("t.pt", zip_bytes([(member, b"x")]))
    assert findings_about_the_artifact(archive.inspect(path)[0]) == {"ACT-ZIP-001"}


def test_ordinary_checkpoint_member_names_are_not_traversal(write_artifact):
    """Negative control: `archive/data/0` and a dot in a name are normal."""
    path = write_artifact(
        "clean.pt",
        zip_bytes(
            [
                ("archive/data.pkl", CLEAN_STATE_DICT),
                ("archive/data/0", b"\x00" * 256),
                ("archive/version", b"3\n"),
            ]
        ),
    )

    report = inspect_artifact(path)

    assert report_rules(report) == {"ACT-ZIP-007"}, "the storage blobs were not decompressed, and it says so"
    assert report.metadata["members_not_inspected"] == ["archive/data/0", "archive/version"]
    # A clean checkpoint passes. Every member had its head read and was
    # classified by content, so the load-time execution surface really was
    # covered end to end; what was declined is the rest of blobs already shown
    # to be data, which is raw tensor content and was never in scope.
    assert report.verdict is Verdict.PASS
    assert report.coverage.state(Surface.LOAD_TIME_EXECUTION) is CoverageState.COMPLETE
    assert report.coverage.state(Surface.RAW_TENSOR_CONTENT) is CoverageState.NOT_ASSESSED
    assert report.detected_format == "pytorch-zip", "a zip holding a pickle is a checkpoint"


def test_a_member_that_expands_without_bound_is_flagged(write_artifact):
    path = write_artifact(
        "bomb.pt",
        zip_bytes([("pad.bin", b"\x00" * 8_000_000), ("archive/data.pkl", CLEAN_STATE_DICT)]),
    )

    findings, _metadata, _imported = archive.inspect(path)

    # `pad.bin` has an ambiguous name, so it is only scanned as a pickle if its
    # bytes look like one at both ends. A block of zeros does not, so the only
    # finding is the expansion ratio.
    assert findings_about_the_artifact(findings) == {"ACT-ZIP-002"}
    assert findings[0].evidence["ratio"] > archive.MAX_COMPRESSION_RATIO
    assert findings[0].evidence["uncompressed_bytes"] == 8_000_000
    assert inspect_artifact(path).verdict is Verdict.FAIL


def test_a_compressible_but_ordinary_member_is_not_a_bomb(write_artifact):
    """Negative control: the most compressible member a real checkpoint carries
    is its weight index, and the threshold has to sit clear above it.

    The shape below is a `model.safetensors.index.json`: highly repetitive JSON
    that deflate handles very well (~35x here). A limit set by feel rather than
    by measurement would fail every sharded checkpoint in existence.
    """
    import json

    index = json.dumps(
        {
            f"model.layers.{layer}.{part}": {"dtype": "F32", "shape": [4096, 4096]}
            for layer in range(80)
            for part in ("self_attn.q_proj.weight", "self_attn.k_proj.weight", "mlp.gate_proj.weight")
        },
        indent=2,
    ).encode()
    path = write_artifact("sharded.pt", zip_bytes([("archive/index.json", index)]))

    findings, _metadata, _imported = archive.inspect(path)

    assert findings_about_the_artifact(findings) == set()
    with zipfile.ZipFile(path) as handle:
        info = handle.getinfo("archive/index.json")
    ratio = info.file_size / info.compress_size
    assert 10 < ratio < archive.MAX_COMPRESSION_RATIO, (
        f"control member compresses {ratio:.0f}x; it must be compressible enough "
        "to be a real test of the threshold, and still legitimate"
    )


def _zip_with_more_members_than_the_budget(write_artifact):
    entries = [(f"archive/data/{index}", b"\x00" * 8) for index in range(archive.MAX_MEMBERS_INSPECTED + 8)]
    # The gadget sits past the budget, so it is never even read.
    entries.append(("archive/data.pkl", corpus_build.craft_reduce("posix", "system", ("id",), 2)))
    return write_artifact("many-members.pt", zip_bytes(entries, zipfile.ZIP_STORED))


def _zip_that_cannot_be_opened(write_artifact):
    return write_artifact("broken.pt", b"PK\x03\x04" + b"\x00" * 200)


def _zip_whose_member_cannot_be_decompressed(write_artifact):
    raw = bytearray(zip_bytes([("archive/data.pkl", CLEAN_STATE_DICT)], zipfile.ZIP_STORED))
    offset = raw.find(CLEAN_STATE_DICT)
    assert offset > 0, "the member payload must be stored uncompressed for this to work"
    raw[offset + 3] ^= 0xFF  # corrupt the payload, leaving the CRC stale
    return write_artifact("corrupt-member.pt", bytes(raw))


@pytest.mark.parametrize(
    "make_artifact, expected_rule",
    [
        (_zip_with_more_members_than_the_budget, "ACT-ZIP-004"),
        (_zip_that_cannot_be_opened, "ACT-ZIP-005"),
        (_zip_whose_member_cannot_be_decompressed, "ACT-ZIP-003"),
    ],
    ids=["over-member-budget", "unopenable-archive", "unreadable-member"],
)
def test_a_zip_that_was_not_fully_read_must_not_come_back_as_pass(
    write_artifact, make_artifact, expected_rule
):
    """The doctrine of D-04 and D-10, applied to the zip inspector.

    "An inspector that cannot parse an artifact must say so instead of
    returning PASS, because a silent PASS on an unparsed file is exactly the
    failure mode that makes a supply-chain tool worthless."

    Each of these three artifacts reports, in its own findings, that part of it
    was not inspected: more members than the budget allows, an archive that
    would not open at all, a member that would not decompress. Every other
    inspector in the project feeds that condition into `fully_read`; the
    zip branch of `inspect_artifact` does not, so all three reach PASS at the
    default threshold. In the first case the gadget in the last member is
    never even scanned.
    """
    path = make_artifact(write_artifact)
    report = inspect_artifact(path)

    assert expected_rule in report_rules(report), "the inspector did not notice at all"
    assert report.metadata["fully_read"] is False
    assert report.verdict is not Verdict.PASS


def test_a_gadget_one_level_down_inside_the_zip_is_still_found(write_artifact):
    path = write_artifact(
        "trojan.pt",
        zip_bytes([("archive/data.pkl", corpus_build.craft_reduce("posix", "system", ("id",), 2))]),
    )

    findings, _metadata, imported = archive.inspect(path)

    assert "ACT-PKL-002" in rule_ids(findings)
    assert imported == {"posix.system"}
    assert findings[0].location == "trojan.pt!archive/data.pkl"


# ---------------------------------------------------------------------------
# .npy
# ---------------------------------------------------------------------------

def test_object_dtype_npy_is_critical_and_its_embedded_pickle_is_scanned(write_artifact):
    buffer = io.BytesIO()
    np.save(buffer, np.array([{"a": 1}], dtype=object), allow_pickle=True)
    path = write_artifact("object.npy", buffer.getvalue())

    findings, _tensors, metadata, imported = npy.inspect(path, "strict")

    assert "ACT-NPY-001" in rule_ids(findings)
    critical = next(f for f in findings if f.rule_id == "ACT-NPY-001")
    assert critical.severity is Severity.CRITICAL
    assert "O" in metadata["descr"]
    assert imported, "the pickle in the body must be scanned, not just noted"
    assert inspect_artifact(path).verdict is Verdict.FAIL


def test_a_concrete_dtype_npy_is_inert(write_artifact):
    buffer = io.BytesIO()
    np.save(buffer, np.zeros((4, 4), dtype=np.float32))
    path = write_artifact("clean.npy", buffer.getvalue())

    findings, tensors, metadata, imported = npy.inspect(path, "strict")

    assert findings == []
    assert imported == set()
    assert metadata["descr"] == "<f4"
    assert [t.n_elements for t in tensors] == [16]
    assert inspect_artifact(path).verdict is Verdict.PASS


# ---------------------------------------------------------------------------
# ONNX
# ---------------------------------------------------------------------------

def test_standard_opset_domain_is_clean(write_artifact):
    path = write_artifact("std.onnx", corpus_build.build_onnx())

    findings, _tensors, metadata = onnx.inspect(path)

    assert findings == []
    assert metadata["opset_domains"] == [""]
    assert metadata["producer_name"] == "actaira-corpus"
    assert metadata["op_types"] == {"Relu": 1}
    assert inspect_artifact(path).verdict is Verdict.PASS


def test_python_executing_domain_is_critical(write_artifact):
    path = write_artifact("contrib.onnx", corpus_build.build_onnx("ai.onnx.contrib", "PyOp"))

    findings, _tensors, metadata = onnx.inspect(path)

    assert [f.rule_id for f in findings] == ["ACT-ONX-001"]
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].evidence["domain"] == "ai.onnx.contrib"
    assert metadata["op_types"] == {"ai.onnx.contrib::PyOp": 1}


def test_a_merely_custom_domain_is_high_not_critical(write_artifact):
    """The two are different claims: `ai.onnx.contrib` runs user Python by
    documentation, a vendor domain only needs a kernel this tool cannot see."""
    path = write_artifact("vendor.onnx", corpus_build.build_onnx("com.acme.kernels", "AcmeOp"))

    findings, _tensors, _metadata = onnx.inspect(path)

    assert [f.rule_id for f in findings] == ["ACT-ONX-002"]
    assert findings[0].severity is Severity.HIGH


def test_a_truncated_protobuf_is_inconclusive_not_clean(write_artifact):
    """Cut inside the graph, so a length-delimited field runs off the end.

    A cut that happens to land on a field boundary leaves a shorter but still
    well-formed protobuf, which this reader (correctly) parses and which no
    rule currently notices. That is a coverage gap, not something this test
    can assert on, so the cut here is deliberately mid-field.
    """
    whole = corpus_build.build_onnx()
    path = write_artifact("cut.onnx", whole[: len(whole) // 2])

    report = inspect_artifact(path)

    assert "ACT-ONX-003" in report_rules(report)
    assert report.metadata["fully_read"] is False
    assert report.verdict is Verdict.INCONCLUSIVE


# ---------------------------------------------------------------------------
# GGUF
# ---------------------------------------------------------------------------

def test_well_formed_gguf_parses_and_reports_no_problem(write_artifact):
    path = write_artifact("ok.gguf", corpus_build.build_gguf(2))

    findings, tensors, metadata = gguf.inspect(path)

    assert findings == []
    assert metadata["gguf_version"] == 3
    assert metadata["kv"]["general.architecture"] == "llama"
    assert [t.name for t in tensors] == ["blk.0.weight", "blk.1.weight"]
    assert metadata["declared_tensor_count"] == len(tensors) == 2
    assert inspect_artifact(path).verdict is Verdict.PASS


def test_truncated_gguf_is_reported_and_never_passes(write_artifact):
    whole = corpus_build.build_gguf(2)
    path = write_artifact("cut.gguf", whole[: len(whole) // 2])

    findings, tensors, _metadata = gguf.inspect(path)

    assert [f.rule_id for f in findings] == ["ACT-GGF-001"]
    assert "truncated gguf" in findings[0].evidence["reason"]
    assert tensors == []

    report = inspect_artifact(path)
    assert report.metadata["fully_read"] is False
    assert report.verdict is Verdict.INCONCLUSIVE


def test_gguf_that_declares_more_tensors_than_it_carries_is_caught(write_artifact):
    """A header that lies about its own tensor count must reach FAIL.

    This originally asserted INCONCLUSIVE, which was the honest description
    of a real defect: the tensor loop ran exactly `declared_tensor_count`
    times or raised, so the counts could never disagree and ACT-GGF-004 was
    unreachable. The loop now keeps what it parsed, so the disagreement is
    observable and the artifact fails on the rule written for it.
    """
    path = write_artifact("mismatch.gguf", corpus_build.build_gguf(1, declared_tensor_count=4))

    findings, tensors, _metadata = gguf.inspect(path)
    ids = rule_ids(findings)

    assert "ACT-GGF-001" in ids, "the truncated descriptor is still reported"
    assert "ACT-GGF-004" in ids, "and so is the count disagreement it exposes"
    assert len(tensors) == 1, "the one tensor actually present is kept, not discarded"
    assert inspect_artifact(path).verdict is Verdict.FAIL


def test_gguf_with_consistent_counts_does_not_fire_the_mismatch_rule(write_artifact):
    """Negative control for the rule above."""
    path = write_artifact("consistent.gguf", corpus_build.build_gguf(3))

    findings, tensors, _metadata = gguf.inspect(path)

    assert "ACT-GGF-004" not in rule_ids(findings)
    assert "ACT-GGF-001" not in rule_ids(findings)
    assert len(tensors) == 3
    assert inspect_artifact(path).verdict is Verdict.PASS


# ---------------------------------------------------------------------------
# Keras / HDF5
# ---------------------------------------------------------------------------

def test_lambda_layer_is_critical(write_artifact):
    path = write_artifact("lambda.h5", corpus_build.build_keras_h5(["Dense", "Lambda"]))

    findings, metadata, config_read = keras_h5.inspect(path)

    assert config_read is True
    assert [f.rule_id for f in findings] == ["ACT-H5-001"]
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].evidence["lambda_layers"] == 1
    assert "Lambda" in metadata["layer_class_names"]
    assert inspect_artifact(path).verdict is Verdict.FAIL


def test_a_model_of_known_layers_is_clean(write_artifact):
    path = write_artifact("clean.h5", corpus_build.build_keras_h5(["Dense", "Dropout", "Dense"]))

    findings, metadata, config_read = keras_h5.inspect(path)

    assert config_read is True
    assert findings == []
    assert metadata["layer_class_names"] == ["Dense", "Dropout", "Sequential"]
    assert inspect_artifact(path).verdict is Verdict.PASS


def test_an_unknown_layer_class_is_reported_separately_from_lambda(write_artifact):
    path = write_artifact("custom.h5", corpus_build.build_keras_h5(["Dense", "AcmeBlock"]))

    findings, _metadata, _config_read = keras_h5.inspect(path)

    assert [f.rule_id for f in findings] == ["ACT-H5-002"]
    assert findings[0].evidence["custom_classes"] == ["AcmeBlock"]


def test_hdf5_without_a_locatable_config_is_inconclusive_not_clean(write_artifact):
    """The honest half of design note D-09: this inspector does not parse HDF5,
    so a real HDF5 file with no findable config must say `unread`."""
    path = write_artifact("opaque.h5", b"\x89HDF\r\n\x1a\n" + b"\x00" * 512)

    findings, _metadata, config_read = keras_h5.inspect(path)

    assert config_read is False
    assert [f.rule_id for f in findings] == ["ACT-H5-003"]
    assert inspect_artifact(path).verdict is Verdict.INCONCLUSIVE


# ---------------------------------------------------------------------------
# Regressions: every bypass a hostile review found
#
# Each of these produced a clean PASS at some point during development. They
# are here so that a refactor which reopens the hole fails a named test rather
# than being rediscovered by whoever is reviewing the repository.
# ---------------------------------------------------------------------------

PROTOCOL_0_GADGET = b"I1\n0" + b"cposix\nsystem\n" + b"(S'id'\ntR."


def test_protocol_zero_gadget_inside_a_checkpoint_is_caught(write_artifact):
    """The seven-byte first-byte gate let this through as a clean PASS.

    `archive.inspect` used to skip any member whose first byte was not one of
    seven "pickle start" opcodes. A protocol 0 stream starts with INT ("I"),
    which was not in the set, so posix.system rode through untouched under
    both policies.
    """
    path = write_artifact(
        "proto0.pt",
        zip_bytes([("archive/data.pkl", PROTOCOL_0_GADGET), ("archive/data/0", b"\x00" * 32)]),
    )

    for policy in ("strict", "known-bad"):
        report = inspect_artifact(path, scan_policy=policy)
        assert report.verdict is Verdict.FAIL, f"policy {policy} must not pass this"
        assert "ACT-PKL-002" in {finding.rule_id for finding in report.findings}
        assert "posix.system" in report.imported_callables


def test_protocol_zero_gadget_loose_on_disk_is_recognised_as_a_pickle(write_artifact):
    """Same stream, no container. It was not even detected as a pickle."""
    path = write_artifact("proto0.pkl", PROTOCOL_0_GADGET)

    report = inspect_artifact(path)

    assert report.detected_format == "pickle"
    assert report.verdict is Verdict.FAIL


def test_a_binary_that_is_not_a_pickle_is_still_not_a_pickle(write_artifact):
    """Negative control for the widened detector.

    Accepting every opcode byte as a pickle start would classify half of all
    binaries as pickles, so detection also requires the stream to end in STOP.
    """
    path = write_artifact("weights.bin", bytes(range(256)) * 8)

    assert inspect_artifact(path).detected_format == "unknown"


def test_the_torch_prefix_no_longer_allows_its_own_executable_siblings(write_artifact):
    """`torch.*` was allowed by prefix, with a hand-written exception list.

    `torch.utils.cpp_extension.load` was excepted; `load_inline`, which
    compiles and runs C++ at load time, was not. Neither were `torch._C`,
    `torch.multiprocessing` or `torch.hub`.
    """
    for module, name in (
        ("torch.utils.cpp_extension", "load_inline"),
        ("torch._C", "_TensorBase"),
        ("torch.multiprocessing", "spawn"),
        ("torch.hub", "load"),
    ):
        path = write_artifact(f"{module}.pkl", corpus_build.craft_reduce(module, name, (), 4))
        report = inspect_artifact(path, scan_policy="strict")
        assert report.verdict is Verdict.FAIL, f"{module}.{name} must not pass"


def test_legitimate_torch_reconstruction_still_passes(write_artifact):
    """Negative control for the fix above: closing the prefix must not break
    the artifacts the allowlist exists to admit."""
    for module, name in (
        ("torch._utils", "_rebuild_tensor_v2"),
        ("torch", "FloatStorage"),
        ("torch", "Size"),
        ("collections", "OrderedDict"),
    ):
        path = write_artifact(f"ok_{name}.pkl", corpus_build.craft_reduce(module, name, (), 4))
        report = inspect_artifact(path, scan_policy="strict")
        assert "ACT-PKL-001" not in {f.rule_id for f in report.findings}, f"{module}.{name} is legitimate"


def test_a_gadget_concatenated_after_the_first_stop_is_reported(write_artifact):
    """`genops` stops at the first STOP, so trailing streams were invisible."""
    import pickle

    path = write_artifact(
        "concat.pkl",
        pickle.dumps({"w": [1.0]}, protocol=2) + corpus_build.craft_reduce("posix", "system", ("id",), 2),
    )

    report = inspect_artifact(path)
    ids = {finding.rule_id for finding in report.findings}

    assert "ACT-PKL-010" in ids, "the trailing stream itself is reported"
    assert "ACT-PKL-002" in ids, "and so is what it contains"
    assert report.verdict is Verdict.FAIL


def test_a_nested_loader_payload_is_disassembled_not_trusted(write_artifact):
    """The wrapper was on the allowlist, so the gadget inside it was invisible.

    `torch.storage._load_from_bytes(b)` is `torch.load(io.BytesIO(b),
    weights_only=False)`. It sat on the allowlist catalogued as tensor
    reconstruction, so a pickle whose only import was that callable, with a
    gadget in the byte operand it is handed, reached PASS with exit 0 under
    both policies. The fix does not merely deny the callable: the bytes an
    inner loader is given are a pickle, and they are now disassembled as one.
    """
    inner = corpus_build.craft_reduce("posix", "system", ("id",), 4)
    path = write_artifact(
        "nested.pt", corpus_build.craft_reduce("torch.storage", "_load_from_bytes", (inner,), 4)
    )

    for policy in ("strict", "known-bad"):
        report = inspect_artifact(path, scan_policy=policy)
        ids = {finding.rule_id for finding in report.findings}
        assert report.verdict is Verdict.FAIL, f"policy {policy} must not pass this"
        assert "ACT-PKL-011" in ids, "the wrapper is reported"
        assert "ACT-PKL-002" in ids, "and so is the gadget one level down"
        assert "posix.system" in report.imported_callables


def test_a_protocol_two_nested_payload_is_still_followed(write_artifact):
    """Protocol 2 has no byte-string opcode, which nearly hid the payload.

    The pickler writes bytes as `_codecs.encode(text, "latin1")`, so at
    protocol 2 the operand handed to the inner loader is the result of a call
    rather than a literal. The first version of the nested-loader check saw an
    opaque operand and said only that it could not follow it, which downgrades
    a known gadget to an unknown one for the price of passing protocol=2.
    """
    inner = corpus_build.craft_reduce("posix", "system", ("id",), 2)
    path = write_artifact(
        "nested2.pt", corpus_build.craft_reduce("torch.storage", "_load_from_bytes", (inner,), 2)
    )

    report = inspect_artifact(path)
    ids = {finding.rule_id for finding in report.findings}

    assert "ACT-PKL-002" in ids, "the inner gadget is named, not merely gestured at"
    assert "posix.system" in report.imported_callables


def test_an_ambiguous_member_with_a_trailing_byte_is_not_dropped(write_artifact):
    """One byte after STOP used to remove a member from the analysis entirely.

    An ambiguously named member was kept only when its bytes looked like a
    pickle at both ends. Appending a single byte broke the tail check, the
    member was skipped with a bare `continue`, no rule was emitted, and
    `fully_read` stayed True: a clean PASS for one byte of work.
    """
    gadget = corpus_build.craft_reduce("posix", "system", ("id",), 4)
    path = write_artifact(
        "tail.pt",
        zip_bytes([("archive/version", b"3"), ("archive/weights.bin", gadget + b"\x00")]),
    )

    report = inspect_artifact(path)

    assert report.verdict is Verdict.FAIL
    assert "ACT-PKL-002" in {finding.rule_id for finding in report.findings}


def test_a_raw_blob_under_an_ambiguous_name_stays_quiet(write_artifact):
    """Negative control for the test above.

    Every ambiguous member is now disassembled and the decision is made on
    what the disassembly found. If that traded the bypass for a parse-error
    line on every checkpoint the fix would be worse than the defect, so a raw
    float blob has to stay clean and be recorded as what it is.
    """
    import struct

    blob = struct.pack("<256f", *([0.5] * 256))
    path = write_artifact(
        "blob.pt", zip_bytes([("archive/version", b"3"), ("archive/weights.bin", blob)])
    )

    report = inspect_artifact(path)

    assert findings_about_the_artifact(report.findings) == set(), "no parse error on a weight blob"
    assert report.metadata["members_not_pickle"] == ["archive/weights.bin"]
    # The blob was opened and found to be data. `archive/version` had its
    # head read and was classified the same way, so nothing here is unknown
    # and nothing keeps the artifact out of PASS.
    assert report.metadata["members_not_inspected"] == ["archive/version"]
    assert report.verdict is Verdict.PASS


def test_trailing_zero_padding_is_stated_rather_than_ignored(write_artifact):
    """Padding does not reach the unpickler, but it is still unaccounted bytes.

    `pickle.load` stops at STOP, so zero padding after it never executes and
    failing an artifact over it would be noise. Saying nothing at all was the
    problem: the report read as "the whole file was analysed", which was true
    only by accident.
    """
    import pickle

    path = write_artifact("padded.pkl", pickle.dumps({"w": [1.0]}, protocol=4) + b"\x00" * 32)

    report = inspect_artifact(path)
    padding = [f for f in report.findings if f.rule_id == "ACT-PKL-012"]

    assert report.verdict is Verdict.PASS, "padding is not a failure"
    assert padding and padding[0].evidence["padding_bytes"] == 32


def test_a_stream_past_the_concatenation_budget_cannot_reach_pass(write_artifact):
    """Falling out of the stream budget in silence was a clean PASS, exit 0.

    `_scan_trailing_streams` walks at most `MAX_CONCATENATED_STREAMS` pickles
    after the first, and when it ran out it simply left the loop: no finding,
    `truncated` never set, `fully_read` still True. The `MAX_OPCODES` path a
    few lines above had exactly this guard and this one did not.

    The artifact below is what a hostile review built out of that. The torch
    legacy magic number buys the exemption that suppresses ACT-PKL-010 on the
    following streams, eight one-byte pickles exhaust the budget, and the
    gadget is stream nine: 115 bytes, empty findings list, `max_severity`
    None, PASS with exit 0, and `os.system` runs in any consumer that loads
    more than one object from the stream.
    """
    import pickle

    from actaira.formats.pickle_scan import TORCH_LEGACY_MAGIC

    blob = (
        pickle.dumps(TORCH_LEGACY_MAGIC, protocol=2)
        + pickle.dumps(1, protocol=2) * 8
        + corpus_build.craft_reduce("posix", "system", ("id",), 2)
    )
    path = write_artifact("budget.pt", blob)

    for policy in ("strict", "known-bad"):
        report = inspect_artifact(path, scan_policy=policy)
        assert "ACT-PKL-013" in {finding.rule_id for finding in report.findings}
        assert report.metadata["fully_read"] is False, "unread bytes are not a read artifact"
        assert report.verdict is Verdict.FAIL, f"policy {policy} must not pass this"


def test_a_nested_loader_called_with_a_mark_tuple_is_still_followed(write_artifact):
    """A pickler emits `MARK ... TUPLE` for more than three arguments.

    The abstract stack read `stack_before` as if every entry sat above the
    mark, so for `TUPLE` it popped one item as a fixed operand and discarded
    the rest of the slice: a four-argument call arrived as a one-element
    tuple holding only the last argument. Putting the payload anywhere but
    last therefore hid it from the nested-loader check.
    """
    import struct

    def short_unicode(text: str) -> bytes:
        raw = text.encode()
        return b"\x8c" + bytes([len(raw)]) + raw

    inner = corpus_build.craft_reduce("posix", "system", ("id",), 2)
    blob = (
        b"\x80\x04"
        + short_unicode("torch.storage") + short_unicode("_load_from_bytes") + b"\x93"
        + b"(" + b"B" + struct.pack("<I", len(inner)) + inner
        + short_unicode("a") + short_unicode("b") + short_unicode("c")
        + b"t" + b"R" + b"."
    )
    report = inspect_artifact(write_artifact("mark4.pt", blob))
    ids = {finding.rule_id for finding in report.findings}

    assert "ACT-PKL-011" in ids
    assert "ACT-PKL-002" in ids, "the payload was not the last argument, and it is still found"
    assert report.verdict is Verdict.FAIL


def test_inst_imports_are_judged_like_any_other_import(write_artifact):
    """Twenty-seven bytes of protocol 0 that ran a denylisted callable.

    `INST` carries `module\nname` inline exactly as `GLOBAL` does and reaches
    `find_class` at load time exactly as `GLOBAL` does, but it lived only in
    `EXECUTION_OPCODES`, where it was counted and never judged. The design
    note at the top of `pickle_scan.py` enumerates the import primitives and
    forgot this one, so `(S'echo PWNED'\nios\nsystem\n.` passed under both
    policies with a single INFO line.
    """
    path = write_artifact("inst.pkl", b"(S'echo PWNED'\nios\nsystem\n.")

    for policy in ("strict", "known-bad"):
        report = inspect_artifact(path, scan_policy=policy)
        assert report.verdict is Verdict.FAIL, f"policy {policy} must not pass this"
        assert "ACT-PKL-002" in {finding.rule_id for finding in report.findings}
        assert "os.system" in report.imported_callables


def test_inst_inside_a_checkpoint_is_caught_too(write_artifact):
    """The same gadget one level down, where a real one would be."""
    path = write_artifact(
        "inst.pt",
        zip_bytes([("archive/data.pkl", b"(S'id'\nios\nsystem\n."), ("archive/data/0", b"\x00" * 32)]),
    )

    report = inspect_artifact(path)

    assert report.verdict is Verdict.FAIL
    assert "os.system" in report.imported_callables


def test_a_tail_the_walker_could_not_measure_is_reported(write_artifact):
    """The legacy exemption plus a genops-versus-pickle divergence.

    Real `pickle` reads `I\x00\n.` as the integer 0 followed by STOP;
    `pickletools.genops` raises on it. So the walker could not compute the
    stream's length, gave up, and returned in silence, while the parse error
    that would have shown it was suppressed by the torch legacy exemption. A
    48-byte file with an `os.system` gadget behind that divergence reached
    PASS with exit 0, and a repeated-load consumer ran it.

    The exemption is now bounded by position: `torch._legacy_save` writes five
    pickles and then the raw storages, so a parse error before the sixth
    stream is a parse error and not the storage region.
    """
    import pickle

    from actaira.formats.pickle_scan import TORCH_LEGACY_MAGIC

    blob = (
        pickle.dumps(TORCH_LEGACY_MAGIC, protocol=2)
        + b"I\x00\n."
        + corpus_build.craft_reduce("os", "system", ("id",), 0)
    )
    report = inspect_artifact(write_artifact("divergent.pt", blob))
    ids = {finding.rule_id for finding in report.findings}

    assert "ACT-PKL-013" in ids, "the unread tail is reported"
    assert report.metadata["fully_read"] is False
    assert report.verdict is Verdict.FAIL


def test_an_oversized_member_is_not_decompressed_into_memory(write_artifact, monkeypatch):
    """`ZipFile.read` has no size limit, so a 400 KiB archive holding a 400 MiB
    member made the inspector allocate 400 MiB. Measured with RSS during a
    hostile review. The cap is lowered here so the test stays fast."""
    monkeypatch.setattr(archive, "MAX_MEMBER_BYTES", 4096)
    path = write_artifact(
        "big.pt", zip_bytes([("archive/data.pkl", b"\x80\x02}." + b"\x00" * 100_000)])
    )

    findings, _metadata, _imported = archive.inspect(path)

    assert "ACT-ZIP-006" in {finding.rule_id for finding in findings}
    assert inspect_artifact(path).verdict is Verdict.FAIL


# ---------------------------------------------------------------------------
# Members the name gate never opened
#
# The gate decides which members are disassembled. Everything it rejects was
# absent from the report entirely - no rule, no metadata - so an archive whose
# one inspected member was clean reached PASS with `fully_read: true` beside
# it, while the storage blobs, the version marker and anything a repackager
# had renamed were never opened at all.
# ---------------------------------------------------------------------------

def test_members_left_undecompressed_are_named_and_say_what_they_limit(write_artifact):
    path = write_artifact(
        "checkpoint.pt",
        zip_bytes(
            [
                ("archive/data.pkl", CLEAN_STATE_DICT),
                ("archive/data/0", b"\x00" * 256),
                ("archive/data/1", b"\x00" * 256),
                ("archive/version", b"3\n"),
            ]
        ),
    )

    report = inspect_artifact(path)
    finding = next(f for f in report.findings if f.rule_id == "ACT-ZIP-007")

    assert finding.evidence["members"] == ["archive/data/0", "archive/data/1", "archive/version"]
    assert finding.evidence["count"] == 3
    assert report.metadata["members_not_inspected"] == finding.evidence["members"]
    # The rule names what was not decompressed and says which surface that
    # limits. It does not touch `fully_read`, because every surface the tool
    # undertook to read was read: this is scope, not a gap.
    assert finding.evidence["limits_surface"] == "raw_tensor_content"
    assert finding.evidence["classified_by"] == "content"
    assert report.metadata["fully_read"] is True
    assert report.verdict is Verdict.PASS


def test_an_archive_whose_every_member_was_opened_says_nothing(write_artifact):
    """Negative control. The rule is a statement about what was skipped, so an
    archive with nothing skipped must not carry it - otherwise it is noise
    rather than information."""
    path = write_artifact("all-pickles.pt", zip_bytes([("archive/data.pkl", CLEAN_STATE_DICT)]))

    report = inspect_artifact(path)

    assert "ACT-ZIP-007" not in report_rules(report)
    assert "members_not_inspected" not in report.metadata
    assert report.metadata["fully_read"] is True
    assert report.verdict is Verdict.PASS


def test_the_skipped_member_note_never_fails_an_artifact_on_its_own(write_artifact):
    """Severity is INFO on purpose: at anything higher `--fail-on=low` would
    fail every checkpoint that exists, which is how a scope note becomes a
    reason to turn the tool off."""
    path = write_artifact(
        "checkpoint.pt",
        zip_bytes([("archive/data.pkl", CLEAN_STATE_DICT), ("archive/version", b"3\n")]),
    )

    for threshold in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        report = inspect_artifact(path, fail_on=threshold)
        assert report.verdict is Verdict.PASS, threshold
        assert report.max_severity is Severity.INFO


def test_the_names_in_the_evidence_are_capped_but_the_count_is_not(write_artifact):
    """A 600-shard checkpoint must not put 600 strings into every report,
    SARIF document and signed attestation that mentions it."""
    members = [("archive/data.pkl", CLEAN_STATE_DICT)]
    members += [(f"archive/data/{index}", b"\x00" * 8) for index in range(120)]
    path = write_artifact("sharded.pt", zip_bytes(members))

    finding = next(f for f in inspect_artifact(path).findings if f.rule_id == "ACT-ZIP-007")

    assert finding.evidence["count"] == 120
    assert len(finding.evidence["members"]) == archive.MAX_NAMES_IN_EVIDENCE


def test_the_rule_limits_raw_tensor_content_and_nothing_else():
    """The classification is the fix, and it is the classification that changed.

    ACT-ZIP-007 used to sit in a flat `UNREAD_RULE_IDS` set that drove one
    global `fully_read` boolean, so "I did not decompress 3.9 GB of float32"
    produced the same verdict as "the header is truncated". It fires on every
    checkpoint ever written, so every checkpoint was INCONCLUSIVE and exited
    3, and teams answered with `--allow-inconclusive` everywhere - which also
    hid the artifacts that genuinely would not parse.

    Now it names a surface. Raw tensor content was never in scope, so the
    rule cannot lower the execution verdict, and a rule that IS about the
    execution surface still can.
    """
    from actaira.coverage import CoverageState, Surface, rule_effect
    from actaira.inspect import UNREAD_RULE_IDS

    surface, state, _ = rule_effect("ACT-ZIP-007")
    assert surface is Surface.RAW_TENSOR_CONTENT
    assert state is CoverageState.NOT_ASSESSED
    assert "ACT-ZIP-007" not in UNREAD_RULE_IDS

    # The contrast that makes the point: a member that would not open is
    # unknown content, which does limit the execution surface.
    surface, state, _ = rule_effect("ACT-ZIP-009")
    assert surface is Surface.LOAD_TIME_EXECUTION
    assert state is CoverageState.PARTIAL
    assert "ACT-ZIP-009" in UNREAD_RULE_IDS


# --------------------------------------------------------------------------
# Content-first member classification (D-102). These are the tests for the
# defect the name gate carried from the first release to 2.0.0.
# --------------------------------------------------------------------------


def test_a_pickle_under_a_raw_storage_name_is_opened_and_reported(write_artifact):
    """The defect this change exists to close, stated as a test.

    `archive/data/0` is what PyTorch calls a raw storage blob, so every
    version of this tool up to 2.0.0 declined to open it. A payload placed
    there produced no pickle finding, no imported callable and nothing about
    `posix.system`: the artifact came back INCONCLUSIVE with a scope note,
    which is what a normal checkpoint also came back with, so there was
    nothing to distinguish them.
    """
    gadget = corpus_build.craft_reduce("posix", "system", ("id",), 2)
    path = write_artifact(
        "evasion.pt",
        zip_bytes(
            [
                ("archive/data.pkl", CLEAN_STATE_DICT),  # the decoy a name gate opens
                ("archive/data/0", gadget),              # the payload it never did
                ("archive/version", b"3\n"),
            ]
        ),
    )

    report = inspect_artifact(path)

    assert "ACT-ZIP-008" in report_rules(report), "the name/content disagreement is itself a finding"
    assert "posix.system" in report.imported_callables
    assert report.verdict is Verdict.FAIL
    finding = next(f for f in report.findings if f.rule_id == "ACT-ZIP-008")
    assert finding.severity is Severity.HIGH
    assert finding.evidence["member"] == "archive/data/0"


def test_a_blob_whose_first_byte_is_an_opcode_is_still_data(write_artifact):
    """Negative control, and the reason the gate counts opcodes.

    Roughly a quarter of arbitrary bytes are valid pickle opcodes, so a
    single-byte test would send a quarter of every checkpoint's shards to the
    full scanner - gigabytes of decompression to prove they were floats. Four
    consecutive opcodes is the bar, and a real pickle clears it in its header.
    """
    import struct

    # 0x28 is MARK, a perfectly valid first opcode, followed by float bytes.
    blob = b"\x28" + struct.pack("<256f", *([0.5] * 256))
    path = write_artifact("floats.pt", zip_bytes([("archive/data.pkl", CLEAN_STATE_DICT), ("archive/data/0", blob)]))

    report = inspect_artifact(path)

    assert "ACT-ZIP-008" not in report_rules(report), "a float buffer is not a bypass"
    assert report.verdict is Verdict.PASS
    assert "archive/data/0" in report.metadata["members_not_inspected"]


def test_a_member_whose_head_will_not_decompress_is_unknown_not_data(write_artifact):
    """Unknown content is an execution-surface gap, not tensor data.

    The distinction is the whole reason ACT-ZIP-009 is a separate rule. A
    member that will not open could have been anything, including a pickle,
    so filing it with the storage blobs would be claiming coverage the tool
    does not have.
    """
    # Stored, not deflated, so flipping the method field below leaves bytes
    # that are not a deflate stream where the reader expects one.
    raw = bytearray(
        zip_bytes(
            [("archive/data.pkl", CLEAN_STATE_DICT), ("archive/data/0", b"\x00" * 64)],
            compression=zipfile.ZIP_STORED,
        )
    )
    marker = b"archive/data/0"
    for index in range(len(raw) - len(marker)):
        if raw[index : index + len(marker)] != marker:
            continue
        for back, signature in ((30, b"PK\x03\x04"), (46, b"PK\x01\x02")):
            start = index - back
            if start >= 0 and raw[start : start + 4] == signature:
                offset = start + (8 if signature == b"PK\x03\x04" else 10)
                raw[offset : offset + 2] = (8).to_bytes(2, "little")
    path = write_artifact("broken-member.pt", bytes(raw))

    report = inspect_artifact(path)

    assert "ACT-ZIP-009" in report_rules(report)
    assert report.coverage.state(Surface.LOAD_TIME_EXECUTION) is CoverageState.PARTIAL
    assert report.verdict is Verdict.INCONCLUSIVE
    assert report.metadata["members_unreadable"] == ["archive/data/0"]


def test_the_peek_never_decompresses_more_than_its_budget(write_artifact):
    """The cost bound, asserted rather than assumed.

    If classifying a member read the member, this change would have traded a
    name-based bypass for decompressing every shard of every checkpoint. The
    gate reads a fixed prefix; a 4 MiB blob is classified from 64 KiB of it.
    """
    assert archive.MEMBER_PEEK_BYTES == 64 * 1024
    blob = b"\x28" + b"\x00" * (4 * 1024 * 1024)
    path = write_artifact("big.pt", zip_bytes([("archive/data.pkl", CLEAN_STATE_DICT), ("archive/data/0", blob)]))

    reads: list[int] = []
    real_open = zipfile.ZipFile.open

    def counting_open(self, name, *args, **kwargs):
        handle = real_open(self, name, *args, **kwargs)
        real_read = handle.read

        def watched(size=-1):
            payload = real_read(size)
            if getattr(name, "filename", name) == "archive/data/0":
                reads.append(len(payload))
            return payload

        handle.read = watched  # type: ignore[method-assign]
        return handle

    zipfile.ZipFile.open = counting_open  # type: ignore[method-assign]
    try:
        inspect_artifact(path)
    finally:
        zipfile.ZipFile.open = real_open  # type: ignore[method-assign]

    assert reads, "the member was classified, so its head was read"
    assert max(reads) <= archive.MEMBER_PEEK_BYTES, reads
