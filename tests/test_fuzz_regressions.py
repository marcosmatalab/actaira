"""Every input that broke a parser, and what it broke.

These came out of `fuzz/fuzz_targets.py`. The property being fuzzed is the
one the product promises, in four parts: for ANY byte sequence,
`inspect_artifact` must terminate, must not raise, must not consume memory
without bound, and must never answer `Verdict.PASS` for an artifact it could
not fully read.

Each test below names one violation, the input that produced it reduced to
the bytes that still reproduce it, and why the code was wrong. The inputs
live in `fuzz/corpus/` as raw bytes so the fuzzer can replay them as a
regression corpus and the test suite can assert on the same files; see
`fuzz/README.md` for the run that produced them.

Nothing here asserts "does not crash" and stops. A parser that has to refuse
an artifact must refuse it with a finding, and the finding has to be one that
keeps the artifact away from PASS, so every test checks the rule id and the
verdict as well.
"""
from __future__ import annotations

import json
import pickle
import struct

import pytest

from actaira.coverage import CoverageState, Surface
from actaira.formats import gguf, keras_h5, npy, onnx, safetensors
from actaira.formats.gguf import MAX_ARRAY_DEPTH
from actaira.formats.pickle_scan import MAX_OPCODES, scan_pickle_bytes
from actaira.formats.shape import MAX_DIM, MAX_RANK, ShapeOutOfRangeError, element_count
from actaira.inspect import UNREAD_RULE_IDS, inspect_artifact
from actaira.model import Verdict, canonical_json
from conftest import CORPUS_DIR as EVAL_CORPUS_DIR
from conftest import REPO_ROOT, _load_module_by_path

CORPUS_DIR = REPO_ROOT / "fuzz" / "corpus"


def corpus(name: str) -> bytes:
    path = CORPUS_DIR / name
    assert path.exists(), f"{path} is part of the regression corpus and must not be deleted"
    return path.read_bytes()


def rules(report) -> set[str]:
    return {finding.rule_id for finding in report.findings}


# ---------------------------------------------------------------------------
# The property itself, over the whole saved corpus
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(path.name for path in CORPUS_DIR.glob("*.bin")))
def test_every_saved_fuzz_input_satisfies_the_property(name, write_artifact):
    """The four promises, asserted together on every input that once broke one.

    This is the test that generalises: a future refactor that reopens any of
    these holes fails here even if it changes which rule fires.
    """
    report = inspect_artifact(write_artifact(name, corpus(name)))

    # (b), at the boundary every consumer of a report crosses.
    canonical_json(report.to_dict())

    # (b), inside the inspectors.
    assert report.inspector_errors == [], f"{name} still escapes an exception"

    # (d), in both directions: PASS requires that nothing said otherwise.
    if report.verdict is Verdict.PASS:
        assert report.metadata["fully_read"] is True
        assert not (rules(report) & UNREAD_RULE_IDS)
    if rules(report) & UNREAD_RULE_IDS:
        assert report.metadata["fully_read"] is False
        assert report.verdict is not Verdict.PASS


# ---------------------------------------------------------------------------
# (a) termination
# ---------------------------------------------------------------------------


def test_concatenated_empty_pickles_do_not_blow_up_exponentially(write_artifact):
    """`b"." * 20`: twenty concatenated empty pickles, each a bare STOP.

    `_scan_trailing_streams` called the full `scan_pickle_bytes` on the
    remainder after each STOP, and that call scanned ITS trailing streams,
    which scanned theirs. With a branching factor of
    `MAX_CONCATENATED_STREAMS` the work grew as 2**n in the number of
    concatenated streams, and every level allocated its own copy of the tail
    and its own findings: 24 bytes took 73 seconds and built 8.1 million
    Finding objects, so this was a hang and an unbounded allocation from one
    input. The fix walks the concatenation forwards, scanning each stream
    exactly once.

    Detection is what must survive the fix, so the second half of the test
    puts a real gadget in the last stream.
    """
    payload = corpus("pickle-concat-quadratic.bin")
    assert payload == b"." * 20

    result = scan_pickle_bytes(payload, "dots.pkl", "strict")

    # 8 trailing streams at the cap, one ACT-PKL-010 each, then ACT-PKL-013
    # for the eleven streams past the cap that were never disassembled. The
    # exponential version produced 513 029 findings for this input.
    assert [f.rule_id for f in result.findings] == ["ACT-PKL-010"] * 8 + ["ACT-PKL-013"]
    assert result.truncated, "bytes past the budget mean the artifact was not read"
    assert inspect_artifact(write_artifact("dots.pkl", payload)).verdict is Verdict.FAIL


def test_a_gadget_in_a_trailing_stream_is_still_found():
    """The fix must not cost the detection the recursion was there for."""
    report = inspect_artifact(EVAL_CORPUS_DIR / "regression_concatenated.pkl")

    assert {"ACT-PKL-010", "ACT-PKL-002"} <= rules(report)
    assert report.verdict is Verdict.FAIL


def test_a_packed_dims_field_cannot_be_multiplied_out_forever(write_artifact):
    """3 KB of maximal varints in a TensorProto `dims` field.

    `_read_tensor` multiplied every dimension it read, with nothing bounding
    the count or the magnitude, so the cost grew with the square of the
    input: 200 KiB of packed dims spent 1.5 s building a single
    1 400 000-bit integer. `dims` is int64 in the ONNX schema, so a reader
    that honours the schema cannot be asked to do this.
    """
    path = write_artifact("dims.onnx", corpus("onnx-packed-dims-overflow.bin"))

    findings, tensors, _metadata = onnx.inspect(path)

    assert [f.rule_id for f in findings] == ["ACT-ONX-003"]
    assert tensors == [], "a shape this reader refuses must not be described anyway"
    assert inspect_artifact(path).verdict is Verdict.INCONCLUSIVE


def test_gguf_arrays_may_not_nest_without_bound(write_artifact):
    """Twelve bytes per level buys one level of `_Reader.value` recursion.

    The recursion was ended by RecursionError, which the inspector caught and
    turned into a finding, so the artifact was never mis-reported. It was
    still the interpreter's stack limit doing the bounding rather than the
    reader, and a RecursionError that deep leaves very little stack for the
    handler. The depth is now the reader's own decision.
    """
    path = write_artifact("nested.gguf", corpus("gguf-nested-array-depth.bin"))

    findings, _tensors, _metadata = gguf.inspect(path)

    assert [f.rule_id for f in findings] == ["ACT-GGF-001"]
    assert str(MAX_ARRAY_DEPTH) in findings[0].evidence["reason"]
    assert inspect_artifact(path).verdict is Verdict.INCONCLUSIVE


# ---------------------------------------------------------------------------
# (b) no uncaught exception
# ---------------------------------------------------------------------------


def test_a_file_that_is_only_the_npy_magic_is_reported_not_raised(write_artifact):
    """Six bytes. `major = handle.read(1)[0]` raised IndexError at EOF.

    `inspect_artifact` caught it at its own boundary and answered
    INCONCLUSIVE, so the four-part property held for the orchestrator, but
    the inspector itself crashed on a six-byte file and said nothing about
    why. A truncated file has a finding for exactly this.
    """
    path = write_artifact("stub.npy", corpus("npy-magic-only.bin"))

    findings, tensors, _metadata, _imported = npy.inspect(path)

    assert [f.rule_id for f in findings] == ["ACT-NPY-002"]
    assert findings[0].evidence["reason"] == "version_truncated"
    assert tensors == []
    assert inspect_artifact(path).inspector_errors == []


@pytest.mark.parametrize(
    ("name", "reason_prefix"),
    [
        ("npy-header-not-a-dict.bin", "header_not_a_dict"),
        ("npy-shape-not-a-sequence.bin", "shape_not_a_sequence"),
    ],
    ids=["header-is-an-int", "shape-is-an-int"],
)
def test_the_npy_header_is_a_literal_not_a_promise(name, reason_prefix, write_artifact):
    """`literal_eval` returns whatever the header said, which is any literal.

    The reader then did `header.get(...)`, `list(header["shape"])` and
    `int(dim)` on it. A header of `1` gave `.get` an int, a shape of `5` gave
    `list()` an int and a dimension of `'a'` gave `int()` a string: three
    uncaught exceptions, each from a one-byte edit to a valid file.
    """
    path = write_artifact("odd.npy", corpus(name))

    findings, tensors, _metadata, _imported = npy.inspect(path)

    assert [f.rule_id for f in findings] == ["ACT-NPY-002"]
    assert findings[0].evidence["reason"].startswith(reason_prefix)
    assert tensors == []


def test_class_names_are_collected_without_borrowing_the_callers_stack():
    """`_collect_class_names` recursed once per level of the parsed config.

    `json.loads` guards its own depth, but that is a different budget from
    the one this walk spends: a config that parses from a shallow stack can
    still overflow the walk when `inspect_artifact` is called from a deep one
    (the web server, a test runner). Fifty thousand levels is far past
    anything a recursive version survives, which is the point.
    """
    node = {"class_name": "Lambda"}
    for _ in range(50_000):
        node = {"config": node}

    assert keras_h5._collect_class_names(node) == ["Lambda"]


# ---------------------------------------------------------------------------
# (b) at the report boundary: a report that cannot be serialised
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["onnx-wire-type-confusion.bin", "onnx-model-version-not-varint.bin"],
    ids=["ir-version-as-fixed32", "model-version-as-length-delimited"],
)
def test_protobuf_wire_type_confusion_cannot_put_bytes_in_the_report(name, write_artifact):
    """One byte, `b"\\r"`: field 1, wire type 5.

    `metadata["ir_version"] = payload` trusted the field number and ignored
    the wire type, so a hostile file could hand the report a raw `bytes`
    slice (wire types 1 and 5) or an `int` where a string was expected. The
    report then failed `json.dumps`, which is the only thing anything ever
    does with a report: `actaira scan --json`, the ML-BOM and the attestation
    all died on a one-byte file. Reported as a malformed protobuf now, which
    is what it is.
    """
    path = write_artifact("confused.onnx", corpus(name))

    findings, _tensors, metadata = onnx.inspect(path)

    assert [f.rule_id for f in findings] == ["ACT-ONX-003"]
    assert all(not isinstance(value, bytes) for value in metadata.values())
    canonical_json(inspect_artifact(path).to_dict())


def test_a_non_finite_gguf_metadata_float_is_a_malformed_file(write_artifact):
    """One flipped exponent byte in a float32 key/value.

    `canonical_json` sets `allow_nan=False` on purpose, because NaN
    serialises to a token no third-party verifier accepts and the whole
    attestation rests on that JSON being standard. A NaN in the metadata
    block therefore produced a report that could not be written down at all.
    Roughly one exponent pattern in 256 is non-finite, so this is a byte flip
    away from any real GGUF file.
    """
    path = write_artifact("nan.gguf", corpus("gguf-non-finite-float.bin"))

    report = inspect_artifact(path)

    assert "ACT-GGF-001" in rules(report)
    assert "non-finite" in report.findings[0].evidence["reason"]
    assert report.verdict is Verdict.INCONCLUSIVE
    canonical_json(report.to_dict())


def test_a_shape_whose_product_cannot_be_printed_is_refused(write_artifact):
    """250 twenty-digit dimensions in a safetensors header, 5.8 KB of JSON.

    JSON integers have no width, so the product of a declared shape has no
    width either. CPython refuses to render an integer wider than 4300
    decimal digits (`sys.set_int_max_str_digits`), so `json.dumps` on the
    finished report raised ValueError - after the inspector had reported the
    file as read. Every dimension in every format here is stored in 64 bits;
    `shape.element_count` holds them to it.
    """
    path = write_artifact("huge.safetensors", corpus("safetensors-shape-product-unprintable.bin"))

    findings, tensors, _metadata = safetensors.inspect(path)

    assert [f.rule_id for f in findings] == ["ACT-STF-007"]
    assert findings[0].evidence["reason"].startswith("bad_shape:w:")
    assert tensors == []
    canonical_json(inspect_artifact(path).to_dict())


def test_element_count_refuses_only_shapes_no_file_can_hold():
    """The bound is the format's, not a number picked to make a test pass."""
    assert element_count([2, 3, 4]) == 24
    assert element_count([]) == 1
    assert element_count([MAX_DIM]) == MAX_DIM
    assert element_count([0, MAX_DIM]) == 0

    with pytest.raises(ShapeOutOfRangeError):
        element_count([MAX_DIM + 1])
    with pytest.raises(ShapeOutOfRangeError):
        element_count([2] * (MAX_RANK + 1))
    with pytest.raises(ShapeOutOfRangeError):
        element_count([-1])
    with pytest.raises(ShapeOutOfRangeError):
        element_count(["4"])

    # The reason the bounds are where they are: the widest count they admit
    # still prints, and printing is what the report does with it.
    widest = element_count([MAX_DIM] * MAX_RANK)
    assert len(str(widest)) < 4300


# ---------------------------------------------------------------------------
# (c) bounded memory
# ---------------------------------------------------------------------------


def test_the_npy_header_length_is_checked_against_the_file_not_trusted(write_artifact):
    """Twelve bytes declaring a 1.6 GB header.

    `header_len` is four attacker-chosen bytes in .npy version 2 and 3, and
    `handle.read(n)` allocates `n` up front, so this file made the inspector
    ask for 1.6 GB (and 4 GiB at 0xFFFFFFFF) before discovering there was
    nothing to read. Under a 1 GiB address-space cap it raised MemoryError
    from a twelve-byte input. The file cannot hold more header than it has
    bytes left, and that is already the malformed case.
    """
    payload = corpus("npy-header-length-unbounded.bin")
    assert len(payload) == 12
    assert int.from_bytes(payload[8:12], "little") > 1_000_000_000

    path = write_artifact("huge.npy", payload)
    findings, _tensors, _metadata, _imported = npy.inspect(path)

    assert [f.rule_id for f in findings] == ["ACT-NPY-002"]
    assert findings[0].evidence["reason"] == "header_truncated"


# ---------------------------------------------------------------------------
# (d) never PASS on something that was not fully read
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected_rule"),
    [
        ("npy-truncated-reached-pass.bin", "ACT-NPY-002"),
        ("safetensors-bad-header-reached-pass.bin", "ACT-STF-007"),
        ("zip-member-pickle-unparseable.bin", "ACT-PKL-006"),
    ],
    ids=["truncated-npy", "unparseable-safetensors-header", "unparseable-pickle-inside-a-zip"],
)
def test_an_artifact_that_reported_itself_unread_cannot_reach_pass(name, expected_rule, write_artifact):
    """D-04, applied to the three branches that were still getting it wrong.

    `tests/test_formats.py` already pins this for the zip and ONNX branches,
    and the comments in `inspect.py` record it being fixed there twice. The
    NumPy and safetensors branches never derived `fully_read` at all, and the
    zip branch derived it only from ZIP rules, so a pickle member that would
    not disassemble was reported (ACT-PKL-006, MEDIUM) and passed anyway.

    All three artifacts state, in their own findings, that they were not
    read. `inspect_artifact` now derives `fully_read` from that fact in one
    place instead of once per branch.
    """
    report = inspect_artifact(write_artifact(name, corpus(name)))

    assert expected_rule in rules(report), "the inspector did not notice at all"
    assert expected_rule in UNREAD_RULE_IDS
    assert report.metadata["fully_read"] is False
    assert report.verdict is not Verdict.PASS


def test_hitting_the_opcode_budget_leaves_the_stream_unread(write_artifact):
    """A stream past `MAX_OPCODES` stops being disassembled where the bound is.

    ACT-PKL-008 is MEDIUM, which on its own does not fail an artifact, and
    the scan did not set `truncated`, so `inspect_artifact` called the file
    fully read and answered PASS. Everything after opcode two million was
    never looked at, which is where a gadget would go. Built from a real
    stream rather than a patched constant, so the bound under test is the one
    that ships.
    """
    flood = pickle.dumps(list(range(MAX_OPCODES + 100)), protocol=2)

    result = scan_pickle_bytes(flood, "flood.pkl", "strict")
    assert [f.rule_id for f in result.findings] == ["ACT-PKL-008"]
    assert result.truncated is True
    assert result.parse_error is None, "it stopped on the budget, not on a parse error"

    report = inspect_artifact(write_artifact("flood.pkl", flood))
    assert report.metadata["fully_read"] is False
    assert report.verdict is Verdict.INCONCLUSIVE


def test_a_keras_file_scanned_only_up_to_the_cap_is_not_fully_read(write_artifact, monkeypatch):
    """`MAX_SCAN_BYTES` bounds the scan; nothing bounded the conclusion.

    The module already recorded `metadata["truncated_scan"]`, and then
    returned `True` for "config was read" regardless, so a file larger than
    the cap reached PASS on the strength of the first 256 MiB. A second
    `model_config` in the tail - a Lambda layer, say - was never scanned. The
    cap is patched down here rather than writing a 256 MiB fixture; the
    branch under test is the same one.
    """
    config = json.dumps({"class_name": "Sequential", "keras_version": "2.15.0", "config": {}}).encode()
    head = keras_h5.MAGIC + b"\x00" * 8 + config
    # The cap falls exactly after the config, so the config itself is found and
    # parsed and the only thing wrong is that 4 KiB of the file went unread.
    monkeypatch.setattr(keras_h5, "MAX_SCAN_BYTES", len(head))
    payload = head + b"\x00" * 4096

    path = write_artifact("big.h5", payload)
    findings, metadata, config_read = keras_h5.inspect(path)

    assert metadata["truncated_scan"] is True
    assert config_read is False, "a scan that stopped at the cap did not read the file"
    assert findings == []

    report = inspect_artifact(path)
    assert report.metadata["fully_read"] is False
    assert report.verdict is Verdict.INCONCLUSIVE


def test_the_unread_rule_set_covers_every_rule_that_means_unread():
    """`UNREAD_RULE_IDS` is the single place the property is decided.

    The same bug - a branch that forgot to feed its own "I could not read
    this" finding into `fully_read` - was fixed three times and shipped a
    fourth. This asserts the set stays in the catalogue rather than drifting
    into a name nothing produces.
    """
    from actaira.i18n.catalog import Catalog

    for lang in ("en", "es"):
        catalogue = Catalog(lang)
        for rule_id in sorted(UNREAD_RULE_IDS):
            assert catalogue.rule(rule_id) != rule_id, f"{rule_id} has no {lang} catalogue entry"


def test_a_well_formed_artifact_still_passes():
    """The bound on all of this: none of it may turn a clean file inconclusive.

    The checkpoint is still listed separately, because it is the case where
    the distinction lives: its storage blobs are classified by content and
    then left undecompressed, ACT-ZIP-007 says so, and that limits raw tensor
    content only. Every surface the tool undertook to read was read, so it
    passes like the rest.
    """
    for name in ("benign_model.safetensors", "benign_model.onnx", "benign_model.gguf",
                 "benign_array.npy", "benign_model.h5"):
        report = inspect_artifact(EVAL_CORPUS_DIR / name)
        assert report.verdict is Verdict.PASS, f"{name}: {rules(report)}"
        assert report.metadata["fully_read"] is True

    checkpoint = inspect_artifact(EVAL_CORPUS_DIR / "benign_checkpoint.pt")
    assert checkpoint.max_severity.value in ("info", "low"), rules(checkpoint)
    assert "ACT-ZIP-007" in rules(checkpoint)
    assert checkpoint.verdict is Verdict.PASS
    assert checkpoint.metadata["fully_read"] is True
    assert checkpoint.coverage.state(Surface.LOAD_TIME_EXECUTION) is CoverageState.COMPLETE
    assert checkpoint.coverage.state(Surface.RAW_TENSOR_CONTENT) is CoverageState.NOT_ASSESSED


def test_safetensors_still_describes_a_shape_it_can_hold(write_artifact):
    """`element_count` must not have made ordinary headers malformed."""
    header = {"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}}
    blob = json.dumps(header).encode()
    path = write_artifact("ok.safetensors", struct.pack("<Q", len(blob)) + blob + b"\x00" * 64)

    findings, tensors, _metadata = safetensors.inspect(path)

    assert findings == []
    assert [t.n_elements for t in tensors] == [16]


# ---------------------------------------------------------------------------
# The fuzzer's own oracle, and the two ways it was lying
#
# A fuzzer is a measuring instrument. These check the instrument: that it
# knows every rule the product can emit, that its soundness oracle can fail
# without the report first admitting something, and that a run reports the
# cases it ran rather than the cases it was asked for.
# ---------------------------------------------------------------------------

fuzz_targets = _load_module_by_path("actaira_fuzz_targets", REPO_ROOT / "fuzz" / "fuzz_targets.py")


def test_the_fuzzer_uses_the_products_unread_rule_list_and_not_a_copy():
    """It held a copy, and the copy had drifted: ACT-PKL-013, the
    concatenated-stream budget, was missing from it. A fuzzer whose list is a
    strict subset of the product's cannot see a PASS next to a rule it has
    never heard of, and that is the only direction the divergence matters in.
    """
    assert fuzz_targets.UNREAD_RULE_IDS is UNREAD_RULE_IDS, "one list, not two"
    assert "ACT-PKL-013" in fuzz_targets.UNREAD_RULE_IDS


def test_the_coverage_oracle_catches_a_claim_the_report_does_not_admit_to(tmp_path, monkeypatch):
    """The oracle used to be circular: PASS implies `fully_read`, and PASS was
    derived from `fully_read`. This is the non-circular form - the claim is
    checked against the archive on disk, so a report that claims to have read
    an archive end to end while never accounting for a member is caught by
    what is in the zip.
    """
    import zipfile

    path = tmp_path / "checkpoint.pt"
    with zipfile.ZipFile(path, "w") as handle:
        handle.writestr("archive/data.pkl", pickle.dumps({"w": 1}, protocol=4))
        handle.writestr("archive/data/0", b"\x00" * 64)

    honest = inspect_artifact(path)
    fuzz_targets._check_report(honest, path)  # the real report passes the oracle

    # The report a pre-ACT-ZIP-007 inspector produced: fully_read, no mention
    # of `archive/data/0` anywhere.
    lying = inspect_artifact(path)
    lying.findings = [f for f in lying.findings if f.rule_id != "ACT-ZIP-007"]
    lying.metadata["fully_read"] = True
    lying.metadata.pop("members_not_inspected", None)

    with pytest.raises(fuzz_targets.PropertyViolationError) as raised:
        fuzz_targets._check_report(lying, path)

    assert raised.value.kind == "coverage"
    assert "archive/data/0" in raised.value.detail


def test_the_coverage_oracle_catches_a_report_that_describes_the_wrong_file(tmp_path):
    """The size is measured here, from the file, not taken from the report."""
    path = tmp_path / "clean.npy"
    path.write_bytes((EVAL_CORPUS_DIR / "benign_array.npy").read_bytes())
    report = inspect_artifact(path)
    report.size_bytes += 1

    with pytest.raises(fuzz_targets.PropertyViolationError) as raised:
        fuzz_targets._check_report(report, path)

    assert raised.value.kind == "coverage"


def test_a_run_publishes_the_cases_it_executed(tmp_path):
    """`iters` is the number on the command line. It was published as though
    it were a measurement, so a run whose worker died after twelve cases
    reported the full figure with zero findings and exit 0."""
    config = fuzz_targets.RunConfig(
        target="npy", seed=7, iters=40, timeout=5.0, memory_mb=1024,
        out_dir=tmp_path / "run", quiet=True,
    )

    summary = fuzz_targets.run_builtin(config)

    assert summary["iters"] == 40, "the budget is still reported"
    assert summary["executed"] == 40, "and so is what actually ran"
    assert summary["hard_failures"] == []


def test_a_worker_that_dies_without_leaving_state_is_a_hard_failure(tmp_path, monkeypatch):
    """It used to be a bare `break`: the run looked complete, published the
    full iteration count, found nothing and exited 0."""

    class _DeadWorker:
        returncode = -9

        def poll(self):
            return -9

        def wait(self):
            return -9

    monkeypatch.setattr(fuzz_targets.subprocess, "Popen", lambda *a, **k: _DeadWorker())
    config = fuzz_targets.RunConfig(
        target="npy", seed=7, iters=10, timeout=5.0, memory_mb=1024,
        out_dir=tmp_path / "run", quiet=True,
    )

    summary = fuzz_targets.run_builtin(config)

    assert summary["executed"] == 0
    assert [record["kind"] for record in summary["hard_failures"]] == ["worker-lost"]
    # It reaches the exit code through findings.jsonl, which is what _cmd_run reads.
    assert any(record["kind"] == "worker-lost" for record in summary["findings"])


def test_the_fuzzer_imports_on_a_platform_without_the_posix_facilities():
    """DEF-103. `resource` was imported at module scope, and it is POSIX-only.

    That import is why this whole file failed to collect on Windows: not one
    of the 41 tests here ran, the release gate compared the figure in
    `figures.json` against a smaller collected count, and the only thing that
    reported the problem was a number it could not explain.

    The module has to be importable everywhere it is read, which is everywhere
    the suite runs. What it must not do is keep quiet about the two promises
    those facilities were enforcing.
    """
    assert fuzz_targets.HAVE_RLIMIT is (fuzz_targets.resource is not None)
    assert isinstance(fuzz_targets.unenforced_oracles(), list)


def test_a_platform_that_cannot_enforce_an_oracle_says_so_in_the_summary(tmp_path, monkeypatch):
    """The other half of DEF-103, and the half that matters.

    Making the import conditional is what lets the fuzzer run on Windows.
    Running there with `RLIMIT_AS` and `SIGALRM` gone means two of the four
    promises are not being enforced at all, and a run that printed
    `0 property violation(s)` without saying which oracles were off would be
    reporting a weaker instrument's silence as the stronger one's result.
    Every summary carries the list, so `0 findings` is never readable without
    what it was measured with.
    """
    monkeypatch.setattr(fuzz_targets, "HAVE_RLIMIT", False)
    monkeypatch.setattr(fuzz_targets, "HAVE_RUSAGE", False)

    missing = fuzz_targets.unenforced_oracles()
    assert any("RLIMIT_AS" in line for line in missing)
    assert any("getrusage" in line for line in missing)

    config = fuzz_targets.RunConfig(
        target="npy", seed=7, iters=4, timeout=5.0, memory_mb=1024,
        out_dir=tmp_path / "run", quiet=True,
    )
    summary = fuzz_targets.run_builtin(config)

    assert summary["unenforced_oracles"] == missing, (
        "the summary reports what this platform could not enforce, not an empty list"
    )


def test_the_peak_rss_reading_does_not_invent_a_number_it_cannot_measure(monkeypatch):
    """Zero, not a guess. A fabricated baseline would make the high-water check
    fire or stay silent for reasons that have nothing to do with the parser,
    which is worse than an oracle that is openly switched off."""
    monkeypatch.setattr(fuzz_targets, "HAVE_RUSAGE", False)
    assert fuzz_targets._peak_rss_kib() == 0
