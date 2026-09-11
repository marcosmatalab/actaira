"""Artifacts written by the real serialisers, read back by Actaira.

Design note D-23, put under test. Every other file in this suite asserts on a
corpus this repository wrote byte by byte, which proves the inspectors agree
with `evals/corpus/build.py` and with nothing else. This file closes that
circle: the artifacts here come out of torch, safetensors, onnx and h5py, and
the assertions are that Actaira reads what those libraries actually wrote.

Two rules keep this from turning into a dependency:

  * every case is guarded by `pytest.importorskip`, per library, so the suite
    stays green on a machine with no ML stack at all. A project whose central
    claim is "you can inspect an artifact without installing the ecosystem
    that loads it" cannot have a test suite that requires torch.
  * nothing here loads an artifact. `torch.save` writes, `inspect_artifact`
    reads bytes. `real_trojan.pt` carries a working `os.system` reduction and
    is never unpickled, by this file or by anything it calls.

Where a real library can also be used as an oracle it is: the safetensors
shapes, the ONNX protobuf fields and the Keras layer names are compared
against what the writing library itself reads back, not only against literals.
Agreement between two independent readers is the property worth pinning;
the literals are kept alongside so that two readers agreeing on nothing
cannot pass.
"""
from __future__ import annotations

import importlib
import json
import os
import pickle
from pathlib import Path
from typing import Any

import pytest

from actaira.coverage import CoverageState, Surface
from actaira.formats.pickle_scan import TORCH_LEGACY_MAGIC
from actaira.inspect import inspect_artifact
from actaira.model import Severity, Verdict
from conftest import REPO_ROOT, _load_module_by_path, corpus_build

corpus_real = _load_module_by_path("actaira_corpus_real", REPO_ROOT / "evals" / "corpus" / "real.py")

# Which library has to be installed for each case to exist at all. The
# safetensors case needs torch too: its generator writes torch tensors.
# Parametrising by name (rather than by whatever the manifest happens to
# contain) means a case that silently stops being generated is a failure with
# a name on it, not a quietly shorter test run.
REQUIRED_LIBRARIES: dict[str, tuple[str, ...]] = {
    "real_state_dict.pt": ("torch",),
    "real_state_dict_legacy.pt": ("torch",),
    "real_full_module.pt": ("torch",),
    "real_trojan.pt": ("torch",),
    "real_model.safetensors": ("safetensors", "torch"),
    "real_model.onnx": ("onnx",),
    "real_custom_domain.onnx": ("onnx",),
    "real_keras.h5": ("h5py",),
    "real_keras_lambda.h5": ("h5py",),
}


class RealCorpus:
    """The generated directory plus the manifest the eval harness reads.

    Expectations are taken from `real_cases.json` on disk rather than from the
    objects `build()` returned, because the manifest is what
    `evals/benchmark.py` consumes. A manifest that disagrees with the case
    objects would be invisible to a test that only looked at the objects.
    """

    def __init__(self, directory: Path, manifest: list[dict[str, Any]]) -> None:
        self.directory = directory
        self.cases = {case["name"]: case for case in manifest}

    def case(self, name: str) -> dict[str, Any]:
        assert name in self.cases, f"{name} is missing from real_cases.json: {sorted(self.cases)}"
        return self.cases[name]

    def path(self, name: str) -> Path:
        return self.directory / name


@pytest.fixture(scope="session")
def real_corpus(tmp_path_factory: pytest.TempPathFactory) -> RealCorpus:
    """Build the real corpus once per session.

    Session scope is not an optimisation detail here: `torch.save` of even a
    tiny state_dict costs more than the whole synthetic corpus, and the ONNX
    and HDF5 writers pull in protobuf and libhdf5. Building it per test would
    make this file the slowest thing in the suite by two orders of magnitude.
    """
    directory = tmp_path_factory.mktemp("actaira-real")
    corpus_real.build(directory)
    manifest = json.loads((directory / "real_cases.json").read_text(encoding="utf-8"))
    return RealCorpus(directory, manifest)


# The nightly sets this. A guard that keeps the suite green on a bare machine
# also keeps it green when the ML stack IS present and nothing ran, and that
# second case is not a neutral outcome - it is a scheduled job that installed
# torch, reported 40 passed, and checked none of the formats it was scheduled
# for. Under this variable every skip below becomes a failure with the missing
# library named. It is off by default, because the ordinary suite must keep
# passing on a machine with no ML stack at all.
REQUIRE_REAL_STACK = os.environ.get("ACTAIRA_REQUIRE_REAL_STACK") == "1"


def require_libraries(name: str) -> None:
    for module in REQUIRED_LIBRARIES[name]:
        if REQUIRE_REAL_STACK and not installed(module):
            pytest.fail(
                f"{name} needs {module} and it is not importable. "
                "ACTAIRA_REQUIRE_REAL_STACK=1 says this run exists to exercise the real "
                "serialisers, so a skip here is the failure it was scheduled to catch."
            )
        pytest.importorskip(module, reason=f"{name} is written by {module}")


def installed(module: str) -> bool:
    """Whether a writer is available, decided the way the generator decides it.

    An import attempt, not `find_spec`: `evals/corpus/real.py` builds a case
    only when the module actually imports, so a half-installed library that
    has a spec and then raises would make the manifest and this table disagree
    for a reason that has nothing to do with the wiring under test.
    """
    try:
        importlib.import_module(module)
    except Exception:  # pragma: no cover - depends on what is installed
        return False
    return True


def rules(report) -> set[str]:
    return {finding.rule_id for finding in report.findings}


# ---------------------------------------------------------------------------
# The manifest itself
# ---------------------------------------------------------------------------

def test_the_manifest_lists_exactly_the_cases_this_file_pins(real_corpus):
    """The generated manifest and the table above must not drift apart.

    Equality in both directions, and each direction catches a different
    accident. A case added to `evals/corpus/real.py` without a line here would
    ship in the eval and the benchmark with nothing asserting on it. A case
    that stops being generated - a writer whose API moved, a builder that
    returned early - would otherwise turn every test below into a silent skip,
    which reads as green.
    """
    expected = {
        name
        for name, libraries in REQUIRED_LIBRARIES.items()
        if all(installed(module) for module in libraries)
    }
    assert set(real_corpus.cases) == expected


def test_every_generated_artifact_records_which_library_wrote_it(real_corpus):
    """`writer` is what makes this corpus evidence rather than another fixture.

    The eval publishes "written by torch 2.14" next to its numbers. If that
    field were empty, or carried the placeholder version `importlib.metadata`
    hands back for a package it cannot find, the claim would be unfalsifiable.
    """
    if not real_corpus.cases:
        if REQUIRE_REAL_STACK:
            pytest.fail("no ML writer installed, and this run was told to require them")
        pytest.skip("no ML writer installed, nothing was generated")
    for name, case in sorted(real_corpus.cases.items()):
        library, _, version = case["writer"].partition(" ")
        assert library in REQUIRED_LIBRARIES[name], f"{name} claims an unexpected writer"
        assert version and version != "?", f"{name} records no version for {library}"
        assert real_corpus.path(name).stat().st_size > 0


# ---------------------------------------------------------------------------
# Case by case, against the expectations the generator recorded
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(REQUIRED_LIBRARIES))
def test_a_real_artifact_meets_the_expectation_its_writer_recorded(real_corpus, name):
    """Format, verdict, required rules, forbidden rules and tensor count.

    This is the whole external-validity claim in one assertion block, per
    artifact. `forbid_rules` is the half that matters most: it is what says
    the allowlist admits the callables a genuine `torch.save` emits, and a
    tool that fired ACT-PKL-001 on every real checkpoint would be useless
    while still catching every gadget in the synthetic corpus.
    """
    require_libraries(name)
    case = real_corpus.case(name)
    report = inspect_artifact(real_corpus.path(name))
    fired = rules(report)

    assert report.detected_format == case["expect_format"], f"detected from bytes: {report.detected_format}"
    assert report.verdict.value == case["expect_verdict"], f"findings were {sorted(fired)}"
    assert set(case["expect_rules"]) <= fired, f"missing {sorted(set(case['expect_rules']) - fired)}"
    assert set(case["forbid_rules"]).isdisjoint(fired), (
        f"false positives on an artifact a real library wrote: "
        f"{sorted(set(case['forbid_rules']) & fired)}"
    )
    assert len(report.tensors) >= case["expect_tensors_at_least"]
    # `fully_read` is derived from the coverage matrix now, and it answers the
    # narrower of the two questions the old boolean was asked: was every
    # surface this tool undertook to read read in full. It is not "was every
    # byte of the file read", because nothing reads every byte of a 4 GB
    # checkpoint and never claimed to (D-104).
    #
    # This test asserted the old meaning until 2.2.0 and only the nightly runs
    # it, so the change that was deliberate everywhere else went unnoticed
    # here for a release (DEF-102). What it checks now is the contract that
    # actually holds: an artifact a real library wrote is fully read, and when
    # ACT-ZIP-007 fires it names the storage members it passed over and the
    # surface they belong to is reported as never undertaken.
    assert report.metadata["fully_read"] is True, (
        "an artifact written by the library it claims to come from must have every "
        "in-scope surface read in full; anything less means the coverage claim is overstated"
    )
    if "ACT-ZIP-007" in fired:
        assert report.metadata["members_not_inspected"], "the rule has to name what it skipped"
        assert report.coverage.state(Surface.RAW_TENSOR_CONTENT) is CoverageState.NOT_ASSESSED, (
            "the surface those members belong to is out of scope, not half-read"
        )


# ---------------------------------------------------------------------------
# safetensors: the header describes tensors torch created
# ---------------------------------------------------------------------------

def test_real_safetensors_exposes_the_tensors_torch_handed_it(real_corpus):
    """Actaira's header reader and the safetensors library must agree.

    The generator asked torch for a 16x16 weight and a 16-element bias and
    handed them to `safetensors.torch.save_file`. Actaira never sees a tensor:
    it reads the u64 length, the JSON header and the offsets. The two shape
    maps agreeing is the evidence that the hand-written reader tracks the
    format rather than tracking `evals/corpus/build.py`.
    """
    require_libraries("real_model.safetensors")
    from safetensors.torch import load_file

    path = real_corpus.path("real_model.safetensors")
    report = inspect_artifact(path)

    observed = {tensor.name: tuple(tensor.shape) for tensor in report.tensors}
    truth = {name: tuple(tensor.shape) for name, tensor in load_file(str(path)).items()}

    assert observed == truth
    assert truth == {"encoder.weight": (16, 16), "encoder.bias": (16,)}, (
        "the oracle itself must see the shapes this test was written around; "
        "two readers agreeing on the wrong file would otherwise pass"
    )
    assert {tensor.dtype for tensor in report.tensors} == {"F32"}
    assert report.metadata["tensor_count"] == 2
    assert report.metadata["total_parameters"] == 16 * 16 + 16 == 272
    assert report.metadata["__metadata__"] == {"format": "pt", "producer": "actaira-eval"}


def test_real_safetensors_offsets_are_consistent_and_therefore_silent(real_corpus):
    """Negative control for the structural rules, on a file written correctly.

    ACT-STF-003, -004 and -006 fire when offsets leave the data region,
    disagree with dtype and shape, or overlap. A file the reference
    implementation produced has none of those, so any of them appearing here
    would be a false positive on every safetensors artifact in existence.
    """
    require_libraries("real_model.safetensors")
    report = inspect_artifact(real_corpus.path("real_model.safetensors"))

    assert report.findings == []
    assert report.verdict is Verdict.PASS


# ---------------------------------------------------------------------------
# ONNX: a hand-written protobuf reader against the real protobuf
# ---------------------------------------------------------------------------

def test_real_onnx_fields_agree_with_the_onnx_library(real_corpus):
    """The zero-dependency protobuf reader, checked against protobuf itself.

    `src/actaira/formats/onnx.py` decodes the wire format by hand so that the
    tool does not have to install onnx. That is only defensible if it reads
    the same values the real parser does, so every field the report publishes
    is compared with `onnx.load` on the same file: the provenance fields a
    reader is asked to trust, the opset domains the risk rules are computed
    from, and the initializer shapes.
    """
    require_libraries("real_model.onnx")
    import onnx

    path = real_corpus.path("real_model.onnx")
    report = inspect_artifact(path)
    model = onnx.load(str(path))

    assert report.metadata["producer_name"] == model.producer_name == "actaira-eval"
    assert report.metadata["ir_version"] == model.ir_version
    assert report.metadata["opset_domains"] == sorted({opset.domain for opset in model.opset_import}) == [""]
    assert report.metadata["op_types"] == {node.op_type: 1 for node in model.graph.node} == {"MatMul": 1}
    assert report.metadata["node_count"] == len(model.graph.node) == 1

    observed = [(tensor.name, tuple(tensor.shape)) for tensor in report.tensors]
    truth = [(initializer.name, tuple(initializer.dims)) for initializer in model.graph.initializer]
    assert observed == truth == [("W", (4, 4))]
    assert report.metadata["initializer_count"] == 1


def test_a_custom_domain_written_by_the_onnx_helper_is_reported(real_corpus):
    """The positive control alongside the file above: same writer, one domain
    different, and that difference alone is what moves the verdict.

    `ACT-ONX-002` is a claim about the graph needing a kernel this tool cannot
    see. Pinning it against a model the onnx helper built, rather than against
    protobuf bytes this repository assembled, is what makes the rule about
    ONNX rather than about our own encoder.
    """
    require_libraries("real_custom_domain.onnx")
    import onnx

    path = real_corpus.path("real_custom_domain.onnx")
    report = inspect_artifact(path)
    model = onnx.load(str(path))

    assert "com.acme.kernels" in {opset.domain for opset in model.opset_import}
    assert report.metadata["opset_domains"] == ["", "com.acme.kernels"]
    finding = next(f for f in report.findings if f.rule_id == "ACT-ONX-002")
    assert finding.severity is Severity.HIGH
    assert finding.evidence == {"domain": "com.acme.kernels", "reason": "custom_operator_domain"}
    assert "ACT-ONX-001" not in rules(report), "a vendor domain is not a Python-executing one"


# ---------------------------------------------------------------------------
# HDF5: a byte scan over a container this tool does not parse
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "name, expected_classes, expected_rules",
    [
        ("real_keras.h5", ["Dense", "Dropout", "Sequential"], set()),
        ("real_keras_lambda.h5", ["Dense", "Lambda", "Sequential"], {"ACT-H5-001"}),
    ],
    ids=["dense-and-dropout", "lambda"],
)
def test_real_hdf5_layer_classes_agree_with_h5py(real_corpus, name, expected_classes, expected_rules):
    """The honest half of D-09, measured on a genuine HDF5 file.

    `keras_h5.py` deliberately does not implement HDF5. It confirms the magic
    number and then scans the raw bytes for the `model_config` attribute,
    which works because h5py stores that string contiguously. Whether it keeps
    working is not something a synthetic blob can answer: the synthetic corpus
    writes the JSON into a file that only pretends to be HDF5, so the byte
    scan is guaranteed to find it. Here the container is real, written by
    libhdf5, and the class names Actaira recovers are compared with the ones
    h5py reads out of the attribute properly.
    """
    require_libraries(name)
    import h5py

    path = real_corpus.path(name)
    report = inspect_artifact(path)

    with h5py.File(path, "r") as handle:
        config = json.loads(handle.attrs["model_config"])
    truth = sorted({config["class_name"]} | {layer["class_name"] for layer in config["config"]["layers"]})

    assert report.metadata["layer_class_names"] == truth == expected_classes
    assert report.metadata["truncated_scan"] is False
    assert rules(report) == expected_rules
    assert report.metadata["fully_read"] is True


def test_the_lambda_layer_in_a_real_container_is_critical(real_corpus):
    """A Lambda body is a marshalled code object run at load, so it is the one
    Keras construct that makes an .h5 file executable. Counted, not just
    noticed: the evidence carries how many were found."""
    require_libraries("real_keras_lambda.h5")
    report = inspect_artifact(real_corpus.path("real_keras_lambda.h5"))

    finding = next(f for f in report.findings if f.rule_id == "ACT-H5-001")
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence["lambda_layers"] == 1
    assert report.verdict is Verdict.FAIL


# ---------------------------------------------------------------------------
# The trojan torch itself serialised
# ---------------------------------------------------------------------------

def test_the_real_trojan_names_the_os_module_as_the_pickle_spells_it(real_corpus):
    """The classic supply-chain payload, written by `torch.save`.

    The gadget is an object whose `__reduce__` returns `(os.system, ("id",))`,
    and the name that lands in the pickle is the name of the module `os` is
    implemented by on the machine that wrote it: `posix.system` on Linux and
    macOS, `nt.system` on Windows. The report must publish whichever one the
    bytes actually carry - a user grepping for `os.system` in a scanner's
    output would find nothing, and the point of `imported_callables` is to say
    exactly what a loader would import.

    DEF-109: this test asserted `posix.system` and nothing else, and its
    docstring said "on this platform" about a name that is a property of the
    writing platform rather than of the format. Run on Windows it failed
    against a report that was entirely correct, which is the worst kind of red:
    a real regression here would have looked exactly the same.

    The expected name is therefore derived from the interpreter rather than
    typed, and the assertion that matters is the one added underneath - that
    **both** policies flag it. `nt` is on the denylist beside `posix`
    (`scan/policy.py`), and a denylist that had only ever been exercised
    against the POSIX spelling is precisely where a Windows-authored gadget
    would have walked through `--policy known-bad`.
    """
    require_libraries("real_trojan.pt")
    expected = f"{os.name}.system"
    assert expected in ("posix.system", "nt.system"), f"unexpected os module {os.name!r}"

    report = inspect_artifact(real_corpus.path("real_trojan.pt"))

    assert expected in report.imported_callables
    finding = next(f for f in report.findings if f.rule_id == "ACT-PKL-002")
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence == {"callable": expected, "policy": "strict"}
    assert finding.location == "real_trojan.pt!real_trojan/data.pkl", (
        "the finding must name the member inside the checkpoint, not just the file"
    )
    assert report.verdict is Verdict.FAIL

    # The half that is a security property rather than a naming one. The
    # allowlist fails closed and would refuse this name whatever it was; the
    # denylist only catches what it enumerates, so it is the one that has to
    # know both spellings.
    denylisted = inspect_artifact(real_corpus.path("real_trojan.pt"), scan_policy="known-bad")
    hit = next(
        (f for f in denylisted.findings if f.rule_id == "ACT-PKL-002"), None
    )
    assert hit is not None, (
        f"the denylist did not recognise {expected}: a gadget written on this platform "
        "walks through `--policy known-bad`"
    )
    assert hit.evidence == {"callable": expected, "policy": "known-bad"}
    assert denylisted.verdict is Verdict.FAIL


def test_the_clean_sibling_of_the_trojan_names_no_denied_callable(real_corpus):
    """Negative control: same writer, same call, same tensors, no gadget.

    `real_state_dict.pt` and `real_trojan.pt` differ by one dictionary entry.
    If ACT-PKL-002 fired on both, it would be reporting the format rather than
    the payload, and the trojan test above would prove nothing.
    """
    require_libraries("real_state_dict.pt")
    report = inspect_artifact(real_corpus.path("real_state_dict.pt"))

    assert "posix.system" not in report.imported_callables
    assert "ACT-PKL-002" not in rules(report)
    assert "ACT-PKL-001" not in rules(report), "a genuine state_dict must clear the strict allowlist"
    assert report.imported_callables == [
        "collections.OrderedDict",
        "torch.FloatStorage",
        "torch._utils._rebuild_tensor_v2",
    ]
    assert report.verdict is Verdict.PASS


# ---------------------------------------------------------------------------
# The legacy torch container, and the exemption it is granted
#
# torch's pre-1.6 format writes four pickles back to back - magic number,
# protocol version, sys_info, then the object - followed by raw storages. Read
# as a plain pickle that is a concatenation with trailing binary, which is
# exactly the shape ACT-PKL-010 and ACT-PKL-006 exist to report. Without an
# exemption Actaira would fail every checkpoint written before 2020.
#
# An exemption in a security tool is a hole unless it is proven to be narrow,
# so the three tests below are (a) that it applies, (b) that it hides nothing,
# and (c) that it cannot be claimed by a file that merely resembles the format.
# ---------------------------------------------------------------------------

def test_the_real_legacy_checkpoint_passes_as_a_recognised_container(real_corpus):
    """(a) The exemption applies to what it was written for.

    `metadata["container"]` is part of the assertion on purpose: the report
    has to say why the multi-stream layout was not reported, otherwise the
    PASS is indistinguishable from a scanner that simply stopped at the first
    STOP and never looked at the rest of the file.
    """
    require_libraries("real_state_dict_legacy.pt")
    report = inspect_artifact(real_corpus.path("real_state_dict_legacy.pt"))

    assert report.detected_format == "pickle"
    assert report.metadata["container"] == "torch-legacy"
    assert "ACT-PKL-010" not in rules(report), "the documented layout is not suspicious concatenation"
    assert "ACT-PKL-006" not in rules(report), "raw storages after the last stream are not a parse failure"
    assert report.metadata["fully_read"] is True
    assert report.verdict is Verdict.PASS


def test_the_legacy_exemption_does_not_hide_a_gadget(write_artifact):
    """(b) The control that makes the exemption defensible.

    A container is hand-built here rather than taken from torch: the real
    magic number, followed by a `posix.system` reduction where the object
    pickle would be. This is what an attacker would write if the exemption
    were a blanket one, and it is the shape a regression would take - a future
    edit that skips the remaining streams instead of only suppressing the two
    container-shaped findings would turn this file into a clean PASS.

    The exemption must be visible (container recorded, ACT-PKL-010 absent) and
    the gadget must still be reported. Both, or the test proves nothing.
    """
    path = write_artifact(
        "legacy_with_gadget.pt",
        pickle.dumps(TORCH_LEGACY_MAGIC, protocol=2) + corpus_build.craft_reduce("posix", "system", ("id",), 2),
    )

    report = inspect_artifact(path)

    assert report.metadata["container"] == "torch-legacy", "the exemption was granted"
    assert "ACT-PKL-010" not in rules(report), "and it did suppress the concatenation finding"
    assert "ACT-PKL-002" in rules(report), "yet the gadget in the trailing stream is still reported"
    assert report.imported_callables == ["posix.system"]
    assert report.verdict is Verdict.FAIL


def test_a_real_checkpoint_reports_its_storages_once_not_once_each(real_corpus):
    """A finding per tensor storage buried the result on every real model.

    `BINPERSID` is how a torch checkpoint names a tensor storage, so a real
    state_dict uses it once per tensor. Emitting a finding each time meant a
    fifty-tensor model produced fifty identical yellow lines, and whatever
    else the scan had found was somewhere below them. Found by reading the
    tool's own output on a checkpoint written by torch, which is a review the
    synthetic corpus could not prompt: its artifacts have two tensors.
    """
    require_libraries("real_state_dict.pt")
    report = inspect_artifact(real_corpus.path("real_state_dict.pt"))
    persid = [finding for finding in report.findings if finding.rule_id == "ACT-PKL-005"]

    assert len(persid) == 1, "one finding, carrying a count"
    assert persid[0].evidence["persistent_ids"] >= 1
    assert persid[0].severity is Severity.INFO, "inside a torch container this is the documented mechanism"


def test_the_legacy_container_rates_its_storages_the_same_way(real_corpus):
    """The same judgement, one container older.

    The severity of a persistent id depends on where it is: inside a torch
    container it is the documented way to name a storage, anywhere else the
    loading application resolves an identifier the artifact chose. A legacy
    checkpoint is scanned stream by stream, and a nested stream cannot see the
    container it is in, so it rated the storages MEDIUM and every pre-1.6
    checkpoint carried a yellow line for obeying its own format.
    """
    require_libraries("real_state_dict_legacy.pt")
    report = inspect_artifact(real_corpus.path("real_state_dict_legacy.pt"))
    persid = [finding for finding in report.findings if finding.rule_id == "ACT-PKL-005"]

    assert persid, "the storages are still reported"
    assert all(finding.severity is Severity.INFO for finding in persid)
    assert report.verdict is Verdict.PASS


def test_only_the_documented_magic_number_buys_the_legacy_exemption(write_artifact):
    """(c) The exemption is keyed on the magic number, not on the shape.

    Both files below are a single integer pickle followed by the same benign
    trailing stream, byte for byte identical apart from that integer. The
    genuine magic gets the exemption and passes; one bit off is an ordinary
    concatenated pickle and is reported. If the check were structural - "first
    stream is a lone integer", or worse, "the file is named .pt" - an attacker
    would suppress ACT-PKL-010 for free by prefixing any integer.
    """
    tail = pickle.dumps({"encoder.weight": [0.0, 1.0]}, protocol=2)
    genuine = write_artifact("genuine_legacy.pt", pickle.dumps(TORCH_LEGACY_MAGIC, protocol=2) + tail)
    impostor = write_artifact("impostor_legacy.pt", pickle.dumps(TORCH_LEGACY_MAGIC ^ 1, protocol=2) + tail)

    exempt = inspect_artifact(genuine)
    refused = inspect_artifact(impostor)

    assert exempt.metadata["container"] == "torch-legacy"
    assert exempt.verdict is Verdict.PASS
    assert rules(exempt) == set()

    assert refused.metadata.get("container") is None, "no container may be claimed without the magic number"
    assert "ACT-PKL-010" in rules(refused)
    assert refused.verdict is Verdict.FAIL, (
        "the trailing stream is the only difference between these two verdicts, "
        "which is what makes the exemption narrow rather than a bypass"
    )


# ---------------------------------------------------------------------------
# The same model, both containers torch offers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload, expected", [("state_dict", Verdict.PASS), ("trojan", Verdict.FAIL)])
def test_both_torch_containers_reach_the_same_verdict_by_different_routes(tmp_path, payload, expected):
    """One object, two serialisations, two entirely different code paths.

    The modern file is a zip: `archive.inspect` walks the members, finds
    `data.pkl` and scans it. The legacy file is a bare pickle: the trailing
    stream walker in `pickle_scan.py` reaches the object through the magic
    number and the container exemption. The two share no branch of
    `inspect_artifact` at all.

    A user does not care which serialisation flag was passed to `torch.save`,
    so the verdict, the rule set and the list of callables a loader would
    import must not depend on it. The parametrisation runs the same comparison
    on a benign checkpoint and on a poisoned one, because agreement on PASS
    alone would also be satisfied by a legacy branch that reports nothing.
    """
    torch = pytest.importorskip("torch", reason="both containers are written by torch.save")
    state_dict = {"encoder.weight": torch.zeros(8, 8), "encoder.bias": torch.zeros(8)}
    obj = state_dict if payload == "state_dict" else {"state_dict": state_dict, "meta": corpus_real.Exploit()}

    modern = tmp_path / "modern.pt"
    legacy = tmp_path / "legacy.pt"
    torch.save(obj, modern)
    torch.save(obj, legacy, _use_new_zipfile_serialization=False)

    zipped = inspect_artifact(modern)
    flat = inspect_artifact(legacy)

    assert zipped.detected_format == "pytorch-zip"
    assert flat.detected_format == "pickle"
    assert "container" not in zipped.metadata
    assert flat.metadata["container"] == "torch-legacy"

    # The zip container carries one rule the bare pickle cannot: ACT-ZIP-007
    # names the storage members, which exist only in the zip layout. It is a
    # statement about the container, not about the object, so it is subtracted
    # before the two routes are compared. The comparison that matters, and the
    # one this test was written for, is that the object inside is read
    # identically by both routes.
    assert rules(zipped) - {"ACT-ZIP-007"} == rules(flat)
    assert "ACT-ZIP-007" in rules(zipped), "the storage members are named, not passed over"
    assert flat.verdict is expected

    # Both routes reach the same verdict, which they did not in 2.1 (DEF-102).
    # Then, ACT-ZIP-007 pushed `raw_tensor_content` to PARTIAL and a benign
    # zip came back INCONCLUSIVE where the identical legacy file came back
    # PASS: the same object, two serialisation flags, two different answers.
    # 2.2 replaced the single `fully_read` boolean with per-surface coverage,
    # and `raw_tensor_content` is NOT_ASSESSED because nothing here ever
    # undertook to read it. A surface nobody undertook to read cannot make a
    # verdict inconclusive, so the zip now agrees with the bare pickle, which
    # is the whole argument of the coverage model.
    assert zipped.verdict is expected
    assert zipped.coverage.state(Surface.RAW_TENSOR_CONTENT) is CoverageState.NOT_ASSESSED, (
        "the surface ACT-ZIP-007 limits must be reported as never undertaken, "
        "not as a partial read that drags the verdict down"
    )
    assert zipped.imported_callables == flat.imported_callables
    assert "torch._utils._rebuild_tensor_v2" in flat.imported_callables, (
        "both routes must actually reach the object pickle; two empty scans would agree too"
    )
