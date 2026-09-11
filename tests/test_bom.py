"""The CycloneDX 1.6 ML-BOM.

D-16's rule is that every emitted field comes from bytes that were parsed.
The test for that is an artifact whose file name and embedded metadata both
lie, and a check that neither lie reaches the document.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from actaira.bom.cyclonedx import SPEC_VERSION, build_bom
from actaira.inspect import inspect_artifact
from conftest import CORPUS_CASES, CORPUS_DIR, REPO_ROOT, corpus_build

# The published CycloneDX 1.6 JSON schema, committed rather than fetched: a
# test that needs the network is a test that is skipped on the machine where
# it matters. `docs/FORMATS.md` records where it came from.
SCHEMA_PATH = REPO_ROOT / "tests" / "fixtures" / "cyclonedx" / "bom-1.6.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

# The lies: none of these describe the two 4x4-ish F32 tensors in the file.
LIES = ("llama", "70b", "f16", "instruct", "8192", "MoE")


@pytest.fixture
def lying_artifact(tmp_path):
    """A safetensors file whose name and `__metadata__` both claim a model that
    is not there. The bytes hold 20 F32 parameters."""
    path = tmp_path / "llama-70b-instruct-f16.safetensors"
    path.write_bytes(
        corpus_build.build_safetensors(
            {
                "__metadata__": {
                    "model_name": "llama-70b-instruct",
                    "dtype": "F16",
                    "hidden_size": "8192",
                    "architecture": "MoE",
                },
                "w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]},
                "b": {"dtype": "F32", "shape": [4], "data_offsets": [64, 80]},
            },
            b"\x00" * 80,
        )
    )
    return path


def properties_of(component) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for row in component.get("properties", []):
        grouped.setdefault(row["name"], []).append(row["value"])
    for row in component.get("modelCard", {}).get("properties", []):
        grouped.setdefault(row["name"], []).append(row["value"])
    return grouped


# ---------------------------------------------------------------------------
# Only observed values
# ---------------------------------------------------------------------------

def test_no_claim_from_the_file_name_or_its_metadata_reaches_the_bom(lying_artifact):
    report = inspect_artifact(lying_artifact)
    document = build_bom([report])
    component = document["components"][0]

    # The file name is recorded once, as the component name, because that is
    # what the artifact was called. It must not turn into a fact about the
    # model anywhere else in the document.
    assert component["name"] == lying_artifact.name
    without_name = dict(component)
    without_name.pop("name")
    serialised = json.dumps(without_name).lower()
    for lie in LIES:
        assert lie.lower() not in serialised, f"{lie!r} came from the name or the metadata"

    observed = properties_of(component)
    assert observed["dtypes_observed"] == ["F32"], "the dtype is read from the header, not the name"
    assert observed["parameters_observed"] == ["20"], "16 + 4 elements, counted from the shapes"
    assert observed["tensor_count"] == ["2"]
    assert observed["actaira:format"] == ["safetensors"]
    assert observed["actaira:size_bytes"] == [str(lying_artifact.stat().st_size)]


def test_publisher_metadata_is_parsed_but_not_republished(lying_artifact):
    """The `__metadata__` block is read (it is part of the header) and kept in
    the report, and it still does not become a BOM field: a BOM that repeats a
    publisher's claim adds nothing to a supply chain."""
    report = inspect_artifact(lying_artifact)

    assert report.metadata["__metadata__"]["model_name"] == "llama-70b-instruct"
    assert "llama" not in json.dumps(build_bom([report])["components"][0]["properties"])


def test_an_unread_artifact_says_so_instead_of_guessing(tmp_path):
    """Negative control for "only observed values": when nothing could be
    parsed, the model card is absent rather than filled with defaults."""
    path = tmp_path / "mystery.model"
    path.write_bytes(b"\x11\x22\x33\x44 not a known format")

    component = build_bom([inspect_artifact(path)])["components"][0]

    assert "modelCard" not in component
    observed = properties_of(component)
    assert observed["actaira:fully_read"] == ["false"]
    assert observed["actaira:verdict"] == ["inconclusive"]


# ---------------------------------------------------------------------------
# Hashes and identity
# ---------------------------------------------------------------------------

def test_the_component_hash_is_the_hash_of_the_file_and_of_the_report(lying_artifact):
    report = inspect_artifact(lying_artifact)
    component = build_bom([report])["components"][0]
    on_disk = hashlib.sha256(lying_artifact.read_bytes()).hexdigest()

    assert component["hashes"] == [{"alg": "SHA-256", "content": on_disk}]
    assert report.sha256 == on_disk
    assert component["bom-ref"] == f"urn:actaira:artifact:0:{on_disk}"


def test_the_bom_ref_is_stable_across_runs_and_the_serial_number_is_not(lying_artifact):
    """`bom-ref` is derived from content, so two runs agree and a downstream
    tool can join on it. `serialNumber` identifies the document, not the
    artifact, so it must differ."""
    first = build_bom([inspect_artifact(lying_artifact)])
    second = build_bom([inspect_artifact(lying_artifact)])

    assert first["components"][0]["bom-ref"] == second["components"][0]["bom-ref"]
    assert first["components"][0]["hashes"] == second["components"][0]["hashes"]
    assert first["serialNumber"] != second["serialNumber"]
    assert first["serialNumber"].startswith("urn:uuid:")


def test_two_different_artifacts_get_two_different_refs(tmp_path, lying_artifact):
    other = tmp_path / "other.safetensors"
    other.write_bytes(
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}}, b"\x01" * 64
        )
    )

    document = build_bom([inspect_artifact(lying_artifact), inspect_artifact(other)])

    refs = [component["bom-ref"] for component in document["components"]]
    assert len(set(refs)) == 2


# ---------------------------------------------------------------------------
# Document shape
# ---------------------------------------------------------------------------

def test_the_document_declares_the_format_a_consumer_will_look_for(lying_artifact):
    document = build_bom([inspect_artifact(lying_artifact)])

    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == SPEC_VERSION == "1.6"
    assert document["version"] == 1
    assert document["components"][0]["type"] == "machine-learning-model"
    assert document["metadata"]["tools"]["components"][0]["name"] == "actaira"


def test_findings_and_imports_travel_with_the_component(tmp_path):
    """A BOM that dropped the findings would describe the artifact without
    describing what is wrong with it."""
    gadget = tmp_path / "gadget.pkl"
    gadget.write_bytes(corpus_build.craft_reduce("posix", "system", ("id",), 2))
    report = inspect_artifact(gadget)

    observed = properties_of(build_bom([report])["components"][0])

    assert "ACT-PKL-002:critical" in observed["actaira:finding"]
    assert observed["actaira:imported_callable"] == ["posix.system"]
    assert observed["actaira:max_severity"] == ["critical"]
    assert observed["actaira:verdict"] == ["fail"]


# ---------------------------------------------------------------------------
# The document is valid against the specVersion it declares
#
# It was not. `modelCard.modelParameters` is declared with
# `"additionalProperties": false` and a closed field list, and every ML-BOM
# this tool emitted put a `properties` array inside it. Tools that do not
# validate accepted it, which is why it shipped, and every tool that does
# rejected the whole document. The assertion below is the published schema,
# not a field list retyped here: a constant that agrees with the code proves
# only that someone typed it twice.
# ---------------------------------------------------------------------------

jsonschema = pytest.importorskip("jsonschema", reason="the 1.6 schema check needs jsonschema")


def validate(document) -> list[str]:
    validator = jsonschema.Draft7Validator(SCHEMA)
    return [
        f"{'/'.join(str(part) for part in error.path)}: {error.message}"
        for error in sorted(validator.iter_errors(document), key=lambda e: list(e.path))
    ]


def test_the_committed_schema_is_the_one_it_claims_to_be():
    """A guard on the fixture: a truncated or wrong-version download would
    make every validation below pass for the wrong reason."""
    assert SCHEMA["$id"] == "http://cyclonedx.org/schema/bom-1.6.schema.json"
    assert SCHEMA["definitions"]["modelCard"]["properties"]["modelParameters"]["additionalProperties"] is False
    assert "properties" in SCHEMA["definitions"]["modelCard"]["properties"]


def test_a_bom_over_the_whole_corpus_validates_against_the_1_6_schema():
    """Every artifact the project ships, in one document, so every branch of
    `_model_card` and `_properties` is exercised at once."""
    reports = [inspect_artifact(CORPUS_DIR / case.name) for case in CORPUS_CASES]
    document = build_bom(reports)

    assert len(document["components"]) == len(reports)
    assert validate(document) == []


@pytest.mark.parametrize("case", CORPUS_CASES, ids=lambda case: case.name)
def test_every_single_artifact_produces_a_valid_document(case):
    assert validate(build_bom([inspect_artifact(CORPUS_DIR / case.name)])) == []


def test_the_schema_check_can_fail(lying_artifact):
    """Negative control. The shape this module used to emit, put back by hand,
    has to be rejected - otherwise the two tests above are decoration."""
    document = build_bom([inspect_artifact(lying_artifact)])
    card = document["components"][0]["modelCard"]
    assert card["properties"], "the fixture has to reach the model card at all"
    document["components"][0]["modelCard"] = {"modelParameters": {"properties": card["properties"]}}

    problems = validate(document)

    assert problems, "the validator accepted the shape the schema forbids"
    assert any("Additional properties are not allowed" in problem for problem in problems)


def test_the_same_bytes_twice_in_one_document_keep_two_refs(tmp_path):
    """`bom-ref` must be unique within a document. Deriving it from the digest
    alone collided whenever one BOM covered the same bytes twice, which is a
    directory holding a file and a copy of it, not an exotic case."""
    blob = corpus_build.build_safetensors(
        {"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}}, b"\x00" * 64
    )
    first, second = tmp_path / "a.safetensors", tmp_path / "copy-of-a.safetensors"
    first.write_bytes(blob)
    second.write_bytes(blob)

    document = build_bom([inspect_artifact(first), inspect_artifact(second)])

    refs = [component["bom-ref"] for component in document["components"]]
    assert len(set(refs)) == 2, "two components under one ref make an ambiguous graph"
    assert document["components"][0]["hashes"] == document["components"][1]["hashes"]
    assert validate(document) == []
