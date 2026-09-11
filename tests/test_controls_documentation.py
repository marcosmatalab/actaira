"""The generatable documentation controls.

The property under test is a negative one and it is the reason this file
exists: no control here can report SATISFIED, on any input, ever. A drafted
Annex IV that reads as finished is exactly the artifact a compliance tool
should not be able to produce, because the person who signs it is asserting
things no software checked. Everything else here - the sections, the
citations, the three provenance states - is in service of making the draft
honest enough to be useful while it stays inconclusive.
"""
from __future__ import annotations

import json

import pytest

from actaira.controls import documentation, engine
from actaira.controls.documentation import (
    ANNEX_IV,
    ANNEX_IV_CONTROL,
    ANNEX_XI_CONTROL,
    ANNEX_XII_CONTROL,
    CONTROLS,
    DECLARED,
    FILLED,
    MISSING,
    SKELETONS,
    TRAINING_SUMMARY_CONTROL,
)
from actaira.controls.engine import load_target
from actaira.controls.model import Control, ControlResult, Method, Outcome
from actaira.governance import catalog
from conftest import corpus_build


def write_model(root, name="model.safetensors"):
    path = root / name
    path.write_bytes(
        corpus_build.build_safetensors(
            {
                "encoder.weight": {"dtype": "F32", "shape": [8, 8], "data_offsets": [0, 256]},
                "encoder.bias": {"dtype": "F32", "shape": [8], "data_offsets": [256, 288]},
            },
            b"\x00" * 288,
        )
    )
    return path


@pytest.fixture
def targets(tmp_path):
    """Four targets, chosen to tempt every branch into a SATISFIED.

    Empty (nothing to say), rich (plenty to say), hostile (a gadget, so the
    cybersecurity point has real content), and fully declared (the operator
    answered every question, which is the case where a careless
    implementation decides the file is finished).
    """
    empty = tmp_path / "empty"
    empty.mkdir()

    rich = tmp_path / "rich"
    rich.mkdir()
    write_model(rich)

    hostile = tmp_path / "hostile"
    hostile.mkdir()
    (hostile / "checkpoint.pkl").write_bytes(corpus_build.craft_reduce("posix", "system", ("id",)))

    declared = tmp_path / "declared"
    declared.mkdir()
    write_model(declared)
    every_point = {
        skeleton.key: {
            point.slug: "declared by the operator"
            for section in skeleton.sections
            for point in section.points
        }
        for skeleton in SKELETONS
    }
    (declared / "actaira.json").write_text(json.dumps(every_point), encoding="utf-8")

    return [load_target(path, role="provider") for path in (empty, rich, hostile, declared)]


# ---------------------------------------------------------------------------
# The property this whole file is about
# ---------------------------------------------------------------------------

def test_no_generatable_control_can_report_satisfied(targets):
    """Design note D-56. A draft nobody signed is not evidence, so the best
    available answer is INCONCLUSIVE with the draft attached."""
    for control in CONTROLS:
        for target in targets:
            result = control(target)

            assert result.outcome is Outcome.INCONCLUSIVE, f"{control.id} on {target.root}"
            assert result.method is Method.GENERATED


def test_a_target_where_every_point_is_answered_is_still_inconclusive(targets):
    """The case a shortcut would break: the file looks finished. Whether the
    file is finished is a fact about the file; whether the obligation is met
    is a fact about the provider, and this control has never seen one."""
    _empty, _rich, _hostile, declared = targets

    result = ANNEX_IV_CONTROL(declared)

    assert result.evidence["gaps"] == []
    assert result.outcome is Outcome.INCONCLUSIVE


def test_the_engine_refuses_a_generated_control_that_claims_satisfied(targets):
    """The guard from the other side. `_run_one` is private and is reached
    into on purpose: the point is that the refusal lives in the engine, so a
    future control cannot opt out of it by being written carelessly."""
    rogue = Control(
        id="ACT-C-ROGUE",
        obligation_ids=("AIA-11",),
        method=Method.GENERATED,
        run=lambda _target: ControlResult(
            control_id="ACT-C-ROGUE",
            obligation_ids=("AIA-11",),
            outcome=Outcome.SATISFIED,
            method=Method.GENERATED,
        ),
    )

    with pytest.raises(ValueError, match="may not return SATISFIED"):
        engine._run_one(rogue, targets[0])


def test_every_result_says_that_it_is_inconclusive_by_construction(targets):
    for control in CONTROLS:
        does_not_cover = control(targets[1]).does_not_cover

        assert "INCONCLUSIVE on every input" in does_not_cover
        assert "not a technical file" in does_not_cover


# ---------------------------------------------------------------------------
# Identifiers, against the catalogue rather than against ourselves
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "control_id, obligation_id",
    [
        ("ACT-C-11-ANNEX-IV", "AIA-11"),
        ("ACT-C-53-ANNEX-XI", "AIA-53-1a"),
        ("ACT-C-53-ANNEX-XII", "AIA-53-1b"),
        ("ACT-C-53-TRAINING-SUMMARY", "AIA-53-1d"),
    ],
)
def test_each_control_id_is_the_one_the_catalogue_declares(control_id, obligation_id):
    """A dangling edge in a compliance mapping is how a tool ends up claiming
    coverage it does not have (D-43), and it is invisible: the obligation
    still renders, with nothing behind it."""
    obligation = catalog.by_id(obligation_id)

    assert obligation is not None
    assert control_id in obligation.controls
    control = next(c for c in CONTROLS if c.id == control_id)
    assert control.obligation_ids == (obligation_id,)
    assert obligation.checkability is catalog.Checkability.GENERATABLE


# ---------------------------------------------------------------------------
# The shape of the drafted document
# ---------------------------------------------------------------------------

def test_the_annex_iv_draft_has_the_nine_sections_of_the_annex(targets):
    draft = ANNEX_IV_CONTROL(targets[1]).evidence["draft"]

    assert [section["number"] for section in draft["sections"]] == list("123456789")
    assert all(section["citation"].startswith("Annex IV(") for section in draft["sections"])


def test_every_point_carries_its_citation_and_one_of_the_three_states(targets):
    for control in CONTROLS:
        draft = control(targets[1]).evidence["draft"]
        points = [point for section in draft["sections"] for point in section["points"]]

        assert points
        for point in points:
            assert point["citation"]
            assert point["asks"]
            assert point["status"] in (FILLED, DECLARED, MISSING)


def test_the_draft_says_it_is_a_draft_and_that_its_annex_text_is_a_paraphrase(targets):
    draft = ANNEX_IV_CONTROL(targets[1]).evidence["draft"]

    assert draft["is_a_draft"] is True
    assert "no part of it is evidence of compliance" in draft["warning"]
    assert "paraphrases" in draft["paraphrase_note"]
    assert draft["citation"].startswith("Regulation (EU) 2024/1689")


def test_the_counts_are_counts_and_are_never_divided_by_anything(targets):
    result = ANNEX_IV_CONTROL(targets[1])
    counts = result.evidence["counts_not_a_score"]
    points = [point for section in result.evidence["draft"]["sections"] for point in section["points"]]

    assert sum(counts.values()) == len(points)
    assert set(counts) == {FILLED, DECLARED, MISSING}
    rendered = json.dumps(result.to_dict())
    assert "percent" not in rendered and "score" not in rendered.replace("counts_not_a_score", "")


def test_the_gaps_are_exactly_what_the_control_abstained_on(targets):
    for control in CONTROLS:
        result = control(targets[0])

        assert tuple(result.evidence["gaps"]) == result.abstained_on
        assert result.abstained_on, "an empty target has nothing filled and everything missing"


# ---------------------------------------------------------------------------
# The three states, which are the product
# ---------------------------------------------------------------------------

def points_of(result) -> dict[str, dict]:
    return {
        point["key"]: point
        for section in result.evidence["draft"]["sections"]
        for point in section["points"]
    }


def test_a_point_is_filled_from_evidence_only_when_bytes_answered_it(targets):
    _empty, rich, _hostile, _declared = targets

    filled = points_of(ANNEX_XI_CONTROL(rich))["annex_xi.architecture_and_parameters"]

    assert filled["status"] == FILLED
    assert filled["from_evidence"][0]["total_parameters"] == 72
    assert "The architecture is not" in filled["note"]


def test_the_same_point_is_missing_when_there_is_nothing_to_read(targets):
    empty = targets[0]

    point = points_of(ANNEX_XI_CONTROL(empty))["annex_xi.architecture_and_parameters"]

    assert point["status"] == MISSING
    assert "from_evidence" not in point


def test_an_operator_statement_is_never_promoted_to_filled_from_evidence(tmp_path):
    """The distinction between a declaration and a measurement is the only
    thing this module sells."""
    root = tmp_path / "declared-only"
    root.mkdir()
    (root / "actaira.yaml").write_text(
        'annex_xi:\n  architecture_and_parameters: "a 70B transformer"\n', encoding="utf-8"
    )

    point = points_of(ANNEX_XI_CONTROL(load_target(root)))["annex_xi.architecture_and_parameters"]

    assert point["status"] == DECLARED
    assert point["declared_by_operator"] == "a 70B transformer"
    assert "from_evidence" not in point


def test_a_declaration_that_disagrees_with_the_bytes_is_kept_next_to_them(tmp_path):
    """Dropping the declaration on a filled point would hide the one thing a
    reader of both would most want to see."""
    root = tmp_path / "disagreement"
    root.mkdir()
    write_model(root)
    (root / "actaira.yaml").write_text(
        "annex_xi:\n  architecture_and_parameters: 70000000000\n", encoding="utf-8"
    )

    point = points_of(ANNEX_XI_CONTROL(load_target(root)))["annex_xi.architecture_and_parameters"]

    assert point["status"] == FILLED
    assert point["from_evidence"][0]["total_parameters"] == 72
    assert point["declared_by_operator"] == 70000000000


def test_the_cybersecurity_point_of_annex_iv_carries_the_static_inspection(targets):
    _empty, _rich, hostile, _declared = targets

    point = points_of(ANNEX_IV_CONTROL(hostile))["annex_iv.cybersecurity_measures"]

    assert point["status"] == FILLED
    assert point["from_evidence"]["loaded_or_executed_anything"] is False
    assert {"rule_id": "ACT-PKL-002", "severity": "critical"} in point["from_evidence"]["findings"]
    assert "organisational" in point["note"]


def test_the_forms_of_distribution_point_is_filled_with_the_digests(targets):
    point = points_of(ANNEX_IV_CONTROL(targets[1]))["annex_iv.forms_of_distribution"]

    assert point["status"] == FILLED
    assert len(point["from_evidence"][0]["sha256"]) == 64
    assert "is not readable from a file" in point["note"]


def test_almost_nothing_of_the_training_summary_can_be_filled_from_an_artifact(targets):
    """Which is the result, not a gap in the implementation: a weight file
    says nothing about what it was trained on, and a control that produced a
    plausible training summary would be inventing one."""
    result = TRAINING_SUMMARY_CONTROL(targets[1])
    counts = result.evidence["counts_not_a_score"]

    assert counts[FILLED] == 1
    assert counts[MISSING] >= 8
    filled = points_of(result)["training_summary.model_identification"]
    assert "Identifying the model is not summarising" in filled["note"]


def test_annex_xi_section_two_is_listed_as_not_drafted_rather_than_as_a_gap(targets):
    """A section listed as a gap reads as work the operator has to do. This
    one is work the tool refused to start, and the two are different
    sentences."""
    result = ANNEX_XI_CONTROL(targets[1])
    not_drafted = result.evidence["draft"]["not_drafted"]

    assert not_drafted[0]["citation"] == "Annex XI, Section 2"
    assert "Art. 51" in not_drafted[0]["reason"]
    assert not any("Section 2" in key for key in result.evidence["gaps"])


# ---------------------------------------------------------------------------
# Structure that has to stay stable between runs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("skeleton", SKELETONS, ids=lambda s: s.key)
def test_no_two_points_of_a_document_share_a_slug(skeleton):
    """The slug is the declaration key and the gap identifier. Two points
    under one slug means one of them can never be declared, and a gap list
    compared across runs would show a point closing that never did."""
    slugs = [point.slug for section in skeleton.sections for point in section.points]

    assert len(slugs) == len(set(slugs))


def test_the_annex_iv_skeleton_covers_the_lettered_subpoints_of_the_first_two_sections():
    lettered = {
        point.citation
        for section in ANNEX_IV.sections[:2]
        for point in section.points
    }

    assert "Annex IV(1)(a)" in lettered and "Annex IV(1)(h)" in lettered
    assert "Annex IV(2)(a)" in lettered and "Annex IV(2)(h)" in lettered


def test_the_draft_is_the_same_document_on_two_runs_over_the_same_target(targets):
    def draft_of(target):
        document = ANNEX_XII_CONTROL(target).evidence["draft"]
        # The ML-BOM carries a fresh serial number per call, by design.
        return json.dumps(document, sort_keys=True, default=str)

    assert draft_of(targets[1]) == draft_of(targets[1])


def test_the_fillers_cannot_reach_the_declarations(targets):
    """`DraftEvidence` holds observations only. A filler that could read the
    declarations could quietly promote a statement to filled_from_evidence."""
    evidence = documentation.gather(targets[3])

    assert not hasattr(evidence, "declarations")
    assert set(vars(evidence)) == {"reports", "bom", "not_fully_read", "truncated"}
