"""The coverage matrix: what it promises, and the two things it must not do.

Design notes D-100 to D-105. The matrix replaced one boolean, and the reason
it had to is that the boolean conflated two statements: "I chose not to read
the weights" and "I tried to read the header and failed". Everything here
defends that separation from the two directions it can be broken - a scope
statement that starts failing verdicts again, and a real failure that stops.
"""
from __future__ import annotations

import io
import pickle
import zipfile

import pytest

from actaira.coverage import (
    REASON_OUTSIDE_STATIC_SCOPE,
    REASON_PARSE_FAILED,
    REASON_READ_IN_FULL,
    Coverage,
    CoverageState,
    Surface,
    SurfaceCoverage,
    apply_findings,
    baseline,
    classified_rules,
    rule_effect,
)
from actaira.inspect import UNREAD_RULE_IDS, inspect_artifact
from actaira.model import Verdict


def zip_bytes(entries, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as archive:
        for name, payload in entries:
            archive.writestr(name, payload)
    return buffer.getvalue()


CLEAN = pickle.dumps({"w": [1.0, 2.0]}, protocol=2)


# --------------------------------------------------------------------------
# The invariant the whole design rests on
# --------------------------------------------------------------------------


def test_a_surface_nobody_undertook_to_read_cannot_make_a_verdict_inconclusive(tmp_path):
    """The defect that made every clean checkpoint exit 3.

    A checkpoint is mostly float buffers. Declining to decompress them is a
    scope statement about raw tensor content, and raw tensor content was
    never in scope, so it cannot lower a verdict about the execution surface.
    """
    path = tmp_path / "clean.pt"
    path.write_bytes(
        zip_bytes([("archive/data.pkl", CLEAN), ("archive/data/0", b"\x00" * 512), ("archive/version", b"3\n")])
    )

    report = inspect_artifact(path)

    assert report.verdict is Verdict.PASS
    assert report.coverage.state(Surface.RAW_TENSOR_CONTENT) is CoverageState.NOT_ASSESSED
    assert report.coverage.state(Surface.LOAD_TIME_EXECUTION) is CoverageState.COMPLETE


def test_a_surface_that_was_in_scope_and_failed_still_does(tmp_path):
    """The other direction, and the reason the first test is not a loophole.

    A file whose format is not recognised had an execution surface in scope
    and nothing was read of it. That is FAILED, not NOT_ASSESSED, and it must
    still produce an inconclusive verdict.
    """
    path = tmp_path / "mystery.pkl"
    path.write_bytes(b"\x11\x22\x33\x44 not a known format")

    report = inspect_artifact(path)

    assert report.coverage.state(Surface.LOAD_TIME_EXECUTION) is CoverageState.FAILED
    assert report.verdict is Verdict.INCONCLUSIVE


def test_an_inspector_that_raised_fails_every_surface_it_was_asked_to_read(tmp_path, monkeypatch):
    """A traceback in one parser says nothing about the others; it says the
    run is void. Marking only the surface the exception happened to be in
    would leave the report claiming coverage that was never established."""
    from actaira.formats import archive as archive_module

    path = tmp_path / "boom.pt"
    path.write_bytes(zip_bytes([("archive/data.pkl", CLEAN)]))

    def explode(*args, **kwargs):
        raise RuntimeError("inspector blew up")

    monkeypatch.setattr(archive_module, "inspect", explode)

    report = inspect_artifact(path)

    assert report.inspector_errors
    for entry in report.coverage.in_scope():
        assert entry.state is CoverageState.FAILED, entry
    assert report.verdict is Verdict.INCONCLUSIVE


# --------------------------------------------------------------------------
# The model itself
# --------------------------------------------------------------------------


def test_the_worst_state_wins_whatever_order_it_arrives_in():
    """Coverage is assembled from several writers - the branch that ran, the
    findings it produced, the floor applied after. If a later writer could
    raise a surface back to COMPLETE, then the order those writers happen to
    run in would decide what the report claims."""
    forward = Coverage()
    forward.set(SurfaceCoverage(Surface.LOAD_TIME_EXECUTION, CoverageState.COMPLETE, REASON_READ_IN_FULL))
    forward.set(SurfaceCoverage(Surface.LOAD_TIME_EXECUTION, CoverageState.PARTIAL, REASON_PARSE_FAILED))

    backward = Coverage()
    backward.set(SurfaceCoverage(Surface.LOAD_TIME_EXECUTION, CoverageState.PARTIAL, REASON_PARSE_FAILED))
    backward.set(SurfaceCoverage(Surface.LOAD_TIME_EXECUTION, CoverageState.COMPLETE, REASON_READ_IN_FULL))

    assert forward.state(Surface.LOAD_TIME_EXECUTION) is CoverageState.PARTIAL
    assert backward.state(Surface.LOAD_TIME_EXECUTION) is CoverageState.PARTIAL


def test_a_surface_can_move_out_of_not_assessed_but_never_back_into_it():
    """The one promotion allowed. A surface nobody had undertaken to look at
    can become one that was looked at; a surface that was looked at and found
    wanting cannot be quietly reclassified as out of scope."""
    coverage = baseline()
    assert coverage.state(Surface.RAW_TENSOR_CONTENT) is CoverageState.NOT_ASSESSED

    coverage.set(SurfaceCoverage(Surface.RAW_TENSOR_CONTENT, CoverageState.PARTIAL, REASON_PARSE_FAILED))
    assert coverage.state(Surface.RAW_TENSOR_CONTENT) is CoverageState.PARTIAL

    coverage.set(SurfaceCoverage(Surface.RAW_TENSOR_CONTENT, CoverageState.NOT_ASSESSED, REASON_OUTSIDE_STATIC_SCOPE))
    assert coverage.state(Surface.RAW_TENSOR_CONTENT) is CoverageState.PARTIAL, "downgrades are sticky"


def test_findings_fold_in_the_same_way_whatever_order_they_come_in():
    forward = apply_findings(baseline(), ["ACT-ZIP-003", "ACT-PKL-006"])
    backward = apply_findings(baseline(), ["ACT-PKL-006", "ACT-ZIP-003"])

    assert forward.to_dict() == backward.to_dict()
    assert forward.state(Surface.LOAD_TIME_EXECUTION) is CoverageState.FAILED


@pytest.mark.parametrize("required", list(CoverageState))
def test_not_assessed_never_satisfies_a_requirement_that_asks_for_anything(required):
    """A policy that requires a COMPLETE execution surface must not be
    satisfied by a tool that declined to look. The only requirement
    NOT_ASSESSED meets is the empty one."""
    coverage = baseline()

    satisfied = coverage.satisfies(Surface.RAW_TENSOR_CONTENT, required)

    assert satisfied is (required is CoverageState.NOT_ASSESSED)


def test_the_weakest_in_scope_surface_ignores_the_ones_out_of_scope():
    coverage = baseline()
    coverage.set(SurfaceCoverage(Surface.LOAD_TIME_EXECUTION, CoverageState.COMPLETE, REASON_READ_IN_FULL))
    coverage.set(SurfaceCoverage(Surface.ARTIFACT_METADATA, CoverageState.PARTIAL, REASON_PARSE_FAILED))

    weakest = coverage.weakest_in_scope()

    assert weakest is not None
    assert weakest.surface is Surface.ARTIFACT_METADATA


def test_coverage_survives_a_round_trip_through_json():
    """It is signed into attestations and read back by `actaira verify`, so a
    lossy round trip would mean a receipt that cannot be checked."""
    original = apply_findings(baseline(), ["ACT-ZIP-007", "ACT-PKL-008"])

    restored = Coverage.from_dict(original.to_dict())

    assert restored.to_dict() == original.to_dict()


# --------------------------------------------------------------------------
# The table itself cannot rot
# --------------------------------------------------------------------------


def test_every_rule_the_inspector_can_emit_is_classified():
    """A rule with no surface is a rule whose effect on coverage is silence,
    which is how the flat set rotted in the first place."""
    import json
    from pathlib import Path

    from conftest import REPO_ROOT

    catalogue = json.loads((Path(REPO_ROOT) / "src" / "actaira" / "i18n" / "en.json").read_text("utf-8"))
    # Only the rules that speak about reading an artifact need a surface. A
    # rule about what was FOUND - a gadget, a traversal - is a finding, not a
    # coverage statement, and classifying it would be a category error.
    coverage_rules = {
        rule for rule in catalogue["rules"]
        if rule in classified_rules() or rule in UNREAD_RULE_IDS
    }
    assert coverage_rules, "the catalogue is loaded"
    for rule in coverage_rules:
        assert rule_effect(rule) is not None, rule


def test_the_legacy_unread_set_is_derived_and_agrees_with_the_table():
    """`UNREAD_RULE_IDS` is kept for anything importing it, computed from the
    table rather than maintained beside it. Two hand-maintained lists of the
    same thing is exactly the shape of the bug this replaced."""
    derived = {
        rule for rule in classified_rules()
        if (effect := rule_effect(rule)) and effect[1].in_scope and effect[1] is not CoverageState.COMPLETE
    }

    assert UNREAD_RULE_IDS == derived
    assert "ACT-ZIP-007" not in UNREAD_RULE_IDS
