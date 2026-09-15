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



# ---------------------------------------------------------------------------
# The rule table, which the inspector used to read
# ---------------------------------------------------------------------------

def test_every_classified_rule_names_a_surface_a_state_and_a_reason():
    """`rule_effect` is the whole of design note D-101: a rule has to say what
    it limits, which is what separates "I did not decompress 3.9 GB of
    float32" from "the header is truncated"."""
    classified = classified_rules()

    assert classified, "the table is empty, so the assertions below are vacuous"
    for rule_id in classified:
        effect = rule_effect(rule_id)

        assert effect is not None
        surface, state, reason = effect
        assert isinstance(surface, Surface)
        assert isinstance(state, CoverageState)
        assert reason, f"{rule_id} limits a surface and does not say why"


def test_a_rule_the_table_does_not_know_has_no_effect():
    """Negative control. A rule id from a package this release never saw must
    not silently pick up the effect of one it did."""
    assert rule_effect("ACT-NOT-A-RULE") is None
    assert "ACT-NOT-A-RULE" not in classified_rules()


def test_the_rule_that_the_table_exists_for_limits_only_raw_tensor_content():
    """ACT-ZIP-007 fires on every PyTorch checkpoint ever made. Design note
    D-101: before the table it meant the same as a truncated header."""
    surface, state, _ = rule_effect("ACT-ZIP-007")

    assert surface is Surface.RAW_TENSOR_CONTENT
    assert state is CoverageState.NOT_ASSESSED
