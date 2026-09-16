"""The canonical trace: one shape for both sources, and what it may claim.

Two gate properties live here. A trace re-parsed and re-serialised has the
same digest, for both sources, or nothing downstream can be signed. And the
capture level decides what the document says about authenticity: at L0 the
question does not apply, at L1 it applies and is answered, and those are three
states rather than two because conflating "does not apply" with "applies and
was not established" is the defect phase 0.1 was spent closing.
"""
from __future__ import annotations

import json

import pytest

from actaira.model import canonical_json
from actaira.trace import CaptureLevel
from actaira.trace.model import (
    SCHEMA_VERSION,
    Gap,
    GapReason,
    Trace,
    TraceEvent,
    parse_trace,
    trace_digest,
)


def _event(index: int, name: str = "Bash", result: str | None = "bb" * 32) -> TraceEvent:
    return TraceEvent(
        index=index,
        capture_level=CaptureLevel.L0,
        tool_name=name,
        call_id=f"toolu_{index:04d}",
        timestamp=f"2026-01-01T00:00:0{index % 10}Z",
        arguments_sha256="aa" * 32,
        result_sha256=result,
    )


def _trace(level: CaptureLevel = CaptureLevel.L0, gaps: list[Gap] | None = None) -> Trace:
    return Trace(
        session_id="0f9c2a51-0000-4000-8000-000000000001",
        source="claude-code",
        capture_level=level,
        agent_name="claude-code",
        agent_versions=("2.1.268",),
        started_at="2026-01-01T00:00:00Z",
        ended_at="2026-01-01T00:00:09Z",
        events=[_event(0), _event(1, "Read")],
        gaps=list(gaps or []),
        end_recorded=not gaps,
    )


# ---------------------------------------------------------------------------
# Gate 4: the digest is reproducible, for both sources
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("level", [CaptureLevel.L0, CaptureLevel.L1])
def test_a_trace_reparsed_and_reserialised_has_the_same_digest(level):
    """Parse, serialise, parse again. Same bytes, same digest, or a signature
    over a trace says nothing about the trace somebody else reads back."""
    document = _trace(level).to_dict()
    first = canonical_json(document)

    reparsed = parse_trace(json.loads(first.decode("utf-8"))).to_dict()

    assert canonical_json(reparsed) == first
    assert trace_digest(reparsed) == trace_digest(document)


def test_the_digest_is_not_taken_over_a_document_carrying_its_own_digest():
    """A self-referential field cannot be hashed into the thing it describes.
    The digest is over the document without it, and the writer puts it beside
    the document rather than inside."""
    document = _trace().to_dict()

    assert "trace_sha256" not in document


def test_a_changed_event_changes_the_digest():
    """The other direction, so the test above cannot pass by hashing nothing."""
    before = trace_digest(_trace().to_dict())
    moved = _trace()
    moved.events[1].tool_name = "Write"

    assert trace_digest(moved.to_dict()) != before


def test_the_document_declares_the_schema_version_it_was_written_against():
    document = _trace().to_dict()

    assert document["schema_version"] == SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Gate 5: what the capture level lets the trace claim about authenticity
# ---------------------------------------------------------------------------


def test_an_l0_trace_declares_authenticity_not_evaluated_with_its_reason():
    """CLAUDE.md: a trace the audited agent produced about itself cannot claim
    authenticity, and says so rather than leaving the field out."""
    document = _trace(CaptureLevel.L0).to_dict()

    authenticity = document["authenticity"]
    assert authenticity["state"] == "not_evaluated"
    assert authenticity["applies"] is False
    assert len(authenticity["reason"]) > 40, "a state with no reason is a state nobody can check"


def test_an_l1_trace_does_not_declare_authenticity_not_evaluated():
    """At L1 the question applies: it was captured at the edge of the process."""
    document = _trace(CaptureLevel.L1).to_dict()

    authenticity = document["authenticity"]
    assert authenticity["applies"] is True
    assert authenticity["state"] == "established"


def test_an_l1_trace_with_a_gap_says_authenticity_was_not_established():
    """The third state, and the one the whole distinction exists for. A gap at
    L1 is not "does not apply" - it is a question that applied and could not
    be answered, which is a failure and reads as one."""
    gap = Gap(reason=GapReason.TRANSPORT_CLOSED, detail="the server closed stdout")
    document = _trace(CaptureLevel.L1, gaps=[gap]).to_dict()

    authenticity = document["authenticity"]
    assert authenticity["applies"] is True
    assert authenticity["state"] == "not_established"
    assert document["complete"] is False


def test_the_three_authenticity_states_are_three_and_not_two():
    """Stated once, as the property rather than as three examples, because the
    two that look alike are the two that were conflated."""
    states = {
        _trace(CaptureLevel.L0).to_dict()["authenticity"]["state"],
        _trace(CaptureLevel.L1).to_dict()["authenticity"]["state"],
        _trace(
            CaptureLevel.L1,
            gaps=[Gap(reason=GapReason.TRANSPORT_CLOSED, detail="x")],
        ).to_dict()["authenticity"]["state"],
    }

    assert states == {"not_evaluated", "established", "not_established"}


# ---------------------------------------------------------------------------
# The inverted default, at the level of one document
# ---------------------------------------------------------------------------


def test_a_trace_whose_end_was_never_recorded_is_not_complete():
    """Nothing is complete because nothing said it was broken. Completeness is
    asserted by a recorded ending, never inferred from an absence of news."""
    trace = _trace()
    trace.end_recorded = False

    document = trace.to_dict()

    assert document["complete"] is False
    assert any(gap["reason"] == GapReason.END_NOT_RECORDED.value for gap in document["gaps"])


def test_an_event_with_no_recorded_result_is_a_gap_rather_than_a_success():
    trace = _trace()
    trace.events[1].result_sha256 = None
    trace.note_missing_results()

    document = trace.to_dict()

    assert document["complete"] is False
    assert any(gap["reason"] == GapReason.RESULT_NOT_RECORDED.value for gap in document["gaps"])


def test_events_are_indexed_from_zero_without_holes():
    """The index is what a non-conformance cites, so a hole in it is a citation
    nobody can follow back to an event."""
    document = _trace().to_dict()

    assert [event["index"] for event in document["events"]] == [0, 1]


def test_a_document_whose_indices_have_a_hole_is_refused_at_load():
    """A format error is a message at load time, per CLAUDE.md's code rules."""
    document = _trace().to_dict()
    document["events"][1]["index"] = 7

    with pytest.raises(ValueError, match="index"):
        parse_trace(document)


def test_a_document_declaring_an_unknown_schema_version_is_refused():
    document = _trace().to_dict()
    document["schema_version"] = "trace/v99"

    with pytest.raises(ValueError, match="trace/v99"):
        parse_trace(document)


def test_a_document_declaring_an_unknown_capture_level_is_refused():
    document = _trace().to_dict()
    document["capture_level"] = "L9"

    with pytest.raises(ValueError, match="L9"):
        parse_trace(document)


# ---------------------------------------------------------------------------
# The vocabulary is OpenTelemetry's where OpenTelemetry has one
# ---------------------------------------------------------------------------


def test_the_event_uses_the_genai_attribute_names():
    """CLAUDE.md: the field names follow the OpenTelemetry GenAI conventions,
    and we do not invent vocabulary where one exists."""
    event = _trace().to_dict()["events"][0]

    assert event["gen_ai.tool.name"] == "Bash"
    assert event["gen_ai.tool.call.id"] == "toolu_0000"
    assert event["gen_ai.operation.name"] == "execute_tool"


def test_every_deviation_from_the_genai_vocabulary_is_written_down():
    """A deviation nobody wrote down is one the next reader has to guess at."""
    from actaira.trace import model as model_mod

    for field in model_mod.OUR_OWN_FIELDS:
        assert field in model_mod.WHY_OUR_OWN, f"{field} deviates from OTel with no reason written"
        assert len(model_mod.WHY_OUR_OWN[field]) > 30, field


def test_a_level_whose_blind_spots_nobody_listed_does_not_claim_to_have_none():
    """An empty `blind_spots` is the strongest claim in the document - this
    level sees everything - and it used to be made by an omission. L2 and L3
    are named and unbuilt, so they were the case that would have hit first."""
    from actaira.trace.model import blind_spots_of

    for level in (CaptureLevel.L2, CaptureLevel.L3):
        spots = blind_spots_of(level)
        assert spots, f"{level.value} published an empty list of blind spots"
        assert level.value in spots[0]["why"]


def test_every_level_says_something_about_what_it_cannot_see():
    from actaira.trace.model import blind_spots_of

    for level in CaptureLevel:
        assert blind_spots_of(level), level
