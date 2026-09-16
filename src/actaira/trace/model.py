"""The canonical trace: one document shape for every source and every level.

Design note D-250. Two sources produce traces - a transcript the agent wrote
about itself, and a proxy that watched it from outside - and they must produce
the SAME document, or every rule downstream is written twice and the second
copy rots. So the reader-specific work ends here: a reader hands over events
and gaps, and this module decides what the document says.

Three decisions the rest of the phase rests on:

**Failure is the default.** A trace is complete only when something recorded
that it ended and nothing recorded a hole. A reader that forgets to close a
trace produces an incomplete one, not a clean one. This is the same inversion
phase 0.1 made in `attest/verify.settle`, for the same reason: the shape that
reads an absence as a pass will eventually read the absence that matters.

**"Does not apply" is not "applies and was not established".** At L0 the
transcript was written by the audited agent, so authenticity has nothing to be
about: the state is `not_evaluated` and `applies` is false. At L1 the question
applies, and the answer is `established` or `not_established` depending on
whether anything was lost. Three states, because the two that look alike are
the two that get conflated.

**Nothing here reads a clock, a file or a socket.** Times are arguments.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..model import canonical_json
from . import CaptureLevel

SCHEMA_VERSION = "trace/v1"

# The OpenTelemetry GenAI attribute names this document uses verbatim, from
# open-telemetry/semantic-conventions-genai. CLAUDE.md: no invented vocabulary
# where one exists.
OTEL_FIELDS = (
    "gen_ai.operation.name",
    "gen_ai.tool.name",
    "gen_ai.tool.call.id",
    "gen_ai.conversation.id",
    "error.type",
)

# Where this document leaves the conventions, and why. Every entry is checked
# by `tests/test_trace_model.py`: a deviation nobody wrote down is one the next
# reader has to reverse-engineer from the writer.
OUR_OWN_FIELDS = ("index", "capture_level", "arguments_sha256", "result_sha256", "timestamp", "sidechain")
WHY_OUR_OWN = {
    "index": (
        "OTel identifies a span by id; a non-conformance has to cite a position "
        "in one ordered document, and an id is not an order."
    ),
    "capture_level": (
        "no OTel attribute says how the observation was made. It is the field "
        "that decides what the record may claim, so it is on every event."
    ),
    "arguments_sha256": (
        "OTel's gen_ai.tool.call.arguments carries the arguments themselves. "
        "These files hold somebody's conversation, so the default is the digest."
    ),
    "result_sha256": (
        "the same decision for gen_ai.tool.call.result, and null here means the "
        "result was never recorded rather than that it was empty."
    ),
    "timestamp": (
        "an OTel span carries start and end times as span fields rather than "
        "attributes; this is a record in a document and has one moment."
    ),
    "sidechain": (
        "whether a call came from a sub-agent of the same session. OTel models "
        "agents but not this relation, and flattening it would understate the run."
    ),
}


class GapReason(str, Enum):
    """The closed vocabulary of ways a trace can be missing something.

    Closed on purpose: a free-text reason is a reason nobody can aggregate,
    and an open one is how "unknown" becomes the commonest value in the field.
    """

    PROXY_START_FAILED = "proxy_start_failed"
    UPSTREAM_EXITED = "upstream_exited"
    TRANSPORT_CLOSED = "transport_closed"
    RESPONSE_TRUNCATED = "response_truncated"
    UPSTREAM_ERROR = "upstream_error"
    UPSTREAM_TIMEOUT = "upstream_timeout"
    END_NOT_RECORDED = "end_not_recorded"
    RESULT_NOT_RECORDED = "result_not_recorded"
    UNPARSABLE_RECORD = "unparsable_record"


@dataclass
class Gap:
    """Something that happened and was not observed, with where and why."""

    after_index: int
    reason: GapReason
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"after_index": self.after_index, "reason": self.reason.value, "detail": self.detail}

    def key(self) -> tuple[int, str]:
        return (self.after_index, self.reason.value)


@dataclass
class TraceEvent:
    index: int
    capture_level: CaptureLevel
    tool_name: str
    call_id: str | None = None
    timestamp: str | None = None
    arguments_sha256: str = ""
    result_sha256: str | None = None
    error_type: str | None = None
    sidechain: bool = False
    conversation_id: str | None = None
    # Present only when the caller asked for it with `--with-content`.
    arguments: Any = None
    result: Any = None

    def to_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "index": self.index,
            "capture_level": self.capture_level.value,
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": self.tool_name,
            "gen_ai.tool.call.id": self.call_id,
            "gen_ai.conversation.id": self.conversation_id,
            "timestamp": self.timestamp,
            "arguments_sha256": self.arguments_sha256,
            "result_sha256": self.result_sha256,
            "error.type": self.error_type,
            "sidechain": self.sidechain,
        }
        # Absent rather than null when no content was asked for: a null here
        # would read as "the arguments were empty".
        if self.arguments is not None:
            document["gen_ai.tool.call.arguments"] = self.arguments
        if self.result is not None:
            document["gen_ai.tool.call.result"] = self.result
        return document

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> TraceEvent:
        index = document.get("index")
        if not isinstance(index, int) or isinstance(index, bool):
            raise ValueError(f"event index is {index!r}, which is not an integer position")
        return cls(
            index=index,
            capture_level=CaptureLevel.parse(document.get("capture_level")),
            tool_name=str(document.get("gen_ai.tool.name", "")),
            call_id=document.get("gen_ai.tool.call.id"),
            timestamp=document.get("timestamp"),
            arguments_sha256=str(document.get("arguments_sha256", "")),
            result_sha256=document.get("result_sha256"),
            error_type=document.get("error.type"),
            sidechain=bool(document.get("sidechain", False)),
            conversation_id=document.get("gen_ai.conversation.id"),
            arguments=document.get("gen_ai.tool.call.arguments"),
            result=document.get("gen_ai.tool.call.result"),
        )


# What each level cannot see, stated by the level rather than remembered at
# each reader. The third negative: what was not observed is declared, never
# assumed away.
BLIND_SPOTS: dict[CaptureLevel, tuple[dict[str, str], ...]] = {
    CaptureLevel.L0: (
        {
            "what": "the permission decision on each individual tool call",
            "why": "the transcript records the session's permissionMode and no per-call decision",
        },
        {
            "what": "anything the agent did outside a tool call",
            "why": "only what the agent chose to write down is in the file",
        },
    ),
    CaptureLevel.L1: (
        {
            "what": "calls to the model provider",
            "why": "an MCP proxy sees tool traffic; the provider connection is L2",
        },
        {
            "what": "files, processes and network touched outside MCP",
            "why": "that is L3, and this run was not sandboxed",
        },
    ),
}

def blind_spots_of(level: CaptureLevel) -> list[dict[str, str]]:
    """What this level cannot see, and never an empty list by accident.

    A level with no entry in the table used to serialise as `blind_spots: []`,
    which reads as "this level sees everything" - the strongest claim in the
    document, made by an omission. L2 and L3 are named and unreachable, so
    that is exactly the case that would have hit first.
    """
    spots = BLIND_SPOTS.get(level)
    if spots is None:
        return [
            {
                "what": "everything this capture level does not observe",
                "why": (
                    f"nobody has enumerated the blind spots of {level.value} in this release, "
                    "so this document does not claim there are none"
                ),
            }
        ]
    return [dict(spot) for spot in spots]


NOT_EVALUATED_REASON = (
    "this trace was read from a transcript the audited agent wrote about itself, so "
    "there is nothing captured at the edge of the process to evaluate. It is diagnosis "
    "and retrospective analysis, not evidence for a third party."
)


@dataclass
class Trace:
    session_id: str
    source: str
    capture_level: CaptureLevel
    agent_name: str = ""
    agent_versions: tuple[str, ...] = ()
    started_at: str | None = None
    ended_at: str | None = None
    events: list[TraceEvent] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    end_recorded: bool = False
    child_returncode: int | None = None

    # -- gaps -------------------------------------------------------------

    def add_gap(self, reason: GapReason, detail: str, after_index: int | None = None) -> None:
        gap = Gap(
            after_index=len(self.events) - 1 if after_index is None else after_index,
            reason=reason,
            detail=detail,
        )
        if gap.key() not in {existing.key() for existing in self.gaps}:
            self.gaps.append(gap)

    def note_missing_results(self) -> None:
        """Every call whose result never arrived becomes a declared hole.

        Called by the readers, and also derived in `to_dict`, so a reader that
        forgets cannot produce a trace that looks whole.
        """
        for event in self.events:
            if event.result_sha256 is None:
                self.add_gap(
                    GapReason.RESULT_NOT_RECORDED,
                    f"the call to {event.tool_name} has no recorded result",
                    after_index=event.index,
                )

    def _all_gaps(self) -> list[Gap]:
        """Recorded holes plus the ones derivable from the events themselves.

        Derived here rather than trusted to the caller: this is the point where
        the default is inverted, and a default that depends on being remembered
        is not a default.
        """
        derived = Trace(
            session_id=self.session_id, source=self.source, capture_level=self.capture_level,
            events=self.events, gaps=list(self.gaps),
        )
        derived.note_missing_results()
        if not self.end_recorded:
            derived.add_gap(
                GapReason.END_NOT_RECORDED,
                "nothing recorded the end of this session, so what came after the last "
                "event was not observed",
                after_index=len(self.events) - 1,
            )
        return sorted(derived.gaps, key=Gap.key)

    # -- the document -----------------------------------------------------

    def authenticity(self, gaps: list[Gap]) -> dict[str, Any]:
        if self.capture_level is CaptureLevel.L0:
            return {"state": "not_evaluated", "applies": False, "reason": NOT_EVALUATED_REASON}
        if gaps:
            return {
                "state": "not_established",
                "applies": True,
                "reason": (
                    f"capture level {self.capture_level.value} observes the process from outside, "
                    f"so authenticity applies here - and {len(gaps)} gap(s) mean it was not "
                    "established for this session."
                ),
            }
        return {
            "state": "established",
            "applies": True,
            "reason": (
                f"captured at level {self.capture_level.value}, from outside the agent, with no "
                "gap recorded between the first and last observed event."
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        gaps = self._all_gaps()
        document: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "session_id": self.session_id,
            "source": self.source,
            "capture_level": self.capture_level.value,
            "agent": {"name": self.agent_name, "versions": list(self.agent_versions)},
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "authenticity": self.authenticity(gaps),
            "complete": not gaps,
            "events": [event.to_dict() for event in self.events],
            "gaps": [gap.to_dict() for gap in gaps],
            "blind_spots": blind_spots_of(self.capture_level),
        }
        if self.child_returncode is not None:
            document["child_returncode"] = self.child_returncode
        return document


def parse_trace(document: dict[str, Any]) -> Trace:
    """Read a document back, refusing what this reader does not understand.

    Format errors are raised here rather than surfacing later as a wrong
    answer, per CLAUDE.md's code rules: a malformed document is a message at
    load time, not a traceback during evaluation.
    """
    if not isinstance(document, dict):
        raise ValueError(f"a trace is an object, not a {type(document).__name__}")
    declared = document.get("schema_version")
    if declared != SCHEMA_VERSION:
        raise ValueError(f"{declared!r} is not a trace this reader understands; it reads {SCHEMA_VERSION}")

    events = [TraceEvent.from_dict(row) for row in document.get("events", [])]
    for position, event in enumerate(events):
        if event.index != position:
            raise ValueError(
                f"event index {event.index} sits at position {position}: the index is what a "
                "non-conformance cites, so a hole in it is a citation nobody can follow"
            )

    gaps = [
        Gap(
            after_index=int(row.get("after_index", -1)),
            reason=GapReason(row.get("reason")),
            detail=str(row.get("detail", "")),
        )
        for row in document.get("gaps", [])
    ]
    agent = document.get("agent") or {}
    return Trace(
        session_id=str(document.get("session_id", "")),
        source=str(document.get("source", "")),
        capture_level=CaptureLevel.parse(document.get("capture_level")),
        agent_name=str(agent.get("name", "")),
        agent_versions=tuple(agent.get("versions", ())),
        started_at=document.get("started_at"),
        ended_at=document.get("ended_at"),
        events=events,
        gaps=gaps,
        end_recorded=not any(gap.reason is GapReason.END_NOT_RECORDED for gap in gaps),
        child_returncode=document.get("child_returncode"),
    )


def trace_digest(document: dict[str, Any]) -> str:
    """sha256 over the canonical bytes of the document.

    Taken over the document WITHOUT its own digest, because a field cannot be
    inside the hash that describes it. The writer puts the digest beside the
    document; phase 3 is what signs the pair.
    """
    payload = {key: value for key, value in document.items() if key != "trace_sha256"}
    return hashlib.sha256(canonical_json(payload)).hexdigest()
