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

SCHEMA_VERSION = "trace/v3"
# What this reader accepts, oldest first. Writing is v2 and reading is both:
# a consumer written against v1 is old rather than wrong, and a v1 document on
# somebody's disk still parses. `schemas.SUPERSEDED` records the same pair for
# the release gate, and `tests/test_schemas.py` holds v1's required fields
# frozen so it cannot shrink out from under a reader that still trusts it.
READS = ("trace/v1", "trace/v2", SCHEMA_VERSION)

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
OUR_OWN_FIELDS = (
    "index", "capture_level", "arguments_sha256", "result_sha256", "timestamp", "sidechain",
    "traceparent", "mcp.protocol.version", "mcp.client", "mcp.server",
    "mcp.result.type", "mcp.result.type_assumed", "mcp.request.state",
)
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
    # The six below come from MCP revision 2026-07-28 (see proxy/protocol.py,
    # D-264). They are spelt in the protocol's own namespace rather than
    # OTel's because OTel has no attribute for any of them, its GenAI
    # conventions are entirely in Development status, and the stabilisation
    # effort excludes MCP by name - so inventing an `gen_ai.*` spelling here
    # would be claiming a convention that does not exist.
    "traceparent": (
        "the key the protocol itself uses (SEP-414) for the W3C trace context "
        "that replaced the session id SEP-2567 removed. It is the correlation "
        "key, and it is spelt the way the wire spells it."
    ),
    "mcp.protocol.version": (
        "which revision this event's server declared. Per event and not per "
        "session, because the handshake is gone and two requests of one run "
        "can legitimately declare different revisions."
    ),
    "mcp.client": (
        "which client software sent the call, from `io.modelcontextprotocol/"
        "clientInfo`. A software name written by its author, like a host."
    ),
    "mcp.server": (
        "the same for the server, from `io.modelcontextprotocol/serverInfo`, "
        "which SEP-2575 asks servers to put in every result."
    ),
    "mcp.result.type": (
        "SEP-2322's required `resultType`: `complete`, or `input_required` "
        "when the call is one leg of a multi round-trip request."
    ),
    "mcp.result.type_assumed": (
        "whether this reader supplied that value because the server omitted "
        "it. The spec says to read an absent one as complete; publishing the "
        "assumption as the server's statement is what this field refuses."
    ),
    "mcp.request.state": (
        "the server's handle on a paused request, which is the only thing "
        "that pairs an `input_required` result with the retry that follows."
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
    NOT_INTERPOSED = "not_interposed"
    SOURCE_CONTRADICTION = "source_contradiction"
    # Added with MCP revision 2026-07-28 and with the concurrent recorder.
    # Each names something this tool could not observe and previously would
    # have had to either invent or stay quiet about; see D-264 and D-266.
    NO_CORRELATION_KEY = "no_correlation_key"
    PROTOCOL_VERSION_UNKNOWN = "protocol_version_unknown"
    DISCOVER_UNAVAILABLE = "discover_unavailable"
    INPUT_STATE_ABSENT = "input_state_absent"
    STREAM_BROKEN = "stream_broken"
    FOREIGN_RECORDS = "foreign_records"
    ORDER_NOT_OBSERVED = "order_not_observed"


@dataclass
class Gap:
    """Something that happened and was not observed, with where and why.

    Design note D-258. `after_index` used to be a field somebody filled in,
    and all three writers filled it with a count of LINES read so far - which
    the schema publishes as "the event this hole sits after". In the L0 reader
    it was worse than wrong: the events are re-sorted and re-indexed after the
    gaps are built, so even a correct index would have gone stale. This is the
    same defect as the one phase 0.1 took out of `merkle.verify_proof`:
    something identified by where it sits instead of by what it is.

    So a gap stores the IDENTITY of the event it follows, and the index is
    resolved at serialisation time against the ordered events. Rejected:
    keeping the integer and fixing the three call sites. `parse_trace` already
    refuses a hole in `event.index` because it would be "a citation nobody can
    follow"; a field that can only be right if three writers each remember the
    same convention is that same citation with nobody checking it.

    When there is no event to anchor to, the field is ABSENT with its reason
    beside it. Never -1, never 0: an invented position is indistinguishable
    from a measured one, which is the whole argument of this repository.
    """

    reason: GapReason
    detail: str
    after: str | None = None
    unanchored: str | None = None

    UNANCHORED_BY_DEFAULT = (
        "this hole is not attributable to a position between two observed events"
    )

    def to_dict(self, index_of: dict[str, int] | None = None) -> dict[str, Any]:
        document: dict[str, Any] = {"reason": self.reason.value, "detail": self.detail}
        if self.after is not None:
            document["after_event"] = self.after
        resolved, absent = self._resolve(index_of or {})
        if resolved is None:
            document["after_index_absent"] = absent
        else:
            document["after_index"] = resolved
        return document

    def _resolve(self, index_of: dict[str, int]) -> tuple[int | None, str]:
        if self.after is None:
            return None, self.unanchored or self.UNANCHORED_BY_DEFAULT
        if self.after not in index_of:
            return None, (
                "the event this hole follows carries an identity that no event in this "
                "document carries, so there is no position to cite"
            )
        position = index_of[self.after]
        if position < 0:
            return None, (
                "more than one event in this document carries that identity, so a position "
                "cited from it would name an arbitrary one of them"
            )
        return position, ""

    def key(self) -> tuple[str, str, str | None, str | None]:
        """What makes two gaps the same gap: all of it.

        Keyed on `(after_index, reason)` before, so two different failures
        after the same event collapsed into one and the second one's sentence
        - the one that said what actually happened - was dropped.
        """
        return (self.reason.value, self.detail, self.after, self.unanchored)


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
    # What MCP revision 2026-07-28 makes every message carry for itself, read
    # per event because the handshake that used to carry it once per session
    # was removed (SEP-2575). See `proxy/protocol.py`.
    traceparent: str | None = None
    protocol_version: str | None = None
    client: str | None = None
    server: str | None = None
    result_type: str | None = None
    result_type_assumed: bool = False
    request_state: str | None = None
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
            "traceparent": self.traceparent,
            "mcp.protocol.version": self.protocol_version,
            "mcp.client": self.client,
            "mcp.server": self.server,
            "mcp.result.type": self.result_type,
            "mcp.result.type_assumed": self.result_type_assumed,
            "mcp.request.state": self.request_state,
        }
        # Absent rather than null when no content was asked for: a null here
        # would read as "the arguments were empty".
        if self.arguments is not None:
            document["gen_ai.tool.call.arguments"] = self.arguments
        if self.result is not None:
            document["gen_ai.tool.call.result"] = self.result
        return document

    def identity(self) -> str | None:
        """What names this event independently of where it sits.

        The tool call id the source issued. `None` when the source recorded
        none, and a gap that would have anchored to such an event says so
        rather than falling back to its position - see `Gap`.
        """
        return self.call_id or None

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
            traceparent=document.get("traceparent"),
            protocol_version=document.get("mcp.protocol.version"),
            client=document.get("mcp.client"),
            server=document.get("mcp.server"),
            result_type=document.get("mcp.result.type"),
            result_type_assumed=bool(document.get("mcp.result.type_assumed", False)),
            request_state=document.get("mcp.request.state"),
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
    # Why nothing recorded the end, when the source is one that structurally
    # cannot. Set by the reader; the generic sentence is used when it is not.
    end_detail: str | None = None
    child_returncode: int | None = None
    # How many records the source wrote twice for one call, collapsed by
    # `claude_code._events`. `None` means nobody counted, which is not zero.
    duplicate_records_collapsed: int | None = None
    # What the protocol said about itself during this run, as far as the
    # READER can say it: per server, the tool inventory `server/discover`
    # advertised at the time. The revisions observed are not here because they
    # are derivable from the events and `to_dict` derives them - a field a
    # reader has to remember to fill in is a field that is eventually empty for
    # the wrong reason, which is the argument of `note_missing_results`.
    mcp: dict[str, Any] | None = None

    # -- gaps -------------------------------------------------------------

    def add_gap(
        self,
        reason: GapReason,
        detail: str,
        after: str | None = None,
        unanchored: str | None = None,
    ) -> None:
        gap = Gap(reason=reason, detail=detail, after=after, unanchored=unanchored)
        if gap.key() not in {existing.key() for existing in self.gaps}:
            self.gaps.append(gap)

    def last_identity(self) -> tuple[str | None, str | None]:
        """The identity of the last observed event, or why there is not one."""
        if not self.events:
            return None, "nothing had been observed when this hole was recorded"
        identity = self.events[-1].identity()
        if identity is None:
            return None, (
                "the last event observed before this hole carries no call id, so there is "
                "nothing to anchor it to that survives the document being ordered"
            )
        return identity, None

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
                    after=event.identity(),
                    unanchored=(
                        None
                        if event.identity()
                        else "the call with no result carries no call id of its own"
                    ),
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
            after, unanchored = derived.last_identity()
            derived.add_gap(
                GapReason.END_NOT_RECORDED,
                self.end_detail
                or "nothing recorded the end of this session, so what came after the last "
                "event was not observed",
                after=after,
                unanchored=unanchored,
            )
        return sorted(derived.gaps, key=Gap.key)

    # -- the document -----------------------------------------------------

    def authenticity(self, gaps: list[Gap]) -> dict[str, Any]:
        if self.capture_level is CaptureLevel.L0:
            return {"state": "not_evaluated", "applies": False, "reason": NOT_EVALUATED_REASON}
        if gaps:
            # The reasons, named, rather than a count of them. A count is a
            # summary of a list the document already carries in full, and the
            # schema's own sentence is "nothing here is a summary".
            named = ", ".join(sorted({gap.reason.value for gap in gaps}))
            unobserved = sorted(
                {gap.detail for gap in gaps if gap.reason is GapReason.NOT_INTERPOSED}
            )
            about = f" What the agent reached without this tool seeing it: {'; '.join(unobserved)}." if unobserved else ""
            return {
                "state": "not_established",
                "applies": True,
                "reason": (
                    f"capture level {self.capture_level.value} observes the process from outside, "
                    f"so authenticity applies here - and this session recorded holes of these "
                    f"kinds, so it was not established: {named}.{about}"
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

    def mcp_block(self) -> dict[str, Any] | None:
        """What the protocol declared about itself, or nothing at all.

        Absent rather than empty when no event declared a revision and no
        reader supplied an inventory: an `mcp` block with two empty lists reads
        as "the protocol said nothing", and "nobody was in a position to hear"
        is a different statement. The L0 reader is the case that would have hit
        first - a transcript carries no MCP metadata whatsoever.
        """
        revisions = sorted(
            {event.protocol_version for event in self.events if event.protocol_version}
        )
        if not revisions and self.mcp is None:
            return None
        return {"protocol_revisions_observed": revisions, **(self.mcp or {})}

    def index_of_identity(self) -> dict[str, int]:
        """Every event identity to its position, and -1 where two share one.

        -1 rather than a silent first-match: an identity two events carry is
        an identity that cites neither of them, and `Gap._resolve` turns that
        into an absent field with its reason.
        """
        positions: dict[str, int] = {}
        for event in self.events:
            identity = event.identity()
            if identity is None:
                continue
            positions[identity] = -1 if identity in positions else event.index
        return positions

    def to_dict(self) -> dict[str, Any]:
        gaps = self._all_gaps()
        index_of = self.index_of_identity()
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
            "gaps": [gap.to_dict(index_of) for gap in gaps],
            "blind_spots": blind_spots_of(self.capture_level),
        }
        if self.child_returncode is not None:
            document["child_returncode"] = self.child_returncode
        if self.duplicate_records_collapsed is not None:
            # A MEASUREMENT OF THE SOURCE, NOT A SCORE OF THE RUN: it counts
            # records this reader collapsed, it is not derived from anything
            # about the agent's behaviour, and nothing aggregates it with
            # anything else - so the first negative does not reach it.
            # It travels because the records it counts are not otherwise
            # recoverable from this document: they are not in it. That is what
            # separates it from the gap count taken out of `authenticity`
            # above, which summarised a list the document already carries.
            document["duplicate_records_collapsed"] = self.duplicate_records_collapsed
        observed = self.mcp_block()
        if observed is not None:
            document["mcp"] = observed
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
    if declared not in READS:
        raise ValueError(
            f"{declared!r} is not a trace this reader understands; it reads "
            f"{', '.join(READS)}"
        )

    events = [TraceEvent.from_dict(row) for row in document.get("events", [])]
    for position, event in enumerate(events):
        if event.index != position:
            raise ValueError(
                f"event index {event.index} sits at position {position}: the index is what a "
                "non-conformance cites, so a hole in it is a citation nobody can follow"
            )

    gaps = [
        Gap(
            reason=GapReason(row.get("reason")),
            detail=str(row.get("detail", "")),
            after=row.get("after_event"),
            unanchored=row.get("after_index_absent"),
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
        duplicate_records_collapsed=document.get("duplicate_records_collapsed"),
        mcp=document.get("mcp"),
    )


def trace_digest(document: dict[str, Any]) -> str:
    """sha256 over the canonical bytes of the document.

    Taken over the document WITHOUT its own digest, because a field cannot be
    inside the hash that describes it. The writer puts the digest beside the
    document; phase 3 is what signs the pair.
    """
    payload = {key: value for key, value in document.items() if key != "trace_sha256"}
    return hashlib.sha256(canonical_json(payload)).hexdigest()
