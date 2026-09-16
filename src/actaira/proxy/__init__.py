"""Recording what an agent asked its tools to do, from outside the agent.

Design note D-254, the invariant this whole package exists to keep.

A proxy is the fail-open surface of this product. Everything it does not see,
it does not know it did not see: the agent called a tool, the transport broke,
and the honest-looking outcome is a trace that simply has one fewer event in
it. That is the exact shape of the three defects phase 0.1 closed in the
verifier, and it is worse here, because there is no second reader to notice.

So COMPLETENESS IS THE INVARIANT, stated once and enforced in one place:

    a trace is complete only if something recorded that it ended
    AND nothing recorded a hole.

Every failure path in `stdio.py` and `http.py` therefore ends in `Recorder.gap`
rather than in a `return`, a `pass` or a swallowed exception, and the recorder
starts out incomplete - a recorder nobody closed produces an incomplete trace,
not an empty clean one. The transports are two thin adapters over this class
precisely so that the rule lives above both of them and cannot be kept in one
and forgotten in the other.

Transparency is the second rule and it points the other way: if the proxy
breaks, the agent keeps working. A recorder that takes the agent down with it
is a recorder nobody runs a second time, so the bad news travels in the trace
instead of in the agent's face.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from ..trace import CaptureLevel
from ..trace.model import Gap, GapReason, Trace, TraceEvent
from ..trace.redact import References, content_or_none, digest, file_ref, new_salt
from . import protocol

SOURCE = "mcp-proxy"
# The one JSON-RPC method that is an act. `initialize`, `tools/list` and the
# notifications are the agent finding out what exists; recording them as
# events would put positions in the index that no rule can ever cite.
TOOL_CALL = "tools/call"


class Recorder:
    """The trace under construction, and the only place a gap is declared.

    Optionally mirrored to a JSONL file as it goes, because `watch` runs one
    proxy process per server and has to reassemble them afterwards. Written
    line by line rather than at the end: a proxy killed with the agent still
    leaves what it had seen, and what it had not becomes a declared gap when
    the session is assembled.
    """

    def __init__(
        self,
        session_id: str,
        source: str = SOURCE,
        capture_level: CaptureLevel = CaptureLevel.L1,
        record_path: Path | None = None,
        with_content: bool = False,
        salt: str | None = None,
        run_id: str = "",
    ) -> None:
        self.session_id = session_id
        self.source = source
        self.capture_level = capture_level
        self.record_path = Path(record_path) if record_path is not None else None
        self.with_content = with_content
        # The operator's own per-session salt, for `redact.file_ref`. Passed in
        # rather than made here: `watch` generates one for the whole session and
        # every proxy in it has to reference the same file the same way. A
        # recorder handed none mints its own, because a recorder that cannot
        # mint a reference cannot give two calls two identities (D-268).
        self.salt = salt or new_salt()
        # D-268. Every third-party value this recorder publishes goes through
        # here and the literal stays on this side of it. `trace/provenance.py`
        # is the table that says which fields those are; this is the door.
        self.refs = References(self.salt)
        # Which run wrote this row. Read back by `assemble`, which refuses the
        # rows a previous run left in the same directory - see D-266.
        self.run_id = run_id
        self.events: list[TraceEvent] = []
        self.gaps: list[Gap] = []
        self.moments: list[str] = []
        self.closed = False
        # A recorder whose sidecar has failed once cannot vouch for what came
        # after, so it never writes an `end` again - see `_append`.
        self.writes_failed = False
        # Design note D-266. The HTTP transport answers on a ThreadingHTTPServer,
        # so several handler threads reach ONE recorder at once. Without this,
        # two appends interleave inside a line - the assembled trace then
        # declares an unparsable record, which is a correct fail-closed outcome
        # for an entirely avoidable cause - and `self.events` was being mutated
        # from two threads besides.
        #
        # Rejected: one file per writer, assembled afterwards. It multiplies the
        # stale-file problem D-266's other half exists to close, and it needs an
        # ordering key across files that MCP 2026-07-28 no longer provides.
        # Rejected: a temporary file per record renamed into place - atomic, and
        # one inode per tool call plus that same ordering problem. A lock costs
        # one uncontended acquire per record, and every writer is in this
        # process, which is the case the other two were solving for writers that
        # are not.
        self._writing = threading.RLock()
        if self.record_path is not None:
            self.record_path.parent.mkdir(parents=True, exist_ok=True)
            self.record_path.write_text("", encoding="utf-8")

    # -- what happened ----------------------------------------------------

    def call(
        self,
        name: str,
        arguments: Any,
        at: str | None = None,
        call_id: str | None = None,
        message: dict[str, Any] | None = None,
    ) -> TraceEvent:
        """A tool call was seen going out. Its result is unrecorded until it
        is recorded, which is what makes a lost answer visible.

        `call_id` is the JSON-RPC id the agent used. It was dropped before, so
        `gen_ai.tool.call.id` was null on every L1 event and a gap had nothing
        to anchor to but its position - which is the defect `Gap` now refuses.
        """
        with self._writing:
            event = TraceEvent(
                index=len(self.events),
                capture_level=self.capture_level,
                tool_name=name,
                call_id=self.refs.of(call_id),
                timestamp=at,
                arguments_sha256=digest(arguments),
                result_sha256=None,
                conversation_id=self.refs.of(self.session_id),
                # Read off THIS request rather than off a handshake, because MCP
                # 2026-07-28 has no handshake left to read it off - see D-264.
                traceparent=protocol.correlation_of(message),
                protocol_version=protocol.revision_of(message),
                client=self.refs.of(protocol.client_of(message)),
                arguments=content_or_none(arguments, self.with_content),
            )
            self.events.append(event)
            self._append({"kind": "call", "event": event.to_dict()})
            if at:
                self.moments.append(at)
            if message is not None:
                self._what_the_request_did_not_say(event)
        return event

    def _what_the_request_did_not_say(self, event: TraceEvent) -> None:
        """Declared, never filled in. Both of these used to be carried by the
        session the protocol no longer has, so their absence is new and is a
        hole rather than a default."""
        if event.protocol_version is None:
            self.gap(
                GapReason.PROTOCOL_VERSION_UNKNOWN,
                f"the call to {event.tool_name} declared no protocol revision in its "
                "_meta, so this tool cannot say which revision of MCP it was "
                "interposing on when it observed it",
            )
        if event.traceparent is None:
            self.gap(
                GapReason.NO_CORRELATION_KEY,
                f"the call to {event.tool_name} carried no traceparent. MCP 2026-07-28 "
                "removed protocol-level sessions (SEP-2567), so there is no key by which "
                "this call can be correlated with anything else observed in this run",
            )

    def discover(self, response: dict[str, Any]) -> None:
        """The tool inventory a `server/discover` result advertised.

        Recorded when it goes past, never requested. Rejected: issuing
        `server/discover` ourselves when the agent does not - it would get the
        inventory at the cost of putting a message into the session that the
        agent did not send, and a witness that acts is a witness to its own
        acts. That is the fourth negative, and `discover_unavailable` is the
        honest answer instead.
        """
        tools = protocol.tools_in_discover(response)
        if tools is None:
            return
        with self._writing:
            self._append({
                "kind": "discover",
                "tools": tools,
                "protocol_version": protocol.revision_of(response),
                "server": self.refs.of(protocol.server_of(response)),
            })

    def settle(self, event: TraceEvent, response: dict[str, Any]) -> None:
        """Record the answer to one call, and whether the tool said it failed.

        MCP reports a TOOL failure inside the result, as `isError`, and keeps
        the JSON-RPC `error` member for protocol faults. Reading only the
        second one is what the first real session through this proxy exposed:
        a verification that had failed was recorded as a call that succeeded -
        a wrong fact in the evidence, which is worse than a declared gap.
        """
        with self._writing:
            event.server = self.refs.of(protocol.server_of(response)) or event.server
            if event.protocol_version is None:
                event.protocol_version = protocol.revision_of(response)
            event.result_type, event.result_type_assumed = protocol.result_type_of(response)
            event.request_state = self.refs.of(protocol.request_state_of(response))
            if "error" in response:
                self.result(event, response.get("error"), is_error=True)
            else:
                payload = response.get("result")
                failed = isinstance(payload, dict) and bool(payload.get("isError"))
                self.result(event, payload, is_error=failed)
            if (
                event.result_type == protocol.RESULT_INPUT_REQUIRED
                and event.request_state is None
            ):
                # SEP-2322: this is the interim result of a multi round-trip
                # request. Its retry is the same logical call arriving a second
                # time, and the handle is the only thing that says so. Never the
                # arrival order - that is the bug phase 1 paid for twice.
                self.gap(
                    GapReason.INPUT_STATE_ABSENT,
                    f"the call to {event.tool_name} was answered `input_required` with no "
                    "requestState, so the retry that follows it cannot be paired with it "
                    "and this tool records the two as two calls",
                )

    def result(self, event: TraceEvent, payload: Any, is_error: bool = False) -> None:
        with self._writing:
            event.result_sha256 = digest(payload)
            event.result = content_or_none(payload, self.with_content)
            if is_error:
                event.error_type = "tool_error"
            self._append({"kind": "result", "event": event.to_dict()})

    def gap(self, reason: GapReason, detail: str) -> None:
        with self._writing:
            after, unanchored = self._anchor()
            gap = Gap(reason=reason, detail=detail, after=after, unanchored=unanchored)
            if gap.key() not in {existing.key() for existing in self.gaps}:
                self.gaps.append(gap)
            self._append({"kind": "gap", "gap": gap.to_dict(self._index_of())})

    def _anchor(self) -> tuple[str | None, str | None]:
        if not self.events:
            return None, "nothing had been observed when this hole was recorded"
        identity = self.events[-1].identity()
        if identity is None:
            return None, "the last call observed before this hole carries no id of its own"
        return identity, None

    def _index_of(self) -> dict[str, int]:
        positions: dict[str, int] = {}
        for event in self.events:
            identity = event.identity()
            if identity is None:
                continue
            positions[identity] = -1 if identity in positions else event.index
        return positions

    def close(self) -> None:
        """The session ended and this recorder saw it end.

        A recorder that has already lost a write does not get to say this: it
        cannot know what it failed to record after the loss, and the assembled
        trace reads a part with no `end` as one that did not finish. That is
        the route by which a sidecar failure survives the process that had it.
        """
        with self._writing:
            if self.writes_failed:
                return
            self.closed = True
            self._append({"kind": "end"})
            self.write_reference_map()

    def write_reference_map(self) -> None:
        """The operator's half of D-268, beside their records and never in a document.

        One file per recorder rather than one shared file: `watch` runs a proxy
        per server in its own process, and two processes appending to one map
        is the interleaving D-266 took out of the record files. `assemble` never
        reads these - it has no need of the literals - and `interposition.json`
        lists them so that the operator has one place to start from.
        """
        if self.record_path is None or not self.refs.map:
            return
        try:
            self.record_path.with_suffix(".refs.json").write_text(
                json.dumps(self.refs.map, indent=2, sort_keys=True, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            # The same rule as `_append`: a recorder that cannot write must not
            # kill the agent's session. What is lost is the operator's ability
            # to resolve their own references, not any claim in the document.
            self.gap(
                GapReason.UNPARSABLE_RECORD,
                "the map from this session's references back to the values they stand for "
                "could not be written, so the trace is readable by a third party and not "
                "by the operator who recorded it",
            )

    # -- the trace --------------------------------------------------------

    def trace(self) -> Trace:
        trace = Trace(
            session_id=self.refs.of(self.session_id) or "",
            source=self.source,
            capture_level=self.capture_level,
            agent_name=self.source,
            started_at=min(self.moments) if self.moments else None,
            ended_at=max(self.moments) if self.moments else None,
            events=list(self.events),
            gaps=list(self.gaps),
            end_recorded=self.closed,
        )
        trace.note_missing_results()
        return trace

    # -- the sidecar file -------------------------------------------------

    def _append(self, row: dict[str, Any]) -> None:
        if self.record_path is None:
            return
        # Every row says which run wrote it, so `assemble` can refuse the rows a
        # previous run left behind in the same directory - see D-266.
        row = {**row, "run": self.run_id}
        try:
            with self._writing, self.record_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
                handle.flush()
        except OSError:
            # A recorder that cannot write must not kill the agent's session.
            # It also must not go on pretending it recorded the session: this
            # gap lives in a process that is about to exit, and `assemble`
            # reads only the file that just refused the write. So the flag is
            # the thing that survives - `close` will not write an `end`, the
            # part has no end, and the assembled trace is incomplete with
            # `end_not_recorded` against it. The comment here used to claim
            # assembly would find the hole; assembly could not see it at all.
            self.writes_failed = True
            after, unanchored = self._anchor()
            gap = Gap(
                reason=GapReason.UNPARSABLE_RECORD,
                detail=(
                    f"the record file {file_ref(self.record_path, self.salt)} could not be "
                    "written, so what this proxy observed after this point did not survive "
                    "to be assembled"
                ),
                after=after,
                unanchored=unanchored,
            )
            if gap.key() not in {existing.key() for existing in self.gaps}:
                self.gaps.append(gap)
