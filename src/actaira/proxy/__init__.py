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
from pathlib import Path
from typing import Any

from ..trace import CaptureLevel
from ..trace.model import Gap, GapReason, Trace, TraceEvent
from ..trace.redact import content_or_none, digest

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
    ) -> None:
        self.session_id = session_id
        self.source = source
        self.capture_level = capture_level
        self.record_path = Path(record_path) if record_path is not None else None
        self.with_content = with_content
        self.events: list[TraceEvent] = []
        self.gaps: list[Gap] = []
        self.moments: list[str] = []
        self.closed = False
        if self.record_path is not None:
            self.record_path.parent.mkdir(parents=True, exist_ok=True)
            self.record_path.write_text("", encoding="utf-8")

    # -- what happened ----------------------------------------------------

    def call(self, name: str, arguments: Any, at: str | None = None) -> TraceEvent:
        """A tool call was seen going out. Its result is unrecorded until it
        is recorded, which is what makes a lost answer visible."""
        event = TraceEvent(
            index=len(self.events),
            capture_level=self.capture_level,
            tool_name=name,
            timestamp=at,
            arguments_sha256=digest(arguments),
            result_sha256=None,
            conversation_id=self.session_id,
            arguments=content_or_none(arguments, self.with_content),
        )
        self.events.append(event)
        self._append({"kind": "call", "event": event.to_dict()})
        if at:
            self.moments.append(at)
        return event

    def settle(self, event: TraceEvent, response: dict[str, Any]) -> None:
        """Record the answer to one call, and whether the tool said it failed.

        MCP reports a TOOL failure inside the result, as `isError`, and keeps
        the JSON-RPC `error` member for protocol faults. Reading only the
        second one is what the first real session through this proxy exposed:
        a verification that had failed was recorded as a call that succeeded -
        a wrong fact in the evidence, which is worse than a declared gap.
        """
        if "error" in response:
            self.result(event, response.get("error"), is_error=True)
            return
        payload = response.get("result")
        failed = isinstance(payload, dict) and bool(payload.get("isError"))
        self.result(event, payload, is_error=failed)

    def result(self, event: TraceEvent, payload: Any, is_error: bool = False) -> None:
        event.result_sha256 = digest(payload)
        event.result = content_or_none(payload, self.with_content)
        if is_error:
            event.error_type = "tool_error"
        self._append({"kind": "result", "event": event.to_dict()})

    def gap(self, reason: GapReason, detail: str) -> None:
        gap = Gap(after_index=len(self.events) - 1, reason=reason, detail=detail)
        if gap.key() not in {existing.key() for existing in self.gaps}:
            self.gaps.append(gap)
        self._append({"kind": "gap", "gap": gap.to_dict()})

    def close(self) -> None:
        """The session ended and this recorder saw it end."""
        self.closed = True
        self._append({"kind": "end"})

    # -- the trace --------------------------------------------------------

    def trace(self) -> Trace:
        trace = Trace(
            session_id=self.session_id,
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
        try:
            with self.record_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
                handle.flush()
        except OSError:
            # A recorder that cannot write must not kill the agent's session.
            # The hole this leaves is found at assembly time, where the parts
            # are counted against what each proxy said it had seen.
            self.gaps.append(
                Gap(
                    after_index=len(self.events) - 1,
                    reason=GapReason.UNPARSABLE_RECORD,
                    detail=(
                        f"the record file {self.record_path} could not be written, so what this "
                        "proxy observed after this point did not survive to be assembled"
                    ),
                )
            )
