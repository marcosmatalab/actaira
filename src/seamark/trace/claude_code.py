"""Reading the transcripts Claude Code already wrote, and nothing more.

Design note D-253, the shape of the file, written here because a later session
cannot re-derive it from a machine that has been cleaned up.

Claude Code keeps one JSONL file per session under
`<config>/projects/<sanitised-cwd>/<session-id>.jsonl`, where `<config>` is
`~/.claude` unless `CLAUDE_CONFIG_DIR` says otherwise. A line's top-level
`type` is `assistant`, `user`, `attachment`, `system` and others; it is
NOT `tool_use`. The tool call is a content block INSIDE `message.content`:

    {"type": "assistant", "uuid": ..., "sessionId": ..., "timestamp": ...,
     "cwd": ..., "gitBranch": ..., "version": "2.1.268", "isSidechain": false,
     "message": {"role": "assistant", "content": [
        {"type": "text", "text": ...},
        {"type": "tool_use", "id": "toolu_...", "name": "Bash",
         "input": {...}, "caller": {"type": "direct"}}]}}

and the result comes back as a `tool_result` block inside a `user` line,
carrying `tool_use_id`, `content` and `is_error`, with a parallel
`toolUseResult` object on the envelope holding the same thing structured.

Older builds wrote the call as its own top-level line, which is the shape the
phase brief described. Both are read, because the format is Anthropic's
internal one and they say so: it changes between versions, and the transcripts
of one machine carry many different versions. So every field is
optional until read, a line that will not parse is a declared gap rather than
an exception, and the versions the file was written by travel in the trace.

What is NOT in the file, checked rather than assumed: the permission decision
for an individual call. Only the session's `permissionMode` is recorded. That
is declared as a blind spot of the level instead of being guessed at, which is
the third negative.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from . import CaptureLevel, Summary
from .model import Gap, GapReason, Trace, TraceEvent
from .redact import (
    References,
    content_or_none,
    digest,
    failure_kind,
    file_ref,
    new_salt,
)

UNPARSABLE_IS_UNANCHORED = (
    "a record that will not parse names no call, and the events of a session are ordered "
    "by their own timestamps afterwards, so there is no observed event this sits between"
)

SOURCE = "claude-code"
AGENT = "claude-code"
DEMO_SESSION = Path(__file__).parent / "demo-session.jsonl"


def default_home() -> Path:
    """`CLAUDE_CONFIG_DIR`, else `~/.claude`, resolved when asked.

    Resolved on call rather than at import for the reason `cli.default_key_path`
    gives: `Path.home()` raises where the environment names no home, and a
    module-level call would kill `--help` on a scrubbed container.
    """
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    if configured:
        return Path(configured)
    try:
        return Path.home() / ".claude"
    except (RuntimeError, OSError):
        return Path(".claude")


def _blocks(line: dict[str, Any]) -> list[dict[str, Any]]:
    message = line.get("message")
    if isinstance(message, dict) and isinstance(message.get("content"), list):
        return [block for block in message["content"] if isinstance(block, dict)]
    return []


class ClaudeCodeReader:
    """One L0 trace per session file, in the order the file records them."""

    def __init__(
        self,
        home: Path | None = None,
        with_content: bool = False,
        salt: str | None = None,
    ) -> None:
        self.home = Path(home) if home is not None else default_home()
        self.with_content = with_content
        # The operator's own per-scan salt for `redact.file_ref` (D-263). None
        # means this reader was given none, and then a gap about a file names
        # no reference at all rather than an unsalted digest of its path -
        # which is a dictionary lookup for anybody who can guess the path.
        # `cli.run_scan` keeps one beside the traces it writes, so re-scanning
        # into the same output produces the same bytes.
        self.salt = salt or new_salt()
        # D-268. A transcript's `sessionId` and its `tool_use.id` are strings
        # the audited agent wrote, which is the whole of the class this table
        # is about. The map goes into the `index.json` `scan` already writes.
        self.refs = References(self.salt)

    # -- finding the files ------------------------------------------------

    def session_files(self) -> list[Path]:
        projects = self.home / "projects"
        if not projects.is_dir():
            return []
        return sorted(projects.glob("*/*.jsonl"))

    def summary(self) -> Summary:
        """How many sessions, and the range of moments they cover.

        Read from the traces rather than from the files' mtimes: a file copied
        between machines carries a new mtime and the same session.
        """
        moments: list[str] = []
        traces = self.read_all()
        for trace in traces:
            moments.extend(moment for moment in (trace.started_at, trace.ended_at) if moment)
        return Summary(
            sessions=len(traces),
            first=min(moments) if moments else None,
            last=max(moments) if moments else None,
        )

    # -- reading one ------------------------------------------------------

    def read_all(self) -> list[Trace]:
        return [self.read(path) for path in self.session_files()]

    def subagent_files(self, session: Path) -> list[Path]:
        """The transcripts of this session's sub-agents.

        A sub-agent's calls do not appear in the session file. They are written
        to `<session-id>/subagents/**/*.jsonl` beside it, with workflow runs
        nested another level down, and there are far more of those files than
        of session files. A reader that took only the session file published a
        trace saying an agent had done a fraction of what it did and was silent
        about the rest. No count here: it was measured on one machine, and
        work rule 6 is that a published figure has a command behind it.
        The sibling directories
        `tool-results/` and `memory/` hold `.txt` and `.md` and are not
        transcripts, so the glob names the one that is.
        """
        directory = session.parent / session.stem / "subagents"
        if not directory.is_dir():
            return []
        return sorted(directory.rglob("*.jsonl"))

    def read(self, path: Path) -> Trace:
        """One session, its sub-agents folded in, ordered by when things happened.

        Sorted by timestamp with the file and line as tie-breakers, so the
        order is the execution's rather than the filesystem's and two runs over
        the same directory produce the same document. A line with no timestamp
        keeps its position relative to its own file, because the sort is stable
        and the events go in in file order.
        """
        sources = [path, *self.subagent_files(path)]
        collected: list[tuple[str, int, int, TraceEvent]] = []
        gaps: list[Gap] = []
        versions: set[str] = set()
        # Every moment the transcript records, not only the ones a call carries:
        # a result arrives after the call it answers, and a session that ended
        # at the last call would understate its own span.
        moments: list[str] = []
        session_id = path.stem

        collapsed = 0
        for rank, source in enumerate(sources):
            lines, source_gaps = self._lines(source)
            gaps.extend(source_gaps)
            moments.extend(
                line["timestamp"] for line in lines if isinstance(line.get("timestamp"), str)
            )
            events, seen, declared, repeats, contradictions = self._events(lines)
            versions |= seen
            collapsed += repeats
            gaps.extend(contradictions)
            if rank == 0 and declared:
                session_id = declared
            for position, event in enumerate(events):
                collected.append((event.timestamp or "", rank, position, event))

        collected.sort(key=lambda row: row[:3])
        ordered: list[TraceEvent] = []
        for index, (_when, _rank, _position, event) in enumerate(collected):
            event.index = index
            ordered.append(event)
        trace = Trace(
            session_id=self.refs.of(session_id) or "",
            source=SOURCE,
            capture_level=CaptureLevel.L0,
            agent_name=AGENT,
            agent_versions=tuple(sorted(versions)),
            started_at=min(moments) if moments else None,
            ended_at=max(moments) if moments else None,
            events=ordered,
            gaps=gaps,
            # Design note D-259. This passed `True` and called the files
            # "finished artifacts". They are not: `scan` is built to run over
            # `~/.claude` while the agent is using it, and the format has no
            # end-of-session record to read - surveyed across this machine's
            # transcripts, the last line of a session is `last-prompt`,
            # `mode`, `assistant` or `bridge-session` depending on where the
            # session stopped, and none of those means "ended".
            #
            # Rejected: reading the file's mtime, or treating "no line for an
            # hour" as ended. Both are inferences about something nobody
            # recorded, which is the third negative. An L0 trace is therefore
            # always incomplete, and says why. That costs nothing it had:
            # L0 could never assert authenticity either.
            end_recorded=False,
            end_detail=(
                "this transcript format records no end of session, so nothing in the file "
                "distinguishes a session that finished from one the agent is still writing "
                "to. What came after the last event was not observed."
            ),
            duplicate_records_collapsed=collapsed,
        )
        trace.note_missing_results()
        return trace

    def _lines(self, path: Path) -> tuple[list[dict[str, Any]], list[Gap]]:
        """Every line that parsed, and a declared gap for every one that did not."""
        lines: list[dict[str, Any]] = []
        gaps: list[Gap] = []
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            # The name and the message both carry the path, and under
            # `~/.claude/projects` the directory name IS the user's working
            # directory. `redact` is the one place that decides what a failure
            # may say: which file, as a digest, and which kind of failure.
            return [], [
                Gap(
                    reason=GapReason.UNPARSABLE_RECORD,
                    detail=(
                        f"the session record {file_ref(path, self.salt)} could not be read "
                        f"({failure_kind(exc)}), so nothing it held was observed"
                    ),
                    unanchored="the file could not be opened, so no event in it was observed",
                )
            ]
        for number, text in enumerate(raw.splitlines(), start=1):
            if not text.strip():
                continue
            try:
                line = json.loads(text)
            except ValueError as exc:
                gaps.append(
                    Gap(
                        reason=GapReason.UNPARSABLE_RECORD,
                        detail=(
                            f"record {number} of the session record {file_ref(path, self.salt)} is not "
                            f"readable JSON ({failure_kind(exc)})"
                        ),
                        unanchored=UNPARSABLE_IS_UNANCHORED,
                    )
                )
                continue
            if isinstance(line, dict):
                lines.append(line)
            else:
                gaps.append(
                    Gap(
                        reason=GapReason.UNPARSABLE_RECORD,
                        detail=(
                            f"record {number} of the session record {file_ref(path, self.salt)} is a "
                            f"{type(line).__name__}, not a record"
                        ),
                        unanchored=UNPARSABLE_IS_UNANCHORED,
                    )
                )
        return lines, gaps

    def _events(
        self, lines: list[dict[str, Any]]
    ) -> tuple[list[TraceEvent], set[str], str, int, list[Gap]]:
        """One file's calls, ONE EVENT PER CALL ID, with the results on them.

        Design note D-260. This made an event per `tool_use` BLOCK, and Claude
        Code rewrites messages: compaction and resume put the same block back
        into the file with the same `tool_use.id`. So a call that happened
        once was in the document twice, each copy fully resulted and
        indistinguishable from a real repeat, and a phase-2 rule asking how
        many times a tool was used would have counted two for one.

        No proportion here, for the reason `subagent_files` gives: it was
        measured over one person's private transcripts, `make figures` cannot
        re-measure somebody else's `~/.claude`, and work rule 6 is
        that a published figure has a command behind it. The measurement is
        in the commit that made this change.

        A `tool_use.id` names a call in the model's own protocol, so it is the
        identity, and the second record of one is a second RECORD, not a
        second call. Rejected: keeping both and marking them; a consumer who
        has to know to filter is a consumer who will not.

        What is NOT collapsed is two records of one id that disagree. That is
        the source contradicting itself, and choosing either one would be this
        tool deciding what happened. It is a hole with both digests named.
        """
        events: list[TraceEvent] = []
        by_call: dict[str, TraceEvent] = {}
        versions: set[str] = set()
        declared_session = ""
        collapsed = 0
        contradictions: list[Gap] = []

        for line in lines:
            if isinstance(line.get("version"), str):
                versions.add(line["version"])
            if isinstance(line.get("sessionId"), str) and line["sessionId"]:
                declared_session = line["sessionId"]

            for block in self._calls(line):
                event = self._event(len(events), block, line)
                known = by_call.get(event.call_id) if event.call_id else None
                if known is not None:
                    collapsed += 1
                    if known.arguments_sha256 != event.arguments_sha256:
                        contradictions.append(
                            Gap(
                                reason=GapReason.SOURCE_CONTRADICTION,
                                detail=(
                                    f"the transcript records call {known.call_id} to "
                                    f"{known.tool_name} more than once with different "
                                    f"arguments ({known.arguments_sha256[:12]} and "
                                    f"{event.arguments_sha256[:12]}). This document keeps the "
                                    "first record and does not decide which of them happened."
                                ),
                                after=known.identity(),
                            )
                        )
                    continue
                events.append(event)
                if event.call_id:
                    by_call[event.call_id] = event

            for block in _blocks(line):
                if block.get("type") != "tool_result":
                    continue
                target = by_call.get(self.refs.of(str(block.get("tool_use_id"))))
                if target is None:
                    continue
                payload = block.get("content")
                recorded = digest(payload)
                if target.result_sha256 is not None and target.result_sha256 != recorded:
                    contradictions.append(
                        Gap(
                            reason=GapReason.SOURCE_CONTRADICTION,
                            detail=(
                                f"the transcript records more than one result for call "
                                f"{target.call_id} to {target.tool_name}, and they differ "
                                f"({target.result_sha256[:12]} and {recorded[:12]}). This "
                                "document keeps the first and does not decide between them."
                            ),
                            after=target.identity(),
                        )
                    )
                    continue
                target.result_sha256 = recorded
                target.result = content_or_none(payload, self.with_content)
                if block.get("is_error"):
                    target.error_type = "tool_error"

        return events, versions, declared_session, collapsed, contradictions

    def _calls(self, line: dict[str, Any]) -> list[dict[str, Any]]:
        """Tool calls in either shape: nested in `message.content`, or the
        older top-level line the format used to write."""
        nested = [block for block in _blocks(line) if block.get("type") == "tool_use"]
        if nested:
            return nested
        if line.get("type") == "tool_use" and line.get("name"):
            return [line]
        return []

    def _event(self, index: int, block: dict[str, Any], line: dict[str, Any]) -> TraceEvent:
        arguments = block.get("input", {})
        return TraceEvent(
            index=index,
            capture_level=CaptureLevel.L0,
            tool_name=str(block.get("name", "")),
            # D-268: the call id and the session id are strings the audited
            # agent wrote, so they are referenced and not published. The
            # correlation `_events` is built on survives, because the same
            # value gives the same reference under this session's salt - see
            # the `tool_use_id` lookup below, which is referenced the same way.
            call_id=self.refs.of(block["id"]) if block.get("id") else None,
            timestamp=line.get("timestamp"),
            arguments_sha256=digest(arguments),
            result_sha256=None,
            sidechain=bool(line.get("isSidechain", False)),
            conversation_id=self.refs.of(line.get("sessionId")),
            arguments=content_or_none(arguments, self.with_content),
        )


# The shipped fixture's salt, fixed and written down. It is the one place a
# constant salt is right: the file is synthetic, it is in the wheel everybody
# downloads, and there is no value in it that a salt would protect. What a
# fresh one would cost is the whole point of the command - `seamark scan
# --demo` has to print the same bytes on every machine, or it is not a
# demonstration of a tool whose claim is that it prints the same bytes twice.
DEMO_SALT = "00" * 16


def demo_trace(with_content: bool = False) -> Trace:
    """The shipped fixture, for a machine with no agent installed at all.

    Synthetic and written by hand. A cleaned copy of a real session is still a
    real session, and this file lives in a public repository for good.
    """
    return ClaudeCodeReader(
        home=DEMO_SESSION.parent, with_content=with_content, salt=DEMO_SALT
    ).read(DEMO_SESSION)
