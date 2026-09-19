"""The stdio transport: one process between the agent and one MCP server.

The agent believes it launched the server. It launched this, and this launched
the server. Lines of JSON-RPC go through in both directions unchanged, and
every `tools/call` leaves a record on the way past.

Every way this can go wrong ends at `Recorder.gap`. A `return` on any of them
would be the fail-open shape - an agent that got no answer and a trace that
never mentioned asking. The list is not repeated here: it is `GapReason`, and
a prose copy of it in this docstring is a second place to record one fact,
which had already gone stale by the time the deadline was added.

Run as a module by `actaira watch`, which rewrites the agent's `.mcp.json` to
point at `python -m actaira.proxy.stdio --record <file> -- <original command>`.
"""
from __future__ import annotations

import argparse
import json
import queue
import subprocess
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..trace.model import GapReason
from ..trace.redact import failure_kind
from . import TOOL_CALL, Recorder, protocol


def _now() -> str:
    """The clock, called at the only place a recorder is allowed to call one.

    Nothing on the decision path reads a clock; this is the capture path, and
    a captured event with no time is a captured event nobody can order against
    anything else.
    """
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# Published limit 15, in one place so that the README, `docs/COMPATIBILITY.md`,
# `CLAUDE.md` and the skip this fact forces on Windows are one sentence and not
# four. Work rule 10: two statements about the same property share their
# definition or they cancel.
#
# Measured on 2026-09-19, three ways of a child ending its output, parent
# reading the pipe: the child EXITS - Windows 0.3s, Linux 0.0s. The child closes
# fd 1 and stays alive - Linux 0.0s, WINDOWS NEVER. The child closes fd 1 and
# exits a second later - Windows 2.1s, Linux 0.0s. So pipes work; the one signal
# Windows does not deliver is a LIVE writer closing its end, which is exactly
# and only the `transport_closed` case.
WINDOWS_TRANSPORT_CLOSED_LIMIT = (
    "On Windows a server that closes its transport while still running cannot be "
    "told apart from one that has simply gone quiet. The operating system does not "
    "deliver EOF to the reader while the writing process is alive, so the gap is "
    "named `upstream_timeout` and not `transport_closed`."
)


class StdioProxy:
    """One process between the agent and one server, with a deadline.

    The deadline is not defensive tidiness. A server that writes half a message
    and then neither finishes it nor exits blocks a blocking read forever, and
    a proxy that blocks forever blocks the agent - which breaks the one promise
    that makes this thing installable at all. So the answer is read on a thread
    and waited for with a timeout, and running out of time is a declared gap
    like every other way of not getting an answer.
    """

    def __init__(self, command: list[str], recorder: Recorder, timeout: float = 30.0) -> None:
        self.command = list(command)
        self.recorder = recorder
        self.timeout = timeout
        self.process: subprocess.Popen[str] | None = None
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._partial = ""
        self._lock = threading.Lock()
        # Anything the server said that was not the answer being waited for.
        # `serve` hands these on to the agent: they are the server's own
        # notifications and progress messages, and none of our business.
        self.out_of_band: list[dict[str, Any]] = []

    # -- lifecycle --------------------------------------------------------

    def start(self) -> bool:
        try:
            self.process = subprocess.Popen(  # noqa: S603 - the operator's own server command
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        except OSError as exc:
            self.recorder.gap(
                GapReason.PROXY_START_FAILED,
                f"the server command {Path(self.command[0]).name!r} would not start "
                f"({failure_kind(exc)}). "
                "Nothing after this point was observed.",
            )
            self.process = None
            return False
        threading.Thread(target=self._pump, daemon=True).start()
        return True

    def _pump(self) -> None:
        """Read the server's output on a thread, one character at a time.

        Character by character rather than `readline` because what is sitting
        in the buffer when time runs out is the difference between "sent
        something unfinished" and "sent nothing at all", and those are two
        different things to write down.
        """
        stdout = self.process.stdout if self.process is not None else None
        if stdout is None:  # pragma: no cover - start() guarantees one
            return
        try:
            while True:
                character = stdout.read(1)
                if character == "":
                    with self._lock:
                        leftover, self._partial = self._partial, ""
                    if leftover:
                        self._lines.put(leftover)
                    self._lines.put(None)
                    return
                with self._lock:
                    self._partial += character
                    complete = character == "\n"
                    if complete:
                        line, self._partial = self._partial, ""
                if complete:
                    self._lines.put(line)
        except (OSError, ValueError):
            self._lines.put(None)

    def close(self) -> None:
        process = self.process
        if process is not None:
            try:
                if process.stdin is not None:
                    process.stdin.close()
                process.wait(timeout=10)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                process.kill()
        # Closed cleanly only when a server was ever running. A proxy that
        # never started has not seen a session end; it has seen nothing.
        if self.process is not None:
            self.recorder.close()

    # -- one message ------------------------------------------------------

    def notify(self, message: dict[str, Any]) -> None:
        """Forward a message that has no answer, and do not wait for one.

        A JSON-RPC message with no `id` is a notification. Treating one as a
        request is what hung the first real session this was run against: MCP
        clients send `notifications/initialized` immediately after
        `initialize`, the proxy forwarded it and then blocked for its deadline
        waiting for a reply the protocol says will never come, and the agent
        gave up on the server before a single tool was registered. The failure
        was declared - the trace said `upstream_timeout` - which is why it took
        one run to find rather than a week.
        """
        process = self.process
        if process is None or process.stdin is None:
            self.recorder.gap(
                GapReason.PROXY_START_FAILED,
                "a notification was sent to a server that is not running",
            )
            return
        try:
            process.stdin.write(json.dumps(message) + "\n")
            process.stdin.flush()
        except (OSError, ValueError) as exc:
            self.recorder.gap(
                GapReason.TRANSPORT_CLOSED,
                f"the server stopped reading before this notification could be delivered "
                f"({failure_kind(exc)})",
            )

    def request(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Forward one JSON-RPC message and hand back what came back.

        Returns None when nothing came back, which is always accompanied by a
        recorded gap - the two are written together here so no caller can get
        one without the other.
        """
        process = self.process
        if process is None or process.stdin is None or process.stdout is None:
            self.recorder.gap(
                GapReason.PROXY_START_FAILED,
                "a message was sent to a server that is not running, so it was not observed",
            )
            return None

        event = None
        if message.get("method") == TOOL_CALL:
            params = message.get("params") or {}
            event = self.recorder.call(
                str(params.get("name", "")),
                params.get("arguments"),
                at=_now(),
                call_id=str(message.get("id")),
                # The whole message, because MCP 2026-07-28 puts the revision,
                # the client and the correlation key in its `_meta` rather than
                # in a handshake there no longer is - see D-264.
                message=message,
            )

        try:
            process.stdin.write(json.dumps(message) + "\n")
            process.stdin.flush()
        except (OSError, ValueError) as exc:
            self.recorder.gap(
                GapReason.TRANSPORT_CLOSED,
                f"the server stopped reading before this call could be delivered "
                f"({failure_kind(exc)})",
            )
            return None

        response = self._answer_to(message)
        if response is None:
            return None

        if event is not None:
            self.recorder.settle(event, response if isinstance(response, dict) else {})
        elif message.get("method") == protocol.DISCOVER and isinstance(response, dict):
            # Not an event: `server/discover` is the agent finding out what
            # exists, like `tools/list`, and recording it as an act would put a
            # position in the index no rule can cite. It is recorded as the tool
            # INVENTORY at the moment of the run, which is what the contract is
            # later derived against.
            self.recorder.discover(response)
        return response

    def _answer_to(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """The reply to THIS message, matched by id rather than by arrival.

        Taking the next line as the answer looked right and was not. A server
        that says anything unsolicited - a progress notification, a log line, a
        reply to a notification a lax server chose to answer - shifts every
        pairing by one, and a call then carries the digest of another call's
        result. That is a wrong fact inside the evidence rather than a missing
        one, which is the only outcome worse than a declared gap.
        """
        wanted = message.get("id")
        while True:
            line = self._read_line()
            if line is None:
                return None
            try:
                answer = json.loads(line)
            except ValueError as exc:
                self.recorder.gap(
                    GapReason.RESPONSE_TRUNCATED,
                    f"the server sent {len(line)} byte(s) that are not a whole JSON-RPC "
                    f"message ({failure_kind(exc)})",
                )
                return None
            if isinstance(answer, dict) and answer.get("id") == wanted:
                return answer
            self.out_of_band.append(answer)

    def _read_line(self) -> str | None:
        process = self.process
        assert process is not None
        try:
            line = self._lines.get(timeout=self.timeout)
        except queue.Empty:
            with self._lock:
                pending = len(self._partial)
            if pending:
                self.recorder.gap(
                    GapReason.RESPONSE_TRUNCATED,
                    f"the server sent {pending} byte(s) that are not a whole message and then "
                    f"stopped, with nothing more arriving in {self.timeout:g}s",
                )
            else:
                self.recorder.gap(
                    GapReason.UPSTREAM_TIMEOUT,
                    f"the server did not answer within {self.timeout:g}s and is still running, "
                    "so what the call did on the other side was not observed",
                )
            return None
        if line is None:
            # EOF. Which of the two it is matters to whoever reads the trace:
            # a server that exited said something by exiting, and a server
            # still running that closed stdout said something else. A moment is
            # allowed for the difference to settle, because EOF on the pipe
            # arrives before the process has finished exiting and polling in
            # that window reports a running process that is already gone.
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            if process.poll() is not None:
                self.recorder.gap(
                    GapReason.UPSTREAM_EXITED,
                    f"the server exited with code {process.returncode} before answering",
                )
            else:
                self.recorder.gap(
                    GapReason.TRANSPORT_CLOSED,
                    "the server closed its output while still running, so the answer never came",
                )
            return None
        if not line.endswith("\n"):
            self.recorder.gap(
                GapReason.RESPONSE_TRUNCATED,
                f"the server's answer ended mid-line after {len(line)} byte(s)",
            )
            return None
        return line

    # -- the loop `watch` runs --------------------------------------------

    def _drain(self, writer: Any) -> None:
        """Hand the agent whatever the server said that was not an answer."""
        while self.out_of_band:
            writer.write(json.dumps(self.out_of_band.pop(0)) + "\n")
            writer.flush()

    def serve(self, reader: Any = None, writer: Any = None) -> int:
        """Pump the agent's stdin to the server and back, recording as it goes."""
        reader = reader or sys.stdin
        writer = writer or sys.stdout
        if not self.start():
            return 1
        try:
            for raw in reader:
                if not raw.strip():
                    continue
                try:
                    message = json.loads(raw)
                except ValueError:
                    # The agent's own bytes, passed through untouched to the
                    # SERVER: this proxy is not the place that decides the
                    # agent is wrong. It went to `writer` before, which is the
                    # agent's own input - so the server never saw the message,
                    # the agent got its own line back, and nothing said so.
                    process = self.process
                    if process is not None and process.stdin is not None:
                        try:
                            process.stdin.write(raw)
                            process.stdin.flush()
                        except (OSError, ValueError) as exc:
                            self.recorder.gap(
                                GapReason.TRANSPORT_CLOSED,
                                "the server stopped reading before a message this proxy could "
                                f"not read could be delivered ({failure_kind(exc)})",
                            )
                            continue
                    self.recorder.gap(
                        GapReason.UNPARSABLE_RECORD,
                        "the agent sent a message this proxy could not read as JSON-RPC. It was "
                        "forwarded to the server unchanged and whatever it asked for was not "
                        "observed",
                    )
                    continue
                if message.get("id") is None:
                    self.notify(message)
                    self._drain(writer)
                    continue
                response = self.request(message)
                self._drain(writer)
                if response is None:
                    # Design note D-302, and published limit 16. The server did
                    # not answer, so neither does this. The agent is left
                    # waiting, and a client with no deadline of its own waits
                    # forever - which is what a first report of "the tool hangs"
                    # will be, and the reporter will be right from where they
                    # are standing.
                    #
                    # Rejected: writing a JSON-RPC error back so the agent
                    # unblocks. That is this tool inventing a message the server
                    # never sent, in the agent's own input, and the agent cannot
                    # tell it from one the server did send. The fourth negative
                    # is that a witness does not act on what it observes, and
                    # fabricating traffic is acting. The gap IS recorded either
                    # way; what a reader gets from the invented reply is a
                    # session that looks like it completed.
                    continue
                writer.write(json.dumps(response) + "\n")
                writer.flush()
        finally:
            self.close()
        return 0


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - driven as a process
    parser = argparse.ArgumentParser(prog="actaira.proxy.stdio")
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--session", default="")
    parser.add_argument("--server", default="")
    parser.add_argument("--with-content", action="store_true")
    parser.add_argument("--salt", default="")
    parser.add_argument("--run", default="")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = [item for item in args.command if item != "--"]
    recorder = Recorder(
        session_id=args.session,
        record_path=args.record,
        with_content=args.with_content,
        salt=args.salt or None,
        run_id=args.run,
    )
    return StdioProxy(command, recorder).serve()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
