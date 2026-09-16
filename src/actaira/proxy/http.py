"""The HTTP transport, for servers the agent reaches over the network.

Same invariant as `stdio.py` and deliberately the same shape: forward, record,
and turn every way of not getting an answer into a declared gap. The failures
differ - a status code the server chose, a connection cut before the body, a
body that stops mid-message - and each is a different sentence in the trace
because they are different things to have happened.

`listen=True` additionally binds a local endpoint the agent points at, which
is how `watch` interposes without the agent knowing. It binds to 127.0.0.1
and nothing else: a recorder that accepted connections from the network would
be a hole in the machine it was installed to make auditable.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ..trace.model import GapReason
from ..trace.redact import endpoint, failure_kind
from . import TOOL_CALL, Recorder
from .stdio import _now

MAX_BODY_BYTES = 32 * 1024 * 1024


class HttpProxy:
    def __init__(
        self,
        upstream: str,
        recorder: Recorder,
        listen: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.upstream = upstream
        self.recorder = recorder
        self.timeout = timeout
        self.listen = listen
        self.server: ThreadingHTTPServer | None = None

    # -- lifecycle --------------------------------------------------------

    def start(self) -> bool:
        if not self.listen:
            return True
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return  # stdout belongs to whoever is reading the trace

            def do_POST(self) -> None:  # noqa: N802 - the base class's spelling
                length = min(int(self.headers.get("Content-Length", "0") or 0), MAX_BODY_BYTES)
                try:
                    message = json.loads(self.rfile.read(length) or b"{}")
                except ValueError:
                    self.send_error(400, "not JSON")
                    return
                answer = proxy.request(message)
                if answer is None:
                    # The gap is already recorded. The agent gets an error it
                    # can act on rather than a hang: transparency both ways.
                    self.send_error(502, "the upstream server did not answer")
                    return
                payload = json.dumps(answer).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        try:
            self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        except OSError as exc:
            self.recorder.gap(
                GapReason.PROXY_START_FAILED,
                f"the local endpoint the agent was to be pointed at would not bind "
                f"({failure_kind(exc)})",
            )
            return False
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return True

    @property
    def address(self) -> tuple[str, int]:
        if self.server is None:
            raise RuntimeError("this proxy is not listening")
        host, port = self.server.server_address[:2]
        return str(host), int(port)

    def close(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        self.recorder.close()

    # -- one message ------------------------------------------------------

    def request(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Forward one message. A notification has no answer to return.

        The same rule as `stdio.notify`: a message with no `id` is answered by
        an empty 202 and reading that as a truncated reply would fill the trace
        with holes that describe nothing that went wrong.
        """
        event = None
        if message.get("method") == TOOL_CALL:
            params = message.get("params") or {}
            event = self.recorder.call(
                str(params.get("name", "")),
                params.get("arguments"),
                at=_now(),
                call_id=str(message.get("id")),
            )

        request = urllib.request.Request(  # noqa: S310 - the operator's own server URL
            self.upstream,
            data=json.dumps(message).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                body = response.read(MAX_BODY_BYTES + 1)
        except urllib.error.HTTPError as exc:
            self.recorder.gap(
                GapReason.UPSTREAM_ERROR,
                f"the server answered {exc.code} instead of a JSON-RPC message, so what the "
                "call did on the other side was not observed",
            )
            return None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self.recorder.gap(
                GapReason.TRANSPORT_CLOSED,
                # The URL entire, query and all, until the phase-1 review:
                # MCP directories hand out endpoints with the token in the
                # query string, and this sentence goes in the acta.
                f"the connection to {endpoint(self.upstream)} did not deliver an answer "
                f"({failure_kind(exc)})",
            )
            return None

        if message.get("id") is None and not body.strip():
            return None
        if len(body) > MAX_BODY_BYTES:
            self.recorder.gap(
                GapReason.RESPONSE_TRUNCATED,
                f"the answer is larger than {MAX_BODY_BYTES} bytes and was not read whole",
            )
            return None
        try:
            answer = json.loads(body)
        except ValueError as exc:
            self.recorder.gap(
                GapReason.RESPONSE_TRUNCATED,
                f"the server sent {len(body)} byte(s) that are not a whole JSON-RPC message "
                f"({failure_kind(exc)})",
            )
            return None

        if event is not None:
            self.recorder.settle(event, answer if isinstance(answer, dict) else {})
        return answer
