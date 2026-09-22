"""The HTTP transport, for servers the agent reaches over the network.

Same invariant as `stdio.py` and deliberately the same shape: forward, record,
and turn every way of not getting an answer into a declared gap. The failures
differ - a status code the server chose, a connection cut before the body, a
body that stops mid-message - and each is a different sentence in the trace
because they are different things to have happened.

`listen=True` additionally binds a local endpoint the agent points at, which is
how `watch` interposes without the agent knowing. It binds to 127.0.0.1 and
nothing else: a recorder that accepted connections from the network would be a
hole in the machine it was installed to make auditable.

Design note D-265, and it is what this phase is for. Until now that
`listen=True` path had exactly one caller and it was a test. `rewrite_config`
took an `http_port_for` argument, `watch` never passed one, and so EVERY remote
MCP server in every real session was reached by the agent directly. Phase 1.1a
made the trace refuse to claim authenticity over that, which was right and left
the product without the half of its value that remote servers are. So:

**The pairing is by JSON-RPC id, here as in stdio.** One POST carries one
message and brings back one body, which makes it look as though there is
nothing to pair - and that is exactly how a wrong pairing gets shipped. A
server answering with somebody else's id, or with the id of the request before,
returns a body this proxy must refuse rather than settle the event with. It is
the same defect as taking the next line on a pipe, and it is not less true for
arriving over a socket.

**A tool failure is `result.isError`, not the JSON-RPC `error` member.** That
lives in `Recorder.settle`, shared with stdio, so neither transport can keep
the rule while the other forgets it.

**TLS is the default context or nothing.** If the operator's server is https,
this speaks https to it with certificates verified. There is no flag that turns
that off and none is accepted in tests: a witness that will talk to anyone
holding the right IP address is not a witness.
"""
from __future__ import annotations

import json
import ssl
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ..trace.model import GapReason
from ..trace.redact import endpoint, failure_kind
from . import TOOL_CALL, Recorder, protocol
from .stdio import _now

MAX_BODY_BYTES = 32 * 1024 * 1024

# SEP-2243: standard MCP request headers, required on Streamable HTTP POSTs.
# They are derived from the body rather than copied from what the agent sent,
# because the body is what the server acts on, and a header that disagrees with
# it would make this proxy the place the two versions of the truth diverged.
METHOD_HEADER = "Mcp-Method"
NAME_HEADER = "Mcp-Name"


def _default_tls() -> ssl.SSLContext:
    """Certificates verified and hostnames checked, which is the default.

    Written out rather than left to `urlopen`'s implicit context so that the
    decision is a line somebody has to delete on purpose. There is no argument
    that reaches it.
    """
    return ssl.create_default_context()


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
        self._tls = _default_tls()

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

    @property
    def url(self) -> str:
        """Where the agent's configuration is pointed, once this is listening."""
        host, port = self.address
        return f"http://{host}:{port}/mcp"

    def close(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        self.recorder.close()

    # -- one message ------------------------------------------------------

    def _headers_for(self, message: dict[str, Any]) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        method = message.get("method")
        if isinstance(method, str) and method:
            headers[METHOD_HEADER] = method
        params = message.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        if isinstance(name, str) and name:
            headers[NAME_HEADER] = name
        return headers

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
                message=message,
            )

        request = urllib.request.Request(  # noqa: S310 - the operator's own server URL
            self.upstream,
            data=json.dumps(message).encode("utf-8"),
            headers=self._headers_for(message),
            method="POST",
        )
        # Opening and reading are two `try`s rather than one, and the split is
        # the whole of the difference between `transport_closed` and
        # `stream_broken`: a connection that was never made lost nothing, and a
        # connection that broke while the answer was arriving lost a request
        # the client will now re-issue under a new id (SEP-2575). Merging them
        # would publish one sentence for two different things to have happened.
        try:
            response = urllib.request.urlopen(  # noqa: S310
                request, timeout=self.timeout, context=self._tls
            )
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
        try:
            with response:
                body = response.read(MAX_BODY_BYTES + 1)
        except (OSError, ValueError) as exc:
            if event is not None:
                self._stream_broken(failure_kind(exc))
                return None
            self.recorder.gap(
                GapReason.RESPONSE_TRUNCATED,
                f"the answer from {endpoint(self.upstream)} stopped arriving part way "
                f"through ({failure_kind(exc)})",
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
            if event is not None:
                self._stream_broken(failure_kind(exc))
                return None
            self.recorder.gap(
                GapReason.RESPONSE_TRUNCATED,
                f"the server sent {len(body)} byte(s) that are not a whole JSON-RPC message "
                f"({failure_kind(exc)})",
            )
            return None

        if not self._answers(message, answer):
            return None

        if event is not None:
            self.recorder.settle(event, answer if isinstance(answer, dict) else {})
        elif message.get("method") == protocol.DISCOVER and isinstance(answer, dict):
            self.recorder.discover(answer)
        return answer

    def _answers(self, message: dict[str, Any], answer: Any) -> bool:
        """Whether this body is the reply to THIS message, by id.

        One POST, one body, so the pairing looks like it cannot go wrong - and
        that is why nothing checked it. A server that echoes the previous id, a
        load balancer that replays a cached body, a server behind a pool that
        answers out of turn: each returns a well-formed JSON-RPC message that
        this proxy would otherwise settle the in-flight call with, writing the
        digest of another call's result under this call's name. A wrong fact in
        the evidence, which is the only outcome worse than a declared gap.
        """
        wanted = message.get("id")
        if wanted is None:
            return True
        if isinstance(answer, dict) and answer.get("id") == wanted:
            return True
        self.recorder.gap(
            GapReason.RESPONSE_TRUNCATED,
            "the server answered with a message whose JSON-RPC id is not the one this "
            "call was sent under, so it is somebody else's answer and what this call did "
            "on the other side was not observed",
        )
        return False

    def _stream_broken(self, kind: str) -> None:
        """SEP-2575 removed SSE resumability and message redelivery.

        A response stream that breaks loses the in-flight request, and the
        client MUST re-issue it as a new request with a NEW request id. So the
        retry arrives here as a second call that this tool cannot tell from a
        second call, and the trace must not say there were two when there may
        have been one. It says it cannot tell.
        """
        self.recorder.gap(
            GapReason.STREAM_BROKEN,
            f"the response stream from {endpoint(self.upstream)} broke before a whole "
            f"answer arrived ({kind}). MCP "
            "2026-07-28 removed stream resumability and message redelivery (SEP-2575), so "
            "the client re-issues the call under a new id: if a later call to the same "
            "tool appears in this trace, this tool cannot tell whether it is a second "
            "call or this one retried",
        )
