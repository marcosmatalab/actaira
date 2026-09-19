"""Completeness, as one property over a corpus of ways to lose an event.

A proxy is the fail-open surface. Every one of these scenarios ends with the
agent having done something the proxy did not see, and the only wrong answer
is a trace that comes out looking whole. So the statement is made once, over
six scenarios, rather than six times in six tests that can drift apart - which
is what phase 0.1 cost us and what its two invariants were written to stop.

The corpus carries a seventh scenario where nothing goes wrong. A property
test in which every case fails is a property test that would pass against a
proxy that always declares a gap, and that proxy is useless.
"""
from __future__ import annotations

import json
import re
import socket
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from actaira.proxy import Recorder
from actaira.proxy.http import HttpProxy
from actaira.proxy.stdio import WINDOWS_TRANSPORT_CLOSED_LIMIT, StdioProxy
from actaira.trace import CaptureLevel
from actaira.trace.model import GapReason, Trace

# What a client speaking MCP 2026-07-28 sends. The `_meta` block is not
# decoration: SEP-2575 removed the handshake, so the protocol revision and the
# client travel on every request, and SEP-414 puts the trace context that
# replaced the removed session id (SEP-2567) in the same place. A call without
# it is `BARE_CALL` below, and it is a scenario of its own.
META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "actaira-test", "version": "1"},
    "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
}
CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "actaira_verify",
        "arguments": {"path": "receipt.zip"},
        "_meta": META,
    },
}
SECOND_CALL = {**CALL, "id": 2}
# The same call from a client that declares nothing about itself, which is
# every client that has not moved to 2026-07-28 yet.
BARE_CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "actaira_verify", "arguments": {"path": "receipt.zip"}},
}
# One with a revision but no correlation key: the half of the loss that
# SEP-2567 causes on its own.
UNCORRELATED_CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "actaira_verify",
        "arguments": {"path": "receipt.zip"},
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"},
    },
}
# What a 2026-07-28 server puts in a result: its own identity and the required
# `resultType` (SEP-2322, SEP-2575).
SERVER_META = (
    "{'io.modelcontextprotocol/protocolVersion': '2026-07-28',"
    " 'io.modelcontextprotocol/serverInfo': {'name': 'fixture-server', 'version': '1'}}"
)


# ---------------------------------------------------------------------------
# Upstreams that misbehave in one specific way each
# ---------------------------------------------------------------------------


def _upstream_script(tmp_path: Path, body: str) -> list[str]:
    """A stdio MCP server written for one scenario, spawned as a real process."""
    path = tmp_path / "upstream.py"
    path.write_text(
        "import json, os, sys\n"
        "def reply(message, payload):\n"
        "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'),\n"
        "                                 'result': payload}) + '\\n')\n"
        "    sys.stdout.flush()\n" + body,
        encoding="utf-8",
    )
    return [sys.executable, str(path)]


HEALTHY_BODY = (
    "for line in sys.stdin:\n"
    "    if not line.strip():\n"
    "        continue\n"
    "    reply(json.loads(line), {'content': [{'type': 'text', 'text': 'ok'}],\n"
    "                             'resultType': 'complete',\n"
    "                             '_meta': " + SERVER_META + "})\n"
)
# Answers every call with the interim result of a multi round-trip request and
# no handle to pair the retry by (SEP-2322).
PAUSES_WITHOUT_A_HANDLE_BODY = (
    "for line in sys.stdin:\n"
    "    if not line.strip():\n"
    "        continue\n"
    "    reply(json.loads(line), {'resultType': 'input_required',\n"
    "                             'content': [{'type': 'text', 'text': 'who?'}]})\n"
)
DIES_AFTER_ONE_BODY = (
    "first = True\n"
    "for line in sys.stdin:\n"
    "    if not line.strip():\n"
    "        continue\n"
    "    if not first:\n"
    "        raise SystemExit(3)\n"
    "    first = False\n"
    "    reply(json.loads(line), {'content': [{'type': 'text', 'text': 'ok'}]})\n"
)
# `os.close(1)` rather than `sys.stdout.close()`: the second one closes the
# Python object and leaves the descriptor open, so the parent's read blocks
# instead of seeing EOF. The scenario is a transport that died under a server
# that is still alive, and only the first spelling produces one.
CLOSES_STDOUT_BODY = "os.close(1)\nsys.stdin.read()\n"
# Alive, reading, and never answering. This is the scenario the six in the
# phase brief did not cover, and the only failure mode worse than a silent gap:
# it deadlocked the proxy, which would have taken the agent down with it.
NEVER_ANSWERS_BODY = "sys.stdin.read()\n"
TRUNCATES_BODY = (
    "for line in sys.stdin:\n"
    "    if not line.strip():\n"
    "        continue\n"
    "    sys.stdout.write('{\"jsonrpc\": \"2.0\", \"id\": 1, \"resu')\n"
    "    sys.stdout.flush()\n"
    "    break\n"
    "sys.stdin.read()\n"
)


class _Handler(BaseHTTPRequestHandler):
    behaviour = "ok"

    def log_message(self, *args):  # noqa: ANN002 - silence the test server
        return

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        if self.behaviour == "5xx":
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.behaviour == "cut":
            self.close_connection = True
            self.wfile.close()
            return
        if self.behaviour == "half":
            # A stream that began and did not finish, which is what SEP-2575
            # leaves unrecoverable now that resumability and redelivery are
            # gone. Distinct from "cut", where nothing arrived at all.
            body = b'{"jsonrpc": "2.0", "id": 1, "resu'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "result": {
                "content": [{"type": "text", "text": "ok"}],
                "resultType": "complete",
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/serverInfo": {
                        "name": "fixture-server", "version": "1"
                    },
                },
            }}
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def http_upstream():
    """A real local HTTP server whose behaviour each scenario sets."""
    handler = type("Scenario", (_Handler,), {})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield handler, f"http://127.0.0.1:{server.server_address[1]}/mcp"
    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# The corpus
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Scenario:
    name: str
    run: Callable[..., Trace]
    expected: GapReason | None
    # Set only where a platform cannot produce the signal the scenario is about.
    # The string is the published limit itself, read from the package, so the
    # skip's reason and the limit are one sentence (work rule 10). A skip whose
    # reason is typed here would be a second definition, free to drift from the
    # one a reader meets in the README.
    windows_skip: str | None = None


def _stdio(tmp_path, body, calls=(CALL,), command=None, timeout=3.0):
    recorder = Recorder(session_id="s-stdio", source="mcp-proxy")
    proxy = StdioProxy(command or _upstream_script(tmp_path, body), recorder, timeout=timeout)
    proxy.start()
    for call in calls:
        proxy.request(call)
    proxy.close()
    return recorder.trace()


def _http(handler, url, behaviour):
    handler.behaviour = behaviour
    recorder = Recorder(session_id="s-http", source="mcp-proxy")
    proxy = HttpProxy(url, recorder)
    proxy.start()
    proxy.request(CALL)
    proxy.close()
    return recorder.trace()


SCENARIOS = [
    Scenario(
        # A binary that is not there, rather than an interpreter handed a
        # missing script: the second one starts perfectly well and then exits,
        # which is a different thing to have happened and gets a different word.
        "the proxy never started",
        lambda tmp_path, http: _stdio(
            tmp_path, HEALTHY_BODY, command=[str(tmp_path / "no-such-server")]
        ),
        GapReason.PROXY_START_FAILED,
    ),
    Scenario(
        "the upstream died halfway through",
        lambda tmp_path, http: _stdio(tmp_path, DIES_AFTER_ONE_BODY, calls=(CALL, SECOND_CALL)),
        GapReason.UPSTREAM_EXITED,
    ),
    Scenario(
        "the stdio transport closed",
        lambda tmp_path, http: _stdio(tmp_path, CLOSES_STDOUT_BODY),
        GapReason.TRANSPORT_CLOSED,
        windows_skip=WINDOWS_TRANSPORT_CLOSED_LIMIT,
    ),
    Scenario(
        "the response was truncated",
        lambda tmp_path, http: _stdio(tmp_path, TRUNCATES_BODY),
        GapReason.RESPONSE_TRUNCATED,
    ),
    Scenario(
        "the HTTP upstream answered 5xx",
        lambda tmp_path, http: _http(*http, "5xx"),
        GapReason.UPSTREAM_ERROR,
    ),
    Scenario(
        "the HTTP upstream cut the connection",
        lambda tmp_path, http: _http(*http, "cut"),
        GapReason.TRANSPORT_CLOSED,
    ),
    Scenario(
        "the server never answered at all",
        lambda tmp_path, http: _stdio(tmp_path, NEVER_ANSWERS_BODY),
        GapReason.UPSTREAM_TIMEOUT,
    ),
    # The four MCP 2026-07-28 brought with it. Each is something a message used
    # to carry once per session and now has to carry for itself, or something
    # the revision made unrecoverable - so each is a way of losing a fact that
    # did not exist as a way of losing anything before.
    Scenario(
        "the call declared no protocol revision",
        lambda tmp_path, http: _stdio(tmp_path, HEALTHY_BODY, calls=(BARE_CALL,)),
        GapReason.PROTOCOL_VERSION_UNKNOWN,
    ),
    Scenario(
        "the call carried no correlation key",
        lambda tmp_path, http: _stdio(tmp_path, HEALTHY_BODY, calls=(UNCORRELATED_CALL,)),
        GapReason.NO_CORRELATION_KEY,
    ),
    Scenario(
        "the server paused the call without a handle to resume it by",
        lambda tmp_path, http: _stdio(tmp_path, PAUSES_WITHOUT_A_HANDLE_BODY),
        GapReason.INPUT_STATE_ABSENT,
    ),
    Scenario(
        "the HTTP response stream broke part way through",
        lambda tmp_path, http: _http(*http, "half"),
        GapReason.STREAM_BROKEN,
    ),
]

HEALTHY = Scenario(
    "nothing went wrong",
    lambda tmp_path, http: _stdio(tmp_path, HEALTHY_BODY),
    None,
)


def _ids(scenarios):
    return [scenario.name for scenario in scenarios]


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario", SCENARIOS, ids=_ids(SCENARIOS))
def test_a_trace_never_looks_complete_when_it_is_not(scenario, tmp_path, http_upstream):
    """The one statement this file exists to make."""
    document = scenario.run(tmp_path, http_upstream).to_dict()

    assert document["complete"] is False, f"{scenario.name}: the trace came out looking whole"
    assert document["gaps"], f"{scenario.name}: incomplete and silent about it"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=_ids(SCENARIOS))
def test_every_gap_names_its_reason_and_says_what_happened(scenario, tmp_path, http_upstream):
    """A gap with no reason is the silence this invariant is against, wearing
    a field name."""
    if scenario.windows_skip and sys.platform == "win32":
        # DEF-121. Not "this is flaky on Windows": the reason IS the published
        # limit, and `test_the_windows_limit_is_published_and_says_what_the_skip_says`
        # refuses a tree where the two have come apart.
        pytest.skip(scenario.windows_skip)
    document = scenario.run(tmp_path, http_upstream).to_dict()

    reasons = {gap["reason"] for gap in document["gaps"]}
    assert scenario.expected.value in reasons, f"{scenario.name}: {sorted(reasons)}"
    for gap in document["gaps"]:
        assert gap["reason"] in {reason.value for reason in GapReason}, gap
        assert len(gap["detail"]) > 10, f"{scenario.name}: a gap that explains nothing"
        # Exactly one of the two, never neither and never both: a hole either
        # cites a position in this document or says why it cannot. `-1` used
        # to stand for both answers at once.
        anchored = "after_index" in gap
        assert anchored != ("after_index_absent" in gap), gap
        if anchored:
            assert 0 <= gap["after_index"] < len(document["events"]), gap
        else:
            assert len(gap["after_index_absent"]) > 10, gap


@pytest.mark.parametrize("scenario", SCENARIOS, ids=_ids(SCENARIOS))
def test_an_incomplete_l1_trace_cannot_claim_authenticity(scenario, tmp_path, http_upstream):
    """L1 is the level at which authenticity applies. A gap does not make it
    inapplicable, it makes it unestablished, and those are different words."""
    document = scenario.run(tmp_path, http_upstream).to_dict()

    assert document["capture_level"] == CaptureLevel.L1.value
    assert document["authenticity"]["applies"] is True
    assert document["authenticity"]["state"] == "not_established"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=_ids(SCENARIOS))
def test_the_agent_still_gets_an_answer_or_an_error_it_can_act_on(scenario, tmp_path, http_upstream):
    """Transparency: the proxy failing must not take the agent down with it.
    A recording tool that breaks the thing it records is a tool nobody runs
    twice, and the trace is what carries the bad news instead."""
    trace = scenario.run(tmp_path, http_upstream)

    assert trace.to_dict()["events"] is not None  # the call was reached at all
    assert trace.capture_level is CaptureLevel.L1


def test_the_corpus_is_not_all_failures(tmp_path, http_upstream):
    """The guard on the property. Without this, a proxy that declared a gap on
    every session would pass every test above."""
    document = HEALTHY.run(tmp_path, http_upstream).to_dict()

    assert document["complete"] is True
    assert document["gaps"] == []
    assert document["authenticity"]["state"] == "established"
    assert len(document["events"]) == 1


def test_every_gap_reason_in_the_vocabulary_is_reachable():
    """A closed vocabulary with an unreachable member is a member nobody can
    test, and the next person deletes it or misuses it."""
    covered = {scenario.expected for scenario in SCENARIOS}
    # Reached from the two readers rather than from a proxy failure, and each
    # has its own test where it is reached: `not_interposed` in
    # test_proxy_transports.py, `source_contradiction` in
    # test_scan_claude_code.py.
    declarative = {GapReason.END_NOT_RECORDED, GapReason.RESULT_NOT_RECORDED,
                   GapReason.UNPARSABLE_RECORD, GapReason.NOT_INTERPOSED,
                   GapReason.SOURCE_CONTRADICTION,
                   # The three that are statements about the RECORDS rather
                   # than about one message, so no single proxy failure reaches
                   # them. Each has its own test in
                   # tests/test_proxy_http_interposition.py.
                   GapReason.DISCOVER_UNAVAILABLE, GapReason.FOREIGN_RECORDS,
                   GapReason.ORDER_NOT_OBSERVED}

    assert covered | declarative == set(GapReason), (
        f"unreachable gap reasons: {sorted(reason.value for reason in set(GapReason) - covered - declarative)}"
    )


def test_a_recorder_that_was_never_closed_yields_an_incomplete_trace():
    """The inverted default at its starkest: no news is not good news."""
    recorder = Recorder(session_id="s", source="mcp-proxy")

    document = recorder.trace().to_dict()

    assert document["complete"] is False
    assert any(gap["reason"] == GapReason.END_NOT_RECORDED.value for gap in document["gaps"])


def test_the_proxy_binds_only_to_the_loopback_interface(http_upstream):
    """`watch` is the one command that opens a socket at all, and it opens it
    where nobody else can reach it."""
    _handler, url = http_upstream
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = HttpProxy(url, recorder, listen=True)
    proxy.start()
    try:
        host, port = proxy.address
        assert host == "127.0.0.1"
        with socket.socket() as probe:
            probe.settimeout(2)
            assert probe.connect_ex(("127.0.0.1", port)) == 0
    finally:
        proxy.close()


# ---------------------------------------------------------------------------
# DEF-121: the skip and the limit are one sentence, or they are nothing
# ---------------------------------------------------------------------------


def test_the_windows_limit_is_published_and_says_what_the_skip_says():
    """The pin for DEF-121, and it is anchored on the LIMIT, not on the skip.

    A skipped test anchors nothing: it is the absence of a check, and an absence
    cannot hold a decision in place. What holds this one is that the platform
    fact is PUBLISHED, so a Windows user reads it before they meet it, and that
    the reason the skip prints is the same sentence.

    Work rule 10 on its first day. Two statements about one property of Windows
    - the limit a reader meets and the reason a skip prints - share their
    definition or they cancel: each would pass on its own terms while saying
    different things, which is DEF-122 in a new place.
    """
    from conftest import REPO_ROOT  # noqa: PLC0415

    root = Path(REPO_ROOT)
    # Whitespace-collapsed on both sides, because a page wraps its prose and the
    # constant is one line. Still one definition: the words have to be the same
    # words, only the line breaks are allowed to differ.
    def flat(text: str) -> str:
        # Blockquote markers come off first: `> ` is markup, not a different
        # word, and `docs/COMPATIBILITY.md` states the limit as a quotation.
        return " ".join(
            " ".join(line.lstrip().removeprefix("> ") for line in text.splitlines()).split()
        )

    wanted = flat(WINDOWS_TRANSPORT_CLOSED_LIMIT)
    for page in ("README.md", "docs/COMPATIBILITY.md"):
        assert wanted in flat((root / page).read_text(encoding="utf-8")), (
            f"{page} does not carry published limit 15 verbatim. The skip on Windows "
            "prints this sentence as its reason; a reader who meets the behaviour has "
            "to be able to find it"
        )

    # And the Spanish page cannot quietly lose it. Counting alone would not
    # catch that - a parity check that passes because a thing is missing from
    # both sides is the `design_notes` error of DEF-122 - so both the count and
    # the presence of the two new numbers are asserted.
    counts = {}
    for page in ("README.md", "README.es.md"):
        text = (root / page).read_text(encoding="utf-8")
        counts[page] = len(re.findall(r"^\d+\. ", text, re.M))
        for number in ("15.", "16."):
            assert re.search(rf"^{re.escape(number)} ", text, re.M), (
                f"{page} does not state published limit {number}"
            )
    assert len(set(counts.values())) == 1, (
        f"the two READMEs state different numbers of limits: {counts}"
    )

