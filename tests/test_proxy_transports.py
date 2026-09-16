"""What the proxy records when nothing goes wrong, and how `watch` wires it up.

Split from `test_proxy_completeness.py` by property rather than by module: that
file asks what the trace says when an event is lost, this one asks whether the
event was recorded faithfully in the first place and whether the agent's own
traffic survives the round trip. Both cover `proxy/stdio.py` and
`proxy/http.py`; this one also covers `proxy/session.py`, which is the piece
that puts a proxy between an agent and each of its servers.
"""
from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from actaira.proxy import Recorder
from actaira.proxy.http import HttpProxy
from actaira.proxy.session import WatchSession, rewrite_config
from actaira.proxy.stdio import StdioProxy
from actaira.trace import CaptureLevel
from actaira.trace.model import GapReason

ECHO_SERVER = (
    "import json, sys\n"
    "for line in sys.stdin:\n"
    "    if not line.strip():\n"
    "        continue\n"
    "    message = json.loads(line)\n"
    # A real MCP server answers a request and stays quiet about a notification.
    # The first version of this fixture answered both, and that is what exposed
    # the response pairing the tests below now pin.
    "    if message.get('id') is None:\n"
    "        continue\n"
    "    name = (message.get('params') or {}).get('name')\n"
    "    if name == 'boom':\n"
    "        out = {'jsonrpc': '2.0', 'id': message.get('id'),\n"
    "               'error': {'code': -32000, 'message': 'no such thing'}}\n"
    "    else:\n"
    "        out = {'jsonrpc': '2.0', 'id': message.get('id'),\n"
    "               'result': {'content': [{'type': 'text', 'text': 'echo ' + str(name)}]}}\n"
    "    sys.stdout.write(json.dumps(out) + '\\n')\n"
    "    sys.stdout.flush()\n"
)


def _call(identifier: int, name: str, arguments: dict | None = None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": identifier,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


@pytest.fixture
def echo(tmp_path: Path) -> list[str]:
    path = tmp_path / "echo_server.py"
    path.write_text(ECHO_SERVER, encoding="utf-8")
    return [sys.executable, str(path)]


# ---------------------------------------------------------------------------
# stdio
# ---------------------------------------------------------------------------


def test_the_agents_call_reaches_the_server_and_the_answer_comes_back(echo):
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = StdioProxy(echo, recorder)
    proxy.start()

    response = proxy.request(_call(1, "actaira_verify", {"path": "x.zip"}))
    proxy.close()

    assert response["result"]["content"][0]["text"] == "echo actaira_verify"
    assert recorder.trace().to_dict()["complete"] is True


def test_each_tool_call_is_recorded_once_with_both_digests(echo):
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = StdioProxy(echo, recorder)
    proxy.start()
    proxy.request(_call(1, "one"))
    proxy.request(_call(2, "two"))
    proxy.close()

    events = recorder.trace().to_dict()["events"]

    assert [event["gen_ai.tool.name"] for event in events] == ["one", "two"]
    assert [event["index"] for event in events] == [0, 1]
    assert all(len(event["arguments_sha256"]) == 64 for event in events)
    assert all(len(event["result_sha256"]) == 64 for event in events)


def test_a_message_that_is_not_a_tool_call_is_forwarded_and_not_recorded_as_one(echo):
    """`initialize`, `tools/list` and the rest are the agent's business. The
    trace is about what the agent DID, and listing what it could do is not an
    act - recording it as one would put events in the index that no rule can
    ever be about."""
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = StdioProxy(echo, recorder)
    proxy.start()

    response = proxy.request({"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}})
    proxy.close()

    assert response is not None
    assert recorder.trace().to_dict()["events"] == []


def test_a_notification_is_forwarded_without_waiting_for_an_answer(echo):
    """The defect the first real agent session found, in one second.

    MCP clients send `notifications/initialized` immediately after
    `initialize`. A notification has no `id` and gets no reply, and the proxy
    forwarded it and then blocked for its whole deadline waiting for one - so
    the agent's server never finished connecting and not one tool registered.
    The trace said `upstream_timeout`, which is the only reason this took a
    single run to find instead of a bug report from somebody else.
    """
    import time

    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = StdioProxy(echo, recorder, timeout=3.0)
    proxy.start()

    started = time.monotonic()
    proxy.notify({"jsonrpc": "2.0", "method": "notifications/initialized"})
    elapsed = time.monotonic() - started
    proxy.request(_call(1, "after_the_notification"))
    proxy.close()

    assert elapsed < 1.0, f"the proxy waited {elapsed:.1f}s for an answer that cannot come"
    document = recorder.trace().to_dict()
    assert document["gaps"] == [], "a notification with no reply is not a hole"
    assert document["complete"] is True
    assert [event["gen_ai.tool.name"] for event in document["events"]] == ["after_the_notification"]


def test_the_serve_loop_routes_a_notification_the_same_way(echo):
    """Through `serve`, because that is the path an agent actually takes and
    the one where the id was not being looked at."""
    import io

    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = StdioProxy(echo, recorder, timeout=3.0)
    messages = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps(_call(2, "actaira_verify")),
    ]
    written = io.StringIO()

    proxy.serve(iter(line + "\n" for line in messages), written)

    answers = [json.loads(line) for line in written.getvalue().splitlines() if line.strip()]
    assert [answer["id"] for answer in answers] == [1, 2], "the notification was answered"
    assert recorder.trace().to_dict()["complete"] is True


CHATTY_SERVER = (
    "import json, sys\n"
    "for line in sys.stdin:\n"
    "    if not line.strip():\n"
    "        continue\n"
    "    message = json.loads(line)\n"
    "    if message.get('id') is None:\n"
    "        continue\n"
    # Something unsolicited first, then the real answer.
    "    sys.stdout.write(json.dumps({'jsonrpc': '2.0',\n"
    "        'method': 'notifications/progress', 'params': {'progress': 1}}) + '\\n')\n"
    "    name = (message.get('params') or {}).get('name')\n"
    "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'),\n"
    "        'result': {'content': [{'type': 'text', 'text': 'for ' + str(name)}]}}) + '\\n')\n"
    "    sys.stdout.flush()\n"
)


def test_an_unsolicited_message_does_not_become_another_calls_result(tmp_path):
    """The pairing, which was by arrival and is now by id.

    A server that says anything on its own account shifts every answer by one,
    and a call then carries the digest of the NEXT call's result. A gap is a
    missing fact; this was a wrong one, recorded as though it had been
    observed, which is the only thing worse.
    """
    path = tmp_path / "chatty.py"
    path.write_text(CHATTY_SERVER, encoding="utf-8")
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = StdioProxy([sys.executable, str(path)], recorder, timeout=5.0)
    proxy.start()

    first = proxy.request(_call(1, "alpha"))
    second = proxy.request(_call(2, "beta"))
    proxy.close()

    assert first["id"] == 1 and first["result"]["content"][0]["text"] == "for alpha"
    assert second["id"] == 2 and second["result"]["content"][0]["text"] == "for beta"
    document = recorder.trace().to_dict()
    assert document["events"][0]["result_sha256"] != document["events"][1]["result_sha256"]
    assert document["complete"] is True


def test_what_the_server_said_unasked_still_reaches_the_agent(tmp_path):
    """Kept rather than dropped. The proxy is not the place that decides the
    server had nothing worth saying."""
    import io

    path = tmp_path / "chatty.py"
    path.write_text(CHATTY_SERVER, encoding="utf-8")
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = StdioProxy([sys.executable, str(path)], recorder, timeout=5.0)
    written = io.StringIO()

    proxy.serve(iter([json.dumps(_call(1, "alpha")) + "\n"]), written)

    answers = [json.loads(line) for line in written.getvalue().splitlines() if line.strip()]
    assert [answer.get("method") for answer in answers] == ["notifications/progress", None]
    assert answers[1]["id"] == 1


def test_an_error_from_the_server_is_recorded_as_an_error_not_as_a_gap(echo):
    """A tool that answers "no" answered. The distinction the whole phase
    rests on: this is an observed failure, not an unobserved event."""
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = StdioProxy(echo, recorder)
    proxy.start()
    proxy.request(_call(1, "boom"))
    proxy.close()

    document = recorder.trace().to_dict()

    assert document["events"][0]["error.type"] == "tool_error"
    assert document["events"][0]["result_sha256"] is not None
    assert document["gaps"] == []
    assert document["complete"] is True


def test_the_recorded_trace_carries_no_argument_content(echo):
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = StdioProxy(echo, recorder)
    proxy.start()
    proxy.request(_call(1, "actaira_verify", {"path": "/home/someone/secret-plans.zip"}))
    proxy.close()

    blob = json.dumps(recorder.trace().to_dict())

    assert "secret-plans" not in blob


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class _Echo(BaseHTTPRequestHandler):
    def log_message(self, *args):  # noqa: ANN002
        return

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {"content": [{"type": "text", "text": "http ok"}]},
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def http_echo():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/mcp"
    server.shutdown()
    server.server_close()


def test_the_http_transport_records_the_same_shape_of_event(http_echo):
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = HttpProxy(http_echo, recorder)
    proxy.start()
    proxy.request(_call(1, "actaira_contract"))
    proxy.close()

    document = recorder.trace().to_dict()

    assert document["events"][0]["gen_ai.tool.name"] == "actaira_contract"
    assert document["events"][0]["capture_level"] == CaptureLevel.L1.value
    assert document["complete"] is True


def test_an_agent_talking_to_the_listening_proxy_reaches_the_real_server(http_echo):
    """End to end over a socket, because the whole claim of the HTTP transport
    is that the agent cannot tell the difference."""
    import urllib.request

    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = HttpProxy(http_echo, recorder, listen=True)
    proxy.start()
    try:
        host, port = proxy.address
        request = urllib.request.Request(
            f"http://{host}:{port}/mcp",
            data=json.dumps(_call(1, "actaira_verify")).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - loopback
            answer = json.loads(response.read())
    finally:
        proxy.close()

    assert answer["result"]["content"][0]["text"] == "http ok"
    assert recorder.trace().to_dict()["events"][0]["gen_ai.tool.name"] == "actaira_verify"


# ---------------------------------------------------------------------------
# `watch`: putting one of those between the agent and each of its servers
# ---------------------------------------------------------------------------


def test_a_stdio_server_is_rewritten_to_run_behind_the_proxy(tmp_path):
    config = {"mcpServers": {"files": {"command": "npx", "args": ["-y", "server-filesystem"]}}}

    rewritten = rewrite_config(config, record_dir=tmp_path)

    entry = rewritten["mcpServers"]["files"]
    assert entry["command"] == sys.executable
    assert "actaira.proxy.stdio" in entry["args"]
    assert "npx" in entry["args"], "the original command has to still be in there"


def test_an_http_server_is_rewritten_to_a_loopback_url(tmp_path):
    config = {"mcpServers": {"remote": {"url": "https://mcp.example/api", "type": "http"}}}

    rewritten = rewrite_config(config, record_dir=tmp_path, http_port_for=lambda name: 8931)

    assert rewritten["mcpServers"]["remote"]["url"].startswith("http://127.0.0.1:8931/")


def test_a_server_shape_the_rewriter_does_not_understand_is_declared_not_dropped(tmp_path):
    """Silently passing an unrecognised server through would leave the agent
    talking to it directly and the trace saying nothing about the calls. The
    rewriter refuses to be quiet about what it could not interpose on."""
    config = {"mcpServers": {"odd": {"transport": "carrier-pigeon"}}}

    rewritten = rewrite_config(config, record_dir=tmp_path)

    assert rewritten["mcpServers"]["odd"] == config["mcpServers"]["odd"]
    assert tmp_path.joinpath("uninterposed.json").is_file()


def test_watch_records_a_gap_when_no_proxy_was_ever_reached(tmp_path):
    """The agent ran and nothing came back through a proxy. That is either a
    session with no tool calls or a session that bypassed us, and this tool
    cannot tell which - so it says so instead of publishing an empty trace
    that reads as a clean run."""
    session = WatchSession(record_dir=tmp_path, session_id="s")

    trace = session.assemble(child_returncode=0)

    document = trace.to_dict()
    assert document["complete"] is False
    assert any(gap["reason"] == GapReason.PROXY_START_FAILED.value for gap in document["gaps"])


def test_watch_assembles_the_parts_every_proxy_wrote_in_index_order(tmp_path, echo):
    """One proxy process per server, one record file each, one trace out."""
    for name in ("alpha", "beta"):
        recorder = Recorder(session_id="s", source="mcp-proxy", record_path=tmp_path / f"{name}.jsonl")
        proxy = StdioProxy(echo, recorder)
        proxy.start()
        proxy.request(_call(1, f"{name}_tool"))
        proxy.close()

    document = WatchSession(record_dir=tmp_path, session_id="s").assemble(child_returncode=0).to_dict()

    assert [event["index"] for event in document["events"]] == [0, 1]
    assert {event["gen_ai.tool.name"] for event in document["events"]} == {"alpha_tool", "beta_tool"}
    assert document["complete"] is True


def test_a_child_that_exited_badly_does_not_make_the_trace_incomplete(tmp_path, echo):
    """The agent's own exit code is the agent's business. A trace that records
    everything the agent did is complete whether or not the agent succeeded,
    and conflating the two would let a failed build look like a lost event."""
    recorder = Recorder(session_id="s", source="mcp-proxy", record_path=tmp_path / "a.jsonl")
    proxy = StdioProxy(echo, recorder)
    proxy.start()
    proxy.request(_call(1, "t"))
    proxy.close()

    document = WatchSession(record_dir=tmp_path, session_id="s").assemble(child_returncode=2).to_dict()

    assert document["complete"] is True
    assert document["child_returncode"] == 2


# ---------------------------------------------------------------------------
# What MCP calls a failure, which is not what JSON-RPC calls one
# ---------------------------------------------------------------------------


TOOL_ERROR_SERVER = (
    "import json, sys\n"
    "for line in sys.stdin:\n"
    "    if not line.strip():\n"
    "        continue\n"
    "    message = json.loads(line)\n"
    "    if message.get('id') is None:\n"
    "        continue\n"
    # The MCP convention: the CALL succeeded, the TOOL failed, and that is
    # reported inside the result rather than as a protocol error.
    "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'),\n"
    "        'result': {'content': [{'type': 'text', 'text': 'no such package'}],\n"
    "                   'isError': True}}) + '\\n')\n"
    "    sys.stdout.flush()\n"
)


def test_a_tool_that_reports_its_own_failure_is_recorded_as_a_failure(tmp_path):
    """Found by the first real agent session and not by any fixture here.

    MCP puts a tool's failure in `result.isError` and keeps the JSON-RPC
    `error` member for protocol faults. Reading only the second one recorded a
    verification that had failed as a call that went fine - a wrong fact inside
    the evidence, which is worse than a gap because nothing marks it.
    """
    path = tmp_path / "failing.py"
    path.write_text(TOOL_ERROR_SERVER, encoding="utf-8")
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = StdioProxy([sys.executable, str(path)], recorder, timeout=5.0)
    proxy.start()

    response = proxy.request(_call(1, "actaira_verify", {"path": "absent.zip"}))
    proxy.close()

    assert response["result"]["isError"] is True
    document = recorder.trace().to_dict()
    assert document["events"][0]["error.type"] == "tool_error"
    assert document["events"][0]["result_sha256"] is not None
    assert document["gaps"] == [], "an observed failure is not a missing observation"
    assert document["complete"] is True


def test_the_session_id_reaches_every_proxy_it_launches(tmp_path):
    """`gen_ai.conversation.id` came out empty on the first real run, because
    the rewriter told each proxy where to record and not what it was recording.
    A published field that is present and says nothing is worse than absent."""
    config = {"mcpServers": {"files": {"command": "npx", "args": ["server"]}}}

    rewritten = rewrite_config(config, record_dir=tmp_path, session_id="the-session")

    arguments = rewritten["mcpServers"]["files"]["args"]
    assert "--session" in arguments
    assert arguments[arguments.index("--session") + 1] == "the-session"


def test_a_configuration_that_will_not_parse_does_not_take_the_agents_tools_away(tmp_path):
    """Read as `{}` before, which is not a smaller interposition: it is handing
    the agent a configuration with no servers in it. The agent runs untouched
    and the unreadable file is left where the operator can find it."""
    bad = tmp_path / "broken.mcp.json"
    bad.write_text("{ not json", encoding="utf-8")
    records = tmp_path / "records"
    session = WatchSession(record_dir=records, session_id="s")

    returncode = session.run([sys.executable, "-c", "pass"], bad)

    assert returncode == 0
    assert (records / "config-error.txt").is_file()
    assert not (records / "mcp-config.json").exists(), "the agent was handed an empty config"
    document = session.assemble(child_returncode=returncode).to_dict()
    assert document["complete"] is False, "an unproxied run must not read as a clean one"


def test_with_content_reaches_the_proxy_processes(tmp_path):
    """A flag in the help text that changes nothing is a claim the code does
    not keep. The proxies are separate processes; this is the only way they
    hear about it."""
    config = {"mcpServers": {"files": {"command": "npx", "args": ["server"]}}}

    on = rewrite_config(config, record_dir=tmp_path, session_id="s", with_content=True)
    off = rewrite_config(config, record_dir=tmp_path, session_id="s")

    assert "--with-content" in on["mcpServers"]["files"]["args"]
    assert "--with-content" not in off["mcpServers"]["files"]["args"]
