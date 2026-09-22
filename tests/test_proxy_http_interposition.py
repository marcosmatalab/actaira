"""Interposing on a remote server for real, and what the records say afterwards.

Two properties that had no test at all before this phase, and one bug class
that had one on the other transport only.

`rewrite_config` took an `http_port_for` argument, exactly one caller passed
it, and that caller was a test. So every HTTP and SSE server in every real
`watch` was reached by the agent directly - the trace refused to claim
authenticity over it, correctly, and the product was missing the half of its
value that remote servers are. The first half of this file is the same
configuration run twice: `not_interposed` without the listener, `established`
with it, both through `seamark watch`.

The second half is about the RECORDS rather than about one message: several
threads writing one file at once, a directory holding another run's leftovers,
and an order taken from what the records say about themselves rather than from
what the files happen to be called.

Every server here is on 127.0.0.1. `tests/netguard.py` is what makes that a
property of the suite rather than a habit of this file.
"""
from __future__ import annotations

import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from seamark import cli
from seamark.proxy import Recorder
from seamark.proxy.http import METHOD_HEADER, NAME_HEADER, HttpProxy
from seamark.proxy.session import MANIFEST, WatchSession, rewrite_config
from seamark.trace import CaptureLevel
from seamark.trace.model import GapReason, TraceEvent

CURRENT = "2026-07-28"
TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
META = {
    "io.modelcontextprotocol/protocolVersion": CURRENT,
    "io.modelcontextprotocol/clientInfo": {"name": "seamark-test", "version": "1"},
    "traceparent": TRACEPARENT,
}
SERVER_META = {
    "io.modelcontextprotocol/protocolVersion": CURRENT,
    "io.modelcontextprotocol/serverInfo": {"name": "remote-fixture", "version": "3"},
}


def call(identifier, name):
    return {
        "jsonrpc": "2.0",
        "id": identifier,
        "method": "tools/call",
        "params": {"name": name, "arguments": {}, "_meta": META},
    }


def discover(identifier=0):
    return {
        "jsonrpc": "2.0",
        "id": identifier,
        "method": "server/discover",
        "params": {"_meta": META},
    }


# ---------------------------------------------------------------------------
# A local MCP server that implements 2026-07-28
# ---------------------------------------------------------------------------


class _Remote(BaseHTTPRequestHandler):
    """Loopback only, and it answers `server/discover` because SEP-2575 says a
    server MUST. `behaviour` is what each test needs it to do wrong."""

    behaviour = "ok"
    seen: list[dict] = []

    def log_message(self, *args):  # noqa: ANN002
        return

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        type(self).seen.append(
            {
                "method": self.headers.get(METHOD_HEADER),
                "name": self.headers.get(NAME_HEADER),
                "body": body,
            }
        )
        identifier = body.get("id")
        if self.behaviour == "wrong-id":
            # Somebody else's answer: a pool that replied out of turn, a cache
            # that replayed, a server that echoed the previous id.
            identifier = 999
        if body.get("method") == "server/discover":
            payload = {
                "tools": [{"name": "read_file"}, {"name": "write_file"}],
                "resultType": "complete",
                "_meta": SERVER_META,
            }
        elif self.behaviour == "tool-error":
            # The MCP convention: the CALL succeeded and the TOOL failed. The
            # JSON-RPC `error` member is for protocol faults and is NOT this.
            payload = {
                "isError": True,
                "content": [{"type": "text", "text": "the file is not there"}],
                "resultType": "complete",
                "_meta": SERVER_META,
            }
        else:
            payload = {
                "content": [{"type": "text", "text": "remote ok"}],
                "resultType": "complete",
                "_meta": SERVER_META,
            }
        out = json.dumps({"jsonrpc": "2.0", "id": identifier, "result": payload}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


@pytest.fixture
def remote():
    handler = type("Remote", (_Remote,), {"seen": []})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield handler, f"http://127.0.0.1:{server.server_address[1]}/mcp"
    server.shutdown()
    server.server_close()


AGENT = """
import json, os, sys, urllib.request

config = json.load(open(os.environ["SEAMARK_MCP_CONFIG"], encoding="utf-8"))
url = config["mcpServers"]["remote"]["url"]
META = json.loads(sys.argv[1])
for message in (
    {"jsonrpc": "2.0", "id": 0, "method": "server/discover", "params": {"_meta": META}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "read_file", "arguments": {}, "_meta": META}},
):
    request = urllib.request.Request(
        url, data=json.dumps(message).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as answer:
        json.loads(answer.read())
"""


def _agent(tmp_path: Path) -> list[str]:
    path = tmp_path / "agent.py"
    path.write_text(AGENT, encoding="utf-8")
    return [sys.executable, str(path), json.dumps(META)]


def _written_trace(out: Path) -> dict:
    files = [path for path in out.glob("*.json") if path.name != "index.json"]
    assert len(files) == 1, sorted(path.name for path in files)
    return json.loads(files[0].read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The same configuration, before and after
# ---------------------------------------------------------------------------


def test_without_interposition_the_same_configuration_refuses_authenticity(tmp_path, remote):
    """The before half, stated against the same server the test below uses, so
    the two are comparable rather than two different situations."""
    _handler, url = remote
    records = tmp_path / "records"
    session = WatchSession(records, "s")
    rewrite_config(
        {"mcpServers": {"remote": {"url": url, "type": "http"}}},
        record_dir=records,
        session_id="s",
        salt=session.salt,
        run_id=session.run_id,
    )  # no http_port_for: this is what production did until this phase

    document = session.assemble(child_returncode=0).to_dict()

    assert document["authenticity"]["state"] == "not_established"
    assert document["complete"] is False
    assert any(
        gap["reason"] == GapReason.NOT_INTERPOSED.value for gap in document["gaps"]
    )


def test_watch_interposes_on_a_remote_server_and_the_trace_is_established(tmp_path, remote):
    """The after half, and it goes through the CLI on purpose: the defect was
    that the capability existed and production never reached it, so a test that
    called `HttpProxy` directly would have passed against the broken tree."""
    _handler, url = remote
    config = tmp_path / ".mcp.json"
    config.write_text(
        json.dumps({"mcpServers": {"remote": {"url": url, "type": "http"}}}), encoding="utf-8"
    )
    out = tmp_path / "trace"

    code = cli.main(
        ["watch", "--mcp-config", str(config), "--out", str(out), "--", *_agent(tmp_path)]
    )

    assert code == 0, "the agent could not reach the server through the proxy"
    document = _written_trace(out)
    assert document["capture_level"] == CaptureLevel.L1.value
    assert [event["gen_ai.tool.name"] for event in document["events"]] == ["read_file"]
    assert document["gaps"] == [], document["gaps"]
    assert document["complete"] is True
    assert document["authenticity"]["state"] == "established"
    assert document["mcp"]["protocol_revisions_observed"] == [CURRENT]
    assert document["mcp"]["servers"][0]["tools_advertised"] == ["read_file", "write_file"]


def test_the_rewritten_configuration_points_the_agent_at_loopback(tmp_path, remote):
    """And the manifest records that this one WAS interposed on, which is what
    `_interposition` reads back."""
    _handler, url = remote
    config = tmp_path / ".mcp.json"
    config.write_text(
        json.dumps({"mcpServers": {"remote": {"url": url, "type": "http"}}}), encoding="utf-8"
    )
    out = tmp_path / "trace"

    cli.main(["watch", "--mcp-config", str(config), "--out", str(out), "--", *_agent(tmp_path)])

    rewritten = json.loads((out / "records" / "mcp-config.json").read_text(encoding="utf-8"))
    manifest = json.loads((out / "records" / MANIFEST).read_text(encoding="utf-8"))

    assert rewritten["mcpServers"]["remote"]["url"].startswith("http://127.0.0.1:")
    assert rewritten["mcpServers"]["remote"]["url"] != url
    assert manifest["servers"]["remote"]["interposed"] is True


# ---------------------------------------------------------------------------
# The two bugs phase 1 paid for, on the transport that never had them tested
# ---------------------------------------------------------------------------


def test_an_answer_carrying_another_calls_id_is_refused_rather_than_settled(tmp_path, remote):
    """One POST, one body, so the pairing looks like it cannot go wrong - and
    that is why nothing checked it. Settling the in-flight call with this body
    would write another call's result digest under this call's name, which is a
    wrong fact in the evidence rather than a missing one."""
    handler, url = remote
    handler.behaviour = "wrong-id"
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = HttpProxy(url, recorder)
    proxy.start()

    answer = proxy.request(call(1, "read_file"))
    proxy.close()

    document = recorder.trace().to_dict()
    assert answer is None, "an answer to somebody else's call was handed back to the agent"
    assert document["events"][0]["result_sha256"] is None
    assert document["complete"] is False
    assert {gap["reason"] for gap in document["gaps"]} >= {
        GapReason.RESPONSE_TRUNCATED.value, GapReason.RESULT_NOT_RECORDED.value
    }


def test_two_concurrent_calls_do_not_pair_by_the_order_they_came_back(tmp_path, remote):
    """The property behind the one above. Both calls are in flight at once
    against a threading server, so arrival order is not request order - and
    each event still carries the digest of its OWN answer, because the id is
    what matched them."""
    import hashlib

    from seamark.model import canonical_json

    _handler, url = remote
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = HttpProxy(url, recorder)
    proxy.start()
    with ThreadPoolExecutor(max_workers=8) as pool:
        answers = list(pool.map(lambda n: proxy.request(call(n, f"tool_{n}")), range(1, 9)))
    proxy.close()

    assert all(answer is not None for answer in answers)
    expected = hashlib.sha256(
        canonical_json(
            {
                "content": [{"type": "text", "text": "remote ok"}],
                "resultType": "complete",
                "_meta": SERVER_META,
            }
        )
    ).hexdigest()
    document = recorder.trace().to_dict()
    # Since D-268 the call id is a salted reference to the id, so the pairing
    # is checked through the recorder's own map - which is exactly what the
    # operator does. The property is unchanged: every event carries the digest
    # of ITS answer, matched by id and not by what came back first.
    resolves = recorder.refs.map
    assert len(document["events"]) == 8
    for event in document["events"]:
        assert event["result_sha256"] == expected
        assert event["gen_ai.tool.name"] == f"tool_{resolves[event['gen_ai.tool.call.id']]}"


def test_a_tool_that_reports_its_own_failure_over_http_is_recorded_as_a_failure(tmp_path, remote):
    """`result.isError`, not the JSON-RPC `error` member. A verification that
    had failed was recorded as a call that succeeded, on the other transport,
    against a real session - this is the same statement on this one."""
    handler, url = remote
    handler.behaviour = "tool-error"
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = HttpProxy(url, recorder)
    proxy.start()
    proxy.request(call(1, "read_file"))
    proxy.close()

    document = recorder.trace().to_dict()
    assert document["events"][0]["error.type"] == "tool_error"
    assert document["gaps"] == [], "an observed failure is not a missing observation"
    assert document["complete"] is True


def test_the_proxy_sends_the_standard_mcp_request_headers(tmp_path, remote):
    """SEP-2243 requires `Mcp-Method` and `Mcp-Name` on a Streamable HTTP POST,
    and they are the cheapest audit hook there is: a network appliance reads
    them without parsing a body."""
    handler, url = remote
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = HttpProxy(url, recorder)
    proxy.start()
    proxy.request(discover())
    proxy.request(call(1, "read_file"))
    proxy.close()

    assert [(row["method"], row["name"]) for row in handler.seen] == [
        ("server/discover", None),
        ("tools/call", "read_file"),
    ]


def test_tls_verification_is_never_switched_off(tmp_path):
    """A witness that will talk to anyone holding the right IP address is not a
    witness. Asserted against the source because the property is the ABSENCE of
    a call, and an absence has no run to observe it in."""
    source = Path(__file__).resolve().parents[1] / "src" / "seamark" / "proxy" / "http.py"
    text = source.read_text(encoding="utf-8")

    for forbidden in ("_create_unverified_context", "CERT_NONE", "check_hostname = False"):
        assert forbidden not in text, f"{forbidden} reached the HTTP transport"
    assert "ssl.create_default_context()" in text


def test_the_listener_binds_only_to_loopback(remote):
    _handler, url = remote
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = HttpProxy(url, recorder, listen=True)
    proxy.start()
    try:
        assert proxy.address[0] == "127.0.0.1"
    finally:
        proxy.close()


# ---------------------------------------------------------------------------
# The records: one writer at a time, and whose run they belong to
# ---------------------------------------------------------------------------


def test_many_writers_lose_no_record_and_leave_every_line_readable(tmp_path, remote):
    """A `ThreadingHTTPServer` puts several handler threads on one recorder, so
    two appends used to be able to interleave inside a line. The assembled
    trace then declared an unparsable record: a correct fail-closed answer to
    an entirely avoidable cause."""
    _handler, url = remote
    record = tmp_path / "remote.jsonl"
    recorder = Recorder(session_id="s", record_path=record, run_id="r")
    proxy = HttpProxy(url, recorder, listen=True)
    proxy.start()
    try:
        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(lambda n: proxy.request(call(n, f"tool_{n}")), range(1, 65)))
    finally:
        proxy.close()

    resolve = recorder.refs.map
    lines = [line for line in record.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = []
    for line in lines:
        rows.append(json.loads(line))  # a torn line raises here, which is the point
    calls = [row for row in rows if row["kind"] == "call"]
    results = [row for row in rows if row["kind"] == "result"]

    assert len(calls) == 64, "a record was lost"
    assert len(results) == 64
    assert {resolve[row["event"]["gen_ai.tool.call.id"]] for row in calls} == {
        str(n) for n in range(1, 65)
    }
    assert {row["event"]["index"] for row in calls} == set(range(64)), (
        "two threads took the same index, so one call overwrote another"
    )


def _part(directory: Path, name: str, run_id: str, moments: list[tuple[str, str]]) -> None:
    """A record file written by hand, so the moments are the test's to choose."""
    directory.mkdir(parents=True, exist_ok=True)
    rows = []
    for index, (moment, tool) in enumerate(moments):
        event = TraceEvent(
            index=index,
            capture_level=CaptureLevel.L1,
            tool_name=tool,
            call_id=f"{name}-{index}",
            timestamp=moment,
            arguments_sha256="aa" * 32,
            result_sha256="bb" * 32,
            protocol_version=CURRENT,
            traceparent=TRACEPARENT,
            result_type="complete",
        )
        rows.append({"kind": "call", "event": event.to_dict(), "run": run_id})
        rows.append({"kind": "result", "event": event.to_dict(), "run": run_id})
    rows.append({"kind": "discover", "tools": ["t"], "protocol_version": CURRENT,
                 "server": None, "run": run_id})
    rows.append({"kind": "end", "run": run_id})
    (directory / f"{name}.jsonl").write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8"
    )


def _configured(session: WatchSession, names: list[str]) -> None:
    rewrite_config(
        {"mcpServers": {name: {"command": "true"} for name in names}},
        record_dir=session.record_dir,
        session_id=session.session_id,
        salt=session.salt,
        run_id=session.run_id,
    )


def test_the_order_comes_from_the_records_and_not_from_the_file_names(tmp_path):
    """`sorted(glob("*.jsonl"))` put a server called `alpha` before one called
    `zeta` because of its NAME, and the document published that as the order in
    which the agent did things. Identity, never position - D-258 applied to the
    sequence rather than to one citation."""
    records = tmp_path / "records"
    session = WatchSession(records, "s")
    _configured(session, ["alpha", "zeta"])
    _part(records, "zeta", session.run_id, [("2026-01-01T00:00:01.000Z", "first")])
    _part(records, "alpha", session.run_id, [("2026-01-01T00:00:02.000Z", "second")])

    document = session.assemble(child_returncode=0).to_dict()

    assert [event["gen_ai.tool.name"] for event in document["events"]] == ["first", "second"]
    assert [event["index"] for event in document["events"]] == [0, 1]
    assert document["gaps"] == [], document["gaps"]


def test_two_calls_sharing_one_moment_across_servers_are_not_claimed_ordered(tmp_path):
    """The other half. The document still has to put them somewhere, and it
    says the placement is this tool's arrangement rather than an observation."""
    records = tmp_path / "records"
    session = WatchSession(records, "s")
    _configured(session, ["alpha", "zeta"])
    _part(records, "zeta", session.run_id, [("2026-01-01T00:00:01.000Z", "one")])
    _part(records, "alpha", session.run_id, [("2026-01-01T00:00:01.000Z", "two")])

    document = session.assemble(child_returncode=0).to_dict()

    assert {gap["reason"] for gap in document["gaps"]} == {
        GapReason.ORDER_NOT_OBSERVED.value
    }
    assert document["complete"] is False


def test_an_event_with_no_moment_of_its_own_is_placed_and_the_placement_declared(tmp_path):
    records = tmp_path / "records"
    session = WatchSession(records, "s")
    _configured(session, ["alpha"])
    _part(records, "alpha", session.run_id, [("", "undated")])

    document = session.assemble(child_returncode=0).to_dict()

    assert len(document["events"]) == 1
    assert GapReason.ORDER_NOT_OBSERVED.value in {
        gap["reason"] for gap in document["gaps"]
    }


def test_records_a_previous_run_left_behind_are_declared_and_not_read(tmp_path):
    """A directory is not an identity. `assemble` read whatever `*.jsonl` was
    there, so last week's watch contributed its calls to this session's acta as
    though the agent had just made them."""
    records = tmp_path / "records"
    session = WatchSession(records, "s")
    _configured(session, ["alpha"])
    _part(records, "alpha", session.run_id, [("2026-01-01T00:00:02.000Z", "mine")])
    _part(records, "leftover", "a-run-that-is-not-this-one",
          [("2026-01-01T00:00:01.000Z", "somebody_elses")])

    document = session.assemble(child_returncode=0).to_dict()

    assert [event["gen_ai.tool.name"] for event in document["events"]] == ["mine"]
    assert GapReason.FOREIGN_RECORDS.value in {gap["reason"] for gap in document["gaps"]}
    assert document["complete"] is False


def test_foreign_records_mixed_into_this_runs_own_file_are_dropped_and_declared(tmp_path):
    records = tmp_path / "records"
    session = WatchSession(records, "s")
    _configured(session, ["alpha"])
    _part(records, "alpha", session.run_id, [("2026-01-01T00:00:02.000Z", "mine")])
    with (records / "alpha.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps({
                "kind": "call",
                "run": "another-run",
                "event": TraceEvent(
                    index=9, capture_level=CaptureLevel.L1, tool_name="not_mine",
                    call_id="x", timestamp="2026-01-01T00:00:03.000Z",
                    arguments_sha256="cc" * 32, result_sha256="dd" * 32,
                ).to_dict(),
            }, sort_keys=True) + "\n"
        )

    document = session.assemble(child_returncode=0).to_dict()

    assert [event["gen_ai.tool.name"] for event in document["events"]] == ["mine"]
    assert GapReason.FOREIGN_RECORDS.value in {gap["reason"] for gap in document["gaps"]}
