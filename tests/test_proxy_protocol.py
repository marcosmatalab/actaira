"""What MCP revision 2026-07-28 makes a message say about itself, observed.

The revision removed the session (SEP-2567) and the handshake (SEP-2575), so
every fact that used to be established once per run is now carried by every
message - or is not carried, and then it is a hole. This file is the property
over that: a revision that is declared is recorded PER EVENT, one that is not
declared is named, `server/discover` is the inventory when it goes past and a
gap when it does not, an absent `resultType` is assumed and the assumption is
published as an assumption, and a paused call is paired with its retry by the
server's own handle and never by the order the two arrived in.

The last one is the lesson phase 1 paid for twice, arriving in a third place.
"""
from __future__ import annotations

import json
import sys

import pytest

from actaira.proxy import Recorder
from actaira.proxy.stdio import StdioProxy
from actaira.trace.model import GapReason

CURRENT = "2026-07-28"
PREVIOUS = "2025-11-25"
TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
OTHER_TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"


def call(identifier: int, name: str, revision: str | None = CURRENT, trace: str | None = TRACEPARENT):
    meta: dict = {}
    if revision is not None:
        meta["io.modelcontextprotocol/protocolVersion"] = revision
        meta["io.modelcontextprotocol/clientInfo"] = {"name": "actaira-test", "version": "1"}
    if trace is not None:
        meta["traceparent"] = trace
    params: dict = {"name": name, "arguments": {}}
    if meta:
        params["_meta"] = meta
    return {"jsonrpc": "2.0", "id": identifier, "method": "tools/call", "params": params}


def discover(identifier: int = 0):
    return {
        "jsonrpc": "2.0",
        "id": identifier,
        "method": "server/discover",
        "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": CURRENT}},
    }


def server(tmp_path, body: str) -> list[str]:
    path = tmp_path / "server.py"
    path.write_text("import json, sys\n" + body, encoding="utf-8")
    return [sys.executable, str(path)]


def run(tmp_path, body: str, messages) -> dict:
    recorder = Recorder(session_id="s", source="mcp-proxy")
    proxy = StdioProxy(server(tmp_path, body), recorder, timeout=5.0)
    assert proxy.start()
    for message in messages:
        proxy.request(message)
    proxy.close()
    return recorder.trace().to_dict()


# A server on the current revision: it declares itself in every result, carries
# `resultType`, and implements `server/discover` as SEP-2575 requires.
CURRENT_SERVER = f"""
META = {{'io.modelcontextprotocol/protocolVersion': {CURRENT!r},
        'io.modelcontextprotocol/serverInfo': {{'name': 'fixture', 'version': '2'}}}}
for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    if message.get('method') == 'server/discover':
        payload = {{'tools': [{{'name': 'read_file'}}, {{'name': 'write_file'}}],
                   'resultType': 'complete', '_meta': META}}
    else:
        payload = {{'content': [{{'type': 'text', 'text': 'ok'}}],
                   'resultType': 'complete', '_meta': META}}
    sys.stdout.write(json.dumps(
        {{'jsonrpc': '2.0', 'id': message.get('id'), 'result': payload}}) + '\\n')
    sys.stdout.flush()
"""

# A server still speaking the previous revision: no `resultType` at all, which
# SEP-2322 only made mandatory in 2026-07-28.
PREVIOUS_SERVER = f"""
META = {{'io.modelcontextprotocol/protocolVersion': {PREVIOUS!r}}}
for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    sys.stdout.write(json.dumps({{'jsonrpc': '2.0', 'id': message.get('id'),
        'result': {{'content': [{{'type': 'text', 'text': 'ok'}}], '_meta': META}}}}) + '\\n')
    sys.stdout.flush()
"""

# A server that declares nothing about itself, which is most of them today.
SILENT_SERVER = """
for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'),
        'result': {'content': [{'type': 'text', 'text': 'ok'}]}}) + '\\n')
    sys.stdout.flush()
"""


# ---------------------------------------------------------------------------
# The revision, per event
# ---------------------------------------------------------------------------


def test_the_revision_a_message_declares_is_published_on_the_event(tmp_path):
    document = run(tmp_path, CURRENT_SERVER, [call(1, "read_file")])

    event = document["events"][0]
    assert event["mcp.protocol.version"] == CURRENT
    assert event["mcp.client"] == "actaira-test@1"
    assert event["mcp.server"] == "fixture@2"
    assert event["traceparent"] == TRACEPARENT
    assert document["mcp"]["protocol_revisions_observed"] == [CURRENT]


def test_two_calls_declaring_two_revisions_are_two_observations_not_an_error(tmp_path):
    """The handshake is gone, so nothing forces one run to be one revision.
    Two answers is a fact about the run and is recorded as two facts."""
    document = run(
        tmp_path, CURRENT_SERVER, [call(1, "read_file"), call(2, "read_file", revision=PREVIOUS)]
    )

    declared = [event["mcp.protocol.version"] for event in document["events"]]
    assert declared == [CURRENT, PREVIOUS]
    assert document["mcp"]["protocol_revisions_observed"] == [PREVIOUS, CURRENT]


def test_a_server_that_declares_no_revision_produces_a_named_hole(tmp_path):
    """A proxy that does not know which revision it is interposing on does not
    know what it is looking at, and says so rather than assuming the latest."""
    document = run(tmp_path, SILENT_SERVER, [call(1, "read_file", revision=None, trace=None)])

    assert document["events"][0]["mcp.protocol.version"] is None
    reasons = {gap["reason"] for gap in document["gaps"]}
    assert GapReason.PROTOCOL_VERSION_UNKNOWN.value in reasons
    assert document["complete"] is False


def test_a_call_with_no_traceparent_loses_the_key_the_session_used_to_be(tmp_path):
    document = run(tmp_path, CURRENT_SERVER, [call(1, "read_file", trace=None)])

    assert document["events"][0]["traceparent"] is None
    reasons = {gap["reason"] for gap in document["gaps"]}
    assert GapReason.NO_CORRELATION_KEY.value in reasons


def test_the_correlation_key_travels_and_two_runs_do_not_share_one(tmp_path):
    document = run(
        tmp_path,
        CURRENT_SERVER,
        [call(1, "read_file"), call(2, "read_file", trace=OTHER_TRACEPARENT)],
    )

    assert [event["traceparent"] for event in document["events"]] == [
        TRACEPARENT, OTHER_TRACEPARENT
    ]


# ---------------------------------------------------------------------------
# server/discover: the inventory, or its absence
# ---------------------------------------------------------------------------


def test_a_discover_result_is_recorded_as_the_inventory_and_not_as_an_act(tmp_path):
    """It is the agent finding out what exists, like `tools/list`. Recording it
    as an event would put a position in the index no rule can cite."""
    recorder = Recorder(session_id="s", source="mcp-proxy", record_path=tmp_path / "srv.jsonl")
    proxy = StdioProxy(server(tmp_path, CURRENT_SERVER), recorder, timeout=5.0)
    assert proxy.start()
    proxy.request(discover())
    proxy.request(call(1, "read_file"))
    proxy.close()

    rows = [
        json.loads(line)
        for line in (tmp_path / "srv.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    inventory = [row for row in rows if row["kind"] == "discover"]

    assert len(inventory) == 1
    assert inventory[0]["tools"] == ["read_file", "write_file"]
    assert inventory[0]["protocol_version"] == CURRENT
    assert [event.tool_name for event in recorder.events] == ["read_file"]


def test_a_server_that_was_never_asked_leaves_the_inventory_unobserved(tmp_path):
    """SEP-2575 makes `server/discover` mandatory for the SERVER, not for the
    client, so a run in which nobody asked observes no inventory. The hole is
    the honest answer; issuing the request ourselves is not - see
    `Recorder.discover`."""
    from actaira.proxy.session import WatchSession, rewrite_config

    records = tmp_path / "records"
    command = server(tmp_path, CURRENT_SERVER)
    session = WatchSession(records, "s")
    rewrite_config(
        {"mcpServers": {"srv": {"command": command[0], "args": command[1:]}}},
        record_dir=records,
        session_id="s",
        salt=session.salt,
        run_id=session.run_id,
    )
    recorder = Recorder(
        session_id="s", record_path=records / "srv.jsonl", run_id=session.run_id
    )
    proxy = StdioProxy(command, recorder, timeout=5.0)
    assert proxy.start()
    proxy.request(call(1, "read_file"))
    proxy.close()

    document = session.assemble(child_returncode=0).to_dict()

    reasons = {gap["reason"] for gap in document["gaps"]}
    assert GapReason.DISCOVER_UNAVAILABLE.value in reasons
    assert document["mcp"]["servers"] == []


# ---------------------------------------------------------------------------
# resultType: required, and assumed out loud when it is missing
# ---------------------------------------------------------------------------


def test_a_previous_revision_server_gets_complete_assumed_and_the_assumption_said(tmp_path):
    """SEP-2322 made `resultType` required and the specification's own
    compatibility rule is to read an absent one as `complete`. That is what
    happens, AND the event says this reader supplied it: an assumption
    published as the server's statement is the third negative."""
    document = run(tmp_path, PREVIOUS_SERVER, [call(1, "read_file", revision=PREVIOUS)])

    event = document["events"][0]
    assert event["mcp.result.type"] == "complete"
    assert event["mcp.result.type_assumed"] is True
    assert event["mcp.protocol.version"] == PREVIOUS


def test_a_current_revision_server_that_states_it_is_not_recorded_as_assumed(tmp_path):
    """The guard on the test above: if `type_assumed` were always true it
    would carry no information at all."""
    document = run(tmp_path, CURRENT_SERVER, [call(1, "read_file")])

    event = document["events"][0]
    assert event["mcp.result.type"] == "complete"
    assert event["mcp.result.type_assumed"] is False


# ---------------------------------------------------------------------------
# Multi round-trip requests: paired by the handle, never by arrival
# ---------------------------------------------------------------------------


PAUSING_SERVER = f"""
META = {{'io.modelcontextprotocol/protocolVersion': {CURRENT!r}}}
seen = 0
for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    seen += 1
    if seen == 1:
        payload = {{'resultType': 'input_required', 'requestState': 'rs-42',
                   'content': [{{'type': 'text', 'text': 'which branch?'}}], '_meta': META}}
    else:
        payload = {{'resultType': 'complete', 'requestState': 'rs-42',
                   'content': [{{'type': 'text', 'text': 'done'}}], '_meta': META}}
    sys.stdout.write(json.dumps(
        {{'jsonrpc': '2.0', 'id': message.get('id'), 'result': payload}}) + '\\n')
    sys.stdout.flush()
"""

PAUSING_SERVER_WITH_NO_HANDLE = PAUSING_SERVER.replace("'requestState': 'rs-42',", "")


def test_an_interim_result_and_its_retry_carry_the_handle_that_pairs_them(tmp_path):
    """One logical call seen twice. The two arrive under DIFFERENT JSON-RPC ids
    - the client re-issues - so nothing about the ids or the order says they
    belong together. `requestState` does, and it is on both events."""
    document = run(
        tmp_path, PAUSING_SERVER, [call(1, "commit"), call(2, "commit")]
    )

    first, second = document["events"]
    assert first["mcp.result.type"] == "input_required"
    assert second["mcp.result.type"] == "complete"
    assert first["mcp.request.state"] == second["mcp.request.state"] == "rs-42"
    assert first["gen_ai.tool.call.id"] != second["gen_ai.tool.call.id"], (
        "the retry has to be a separate JSON-RPC request, or this pairs nothing"
    )
    assert GapReason.INPUT_STATE_ABSENT.value not in {
        gap["reason"] for gap in document["gaps"]
    }


def test_without_the_handle_the_pairing_is_a_hole_and_not_the_arrival_order(tmp_path):
    document = run(
        tmp_path,
        PAUSING_SERVER_WITH_NO_HANDLE,
        [call(1, "commit"), call(2, "commit")],
    )

    assert all(event["mcp.request.state"] is None for event in document["events"])
    reasons = {gap["reason"] for gap in document["gaps"]}
    assert GapReason.INPUT_STATE_ABSENT.value in reasons
    assert document["complete"] is False


# ---------------------------------------------------------------------------
# What the reader refuses to publish
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "/home/aurelia/projects/payroll",
        "https://mcp.example/sse?api_key=FAKE-NOT-A-REAL-KEY",
        "C:\\Users\\aurelia\\.env",
        "a name with spaces in it",
        "x" * 200,
    ],
)
def test_a_server_name_that_is_not_a_software_name_is_dropped_not_published(value):
    """`serverInfo` and `clientInfo` are written by the software's own author,
    which is the argument that lets them travel at all - the same one that lets
    `redact.endpoint` keep a host. A field is only as safe as the value space
    it is matched against, so anything that is not shaped like a software name
    is dropped rather than published."""
    from actaira.proxy import protocol

    message = {
        "result": {"_meta": {"io.modelcontextprotocol/serverInfo": {"name": value}}}
    }

    assert protocol.server_of(message) is None


def test_a_traceparent_that_is_not_one_is_dropped_not_published():
    from actaira.proxy import protocol

    message = {"params": {"_meta": {"traceparent": "/home/aurelia/secrets"}}}

    assert protocol.correlation_of(message) is None
