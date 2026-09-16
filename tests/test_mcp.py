"""The MCP server: three tools, and two of them saying so.

Why it exists before two of its three tools do: directories list servers, not
proxies, and a server is how this reaches anybody. That is a distribution
argument, and it is only honest if the two unbuilt tools say they are unbuilt
rather than returning something plausible. A stub that invents a verdict is
the fail-open shape of this whole product, in the one surface other people's
agents will call.
"""
from __future__ import annotations

import json
import subprocess
import sys
import zipfile

import pytest

from actaira.attest import package, signing
from actaira.mcp import NOT_IMPLEMENTED, TOOLS, handle
from actaira.trace import CaptureLevel


def _request(identifier, method, params=None):
    return {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params or {}}


def _call(name, arguments=None):
    return handle(_request(1, "tools/call", {"name": name, "arguments": arguments or {}}))


# ---------------------------------------------------------------------------
# Gate 7: three tools, and the two unbuilt ones are explicit about it
# ---------------------------------------------------------------------------


def test_the_server_publishes_exactly_three_tools():
    listed = handle(_request(1, "tools/list"))

    names = [tool["name"] for tool in listed["result"]["tools"]]
    assert names == ["actaira_contract", "actaira_verdict", "actaira_verify"]
    assert set(names) == set(TOOLS)


@pytest.mark.parametrize("name", ["actaira_verdict", "actaira_contract"])
def test_an_unbuilt_tool_returns_an_explicit_state_and_never_a_value(name):
    response = _call(name, {"session_id": "whatever"})

    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["state"] == NOT_IMPLEMENTED
    assert payload["phase"], "it has to say which phase answers this"
    assert "verdict" not in payload
    assert "contract" not in payload
    assert response["result"]["isError"] is False, "unbuilt is not the same as broken"


@pytest.mark.parametrize("name", ["actaira_verdict", "actaira_contract"])
def test_an_unbuilt_tool_says_the_same_thing_however_it_is_called(name):
    """A stub that answers differently for different inputs is a stub that is
    pretending to compute something."""
    first = _call(name, {"session_id": "a"})
    second = _call(name, {"session_id": "b", "unexpected": 1})

    assert first["result"] == second["result"]


def test_verify_answers_for_real_on_a_healthy_package(tmp_path):
    from actaira.attest import chain
    from support.reports import record

    report = record(tmp_path / "clean.safetensors")
    entries: list[chain.Entry] = []
    chain.append(entries, report.sha256, report.to_dict(), timestamp="2026-01-01T00:00:00")
    written = package.write_package(tmp_path / "a.zip", entries, signing.generate())

    payload = json.loads(_call("actaira_verify", {"path": str(written.path)})["result"]["content"][0]["text"])

    assert payload["ok"] is True
    assert payload["trust_state"] == "embedded_key_only"
    assert payload["state"] != NOT_IMPLEMENTED


def test_verify_on_a_path_that_does_not_exist_is_an_error_not_a_pass(tmp_path):
    """The inverted default reaching the one surface other agents call."""
    response = _call("actaira_verify", {"path": str(tmp_path / "absent.zip")})

    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["ok"] is False
    assert payload["problems"], "a refusal with no reason is not a refusal"
    assert response["result"]["isError"] is True


def test_verify_with_no_path_is_a_usage_error_and_not_a_verdict():
    response = _call("actaira_verify", {})

    assert response["result"]["isError"] is True
    assert "path" in response["result"]["content"][0]["text"]


def test_an_unknown_tool_is_a_json_rpc_error():
    response = _call("actaira_do_my_taxes")

    assert "error" in response
    assert response["error"]["code"] == -32602


def test_an_unknown_method_is_a_json_rpc_error():
    response = handle(_request(1, "resources/list"))

    assert response["error"]["code"] == -32601


def test_initialize_answers_with_the_protocol_and_the_tool_capability():
    response = handle(_request(1, "initialize", {"protocolVersion": "2025-06-18"}))

    assert "tools" in response["result"]["capabilities"]
    assert response["result"]["serverInfo"]["name"] == "actaira"


def test_a_notification_gets_no_response():
    """A JSON-RPC message with no id is a notification, and answering one is a
    protocol error that some clients treat as a fatal desync."""
    assert handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_the_server_never_claims_a_capture_level_it_did_not_reach():
    """The server reports on packages, not on sessions, and it must not let a
    caller read a verification as a statement about how a trace was captured."""
    listed = handle(_request(1, "tools/list"))

    blob = json.dumps(listed)
    assert CaptureLevel.L3.value not in blob


# ---------------------------------------------------------------------------
# It has to work as a process, because that is how it will be run
# ---------------------------------------------------------------------------


def test_the_entry_point_speaks_json_rpc_over_stdio():
    """`.mcp.json` runs a command. This is that command, driven the way a
    client drives it."""
    messages = [
        json.dumps(_request(1, "initialize", {"protocolVersion": "2025-06-18"})),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps(_request(2, "tools/list")),
    ]
    run = subprocess.run(  # noqa: S603 - a fixed argv, no shell
        [sys.executable, "-m", "actaira.mcp"],
        input="\n".join(messages) + "\n",
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert run.returncode == 0, run.stderr
    answers = [json.loads(line) for line in run.stdout.splitlines() if line.strip()]
    assert [answer["id"] for answer in answers] == [1, 2], "the notification was answered"
    assert len(answers[1]["result"]["tools"]) == 3


def test_the_server_prints_nothing_on_stdout_that_is_not_a_response():
    """stdout is the transport. A stray print corrupts the protocol, which is
    the classic way an MCP server dies in somebody else's client."""
    run = subprocess.run(  # noqa: S603 - a fixed argv, no shell
        [sys.executable, "-m", "actaira.mcp"],
        input=json.dumps(_request(1, "tools/list")) + "\n",
        capture_output=True,
        text=True,
        timeout=60,
    )

    for line in run.stdout.splitlines():
        if line.strip():
            json.loads(line)


# ---------------------------------------------------------------------------
# `state` and `ok` are the same fact, and the property says so
# ---------------------------------------------------------------------------


def _verify_payloads(tmp_path) -> list[tuple[str, dict]]:
    """One payload per way `actaira_verify` can come back, named.

    Built as a corpus rather than asserted one case at a time, for the reason
    `test_the_corpus_is_not_all_failures` gives next door: a property stated
    over three examples is three examples.
    """
    from actaira.attest import chain
    from support.reports import record

    report = record(tmp_path / "clean.safetensors")
    entries: list[chain.Entry] = []
    chain.append(entries, report.sha256, report.to_dict(), timestamp="2026-01-01T00:00:00")
    healthy = package.write_package(tmp_path / "healthy.zip", entries, signing.generate())

    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(tampered, "w") as archive:
        archive.writestr("manifest.json", '{"not": "a package"}')

    cases = {
        "a package that verifies": str(healthy.path),
        "a package that does not": str(tampered),
        "a path that is not a package at all": str(tmp_path / "absent.zip"),
    }
    return [
        (name, json.loads(_call("actaira_verify", {"path": path})["result"]["content"][0]["text"]))
        for name, path in cases.items()
    ]


def test_state_says_verified_if_and_only_if_the_package_verified(tmp_path):
    """The bicondition, which is the whole of the defect.

    `payload["state"] = "verified"` sat outside every condition, so a tampered
    package came back `{"state": "verified", "ok": false}`. `ok` was right and
    `isError` was right; the field whose NAME invites a caller to read it was
    the one that lied, on the one surface other people's agents call directly.

    Stated as `state == "verified"` exactly when `ok`, in both directions, for
    the same reason phase 0.1 wrote `recorded is applies` rather than two
    assertions: an implication in one direction is satisfied by a field that
    is always the same word.
    """
    payloads = _verify_payloads(tmp_path)

    for name, payload in payloads:
        assert (payload["state"] == "verified") == (payload["ok"] is True), (
            f"{name}: state is {payload['state']!r} and ok is {payload['ok']!r}"
        )
        assert payload["state"] in {"verified", "not_verified"}, name
    # The guard on the property: a corpus that verified nothing, or one that
    # verified everything, would satisfy the bicondition and prove neither
    # direction of it.
    outcomes = {payload["ok"] for _name, payload in payloads}
    assert outcomes == {True, False}, "the corpus has to reach both answers"


def test_a_package_that_does_not_verify_is_never_reported_as_verified(tmp_path):
    """The direction that was broken, on its own, so a later change that makes
    `state` always say `not_verified` cannot pass the bicondition above and
    this one at the same time."""
    payloads = _verify_payloads(tmp_path)

    for name, payload in payloads:
        if payload["ok"] is not True:
            assert payload["state"] == "not_verified", name
            assert payload["problems"], f"{name}: a refusal with no reason is not a refusal"
