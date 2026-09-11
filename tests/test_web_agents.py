"""The four agent routes, and the ways a declaration can be hostile.

`actaira agent` was reachable only from the CLI: the interface covered
inspection, attestation, verification and governance, and the capability that
is hardest to reason about without a picture, an agent and the routes it can
be walked down, had no picture. These are the routes that closed that, and
this file is about what they must refuse.

The rule that shapes all four: **the browser and the terminal must not be able
to disagree.** Each handler loads the declaration with `agentgov.load_text`
and hands it to the same function the CLI calls, so there is one
implementation of what a finding is, and a test here that compares the two
would be comparing a function with itself. What is worth testing is the
boundary: the size ceiling, the decoding, the refusals, and the fact that a
declaration the parser rejects comes back as a sentence rather than a 500.

A declaration is not an artifact, and the difference is the reason for
`MAX_DECLARATION_BYTES`. An artifact may be gigabytes and is streamed to disk
and never buffered. A declaration is a page of YAML that has to be read into
memory to be parsed at all, so it gets a ceiling of its own rather than
inheriting a 2 GiB one it would then have to honour by allocating 2 GiB.
"""
from __future__ import annotations

import http.client
import json
import threading
from pathlib import Path

import pytest

from actaira.web import server as web
from conftest import REPO_ROOT

BOUNDARY = "----actairaagents"
DECLARATION = (Path(REPO_ROOT) / "examples" / "agent-ticket-triage.yaml").read_text(encoding="utf-8")

ROUTES = ("/api/agent/check", "/api/agent/bom", "/api/agent/paths", "/api/agent/diff")


@pytest.fixture(scope="module")
def running():
    httpd = web.build_server("127.0.0.1", 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address
    finally:
        httpd.shutdown()
        httpd.server_close()


def multipart(file_bytes: bytes, filename: str = "agent.yaml", **fields: str) -> bytes:
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.append(
            f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
            + value.encode("utf-8") + b"\r\n"
        )
    chunks.append(
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n\r\n'.encode()
        + file_bytes + b"\r\n"
    )
    chunks.append(f"--{BOUNDARY}--\r\n".encode())
    return b"".join(chunks)


def post(address, path: str, body: bytes, **overrides: str) -> tuple[int, dict]:
    headers = {
        "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
        "Host": f"{address[0]}:{address[1]}",
    }
    headers.update(overrides)
    connection = http.client.HTTPConnection(address[0], address[1], timeout=30)
    try:
        connection.request("POST", path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        try:
            return response.status, json.loads(payload)
        except ValueError:
            return response.status, {}
    finally:
        connection.close()


def send(address, path: str, text: str, filename: str = "agent.yaml", **fields: str):
    return post(address, path, multipart(text.encode("utf-8"), filename, **fields))


# ---------------------------------------------------------------------------
# What each route answers when the declaration is real
# ---------------------------------------------------------------------------


def test_check_reports_the_capability_findings_the_engine_found(running):
    from actaira.agentgov import assess, load_text

    status, payload = send(running, "/api/agent/check", DECLARATION)
    assert status == 200, payload
    expected = [finding.to_dict() for finding in assess(load_text(DECLARATION))]
    assert payload["findings"] == expected, (
        "the route reported something other than what `agentgov.assess` returns, "
        "so the browser and the terminal now disagree about this declaration"
    )
    assert payload["agent"]["name"] == "ticket-triage"


def test_paths_reports_the_routes_the_engine_found(running):
    from actaira.agentgov import load_text, paths

    status, payload = send(running, "/api/agent/paths", DECLARATION)
    assert status == 200, payload
    assert payload["report"] == paths.find(load_text(DECLARATION)).to_dict()
    assert payload["report"]["paths"], "the shipped example has routes and the route found none"


def test_bom_carries_the_digest_that_makes_it_comparable(running):
    status, payload = send(running, "/api/agent/bom", DECLARATION)
    assert status == 200, payload
    # An A-BOM without the agent's digest is a list you cannot tell two
    # releases apart with, which is the only thing an A-BOM is for.
    assert payload["bom"]["agent_digest"].startswith("sha256:")


def test_diff_answers_with_what_the_second_declaration_gained(running):
    after = DECLARATION.replace('version: "4"', 'version: "5"')
    assert after != DECLARATION, "the fixture no longer carries the version this test bumps"
    status, payload = send(running, "/api/agent/diff", DECLARATION, after=after)
    assert status == 200, payload
    assert payload["before"]["version"] != payload["after"]["version"]
    assert payload["diff"]["from_digest"] != payload["diff"]["to_digest"]


# ---------------------------------------------------------------------------
# What they refuse
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", ROUTES)
def test_an_empty_declaration_is_refused_by_name(running, route):
    """`_receive_upload` refuses an empty part before any of this runs, and
    that is the answer either way: an empty file is not a declaration."""
    status, payload = send(running, route, "")
    assert status == 400
    assert payload["error"]["code"] in ("empty_file", "empty_declaration")


@pytest.mark.parametrize("route", ROUTES)
def test_a_declaration_that_is_not_utf8_is_refused_as_text(running, route):
    """A binary file dropped on the agent panel by mistake.

    Reported as "not text" rather than as a parser error about a byte nobody
    typed, because the reader's mistake was the file, not its contents.
    """
    status, payload = post(running, route, multipart(bytes(range(256)) * 4))
    assert status == 400
    assert payload["error"]["code"] == "declaration_not_text"


@pytest.mark.parametrize("route", ROUTES)
def test_a_declaration_past_the_ceiling_is_refused_before_it_is_read(running, route):
    """The ceiling exists so that parsing never allocates what a stranger sent.

    It is deliberately far below the 2 GiB an artifact may be: a declaration
    that meets this limit is not a declaration.
    """
    huge = "agent: x\n" + ("# pad\n" * ((web.MAX_DECLARATION_BYTES // 6) + 64))
    assert len(huge.encode("utf-8")) > web.MAX_DECLARATION_BYTES
    status, payload = send(running, route, huge)
    assert status == 413
    assert payload["error"]["code"] == "declaration_too_large"


@pytest.mark.parametrize(
    "text",
    [
        "- a list\n- not a mapping\n",
        "tools: []\n",
        "agent: \n",
        ": : :\n",
        "agent: ok\ntools: [{name: a}, {name: a}]\n",
    ],
)
@pytest.mark.parametrize("route", ["/api/agent/check", "/api/agent/paths", "/api/agent/bom"])
def test_a_declaration_the_loader_refuses_comes_back_as_a_sentence(running, route, text):
    """Every way a declaration can be wrong is the caller's fault, not a crash.

    `DeclarationError` is the loader's one refusal type, so these are 400 with
    the loader's own words rather than 500 with a traceback the browser would
    then render.
    """
    status, payload = send(running, route, text)
    assert status == 400, payload
    assert payload["error"]["code"] == "bad_declaration"
    assert payload["error"]["message"], "a refusal with no reason is not a refusal"


def test_a_diff_with_only_one_declaration_says_which_half_is_missing(running):
    status, payload = send(running, "/api/agent/diff", DECLARATION)
    assert status == 400
    assert payload["error"]["code"] == "missing_after"


def test_a_diff_whose_second_declaration_is_broken_is_refused(running):
    status, payload = send(running, "/api/agent/diff", DECLARATION, after="- not a mapping\n")
    assert status == 400
    assert payload["error"]["code"] == "bad_declaration"


# ---------------------------------------------------------------------------
# The rules every POST route on this server already lived under
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", ROUTES)
def test_a_cross_origin_post_is_refused(running, route):
    """CSRF: a page on the internet driving this server through the operator's
    browser. The new routes inherit the check rather than negotiating one."""
    status, payload = post(running, route, multipart(DECLARATION.encode("utf-8")),
                           Origin="https://evil.example")
    assert status == 403
    assert payload["error"]["code"] == "cross_origin"


@pytest.mark.parametrize("route", ROUTES)
def test_a_rebound_host_is_refused(running, route):
    """DNS rebinding: a name re-pointed at 127.0.0.1 arrives with its own Host."""
    status, payload = post(running, route, multipart(DECLARATION.encode("utf-8")),
                           Host="evil.example")
    assert status == 403
    assert payload["error"]["code"] == "bad_host"


@pytest.mark.parametrize("route", ROUTES)
def test_a_body_that_is_not_multipart_is_refused(running, route):
    connection = http.client.HTTPConnection(running[0], running[1], timeout=30)
    try:
        connection.request("POST", route, body=b'{"agent": "x"}', headers={
            "Content-Type": "application/json",
            "Host": f"{running[0]}:{running[1]}",
        })
        assert connection.getresponse().status == 415
    finally:
        connection.close()


@pytest.mark.parametrize("route", ROUTES)
def test_the_agent_routes_answer_no_get(running, route):
    """They mutate nothing, but a GET is reachable as a subresource from a page
    this server did not serve, and the origin check only covers POST."""
    connection = http.client.HTTPConnection(running[0], running[1], timeout=30)
    try:
        connection.request("GET", route, headers={"Host": f"{running[0]}:{running[1]}"})
        assert connection.getresponse().status == 404
    finally:
        connection.close()


def test_a_hostile_filename_never_becomes_a_path(running):
    """The client's filename is used for its sanitised basename only.

    The declaration is read from the file the server wrote inside its own
    `mkdtemp()`, so a traversal in the name cannot reach anything: the request
    succeeds and reads the bytes that were uploaded, not `/etc/passwd`.
    """
    status, payload = send(running, "/api/agent/check", DECLARATION,
                           filename="../../../../etc/passwd")
    assert status == 200
    assert payload["agent"]["name"] == "ticket-triage"
