"""The limits the local server has to enforce, and the two headers it checks.

D-18 says this server treats every request as hostile because the files it is
handed are hostile by definition. That argument only holds where a limit
actually exists, and four places had none:

  * a multipart part could carry unbounded headers - each line capped, the
    number of lines not;
  * a request could carry unbounded parts, and unbounded distinct field
    names, each one 64 KiB;
  * `verify_package` read every zip member with `ZipFile.read`, which
    decompresses without limit, so `POST /api/verify` with a 1.4 MiB package
    allocated gigabytes;
  * `_Server.timeout` was set on the wrong class. `BaseServer.timeout` is read
    by `handle_request()`, which `serve_forever()` never calls, so the
    slowloris bound it was written for did not exist.

And two headers that were not checked at all: a page on the internet could
POST to this server through the operator's browser (CSRF), and a name
re-pointed at 127.0.0.1 could reach it as a same-origin request (DNS
rebinding).
"""
from __future__ import annotations

import http.client
import io
import json
import socket
import threading
import zipfile
from pathlib import Path

import pytest

from actaira.attest import chain, package
from actaira.attest.verify import MAX_MEMBER_BYTES, verify_package
from actaira.web import server as web
from conftest import corpus_build

BOUNDARY = "----actairalimits"


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


def post(address, path: str, body: bytes, headers: dict[str, str]) -> tuple[int, dict]:
    """A POST written against `http.client`, so the headers are ours to choose."""
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


def multipart(parts: list[tuple[str, str | None, bytes]], extra_headers: bytes = b"") -> bytes:
    chunks: list[bytes] = []
    for name, filename, blob in parts:
        disposition = f'form-data; name="{name}"'
        if filename is not None:
            disposition += f'; filename="{filename}"'
        head = f"--{BOUNDARY}\r\nContent-Disposition: {disposition}\r\n".encode()
        chunks.append(head + extra_headers + b"\r\n" + blob + b"\r\n")
    chunks.append(f"--{BOUNDARY}--\r\n".encode())
    return b"".join(chunks)


def artifact() -> bytes:
    return corpus_build.build_safetensors(
        {"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}}, b"\x00" * 64
    )


def scan_headers(address, **overrides: str) -> dict[str, str]:
    headers = {
        "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
        "Host": f"{address[0]}:{address[1]}",
    }
    headers.update(overrides)
    return headers


# ---------------------------------------------------------------------------
# Counts that had no ceiling
# ---------------------------------------------------------------------------

def test_a_part_with_more_headers_than_any_client_sends_is_refused(running):
    body = multipart(
        [("file", "clean.safetensors", artifact())],
        extra_headers=b"".join(b"X-%d: 1\r\n" % index for index in range(web.MAX_PART_HEADERS + 5)),
    )

    status, payload = post(running, "/api/scan", body, scan_headers(running))

    assert status == 400
    assert payload["error"]["code"] == "malformed_multipart"
    assert "headers" in payload["error"]["message"]


def test_a_part_with_the_headers_a_real_client_sends_is_accepted(running):
    """Negative control: two headers is what a browser sends."""
    body = multipart(
        [("file", "clean.safetensors", artifact())],
        extra_headers=b"Content-Type: application/octet-stream\r\n",
    )

    status, payload = post(running, "/api/scan", body, scan_headers(running))

    assert status == 200, payload
    assert payload["reports"][0]["verdict"] == "pass", payload


def test_a_request_with_more_parts_than_any_route_reads_is_refused(running):
    parts = [(f"field{index}", None, b"x") for index in range(web.MAX_PARTS + 2)]
    parts.append(("file", "clean.safetensors", artifact()))

    status, payload = post(running, "/api/scan", multipart(parts), scan_headers(running))

    assert status == 400
    assert payload["error"]["code"] in ("malformed_multipart", "too_many_fields")


def test_a_request_with_more_distinct_field_names_than_the_dictionary_holds_is_refused(running):
    parts: list[tuple[str, str | None, bytes]] = [("file", "clean.safetensors", artifact())]
    parts += [(f"field{index}", None, b"x") for index in range(web.MAX_FIELDS + 2)]

    status, payload = post(running, "/api/scan", multipart(parts), scan_headers(running))

    assert status == 400
    assert payload["error"]["code"] == "too_many_fields"


def test_the_fields_every_route_actually_uses_still_fit(running):
    """Negative control for both counts: the governance route reads four."""
    parts: list[tuple[str, str | None, bytes]] = [
        ("policy", None, b"strict"),
        ("fail_on", None, b"high"),
        ("on", None, b"2026-09-10"),
        ("role", None, b"provider"),
        ("lang", None, b"en"),
        ("file", "clean.safetensors", artifact()),
    ]

    status, payload = post(running, "/api/governance/assess", multipart(parts), scan_headers(running))

    assert status == 200, payload
    assert payload["assessed_on"] == "2026-09-10"


# ---------------------------------------------------------------------------
# A package member is not decompressed without a limit
# ---------------------------------------------------------------------------

def zip_bomb_package(path: Path) -> Path:
    """A package whose `entries.jsonl` is a few hundred KiB and gigabytes out.

    Nothing else about it is unusual: it has the four required members and a
    manifest, so the read happens before any check can reject it.
    """
    keypair_entries: list[chain.Entry] = []
    chain.append(keypair_entries, "0" * 64, {"path": "x", "verdict": "pass"})
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("manifest.json", json.dumps({"files": [], "time_anchor": "none"}))
        handle.writestr("manifest.sig", json.dumps({"signature_b64": ""}))
        handle.writestr("keyring.json", json.dumps({"keys": []}))
        handle.writestr("entries.jsonl", b"A" * (MAX_MEMBER_BYTES + 1024))
    return path


def test_a_package_member_that_decompresses_past_the_cap_is_refused_not_read(tmp_path):
    """Measured rather than argued: the refusal happens without the member
    ever being materialised, so this test costs a few hundred KiB of RAM."""
    path = zip_bomb_package(tmp_path / "bomb.zip")
    assert path.stat().st_size < 2 * 1024 * 1024, "the point is a small file with a huge member"

    result = verify_package(path)

    assert result.ok is False
    assert any("refusing to read it" in problem for problem in result.problems), result.problems


def test_the_verify_route_refuses_the_same_package_without_dying(running, tmp_path):
    path = zip_bomb_package(tmp_path / "bomb.zip")
    body = multipart([("file", "bomb.zip", path.read_bytes())])

    status, payload = post(running, "/api/verify", body, scan_headers(running))

    assert status == 200
    assert payload["ok"] is False
    assert any("refusing to read it" in problem for problem in payload["problems"])


def test_an_ordinary_package_is_still_read(tmp_path, keypair):
    """Negative control: the cap sits far above anything the writer produces."""
    entries: list[chain.Entry] = []
    for index in range(20):
        chain.append(entries, f"{index:064x}", {"path": f"model{index}.pt", "verdict": "pass"})
    result = package.write_package(tmp_path / "real.zip", entries, keypair)

    assert verify_package(result.path).ok is True


# ---------------------------------------------------------------------------
# The read timeout is on the object that reads
# ---------------------------------------------------------------------------

def test_the_socket_timeout_is_set_on_the_handler_and_not_on_the_server():
    """`BaseServer.timeout` is consulted by `handle_request()`, which
    `serve_forever()` never calls, so the number on the server class was dead
    code and the slowloris it was written for was unbounded."""
    assert web.ActairaHandler.timeout == 120
    assert "timeout" not in vars(web._Server), "a timeout here does nothing and reads as if it does"


def test_a_connection_actually_gets_that_timeout(running):
    """The handler's timeout reaches the socket, which is the whole claim."""
    seen: list[float | None] = []
    original = web.ActairaHandler.setup

    def record(self):
        original(self)
        seen.append(self.connection.gettimeout())

    web.ActairaHandler.setup = record
    try:
        post(running, "/api/health", b"", scan_headers(running))
    finally:
        web.ActairaHandler.setup = original

    assert seen and seen[0] == 120


# ---------------------------------------------------------------------------
# Origin and Host
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "origin",
    ["https://evil.example", "http://evil.example:8765", "http://127.0.0.1.evil.example",
     "http://[::ffff:8.8.8.8]", "http://user@127.0.0.1"],
)
def test_a_cross_origin_post_is_refused(running, origin):
    body = multipart([("file", "clean.safetensors", artifact())])

    status, payload = post(running, "/api/scan", body, scan_headers(running, Origin=origin))

    assert status == 403
    assert payload["error"]["code"] == "cross_origin"


@pytest.mark.parametrize("origin", ["http://127.0.0.1:8765", "http://localhost:8765", "http://[::1]:8765"])
def test_a_loopback_origin_is_accepted(running, origin):
    """Negative control: the panel this server ships is served from loopback
    and posts to itself."""
    body = multipart([("file", "clean.safetensors", artifact())])

    status, payload = post(running, "/api/scan", body, scan_headers(running, Origin=origin))

    assert status == 200, payload


def test_a_post_with_no_origin_header_is_accepted(running):
    """`curl` from the operator's own shell sends none, and refusing it would
    break every scripted use of this server for no gain: a browser always
    sends `Origin` on a cross-site POST."""
    body = multipart([("file", "clean.safetensors", artifact())])

    status, payload = post(running, "/api/scan", body, scan_headers(running))

    assert status == 200, payload


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8765", "rebind.attacker.test"])
def test_a_host_header_that_is_a_name_this_server_does_not_know_is_refused(running, host):
    """DNS rebinding: the page is served from a name whose A record is then
    flipped to 127.0.0.1, and the browser sends that name in `Host`."""
    body = multipart([("file", "clean.safetensors", artifact())])

    status, payload = post(running, "/api/scan", body, scan_headers(running, Host=host))

    assert status == 403
    assert payload["error"]["code"] == "bad_host"


@pytest.mark.parametrize("host", ["127.0.0.1:8765", "localhost:8765", "[::1]:8765", "192.168.1.5:8765"])
def test_an_address_literal_or_localhost_is_accepted_as_a_host(running, host):
    """An address cannot be rebound, and the operator may have bound this to a
    LAN address on purpose - `serve()` warns them about that in its own
    words."""
    body = multipart([("file", "clean.safetensors", artifact())])

    status, payload = post(running, "/api/scan", body, scan_headers(running, Host=host))

    assert status == 200, payload


def test_the_authority_check_is_tested_directly_too():
    """The parsing, without a socket in the way."""
    assert web._authority_is_local("127.0.0.1:8765")
    assert web._authority_is_local("[::1]:8765")
    assert web._authority_is_local("localhost")
    assert web._authority_is_local("192.168.1.5")
    assert not web._authority_is_local("evil.example")
    assert not web._authority_is_local("")
    assert not web._authority_is_local("127.0.0.1.evil.example")

    assert web._origin_is_local("http://127.0.0.1:8765")
    assert not web._origin_is_local("http://192.168.1.5:8765"), "an origin has to be loopback"
    assert not web._origin_is_local("file://")
    assert not web._origin_is_local("null")


def test_a_get_is_not_subject_to_the_origin_check(running):
    """Reads are safe and the panel fetches its own catalogue on load, so the
    check is where the side effects are."""
    connection = http.client.HTTPConnection(running[0], running[1], timeout=30)
    try:
        connection.request("GET", "/api/health", headers={"Origin": "https://evil.example"})
        response = connection.getresponse()
        assert response.status == 200
        assert json.loads(response.read())["ok"] is True
    finally:
        connection.close()


def test_the_module_still_imports_the_symbols_this_file_reaches_into():
    """A guard on the test, not the code: these are private names, and a
    rename would otherwise make the assertions above vanish silently."""
    for name in ("MAX_PART_HEADERS", "MAX_PARTS", "MAX_FIELDS", "_authority_is_local",
                 "_origin_is_local", "ActairaHandler", "_Server"):
        assert hasattr(web, name), name
    assert isinstance(io.BytesIO, type) and isinstance(socket.AF_INET, int)


# ---------------------------------------------------------------------------
# The headers, stated as a set rather than one at a time
# ---------------------------------------------------------------------------

def test_every_response_carries_the_whole_header_set(running):
    """Two of these were added in the 2.2 closing pass and the reason they are
    asserted together is that a header set is only as good as its weakest
    response: a route that answers through a different path and loses one of
    them is exactly the bug this catches.

    `Cross-Origin-Resource-Policy` is the one that closes a real gap. The
    origin check refuses a cross-site POST, and a subresource load is a GET -
    so `<img src="http://127.0.0.1:8765/api/samples">` on a page the operator
    is reading reached this server before, and what came back was readable to
    the embedding page's timing and error handlers.
    """
    expected = {
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cache-Control": "no-store",
    }

    for route in ("/", "/api/health", "/static/app.js"):
        connection = http.client.HTTPConnection(*running, timeout=10)
        connection.request("GET", route)
        response = connection.getresponse()
        response.read()
        for header, value in expected.items():
            assert response.getheader(header) == value, f"{route} lost {header}"
        assert "'self'" in (response.getheader("Content-Security-Policy") or "")
        policy = response.getheader("Permissions-Policy") or ""
        for feature in ("camera", "microphone", "geolocation", "payment", "usb"):
            assert f"{feature}=()" in policy, f"{route} does not refuse {feature}"
        connection.close()


def test_the_local_server_does_not_send_hsts(running):
    """Asserted as an absence, because it is a decision rather than an omission.

    This server binds 127.0.0.1 over plain HTTP. `Strict-Transport-Security`
    from it would pin the whole of `localhost` to HTTPS in the operator's
    browser - breaking every other local development server on that machine -
    in exchange for a protection that does not apply to loopback. A future
    edit that adds it "for completeness" fails here.
    """
    connection = http.client.HTTPConnection(*running, timeout=10)
    connection.request("GET", "/")
    response = connection.getresponse()
    response.read()

    assert response.getheader("Strict-Transport-Security") is None
    connection.close()
