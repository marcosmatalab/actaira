"""The evidence, change and decision routes: what they answer and what they refuse.

Three properties, and the third needs the most tests.

**They agree with the engine.** Every assertion that could be written against
a literal is written against the function the CLI calls instead, because a
test that pins the browser's answer to a constant passes while the two
surfaces drift apart.

**They are readers.** Nothing here writes, and the tests that matter prove it
by comparing the database file's bytes before and after - including on the
paths that refuse, because a refusal that had already migrated the schema
would have done the damage before saying no.

**They draw text that came from somewhere else.** The ledger holds ids,
subject names and payload keys that arrived from a registry, a manifest or a
filename. So the markup tests are not decoration: they put a script tag
through an evidence id, a subject name and a payload value, and assert it
comes back as text.
"""
from __future__ import annotations

import http.client
import json
import sqlite3
import threading
from http import HTTPStatus
from pathlib import Path

import pytest

from actaira.state import change as change_mod
from actaira.state import decide as decide_mod
from actaira.state import evidence as evidence_mod
from actaira.state import graph as graph_mod
from actaira.state import record as record_mod
from actaira.state.evidence import KINDS, EvidenceState
from actaira.state.snapshot import snapshot_of
from actaira.state.store import MIGRATIONS, Store
from actaira.state.watch import observe
from actaira.web import server as web

HOSTILE = "<script>alert(1)</script>"
STATE_ROUTES = ("/api/evidence", "/api/changes", "/api/decisions")


# ---------------------------------------------------------------------------
# A workspace with the whole story in it, and a server reading it
# ---------------------------------------------------------------------------


class _Decision:
    """The smallest thing `record_decision` reads.

    A real `PolicyDecision` would drag a policy file and an evaluation into a
    test about HTTP, and the storage rule is what is under test here.
    """

    def __init__(self, value: str = "allow") -> None:
        from datetime import date

        self.decision = type("V", (), {"value": value})()
        self.policy_id = "production"
        self.policy_version = 1
        self.policy_digest = "sha256:" + "pol" * 10
        self.decided_on = date(2026, 1, 1)
        self.subjects = ()

    def to_dict(self) -> dict:
        return {"decision": self.decision.value, "policy": self.policy_id}


def build(root: Path) -> Path:
    """Observed, scanned, approved, then changed.

    Built through the engine rather than by inserting rows, so no panel can be
    tested against a state the commands could not have produced.
    """
    from actaira.inspect import inspect_artifact

    models = root / "models"
    models.mkdir()
    (models / "model.bin").write_bytes(b"\x80\x04}\x94.")
    (models / "tokenizer.bin").write_bytes(b"vocabulary")

    def listing() -> list[dict]:
        return [{"uri": path.as_uri(), "path": path.name, "size": path.stat().st_size}
                for path in sorted(models.glob("*.bin"))]

    path = root / "state.db"
    with Store(path) as store:
        store.add_source("m", "filesystem", str(models))
        observe(store, snapshot_of("m", str(models), "filesystem", listing(),
                                   measure_local=True))
        model = next(row["asset_id"] for row in store.assets()
                     if row["name"].endswith("model.bin"))
        record_mod.artifact_scan(store, inspect_artifact(models / "model.bin"))
        store.record_decision(
            _Decision(), "proof-1",
            [decide_mod.subject_input(model, store.asset(model)["digest"])],
        )
        (models / "model.bin").write_bytes(b"\x80\x04}\x94\x8c\x01a\x94K\x01s.")
        observe(store, snapshot_of("m", str(models), "filesystem", listing(),
                                   measure_local=True))
    return path


def serve(state: Path | None):
    httpd = web.build_server("127.0.0.1", 0, state)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


@pytest.fixture(scope="module")
def workspace(tmp_path_factory):
    return build(tmp_path_factory.mktemp("assurance"))


@pytest.fixture(scope="module")
def running(workspace):
    httpd = serve(workspace)
    try:
        yield httpd.server_address
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture
def stateless(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    httpd = serve(None)
    try:
        yield httpd.server_address
    finally:
        httpd.shutdown()
        httpd.server_close()


def post(address, path: str, body: dict | None = None, **overrides: str) -> tuple[int, dict]:
    status, _, raw = post_raw(address, path, body, **overrides)
    try:
        return status, json.loads(raw.decode("utf-8"))
    except ValueError:
        return status, {"raw": raw.decode("utf-8", "replace")}


def post_raw(address, path: str, body, **overrides: str) -> tuple[int, dict, bytes]:
    blob = json.dumps(body if body is not None else {}).encode("utf-8")
    headers = {"Content-Type": "application/json", "Content-Length": str(len(blob)),
               "Host": f"{address[0]}:{address[1]}"}
    headers.update(overrides)
    connection = http.client.HTTPConnection(*address, timeout=30)
    try:
        connection.request("POST", path, blob, headers)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def ok(address, path: str, body: dict | None = None) -> dict:
    status, payload = post(address, path, body)
    assert status == HTTPStatus.OK, (status, payload)
    return payload


def get(address, path: str) -> int:
    connection = http.client.HTTPConnection(*address, timeout=30)
    try:
        connection.request("GET", path, headers={"Host": f"{address[0]}:{address[1]}"})
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Agreement with the engine
# ---------------------------------------------------------------------------


def test_the_ledger_route_returns_what_the_store_holds(running, workspace):
    payload = ok(running, "/api/evidence")
    with Store(workspace, create=False) as store:
        expected = store.all_evidence()
    assert payload["total"] == len(expected)
    assert [row["evidence_id"] for row in payload["evidence"]] == \
        [row["evidence_id"] for row in expected]


def test_the_tallies_carry_every_state_and_every_kind(running):
    """Including the zeroes.

    A summary whose absent keys mean zero cannot be told apart from one whose
    absent keys mean the server did not compute it, so it can never say
    "nothing has been revoked".
    """
    payload = ok(running, "/api/evidence")
    assert set(payload["by_state"]) == {item.value for item in EvidenceState}
    assert set(payload["by_kind"]) == set(KINDS)
    assert sum(payload["by_state"].values()) == payload["total"]


def test_the_tallies_do_not_move_with_the_filter(running):
    """A reader who has filtered to one state still needs the whole picture."""
    everything = ok(running, "/api/evidence")
    filtered = ok(running, "/api/evidence", {"state": "superseded"})
    assert filtered["by_state"] == everything["by_state"]
    assert filtered["total"] == everything["total"]
    assert filtered["matched"] < everything["total"]


def test_filtering_by_state_returns_only_that_state(running):
    payload = ok(running, "/api/evidence", {"state": "superseded"})
    assert payload["evidence"]
    assert {row["state"] for row in payload["evidence"]} == {"superseded"}


def test_filtering_by_kind_returns_only_that_kind(running):
    payload = ok(running, "/api/evidence", {"kind": "artifact_scan"})
    assert payload["evidence"]
    assert {row["kind"] for row in payload["evidence"]} == {"artifact_scan"}


def test_searching_matches_the_subject_and_the_id(running):
    one = ok(running, "/api/evidence")["evidence"][0]
    for needle in (one["subject"], one["evidence_id"]):
        found = ok(running, "/api/evidence", {"subject": needle})
        assert one["evidence_id"] in [row["evidence_id"] for row in found["evidence"]]


def test_one_record_puts_the_digest_it_was_taken_about_beside_the_current_one(running, workspace):
    """The comparison the panel exists for.

    A record says which digest it was taken about; the asset row says what the
    subject has now; and showing the two together is what turns "superseded"
    from a label into a fact somebody can check.
    """
    scan = ok(running, "/api/evidence", {"kind": "artifact_scan"})["evidence"][0]
    payload = ok(running, "/api/evidence/record", {"id": scan["evidence_id"]})
    with Store(workspace, create=False) as store:
        asset = store.asset(scan["subject"])
    assert payload["found"]
    assert payload["payload"]["verdict"]
    assert payload["subject"]["digest_then"] == scan["subject_digest"]
    assert payload["subject"]["digest_now"] == asset["digest"]
    assert payload["subject"]["digest_then"] != payload["subject"]["digest_now"]


def test_one_record_carries_its_subjects_currentness(running):
    """The third fact, without which two equal digests read as "nothing changed".

    An artifact removed from its source keeps the last digest the store saw,
    so `then` and `now` agree while the subject is not in the latest
    observation at all. Same three-valued projection the graph panel draws.
    """
    scan = ok(running, "/api/evidence", {"kind": "artifact_scan"})["evidence"][0]
    payload = ok(running, "/api/evidence/record", {"id": scan["evidence_id"]})
    assert payload["subject"]["currentness"] in graph_mod.CURRENTNESS


def test_a_record_carries_the_whole_history_of_its_subject(running, workspace):
    scan = ok(running, "/api/evidence", {"kind": "artifact_scan"})["evidence"][0]
    payload = ok(running, "/api/evidence/record", {"id": scan["evidence_id"]})
    with Store(workspace, create=False) as store:
        expected = store.evidence_for(scan["subject"])
    assert [row["evidence_id"] for row in payload["timeline"]] == \
        [row["evidence_id"] for row in expected]


def test_an_unknown_record_is_a_fact_rather_than_an_error(running):
    """A 404 would make the panel render a failure for a true answer."""
    status, payload = post(running, "/api/evidence/record", {"id": "ev_nothing"})
    assert status == HTTPStatus.OK
    assert payload["found"] is False
    assert payload["asked"] == "ev_nothing"


def test_the_changes_route_agrees_with_the_engine(running, workspace):
    payload = ok(running, "/api/changes")
    with Store(workspace, create=False) as store:
        expected = change_mod.history(store, limit=web.MAX_CHANGE_ROWS)
    assert payload["changes"] == expected


def test_the_changes_route_names_the_two_states_no_stored_row_can_hold(running):
    """UNCHANGED and INCOMPLETE write no snapshot, by design.

    A vocabulary that listed them would promise a timeline this store cannot
    draw, so they are named separately as what is NOT recorded.
    """
    payload = ok(running, "/api/changes")
    assert payload["not_recorded"] == ["unchanged", "incomplete"]
    assert "unchanged" not in payload["states"]
    assert "incomplete" not in payload["states"]


def test_every_change_entry_says_supersession_is_not_reconstructible(running):
    """Never a zero standing in for a gap."""
    payload = ok(running, "/api/changes")
    assert payload["changes"]
    assert all(row["supersession_known"] is False for row in payload["changes"])


def test_the_decisions_route_agrees_with_the_engine(running, workspace):
    payload = ok(running, "/api/decisions")
    with Store(workspace, create=False) as store:
        expected = [row.to_dict() for row in decide_mod.review(store)]
    assert payload["decisions"] == expected
    assert set(payload["counts"]) == set(decide_mod.VALIDITIES)


def test_a_decision_keeps_its_value_and_gains_a_separate_validity(running):
    """The two fields a panel must never merge.

    This route is not allowed to rewrite `decision`, and this is the assertion
    that fails if somebody decides one field would be simpler.
    """
    row = ok(running, "/api/decisions")["decisions"][0]
    assert row["decision"] == "allow"
    assert row["validity"] == decide_mod.REQUIRES_REASSESSMENT
    assert row["reasons"]


def test_every_reassessment_reason_is_machine_readable_and_carries_no_score(running):
    row = ok(running, "/api/decisions")["decisions"][0]
    assert row["reasons"]
    for reason in row["reasons"]:
        assert reason["reason"]
        if reason["reason"] == "subject_digest_changed":
            assert reason["was"] and reason["now"] and reason["was"] != reason["now"]
    blob = json.dumps(row).lower()
    for word in ("score", "grade", "rating", "percent"):
        assert word not in blob


# ---------------------------------------------------------------------------
# Readers, proven by the file
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", STATE_ROUTES)
def test_reading_leaves_the_database_byte_identical(running, workspace, route):
    before = workspace.read_bytes()
    ok(running, route)
    assert workspace.read_bytes() == before


def test_an_older_database_is_refused_and_not_migrated(tmp_path):
    """The refusal has to happen before anything opens the store for writing.

    A read that migrated on the way to saying no would have changed the file
    the operator asked it only to look at.
    """
    path = tmp_path / "old.db"
    connection = sqlite3.connect(path)
    MIGRATIONS[0](connection)
    connection.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '1')")
    connection.commit()
    connection.close()
    before = path.read_bytes()

    httpd = serve(path)
    try:
        for route in STATE_ROUTES:
            status, body = post(httpd.server_address, route)
            assert status == HTTPStatus.CONFLICT
            assert body["error"]["code"] == "workspace_older_schema"
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert path.read_bytes() == before


def test_a_future_database_is_a_structured_error_not_a_traceback(tmp_path):
    path = tmp_path / "future.db"
    connection = sqlite3.connect(path)
    for step in MIGRATIONS:
        step(connection)
    connection.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '99')")
    connection.commit()
    connection.close()

    httpd = serve(path)
    try:
        status, body = post(httpd.server_address, "/api/evidence")
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert status == HTTPStatus.CONFLICT
    assert body["error"]["code"] == "workspace_newer_schema"
    assert "Traceback" not in json.dumps(body)


def test_a_file_that_is_not_a_database_is_refused_legibly(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("this is not a database", encoding="utf-8")
    httpd = serve(path)
    try:
        status, body = post(httpd.server_address, "/api/decisions")
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert status == HTTPStatus.CONFLICT
    assert body["error"]["code"] == "workspace_unreadable"
    assert "Traceback" not in json.dumps(body)


def test_with_no_workspace_every_route_refuses_the_same_way(stateless):
    for route in STATE_ROUTES:
        status, body = post(stateless, route)
        assert status == HTTPStatus.CONFLICT
        assert body["error"]["code"] == "workspace_absent"


def test_a_read_never_creates_a_workspace(stateless, tmp_path):
    for route in STATE_ROUTES:
        post(stateless, route)
    assert not (tmp_path / ".actaira").exists()
    assert not list(tmp_path.glob("*.db"))


# ---------------------------------------------------------------------------
# The browser cannot name a database
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field", ["state_path", "path", "db", "workspace", "file", "state"])
def test_no_body_field_can_point_the_server_at_another_file(running, tmp_path, field):
    """The state path is chosen at start-up and nowhere else.

    A route that accepted a path would be a file-existence oracle at best and
    an sqlite parser fed hostile input at worst. `state` is in this list on
    purpose: it IS a field on this route, meaning an evidence state, and the
    test is that it cannot be made to mean a filename.
    """
    other = tmp_path / "elsewhere.db"
    with Store(other) as store:
        store.add_source("x", "filesystem", "/tmp/x")
    mine = ok(running, "/api/evidence")
    status, body = post(running, "/api/evidence", {field: str(other)})
    if status == HTTPStatus.OK:
        assert body["total"] == mine["total"], f"`{field}` changed which database was read"
    else:
        assert status == HTTPStatus.BAD_REQUEST


def test_no_response_carries_an_absolute_filesystem_path(running, workspace):
    """Where this machine keeps things is not the browser's business."""
    blob = json.dumps([ok(running, route) for route in STATE_ROUTES])
    assert str(workspace) not in blob
    assert str(workspace.parent) not in blob
    assert workspace.name in blob


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", STATE_ROUTES)
def test_a_rebound_host_is_refused(running, route):
    status, _ = post(running, route, {}, Host="evil.example")
    assert status == HTTPStatus.FORBIDDEN


@pytest.mark.parametrize("route", STATE_ROUTES)
def test_a_cross_origin_request_is_refused(running, route):
    status, _ = post(running, route, {}, Origin="https://evil.example")
    assert status == HTTPStatus.FORBIDDEN


def test_get_is_not_a_way_in(running):
    """None of these is reachable as a subresource from a page elsewhere."""
    for route in (*STATE_ROUTES, "/api/evidence/record"):
        assert get(running, route) == HTTPStatus.NOT_FOUND


@pytest.mark.parametrize("field,value", [("state", "nearly_valid"), ("kind", "vibes")])
def test_an_unknown_filter_value_is_refused_rather_than_ignored(running, field, value):
    """A filter the server silently dropped would show every record under a
    heading saying it had shown one kind."""
    status, body = post(running, "/api/evidence", {field: value})
    assert status == HTTPStatus.BAD_REQUEST
    assert body["error"]["code"] == "bad_" + field


def test_an_oversized_id_is_refused_before_it_reaches_sqlite(running):
    status, body = post(running, "/api/evidence/record",
                        {"id": "e" * (web.MAX_NODE_ID_CHARS + 1)})
    assert status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    assert body["error"]["code"] == "id_too_long"


def test_a_subject_that_is_not_text_is_refused(running):
    status, body = post(running, "/api/evidence", {"subject": {"not": "text"}})
    assert status == HTTPStatus.BAD_REQUEST
    assert body["error"]["code"] == "bad_subject"


def test_a_missing_id_is_refused(running):
    status, body = post(running, "/api/evidence/record", {})
    assert status == HTTPStatus.BAD_REQUEST
    assert body["error"]["code"] == "missing_id"


def test_the_security_headers_are_the_same_on_these_routes(running):
    """Nothing about reading a workspace relaxes them.

    Checked on the new routes specifically, because a route added later is the
    one that gets a bespoke response helper and loses them.
    """
    _, headers, _ = post_raw(running, "/api/evidence", {})
    assert "unsafe-inline" not in headers["Content-Security-Policy"]
    assert headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert "no-store" in headers["Cache-Control"]
    assert headers["X-Content-Type-Options"] == "nosniff"


# ---------------------------------------------------------------------------
# Hostile text, which is most of what this panel draws
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def hostile(tmp_path_factory):
    """A ledger whose every text field came from somewhere untrusted."""
    path = tmp_path_factory.mktemp("hostile") / "state.db"
    with Store(path) as store:
        store.upsert_asset(f"artifact:{HOSTILE}", "artifact", HOSTILE,
                           digest="sha256:" + "aa" * 32)
        store.record_evidence(evidence_mod.for_subject(
            f"artifact:{HOSTILE}", "artifact_scan",
            subject_digest="sha256:" + "aa" * 32,
            payload={HOSTILE: HOSTILE, "verdict": HOSTILE},
        ))
    httpd = serve(path)
    try:
        yield httpd.server_address
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_hostile_text_round_trips_as_text(hostile):
    """The ledger holds names that came from a registry, a manifest or a file.

    The server's job is to return them unchanged - the front end never assigns
    to `innerHTML`, which `test_web_frontend.py` asserts from the other side -
    and what must not happen is the server helpfully rendering any of it.
    """
    listing = ok(hostile, "/api/evidence")
    row = listing["evidence"][0]
    assert row["subject"] == f"artifact:{HOSTILE}"

    detail = ok(hostile, "/api/evidence/record", {"id": row["evidence_id"]})
    assert detail["subject"]["name"] == HOSTILE
    assert detail["payload"]["verdict"] == HOSTILE
    assert HOSTILE in detail["payload"]

    # The markup is in the body, because `json.dumps` does not escape `<` and
    # pretending otherwise would be testing a defence this response does not
    # rely on. What it relies on is that the bytes never reach an HTML parser:
    # the response is `application/json` and `nosniff` forbids the browser
    # from deciding otherwise. Asserting the real mitigation rather than an
    # incidental absence is the difference between a test and a comfort.
    _, headers, raw = post_raw(hostile, "/api/evidence", {})
    assert HOSTILE.encode() in raw
    assert headers["Content-Type"].startswith("application/json")
    assert headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize("needle", ["%", "_", "*", "(((((", "[a-z]+", "'; DROP TABLE evidence;--"])
def test_a_search_needle_is_a_substring_and_never_a_pattern(hostile, needle):
    """Not a LIKE, not a regex, not concatenated into SQL.

    `%` reaching LIKE would match everything; `(((((` reaching a regex engine
    could be made to take exponential time; and the last one is there because
    a search box that is not parameterised is the oldest bug there is.
    """
    everything = ok(hostile, "/api/evidence")
    found = ok(hostile, "/api/evidence", {"subject": needle})
    assert found["matched"] <= everything["total"]
    if found["matched"]:
        assert needle.lower() in json.dumps(found["evidence"]).lower()
    # And the table is still there.
    assert ok(hostile, "/api/evidence")["total"] == everything["total"]


# ---------------------------------------------------------------------------
# Bounds and empty states
# ---------------------------------------------------------------------------


def test_a_long_ledger_is_capped_and_says_so(tmp_path):
    """A page of results that says nothing about the rest looks complete."""
    path = tmp_path / "many.db"
    with Store(path) as store, store.transaction() as connection:
        for index in range(web.MAX_EVIDENCE_ROWS + 25):
            store.record_evidence(
                evidence_mod.for_subject(f"artifact:{index}", "artifact_scan",
                                         subject_digest=f"sha256:{index:064d}"),
                connection,
            )
    httpd = serve(path)
    try:
        payload = ok(httpd.server_address, "/api/evidence")
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert len(payload["evidence"]) == web.MAX_EVIDENCE_ROWS
    assert payload["truncated"] is True
    assert payload["matched"] == web.MAX_EVIDENCE_ROWS + 25
    assert payload["limit"] == web.MAX_EVIDENCE_ROWS


def test_an_empty_workspace_is_an_answer_rather_than_an_error(tmp_path):
    path = tmp_path / "empty.db"
    with Store(path):
        pass
    httpd = serve(path)
    try:
        address = httpd.server_address
        assert ok(address, "/api/evidence")["total"] == 0
        assert ok(address, "/api/evidence")["truncated"] is False
        assert ok(address, "/api/changes")["changes"] == []
        assert ok(address, "/api/decisions")["decisions"] == []
        assert ok(address, "/api/decisions")["counts"] == dict.fromkeys(
            decide_mod.VALIDITIES, 0)
    finally:
        httpd.shutdown()
        httpd.server_close()
