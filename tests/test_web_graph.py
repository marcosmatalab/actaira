"""The four workspace routes: what they answer, what they refuse, what they never do.

Design note D-244. These are the first routes that read something other than
the bytes the operator just handed over, so the questions they have to survive
are different from every other route's.

**Whose database is it?** The path is chosen when the server starts and no
request can name one. A route that accepted a path would be a file-existence
oracle at best and an sqlite parser fed hostile input at worst, and the tests
below try to give it one in three different ways.

**Does reading change anything?** No. A workspace older than this release is
reported, not migrated; a missing one is reported, not created. Every other
command in this tool migrates on the way in, which is right for something
somebody typed and wrong for a page left open in a tab.

**Does the browser get a different answer from the terminal?** It must not, so
the tests that matter compare the response with what `state/graph.py` returns
for the same store, rather than with a literal.
"""
from __future__ import annotations

import http.client
import json
import sqlite3
import threading
from pathlib import Path

import pytest

from actaira.state import graph as graph_mod
from actaira.state.snapshot import snapshot_of
from actaira.state.store import SCHEMA_VERSION, Store
from actaira.state.watch import observe
from actaira.web import server as web
from conftest import REPO_ROOT

SUBJECTS = Path(REPO_ROOT) / "examples" / "subjects.yaml"

KEPT = {"uri": "hf://acme/m/model.safetensors", "size": 40, "declared_sha256": "a1" * 32}
DROPPED = {"uri": "hf://acme/m/old.bin", "size": 80, "declared_sha256": "c3" * 32}


def build(path: Path) -> Path:
    """A workspace with both kinds of edge and one asset that has gone away."""
    from actaira import manifest as manifest_mod
    from actaira.statecli import _record_manifest

    with Store(path) as store:
        _record_manifest(store, manifest_mod.load(SUBJECTS), SUBJECTS)
        store.add_source("m", "huggingface", "hf://acme/m")
        for rows, revision, moment in (
            ([KEPT, DROPPED], "r1", "2026-01-01T00:00:00+00:00"),
            ([KEPT], "r2", "2026-01-02T00:00:00+00:00"),
        ):
            observe(store, snapshot_of("m", "hf://acme/m", "huggingface", rows,
                                       revision=revision, observed_at=moment))
    return path


def serve(state: Path | None):
    httpd = web.build_server("127.0.0.1", 0, state)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


@pytest.fixture(scope="module")
def workspace(tmp_path_factory):
    return build(tmp_path_factory.mktemp("ws") / "state.db")


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
    """A server started with no `--state`, in a directory with no workspace.

    The default path is resolved from the working directory, so the directory
    is moved as well: without that, a checkout that happens to have `.actaira/`
    would make this fixture silently test the wrong thing.
    """
    monkeypatch.chdir(tmp_path)
    httpd = serve(None)
    try:
        yield httpd.server_address
    finally:
        httpd.shutdown()
        httpd.server_close()


def post(address, path: str, body: dict | None = None, **overrides: str) -> tuple[int, dict]:
    blob = json.dumps(body if body is not None else {}).encode("utf-8")
    headers = {"Content-Type": "application/json", "Content-Length": str(len(blob)),
               "Host": f"{address[0]}:{address[1]}"}
    headers.update(overrides)
    connection = http.client.HTTPConnection(*address, timeout=30)
    try:
        connection.request("POST", path, blob, headers)
        response = connection.getresponse()
        raw = response.read().decode("utf-8")
        try:
            return response.status, json.loads(raw)
        except ValueError:
            return response.status, {"raw": raw}
    finally:
        connection.close()


def engine_graph(workspace: Path) -> dict:
    with Store(workspace) as store:
        return graph_mod.Graph.from_store(store).to_dict()


# ---------------------------------------------------------------------------
# The workspace itself
# ---------------------------------------------------------------------------


def test_a_workspace_is_reported_as_ready_with_its_counts(running, workspace):
    status, payload = post(running, "/api/workspace")
    assert status == 200
    assert payload["workspace"]["state"] == "ready"
    assert payload["workspace"]["schema_version"] == SCHEMA_VERSION
    assert payload["counts"]["edges"] == len(engine_graph(workspace)["edges"])


def test_the_response_carries_a_label_and_never_a_path(running, workspace):
    """Where this machine keeps things is not the browser's business.

    The operator chose the path at the command line, so a file name is enough
    to tell them which workspace they are looking at, and the directories
    above it are a disclosure with nothing to buy it.
    """
    status, payload = post(running, "/api/workspace")
    assert payload["workspace"]["label"] == "state.db"
    blob = json.dumps(payload)
    assert str(workspace) not in blob
    assert str(workspace.parent) not in blob


def test_with_no_workspace_the_route_answers_rather_than_failing(stateless):
    """"There is no workspace" is an ordinary state for this interface, not an
    error: every other panel works without one."""
    status, payload = post(stateless, "/api/workspace")
    assert status == 200
    assert payload["workspace"]["state"] == "absent"
    assert payload["workspace"]["configured"] is False
    assert "counts" not in payload


def test_opening_the_interface_does_not_create_a_workspace(stateless, tmp_path):
    post(stateless, "/api/workspace")
    post(stateless, "/api/graph")
    assert not (tmp_path / ".actaira").exists(), (
        "reading the interface created a workspace on the operator's disk"
    )


def test_the_graph_routes_refuse_when_there_is_no_workspace(stateless):
    for route in ("/api/graph", "/api/graph/node", "/api/impact"):
        status, payload = post(stateless, route, {"id": "agent:x", "subject": "agent:x"})
        assert status == 409, route
        assert payload["error"]["code"] == "workspace_absent", route
        assert "actaira init" in payload["error"]["message"]


# ---------------------------------------------------------------------------
# A database that cannot be read, and one that must not be rewritten
# ---------------------------------------------------------------------------


def test_a_file_that_is_not_a_database_is_a_message_and_not_a_traceback(tmp_path):
    junk = tmp_path / "state.db"
    junk.write_bytes(b"this is not a database" * 40)
    httpd = serve(junk)
    try:
        status, payload = post(httpd.server_address, "/api/graph")
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert status == 409
    assert payload["error"]["code"] == "workspace_unreadable"
    assert "Traceback" not in json.dumps(payload)


def test_a_database_from_the_future_is_refused_rather_than_guessed_at(tmp_path):
    path = build(tmp_path / "state.db")
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'",
                           (str(SCHEMA_VERSION + 5),))
    httpd = serve(path)
    try:
        status, payload = post(httpd.server_address, "/api/graph")
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert status == 409
    assert payload["error"]["code"] == "workspace_newer_schema"


def test_a_database_from_an_earlier_release_is_reported_and_not_migrated(tmp_path):
    """The property that makes this interface safe to leave open.

    Every other command migrates a store forward on the way in. A page does
    not: it says the database is older and names the thing that would migrate
    it, and the file on disk is byte-identical afterwards.
    """
    path = build(tmp_path / "state.db")
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE meta SET value = '1' WHERE key = 'schema_version'")
    before = path.read_bytes()

    httpd = serve(path)
    try:
        status, payload = post(httpd.server_address, "/api/graph")
        again, _ = post(httpd.server_address, "/api/workspace")
    finally:
        httpd.shutdown()
        httpd.server_close()

    assert status == 409
    assert payload["error"]["code"] == "workspace_older_schema"
    assert again == 200
    assert path.read_bytes() == before, "a read migrated the operator's database"


def test_an_empty_workspace_draws_nothing_and_says_nothing_is_wrong(tmp_path):
    path = tmp_path / "state.db"
    with Store(path):
        pass
    httpd = serve(path)
    try:
        status, payload = post(httpd.server_address, "/api/graph")
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert status == 200
    assert payload["graph"]["nodes"] == []
    assert payload["graph"]["edges"] == []


# ---------------------------------------------------------------------------
# The graph, against the engine
# ---------------------------------------------------------------------------


def test_the_route_returns_exactly_what_the_engine_builds(running, workspace):
    status, payload = post(running, "/api/graph")
    assert status == 200
    assert payload["graph"] == engine_graph(workspace)


def test_the_published_shape_is_asset_graph_v1(running):
    jsonschema = pytest.importorskip("jsonschema")
    from actaira import schemas

    _, payload = post(running, "/api/graph")
    assert payload["graph"]["schema_version"] == "asset-graph/v1"
    jsonschema.Draft202012Validator(schemas.load("asset-graph-v1")).validate(payload["graph"])


def test_everything_the_panel_needs_beyond_the_contract_rides_in_view(running):
    """A presentation need is not a reason to version a published schema."""
    _, payload = post(running, "/api/graph")
    assert set(payload["view"]) >= {"mode", "totals", "currentness", "kinds", "names"}
    for node in payload["graph"]["nodes"]:
        assert set(node) <= {"id", "kind", "digest"}, node


def test_every_edge_that_leaves_this_server_says_who_stated_it(running):
    _, payload = post(running, "/api/graph")
    assert payload["graph"]["edges"]
    for edge in payload["graph"]["edges"]:
        assert edge["stated_by"], edge


def test_currentness_agrees_with_the_engines_projection(running, workspace):
    _, payload = post(running, "/api/graph")
    with Store(workspace) as store:
        graph = graph_mod.Graph.from_store(store)
        expected = graph_mod.project(graph, graph_mod.latest_observations(store)).to_dict()
    assert payload["view"]["currentness"] == expected


def test_the_three_currentness_values_all_occur_in_a_real_workspace(running):
    """Not a unit of the projection: proof that a workspace built the way an
    operator builds one exercises all three answers, so the panel's third
    value is a thing readers will actually meet."""
    _, payload = post(running, "/api/graph")
    counts = payload["view"]["currentness"]["counts"]["edges"]
    assert counts["current"] > 0
    assert counts["not_in_latest_observation"] > 0
    assert counts["undetermined"] > 0


def test_a_workspace_too_large_to_draw_is_refused_rather_than_sampled(tmp_path):
    """A subset presented as the graph is the worst of the available options.

    It draws a picture that looks complete and the reader has no way to know
    which of their assets were left out, or why. So the panel says no, says
    how big the workspace is, and names the thing that would work instead.
    """
    path = tmp_path / "state.db"
    with Store(path) as store:
        with store.transaction() as connection:
            for index in range(web.MAX_GRAPH_NODES + 40):
                store.upsert_asset(f"artifact:{index:05d}", "artifact", f"a{index}",
                                   connection=connection)
    httpd = serve(path)
    try:
        status, payload = post(httpd.server_address, "/api/graph")
        focused, _ = post(httpd.server_address, "/api/graph",
                          {"focus": "artifact:00001", "depth": 1})
    finally:
        httpd.shutdown()
        httpd.server_close()

    assert status == 409
    assert payload["error"]["code"] == "graph_too_large"
    assert str(web.MAX_GRAPH_NODES) in payload["error"]["message"]
    assert "Focus on one asset" in payload["error"]["message"]
    assert focused == 200, "the way out the refusal names has to actually work"


def test_a_workspace_with_assets_and_no_relations_is_not_an_empty_one(tmp_path):
    """Two different answers that a node count alone would merge.

    An impact answer over this graph is empty because nothing was stated, not
    because nothing depends on anything, and the panel has a separate state
    saying exactly that.
    """
    path = tmp_path / "state.db"
    with Store(path) as store:
        store.upsert_asset("artifact:alone", "artifact", "alone.pt")
    httpd = serve(path)
    try:
        _, payload = post(httpd.server_address, "/api/graph")
        _, answer = post(httpd.server_address, "/api/impact", {"subject": "artifact:alone"})
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert len(payload["graph"]["nodes"]) == 1
    assert payload["graph"]["edges"] == []
    assert answer["impact"]["found"] is True, "the asset is known; it simply has no relations"
    assert answer["impact"]["affected"] == []


# ---------------------------------------------------------------------------
# Focus
# ---------------------------------------------------------------------------


def test_a_focused_graph_is_the_engines_neighbourhood(running, workspace):
    status, payload = post(running, "/api/graph",
                           {"focus": "mcp:jira", "depth": 2, "direction": "dependents"})
    assert status == 200
    with Store(workspace) as store:
        graph = graph_mod.Graph.from_store(store)
        view = graph_mod.neighbourhood(graph, "mcp:jira", depth=2, direction="dependents")
        expected = graph_mod.subgraph(graph, view).to_dict()
    assert payload["graph"] == expected
    assert payload["view"]["neighbourhood"] == view.to_dict()


@pytest.mark.parametrize(
    ("depth", "expected"),
    [(1, ["mcp:jira", "agent:ticket-triage"]),
     (2, ["mcp:jira", "agent:ticket-triage", "system:ticket-triage-service"])],
)
def test_the_hop_limit_is_the_hop_limit(running, depth, expected):
    _, payload = post(running, "/api/graph",
                      {"focus": "mcp:jira", "depth": depth, "direction": "dependents"})
    assert [row["id"] for row in payload["view"]["neighbourhood"]["nodes"]] == expected


def test_a_view_that_stopped_early_says_so_through_the_api(running):
    _, payload = post(running, "/api/graph",
                      {"focus": "mcp:jira", "depth": 1, "direction": "dependents"})
    assert payload["view"]["neighbourhood"]["truncated"] is True


def test_two_identical_requests_return_identical_bytes(running):
    """Determinism survives the wire, which is what lets a screenshot of this
    panel be regenerated and compared."""
    first = post(running, "/api/graph", {"focus": "agent:ticket-triage", "depth": 2})[1]
    second = post(running, "/api/graph", {"focus": "agent:ticket-triage", "depth": 2})[1]
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


# ---------------------------------------------------------------------------
# A node
# ---------------------------------------------------------------------------


def test_a_node_carries_what_the_store_holds_and_its_relations(running):
    status, payload = post(running, "/api/graph/node", {"id": "agent:ticket-triage"})
    assert status == 200
    assert payload["found"] is True
    assert payload["node"]["kind"] == "agent"
    assert payload["node"]["digest"].startswith("sha256:")
    assert len(payload["outgoing"]) >= 11
    assert all(edge["stated_by"] for edge in payload["outgoing"] + payload["incoming"])


def test_a_node_can_be_asked_for_by_digest(running, workspace):
    with Store(workspace) as store:
        digest = store.asset("agent:ticket-triage")["digest"]
    _, payload = post(running, "/api/graph/node", {"id": digest})
    assert payload["found"] is True
    assert payload["node"]["id"] == "agent:ticket-triage"


def test_an_unknown_asset_is_unknown_rather_than_independent(running):
    """The distinction `impact` makes, kept here. An asset nobody recorded has
    no recorded dependents, which is not a proof that it has none."""
    _, payload = post(running, "/api/graph/node", {"id": "artifact:nobody-ever-saw-this"})
    assert payload["found"] is False
    assert payload["incoming"] == []
    assert payload["outgoing"] == []


def test_a_node_reports_the_evidence_already_recorded_about_it(running, workspace):
    with Store(workspace) as store:
        subject = next(row["asset_id"] for row in store.assets()
                       if row["kind"] == "source" and row["last_snapshot"])
    _, payload = post(running, "/api/graph/node", {"id": subject})
    assert payload["evidence"]["total"] >= 1
    assert set(payload["evidence"]["counts"]) == {
        "valid", "stale", "superseded", "revoked", "untrusted"}


def test_each_relation_of_a_node_carries_its_own_currentness(running):
    _, payload = post(running, "/api/graph/node", {"id": "agent:ticket-triage"})
    values = {edge["currentness"] for edge in payload["outgoing"]}
    assert values <= set(graph_mod.CURRENTNESS)
    assert values == {graph_mod.UNDETERMINED}, (
        "every relation of this agent is declared, so every one of them must be undetermined"
    )


# ---------------------------------------------------------------------------
# Impact
# ---------------------------------------------------------------------------


def test_impact_is_exactly_what_the_engine_returns(running, workspace):
    status, payload = post(running, "/api/impact", {"subject": "tool:fetch_url"})
    assert status == 200
    with Store(workspace) as store:
        expected = graph_mod.impact(graph_mod.Graph.from_store(store), "tool:fetch_url")
    answer = dict(payload["impact"])
    answer.pop("cycles_may_be_incomplete")
    assert answer == expected


def test_every_hop_of_an_impact_route_keeps_relation_and_provenance(running):
    _, payload = post(running, "/api/impact", {"subject": "tool:fetch_url"})
    rows = payload["impact"]["affected"]
    assert rows
    for row in rows:
        assert row["route"]
        for hop in row["route"]:
            assert hop["relation"] and hop["stated_by"]


def test_an_unknown_subject_is_not_reported_as_nothing_affected(running):
    _, payload = post(running, "/api/impact", {"subject": "artifact:never-recorded"})
    assert payload["impact"]["found"] is False
    assert payload["impact"]["affected"] == []


def test_the_depth_bound_reaches_impact_and_its_truncation_survives(running):
    _, payload = post(running, "/api/impact", {"subject": "tool:fetch_url", "depth": 1})
    assert payload["impact"]["truncated"] is True
    assert [row["asset"] for row in payload["impact"]["affected"]] == ["agent:ticket-triage"]


def test_the_cycle_flag_survives_the_route(running):
    _, payload = post(running, "/api/impact", {"subject": "tool:fetch_url"})
    assert payload["impact"]["cycles_may_be_incomplete"] is False
    assert payload["impact"]["cycles"] == []


def test_no_document_this_route_returns_carries_a_score(running):
    for route, body in (("/api/graph", {}), ("/api/impact", {"subject": "tool:fetch_url"}),
                        ("/api/graph/node", {"id": "agent:ticket-triage"})):
        _, payload = post(running, route, body)
        blob = json.dumps(payload).lower()
        for word in ("score", "grade", "rating", "percent"):
            assert word not in blob, f"{route} carries {word}"


# ---------------------------------------------------------------------------
# What a request may not do
# ---------------------------------------------------------------------------


def test_the_browser_cannot_choose_which_database_to_open(running, tmp_path):
    """The refusal that matters most.

    Three spellings of "open this file instead", all ignored: the path is on
    the server, set when the operator started it, and no field of any body
    reaches it.
    """
    elsewhere = build(tmp_path / "other.db")
    for body in ({"state": str(elsewhere)}, {"path": str(elsewhere)},
                 {"focus": "agent:ticket-triage", "state_path": str(elsewhere)}):
        status, payload = post(running, "/api/graph", body)
        assert status == 200
        assert payload["workspace"]["label"] == "state.db"
        assert str(elsewhere) not in json.dumps(payload)


def test_a_traversal_path_in_an_id_is_data_and_not_a_path(running):
    _, payload = post(running, "/api/graph/node", {"id": "../../../etc/passwd"})
    assert payload["found"] is False
    assert payload["node"]["id"] == "../../../etc/passwd"


@pytest.mark.parametrize("route", ["/api/workspace", "/api/graph", "/api/graph/node", "/api/impact"])
def test_a_rebound_host_is_refused(running, route):
    """DNS rebinding: the page is served from `evil.example`, its A record is
    flipped to 127.0.0.1, and the browser sends same-origin requests here."""
    status, payload = post(running, route, {"id": "a", "subject": "a"}, Host="evil.example")
    assert status == 403
    assert payload["error"]["code"] == "bad_host"


@pytest.mark.parametrize("route", ["/api/workspace", "/api/graph", "/api/graph/node", "/api/impact"])
def test_a_cross_origin_request_is_refused(running, route):
    status, payload = post(running, route, {"id": "a", "subject": "a"},
                           Origin="https://evil.example")
    assert status == 403
    assert payload["error"]["code"] == "cross_origin"


@pytest.mark.parametrize("route", ["/api/workspace", "/api/graph", "/api/graph/node", "/api/impact"])
def test_none_of_these_is_reachable_by_get(running, route):
    """A GET is reachable as a subresource from a page on the internet, which
    the Origin check on POST does not cover. These carry internal names,
    digests, identities and topology, so none of them is a GET."""
    connection = http.client.HTTPConnection(*running, timeout=30)
    try:
        connection.request("GET", route)
        response = connection.getresponse()
        response.read()
    finally:
        connection.close()
    assert response.status == 404


def test_an_absurdly_long_id_is_refused_by_size(running):
    status, payload = post(running, "/api/impact", {"subject": "a" * 5000})
    assert status == 413
    assert payload["error"]["code"] == "id_too_long"


@pytest.mark.parametrize("body", [{"id": ""}, {"id": "   "}, {"id": 7}, {}])
def test_an_id_that_is_not_one_is_refused(running, body):
    status, payload = post(running, "/api/graph/node", body)
    assert status == 400
    assert payload["error"]["code"] == "missing_id"


@pytest.mark.parametrize("depth", [-1, 99, "two", True, 1.5])
def test_a_depth_outside_the_engines_range_is_refused(running, depth):
    status, _ = post(running, "/api/graph", {"focus": "agent:ticket-triage", "depth": depth})
    assert status == 400


def test_a_direction_nobody_defined_is_refused(running):
    status, payload = post(running, "/api/graph",
                           {"focus": "agent:ticket-triage", "direction": "sideways"})
    assert status == 400
    assert payload["error"]["code"] == "bad_direction"


def test_a_body_that_is_not_json_is_refused(running):
    connection = http.client.HTTPConnection(*running, timeout=30)
    try:
        connection.request("POST", "/api/graph", b"<<<not json>>>", {
            "Content-Type": "application/json", "Content-Length": "14",
            "Host": f"{running[0]}:{running[1]}"})
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()
    assert response.status == 400
    assert payload["error"]["code"] == "bad_json"


# ---------------------------------------------------------------------------
# Hostile content inside the workspace
# ---------------------------------------------------------------------------


HOSTILE = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg onload=alert(1)>",
    "javascript:alert(1)",
]


@pytest.fixture(scope="module")
def poisoned(tmp_path_factory):
    """A workspace whose asset names, stated_by and evidence ids are payloads.

    Every one of these reaches the browser and is written with `textContent`
    there, so what this file can check is the half it owns: that the server
    returns them as data, unaltered, and that nothing in the pipeline tries to
    be clever about them.
    """
    path = build(tmp_path_factory.mktemp("poison") / "state.db")
    with Store(path) as store:
        for index, payload in enumerate(HOSTILE):
            store.upsert_asset(f"artifact:{payload}", "artifact", payload,
                               digest=f"sha256:{index:064d}")
            store.add_edge(f"artifact:{payload}", "uses", "agent:ticket-triage",
                           stated_by=payload, evidence_id=f"ev_{payload}")
    return path


@pytest.fixture(scope="module")
def hostile_server(poisoned):
    httpd = serve(poisoned)
    try:
        yield httpd.server_address
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize("payload", HOSTILE)
def test_markup_in_an_asset_id_round_trips_as_data(hostile_server, payload):
    status, body = post(hostile_server, "/api/graph/node", {"id": f"artifact:{payload}"})
    assert status == 200
    assert body["found"] is True
    assert body["node"]["id"] == f"artifact:{payload}"
    assert body["node"]["name"] == payload


@pytest.mark.parametrize("payload", HOSTILE)
def test_markup_in_stated_by_and_in_an_evidence_id_survives_unaltered(hostile_server, payload):
    """An edge's provenance is attacker-influenced text and must stay text.

    Not escaped here on purpose: escaping in the API would mean the CLI and
    the browser hold different strings for one fact. The browser writes it
    with `textContent`, which is where markup stops being markup.
    """
    _, body = post(hostile_server, "/api/graph/node", {"id": f"artifact:{payload}"})
    edge = body["outgoing"][0]
    assert edge["stated_by"] == payload
    assert edge["evidence_id"] == f"ev_{payload}"


def test_a_hostile_workspace_does_not_break_the_graph_route(hostile_server):
    status, payload = post(hostile_server, "/api/graph")
    assert status == 200
    ids = {node["id"] for node in payload["graph"]["nodes"]}
    assert all(f"artifact:{item}" in ids for item in HOSTILE)


def test_no_response_is_ever_a_traceback(hostile_server, running, stateless):
    for address in (hostile_server, running, stateless):
        for route in ("/api/workspace", "/api/graph", "/api/graph/node", "/api/impact"):
            _, payload = post(address, route, {"id": "\x00\x01", "subject": "\x00\x01"})
            blob = json.dumps(payload)
            assert "Traceback" not in blob
            assert "site-packages" not in blob
