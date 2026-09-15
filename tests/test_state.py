"""Local state: migrations, snapshots, watch semantics, evidence and impact.

Design notes D-220 to D-225. The tests that matter here are the ones about
distinctions a naive implementation collapses - first observation against no
change, a revision moving against content moving, a failed listing against an
empty source - because every one of those collapses produces a confident wrong
answer rather than an error.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from actaira.state import evidence as evidence_mod
from actaira.state import graph as graph_mod
from actaira.state.snapshot import Snapshot, SnapshotArtifact, scrub, snapshot_of
from actaira.state.store import MIGRATIONS, SCHEMA_VERSION, Store, StoreError, default_path
from actaira.state.watch import ObservationState, observe, stale_sweep


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / ".actaira" / "state.db") as opened:
        yield opened


def listing(*rows) -> list[dict]:
    return [
        {"uri": uri, "size": size, "declared_sha256": digest}
        for uri, size, digest in rows
    ]


def snap(store_source: str, rows: list[dict], *, revision: str = "", complete: bool = True,
         reason: str = "", at: str | None = None) -> Snapshot:
    return snapshot_of(
        store_source, f"hf://acme/{store_source}", "huggingface", rows,
        revision=revision, listing_complete=complete, incomplete_because=reason, observed_at=at,
    )


# --------------------------------------------------------------------------
# The store and its migrations
# --------------------------------------------------------------------------


def test_a_fresh_store_is_at_the_current_schema_version(store):
    assert store.schema_version == SCHEMA_VERSION
    assert store.meta()["tool_version"]


def test_the_default_path_is_inside_a_dot_directory(tmp_path):
    assert default_path(tmp_path).parts[-2:] == (".actaira", "state.db")


def test_every_migration_in_the_list_is_reachable_one_step_at_a_time(tmp_path):
    """A migration that has never run is a migration that does not work.

    Each step is applied to a database built by all the ones before it, which
    is the only way to find out that step 3 assumed a column step 2 renamed.
    """
    for target in range(1, len(MIGRATIONS) + 1):
        path = tmp_path / f"v{target}.db"
        connection = sqlite3.connect(path)
        for step in range(target):
            MIGRATIONS[step](connection)
        connection.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)", (str(target),)
        )
        connection.commit()
        connection.close()

        with Store(path) as migrated:
            assert migrated.schema_version == SCHEMA_VERSION


def test_migrating_an_old_database_keeps_its_digests_and_relations(tmp_path):
    """The gate the roadmap names: `DB N migra a N+1 y conserva digests/relations`.

    A fixture at version 1 with real rows in it, migrated forward, checked
    field by field. A migration that dropped and recreated a table would pass
    a version check and fail this.
    """
    path = tmp_path / "old.db"
    connection = sqlite3.connect(path)
    MIGRATIONS[0](connection)
    now = datetime.now(UTC).isoformat()
    digest = "sha256:" + "a" * 64
    evidence_digest = "sha256:" + "b" * 64
    connection.executemany(
        "INSERT INTO meta (key, value) VALUES (?, ?)", [("schema_version", "1")]
    )
    connection.execute(
        "INSERT INTO sources (source_id, connector, uri, revision, config_digest, added_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("s1", "huggingface", "hf://acme/fraud", "abc1234", "", now),
    )
    connection.execute(
        "INSERT INTO assets (asset_id, kind, digest, name, source_id, first_seen, last_seen) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("bundle:fraud", "bundle", digest, "fraud", "s1", now, now),
    )
    connection.execute(
        "INSERT INTO edges (from_asset, relation, to_asset, stated_by, first_seen) "
        "VALUES (?, ?, ?, ?, ?)",
        ("agent:x", "uses", "bundle:fraud", "manifest", now),
    )
    connection.execute(
        "INSERT INTO evidence (evidence_id, subject_id, subject_digest, kind, collector, "
        "collector_version, observed_at, state, digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("ev_1", "bundle:fraud", digest, "bundle", "actaira-core", "2.1.0", now, "valid",
         evidence_digest),
    )
    connection.commit()
    connection.close()

    with Store(path) as migrated:
        assert migrated.schema_version == SCHEMA_VERSION
        asset = migrated.asset("bundle:fraud")
        assert asset["digest"] == digest
        assert asset["kind"] == "bundle"
        assert migrated.edges() == [
            {
                "from_asset": "agent:x",
                "relation": "uses",
                "to_asset": "bundle:fraud",
                "evidence_id": None,
                "stated_by": "manifest",
                "first_seen": now,
            }
        ]
        records = migrated.evidence_for("bundle:fraud")
        assert [row["evidence_id"] for row in records] == ["ev_1"]
        assert records[0]["digest"] == evidence_digest


def test_a_store_from_the_future_is_refused_rather_than_guessed_at(tmp_path):
    """Migrations run forward only, and a newer store's extra columns mean
    something this release would have to invent."""
    path = tmp_path / "future.db"
    with Store(path):
        pass
    connection = sqlite3.connect(path)
    connection.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'", (str(SCHEMA_VERSION + 5),))
    connection.commit()
    connection.close()

    with pytest.raises(StoreError) as problem:
        Store(path)

    assert "forward only" in str(problem.value)


def test_a_missing_store_with_create_off_names_the_command_that_makes_one(tmp_path):
    with pytest.raises(StoreError) as problem:
        Store(tmp_path / "nope.db", create=False)

    assert "actaira init" in str(problem.value)


# --------------------------------------------------------------------------
# Snapshots
# --------------------------------------------------------------------------


def test_the_same_listing_in_a_different_order_has_the_same_digest():
    """The gate the roadmap names. Without it, a connector that paginated
    differently on Tuesday would report that every artifact had changed."""
    rows = listing(("a", 1, "aa"), ("b", 2, "bb"), ("c", 3, "cc"))
    forward = snap("s", rows)
    backward = snap("s", list(reversed(rows)))

    assert forward.digest == backward.digest


def test_the_observation_time_is_in_the_document_and_out_of_the_digest():
    """Two observations of an unchanged source must produce one digest, or
    `watch` would report a change every time it ran."""
    rows = listing(("a", 1, "aa"))
    early = snap("s", rows, at="2026-01-01T00:00:00+00:00")
    late = snap("s", rows, at="2026-09-11T00:00:00+00:00")

    assert early.digest == late.digest
    assert early.to_dict()["observed_at"] != late.to_dict()["observed_at"]


def test_a_changed_declared_digest_moves_the_snapshot_digest():
    assert snap("s", listing(("a", 1, "aa"))).digest != snap("s", listing(("a", 1, "bb"))).digest


def test_an_incomplete_snapshot_always_says_why():
    document = snap("s", [], complete=False).to_dict()

    assert document["listing_complete"] is False
    assert document["incomplete_because"], (
        "'incomplete' with no reason reads as a bug in Actaira rather than a fact about the source"
    )


def test_a_complete_snapshot_carries_no_reason_field():
    assert "incomplete_because" not in snap("s", listing(("a", 1, "aa"))).to_dict()


@pytest.mark.parametrize(
    "field", ["token", "Authorization", "api_key", "session_cookie", "x-amz-signature"]
)
def test_anything_that_looks_like_a_credential_is_dropped(field):
    """This is the document an operator commits to a repository. A snapshot
    that might contain a bearer token is one nobody can share."""
    assert field not in scrub({field: "s3cret", "uri": "a", "size": 1})


def test_scrubbing_reaches_into_nested_objects():
    assert scrub({"outer": {"token": "x", "size": 2}}) == {"outer": {"size": 2}}


def test_a_declared_digest_survives_the_scrub():
    """It is the one field named like a secret that the whole comparison
    depends on, and it is read before scrubbing for exactly that reason."""
    built = snapshot_of("s", "hf://a/b", "hf", [{"uri": "u", "size": 1, "sha256": "ab" * 32}])

    assert built.artifacts[0].declared_sha256 == "ab" * 32


# --------------------------------------------------------------------------
# Watch: the four distinctions
# --------------------------------------------------------------------------


@pytest.fixture
def watched(store):
    store.add_source("s1", "huggingface", "hf://acme/s1")
    return store


def test_the_first_observation_is_a_baseline_and_not_no_change(watched):
    """Reporting 'nothing changed' the first time is how an operator concludes
    the watch is working when it has never compared anything."""
    result = observe(watched, snap("s1", listing(("a", 1, "aa"))))

    assert result.state is ObservationState.BASELINE
    assert result.added == ["a"]
    assert "nothing to compare" in result.note


def test_observing_the_same_listing_again_is_unchanged_and_writes_nothing_new(watched):
    rows = listing(("a", 1, "aa"))
    observe(watched, snap("s1", rows))
    before = len(watched.all_evidence())

    again = observe(watched, snap("s1", rows))

    assert again.state is ObservationState.UNCHANGED
    assert again.recorded is False
    assert len(watched.all_evidence()) == before, (
        "a watch in cron must not grow the store by a row an hour"
    )


def test_a_revision_that_moved_with_identical_content_is_source_drift(watched):
    rows = listing(("a", 1, "aa"))
    observe(watched, snap("s1", rows, revision="r1"))

    drifted = observe(watched, snap("s1", rows, revision="r2"))

    assert drifted.state is ObservationState.SOURCE_DRIFT
    assert drifted.changed == []
    assert "unchanged" in drifted.note


def test_content_that_moved_is_content_drift_and_names_what_moved(watched):
    observe(watched, snap("s1", listing(("a", 1, "aa"), ("b", 2, "bb"))))

    changed = observe(watched, snap("s1", listing(("a", 1, "aa"), ("b", 2, "ZZ"), ("c", 3, "cc"))))

    assert changed.state is ObservationState.CONTENT_DRIFT
    assert changed.changed == ["b"]
    assert changed.added == ["c"]
    assert changed.removed == []


def test_a_removal_is_reported_as_a_removal(watched):
    observe(watched, snap("s1", listing(("a", 1, "aa"), ("b", 2, "bb"))))

    result = observe(watched, snap("s1", listing(("a", 1, "aa"))))

    assert result.removed == ["b"]


def test_an_incomplete_listing_writes_no_baseline_at_all(watched):
    """The most destructive false report this tool could produce: a failed page
    read as every artifact having been deleted."""
    observe(watched, snap("s1", listing(("a", 1, "aa"), ("b", 2, "bb"))))
    before = watched.latest_snapshot("s1")["digest"]

    failed = observe(watched, snap("s1", [], complete=False, reason="page 2 returned 503"))

    assert failed.state is ObservationState.INCOMPLETE
    assert failed.removed == []
    assert watched.latest_snapshot("s1")["digest"] == before, "the stored baseline is untouched"


def test_an_incomplete_first_listing_leaves_the_source_unobserved(watched):
    failed = observe(watched, snap("s1", [], complete=False, reason="no credentials"))

    assert failed.state is ObservationState.INCOMPLETE
    assert watched.latest_snapshot("s1") is None


def test_a_failed_listing_does_not_invalidate_earlier_evidence(watched):
    """A network error is not a fact about the artifacts. Evidence goes stale
    on the policy's terms and not because a TLS handshake failed."""
    observe(watched, snap("s1", listing(("a", 1, "aa"))))
    valid_before = [row["evidence_id"] for row in watched.all_evidence("valid")]

    observe(watched, snap("s1", [], complete=False, reason="connection reset"))

    assert [row["evidence_id"] for row in watched.all_evidence("valid")] == valid_before


# --------------------------------------------------------------------------
# Idempotency and crash consistency
# --------------------------------------------------------------------------


def test_running_watch_twice_duplicates_neither_evidence_nor_edges(watched):
    rows = listing(("a", 1, "aa"), ("b", 2, "bb"))
    observe(watched, snap("s1", rows))
    first = watched.export()

    observe(watched, snap("s1", rows))
    second = watched.export()

    assert len(second["edges"]) == len(first["edges"])
    assert len(second["evidence"]) == len(first["evidence"])
    assert len(second["snapshots"]) == len(first["snapshots"])


def test_two_runs_over_the_same_fixture_export_identically(tmp_path):
    """The determinism gate. `watch` over fixtures has to produce the same
    state export twice, or nothing downstream can be compared."""
    rows = listing(("a", 1, "aa"), ("b", 2, "bb"))
    exports = []
    for name in ("one", "two"):
        with Store(tmp_path / name / "state.db") as store:
            store.add_source("s1", "huggingface", "hf://acme/s1")
            observe(store, snap("s1", rows, at="2026-09-11T00:00:00+00:00"))
            document = store.export()
            exports.append(
                json.dumps(
                    {
                        "snapshots": [row["digest"] for row in document["snapshots"]],
                        "assets": sorted(row["asset_id"] for row in document["assets"]),
                        "edges": [
                            (row["from_asset"], row["relation"], row["to_asset"])
                            for row in document["edges"]
                        ],
                        "evidence": sorted(row["evidence_id"] for row in document["evidence"]),
                    },
                    sort_keys=True,
                )
            )

    assert exports[0] == exports[1]


# --------------------------------------------------------------------------
# Evidence lifecycle
# --------------------------------------------------------------------------


def test_only_valid_evidence_counts():
    from actaira.state.evidence import EvidenceState

    assert EvidenceState.VALID.counts
    for state in (EvidenceState.STALE, EvidenceState.SUPERSEDED,
                  EvidenceState.REVOKED, EvidenceState.UNTRUSTED):
        assert not state.counts, "these are four different reasons, not degrees of confidence"


def test_two_identical_observations_have_one_digest():
    left = evidence_mod.for_subject("artifact:a", "artifact_scan", subject_digest="sha256:aa",
                                    payload={"verdict": "pass"})
    right = evidence_mod.for_subject("artifact:a", "artifact_scan", subject_digest="sha256:aa",
                                     payload={"verdict": "pass"})

    assert left.digest == right.digest
    assert left.evidence_id == right.evidence_id


def test_the_digest_is_over_what_it_says_and_not_when_it_ran():
    record = evidence_mod.for_subject("artifact:a", "artifact_scan", payload={"v": 1})
    before = record.digest
    record.observed_at = "2020-01-01T00:00:00+00:00"

    assert record.digest == before


def test_an_unknown_evidence_kind_is_refused():
    with pytest.raises(ValueError, match="not an evidence kind"):
        evidence_mod.for_subject("x", "vibes")


def test_supersession_is_bound_to_the_digest_and_spares_the_siblings(watched):
    """The gate the roadmap names, and the difference between an invalidation
    somebody acts on and a wall of red."""
    observe(watched, snap("s1", listing(("a", 1, "aa"), ("b", 2, "bb"))))

    observe(watched, snap("s1", listing(("a", 1, "aa"), ("b", 2, "ZZ"))))

    states = {}
    for row in watched.all_evidence():
        payload = json.loads(row["document"]).get("payload", {})
        if payload.get("uri"):
            states.setdefault(payload["uri"], []).append(row["state"])
    assert states["a"] == ["valid"], "the artifact nobody touched stays valid"
    assert sorted(states["b"]) == ["superseded", "valid"]


def test_re_observing_an_unchanged_subject_supersedes_nothing(watched):
    rows = listing(("a", 1, "aa"))
    observe(watched, snap("s1", rows))
    observe(watched, snap("s1", rows, revision="r2"))

    assert all(row["state"] == "valid" for row in watched.all_evidence())


def test_a_records_own_valid_until_beats_a_global_limit(store):
    record = evidence_mod.for_subject("artifact:a", "artifact_scan", valid_for_days=365)
    record.observed_at = (datetime.now(UTC) - timedelta(days=200)).isoformat()
    store.record_evidence(record)

    expired = evidence_mod.expire(store, max_age_days=30)

    assert expired == [], (
        "a collector that said how long its observation is good for knows something the limit does not"
    )


def test_evidence_with_no_stated_lifetime_falls_back_to_the_limit(store):
    record = evidence_mod.for_subject("artifact:a", "artifact_scan")
    record.observed_at = (datetime.now(UTC) - timedelta(days=200)).isoformat()
    store.record_evidence(record)

    assert evidence_mod.expire(store, max_age_days=30) == [record.evidence_id]
    assert store.all_evidence()[0]["state"] == "stale"


def test_the_stale_sweep_is_a_separate_call_from_observing(watched):
    """Freshness is a policy question and observation is a fact-gathering one.
    A watch that expired evidence would make 'how old may this be' depend on
    how often somebody ran the watch."""
    observe(watched, snap("s1", listing(("a", 1, "aa"))))

    assert stale_sweep(watched, max_age_days=0, on=datetime.now(UTC) + timedelta(days=5))


# --------------------------------------------------------------------------
# Graph and impact
# --------------------------------------------------------------------------


def built_graph() -> graph_mod.Graph:
    graph = graph_mod.Graph(
        assets={
            "system:fraud": {"asset_id": "system:fraud", "kind": "system", "digest": ""},
            "agent:review": {"asset_id": "agent:review", "kind": "agent", "digest": "sha256:ag"},
            "bundle:model": {"asset_id": "bundle:model", "kind": "bundle", "digest": "sha256:bd"},
            "bundle:other": {"asset_id": "bundle:other", "kind": "bundle", "digest": "sha256:ot"},
        }
    )
    graph.add(graph_mod.Edge("system:fraud", "uses", "agent:review", "manifest"))
    graph.add(graph_mod.Edge("agent:review", "uses", "bundle:model", "manifest"))
    return graph


def test_impact_reaches_dependents_by_edges_and_reports_the_route():
    result = graph_mod.impact(built_graph(), "bundle:model")

    assert [row["asset"] for row in result["affected"]] == ["agent:review", "system:fraud"]
    assert result["by_kind"] == {"agent": 1, "system": 1}
    assert result["affected"][1]["why"] == (
        "system:fraud -> USES -> agent:review -> USES -> bundle:model"
    )


def test_impact_does_not_reach_a_neighbour_with_no_edge():
    """'Affected' must mean an edge exists, not that two things share a
    manifest, a registry or an organisation."""
    result = graph_mod.impact(built_graph(), "bundle:other")

    assert result["affected"] == []
    assert result["found"] is True


def test_impact_accepts_a_digest_as_well_as_an_id():
    assert graph_mod.impact(built_graph(), "sha256:bd")["changed"] == "bundle:model"


def test_an_asset_this_store_has_never_seen_is_reported_as_unknown():
    result = graph_mod.impact(built_graph(), "bundle:never-heard-of")

    assert result["found"] is False
    assert result["affected"] == []


def test_the_shortest_route_is_the_one_reported():
    graph = built_graph()
    graph.add(graph_mod.Edge("system:fraud", "uses", "bundle:model", "manifest"))

    result = graph_mod.impact(graph, "bundle:model")
    system = next(row for row in result["affected"] if row["asset"] == "system:fraud")

    assert system["hops"] == 1


def test_a_cycle_is_cut_and_reported_rather_than_recursed_into():
    """Sub-agent A delegates to B and B back to A. A walk that recursed would
    die on a declaration people really write."""
    graph = graph_mod.Graph()
    graph.add(graph_mod.Edge("agent:a", "delegates_to", "agent:b", "declaration"))
    graph.add(graph_mod.Edge("agent:b", "delegates_to", "agent:a", "declaration"))

    result = graph_mod.impact(graph, "agent:a")

    assert result["cycles"], "the cycle is reported as a fact"
    assert [row["asset"] for row in result["affected"]] == ["agent:b"]


def test_an_undeclared_relation_kind_is_refused():
    with pytest.raises(ValueError, match="not a relation"):
        graph_mod.Graph().add(graph_mod.Edge("a", "vibes_with", "b"))


def test_every_edge_records_who_stated_it():
    document = built_graph().to_dict()

    assert all(edge["stated_by"] for edge in document["edges"])


def test_the_graph_loads_back_out_of_the_store(watched):
    observe(watched, snap("s1", listing(("a", 1, "aa"))))

    loaded = graph_mod.Graph.from_store(watched)

    assert any(edge.relation == "contains" for edge in loaded.edges)
    assert all(edge.stated_by.startswith("snapshot") for edge in loaded.edges)


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------


def test_an_evidence_record_validates_against_its_schema():
    jsonschema = pytest.importorskip("jsonschema")
    from actaira import schemas

    record = evidence_mod.for_subject("artifact:a", "artifact_scan", subject_digest="sha256:aa")

    jsonschema.Draft202012Validator(schemas.load("evidence-record-v1")).validate(record.to_dict())


def test_a_snapshot_artifact_keeps_only_the_fields_it_declares():
    artifact = SnapshotArtifact(uri="u", size_bytes=3)

    assert artifact.to_dict() == {"uri": "u", "size_bytes": 3, "identity_basis": "size_only"}


@pytest.mark.parametrize(
    "kwargs,basis",
    [
        ({}, "size_only"),
        ({"declared_sha256": "aa" * 32}, "declared_digest"),
        ({"measured_sha256": "bb" * 32}, "measured_digest"),
        ({"declared_sha256": "aa" * 32, "measured_sha256": "bb" * 32}, "measured_digest"),
    ],
)
def test_every_artifact_says_how_firmly_it_is_identified(kwargs, basis):
    """Emitted always, not only when it is weak. A field that appears only
    when something is wrong is one readers learn to stop looking for."""
    artifact = SnapshotArtifact(uri="u", size_bytes=3, **kwargs)

    assert artifact.identity_basis == basis
    assert artifact.to_dict()["identity_basis"] == basis


def test_the_store_path_is_created_on_demand(tmp_path):
    path = tmp_path / "deep" / "nested" / "state.db"
    with Store(path):
        pass

    assert Path(path).is_file()


# --------------------------------------------------------------------------
# The defects an adversarial read of this module found
# --------------------------------------------------------------------------


def test_a_revoked_record_is_not_resurrected_by_an_unrelated_observation(watched):
    """DEF-72. An evidence id is the digest of what the evidence says, so
    re-observing an unchanged artifact produces the same id - and the conflict
    clause used to overwrite whatever state a revocation had set. Observing a
    sibling was enough, and `EvidenceState.counts` gates every policy decision
    on VALID."""
    observe(watched, snap("s1", listing(("a", 1, "aa"), ("b", 2, "bb"))))
    target = next(
        row["evidence_id"]
        for row in watched.all_evidence()
        if json.loads(row["document"]).get("payload", {}).get("uri") == "a"
    )
    watched.set_evidence_state(target, "revoked")

    observe(watched, snap("s1", listing(("a", 1, "aa"), ("b", 2, "ZZ"))))

    assert next(row for row in watched.all_evidence() if row["evidence_id"] == target)["state"] == "revoked"


def test_re_observing_a_stale_record_makes_it_current_again(watched):
    """The other half of DEF-72 and of DEF-73. STALE means nobody has looked
    lately; somebody looking is exactly what clears it."""
    observe(watched, snap("s1", listing(("a", 1, "aa")), at="2026-01-01T00:00:00+00:00"))
    stale_sweep(watched, max_age_days=0, on=datetime(2026, 6, 1, tzinfo=UTC))
    assert all(row["state"] == "stale" for row in watched.all_evidence())

    observe(watched, snap("s1", listing(("a", 1, "aa")), at="2026-09-11T00:00:00+00:00"))

    refreshed = watched.all_evidence()
    assert all(row["state"] == "valid" for row in refreshed)
    assert all(row["observed_at"] == "2026-09-11T00:00:00+00:00" for row in refreshed)


def test_an_unchanged_source_keeps_its_evidence_current(watched):
    """DEF-73. A source watched every day with no changes went stale after
    thirty, and re-observing could never clear it: `_write` returned early, so
    the timestamp the freshness check reads was never refreshed."""
    observe(watched, snap("s1", listing(("a", 1, "aa")), at="2026-01-01T00:00:00+00:00"))

    observe(watched, snap("s1", listing(("a", 1, "aa")), at="2026-09-11T00:00:00+00:00"))

    assert {row["observed_at"] for row in watched.all_evidence()} == {"2026-09-11T00:00:00+00:00"}
    assert stale_sweep(watched, max_age_days=30, on=datetime(2026, 9, 12, tzinfo=UTC)) == []


def test_an_unchanged_source_still_records_that_it_was_looked_at(watched):
    """`source list` reads `last_seen`. A source watched hourly with no
    changes showing the date of its last CHANGE reads as a watch that stopped."""
    observe(watched, snap("s1", listing(("a", 1, "aa")), at="2026-01-01T00:00:00+00:00"))

    observe(watched, snap("s1", listing(("a", 1, "aa")), at="2026-09-11T00:00:00+00:00"))

    assert watched.source("s1")["last_seen"] == "2026-09-11T00:00:00+00:00"


def test_a_source_that_returns_to_an_earlier_state_is_recorded(watched):
    """DEF-70. Keying the snapshot row on the content digest meant A -> B -> A
    could not record the return: the insert collided with the first row, was
    skipped, and the baseline stayed at B. Every later run then reported the
    same artifact as changed, forever."""
    first = listing(("w.bin", 3, "aa"))
    second = listing(("w.bin", 3, "bb"))

    assert observe(watched, snap("s1", first, at="2026-09-01T00:00:00+00:00")).state is ObservationState.BASELINE
    assert observe(watched, snap("s1", second, at="2026-09-02T00:00:00+00:00")).state is ObservationState.CONTENT_DRIFT
    back = observe(watched, snap("s1", first, at="2026-09-03T00:00:00+00:00"))
    again = observe(watched, snap("s1", first, at="2026-09-04T00:00:00+00:00"))

    assert back.state is ObservationState.CONTENT_DRIFT
    assert back.recorded is True, "a state this store has seen before is still a change from the baseline"
    assert again.state is ObservationState.UNCHANGED
    assert watched.source("s1")["last_seen"] == "2026-09-04T00:00:00+00:00"


def test_a_failure_partway_through_leaves_nothing_at_all(watched, monkeypatch):
    """DEF-71, tightened. The old assertion was a disjunction whose right-hand
    side was true, so it passed while the snapshot it was written to check
    sat committed with nothing behind it."""
    import actaira.state.watch as watch_module

    real = watch_module.evidence_mod.for_subject
    calls = {"n": 0}

    def explode(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] > 1:
            raise sqlite3.OperationalError("disk went away")
        return real(*args, **kwargs)

    monkeypatch.setattr(watch_module.evidence_mod, "for_subject", explode)

    with pytest.raises(StoreError):
        observe(watched, snap("s1", listing(("a", 1, "aa"), ("b", 2, "bb"))))

    assert watched.latest_snapshot("s1") is None
    assert watched.all_evidence() == []
    assert watched.assets() == []
    assert watched.edges() == []


def test_a_local_source_is_compared_by_its_bytes(tmp_path):
    """DEF-74. The filesystem connector publishes no digests by design, so
    comparison fell back to size: a weight file replaced with different bytes
    of the same length came back UNCHANGED, exit 0, with nothing saying the
    comparison had been weak."""
    weights = tmp_path / "w.bin"
    weights.write_bytes(b"weights")
    # `as_uri()`, which is what the filesystem connector emits, rather than
    # a hand-assembled `file://` plus a native path. DEF-114: the
    # hand-assembled spelling is the one this test used, it is the one shape
    # that happened to survive the old slice on Windows, and the real one did
    # not - so the regression test for DEF-74 passed on every platform while
    # the behaviour it guards was broken on one of them.
    rows = [{"uri": weights.as_uri(), "size": 7, "path": "w.bin"}]

    with Store(tmp_path / "state.db") as store:
        store.add_source("m", "filesystem", str(tmp_path))
        observe(store, snapshot_of("m", str(tmp_path), "filesystem", rows, measure_local=True))
        weights.write_bytes(b"HACKED!")

        after = observe(store, snapshot_of("m", str(tmp_path), "filesystem", rows, measure_local=True))

    assert len(b"HACKED!") == len(b"weights"), "the fixture is only interesting if the sizes match"
    assert after.state is ObservationState.CONTENT_DRIFT
    assert after.changed == [weights.as_uri()]


def test_an_artifact_compared_by_size_alone_is_named(watched):
    """And when there is nothing to hash, the weakness is reported rather than
    left in a docstring."""
    result = observe(watched, snap("s1", [{"uri": "hf://a/b/w.bin", "size": 7}]))

    assert result.weakly_compared == ["hf://a/b/w.bin"]
    assert result.to_dict()["weakly_compared"] == ["hf://a/b/w.bin"]


def test_a_snapshot_never_carries_the_string_none(watched):
    """DEF-75. `str(clean.get("revision", ""))` returns the default only when
    the key is ABSENT, and every connector emits `revision`, set to None by
    two of them. The literal `"None"` went into the digest and into the
    document an operator commits."""
    document = snapshot_of(
        "s1", "hf://a/b", "hf", [{"uri": "u", "size": 1, "revision": None, "path": None}]
    ).to_dict()

    assert "None" not in json.dumps(document)
    assert "revision" not in document["artifacts"][0]


@pytest.mark.parametrize("size", ["12 MB", [1, 2], None, {"bytes": 3}, 1.5, True])
def test_a_size_that_is_not_a_number_does_not_take_the_command_down(size):
    """A connector reading an operator's index file can hand over any of
    these, and `int()` on most of them raises - outside `_list_source`'s
    guard, so the whole command died with a traceback."""
    built = snapshot_of("s", "hf://a/b", "hf", [{"uri": "u", "size": size}])

    assert built.artifacts[0].size_bytes >= 0


def test_a_file_that_is_not_a_database_is_a_message_and_not_a_traceback(tmp_path):
    """DEF-69."""
    rubbish = tmp_path / "state.db"
    rubbish.write_bytes(b"this is not a database")

    with pytest.raises(StoreError) as problem:
        Store(rubbish)

    assert "not a readable Actaira state database" in str(problem.value)


def test_a_failed_open_does_not_leak_its_connection(tmp_path):
    """An `__init__` that raises leaves no object for `__exit__` to clean up,
    so a caller that retries leaks a descriptor and a `-wal` file each time.

    Two oracles, because the two kinds of host notice this differently. Where
    there is a descriptor table with a soft limit, 200 failed opens against a
    limit this test first checks is high enough would exhaust it. Where a file
    cannot be deleted while a handle is open, the delete at the end is the
    stronger check of the two: it fails outright on a single leaked handle.
    """
    import gc

    rubbish = tmp_path / "bad.db"
    rubbish.write_bytes(b"not a database")
    try:
        import resource

        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        assert soft > 100, "this test needs room to attempt many opens"
    except ImportError:  # no descriptor-table oracle on this host; the unlink below is
        pass            # the one that answers instead, and it is the stricter of the two

    for _ in range(200):
        with pytest.raises(StoreError):
            Store(rubbish)
    gc.collect()

    with Store(tmp_path / "good.db") as store:
        assert store.schema_version == SCHEMA_VERSION

    # On a host that locks open files this raises `PermissionError` if even one
    # of the 200 attempts kept its connection. On POSIX it always succeeds and
    # the loop above is what did the work.
    rubbish.unlink()


# --------------------------------------------------------------------------
# Cycle enumeration (DEF-79)
# --------------------------------------------------------------------------


def digraph(*edges) -> graph_mod.Graph:
    graph = graph_mod.Graph()
    for source, target in edges:
        graph.add(graph_mod.Edge(source, "uses", target))
    return graph


def normalised(graph: graph_mod.Graph) -> set[tuple[str, ...]]:
    found = set()
    for cycle in graph.cycles():
        body = tuple(cycle[:-1])
        pivot = body.index(min(body))
        found.add(body[pivot:] + body[:pivot])
    return found


def test_the_counterexample_that_the_colouring_version_missed():
    """DEF-79. `a->b, a->c, b->a, c->b` has two cycles and the three-colour
    walk reported one: the LIFO order let the `c` branch mark `b` finished
    before the `b` branch had been walked at all."""
    assert normalised(digraph(("a", "b"), ("a", "c"), ("b", "a"), ("c", "b"))) == {
        ("a", "b"),
        ("a", "c", "b"),
    }


@pytest.mark.parametrize("seed", range(12))
def test_cycle_enumeration_agrees_with_brute_force(seed):
    """Differential, because the first two implementations were both wrong in
    ways that looked right on the examples they were written against."""
    import random

    generator = random.Random(seed)
    names = [chr(97 + index) for index in range(generator.randint(3, 6))]
    edges = [
        (left, right)
        for left in names
        for right in names
        if left != right and generator.random() < 0.4
    ]

    adjacency: dict[str, list[str]] = {}
    for left, right in edges:
        adjacency.setdefault(left, []).append(right)
    expected = set()
    for start in names:
        stack = [(start, [start])]
        while stack:
            node, trail = stack.pop()
            for target in adjacency.get(node, []):
                if target == start:
                    pivot = trail.index(min(trail))
                    expected.add(tuple(trail[pivot:] + trail[:pivot]))
                elif target not in trail and len(trail) < graph_mod.MAX_DEPTH:
                    stack.append((target, [*trail, target]))

    assert normalised(digraph(*edges)) == expected


def test_a_dense_graph_stops_at_the_cap_and_says_so():
    names = [f"n{index}" for index in range(10)]
    graph = digraph(*[(left, right) for left in names for right in names if left != right])

    cycles = graph.cycles()

    assert len(cycles) == graph_mod.MAX_CYCLES
    assert graph.cycles_may_be_incomplete is True
    assert graph.to_dict()["cycles_may_be_incomplete"] is True


def test_an_acyclic_graph_reports_none_and_claims_completeness():
    graph = digraph(("a", "b"), ("b", "c"))

    assert graph.cycles() == []
    assert graph.cycles_may_be_incomplete is False


# ---------------------------------------------------------------------------
# DEF-99: a published field nothing could ever populate
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# The receipt table
# ---------------------------------------------------------------------------

def test_a_recorded_receipt_comes_back_with_what_was_written(store):
    """The store notes that a receipt was issued; it never holds the receipt.

    A second copy of a signed document can disagree with the first, so what is
    filed is the digest, where it was written, who signed it and when.
    """
    store.record_receipt("sha256:" + "a" * 64, "receipts/one.json", "key:1635cd10", "2026-01-01T00:00:00+00:00")

    rows = store.receipts()

    assert len(rows) == 1
    assert rows[0]["receipt_digest"] == "sha256:" + "a" * 64
    assert rows[0]["path"] == "receipts/one.json"
    assert rows[0]["signer"] == "key:1635cd10"


def test_the_same_receipt_written_twice_is_one_row_with_the_newer_path(store):
    """Re-issuing the same bytes to a new location is a move, not a second
    receipt: the digest is the identity and a second row would double-count it."""
    digest = "sha256:" + "b" * 64
    store.record_receipt(digest, "receipts/one.json", "key:1635cd10", "2026-01-01T00:00:00+00:00")
    store.record_receipt(digest, "receipts/moved.json", "key:1635cd10", "2026-01-02T00:00:00+00:00")

    rows = store.receipts()

    assert len(rows) == 1
    assert rows[0]["path"] == "receipts/moved.json"


def test_receipts_come_back_in_the_order_they_were_observed(store):
    """`export()` is asserted byte-identical over the same observation, which
    it cannot be if any table comes back in whatever order SQLite chose."""
    for index, day in enumerate(("03", "01", "02"), start=1):
        store.record_receipt(f"sha256:{index}" + "c" * 63, f"receipts/{day}.json",
                             "key:1635cd10", f"2026-01-{day}T00:00:00+00:00")

    assert [row["path"] for row in store.receipts()] == [
        "receipts/01.json", "receipts/02.json", "receipts/03.json",
    ]
