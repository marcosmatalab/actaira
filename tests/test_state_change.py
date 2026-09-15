"""Evidence producers, exact change propagation, and whether a decision still holds.

The increment these cover is the loop the whole tool is for:

    observe -> state -> change -> invalidate -> impact -> decide -> prove

Each of those steps has a way of being wrong that looks right, and most of the
tests here are about that rather than about the happy path. Evidence filed
under a name instead of a digest invalidates the wrong thing. Impact asked
from the source instead of the artifact answers a coarser question with a
confident face. A decision rewritten when reality moves destroys the record of
what was approved. And a decision with no recorded inputs reported as
"current" turns the rows this store knows least about into the ones it
reassures you about.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from actaira.state import change as change_mod
from actaira.state import decide as decide_mod
from actaira.state import evidence as evidence_mod
from actaira.state import graph as graph_mod
from actaira.state import record as record_mod
from actaira.state.evidence import EvidenceState
from actaira.state.snapshot import snapshot_of
from actaira.state.store import MIGRATIONS, Store
from actaira.state.store import SCHEMA_VERSION as STORE_VERSION
from actaira.state.watch import observe
from conftest import REPO_ROOT

# ---------------------------------------------------------------------------
# Fixtures: a workspace shaped the way a person would actually build one
# ---------------------------------------------------------------------------


def _listing(root: Path) -> list[dict]:
    return [
        {"uri": path.as_uri(), "path": path.name, "size": path.stat().st_size}
        for path in sorted(root.glob("*.bin"))
    ]


def _observe(store: Store, root: Path, *, revision: str = "") -> object:
    return observe(
        store,
        snapshot_of("m", str(root), "filesystem", _listing(root),
                    revision=revision, measure_local=True),
    )


@pytest.fixture
def workspace(tmp_path):
    """A source with two local artifacts, observed once."""
    models = tmp_path / "models"
    models.mkdir()
    (models / "model.bin").write_bytes(b"weights-one")
    (models / "tokenizer.bin").write_bytes(b"vocabulary")
    store = Store(tmp_path / "state.db")
    store.add_source("m", "filesystem", str(models))
    _observe(store, models)
    yield store, models
    store.close()


def _asset_for(store: Store, name: str) -> str:
    return next(row["asset_id"] for row in store.assets() if row["name"].endswith(name))


def run_cli(argv: list[str]) -> int:
    """Run one command the way a person does, and give back its exit code.

    Through `main` rather than by calling the handler, because the defect this
    file's last test is about lived in the wiring between them.
    """
    import sys as sys_mod

    from actaira.cli import main

    saved = sys_mod.argv
    sys_mod.argv = ["actaira", *argv]
    try:
        return main()
    finally:
        sys_mod.argv = saved

# ---------------------------------------------------------------------------
# DEF-113 and DEF-114: the digest that was measured and then thrown away
# ---------------------------------------------------------------------------


def test_a_local_artifacts_measured_digest_reaches_the_asset_row(workspace):
    """DEF-113. `watch` read the bytes and stored no digest.

    The filesystem connector publishes no `declared_sha256` by design (D-85b)
    and `_write` consulted only that field, so on a local source - the
    commonest workspace there is - every artifact asset carried an empty
    digest. Everything downstream reads that column: supersession binds to it,
    the graph panel shows it, and `record.resolve` finds a scanned file by it.
    """
    store, models = workspace
    row = store.asset(_asset_for(store, "model.bin"))
    assert row is not None
    assert row["digest"].startswith("sha256:"), (
        "the bytes were read and the digest was not written down"
    )
    # And which kind of digest it is, kept beside it rather than folded in.
    assert json.loads(row["attributes"])["identity_basis"] == "measured"


def test_a_local_artifact_gets_its_own_evidence_record(workspace):
    """DEF-113, the other half. No per-artifact evidence was ever written.

    `_record_evidence` skipped any artifact without a declared digest, so a
    local source produced exactly one record - about the source - and nothing
    bound to any individual file. Supersession had nothing to supersede.
    """
    store, _ = workspace
    subjects = {row["subject_id"] for row in store.all_evidence()}
    assert _asset_for(store, "model.bin") in subjects
    assert _asset_for(store, "tokenizer.bin") in subjects


def test_a_file_uri_is_measured_on_the_platform_this_is_running_on(tmp_path):
    """DEF-114. `uri[len("file://"):]` is not a path parser.

    On POSIX it happens to be right. On Windows `file:///C:/x/w.bin` becomes
    `/C:/x/w.bin`, which is not a path that exists, so `_measure` returned ""
    and every local comparison silently fell back to a byte count - which is
    exactly the DEF-74 failure DEF-74 was fixed to prevent.

    The regression test for DEF-74 did not catch it because its fixture built
    `file://` + a native path by hand, and that spelling is the one the old
    slice happened to survive. This one uses `Path.as_uri()`, which is what
    the connector actually emits.
    """
    from actaira.state.snapshot import _measure

    weights = tmp_path / "w.bin"
    weights.write_bytes(b"weights")
    assert _measure(weights.as_uri(), "w.bin"), (
        "the connector's own URI spelling produced no measurement"
    )


def test_a_file_uri_with_a_space_in_it_is_still_measured(tmp_path):
    """Percent-escapes, which a hand-rolled slice also gets wrong.

    `Path.as_uri()` escapes a space as `%20`, and a parser that only strips a
    prefix hands `my%20models` to the filesystem as a literal directory name.
    """
    from actaira.state.snapshot import _measure

    folder = tmp_path / "my models"
    folder.mkdir()
    weights = folder / "w.bin"
    weights.write_bytes(b"weights")
    assert "%20" in weights.as_uri()
    assert _measure(weights.as_uri(), "w.bin")


# ---------------------------------------------------------------------------
# Evidence producers
# ---------------------------------------------------------------------------


def test_a_scan_of_an_unrecorded_artifact_records_nothing_and_says_so(workspace, tmp_path):
    """Identity is not invented. §3.

    A file this workspace has never observed has no stable identity here. The
    tempting thing is `artifact:<basename>`, and the first time two teams both
    have a `model.pt` that is evidence about whichever was scanned last.
    """
    from support.reports import write_report

    store, _ = workspace
    stranger = tmp_path / "elsewhere.bin"
    stranger.write_bytes(b"nobody observed this")
    result = record_mod.artifact_scan(store, write_report(stranger, payload=stranger.read_bytes()))
    assert not result.written
    assert result.identity.basis == record_mod.UNRECORDED
    assert not any(row["kind"] == "artifact_scan" for row in store.all_evidence())


def test_a_scan_of_a_recorded_artifact_binds_to_the_asset_watch_uses(workspace):
    """The identity rule, and why it is the one that makes the loop work.

    The scan record has to land on the same asset id `watch` files its
    observations under, or supersession - which is bound to the digest of a
    subject id - will never reach it.
    """
    from support.reports import write_report

    store, models = workspace
    result = record_mod.artifact_scan(store, write_report(models / "model.bin", payload=(models / "model.bin").read_bytes()))
    assert result.written
    assert result.identity.asset_id == _asset_for(store, "model.bin")
    assert result.identity.basis == record_mod.FROM_DIGEST


def test_the_same_bytes_scanned_twice_produce_one_record(workspace):
    """Evidence identity is over what the evidence says. D-223.

    A store that grew a row every time CI ran would be a log rather than a
    ledger, and `watch` would have something new to supersede on every run.
    """
    from support.reports import write_report

    store, models = workspace
    first = record_mod.artifact_scan(store, write_report(models / "model.bin", payload=(models / "model.bin").read_bytes()))
    second = record_mod.artifact_scan(store, write_report(models / "model.bin", payload=(models / "model.bin").read_bytes()))
    assert first.evidence_id == second.evidence_id
    scans = [row for row in store.all_evidence() if row["kind"] == "artifact_scan"]
    assert len(scans) == 1


def test_changed_bytes_do_not_reuse_the_old_records_identity(workspace):
    """The other half of the same rule.

    An evidence id that did not move with the content would make a scan of
    new bytes refresh the record about the old ones, and the ledger would
    show a valid scan of a file that no longer exists.
    """
    from support.reports import write_report

    store, models = workspace
    before = record_mod.artifact_scan(store, write_report(models / "model.bin", payload=(models / "model.bin").read_bytes()))
    (models / "model.bin").write_bytes(b"weights-two!")
    _observe(store, models)
    after = record_mod.artifact_scan(store, write_report(models / "model.bin", payload=(models / "model.bin").read_bytes()))
    assert before.evidence_id != after.evidence_id
    assert store.evidence(before.evidence_id)["state"] == EvidenceState.SUPERSEDED.value
    assert store.evidence(after.evidence_id)["state"] == EvidenceState.VALID.value


def test_an_agent_assessment_is_bound_to_the_agent_digest(tmp_path):
    """§4. "Was this evidence produced about the agent in front of me?"

    One string comparison, and it only works if the record is bound to
    `Agent.digest` rather than to the agent's name - a declaration that has
    since gained a shell tool keeps its name and not its digest.
    """
    from actaira.conformance import assess, load
    from actaira.conformance import paths as path_engine

    agent = load(Path(REPO_ROOT) / "examples" / "agent-ticket-triage.yaml")
    with Store(tmp_path / "state.db") as store:
        store.upsert_asset(f"agent:{agent.name}", "agent", agent.name, digest=agent.digest)
        result = record_mod.agent_assessment(
            store, agent, assess(agent), path_engine.find(agent)
        )
        assert result.written
        row = store.evidence(result.evidence_id)
        assert row["subject_digest"] == agent.digest
        payload = json.loads(row["document"])["payload"]
        assert payload["agent"] == agent.name
        # Both halves of the assessment in one record, not two that a reader
        # has to reconcile without being told they are halves.
        assert "findings" in payload
        assert payload["attack_paths"]["searched"] is True
        assert payload["attack_paths"]["open"] + payload["attack_paths"]["closed"] == \
            payload["attack_paths"]["total"]


def test_an_agent_assessment_does_not_inline_the_routes(tmp_path):
    """§4 again: counts, not a graph pasted into a cell.

    `actaira agent paths` is where the routes live. A ledger row that carried
    every node of every route would be a second copy of a document that can
    disagree with the first.
    """
    from actaira.conformance import assess, load
    from actaira.conformance import paths as path_engine

    agent = load(Path(REPO_ROOT) / "examples" / "agent-ticket-triage.yaml")
    with Store(tmp_path / "state.db") as store:
        store.upsert_asset(f"agent:{agent.name}", "agent", agent.name, digest=agent.digest)
        result = record_mod.agent_assessment(
            store, agent, assess(agent), path_engine.find(agent)
        )
        payload = json.loads(store.evidence(result.evidence_id)["document"])["payload"]
    assert "paths" not in payload
    assert "route" not in json.dumps(payload)


def test_every_evidence_kind_is_either_produced_or_recorded_as_not_yet(tmp_path):
    """§26: no dead enum entries advertised as if they were obtainable.

    The split is pinned rather than asserted away. Three kinds gained a
    producer in this release, one already had one, and three have none - and
    that last set is the point of the test: it is written down here, it is
    written down in the README's capability prose, and a kind that quietly
    joins or leaves it fails this.
    """
    produced = {"source_snapshot", "artifact_scan", "agent_assessment", "policy_decision"}
    not_yet = {"bundle", "governance", "attestation"}
    assert produced | not_yet == set(evidence_mod.KINDS)
    assert not produced & not_yet

    # Every kind claimed as produced has a function that can produce it, named
    # here so "produced" is not a claim about a string.
    assert callable(record_mod.artifact_scan)
    assert callable(record_mod.agent_assessment)
    assert callable(record_mod.policy_decision)


# ---------------------------------------------------------------------------
# Watch: what must and must not be invalidated
# ---------------------------------------------------------------------------


def test_one_changed_artifact_supersedes_only_its_own_evidence(workspace):
    """The rule the whole ledger rests on. D-223.

    Evidence about a sibling nobody touched stays VALID, which is the
    difference between an invalidation somebody acts on and a page of red
    nobody reads.
    """
    store, models = workspace
    sibling = _asset_for(store, "tokenizer.bin")
    (models / "model.bin").write_bytes(b"weights-two!")
    observation = _observe(store, models)

    assert observation.superseded_evidence
    for row in store.evidence_for(sibling):
        assert row["state"] == EvidenceState.VALID.value
    superseded = {row["subject_id"] for row in store.all_evidence()
                  if row["state"] == EvidenceState.SUPERSEDED.value}
    assert superseded == {_asset_for(store, "model.bin")}


def test_a_removed_artifact_supersedes_its_evidence_and_keeps_its_history(workspace):
    """§9. The asset stays in the recorded graph; the evidence stops counting.

    Removing the row would make the store forget what was there, which is the
    one thing a store exists not to do.
    """
    store, models = workspace
    gone = _asset_for(store, "tokenizer.bin")
    (models / "tokenizer.bin").unlink()
    observation = _observe(store, models)

    assert [item.uri for item in observation.subjects if item.how == "removed"]
    assert store.asset(gone) is not None, "the recorded graph forgot what was there"
    assert any(row["state"] == EvidenceState.SUPERSEDED.value
               for row in store.evidence_for(gone))


def test_an_added_artifact_supersedes_nothing(workspace):
    """§9. There was no earlier evidence about something that did not exist."""
    store, models = workspace
    (models / "extra.bin").write_bytes(b"new file")
    observation = _observe(store, models)
    assert [item.how for item in observation.subjects] == ["added"]
    assert observation.superseded_evidence == []


def test_source_drift_with_identical_content_supersedes_nothing(tmp_path):
    """§9. A re-tag is not a weight file changing.

    The alarm has to be reserved for the thing that deserves it, or people
    stop reading it.
    """
    rows = [{"uri": "hf://acme/m/w.safetensors", "size": 9, "sha256": "ab" * 32}]
    with Store(tmp_path / "state.db") as store:
        store.add_source("m", "huggingface", "hf://acme/m")
        observe(store, snapshot_of("m", "hf://acme/m", "huggingface", rows, revision="v1"))
        after = observe(store, snapshot_of("m", "hf://acme/m", "huggingface", rows, revision="v2"))
        assert after.state.value == "source_drift"
        assert after.superseded_evidence == []
        assert after.subjects == []
        assert all(row["state"] == EvidenceState.VALID.value for row in store.all_evidence())


def test_an_incomplete_listing_supersedes_nothing_and_reports_no_deletion(workspace):
    """§9, and the most destructive false report this tool could produce.

    Treating a failed page as a set of deletions means every artifact gone and
    every record superseded, on a source where nothing happened.
    """
    store, models = workspace
    before = {row["evidence_id"]: row["state"] for row in store.all_evidence()}
    observation = observe(
        store,
        snapshot_of("m", str(models), "filesystem", [], listing_complete=False,
                    incomplete_because="the connector could not list it"),
    )
    assert observation.state.value == "incomplete"
    assert observation.removed == []
    assert observation.superseded_evidence == []
    assert observation.subjects == []
    assert {row["evidence_id"]: row["state"] for row in store.all_evidence()} == before


def test_an_unchanged_observation_supersedes_nothing(workspace):
    """§9. Nothing moved, so nothing stopped counting."""
    store, models = workspace
    observation = _observe(store, models)
    assert observation.state.value == "unchanged"
    assert observation.superseded_evidence == []
    assert all(row["state"] == EvidenceState.VALID.value for row in store.all_evidence())


def test_a_weak_comparison_stays_visible_all_the_way_to_the_change(tmp_path):
    """§9. It must never quietly become strong evidence of sameness.

    DEF-74 is carried through the whole chain rather than stopping at the
    observation: a consequence drawn from a size-only comparison inherits that
    comparison's weakness, and the change object has to say so.
    """
    rows = [{"uri": "s3://b/w.bin", "size": 12}]
    with Store(tmp_path / "state.db") as store:
        store.add_source("m", "s3", "s3://b")
        observe(store, snapshot_of("m", "s3://b", "s3", rows))
        after = observe(store, snapshot_of("m", "s3://b", "s3", [{"uri": "s3://b/w.bin", "size": 13}]))
        change = change_mod.of_observation(store, after)
    assert after.weakly_compared or [item for item in after.subjects
                                     if item.basis == "size_only"]
    assert any(row["reason"] == "weak_comparison" for row in change.unknowns)


# ---------------------------------------------------------------------------
# Exact per-artifact impact
# ---------------------------------------------------------------------------


def _two_changed_into_one_system(store: Store, models: Path) -> tuple[str, str]:
    """A system that uses both artifacts, so one change can reach it twice."""
    model = _asset_for(store, "model.bin")
    tokenizer = _asset_for(store, "tokenizer.bin")
    store.upsert_asset("system:checkout", "system", "checkout")
    store.add_edge("system:checkout", "uses", model, stated_by="manifest subjects.yaml")
    store.add_edge("system:checkout", "uses", tokenizer, stated_by="manifest subjects.yaml")
    return model, tokenizer


def test_impact_starts_from_the_exact_changed_artifact(workspace):
    """§8. Not from the source, which answers a coarser question.

    A source holding forty files, one of which changed, used to report every
    dependent of all forty.
    """
    store, models = workspace
    model, tokenizer = _two_changed_into_one_system(store, models)
    (models / "model.bin").write_bytes(b"weights-two!")
    change = change_mod.of_observation(store, _observe(store, models))

    assert change.impact["changed"] == [model]
    assert tokenizer not in change.impact["changed"]
    # `source:m` is there because `source:m CONTAINS artifact:model` is a
    # recorded edge and the walk goes backwards along recorded edges. That is
    # the coarse answer arriving as one row of a precise one rather than as
    # the whole of it: before this increment the walk STARTED at `source:m`
    # and every artifact it contains came back as affected.
    assert [row["asset"] for row in change.impact["targets"]] == ["source:m", "system:checkout"]
    assert tokenizer not in [row["asset"] for row in change.impact["targets"]]


def test_two_changed_artifacts_keep_two_causes(workspace):
    """§8. "NEVER discard causality."

    A system downstream of two changes has two reasons to be re-examined, and
    a deduplicated list of targets would have told the reader it had one.
    """
    store, models = workspace
    model, tokenizer = _two_changed_into_one_system(store, models)
    (models / "model.bin").write_bytes(b"weights-two!")
    (models / "tokenizer.bin").write_bytes(b"vocabulary-two")
    change = change_mod.of_observation(store, _observe(store, models))

    targets = {row["asset"]: row for row in change.impact["targets"]}
    assert set(change.impact["changed"]) == {model, tokenizer}
    # The system appears once, deduplicated, with both causes kept under it.
    # That is the whole property: a reader asked to reassess `system:checkout`
    # has to be able to see it is downstream of two changes and not one.
    assert "system:checkout" in targets
    assert {cause["changed"] for cause in targets["system:checkout"]["causes"]} == {model, tokenizer}
    # And the routes are two different routes, not one repeated.
    routes = [cause["route"][0]["to"] for cause in targets["system:checkout"]["causes"]]
    assert sorted(routes) == sorted([model, tokenizer])


def test_every_cause_carries_its_whole_route(workspace):
    """§8. Relation, what stated it, hop count - not just the endpoints.

    An answer a reader cannot check against their own understanding is an
    answer they have to take on trust, which is the one thing this tool does
    not ask for.
    """
    store, models = workspace
    _two_changed_into_one_system(store, models)
    (models / "model.bin").write_bytes(b"weights-two!")
    change = change_mod.of_observation(store, _observe(store, models))

    target = next(row for row in change.impact["targets"] if row["asset"] == "system:checkout")
    cause = target["causes"][0]
    assert cause["hops"] == 1
    edge = cause["route"][0]
    assert edge["relation"] == "uses"
    assert edge["stated_by"] == "manifest subjects.yaml"
    assert "->" in cause["why"]

    # And the observed edge keeps its own provenance rather than borrowing
    # the declaration's: `source:m CONTAINS artifact` was stated by a
    # snapshot, and the graph has to be able to show which claims came from
    # a document somebody wrote and which from something this tool observed.
    contained = next(row for row in change.impact["targets"] if row["asset"] == "source:m")
    assert contained["causes"][0]["route"][0]["relation"] == "contains"
    assert contained["causes"][0]["route"][0]["stated_by"].startswith("snapshot ")


def test_per_cause_impact_agrees_with_impact_asked_one_at_a_time(workspace):
    """The batched walk is the single walk, run once per cause.

    A second implementation that drifted would give the browser and the
    terminal two different answers, which is the thing `impact_of_changes`
    exists to prevent rather than to introduce.
    """
    store, models = workspace
    model, tokenizer = _two_changed_into_one_system(store, models)
    graph = graph_mod.Graph.from_store(store)
    batched = graph_mod.impact_of_changes(graph, [model, tokenizer])
    for row in batched["by_changed"]:
        one = graph_mod.impact(graph, row["changed"])
        assert row["affected"] == one["affected"]
        assert row["by_kind"] == one["by_kind"]


def test_a_change_nobody_declared_a_dependency_on_manufactures_no_impact(tmp_path):
    """§9: a change must not invent consequences it cannot show.

    An artifact in a source nobody has declared anything about reaches exactly
    one thing - the source that contains it, which is a recorded edge a
    snapshot stated - and nothing else. The failure this guards against is an
    impact walk that reaches sideways through the source into every sibling,
    which is what asking the question from `source:<id>` used to do.
    """
    models = tmp_path / "models"
    models.mkdir()
    (models / "lonely.bin").write_bytes(b"nobody declared anything about this")
    (models / "sibling.bin").write_bytes(b"and nobody touched me")
    with Store(tmp_path / "state.db") as store:
        store.add_source("m", "filesystem", str(models))
        _observe(store, models)
        sibling = _asset_for(store, "sibling.bin")
        (models / "lonely.bin").write_bytes(b"and now it has changed entirely")
        change = change_mod.of_observation(store, _observe(store, models))

    assert [row["asset"] for row in change.impact["targets"]] == ["source:m"]
    assert sibling not in [row["asset"] for row in change.impact["targets"]]


def test_the_change_object_counts_every_key_even_at_zero(workspace):
    """A summary whose missing keys mean zero cannot be read."""
    store, models = workspace
    change = change_mod.of_observation(store, _observe(store, models))
    assert set(change.counts()) == {
        "subjects", "superseded", "stale", "affected",
        "decisions_requiring_reassessment", "unknowns",
    }


def test_the_change_object_serialises_the_same_way_twice(workspace):
    """Determinism, because this is what both surfaces render."""
    store, models = workspace
    _two_changed_into_one_system(store, models)
    (models / "model.bin").write_bytes(b"weights-two!")
    observation = _observe(store, models)
    first = json.dumps(change_mod.of_observation(store, observation).to_dict(), sort_keys=True)
    second = json.dumps(change_mod.of_observation(store, observation).to_dict(), sort_keys=True)
    assert first == second


def test_the_two_identity_comparisons_agree(tmp_path):
    """`change._identity` restates `watch._identity` and must not drift.

    Asserted rather than trusted to a comment, because the two live in two
    modules that cannot import each other.
    """
    from actaira.state.change import _identity as reconstructed
    from actaira.state.watch import _identity as original

    for row in (
        {"measured_sha256": "aa", "declared_sha256": "bb", "size_bytes": 1},
        {"declared_sha256": "bb", "size_bytes": 1},
        {"size_bytes": 1},
        {},
    ):
        assert reconstructed(row) == original(row)


# ---------------------------------------------------------------------------
# The timeline
# ---------------------------------------------------------------------------


def test_the_timeline_shows_the_observations_that_were_recorded(workspace):
    store, models = workspace
    (models / "model.bin").write_bytes(b"weights-two!")
    _observe(store, models)
    rows = change_mod.history(store)
    assert [row["state"] for row in rows] == ["baseline", "content_drift"]
    assert rows[1]["previous_digest"] == rows[0]["digest"]


def test_the_timeline_does_not_invent_the_two_states_no_row_can_hold(workspace):
    """UNCHANGED and INCOMPLETE write no snapshot, by design.

    A vocabulary that listed them would promise a timeline this store cannot
    draw. Both are named in the response instead, so the panel can say so.
    """
    store, models = workspace
    _observe(store, models)  # unchanged: writes nothing
    observe(store, snapshot_of("m", str(models), "filesystem", [], listing_complete=False))
    rows = change_mod.history(store)
    assert [row["state"] for row in rows] == ["baseline"]
    assert "unchanged" not in change_mod.TIMELINE_STATES
    assert "incomplete" not in change_mod.TIMELINE_STATES


def test_every_timeline_entry_says_supersession_is_not_reconstructible(workspace):
    """Never a zero standing in for a gap.

    An evidence row keeps its current state and not its history, so what an
    old observation invalidated is not in this store. A panel must not render
    that absence as "it invalidated nothing".
    """
    store, _ = workspace
    assert all(row["supersession_known"] is False for row in change_mod.history(store))


def test_the_timeline_honours_its_limit(workspace):
    store, models = workspace
    for payload in (b"two!!!!!!!!", b"three!!!!!!", b"four!!!!!!!"):
        (models / "model.bin").write_bytes(payload)
        _observe(store, models)
    assert len(change_mod.history(store, limit=2)) == 2
    assert len(change_mod.history(store)) == 4


# ---------------------------------------------------------------------------
# Decision validity
# ---------------------------------------------------------------------------


class _FakeDecision:
    """The smallest thing `record_decision` reads, so these tests do not have
    to route a whole policy evaluation through to reach the storage rule."""

    def __init__(self, value="allow", digest="sha256:policy"):
        from datetime import date

        self.decision = type("V", (), {"value": value})()
        self.policy_id = "production"
        self.policy_version = 1
        self.policy_digest = digest
        self.decided_on = date(2026, 1, 1)
        self.subjects = ("artifact:x",)

    def to_dict(self):
        return {"decision": self.decision.value, "policy": self.policy_id}


def _decide(store: Store, inputs, *, proof="proof-1", value="allow") -> str:
    return store.record_decision(_FakeDecision(value), proof, inputs)


def test_a_decision_with_no_recorded_inputs_is_undetermined(workspace):
    """§6. Old decisions become UNDETERMINED, not CURRENT and not invalid.

    Reading "no inputs" as "nothing it depended on has changed" would mark
    exactly the decisions this release knows least about as the ones needing
    no attention.
    """
    store, _ = workspace
    _decide(store, [])
    row = decide_mod.review(store)[0]
    assert row.status == decide_mod.UNDETERMINED
    assert row.reasons[0]["reason"] == "no_recorded_inputs"
    assert not row.stands


def test_valid_inputs_make_a_decision_current(workspace):
    store, _ = workspace
    model = _asset_for(store, "model.bin")
    evidence_id = store.evidence_for(model)[0]["evidence_id"]
    _decide(store, [
        decide_mod.subject_input(model, store.asset(model)["digest"]),
        decide_mod.evidence_input(evidence_id, model, store.asset(model)["digest"]),
    ])
    row = decide_mod.review(store)[0]
    assert row.status == decide_mod.CURRENT
    assert row.stands
    assert row.reasons == []


@pytest.mark.parametrize(
    "state",
    [EvidenceState.SUPERSEDED, EvidenceState.STALE,
     EvidenceState.REVOKED, EvidenceState.UNTRUSTED],
)
def test_an_input_that_stopped_counting_requires_reassessment(workspace, state):
    """All four, and each names itself.

    They are four different reasons to look again - re-observe, stop trusting
    a signer, accept a new key - and a reason that said "invalid" would leave
    the reader to work out which.
    """
    store, _ = workspace
    model = _asset_for(store, "model.bin")
    evidence_id = store.evidence_for(model)[0]["evidence_id"]
    _decide(store, [decide_mod.evidence_input(evidence_id, model, "sha256:old")])
    store.set_evidence_state(evidence_id, state.value)

    row = decide_mod.review(store)[0]
    assert row.status == decide_mod.REQUIRES_REASSESSMENT
    assert row.reasons[0]["reason"] == f"evidence_{state.value}"
    assert row.reasons[0]["evidence_id"] == evidence_id


def test_a_subject_whose_digest_moved_requires_reassessment(workspace):
    """§18. The reason is the two digests, not a sentence about recency."""
    store, models = workspace
    model = _asset_for(store, "model.bin")
    was = store.asset(model)["digest"]
    _decide(store, [decide_mod.subject_input(model, was)])
    (models / "model.bin").write_bytes(b"weights-two!")
    _observe(store, models)

    row = decide_mod.review(store)[0]
    assert row.status == decide_mod.REQUIRES_REASSESSMENT
    reason = next(r for r in row.reasons if r["reason"] == "subject_digest_changed")
    assert reason["was"] == was
    assert reason["now"] == store.asset(model)["digest"]
    assert reason["was"] != reason["now"]


def test_a_historical_decision_is_never_rewritten(workspace):
    """§5. "DO NOT MUTATE A HISTORICAL ALLOW INTO REVIEW OR DENY."

    The row is what was approved. Overwriting it when reality moves destroys
    the only record of the approval, which is the document an auditor asks
    for.
    """
    store, models = workspace
    model = _asset_for(store, "model.bin")
    decision_id = _decide(store, [decide_mod.subject_input(model, store.asset(model)["digest"])])
    before = store.decision(decision_id)

    (models / "model.bin").write_bytes(b"weights-two!")
    _observe(store, models)
    reviewed = decide_mod.review(store)[0]

    assert reviewed.status == decide_mod.REQUIRES_REASSESSMENT
    assert reviewed.decision == "allow"
    assert store.decision(decision_id) == before, "the stored decision row moved"


def test_unrelated_evidence_changing_does_not_touch_a_decision(workspace):
    """§26. A decision that never depended on it is not affected by it.

    This is what makes the reassessment signal worth reading: if every change
    anywhere invalidated everything, nobody would act on any of it.
    """
    store, models = workspace
    model = _asset_for(store, "model.bin")
    _decide(store, [decide_mod.subject_input(model, store.asset(model)["digest"])])

    (models / "tokenizer.bin").write_bytes(b"vocabulary-two")
    _observe(store, models)

    assert decide_mod.review(store)[0].status == decide_mod.CURRENT


def test_an_input_naming_something_absent_is_undetermined_not_reassessment(workspace):
    """Absence is not falsehood, one level down.

    A record that was never here is not a record that was withdrawn, and only
    the second is a reason to re-decide.
    """
    store, _ = workspace
    _decide(store, [decide_mod.evidence_input("ev_nothing", "artifact:ghost", "sha256:x")])
    row = decide_mod.review(store)[0]
    assert row.status == decide_mod.UNDETERMINED
    assert row.reasons[0]["reason"] == "evidence_not_in_store"


def test_one_proven_reason_outranks_any_number_of_gaps(workspace):
    """The precedence rule, stated as a test.

    A decision with one demonstrably broken input and three unanswerable ones
    needs a second look, and this module can say why. Only when nothing is
    proven do the gaps decide, and a gap is never a pass.
    """
    store, _ = workspace
    model = _asset_for(store, "model.bin")
    evidence_id = store.evidence_for(model)[0]["evidence_id"]
    _decide(store, [
        decide_mod.evidence_input(evidence_id, model, "sha256:old"),
        decide_mod.evidence_input("ev_ghost", "artifact:ghost", ""),
        decide_mod.subject_input("artifact:ghost", "sha256:x"),
    ])
    store.set_evidence_state(evidence_id, EvidenceState.REVOKED.value)
    row = decide_mod.review(store)[0]
    assert row.status == decide_mod.REQUIRES_REASSESSMENT
    assert row.reasons[0]["reason"] == "evidence_revoked"
    # The gaps are still reported, after the proof, rather than dropped.
    assert len(row.reasons) == 3


def test_a_decision_never_depends_on_another_decisions_note(workspace):
    """A `policy_decision` record is the note that a decision happened.

    It is not something a decision rested on, and the first version of this
    excluded only the records the current run was about to write - which is
    enough on a first run and wrong on every one after it. Deciding twice
    about one subject made the second decision record the first one's note as
    an input, so replacing the model would then report the newer decision as
    needing reassessment partly because an older decision's note about the
    same model had been superseded. True, circular, and useless as a reason
    to act on.
    """
    from actaira.state import record as record_mod

    store, models = workspace
    model = _asset_for(store, "model.bin")

    class _Ref:
        handle = ""
        digest = ""

    class _Claims:
        ref = _Ref()

    _Ref.digest = store.asset(model)["digest"]
    first = record_mod.decision_inputs(store, [_Claims()])
    assert [item.ref for item in first if item.role == decide_mod.ROLE_SUBJECT] == [model]

    # File a decision, which writes a `policy_decision` record about the same
    # subject, and then ask again.
    store.record_decision(_FakeDecision(), "proof-first", first)
    record_mod.policy_decision(store, _FakeDecision(), "proof-first", [_Claims()])
    assert any(row["kind"] == "policy_decision" for row in store.evidence_for(model)), (
        "the fixture is only interesting if the note was actually written"
    )

    second = record_mod.decision_inputs(store, [_Claims()])
    kinds = {store.evidence(item.ref)["kind"] for item in second
             if item.role == decide_mod.ROLE_EVIDENCE}
    assert "policy_decision" not in kinds
    assert [item.to_dict() for item in second] == [item.to_dict() for item in first]

def test_the_counts_carry_every_validity_even_at_zero(workspace):
    store, _ = workspace
    _decide(store, [])
    assert set(decide_mod.counts(decide_mod.review(store))) == set(decide_mod.VALIDITIES)


def test_a_decision_and_its_inputs_are_written_in_one_transaction(workspace, monkeypatch):
    """A decision readable without its dependencies reads as one that had none.

    And "had none" is the one shape reported as UNDETERMINED, so a crash
    between two statements would permanently mislabel the decision.
    """
    store, _ = workspace
    model = _asset_for(store, "model.bin")

    class Poisoned:
        """An input that fails while the decision row is already written.

        A poisoned value rather than a patched `sqlite3.Connection`, whose
        methods are not settable. The effect is the one being tested: the
        insert of the decision has happened, the insert of its dependencies
        raises, and the question is whether the transaction took both back.
        """

        role = decide_mod.ROLE_SUBJECT
        ref = model
        subject_id = model

        @property
        def subject_digest(self):
            raise RuntimeError("interrupted between two statements")

    with pytest.raises(RuntimeError):
        _decide(store, [Poisoned()])

    assert store.decisions() == [], "the decision was filed without its dependencies"
    assert store.decision_inputs("proof-1") == []


# ---------------------------------------------------------------------------
# Migration 3
# ---------------------------------------------------------------------------


def test_the_new_migration_is_the_one_the_store_declares():
    assert len(MIGRATIONS) == STORE_VERSION == 3


def test_a_version_two_store_migrates_and_keeps_everything(tmp_path):
    """§26. Evidence ids, decisions, assets and edges all survive.

    Built by running the earlier migrations rather than by shipping a binary
    fixture, so the chain that produces a v2 database is the chain this
    repository actually has.
    """
    path = tmp_path / "old.db"
    connection = sqlite3.connect(path)
    for step in range(2):
        MIGRATIONS[step](connection)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    connection.execute("INSERT OR REPLACE INTO meta VALUES ('schema_version', '2')")
    connection.execute(
        "INSERT INTO assets (asset_id, kind, digest, name, first_seen, last_seen) "
        "VALUES ('artifact:a', 'artifact', 'sha256:aa', 'a.bin', 'then', 'then')"
    )
    connection.execute(
        "INSERT INTO edges (from_asset, relation, to_asset, stated_by, first_seen) "
        "VALUES ('system:s', 'uses', 'artifact:a', 'manifest old.yaml', 'then')"
    )
    connection.execute(
        "INSERT INTO evidence (evidence_id, subject_id, subject_digest, kind, collector, "
        "collector_version, observed_at, state, digest) VALUES "
        "('ev_old', 'artifact:a', 'sha256:aa', 'artifact_scan', 'c', '1', 'then', 'valid', 'd')"
    )
    connection.execute(
        "INSERT INTO decisions (decision_id, policy_digest, observed_at, decision, proof_digest) "
        "VALUES ('d_old', 'sha256:p', 'then', 'allow', 'proof')"
    )
    connection.commit()
    connection.close()

    with Store(path) as store:
        assert store.schema_version == 3
        assert store.evidence("ev_old")["state"] == "valid"
        assert store.asset("artifact:a")["digest"] == "sha256:aa"
        assert len(store.edges()) == 1
        decision = store.decision("d_old")
        assert decision is not None and decision["decision"] == "allow"
        # And the fact the migration cannot invent: a decision written before
        # dependencies were recorded has none, and is undetermined rather
        # than rewritten into a fact the old store did not know.
        assert store.decision_inputs("d_old") == []
        assert decide_mod.validity(store, decision).status == decide_mod.UNDETERMINED


def test_the_export_carries_decision_inputs_beside_the_decisions(workspace):
    """A v1 consumer iterates `decisions`; a nested array would be a shape it
    was never written against. So the rows ride beside them."""
    store, _ = workspace
    model = _asset_for(store, "model.bin")
    _decide(store, [decide_mod.subject_input(model, "sha256:x")])
    document = store.export()
    assert document["schema_version"] == "state-export/v1"
    assert len(document["decisions"]) == 1
    assert [row["ref"] for row in document["decision_inputs"]] == [model]
    assert "decision_inputs" not in document["decisions"][0]


# ---------------------------------------------------------------------------
# What a receipt issued from a workspace can point at
# ---------------------------------------------------------------------------


