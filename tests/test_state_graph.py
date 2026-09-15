"""Recorded against current, the traversals the panel asks for, and the agent graph.

Design note D-243. `tests/test_state.py` holds the store, the watch semantics
and `impact`. This file holds the three things the graph panel made necessary,
and each one exists because of a question that was answered by reading the code
rather than by assuming:

  * **Does the stored graph mean "what is there" or "what has ever been
    recorded"?** It means the second, and the first three tests here prove it
    rather than assert it. Everything downstream - the word on the heading, the
    three-valued currentness, the refusal to filter - follows from that fact.
  * **Can the graph answer "what is within two hops of this"?** It can now, in
    Python, once, for both the CLI and the interface. A traversal written in
    the browser would be a second implementation of reachability over the same
    edges and the two would agree until they did not.
  * **Does the persistent asset graph reach an agent's tools?** It did not: the
    shipped example declared five tools, two MCP servers, an identity and two
    data sources and contributed one edge. It does now, from the declaration,
    and the agent's digest has not moved.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from actaira.conformance import load as load_agent
from actaira.state import graph as graph_mod
from actaira.state.graph import Edge, Graph
from actaira.state.snapshot import snapshot_of
from actaira.state.store import Store
from actaira.state.watch import observe
from conftest import REPO_ROOT

A = {"uri": "hf://acme/m/a.bin", "size": 10, "declared_sha256": "aa" * 32}
B = {"uri": "hf://acme/m/b.bin", "size": 20, "declared_sha256": "bb" * 32}


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / ".actaira" / "state.db") as opened:
        yield opened


def observed(store, rows, *, revision: str, at: str):
    return observe(store, snapshot_of("m", "hf://acme/m", "huggingface", rows,
                                      revision=revision, observed_at=at))


def watched(store, rows, *, revision="r1", at="2026-01-01T00:00:00+00:00"):
    store.add_source("m", "huggingface", "hf://acme/m")
    return observed(store, rows, revision=revision, at=at)


# ---------------------------------------------------------------------------
# Recorded, and what that word has to mean on a screen
# ---------------------------------------------------------------------------


def test_an_artifact_the_latest_observation_did_not_see_stays_in_the_graph(store):
    """The question this whole feature turned on, answered by the code.

    A source is observed with A and B, then with A alone. `watch` supersedes
    the evidence bound to B's digest and removes neither B's asset row nor the
    `contains` edge that reaches it - which is right for a store whose purpose
    is to remember, and is exactly why a panel may not put the word "current"
    over what it returns.
    """
    watched(store, [A, B])
    before = Graph.from_store(store)
    assert len(before.nodes()) == 3
    assert len(before.edges) == 2

    observation = observed(store, [A], revision="r2", at="2026-01-02T00:00:00+00:00")
    assert observation.removed == [B["uri"]]

    after = Graph.from_store(store)
    assert len(after.nodes()) == 3, "a removed artifact left the recorded graph"
    assert len(after.edges) == 2, "a relation was deleted when an observation stopped seeing it"


def test_the_projection_tells_a_current_observation_from_an_earlier_one(store):
    """What the store *can* prove, proven.

    `assets.last_snapshot` says which observation last confirmed an asset and
    `sources` says which observation is the latest, so for anything a snapshot
    produced the question has a real answer. No migration was needed for this:
    the columns were already there.
    """
    watched(store, [A, B])
    observed(store, [A], revision="r2", at="2026-01-02T00:00:00+00:00")

    graph = Graph.from_store(store)
    projection = graph_mod.project(graph, graph_mod.latest_observations(store))

    states = {name: projection.nodes[name] for name in graph.nodes()}
    assert sorted(states.values()).count(graph_mod.CURRENT) == 2, states
    assert sorted(states.values()).count(graph_mod.NOT_IN_LATEST) == 1, states

    kept = [name for name, value in states.items() if value == graph_mod.NOT_IN_LATEST]
    assert len(kept) == 1
    edges = {key: value for key, value in projection.edges.items() if kept[0] in key}
    assert set(edges.values()) == {graph_mod.NOT_IN_LATEST}


def test_a_declared_edge_is_undetermined_and_never_guessed_at():
    """The honest third value, and the reason it is not two.

    Nothing in the store says which run of a declaration is live, so a
    declared edge cannot be called current and must not be called gone. Both
    of the other answers would be this module inventing a fact.
    """
    graph = Graph()
    graph.add(Edge("system:x", "uses", "agent:y", stated_by="manifest subjects.yaml"))
    projection = graph_mod.project(graph, {"m": "sha256:" + "aa" * 32})
    assert set(projection.edges.values()) == {graph_mod.UNDETERMINED}


def test_an_asset_from_a_database_with_no_snapshot_column_is_undetermined():
    """A row written under schema version 1 has no `last_snapshot`.

    It must read as undetermined, never as gone: an older database is not a
    statement that everything in it has disappeared.
    """
    graph = Graph(
        edges=[Edge("source:m", "contains", "artifact:a", stated_by="snapshot sha256:aaaa")],
        assets={"artifact:a": {"asset_id": "artifact:a", "kind": "artifact",
                               "source_id": "m", "last_snapshot": None}},
    )
    projection = graph_mod.project(graph, {"m": "sha256:" + "aa" * 32})
    assert projection.nodes["artifact:a"] == graph_mod.UNDETERMINED


def test_the_marker_a_snapshot_writes_is_the_one_the_projection_reads(store):
    """One spelling of "stated by this snapshot", in one place.

    `watch` writes the marker and `project` parses it back. Two copies of that
    format would agree until one was widened, and the failure would be an edge
    silently reclassified - a wrong answer that looks like a real one.
    """
    watched(store, [A])
    latest = graph_mod.latest_observations(store)
    marker = graph_mod.snapshot_marker(latest["m"])
    stated = {edge.stated_by for edge in Graph.from_store(store).edges}
    assert stated == {marker}, stated


def test_the_projection_counts_every_node_and_edge_it_was_given(store):
    watched(store, [A, B])
    graph = Graph.from_store(store)
    projection = graph_mod.project(graph, graph_mod.latest_observations(store))
    counts = projection.counts()
    assert sum(counts["nodes"].values()) == len(graph.nodes())
    assert sum(counts["edges"].values()) == len(graph.edges)


# ---------------------------------------------------------------------------
# Neighbourhoods
# ---------------------------------------------------------------------------


def chain_graph() -> Graph:
    """system -> agent -> tool -> data, plus a bundle nothing reaches."""
    graph = Graph()
    graph.add(Edge("system:fraud", "uses", "agent:review", stated_by="manifest m.yaml"))
    graph.add(Edge("agent:review", "uses", "tool:fetch", stated_by="declaration a.yaml"))
    graph.add(Edge("tool:fetch", "reads", "data:tickets", stated_by="declaration a.yaml"))
    graph.assets["bundle:lonely"] = {"asset_id": "bundle:lonely", "kind": "bundle"}
    return graph


def test_one_hop_of_dependents_is_one_hop():
    view = graph_mod.neighbourhood(chain_graph(), "tool:fetch", depth=1,
                                   direction=graph_mod.DEPENDENTS)
    assert set(view.hops) == {"tool:fetch", "agent:review"}
    assert view.hops["agent:review"] == 1


def test_two_hops_reach_further_and_three_reach_the_end():
    graph = chain_graph()
    two = graph_mod.neighbourhood(graph, "data:tickets", depth=2, direction=graph_mod.DEPENDENTS)
    three = graph_mod.neighbourhood(graph, "data:tickets", depth=3, direction=graph_mod.DEPENDENTS)
    assert set(two.hops) == {"data:tickets", "tool:fetch", "agent:review"}
    assert set(three.hops) == {"data:tickets", "tool:fetch", "agent:review", "system:fraud"}


def test_dependencies_walk_the_other_way():
    view = graph_mod.neighbourhood(chain_graph(), "system:fraud", depth=2,
                                   direction=graph_mod.DEPENDENCIES)
    assert set(view.hops) == {"system:fraud", "agent:review", "tool:fetch"}


def test_both_directions_reach_what_either_reaches():
    view = graph_mod.neighbourhood(chain_graph(), "agent:review", depth=1, direction=graph_mod.BOTH)
    assert set(view.hops) == {"agent:review", "system:fraud", "tool:fetch"}


def test_a_view_that_stops_early_says_so_and_one_that_does_not_does_not():
    graph = chain_graph()
    short = graph_mod.neighbourhood(graph, "data:tickets", depth=1,
                                    direction=graph_mod.DEPENDENTS)
    full = graph_mod.neighbourhood(graph, "data:tickets", depth=9,
                                   direction=graph_mod.DEPENDENTS)
    assert short.truncated is True
    assert full.truncated is False, (
        "a complete view claimed to be truncated, which teaches a reader to ignore the warning"
    )


def test_an_isolated_node_survives_a_view_built_to_show_it():
    """`Graph.nodes()` is the union of edge endpoints and asset keys, so a
    focus with no edges inside the view would vanish from the view unless it
    is carried explicitly."""
    graph = chain_graph()
    view = graph_mod.neighbourhood(graph, "bundle:lonely", depth=2)
    assert view.found is True
    assert set(view.hops) == {"bundle:lonely"}
    assert "bundle:lonely" in graph_mod.subgraph(graph, view).nodes()


def test_the_subgraph_draws_every_edge_between_visible_nodes():
    """Induced, not just the edges the search walked: a picture of the search
    is not a picture of the graph."""
    graph = chain_graph()
    graph.add(Edge("system:fraud", "uses", "tool:fetch", stated_by="manifest m.yaml"))
    view = graph_mod.neighbourhood(graph, "agent:review", depth=1)
    edges = {(edge.source, edge.target) for edge in graph_mod.subgraph(graph, view).edges}
    assert ("system:fraud", "tool:fetch") in edges


def test_an_asset_this_store_never_saw_is_not_found_rather_than_empty():
    view = graph_mod.neighbourhood(chain_graph(), "artifact:never", depth=3)
    assert view.found is False
    assert set(view.hops) == {"artifact:never"}


def test_a_digest_resolves_to_its_asset_the_way_impact_resolves_one(store):
    watched(store, [A])
    graph = Graph.from_store(store)
    digest = f"sha256:{A['declared_sha256']}"
    view = graph_mod.neighbourhood(graph, digest, depth=1)
    assert view.found is True
    assert view.focus.startswith("artifact:")


def test_a_direction_nobody_defined_is_refused():
    with pytest.raises(ValueError, match="not a direction"):
        graph_mod.neighbourhood(chain_graph(), "agent:review", direction="sideways")


def test_a_depth_past_the_engine_limit_is_clamped_rather_than_obeyed():
    view = graph_mod.neighbourhood(chain_graph(), "agent:review", depth=9999)
    assert view.depth == graph_mod.MAX_DEPTH


def test_a_cycle_does_not_make_a_neighbourhood_recurse():
    graph = Graph()
    graph.add(Edge("agent:a", "delegates_to", "agent:b", stated_by="declaration a.yaml"))
    graph.add(Edge("agent:b", "delegates_to", "agent:a", stated_by="declaration b.yaml"))
    view = graph_mod.neighbourhood(graph, "agent:a", depth=graph_mod.MAX_DEPTH)
    assert set(view.hops) == {"agent:a", "agent:b"}


def test_two_walks_over_one_graph_give_byte_identical_answers():
    """Determinism, because the screenshots are generated and tested. A layout
    that depended on iteration order would make every capture a coin toss."""
    graph = chain_graph()
    first = graph_mod.neighbourhood(graph, "data:tickets", depth=3).to_dict()
    second = graph_mod.neighbourhood(graph, "data:tickets", depth=3).to_dict()
    assert first == second
    assert [row["id"] for row in first["nodes"]] == sorted(
        (row["id"] for row in first["nodes"]),
        key=lambda name: (first["nodes"][[r["id"] for r in first["nodes"]].index(name)]["hops"], name),
    )


def test_every_edge_of_a_view_keeps_its_provenance():
    graph = chain_graph()
    view = graph_mod.neighbourhood(graph, "agent:review", depth=2)
    assert all(edge.stated_by for edge in view.edges)


def test_an_edge_that_carries_an_evidence_id_keeps_it_through_a_view():
    graph = Graph()
    graph.add(Edge("system:x", "uses", "agent:y", stated_by="manifest m.yaml",
                   evidence_id="ev_abc"))
    view = graph_mod.neighbourhood(graph, "agent:y", depth=1)
    assert [edge.evidence_id for edge in view.edges] == ["ev_abc"]
    assert graph_mod.subgraph(graph, view).to_dict()["edges"][0]["evidence_id"] == "ev_abc"


# ---------------------------------------------------------------------------
# The agent half of the graph
# ---------------------------------------------------------------------------

EXAMPLE = Path(REPO_ROOT) / "examples" / "agent-ticket-triage.yaml"

# The digest of the shipped declaration, written out. This is the number that
# answers "is this the agent that was approved?", and the whole point of
# `membership_relations` living outside `relations()` is that improving the
# graph must not move it. A literal fails loudly; a computed comparison would
# pass whatever the code did.
EXAMPLE_DIGEST = "sha256:eede34465e6fb75aeff8692b454df4553a2e428845ec2b4ec76df3081ce058c9"


def test_the_shipped_agents_digest_has_not_moved():
    assert load_agent(EXAMPLE).digest == EXAMPLE_DIGEST, (
        "the agent digest changed. If that was deliberate it is a versioned change to "
        "agent-bom, and if it was a side effect of a graph improvement it is the bug this "
        "test exists for"
    )


def test_membership_is_not_in_the_bom_and_does_not_reach_the_digest():
    agent = load_agent(EXAMPLE)
    declared = {(edge.source, edge.relation, edge.target) for edge in agent.relations()}
    membership = {(edge.source, edge.relation, edge.target)
                  for edge in agent.membership_relations()}
    assert not (declared & membership), "membership edges leaked into the declared relations"

    bom = agent.to_bom()
    listed = {(row["from"], row["relation"], row["to"]) for row in bom["relations"]}
    assert listed == declared
    assert not (listed & membership), "the A-BOM gained edges, so every stored digest moved"


def test_membership_names_every_part_the_declaration_lists():
    agent = load_agent(EXAMPLE)
    targets = {edge.target for edge in agent.membership_relations()}
    for tool in agent.tools:
        assert f"tool:{tool.name}" in targets
    for server in agent.mcp_servers:
        assert f"mcp:{server.name}" in targets
    for identity in agent.identities:
        assert f"identity:{identity.name}" in targets
    for source in agent.data_sources:
        assert f"data:{source.name}" in targets
    assert all(edge.source == f"agent:{agent.name}" for edge in agent.membership_relations())


def test_nothing_in_membership_is_inferred_from_a_name():
    """Every membership edge names something the document lists. A target that
    is not in the declaration would be this code guessing."""
    agent = load_agent(EXAMPLE)
    declared_names = (
        {f"tool:{tool.name}" for tool in agent.tools}
        | {f"mcp:{server.name}" for server in agent.mcp_servers}
        | {f"identity:{item.name}" for item in agent.identities}
        | {f"data:{source.name}" for source in agent.data_sources}
    )
    assert {edge.target for edge in agent.membership_relations()} == declared_names


