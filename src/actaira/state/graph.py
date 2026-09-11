"""Which things depend on which, and what that means when one of them changes.

Design note D-224. "What does this model change affect?" is the question every
other part of this tool exists to make answerable, and in 2.1 the answer was a
person with a spreadsheet. It needs two things Actaira did not have: edges that
were recorded rather than guessed, and a walk that can explain itself.

Both halves are rules here.

**An edge exists because something said so.** Every one carries `stated_by` -
the declaration it came from, or the snapshot that observed it - and nothing
in this module infers an edge from two names that look alike or two assets
sharing an organisation. That restraint is the whole value: an impact report
that listed everything in the same registry would be technically complete,
practically useless, and would train people to ignore it.

**An answer comes with its route.** `impact` returns not "these six things are
affected" but, for each, the exact chain of edges that reaches it - "model
bundle changed -> agent USES bundle -> system USES agent". A reader can check
that chain against their own understanding and tell you it is wrong, which is
the only kind of automated answer worth having.

Cycles are expected rather than defended against. Sub-agents call each other,
systems contain systems, and a walk that recursed would die on a real
declaration. The visited set cuts it, the cycle is reported as a fact, and the
answer says it is incomplete rather than pretending otherwise.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = "asset-graph/v1"

# The relation vocabulary. Closed, documented and translated: an edge kind
# that shows up in a graph view under a word nobody defined is how one diagram
# starts meaning two things. `release_check.py` asserts every member of this
# tuple is in both catalogues.
RELATIONS = (
    "uses",
    "runs_as",
    "reads",
    "writes",
    "exposes",
    "delegates_to",
    "uses_model",
    "governed_by",
    "evidenced_by",
    "supports",
    "served_by",
    "contains",
)

# How far a walk goes. A dependency chain longer than this is not something an
# operator reasons about, and a bound is the difference between a search and a
# hang on a graph somebody wrote in a loop.
MAX_DEPTH = 12

# How many cycles `cycles()` will enumerate before it stops. Simple-cycle
# enumeration is exponential in the worst case, and the worst case is a dense
# graph somebody generated rather than declared. Reaching this sets
# `cycles_may_be_incomplete`, so a truncated answer says it is one.
MAX_CYCLES = 256


@dataclass(frozen=True)
class Edge:
    source: str
    relation: str
    target: str
    stated_by: str = "declaration"
    evidence_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "from": self.source,
            "relation": self.relation,
            "to": self.target,
            "stated_by": self.stated_by,
        }
        if self.evidence_id:
            payload["evidence_id"] = self.evidence_id
        return payload


@dataclass
class Graph:
    """Assets and the edges between them, loaded from the store or built in memory."""

    edges: list[Edge] = field(default_factory=list)
    assets: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Set by `cycles()` when the walk stopped at MAX_DEPTH. Read through
    # `cycles_may_be_incomplete`, so an empty cycle list is never mistaken for
    # a proof that there are none.
    _depth_capped: bool = False

    @classmethod
    def from_store(cls, store: Any) -> Graph:
        return cls(
            edges=[
                Edge(
                    source=row["from_asset"],
                    relation=row["relation"],
                    target=row["to_asset"],
                    stated_by=row["stated_by"],
                    evidence_id=row["evidence_id"],
                )
                for row in store.edges()
            ],
            assets={row["asset_id"]: row for row in store.assets()},
        )

    def add(self, edge: Edge) -> None:
        if edge.relation not in RELATIONS:
            raise ValueError(
                f"{edge.relation!r} is not a relation. Known: {', '.join(RELATIONS)}. "
                "An edge kind nobody defined is one two readers will read differently."
            )
        if edge not in self.edges:
            self.edges.append(edge)

    def outgoing(self, node: str) -> list[Edge]:
        return [edge for edge in self.edges if edge.source == node]

    def incoming(self, node: str) -> list[Edge]:
        return [edge for edge in self.edges if edge.target == node]

    def nodes(self) -> list[str]:
        names = {edge.source for edge in self.edges} | {edge.target for edge in self.edges}
        return sorted(names | set(self.assets))

    def cycles(self) -> list[list[str]]:
        """Every simple cycle, each reported once.

        Defect DEF-79, and the second attempt at it. The first version marked
        a node finished as soon as its children were pushed, so the LIFO order
        let one branch close a node before another branch had walked it, and a
        differential test against brute-force enumeration disagreed on about a
        fifth of random small digraphs - always under-reporting. Repairing the
        colouring did not fix it, and that was the useful part: a three-colour
        DFS finds *whether* a graph has a cycle, which is a different question
        from *which cycles it has*. Once a node is black, every cycle that
        could only be reached through it is invisible, whatever the colouring
        gets right.

        So this enumerates properly. From each node in turn, walk forward over
        nodes that sort at or after the start; a path that returns to the
        start is a cycle, and the ordering constraint is what makes each one
        appear exactly once rather than once per member. It is the textbook
        enumeration rather than a clever one, because these graphs are the
        assets in one workspace and the sub-agents of one declaration - tens
        of nodes, not thousands.

        Both bounds are reported rather than silent. `MAX_DEPTH` caps the trail
        and `MAX_CYCLES` caps the answer, and `cycles_may_be_incomplete` says
        when either was reached: an empty list must never be readable as a
        proof that there are none.
        """
        order = {name: index for index, name in enumerate(self.nodes())}
        found: list[list[str]] = []
        self._depth_capped = False

        for start in self.nodes():
            floor = order[start]
            stack: list[tuple[str, list[str]]] = [(start, [start])]
            while stack:
                node, trail = stack.pop()
                if len(trail) > MAX_DEPTH:
                    self._depth_capped = True
                    continue
                for edge in sorted(self.outgoing(node), key=lambda item: item.target):
                    target = edge.target
                    if target == start:
                        found.append([*trail, start])
                        if len(found) >= MAX_CYCLES:
                            self._depth_capped = True
                            return sorted(found)
                        continue
                    # Only forward in the node ordering, and never twice in one
                    # trail. Together those make each simple cycle appear once,
                    # under its lowest-ordered member.
                    if order.get(target, -1) <= floor or target in trail:
                        continue
                    stack.append((target, [*trail, target]))
        return sorted(found)

    @property
    def cycles_may_be_incomplete(self) -> bool:
        """Whether the last cycle walk stopped at its depth bound."""
        return bool(self._depth_capped)

    def to_dict(self) -> dict[str, Any]:
        cycles = self.cycles()
        return {
            "schema_version": SCHEMA_VERSION,
            "nodes": [
                {
                    "id": name,
                    "kind": self.assets.get(name, {}).get("kind", _kind_of(name)),
                    "digest": self.assets.get(name, {}).get("digest", ""),
                }
                for name in self.nodes()
            ],
            "edges": [edge.to_dict() for edge in sorted(
                self.edges, key=lambda edge: (edge.source, edge.relation, edge.target)
            )],
            "cycles": cycles,
            "cycles_may_be_incomplete": self.cycles_may_be_incomplete,
        }


def _kind_of(node: str) -> str:
    head, separator, _ = node.partition(":")
    return head if separator else "unknown"


@dataclass
class Affected:
    """One thing a change reaches, and the exact route that reaches it."""

    node: str
    route: list[Edge]

    @property
    def why(self) -> str:
        """The route as one line: `system:x -> USES -> agent:y -> USES -> bundle:z`.

        Read left to right it is the dependency as somebody declared it, and
        the changed asset is at the right-hand end. That ordering is on
        purpose: the reader knows what changed and is looking for who cares.
        """
        if not self.route:
            return "the changed asset itself"
        text = self.route[0].source
        for edge in self.route:
            text += f" -> {edge.relation.upper()} -> {edge.target}"
        return text

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.node,
            "why": self.why,
            "route": [edge.to_dict() for edge in self.route],
            "hops": len(self.route),
        }


def impact(graph: Graph, changed: str, *, max_depth: int = MAX_DEPTH) -> dict[str, Any]:
    """Everything that depends on `changed`, each with the chain that reaches it.

    The walk goes backwards along the edges, because "affected by" is the
    reverse of "uses": a system that USES an agent that USES a bundle is
    affected when the bundle moves, and following the edges forwards would
    have answered the opposite question.

    Breadth-first, so the route reported for each node is the shortest one.
    A reader checking a three-hop explanation against their understanding of
    the system can do it; one checking an arbitrary seven-hop path that
    happened to be found first cannot.
    """
    start = resolve(graph, changed)
    affected: dict[str, Affected] = {}
    queue: deque[tuple[str, list[Edge]]] = deque([(start, [])])
    visited = {start}
    truncated = False

    while queue:
        node, route = queue.popleft()
        for edge in graph.incoming(node):
            if edge.source in visited:
                continue
            if len(route) + 1 > max_depth:
                truncated = True
                continue
            path = [edge, *route]
            visited.add(edge.source)
            affected[edge.source] = Affected(edge.source, path)
            queue.append((edge.source, path))

    by_kind: dict[str, int] = {}
    for name in affected:
        kind = graph.assets.get(name, {}).get("kind", _kind_of(name))
        by_kind[kind] = by_kind.get(kind, 0) + 1

    return {
        "changed": start,
        "found": start in graph.nodes(),
        "affected": [
            affected[name].to_dict() for name in sorted(affected, key=lambda key: (len(affected[key].route), key))
        ],
        "by_kind": dict(sorted(by_kind.items())),
        "cycles": graph.cycles(),
        "truncated": truncated,
    }


def resolve(graph: Graph, changed: str) -> str:
    """Accept a node id or a digest, because an operator has whichever they have.

    `actaira impact sha256:...` is the shape the roadmap asks for and a digest
    is not a node id, so the assets table is consulted. When nothing matches,
    the string is used as given and `found` is false - a walk that silently
    substituted a nearby asset would answer a question nobody asked.
    """
    if changed in graph.assets or any(edge.source == changed or edge.target == changed for edge in graph.edges):
        return changed
    for asset_id, row in sorted(graph.assets.items()):
        if row.get("digest") and row["digest"] == changed:
            return asset_id
    return changed


# --------------------------------------------------------------------------
# Recorded, and what can be proven current
#
# Design note D-243. `Graph.from_store` returns every relation this workspace
# has ever recorded, and that was audited rather than assumed: a source
# observed with artifacts A and B, then observed again with only A, keeps
# three nodes and two edges. `watch` supersedes the evidence bound to B's
# digest and removes neither B's asset row nor the `contains` edge that
# reaches it, which is the right thing for a store whose whole purpose is to
# remember - and the wrong thing to put on a screen under the word "current".
#
# So the recorded graph keeps its meaning, `asset-graph/v1` is untouched, and
# currentness is a separate, three-valued question asked of it:
#
#   CURRENT         the latest observation of this asset's source confirmed it
#   NOT_IN_LATEST   an earlier observation recorded it and the latest did not
#   UNDETERMINED    nothing in this store answers the question
#
# The third value is the honest one and it is not a corner case: an edge a
# manifest declared carries no notion of a current manifest run, so its
# currentness is genuinely unknown here. Collapsing it into either of the
# other two would be this module inventing a fact, which is precisely what
# D-224 exists to refuse. Making it answerable is the Evidence and Watch
# increment's problem, and it needs a store that records which declaration
# run is the live one - not a guess made at read time.
#
# Nothing below needs a migration. `assets.last_snapshot` and the snapshot
# digest each edge's `stated_by` already names are enough, which is why this
# is a projection over recorded state rather than a second copy of it.
# --------------------------------------------------------------------------

CURRENT = "current"
NOT_IN_LATEST = "not_in_latest_observation"
UNDETERMINED = "undetermined"

CURRENTNESS = (CURRENT, NOT_IN_LATEST, UNDETERMINED)

SNAPSHOT_STATED_PREFIX = "snapshot "

# How much of a digest an edge's `stated_by` carries. Long enough to identify
# the observation, short enough to read in a terminal.
SNAPSHOT_MARKER_DIGITS = 19


def snapshot_marker(digest: str) -> str:
    """What `watch` writes into `stated_by` when a snapshot states an edge.

    One spelling, in one place, imported by the writer and by the reader. Two
    copies of this format would agree until somebody widened one of them, and
    the failure would be an edge silently reclassified as not current - a
    wrong answer that looks like a real one.
    """
    return f"{SNAPSHOT_STATED_PREFIX}{digest[:SNAPSHOT_MARKER_DIGITS]}"


def latest_observations(store: Any) -> dict[str, str]:
    """Each source's most recent snapshot digest, or nothing where there is none."""
    latest: dict[str, str] = {}
    for source in store.sources():
        row = store.latest_snapshot(source["source_id"])
        if row and row["digest"]:
            latest[source["source_id"]] = row["digest"]
    return latest


@dataclass(frozen=True)
class Projection:
    """What is still there, as far as this store can prove.

    Never a filter. The recorded graph is the graph; this says, per node and
    per edge, which of the three answers applies - so a caller can grey a
    node out, hide it, or refuse to do either, and a reader is never shown a
    subset under a word that claims completeness.
    """

    nodes: dict[str, str] = field(default_factory=dict)
    edges: dict[tuple[str, str, str], str] = field(default_factory=dict)

    def counts(self) -> dict[str, dict[str, int]]:
        return {
            "nodes": {state: sum(1 for value in self.nodes.values() if value == state)
                      for state in CURRENTNESS},
            "edges": {state: sum(1 for value in self.edges.values() if value == state)
                      for state in CURRENTNESS},
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": dict(sorted(self.nodes.items())),
            "edges": [
                {"from": key[0], "relation": key[1], "to": key[2], "currentness": value}
                for key, value in sorted(self.edges.items())
            ],
            "counts": self.counts(),
        }


def project(graph: Graph, latest: dict[str, str]) -> Projection:
    """Classify every node and edge of a recorded graph against the latest observations.

    `latest` maps a source id to the digest of its most recent snapshot, which
    is what `latest_observations` reads out of the store. Passed in rather
    than fetched, so this function is pure and a test can hand it a state no
    fixture would produce.
    """
    nodes: dict[str, str] = {}
    for name in graph.nodes():
        row = graph.assets.get(name) or {}
        source_id = row.get("source_id")
        confirmed_by = row.get("last_snapshot")
        if not source_id or not confirmed_by or source_id not in latest:
            nodes[name] = UNDETERMINED
            continue
        nodes[name] = CURRENT if confirmed_by == latest[source_id] else NOT_IN_LATEST

    edges: dict[tuple[str, str, str], str] = {}
    for edge in graph.edges:
        key = (edge.source, edge.relation, edge.target)
        if not edge.stated_by.startswith(SNAPSHOT_STATED_PREFIX):
            # Declared by a manifest or a declaration. Nothing in this store
            # says which run of it is the live one, so the honest answer is
            # that this does not know.
            edges[key] = UNDETERMINED
            continue
        row = graph.assets.get(edge.source) or {}
        source_id = row.get("source_id")
        if not source_id or source_id not in latest:
            edges[key] = UNDETERMINED
            continue
        edges[key] = CURRENT if edge.stated_by == snapshot_marker(latest[source_id]) else NOT_IN_LATEST
    return Projection(nodes=nodes, edges=edges)


# --------------------------------------------------------------------------
# Neighbourhoods
#
# Part of D-243. The panel offers focus, upstream, downstream and a hop limit,
# and every one of those is a traversal. A traversal written in the browser
# would be a second implementation of reachability over the same edges, which
# is the one thing this layer exists to prevent: `impact` and a hand-written
# JavaScript walk would agree until they did not, and the disagreement would
# be invisible because each looks right on its own.
#
# So it lives here, beside `impact`, deterministic and bounded the same way.
# --------------------------------------------------------------------------

# Which way a walk goes, in the words the question is asked in.
#
#   DEPENDENTS    what depends on this - the direction `impact` walks, along
#                 incoming edges, because "affected by" is the reverse of "uses"
#   DEPENDENCIES  what this depends on, along outgoing edges
#   BOTH          the neighbourhood around it, in both
DEPENDENTS = "dependents"
DEPENDENCIES = "dependencies"
BOTH = "both"

DIRECTIONS = (BOTH, DEPENDENTS, DEPENDENCIES)


@dataclass
class Neighbourhood:
    """The part of a graph within N hops of one node, and whether it stops early."""

    focus: str
    found: bool
    direction: str
    depth: int
    hops: dict[str, int] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "focus": self.focus,
            "found": self.found,
            "direction": self.direction,
            "depth": self.depth,
            "nodes": [
                {"id": name, "hops": self.hops[name]}
                for name in sorted(self.hops, key=lambda key: (self.hops[key], key))
            ],
            "edges": [edge.to_dict() for edge in self.edges],
            "truncated": self.truncated,
        }


def _reachable_edges(graph: Graph, node: str, direction: str) -> list[tuple[Edge, str]]:
    """The edges a walk in `direction` follows out of `node`, each with where it lands.

    Sorted, always, because two runs over one workspace must draw the same
    graph: this repository generates its screenshots and tests them, and a
    layout that depended on dictionary order would make every capture a
    coin toss.
    """
    steps: list[tuple[Edge, str]] = []
    if direction in (DEPENDENTS, BOTH):
        steps.extend((edge, edge.source) for edge in graph.incoming(node))
    if direction in (DEPENDENCIES, BOTH):
        steps.extend((edge, edge.target) for edge in graph.outgoing(node))
    return sorted(steps, key=lambda item: (item[1], item[0].relation, item[0].source, item[0].target))


def neighbourhood(
    graph: Graph, focus: str, *, depth: int = 2, direction: str = BOTH
) -> Neighbourhood:
    """Every node within `depth` hops of `focus`, with the edges between them.

    Three properties, each of which is the reason a line of this exists.

    **It resolves the same way `impact` does.** An operator has a node id or a
    digest, whichever they were given, and a view that accepted one of the two
    would send them to the terminal to convert it.

    **The subgraph is induced, not just the path.** Every recorded edge whose
    two ends are both visible is drawn, including the ones the walk did not
    travel. A picture that showed only the edges a breadth-first search
    happened to use would be a picture of the search rather than of the graph.

    **It says when it stopped.** `truncated` is set when an edge leaves the
    visible set in the direction being walked, so "nothing else is connected"
    and "the limit was reached" can never look the same. That is the same rule
    `impact` and `cycles` follow, and the reason is the same: a bounded
    computation must never turn into a visual claim of completeness.
    """
    if direction not in DIRECTIONS:
        raise ValueError(
            f"{direction!r} is not a direction. Known: {', '.join(DIRECTIONS)}."
        )
    start = resolve(graph, focus)
    bound = max(0, min(int(depth), MAX_DEPTH))

    hops = {start: 0}
    frontier = [start]
    for level in range(bound):
        following: list[str] = []
        for node in frontier:
            for _edge, other in _reachable_edges(graph, node, direction):
                if other in hops:
                    continue
                hops[other] = level + 1
                following.append(other)
        frontier = sorted(following)

    visible = set(hops)
    edges = sorted(
        (edge for edge in graph.edges if edge.source in visible and edge.target in visible),
        key=lambda edge: (edge.source, edge.relation, edge.target),
    )
    truncated = any(
        other not in visible
        for node in visible
        for _edge, other in _reachable_edges(graph, node, direction)
    )
    return Neighbourhood(
        focus=start,
        found=start in graph.nodes(),
        direction=direction,
        depth=bound,
        hops=hops,
        edges=edges,
        truncated=truncated,
    )


def subgraph(graph: Graph, view: Neighbourhood) -> Graph:
    """A `Graph` holding only what a neighbourhood made visible.

    So a view goes through `to_dict` and comes out as `asset-graph/v1` like
    any other graph, rather than needing a second serialisation that would
    drift from the published one.

    Every visible node gets an entry even when the store holds no row for it,
    because `Graph.nodes()` is the union of the edge endpoints and the asset
    keys: a focus with no edges inside the view and no row of its own would
    otherwise vanish from a view built to show it. An empty mapping is the
    honest entry - it says the graph knows this node and the store records
    nothing else about it - and `to_dict` already derives a kind from the id
    for exactly that case.
    """
    visible = set(view.hops)
    return Graph(
        edges=list(view.edges),
        assets={name: graph.assets.get(name, {}) for name in sorted(visible)},
    )
