"""The commands that read and write local state: init, source, watch, evidence, graph, impact, trust.

Design note D-227. These live in their own module rather than in `cli.py` for
one reason worth stating: every command here can only run against a store, and
every command in `cli.py` must keep running without one. Putting them side by
side is how the import of `sqlite3` and the assumption that `.actaira/` exists
leak into a `scan` that has neither. The dispatch in `cli.py` calls in here and
nothing in here is imported until one of these commands is used.

The output format follows the same rule as the rest of the tool: the
interesting thing first, the complete thing after, and never a number that
stands in for the evidence. `watch` prints what changed, then what that
invalidated, then what is affected - in that order, because that is the order
an operator asks the questions in.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from .i18n.catalog import Catalog
from .state import graph as graph_mod
from .state.store import Store, StoreError, default_path

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_INCONCLUSIVE = 3


def add_parsers(sub: Any) -> None:
    """Every state command's arguments, in one place next to their handlers."""
    init = sub.add_parser("init", help="create .actaira/ and a versioned state database")
    init.add_argument("--state", type=Path, default=None, help="where the database lives")
    init.add_argument("--json", action="store_true")

    src = sub.add_parser("source", help="register and list the sources this workspace watches")
    src_sub = src.add_subparsers(dest="source_command", required=True)
    src_add = src_sub.add_parser("add", help="register a monitorable source")
    src_add.add_argument("uri", help="for example huggingface://org/model or ./models/fraud")
    src_add.add_argument("--id", dest="source_id", default="", help="a short name for it")
    src_add.add_argument("--connector", default="", help="override the connector inferred from the URI")
    src_add.add_argument("--state", type=Path, default=None)
    src_list = src_sub.add_parser("list", help="what is registered, and when each was last seen")
    src_list.add_argument("--state", type=Path, default=None)
    src_list.add_argument("--json", action="store_true")

    watch = sub.add_parser(
        "watch",
        help="observe a source now, compare it with the stored baseline and record what moved",
    )
    watch.add_argument("source", help="a source id or URI that `source add` registered")
    watch.add_argument("--state", type=Path, default=None)
    watch.add_argument("--json", action="store_true")
    watch.add_argument("--offline", action="store_true",
                       help="refuse to open a socket. A source that only exists over the network "
                            "then reports an incomplete listing, which is what it is")
    watch.add_argument("--max-age-days", type=int, default=0,
                       help="also mark evidence older than this as stale. Off by default: "
                            "freshness is a policy question, and a watch that expired evidence "
                            "would make 'how old may this be' depend on how often it ran")

    snap = sub.add_parser("snapshot", help="print or export the stored snapshot of a source")
    snap.add_argument("source")
    snap.add_argument("--state", type=Path, default=None)
    snap.add_argument("--out", type=Path)
    snap.add_argument("--all", action="store_true", help="every snapshot, oldest first")
    snap.add_argument("--json", action="store_true")

    ev = sub.add_parser("evidence", help="what has been observed, and what is still good")
    ev_sub = ev.add_subparsers(dest="evidence_command", required=True)
    ev_list = ev_sub.add_parser("list", help="every record, with its state and age")
    ev_list.add_argument("--state-is", dest="state_filter", default="",
                         choices=("", "valid", "stale", "superseded", "revoked", "untrusted"))
    ev_list.add_argument("--state", type=Path, default=None)
    ev_list.add_argument("--json", action="store_true")
    ev_show = ev_sub.add_parser("show", help="one subject's evidence, oldest first")
    ev_show.add_argument("subject")
    ev_show.add_argument("--state", type=Path, default=None)
    ev_show.add_argument("--json", action="store_true")

    gph = sub.add_parser("graph", help="the relations between what this workspace knows about")
    gph_sub = gph.add_subparsers(dest="graph_command", required=True)
    gph_show = gph_sub.add_parser("show", help="print the nodes and edges")
    gph_show.add_argument("--state", type=Path, default=None)
    gph_show.add_argument("--json", action="store_true")
    # The same traversal the interface's graph panel calls, so one function
    # answers "what is within two hops of this" on both surfaces. See D-243.
    gph_show.add_argument("--focus", default="", help="an asset id or digest to centre on")
    gph_show.add_argument("--depth", type=int, default=2,
                          help="how many hops from --focus, up to the engine limit")
    gph_show.add_argument("--direction", default=graph_mod.BOTH, choices=graph_mod.DIRECTIONS,
                          help="dependents walks towards what depends on the focus, "
                               "dependencies towards what it depends on")
    gph_export = gph_sub.add_parser("export", help="write the graph as asset-graph/v1")
    gph_export.add_argument("--out", type=Path, required=True)
    gph_export.add_argument("--state", type=Path, default=None)
    gph_build = gph_sub.add_parser(
        "build", help="record the assets and relations a subject manifest declares"
    )
    gph_build.add_argument("--subjects", type=Path, required=True, dest="subjects_manifest")
    gph_build.add_argument("--state", type=Path, default=None)
    gph_build.add_argument("--json", action="store_true")

    imp = sub.add_parser("impact", help="what depends on this, and the exact route that reaches it")
    imp.add_argument("subject", help="an asset id or a digest")
    imp.add_argument("--state", type=Path, default=None)
    imp.add_argument("--json", action="store_true")

    trust = sub.add_parser("trust", help="apply a trust policy, which is not the same as verifying")
    trust_sub = trust.add_subparsers(dest="trust_command", required=True)
    trust_check = trust_sub.add_parser("check", help="decide what this environment accepts")
    trust_check.add_argument("--trust-policy", type=Path, required=True, dest="trust_policy")
    trust_check.add_argument("--agent", type=Path, help="an agent declaration, for the MCP rules")
    trust_check.add_argument("--connector", default="", help="the connector a subject came from")
    trust_check.add_argument("--revision", default="", help="the revision it came from")
    trust_check.add_argument("--signer", default="", help="the signer fingerprint a verifier reported")
    trust_check.add_argument("--declared-digests", choices=("yes", "no"), default=None,
                             dest="declared_digests",
                             help="whether the source published a digest for what it served. "
                                  "Omitted, a rule that requires one is reported as unevaluated "
                                  "rather than silently satisfied")
    trust_check.add_argument("--json", action="store_true")


def dispatch(args: argparse.Namespace, catalog: Catalog) -> int | None:
    handlers = {
        "init": _init,
        "source": _source,
        "watch": _watch,
        "snapshot": _snapshot,
        "evidence": _evidence,
        "graph": _graph,
        "impact": _impact,
        "trust": _trust,
    }
    handler = handlers.get(args.command)
    if handler is None:
        return None
    try:
        return handler(args, catalog)
    except StoreError as exc:
        print(f"{exc}", file=sys.stderr)
        return EXIT_USAGE


def _write_out(path: Path, blob: str) -> None:
    """Write a requested output, creating the directory it was asked for.

    DEF-78. `--out reports/graph.json` before `reports/` existed raised
    `FileNotFoundError` as a traceback. A path the operator typed is a
    statement of where they want the file, not a bet on whether the directory
    is already there.
    """
    path = Path(path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(blob, encoding="utf-8", newline="\n")


def _open(args: argparse.Namespace, *, create: bool = False) -> Store:
    return Store(getattr(args, "state", None) or default_path(), create=create)


# --------------------------------------------------------------------------
# init, source
# --------------------------------------------------------------------------


def _init(args: argparse.Namespace, catalog: Catalog) -> int:
    path = args.state or default_path()
    with Store(path, create=True) as store:
        meta = store.meta()
    if args.json:
        print(json.dumps({"path": str(path), **meta}, ensure_ascii=False, indent=2))
    else:
        print()
        print(f"{path}")
        print(f"  {catalog.line('state.schema', version=meta.get('schema_version', '?'))}")
        print(f"  {catalog.line('state.optional')}")
    return EXIT_OK


def _infer_connector(uri: str) -> str:
    """Which connector a URI belongs to, from its scheme alone.

    Deliberately shallow: a guess that reaches the network to find out would
    make registering a source an online operation, and `source add` has to
    work on a laptop on a train.
    """
    scheme, separator, _ = uri.partition("://")
    if not separator:
        return "filesystem"
    return {"hf": "huggingface", "huggingface": "huggingface", "s3": "s3", "oci": "oci",
            "gh": "github", "github": "github", "mlflow": "mlflow", "file": "filesystem",
            "http": "url", "https": "url"}.get(scheme, scheme)


def _source(args: argparse.Namespace, catalog: Catalog) -> int:
    with _open(args) as store:
        if args.source_command == "add":
            connector = args.connector or _infer_connector(args.uri)
            source_id = args.source_id or _slug(args.uri)
            store.add_source(source_id, connector, args.uri)
            print()
            print(f"  {catalog.line('state.source_added', id=source_id, connector=connector)}")
            print(f"  {args.uri}")
            return EXIT_OK

        rows = store.sources()
        if args.json:
            print(json.dumps(rows, ensure_ascii=False, indent=2))
            return EXIT_OK
        print()
        if not rows:
            print(f"  {catalog.line('state.no_sources')}")
            return EXIT_OK
        for row in rows:
            seen = row["last_seen"] or catalog.line("state.never_observed")
            print(f"  {row['source_id']:<24} {row['connector']:<14} {seen}")
            print(f"  {'':<24} {row['uri']}")
        return EXIT_OK


def _slug(uri: str) -> str:
    cleaned = uri.split("://", 1)[-1].strip("/").replace("/", "-")
    return cleaned or "source-" + hashlib.sha256(uri.encode()).hexdigest()[:8]


# --------------------------------------------------------------------------
# watch
# --------------------------------------------------------------------------


def _watch(args: argparse.Namespace, catalog: Catalog) -> int:
    from .connectors import registry as connector_registry
    from .state.snapshot import snapshot_of
    from .state.watch import ObservationState, observe, stale_sweep

    with _open(args) as store:
        source = store.source(args.source)
        if source is None:
            print(catalog.line("state.unknown_source", id=args.source), file=sys.stderr)
            return EXIT_USAGE

        listing, complete, reason, revision, hosts, local = _list_source(
            connector_registry, source, offline=getattr(args, "offline", False)
        )
        snapshot = snapshot_of(
            source["source_id"],
            source["uri"],
            source["connector"],
            listing,
            revision=revision,
            listing_complete=complete,
            incomplete_because=reason,
            hosts_contacted=hosts,
            # A local source's bytes are right here, so they are read rather
            # than taken on trust. DEF-74: falling back to file size on the
            # default case meant a replaced weight file of the same length
            # came back UNCHANGED.
            measure_local=local,
        )
        observation = observe(store, snapshot)

        expired: list[str] = []
        if args.max_age_days:
            expired = stale_sweep(store, max_age_days=args.max_age_days)

        affected = _affected_by(store, observation)

        if args.json:
            document = observation.to_dict()
            document["stale_evidence"] = sorted(expired)
            document["impact"] = affected
            print(json.dumps(document, ensure_ascii=False, indent=2))
        else:
            _print_observation(observation, expired, affected, catalog)

    return {
        ObservationState.INCOMPLETE: EXIT_INCONCLUSIVE,
        ObservationState.CONTENT_DRIFT: EXIT_FAIL,
    }.get(observation.state, EXIT_OK)


def _list_source(connector_registry: Any, source: dict[str, Any], *, offline: bool = False):
    """Ask the connector what is there, and be explicit when it could not say.

    Every failure path here ends in `complete=False` with a reason, never in
    an empty listing. An exception swallowed into "no artifacts" would be read
    by `observe` as every artifact having been deleted - the single most
    destructive false report this tool could produce, and the one the roadmap
    names: a network failure must not invalidate what was observed before.
    """
    from .connectors.model import Http

    try:
        connector = connector_registry.for_uri(source["uri"])
    except Exception as exc:  # noqa: BLE001 - any failure is an incomplete listing
        return [], False, f"no connector could read {source['uri']}: {exc}", "", [], False
    try:
        result = connector.discover(source["uri"], http=Http(offline=offline), revision=None)
    except Exception as exc:  # noqa: BLE001 - see the docstring
        return (
            [], False,
            f"{connector.name} could not list the source: {type(exc).__name__}: {exc}",
            "", [], False,
        )

    artifacts = [artifact.to_dict() for artifact in result.artifacts]
    reason = "; ".join(result.notes) if not result.complete else ""
    if not result.complete and not reason:
        reason = f"{connector.name} reported an incomplete listing and did not say why"
    return (
        artifacts,
        bool(result.complete),
        reason,
        str(result.revision or ""),
        list(result.hosts_contacted),
        not connector.needs_network,
    )


def _affected_by(store: Store, observation: Any) -> dict[str, Any]:
    if not observation.changed_anything:
        return {"affected": [], "by_kind": {}}
    graph = graph_mod.Graph.from_store(store)
    return graph_mod.impact(graph, f"source:{observation.source_id}")


_STATE_MARK = {
    "baseline": "=",
    "unchanged": ".",
    "source_drift": "~",
    "content_drift": "!",
    "incomplete": "?",
}


def _print_observation(observation: Any, expired: list[str], affected: dict[str, Any], catalog: Catalog) -> None:
    print()
    print(f"SOURCE      {observation.uri}")
    if observation.previous_revision or observation.snapshot.revision:
        print(
            f"REVISION    {observation.previous_revision or '-'} -> "
            f"{observation.snapshot.revision or '-'}"
        )
    mark = _STATE_MARK[observation.state.value]
    print(f"STATE       {mark} {catalog.line('watch.state.' + observation.state.value)}")
    if observation.note:
        print(f"            {observation.note}")
    print()

    if observation.changed_anything:
        print(f"  {catalog.line('watch.changed_subjects')}")
        for uri in observation.added:
            print(f"    + {uri}")
        for uri in observation.changed:
            print(f"    ~ {uri}")
        for uri in observation.removed:
            print(f"    - {uri}")
        print()

    if observation.superseded_evidence or expired:
        print(f"  {catalog.line('watch.evidence')}")
        if observation.superseded_evidence:
            print(f"    {catalog.line('watch.superseded', n=len(observation.superseded_evidence))}")
        if expired:
            print(f"    {catalog.line('watch.stale', n=len(expired))}")
        print()

    rows = affected.get("affected", [])
    if rows:
        print(f"  {catalog.line('watch.impact')}")
        for row in rows[:12]:
            print(f"    {row['asset']}")
        print()
        print(f"  {catalog.line('watch.why')}")
        for row in rows[:3]:
            print(f"    {row['why']}")


# --------------------------------------------------------------------------
# snapshot, evidence, graph, impact
# --------------------------------------------------------------------------


def _snapshot(args: argparse.Namespace, catalog: Catalog) -> int:
    with _open(args) as store:
        source = store.source(args.source)
        if source is None:
            print(catalog.line("state.unknown_source", id=args.source), file=sys.stderr)
            return EXIT_USAGE
        if args.all:
            rows = store.snapshots(source["source_id"])
        else:
            # One query, not two: the expression this replaces called
            # `latest_snapshot` in the condition and again in the value.
            latest = store.latest_snapshot(source["source_id"])
            rows = [latest] if latest is not None else []
        if not rows:
            print(catalog.line("state.never_observed"), file=sys.stderr)
            return EXIT_INCONCLUSIVE
        documents = [json.loads(row["document"]) for row in rows]
        blob = json.dumps(documents if args.all else documents[0], ensure_ascii=False, indent=2)
        if args.out is not None:
            _write_out(args.out, blob + "\n")
        print(blob)
    return EXIT_OK


def _evidence(args: argparse.Namespace, catalog: Catalog) -> int:
    with _open(args) as store:
        if args.evidence_command == "show":
            rows = store.evidence_for(args.subject)
        else:
            rows = store.all_evidence(args.state_filter or None)
        # The exit code is computed once and returned from every branch.
        # DEF-76: `--json` used to return EXIT_OK before reaching the
        # computation, so the one mode a pipeline reads never signalled - and
        # the comment below says the code exists precisely so a pipeline need
        # not parse the text.
        code = EXIT_FAIL if any(row["state"] != "valid" for row in rows) else EXIT_OK
        if args.json:
            print(json.dumps(rows, ensure_ascii=False, indent=2, default=str))
            return code
        print()
        if not rows:
            print(f"  {catalog.line('state.no_evidence')}")
            return code
        for row in rows:
            print(
                f"  {row['evidence_id']:<36} {row['state']:<11} {row['kind']:<16} {row['subject_id']}"
            )
            print(f"  {'':<36} {row['observed_at']}")
        counts: dict[str, int] = {}
        for row in rows:
            counts[row["state"]] = counts.get(row["state"], 0) + 1
        print()
        print("  " + ", ".join(f"{count} {state}" for state, count in sorted(counts.items())))
    # Evidence that is not VALID is not a failure of this command; it is what
    # the command was asked to report. The exit code says "something here
    # needs attention" so a pipeline can act on it without parsing the text.
    return code


def _graph(args: argparse.Namespace, catalog: Catalog) -> int:
    with _open(args) as store:
        if args.graph_command == "build":
            return _graph_build(args, catalog, store)
        graph = graph_mod.Graph.from_store(store)
        view = None
        if getattr(args, "focus", ""):
            view = graph_mod.neighbourhood(
                graph, args.focus, depth=args.depth, direction=args.direction
            )
            graph = graph_mod.subgraph(graph, view)
        document = graph.to_dict()
        if view is not None:
            # Beside the graph rather than inside it: `asset-graph/v1` is a
            # published contract and a view is a question somebody asked of
            # it, not a new kind of graph.
            document["view"] = view.to_dict()
        if args.graph_command == "export":
            _write_out(args.out, json.dumps(document, ensure_ascii=False, indent=2) + "\n")
            print(f"  {catalog.line('state.graph_written', path=str(args.out), n=len(document['edges']))}")
            return EXIT_OK
        if args.json:
            print(json.dumps(document, ensure_ascii=False, indent=2))
            return EXIT_OK
        print()
        for edge in document["edges"]:
            print(f"  {edge['from']}  --{edge['relation']}-->  {edge['to']}")
            print(f"      {catalog.line('state.stated_by', who=edge['stated_by'])}")
        if not document["edges"]:
            print(f"  {catalog.line('state.no_edges')}")
        for cycle in document["cycles"]:
            print(f"  {catalog.line('state.cycle', route=' -> '.join(cycle))}")
        if view is not None and not view.found:
            # Never "nothing is connected to it". A node this store has never
            # seen has no recorded relations, which is not a proof that it has
            # none - the same distinction `impact` makes.
            print(f"  {catalog.line('state.unknown_asset')}")
            return EXIT_INCONCLUSIVE
        if view is not None and view.truncated:
            print(f"  {catalog.line('state.truncated')}")
    return EXIT_OK


def _graph_build(args: argparse.Namespace, catalog: Catalog, store: Store) -> int:
    """Record what a manifest declares, and nothing it does not.

    Two sources of edges and both are declarations. The manifest's own `uses`
    lines, and the relations an agent declaration states about its own parts
    (D-202). Nothing is inferred from two assets sharing a name, a registry or
    a manifest - see D-224 for why an impact report that guessed would be
    worse than none.
    """
    from . import manifest as manifest_mod
    from .agentgov import DeclarationError
    # One `try` around the load AND the walk. DEF-77: the guard used to wrap
    # only `manifest_mod.load`, so an agent file that did not parse - reached
    # a few lines further down, inside the transaction - came back as a raw
    # traceback, where the identical error one step earlier came back as a
    # message and exit 2.
    try:
        document = manifest_mod.load(args.subjects_manifest)
        recorded, edges = _record_manifest(store, document, args.subjects_manifest)
    except (manifest_mod.ManifestError, DeclarationError) as exc:
        print(f"{args.subjects_manifest}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.json:
        print(json.dumps({"assets": recorded, "edges": edges}, indent=2))
    else:
        print()
        print(f"  {catalog.line('state.graph_built', assets=recorded, edges=edges)}")
    return EXIT_OK


def _record_manifest(store: Store, document: Any, manifest_path: Path) -> tuple[int, int]:
    from . import manifest as manifest_mod
    from .agentgov import load as load_agent
    from .bundle import resolve as resolve_bundle
    from .subject import SubjectKind

    recorded, edges = 0, 0
    with store.transaction() as connection:
        for entry in document.entries:
            node = manifest_mod.handle(entry, document.system)
            digest, attributes = "", {}
            if entry.kind is SubjectKind.BUNDLE and entry.path is not None:
                bundle = resolve_bundle(entry.path, hash_weights=entry.hash_weights)
                identity = bundle.content_identity()
                # The content digest when there is one, the layout digest
                # otherwise, and the state recorded beside it so a reader of
                # the graph is never left guessing which they are looking at.
                digest = identity["digest"] or bundle.structural_digest
                attributes = {"content_identity": identity["state"], "members": len(bundle.members)}
            elif entry.kind is SubjectKind.AGENT and entry.path is not None:
                agent = load_agent(entry.path)
                digest = agent.digest
                attributes = {"version": agent.version, "effects": sorted(e.value for e in agent.effects)}
                # The declared relations, and the declared membership. The
                # second list is separate in the model because it is not part
                # of the A-BOM or the agent digest (see
                # `Agent.membership_relations`), and it is recorded here
                # because without it a tool, an MCP server or an identity sits
                # in the graph with no edge back to the agent that declared
                # it - so `impact` on any of them reached nothing.
                for edge in agent.relations() + agent.membership_relations():
                    store.add_edge(
                        edge.source if edge.source != f"agent:{agent.name}" else node,
                        _map_relation(edge.relation),
                        edge.target,
                        stated_by=f"declaration {entry.path.name}",
                        connection=connection,
                    )
                    edges += 1
            elif entry.kind is SubjectKind.SOURCE:
                attributes = {"connector": entry.connector, "revision": entry.revision}

            store.upsert_asset(
                node,
                entry.kind.value,
                entry.name or (entry.path.name if entry.path else entry.uri),
                digest=digest,
                attributes=attributes,
                connection=connection,
            )
            recorded += 1

        for entry in document.entries:
            node = manifest_mod.handle(entry, document.system)
            for target in entry.uses:
                store.add_edge(
                    node, "uses", target,
                    stated_by=f"manifest {Path(manifest_path).name}",
                    connection=connection,
                )
                edges += 1

    return recorded, edges


# The agent vocabulary and the graph vocabulary overlap but are not identical:
# the graph has to describe systems and sources too. Mapped explicitly rather
# than by assuming the two lists stay equal, because they will not.
_RELATION_MAP = {"uses_model": "uses_model", "runs_as": "runs_as", "reads": "reads",
                 "writes": "writes", "exposes": "exposes", "delegates_to": "delegates_to"}


def _map_relation(relation: str) -> str:
    return _RELATION_MAP.get(relation, "uses")


def _impact(args: argparse.Namespace, catalog: Catalog) -> int:
    with _open(args) as store:
        graph = graph_mod.Graph.from_store(store)
        document = graph_mod.impact(graph, args.subject)
        if args.json:
            print(json.dumps(document, ensure_ascii=False, indent=2))
            return EXIT_OK
        print()
        print(f"{document['changed']}")
        if not document["found"]:
            # Said plainly rather than reported as "nothing is affected". A
            # subject this store has never seen has no dependents recorded,
            # which is not the same as having none.
            print(f"  {catalog.line('state.unknown_asset')}")
            return EXIT_INCONCLUSIVE
        print()
        if not document["affected"]:
            print(f"  {catalog.line('state.nothing_affected')}")
            return EXIT_OK
        print(f"  {catalog.line('state.affected')}")
        for kind, count in document["by_kind"].items():
            print(f"    {count} {kind}")
        print()
        print(f"  {catalog.line('state.reevaluate')}")
        for row in document["affected"]:
            print(f"    {row['asset']}")
        print()
        print(f"  {catalog.line('watch.why')}")
        for row in document["affected"]:
            print(f"    {row['why']}")
        if document["truncated"]:
            print()
            print(f"  {catalog.line('state.truncated')}")
    return EXIT_FAIL if document["affected"] else EXIT_OK


def _trust(args: argparse.Namespace, catalog: Catalog) -> int:
    from . import trustpolicy

    try:
        policy = trustpolicy.load(args.trust_policy)
    except trustpolicy.TrustPolicyError as exc:
        print(f"{args.trust_policy}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    servers = []
    if args.agent:
        from .agentgov import DeclarationError
        from .agentgov import load as load_agent

        try:
            servers = load_agent(args.agent).mcp_servers
        except DeclarationError as exc:
            print(f"{args.agent}: {exc}", file=sys.stderr)
            return EXIT_USAGE

    declared = getattr(args, "declared_digests", None)
    result = trustpolicy.check(
        policy,
        signer_fingerprint=args.signer,
        connector=args.connector,
        revision=args.revision,
        declared_digests=None if declared is None else declared == "yes",
        mcp_servers=servers,
    )
    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print()
        print(f"TRUST       {result.state.value.upper()}")
        for reason in result.reasons:
            print(f"  {reason}")
        for pending in result.unevaluated:
            print(f"  ? {pending}")
        for note in result.notes:
            print(f"  . {note}")
        if result.checked:
            print()
            print(f"  {catalog.line('state.trust_checked', what=', '.join(result.checked))}")
    return {
        trustpolicy.TrustState.TRUSTED: EXIT_OK,
        trustpolicy.TrustState.UNTRUSTED: EXIT_FAIL,
        trustpolicy.TrustState.UNKNOWN: EXIT_INCONCLUSIVE,
    }[result.state]


