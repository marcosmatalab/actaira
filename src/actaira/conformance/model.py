"""The objects an agent is made of, each versioned and each digestible.

Design note D-141. Everything here is identified by a digest over its own
declaration, not by its name. The reason is drift: a tool called
`search_tickets` in March and a tool called `search_tickets` in September are
the same name over possibly very different behaviour, and an approved-tool
baseline that matched on names would approve the September one because it
approved the March one. Digests make "this is the tool you reviewed" a
checkable statement.

`Effect` is the vocabulary the capability rules reason over, and it is
deliberately about consequences rather than implementations. Whether a tool
reaches the network through HTTP, a database driver or an MCP server does not
change what a policy needs to know, which is that bytes can leave. A taxonomy
organised by implementation would need a new entry for every new transport and
would still miss the first one nobody thought of.

Design note D-202 is the 2.2 half of this file. v1 declared the parts and left
the relations between them to convention: a tool's `scopes` were compared with
data source names by string, and which identity a tool ran as was not
expressible at all. That made the most valuable mitigation in this whole area
- "the tool that reads secrets runs as an identity the tool that talks to the
internet does not have" - unprovable, because there was nowhere to write it
down. So the relations are declared, validated against the same document, and
emitted as edges: `tool -> identity`, `tool -> data source` in each direction,
`mcp server -> tool`, `agent -> sub-agent`. A rule may then say "these two
capabilities are reachable under one identity" and point at the edges that
make it true, instead of inferring it from two strings that happened to match.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..model import canonical_json
from .vocabulary import VOCABULARY_VERSION, Access, Classification

SCHEMA_VERSION = "agent-bom/v2"

# Why v2: `sub_agents` used to be a list of strings and is now a list of
# objects, and `data_sources[].classification` used to be any string and is now
# a checked vocabulary. Both are changes of meaning, which `docs/COMPATIBILITY.md`
# says is a major. v1 stays published and readable.
LEGACY_SCHEMA_VERSION = "agent-bom/v1"


class Effect(str, Enum):
    """What a tool can cause, stated as consequences rather than mechanisms.

    `UNTRUSTED_INPUT` is the one that is not a power. It marks a tool whose
    output reaches the model and is authored by somebody outside the trust
    boundary: a web page, an inbox, a ticket comment, a pull request body. It
    is in this list because every serious agent incident is a combination
    involving it, and a taxonomy that recorded only powers would be unable to
    express the combination at all.
    """

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    NETWORK = "network"
    EXEC = "exec"
    SECRETS = "secrets"
    SEND = "send"
    PAY = "pay"
    UNTRUSTED_INPUT = "untrusted_input"


# The effects that carry data out of the agent's boundary. An attack path ends
# at one of these; a capability that only reads is not a sink.
SINK_EFFECTS = (Effect.NETWORK, Effect.SEND, Effect.PAY, Effect.WRITE, Effect.DELETE, Effect.EXEC)

# The effects that bring material worth stealing into reach.
SENSITIVE_EFFECTS = (Effect.SECRETS, Effect.EXEC, Effect.PAY, Effect.DELETE)


def _digest(payload: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(payload)).hexdigest()


@dataclass(frozen=True)
class Tool:
    """One capability the agent can invoke, and what invoking it can cause.

    `identity`, `inputs` and `outputs` are the 2.2 additions, and all three
    are references into the same declaration rather than free text. The loader
    refuses a dangling one: a tool that says it runs as `triage-bot` when no
    such identity is declared is a typo, and a typo that silently produced "no
    identity binding" would make the mitigation look absent when it was only
    misspelt.
    """

    name: str
    effects: tuple[Effect, ...] = ()
    description: str = ""
    scopes: tuple[str, ...] = ()
    environment: str = ""
    requires_approval: bool = False
    schema_sha256: str = ""
    identity: str = ""
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    served_by: str = ""

    @property
    def digest(self) -> str:
        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "effects": [effect.value for effect in self.effects],
            "requires_approval": self.requires_approval,
        }
        if self.description:
            payload["description"] = self.description
        if self.scopes:
            payload["scopes"] = list(self.scopes)
        if self.environment:
            payload["environment"] = self.environment
        if self.schema_sha256:
            payload["schema_sha256"] = self.schema_sha256
        if self.identity:
            payload["identity"] = self.identity
        if self.inputs:
            payload["inputs"] = list(self.inputs)
        if self.outputs:
            payload["outputs"] = list(self.outputs)
        if self.served_by:
            payload["served_by"] = self.served_by
        return payload


@dataclass(frozen=True)
class McpServer:
    """An MCP server the agent dials, and how firmly it is pinned.

    `reference` is whatever the deployment actually uses - an image, a package
    spec, a URL. `pinned` is the question that matters: a reference resolving
    to a tag resolves to different bytes tomorrow, so an approved server is
    only approved until somebody pushes.
    """

    name: str
    reference: str
    publisher: str = ""
    digest: str = ""
    transport: str = ""
    tools: tuple[str, ...] = ()

    @property
    def pinned(self) -> bool:
        return bool(self.digest) or "@sha256:" in self.reference

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": self.name, "reference": self.reference, "pinned": self.pinned}
        for key, value in (
            ("publisher", self.publisher),
            ("digest", self.digest),
            ("transport", self.transport),
        ):
            if value:
                payload[key] = value
        if self.tools:
            payload["tools"] = list(self.tools)
        return payload


@dataclass(frozen=True)
class Identity:
    """A credential the agent runs as."""

    name: str
    kind: str = "service_account"
    scopes: tuple[str, ...] = ()
    expires: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": self.name, "kind": self.kind}
        if self.scopes:
            payload["scopes"] = list(self.scopes)
        if self.expires:
            payload["expires"] = self.expires
        return payload


@dataclass(frozen=True)
class DataSource:
    """Something the agent reads from or writes to, and how it is classified.

    `classification` and `access` come from the versioned vocabulary in
    `vocabulary.py`, or carry an explicit namespace. See D-201 for why a free
    string was not good enough for two fields the rules compare.
    """

    name: str
    classification: str = Classification.UNKNOWN.value
    access: str = Access.READ.value
    trusted: bool = True

    @property
    def sensitivity(self) -> int:
        """How much a disclosure costs, or -1 when the word is not ours.

        A namespaced classification is a word this tool does not understand.
        Ranking it would be inventing knowledge, so it ranks below nothing and
        the rules that use it treat it as unevaluable rather than harmless.
        """
        try:
            return Classification(self.classification).rank
        except ValueError:
            return -1

    @property
    def mutable(self) -> bool:
        try:
            return Access(self.access).mutates
        except ValueError:
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "classification": self.classification,
            "access": self.access,
            "trusted": self.trusted,
        }


@dataclass(frozen=True)
class SubAgent:
    """Another agent this one can call, referenced rather than merely named.

    D-202. v1 said `sub_agents: [research-bot]`, which records that something
    called research-bot is involved and nothing else: not which version, not
    what it can do, not whether the thing running in production is the thing
    that was reviewed. The capabilities of a sub-agent are the capabilities of
    the agent that calls it, so a declaration that cannot identify its
    sub-agents cannot state its own powers.

    `declaration` points at another declaration file, so `agent check` can
    expand the tree; `digest` pins which one. A sub-agent with a declaration
    and no digest is still useful and says so - the expansion happens, and the
    report states that nothing bound it to a reviewed version.
    """

    name: str
    reference: str = ""
    digest: str = ""
    declaration: str = ""

    @property
    def pinned(self) -> bool:
        return bool(self.digest)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": self.name, "pinned": self.pinned}
        for key, value in (
            ("reference", self.reference),
            ("digest", self.digest),
            ("declaration", self.declaration),
        ):
            if value:
                payload[key] = value
        return payload


# The relation vocabulary. Every edge this package emits uses one of these, and
# `release_check.py` asserts each is documented and translated - an edge kind
# that appears in a graph view under a name nobody defined is how a diagram
# starts meaning different things to different readers.
RELATIONS = (
    "runs_as",
    "reads",
    "writes",
    "exposes",
    "delegates_to",
    "uses_model",
)


@dataclass(frozen=True)
class Relation:
    """One declared edge, with the reason it is in the graph.

    `stated_by` is what makes the graph auditable: an edge that came out of a
    declaration is a claim its author made, and an edge this tool inferred is
    a different kind of thing. Keeping them apart is the same discipline the
    rest of Actaira applies to measured against declared.
    """

    source: str
    relation: str
    target: str
    stated_by: str = "declaration"

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.source,
            "relation": self.relation,
            "to": self.target,
            "stated_by": self.stated_by,
        }


@dataclass
class Agent:
    """The whole thing, as one versioned object."""

    name: str
    version: str = ""
    model: str = ""
    model_digest: str = ""
    prompt_sha256: str = ""
    environment: str = ""
    owner: str = ""
    tools: list[Tool] = field(default_factory=list)
    mcp_servers: list[McpServer] = field(default_factory=list)
    identities: list[Identity] = field(default_factory=list)
    data_sources: list[DataSource] = field(default_factory=list)
    sub_agents: list[SubAgent] = field(default_factory=list)
    source: str = ""
    # Findings raised while loading: relations that do not resolve, and other
    # gaps that are worth reporting but not worth refusing a file over.
    declaration_findings: list[Any] = field(default_factory=list)

    @property
    def effects(self) -> set[Effect]:
        collected: set[Effect] = set()
        for tool in self.tools:
            collected.update(tool.effects)
        return collected

    def tools_with(self, effect: Effect) -> list[Tool]:
        return [tool for tool in self.tools if effect in tool.effects]

    def tool(self, name: str) -> Tool | None:
        for item in self.tools:
            if item.name == name:
                return item
        return None

    def data_source(self, name: str) -> DataSource | None:
        for item in self.data_sources:
            if item.name == name:
                return item
        return None

    def identity(self, name: str) -> Identity | None:
        for item in self.identities:
            if item.name == name:
                return item
        return None

    def relations(self) -> list[Relation]:
        """Every declared edge, sorted, ready for the graph.

        Only what the declaration says. Nothing here infers an edge from a
        name that looks like another name - that was the v1 convention this
        replaces, and its failure mode was a mitigation that appeared to be in
        place because two strings matched.
        """
        node = f"agent:{self.name}"
        edges: list[Relation] = []
        if self.model:
            edges.append(Relation(node, "uses_model", f"model:{self.model}"))
        for tool in self.tools:
            handle = f"tool:{tool.name}"
            if tool.identity:
                edges.append(Relation(handle, "runs_as", f"identity:{tool.identity}"))
            for name in tool.inputs:
                edges.append(Relation(handle, "reads", f"data:{name}"))
            for name in tool.outputs:
                edges.append(Relation(handle, "writes", f"data:{name}"))
        for server in self.mcp_servers:
            for name in server.tools:
                edges.append(Relation(f"mcp:{server.name}", "exposes", f"tool:{name}"))
        for sub in self.sub_agents:
            edges.append(Relation(node, "delegates_to", f"agent:{sub.name}"))
        return sorted(edges, key=lambda edge: (edge.source, edge.relation, edge.target))

    def membership_relations(self) -> list[Relation]:
        """What this declaration says the agent is made of, for the asset graph.

        Deliberately not part of `relations()`, and therefore not part of the
        A-BOM or of `digest`. That separation is the whole point of this
        method existing rather than the four lines being added above.

        The connectivity problem it solves is real and was measured rather
        than supposed: the declaration shipped in `examples/` has five tools,
        two MCP servers, one identity and two data sources, and contributes
        exactly one edge to the stored graph, because `relations()` links a
        tool to an identity only when the tool names one and links an agent to
        nothing but its model and its sub-agents. So `impact` on a tool could
        not reach the agent that runs it, and an operator asking what a
        compromised MCP server affects was told nothing depends on it.

        The fix is not inference. An agent declaration listing a tool is that
        declaration stating the agent has that tool; the edge is read off the
        document, exactly as every other edge in this file is, and the
        graph-build layer stamps it with the declaration it came from.

        What must not happen is this improving the graph and moving the number
        that answers "is this the agent that was approved?". `digest` is over
        `to_bom()`, `to_bom()` carries `relations()`, and neither has changed.
        `tests/test_conformance.py` pins the shipped example's digest to a
        literal so that stays true by failure rather than by intention.
        """
        node = f"agent:{self.name}"
        edges = [Relation(node, "uses", f"tool:{tool.name}") for tool in self.tools]
        edges += [Relation(node, "uses", f"mcp:{server.name}") for server in self.mcp_servers]
        edges += [Relation(node, "uses", f"identity:{identity.name}") for identity in self.identities]
        # `uses` rather than `reads` or `writes`. The access mode is declared
        # per data source and the tool-level `inputs`/`outputs` are what say
        # which tool touches which; an agent-level edge that picked a
        # direction out of the `access:` field would be stating something the
        # document does not, which is the failure D-224 is written against.
        edges += [Relation(node, "uses", f"data:{source.name}") for source in self.data_sources]
        return sorted(edges, key=lambda edge: (edge.source, edge.relation, edge.target))

    @property
    def digest(self) -> str:
        """The digest of the agent's whole declared shape.

        This is the number that answers "is this the agent that was
        approved?". It moves when a tool is added, when a tool's effects
        change, when an MCP server's reference changes, when the system prompt
        changes, and when the model does - which is the complete list of
        things that change what the agent can do.
        """
        return _digest(self.to_bom())

    def to_bom(self) -> dict[str, Any]:
        """The A-BOM: the agent equivalent of an ML-BOM.

        A list a reader can diff between two releases to see what gained a
        capability. Sorted everywhere, so two runs over the same declaration
        produce byte-identical output and a diff shows only real change.
        """
        return {
            "schema_version": SCHEMA_VERSION,
            "vocabulary": VOCABULARY_VERSION,
            "agent": {
                "name": self.name,
                "version": self.version,
                "environment": self.environment,
                "owner": self.owner,
            },
            "model": {"reference": self.model, "digest": self.model_digest or None},
            "prompt": {"sha256": self.prompt_sha256 or None},
            "tools": sorted((tool.to_dict() for tool in self.tools), key=lambda row: row["name"]),
            "mcp_servers": sorted(
                (server.to_dict() for server in self.mcp_servers), key=lambda row: row["name"]
            ),
            "identities": sorted(
                (identity.to_dict() for identity in self.identities), key=lambda row: row["name"]
            ),
            "data_sources": sorted(
                (source.to_dict() for source in self.data_sources), key=lambda row: row["name"]
            ),
            "sub_agents": sorted((sub.to_dict() for sub in self.sub_agents), key=lambda row: row["name"]),
            "relations": [edge.to_dict() for edge in self.relations()],
            "effects": sorted(effect.value for effect in self.effects),
        }


@dataclass
class AgentBom:
    """An A-BOM with its digest, ready to sign or to diff."""

    agent: Agent

    def to_dict(self) -> dict[str, Any]:
        document = self.agent.to_bom()
        document["agent_digest"] = self.agent.digest
        return document


# --------------------------------------------------------------------------
# Diff
# --------------------------------------------------------------------------


def _changed(before: Any, after: Any) -> dict[str, Any] | None:
    return None if before == after else {"from": before, "to": after}


def _by_name(items) -> dict[str, Any]:
    return {item.name: item for item in items}


def _mcp_changes(before: McpServer, after: McpServer) -> dict[str, Any] | None:
    """Why one MCP server with one name is not the same server it was.

    Design note D-203, and the gap ACT22-P0-04 names. v1 reported `mcp_added` and
    `mcp_removed`, so a server whose name stayed `github` while its reference
    moved from a reviewed digest to `:latest` produced an empty MCP section
    and a changed agent digest. The reviewer saw "something changed" and had
    to diff two YAML files by hand to find out what - which is the one thing a
    change-review tool exists to save them from.
    """
    entry: dict[str, Any] = {"name": after.name}
    for field_name, old, new in (
        ("reference", before.reference, after.reference),
        ("digest", before.digest, after.digest),
        ("publisher", before.publisher, after.publisher),
        ("transport", before.transport, after.transport),
    ):
        delta = _changed(old, new)
        if delta:
            entry[field_name] = delta
    tools_before, tools_after = set(before.tools), set(after.tools)
    if tools_after - tools_before:
        entry["tools_added"] = sorted(tools_after - tools_before)
    if tools_before - tools_after:
        entry["tools_removed"] = sorted(tools_before - tools_after)
    pinning = _changed(before.pinned, after.pinned)
    if pinning:
        entry["pinned"] = pinning
    return entry if len(entry) > 1 else None


def _tool_changes(before: Tool, after: Tool) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": after.name,
        "effects_gained": sorted(
            effect.value for effect in set(after.effects) - set(before.effects)
        ),
        "effects_lost": sorted(
            effect.value for effect in set(before.effects) - set(after.effects)
        ),
    }
    for field_name, old, new in (
        ("scopes", set(before.scopes), set(after.scopes)),
        ("inputs", set(before.inputs), set(after.inputs)),
        ("outputs", set(before.outputs), set(after.outputs)),
    ):
        if new - old:
            entry[f"{field_name}_added"] = sorted(new - old)
        if old - new:
            entry[f"{field_name}_removed"] = sorted(old - new)
    # Its own names: the loop above walks sets and this one walks scalars, and
    # sharing `old`/`new` between them asks a reader, and a checker, to believe
    # one variable is two types.
    for scalar_name, was, now in (
        ("identity", before.identity, after.identity),
        ("served_by", before.served_by, after.served_by),
        ("requires_approval", before.requires_approval, after.requires_approval),
        ("schema_sha256", before.schema_sha256, after.schema_sha256),
        ("environment", before.environment, after.environment),
    ):
        delta = _changed(was, now)
        if delta:
            entry[scalar_name] = delta
    return entry


def _identity_changes(before: Identity, after: Identity) -> dict[str, Any] | None:
    entry: dict[str, Any] = {"name": after.name}
    scopes_before, scopes_after = set(before.scopes), set(after.scopes)
    if scopes_after - scopes_before:
        entry["scopes_added"] = sorted(scopes_after - scopes_before)
    if scopes_before - scopes_after:
        entry["scopes_removed"] = sorted(scopes_before - scopes_after)
    for field_name, old, new in (("kind", before.kind, after.kind), ("expires", before.expires, after.expires)):
        delta = _changed(old, new)
        if delta:
            entry[field_name] = delta
    return entry if len(entry) > 1 else None


def _data_source_changes(before: DataSource, after: DataSource) -> dict[str, Any] | None:
    entry: dict[str, Any] = {"name": after.name}
    for field_name, old, new in (
        ("classification", before.classification, after.classification),
        ("access", before.access, after.access),
        ("trusted", before.trusted, after.trusted),
    ):
        delta = _changed(old, new)
        if delta:
            entry[field_name] = delta
    return entry if len(entry) > 1 else None


def _sub_agent_changes(before: SubAgent, after: SubAgent) -> dict[str, Any] | None:
    entry: dict[str, Any] = {"name": after.name}
    for field_name, old, new in (
        ("digest", before.digest, after.digest),
        ("reference", before.reference, after.reference),
        ("declaration", before.declaration, after.declaration),
    ):
        delta = _changed(old, new)
        if delta:
            entry[field_name] = delta
    return entry if len(entry) > 1 else None


def _risk_of_metadata(field_name: str, before: Any, after: Any) -> str:
    """Whether a metadata change makes the agent's blast radius larger.

    Three values and no scale. `increase` means the same declaration now
    applies somewhere it matters more, or stops naming somebody accountable;
    `decrease` is the reverse; `neutral` is everything else. This is a
    classification of the change, not a rating of the agent - a version bump
    is neutral and that is all this is ever asked to say.
    """
    if field_name == "environment":
        if str(after).lower() in ("production", "prod"):
            return "increase"
        if str(before).lower() in ("production", "prod"):
            return "decrease"
        return "neutral"
    if field_name == "owner":
        if not after:
            return "increase"
        if not before:
            return "decrease"
    return "neutral"


def diff(before: Agent, after: Agent) -> dict[str, Any]:
    """What changed between two versions of one agent, in full.

    The output a change-review workflow reads. Effects gained are listed
    separately from tools added, because the two questions are different: a
    new tool that only reads is a smaller change than an existing tool that
    quietly gained `write`, and a diff that only listed names would show the
    first and miss the second.

    Design note D-203. Everything a digest covers is now explained, because the digest
    changing and nothing else being reported is the worst possible output of a
    change-review tool: it tells the reviewer that something matters and
    refuses to say what. The sections are stable and empty ones are kept, so a
    consumer can read `diff["mcp_changed"]` without guarding for its absence.
    """
    before_tools, after_tools = _by_name(before.tools), _by_name(after.tools)
    tool_names = sorted(
        name
        for name in set(before_tools) & set(after_tools)
        if before_tools[name].digest != after_tools[name].digest
    )

    before_mcp, after_mcp = _by_name(before.mcp_servers), _by_name(after.mcp_servers)
    mcp_changed = [
        entry
        for name in sorted(set(before_mcp) & set(after_mcp))
        if (entry := _mcp_changes(before_mcp[name], after_mcp[name])) is not None
    ]

    before_ids, after_ids = _by_name(before.identities), _by_name(after.identities)
    identities_changed = [
        entry
        for name in sorted(set(before_ids) & set(after_ids))
        if (entry := _identity_changes(before_ids[name], after_ids[name])) is not None
    ]

    before_data, after_data = _by_name(before.data_sources), _by_name(after.data_sources)
    data_changed = [
        entry
        for name in sorted(set(before_data) & set(after_data))
        if (entry := _data_source_changes(before_data[name], after_data[name])) is not None
    ]

    before_subs, after_subs = _by_name(before.sub_agents), _by_name(after.sub_agents)
    subs_changed = [
        entry
        for name in sorted(set(before_subs) & set(after_subs))
        if (entry := _sub_agent_changes(before_subs[name], after_subs[name])) is not None
    ]

    metadata_changed = []
    for field_name, old, new in (
        ("version", before.version, after.version),
        ("environment", before.environment, after.environment),
        ("owner", before.owner, after.owner),
    ):
        if old != new:
            metadata_changed.append(
                {"field": field_name, "from": old, "to": new, "risk": _risk_of_metadata(field_name, old, new)}
            )

    before_edges = {(edge.source, edge.relation, edge.target) for edge in before.relations()}
    after_edges = {(edge.source, edge.relation, edge.target) for edge in after.relations()}

    document: dict[str, Any] = {
        "agent": after.name,
        "from_digest": before.digest,
        "to_digest": after.digest,
        "tools_added": sorted(set(after_tools) - set(before_tools)),
        "tools_removed": sorted(set(before_tools) - set(after_tools)),
        "tools_changed": [_tool_changes(before_tools[name], after_tools[name]) for name in tool_names],
        "effects_gained": sorted(effect.value for effect in after.effects - before.effects),
        "effects_lost": sorted(effect.value for effect in before.effects - after.effects),
        "mcp_added": sorted(set(after_mcp) - set(before_mcp)),
        "mcp_removed": sorted(set(before_mcp) - set(after_mcp)),
        "mcp_changed": mcp_changed,
        "identities_added": sorted(set(after_ids) - set(before_ids)),
        "identities_removed": sorted(set(before_ids) - set(after_ids)),
        "identities_changed": identities_changed,
        "data_sources_added": sorted(set(after_data) - set(before_data)),
        "data_sources_removed": sorted(set(before_data) - set(after_data)),
        "data_sources_changed": data_changed,
        "sub_agents_added": sorted(set(after_subs) - set(before_subs)),
        "sub_agents_removed": sorted(set(before_subs) - set(after_subs)),
        "sub_agents_changed": subs_changed,
        "relations_added": _edges(after_edges - before_edges),
        "relations_removed": _edges(before_edges - after_edges),
        "metadata_changed": metadata_changed,
        "model_changed": before.model_digest != after.model_digest or before.model != after.model,
        "prompt_changed": before.prompt_sha256 != after.prompt_sha256,
    }
    document["risk_increasing"] = _risk_increasing(document)
    document["explains_digest_change"] = _explains(document)
    return document


def _edges(triples: set[tuple[str, str, str]]) -> list[dict[str, str]]:
    """Sorted as tuples, emitted as objects. Dictionaries do not order."""
    return [
        {"from": source, "relation": relation, "to": target}
        for source, relation, target in sorted(triples)
    ]


def _risk_increasing(document: dict[str, Any]) -> list[str]:
    """The subset of the diff a reviewer should look at first.

    Not a score and not a total: a list of the specific changes that widen
    what the agent can do. Everything in it is also somewhere else in the
    document, so nothing is hidden behind this summary - it is an ordering,
    not a filter.
    """
    reasons: list[str] = []
    for effect in document["effects_gained"]:
        reasons.append(f"effect gained: {effect}")
    for name in document["tools_added"]:
        reasons.append(f"tool added: {name}")
    for entry in document["tools_changed"]:
        for effect in entry["effects_gained"]:
            reasons.append(f"tool {entry['name']} gained effect {effect}")
        if entry.get("requires_approval", {}).get("to") is False:
            reasons.append(f"tool {entry['name']} no longer requires approval")
    for name in document["mcp_added"]:
        reasons.append(f"mcp server added: {name}")
    for entry in document["mcp_changed"]:
        if entry.get("pinned", {}).get("to") is False:
            reasons.append(f"mcp server {entry['name']} is no longer pinned")
        elif "reference" in entry or "digest" in entry:
            reasons.append(f"mcp server {entry['name']} now resolves to different bytes")
        for tool in entry.get("tools_added", []):
            reasons.append(f"mcp server {entry['name']} now exposes {tool}")
    for entry in document["identities_changed"]:
        for scope in entry.get("scopes_added", []):
            reasons.append(f"identity {entry['name']} gained scope {scope}")
    for entry in document["data_sources_changed"]:
        if entry.get("trusted", {}).get("to") is False:
            reasons.append(f"data source {entry['name']} is no longer trusted")
        if "classification" in entry:
            reasons.append(
                f"data source {entry['name']} reclassified "
                f"{entry['classification']['from']} -> {entry['classification']['to']}"
            )
        if entry.get("access", {}).get("to") in ("write", "read_write", "admin", "append"):
            reasons.append(f"data source {entry['name']} access widened to {entry['access']['to']}")
    for name in document["sub_agents_added"]:
        reasons.append(f"sub-agent added: {name}")
    for entry in document["sub_agents_changed"]:
        if "digest" in entry:
            reasons.append(f"sub-agent {entry['name']} points at a different version")
    for entry in document["metadata_changed"]:
        if entry["risk"] == "increase":
            reasons.append(f"{entry['field']}: {entry['from'] or 'none'} -> {entry['to'] or 'none'}")
    if document["model_changed"]:
        reasons.append("model changed")
    if document["prompt_changed"]:
        reasons.append("system prompt changed")
    return reasons


# The sections that, between them, cover everything the agent digest is taken
# over. If the digest moved and every one of these is empty, the diff has
# failed at its job, and `explains_digest_change` says so rather than letting
# a reviewer conclude nothing happened.
_SECTIONS = (
    "tools_added", "tools_removed", "tools_changed",
    "mcp_added", "mcp_removed", "mcp_changed",
    "identities_added", "identities_removed", "identities_changed",
    "data_sources_added", "data_sources_removed", "data_sources_changed",
    "sub_agents_added", "sub_agents_removed", "sub_agents_changed",
    "relations_added", "relations_removed",
    "metadata_changed",
)


def _explains(document: dict[str, Any]) -> bool:
    if document["from_digest"] == document["to_digest"]:
        return True
    if document["model_changed"] or document["prompt_changed"]:
        return True
    return any(document[section] for section in _SECTIONS)
