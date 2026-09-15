"""Loading an agent declaration, and refusing one that says less than it means.

Design note D-143. The declaration is written by the team that owns the agent,
which makes it the weakest link in this whole layer: a capability nobody wrote
down is a capability nobody checks. Two decisions follow.

An unknown effect is refused rather than ignored. `effects: [wirte]` in a YAML
file would otherwise produce an agent with one fewer capability than it has,
and the report would say so confidently. The loader raises and names the
effects it knows.

A tool with no effects at all is refused too. "This tool does nothing" is
never true, and an empty list is what a declaration looks like when somebody
filled in the names and left the analysis for later. Refusing it costs one
minute at authoring time and buys the only thing the capability rules have to
reason over.

Design note D-204 adds the 2.2 half: which errors are refusals and which are
findings. The line is whether the author can see the problem in the file in
front of them. A tool that runs as `triage-bott` when the identities list says
`triage-bot` is a typo in one document, visible at authoring time, and it is
refused - accepting it would produce a declaration whose identity binding is
silently absent, which is exactly the state the binding exists to rule out. An
MCP server that advertises a tool the agent has not declared is the opposite:
the author may not control that server's tool list, the mismatch is real
information about the deployment, and refusing the file would leave the
operator with no report at all. That one is ACT-AGT-009, a finding, and the
report names the tools nobody analysed.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..miniyaml import loads as parse_yaml
from ..model import Finding, Severity
from .model import Agent, DataSource, Effect, Identity, McpServer, SubAgent, Tool
from .vocabulary import ACCESS_MODES, CLASSIFICATIONS, namespaced


class DeclarationError(ValueError):
    """A declaration that cannot be loaded. Never a warning."""


def load(path: Path) -> Agent:
    return load_text(Path(path).read_text(encoding="utf-8"), source=str(path))


def load_text(text: str, source: str = "") -> Agent:
    try:
        document = parse_yaml(text)
    except ValueError as exc:
        raise DeclarationError(f"declaration does not parse: {exc}") from exc
    if not isinstance(document, dict):
        raise DeclarationError("an agent declaration must be a mapping at the top level")

    name = document.get("agent")
    if not isinstance(name, str) or not name:
        raise DeclarationError("an agent needs a name: `agent: <name>`")

    agent = Agent(
        name=name,
        version=str(document.get("version", "")),
        model=str(document.get("model", "")),
        model_digest=str(document.get("model_digest", "")),
        prompt_sha256=str(document.get("prompt_sha256", "")),
        environment=str(document.get("environment", "")),
        owner=str(document.get("owner", "")),
        source=source,
    )

    for index, raw in enumerate(_as_list(document.get("tools")), 1):
        agent.tools.append(_tool(raw, index, agent.environment))
    for index, raw in enumerate(_as_list(document.get("mcp_servers")), 1):
        agent.mcp_servers.append(_mcp(raw, index))
    for index, raw in enumerate(_as_list(document.get("identities")), 1):
        agent.identities.append(_identity(raw, index))
    for index, raw in enumerate(_as_list(document.get("data_sources")), 1):
        agent.data_sources.append(_data_source(raw, index))
    for index, raw in enumerate(_as_list(document.get("sub_agents")), 1):
        agent.sub_agents.append(_sub_agent(raw, index))

    _refuse_duplicates(agent)
    _resolve_references(agent)
    return agent


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise DeclarationError(f"expected a list, got {type(value).__name__}")


def _tool(raw: Any, index: int, agent_environment: str) -> Tool:
    if not isinstance(raw, dict):
        raise DeclarationError(f"tool {index} is not a mapping")
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        raise DeclarationError(f"tool {index} has no name")
    raw_effects = _as_list(raw.get("effects"))
    if not raw_effects:
        raise DeclarationError(
            f"tool {name!r} declares no effects. "
            f"'This tool does nothing' is never true, and an empty list is what a declaration looks "
            f"like when the analysis was left for later. Known effects: "
            f"{', '.join(effect.value for effect in Effect)}"
        )
    effects: list[Effect] = []
    for item in raw_effects:
        try:
            effects.append(Effect(str(item)))
        except ValueError:
            raise DeclarationError(
                f"tool {name!r}: {item!r} is not an effect. Known: "
                f"{', '.join(effect.value for effect in Effect)}"
            ) from None
    return Tool(
        name=name,
        effects=tuple(sorted(set(effects), key=lambda effect: effect.value)),
        description=str(raw.get("description", "")),
        scopes=tuple(str(item) for item in _as_list(raw.get("scopes"))),
        environment=str(raw.get("environment", "") or agent_environment),
        requires_approval=bool(raw.get("requires_approval", False)),
        schema_sha256=str(raw.get("schema_sha256", "")),
        identity=str(raw.get("identity", "")),
        inputs=tuple(str(item) for item in _as_list(raw.get("inputs"))),
        outputs=tuple(str(item) for item in _as_list(raw.get("outputs"))),
        served_by=str(raw.get("served_by", "")),
    )


def _mcp(raw: Any, index: int) -> McpServer:
    if not isinstance(raw, dict):
        raise DeclarationError(f"mcp_server {index} is not a mapping")
    name = raw.get("name")
    reference = raw.get("reference")
    if not isinstance(name, str) or not name:
        raise DeclarationError(f"mcp_server {index} has no name")
    if not isinstance(reference, str) or not reference:
        raise DeclarationError(f"mcp_server {name!r} has no reference; there is nothing to pin or review")
    return McpServer(
        name=name,
        reference=reference,
        publisher=str(raw.get("publisher", "")),
        digest=str(raw.get("digest", "")),
        transport=str(raw.get("transport", "")),
        tools=tuple(str(item) for item in _as_list(raw.get("tools"))),
    )


def _identity(raw: Any, index: int) -> Identity:
    if not isinstance(raw, dict):
        raise DeclarationError(f"identity {index} is not a mapping")
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        raise DeclarationError(f"identity {index} has no name")
    return Identity(
        name=name,
        kind=str(raw.get("kind", "service_account")),
        scopes=tuple(str(item) for item in _as_list(raw.get("scopes"))),
        expires=str(raw.get("expires", "")),
    )


def _vocabulary(value: str, allowed: tuple[str, ...], field: str, owner: str) -> str:
    """A word from the list, or one the author marked as theirs.

    D-201. The escape hatch is a namespace, not an absence of checking:
    `acme:pci-cardholder` is accepted because its author has said, in the
    file, that this word is outside Actaira's vocabulary. A bare word that is
    not in the list is refused, because it is nearly always a misspelling of
    one that is, and a misspelt classification compares equal to nothing.
    """
    if value in allowed or namespaced(value):
        return value
    raise DeclarationError(
        f"data_source {owner!r}: {value!r} is not a {field}. Known: {', '.join(allowed)}. "
        f"For a word of your own, namespace it - for example `yourteam:{value}`."
    )


def _data_source(raw: Any, index: int) -> DataSource:
    if not isinstance(raw, dict):
        raise DeclarationError(f"data_source {index} is not a mapping")
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        raise DeclarationError(f"data_source {index} has no name")
    return DataSource(
        name=name,
        classification=_vocabulary(
            str(raw.get("classification", "unknown")), CLASSIFICATIONS, "classification", name
        ),
        access=_vocabulary(str(raw.get("access", "read")), ACCESS_MODES, "access mode", name),
        trusted=bool(raw.get("trusted", True)),
    )


def _sub_agent(raw: Any, index: int) -> SubAgent:
    """Accepts both shapes: the v1 bare name and the v2 reference.

    A repository that upgrades should not have to rewrite every declaration on
    the same day the tool does, so `sub_agents: [research-bot]` still loads and
    produces a SubAgent with nothing pinned. What it does not do is pretend
    that is as good as a digest - `pinned` is false and the rules can ask.
    """
    if isinstance(raw, str):
        return SubAgent(name=raw)
    if not isinstance(raw, dict):
        raise DeclarationError(f"sub_agent {index} is neither a name nor a mapping")
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        raise DeclarationError(f"sub_agent {index} has no name")
    return SubAgent(
        name=name,
        reference=str(raw.get("reference", "")),
        digest=str(raw.get("digest", "")),
        declaration=str(raw.get("declaration", "")),
    )


def _refuse_duplicates(agent: Agent) -> None:
    for label, names in (
        ("tool", [tool.name for tool in agent.tools]),
        ("mcp_server", [server.name for server in agent.mcp_servers]),
        ("identity", [identity.name for identity in agent.identities]),
        ("data_source", [source.name for source in agent.data_sources]),
        ("sub_agent", [sub.name for sub in agent.sub_agents]),
    ):
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            # Two things with one name makes the evidence ambiguous: a finding
            # naming `search` would not say which `search`, and an approved
            # baseline could not tell them apart either.
            raise DeclarationError(f"{label} name(s) declared twice: {', '.join(duplicates)}")


def _resolve_references(agent: Agent) -> None:
    """Every relation points at something in this document, or the load fails.

    D-204. These are intra-document references: the target is a few lines away
    in the same file, so a dangling one is a typo and the author is the person
    who can see it. The alternative - accepting it and reporting "no identity
    binding" - produces a declaration that looks like it never claimed the
    mitigation, which is the one outcome worth ruling out, because the whole
    point of these fields is to make a claimed mitigation checkable.
    """
    identities = {identity.name for identity in agent.identities}
    sources = {source.name for source in agent.data_sources}
    servers = {server.name for server in agent.mcp_servers}
    tools = {tool.name for tool in agent.tools}

    for tool in agent.tools:
        if tool.identity and tool.identity not in identities:
            raise DeclarationError(
                f"tool {tool.name!r} runs as identity {tool.identity!r}, which is not declared. "
                f"Declared identities: {', '.join(sorted(identities)) or 'none'}."
            )
        for field, names in (("inputs", tool.inputs), ("outputs", tool.outputs)):
            dangling = sorted(name for name in names if name not in sources)
            if dangling:
                raise DeclarationError(
                    f"tool {tool.name!r} lists {field} {', '.join(dangling)}, which are not declared "
                    f"data sources. Declared: {', '.join(sorted(sources)) or 'none'}."
                )
        if tool.served_by and tool.served_by not in servers:
            raise DeclarationError(
                f"tool {tool.name!r} is served by {tool.served_by!r}, which is not a declared MCP "
                f"server. Declared: {', '.join(sorted(servers)) or 'none'}."
            )

    for server in agent.mcp_servers:
        # The other direction is a finding, not a refusal: the agent's authors
        # may not own the server, and a server exposing a tool nobody analysed
        # is real information about the deployment rather than a typo.
        unanalysed = sorted(name for name in server.tools if name not in tools)
        if unanalysed:
            agent.declaration_findings.append(
                Finding(
                    rule_id="ACT-AGT-009",
                    severity=Severity.MEDIUM,
                    location=f"mcp_servers/{server.name}",
                    evidence={
                        "server": server.name,
                        "exposes": unanalysed,
                        "declared_tools": sorted(tools),
                        "consequence": (
                            "the agent can call these and no declaration says what they cause, "
                            "so no capability rule can reason about them"
                        ),
                    },
                )
            )
