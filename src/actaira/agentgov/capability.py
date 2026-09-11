"""Dangerous combinations, which is where the risk in an agent actually is.

Design note D-142. Take the components of a real incident one at a time and
every one of them is defensible. A tool that reads pull request comments is
obviously fine. A tool that opens pull requests is obviously fine. A service
account that can push to the default branch is how CI has always worked. The
incident is that all three are in the same agent, so text an outsider wrote
reaches a model that can act on it with a credential that can merge.

That is why these rules take the agent as their subject rather than the tool.
A per-tool check cannot express any of them, and a per-tool check is what an
inventory naturally produces.

Two things every rule here does, and both are load-bearing. It names the exact
tools on each side of the combination, so the finding is actionable rather
than a category. And it says what would make the combination acceptable -
approval, a narrowed scope, a separated identity - because a finding that
names a risk with no exit is one that gets waived permanently on the first
sprint where nobody has time.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..model import Finding, Severity
from .model import Agent, Effect, Tool


@dataclass(frozen=True)
class CapabilityRule:
    rule_id: str
    severity: Severity
    check: Callable[[Agent], dict[str, Any] | None]


def _names(tools: list[Tool]) -> list[str]:
    return sorted(tool.name for tool in tools)


def _untrusted_reach(agent: Agent) -> list[Tool]:
    """Tools whose output is authored outside the trust boundary.

    Three tiers, and D-202 added the middle one. A declared
    `untrusted_input` effect is the author saying so. A declared `inputs`
    edge to a data source marked `trusted: false` is the author saying so in
    two places that have to agree - a relation, not a coincidence of names.
    A tool whose `scopes` happen to contain the name of an untrusted source is
    the old convention, kept because nobody remembers to mark the web fetcher,
    and now clearly the weakest of the three.

    The distinction matters to the evidence, not just to the reasoning: a
    finding that says "inferred from a scope string" invites the author to
    declare the relation, and one that says "you declared this" does not
    invite an argument about whether the tool really reads untrusted text.
    """
    declared = agent.tools_with(Effect.UNTRUSTED_INPUT)
    untrusted_sources = {source.name for source in agent.data_sources if not source.trusted}
    if not untrusted_sources:
        return declared
    bound = [
        tool
        for tool in agent.tools
        if tool not in declared and set(tool.inputs) & untrusted_sources
    ]
    # The scope inference needs the READ effect, not just the scope. A tool
    # that only writes to an untrusted source does not carry its text back into
    # the model, and counting it made the evidence name tools that could not
    # possibly be the injection path - which is how a finding that is correct
    # in substance becomes one nobody acts on.
    inferred = [
        tool
        for tool in agent.tools
        if tool not in declared
        and tool not in bound
        and Effect.READ in tool.effects
        and set(tool.scopes) & untrusted_sources
    ]
    return declared + bound + inferred


def _how_untrusted(agent: Agent, tool: Tool) -> str:
    if Effect.UNTRUSTED_INPUT in tool.effects:
        return "declared effect"
    untrusted_sources = {source.name for source in agent.data_sources if not source.trusted}
    if set(tool.inputs) & untrusted_sources:
        return "declared inputs edge to an untrusted data source"
    return "inferred from a scope naming an untrusted data source"


def identity_separated(left: list[Tool], right: list[Tool]) -> bool:
    """Whether two sets of tools provably run under identities that do not meet.

    Design note D-205. Separation is only claimed when every tool on both
    sides names an identity and the two sets are disjoint. A tool that named
    none proves nothing, and treating "unstated" as "separate" would turn a
    missing field into a mitigation - the failure this whole module is built
    to avoid.

    What this does NOT do is suppress a finding, and that is worth stating
    because the obvious implementation suppresses one. "Run the secret reader
    under an identity the egress tool does not have" is the mitigation
    everyone recommends for the exfiltration combination, and inside a single
    agent it does not work: `read_deploy_key` returns the credential as text
    into the model's context, and `fetch_url` is called by that same model.
    The credential never needs to be re-read under the second identity,
    because it is already in the conversation. Separate identities stop the
    second tool from FETCHING the secret itself; they do not stop the first
    tool from handing it over.

    So the separation is recorded, in the evidence and on every attack path,
    under a name that says what it is: a mitigation that is present and that
    does not break this class of path. Where it does break one - a sink whose
    power comes from a credential rather than from text - `paths.py` says so
    there instead.
    """
    if not left or not right:
        return False
    if any(not tool.identity for tool in left + right):
        return False
    return not ({tool.identity for tool in left} & {tool.identity for tool in right})


def _injection_to_action(agent: Agent) -> dict[str, Any] | None:
    """Untrusted text in, consequential action out, with nobody in between.

    The shape of every prompt-injection incident that mattered. Approval is
    what breaks it, so a tool that requires approval is not counted on the
    action side: the point is not that the agent can act, it is that it can
    act on instructions written by whoever it was reading.
    """
    readers = _untrusted_reach(agent)
    if not readers:
        return None
    actors = [
        tool
        for tool in agent.tools
        if not tool.requires_approval
        and set(tool.effects) & {Effect.WRITE, Effect.DELETE, Effect.SEND, Effect.PAY}
    ]
    if not actors:
        return None
    return {
        "reads_untrusted": _names(readers),
        "established_by": {tool.name: _how_untrusted(agent, tool) for tool in sorted(readers, key=lambda t: t.name)},
        "acts_without_approval": _names(actors),
        "effects": sorted(
            {
                effect.value
                for tool in actors
                for effect in tool.effects
                if effect in (Effect.WRITE, Effect.DELETE, Effect.SEND, Effect.PAY)
            }
        ),
        "would_be_acceptable_if": "the acting tools required approval, or the reading tools were removed",
    }


def _secrets_and_egress(agent: Agent) -> dict[str, Any] | None:
    """A tool that can read credentials beside one that can reach outside.

    Does not require the same tool to do both, and must not: the model sits
    between them and can pass what one returned to the other. This is the
    exfiltration path, and it is invisible to any check that examines tools
    one at a time.
    """
    holders = agent.tools_with(Effect.SECRETS)
    egress = [
        tool for tool in agent.tools if set(tool.effects) & {Effect.NETWORK, Effect.SEND}
    ]
    if not holders or not egress:
        return None
    evidence: dict[str, Any] = {
        "can_read_secrets": _names(holders),
        "can_reach_outside": _names(egress),
        "note": "the same tool need not do both; the model sits between them",
        "identities": {
            "secret_side": sorted({tool.identity for tool in holders if tool.identity}),
            "egress_side": sorted({tool.identity for tool in egress if tool.identity}),
            "unstated": sorted(tool.name for tool in holders + egress if not tool.identity),
        },
    }
    if identity_separated(holders, egress):
        # Recorded, and explicitly not treated as a fix. See D-205: the
        # credential reaches the model as text and the same model calls the
        # egress tool, so the second identity is never needed. Reporting this
        # as mitigated would be the most expensive kind of wrong answer -
        # a real finding closed by a control that does not apply.
        evidence["declared_mitigation"] = "separate identities"
        evidence["why_it_does_not_break_this"] = (
            "the secret reaches the model as text and the same model calls the egress tool, "
            "so nothing needs to re-read it under the second identity"
        )
    approved = [tool for tool in egress if tool.requires_approval]
    if approved and len(approved) == len(egress):
        # Every way out needs a human first. That IS a breaker: the path
        # requires an unattended action and there is none.
        return None
    evidence["would_be_acceptable_if"] = (
        "every egress tool required approval, or the secret-reading tool were scoped to a secret "
        "the egress path cannot use"
    )
    return evidence


def _arbitrary_execution(agent: Agent) -> dict[str, Any] | None:
    """A tool that runs code the model composed.

    Every other rule here is about a combination. This one is about a single
    capability, because arbitrary execution subsumes the rest: a shell is a
    write tool, a network tool and a secret reader at once, and enumerating
    those separately would understate it.
    """
    runners = agent.tools_with(Effect.EXEC)
    if not runners:
        return None
    unapproved = [tool for tool in runners if not tool.requires_approval]
    return {
        "executes_code": _names(runners),
        "without_approval": _names(unapproved),
        "subsumes": ["write", "network", "secrets", "delete"],
        "would_be_acceptable_if": "execution happened in a sandbox with no network and no credentials, "
        "or required approval",
    }


def _unpinned_mcp(agent: Agent) -> dict[str, Any] | None:
    """An MCP server referenced by tag rather than digest.

    An approved server referenced by tag is approved until somebody pushes.
    The tools it exposes, their schemas and their effects can all change
    without any artifact in the deployment changing, which means the agent's
    capability set is mutable by a third party.
    """
    unpinned = [server for server in agent.mcp_servers if not server.pinned]
    if not unpinned:
        return None
    return {
        "unpinned": sorted(server.name for server in unpinned),
        "references": sorted(server.reference for server in unpinned),
        "consequence": "the tools this agent has can change without anything in this deployment changing",
        "would_be_acceptable_if": "each reference carried a digest",
    }


def _unattributed_mcp(agent: Agent) -> dict[str, Any] | None:
    """An MCP server with no publisher recorded.

    Not a risk in itself, and it is MEDIUM for that reason. It is the field
    that makes every other question answerable - is this the vendor we
    reviewed, did they announce a change, who do we contact - and an
    inventory without it cannot be audited even when nothing is wrong.
    """
    anonymous = [server for server in agent.mcp_servers if not server.publisher]
    if not anonymous:
        return None
    return {
        "no_publisher": sorted(server.name for server in anonymous),
        "would_be_acceptable_if": "the declaration recorded who publishes each server",
    }


def _unbound_model(agent: Agent) -> dict[str, Any] | None:
    """The model named but not pinned to a digest.

    An agent whose model reference is a name resolves to whatever that name
    points at today. The A-BOM would be a document about a different model
    tomorrow while its own digest stayed the same, which is the one thing the
    digest exists to prevent.
    """
    if agent.model and not agent.model_digest:
        return {
            "model": agent.model,
            "digest": None,
            "would_be_acceptable_if": "the declaration recorded the model's digest alongside its name",
        }
    return None


def _unbound_prompt(agent: Agent) -> dict[str, Any] | None:
    """No digest over the system prompt.

    The system prompt is the agent's policy. Changing it changes behaviour as
    thoroughly as changing a tool, and an agent digest that did not cover it
    would say "unchanged" across a rewrite of the instructions.
    """
    if not agent.prompt_sha256:
        return {
            "prompt_sha256": None,
            "consequence": "the agent's digest does not change when its instructions do",
            "would_be_acceptable_if": "the declaration recorded the system prompt's sha256",
        }
    return None


def _production_write_without_approval(agent: Agent) -> dict[str, Any] | None:
    writers = [
        tool
        for tool in agent.tools
        if not tool.requires_approval
        and set(tool.effects) & {Effect.WRITE, Effect.DELETE, Effect.PAY}
        and (tool.environment or agent.environment).lower() in ("prod", "production")
    ]
    if not writers:
        return None
    return {
        "writes_to_production": _names(writers),
        "would_be_acceptable_if": "these required approval, or ran against a staging environment",
    }


def _unbound_sub_agent(agent: Agent) -> dict[str, Any] | None:
    """Delegation to an agent nobody pinned.

    D-202. A sub-agent's capabilities are this agent's capabilities: whatever
    the delegate can do, the delegator can cause. An unpinned delegate is
    therefore the same problem as an unpinned MCP server one level up - the
    set of things this agent can cause is mutable by whoever owns the other
    declaration, without anything in this one changing.

    MEDIUM rather than HIGH because, unlike an MCP server, the other end is
    usually inside the same organisation. It is still the reason a review of
    this agent does not cover what it can do.
    """
    unpinned = [sub for sub in agent.sub_agents if not sub.pinned]
    if not unpinned:
        return None
    return {
        "unpinned": sorted(sub.name for sub in unpinned),
        "with_a_declaration": sorted(sub.name for sub in unpinned if sub.declaration),
        "consequence": (
            "whatever these can do, this agent can cause, and nothing here records which version "
            "of them was reviewed"
        ),
        "would_be_acceptable_if": "each sub-agent carried a digest, as `sub_agents: [{name: x, digest: sha256:...}]`",
    }


CAPABILITY_RULES: tuple[CapabilityRule, ...] = (
    CapabilityRule("ACT-AGT-001", Severity.HIGH, _injection_to_action),
    CapabilityRule("ACT-AGT-002", Severity.HIGH, _secrets_and_egress),
    CapabilityRule("ACT-AGT-003", Severity.HIGH, _arbitrary_execution),
    CapabilityRule("ACT-AGT-004", Severity.HIGH, _unpinned_mcp),
    CapabilityRule("ACT-AGT-005", Severity.MEDIUM, _unattributed_mcp),
    CapabilityRule("ACT-AGT-006", Severity.MEDIUM, _unbound_model),
    CapabilityRule("ACT-AGT-007", Severity.MEDIUM, _unbound_prompt),
    CapabilityRule("ACT-AGT-008", Severity.HIGH, _production_write_without_approval),
    CapabilityRule("ACT-AGT-010", Severity.MEDIUM, _unbound_sub_agent),
)

# ACT-AGT-009 is not in this table on purpose. It is raised by the loader,
# where the information is - a tool an MCP server advertises and the
# declaration does not describe is a fact about the document, established
# while reading it. `assess` carries it through so a caller sees one list.


def assess(agent: Agent) -> list[Finding]:
    """Run every rule. Every one, always, in a fixed order.

    No short-circuiting and no severity ordering at evaluation time: the
    findings a reader gets must depend only on the agent, so that two
    declarations can be compared. Sorting for display happens where display
    happens.
    """
    findings: list[Finding] = list(agent.declaration_findings)
    for rule in CAPABILITY_RULES:
        evidence = rule.check(agent)
        if evidence is None:
            continue
        findings.append(
            Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                location=agent.name,
                evidence=evidence,
            )
        )
    return findings
