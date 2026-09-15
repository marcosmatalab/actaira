"""Not "these capabilities are dangerous together" but "here is the route".

Design note D-210. The eight rules in `capability.py` are good fast checks and
they have one shape in common: they take the agent's whole capability set and
report that two members of it are a bad pair. That is enough to start a
conversation and not enough to finish one, because the first question a
reviewer asks is "how?" and the second is "what do I change?". A set cannot
answer either. A route can.

So this walks the declared graph and returns paths: a specific entry, the
specific hops, the specific sink, and - the part that makes the output worth
reading - the specific change that breaks that route. Every hop is an edge
somebody declared, so nothing here is inferred from names that happened to
match, which is what D-202 built the relations for.

Two things this module is careful about, and both cost more code than the
alternative.

The first is what actually breaks a path. Inside one agent every tool's output
lands in one model's context, so the model is a shared channel and a mitigation
that scopes credentials does not close a route that carries text. Approval
does, because the route requires an unattended action. Separate identities do
where the sink's power comes from the credential rather than from what is
written in the conversation. These are different, `breakers` and
`present_but_ineffective` keep them apart, and a tool that reported the second
as the first would close a real finding with a control that does not apply to
it - the most expensive wrong answer this file could give.

The second is sub-agents. A delegate's capabilities are the delegator's, so
the walk follows `delegates_to` into any declaration the caller resolved. A
delegation cycle is a declaration people really write, and it is cut with a
visited set and reported as a fact rather than as a stack overflow.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..model import Finding, Severity
from .capability import identity_separated
from .model import Agent, Effect, Tool
from .vocabulary import Classification

SCHEMA_VERSION = "attack-paths/v1"

# How deep the walk goes before it stops. A path longer than this is not a
# finding anybody acts on, and a bound that exists is the difference between
# a search and a hang on a declaration written in a loop.
MAX_DEPTH = 8

# What counts as the far end of a route: an effect that carries something out
# of the agent's boundary or changes the world.
_EGRESS = (Effect.NETWORK, Effect.SEND, Effect.PAY)
_MUTATION = (Effect.WRITE, Effect.DELETE, Effect.PAY)


@dataclass(frozen=True)
class Hop:
    """One step of a route, with the reason it is a step.

    `via` is the declared relation that put it there. A hop with no relation
    behind it would be this module inferring a flow, which is exactly what
    the relations exist to stop.
    """

    node: str
    label: str
    via: str

    def to_dict(self) -> dict[str, str]:
        return {"node": self.node, "label": self.label, "via": self.via}


@dataclass
class AttackPath:
    """A route from untrusted input to a consequence, and how to break it."""

    rule_id: str
    severity: Severity
    hops: list[Hop] = field(default_factory=list)
    # Controls the declaration already carries that close this exact route.
    closed_by: list[str] = field(default_factory=list)
    # What to change when it does not. Only meaningful on an open route, and
    # every entry has to actually close THIS route - a suggestion that does
    # not is worse than none, because it gets implemented.
    break_path_by: list[str] = field(default_factory=list)
    # Controls that are declared, that a reader will expect to have closed
    # this, and that do not. The unusual field, and the useful one.
    present_but_ineffective: list[dict[str, str]] = field(default_factory=list)
    carries: str = "text"
    note: str = ""

    @property
    def broken(self) -> bool:
        return bool(self.closed_by)

    @property
    def entry(self) -> str:
        return self.hops[0].node if self.hops else ""

    @property
    def sink(self) -> str:
        return self.hops[-1].node if self.hops else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "entry": self.entry,
            "sink": self.sink,
            "carries": self.carries,
            "hops": [hop.to_dict() for hop in self.hops],
            "broken": self.broken,
            "closed_by": self.closed_by,
            "break_path_by": self.break_path_by,
            "present_but_ineffective": self.present_but_ineffective,
            "note": self.note,
        }


@dataclass
class PathReport:
    """Every route found, plus what the walk could not see."""

    agent: str
    paths: list[AttackPath] = field(default_factory=list)
    cycles: list[list[str]] = field(default_factory=list)
    unresolved_sub_agents: list[str] = field(default_factory=list)
    contexts: list[str] = field(default_factory=list)

    @property
    def open_paths(self) -> list[AttackPath]:
        return [path for path in self.paths if not path.broken]

    def findings(self) -> list[Finding]:
        """One finding per open route. Broken ones are reported and not raised.

        A route with a breaker on it is information - it is the mitigation
        working, and an operator who removes that approval next quarter wants
        to know what it was holding. It is in the document and it is not a
        finding, because a finding that fires on a control that is in place is
        how a team learns to ignore the output.
        """
        findings: list[Finding] = []
        for path in self.open_paths:
            findings.append(
                Finding(
                    rule_id=path.rule_id,
                    severity=path.severity,
                    location=self.agent,
                    evidence={
                        "route": " -> ".join(hop.node for hop in path.hops),
                        "carries": path.carries,
                        "hops": [hop.to_dict() for hop in path.hops],
                        "break_path_by": path.break_path_by,
                        "present_but_ineffective": path.present_but_ineffective,
                        "note": path.note,
                    },
                )
            )
        for cycle in self.cycles:
            findings.append(
                Finding(
                    rule_id="ACT-PATH-009",
                    severity=Severity.MEDIUM,
                    location=self.agent,
                    evidence={
                        "cycle": cycle,
                        "consequence": (
                            "the set of capabilities reachable from this agent cannot be enumerated "
                            "from the declarations, because following them does not terminate"
                        ),
                        "handled_by": "the walk cut the cycle here rather than recursing",
                    },
                )
            )
        return findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "agent": self.agent,
            "contexts": self.contexts,
            "paths": [path.to_dict() for path in self.paths],
            "open_paths": len(self.open_paths),
            "cycles": self.cycles,
            "unresolved_sub_agents": self.unresolved_sub_agents,
        }


# --------------------------------------------------------------------------
# The route definitions
# --------------------------------------------------------------------------


def _is_untrusted(agent: Agent, tool: Tool) -> bool:
    if Effect.UNTRUSTED_INPUT in tool.effects:
        return True
    untrusted = {source.name for source in agent.data_sources if not source.trusted}
    return bool(set(tool.inputs) & untrusted)


def _sensitive_reads(agent: Agent, tool: Tool) -> str:
    """What this tool brings into the context that is worth stealing.

    Two sources, and the second is why `classification` had to become a
    vocabulary: a tool that reads a source classified `restricted` is a
    sensitive read whether or not anybody remembered to write `secrets` in its
    effects.
    """
    if Effect.SECRETS in tool.effects:
        return "credentials"
    for name in tool.inputs:
        source = agent.data_source(name)
        if source and source.sensitivity >= Classification.CONFIDENTIAL.rank:
            return f"{source.classification} data from {name}"
    return ""


def _egress(tool: Tool) -> bool:
    return bool(set(tool.effects) & set(_EGRESS))


def _mutates(tool: Tool) -> bool:
    return bool(set(tool.effects) & set(_MUTATION))


# --------------------------------------------------------------------------
# The walk
# --------------------------------------------------------------------------


@dataclass
class _Context:
    """One agent's tools, the agent they belong to, and how it was reached.

    A context is the unit that matters for these paths, because every tool
    inside one writes into the same model's conversation. Two tools in two
    contexts are connected only where a delegation says they are.

    `trail` is the chain of delegations that reached this agent, and it is
    kept because of defect DEF-88: route 4 used to pair the root with every
    other context and emit a single `declared delegates_to` hop between them.
    For `A -> B -> D` that asserted an edge from A to D that A's declaration
    does not contain, and elided B - so the reviewer could not see which
    declaration to change, and `Hop.via` said "declared" about something
    nobody declared.
    """

    name: str
    agent: Agent
    trail: tuple[str, ...] = ()


def _contexts(
    agent: Agent, resolve: dict[str, Agent] | None
) -> tuple[list[_Context], list[list[str]], list[str]]:
    """Expand delegation, cutting cycles rather than recursing into them."""
    resolve = resolve or {}
    found: list[_Context] = []
    cycles: list[list[str]] = []
    unresolved: list[str] = []
    seen: set[str] = set()
    depth_capped = False

    def walk(current: Agent, trail: list[str]) -> None:
        if current.name in seen:
            if current.name in trail:
                cycles.append([*trail[trail.index(current.name):], current.name])
            return
        seen.add(current.name)
        found.append(_Context(current.name, current, tuple(trail)))
        if len(trail) >= MAX_DEPTH:
            nonlocal depth_capped
            depth_capped = bool(current.sub_agents)
            return
        for sub in current.sub_agents:
            if sub.name in trail:
                cycles.append([*trail[trail.index(sub.name):], current.name, sub.name])
                continue
            delegate = resolve.get(sub.name)
            if delegate is None:
                unresolved.append(sub.name)
                continue
            walk(delegate, [*trail, current.name])

    walk(agent, [])
    if depth_capped:
        # Said, not left to be inferred from a short list. DEF-89: a chain
        # longer than MAX_DEPTH was cut silently, so an agent that could reach
        # a payment tool eleven delegations away reported no routes, no
        # unresolved sub-agents and no cycles - three statements that together
        # read as "there is nothing here".
        cycles.append(["<walk stopped at the delegation depth limit>"])
    return found, cycles, sorted(set(unresolved))


def _mitigations(
    walked: list[Tool], carries: str, entry: Tool, sink: Tool
) -> tuple[list[str], list[str], list[dict[str, str]]]:
    """What closes this exact route, what would, and what looks like it does.

    Design note D-214, and the conclusion took some working out. Within one
    agent there is exactly one declared control that closes a route of this
    shape, and it is approval: the route requires an unattended action, and a
    step a person has to confirm is not unattended.

    Separate identities do not, and this is the part worth being explicit
    about because it is the mitigation everyone reaches for first. Every tool
    in one agent writes its result into one model's conversation. A secret
    that `read_secret` returns is in that conversation, and `post_http` is
    called by the model that is holding it - it never has to fetch the secret
    itself, so it never has to be able to. A second identity changes who may
    READ the credential, not who may REPEAT it.

    That does not make the separation worthless; it makes it a control against
    a different threat, and Actaira has no way to observe that threat from a
    declaration. So it is reported under `present_but_ineffective` with the
    reason attached. A tool that counted it as a fix would close a real
    finding with a control that does not apply to it, which is worse than
    never mentioning it: the finding disappears and the operator believes the
    problem was solved.

    The mitigation that DOES separate the material is moving the sensitive
    step into a different agent whose result never returns to this
    conversation, and that is in the suggestions rather than in the
    declaration, because a declaration cannot state it today.
    """
    closed: list[str] = []
    ineffective: list[dict[str, str]] = []

    approving = sorted(tool.name for tool in walked if tool.requires_approval)
    if approving:
        closed.append(
            f"approval is required at {', '.join(approving)}, so this route cannot run unattended"
        )

    if identity_separated([tool for tool in walked if tool is not sink], [sink]):
        ineffective.append(
            {
                "mitigation": f"{sink.name} runs under an identity the earlier hops do not hold",
                "why": (
                    "every tool in one agent writes into one model's conversation, so the material "
                    "is already in the context that calls the sink and nothing has to re-read it "
                    "under the other identity"
                ),
            }
        )

    if closed:
        return closed, [], ineffective

    suggestions = [
        f"require approval on {sink.name}",
        f"stop {entry.name} from returning outside text into this conversation, or remove it",
    ]
    if carries != "text":
        suggestions.append(
            "move the sensitive read into a separate agent whose result never returns to this "
            "conversation, so the material is never in the same context as the sink"
        )
    if any(Effect.EXEC in tool.effects for tool in walked):
        suggestions.append(
            "run the executing step in a sandbox with no network and no credentials"
        )
    return [], suggestions, ineffective


def find(agent: Agent, resolve: dict[str, Agent] | None = None) -> PathReport:
    """Every route from untrusted input to a consequence, with its breakers.

    `resolve` maps a sub-agent's name to its loaded declaration. Without it a
    delegation is recorded as unresolved rather than assumed harmless: an
    agent that calls something nobody has read is not an agent with no
    sub-agent capabilities.
    """
    contexts, cycles, unresolved = _contexts(agent, resolve)
    report = PathReport(
        agent=agent.name,
        cycles=cycles,
        unresolved_sub_agents=unresolved,
        contexts=[context.name for context in contexts],
    )

    for context in contexts:
        owner = context.agent
        entries = [tool for tool in owner.tools if _is_untrusted(owner, tool)]
        if not entries:
            continue
        for entry in sorted(entries, key=lambda tool: tool.name):
            # Route 1: untrusted text straight into arbitrary execution.
            for runner in sorted(owner.tools_with(Effect.EXEC), key=lambda tool: tool.name):
                report.paths.append(
                    _path("ACT-PATH-003", Severity.CRITICAL, owner, entry, [], runner, "text",
                          "text an outsider wrote reaches a step that runs what the model composed")
                )
            # Route 2: untrusted text into a consequential action.
            for actor in sorted(
                (tool for tool in owner.tools if _mutates(tool) or Effect.SEND in tool.effects),
                key=lambda tool: tool.name,
            ):
                # `actor is entry` is not skipped. DEF-90: one tool that both
                # reads outside text and acts on it is the injection shape at
                # its shortest, ACT-AGT-001 already fires on it, and skipping
                # it here meant the set-based rule reported a finding for which
                # this command offered no route and no way to break it - the
                # precise gap routes exist to fill. The EXEC route never
                # skipped it, so the two disagreed.
                note = (
                    "an instruction written by whoever the agent was reading becomes an action"
                    if actor is not entry
                    else "one tool both reads outside text and acts on it, with nothing in between"
                )
                report.paths.append(
                    _path("ACT-PATH-002", Severity.HIGH, owner, entry, [], actor, "text", note)
                )
            # Route 3: untrusted text steers a sensitive read, and the result
            # leaves. The three-hop route, and the one a set-based rule
            # cannot express at all.
            for carrier in sorted(owner.tools, key=lambda tool: tool.name):
                what = _sensitive_reads(owner, carrier)
                if not what:
                    continue
                for sink in sorted((tool for tool in owner.tools if _egress(tool)), key=lambda tool: tool.name):
                    # No tool is skipped for being the same as another hop.
                    # Defect DEF-95, and the same shape as DEF-90 one route
                    # along: `carrier is entry` was skipped, so an agent whose
                    # one reader brings in BOTH outside text and personal data
                    # - `trusted: false` and `classification: personal` on the
                    # same source, which is what a ticket queue or a case file
                    # actually is - reported no route at all. The shortest form
                    # of a route is still a route, and it is usually the worst
                    # one.
                    report.paths.append(
                        _path(
                            "ACT-PATH-001", Severity.HIGH, owner, entry, [carrier], sink,
                            "credentials" if what == "credentials" else "sensitive data",
                            f"{carrier.name} brings {what} into the conversation and "
                            f"{sink.name} can take it out"
                            + (
                                f". {carrier.name} is also where the outside text comes from, so one "
                                "tool supplies both the instruction and the material"
                                if carrier is entry
                                else ""
                            ),
                        )
                    )

    # Route 4: the delegated version. An agent whose own tools are harmless
    # and which can call one whose tools are not has the capabilities of both,
    # and a review that stopped at the first declaration would say otherwise.
    if len(contexts) > 1:
        root = contexts[0]
        for context in contexts[1:]:
            entries = [tool for tool in root.agent.tools if _is_untrusted(root.agent, tool)]
            sinks = [tool for tool in context.agent.tools if _egress(tool) or _mutates(tool)]
            for entry in sorted(entries, key=lambda tool: tool.name):
                for sink in sorted(sinks, key=lambda tool: tool.name):
                    report.paths.append(
                        _delegated_path(root.agent, context, entry, sink)
                    )

    report.paths.sort(key=lambda path: (-path.severity.rank, path.rule_id, path.entry, path.sink))
    return report


def _path(
    rule_id: str,
    severity: Severity,
    agent: Agent,
    entry: Tool,
    middle: list[Tool],
    sink: Tool,
    carries: str,
    note: str,
) -> AttackPath:
    node = f"agent:{agent.name}"
    hops = [Hop(f"tool:{entry.name}", "untrusted input", "declared effect or inputs edge")]
    hops.append(Hop(node, "the model's context", "every tool result lands here"))
    for tool in middle:
        hops.append(Hop(f"tool:{tool.name}", "sensitive read", "declared effects or a classified input"))
        hops.append(Hop(node, "the model's context", "every tool result lands here"))
    hops.append(Hop(f"tool:{sink.name}", "sink", "declared effects"))

    walked = [entry, *middle, sink]
    closed, suggestions, ineffective = _mitigations(walked, carries, entry, sink)
    return AttackPath(
        rule_id=rule_id,
        severity=severity,
        hops=hops,
        closed_by=closed,
        break_path_by=suggestions,
        present_but_ineffective=ineffective,
        carries=carries,
        note=note,
    )


def _delegated_path(root: Agent, context: _Context, entry: Tool, sink: Tool) -> AttackPath:
    """The delegated route, with every declaration it passes through named.

    DEF-88. Each `delegates_to` hop is one edge from one declaration, so a
    three-agent chain shows three hops and a reviewer can see which file to
    change. Collapsing them into one hop asserted an edge the root's
    declaration does not contain.
    """
    delegate = context.agent
    hops = [
        Hop(f"tool:{entry.name}", "untrusted input", "declared effect or inputs edge"),
        Hop(f"agent:{root.name}", "the model's context", "every tool result lands here"),
    ]
    chain = [*context.trail[1:], delegate.name]
    previous = root.name
    for name in chain:
        hops.append(Hop(f"agent:{name}", "delegate", f"declared delegates_to by {previous}"))
        previous = name
    hops.append(Hop(f"tool:{sink.name}", "sink", f"declared by {delegate.name}"))
    closed, suggestions, ineffective = _mitigations([entry, sink], "text", entry, sink)
    return AttackPath(
        rule_id="ACT-PATH-004",
        severity=Severity.HIGH,
        hops=hops,
        closed_by=closed,
        break_path_by=suggestions,
        present_but_ineffective=ineffective,
        carries="text",
        note=(
            f"{root.name} can pass what it read to {delegate.name}, whose capabilities are therefore "
            f"{root.name}'s capabilities"
        ),
    )
