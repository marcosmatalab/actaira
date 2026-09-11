"""Evaluating a policy against what a run actually observed.

Design note D-113. The predicates below are the whole vocabulary a policy can
use, and the list is short on purpose. Every one of them reads something this
tool measured - a finding's severity, a coverage state, whether a signature
verified, how old a piece of evidence is - and nothing reads the filesystem,
the network or the clock. `decided_on` is an argument, exactly as it is
everywhere else in this repository, because a decision that depends on when it
was run cannot be reproduced by the person checking it.

The other rule, and the one that shapes the code: a predicate that cannot
evaluate must not quietly return False. A policy that requires a trusted
signature and is handed a run with no attestation at all has not been
satisfied, and treating "I have no information" as "the condition does not
hold" would make a `deny` rule silently pass. So an unevaluable predicate
raises `Unevaluable`, and the engine turns that into a REVIEW outcome naming
what was missing.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from datetime import date, datetime
from pathlib import Path
from typing import Any

from .. import __version__
from ..coverage import CoverageState, Surface
from ..miniyaml import loads as parse_yaml
from ..model import Severity
from ..subject import SubjectClaims, SubjectKind
from .model import (
    Decision,
    Effect,
    Policy,
    PolicyDecision,
    Rule,
    RuleOutcome,
    Waiver,
)


class PolicyError(ValueError):
    """A policy document that cannot be loaded. Never a warning."""


class Unevaluable(Exception):
    """A predicate that has no information to decide on.

    Not an error in the policy and not a failure of the artifact: a gap in
    what this run observed. It becomes a REVIEW outcome that names the gap,
    which is the honest answer and the one that gets a human to look.
    """

    def __init__(self, missing: str) -> None:
        super().__init__(missing)
        self.missing = missing


def load_policy(path: Path) -> Policy:
    return load_policy_text(Path(path).read_text(encoding="utf-8"), source=str(path))


def load_policy_text(text: str, source: str = "") -> Policy:
    try:
        document = parse_yaml(text)
    except ValueError as exc:
        raise PolicyError(f"policy does not parse: {exc}") from exc
    if not isinstance(document, dict):
        raise PolicyError("a policy must be a mapping at the top level")

    policy_id = document.get("policy")
    if not isinstance(policy_id, str) or not policy_id:
        raise PolicyError("a policy needs an id: `policy: <name>`")
    version = document.get("version")
    if not isinstance(version, int):
        raise PolicyError(f"policy {policy_id} needs an integer `version`")

    raw_rules = document.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise PolicyError(f"policy {policy_id} declares no rules")

    rules: list[Rule] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_rules, 1):
        if not isinstance(raw, dict):
            raise PolicyError(f"rule {index} is not a mapping")
        rule_id = raw.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise PolicyError(f"rule {index} has no id")
        if rule_id in seen:
            # Two rules with one id makes an exception ambiguous: waiving
            # "no-criticals" would waive whichever of them the loop reached
            # last. Refuse the document rather than pick.
            raise PolicyError(f"rule id {rule_id!r} appears twice")
        seen.add(rule_id)
        try:
            effect = Effect(raw.get("effect"))
        except ValueError:
            raise PolicyError(
                f"rule {rule_id}: effect must be one of {', '.join(item.value for item in Effect)}"
            ) from None
        when = raw.get("when")
        if not isinstance(when, dict) or not when:
            raise PolicyError(f"rule {rule_id}: `when` must be a mapping with at least one condition")
        unknown = sorted(set(when) - set(PREDICATES))
        if unknown:
            # A misspelt predicate must not silently never match. That is a
            # rule that looks present in the file and is absent in effect,
            # which is the worst failure mode a policy language has.
            raise PolicyError(
                f"rule {rule_id}: unknown condition(s) {', '.join(unknown)}. "
                f"Known: {', '.join(sorted(PREDICATES))}"
            )
        for name, argument in sorted(when.items()):
            # And a misspelt ARGUMENT must not either. Defect DEF-83: the
            # names were checked here and the values were checked inside the
            # predicate, at evaluation time, where nothing catches a
            # `PolicyError` - so `subject_kind: agnet` produced a traceback and
            # exit 1, which is `EXIT_FAIL` and therefore indistinguishable from
            # a policy DENY. A typo in the name gave a clean message and exit
            # 2; a typo in the value did not.
            checker = ARGUMENT_CHECKS.get(name)
            if checker is not None:
                checker(rule_id, argument)
        rules.append(
            Rule(
                id=rule_id,
                effect=effect,
                when=when,
                description=str(raw.get("description", "")),
            )
        )

    exceptions = _parse_exceptions(document.get("exceptions"), policy_id, seen)
    return Policy(
        id=policy_id,
        version=version,
        rules=tuple(rules),
        exceptions=exceptions,
        description=str(document.get("description", "")),
        source=source,
    )


def _values(argument: Any) -> list[str]:
    return [str(item) for item in (argument if isinstance(argument, list) else [argument])]


def _enum_check(field: str, allowed: Callable[[], set[str]]) -> Callable[[str, Any], None]:
    def check(rule_id: str, argument: Any) -> None:
        known = allowed()
        unknown = sorted(set(_values(argument)) - known)
        if unknown:
            raise PolicyError(
                f"rule {rule_id}: {field}: {', '.join(unknown)} is not a valid value. "
                f"Known: {', '.join(sorted(known))}"
            )

    return check


def _check_coverage(rule_id: str, argument: Any) -> None:
    if not isinstance(argument, dict) or "surface" not in argument:
        raise PolicyError(f"rule {rule_id}: coverage: expected `surface:` and `at_least:`")
    if str(argument["surface"]) not in {item.value for item in Surface}:
        raise PolicyError(
            f"rule {rule_id}: coverage: {argument['surface']!r} is not a surface. "
            f"Known: {', '.join(item.value for item in Surface)}"
        )
    at_least = str(argument.get("at_least", "complete"))
    if at_least not in {item.value for item in CoverageState}:
        raise PolicyError(
            f"rule {rule_id}: coverage: {at_least!r} is not a coverage state. "
            f"Known: {', '.join(item.value for item in CoverageState)}"
        )


def _check_relation(rule_id: str, argument: Any) -> None:
    if not isinstance(argument, dict) or not argument:
        raise PolicyError(
            f"rule {rule_id}: relation_exists: expected a mapping with any of `from`, "
            "`relation`, `to`"
        )
    unknown = sorted(set(argument) - {"from", "relation", "to"})
    if unknown:
        raise PolicyError(f"rule {rule_id}: relation_exists: unknown key(s) {', '.join(unknown)}")


def _check_days(rule_id: str, argument: Any) -> None:
    try:
        days = int(argument)
    except (TypeError, ValueError):
        raise PolicyError(
            f"rule {rule_id}: evidence_max_age_days: {argument!r} is not a whole number of days"
        ) from None
    if days < 0:
        raise PolicyError(f"rule {rule_id}: evidence_max_age_days: {days} is negative")


def _check_fact(rule_id: str, argument: Any) -> None:
    if not isinstance(argument, dict) or "name" not in argument:
        raise PolicyError(f"rule {rule_id}: fact_is: expected `name:` and `equals:`")


# Every predicate whose argument comes from a closed set, checked when the
# document loads rather than when it runs. See DEF-83: the two halves of
# "this rule is well formed" belong in one place, and that place is the one
# whose errors a caller already handles.
ARGUMENT_CHECKS: dict[str, Callable[[str, Any], None]] = {}


def _register_argument_checks() -> None:
    from ..agentgov.model import Effect as AgentEffect
    from ..bundle import ContentIdentity
    from ..model import Verdict
    from ..subject import SubjectKind

    ARGUMENT_CHECKS.update(
        {
            "finding_severity_at_least": _enum_check(
                "finding_severity_at_least", lambda: {item.value for item in Severity}
            ),
            "attack_path_severity_at_least": _enum_check(
                "attack_path_severity_at_least", lambda: {item.value for item in Severity}
            ),
            "subject_kind": _enum_check("subject_kind", lambda: {item.value for item in SubjectKind}),
            "bundle_content_identity": _enum_check(
                "bundle_content_identity", lambda: {item.value for item in ContentIdentity}
            ),
            "agent_effect": _enum_check("agent_effect", lambda: {item.value for item in AgentEffect}),
            "verdict_is": _enum_check("verdict_is", lambda: {item.value for item in Verdict}),
            "evidence_state": _enum_check(
                "evidence_state",
                lambda: {"valid", "stale", "superseded", "revoked", "untrusted"},
            ),
            "trust_state": _enum_check("trust_state", lambda: {"trusted", "untrusted", "unknown"}),
            "coverage": _check_coverage,
            "relation_exists": _check_relation,
            "evidence_max_age_days": _check_days,
            "fact_is": _check_fact,
        }
    )


_register_argument_checks()


def _parse_exceptions(raw: Any, policy_id: str, rule_ids: set[str]) -> tuple[Waiver, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise PolicyError(f"policy {policy_id}: `exceptions` must be a list")
    parsed: list[Waiver] = []
    for index, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            raise PolicyError(f"exception {index} is not a mapping")
        missing = [key for key in ("rule", "owner", "reason", "expires") if not item.get(key)]
        if missing:
            # The whole reason exceptions are safe to have. An exception with
            # no owner is one nobody revisits; with no expiry it is a
            # permanent policy change written where temporary ones go. The
            # document does not load.
            raise PolicyError(
                f"exception {index} for rule {item.get('rule', '?')} is missing: {', '.join(missing)}. "
                "An exception without an owner, a reason and an expiry date is a policy change in disguise."
            )
        if item["rule"] not in rule_ids:
            raise PolicyError(f"exception {index} waives {item['rule']!r}, which is not a rule in this policy")
        parsed.append(
            Waiver(
                rule=str(item["rule"]),
                owner=str(item["owner"]),
                reason=str(item["reason"]),
                expires=_as_date(item["expires"], f"exception {index}"),
                subject=str(item["subject"]) if item.get("subject") else None,
                ticket=str(item.get("ticket", "")),
            )
        )
    return tuple(parsed)


def _as_date(value: Any, where: str) -> date:
    if isinstance(value, date):
        return value
    try:
        return datetime.strptime(str(value), "%Y-%m-%d").date()
    except ValueError:
        raise PolicyError(f"{where}: `expires` must be a date as YYYY-MM-DD, got {value!r}") from None


# --------------------------------------------------------------------------
# What a rule can ask about
# --------------------------------------------------------------------------


# `Claims` is the 2.1 name and the 2.2 shape. See `actaira/subject.py`, design
# note D-211: the class moved out of this module and grew the bundle, agent,
# relation, evidence and provenance slots, and the constructor signature it had
# in 2.1 is unchanged, so every policy and every caller written against that
# release keeps working.
Claims = SubjectClaims


Predicate = Callable[[Claims, Any, date], tuple[bool, dict[str, Any]]]


def _finding_severity_at_least(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    if claims.report is None:
        raise Unevaluable("no inspection report for this subject")
    try:
        threshold = Severity(str(argument))
    except ValueError:
        raise PolicyError(f"finding_severity_at_least: {argument!r} is not a severity") from None
    hits = [
        {"rule": finding.rule_id, "severity": finding.severity.value}
        for finding in claims.report.findings
        if finding.severity.rank >= threshold.rank
    ]
    return bool(hits), {"threshold": threshold.value, "findings": hits[:10], "count": len(hits)}


def _finding_rule(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    if claims.report is None:
        raise Unevaluable("no inspection report for this subject")
    wanted = {str(item) for item in (argument if isinstance(argument, list) else [argument])}
    present = sorted({finding.rule_id for finding in claims.report.findings} & wanted)
    return bool(present), {"looked_for": sorted(wanted), "present": present}


def _coverage(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    if claims.report is None:
        raise Unevaluable("no inspection report for this subject")
    if not isinstance(argument, dict) or "surface" not in argument:
        raise PolicyError("coverage: expected `surface:` and `at_least:`")
    try:
        surface = Surface(str(argument["surface"]))
    except ValueError:
        raise PolicyError(f"coverage: {argument['surface']!r} is not a surface") from None
    try:
        required = CoverageState(str(argument.get("at_least", "complete")))
    except ValueError:
        raise PolicyError(f"coverage: {argument.get('at_least')!r} is not a coverage state") from None
    actual = claims.report.coverage.state(surface)
    satisfied = claims.report.coverage.satisfies(surface, required)
    return satisfied, {
        "surface": surface.value,
        "required": required.value,
        "actual": actual.value,
        "reason": claims.report.coverage.reason(surface),
    }


def _verdict_is(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    if claims.report is None:
        raise Unevaluable("no inspection report for this subject")
    wanted = {str(item).lower() for item in (argument if isinstance(argument, list) else [argument])}
    return claims.report.verdict.value in wanted, {
        "verdict": claims.report.verdict.value,
        "accepted": sorted(wanted),
    }


def _detected_format(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    if claims.report is None:
        raise Unevaluable("no inspection report for this subject")
    wanted = {str(item) for item in (argument if isinstance(argument, list) else [argument])}
    return claims.report.detected_format in wanted, {
        "detected": claims.report.detected_format,
        "matched_against": sorted(wanted),
    }


def _imports_callable(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    if claims.report is None:
        raise Unevaluable("no inspection report for this subject")
    wanted = [str(item) for item in (argument if isinstance(argument, list) else [argument])]
    # Prefix match, so `os.` covers `os.system` and `os.popen`. A policy that
    # had to enumerate every dangerous callable would be out of date the day
    # it was written.
    hits = sorted(
        name
        for name in claims.report.imported_callables
        if any(name == pattern or name.startswith(pattern) for pattern in wanted)
    )
    return bool(hits), {"patterns": wanted, "imported": hits}


def _signature_verified(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    if claims.attestation is None:
        raise Unevaluable("no attestation was supplied with this run")
    actual = bool(claims.attestation.get("signature_verified"))
    return actual is bool(argument), {"expected": bool(argument), "actual": actual}


def _signer_trusted(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    if claims.attestation is None:
        raise Unevaluable("no attestation was supplied with this run")
    if "signer_trusted" not in claims.attestation:
        # A signature that verifies says the bytes were not altered. It says
        # nothing about whether the key belongs to anyone you trust, and
        # conflating the two is the oldest mistake in supply-chain tooling.
        raise Unevaluable("the attestation records no trust decision about the signer")
    actual = bool(claims.attestation["signer_trusted"])
    return actual is bool(argument), {"expected": bool(argument), "actual": actual}


def _time_anchor_trusted(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    if claims.attestation is None:
        raise Unevaluable("no attestation was supplied with this run")
    state = claims.attestation.get("time_anchor_trust")
    if state is None:
        raise Unevaluable("the attestation records no time anchor trust state")
    return str(state) == str(argument), {"expected": str(argument), "actual": str(state)}


def _observed_on(claims: Claims) -> tuple[date, str] | None:
    """When the evidence behind this subject was taken, and where that came from.

    Two sources, and the older one still wins where it is set: a caller that
    passed `evidence_observed_on` said so explicitly. Otherwise the OLDEST
    attached evidence record decides, which is the conservative direction - a
    decision resting on six records is only as fresh as the one that was taken
    longest ago, and picking the newest would let a re-observation of one part
    make a stale whole look current.
    """
    if claims.evidence_observed_on is not None:
        return claims.evidence_observed_on, "supplied with the run"
    dates: list[date] = []
    for record in claims.evidence:
        stamp = record.get("observed_at")
        if not stamp:
            continue
        try:
            dates.append(datetime.fromisoformat(str(stamp)).date())
        except (TypeError, ValueError):
            # A timestamp this reader cannot parse is not a date it may guess
            # at. The record contributes nothing and, if none of them parse,
            # the predicate is unevaluable rather than confidently fresh.
            continue
    if not dates:
        return None
    return min(dates), f"the oldest of {len(dates)} evidence record(s)"


def _evidence_max_age_days(claims: Claims, argument: Any, on: date) -> tuple[bool, dict[str, Any]]:
    observed = _observed_on(claims)
    if observed is None:
        raise Unevaluable("this subject carries no observation date")
    when, where = observed
    limit = int(argument)
    age = (on - when).days
    return age <= limit, {
        "observed_on": when.isoformat(),
        "from": where,
        "age_days": age,
        "limit_days": limit,
    }


def _fact_is(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    """An escape hatch for facts the caller asserts, named so it reads as one.

    The point of the name is that a proof containing `fact_is` is visibly
    resting on something the caller said rather than something this tool
    measured. A reader can see the difference; a generic `custom:` predicate
    would hide it.
    """
    if not isinstance(argument, dict) or "name" not in argument:
        raise PolicyError("fact_is: expected `name:` and `equals:`")
    name = str(argument["name"])
    if name not in claims.facts:
        raise Unevaluable(f"no fact named {name!r} was supplied")
    actual = claims.facts[name]
    expected = argument.get("equals")
    return actual == expected, {"fact": name, "expected": expected, "actual": actual}


# --------------------------------------------------------------------------
# The 2.2 predicates: one policy language over every kind of subject
# --------------------------------------------------------------------------
#
# Design note D-212. Every one of these follows the same two rules as the
# predicates above, and they are worth restating because they are what keeps
# the language honest as it grows.
#
# A predicate reads what this run observed and nothing else - no filesystem, no
# network, no clock. And a predicate with no information raises `Unevaluable`
# rather than returning False, so a policy that requires a complete weight
# identity and is handed a subject with no bundle goes to REVIEW instead of
# silently passing or silently failing.


def _subject_kind(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    """Which kind of thing this is. The gate every other new predicate needs.

    A policy that applies a bundle rule to an agent has not found a problem
    with the agent; it has asked a question with no meaning. `subject_kind`
    written first in a rule's `when` is how a policy says which subjects the
    rest of the rule is about.
    """
    if claims.kind is None:
        raise Unevaluable("this subject carries no reference, so its kind is unknown")
    wanted = {str(item) for item in (argument if isinstance(argument, list) else [argument])}
    unknown = sorted(wanted - {item.value for item in SubjectKind})
    if unknown:
        raise PolicyError(
            f"subject_kind: {', '.join(unknown)} is not a kind. Known: "
            f"{', '.join(item.value for item in SubjectKind)}"
        )
    return claims.kind.value in wanted, {"kind": claims.kind.value, "accepted": sorted(wanted)}


def _bundle_finding(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    if claims.bundle is None:
        raise Unevaluable("no bundle resolution for this subject")
    wanted = {str(item) for item in (argument if isinstance(argument, list) else [argument])}
    present = sorted({finding.rule_id for finding in claims.bundle.findings} & wanted)
    return bool(present), {"looked_for": sorted(wanted), "present": present}


def _bundle_content_identity(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    """How firmly the weights are identified, as a policy question.

    The predicate D-200 exists for. "This is the model we approved" is a claim
    about bytes, and a bundle whose shards were never read cannot support it
    however stable its layout digest is. A production policy says
    `bundle_content_identity: [complete, externally_bound]` and a repository
    that has not been hashed goes to REVIEW rather than through.
    """
    from ..bundle import ContentIdentity

    if claims.bundle is None:
        raise Unevaluable("no bundle resolution for this subject")
    wanted = {str(item) for item in (argument if isinstance(argument, list) else [argument])}
    unknown = sorted(wanted - {item.value for item in ContentIdentity})
    if unknown:
        raise PolicyError(
            f"bundle_content_identity: {', '.join(unknown)} is not a state. Known: "
            f"{', '.join(item.value for item in ContentIdentity)}"
        )
    identity = claims.bundle.content_identity()
    return identity["state"] in wanted, {
        "state": identity["state"],
        "accepted": sorted(wanted),
        "binding_source": identity["binding_source"],
        "members_unidentified": identity["members_unidentified"],
    }


def _agent_effect(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    from ..agentgov.model import Effect as AgentEffect

    # The argument is checked before the payload is. Order matters: with the
    # checks the other way round a misspelt effect passed silently for every
    # artifact and bundle subject and raised on the first agent, so whether a
    # policy was well-formed depended on what it was pointed at.
    wanted = {str(item) for item in (argument if isinstance(argument, list) else [argument])}
    unknown = sorted(wanted - {item.value for item in AgentEffect})
    if unknown:
        raise PolicyError(
            f"agent_effect: {', '.join(unknown)} is not an effect. Known: "
            f"{', '.join(item.value for item in AgentEffect)}"
        )
    if claims.agent is None:
        raise Unevaluable("no agent declaration for this subject")
    held = {effect.value for effect in claims.agent.effects}
    present = sorted(held & wanted)
    return bool(present), {
        "looked_for": sorted(wanted),
        "present": present,
        "tools": sorted(
            tool.name
            for tool in claims.agent.tools
            for effect in tool.effects
            if effect.value in present
        ),
    }


def _agent_finding(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    if claims.agent is None:
        raise Unevaluable("no agent declaration for this subject")
    wanted = {str(item) for item in (argument if isinstance(argument, list) else [argument])}
    present = sorted(
        {finding.rule_id for finding in claims.findings_of(SubjectKind.AGENT)} & wanted
    )
    return bool(present), {"looked_for": sorted(wanted), "present": present}


def _attack_path_severity_at_least(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    """An OPEN route at or above a severity. Closed ones do not count.

    The distinction matters more here than anywhere else in the language. A
    route with an approval on it is a route that cannot run unattended, and a
    policy that denied on it would be denying the mitigation working - which
    is how a team ends up removing the approval to get the build green.
    """
    if not claims.paths_searched:
        # DEF-81. This used to be `claims.agent is None and not
        # claims.attack_paths`, which reads "an agent is attached" as "routes
        # were searched". `SubjectClaims(agent=...)` and
        # `for_agent(..., with_paths=False)` both leave the list empty, so a
        # deny rule on an open HIGH route came back ALLOW with
        # `"count": 0` beside an agent that had one.
        raise Unevaluable("no route search was run for this subject")
    try:
        threshold = Severity(str(argument))
    except ValueError:
        raise PolicyError(f"attack_path_severity_at_least: {argument!r} is not a severity") from None

    open_paths = []
    for path in claims.attack_paths:
        if not isinstance(path, dict) or path.get("broken"):
            continue
        try:
            severity = Severity(str(path.get("severity", "")))
        except ValueError:
            # A path whose severity this release does not know is not a path
            # this rule can dismiss. Treating it as below the threshold would
            # let a document from a newer producer disarm the rule.
            raise Unevaluable(
                f"an attack path records severity {path.get('severity')!r}, which is not one of "
                f"{', '.join(item.value for item in Severity)}"
            ) from None
        if severity.rank >= threshold.rank:
            open_paths.append(path)

    return bool(open_paths), {
        "threshold": threshold.value,
        "open_paths": [
            {
                "rule_id": path.get("rule_id", "?"),
                "route": " -> ".join(
                    str(hop.get("node", "?")) for hop in path.get("hops", []) if isinstance(hop, dict)
                ),
            }
            for path in open_paths[:10]
        ],
        "count": len(open_paths),
        "closed_paths": sum(
            1 for path in claims.attack_paths if isinstance(path, dict) and path.get("broken")
        ),
    }


def _relation_exists(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    """Whether a declared edge is present. Any field omitted means any value.

    `relation_exists: {from: tool:read_deploy_key, relation: runs_as}` is how
    a policy requires that the secret-reading tool names an identity at all.
    The point of matching on edges rather than on names is D-202: a policy
    that compared two strings would be satisfied by a coincidence.
    """
    if not isinstance(argument, dict) or not argument:
        raise PolicyError("relation_exists: expected a mapping with any of `from`, `relation`, `to`")
    unknown = sorted(set(argument) - {"from", "relation", "to"})
    if unknown:
        raise PolicyError(f"relation_exists: unknown key(s) {', '.join(unknown)}")
    if not claims.relations_known:
        # DEF-82. The old test was `if not claims.relations`, which conflated
        # "this kind of subject never had relations gathered" with "this fully
        # loaded declaration states none". Only the first is a gap. The second
        # is exactly the agent a rule like `relation_exists: {from:
        # tool:read_deploy_key, relation: runs_as}` exists to catch, and it
        # came back REVIEW instead of DENY.
        raise Unevaluable("no relations were gathered for this subject")
    matched = [
        edge
        for edge in claims.relations
        if all(str(edge.get(key, "")) == str(value) for key, value in argument.items())
    ]
    return bool(matched), {"pattern": dict(argument), "matched": matched[:10], "count": len(matched)}


def _evidence_state(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    """Every evidence record attached is in one of these states.

    Universally quantified, not existentially, and the difference is the whole
    value of the predicate. `evidence_state: valid` has to mean "none of the
    evidence behind this decision has gone stale"; if one valid record among
    six revoked ones satisfied it, the rule would pass in exactly the
    situation it exists to catch.
    """
    if not claims.evidence:
        raise Unevaluable("no evidence records are attached to this subject")
    wanted = {str(item) for item in (argument if isinstance(argument, list) else [argument])}
    states = [str(item.get("state", "unknown")) for item in claims.evidence]
    offending = sorted({state for state in states if state not in wanted})
    return not offending, {
        "required": sorted(wanted),
        "states": sorted(set(states)),
        "not_accepted": offending,
        "records": len(claims.evidence),
    }


def _source_revision_pinned(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    """Whether the revision this came from is immutable.

    A branch name and a commit digest are both revisions and only one of them
    means the same bytes tomorrow. The test is a digest-shaped revision, which
    is conservative: a tag that a registry happens to have made immutable
    reads as unpinned here, and saying "we cannot tell" about a tag is the
    right answer for a tool that has not asked the registry.
    """
    if not claims.provenance:
        raise Unevaluable("this subject records no provenance, so there is no revision to judge")
    revision = str(claims.provenance.get("revision", ""))
    pinned = bool(revision) and (
        revision.startswith("sha256:") or bool(re.fullmatch(r"[0-9a-f]{7,64}", revision))
    )
    return pinned is bool(argument), {
        "expected": bool(argument),
        "actual": pinned,
        "revision": revision or None,
        "uri": claims.provenance.get("uri"),
    }


def _trust_state(claims: Claims, argument: Any, _on: date) -> tuple[bool, dict[str, Any]]:
    """What the environment's trust policy concluded, which is not a signature.

    Kept separate from `signature_verified` and `signer_trusted` on purpose:
    a signature verifying is a cryptographic fact, and whether this
    environment accepts that signer is a local decision made by
    `trust-policy/v1`. Merging them would make "the bytes are intact" and "we
    accept them" one field, which is the oldest mistake in supply-chain
    tooling.
    """
    if not claims.trust:
        raise Unevaluable("no trust policy was applied to this subject")
    state = str(claims.trust.get("state", ""))
    if not state:
        raise Unevaluable("the trust result records no state")
    wanted = {str(item) for item in (argument if isinstance(argument, list) else [argument])}
    return state in wanted, {
        "state": state,
        "accepted": sorted(wanted),
        "reasons": claims.trust.get("reasons", [])[:10],
    }


PREDICATES: dict[str, Predicate] = {
    "finding_severity_at_least": _finding_severity_at_least,
    "finding_rule": _finding_rule,
    "coverage": _coverage,
    "verdict_is": _verdict_is,
    "detected_format": _detected_format,
    "imports_callable": _imports_callable,
    "signature_verified": _signature_verified,
    "signer_trusted": _signer_trusted,
    "time_anchor_trusted": _time_anchor_trusted,
    "evidence_max_age_days": _evidence_max_age_days,
    "fact_is": _fact_is,
    # 2.2, design note D-212
    "subject_kind": _subject_kind,
    "bundle_finding": _bundle_finding,
    "bundle_content_identity": _bundle_content_identity,
    "agent_effect": _agent_effect,
    "agent_finding": _agent_finding,
    "attack_path_severity_at_least": _attack_path_severity_at_least,
    "relation_exists": _relation_exists,
    "evidence_state": _evidence_state,
    "source_revision_pinned": _source_revision_pinned,
    "trust_state": _trust_state,
}


# --------------------------------------------------------------------------
# The decision
# --------------------------------------------------------------------------


def decide(policy: Policy, subjects: list[Claims], on: date) -> PolicyDecision:
    """Evaluate every rule against every subject and return the proof.

    Every rule is evaluated against every subject even after the decision is
    already DENY. Short-circuiting would make the proof depend on rule order,
    and a reader comparing two runs would see a different set of outcomes for
    reasons that have nothing to do with the artifacts.
    """
    outcomes: list[RuleOutcome] = []
    expired: list[dict[str, Any]] = []

    for exception in policy.exceptions:
        if exception.expired_on(on):
            # An expired exception is reported, not silently dropped. The
            # whole risk of a waiver is that it outlives the reason for it,
            # so the run that stops honouring one has to say so.
            expired.append({**exception.to_dict(), "state": "expired"})

    if not subjects:
        # Defect DEF-92. This used to evaluate against `[Claims()]` - a
        # subject with no reference - and emit a proof whose outcomes named
        # `"subject": ""` beside a `"subjects": []` list. A document that
        # contradicts itself is worse than an error: it looks like a decision.
        raise PolicyError(
            "a decision needs at least one subject. `policy check` reports this as a usage error; "
            "an empty proof would be a document about nothing that reads like a document about "
            "something."
        )
    for rule in policy.rules:
        for claims in subjects:
            outcomes.append(_evaluate(rule, claims, policy, on))

    decision = Decision.ALLOW
    for outcome in outcomes:
        if outcome.contributes.rank > decision.rank:
            decision = outcome.contributes

    return PolicyDecision(
        decision=decision,
        policy_id=policy.id,
        policy_version=policy.version,
        policy_digest=policy.digest,
        decided_on=on,
        subjects=tuple(claims.subject for claims in subjects),
        outcomes=tuple(outcomes),
        expired_exceptions=tuple(expired),
        tool_version=__version__,
    )


def _evaluate(rule: Rule, claims: Claims, policy: Policy, on: date) -> RuleOutcome:
    evidence: dict[str, Any] = {}
    matched = True

    # `subject_kind` is a guard, not a condition, so it is evaluated first and
    # it short-circuits. Design note D-212a: without this, a rule reading
    # `subject_kind: bundle` plus `bundle_content_identity: complete` would
    # evaluate its second predicate against an agent - predicates run in
    # sorted order and `bundle_content_identity` sorts first - and that
    # predicate would raise `Unevaluable`, sending the whole decision to
    # REVIEW because a bundle rule was correctly not about this agent. Every
    # multi-kind policy would be permanently inconclusive.
    if "subject_kind" in rule.when:
        try:
            applies, detail = PREDICATES["subject_kind"](claims, rule.when["subject_kind"], on)
        except Unevaluable as gap:
            return RuleOutcome(
                rule_id=rule.id,
                effect=Effect.REVIEW,
                matched=True,
                subject=claims.subject,
                evidence={"subject_kind": {"unevaluable": gap.missing}},
                note="the policy could not tell what kind of subject this is",
            )
        if not applies:
            return RuleOutcome(
                rule_id=rule.id,
                effect=rule.effect,
                matched=False,
                subject=claims.subject,
                evidence={"subject_kind": detail},
                note="this rule is not about this kind of subject",
                applicable=False,
            )
        evidence["subject_kind"] = detail

    for name, argument in sorted(rule.when.items()):
        if name == "subject_kind":
            continue
        predicate = PREDICATES[name]
        try:
            result, detail = predicate(claims, argument, on)
        except Unevaluable as gap:
            # Not False. A requirement that could not be checked has not been
            # met, and a denial that could not be checked has not been
            # cleared: either way a human decides.
            return RuleOutcome(
                rule_id=rule.id,
                effect=Effect.REVIEW,
                matched=True,
                subject=claims.subject,
                evidence={**evidence, name: {"unevaluable": gap.missing}},
                note="the policy could not be evaluated against what this run observed",
            )
        evidence[name] = detail
        matched = matched and result

    waiver = None
    if matched and rule.effect in (Effect.DENY, Effect.REVIEW):
        waiver = _find_waiver(policy, rule.id, claims.subject, on)
    if not matched and rule.effect is Effect.REQUIRE:
        waiver = _find_waiver(policy, rule.id, claims.subject, on)

    return RuleOutcome(
        rule_id=rule.id,
        effect=rule.effect,
        matched=matched,
        subject=claims.subject,
        evidence=evidence,
        waived_by=waiver,
    )


def _find_waiver(policy: Policy, rule_id: str, subject: str, on: date) -> dict[str, Any] | None:
    for exception in policy.exceptions:
        if not exception.applies_to(rule_id, subject):
            continue
        if exception.expired_on(on):
            continue
        return {**exception.to_dict(), "days_remaining": (exception.expires - on).days}
    return None
