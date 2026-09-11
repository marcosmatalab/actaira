"""What a policy is, what a decision is, and what a proof has to contain.

Design note D-112. The shape here is chosen so that a decision can be checked
by someone who was not there. Three things make that possible and all three
are load-bearing:

* the policy has a digest, so "which rules applied" is answerable later;
* every rule outcome names the evidence that produced it, so "why" is
  answerable without re-running anything;
* the subject is identified by digest, not by path, so "to what" cannot drift.

There is deliberately no score. A percentage hides the difference between a
critical finding and a missing document, and the moment a number exists
somebody tunes the threshold instead of fixing the artifact. The output is a
decision and the reasons for it.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import Any

from ..model import canonical_json

SCHEMA_VERSION = "policy-decision/v1"
POLICY_SCHEMA_VERSION = "policy/v1"


class Effect(str, Enum):
    """What a rule does when its condition matches.

    `require` is the inverse of `deny` and both exist because operators think
    in both directions. "Deny anything with a high-severity finding" and
    "require a complete execution surface" are the same kind of statement
    about different polarities, and forcing one into the other's shape is how
    policy files become unreadable.

    `review` is the third outcome a real pipeline needs: not a refusal, but a
    refusal to decide automatically. Collapsing it into deny is what makes
    teams weaken the deny rules.
    """

    DENY = "deny"
    REQUIRE = "require"
    REVIEW = "review"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REVIEW = "review"

    @property
    def rank(self) -> int:
        """DENY beats REVIEW beats ALLOW, whatever order the rules ran in."""
        return {"allow": 0, "review": 1, "deny": 2}[self.value]


@dataclass(frozen=True)
class Rule:
    """One condition and what it does when it matches.

    `when` is a mapping of predicate name to argument, evaluated by
    `engine.py`. Keeping it data rather than code is the point: a rule is a
    thing that can be hashed, diffed, shipped and reviewed, and a lambda is
    none of those.
    """

    id: str
    effect: Effect
    when: dict[str, Any]
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = {"id": self.id, "effect": self.effect.value, "when": self.when}
        if self.description:
            payload["description"] = self.description
        return payload


@dataclass(frozen=True)
class Waiver:
    """A temporary waiver of one rule, with an owner and an end date.

    The policy file calls these `exceptions`, which is the word operators use
    and the word the roadmap uses. The class is `Waiver` because `Exception`
    is taken in Python and a trailing underscore in a public type name is a
    workaround readers have to decode every time they meet it.

    Every field except `subject` is mandatory, and that is the design. An
    exception with no owner is an exception nobody will ever revisit; one with
    no expiry is a permanent change to the policy written in the place
    reserved for temporary ones. This tool will not load either: `parse`
    raises, so a policy file that tries to grant one does not load at all
    rather than loading with the waiver quietly dropped.
    """

    rule: str
    owner: str
    reason: str
    expires: date
    subject: str | None = None
    ticket: str = ""

    def applies_to(self, rule_id: str, subject_digest: str | None) -> bool:
        if self.rule != rule_id:
            return False
        if self.subject is None:
            return True
        return self.subject == subject_digest

    def expired_on(self, day: date) -> bool:
        return day > self.expires

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "rule": self.rule,
            "owner": self.owner,
            "reason": self.reason,
            "expires": self.expires.isoformat(),
        }
        if self.subject:
            payload["subject"] = self.subject
        if self.ticket:
            payload["ticket"] = self.ticket
        return payload


@dataclass(frozen=True)
class Policy:
    """A named, versioned set of rules with a digest.

    The digest covers the canonical JSON of the whole document, so two
    decisions that cite the same digest were made under exactly the same
    rules, and a decision citing a digest nobody recognises is a decision
    made under a policy that was never reviewed.
    """

    id: str
    version: int
    rules: tuple[Rule, ...]
    exceptions: tuple[Waiver, ...] = ()
    description: str = ""
    source: str = ""

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(canonical_json(self.to_dict())).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": POLICY_SCHEMA_VERSION,
            "policy": self.id,
            "version": self.version,
            "rules": [rule.to_dict() for rule in self.rules],
        }
        if self.description:
            payload["description"] = self.description
        if self.exceptions:
            payload["exceptions"] = [item.to_dict() for item in self.exceptions]
        return payload


@dataclass(frozen=True)
class RuleOutcome:
    """One rule's result, and the evidence that produced it.

    `evidence` is what makes the proof checkable rather than assertive. A rule
    that says "matched" and nothing else is asking to be trusted; one that
    says "matched, because ACT-PKL-002 is CRITICAL and the threshold is HIGH"
    can be argued with.
    """

    rule_id: str
    effect: Effect
    matched: bool
    subject: str
    evidence: dict[str, Any] = field(default_factory=dict)
    waived_by: dict[str, Any] | None = None
    note: str = ""
    # False when the rule's `subject_kind` guard says this rule is not about
    # this kind of subject. Distinct from `matched` because the two mean
    # opposite things for a `require` rule: a requirement that was not met is
    # a denial, and a requirement that does not apply is nothing at all. One
    # boolean for both would make every bundle requirement deny every agent.
    applicable: bool = True

    @property
    def contributes(self) -> Decision:
        """What this outcome pushes the overall decision towards.

        The waiver is checked first, before either branch. Checking it only on
        the `matched` path was a live bug for exactly as long as it took to
        write the test: a `require` rule that was NOT met is the case an
        exception exists to cover, and that is the path the check was missing
        from, so every waiver on a requirement was ignored while every waiver
        on a denial worked.
        """
        if not self.applicable:
            return Decision.ALLOW
        if self.waived_by is not None:
            return Decision.ALLOW
        if not self.matched:
            # A `require` rule that did not match is a requirement that was
            # not met. This is the asymmetry between the two effects and the
            # easiest thing to get backwards.
            return Decision.DENY if self.effect is Effect.REQUIRE else Decision.ALLOW
        return {
            Effect.DENY: Decision.DENY,
            Effect.REVIEW: Decision.REVIEW,
            Effect.REQUIRE: Decision.ALLOW,
        }[self.effect]

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "rule": self.rule_id,
            "effect": self.effect.value,
            "matched": self.matched,
            "subject": self.subject,
            "contributes": self.contributes.value,
        }
        if not self.applicable:
            payload["applicable"] = False
        if self.evidence:
            payload["evidence"] = self.evidence
        if self.waived_by is not None:
            payload["waived_by"] = self.waived_by
        if self.note:
            payload["note"] = self.note
        return payload


@dataclass(frozen=True)
class PolicyDecision:
    """The decision, the proof, and everything needed to re-derive both."""

    decision: Decision
    policy_id: str
    policy_version: int
    policy_digest: str
    decided_on: date
    subjects: tuple[str, ...]
    outcomes: tuple[RuleOutcome, ...]
    expired_exceptions: tuple[dict[str, Any], ...] = ()
    tool_version: str = ""

    @property
    def reasons(self) -> tuple[RuleOutcome, ...]:
        """The outcomes that actually decided it, in severity order.

        A proof tree with forty satisfied rules and one refusal is technically
        complete and practically unreadable. This is what the CLI prints first
        and what a webhook carries: the outcomes whose contribution is not
        ALLOW, worst first.
        """
        return tuple(
            sorted(
                (outcome for outcome in self.outcomes if outcome.contributes is not Decision.ALLOW),
                key=lambda outcome: -outcome.contributes.rank,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "decision": self.decision.value,
            "policy": {
                "id": self.policy_id,
                "version": self.policy_version,
                "digest": self.policy_digest,
            },
            "decided_on": self.decided_on.isoformat(),
            "subjects": list(self.subjects),
            "proof": [outcome.to_dict() for outcome in self.outcomes],
        }
        if self.expired_exceptions:
            payload["expired_exceptions"] = list(self.expired_exceptions)
        if self.tool_version:
            payload["tool_version"] = self.tool_version
        return payload
