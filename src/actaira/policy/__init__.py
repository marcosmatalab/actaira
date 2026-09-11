"""Policy-as-code: a versioned document that turns claims into a decision.

Design note D-111. Everything else in this tool reports. A report is not a
decision, and a pipeline needs one: this artifact either goes to production or
it does not. Until now that step lived in whatever `if` a team wrote around
the exit code, which meant the rule that actually governed a release was in a
CI config nobody reviewed, in a form nobody could diff, attached to no version
and recorded nowhere.

A policy here is a file with a digest. It consumes claims - findings,
coverage, attestation trust, evidence freshness - and returns ALLOW, DENY or
REVIEW together with a proof: every rule, whether it fired, and the exact
evidence that made it fire. No score, no weighting, no threshold on a number
nobody can reconstruct. A decision a reader cannot re-derive from the proof is
a decision this module refuses to emit.
"""
from .engine import decide, load_policy, load_policy_text
from .model import (
    Decision,
    Effect,
    Policy,
    PolicyDecision,
    Rule,
    RuleOutcome,
    Waiver,
)

__all__ = [
    "Decision",
    "Effect",
    "Policy",
    "PolicyDecision",
    "Rule",
    "RuleOutcome",
    "Waiver",
    "decide",
    "load_policy",
    "load_policy_text",
]
