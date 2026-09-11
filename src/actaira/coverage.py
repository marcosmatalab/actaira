"""What was looked at, surface by surface, and what was deliberately not.

Design note D-100. Until this module existed the report carried one boolean,
`fully_read`, and it had to answer two unrelated questions at once: did every
parser finish, and was the whole file examined. Nothing examines the whole
file. A 4 GB checkpoint holds a few kilobytes of pickle and the rest is float
buffers, and decompressing those buffers would establish nothing about whether
loading the file executes code. So `fully_read` was always going to be False
for an honest inspector, which meant a normal, clean, safe PyTorch checkpoint
came back INCONCLUSIVE and exited 3.

Two bad outcomes follow from one boolean. Teams turn the tool off, or they
pass `--allow-inconclusive` permanently, and then a genuinely unreadable
artifact - a truncated header, a member that would not decompress - arrives
looking exactly like a normal checkpoint. "I chose not to read the weights"
and "I tried to read the header and failed" are not the same statement, and
collapsing them destroys the only distinction that matters.

The unit of certainty here is the claim, not the file. Each surface carries
its own state and its own reason:

    load-time execution surface   COMPLETE     every byte that could execute
    archive structure             COMPLETE     members, ratios, paths
    artifact metadata             COMPLETE     shapes, dtypes, config
    raw tensor content            NOT_ASSESSED outside static-safety scope
    behavioural safety            NOT_ASSESSED requires controlled execution
    organizational facts          NOT_ASSESSED not readable from bytes

NOT_ASSESSED is not a failure and never becomes one. It is a scope statement
with a written reason, and a policy that needs a surface says so explicitly:
`coverage.load_time_execution >= COMPLETE` is a requirement a pipeline can
express, and `raw_tensor_content` is one nobody should ever demand from a
static tool. FAILED is the honest failure: something was in scope, was
attempted, and did not parse.

`fully_read` is still emitted, derived from this, so every consumer written
against the old contract keeps working. Design note D-104 covers that.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = "coverage/v1"


class Surface(str, Enum):
    """The distinct things a claim can be about.

    Ordered from what a static inspector can prove to what it cannot. The
    order is not cosmetic: `Coverage.weakest_in_scope` walks it, and the
    report prints it, so a reader meets provable claims before scope
    statements rather than the other way round.
    """

    LOAD_TIME_EXECUTION = "load_time_execution"
    ARCHIVE_STRUCTURE = "archive_structure"
    ARTIFACT_METADATA = "artifact_metadata"
    RAW_TENSOR_CONTENT = "raw_tensor_content"
    BEHAVIORAL_SAFETY = "behavioral_safety"
    ORGANIZATIONAL_FACTS = "organizational_facts"


class CoverageState(str, Enum):
    """How much of a surface was actually examined.

    `rank` exists so a policy can say "at least PARTIAL" without the caller
    hand-writing a comparison, and so `weakest_in_scope` has a total order.
    NOT_ASSESSED sits outside that order deliberately - it is not "worse than
    partial", it is a different kind of statement - and `in_scope` is what
    separates the two.
    """

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_ASSESSED = "not_assessed"

    @property
    def rank(self) -> int:
        return {"complete": 3, "partial": 2, "failed": 1, "not_assessed": 0}[self.value]

    @property
    def in_scope(self) -> bool:
        """True when the tool undertook to look at this surface."""
        return self is not CoverageState.NOT_ASSESSED


@dataclass(frozen=True)
class SurfaceCoverage:
    """One surface's state, and why it is in that state.

    `reason` is a key, not a sentence. The English and Spanish wording lives
    in `i18n/`, next to every other piece of prose the tool emits, so a
    reader of a Spanish report is not handed an English explanation of why a
    claim is limited. `rules` names the findings that put the surface in this
    state, which is what makes a state clickable: from "PARTIAL" a reader
    reaches the exact finding that limited it.
    """

    surface: Surface
    state: CoverageState
    reason: str
    rules: tuple[str, ...] = ()
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "surface": self.surface.value,
            "state": self.state.value,
            "reason": self.reason,
        }
        if self.rules:
            payload["rules"] = list(self.rules)
        if self.detail:
            payload["detail"] = self.detail
        return payload


# The reason keys. Every one of these has an entry in i18n/en.json and
# i18n/es.json under "coverage", and tests/test_i18n.py fails if one is
# missing in either language.
REASON_READ_IN_FULL = "read_in_full"
REASON_NOT_APPLICABLE_TO_FORMAT = "not_applicable_to_format"
REASON_OUTSIDE_STATIC_SCOPE = "outside_static_execution_scope"
REASON_REQUIRES_EXECUTION = "requires_controlled_execution"
REASON_NOT_READABLE_FROM_BYTES = "not_readable_from_bytes"
REASON_PARSE_FAILED = "parse_failed"
REASON_BUDGET_EXHAUSTED = "budget_exhausted"
REASON_MEMBER_UNREADABLE = "member_unreadable"
REASON_FORMAT_UNKNOWN = "format_not_recognised"
REASON_INSPECTOR_CRASHED = "inspector_raised"
REASON_EMPTY = "artifact_is_empty"


@dataclass
class Coverage:
    """The coverage matrix for one subject.

    A subject is usually an artifact, but nothing here assumes that: a bundle,
    an agent or a whole AI system carries the same six surfaces, which is what
    lets a policy be written once and evaluated against any of them.
    """

    surfaces: dict[Surface, SurfaceCoverage] = field(default_factory=dict)

    def set(self, entry: SurfaceCoverage) -> None:
        """Record a surface's state, keeping the worst one seen.

        Worst-wins rather than last-wins, and this is the invariant that makes
        the matrix trustworthy. Coverage is assembled from several places -
        the branch that ran, the findings it produced, the floor applied
        afterwards - and if a later writer could raise a surface back to
        COMPLETE then the order those writers happen to run in would decide
        what the report claims. A downgrade must be sticky. The one promotion
        allowed is out of NOT_ASSESSED: a surface nobody had undertaken to
        look at can become one that was looked at.
        """
        current = self.surfaces.get(entry.surface)
        if current is None:
            self.surfaces[entry.surface] = entry
            return
        if not current.state.in_scope and entry.state.in_scope:
            self.surfaces[entry.surface] = entry
            return
        if not entry.state.in_scope:
            return
        if entry.state.rank < current.state.rank:
            self.surfaces[entry.surface] = entry

    def state(self, surface: Surface) -> CoverageState:
        entry = self.surfaces.get(surface)
        return entry.state if entry is not None else CoverageState.NOT_ASSESSED

    def reason(self, surface: Surface) -> str:
        entry = self.surfaces.get(surface)
        return entry.reason if entry is not None else REASON_NOT_APPLICABLE_TO_FORMAT

    def satisfies(self, surface: Surface, required: CoverageState) -> bool:
        """Whether this coverage meets a requirement a policy states.

        A requirement of NOT_ASSESSED is meaningless and returns True for
        anything: asking for "at least a scope statement" is asking for
        nothing. Every other requirement is a rank comparison, and
        NOT_ASSESSED never satisfies it - which is the point. A policy that
        requires a COMPLETE execution surface must not be satisfied by a tool
        that declined to look.
        """
        if required is CoverageState.NOT_ASSESSED:
            return True
        return self.state(surface).rank >= required.rank

    def in_scope(self) -> list[SurfaceCoverage]:
        return [entry for entry in self.ordered() if entry.state.in_scope]

    def weakest_in_scope(self) -> SurfaceCoverage | None:
        """The surface that limits what this report can be used for."""
        candidates = self.in_scope()
        if not candidates:
            return None
        return min(candidates, key=lambda entry: entry.state.rank)

    def ordered(self) -> list[SurfaceCoverage]:
        return [self.surfaces[surface] for surface in Surface if surface in self.surfaces]

    def rules(self) -> tuple[str, ...]:
        seen: list[str] = []
        for entry in self.ordered():
            for rule in entry.rules:
                if rule not in seen:
                    seen.append(rule)
        return tuple(seen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "surfaces": [entry.to_dict() for entry in self.ordered()],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Coverage:
        coverage = cls()
        for raw in payload.get("surfaces", []):
            coverage.surfaces[Surface(raw["surface"])] = SurfaceCoverage(
                surface=Surface(raw["surface"]),
                state=CoverageState(raw["state"]),
                reason=raw.get("reason", REASON_NOT_APPLICABLE_TO_FORMAT),
                rules=tuple(raw.get("rules", ())),
                detail=dict(raw.get("detail", {})),
            )
        return coverage


def not_assessed(surface: Surface, reason: str) -> SurfaceCoverage:
    return SurfaceCoverage(surface=surface, state=CoverageState.NOT_ASSESSED, reason=reason)


# The three surfaces no static inspector can ever cover, stated once rather
# than repeated in every branch. `behavioral_safety` needs the artifact to
# run, which is the one thing this tool promises never to do; organizational
# facts are about people and procedures; raw tensor content is deliberately
# out of scope, because a float buffer is data and this tool looks for code.
def baseline() -> Coverage:
    coverage = Coverage()
    coverage.set(not_assessed(Surface.RAW_TENSOR_CONTENT, REASON_OUTSIDE_STATIC_SCOPE))
    coverage.set(not_assessed(Surface.BEHAVIORAL_SAFETY, REASON_REQUIRES_EXECUTION))
    coverage.set(not_assessed(Surface.ORGANIZATIONAL_FACTS, REASON_NOT_READABLE_FROM_BYTES))
    return coverage


# Which surface each rule speaks about, and what state it forces.
#
# Design note D-101, and the reason this table exists at all. The previous
# version had one flat set, `UNREAD_RULE_IDS`, whose members were the rules
# that meant "something was not read". ACT-ZIP-007 was in it, and ACT-ZIP-007
# fires on every PyTorch checkpoint ever made, because a checkpoint is mostly
# storage blobs. So "I did not decompress 3.9 GB of float32" and "the header
# is truncated" produced the same verdict, and the first is the normal case.
#
# Assigning a surface to each rule is what separates them. A rule now has to
# say what it limits, and a rule that limits nothing a static tool claims -
# raw tensor content - does not touch the execution verdict at all.
_RULE_COVERAGE: dict[str, tuple[Surface, CoverageState, str]] = {
    # Format-level: nothing was read, so nothing is claimed.
    "ACT-FMT-001": (Surface.LOAD_TIME_EXECUTION, CoverageState.FAILED, REASON_FORMAT_UNKNOWN),
    "ACT-FMT-003": (Surface.LOAD_TIME_EXECUTION, CoverageState.FAILED, REASON_EMPTY),
    # Pickle: the execution surface itself.
    "ACT-PKL-006": (Surface.LOAD_TIME_EXECUTION, CoverageState.FAILED, REASON_PARSE_FAILED),
    "ACT-PKL-008": (Surface.LOAD_TIME_EXECUTION, CoverageState.PARTIAL, REASON_BUDGET_EXHAUSTED),
    "ACT-PKL-013": (Surface.LOAD_TIME_EXECUTION, CoverageState.PARTIAL, REASON_BUDGET_EXHAUSTED),
    "ACT-PKL-014": (Surface.LOAD_TIME_EXECUTION, CoverageState.FAILED, REASON_BUDGET_EXHAUSTED),
    # Archive: a member that would not open is an execution-surface gap,
    # because what was in it is unknown and it might have been a pickle.
    "ACT-ZIP-003": (Surface.LOAD_TIME_EXECUTION, CoverageState.PARTIAL, REASON_MEMBER_UNREADABLE),
    "ACT-ZIP-004": (Surface.ARCHIVE_STRUCTURE, CoverageState.PARTIAL, REASON_BUDGET_EXHAUSTED),
    "ACT-ZIP-005": (Surface.ARCHIVE_STRUCTURE, CoverageState.FAILED, REASON_PARSE_FAILED),
    "ACT-ZIP-006": (Surface.LOAD_TIME_EXECUTION, CoverageState.PARTIAL, REASON_BUDGET_EXHAUSTED),
    # ACT-ZIP-007 is the whole point of this table. It reports members that
    # were classified by content and found not to be pickles, so their bytes
    # were never decompressed in full. That limits raw tensor content and
    # nothing else, and raw tensor content was never in scope.
    "ACT-ZIP-007": (Surface.RAW_TENSOR_CONTENT, CoverageState.NOT_ASSESSED, REASON_OUTSIDE_STATIC_SCOPE),
    # A member whose head could not be peeked at all: unknown content, so the
    # execution surface really is incomplete.
    "ACT-ZIP-009": (Surface.LOAD_TIME_EXECUTION, CoverageState.PARTIAL, REASON_MEMBER_UNREADABLE),
    # ONNX, GGUF, NumPy, HDF5, safetensors: metadata parsers.
    "ACT-ONX-003": (Surface.ARTIFACT_METADATA, CoverageState.FAILED, REASON_PARSE_FAILED),
    "ACT-ONX-004": (Surface.ARTIFACT_METADATA, CoverageState.FAILED, REASON_BUDGET_EXHAUSTED),
    "ACT-GGF-001": (Surface.ARTIFACT_METADATA, CoverageState.FAILED, REASON_PARSE_FAILED),
    "ACT-GGF-003": (Surface.ARTIFACT_METADATA, CoverageState.PARTIAL, REASON_BUDGET_EXHAUSTED),
    "ACT-GGF-004": (Surface.ARTIFACT_METADATA, CoverageState.PARTIAL, REASON_PARSE_FAILED),
    "ACT-NPY-002": (Surface.ARTIFACT_METADATA, CoverageState.FAILED, REASON_PARSE_FAILED),
    "ACT-H5-003": (Surface.LOAD_TIME_EXECUTION, CoverageState.PARTIAL, REASON_PARSE_FAILED),
    "ACT-H5-004": (Surface.ARTIFACT_METADATA, CoverageState.FAILED, REASON_PARSE_FAILED),
    "ACT-STF-001": (Surface.ARTIFACT_METADATA, CoverageState.FAILED, REASON_BUDGET_EXHAUSTED),
    "ACT-STF-002": (Surface.ARTIFACT_METADATA, CoverageState.FAILED, REASON_PARSE_FAILED),
    "ACT-STF-007": (Surface.ARTIFACT_METADATA, CoverageState.FAILED, REASON_PARSE_FAILED),
}


def rule_effect(rule_id: str) -> tuple[Surface, CoverageState, str] | None:
    return _RULE_COVERAGE.get(rule_id)


def classified_rules() -> frozenset[str]:
    return frozenset(_RULE_COVERAGE)


def apply_findings(coverage: Coverage, rule_ids: Iterable[str]) -> Coverage:
    """Fold every finding's coverage effect into the matrix.

    Order-independent by construction, because `Coverage.set` keeps the worst
    state per surface. That property is load-bearing: findings arrive in
    whatever order an inspector produced them, and a report whose coverage
    depended on that order would be a report whose coverage was arbitrary.
    """
    grouped: dict[tuple[Surface, CoverageState, str], list[str]] = {}
    for rule_id in rule_ids:
        effect = _RULE_COVERAGE.get(rule_id)
        if effect is None:
            continue
        grouped.setdefault(effect, []).append(rule_id)
    for (surface, state, reason), rules in grouped.items():
        coverage.set(
            SurfaceCoverage(surface=surface, state=state, reason=reason, rules=tuple(sorted(set(rules))))
        )
    return coverage
