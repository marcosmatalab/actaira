"""The contract every compliance control obeys.

Design note D-40, and the decision that keeps this layer from becoming the
thing the governance module was built in reaction to.

A control is a piece of code that looks at something real and reports what it
observed. It never reports whether an organisation complies, because that is
a legal question about a system in its context and no control can answer it.
The distance between those two sentences is the whole design.

Four outcomes, not two, for the same reason the inspector has three verdicts:

  SATISFIED       the control looked and found what the obligation asks for.
                  It says nothing about the rest of the obligation.
  NOT_SATISFIED   the control looked and the thing is absent. This is a fact
                  about the target, not a verdict about the operator.
  INCONCLUSIVE    the control could not decide. A format it cannot read, a
                  target it could not reach, a judgement it declined to make.
                  Never collapsed into NOT_SATISFIED, because "I did not find
                  it" and "it is not there" are different claims and only one
                  of them is usually true.
  NOT_APPLICABLE  the obligation does not bind this target at this date for
                  this role. Distinct from SATISFIED: nothing was checked.

The rule that makes the outcomes mean something: a control may only return
SATISFIED for what it actually inspected. `ACT-C-50-2-MARK` returning
SATISFIED means "every file I read carried a machine-readable marking I could
parse". It does not mean the deployer met Article 50(2), because Article 50(2)
also covers content this control never saw. `covers` and `does_not_cover` on
the result carry that boundary in the output itself rather than in a footnote.

Design note D-41, on why there is no aggregate. Controls are not summed, not
averaged and not weighted. `ControlRun` holds a list and counts by outcome,
and the count is a count: eleven SATISFIED out of fourteen run is not
seventy-eight per cent of anything. The test that walks assessment output
looking for a fabricated score walks this output too.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Any

from ..model import Finding


class Outcome(str, Enum):
    SATISFIED = "satisfied"
    NOT_SATISFIED = "not_satisfied"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"


class Method(str, Enum):
    """How a control reached its outcome, carried into every result.

    A reader has to be able to tell a parsed byte from a language model's
    opinion without reading the source, so the method is part of the record
    and the renderer never hides it.

    DETERMINISTIC  bytes were parsed and a rule decided. Reproducible: the
                   same target gives the same outcome on any machine, and the
                   eval harness asserts exactly that.
    JUDGED         a model judged supplied evidence against the obligation
                   text, and a verifier checked every span it cited. Carries
                   an abstention rate measured on a gold set, published in
                   docs/FIGURES.md rather than asserted here.
    GENERATED      the control drafted an artifact for a human to review. The
                   outcome is never SATISFIED: a draft nobody signed is not
                   evidence, so the best available answer is INCONCLUSIVE
                   with the draft attached.
    """

    DETERMINISTIC = "deterministic"
    JUDGED = "judged"
    GENERATED = "generated"


@dataclass(frozen=True)
class Target:
    """What a control is pointed at.

    Deliberately a directory of files plus a mapping of declarations, and not
    a live system. Actaira reads artifacts; it does not drive a deployment,
    hold credentials or make network calls, and a Target that could name a
    production endpoint would invite all three. A control that wants runtime
    facts asks for them as a declaration file the operator wrote, which is
    evidence with a known provenance rather than a measurement pretending to
    be one.

    `declarations` is whatever `actaira.yaml` in the target directory holds:
    the operator's own statements about roles, systems and where the
    artifacts live. Statements are labelled as such everywhere they surface.
    """

    root: Path
    role: str = "any"
    declarations: dict[str, Any] = field(default_factory=dict)
    files: tuple[Path, ...] = ()

    def declared(self, *path: str, default: Any = None) -> Any:
        cursor: Any = self.declarations
        for key in path:
            if not isinstance(cursor, dict) or key not in cursor:
                return default
            cursor = cursor[key]
        return cursor


@dataclass(frozen=True)
class ControlResult:
    """One control's answer, with the boundary of the answer attached.

    `evidence` holds observed values only: what was parsed, from which file,
    at which offset. Nothing in it is copied from a declaration without being
    labelled `declared_`, because a BOM that repeats the publisher's claims
    adds nothing and the same is true of a control.
    """

    control_id: str
    obligation_ids: tuple[str, ...]
    outcome: Outcome
    method: Method
    evidence: dict[str, Any] = field(default_factory=dict)
    findings: tuple[Finding, ...] = ()
    covers: str = ""
    does_not_cover: str = ""
    inspected: tuple[str, ...] = ()
    abstained_on: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "obligation_ids": list(self.obligation_ids),
            "outcome": self.outcome.value,
            "method": self.method.value,
            "evidence": self.evidence,
            "findings": [f.to_dict() for f in self.findings],
            "covers": self.covers,
            "does_not_cover": self.does_not_cover,
            "inspected": list(self.inspected),
            "abstained_on": list(self.abstained_on),
        }


@dataclass(frozen=True)
class Control:
    """A control definition. Data, so the registry can be walked and printed.

    `obligation_ids` is the join to the catalogue and it is checked in both
    directions by a test: a control naming an obligation that does not exist
    fails, and an obligation whose `controls` tuple names a control that does
    not exist fails too. A dangling edge in a compliance mapping is how a
    tool ends up claiming coverage it does not have.
    """

    id: str
    obligation_ids: tuple[str, ...]
    method: Method
    run: Callable[[Target], ControlResult]
    summary_key: str = ""

    def __call__(self, target: Target) -> ControlResult:
        """Run the control and attach the boundary of its answer.

        Design note D-45. The boundary used to be a literal inside each
        control's success path, and eleven of the fifteen controls therefore
        stated it when they decided something and said nothing when they came
        back INCONCLUSIVE. That is backwards: a reader who gets "inconclusive"
        with no scope cannot tell "I read your files and could not decide" from
        "I was never pointed at anything", and the inconclusive result is the
        one that most needs its scope printed.

        So a control does not get to remember it. The text is prose keyed by
        control id in `i18n/<lang>.json` under `controls`, exactly as the
        obligation catalogue keys its prose (design note D-33), and it is
        attached here, on the way out of every call. A control cannot forget
        it, cannot disagree with the catalogue, and the Spanish reader gets the
        Spanish boundary because the renderer resolves the same key.

        Attached here rather than in the engine because a caller holding a
        Control and invoking it directly, which every test in this repository
        does, must get the same object the engine would have handed them.
        """
        return _with_boundary(self.id, self.run(target))


def _with_boundary(control_id: str, result: ControlResult) -> ControlResult:
    from ..i18n.catalog import load as load_catalog  # noqa: PLC0415 - avoids a cycle

    text = load_catalog("en").get("controls", {}).get(control_id, {})
    covers = str(text.get("covers", "")) or result.covers
    does_not = str(text.get("does_not_cover", "")) or result.does_not_cover
    if covers == result.covers and does_not == result.does_not_cover:
        return result
    return replace(result, covers=covers, does_not_cover=does_not)


def localized_boundary(control_id: str, lang: str) -> tuple[str, str]:
    """The boundary of one control in one language, falling back field by field."""
    from ..i18n.catalog import load as load_catalog  # noqa: PLC0415

    english = load_catalog("en").get("controls", {}).get(control_id, {})
    translated = load_catalog(lang).get("controls", {}).get(control_id, {})
    return (
        str(translated.get("covers") or english.get("covers", "")),
        str(translated.get("does_not_cover") or english.get("does_not_cover", "")),
    )


@dataclass(frozen=True)
class ControlRun:
    """The result of running a set of controls over one target.

    Counts by outcome, never a ratio. See design note D-41.
    """

    results: tuple[ControlResult, ...]
    target_root: str
    role: str

    def counts(self) -> dict[str, int]:
        tally = {outcome.value: 0 for outcome in Outcome}
        for result in self.results:
            tally[result.outcome.value] += 1
        return tally

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target_root,
            "role": self.role,
            "controls_run": len(self.results),
            "counts_not_a_score": self.counts(),
            "results": [r.to_dict() for r in self.results],
        }


def inconclusive(
    control_id: str,
    obligation_ids: Sequence[str],
    method: Method,
    reason: str,
    **evidence: Any,
) -> ControlResult:
    """The answer a control gives when it could not decide.

    A helper, because the failure mode this project keeps finding in other
    tools is that the inconclusive branch is the one nobody writes carefully:
    it degrades to a pass, or to a silent skip, or to an empty report. Making
    it one line long removes the incentive.
    """
    return ControlResult(
        control_id=control_id,
        obligation_ids=tuple(obligation_ids),
        outcome=Outcome.INCONCLUSIVE,
        method=method,
        evidence={"reason": reason, **evidence},
    )
