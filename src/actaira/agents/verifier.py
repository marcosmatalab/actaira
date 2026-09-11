"""Checking the judge, and refusing to take its word for anything.

Design note D-49. Two questions are asked of every citation, and they fail in
completely different ways, so they are answered separately and reported
separately.

(a) **Is the quotation real?** `document[start:end] == quote`, exactly, byte
    for byte after decoding. This is the cheap check and it is the one that
    matters most, because the failure it catches is the one that destroys the
    output's value: a fabricated sentence attributed to the operator's own
    compliance document. A single failed literal check invalidates the entire
    answer, not just that citation. The reasoning is the same as for a
    witness caught inventing one quotation: the remaining testimony is not
    partially reliable, it is unweighable. The pipeline abstains.

(b) **Does the quotation support the claim?** This is a judgement, not a
    comparison, and the check is verdict-dependent, which is the part worth
    arguing about:

      * For `addressed`, the claim is "the document supplies what the
        obligation asks for". A quotation supports it by being written in the
        vocabulary of what is asked for. So the check is a *floor* on the
        overlap between the quotation's content terms and the terms of the
        obligation's `evidence_expected` spans.
      * For `not_addressed`, the claim is "the document does not supply it".
        A quotation supports *that* by being the nearest thing the document
        offers and still falling short. So the check is a *ceiling*: if the
        judge says the obligation is unmet while quoting a passage that
        plainly states the asked-for measure, the judge has contradicted its
        own evidence and the answer is thrown out.

    The second direction is not symmetry for its own sake. Without it the
    verifier could only ever catch an over-claiming judge, and a grader that
    marks everything unmet would sail through — which is the failure mode a
    conservative model actually has.

The overlap is computed against the `evidence_expected` spans specifically,
never the `summary` spans. See `corpus.evidence_spans`: the summary describes
the obligation and therefore agrees with any document on the same topic,
which is exactly the hard negative this whole gold set is built around.

**On the thresholds.** They are fitted, not chosen. `calibrate()` sweeps both
over a grid, replays the full pipeline policy on labelled samples, and
maximises (answered correctly − answered incorrectly), an objective that
prices a wrong answer at exactly what a right one is worth and an abstention
at nothing. The fit is done on a calibration split of the gold set and the
numbers the harness publishes are computed on the held-out half, so the
threshold has not seen the pairs it is scored on. The sweep table for the
values below is in the constants' own comments, and `tests/test_agents.py`
re-runs the fit and fails if the constants and the data disagree.

**What this is not.** The lexical check is a stand-in for entailment, and a
weak one: it can be satisfied by a sentence that uses every right word in the
wrong order. `check_support_entailment` is the real thing and runs when a
provider is configured. The offline path is what makes the harness runnable
with no key, and the harness labels every figure it produces with which path
produced it, because a grounding number from a term-overlap check and one
from a model are not the same measurement and must never be averaged.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Any

from ..governance.catalog import Obligation
from . import corpus
from .corpus import Span
from .judge import Citation, JudgeVerdict
from .provider import LLMProvider

# ---------------------------------------------------------------------------
# The calibrated thresholds
# ---------------------------------------------------------------------------
#
# Fitted by `calibrate()` on the calibration split of evals/agents/gold.json
# (the odd-indexed pairs; the split rule is `harness.split_of`). Regenerate
# with `python3 evals/agents/harness.py --calibrate`, which writes the sweep
# to evals/agents/calibration.json. `tests/test_agents.py` re-runs the fit and
# fails if these constants drift from what the data supports.
#
# THE FIT, and the part of it that matters more than the numbers.
#
#   grid            floor and ceiling over 0.00..0.80 in steps of 0.05,
#                   minimum quote terms over 0..12: 3757 cells.
#   admissible      938 of them. The other 2819 break one of the harness's
#                   negative controls and are not candidates at any score;
#                   see `Constraint`.
#   objective       correct - incorrect over the answered pairs, maximised
#                   inside the admissible region. Best value 21, on a
#                   calibration split of 32 pairs: 23 correct, 2 incorrect,
#                   7 abstentions.
#   generalisation  the same triple on the 33 held-out pairs: 23 correct, 1
#                   incorrect, 9 abstentions. No gap, which is the only
#                   evidence available here that three fitted parameters on
#                   32 samples did not simply memorise them.
#
# WHAT THE DATA ACTUALLY IDENTIFIES. The winning plateau is 42 cells wide and
# every single one of them has `min_terms = 12`. Within it the floor ranges
# over 0.00..0.25 and the ceiling over 0.50..0.80 with *identical* counts in
# every cell. So this data identifies exactly one of the three parameters.
# The quotation-length rule is carrying the signal; the two overlap ratios are
# not distinguishable at all in that region, and the values below for them
# come from the tie-break — fewest answers, then the most conservative corner
# — and not from evidence. Written down here rather than left implicit,
# because a reader who assumed all three had been measured would trust the
# floor and the ceiling more than this corpus can support.

#: Minimum share of a quotation's content terms that must also appear in the
#: obligation's `evidence_expected` vocabulary, for an `addressed` verdict.
#: The upper end of the identified-nothing plateau; see above.
SUPPORT_FLOOR_ADDRESSED = 0.25

#: Maximum share of that overlap for a `not_addressed` verdict. Above this,
#: the judge is quoting a passage that states the asked-for measure while
#: claiming the obligation is unmet, and the answer is discarded. The lower
#: end of the plateau, for the same reason.
SUPPORT_CEILING_NOT_ADDRESSED = 0.5

#: Minimum content terms a quotation must have before its ratio is allowed to
#: support `addressed` at all. The one parameter this corpus identifies.
#:
#: The parameter exists for a resolution argument, not a tuning one. The
#: ratio's denominator is the quotation's content terms; a three-term
#: quotation can only take the values 0, 1/3, 2/3 and 1, so any floor below
#: 0.34 is satisfied by a single matching word and the check has nothing left
#: to discriminate with.
#:
#: It was found, not foreseen. The first measured run had the stand-in judge
#: citing the documents' own markdown headings — "# AI literacy measures",
#: three content terms, all three in the obligation's vocabulary, ratio 1.0 —
#: as the evidence that a measure had been taken, and the verifier waved it
#: through on `filler`, `crossref` and `wrong_actor` documents alike. A title
#: is the subject of a document, never evidence about it.
MIN_QUOTE_TERMS_ADDRESSED = 12

#: The grid `calibrate()` sweeps. Coarse on purpose: a finer grid on 33
#: calibration pairs fits noise, and the objective is flat over wide plateaus
#: anyway, which the sweep table shows.
GRID: tuple[float, ...] = tuple(round(0.05 * step, 2) for step in range(17))

#: The grid for `MIN_QUOTE_TERMS_ADDRESSED`. Three fitted parameters on a
#: calibration split of 33 pairs is more freedom than that many samples
#: really support, and the harness is written so a reader can see it: it
#: prints the objective on the calibration split and on the held-out split
#: side by side, and a gap between them is what overfitting looks like here.
TERM_GRID: tuple[int, ...] = tuple(range(0, 13))


@dataclass(frozen=True)
class CitationCheck:
    """The verdict on one citation, with the counts behind it.

    Counts, not a ratio, in the output. `overlap_terms` and `quote_terms` are
    two integers a reader can divide themselves if they want to; a float
    printed next to a regulation citation reads as a confidence, and this
    project does not publish those. Design note D-41.
    """

    citation: Citation
    literal: bool
    supported: bool
    overlap_terms: int
    quote_terms: int
    reason: str
    method: str = "lexical"

    @property
    def ok(self) -> bool:
        return self.literal and self.supported

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.citation.start,
            "end": self.citation.end,
            "quote": self.citation.quote,
            "literal": self.literal,
            "supported": self.supported,
            "overlap_terms": self.overlap_terms,
            "quote_terms": self.quote_terms,
            "reason": self.reason,
            "method": self.method,
        }


# ---------------------------------------------------------------------------
# (a) the quotation is real
# ---------------------------------------------------------------------------

def check_literal(document: str, citation: Citation) -> tuple[bool, str]:
    """Is `document[start:end]` exactly `quote`?

    Four ways to fail, each named, because "citation invalid" in a report
    that a compliance officer reads has to say which kind of invalid:

      * offsets out of range, or inverted. A model that emitted `end` before
        `start` produces an empty slice in Python rather than an error, which
        would silently pass an empty-quote check.
      * an empty or whitespace-only quotation. Grounding a verdict on `""`
        is trivially "literal" and means nothing.
      * a mismatch: the offsets point somewhere real but not there. This is
        the off-by-N case, usually a model counting from the wrong origin.
      * a fabrication: the quoted text does not occur in the document at all.
        Distinguished from a mismatch, because they need different fixes —
        one is a prompt bug, the other is the model inventing evidence — and
        a report that conflated them would send the reader to the wrong one.
    """
    start, end = citation.start, citation.end
    if not citation.quote.strip():
        return False, "empty quotation"
    if start < 0 or end > len(document) or start >= end:
        return False, f"offsets [{start}:{end}] are outside the document (length {len(document)})"
    found = document[start:end]
    if found == citation.quote:
        return True, ""
    if citation.quote not in document:
        return False, "quoted text does not occur anywhere in the document"
    return False, f"offsets point at {found[:60]!r}, not at the quoted text"


# ---------------------------------------------------------------------------
# (b) the quotation supports the claim
# ---------------------------------------------------------------------------

def support_overlap(quote: str, spans: tuple[Span, ...]) -> tuple[int, int]:
    """`(overlapping content terms, content terms in the quotation)`.

    The denominator is the quotation, not the obligation. "How much of what
    you quoted is about what the obligation asks for" is the question; the
    other direction ("how much of the obligation does this quotation cover")
    would punish a correct citation for being one sentence rather than the
    whole policy, and one sentence is what the judge was told to give.
    """
    terms = corpus.content_terms(quote)
    if not terms:
        return 0, 0
    vocabulary: set[str] = set()
    for span in corpus.evidence_spans(spans):
        vocabulary |= corpus.content_terms(span.text)
    return len(terms & vocabulary), len(terms)


def check_support_lexical(
    quote: str,
    verdict: JudgeVerdict,
    spans: tuple[Span, ...],
    *,
    floor: float = SUPPORT_FLOOR_ADDRESSED,
    ceiling: float = SUPPORT_CEILING_NOT_ADDRESSED,
    min_terms: int = MIN_QUOTE_TERMS_ADDRESSED,
) -> tuple[bool, int, int, str]:
    """The offline support check. See the module docstring for the direction."""
    overlap, total = support_overlap(quote, spans)
    if not total:
        return False, 0, 0, "the quotation has no content terms"
    ratio = overlap / total
    if verdict is JudgeVerdict.ADDRESSED:
        if total < min_terms:
            return (
                False,
                overlap,
                total,
                f"the quotation carries {total} content terms, fewer than the {min_terms} needed for "
                "the overlap to mean anything; a heading or a fragment is not evidence of a measure",
            )
        if ratio >= floor:
            return True, overlap, total, ""
        return (
            False,
            overlap,
            total,
            f"only {overlap} of {total} content terms are in what the obligation asks for; "
            "this quotation is on the topic but does not state the measure",
        )
    if verdict is JudgeVerdict.NOT_ADDRESSED:
        if ratio <= ceiling:
            return True, overlap, total, ""
        return (
            False,
            overlap,
            total,
            f"{overlap} of {total} content terms are in what the obligation asks for; "
            "the judge called the obligation unmet while quoting a passage that states it",
        )
    # ABSTAIN carries no claim for a citation to support.
    return True, overlap, total, ""


def entailment_prompt(quote: str, obligation: Obligation, spans: tuple[Span, ...], verdict: JudgeVerdict) -> str:
    """The prompt `check_support_entailment` sends. Separate so it is testable.

    Deliberately not the judging prompt with a different question bolted on.
    The verifier has to be able to disagree with the judge, and a verifier
    that saw the judge's reasoning would agree with it; it is shown the
    quotation and the obligation and nothing else.
    """
    asked = "\n".join(f"  - {span.text}" for span in corpus.evidence_spans(spans))
    claim = {
        JudgeVerdict.ADDRESSED: "this passage supplies what the obligation asks for",
        JudgeVerdict.NOT_ADDRESSED: "this passage falls short of what the obligation asks for",
        JudgeVerdict.ABSTAIN: "this passage is relevant to the obligation",
    }[verdict]
    return "\n".join(
        [
            f"Obligation {obligation.id} ({obligation.article}) asks for:",
            asked,
            "",
            "A passage from an operator's document:",
            f"  {quote}",
            "",
            f"Claim: {claim}.",
            "Answer with one JSON object: {\"supports\": true|false, \"why\": \"<one sentence>\"}",
        ]
    )


def check_support_entailment(
    quote: str,
    verdict: JudgeVerdict,
    obligation: Obligation,
    spans: tuple[Span, ...],
    provider: LLMProvider,
) -> tuple[bool, str]:
    """The support check when a real provider is configured.

    Never reached by the test suite or the eval harness: both run on
    cassettes, and recording a second round trip per citation would triple
    the corpus for a check whose offline stand-in is what the published
    numbers were measured with. It is here so an operator who configures
    `HTTPProvider` gets entailment rather than term overlap, and so that the
    difference between the two paths is a code path a reviewer can read
    rather than a footnote.

    A provider failure is `False`, not an exception: the verifier's job is to
    withhold approval when it cannot confirm, and an unreachable endpoint is
    a case where it cannot confirm.
    """
    import json

    prompt = entailment_prompt(quote, obligation, spans, verdict)
    try:
        answer = provider.complete(prompt, max_tokens=200, temperature=0.0)
    except Exception as exc:  # noqa: BLE001 - see the docstring
        return False, f"the verifier could not reach its provider: {type(exc).__name__}: {exc}"
    try:
        start = answer.text.index("{")
        payload = json.loads(answer.text[start : answer.text.rindex("}") + 1])
    except (ValueError, TypeError) as exc:
        return False, f"the verifier's provider did not answer in the required shape: {exc}"
    supports = payload.get("supports")
    if not isinstance(supports, bool):
        return False, "the verifier's provider did not answer with a boolean"
    return supports, str(payload.get("why", ""))[:200]


# ---------------------------------------------------------------------------
# The whole answer
# ---------------------------------------------------------------------------

def verify(
    document: str,
    verdict: JudgeVerdict,
    citations: tuple[Citation, ...],
    spans: tuple[Span, ...],
    *,
    floor: float = SUPPORT_FLOOR_ADDRESSED,
    ceiling: float = SUPPORT_CEILING_NOT_ADDRESSED,
    min_terms: int = MIN_QUOTE_TERMS_ADDRESSED,
    obligation: Obligation | None = None,
    provider: LLMProvider | None = None,
) -> tuple[CitationCheck, ...]:
    """Check every citation. Order preserved, nothing dropped.

    Every citation is checked even after one has already failed. The
    pipeline only needs to know that one failed, but the eval harness needs
    the whole picture — "one of four citations was fabricated" and "four of
    four were" are different diagnoses of the same discarded answer.

    The support check is skipped when the literal check failed. Computing an
    overlap against a quotation that is not in the document would produce a
    number about a sentence the model invented, and that number would then
    appear in the output next to the words "supported: true".
    """
    checks: list[CitationCheck] = []
    for citation in citations:
        literal, literal_reason = check_literal(document, citation)
        if not literal:
            checks.append(
                CitationCheck(
                    citation=citation,
                    literal=False,
                    supported=False,
                    overlap_terms=0,
                    quote_terms=0,
                    reason=literal_reason,
                    method="literal",
                )
            )
            continue
        if provider is not None and obligation is not None:
            supported, reason = check_support_entailment(citation.quote, verdict, obligation, spans, provider)
            overlap, total = support_overlap(citation.quote, spans)
            method = "entailment"
        else:
            supported, overlap, total, reason = check_support_lexical(
                citation.quote, verdict, spans, floor=floor, ceiling=ceiling, min_terms=min_terms
            )
            method = "lexical"
        checks.append(
            CitationCheck(
                citation=citation,
                literal=True,
                supported=supported,
                overlap_terms=overlap,
                quote_terms=total,
                reason=reason,
                method=method,
            )
        )
    return tuple(checks)


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CalibrationSample:
    """One gold pair, reduced to what the threshold can change.

    Extracted once by the harness so the sweep does not re-run the pipeline
    289 times per pair. The reduction is exact: `ratios` is the support ratio
    of each citation, and nothing else in the policy depends on the
    thresholds, which is asserted by the harness re-running the real pipeline
    at the fitted values and comparing against `simulate`.
    """

    pair_id: str
    gold_label: str
    judge_verdict: str
    all_literal: bool
    has_citations: bool
    empty_document: bool
    ratios: tuple[float, ...]
    quote_terms: tuple[int, ...]


def simulate(sample: CalibrationSample, floor: float, ceiling: float, min_terms: int) -> str:
    """Replay the pipeline's decision for one sample at one threshold pair.

    A second implementation of the policy in `pipeline.decide`, which is a
    duplication and is deliberate: the harness asserts that the two agree at
    the fitted thresholds over the whole gold set. A sweep that shared code
    with the thing it is fitting would be unable to detect the case where the
    policy changed and the calibration silently kept optimising the old one.
    """
    if sample.judge_verdict == JudgeVerdict.ABSTAIN.value:
        return JudgeVerdict.ABSTAIN.value
    if not sample.has_citations:
        if sample.judge_verdict == JudgeVerdict.NOT_ADDRESSED.value and sample.empty_document:
            return JudgeVerdict.NOT_ADDRESSED.value
        return JudgeVerdict.ABSTAIN.value
    if not sample.all_literal:
        return JudgeVerdict.ABSTAIN.value
    for ratio, terms in zip(sample.ratios, sample.quote_terms, strict=True):
        if sample.judge_verdict == JudgeVerdict.ADDRESSED.value and (terms < min_terms or ratio < floor):
            return JudgeVerdict.ABSTAIN.value
        if sample.judge_verdict == JudgeVerdict.NOT_ADDRESSED.value and ratio > ceiling:
            return JudgeVerdict.ABSTAIN.value
    return sample.judge_verdict


def score_thresholds(
    samples: list[CalibrationSample], floor: float, ceiling: float, min_terms: int
) -> dict[str, int]:
    correct = incorrect = abstained = 0
    for sample in samples:
        decision = simulate(sample, floor, ceiling, min_terms)
        if decision == JudgeVerdict.ABSTAIN.value:
            abstained += 1
        elif decision == sample.gold_label:
            correct += 1
        else:
            incorrect += 1
    return {
        "correct": correct,
        "incorrect": incorrect,
        "abstained": abstained,
        "objective": correct - incorrect,
    }


@dataclass(frozen=True)
class Constraint:
    """A behaviour the thresholds are not allowed to break.

    Calibration without this was measurably wrong, and the failure is worth
    recording because it is the standard one for a fitted parameter. The
    first fit maximised the objective freely and chose a ceiling of 0.05,
    under which essentially every `not_addressed` citation is rejected —
    scoring well by abstaining on almost everything, and taking the harness's
    second negative control with it: a document that addresses a *different*
    obligation stopped coming out `not_addressed` and started coming out
    `abstain`.

    The negative controls are requirements, not metrics. A threshold triple
    that breaks one is not a worse candidate, it is not a candidate, so the
    search is restricted to the admissible region and the objective decides
    only within it. If the region turns out to be empty the fit says so
    rather than quietly returning the unconstrained winner — an empty region
    means the policy and the controls disagree, which is a design problem and
    not something to optimise around.

    Two shapes, because the controls have two shapes:

      VERDICT   this sample must decide to exactly this verdict. Blank
                documents must be `not_addressed`; misfiled documents must be
                `not_addressed`.
      DIFFERS   this sample must decide `addressed`, and its partner (the
                same document with the load-bearing sentence deleted) must
                not. The ablation control cannot be written as a fixed
                verdict, because what the ablated document *becomes* is not
                the point; that it changes is.
    """

    VERDICT = "verdict"
    DIFFERS = "differs"

    kind: str
    label: str
    sample: CalibrationSample
    required: str = ""
    partner: CalibrationSample | None = None

    def holds(self, floor: float, ceiling: float, min_terms: int) -> bool:
        decided = simulate(self.sample, floor, ceiling, min_terms)
        if self.kind == self.VERDICT:
            return decided == self.required
        if self.partner is None:  # pragma: no cover - guards a caller bug
            raise ValueError(f"{self.label}: a DIFFERS constraint needs a partner")
        other = simulate(self.partner, floor, ceiling, min_terms)
        return decided == JudgeVerdict.ADDRESSED.value and other != decided


def calibrate(
    samples: list[CalibrationSample],
    grid: tuple[float, ...] = GRID,
    term_grid: tuple[int, ...] = TERM_GRID,
    constraints: tuple[Constraint, ...] = (),
) -> dict[str, Any]:
    """Fit both thresholds. Deterministic, including the tie-break.

    The objective is `correct - incorrect` over the answered pairs. It prices
    a wrong answer at exactly what a right one is worth and an abstention at
    zero, which is the trade this tool actually faces: an abstention costs an
    operator a manual review, a wrong `addressed` costs them a finding they
    believed was covered.

    Ties are broken towards caution, in this order: fewer answers, then a
    higher floor, then a lower ceiling. On a plateau — and the objective has
    wide plateaus on a set this size — that picks the corner that abstains
    most, because among threshold pairs the data cannot distinguish, the one
    that hands more cases to a human is the one to ship.
    """
    rows: list[dict[str, Any]] = []
    for floor, ceiling, min_terms in itertools.product(grid, grid, term_grid):
        # `score_thresholds` returns counts; the columns added below are the
        # thresholds themselves and the admissibility verdict, which are not.
        row: dict[str, Any] = dict(score_thresholds(samples, floor, ceiling, min_terms))
        broken = sorted(c.label for c in constraints if not c.holds(floor, ceiling, min_terms))
        row.update(
            {"floor": floor, "ceiling": ceiling, "min_terms": min_terms, "admissible": not broken, "broken": broken}
        )
        rows.append(row)
    admissible = [row for row in rows if row["admissible"]]
    if constraints and not admissible:
        # Nothing to optimise over. Reported rather than worked around: see
        # `Constraint`. The caller gets the unconstrained surface so a human
        # can see which constraint is impossible and why.
        return {
            "n_samples": len(samples),
            "constraints": [c.label for c in constraints],
            "admissible_cells": 0,
            "cells": len(rows),
            "chosen": None,
            "error": "no threshold triple satisfies every negative control",
            "most_nearly_admissible": sorted(rows, key=lambda row: (len(row["broken"]), -row["objective"]))[:5],
        }
    best = min(
        admissible or rows,
        key=lambda row: (
            -row["objective"],
            row["correct"] + row["incorrect"],
            -row["floor"],
            row["ceiling"],
            -row["min_terms"],
        ),
    )
    return {
        "n_samples": len(samples),
        "grid": list(grid),
        "term_grid": list(term_grid),
        "constraints": [c.label for c in constraints],
        "admissible_cells": len(admissible),
        "objective": "correct_minus_incorrect_over_answered, maximised inside the admissible region",
        "tie_break": "fewest answered, then highest floor, then lowest ceiling, then highest min_terms",
        "chosen": {
            "floor": best["floor"],
            "ceiling": best["ceiling"],
            "min_terms": best["min_terms"],
        },
        "chosen_counts": {
            "correct": best["correct"],
            "incorrect": best["incorrect"],
            "abstained": best["abstained"],
        },
        "shipped": {
            "floor": SUPPORT_FLOOR_ADDRESSED,
            "ceiling": SUPPORT_CEILING_NOT_ADDRESSED,
            "min_terms": MIN_QUOTE_TERMS_ADDRESSED,
        },
        # Only the cells on the winning objective are kept. The full product is
        # 17 x 17 x 13 = 3757 rows, and a JSON file nobody opens is not a
        # published sweep, it is ballast.
        "plateau": sorted(
            (
                {
                    "floor": row["floor"],
                    "ceiling": row["ceiling"],
                    "min_terms": row["min_terms"],
                    "correct": row["correct"],
                    "incorrect": row["incorrect"],
                    "abstained": row["abstained"],
                }
                for row in (admissible or rows)
                if row["objective"] == best["objective"]
            ),
            key=lambda row: (row["floor"], row["ceiling"], row["min_terms"]),
        ),
        "cells": len(rows),
    }
