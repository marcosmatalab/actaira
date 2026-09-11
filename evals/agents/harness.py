"""The judged-evidence eval. Every figure published about the judge is here.

Design note D-52, on what this measures, what it refuses to measure, and the
one caveat that has to travel with every number it prints.

**The caveat first, because it changes how everything below should be read.**
The cassettes are recorded from `StubJudgeProvider` in `build.py`, a
deterministic rule-based grader, because there is no API key here and CI must
not need one. So the figures below are figures for *the pipeline*: retrieval,
the offset contract, citation verification, the abstention policy, and the
negative controls. They are not figures for a language model, and the JSON
carries `recorded_with` on every run so the distinction cannot be lost in a
copy-paste. Point the recorder at `HTTPProvider`, re-record, and the same
harness scores a real model against the same 65 labels — that separation is
the reason the provider is a seam at all.

**MEASURED**

  conditional accuracy   of the pairs the pipeline answered, how many matched
                         the label. Reported as two counts, never as a rate:
                         the gold set is closed and hand-labelled, so "34 of
                         53" is the honest unit and a percentage would invite
                         a reader to treat it as an estimate of a population
                         nobody sampled. Same argument as design note D-41
                         and as `evals/harness.py`.
  abstention             how often it declined, broken down by which rule in
                         the policy fired. A single abstention count would
                         hide the difference between a cautious judge and a
                         verifier that is rejecting everything.
  citation grounding     of every citation the judge emitted, how many are
                         literally present in the document at the offsets
                         given. This is the number that matters most and it
                         is the cheapest to check.
  calibration            when the pipeline says `addressed`, how often is it
                         right, and separately when it says `not_addressed`.
                         An aggregate accuracy hides a grader that is right
                         about one and useless about the other.
  retrieval              recall@k of `retriever.retrieve` against the gold
                         spans, at three values of k, plus a count of how many
                         pairs the anchor rescued. See
                         `retriever.spans_for_judgement` for why the anchor
                         exists; publishing recall without publishing that
                         count would be publishing a number whose failures
                         are silently masked downstream.
  cost                   tokens per judgement, and the recorded latency. The
                         latency is the stand-in's, at cassette time, and the
                         field name says so.

**NOT MEASURED**

  Anything about real compliance documents. The corpus is synthetic and
  generated (design note D-51), so it measures behaviour against the shapes
  it contains and nothing beyond them. There is no confidence interval here
  and there will not be one.

**NEGATIVE CONTROLS.** A metric that cannot fail is not a metric. Four
controls, and the harness exits non-zero if any of them stops behaving:

  1. A blank document must come out `not_addressed`, not `abstain`. This is
     the pipeline's one exemption to cite-or-abstain, and if it ever silently
     started abstaining the abstention rate would improve while the tool got
     worse.
  2. A document that addresses a *different* obligation must come out
     `not_addressed`. If this passes as `addressed`, the judge is grading
     topic rather than obligation and every other figure is meaningless.
  3. A correct document with its load-bearing sentence deleted must *change
     verdict*. Not become anything in particular — change. If it does not,
     the verdict was never being driven by the document.
  4. A hand-forged citation must be rejected by the verifier. Offsets that
     point at real text which is not the quoted text; the check has to catch
     it, and the pipeline has to turn that into an abstention.

**DETERMINISM.** Two full runs must produce byte-identical JSON. Enforced
here rather than assumed: everything upstream was built for it — cassette
replay, a fixed prompt, integer arithmetic in the retriever, sorted iteration
— and a single dictionary iterated in insertion order from a set would undo
all of it without any other symptom.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import build as gold_build  # noqa: E402

from actaira.agents import corpus, judge, pipeline, retriever, verifier  # noqa: E402
from actaira.agents.judge import Citation, JudgeVerdict  # noqa: E402
from actaira.agents.provider import CassetteProvider  # noqa: E402
from actaira.governance import catalog  # noqa: E402

HERE = Path(__file__).resolve().parent
DOCUMENTS_DIR = HERE / "documents"
GOLD_PATH = HERE / "gold.json"
RESULTS_PATH = HERE / "results.json"
CALIBRATION_PATH = HERE / "calibration.json"

RECALL_KS = (3, 5, 8)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def ensure_corpus() -> dict[str, Any]:
    """Build the gold set if it is not on disk, then load it.

    Same shape as `evals/harness.py`: the corpus is generated, so a missing
    one is a build step rather than an error. A stale one is not detected
    here and is not meant to be — `tests/test_agents.py` rebuilds into a
    temporary directory and compares digests, which is where a drift between
    the generator and the committed corpus belongs.
    """
    if not GOLD_PATH.exists():
        gold_build.write()
    return json.loads(GOLD_PATH.read_text(encoding="utf-8"))


def read_document(document_id: str) -> str:
    """Read a corpus document exactly as a control would read a target file.

    `decode` rather than `read_text` with a strict codec, and `replace` rather
    than `strict`, because that is what `controls/judged.py` does to an
    operator's file and the two must not differ: a byte the control replaced
    and the harness rejected would give the two different documents, different
    offsets, and a grounding figure measured on a string the tool never sees.
    """
    return (DOCUMENTS_DIR / f"{document_id}.md").read_bytes().decode("utf-8", errors="replace")


def split_of(index: int) -> str:
    """Which half of the gold set a pair belongs to.

    Parity of position, which is a deterministic, corpus-order-stable split
    that puts positives, hard negatives and easy negatives on both sides —
    the generator emits them in a fixed interleaved order per obligation, so
    parity stratifies for free. Hashing the identifier would also be
    deterministic but would stratify by luck, and on 65 pairs luck is a real
    risk.
    """
    return "calibration" if index % 2 else "heldout"


# ---------------------------------------------------------------------------
# Running the pipeline over the gold set
# ---------------------------------------------------------------------------

def run_pairs(
    gold: dict[str, Any],
    provider: CassetteProvider,
    *,
    floor: float = verifier.SUPPORT_FLOOR_ADDRESSED,
    ceiling: float = verifier.SUPPORT_CEILING_NOT_ADDRESSED,
    min_terms: int = verifier.MIN_QUOTE_TERMS_ADDRESSED,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, pair in enumerate(gold["pairs"]):
        obligation = catalog.by_id(pair["obligation_id"])
        if obligation is None:  # pragma: no cover - guards a catalogue edit
            raise ValueError(f"{pair['pair_id']}: obligation not in the catalogue")
        document = read_document(pair["document"])
        result = pipeline.judge_document(
            document,
            obligation,
            provider,
            document_id=pair["document"],
            floor=floor,
            ceiling=ceiling,
            min_terms=min_terms,
        )
        rows.append(
            {
                "pair_id": pair["pair_id"],
                "obligation_id": pair["obligation_id"],
                "kind": pair["kind"],
                "negative_kind": pair["negative_kind"],
                "split": split_of(index),
                "label": pair["label"],
                "verdict": result.verdict,
                "reason": result.reason,
                "judge_verdict": result.judge_verdict,
                "citations": [check.to_dict() for check in result.citations],
                "prompt_tokens": result.prompt_tokens,
                "completion_tokens": result.completion_tokens,
                "latency_ms_recorded": round(result.latency_ms, 4),
                "relevant_spans": pair["relevant_spans"],
                "document": pair["document"],
            }
        )
    return rows


def samples_from(rows: list[dict[str, Any]], gold: dict[str, Any]) -> list[verifier.CalibrationSample]:
    """Reduce each pair to the facts the thresholds can change.

    The support ratio is recomputed here from the anchor spans rather than
    read off the row, because the row was produced at one threshold and the
    sweep has to evaluate every other one. `verify` reports the counts, not
    the ratio, so the division happens once, here, where it is a fitting
    quantity and not an output.
    """
    by_pair = {pair["pair_id"]: pair for pair in gold["pairs"]}
    out: list[verifier.CalibrationSample] = []
    for row in rows:
        pair = by_pair[row["pair_id"]]
        document = read_document(pair["document"])
        ratios: list[float] = []
        terms: list[int] = []
        for check in row["citations"]:
            total = check["quote_terms"]
            ratios.append((check["overlap_terms"] / total) if total else 0.0)
            terms.append(total)
        out.append(
            verifier.CalibrationSample(
                pair_id=row["pair_id"],
                gold_label=row["label"],
                judge_verdict=row["judge_verdict"],
                all_literal=all(check["literal"] for check in row["citations"]),
                has_citations=bool(row["citations"]),
                empty_document=not corpus.content_terms(document),
                ratios=tuple(ratios),
                quote_terms=tuple(terms),
            )
        )
    return out


# ---------------------------------------------------------------------------
# Metrics. Counts, never rates. See design note D-41.
# ---------------------------------------------------------------------------

def accuracy_counts(rows: list[dict[str, Any]]) -> dict[str, Any]:
    answered = [row for row in rows if row["verdict"] != JudgeVerdict.ABSTAIN.value]
    correct = [row for row in answered if row["verdict"] == row["label"]]
    return {
        "pairs": len(rows),
        "answered": len(answered),
        "answered_correct": len(correct),
        "answered_incorrect": len(answered) - len(correct),
        "abstained": len(rows) - len(answered),
        "wrong_pairs": sorted(
            row["pair_id"] for row in answered if row["verdict"] != row["label"]
        ),
    }


def abstention_breakdown(rows: list[dict[str, Any]]) -> dict[str, Any]:
    reasons = Counter(row["reason"] for row in rows if row["verdict"] == JudgeVerdict.ABSTAIN.value)
    overridden = [
        row["pair_id"]
        for row in rows
        if row["verdict"] == JudgeVerdict.ABSTAIN.value
        and row["judge_verdict"] != JudgeVerdict.ABSTAIN.value
    ]
    return {
        "abstained": sum(reasons.values()),
        "of_pairs": len(rows),
        "by_reason": dict(sorted(reasons.items())),
        "judge_answered_but_policy_abstained": len(overridden),
        "overridden_pairs": sorted(overridden),
    }


def grounding(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """How many citations are literally in the document at the offsets given."""
    total = literal = supported = 0
    failures: list[dict[str, str]] = []
    for row in rows:
        for check in row["citations"]:
            total += 1
            if check["literal"]:
                literal += 1
                supported += 1 if check["supported"] else 0
            else:
                failures.append({"pair_id": row["pair_id"], "reason": check["reason"]})
    return {
        "citations_emitted": total,
        "citations_found_in_document": literal,
        "citations_not_found": total - literal,
        "of_the_literal_ones_supported": supported,
        "failures": failures,
    }


def calibration_by_verdict(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Right-when-it-says-X, for each X it can say.

    The single most useful table here and the one an aggregate accuracy
    destroys: a grader that answers `addressed` correctly 20 times out of 21
    and `not_addressed` correctly 14 times out of 32 has one usable half and
    one that should be abstaining, and the aggregate says only "34 of 53".
    """
    out: dict[str, Any] = {}
    for verdict in (JudgeVerdict.ADDRESSED.value, JudgeVerdict.NOT_ADDRESSED.value):
        said = [row for row in rows if row["verdict"] == verdict]
        right = [row for row in said if row["label"] == verdict]
        out[verdict] = {
            "said": len(said),
            "and_was_right": len(right),
            "and_was_wrong": len(said) - len(right),
            "wrong_by_shape": dict(
                sorted(
                    Counter(
                        row["negative_kind"] or row["kind"] for row in said if row["label"] != verdict
                    ).items()
                )
            ),
        }
    return out


def retrieval(gold: dict[str, Any]) -> dict[str, Any]:
    """Recall@k of the retriever alone, plus what the anchor is covering up.

    `rescued_by_anchor` is the count of pairs where retrieval at the default
    k returned *none* of the target obligation's spans. On those, everything
    downstream is working from the anchor and the retriever contributed
    nothing to the judgement. Publishing recall@k without it would be
    publishing a component figure whose consequences are masked.
    """
    out: dict[str, Any] = {"k": {}}
    for k in RECALL_KS:
        found = total = 0
        for pair in gold["pairs"]:
            obligation = catalog.by_id(pair["obligation_id"])
            document = read_document(pair["document"])
            got = retriever.retrieve(obligation, document, k=k)
            hit, want = retriever.recall_at_k(got, tuple(pair["relevant_spans"]))
            found += hit
            total += want
        out["k"][str(k)] = {"gold_spans": total, "retrieved": found, "missed": total - found}

    rescued: list[str] = []
    for pair in gold["pairs"]:
        obligation = catalog.by_id(pair["obligation_id"])
        document = read_document(pair["document"])
        got = retriever.retrieve(obligation, document, k=retriever.DEFAULT_K)
        if not any(item.span.obligation_id == pair["obligation_id"] for item in got):
            rescued.append(pair["pair_id"])
    out["default_k"] = retriever.DEFAULT_K
    out["pairs"] = len(gold["pairs"])
    out["pairs_where_retrieval_returned_no_target_span"] = len(rescued)
    out["rescued_by_anchor"] = sorted(rescued)
    return out


def cost(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Tokens and recorded latency per judgement.

    The latency is the stand-in provider's own wall time at recording, kept
    under a name that says so. Reporting the replay's microseconds as a model
    latency would be a fabricated number, and reporting the stand-in's as one
    would be worse: it is four orders of magnitude off and would make a
    judged control look free.
    """
    prompt = [row["prompt_tokens"] for row in rows]
    completion = [row["completion_tokens"] for row in rows]
    latency = [row["latency_ms_recorded"] for row in rows]
    return {
        "judgements": len(rows),
        "prompt_tokens_total": sum(prompt),
        "prompt_tokens_median": round(statistics.median(prompt), 1) if prompt else 0,
        "prompt_tokens_max": max(prompt) if prompt else 0,
        "completion_tokens_total": sum(completion),
        "completion_tokens_median": round(statistics.median(completion), 1) if completion else 0,
        "usage_source": "whitespace count, not a vendor tokenizer",
        "latency_ms_recorded_median": round(statistics.median(latency), 4) if latency else 0.0,
        "latency_caveat": (
            "recorded from StubJudgeProvider at cassette time; this is not a language-model latency"
        ),
    }


# ---------------------------------------------------------------------------
# Negative controls
# ---------------------------------------------------------------------------

def negative_controls(gold: dict[str, Any], provider: CassetteProvider, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """The four controls. Each returns a pass/fail and what it observed."""
    by_pair = {row["pair_id"]: row for row in rows}
    controls: dict[str, Any] = {}

    # 1. blank document -> not_addressed, never abstain
    blanks = [row for row in rows if row["negative_kind"] == "blank"]
    bad_blanks = [row["pair_id"] for row in blanks if row["verdict"] != JudgeVerdict.NOT_ADDRESSED.value]
    controls["blank_document_is_not_addressed"] = {
        "checked": len(blanks),
        "behaved": len(blanks) - len(bad_blanks),
        "misbehaved": sorted(bad_blanks),
        "ok": bool(blanks) and not bad_blanks,
    }

    # 2. a document about another obligation -> not_addressed
    misfiled: list[dict[str, Any]] = []
    for control in gold["misfiled_controls"]:
        obligation = catalog.by_id(control["obligation_id"])
        document = read_document(control["source_document"])
        result = pipeline.judge_document(document, obligation, provider, document_id=control["control_id"])
        misfiled.append(
            {
                "control_id": control["control_id"],
                "obligation_id": control["obligation_id"],
                "source_document": control["source_document"],
                "verdict": result.verdict,
                "reason": result.reason,
                "ok": result.verdict == JudgeVerdict.NOT_ADDRESSED.value,
            }
        )
    controls["document_for_another_obligation_is_not_addressed"] = {
        "checked": len(misfiled),
        "behaved": sum(1 for row in misfiled if row["ok"]),
        "misbehaved": sorted(row["control_id"] for row in misfiled if not row["ok"]),
        "detail": misfiled,
        "ok": bool(misfiled) and all(row["ok"] for row in misfiled),
    }

    # 3. deleting the load-bearing sentence must change the verdict
    ablations: list[dict[str, Any]] = []
    for control in gold["ablations"]:
        obligation = catalog.by_id(control["obligation_id"])
        base = by_pair[control["base_pair_id"]]
        document = read_document(control["document"])
        result = pipeline.judge_document(document, obligation, provider, document_id=control["control_id"])
        ablations.append(
            {
                "control_id": control["control_id"],
                "base_pair_id": control["base_pair_id"],
                "before": base["verdict"],
                "after": result.verdict,
                "after_reason": result.reason,
                # The base pair must have been `addressed` for the control to
                # mean anything: an ablation of a document the pipeline already
                # abstained on proves nothing, and would pass vacuously.
                "base_was_addressed": base["verdict"] == JudgeVerdict.ADDRESSED.value,
                "ok": base["verdict"] == JudgeVerdict.ADDRESSED.value and result.verdict != base["verdict"],
            }
        )
    controls["removing_the_key_sentence_changes_the_verdict"] = {
        "checked": len(ablations),
        "behaved": sum(1 for row in ablations if row["ok"]),
        "misbehaved": sorted(row["control_id"] for row in ablations if not row["ok"]),
        "detail": ablations,
        "ok": bool(ablations) and all(row["ok"] for row in ablations),
    }

    # 4. a forged citation must be rejected
    controls["a_forged_citation_is_rejected"] = forged_citation_control(gold)

    controls["all_ok"] = all(
        value["ok"] for key, value in controls.items() if key != "all_ok" and isinstance(value, dict)
    )
    return controls


def forged_citation_control(gold: dict[str, Any]) -> dict[str, Any]:
    """Hand-forge a citation on every positive document and require rejection.

    Three forgeries per document, because they fail through different code
    paths and a control that only exercised one would let the other two rot:

      * `shifted`   real offsets, real text, but the offsets moved by seven
                    characters so the slice no longer equals the quote. This
                    is the off-by-N a model actually produces.
      * `invented`  a sentence that is nowhere in the document, at offsets
                    that are inside it. The fabrication case.
      * `outside`   offsets past the end of the document.

    The assertion is on the verifier *and* on the policy: the check must fail,
    and `pipeline.decide` must turn that into an abstention. Checking only the
    first would leave the door open for a policy that recorded the failure and
    answered anyway.
    """
    forged: list[dict[str, Any]] = []
    for pair in gold["pairs"]:
        if pair["kind"] != "positive":
            continue
        obligation = catalog.by_id(pair["obligation_id"])
        document = read_document(pair["document"])
        anchor, _ = retriever.spans_for_judgement(obligation, document)
        sentence = corpus.sentences(document)[-1]
        cases = {
            "shifted": Citation(start=sentence.start + 7, end=sentence.end + 7, quote=sentence.text),
            "invented": Citation(
                start=sentence.start,
                end=sentence.end,
                quote="Every measure required by this article was implemented in full last year.",
            ),
            "outside": Citation(start=len(document) + 5, end=len(document) + 40, quote=sentence.text),
        }
        for name, citation in cases.items():
            checks = verifier.verify(document, JudgeVerdict.ADDRESSED, (citation,), anchor)
            decided, reason = pipeline.decide(
                document,
                judge.Judgement(
                    verdict=JudgeVerdict.ADDRESSED,
                    citations=(citation,),
                    spans_used=(),
                    reason="forged",
                    prompt_key="",
                    prompt_tokens=0,
                    completion_tokens=0,
                    latency_ms=0.0,
                ),
                checks,
            )
            forged.append(
                {
                    "pair_id": pair["pair_id"],
                    "forgery": name,
                    "verifier_rejected": not checks[0].literal,
                    "pipeline_verdict": decided,
                    "pipeline_reason": reason,
                    "ok": (not checks[0].literal)
                    and decided == JudgeVerdict.ABSTAIN.value
                    and reason == pipeline.REASON_HALLUCINATED,
                }
            )
    return {
        "checked": len(forged),
        "behaved": sum(1 for row in forged if row["ok"]),
        "misbehaved": sorted({f"{row['pair_id']}:{row['forgery']}" for row in forged if not row["ok"]}),
        "ok": bool(forged) and all(row["ok"] for row in forged),
    }


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------

def control_samples(gold: dict[str, Any], provider: CassetteProvider) -> tuple[verifier.Constraint, ...]:
    """The negative controls, expressed as constraints the fit must respect.

    Built at permissive thresholds for the same reason the fit's samples are:
    a constraint evaluated at the shipped settings would already carry their
    effect and the sweep would be checking a foregone conclusion.

    The blank-document control is not here. It is decided by the pipeline's
    empty-document exemption, which no threshold can reach, so including it
    would add a constraint that is satisfied in every cell and read as
    though the fit had been asked something.
    """
    permissive = {"floor": 0.0, "ceiling": 1.0, "min_terms": 0}
    constraints: list[verifier.Constraint] = []

    def sample_for(document_id: str, obligation_id: str, label: str, pair_id: str) -> verifier.CalibrationSample:
        obligation = catalog.by_id(obligation_id)
        document = read_document(document_id)
        result = pipeline.judge_document(document, obligation, provider, document_id=document_id, **permissive)
        return verifier.CalibrationSample(
            pair_id=pair_id,
            gold_label=label,
            judge_verdict=result.judge_verdict,
            all_literal=all(check.literal for check in result.citations),
            has_citations=bool(result.citations),
            empty_document=not corpus.content_terms(document),
            ratios=tuple(
                (check.overlap_terms / check.quote_terms) if check.quote_terms else 0.0
                for check in result.citations
            ),
            quote_terms=tuple(check.quote_terms for check in result.citations),
        )

    for control in gold["misfiled_controls"]:
        constraints.append(
            verifier.Constraint(
                kind=verifier.Constraint.VERDICT,
                label=f"misfiled:{control['control_id']}",
                sample=sample_for(
                    control["source_document"],
                    control["obligation_id"],
                    JudgeVerdict.NOT_ADDRESSED.value,
                    control["control_id"],
                ),
                required=JudgeVerdict.NOT_ADDRESSED.value,
            )
        )
    by_pair = {pair["pair_id"]: pair for pair in gold["pairs"]}
    for control in gold["ablations"]:
        base = by_pair[control["base_pair_id"]]
        constraints.append(
            verifier.Constraint(
                kind=verifier.Constraint.DIFFERS,
                label=f"ablation:{control['control_id']}",
                sample=sample_for(
                    base["document"], base["obligation_id"], base["label"], base["pair_id"]
                ),
                partner=sample_for(
                    control["document"], control["obligation_id"], "", control["control_id"]
                ),
            )
        )
    return tuple(constraints)


def calibrate(gold: dict[str, Any], provider: CassetteProvider) -> dict[str, Any]:
    """Fit the thresholds on the calibration split and score both splits.

    The fit runs on a pass of the pipeline taken at *permissive* thresholds
    (floor 0, ceiling 1, no minimum), so the samples carry every citation's
    ratio rather than only those that happened to survive the shipped
    settings. Fitting on a pass taken at the shipped thresholds would have
    been a fit on the fit's own output.

    The negative controls enter as constraints rather than as part of the
    objective. See `verifier.Constraint` for the run that made that necessary.
    """
    permissive = run_pairs(gold, provider, floor=0.0, ceiling=1.0, min_terms=0)
    samples = samples_from(permissive, gold)
    by_split: dict[str, list[verifier.CalibrationSample]] = {"calibration": [], "heldout": []}
    for row, sample in zip(permissive, samples, strict=True):
        by_split[row["split"]].append(sample)

    fit = verifier.calibrate(by_split["calibration"], constraints=control_samples(gold, provider))
    if fit.get("chosen") is None:
        return fit
    chosen = fit["chosen"]
    fit["heldout_counts_at_chosen"] = verifier.score_thresholds(
        by_split["heldout"], chosen["floor"], chosen["ceiling"], chosen["min_terms"]
    )
    fit["calibration_counts_at_shipped"] = verifier.score_thresholds(
        by_split["calibration"],
        verifier.SUPPORT_FLOOR_ADDRESSED,
        verifier.SUPPORT_CEILING_NOT_ADDRESSED,
        verifier.MIN_QUOTE_TERMS_ADDRESSED,
    )
    fit["heldout_counts_at_shipped"] = verifier.score_thresholds(
        by_split["heldout"],
        verifier.SUPPORT_FLOOR_ADDRESSED,
        verifier.SUPPORT_CEILING_NOT_ADDRESSED,
        verifier.MIN_QUOTE_TERMS_ADDRESSED,
    )
    fit["split_sizes"] = {name: len(values) for name, values in sorted(by_split.items())}
    fit["agrees_with_shipped"] = (
        chosen["floor"] == verifier.SUPPORT_FLOOR_ADDRESSED
        and chosen["ceiling"] == verifier.SUPPORT_CEILING_NOT_ADDRESSED
        and chosen["min_terms"] == verifier.MIN_QUOTE_TERMS_ADDRESSED
    )
    return fit


def run(gold: dict[str, Any], provider: CassetteProvider) -> dict[str, Any]:
    rows = run_pairs(gold, provider)
    heldout = [row for row in rows if row["split"] == "heldout"]
    calibration_rows = [row for row in rows if row["split"] == "calibration"]
    controls = negative_controls(gold, provider, rows)
    return {
        "schema": "actaira-judged-eval/1",
        "recorded_with": gold.get("recorded_with", ""),
        "what_this_measures": (
            "the pipeline (retrieval, offsets, verification, abstention policy) replaying "
            "cassettes recorded from a deterministic stand-in grader. It is not a measurement "
            "of a language model."
        ),
        "thresholds": {
            "support_floor_addressed": verifier.SUPPORT_FLOOR_ADDRESSED,
            "support_ceiling_not_addressed": verifier.SUPPORT_CEILING_NOT_ADDRESSED,
            "min_quote_terms_addressed": verifier.MIN_QUOTE_TERMS_ADDRESSED,
            "fitted_on": "the calibration split of this gold set; see calibration.json",
        },
        "corpus": {
            "pairs": len(gold["pairs"]),
            "obligations": gold["obligations"],
            "positives": sum(1 for p in gold["pairs"] if p["kind"] == "positive"),
            "hard_negatives": sum(1 for p in gold["pairs"] if p["kind"] == "hard_negative"),
            "easy_negatives": sum(1 for p in gold["pairs"] if p["kind"] == "easy_negative"),
            "hard_negative_shapes": dict(
                sorted(Counter(p["negative_kind"] for p in gold["pairs"] if p["kind"] == "hard_negative").items())
            ),
        },
        "accuracy_conditional_on_answering": {
            "all": accuracy_counts(rows),
            "heldout": accuracy_counts(heldout),
            "calibration": accuracy_counts(calibration_rows),
            "by_shape": {
                shape: accuracy_counts([row for row in rows if (row["negative_kind"] or row["kind"]) == shape])
                for shape in sorted({row["negative_kind"] or row["kind"] for row in rows})
            },
        },
        "abstention": abstention_breakdown(rows),
        "citation_grounding": grounding(rows),
        "calibration_by_verdict": calibration_by_verdict(rows),
        "retrieval": retrieval(gold),
        "cost": cost(rows),
        "negative_controls": controls,
        "pairs": rows,
    }


def determinism(gold: dict[str, Any], provider: CassetteProvider, summary: dict[str, Any]) -> dict[str, Any]:
    """A second full run must serialise identically to the first."""
    again = run(gold, provider)
    first = json.dumps(summary, indent=2, sort_keys=True)
    second = json.dumps(again, indent=2, sort_keys=True)
    return {"runs": 2, "identical": first == second}


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    corpus_row = summary["corpus"]
    lines.append(
        f"gold set: {corpus_row['pairs']} pairs over {len(corpus_row['obligations'])} obligations "
        f"({corpus_row['positives']} positive, {corpus_row['hard_negatives']} hard negative, "
        f"{corpus_row['easy_negatives']} easy negative)"
    )
    lines.append(f"recorded with: {summary['recorded_with']}")
    lines.append("")

    lines.append("accuracy conditional on answering (counts over a closed corpus, not rates)")
    for name in ("all", "heldout", "calibration"):
        row = summary["accuracy_conditional_on_answering"][name]
        lines.append(
            f"  {name:12} answered {row['answered']}/{row['pairs']}   "
            f"correct {row['answered_correct']}/{row['answered']}   "
            f"abstained {row['abstained']}"
        )
    lines.append("")
    lines.append("  by document shape")
    for shape, row in sorted(summary["accuracy_conditional_on_answering"]["by_shape"].items()):
        lines.append(
            f"    {shape:14} answered {row['answered']}/{row['pairs']}  "
            f"correct {row['answered_correct']}/{row['answered']}"
        )
    lines.append("")

    abstention = summary["abstention"]
    lines.append(f"abstention: {abstention['abstained']}/{abstention['of_pairs']}")
    for reason, count in abstention["by_reason"].items():
        lines.append(f"    {reason:44} {count}")
    lines.append(
        f"    of those, the judge had answered and the policy overrode it: "
        f"{abstention['judge_answered_but_policy_abstained']}"
    )
    lines.append("")

    ground = summary["citation_grounding"]
    lines.append(
        f"citation grounding: {ground['citations_found_in_document']}/{ground['citations_emitted']} "
        f"citations occur literally at the offsets given "
        f"({ground['citations_not_found']} did not)"
    )
    lines.append(
        f"  of the literal ones, {ground['of_the_literal_ones_supported']}/"
        f"{ground['citations_found_in_document']} passed the support check"
    )
    lines.append("")

    lines.append("calibration by verdict")
    for verdict, row in summary["calibration_by_verdict"].items():
        lines.append(f"  says {verdict:15} {row['and_was_right']}/{row['said']} right")
        if row["wrong_by_shape"]:
            shapes = ", ".join(f"{shape} x{count}" for shape, count in row["wrong_by_shape"].items())
            lines.append(f"       wrong on: {shapes}")
    lines.append("")

    retrieval_row = summary["retrieval"]
    for k, row in sorted(retrieval_row["k"].items(), key=lambda item: int(item[0])):
        lines.append(f"retrieval recall@{k}: {row['retrieved']}/{row['gold_spans']} gold spans")
    lines.append(
        f"  pairs where retrieval at k={retrieval_row['default_k']} returned no span of the target "
        f"obligation: {retrieval_row['pairs_where_retrieval_returned_no_target_span']}"
        f"/{retrieval_row['pairs']} (the anchor covers these; see retriever.spans_for_judgement)"
    )
    lines.append("")

    cost_row = summary["cost"]
    lines.append(
        f"cost: {cost_row['prompt_tokens_median']} prompt tokens and "
        f"{cost_row['completion_tokens_median']} completion tokens per judgement (median, "
        f"{cost_row['usage_source']})"
    )
    lines.append(f"      recorded latency median {cost_row['latency_ms_recorded_median']} ms — {cost_row['latency_caveat']}")
    lines.append("")

    lines.append("negative controls")
    for name, row in sorted(summary["negative_controls"].items()):
        if name == "all_ok" or not isinstance(row, dict):
            continue
        status = "ok  " if row["ok"] else "FAIL"
        lines.append(f"  [{status}] {name}: {row['behaved']}/{row['checked']}")
        if row["misbehaved"]:
            lines.append(f"           misbehaved: {', '.join(row['misbehaved'])}")
    determinism_row = summary.get("determinism")
    if determinism_row:
        lines.append("")
        lines.append(f"determinism: two runs {'produced identical JSON' if determinism_row['identical'] else 'DIFFERED'}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the judged-evidence eval")
    parser.add_argument("--json-out", type=Path, default=RESULTS_PATH)
    parser.add_argument("--calibration-out", type=Path, default=CALIBRATION_PATH)
    parser.add_argument("--rebuild", action="store_true", help="regenerate documents, labels and cassettes first")
    parser.add_argument("--calibrate", action="store_true", help="re-fit the thresholds and write calibration.json")
    parser.add_argument("--skip-determinism", action="store_true")
    args = parser.parse_args()

    if args.rebuild:
        gold_build.write()
    gold = ensure_corpus()
    provider = CassetteProvider()

    if args.calibrate:
        fit = calibrate(gold, provider)
        args.calibration_out.write_text(json.dumps(fit, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        if fit.get("chosen") is None:
            # The admissible region is empty: no threshold triple satisfies
            # every negative control. Reported as a failure rather than
            # resolved by dropping a control, because a control that gets
            # dropped when it is inconvenient was never a control.
            print(f"calibration failed: {fit['error']}")
            for row in fit["most_nearly_admissible"]:
                print(f"  floor={row['floor']} ceiling={row['ceiling']} min_terms={row['min_terms']} broke {row['broken']}")
            return 1
        print(
            f"fitted on {fit['split_sizes']['calibration']} calibration pairs: "
            f"floor={fit['chosen']['floor']} ceiling={fit['chosen']['ceiling']} "
            f"min_terms={fit['chosen']['min_terms']}"
        )
        print(f"  calibration split at the fit: {fit['chosen_counts']}")
        print(f"  held-out split at the fit:    {fit['heldout_counts_at_chosen']}")
        print(f"  held-out split at shipped:    {fit['heldout_counts_at_shipped']}")
        print(f"  agrees with the shipped constants: {fit['agrees_with_shipped']}")
        print(f"  plateau cells on the winning objective: {len(fit['plateau'])} of {fit['cells']}")
        return 0

    summary = run(gold, provider)
    if not args.skip_determinism:
        summary["determinism"] = determinism(gold, provider, summary)
    args.json_out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(render(summary))

    ok = summary["negative_controls"]["all_ok"] and summary.get("determinism", {"identical": True})["identical"]
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
