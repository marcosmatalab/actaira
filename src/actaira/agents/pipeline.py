"""Retrieve, judge, verify, decide — and the policy for when not to answer.

Design note D-50, the abstention policy, which is the only part of this
package that decides anything.

The rule is short and it is absolute: **an answer that cannot be grounded in
the document is not given.** Concretely, the pipeline abstains when

  1. the provider had nothing to say — a cassette miss, a failed request, a
     malformed answer the parser rejected;
  2. the judge itself abstained;
  3. the judge returned a verdict with no citations at all;
  4. any citation fails the literal check — the quotation is not in the
     document at those offsets;
  5. any citation fails the support check — it is in the document, but it
     does not carry the claim.

Note the quantifier in 4 and 5. *Any*, not *all*. One fabricated quotation
discards the whole answer including the citations that were real. This is
strictly stronger than necessary to avoid reporting the bad citation, and it
is chosen for a reason that has nothing to do with that citation: a model
that fabricated one sentence was not doing the task on this document, and the
verdict it produced is not evidence about the document, whatever else it
attached. Grading the good citations and keeping the verdict would be reading
tea leaves from a witness who was caught making things up.

**The one exemption, and why it is not a hole.** Rule 3 would make an empty
document abstain, because there is nothing in an empty document to cite. That
is the wrong answer: a document with no content does not address any
obligation, and that is not a close call, it is the clearest case there is.
So when the judge says `not_addressed` and the document has no content terms
at all, the verdict stands with no citations and the reason records why.

The exemption is deliberately narrow in three ways. It requires the judge to
have been asked and to have said `not_addressed` — the model is consulted on
the empty document rather than short-circuited, so the branch is not a way to
manufacture an answer without one. It cannot produce `addressed`: an empty
document that the judge called addressed still falls through to rule 3 and
abstains. And it turns on `corpus.content_terms` being empty, not on the
string being empty, so a file of whitespace and section numbers is covered
too, which is the shape a real "we filed a placeholder" document has.

**What the pipeline never does.** It does not average, weight or score. It
returns one of three verdicts, the citations that survived verification, the
identifiers of the regulation spans the judgement was given, and the cost.
There is no confidence attached to any of it, because there is no number here
that could honestly carry one — see design note D-41 in `controls/model.py`.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from ..governance.catalog import Obligation
from . import corpus, retriever, verifier
from . import judge as judge_module
from .judge import JudgeVerdict
from .provider import CassetteMiss, LLMProvider
from .verifier import CitationCheck

#: Reasons a pipeline result carries. Constants because a control puts them
#: in front of an operator and the eval harness groups by them, and a typo in
#: a literal would silently create a new category of abstention.
REASON_JUDGED = "judged"
REASON_EMPTY_DOCUMENT = "document_has_no_content_to_cite"
REASON_NO_CITATIONS = "judge_cited_nothing"
REASON_HALLUCINATED = "citation_not_found_in_document"
REASON_UNSUPPORTED = "citation_does_not_support_the_verdict"
REASON_JUDGE_ABSTAINED = "judge_abstained"
REASON_UNPARSEABLE = "judge_answer_could_not_be_parsed"
REASON_NO_RECORDING = "no_recorded_judgement_for_this_document"
REASON_PROVIDER_FAILED = "provider_failed"


@dataclass(frozen=True)
class JudgedDocument:
    """The whole result of judging one document against one obligation.

    `judge_verdict` is kept alongside `verdict` on purpose. They differ
    exactly when the policy overrode the model, and that difference is the
    measurement the eval harness is most interested in: it is the abstention
    the verifier bought. Collapsing them would hide the value of the
    verifier behind the number it produces.
    """

    obligation_id: str
    document_id: str
    document_sha256: str
    verdict: str
    reason: str
    judge_verdict: str
    citations: tuple[CitationCheck, ...] = ()
    regulation_spans: tuple[str, ...] = ()
    prompt_key: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def verified_citations(self) -> tuple[CitationCheck, ...]:
        """Only the citations that passed both checks.

        A separate accessor rather than a filtered `citations`, because the
        control renders these and the eval harness needs the ones that
        failed. A field holding only the survivors would have made the
        failures unrecoverable from the result.
        """
        return tuple(check for check in self.citations if check.ok)

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "document_id": self.document_id,
            "document_sha256": self.document_sha256,
            "verdict": self.verdict,
            "reason": self.reason,
            "judge_verdict": self.judge_verdict,
            "citations": [check.to_dict() for check in self.citations],
            "regulation_spans": list(self.regulation_spans),
            "prompt_key": self.prompt_key,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "latency_ms_recorded": self.latency_ms,
            "detail": self.detail,
        }


def decide(
    document: str,
    judgement: judge_module.Judgement,
    checks: tuple[CitationCheck, ...],
) -> tuple[str, str]:
    """`(verdict, reason)`. The policy, and nothing else.

    Pure: a document, what the model said, what the verifier found. No
    provider, no I/O, no clock. That is what lets `tests/test_agents.py`
    drive every branch with hand-built inputs, including the branches a
    cassette could not reach — a fabricated citation, an answer that is not
    JSON, a judge that returned `addressed` with nothing attached.
    """
    if judgement.parse_error:
        return JudgeVerdict.ABSTAIN.value, REASON_UNPARSEABLE
    if judgement.verdict is JudgeVerdict.ABSTAIN:
        return JudgeVerdict.ABSTAIN.value, REASON_JUDGE_ABSTAINED
    if not judgement.citations:
        # The one exemption. See design note D-50, and note that it cannot
        # yield ADDRESSED: an empty document the judge called addressed falls
        # straight through to the abstention below.
        if judgement.verdict is JudgeVerdict.NOT_ADDRESSED and not corpus.content_terms(document):
            return JudgeVerdict.NOT_ADDRESSED.value, REASON_EMPTY_DOCUMENT
        return JudgeVerdict.ABSTAIN.value, REASON_NO_CITATIONS
    if any(not check.literal for check in checks):
        return JudgeVerdict.ABSTAIN.value, REASON_HALLUCINATED
    if any(not check.supported for check in checks):
        return JudgeVerdict.ABSTAIN.value, REASON_UNSUPPORTED
    return judgement.verdict.value, REASON_JUDGED


def judge_document(
    document: str,
    obligation: Obligation,
    provider: LLMProvider,
    *,
    document_id: str = "",
    k: int = retriever.DEFAULT_K,
    floor: float = verifier.SUPPORT_FLOOR_ADDRESSED,
    ceiling: float = verifier.SUPPORT_CEILING_NOT_ADDRESSED,
    min_terms: int = verifier.MIN_QUOTE_TERMS_ADDRESSED,
    verify_with_provider: bool = False,
) -> JudgedDocument:
    """Retrieve, judge, verify, decide. The whole tube, one document.

    `verify_with_provider` is off by default and is the switch between the
    two support checks in `verifier.py`. It is off rather than "on when the
    provider is real" because that would make the meaning of a published
    figure depend on an environment variable: the same harness would produce
    a lexical grounding number on one machine and an entailment one on
    another, under the same field name.

    A provider failure is caught here and only here. `judge()` deliberately
    lets it out — see its docstring — so that the layer which knows how to
    record it as its own reason is the one that handles it. A cassette miss
    becomes `no_recorded_judgement_for_this_document`, distinct from every
    other abstention, so an eval whose corpus has gone stale reports a
    missing recording rather than a cautious model.
    """
    digest = hashlib.sha256(document.encode("utf-8")).hexdigest()
    # Two sets, two jobs. `anchor` is the obligation's own spans, looked up
    # rather than retrieved, and it is what the verifier checks support
    # against: the question is whether a quotation carries what *this*
    # obligation asks for, and a neighbour's vocabulary in that denominator
    # would let a copyright policy support a finding about AI literacy.
    # `shown` is the anchor plus the retrieved neighbours, and it is what the
    # judge reads. See `retriever.spans_for_judgement` for what happened when
    # these were the same set.
    anchor, neighbours = retriever.spans_for_judgement(obligation, document, k=k)
    shown = anchor + neighbours
    span_ids = tuple(span.span_id for span in shown)

    try:
        judgement = judge_module.judge(document, obligation, shown, provider)
    except CassetteMiss as exc:
        return JudgedDocument(
            obligation_id=obligation.id,
            document_id=document_id,
            document_sha256=digest,
            verdict=JudgeVerdict.ABSTAIN.value,
            reason=REASON_NO_RECORDING,
            judge_verdict=JudgeVerdict.ABSTAIN.value,
            regulation_spans=span_ids,
            detail={"error": str(exc)},
        )
    except Exception as exc:  # noqa: BLE001 - a provider is I/O; see design note D-44
        return JudgedDocument(
            obligation_id=obligation.id,
            document_id=document_id,
            document_sha256=digest,
            verdict=JudgeVerdict.ABSTAIN.value,
            reason=REASON_PROVIDER_FAILED,
            judge_verdict=JudgeVerdict.ABSTAIN.value,
            regulation_spans=span_ids,
            detail={"error": f"{type(exc).__name__}: {exc}"},
        )

    checks = verifier.verify(
        document,
        judgement.verdict,
        judgement.citations,
        anchor,
        floor=floor,
        ceiling=ceiling,
        min_terms=min_terms,
        obligation=obligation if verify_with_provider else None,
        provider=provider if verify_with_provider else None,
    )
    verdict, reason = decide(document, judgement, checks)
    return JudgedDocument(
        obligation_id=obligation.id,
        document_id=document_id,
        document_sha256=digest,
        verdict=verdict,
        reason=reason,
        judge_verdict=judgement.verdict.value,
        citations=checks,
        regulation_spans=span_ids,
        prompt_key=judgement.prompt_key,
        prompt_tokens=judgement.prompt_tokens,
        completion_tokens=judgement.completion_tokens,
        latency_ms=judgement.latency_ms,
        detail={
            "judge_reason": judgement.reason,
            "judge_spans_used": list(judgement.spans_used),
            "parse_error": judgement.parse_error,
            "support_check": "entailment" if verify_with_provider else "lexical",
            "anchor_spans": [span.span_id for span in anchor],
            "neighbour_spans": [span.span_id for span in neighbours],
        },
    )
