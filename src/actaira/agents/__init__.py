"""The judging layer: a model reads a document, a verifier checks its work.

This package exists to answer one question that `formats/` cannot: the
operator handed us a document and said it discharges Article 53(1)(c) — does
it? That is a grading problem, not a parsing problem, and the whole package
is arranged around the fact that a grader's output is worthless unless it can
be checked against the thing it graded.

The tube, and where each decision is argued:

    provider.py    where an answer comes from. Cassettes by default, so the
                   thing is reproducible and the eval is a measurement.
                   Design note D-45.
    corpus.py      the obligations as citable spans, plus the shared text
                   handling. The spans are an operational paraphrase with a
                   citation attached, never the legal text. Design note D-46.
    retriever.py   BM25 by hand, over the standard library, because on a
                   corpus this size a dense retriever buys nothing this
                   project can measure. Design note D-47.
    judge.py       the prompt and the answer schema. Every verdict must quote
                   the document at exact offsets. Design note D-48.
    verifier.py    the quotation is real, and it carries the claim. Both
                   checked; the threshold for the second is fitted on a
                   held-out split, not chosen. Design note D-49.
    pipeline.py    the abstention policy: anything ungrounded is not
                   answered. Design note D-50.

Nothing here emits a score, a percentage or a confidence, in keeping with
design note D-41. What it emits is a verdict of three, the exact quotations
that survived verification, the identifiers of the regulation spans the
judgement was given, and what the call cost.
"""
from __future__ import annotations

from .corpus import ALL_SPANS, Span, spans_for

# NOT `judge` itself: `actaira.agents.judge` is a module, and re-exporting the
# function of the same name here would rebind the package attribute so that
# `from actaira.agents import judge` handed a caller the function instead of
# the module. That is a five-minute bug the first time and a confusing one the
# second, so the function is reached as `judge.judge` and nowhere else.
from .judge import Citation, Judgement, JudgeVerdict
from .pipeline import JudgedDocument, decide, judge_document
from .provider import (
    CassetteMiss,
    CassetteProvider,
    Completion,
    HTTPProvider,
    LLMProvider,
    MissingCredential,
    RecordingProvider,
)
from .retriever import retrieve
from .verifier import CitationCheck, verify

__all__ = [
    "ALL_SPANS",
    "CassetteMiss",
    "CassetteProvider",
    "Citation",
    "CitationCheck",
    "Completion",
    "HTTPProvider",
    "JudgeVerdict",
    "JudgedDocument",
    "Judgement",
    "LLMProvider",
    "MissingCredential",
    "RecordingProvider",
    "Span",
    "decide",
    "judge_document",
    "retrieve",
    "spans_for",
    "verify",
]
