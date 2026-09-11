"""Finding the spans of the regulation a document has to be judged against.

Design note D-47, on choosing BM25 over a dense retriever, argued on this
corpus rather than in general.

The corpus is 101 spans of at most three lines each, built from a catalogue
of 21 obligations. Every candidate for retrieval was measured against four
questions, and the answers are what decided it:

  What does it cost to run?     BM25: an inverted index over a few thousand
                                terms, built at import in under a
                                millisecond. Embeddings: a model to download,
                                a runtime to install, and either a network
                                call per document or several hundred
                                megabytes of weights in a tool whose argument
                                is that it has one runtime dependency.
  Is it reproducible?           BM25 is arithmetic over integers and two
                                constants. The same query gives the same
                                ranking on every machine, forever, which is
                                the property `provider.py` gives up the
                                network to preserve; buying it there and
                                throwing it away here would be incoherent.
  What has to be versioned?     BM25: this file. Embeddings: this file, a
                                checkpoint, its tokenizer, and the fact that
                                a re-embedding changes retrieval for every
                                obligation at once, which is a change no
                                diff shows.
  What does it actually buy?    This is the one that settles it. Dense
                                retrieval earns its keep on vocabulary
                                mismatch, where the query and the document
                                say the same thing in different words. Here
                                the query is an obligation title plus an
                                operator's compliance document, and the
                                corpus is a paraphrase written in the
                                vocabulary of the same regulation the
                                document is trying to answer. The mismatch
                                dense retrieval fixes is largely absent, and
                                the harness publishes recall@k so the claim
                                is checkable rather than asserted.

Where this would stop being the right answer, stated so the decision can be
revisited on evidence rather than on taste: a corpus of the consolidated
legal text (thousands of spans), or documents in a language the corpus is
not written in. Both change the fourth answer, and neither is true today.

The parameters `k1 = 1.2` and `b = 0.75` are the Robertson/Sparck-Jones
defaults. They are not tuned here, deliberately: tuning two constants on a
gold set of 65 pairs would fit the gold set, and the harness would then be
measuring a retriever that had already seen its own test.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Any

from ..governance.catalog import Obligation
from . import corpus
from .corpus import Span

#: Robertson/Sparck-Jones defaults. See the module docstring on why they are
#: not tuned.
K1 = 1.2
B = 0.75

#: How many spans a judgement is given by default. Chosen from the shape of
#: the corpus rather than by a sweep: an obligation contributes between two
#: and five spans, so a `k` below five cannot return one obligation's spans
#: in full and a `k` far above it spends prompt on other articles. The
#: harness publishes recall at 3, 5 and 8 so the choice is inspectable.
DEFAULT_K = 5


@dataclass(frozen=True)
class Retrieved:
    """One ranked span.

    `rank` is in the output; `score` is not. A BM25 score is an internal
    ranking quantity with no meaning outside this index, and a number next to
    a regulation citation in a compliance report reads as a confidence. The
    project's rule is that it publishes no such number, so the score stays
    inside the retriever and only the ordering leaves it. See design note
    D-41 in `controls/model.py`.
    """

    span: Span
    rank: int
    score: float

    def to_dict(self) -> dict[str, Any]:
        return {"span_id": self.span.span_id, "rank": self.rank}


class BM25Index:
    """An inverted index over spans, built once and queried many times.

    Okapi BM25 exactly as published: an IDF that is the log of the
    probabilistic ratio, a length-normalised term frequency saturating at
    `k1`, and no query-side saturation. Written out rather than pulled in
    because it is thirty lines and the alternative is a dependency.

    One deviation, and it is the standard one: the IDF is floored at zero.
    The unmodified formula goes negative for a term appearing in more than
    half the corpus, which on a corpus this small means a span is *penalised*
    for containing the word "providers". With the floor such a term simply
    stops discriminating, which is what it should do.
    """

    def __init__(self, spans: tuple[Span, ...]) -> None:
        self.spans = spans
        self._terms: list[Counter[str]] = [Counter(corpus.tokenize(span.text)) for span in spans]
        self._lengths = [sum(counter.values()) for counter in self._terms]
        self._avg_length = (sum(self._lengths) / len(self._lengths)) if self._lengths else 0.0
        document_frequency: Counter[str] = Counter()
        for counter in self._terms:
            document_frequency.update(counter.keys())
        total = len(spans)
        self._idf: dict[str, float] = {
            term: max(0.0, math.log(1.0 + (total - frequency + 0.5) / (frequency + 0.5)))
            for term, frequency in document_frequency.items()
        }

    def __len__(self) -> int:
        return len(self.spans)

    def rank(self, query: str, k: int = DEFAULT_K) -> tuple[Retrieved, ...]:
        """Top `k` spans for a query, most relevant first.

        Ties are broken by span identifier, not by index order. Index order
        is catalogue order, so a tie would otherwise be resolved in favour of
        whichever obligation happens to sit earlier in `catalog.py`, and
        reordering the catalogue would silently change what the judge was
        shown. Breaking on the identifier makes the ranking a function of the
        query and the corpus alone.
        """
        query_terms = corpus.tokenize(query)
        if not query_terms or not self.spans:
            return ()
        scored: list[tuple[float, str, int]] = []
        for index, counter in enumerate(self._terms):
            length = self._lengths[index]
            score = 0.0
            for term in query_terms:
                frequency = counter.get(term, 0)
                if not frequency:
                    continue
                denominator = frequency + K1 * (1 - B + B * length / (self._avg_length or 1.0))
                score += self._idf.get(term, 0.0) * frequency * (K1 + 1) / denominator
            if score > 0.0:
                scored.append((score, self.spans[index].span_id, index))
        scored.sort(key=lambda row: (-row[0], row[1]))
        return tuple(
            Retrieved(span=self.spans[index], rank=position, score=score)
            for position, (score, _span_id, index) in enumerate(scored[:k], start=1)
        )


#: The index over the whole catalogue. Built at import: see the note on
#: `corpus.ALL_SPANS`.
INDEX = BM25Index(corpus.ALL_SPANS)


def build_query(obligation: Obligation, document: str) -> str:
    """The string the index is asked with.

    Both halves are needed and each is here for a different reason.

    The obligation's title and article name the thing being asked about. On
    their own they would make retrieval trivially correct, because the spans
    for an obligation are cut from that obligation's own prose: a query of
    "Copyright policy Art. 53(1)(c)" retrieves `AIA-53-1c#*` and nothing
    else, and a recall@k measured that way would be a measurement of an
    identity function.

    The document is what makes the number mean something. It is what the
    operator actually supplied, it dominates the query by length, and it is
    what drags retrieval towards the wrong article when the document is about
    something else. A retriever that still surfaces the right spans for a
    copyright-flavoured document filed against Article 4 has demonstrated
    something; one that was only ever handed the title has not.

    The document is truncated at `MAX_QUERY_CHARS`. A 200-page annex would
    otherwise swamp the title entirely, and BM25 has no positional notion to
    recover it with.
    """
    head = document[:MAX_QUERY_CHARS]
    return f"{obligation.title} {obligation.article} {head}"


#: How much of a document enters the query. A compliance document that says
#: what it is says it early; past this point a query is being decided by an
#: appendix.
MAX_QUERY_CHARS = 4000


def retrieve(obligation: Obligation, document: str, *, k: int = DEFAULT_K) -> tuple[Retrieved, ...]:
    """The spans a judgement of `document` against `obligation` is given."""
    return INDEX.rank(build_query(obligation, document), k=k)


#: The most spans a judgement is ever shown. The anchor (below) is two to
#: five spans depending on the obligation, so this leaves room for three or
#: four neighbours without turning the prompt into a reading exercise.
MAX_SPANS_IN_PROMPT = 8


def spans_for_judgement(
    obligation: Obligation,
    document: str,
    *,
    k: int = DEFAULT_K,
    budget: int = MAX_SPANS_IN_PROMPT,
) -> tuple[tuple[Span, ...], tuple[Span, ...]]:
    """`(anchor, neighbours)` — what the judge is shown, and in which role.

    This function exists because the first version of this package did not
    have it, and the measurement is what killed that version. Retrieval ran
    over the whole catalogue with the obligation title and the operator's
    document as the query, and whatever came back was what the judge saw.
    Recall of the target obligation's own spans at k=5 was **128 of 260**:
    on half the gold set the prompt said "OBLIGATION AIA-4" at the top and
    then quoted what Article 53(1)(c) asks for underneath. The judge was
    being asked one question and shown the answer key to another, and the
    conditional accuracy that came out of it was 24 correct against 24
    incorrect — a coin toss, produced entirely by the retriever.

    The lesson is not that BM25 is bad. It is that *which obligation is being
    graded is not a retrieval problem*. It is given: the control knows, the
    catalogue knows, and asking an inverted index to rediscover it from a
    bag of words is inventing uncertainty where none existed. The document
    dominates the query by length, so the index answers a question closer to
    "which article is this document about", which is a different and much
    harder question than the one being asked.

    So the obligation's own spans are always shown — that is the *anchor*,
    and it is not retrieved, it is looked up. Retrieval keeps a real job:
    surfacing spans of *other* articles that the document appears to be
    about, which is what lets a judge say "this document is a copyright
    policy, and the obligation in front of me is Article 4". Those are the
    *neighbours*.

    Retrieval is still measured, and measured as retrieval: `recall_at_k`
    scores `retrieve()` alone against the gold spans, and the harness
    publishes it next to a count of how many pairs would have lost the target
    obligation entirely without the anchor. Publishing a recall figure for a
    component whose failures are masked, without saying they are masked,
    would be the worst of both.
    """
    anchor = corpus.spans_for(obligation.id)
    room = max(0, budget - len(anchor))
    neighbours = tuple(
        item.span for item in retrieve(obligation, document, k=k) if item.span.obligation_id != obligation.id
    )[:room]
    return anchor, neighbours


def recall_at_k(retrieved: tuple[Retrieved, ...], relevant: tuple[str, ...]) -> tuple[int, int]:
    """`(found, total)` — a count pair, never a ratio.

    The harness sums these across the gold set and prints "300 of 312". The
    same argument as design note D-41: over a closed, hand-labelled corpus
    the honest unit is a count, and a rate printed from one invites a reader
    to treat it as an estimate of a population that was never sampled.
    """
    got = {item.span.span_id for item in retrieved}
    return sum(1 for span_id in relevant if span_id in got), len(relevant)
