"""The regulation, cut into citable spans, and what those spans are not.

Design note D-46, and the sentence that has to survive every reading of this
file: **nothing here is the text of Regulation (EU) 2024/1689.**

What is here is the operational paraphrase this project already carries. The
catalogue in `governance/catalog.py` holds, for each obligation, an article
reference, a date, a role and a citation; the prose lives in
`i18n/en.json` under `governance`, as a `summary` of what the article
requires and a list of `evidence_expected` describing what a file would have
to contain for the obligation to be evidenced. Both were written by this
project, reviewed against the legal text, and are maintained as such. This
module cuts that prose into addressable pieces and attaches each piece to
the article it was written from.

Why a paraphrase rather than the official text, argued rather than excused:

  * The official text cannot be fetched here. `evals/corpus/build.py` makes
    the same argument about model artifacts and reaches the same conclusion:
    a corpus that is downloaded is a corpus that is not reproducible, and a
    test that depends on a third party is a test that fails on their
    schedule. Vendoring the Regulation would also mean vendoring a
    translation decision, a consolidation date and roughly a megabyte of
    text whose review is not a review this repository is equipped to do.
  * The judge does not need the legal text. It needs a statement of what the
    obligation asks for, precise enough to decide whether a document
    supplies it. That is what `evidence_expected` already is, and it is the
    field a compliance reviewer would argue with, which is the right thing
    to be arguing with.

The consequence, and it is a hard rule the rest of the package obeys: the
judge cites **the article and the span identifier**, and it quotes **the
operator's document**, never this corpus. A span's text is a paraphrase; a
quotation from it, rendered next to an article number, would read as the
Regulation's own words and would be a fabricated legal quotation in a
compliance report. `Span.attribution` carries that caveat into every output,
and `pipeline` records span identifiers rather than span prose for the same
reason.

The second thing this module owns is text handling, shared by the retriever
and the verifier: tokenisation, a content-word filter and a sentence
splitter with offsets. They live here rather than in a `text.py` because
they exist to make regulation prose and operator documents comparable, and
splitting them across two modules would let the retriever and the verifier
drift onto different notions of a word, which would silently decouple the
threshold the verifier was calibrated with from the retrieval it verifies.
"""
from __future__ import annotations

import itertools
import re
from dataclasses import dataclass
from typing import Any

from ..governance import catalog
from ..i18n.catalog import load as _load_catalog

#: What a span was cut from. `SUMMARY` describes the obligation, `EVIDENCE`
#: states what a document would have to supply. They are kept apart because
#: the verifier only trusts the second: "the obligation is about copyright"
#: is a description, "a written copyright policy" is the thing being asked
#: for, and only the second can decide whether a document supplied it.
KIND_SUMMARY = "summary"
KIND_EVIDENCE = "evidence_expected"

# Splits after a full stop that ends a word and precedes a capitalised word.
# `Art. 26(5)` and `(EU) 2019/790.` survive: the first is followed by a digit
# rather than a capital, and the second ends a sentence anyway. Written as one
# regex with a lookbehind and a lookahead so the offsets it produces are
# offsets into the original string, which is the whole reason the verifier can
# check a citation against a document.
_SENTENCE_BREAK = re.compile(r"(?<=[a-z0-9)\]])[.!?](?:[\"')\]]*)\s+(?=[A-Z(])")
_WORD = re.compile(r"[a-z0-9]+")
_LEADING_PARAGRAPH = re.compile(r"^(?:\([^)]*\)|-)+")

# Function words carry no evidence. The list is short and hand-written rather
# than imported, for the same reason everything else here is: a stopword list
# from a package is a dependency and a version to pin, and the terms below are
# the ones that actually distort a lexical overlap over documents of this
# shape. Regulatory verbs are deliberately absent: "ensure", "keep", "inform"
# and "assess" are exactly the words that decide whether a document describes
# a measure, and dropping them would blind the verifier.
#
# The list is written unstemmed and stemmed at the bottom of this module, once
# `stem` exists. Writing it pre-stemmed would have been a bug waiting to
# happen: `does` stems to `doe`, so a hand-stemmed list that anyone later
# edited in its natural spelling would silently stop filtering half of itself.
_STOPWORD_SOURCE = """
    a an the and or but if then than that this these those of in on at to for
    from by with without as is are was were be been being it its their there
    here which who whom whose what when where while any all each both other
    such not no nor so too very can may might shall should will would do does
    did done has have had having we our us you your they them he she his her
    i me my one two three per about into over under above below between within
"""


@dataclass(frozen=True)
class Span:
    """One citable piece of the operational paraphrase.

    `span_id` is the stable interface, in the same sense `rule_id` is in
    `model.py`: it is what the pipeline records, what a test asserts on and
    what an output cites. `text` is prose and may be reworded; anything that
    depended on the wording would break on a translation review, which is a
    review that should be free to happen.
    """

    span_id: str
    obligation_id: str
    article: str
    paragraph: str
    kind: str
    index: int
    text: str
    citation: str

    @property
    def attribution(self) -> str:
        """What a renderer must print next to this span. Never omitted.

        The wording is fixed here rather than left to each caller because a
        caller that forgets it turns a paraphrase into a quotation of the
        Official Journal, and that is a defect a reader cannot detect from
        the output.
        """
        return (
            f"Operational paraphrase of {self.article} written for Actaira, "
            f"not the text of the Regulation. Source: {self.citation}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "span_id": self.span_id,
            "obligation_id": self.obligation_id,
            "article": self.article,
            "paragraph": self.paragraph,
            "kind": self.kind,
            "index": self.index,
            "text": self.text,
            "citation": self.citation,
            "attribution": self.attribution,
        }


# ---------------------------------------------------------------------------
# Text handling, shared by the retriever and the verifier
# ---------------------------------------------------------------------------

def stem(term: str) -> str:
    """Four suffix rules, and an argument for why there are only four.

    A real stemmer (Porter, Snowball) is a dependency or two hundred lines
    of transliterated rules, and it would be doing violence to a vocabulary
    that is almost entirely legal-register English nouns and participles.
    What actually costs this package accuracy is narrower than that: the
    obligation says "records of how reservations of rights are identified
    and honoured" and the document says "we honour every reservation", and
    an exact-match overlap scores those two as sharing nothing. Four rules
    fix that class and stop:

        -ies -> -y      policies -> policy
        -s              records -> record, but not "process" or "less"
        -ed             honoured -> honour
        -ing            monitoring -> monitor

    Guarded by length so short words are left alone (`is`, `bed`, `ring`),
    and `-ss` is exempt because stripping it turns `process` into `proces`
    and `assess` into `asses`, both of which then fail to match themselves.

    The known cost, stated rather than discovered later: this conflates
    words a linguist would keep apart (`training` and `train`), and it does
    nothing for irregular forms. Both are acceptable because the same
    function is applied to the obligation and to the document, so a
    conflation affects the two sides identically and cannot make a document
    match an obligation it does not share vocabulary with.
    """
    if len(term) > 4 and term.endswith("ies"):
        return term[:-3] + "y"
    # `identified` -> `identify`, and it has to run before the `-ed` rule or
    # that rule turns it into `identifi` while the obligation's own
    # `identify` stays put, and the two stop matching. That mismatch was
    # real: it cost the copyright key sentence one overlapping term out of
    # twenty-two, which was enough to drop it below the stand-in judge's
    # topicality gate and leave the document's heading as the only thing
    # cited.
    if len(term) > 4 and term.endswith("ied"):
        return term[:-3] + "y"
    if len(term) > 5 and term.endswith("ing"):
        return term[:-3]
    if len(term) > 4 and term.endswith("ed"):
        return term[:-2]
    if len(term) > 3 and term.endswith("s") and not term.endswith("ss"):
        return term[:-1]
    return term


#: The stopword set the tokeniser filters against, in the tokeniser's own
#: vocabulary. Built from `_STOPWORD_SOURCE` through `stem` so the two can
#: never disagree about what a word looks like.
STOPWORDS: frozenset[str] = frozenset(stem(word) for word in _STOPWORD_SOURCE.split())


def tokenize(text: str) -> list[str]:
    """Lowercase alphanumeric runs, suffix-normalised. Duplicates kept.

    Duplicates are kept because BM25 needs term frequency. Callers that want
    a set say so.

    Stemming happens here, in the one function both the retriever and the
    verifier call, rather than at either call site. If the two ever tokenised
    differently, the threshold in `verifier.py` would have been fitted
    against a vocabulary the retriever does not produce, and nothing in the
    output would show it.
    """
    return [stem(term) for term in _WORD.findall(text.lower())]


def content_terms(text: str) -> set[str]:
    """The terms an overlap is allowed to be computed over.

    Single characters go too: a stray "a" or "5" from a split article
    reference would otherwise count as agreement between a document and the
    regulation, and with quotes as short as a sentence that is a real
    distortion rather than a rounding one.
    """
    return {term for term in tokenize(text) if len(term) > 1 and term not in STOPWORDS}


@dataclass(frozen=True)
class Sentence:
    """A sentence and where it starts in the string it came from.

    The offsets are the product here. A judge that cites `(start, end)` into
    a document can be checked by slicing that document, and the check is
    exact rather than a fuzzy match. Everything in `verifier.py` rests on
    these two integers being right, so the splitter is written to return
    slices of the original rather than pieces it reassembled.
    """

    start: int
    end: int
    text: str


def sentences(text: str) -> list[Sentence]:
    """Split into sentences, carrying exact offsets into `text`.

    Paragraph breaks split too, because a bulleted policy document has few
    full stops and treating a whole list as one sentence would make every
    citation the size of the document, which defeats the point of asking for
    one. `text[s.start:s.end] == s.text` holds for every result, and a test
    asserts it over the whole gold corpus rather than over an example.
    """
    if not text.strip():
        return []
    cuts: list[int] = [0]
    for match in _SENTENCE_BREAK.finditer(text):
        cuts.append(match.end())
    for match in re.finditer(r"\n\s*\n", text):
        cuts.append(match.end())
    cuts.append(len(text))
    cuts = sorted(set(cuts))

    out: list[Sentence] = []
    for start, end in itertools.pairwise(cuts):
        chunk = text[start:end]
        stripped = chunk.strip()
        if not stripped:
            continue
        offset = start + (len(chunk) - len(chunk.lstrip()))
        out.append(Sentence(start=offset, end=offset + len(stripped), text=stripped))
    return out


# ---------------------------------------------------------------------------
# Building the corpus
# ---------------------------------------------------------------------------

def _paragraph_of(article: str) -> str:
    """`Art. 53(1)(c)` -> `(1)(c)`; `Art. 11 + Annex IV` -> ``.

    Only a leading run of parenthesised groups counts. An article string that
    continues into prose ("Art. 26, in particular 26(5) and 26(6)") yields an
    empty paragraph rather than a guess, because a wrong paragraph reference
    in a compliance citation is worse than a missing one: the reader checks
    it, finds the wrong text, and stops trusting the rest.
    """
    _, _, rest = article.partition("Art.")
    rest = rest.strip()
    number, _, tail = rest.partition("(")
    if not tail:
        return ""
    del number
    match = _LEADING_PARAGRAPH.match("(" + tail)
    return match.group(0) if match else ""


def _spans_for(obligation: catalog.Obligation) -> list[Span]:
    text = _load_catalog("en").get(catalog.TEXT_SECTION, {}).get(obligation.id, {})
    paragraph = _paragraph_of(obligation.article)
    out: list[Span] = []

    for index, sentence in enumerate(sentences(str(text.get("summary", ""))), start=1):
        out.append(
            Span(
                span_id=f"{obligation.id}#s{index}",
                obligation_id=obligation.id,
                article=obligation.article,
                paragraph=paragraph,
                kind=KIND_SUMMARY,
                index=index,
                text=sentence.text,
                citation=obligation.citation,
            )
        )
    for index, item in enumerate(text.get("evidence_expected", ()), start=1):
        out.append(
            Span(
                span_id=f"{obligation.id}#e{index}",
                obligation_id=obligation.id,
                article=obligation.article,
                paragraph=paragraph,
                kind=KIND_EVIDENCE,
                index=index,
                text=str(item),
                citation=obligation.citation,
            )
        )
    return out


def build() -> tuple[Span, ...]:
    """Every span, over every obligation in the catalogue, in catalogue order.

    Forthcoming obligations are included. `AIA-26` is one of the five the
    judged controls cover and it is in `FORTHCOMING`, so excluding them would
    leave a judged control with no corpus; and a retriever that only knows
    about obligations already in force cannot demonstrate that it declines to
    return the wrong article, which is most of what its measurement is for.
    """
    out: list[Span] = []
    for obligation in catalog.ALL_OBLIGATIONS:
        out.extend(_spans_for(obligation))
    return tuple(out)


#: Built once at import. It is a few hundred short strings assembled from
#: JSON already in memory, so the cost is not worth a lazy accessor, and a
#: module-level constant is what makes `ALL_SPANS` safe to iterate in a
#: comprehension without wondering whether it is being rebuilt.
ALL_SPANS: tuple[Span, ...] = build()

_BY_ID: dict[str, Span] = {span.span_id: span for span in ALL_SPANS}


def by_id(span_id: str) -> Span | None:
    return _BY_ID.get(span_id)


def spans_for(obligation_id: str) -> tuple[Span, ...]:
    """The spans cut from one obligation. These are the gold set's labels."""
    return tuple(span for span in ALL_SPANS if span.obligation_id == obligation_id)


def evidence_spans(spans: tuple[Span, ...]) -> tuple[Span, ...]:
    """The `evidence_expected` spans among `spans`, or all of them.

    The verifier calls this. See the note on `KIND_EVIDENCE`: a support check
    computed against a description of the obligation would agree with any
    document on the same topic, which is precisely the hard negative the gold
    set is built around. Falling back to everything rather than to nothing
    matters because a few obligations carry no `evidence_expected` list, and
    an empty support vocabulary would make every citation unsupported and
    every judgement an abstention.
    """
    evidence = tuple(span for span in spans if span.kind == KIND_EVIDENCE)
    return evidence or spans
