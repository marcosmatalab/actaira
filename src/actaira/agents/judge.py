"""Asking a model whether a document addresses an obligation.

Design note D-48, and the one constraint that makes the answer checkable.

A grader that returns a verdict and a paragraph of reasoning is unfalsifiable.
The reasoning reads well whether or not the document says what it claims,
and the reader has no way to tell the two apart short of reading the document
themselves, at which point the grader added nothing. Worse, it is exactly the
shape a model is best at producing when it has nothing: fluent agreement.

So the judge is not allowed to say anything that is not an offset. Every
verdict must come with citations, and every citation is a `(start, end)` pair
into the document plus the text that has to be found there. That makes the
answer mechanically checkable by `verifier.py`: slice the document at the
offsets, compare. A model that invented a supporting sentence produces a
slice that does not match, the whole answer is discarded, and the pipeline
abstains. A model that merely misjudged produces a real quotation that a
human can read in one second and disagree with.

Three verdicts, not two, for the reason `model.py` gives three: `abstain` has
to be reachable *by the model*, not only imposed on it by the policy
downstream. A grader whose only options are yes and no will pick one, and the
pick will be uniform-ish noise on the cases where it has no idea. Naming the
third option in the instructions and in the schema is what makes "I cannot
tell from this document" an answer rather than a coin flip.

What this module does not do: decide. It returns what the model said, parsed
and normalised, including what it failed to parse. `pipeline.py` owns the
abstention policy, and keeping the two apart is what lets a test drive a
hand-written malformed response through the parser without a model.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..governance.catalog import Obligation
from .corpus import Span
from .provider import LLMProvider, prompt_key

#: Delimiters around the document in the prompt. Two properties are required
#: of them and both are load-bearing: they must not occur in a compliance
#: document written by a human, and they must be stable, because they are
#: part of the prompt and therefore part of the cassette key. Changing them
#: invalidates every recording, which is why they are constants named here
#: rather than string literals in a template.
DOCUMENT_OPEN = "<<<BEGIN OPERATOR DOCUMENT>>>"
DOCUMENT_CLOSE = "<<<END OPERATOR DOCUMENT>>>"

#: The default budget for one judgement. A judgement is a verdict, a handful
#: of offsets and one sentence of reason, so this is generous; it is a cap
#: against a runaway generation rather than a target.
MAX_TOKENS = 900


class JudgeVerdict(str, Enum):
    """What the model may answer.

    Kept as its own enum rather than reusing `controls.model.Outcome`. The
    judge answers a question about a document ("does this address the
    obligation") and a control answers a question about a target ("did I
    observe what the obligation asks for"); mapping one to the other is a
    decision `controls/judged.py` makes explicitly and records. Sharing an
    enum would have made that mapping invisible, and the mapping is the part
    a reviewer should be able to argue with.
    """

    ADDRESSED = "addressed"
    NOT_ADDRESSED = "not_addressed"
    ABSTAIN = "abstain"


@dataclass(frozen=True)
class Citation:
    """A claim that `document[start:end] == quote`. Checked, never trusted."""

    start: int
    end: int
    quote: str

    def to_dict(self) -> dict[str, Any]:
        return {"start": self.start, "end": self.end, "quote": self.quote}


@dataclass(frozen=True)
class Judgement:
    """What the model said, parsed. Not yet a decision.

    `parse_error` is a field rather than an exception because an unparseable
    answer is a normal event with a defined handling (the pipeline abstains),
    and raising would push that handling into every call site. It also keeps
    the malformed text available for the eval output, where "the model
    emitted prose instead of JSON" and "the model judged wrongly" need to be
    distinguishable.
    """

    verdict: JudgeVerdict
    citations: tuple[Citation, ...]
    spans_used: tuple[str, ...]
    reason: str
    prompt_key: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    parse_error: str = ""
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "citations": [c.to_dict() for c in self.citations],
            "spans_used": list(self.spans_used),
            "reason": self.reason,
            "prompt_key": self.prompt_key,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "latency_ms_recorded": self.latency_ms,
            "parse_error": self.parse_error,
        }


# ---------------------------------------------------------------------------
# The prompt
# ---------------------------------------------------------------------------

def build_prompt(document: str, obligation: Obligation, spans: tuple[Span, ...]) -> str:
    """Assemble the prompt. Deterministic, and that is a requirement.

    Nothing here may vary between two calls with the same arguments: no
    timestamp, no random ordering, no machine name, no locale-dependent
    formatting. The prompt is hashed into the cassette key, so a single
    varying character would turn every replay into a miss and the offline
    harness into a wall of `CassetteMiss`.

    The document is emitted verbatim between two markers and the model is
    told that offsets are counted from the first character after the opening
    marker's newline. That sentence is the contract `verifier.py` enforces;
    if it were vague the model would be within its rights to count from the
    start of the prompt, and every citation would be off by a constant that
    a reviewer would waste an afternoon on.
    """
    span_lines = [
        f"  [{span.span_id}] ({span.article}{' ' + span.paragraph if span.paragraph else ''}) {span.text}"
        for span in spans
    ]
    return "\n".join(
        [
            "You are grading one document against one obligation of Regulation (EU) 2024/1689.",
            "",
            f"OBLIGATION {obligation.id} — {obligation.article} — {obligation.title}",
            f"Binds: {obligation.role.value}",
            "",
            "What the obligation asks for, as operational paraphrase written by the",
            "tool (NOT the text of the Regulation; do not quote these lines back as",
            "if they were legal text, cite them by their identifier instead):",
            *span_lines,
            "",
            "The operator's document follows. Character offsets are counted from the",
            "first character after the line with the opening marker, and the document",
            "ends at the character before the newline preceding the closing marker.",
            "",
            DOCUMENT_OPEN,
            document,
            DOCUMENT_CLOSE,
            "",
            "Decide one of:",
            "  addressed      — the document supplies what this obligation asks for.",
            "  not_addressed  — the document does not. It may be about the topic, it",
            "                   may promise a future measure, it may answer a",
            "                   different limb of the article: none of that counts.",
            "  abstain        — you cannot tell from this document alone.",
            "",
            "Rules you must obey:",
            "  1. Every verdict other than abstain MUST cite at least one span of the",
            "     document, given as exact character offsets and the exact text found",
            "     there. A citation whose text does not match the document at those",
            "     offsets invalidates your whole answer.",
            "  2. Cite the document. Never quote the obligation paraphrase above.",
            "  3. A stated intention to do something is not the doing of it.",
            "  4. If the document addresses a different obligation, that is",
            "     not_addressed, not abstain.",
            "",
            "Answer with one JSON object and nothing else:",
            '{"verdict": "addressed|not_addressed|abstain",',
            ' "citations": [{"start": <int>, "end": <int>, "quote": "<exact text>"}],',
            ' "spans_used": ["<span identifier>", ...],',
            ' "reason": "<one sentence>"}',
        ]
    )


def document_from_prompt(prompt: str) -> str:
    """Recover the document a prompt carries, or raise.

    Used by the eval harness's stand-in provider, which only ever sees the
    prompt string, and by tests that want to assert the document survived
    templating unmodified. It lives here rather than in the harness because
    the markers are defined here, and a second copy of the parsing would be
    free to disagree with the first about whether the newline belongs to the
    marker or to the document — an off-by-one that would corrupt every
    offset the stand-in produced.
    """
    start = prompt.index(DOCUMENT_OPEN) + len(DOCUMENT_OPEN) + 1
    end = prompt.index(DOCUMENT_CLOSE) - 1
    return prompt[start:end]


# ---------------------------------------------------------------------------
# Parsing the answer
# ---------------------------------------------------------------------------

_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


def parse_answer(text: str) -> tuple[JudgeVerdict, tuple[Citation, ...], tuple[str, ...], str, str]:
    """`(verdict, citations, spans_used, reason, parse_error)`.

    Tolerant about the envelope, strict about the contents. Models wrap JSON
    in prose and in code fences, and refusing those would turn a formatting
    habit into an abstention, which is a measurement of the wrapper rather
    than of the judgement. So the widest `{...}` is taken and parsed.

    Strict about the contents, because every leniency here is a way for a
    malformed answer to become a confident one:

      * an unknown verdict string is a parse error, not a default. Mapping
        an unrecognised word onto `not_addressed` would let a model that
        answered "unclear" be recorded as having found the obligation
        unmet.
      * a citation whose `start`/`end` are not integers, or whose `quote` is
        not a string, is a parse error for the whole answer rather than a
        dropped citation. Dropping it silently would leave a verdict standing
        on the citations that happened to parse.
      * booleans are rejected where integers are required. `True` is an
        `int` in Python and would slice a document at index 1.
    """
    match = _JSON_BLOCK.search(text or "")
    if not match:
        return JudgeVerdict.ABSTAIN, (), (), "", "no JSON object in the answer"
    try:
        payload = json.loads(match.group(0))
    except (ValueError, TypeError) as exc:
        return JudgeVerdict.ABSTAIN, (), (), "", f"answer is not valid JSON: {exc}"
    if not isinstance(payload, dict):
        return JudgeVerdict.ABSTAIN, (), (), "", "answer JSON is not an object"

    raw_verdict = payload.get("verdict")
    try:
        verdict = JudgeVerdict(str(raw_verdict))
    except ValueError:
        return JudgeVerdict.ABSTAIN, (), (), "", f"unknown verdict {raw_verdict!r}"

    citations: list[Citation] = []
    raw_citations = payload.get("citations", [])
    if not isinstance(raw_citations, list):
        return JudgeVerdict.ABSTAIN, (), (), "", "citations is not a list"
    for item in raw_citations:
        if not isinstance(item, dict):
            return JudgeVerdict.ABSTAIN, (), (), "", "a citation is not an object"
        start, end, quote = item.get("start"), item.get("end"), item.get("quote")
        if isinstance(start, bool) or isinstance(end, bool):
            return JudgeVerdict.ABSTAIN, (), (), "", "a citation offset is a boolean"
        if not isinstance(start, int) or not isinstance(end, int) or not isinstance(quote, str):
            return JudgeVerdict.ABSTAIN, (), (), "", "a citation is missing start, end or quote"
        citations.append(Citation(start=start, end=end, quote=quote))

    raw_spans = payload.get("spans_used", [])
    spans_used = tuple(str(item) for item in raw_spans) if isinstance(raw_spans, list) else ()
    reason = str(payload.get("reason", ""))[:400]
    return verdict, tuple(citations), spans_used, reason, ""


def judge(
    document: str,
    obligation: Obligation,
    spans: tuple[Span, ...],
    provider: LLMProvider,
    *,
    max_tokens: int = MAX_TOKENS,
    temperature: float = 0.0,
) -> Judgement:
    """One judgement. The provider's exceptions are the caller's problem.

    `CassetteMiss` in particular is deliberately not caught here. A miss
    means the harness is being run against a prompt nobody recorded, which is
    a broken setup, and turning it into an abstention at this depth would
    make a broken setup look like a cautious model — the abstention rate
    would quietly absorb it and the eval would report a number that measured
    the cassette directory. `pipeline.py` catches it one layer up, where it
    can be recorded as its own reason.

    `temperature` defaults to zero. Not because zero guarantees determinism
    at a real endpoint (it does not), but because anything else asks for
    variance in a decision that will be attested to.
    """
    prompt = build_prompt(document, obligation, spans)
    completion = provider.complete(prompt, max_tokens=max_tokens, temperature=temperature)
    verdict, citations, spans_used, reason, parse_error = parse_answer(completion.text)
    return Judgement(
        verdict=verdict,
        citations=citations,
        spans_used=spans_used,
        reason=reason,
        prompt_key=completion.cassette_key or prompt_key(prompt),
        prompt_tokens=completion.prompt_tokens,
        completion_tokens=completion.completion_tokens,
        latency_ms=completion.latency_ms,
        parse_error=parse_error,
        raw=completion.text,
    )
