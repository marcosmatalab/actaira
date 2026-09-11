"""Controls for the obligations whose evidence is a document somebody wrote.

Design note D-53. Five obligations in the catalogue carry
`Checkability.EVIDENCE_JUDGED`, and they have nothing in common except the
shape of their evidence: Article 4 asks for measures supporting AI literacy,
Article 53(1)(c) for a copyright policy, Article 55 for evaluation and
mitigation records, Articles 26 and 50(3) for what a deployer did and told
people. None of that is in a weight file. All of it arrives as a document the
operator hands over, and the only question software can ask about such a
document is whether it addresses the obligation or fills space.

That question is a judgement, so these controls carry `Method.JUDGED` and
everything in `agents/` sits behind them: retrieval, a grader that must quote
the document at exact offsets, a verifier that checks every quotation, and an
abstention policy that discards an answer it cannot ground. What arrives here
is one of three words per document, and this module's job is the last mile —
finding the right documents, mapping three words onto four outcomes, and
writing down the boundary of what was actually judged.

**Which documents.** Two sources, in this order, and the order is the point:

  1. What the operator declared. `actaira.yaml` may name the files that
     answer each obligation, and a named file is used whether or not its name
     looks like anything. This is the path that should be used, because it is
     the operator asserting what their evidence is, and an assertion with a
     name on it is auditable.
  2. Failing that, a filename convention. `copyright-policy.md` for Article
     53(1)(c), `ai-literacy.md` for Article 4, and so on. This exists so the
     tool does something useful on a directory nobody has configured, and it
     is strictly a guess — recorded in the evidence as `found_by: filename`
     so nobody mistakes it for a declaration.

A file found by convention and a file named in a declaration are never mixed
in the same result without saying which was which, for the same reason the
BOM labels every declared field: a reader has to be able to tell what the
operator asserted from what this tool inferred.

**Mapping three words onto four outcomes.**

    addressed      -> SATISFIED       the control read this document and
                                      found, in it, quotations it verified
                                      that state what the obligation asks
                                      for. Nothing more.
    not_addressed  -> NOT_SATISFIED   the control read this document and it
                                      does not state that. A fact about the
                                      document, not a verdict about the
                                      operator, and not a claim that no such
                                      document exists somewhere else.
    abstain        -> INCONCLUSIVE    the pipeline would not ground an answer.
                                      Never collapsed into NOT_SATISFIED: see
                                      design note D-40, and note that on this
                                      corpus abstention is the *most common*
                                      non-answer, so collapsing it would turn
                                      a cautious tool into a confidently
                                      wrong one at a stroke.
    no documents   -> INCONCLUSIVE    with a reason naming what it looked for.
                                      Not NOT_SATISFIED: "the operator did not
                                      put a copyright policy in this directory"
                                      and "the operator has no copyright
                                      policy" are different claims and only
                                      the first is observable from here.

Across several documents the rule is: one `addressed` document makes the
control SATISFIED, and the documents it could not decide go into
`abstained_on` rather than disappearing. That follows the rule in
`controls/model.py` that a control may only answer for what it inspected —
finding the policy does not stop the second file from being unreadable, and
the result says so.

**What SATISFIED here does not mean.** It does not mean the obligation is
discharged. It does not mean the measures described were carried out. It does
not mean the document is true. `covers` and `does_not_cover` carry those
three sentences into every single result, filled from what this run actually
did, because a boundary written in a docstring is a boundary the output does
not have.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..agents import pipeline
from ..agents.judge import JudgeVerdict
from ..agents.provider import (
    API_KEY_ENV,
    ENDPOINT_ENV,
    MODEL_ENV,
    CassetteProvider,
    HTTPProvider,
    LLMProvider,
)
from ..governance import catalog
from ..io_budget import read_at_most
from . import registry
from .model import Control, ControlResult, Method, Outcome, Target, inconclusive

#: Extensions a compliance document plausibly arrives in. Deliberately short
#: and deliberately text-only: this package judges characters at offsets, and
#: a `.pdf` or a `.docx` would have to be extracted first by something that
#: decides what the reading order is. That decision changes the offsets, so
#: it would have to be in the record, and it is not in this release. A `.pdf`
#: in the target is left alone rather than half-read.
DOCUMENT_SUFFIXES = (".md", ".markdown", ".txt", ".rst")

#: Past this, the control declines rather than truncating. A truncated
#: document judged as though it were whole is the worst available outcome:
#: the part that answered the obligation may be exactly the part that was cut,
#: and nothing in the result would show it. 256 KiB is far above any policy
#: document and far below anything that would strain a prompt.
MAX_DOCUMENT_BYTES = 256 * 1024

#: Filename fragments that suggest a file answers an obligation. Only ever
#: consulted when the operator declared nothing; see the module docstring.
#: They are matched against the lowercased filename, not the path, so a
#: directory called `copyright/` does not make every file in it a policy.
DOCUMENT_HINTS: dict[str, tuple[str, ...]] = {
    "AIA-4": ("ai-literacy", "ai_literacy", "literacy"),
    "AIA-26": ("deployer", "human-oversight", "human_oversight", "oversight", "instructions-for-use"),
    "AIA-50-3": ("emotion", "biometric", "affected-persons", "disclosure", "notice"),
    "AIA-53-1c": ("copyright", "tdm", "rights-reservation", "text-and-data-mining"),
    "AIA-55": ("systemic-risk", "systemic_risk", "adversarial", "red-team", "incident-report", "model-evaluation"),
}

#: Where a declaration may name the evidence for an obligation. Two spellings
#: because `actaira.yaml` is written by hand and both read naturally; the
#: control tries each and records which one it used.
DECLARATION_KEYS = ("evidence", "documents")


def _provider() -> LLMProvider:
    """The provider a registered control uses when nobody passed one.

    Cassettes unless all three environment variables are set. The condition is
    "all three" rather than "a key is present" on purpose: a half-configured
    endpoint would raise inside the control, the engine would turn it into
    INCONCLUSIVE with a stack trace in the evidence (design note D-44), and
    the operator would be looking at an exception where they should be looking
    at a judgement. A missing configuration is not an error here, it is the
    offline default.

    The offline default is not a silent downgrade either: with cassettes, a
    document nobody recorded produces `no_recorded_judgement_for_this_document`
    and an INCONCLUSIVE that names the problem.
    """
    if all(os.environ.get(name, "").strip() for name in (API_KEY_ENV, ENDPOINT_ENV, MODEL_ENV)):
        return HTTPProvider()
    return CassetteProvider()



@dataclass(frozen=True)
class FoundDocument:
    """One file this control decided to judge, and how it decided to.

    `found_by` is not decoration. A control that cannot say whether it read a
    file because the operator named it or because the filename looked
    promising is a control whose SATISFIED nobody can audit.
    """

    relative: str
    text: str
    found_by: str
    bytes_read: int
    too_large: bool = False


def find_documents(target: Target, obligation_id: str) -> tuple[tuple[FoundDocument, ...], dict[str, Any]]:
    """`(documents, how)` — what to judge, and an account of the search.

    The account is returned rather than logged because it goes into the
    result's evidence. When a judged control comes back INCONCLUSIVE with no
    documents, the only useful thing it can say is what it looked for and
    where, and reconstructing that from the source afterwards is exactly the
    kind of archaeology a compliance report should not require.
    """
    how: dict[str, Any] = {"obligation_id": obligation_id}
    parse_error = target.declared("_parse_error")
    if parse_error:
        # The engine could not read the declaration file. Recorded, because
        # otherwise this control quietly falls through to guessing at
        # filenames and the operator sees a result that ignored the file they
        # wrote without ever saying so.
        how["declaration_parse_error"] = str(parse_error)
    declared = _declared_paths(target, obligation_id)
    if declared:
        how["declared_paths"] = list(declared)
        how["source"] = "declaration"
        found: list[FoundDocument] = []
        missing: list[str] = []
        for item in declared:
            document = _read(target, Path(item), "declaration")
            # A declared path that does not resolve to a readable file inside
            # the target is named in the evidence rather than dropped. The
            # operator asserted that this file is their evidence; "it is not
            # there" is the single most useful thing the control can tell them,
            # and a silently shorter list is the least useful.
            if document is not None:
                found.append(document)
            else:
                missing.append(item)
        how["declared_paths_missing"] = missing
        return tuple(found), how

    hints = DOCUMENT_HINTS.get(obligation_id, ())
    how["source"] = "filename_convention"
    how["filename_hints"] = list(hints)
    how["files_considered"] = len(target.files)
    matches: list[FoundDocument] = []
    for path in target.files:
        if path.suffix.lower() not in DOCUMENT_SUFFIXES:
            continue
        name = path.name.lower()
        if not any(hint in name for hint in hints):
            continue
        document = _read(target, path, "filename")
        if document is not None:
            matches.append(document)
    matches.sort(key=lambda doc: doc.relative)
    return tuple(matches), how


def _declared_paths(target: Target, obligation_id: str) -> tuple[str, ...]:
    """Paths the operator named for this obligation, as a tuple of strings.

    Both a bare string and a list are accepted, and which of them an operator
    can actually write depends on the file they write it in. That is worth
    stating precisely rather than leaving to be discovered:

        actaira.yaml    one path per obligation, as a scalar:

                            evidence:
                              AIA-53-1c: docs/copyright-policy.md

                        A YAML *list* under an obligation id does not parse.
                        `engine._mini_yaml` is the standard library subset
                        this project uses instead of taking a second runtime
                        dependency (see its docstring), and in its current
                        form a `- item` under a key raises. The engine turns
                        that into `{"_parse_error": ...}` and the whole
                        declaration is lost, which is why this control
                        records the parse error rather than silently falling
                        through to guessing at filenames.

        actaira.json    several paths, because the engine parses that file
                        with `json.loads` and lists come for free:

                            {"evidence": {"AIA-53-1c": ["a.md", "b.md"]}}

    Anything that is neither a string nor a list is ignored rather than
    coerced. A mapping under an obligation id is a shape this code does not
    understand, and guessing at it would be guessing at what the operator
    meant their evidence to be.
    """
    for key in DECLARATION_KEYS:
        value = target.declared(key, obligation_id)
        if isinstance(value, str) and value.strip():
            return (value.strip(),)
        if isinstance(value, list):
            return tuple(str(item).strip() for item in value if str(item).strip())
    return ()


def _read(target: Target, relative: Path, found_by: str) -> FoundDocument | None:
    """Read one candidate, or `None` if it is not a file we can judge.

    Two defences, and both have a specific failure behind them.

    The path is resolved and required to stay inside the target. A declaration
    file is written by whoever wrote the target directory, so
    `evidence: {AIA-4: ../../../etc/passwd}` is a thing that can be in one,
    and a control that read it would put its contents into a report and, if
    attested, into a signed package. The check is on the resolved path, not on
    the string, because `a/../../b` passes any test that looks for `..` at the
    front.

    Decoding is `errors="replace"`. It has to be lossy-but-total rather than
    strict: a byte sequence that is not UTF-8 is a reason to judge a slightly
    mangled document, not a reason for the whole control to raise. The
    replacement characters occupy one position each, so offsets stay exact
    over the string that was actually judged — which is the string every
    citation is checked against.
    """
    candidate = relative if relative.is_absolute() else target.root / relative
    try:
        resolved = candidate.resolve()
        root = target.root.resolve()
    except OSError:
        return None
    if root != resolved and root not in resolved.parents:
        return None
    if not resolved.is_file():
        return None
    try:
        # D-160. The size check below used to run on a buffer that already
        # held the document, so `too_large` was reported after the memory
        # had been spent - the one case where it matters.
        raw, over_budget = read_at_most(resolved, MAX_DOCUMENT_BYTES)
    except OSError:
        return None
    display = str(relative) if not relative.is_absolute() else resolved.name
    if over_budget:
        # The size reported is the file's real size from `stat`, not how much
        # was read. The read is bounded; the report is not, because "this is
        # 900 MB" and "I stopped at 256 KiB" answer different questions and a
        # reader needs the first to know what to do about it.
        try:
            actual = resolved.stat().st_size
        except OSError:
            actual = len(raw)
        return FoundDocument(
            relative=display, text="", found_by=found_by, bytes_read=actual, too_large=True
        )
    return FoundDocument(
        relative=display,
        text=raw.decode("utf-8", errors="replace"),
        found_by=found_by,
        bytes_read=len(raw),
    )


# ---------------------------------------------------------------------------
# The boundary, written into every result
# ---------------------------------------------------------------------------

def _covers(obligation: catalog.Obligation, judged: list[dict[str, Any]]) -> str:
    names = ", ".join(row["document"] for row in judged) or "no document"
    spans = sorted({span for row in judged for span in row["regulation_spans"]})
    return (
        f"the text of {names}, judged against {len(spans)} span(s) of "
        f"{obligation.article} written as an operational paraphrase by this tool. "
        "Every quotation in this result was checked to occur literally in the document "
        "at the offset given."
    )


def _does_not_cover(obligation: catalog.Obligation) -> str:
    return (
        f"whether the measures described were actually carried out; whether the document is "
        f"true; any limb of {obligation.article} the spans above do not state; any evidence "
        f"the operator holds but did not put in this directory; and the legal question of "
        f"whether the {obligation.role.value} discharged the obligation, which no control "
        "answers. The judgement is a model's, checked against the document; it is not a legal "
        "opinion and the regulation text is not quoted here, only cited."
    )


# ---------------------------------------------------------------------------
# Running one obligation
# ---------------------------------------------------------------------------

def judge_target(obligation_id: str, target: Target, provider: LLMProvider | None = None) -> ControlResult:
    """The whole control, with the provider as an argument.

    Split from the registered `Control` so the test suite can hand in a
    `CassetteProvider` over a temporary directory and drive every branch,
    without the result depending on which environment variables happened to
    be set on the machine running the tests. The registered control calls
    this with `_provider()`.
    """
    control_id = f"ACT-C-JUDGE-{obligation_id}"
    obligation = catalog.by_id(obligation_id)
    if obligation is None:  # pragma: no cover - guards a catalogue edit
        raise ValueError(f"{control_id}: {obligation_id} is not in the catalogue")

    documents, how = find_documents(target, obligation_id)
    if not documents:
        return inconclusive(
            control_id,
            (obligation_id,),
            Method.JUDGED,
            "no_document_supplied_for_this_obligation",
            search=how,
            note=(
                "Nothing was found to judge. This is not a finding that the obligation is "
                "unmet: it is a statement that no document answering it was supplied in this "
                "directory or named in the declaration."
            ),
        )

    judge_with = provider if provider is not None else _provider()
    judged: list[dict[str, Any]] = []
    for document in documents:
        if document.too_large:
            judged.append(
                {
                    "document": document.relative,
                    "found_by": document.found_by,
                    "verdict": JudgeVerdict.ABSTAIN.value,
                    "reason": "document_larger_than_this_control_will_judge",
                    "bytes": document.bytes_read,
                    "limit_bytes": MAX_DOCUMENT_BYTES,
                    "regulation_spans": [],
                    "verified_quotations": [],
                }
            )
            continue
        result = pipeline.judge_document(
            document.text, obligation, judge_with, document_id=document.relative
        )
        judged.append(
            {
                "document": document.relative,
                "found_by": document.found_by,
                "sha256": result.document_sha256,
                "verdict": result.verdict,
                "reason": result.reason,
                "judge_said": result.judge_verdict,
                "regulation_spans": list(result.regulation_spans),
                "verified_quotations": [
                    {"start": check.citation.start, "end": check.citation.end, "quote": check.citation.quote}
                    for check in result.verified_citations
                ],
                "rejected_quotations": [
                    {"start": check.citation.start, "end": check.citation.end, "reason": check.reason}
                    for check in result.citations
                    if not check.ok
                ],
                "prompt_tokens": result.prompt_tokens,
                "completion_tokens": result.completion_tokens,
                "latency_ms_recorded": round(result.latency_ms, 4),
            }
        )

    addressed = [row for row in judged if row["verdict"] == JudgeVerdict.ADDRESSED.value]
    abstained = [row for row in judged if row["verdict"] == JudgeVerdict.ABSTAIN.value]
    if addressed:
        outcome = Outcome.SATISFIED
    elif abstained:
        outcome = Outcome.INCONCLUSIVE
    else:
        outcome = Outcome.NOT_SATISFIED

    return ControlResult(
        control_id=control_id,
        obligation_ids=(obligation_id,),
        outcome=outcome,
        method=Method.JUDGED,
        evidence={
            "search": how,
            "documents": judged,
            "provider": getattr(judge_with, "name", type(judge_with).__name__),
            "support_check": "lexical",
            "note": (
                "Each verdict below is a model's judgement about one document, with every "
                "quotation verified against that document. It is not an assessment of "
                "compliance."
            ),
        },
        # No findings. A `Finding` in this project is an observation about an
        # artifact's bytes, keyed by a rule identifier that both message
        # catalogues have to carry; a judgement about a policy document is not
        # that, and minting rule ids for it would put prose about grading into
        # a catalogue whose subject is file formats. The judgements are in
        # `evidence`, where the renderer already labels them by method.
        covers=_covers(obligation, judged),
        does_not_cover=_does_not_cover(obligation),
        inspected=tuple(row["document"] for row in judged),
        abstained_on=tuple(row["document"] for row in abstained),
    )


def make_control(obligation_id: str) -> Control:
    """Build the registered control for one obligation.

    A closure over the identifier rather than five near-identical functions.
    The five differ only in which obligation they name and which filenames
    they look for, and five copies of this body would drift: the first bug
    fixed in one of them would be fixed in one of them.
    """

    def run(target: Target) -> ControlResult:
        return judge_target(obligation_id, target)

    run.__name__ = f"run_judge_{obligation_id.replace('-', '_')}"
    return Control(
        id=f"ACT-C-JUDGE-{obligation_id}",
        obligation_ids=(obligation_id,),
        method=Method.JUDGED,
        run=run,
    )


#: The obligations this module answers for, read from the catalogue rather
#: than listed. If a sixth obligation is promoted to `EVIDENCE_JUDGED` and
#: nothing here changes, it gets a control automatically — and if the
#: catalogue names a control id this module would not produce, the registry's
#: both-directions check fails at import, which is the point of taking the
#: list from the catalogue instead of writing it twice.
JUDGED_OBLIGATION_IDS: tuple[str, ...] = tuple(
    obligation.id
    for obligation in catalog.ALL_OBLIGATIONS
    if obligation.checkability is catalog.Checkability.EVIDENCE_JUDGED
)

CONTROLS: tuple[Control, ...] = tuple(
    registry.register(make_control(obligation_id)) for obligation_id in JUDGED_OBLIGATION_IDS
)
