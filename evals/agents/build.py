"""Build the judged-evidence gold set: documents, labels and cassettes.

Design note D-51. Same argument as design note D-19 one layer up, applied to
documents instead of to model artifacts: the corpus is generated from the code
in this file, so it is reproducible byte for byte on any machine, its SHA-256
values are published in `gold.json`, and a change to a document is a change to
a diff rather than to a file somebody uploaded once.

Downloading real compliance documents was never an option and it is worth
saying why, because it is not only about reproducibility. Real AI-literacy
policies and copyright statements belong to the companies that wrote them,
they are not licensed for redistribution, and a corpus of them would be a
corpus this project could not publish — which means the numbers measured on
it could not be checked by anyone. A synthetic corpus that ships is worth
more than a real one that cannot.

**What a hard negative is here, and why 25 of the 65 pairs are one.**

The easy negative — a document about something else entirely — measures
almost nothing. Any grader that reads the first line gets it right, and a
gold set made of those produces a flattering number that predicts nothing
about the case an operator actually files: a document that is *about the
obligation* and still does not discharge it. Five shapes, one of each per
obligation, each drawn from a way real filings fall short:

  intent        the measure is described in the future tense. "We will roll
                out training in Q3." A stated intention is not a measure
                taken, and this is the single most common shape of filler.
  adjacent      the right topic, the wrong limb. Article 4 asks about staff;
                the document describes AI literacy material published for
                customers. Every content word matches; the obligation does
                not.
  wrong_actor   somebody else's measures. The vendor's training, the
                provider's policy, quoted by a deployer who owes their own.
  filler        governance boilerplate with the obligation's title on top and
                no content under it. This is what a template generator emits.
  crossref      a pointer to a document that is not supplied. "See Annex C."
                Possibly true, and evidence of nothing, because the annex was
                not filed.

**On the stand-in provider.** There is no API key here and there must not be
one in CI, so the cassettes are recorded from `StubJudgeProvider`, a
deterministic rule-based grader defined in this file. That has to be stated
plainly wherever its numbers are: *the harness measures the pipeline, not a
language model.* Retrieval, the offset contract, citation verification, the
abstention policy and the negative controls are all exercised end to end and
their numbers are real. The quality of the *judgement* is the quality of a
stub. Re-record with `RecordingProvider` wrapping `HTTPProvider` and the same
harness measures a real model against the same labels, which is the point of
keeping the two apart.

The stub deliberately reads the `summary` spans of the retrieved set while
`verifier.py` checks against the `evidence_expected` spans. That is not a
detail: if both used the same vocabulary the verifier would be a rubber stamp
on the stub, the grounding figures would be circular, and the harness would
be measuring nothing at all.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from actaira.agents import corpus, judge, retriever  # noqa: E402
from actaira.agents.provider import Completion, RecordingProvider, count_tokens  # noqa: E402
from actaira.governance import catalog  # noqa: E402

HERE = Path(__file__).resolve().parent
DOCUMENTS_DIR = HERE / "documents"
GOLD_PATH = HERE / "gold.json"
CASSETTE_DIR = ROOT / "src" / "actaira" / "agents" / "cassettes"

GOLD_SCHEMA = "actaira-judged-gold/1"

#: The five obligations the catalogue marks EVIDENCE_JUDGED. Read from the
#: catalogue rather than listed, so that promoting a sixth obligation to that
#: tier extends the gold set instead of silently leaving it unmeasured.
JUDGED_OBLIGATIONS: tuple[str, ...] = tuple(
    obligation.id
    for obligation in catalog.ALL_OBLIGATIONS
    if obligation.checkability is catalog.Checkability.EVIDENCE_JUDGED
)

#: Boilerplate every `filler` hard negative is built from. One shared block,
#: because that is what makes it filler: the same paragraph appears under
#: every heading and says nothing about any of them.
FILLER = (
    "This organisation is committed to the responsible development and use of "
    "artificial intelligence.",
    "Oversight sits with a cross-functional steering group that meets each quarter "
    "and reports to the executive committee.",
    "Our stated values are transparency, accountability, proportionality and respect "
    "for fundamental rights.",
    "Any questions about this document should be directed to the compliance mailbox.",
)

#: The `unrelated` easy negative. Plausible corporate prose about a subject no
#: obligation in the catalogue touches.
UNRELATED = (
    "Facilities update for the London and Dublin offices.",
    "The lease on the third floor was renewed in January for a further five years.",
    "Desk booking moves to the new system on the first of next month, and the old "
    "kiosks will be removed once every team has migrated.",
    "Catering contracts were retendered and the incumbent supplier was retained.",
)


@dataclass(frozen=True)
class Topic:
    """The vocabulary one obligation's documents are written from.

    Held as data rather than as five hand-written files per obligation so
    that the *shape* of each document is a property of the generator and can
    be reasoned about. A hand-written corpus drifts: after twenty documents
    nobody can say whether the hard negatives are still hard or whether they
    picked up a tell.
    """

    slug: str
    heading: str
    preamble: tuple[str, ...]
    key: tuple[str, ...]
    support: tuple[str, ...]
    intent: str
    adjacent: str
    wrong_actor: str
    crossref: str


TOPICS: dict[str, Topic] = {
    "AIA-4": Topic(
        slug="ai-literacy",
        heading="AI literacy measures",
        preamble=(
            "This note covers the staff and contractors who operate or use AI systems on our behalf.",
            "It is maintained by the people team and reviewed each year.",
        ),
        key=(
            "The measures taken to support AI literacy are set out below for each role, and "
            "attendance records for the training made available to staff are kept in the "
            "learning management system.",
            "Every member of staff who operates an AI system completed a two-hour induction in "
            "March, and the guidance made available to them is archived together with a record "
            "of who received it.",
            "AI literacy measures proportionate to each role were rolled out across the three "
            "teams that use the system, and the training records for the staff concerned are "
            "retained for five years.",
            "A written description of the AI literacy measures taken sits in section 4 of the "
            "staff handbook, and records of the guidance actually made available to staff are "
            "held by the people team.",
            "Support for AI literacy is delivered through role-specific briefings that have run "
            "twice so far this year, with a record of the training kept for each member of staff "
            "who attended.",
        ),
        support=(
            "Roles are grouped into three tiers according to how directly a person acts on the "
            "output of a model.",
            "The material is written in plain language and does not assume a technical background.",
            "Contractors working on our behalf are treated the same as employees for this purpose.",
        ),
        intent=(
            "We will put in place measures to support AI literacy among staff during the next "
            "financial year, and records of the training made available will be kept from that "
            "point onwards."
        ),
        adjacent=(
            "All staff complete annual data protection and information security training, and "
            "attendance records are kept for every session."
        ),
        wrong_actor=(
            "Our model vendor states in its documentation that it supports AI literacy among its "
            "own engineering staff and keeps records of the training it provides to them."
        ),
        crossref=(
            "AI literacy: see Annex C of the Group Compliance Manual, which is held by the "
            "department named there."
        ),
    ),
    "AIA-26": Topic(
        slug="deployer-oversight",
        heading="Deployer operating procedure for the high-risk system",
        preamble=(
            "This procedure governs our use of the automated screening system supplied under contract 4471.",
            "It applies to the operations team and to the two reviewers named in appendix A.",
        ),
        key=(
            "Human oversight is assigned to two named reviewers whose competence, training and "
            "authority to override an output are recorded in appendix A, and the automatically "
            "generated logs are kept for eighteen months.",
            "The assignment of human oversight is documented for each shift, monitoring records "
            "under Article 26(5) are produced weekly, and the notifications sent to the provider "
            "in April and in June are filed with them.",
            "We keep the automatically generated logs for twelve months, above the six-month "
            "minimum, and the information given to workers before deployment is reproduced in "
            "appendix B.",
            "Monitoring records are reviewed each month by the named reviewer, who holds the "
            "authority to suspend use, and the notification sent to the provider when an "
            "anomaly appeared is attached.",
            "Oversight is assigned to a person with the necessary competence and authority, "
            "their training is recorded, the logs are retained, and affected persons are "
            "informed at the point the system is used on them.",
        ),
        support=(
            "The system is used only for the purpose described in the provider's instructions for use.",
            "Input data is drawn from the applicant record and is checked for completeness before submission.",
            "Appendix A is reviewed whenever a reviewer changes role.",
        ),
        intent=(
            "Human oversight will be assigned to named reviewers once the system goes live, and "
            "we intend to keep the automatically generated logs for at least six months from "
            "that date."
        ),
        adjacent=(
            "The provider's technical documentation describes the logging capability of the "
            "system and the accuracy metrics measured during its conformity assessment."
        ),
        wrong_actor=(
            "Under the contract the supplier retains the logs on our behalf and confirms that "
            "its own staff monitor the operation of the system."
        ),
        crossref=(
            "Human oversight, monitoring and log retention are covered by the Group Operating "
            "Standard, which is available on request."
        ),
    ),
    "AIA-50-3": Topic(
        slug="emotion-recognition-notice",
        heading="Notice for the emotion recognition pilot",
        preamble=(
            "This note covers the pilot running in the contact centre between March and September.",
            "It is owned by the operations lead and reviewed by the data protection officer.",
        ),
        key=(
            "The notice given to affected persons is read out at the start of every call and is "
            "reproduced in appendix A, and the lawful basis together with the record of "
            "processing is held by the data protection officer.",
            "Every person exposed to the system is informed of its operation before it runs, "
            "through the on-screen notice reproduced below, and the record of processing "
            "activities entry for this pilot was updated in February.",
            "Affected persons are informed of the operation of the emotion recognition system by "
            "the written notice at the entrance and by the spoken notice on each call, and the "
            "lawful basis relied on is legitimate interests as recorded in the register.",
            "The notice given to affected persons is displayed at every workstation covered by "
            "the pilot, and the records of processing name the controller, the purpose and the "
            "retention period.",
            "Persons exposed to the biometric categorisation feature are informed at the point "
            "of exposure, and the GDPR lawful basis together with the record of processing is "
            "maintained by the data protection officer.",
        ),
        support=(
            "The pilot covers four teams and is limited to inbound calls.",
            "No output of the system is used to make a decision about an individual on its own.",
            "The supplier is named in the contract register.",
        ),
        intent=(
            "A notice for affected persons is being drafted and will be displayed once the pilot "
            "moves out of the test phase, at which point the record of processing will also be "
            "updated."
        ),
        adjacent=(
            "Our privacy notice on the public website explains in general terms that we may use "
            "automated tools to improve service quality, and the retention schedule is published "
            "alongside it."
        ),
        wrong_actor=(
            "The supplier informs its own employees that the emotion recognition feature is "
            "running and holds the record of processing for its side of the arrangement."
        ),
        crossref=(
            "The notice to affected persons and the processing record are held in the DPO "
            "workspace under the pilot reference."
        ),
    ),
    "AIA-53-1c": Topic(
        slug="copyright-policy",
        heading="Copyright policy for model training",
        preamble=(
            "This policy applies to every corpus used to train or fine-tune the models we publish.",
            "It is owned by the legal team and was last reviewed in January.",
        ),
        key=(
            "This written copyright policy requires the crawler to read robots.txt and the TDM "
            "reservation signals on every domain, and the records of how each reservation of "
            "rights was identified and honoured are kept in the crawl ledger.",
            "We identify reservations of rights expressed under Article 4(3) of Directive (EU) "
            "2019/790 using the tdm-reservation header and the ai.txt convention, and the "
            "records of which domains were excluded on that basis are retained per crawl.",
            "The policy set out here obliges us to honour every machine-readable reservation of "
            "rights, and the record of identified reservations, with the date each was honoured, "
            "is held with the dataset card.",
            "A written copyright policy is in force across all training runs, and the exclusion "
            "list it produces, together with the record of how each reservation of rights was "
            "identified, is versioned in the data repository.",
            "Reservations of rights are identified through state-of-the-art detection of the "
            "TDM opt-out signals, they are honoured before the crawl begins, and the records of "
            "both steps are kept for each corpus.",
        ),
        support=(
            "Licensed corpora are handled under their own agreements and are listed separately.",
            "The crawl runs monthly and the exclusion list is refreshed on each run.",
            "Questions about a specific domain go to the legal mailbox.",
        ),
        intent=(
            "A copyright policy is being drafted and we intend to honour reservations of rights "
            "expressed under Article 4(3) of Directive (EU) 2019/790 once the detection tooling "
            "is in place."
        ),
        adjacent=(
            "Our terms of service set out who owns the output of the model and grant the "
            "customer a licence to use generated material commercially."
        ),
        wrong_actor=(
            "The dataset we licensed comes with the supplier's own statement that it honoured "
            "rights reservations during collection and keeps records of the domains it excluded."
        ),
        crossref=(
            "Copyright and text and data mining: refer to the Group IP Standard, section 9, "
            "which the legal team maintains."
        ),
    ),
    "AIA-55": Topic(
        slug="systemic-risk",
        heading="Systemic risk measures for the frontier model",
        preamble=(
            "This document covers the model classified under Article 51 and released in June.",
            "It is maintained by the safety team and the security team jointly.",
        ),
        key=(
            "Model evaluation including documented adversarial testing was carried out against "
            "the published protocol in May, the systemic risk assessment and the mitigation "
            "measures taken are recorded in section 3, and serious incidents are reported to "
            "the AI Office through the process in section 5.",
            "We completed adversarial testing with an external red team, documented the "
            "systemic risk assessment, applied the mitigation measures listed, and hold "
            "cybersecurity measures for the model weights and for the physical infrastructure "
            "they sit on.",
            "The model evaluation records and the adversarial testing report are attached, the "
            "risks assessed at Union level are listed with the mitigation applied to each, and "
            "the incident reporting process to the AI Office was exercised in a drill in April.",
            "Adversarial testing against standardised protocols was documented in March, the "
            "systemic risk assessment was updated at the same time, and cybersecurity measures "
            "for the model and its physical infrastructure are audited each quarter.",
            "Serious incident tracking runs to the AI Office under the process described here, "
            "model evaluation and adversarial testing records are retained, and the mitigation "
            "measures taken after the last assessment are itemised in appendix D.",
        ),
        support=(
            "The model card and the evaluation harness version are recorded with each release.",
            "Weights are held in a segregated environment with hardware-backed key custody.",
            "The safety team reports to the board twice a year.",
        ),
        intent=(
            "Adversarial testing is planned for the next release cycle, a systemic risk "
            "assessment will follow, and we expect to have an incident reporting channel to the "
            "AI Office in place before the end of the year."
        ),
        adjacent=(
            "Benchmark scores for the model on the standard public evaluation suites are "
            "published in the model card, together with the training compute used."
        ),
        wrong_actor=(
            "The infrastructure provider carries out adversarial testing of its own platform and "
            "reports serious incidents affecting the data centre to its regulator."
        ),
        crossref=(
            "Model evaluation, systemic risk and incident reporting are addressed in the "
            "internal Safety Framework, which is available to auditors on request."
        ),
    ),
}

#: The order hard negatives are generated in. Fixed, so a pair identifier
#: means the same thing across regenerations and a diff of `gold.json` is
#: readable.
NEGATIVE_KINDS = ("intent", "adjacent", "wrong_actor", "filler", "crossref")

#: A document with no content at all. Whitespace rather than the empty string
#: because that is the shape a real placeholder file has, and because it
#: exercises `content_terms` rather than a length check.
BLANK_DOCUMENT = "\n   \n\n"


@dataclass
class GoldPair:
    """One labelled (document, obligation) pair."""

    pair_id: str
    obligation_id: str
    document: str
    sha256: str
    label: str
    kind: str
    negative_kind: str = ""
    relevant_spans: list[str] = field(default_factory=list)
    key_sentence: str = ""
    note: str = ""


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _document(heading: str, paragraphs: tuple[str, ...]) -> str:
    """Assemble a document. One paragraph per line, blank line between.

    Markdown-flavoured because that is what an operator files, and because
    the blank lines give `corpus.sentences` paragraph boundaries to split on,
    which is what keeps a citation the size of a sentence rather than the
    size of the file.
    """
    body = "\n\n".join(paragraphs)
    return f"# {heading}\n\n{body}\n"


def build_documents() -> tuple[dict[str, str], list[GoldPair]]:
    """Every document and its label. Pure: no filesystem, no provider.

    Returns `(document_id -> text, pairs)`. Split out from `write()` so a
    test can assert on the corpus without writing 65 files, and so the
    cassette recorder and the writer are looking at the same strings rather
    than at a file each of them read back.
    """
    documents: dict[str, str] = {}
    pairs: list[GoldPair] = []
    ordered = [oid for oid in JUDGED_OBLIGATIONS if oid in TOPICS]

    for position, obligation_id in enumerate(ordered):
        topic = TOPICS[obligation_id]
        spans = [span.span_id for span in corpus.spans_for(obligation_id)]

        # `obligation_id` and `spans` are bound as defaults rather than
        # captured. A closure over a loop variable reads the value at call
        # time, and every call here happens inside the same iteration only by
        # accident of how the function is used today.
        def add(
            doc_id: str,
            text: str,
            label: str,
            kind: str,
            negative_kind: str,
            note: str,
            key: str = "",
            obligation_id: str = obligation_id,
            spans: list[str] = spans,
        ) -> None:
            documents[doc_id] = text
            pairs.append(
                GoldPair(
                    pair_id=f"{obligation_id}/{doc_id}",
                    obligation_id=obligation_id,
                    document=doc_id,
                    sha256=_digest(text),
                    label=label,
                    kind=kind,
                    negative_kind=negative_kind,
                    relevant_spans=list(spans),
                    key_sentence=key,
                    note=note,
                )
            )

        # -- five positives ------------------------------------------------
        for index, key_sentence in enumerate(topic.key, start=1):
            text = _document(
                topic.heading,
                (
                    topic.preamble[0],
                    topic.support[(index - 1) % len(topic.support)],
                    key_sentence,
                    topic.support[index % len(topic.support)],
                ),
            )
            add(
                f"{topic.slug}-positive-{index}",
                text,
                "addressed",
                "positive",
                "",
                "states a measure taken, in the vocabulary the obligation asks for",
                key=key_sentence,
            )

        # -- five hard negatives, one of each shape -------------------------
        hard = {
            "intent": (topic.preamble[0], topic.intent, topic.support[0]),
            "adjacent": (topic.preamble[1], topic.adjacent, topic.support[1]),
            "wrong_actor": (topic.preamble[0], topic.wrong_actor, topic.support[2]),
            "filler": FILLER,
            "crossref": (topic.preamble[1], topic.crossref, "The department named there holds the underlying material."),
        }
        notes = {
            "intent": "describes a future intention rather than a measure taken",
            "adjacent": "on the obligation's topic but answering a different limb of it",
            "wrong_actor": "somebody else's measures, quoted by the party who owes their own",
            "filler": "governance boilerplate under the obligation's own heading",
            "crossref": "points at a document that was not supplied",
        }
        for kind_name in NEGATIVE_KINDS:
            text = _document(topic.heading, hard[kind_name])
            add(
                f"{topic.slug}-hard-{kind_name}",
                text,
                "not_addressed",
                "hard_negative",
                kind_name,
                notes[kind_name],
            )

        # -- three easy negatives -------------------------------------------
        add(
            f"{topic.slug}-easy-blank",
            BLANK_DOCUMENT,
            "not_addressed",
            "easy_negative",
            "blank",
            "no content at all; the pipeline must answer, not abstain",
        )
        other = TOPICS[ordered[(position + 1) % len(ordered)]]
        add(
            f"{topic.slug}-easy-crossfiled",
            _document(
                other.heading,
                (other.preamble[0], other.support[0], other.key[0], other.support[1]),
            ),
            "not_addressed",
            "easy_negative",
            "crossfiled",
            "a document that addresses a different obligation, filed against this one",
        )
        add(
            f"{topic.slug}-easy-unrelated",
            _document("Office update", UNRELATED),
            "not_addressed",
            "easy_negative",
            "unrelated",
            "about nothing in the catalogue",
        )

    return documents, pairs


@dataclass
class Ablation:
    """A positive document with its load-bearing sentence removed.

    A negative control rather than a gold pair. The assertion is not about
    the resulting verdict's correctness but about the pipeline *reacting*:
    if deleting the one sentence that states the measure leaves the verdict
    unchanged, the verdict was not being driven by the document, and every
    other number the harness prints is describing something else.
    """

    control_id: str
    base_pair_id: str
    obligation_id: str
    document: str
    sha256: str
    removed: str


def build_ablations(documents: dict[str, str], pairs: list[GoldPair]) -> tuple[dict[str, str], list[Ablation]]:
    """One ablation per obligation, from that obligation's first positive."""
    ablated: dict[str, str] = {}
    controls: list[Ablation] = []
    seen: set[str] = set()
    for pair in pairs:
        if pair.kind != "positive" or pair.obligation_id in seen:
            continue
        seen.add(pair.obligation_id)
        original = documents[pair.document]
        stripped = original.replace(pair.key_sentence, "").replace("\n\n\n", "\n\n")
        if stripped == original:  # pragma: no cover - guards a generator bug
            raise ValueError(f"{pair.pair_id}: key sentence not found in its own document")
        doc_id = f"{pair.document}--ablated"
        ablated[doc_id] = stripped
        controls.append(
            Ablation(
                control_id=doc_id,
                base_pair_id=pair.pair_id,
                obligation_id=pair.obligation_id,
                document=doc_id,
                sha256=_digest(stripped),
                removed=pair.key_sentence,
            )
        )
    return ablated, controls


# ---------------------------------------------------------------------------
# The stand-in model
# ---------------------------------------------------------------------------

#: Phrases that mark a sentence as describing an intention rather than a
#: measure. Matched on the lowercased raw text, not on stems, because the
#: signal is grammatical: "will keep" and "keeps" stem alike and mean
#: opposite things for this purpose.
INTENT_MARKERS = (
    "will ",
    "we intend",
    "intends to",
    "is planned",
    "are planned",
    "is being drafted",
    "is being designed",
    "expect to",
    "expects to",
    "we aim",
    "once the",
    "once it",
    "plan to",
    "going to",
    "in due course",
    "next financial year",
    "before the end of the year",
)

#: Minimum share of a sentence's content terms that must be in the retrieved
#: summary vocabulary for the stub to treat it as being about the obligation
#: at all. Below this the stub answers not_addressed. It is the stub's own
#: constant, deliberately not the verifier's: the stub is standing in for a
#: model and the verifier must be able to disagree with it.
STUB_TOPIC_FLOOR = 0.20

_SPAN_LINE = re.compile(r"^\s*\[([A-Za-z0-9#\-]+)\]\s*\([^)]*\)\s*(.*)$")


class StubJudgeProvider:
    """A deterministic rule-based grader standing in for a language model.

    Defined in the eval harness and never in `src/`, so it cannot be wired
    into a control by accident and so nobody can mistake it for something
    this project ships as a judge.

    It sees only the prompt, like any provider, and recovers the document and
    the spans from it with the helpers in `judge.py` — reusing those rather
    than re-parsing is what keeps its offsets aligned with the ones the
    verifier will check.

    The rule, in order:

      1. A document with no sentences is `not_addressed`, cited by nothing.
         That is the case the pipeline's one exemption exists for.
      2. Otherwise every sentence is scored by the share of its content terms
         that appear in the retrieved *summary* spans.
      3. If the best sentence is below `STUB_TOPIC_FLOOR`, the document is
         not about the obligation: `not_addressed`, citing the best sentence
         so the claim is still grounded.
      4. If the best sentence carries an intent marker, the document
         describes a plan: `not_addressed`, citing it.
      5. Otherwise `addressed`, citing the best sentence and the runner-up
         when the runner-up also clears the floor.

    Rules 3 and 4 are the only two negatives it can detect. It has nothing
    that distinguishes the wrong actor's measures from ours, or a heading
    with boilerplate under it from a heading with content — which is exactly
    why the gold set contains those shapes. A stand-in that got everything
    right would tell nobody anything about the harness.
    """

    name = "stub-judge/1"
    model = "stub-judge/1"

    def complete(self, prompt: str, *, max_tokens: int = 1024, temperature: float = 0.0) -> Completion:
        del max_tokens, temperature
        started = time.perf_counter()
        text = self.answer(prompt)
        elapsed = (time.perf_counter() - started) * 1000.0
        return Completion(
            text=text,
            prompt_tokens=count_tokens(prompt),
            completion_tokens=count_tokens(text),
            latency_ms=elapsed,
            model=self.model,
            usage_source="whitespace",
        )

    def answer(self, prompt: str) -> str:
        document = judge.document_from_prompt(prompt)
        summary_terms, all_terms, span_ids = self._span_vocabulary(prompt)
        vocabulary = summary_terms or all_terms

        pieces = corpus.sentences(document)
        if not pieces:
            return self._json("not_addressed", [], span_ids, "the document has no content to cite")

        scored: list[tuple[int, float, corpus.Sentence]] = []
        for piece in pieces:
            # A markdown heading names the document; it asserts nothing about
            # it. "# Copyright policy for model training" is the subject line
            # of a filing, and a grader asked which sentence shows a measure
            # was taken would never offer the title. Skipping it here is a
            # property of the stand-in, not a rule of the package: the
            # verifier's `MIN_QUOTE_TERMS_ADDRESSED` catches a title from any
            # judge, and it has to, because a real model is not bound by this
            # loop.
            if piece.text.lstrip().startswith("#"):
                continue
            terms = corpus.content_terms(piece.text)
            overlap = len(terms & vocabulary)
            share = (overlap / len(terms)) if terms else 0.0
            scored.append((overlap, share, piece))

        # Ranked by how many of the asked-for things a sentence mentions, with
        # the share used only as a topicality gate. The first version ranked
        # by share alone and it was wrong in a way worth recording: share
        # rewards a sentence for having *no other content*, so the documents'
        # own markdown headings ("# AI literacy measures": three content
        # terms, all three in the obligation's vocabulary, share 1.0) beat
        # every sentence that actually stated a measure. The stub then cited
        # the title of the document as the evidence that the document was
        # true, and — because it cited the same title before and after — the
        # harness's ablation control could never fire.
        if not scored:
            return self._json("not_addressed", [], span_ids, "the document has nothing but a heading")
        gated = [row for row in scored if row[1] >= STUB_TOPIC_FLOOR]
        gated.sort(key=lambda row: (-row[0], row[2].start))
        fallback = max(scored, key=lambda row: (row[0], -row[2].start))[2]

        if not gated:
            return self._json(
                "not_addressed",
                [fallback],
                span_ids,
                "the closest passage in the document is not about what this obligation asks for",
            )
        best = gated[0][2]

        # Is this document more about one of the neighbouring articles than
        # about the one in front of us? If some neighbour's best sentence
        # mentions strictly more of that article's vocabulary than the best
        # sentence here mentions of the target's, the document is answering a
        # different obligation, and answering a different obligation is
        # `not_addressed` — never `abstain`, because there is nothing unclear
        # about it.
        best_overlap = gated[0][0]
        for owner, vocabulary_other in sorted(self._neighbour_vocabularies(prompt).items()):
            rival = max(
                (len(corpus.content_terms(piece.text) & vocabulary_other) for _o, _s, piece in scored),
                default=0,
            )
            if rival > best_overlap:
                return self._json(
                    "not_addressed",
                    [best],
                    span_ids,
                    f"the document answers {owner} rather than the obligation in front of it",
                )

        lowered = best.text.lower()
        if any(marker in lowered for marker in INTENT_MARKERS):
            return self._json(
                "not_addressed",
                [best],
                span_ids,
                "the document describes an intention rather than a measure taken",
            )
        # One citation, plus any that is exactly as strong. The policy in
        # `pipeline.decide` discards the whole answer if *any* citation fails
        # verification, so attaching a weaker second sentence can only lose:
        # it was measured doing exactly that, dragging an `addressed` verdict
        # into an abstention on the strength of a preamble line the grader
        # had no need to quote. Evidence is cited because it carries the
        # claim, not to pad a list.
        cited = [row[2] for row in gated if row[0] == gated[0][0]][:3]
        cited.sort(key=lambda piece: piece.start)
        return self._json("addressed", cited, span_ids, "the document states the measure the obligation asks for")

    @staticmethod
    def _neighbour_vocabularies(prompt: str) -> dict[str, set[str]]:
        """Summary vocabulary per *other* obligation quoted in the prompt.

        This is what the retriever's neighbours are for. A document filed
        against Article 26 that reads far more like Article 50(3) is a
        misfiling, and saying so requires something to compare against — the
        judge cannot conclude "this is about a different article" from the
        target article alone. The neighbours are that something, and without
        this the stand-in had no way at all to reach `not_addressed` on a
        document whose vocabulary genuinely overlaps the target's.
        """
        out: dict[str, set[str]] = {}
        head = prompt.split(judge.DOCUMENT_OPEN, 1)[0]
        target = ""
        for line in head.splitlines():
            if line.startswith("OBLIGATION "):
                target = line.split()[1]
            match = _SPAN_LINE.match(line)
            if not match:
                continue
            span_id, text = match.group(1), match.group(2)
            owner = span_id.split("#")[0]
            if owner == target or "#s" not in span_id:
                continue
            out.setdefault(owner, set()).update(corpus.content_terms(text))
        return out

    @staticmethod
    def _span_vocabulary(prompt: str) -> tuple[set[str], set[str], list[str]]:
        """Summary vocabulary, all vocabulary, and the span ids, from the prompt.

        Two filters, and both matter.

        The stub reads the *summary* spans while `verifier.py` checks against
        the *evidence* spans. See the module docstring: sharing a vocabulary
        would make the verifier a rubber stamp on the stub.

        And it reads only the spans of the obligation named in the prompt
        header. The prompt also carries neighbouring articles the retriever
        surfaced, which are there so a grader can recognise a document that
        answers a different obligation; pooling their vocabulary into the
        score would do the opposite, and would mark a copyright policy as
        addressing Article 4 because Article 53 was quoted three lines above.
        A real model reads the header; so does this.
        """
        summary: set[str] = set()
        every: set[str] = set()
        ids: list[str] = []
        head = prompt.split(judge.DOCUMENT_OPEN, 1)[0]
        target = ""
        for line in head.splitlines():
            if line.startswith("OBLIGATION "):
                target = line.split()[1]
            match = _SPAN_LINE.match(line)
            if not match:
                continue
            span_id, text = match.group(1), match.group(2)
            ids.append(span_id)
            if target and not span_id.startswith(target + "#"):
                continue
            terms = corpus.content_terms(text)
            every |= terms
            if "#s" in span_id:
                summary |= terms
        return summary, every, ids

    @staticmethod
    def _json(verdict: str, cited: list[corpus.Sentence], span_ids: list[str], reason: str) -> str:
        return json.dumps(
            {
                "verdict": verdict,
                "citations": [{"start": p.start, "end": p.end, "quote": p.text} for p in cited],
                "spans_used": span_ids,
                "reason": reason,
            }
        )


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------

def record(documents: dict[str, str], obligation_of: dict[str, str], *, k: int = retriever.DEFAULT_K) -> RecordingProvider:
    """Run every document through the judge once, capturing what was said.

    The prompt is rebuilt exactly as `pipeline.judge_document` would build
    it, by calling the same retriever with the same `k`. A recorder that
    assembled its own prompt would record answers under keys the pipeline
    never asks for, and every replay would miss — which is the failure this
    whole arrangement exists to make impossible.
    """
    recorder = RecordingProvider(StubJudgeProvider(), name="stub-judge/1")
    for document_id in sorted(documents):
        obligation = catalog.by_id(obligation_of[document_id])
        if obligation is None:  # pragma: no cover - guards a generator bug
            raise ValueError(f"{document_id}: unknown obligation {obligation_of[document_id]!r}")
        text = documents[document_id]
        anchor, neighbours = retriever.spans_for_judgement(obligation, text, k=k)
        prompt = judge.build_prompt(text, obligation, anchor + neighbours)
        recorder.complete(prompt, max_tokens=judge.MAX_TOKENS, temperature=0.0)
    return recorder


def write(
    documents_dir: Path = DOCUMENTS_DIR,
    gold_path: Path = GOLD_PATH,
    cassette_dir: Path = CASSETTE_DIR,
) -> dict[str, Any]:
    """Build everything and put it on disk. Idempotent."""
    documents, pairs = build_documents()
    ablated, ablations = build_ablations(documents, pairs)

    documents_dir.mkdir(parents=True, exist_ok=True)
    for document_id, text in sorted({**documents, **ablated}.items()):
        (documents_dir / f"{document_id}.md").write_text(text, encoding="utf-8", newline="\n")

    obligation_of = {pair.document: pair.obligation_id for pair in pairs}
    obligation_of.update({control.document: control.obligation_id for control in ablations})

    # The cross-obligation negative control: a positive document for one
    # obligation, judged against the next one along. Its prompt is not any
    # gold pair's prompt, so it needs its own recording.
    ordered = [oid for oid in JUDGED_OBLIGATIONS if oid in TOPICS]
    misfiled: dict[str, str] = {}
    misfiled_of: dict[str, str] = {}
    misfiled_rows: list[dict[str, str]] = []
    for position, obligation_id in enumerate(ordered):
        source_slug = TOPICS[ordered[(position + 1) % len(ordered)]].slug
        source_id = f"{source_slug}-positive-1"
        control_id = f"{TOPICS[obligation_id].slug}-control-misfiled"
        misfiled[control_id] = documents[source_id]
        misfiled_of[control_id] = obligation_id
        misfiled_rows.append(
            {
                "control_id": control_id,
                "obligation_id": obligation_id,
                "source_document": source_id,
                "sha256": _digest(documents[source_id]),
            }
        )

    recorder = record({**documents, **ablated, **misfiled}, {**obligation_of, **misfiled_of})
    cassette_dir.mkdir(parents=True, exist_ok=True)
    recorder.save(cassette_dir / "judged-gold.json", recorded_by="evals/agents/build.py :: StubJudgeProvider")

    payload = {
        "schema": GOLD_SCHEMA,
        "generated_by": "evals/agents/build.py",
        "recorded_with": "StubJudgeProvider (see the module docstring: this is not a language model)",
        "retriever_k": retriever.DEFAULT_K,
        "obligations": list(ordered),
        "pairs": [asdict(pair) for pair in pairs],
        "ablations": [asdict(control) for control in ablations],
        "misfiled_controls": misfiled_rows,
    }
    gold_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the judged-evidence gold set")
    parser.add_argument("--documents", type=Path, default=DOCUMENTS_DIR)
    parser.add_argument("--gold", type=Path, default=GOLD_PATH)
    parser.add_argument("--cassettes", type=Path, default=CASSETTE_DIR)
    args = parser.parse_args()
    payload = write(args.documents, args.gold, args.cassettes)
    hard = sum(1 for pair in payload["pairs"] if pair["kind"] == "hard_negative")
    print(
        f"{len(payload['pairs'])} pairs over {len(payload['obligations'])} obligations "
        f"({hard} hard negatives), {len(payload['ablations'])} ablations, "
        f"{len(payload['misfiled_controls'])} misfiled controls"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
