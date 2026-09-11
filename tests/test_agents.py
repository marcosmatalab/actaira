"""The judging layer: grounding, the abstention policy, and reproducibility.

Three things are worth testing here and everything else is detail.

The first is that a citation is checked. The whole package exists so that a
model's verdict about a compliance document can be verified against the
document, and every branch of that check is exercised with hand-built inputs
rather than through a provider — a fabricated quotation, an off-by-seven
offset, offsets past the end, a boolean where an integer belongs — because
those are exactly the answers a cassette will never contain and a real model
eventually will.

The second is the abstention policy. `pipeline.decide` is pure, so each of its
branches is one assertion, and the one branch that is an exemption (an empty
document) is tested from both sides: it must produce `not_addressed`, and it
must not be reachable for `addressed`.

The third is that the harness is a measurement. The cassette provider must
replay identically across instances, the prompt must be a pure function of its
arguments, and the corpus must regenerate byte for byte. If any of those
stops holding, every number in `evals/agents/results.json` is describing
something other than what it says.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from conftest import REPO_ROOT

EVALS_AGENTS = Path(REPO_ROOT) / "evals" / "agents"
if str(EVALS_AGENTS) not in sys.path:
    sys.path.insert(0, str(EVALS_AGENTS))

import build as gold_build  # noqa: E402

import harness as gold_harness  # noqa: E402
from actaira.agents import corpus, judge, pipeline, provider, retriever, verifier  # noqa: E402
from actaira.agents.judge import Citation, Judgement, JudgeVerdict  # noqa: E402
from actaira.governance import catalog  # noqa: E402

GOLD = json.loads((EVALS_AGENTS / "gold.json").read_text(encoding="utf-8"))
DOCUMENTS = EVALS_AGENTS / "documents"
PROVIDER = provider.CassetteProvider()


def a_judgement(verdict: JudgeVerdict, citations: tuple[Citation, ...], parse_error: str = "") -> Judgement:
    """A `Judgement` with the fields the policy reads and nothing else set."""
    return Judgement(
        verdict=verdict,
        citations=citations,
        spans_used=(),
        reason="",
        prompt_key="",
        prompt_tokens=0,
        completion_tokens=0,
        latency_ms=0.0,
        parse_error=parse_error,
    )


def a_positive_pair() -> tuple[str, catalog.Obligation, dict]:
    pair = next(row for row in GOLD["pairs"] if row["kind"] == "positive")
    document = (DOCUMENTS / f"{pair['document']}.md").read_text(encoding="utf-8")
    return document, catalog.by_id(pair["obligation_id"]), pair


# ---------------------------------------------------------------------------
# provider.py
# ---------------------------------------------------------------------------

def test_normalisation_ignores_invisible_edits():
    base = "one\ntwo\nthree"
    for variant in ("one\r\ntwo\r\nthree", "one  \ntwo\t\nthree", "\n\none\ntwo\nthree\n\n"):
        assert provider.prompt_key(variant) == provider.prompt_key(base), variant


def test_normalisation_does_not_ignore_a_changed_question():
    """The failure this guards against: a prompt edited to fix a bug, and the
    pre-bug answer served from the cassette because normalisation swallowed
    the edit."""
    assert provider.prompt_key("cite the document") != provider.prompt_key("cite the regulation")
    assert provider.prompt_key("a b") != provider.prompt_key("b a")
    assert provider.prompt_key("Addressed") != provider.prompt_key("addressed")


def test_the_cassette_replays_identically_across_instances():
    document, obligation, _ = a_positive_pair()
    anchor, neighbours = retriever.spans_for_judgement(obligation, document)
    prompt = judge.build_prompt(document, obligation, anchor + neighbours)

    first = provider.CassetteProvider().complete(prompt)
    second = provider.CassetteProvider().complete(prompt)
    assert first == second
    assert first.text == PROVIDER.complete(prompt).text


def test_a_prompt_nobody_recorded_raises_instead_of_inventing():
    with pytest.raises(provider.CassetteMiss) as caught:
        PROVIDER.complete("a prompt that was never recorded anywhere")
    assert "evals/agents/build.py" in str(caught.value)


def test_a_cassette_directory_that_does_not_exist_is_empty_rather_than_fatal(tmp_path):
    empty = provider.CassetteProvider(tmp_path / "nothing-here")
    assert len(empty) == 0
    with pytest.raises(provider.CassetteMiss):
        empty.complete("anything")


def test_recording_round_trips(tmp_path):
    class Fixed:
        name = "fixed"

        def complete(self, prompt, *, max_tokens=1024, temperature=0.0):
            return provider.Completion(
                text="the answer", prompt_tokens=3, completion_tokens=2, latency_ms=1.5, model="fixed"
            )

    recorder = provider.RecordingProvider(Fixed())
    recorder.complete("the question")
    recorder.save(tmp_path / "cassettes" / "one.json")

    replayed = provider.CassetteProvider(tmp_path / "cassettes")
    assert len(replayed) == 1
    assert replayed.complete("the question").text == "the answer"
    assert replayed.complete("the question").latency_ms == 1.5


def test_a_cassette_written_twice_is_identical(tmp_path):
    """No timestamp, no machine name: a regeneration that changed no answer
    must produce no diff, or reviewers learn to skim cassette diffs."""

    class Fixed:
        name = "fixed"

        def complete(self, prompt, *, max_tokens=1024, temperature=0.0):
            return provider.Completion(text="x", prompt_tokens=1, completion_tokens=1, latency_ms=0.0)

    def write(name: str) -> bytes:
        recorder = provider.RecordingProvider(Fixed())
        for question in ("b", "a", "c"):
            recorder.complete(question)
        return recorder.save(tmp_path / name).read_bytes()

    assert write("first.json") == write("second.json")


def test_two_cassettes_disagreeing_about_one_prompt_are_refused(tmp_path):
    key = provider.prompt_key("q")
    for name, answer in (("a.json", "yes"), ("b.json", "no")):
        (tmp_path / name).write_text(
            json.dumps(
                {
                    "schema": provider.CASSETTE_SCHEMA,
                    "entries": [{"key": key, "text": answer, "prompt_tokens": 0, "completion_tokens": 0}],
                }
            ),
            encoding="utf-8",
        )
    with pytest.raises(ValueError, match="recorded twice"):
        provider.CassetteProvider(tmp_path)


def test_the_http_provider_will_not_exist_without_a_key(monkeypatch):
    for name in (provider.API_KEY_ENV, provider.ENDPOINT_ENV, provider.MODEL_ENV):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(provider.MissingCredential):
        provider.HTTPProvider()


def test_the_http_provider_refuses_a_plaintext_endpoint(monkeypatch):
    monkeypatch.setenv(provider.API_KEY_ENV, "k")
    monkeypatch.setenv(provider.ENDPOINT_ENV, "http://example.invalid/v1")
    monkeypatch.setenv(provider.MODEL_ENV, "m")
    with pytest.raises(ValueError, match="https"):
        provider.HTTPProvider()


# ---------------------------------------------------------------------------
# corpus.py
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("document_id", sorted(row["document"] for row in GOLD["pairs"]))
def test_every_sentence_offset_slices_back_to_its_own_text(document_id):
    """The property every citation check rests on, asserted over the whole
    corpus rather than over an example."""
    text = (DOCUMENTS / f"{document_id}.md").read_text(encoding="utf-8")
    for sentence in corpus.sentences(text):
        assert text[sentence.start : sentence.end] == sentence.text


def test_a_span_never_presents_itself_as_the_regulation():
    for span in corpus.ALL_SPANS:
        assert "not the text of the Regulation" in span.attribution
        assert span.citation


def test_the_stopword_filter_survives_stemming():
    """`does` stems to `doe`. A stopword list stored unstemmed and compared
    against stemmed tokens filters nothing, silently."""
    assert corpus.content_terms("It does have all of these") == set()


def test_every_judged_obligation_has_spans():
    for obligation in catalog.ALL_OBLIGATIONS:
        if obligation.checkability is catalog.Checkability.EVIDENCE_JUDGED:
            assert corpus.spans_for(obligation.id), obligation.id


# ---------------------------------------------------------------------------
# retriever.py
# ---------------------------------------------------------------------------

def test_the_anchor_is_always_the_obligation_being_judged():
    """The bug that made this function exist: on half the gold set the prompt
    named one obligation and quoted another."""
    for pair in GOLD["pairs"]:
        obligation = catalog.by_id(pair["obligation_id"])
        document = (DOCUMENTS / f"{pair['document']}.md").read_text(encoding="utf-8")
        anchor, neighbours = retriever.spans_for_judgement(obligation, document)
        assert anchor == corpus.spans_for(obligation.id)
        assert all(span.obligation_id != obligation.id for span in neighbours)


def test_ranking_is_deterministic():
    document, obligation, _ = a_positive_pair()
    first = [item.span.span_id for item in retriever.retrieve(obligation, document, k=8)]
    second = [item.span.span_id for item in retriever.retrieve(obligation, document, k=8)]
    assert first == second


def test_recall_is_reported_as_a_count_pair():
    document, obligation, pair = a_positive_pair()
    found, total = retriever.recall_at_k(
        retriever.retrieve(obligation, document), tuple(pair["relevant_spans"])
    )
    assert isinstance(found, int) and isinstance(total, int)
    assert 0 <= found <= total


# ---------------------------------------------------------------------------
# judge.py
# ---------------------------------------------------------------------------

def test_the_prompt_is_a_pure_function_of_its_arguments():
    document, obligation, _ = a_positive_pair()
    anchor, neighbours = retriever.spans_for_judgement(obligation, document)
    built = [judge.build_prompt(document, obligation, anchor + neighbours) for _ in range(3)]
    assert len(set(built)) == 1


def test_the_document_survives_the_prompt_unmodified():
    """If this drifts by one character every offset in every cassette is
    wrong, and nothing else would show it."""
    for pair in GOLD["pairs"][:12]:
        obligation = catalog.by_id(pair["obligation_id"])
        document = (DOCUMENTS / f"{pair['document']}.md").read_text(encoding="utf-8")
        anchor, neighbours = retriever.spans_for_judgement(obligation, document)
        prompt = judge.build_prompt(document, obligation, anchor + neighbours)
        assert judge.document_from_prompt(prompt) == document


@pytest.mark.parametrize(
    "answer, expected_error",
    [
        ("no json at all", "no JSON object"),
        ("{not json}", "not valid JSON"),
        ('{"verdict": "maybe", "citations": []}', "unknown verdict"),
        ('{"verdict": "addressed", "citations": "nope"}', "citations is not a list"),
        ('{"verdict": "addressed", "citations": [{"start": 1}]}', "missing start, end or quote"),
        ('{"verdict": "addressed", "citations": [{"start": true, "end": 4, "quote": "x"}]}', "boolean"),
        ('{"verdict": "addressed", "citations": [3]}', "not an object"),
        ("[1, 2, 3]", "no JSON object"),
    ],
)
def test_a_malformed_answer_is_a_parse_error_and_never_a_default(answer, expected_error):
    verdict, citations, _spans, _reason, error = judge.parse_answer(answer)
    assert verdict is JudgeVerdict.ABSTAIN
    assert citations == ()
    assert expected_error in error


def test_json_wrapped_in_prose_or_a_code_fence_still_parses():
    wrapped = 'Sure!\n```json\n{"verdict": "addressed", "citations": [{"start": 0, "end": 3, "quote": "abc"}]}\n```'
    verdict, citations, _spans, _reason, error = judge.parse_answer(wrapped)
    assert error == ""
    assert verdict is JudgeVerdict.ADDRESSED
    assert citations[0].quote == "abc"


# ---------------------------------------------------------------------------
# verifier.py
# ---------------------------------------------------------------------------

DOCUMENT = "We keep records of the training made available to staff. The lease was renewed."


def test_a_real_quotation_at_its_real_offsets_is_literal():
    quote = "We keep records of the training made available to staff."
    literal, reason = verifier.check_literal(DOCUMENT, Citation(0, len(quote), quote))
    assert literal and reason == ""


@pytest.mark.parametrize(
    "citation, expected",
    [
        (Citation(7, 63, "We keep records of the training made available to staff."), "offsets point at"),
        (Citation(0, 20, "Nothing like this appears anywhere."), "does not occur anywhere"),
        (Citation(500, 540, "We keep records"), "outside the document"),
        (Citation(10, 4, "We keep records"), "outside the document"),
        (Citation(0, 3, "   "), "empty quotation"),
    ],
)
def test_every_shape_of_bad_citation_is_named(citation, expected):
    literal, reason = verifier.check_literal(DOCUMENT, citation)
    assert not literal
    assert expected in reason


def test_the_support_check_runs_in_opposite_directions():
    """A quotation that plainly states the measure supports `addressed` and
    refutes `not_addressed`. Without the second direction a grader that marks
    everything unmet would never be caught."""
    spans = corpus.spans_for("AIA-4")
    quote = (
        "The measures taken to support AI literacy are set out for each role, and attendance "
        "records for the training made available to staff are kept."
    )
    assert verifier.check_support_lexical(quote, JudgeVerdict.ADDRESSED, spans)[0]
    assert not verifier.check_support_lexical(quote, JudgeVerdict.NOT_ADDRESSED, spans)[0]


def test_a_quotation_too_short_to_measure_cannot_support_addressed():
    """The heading case: three content terms, all of them in the obligation's
    vocabulary, and no evidence of anything."""
    spans = corpus.spans_for("AIA-4")
    supported, _overlap, total, reason = verifier.check_support_lexical(
        "AI literacy measures", JudgeVerdict.ADDRESSED, spans
    )
    assert not supported
    assert total < verifier.MIN_QUOTE_TERMS_ADDRESSED
    assert "content terms" in reason


def test_the_support_check_is_skipped_when_the_quotation_is_not_real():
    """Computing an overlap against a sentence the model invented would put a
    number next to the words `supported: true`."""
    checks = verifier.verify(
        DOCUMENT,
        JudgeVerdict.ADDRESSED,
        (Citation(0, 20, "Invented text that is not here at all."),),
        corpus.spans_for("AIA-4"),
    )
    assert not checks[0].literal
    assert not checks[0].supported
    assert checks[0].quote_terms == 0
    assert checks[0].method == "literal"


def test_the_shipped_thresholds_are_the_ones_the_data_chooses():
    """The constants in `verifier.py` are fitted. This re-runs the fit and
    fails if somebody edited a constant without re-running it, which is the
    only way a 'calibrated' threshold becomes a threshold chosen by eye."""
    fit = gold_harness.calibrate(gold_harness.ensure_corpus(), PROVIDER)
    assert fit["chosen"] is not None, fit.get("error")
    assert fit["agrees_with_shipped"], fit["chosen"]


def test_the_calibration_replay_agrees_with_the_real_policy():
    """`verifier.simulate` is a second implementation of `pipeline.decide`,
    written so the sweep cannot share a bug with the thing it is fitting.
    Two implementations are worth having only if something checks they agree."""
    gold = gold_harness.ensure_corpus()
    rows = gold_harness.run_pairs(gold, PROVIDER, floor=0.0, ceiling=1.0, min_terms=0)
    samples = gold_harness.samples_from(rows, gold)
    real = gold_harness.run_pairs(gold, PROVIDER)
    for sample, actual in zip(samples, real, strict=True):
        replayed = verifier.simulate(
            sample,
            verifier.SUPPORT_FLOOR_ADDRESSED,
            verifier.SUPPORT_CEILING_NOT_ADDRESSED,
            verifier.MIN_QUOTE_TERMS_ADDRESSED,
        )
        assert replayed == actual["verdict"], actual["pair_id"]


# ---------------------------------------------------------------------------
# pipeline.py — the abstention policy, one assertion per branch
# ---------------------------------------------------------------------------

GOOD = Citation(0, 56, "We keep records of the training made available to staff.")


@pytest.mark.parametrize(
    "judgement, checks, expected_verdict, expected_reason",
    [
        (
            a_judgement(JudgeVerdict.ADDRESSED, (GOOD,), parse_error="not JSON"),
            (),
            "abstain",
            pipeline.REASON_UNPARSEABLE,
        ),
        (a_judgement(JudgeVerdict.ABSTAIN, ()), (), "abstain", pipeline.REASON_JUDGE_ABSTAINED),
        (a_judgement(JudgeVerdict.ADDRESSED, ()), (), "abstain", pipeline.REASON_NO_CITATIONS),
        (a_judgement(JudgeVerdict.NOT_ADDRESSED, ()), (), "abstain", pipeline.REASON_NO_CITATIONS),
    ],
)
def test_the_abstention_policy_on_a_document_with_content(judgement, checks, expected_verdict, expected_reason):
    verdict, reason = pipeline.decide(DOCUMENT, judgement, checks)
    assert (verdict, reason) == (expected_verdict, expected_reason)


def test_an_empty_document_the_judge_called_unmet_is_answered_not_abstained():
    verdict, reason = pipeline.decide("\n   \n", a_judgement(JudgeVerdict.NOT_ADDRESSED, ()), ())
    assert verdict == JudgeVerdict.NOT_ADDRESSED.value
    assert reason == pipeline.REASON_EMPTY_DOCUMENT


def test_the_empty_document_exemption_cannot_produce_addressed():
    """The exemption is a hole only if it can be walked through in the other
    direction. It cannot: `addressed` with nothing cited still abstains."""
    verdict, reason = pipeline.decide("\n   \n", a_judgement(JudgeVerdict.ADDRESSED, ()), ())
    assert verdict == JudgeVerdict.ABSTAIN.value
    assert reason == pipeline.REASON_NO_CITATIONS


def test_one_hallucinated_citation_discards_the_whole_answer():
    """Two citations, one of them real. The real one does not rescue the
    verdict: a model that fabricated a sentence was not doing the task."""
    forged = Citation(0, 30, "A sentence that is simply not in this document.")
    checks = verifier.verify(DOCUMENT, JudgeVerdict.ADDRESSED, (GOOD, forged), corpus.spans_for("AIA-4"))
    assert checks[0].literal and not checks[1].literal
    verdict, reason = pipeline.decide(DOCUMENT, a_judgement(JudgeVerdict.ADDRESSED, (GOOD, forged)), checks)
    assert verdict == JudgeVerdict.ABSTAIN.value
    assert reason == pipeline.REASON_HALLUCINATED


def test_a_citation_that_does_not_carry_the_claim_abstains():
    weak = Citation(57, 79, "The lease was renewed.")
    assert DOCUMENT[weak.start : weak.end] == weak.quote
    checks = verifier.verify(DOCUMENT, JudgeVerdict.ADDRESSED, (weak,), corpus.spans_for("AIA-4"))
    assert checks[0].literal and not checks[0].supported
    verdict, reason = pipeline.decide(DOCUMENT, a_judgement(JudgeVerdict.ADDRESSED, (weak,)), checks)
    assert verdict == JudgeVerdict.ABSTAIN.value
    assert reason == pipeline.REASON_UNSUPPORTED


def test_a_cassette_miss_is_its_own_reason_and_not_a_cautious_model():
    """An eval whose corpus has gone stale must report a missing recording,
    not quietly inflate its abstention rate."""
    obligation = catalog.by_id("AIA-4")
    result = pipeline.judge_document("a document nobody ever recorded a judgement for", obligation, PROVIDER)
    assert result.verdict == JudgeVerdict.ABSTAIN.value
    assert result.reason == pipeline.REASON_NO_RECORDING


def test_a_provider_that_raises_becomes_an_abstention_and_not_a_stack_trace():
    class Broken:
        name = "broken"

        def complete(self, prompt, *, max_tokens=1024, temperature=0.0):
            raise RuntimeError("the endpoint went away")

    result = pipeline.judge_document("some text about literacy", catalog.by_id("AIA-4"), Broken())
    assert result.verdict == JudgeVerdict.ABSTAIN.value
    assert result.reason == pipeline.REASON_PROVIDER_FAILED
    assert "the endpoint went away" in result.detail["error"]


def test_the_pipeline_is_deterministic():
    document, obligation, _ = a_positive_pair()
    first = pipeline.judge_document(document, obligation, PROVIDER, document_id="d").to_dict()
    second = pipeline.judge_document(document, obligation, provider.CassetteProvider(), document_id="d").to_dict()
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


# ---------------------------------------------------------------------------
# The gold set and the harness
# ---------------------------------------------------------------------------

def test_the_gold_set_is_the_shape_it_claims_to_be():
    kinds = {kind: sum(1 for row in GOLD["pairs"] if row["kind"] == kind) for row in GOLD["pairs"] for kind in [row["kind"]]}
    assert 60 <= len(GOLD["pairs"]) <= 80
    assert kinds["hard_negative"] >= 20
    shapes = {row["negative_kind"] for row in GOLD["pairs"] if row["kind"] == "hard_negative"}
    assert shapes == set(gold_build.NEGATIVE_KINDS)


def test_the_corpus_regenerates_byte_for_byte(tmp_path):
    """Design note D-51. A corpus that cannot be rebuilt is a corpus nobody
    can check the published numbers against."""
    gold_build.write(tmp_path / "documents", tmp_path / "gold.json", tmp_path / "cassettes")
    assert (tmp_path / "gold.json").read_bytes() == (EVALS_AGENTS / "gold.json").read_bytes()
    for row in GOLD["pairs"]:
        rebuilt = (tmp_path / "documents" / f"{row['document']}.md").read_bytes()
        assert rebuilt == (DOCUMENTS / f"{row['document']}.md").read_bytes(), row["document"]


def test_the_cassettes_regenerate_with_the_same_answers(tmp_path):
    """The file itself is not compared: it carries the recording machine's
    latency, which is a measurement and not a constant. What must not move is
    what the stand-in said, keyed by prompt."""
    gold_build.write(tmp_path / "documents", tmp_path / "gold.json", tmp_path / "cassettes")
    rebuilt = json.loads((tmp_path / "cassettes" / "judged-gold.json").read_text(encoding="utf-8"))
    shipped = json.loads(
        (Path(REPO_ROOT) / "src" / "actaira" / "agents" / "cassettes" / "judged-gold.json").read_text("utf-8")
    )
    assert {row["key"]: row["text"] for row in rebuilt["entries"]} == {
        row["key"]: row["text"] for row in shipped["entries"]
    }


def test_every_gold_document_has_a_recorded_judgement():
    """A cassette miss inside the harness would show up as an abstention with
    its own reason, but it would still be a number describing the cassette
    directory rather than the pipeline."""
    for pair in GOLD["pairs"]:
        obligation = catalog.by_id(pair["obligation_id"])
        document = (DOCUMENTS / f"{pair['document']}.md").read_text(encoding="utf-8")
        anchor, neighbours = retriever.spans_for_judgement(obligation, document)
        assert PROVIDER.has(judge.build_prompt(document, obligation, anchor + neighbours)), pair["pair_id"]


@pytest.fixture(scope="module")
def harness_summary():
    return gold_harness.run(gold_harness.ensure_corpus(), PROVIDER)


def test_every_negative_control_behaves(harness_summary):
    controls = harness_summary["negative_controls"]
    for name, row in sorted(controls.items()):
        if name == "all_ok":
            continue
        assert row["ok"], f"{name}: {row['misbehaved']}"
    assert controls["all_ok"]


def test_two_harness_runs_produce_the_same_json(harness_summary):
    again = gold_harness.run(gold_harness.ensure_corpus(), provider.CassetteProvider())
    assert json.dumps(again, sort_keys=True) == json.dumps(harness_summary, sort_keys=True)


def test_the_harness_reports_counts_and_never_a_rate(harness_summary):
    """Design note D-41. The gold set is closed and hand-labelled, so the
    honest unit is a count; a rate printed from one reads as an estimate of a
    population that was never sampled."""
    accuracy = harness_summary["accuracy_conditional_on_answering"]["all"]
    assert set(accuracy) >= {"pairs", "answered", "answered_correct", "answered_incorrect", "abstained"}
    assert all(isinstance(accuracy[key], int) for key in ("answered", "answered_correct", "abstained"))
    assert "%" not in gold_harness.render(harness_summary)


# ---------------------------------------------------------------------------
# No scores anywhere
# ---------------------------------------------------------------------------

FORBIDDEN_KEY = ("score", "percent", "pct", "confidence", "rating", "grade", "probability")

#: The only float in a pipeline result, and it is a cost, not a judgement.
ALLOWED_FLOAT_KEYS = ("latency_ms_recorded",)


def walk(node, path=""):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from walk(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, f"{path}[{index}]")
    else:
        yield path, node


def test_no_pipeline_output_carries_a_score():
    document, obligation, _ = a_positive_pair()
    payload = pipeline.judge_document(document, obligation, PROVIDER, document_id="d").to_dict()
    for path, value in walk(payload):
        leaf = path.rsplit(".", 1)[-1].split("[")[0].lower()
        assert not any(word in leaf for word in FORBIDDEN_KEY), path
        if isinstance(value, str):
            assert "%" not in value, path
        if isinstance(value, float):
            assert leaf in ALLOWED_FLOAT_KEYS, f"{path} = {value}"


def test_the_retriever_keeps_its_ranking_score_to_itself():
    """A BM25 score has no meaning outside the index, and a number printed
    next to a regulation citation reads as a confidence."""
    document, obligation, _ = a_positive_pair()
    for item in retriever.retrieve(obligation, document):
        assert set(item.to_dict()) == {"span_id", "rank"}
