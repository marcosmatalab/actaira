"""The judged controls: the mapping, the boundary, and what they refuse to do.

Four things are asserted here, in decreasing order of how badly they would
hurt if they broke.

The mapping. Three words from the pipeline become four outcomes, and the one
that matters is that `abstain` becomes INCONCLUSIVE and never NOT_SATISFIED.
Collapsing those two is how a cautious tool becomes a confidently wrong one,
and on this corpus it would silently convert a quarter of all judgements.

The boundary. Every result carries `covers` and `does_not_cover` filled from
what the run actually did. A control that returns SATISFIED without saying
that it read one file and knows nothing about whether the measures described
happened is a control whose output will be quoted at a regulator.

The search. A declaration outranks a filename guess, a path that leaves the
target directory is refused, and a file too large to judge is declined rather
than truncated.

And no scores, anywhere, in anything these controls emit.
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

from actaira.agents import pipeline  # noqa: E402
from actaira.agents.provider import CassetteProvider  # noqa: E402
from actaira.controls import engine, judged, registry  # noqa: E402
from actaira.controls.model import Method, Outcome  # noqa: E402
from actaira.governance import catalog  # noqa: E402

GOLD = json.loads((EVALS_AGENTS / "gold.json").read_text(encoding="utf-8"))
DOCUMENTS = EVALS_AGENTS / "documents"
PROVIDER = CassetteProvider()

JUDGED_IDS = tuple(
    obligation.id
    for obligation in catalog.ALL_OBLIGATIONS
    if obligation.checkability is catalog.Checkability.EVIDENCE_JUDGED
)

#: One filename per obligation that the control's own hints will match. Taken
#: from `DOCUMENT_HINTS` rather than written out, so a hint that is renamed
#: without the fixture being updated fails here instead of quietly making
#: every test in this file exercise the empty-directory branch.
FILENAME = {obligation_id: f"{judged.DOCUMENT_HINTS[obligation_id][0]}.md" for obligation_id in JUDGED_IDS}


def documents_by_verdict() -> dict[tuple[str, str], str]:
    """`(obligation, pipeline verdict) -> document id`, from the gold corpus.

    Chosen by running the pipeline rather than hard-coded, because a
    hard-coded "this document abstains" is a fixture that silently stops
    testing the abstention branch the first time a threshold moves. Sorted
    and first-wins, so the choice is deterministic.
    """
    found: dict[tuple[str, str], str] = {}
    for pair in sorted(GOLD["pairs"], key=lambda row: row["pair_id"]):
        obligation = catalog.by_id(pair["obligation_id"])
        text = (DOCUMENTS / f"{pair['document']}.md").read_text(encoding="utf-8")
        result = pipeline.judge_document(text, obligation, PROVIDER, document_id=pair["document"])
        found.setdefault((pair["obligation_id"], result.verdict), pair["document"])
    return found


BY_VERDICT = documents_by_verdict()


def target_with(tmp_path: Path, obligation_id: str, document_id: str, name: str | None = None):
    """Copy one corpus document into a target directory under a name the
    control will find, and load the target the way the engine does."""
    text = (DOCUMENTS / f"{document_id}.md").read_bytes()
    (tmp_path / (name or FILENAME[obligation_id])).write_bytes(text)
    return engine.load_target(tmp_path, role="any")


def a_case(verdict: str) -> tuple[str, str]:
    """An `(obligation_id, document_id)` the pipeline decides `verdict` on."""
    for obligation_id in JUDGED_IDS:
        document_id = BY_VERDICT.get((obligation_id, verdict))
        if document_id:
            return obligation_id, document_id
    raise AssertionError(f"the gold corpus produces no {verdict} judgement")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def registered_ids() -> set[str]:
    """Every control id in the registry.

    `registry._ensure_loaded` imports every control module by name, and on a
    branch where one of those modules has not been written yet that import
    raises. It sets its own loaded flag *before* importing, so a second call
    returns the controls that did register — which includes ours, since
    importing this test module imported `judged`. Retrying once is therefore
    correct rather than a workaround, and it costs nothing once the missing
    module lands.
    """
    try:
        return {control.id for control in registry.all_controls()}
    except ImportError:
        return {control.id for control in registry.all_controls()}


def test_one_control_per_judged_obligation_under_the_catalogue_s_own_id():
    assert {control.id for control in judged.CONTROLS} == {f"ACT-C-JUDGE-{oid}" for oid in JUDGED_IDS}
    assert registered_ids() >= {control.id for control in judged.CONTROLS}


def test_the_catalogue_and_the_module_name_the_same_controls():
    """The edge is checked in both directions, per design note D-43. A
    dangling edge in a compliance mapping is how a tool claims coverage it
    does not have."""
    for obligation_id in JUDGED_IDS:
        obligation = catalog.by_id(obligation_id)
        assert obligation.controls == (f"ACT-C-JUDGE-{obligation_id}",), obligation_id


def test_every_judged_control_declares_the_method_that_produced_it():
    for control in judged.CONTROLS:
        assert control.method is Method.JUDGED
        assert len(control.obligation_ids) == 1


def test_no_judged_control_is_bound_to_an_obligation_that_is_not_evidence_judged():
    for control in judged.CONTROLS:
        for obligation_id in control.obligation_ids:
            assert catalog.by_id(obligation_id).checkability is catalog.Checkability.EVIDENCE_JUDGED


# ---------------------------------------------------------------------------
# The mapping
# ---------------------------------------------------------------------------

def test_addressed_becomes_satisfied(tmp_path):
    obligation_id, document_id = a_case("addressed")
    result = judged.judge_target(obligation_id, target_with(tmp_path, obligation_id, document_id), PROVIDER)
    assert result.outcome is Outcome.SATISFIED
    assert result.inspected == (FILENAME[obligation_id],)
    assert result.abstained_on == ()
    assert result.evidence["documents"][0]["verified_quotations"]


def test_not_addressed_becomes_not_satisfied(tmp_path):
    obligation_id, document_id = a_case("not_addressed")
    result = judged.judge_target(obligation_id, target_with(tmp_path, obligation_id, document_id), PROVIDER)
    assert result.outcome is Outcome.NOT_SATISFIED
    assert result.abstained_on == ()


def test_abstain_becomes_inconclusive_and_never_not_satisfied(tmp_path):
    """The single most important line in this module. `not_satisfied` is a
    claim about the document; `abstain` is a statement that no claim could be
    grounded, and the two must not be spelled the same."""
    obligation_id, document_id = a_case("abstain")
    result = judged.judge_target(obligation_id, target_with(tmp_path, obligation_id, document_id), PROVIDER)
    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.abstained_on == (FILENAME[obligation_id],)


def test_no_document_is_inconclusive_with_a_reason_that_names_the_search(tmp_path):
    result = judged.judge_target("AIA-53-1c", engine.load_target(tmp_path), PROVIDER)
    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.evidence["reason"] == "no_document_supplied_for_this_obligation"
    assert result.evidence["search"]["filename_hints"]
    assert result.inspected == ()


def test_one_addressed_document_carries_the_control_and_the_rest_are_recorded(tmp_path):
    """A control may only answer for what it inspected. Finding the policy
    does not make the second file readable, and the result says so."""
    obligation_id, addressed = a_case("addressed")
    abstaining = BY_VERDICT.get((obligation_id, "abstain"))
    if abstaining is None:
        pytest.skip(f"{obligation_id} has no abstaining document in the gold corpus")
    (tmp_path / FILENAME[obligation_id]).write_bytes((DOCUMENTS / f"{addressed}.md").read_bytes())
    second = FILENAME[obligation_id].replace(".md", "-annex.md")
    (tmp_path / second).write_bytes((DOCUMENTS / f"{abstaining}.md").read_bytes())

    result = judged.judge_target(obligation_id, engine.load_target(tmp_path), PROVIDER)
    assert result.outcome is Outcome.SATISFIED
    assert set(result.inspected) == {FILENAME[obligation_id], second}
    assert result.abstained_on == (second,)


# ---------------------------------------------------------------------------
# The boundary
# ---------------------------------------------------------------------------

def test_every_result_carries_the_boundary_of_what_it_judged(tmp_path):
    obligation_id, document_id = a_case("addressed")
    result = judged.judge_target(obligation_id, target_with(tmp_path, obligation_id, document_id), PROVIDER)
    obligation = catalog.by_id(obligation_id)

    assert FILENAME[obligation_id] in result.covers
    assert obligation.article in result.covers
    assert "literally in the document" in result.covers
    for must_disclaim in ("actually carried out", obligation.role.value, "not a legal opinion"):
        assert must_disclaim in result.does_not_cover


def test_the_result_says_which_provider_answered(tmp_path):
    obligation_id, document_id = a_case("addressed")
    result = judged.judge_target(obligation_id, target_with(tmp_path, obligation_id, document_id), PROVIDER)
    assert result.evidence["provider"] == "cassette"
    assert result.evidence["support_check"] == "lexical"


def test_a_verified_quotation_really_is_in_the_document(tmp_path):
    obligation_id, document_id = a_case("addressed")
    target = target_with(tmp_path, obligation_id, document_id)
    result = judged.judge_target(obligation_id, target, PROVIDER)
    text = (tmp_path / FILENAME[obligation_id]).read_bytes().decode("utf-8")
    for row in result.evidence["documents"]:
        for quotation in row["verified_quotations"]:
            assert text[quotation["start"] : quotation["end"]] == quotation["quote"]


# ---------------------------------------------------------------------------
# The search
# ---------------------------------------------------------------------------

def test_a_declaration_outranks_the_filename_convention(tmp_path):
    """A file the operator named is evidence they asserted. A file whose name
    looked promising is a guess this tool made, and the two are not the same
    kind of thing."""
    obligation_id, document_id = a_case("addressed")
    (tmp_path / "annex-7.md").write_bytes((DOCUMENTS / f"{document_id}.md").read_bytes())
    (tmp_path / "actaira.yaml").write_text(
        f"evidence:\n  {obligation_id}: annex-7.md\n", encoding="utf-8"
    )
    target = engine.load_target(tmp_path)
    result = judged.judge_target(obligation_id, target, PROVIDER)

    assert result.evidence["search"]["source"] == "declaration"
    assert result.inspected == ("annex-7.md",)
    assert result.evidence["documents"][0]["found_by"] == "declaration"


def test_several_declared_paths_come_through_the_json_declaration(tmp_path):
    """`engine._mini_yaml` cannot parse a list, so a multi-document
    declaration has to be written as `actaira.json`. Tested because the
    control accepts both shapes and only one of them is reachable from YAML;
    a reader who assumed otherwise would write a list, get a parse error, and
    see a result computed from filenames."""
    obligation_id, first = a_case("addressed")
    second = BY_VERDICT.get((obligation_id, "not_addressed")) or first
    (tmp_path / "one.md").write_bytes((DOCUMENTS / f"{first}.md").read_bytes())
    (tmp_path / "two.md").write_bytes((DOCUMENTS / f"{second}.md").read_bytes())
    (tmp_path / "actaira.json").write_text(
        json.dumps({"evidence": {obligation_id: ["one.md", "two.md"]}}), encoding="utf-8"
    )
    result = judged.judge_target(obligation_id, engine.load_target(tmp_path), PROVIDER)
    assert result.evidence["search"]["source"] == "declaration"
    assert result.inspected == ("one.md", "two.md")


def test_a_declaration_that_does_not_parse_is_recorded_not_ignored(tmp_path):
    """A declaration the parser cannot read must be visible, not silently dropped.

    An operator who wrote a declaration and had it ignored believes they
    declared something they did not, which is the worst of the three possible
    outcomes: worse than a hard error, and much worse than the declaration
    being honoured. The line below is not a key and not a list item, so it is
    outside the documented subset and `_mini_yaml` raises.

    This test used to assert the opposite of what it meant. It fed the parser
    a perfectly ordinary nested list and asserted a parse error, because the
    first `_mini_yaml` could not parse a block sequence at all: it opened a
    mapping for `AIA-4:` and then raised on the `- ` beneath it. The test
    passed, and it was pinning a bug. Fixing the parser turned it red, which
    is the only reason the confusion surfaced.
    """
    (tmp_path / "actaira.yaml").write_text(
        "evidence:\n  this line is not a key\n", encoding="utf-8"
    )
    result = judged.judge_target("AIA-4", engine.load_target(tmp_path), PROVIDER)
    assert "declaration_parse_error" in result.evidence["search"]


def test_a_declaration_may_list_several_documents_for_one_obligation(tmp_path):
    """The block sequence the previous test used to reject. Regression for D-44."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "literacy.md").write_text("training programme", encoding="utf-8")
    (tmp_path / "docs" / "extra.md").write_text("annexe", encoding="utf-8")
    (tmp_path / "actaira.yaml").write_text(
        "evidence:\n  AIA-4:\n    - docs/literacy.md\n    - docs/extra.md\n", encoding="utf-8"
    )
    target = engine.load_target(tmp_path)
    assert target.declarations["evidence"]["AIA-4"] == ["docs/literacy.md", "docs/extra.md"]
    result = judged.judge_target("AIA-4", target, PROVIDER)
    assert result.evidence["search"]["source"] == "declaration"
    assert "declaration_parse_error" not in result.evidence["search"]


def test_a_declared_path_that_is_not_there_is_named_rather_than_dropped(tmp_path):
    (tmp_path / "actaira.yaml").write_text(
        "evidence:\n  AIA-4: policies/nowhere.md\n", encoding="utf-8"
    )
    result = judged.judge_target("AIA-4", engine.load_target(tmp_path), PROVIDER)
    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.evidence["search"]["declared_paths_missing"] == ["policies/nowhere.md"]


def test_a_declared_path_that_leaves_the_target_is_refused(tmp_path):
    """A declaration file is written by whoever wrote the target directory,
    so `../../../etc/passwd` is a thing that can be in one, and a control
    that read it would put the contents in a report."""
    outside = tmp_path.parent / "outside-the-target.md"
    outside.write_text("secrets about copyright policy and rights reservations\n", encoding="utf-8")
    root = tmp_path / "target"
    root.mkdir()
    (root / "actaira.yaml").write_text(
        f"evidence:\n  AIA-53-1c: ../{outside.name}\n", encoding="utf-8"
    )
    result = judged.judge_target("AIA-53-1c", engine.load_target(root), PROVIDER)
    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.inspected == ()
    assert json.dumps(result.to_dict()).count("secrets about") == 0


def test_a_file_too_large_to_judge_is_declined_and_not_truncated(tmp_path):
    """The part that answers the obligation may be exactly the part that
    would be cut, and nothing in a truncated result would show it."""
    padded = "x " * judged.MAX_DOCUMENT_BYTES
    (tmp_path / FILENAME["AIA-53-1c"]).write_text(padded, encoding="utf-8")
    result = judged.judge_target("AIA-53-1c", engine.load_target(tmp_path), PROVIDER)

    assert result.outcome is Outcome.INCONCLUSIVE
    row = result.evidence["documents"][0]
    assert row["reason"] == "document_larger_than_this_control_will_judge"
    assert row["bytes"] > judged.MAX_DOCUMENT_BYTES


def test_a_file_that_is_not_valid_utf8_does_not_take_the_control_down(tmp_path):
    (tmp_path / FILENAME["AIA-4"]).write_bytes(b"\xff\xfe measures for AI literacy among staff\n")
    result = judged.judge_target("AIA-4", engine.load_target(tmp_path), PROVIDER)
    assert result.outcome in (Outcome.INCONCLUSIVE, Outcome.NOT_SATISFIED)
    assert result.inspected == (FILENAME["AIA-4"],)


def test_a_pdf_is_left_alone_rather_than_half_read(tmp_path):
    (tmp_path / "copyright-policy.pdf").write_bytes(b"%PDF-1.7\n... a real policy, in a format this cannot read")
    result = judged.judge_target("AIA-53-1c", engine.load_target(tmp_path), PROVIDER)
    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.evidence["reason"] == "no_document_supplied_for_this_obligation"


# ---------------------------------------------------------------------------
# Through the engine, and no scores
# ---------------------------------------------------------------------------

def test_the_control_runs_through_the_engine(tmp_path):
    obligation_id, document_id = a_case("addressed")
    target = target_with(tmp_path, obligation_id, document_id)
    run = engine.run(target, control_ids=(f"ACT-C-JUDGE-{obligation_id}",))

    assert run.counts()["satisfied"] == 1
    assert run.to_dict()["results"][0]["method"] == "judged"
    assert "counts_not_a_score" in run.to_dict()


FORBIDDEN = ("score", "percent", "pct", "confidence", "rating", "grade", "probability")
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


@pytest.mark.parametrize("verdict", ["addressed", "not_addressed", "abstain"])
def test_no_judged_control_result_contains_a_score(tmp_path, verdict):
    obligation_id, document_id = a_case(verdict)
    result = judged.judge_target(obligation_id, target_with(tmp_path, obligation_id, document_id), PROVIDER)
    for path, value in walk(result.to_dict()):
        leaf = path.rsplit(".", 1)[-1].split("[")[0].lower()
        assert not any(word in leaf for word in FORBIDDEN), path
        if isinstance(value, str):
            assert "%" not in value, path
        if isinstance(value, float):
            assert leaf in ALLOWED_FLOAT_KEYS, f"{path} = {value}"


def test_the_result_is_json_serialisable_as_it_stands(tmp_path):
    """It ends up in a signed package. A value that only survives `repr` would
    be discovered at attestation time."""
    obligation_id, document_id = a_case("addressed")
    result = judged.judge_target(obligation_id, target_with(tmp_path, obligation_id, document_id), PROVIDER)
    assert json.loads(json.dumps(result.to_dict(), sort_keys=True))["control_id"].startswith("ACT-C-JUDGE-")
