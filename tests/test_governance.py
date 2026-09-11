"""The EU AI Act layer: what it maps, and what it refuses to say.

This module's thesis is negative. It exists because compliance tooling
reliably produces a number nothing in the artifact can support, so the tests
here are arranged around the four ways that number could creep back in:

  * a key in the output that a reader could take for a grade;
  * an obligation that claims coverage without saying what it leaves out;
  * a date that moves because the tool asked the machine what day it is;
  * an assessment that ends up attached to files it was not computed from.

Every capability is paired with its negative control, including the
detectors this file defines: a guard that cannot catch a planted violation
is a guard that passes for the wrong reason.
"""
from __future__ import annotations

import ast
import inspect as inspect_mod
import json
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import replace
from datetime import date
from http import HTTPStatus
from pathlib import Path

import pytest

from actaira.attest import chain, package
from actaira.attest.verify import verify_package
from actaira.governance import (
    ALL_OBLIGATIONS,
    Coverage,
    Role,
    Status,
    assess,
    by_id,
    clock,
    gaps,
    localized,
    render,
    unread_artifacts,
)
from actaira.governance.assess import _EVIDENCE_FOR as EVIDENCE_FOR
from actaira.governance.assess import DISCLAIMER
from actaira.governance.catalog import CELEX, OMNIBUS
from actaira.governance.clock import ClockRow
from actaira.governance.pack import DOSSIER_KIND, build_dossier, write_evidence_package
from actaira.i18n.catalog import SUPPORTED as SUPPORTED_LANGS
from actaira.i18n.catalog import load as load_catalog
from actaira.inspect import inspect_artifact
from actaira.model import ArtifactReport, Verdict
from conftest import SRC_DIR, corpus_build

GOVERNANCE_DIR = SRC_DIR / "actaira" / "governance"

# Article 113 as rewritten by Regulation (EU) 2026/1744, restated here rather
# than read out of the catalogue: a table asserted against itself proves
# nothing. Every date below traces to one of:
#   Art. 113(a): Chapters I and II from 2 February 2025, except the Art. 5(1)
#     points (ba) and (bb) prohibitions, which run from 2 December 2026.
#   Art. 113(b): Chapter V from 2 August 2025.
#   Art. 113(c): Chapter III Sections 1 to 3 from 2 December 2027 for Annex III
#     systems and 2 August 2028 for Annex I ones. The catalogue carries the
#     earlier date.
#   The general date, 2 August 2026, for what none of those move: Chapter IV,
#     Chapter III Section 5 and Chapter IX.
#   27 July 2026 for Art. 4a, inserted into an already-applicable Chapter I,
#     so it binds from the amending Regulation's entry into force.
APPLICATION_DATES = {
    "Art. 4": date(2025, 2, 2),
    "Art. 4a": date(2026, 7, 27),
    "Art. 5": date(2025, 2, 2),
    "Art. 5(1)(ba)-(bb)": date(2026, 12, 2),
    "Art. 52": date(2025, 8, 2),
    "Art. 53(1)(a)": date(2025, 8, 2),
    "Art. 53(1)(b)": date(2025, 8, 2),
    "Art. 53(1)(c)": date(2025, 8, 2),
    "Art. 53(1)(d)": date(2025, 8, 2),
    "Art. 54": date(2025, 8, 2),
    "Art. 55": date(2025, 8, 2),
    "Art. 50(1)": date(2026, 8, 2),
    "Art. 50(2)": date(2026, 8, 2),
    "Art. 50(3)": date(2026, 8, 2),
    "Art. 50(4)": date(2026, 8, 2),
    "Art. 49": date(2026, 8, 2),
    "Art. 73": date(2026, 8, 2),
    "Art. 11 + Annex IV": date(2027, 12, 2),
    "Art. 12": date(2027, 12, 2),
    "Art. 15": date(2027, 12, 2),
    "Art. 26": date(2027, 12, 2),
}

CHAPTER_I = ("AIA-4", "AIA-5")
BIAS_DATA = ("AIA-4a",)
NEW_PROHIBITIONS = ("AIA-5-1ba",)
CHAPTER_V = ("AIA-52", "AIA-53-1a", "AIA-53-1b", "AIA-53-1c", "AIA-53-1d",
             "AIA-54", "AIA-55")
# Everything in Chapter V except Art. 55, which binds the narrower
# systemic-risk role. A plain GPAI provider gets exactly this set.
CHAPTER_V_NON_SYSTEMIC = tuple(o for o in CHAPTER_V if o != "AIA-55")
CHAPTER_IV = ("AIA-50-1", "AIA-50-2", "AIA-50-3", "AIA-50-4")
# Not deferred by Art. 113(c), so they start on the general date even though
# their subject, a high-risk system, does not exist until 2 December 2027.
AUGUST_2026 = ("AIA-49", "AIA-73")
HIGH_RISK = ("AIA-11", "AIA-12", "AIA-15", "AIA-26")

# What applies on each date, written out rather than derived, so a changed
# date in the catalogue has to be changed here too and gets a second reader.
APPLICABLE_ON = {
    date(2025, 2, 1): (),
    date(2025, 2, 2): CHAPTER_I,
    date(2025, 8, 2): CHAPTER_I + CHAPTER_V,
    date(2026, 7, 26): CHAPTER_I + CHAPTER_V,
    date(2026, 7, 27): CHAPTER_I + CHAPTER_V + BIAS_DATA,
    date(2026, 8, 1): CHAPTER_I + CHAPTER_V + BIAS_DATA,
    date(2026, 8, 2): CHAPTER_I + CHAPTER_V + BIAS_DATA + CHAPTER_IV + AUGUST_2026,
    date(2026, 12, 1): CHAPTER_I + CHAPTER_V + BIAS_DATA + CHAPTER_IV + AUGUST_2026,
    date(2026, 12, 2): (CHAPTER_I + CHAPTER_V + BIAS_DATA + CHAPTER_IV + AUGUST_2026
                        + NEW_PROHIBITIONS),
    date(2027, 12, 2): (CHAPTER_I + CHAPTER_V + BIAS_DATA + CHAPTER_IV + AUGUST_2026
                        + NEW_PROHIBITIONS + HIGH_RISK),
}

# Regulation (EU) 2026/1744 of 8 July 2026, the Digital Omnibus on AI:
# published in the Official Journal on 24 July 2026, in force since 27 July
# 2026. Stated here so the tests below assert against a date a reader can
# check rather than against whatever the catalogue happens to say.
OMNIBUS_IN_FORCE = date(2026, 7, 27)

TODAY = date(2026, 9, 10)          # any fixed date; never the machine's


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

def _safetensors(name: str, width: int) -> tuple[str, bytes]:
    """A well-formed safetensors artifact whose bytes depend on `width`."""
    elements = width * width
    payload = b"\x00" * (elements * 4)
    return name, corpus_build.build_safetensors(
        {"w": {"dtype": "F32", "shape": [width, width], "data_offsets": [0, len(payload)]}},
        payload,
    )


@pytest.fixture
def readable_reports(write_artifact) -> list[ArtifactReport]:
    """Two artifacts the inspector reads all the way through."""
    reports = [
        inspect_artifact(write_artifact(*_safetensors("alpha.safetensors", 4))),
        inspect_artifact(write_artifact(*_safetensors("beta.safetensors", 6))),
    ]
    assert all(report.verdict is Verdict.PASS for report in reports)
    assert all(report.metadata.get("fully_read") for report in reports)
    return reports


@pytest.fixture
def other_reports(write_artifact) -> list[ArtifactReport]:
    """A different pair, for the tests about rebinding a dossier."""
    reports = [
        inspect_artifact(write_artifact(*_safetensors("gamma.safetensors", 8))),
        inspect_artifact(write_artifact(*_safetensors("delta.safetensors", 10))),
    ]
    assert all(report.verdict is Verdict.PASS for report in reports)
    return reports


@pytest.fixture
def unread_report(write_artifact) -> ArtifactReport:
    """An artifact the inspector could not read to the end."""
    truncated = corpus_build.craft_reduce("posix", "system", ("id",), 2)[:12]
    report = inspect_artifact(write_artifact("cut.pkl", truncated))
    assert report.verdict is Verdict.INCONCLUSIVE
    assert not report.metadata.get("fully_read", False)
    return report


def write_bytes(directory: Path, name: str, blob: bytes) -> Path:
    target = directory / name
    target.write_bytes(blob)
    return target


def package_entries(path: Path) -> list[dict]:
    with zipfile.ZipFile(path) as archive:
        return [
            json.loads(line)
            for line in archive.read(package.ENTRIES_NAME).splitlines()
            if line.strip()
        ]


# ---------------------------------------------------------------------------
# 1. Nothing in the output can be read as a grade
#
# The guardian of the module's thesis. If these fail, the layer has become
# the thing it was written in reaction to.
# ---------------------------------------------------------------------------

# Key vocabulary. A key is enough on its own: `readiness_index: 87` is a grade
# whatever the integer under it happens to be, and the earlier list missed it
# because it only knew the words a grade is usually *called*.
SCORE_WORDS = (
    "score", "percent", "pct", "compliant", "compliance", "rating", "grade",
    "ranking", "rank", "index", "readiness", "maturity",
    "puntuacion", "puntuación", "nota", "calificacion", "calificación",
)

# The one key allowed to contain a forbidden word, because the word is a
# denial: `counts_not_a_score` is named so a reader who sees only the key
# already knows what it is not.
DENIAL_KEY = "counts_not_a_score"

# Value vocabulary, which is the half that was missing entirely.
#
# The guard walked keys and nothing else, so the whole of the prose surface
# was outside it: putting "Actaira rates this obligation 87% compliant (grade
# B, overall score 4.2/5)" into `governance.AIA-4.summary` in `i18n/en.json`
# left all 172 governance tests green while every rendering of that obligation
# - the CLI, the JSON, the web panel - printed a grade. The keys were clean
# because the score was in a string.
SCORE_TEXT_PATTERNS = {
    "a percentage": re.compile(r"\d+(?:[.,]\d+)?\s*%"),
    "a score": re.compile(r"\b(?:scor(?:e|es|ed|ing)|puntuaci[oó]n|puntuaciones)\b", re.I),
    "a grade": re.compile(r"\b(?:grade|grades|graded|calificaci[oó]n|calificaciones)\b", re.I),
    "a rating": re.compile(r"\b(?:rating|ratings|rated|rates|valoraci[oó]n|valoraciones)\b", re.I),
    "a compliance verdict": re.compile(r"\b(?:compliant|cumplidor|cumplidora)\b", re.I),
    # The Spanish idiom puts the number first ("8 sobre 10"), and the bare
    # preposition means "about": requiring the numerator is what keeps
    # "evidencia sobre 1 componente" from reading as a grade.
    "an x-out-of-y": re.compile(r"\bout of \d+\b|\b\d+(?:[.,]\d+)?\s+sobre\s+\d+\b", re.I),
}

# `4.2/5` is a score; `Regulation (EU) 2024/1689` is a citation, and the
# catalogue is full of those. A pair is only read as a score when the second
# number is small enough to be a maximum and the first does not exceed it,
# which no CELEX number or Official Journal reference satisfies.
NUMERIC_RATIO = re.compile(r"(?<![\d/.])(\d{1,4}(?:\.\d+)?)\s*/\s*(\d{1,4}(?:\.\d+)?)(?![\d/])")
MAX_PLAUSIBLE_DENOMINATOR = 100

# Words the catalogue is allowed to use *about* scoring, because saying "there
# is no score here" requires the word. The window is short on purpose: a
# denial three sentences away is not a denial of this sentence.
DENIALS = ("no", "not", "never", "without", "neither", "nor", "cannot",
           "sin", "ni", "nunca", "ningun", "ningún", "ninguna", "tampoco")
DENIAL_WINDOW = 40

# Terms of art from the Regulation itself, which the catalogue has to be able
# to quote verbatim. "Social scoring" is a practice Article 5 prohibits, not
# something this tool computes, and AIA-5 would be unwritable without it.
TERMS_OF_ART = ("social scoring", "puntuación social", "puntuacion social")


def _blank_terms_of_art(text: str) -> str:
    """Blank out quoted terms of art, keeping every offset where it was."""
    lowered = text.lower()
    for term in TERMS_OF_ART:
        start = 0
        while (found := lowered.find(term, start)) != -1:
            text = text[:found] + " " * len(term) + text[found + len(term):]
            start = found + len(term)
    return text


def _is_denied(text: str, start: int) -> bool:
    window = text[max(0, start - DENIAL_WINDOW):start].lower()
    return any(re.search(rf"\b{re.escape(word)}\b", window) for word in DENIALS)


def _score_ratios(text: str):
    for match in NUMERIC_RATIO.finditer(text):
        numerator, denominator = float(match.group(1)), float(match.group(2))
        if denominator <= MAX_PLAUSIBLE_DENOMINATOR and numerator <= denominator:
            yield match


def score_like(payload: object) -> list[str]:
    """Every place in `payload` a reader could take for a grade.

    Keys and string values alike, descending through dicts, lists *and*
    tuples: `Obligation` carries several of its fields as tuples, and a walker
    that only knew about lists stepped over every one of them.
    """
    found: list[str] = []

    def walk(node: object, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                here = f"{path}.{key}"
                lowered = str(key).lower()
                if key != DENIAL_KEY and any(word in lowered for word in SCORE_WORDS):
                    found.append(f"{here} (key)")
                walk(value, here)
        elif isinstance(node, (list, tuple, set, frozenset)):
            for index, item in enumerate(node):
                walk(item, f"{path}[{index}]")
        elif isinstance(node, str):
            text = _blank_terms_of_art(node)
            matches = [(name, m) for name, rx in SCORE_TEXT_PATTERNS.items() for m in rx.finditer(text)]
            matches += [("a ratio", m) for m in _score_ratios(text)]
            for name, match in matches:
                if _is_denied(text, match.start()):
                    continue
                found.append(f"{path} ({name}: {match.group(0)!r})")

    walk(payload, "")
    return sorted(found)


def score_like_keys(payload: object) -> list[str]:
    """The key half on its own, for the tests that assert on exact paths."""
    return [entry[: -len(" (key)")] for entry in score_like(payload) if entry.endswith(" (key)")]


def floats_in(payload: object) -> list[str]:
    """Every non-integer number in `payload`, with its path."""
    found: list[str] = []

    def walk(node: object, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, f"{path}[{index}]")
        elif isinstance(node, float):
            found.append(f"{path} = {node}")

    walk(payload, "")
    return found


def test_no_key_anywhere_in_an_assessment_reads_as_a_score(readable_reports):
    """The whole payload, not just the top level: a percentage hidden three
    levels down inside an obligation row is still a percentage."""
    payload = assess(readable_reports, on=TODAY, role=Role.PROVIDER_GPAI, has_bom=True).to_dict()

    assert score_like_keys(payload) == []


def test_the_score_detector_catches_a_planted_grade():
    """Negative control for the test above: it has to be able to fail."""
    planted = {
        "obligations": [{"id": "AIA-4", "compliance_score": 0.8}],
        "summary": {"pct_complete": 80, "rating": "B"},
        DENIAL_KEY: {"applicable": 4},
    }

    found = score_like_keys(planted)

    assert sorted(found) == [
        ".obligations[0].compliance_score",
        ".summary.pct_complete",
        ".summary.rating",
    ]
    assert not any(DENIAL_KEY in entry for entry in found), "the denial key must stay exempt"


# ---------------------------------------------------------------------------
# The same guard, over every surface the tool actually prints
#
# The assessment dictionary was the only thing ever checked, and it is the one
# surface a reader never sees directly. `governance clock --json`, the text
# render, the dossier and the message catalogues themselves were all outside
# the guard, which is where a grade would live if anyone put one there.
# ---------------------------------------------------------------------------

PLANTED_SCORE = "Actaira rates this obligation 87% compliant (grade B, overall score 4.2/5)."


def every_output_surface(reports: list) -> dict[str, object]:
    """Everything this package can put in front of a reader, by name."""
    surfaces: dict[str, object] = {}
    for lang in SUPPORTED_LANGS:
        catalogue = load_catalog(lang)
        for section in ("ui", "rules", "rule_help", "governance"):
            surfaces[f"catalogue.{lang}.{section}"] = catalogue[section]
        rows = clock(TODAY)
        surfaces[f"clock.render.{lang}"] = render(rows, TODAY, lang)
        surfaces[f"clock.rows.{lang}"] = [localized(row.obligation, lang) for row in rows]
    # exactly what `governance clock --json` writes
    surfaces["clock.json"] = {
        "on": TODAY.isoformat(),
        "obligations": [row.to_dict() for row in clock(TODAY)],
    }
    for role in Role:
        surfaces[f"assess.{role.value}"] = assess(
            reports, on=TODAY, role=role, has_bom=True
        ).to_dict()
    surfaces["dossier"] = build_dossier(reports, on=TODAY, role=Role.PROVIDER_GPAI)
    return surfaces


@pytest.mark.parametrize("surface", sorted(every_output_surface([])))
def test_no_output_surface_carries_anything_that_reads_as_a_grade(surface, readable_reports):
    payload = every_output_surface(readable_reports)[surface]

    assert score_like(payload) == []


def test_the_cli_text_render_of_the_clock_carries_no_grade(capsys):
    from actaira import cli

    for lang in SUPPORTED_LANGS:
        assert cli.main(["--lang", lang, "governance", "clock", "--on", TODAY.isoformat()]) == 0
        assert score_like(capsys.readouterr().out) == []


def test_the_cli_text_render_of_an_assessment_carries_no_grade(capsys, tmp_path, readable_reports):
    from actaira import cli

    artifact = tmp_path / "clean.safetensors"
    artifact.write_bytes(
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}}, b"\x00" * 64
        )
    )
    for lang in SUPPORTED_LANGS:
        cli.main(["--lang", lang, "governance", "assess", str(artifact),
                  "--on", TODAY.isoformat()])
        assert score_like(capsys.readouterr().out) == []


@pytest.fixture
def planted_prose():
    """Put a grade in the catalogue prose, where the old guard could not see it.

    The catalogue is `lru_cache`d, so the dictionary handed out is the one
    every renderer reads; putting the sentence in it and taking it out again
    is the whole fixture.
    """
    catalogue = load_catalog("en")["governance"]["AIA-4"]
    original = catalogue["summary"]
    catalogue["summary"] = PLANTED_SCORE
    try:
        yield PLANTED_SCORE
    finally:
        catalogue["summary"] = original


def test_the_guard_catches_a_grade_planted_in_the_prose(planted_prose):
    """The negative control the guard never had: it has to be able to fail.

    Six different readings of the same sentence, because a guard that catches
    a percentage and nothing else is one rewording away from useless.
    """
    found = score_like(load_catalog("en")["governance"])

    assert found, "the guard cannot fail, so its green is worth nothing"
    reasons = {entry.split("(", 1)[1].split(":")[0].strip() for entry in found}
    assert reasons == {"a percentage", "a score", "a grade", "a rating",
                       "a compliance verdict", "a ratio"}
    assert all(entry.startswith(".AIA-4.summary") for entry in found)


def test_the_planted_grade_reaches_the_clock_and_the_guard_catches_it_there(planted_prose):
    """And it has to be caught on the surfaces, not only at the source: this
    is the path the sentence actually takes to a reader."""
    rows = clock(TODAY)

    assert score_like(render(rows, TODAY, "en")) == [], "AIA-4's title is what the clock prints"
    assert score_like([localized(row.obligation, "en") for row in rows]), (
        "the localized rows carry the summary, and the guard has to see it there"
    )


def test_the_guard_catches_a_grade_the_score_words_do_not_name(planted_prose):
    """A neutral key over a bare integer, and a tuple in the way: two shapes
    the old guard walked straight past."""
    assert score_like({"readiness_index": 87}) == [".readiness_index (key)"]
    assert score_like({"rows": ({"maturity": 3},)}) == [".rows[0].maturity (key)"]
    assert score_like({"summary": "we rate this 9 out of 10"}), "x out of y is a grade"
    assert score_like({"summary": "Regulation (EU) 2024/1689"}) == [], (
        "a CELEX citation is not a ratio; the guard would be unusable if it were"
    )


def test_the_counts_are_whole_numbers_and_never_a_fraction(readable_reports):
    """A ratio is how a count becomes a score. Every value here is a count of
    obligations, so a float in this block would already be the wrong shape."""
    payload = assess(readable_reports, on=TODAY, role=Role.PROVIDER_GPAI, has_bom=True).to_dict()
    counts = payload[DENIAL_KEY]

    assert set(counts) == {"applicable", "with_evidence", "outside_this_tool"}
    for name, value in counts.items():
        assert isinstance(value, int) and not isinstance(value, bool), f"{name} is {type(value)}"
        assert value >= 0, name
    assert floats_in(payload) == [], "no number in an assessment is fractional"


def test_the_fraction_detector_catches_a_planted_ratio():
    """Negative control: `floats_in` must find one where there is one."""
    assert floats_in({DENIAL_KEY: {"applicable": 4, "with_evidence": 0.25}}) == [
        f".{DENIAL_KEY}.with_evidence = 0.25"
    ]
    assert floats_in({DENIAL_KEY: {"applicable": 4, "with_evidence": 1}}) == []


def test_the_counts_are_the_counts_they_say_they_are(readable_reports):
    """Recomputed from the obligation rows rather than from the same sum, so
    a count that drifts from what the rows show is caught."""
    payload = assess(readable_reports, on=TODAY, role=Role.PROVIDER_GPAI, has_bom=True).to_dict()
    rows = payload["obligations"]
    counts = payload[DENIAL_KEY]

    assert counts["applicable"] == len([row for row in rows if row["applicable"]])
    assert counts["with_evidence"] == len(
        [row for row in rows if row["applicable"] and row["evidence"]]
    )
    assert counts["outside_this_tool"] == len(
        [row for row in rows if row["applicable"] and row["coverage"] == "not_covered"]
    )
    assert counts["applicable"] > counts["with_evidence"], (
        "more obligations apply than this tool can speak to; if that ever inverts, "
        "the catalogue has stopped listing what Actaira cannot do"
    )


def test_every_assessment_carries_the_disclaimer(readable_reports):
    payload = assess(readable_reports, on=TODAY).to_dict()

    assert payload["disclaimer"] == DISCLAIMER
    assert "not a compliance opinion" in payload["disclaimer"]
    assert "no score" in payload["disclaimer"]


# ---------------------------------------------------------------------------
# 2. Coverage, and the two lists that have to travel together
# ---------------------------------------------------------------------------

UNCOVERED = tuple(o for o in ALL_OBLIGATIONS if o.coverage is Coverage.NOT_COVERED)
COVERED = tuple(o for o in ALL_OBLIGATIONS if o.coverage is not Coverage.NOT_COVERED)


@pytest.mark.parametrize("obligation", UNCOVERED, ids=lambda o: o.id)
def test_an_uncovered_obligation_says_so_and_claims_nothing(obligation):
    """NOT_COVERED means the tool contributes nothing, and the entry has to
    say what it is not contributing. An empty pair of lists would read on
    screen as an obligation nobody has to do anything about."""
    assert obligation.actaira_provides == ()
    assert obligation.actaira_does_not_provide, obligation.id


@pytest.mark.parametrize("obligation", COVERED, ids=lambda o: o.id)
def test_a_covered_obligation_states_both_halves(obligation):
    """The mirror of the test above, with one deliberate asymmetry.

    SUPPORTS and PARTIAL must list what Actaira provides, or the coverage
    verdict is unsupported. They must *also* list what it does not, which is
    not the mirror image: an obligation marked SUPPORTS with an empty
    `actaira_does_not_provide` is the silent-completeness claim this
    catalogue exists to prevent, so the doctrine is not symmetric here and
    the test is not either.
    """
    assert obligation.actaira_provides, obligation.id
    assert obligation.actaira_does_not_provide, (
        f"{obligation.id} claims {obligation.coverage.value} without stating its limits"
    )


def test_the_catalogue_stays_mostly_honest_about_what_it_cannot_do():
    """A drift guard. Coverage verdicts only ever get upgraded by hand, and
    the shape of the catalogue is the claim: uncovered is the largest group.

    The SUPPORTS assertion changed from `<= 1` to `== 0`. AIA-53-1b held the
    single SUPPORTS entry, on the reasoning that a signed BOM answers the
    integrator's question. It does, but Annex XII does not ask for a hash, a
    bill of materials or a signature anywhere in its eleven points, so the
    tool supplies one of them and none of what the Annex actually lists. That
    is PARTIAL. The tier stays in the enum because the bar it sets is the
    right bar; nothing is promoted into it to keep it occupied, and this
    assertion is what stops that from happening quietly.
    """
    buckets = {coverage: 0 for coverage in Coverage}
    for obligation in ALL_OBLIGATIONS:
        buckets[obligation.coverage] += 1

    assert UNCOVERED and COVERED, "one of the two parametrised groups above is empty"
    assert buckets[Coverage.NOT_COVERED] > buckets[Coverage.PARTIAL]
    assert buckets[Coverage.SUPPORTS] == 0, (
        "nothing in this catalogue produces a substantial part of what an "
        "obligation asks for; promoting an entry to say otherwise is the claim "
        "this project exists to refuse"
    )
    assert buckets[Coverage.NOT_COVERED] >= len(ALL_OBLIGATIONS) / 2


@pytest.mark.parametrize("obligation", ALL_OBLIGATIONS, ids=lambda o: o.id)
def test_every_obligation_is_cited_and_dated_from_article_113(obligation):
    """A citation nobody can follow is decoration, and a date that does not
    match the provision it claims to come from is worse than no date."""
    assert obligation.citation.strip(), obligation.id
    assert CELEX in obligation.citation
    assert obligation.article.split(" +")[0] in obligation.citation

    assert obligation.applies_from == APPLICATION_DATES[obligation.article], obligation.id
    if obligation.status is Status.PROVISIONAL:
        assert "Digital Omnibus" in obligation.citation
        assert obligation.applies_from > date(2026, 8, 2)


def test_every_obligation_has_prose_and_expected_evidence():
    for obligation in ALL_OBLIGATIONS:
        assert obligation.title.strip(), obligation.id
        assert len(obligation.summary) > 40, obligation.id
        assert obligation.evidence_expected, obligation.id


def test_a_grace_period_never_stands_without_a_scope():
    """A transitional period that does not say who it covers is read as
    covering everybody, which is how a deadline gets missed."""
    for obligation in ALL_OBLIGATIONS:
        if obligation.grace_until is None:
            assert obligation.grace_scope is None, obligation.id
            continue
        assert obligation.grace_scope, obligation.id
        assert obligation.grace_until > obligation.applies_from, obligation.id


def test_article_4_carries_the_wording_it_has_had_since_july_2026():
    """Art. 4 was replaced in full by Regulation (EU) 2026/1744.

    The catalogue described the original: providers and deployers "take
    measures to ensure a sufficient level of AI literacy". Since 27 July 2026
    the article says they take measures to *support the development of* AI
    literacy, and adds expressly that no particular level has to be
    guaranteed. That is the difference between an obligation of result and one
    of means, and it changes what evidence discharges it, so the summary is
    asserted here against the current wording rather than left to drift.

    The application date does not move: Art. 4 has bound almost every
    organisation using AI since 2 February 2025 under Art. 113(a). Only the
    text changed.
    """
    obligation = by_id("AIA-4")
    summary = obligation.summary.lower()

    assert obligation.applies_from == date(2025, 2, 2)
    assert "support the development" in summary
    assert "ensure a sufficient level" not in summary, "that is the repealed wording"
    assert "guarantee" in summary, "the article says no particular level is required"
    assert "2026/1744" in obligation.note
    assert "27 july 2026" in obligation.note.lower()

    spanish = localized(obligation, "es")["summary"].lower()
    assert "impulsar el desarrollo" in spanish
    assert "garantizar un nivel suficiente" not in spanish


def test_annex_iv_point_5_is_the_risk_management_system():
    """Annex IV, point 5 is "a detailed description of the risk management
    system in accordance with Article 9". The catalogue cited it as validation
    and testing, which is point 2(g).

    The error was self-contradicting as well as wrong: the same entry listed
    "risk management documentation" among the things Actaira does not provide,
    so it named point 5 as expected evidence and disclaimed its actual
    content two lines later.
    """
    obligation = by_id("AIA-11")
    expected = {line.split(":")[0].strip(): line for line in obligation.evidence_expected}

    point_5 = expected["Annex IV, point 5"]
    assert "risk management" in point_5
    assert "Article 9" in point_5
    assert "validation" not in point_5

    point_2g = expected["Annex IV, point 2(g)"]
    assert "validation and testing" in point_2g

    # And the disclaimer now names the same point it disclaims.
    assert any("point 5" in line for line in obligation.actaira_does_not_provide)


def test_article_12_is_not_claimed_by_a_ledger_of_artifact_inspections():
    """Art. 12 asks the high-risk *system* to be able to record its own events
    over its lifetime, for the purposes in Art. 12(2) and, for remote
    biometric identification, the elements in Art. 12(3).

    Actaira keeps an append-only signed ledger of its own inspections. That is
    traceability over an artifact, not a logging capability in a running
    system, and the entry claimed it as PARTIAL coverage. It is NOT_COVERED
    now, and the ledger reaches AIA-15, whose text does claim "a verifiable
    record of which artifact was deployed".
    """
    obligation = by_id("AIA-12")

    assert obligation.coverage is Coverage.NOT_COVERED
    assert obligation.actaira_provides == ()
    assert len(obligation.actaira_does_not_provide) >= 3
    assert "AIA-12" not in EVIDENCE_FOR, "no evidence kind may point at it"
    assert {"consistency_proof", "time_anchor"} <= set(EVIDENCE_FOR["AIA-15"])


def test_by_id_finds_every_obligation_and_invents_none():
    for obligation in ALL_OBLIGATIONS:
        assert by_id(obligation.id) is obligation
    assert by_id("AIA-999") is None


# ---------------------------------------------------------------------------
# 3. The clock
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("on", sorted(APPLICABLE_ON), ids=lambda d: d.isoformat())
def test_the_clock_says_exactly_what_applies_on_each_date(on):
    rows = clock(on)

    applicable = {row.obligation.id for row in rows if row.applicable}
    assert applicable == set(APPLICABLE_ON[on]), on.isoformat()
    assert len(rows) == len(ALL_OBLIGATIONS), "every obligation is listed, applicable or not"

    for row in rows:
        if row.applicable:
            assert row.days_until is None
            assert row.obligation.applies_from <= on
        else:
            assert row.days_until == (row.obligation.applies_from - on).days
            assert row.days_until > 0


def test_the_day_before_an_obligation_applies_it_does_not_apply():
    """The boundary, taken one obligation at a time: an off-by-one here moves
    a legal deadline by a day for everybody reading the output."""
    for obligation in ALL_OBLIGATIONS:
        day_before = date.fromordinal(obligation.applies_from.toordinal() - 1)
        before = {row.obligation.id for row in clock(day_before) if row.applicable}
        on_the_day = {row.obligation.id for row in clock(obligation.applies_from) if row.applicable}

        assert obligation.id not in before, obligation.id
        assert obligation.id in on_the_day, obligation.id


@pytest.mark.parametrize(
    ("on", "in_grace"),
    [
        (date(2026, 8, 2), True),
        (date(2026, 12, 1), True),
        (date(2026, 12, 2), False),
        (date(2027, 12, 2), False),
    ],
    ids=lambda value: str(value),
)
def test_the_article_50_2_grace_period_opens_and_closes_on_its_dates(on, in_grace):
    row = next(row for row in clock(on) if row.obligation.id == "AIA-50-2")

    assert row.applicable is True
    assert row.in_grace is in_grace
    assert row.to_dict()["in_grace_period"] is in_grace


def test_the_chapter_v_rows_carry_the_article_111_3_transitional():
    """Art. 111(3): a general-purpose AI model already on the market on
    2 August 2025 has until 2 August 2027 to comply with Chapter V.

    The catalogue used to carry no grace period on any Chapter V row, so it
    told the provider of a model published in 2024 that Art. 53 had bound it
    since 2 August 2025. It had two more years. The mechanism to say so was
    already here, used for Art. 50(2), and simply was not applied.
    """
    rows = {row.obligation.id: row for row in clock(date(2026, 8, 2))}

    for identifier in CHAPTER_V:
        row = rows[identifier]
        assert row.applicable is True, identifier
        assert row.obligation.grace_until == date(2027, 8, 2), identifier
        assert row.in_grace is True, identifier
        assert "2 August 2025" in (row.obligation.grace_scope or ""), identifier
        assert "Art. 111(3)" in row.obligation.citation, identifier

    # It closes on its date like any other.
    after = {row.obligation.id: row for row in clock(date(2027, 8, 2))}
    assert all(after[identifier].in_grace is False for identifier in CHAPTER_V)


def test_no_other_obligation_carries_a_grace_period():
    """Negative control for the grace flag: it is not simply always on.

    Two transitionals exist and they are the two the Regulation has:
    Art. 111(4) for the Art. 50(2) marking limb, and Art. 111(3) for
    general-purpose AI models already on the market. Nothing else.
    """
    in_grace = {row.obligation.id for row in clock(date(2026, 8, 2)) if row.in_grace}

    assert in_grace == {"AIA-50-2", *CHAPTER_V}
    assert {o.id for o in ALL_OBLIGATIONS if o.grace_until} == in_grace


def test_the_high_risk_deferral_is_published_law_and_nothing_is_provisional():
    """The Digital Omnibus deferral stopped being a rumour.

    This test replaces one that asserted the opposite. AIA-11, AIA-12 and
    AIA-15 were marked PROVISIONAL with the note "agreed but not yet published
    in the Official Journal", and the clock printed a banner telling the reader
    that until publication "the original date is what binds". Regulation (EU)
    2026/1744 of 8 July 2026 was published in the Official Journal on 24 July
    2026 and entered into force on 27 July 2026, so from that day the banner
    was asserting the opposite of the law and pointing the reader at a date,
    2 August 2026, that had been superseded.

    The three rows are IN_FORCE now, the dates they carry are the ones
    Art. 113(c) carries, and no row anywhere in the catalogue is provisional.
    """
    on = date(2026, 9, 10)
    rows = clock(on)
    text = render(rows, on)

    assert on > OMNIBUS_IN_FORCE, "this test only means anything after the OJ date"
    assert [o.id for o in ALL_OBLIGATIONS if o.status is Status.PROVISIONAL] == []
    assert all(row.to_dict()["status"] == "in_force" for row in rows)

    # The citation a reader follows has to carry the facts that make the
    # deferral checkable: the act, its date, and when it reached the OJ.
    assert "2026/1744" in OMNIBUS
    assert "24 July 2026" in OMNIBUS
    assert "27 July 2026" in OMNIBUS

    for identifier in HIGH_RISK:
        obligation = by_id(identifier)
        assert obligation.applies_from == date(2027, 12, 2), identifier
        assert "2026/1744" in obligation.citation, identifier
        assert "Art. 113(c)" in obligation.citation, identifier

    assert "PROVISIONAL" not in text
    assert "not yet published" not in text
    assert "the original date is what binds" not in text


def test_the_provisional_marker_still_fires_on_a_row_that_is_provisional():
    """Negative control for the test above, and the reason the status stays.

    Nothing being provisional today could mean the flag works and nothing is
    in that state, or that the flag stopped working. This builds a row that is
    provisional and checks the clock marks it and prints the banner, so the
    machinery is proven rather than assumed. The next amendment will spend
    months in exactly this state.
    """
    on = date(2026, 9, 10)
    real = by_id("AIA-11")
    pending = replace(
        real,
        id="AIA-9999",
        applies_from=date(2029, 1, 1),
        status=Status.PROVISIONAL,
    )
    rows = [*clock(on), ClockRow(pending, applicable=False, in_grace=False, days_until=843)]

    text = render(rows, on)
    line = next(entry for entry in text.splitlines() if entry.strip().startswith("AIA-9999"))

    assert pending.to_dict()["status"] == "provisional"
    assert "PROVISIONAL" in line
    assert "not yet published in the" in text
    assert "Official Journal" in text
    assert "the original date is what binds" in text

    # And the rows that are in force are not swept up by the same banner.
    in_force_line = next(
        entry for entry in text.splitlines() if entry.strip().startswith("AIA-11")
    )
    assert "PROVISIONAL" not in in_force_line


def test_the_horizon_filters_what_is_coming_without_hiding_what_applies():
    on = date(2026, 9, 10)
    near = clock(on, horizon_days=30)
    far = clock(on, horizon_days=1000)

    assert {row.obligation.id for row in near if row.applicable} == set(APPLICABLE_ON[date(2026, 12, 1)])
    assert [row for row in near if not row.applicable] == []
    # 1000 days from 2026-09-10 reaches mid-2029, so it covers both the
    # 2 December 2026 prohibitions and the 2 December 2027 high-risk set.
    assert {row.obligation.id for row in far if not row.applicable} == set(
        NEW_PROHIBITIONS + HIGH_RISK
    )


def test_the_new_article_5_prohibitions_are_the_next_thing_to_fall_due():
    """The one duty in this catalogue with a date between today and the end of
    2026, so a consultant reading the clock in autumn 2026 sees it coming.

    Art. 5(1), points (ba) and (bb), inserted by Regulation (EU) 2026/1744,
    prohibit generating non-consensual intimate imagery and child sexual abuse
    material. Art. 113(a) excepts them from the 2 February 2025 date of the
    rest of Chapter II and applies them from 2 December 2026.
    """
    on = date(2026, 9, 10)
    upcoming = [row for row in clock(on) if not row.applicable]
    soonest = min(upcoming, key=lambda row: row.obligation.applies_from)

    assert soonest.obligation.id == "AIA-5-1ba"
    assert soonest.obligation.applies_from == date(2026, 12, 2)
    assert soonest.obligation.role is Role.ANY, "it binds providers and deployers alike"
    assert soonest.obligation.coverage is Coverage.NOT_COVERED
    assert "2026/1744" in soonest.obligation.citation

    # And it is not folded into the general Art. 5 row, which keeps its own
    # 2 February 2025 date.
    assert by_id("AIA-5").applies_from == date(2025, 2, 2)


def test_the_clock_renders_in_spanish_without_moving_a_date():
    """`PROVISIONAL` was in the list of strings this asserted. It is gone
    because no row is provisional now; the marker itself is covered by
    `test_the_provisional_marker_still_fires_on_a_row_that_is_provisional`."""
    on = date(2026, 9, 10)
    rows = clock(on)

    english = render(rows, on, "en")
    spanish = render(rows, on, "es")

    assert spanish != english
    assert "Alfabetización en materia de IA" in spanish
    assert "AI literacy" not in spanish
    for line in (on.isoformat(), "AIA-50-2", "2027-12-02", "2026-12-02"):
        assert line in spanish, line


# ---------------------------------------------------------------------------
# 4. The date is an argument, never the machine's opinion
# ---------------------------------------------------------------------------

CLOCK_CALLS = ("today", "now", "utcnow", "fromtimestamp", "monotonic")


def wall_clock_reads(source: str, filename: str) -> list[str]:
    """Calls in `source` that would ask the machine what time it is."""
    tree = ast.parse(source, filename=filename)
    return [
        f"{filename}:{node.lineno}: .{node.func.attr}()"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in CLOCK_CALLS
    ]


@pytest.mark.parametrize(
    "path",
    sorted(p for p in GOVERNANCE_DIR.glob("*.py")),
    ids=lambda path: path.name,
)
def test_no_module_in_the_governance_package_reads_the_system_clock(path):
    """Every date this layer reasons about arrives as an argument. The CLI
    and the web layer are where `today` is chosen, once and visibly, so that
    the same inputs always produce the same evidence map."""
    assert wall_clock_reads(path.read_text("utf-8"), path.name) == []


def test_the_wall_clock_scan_catches_one():
    """Negative control for the scan above."""
    source = (
        "from datetime import date, datetime\n"
        "def f():\n"
        "    return date.today(), datetime.now()\n"
    )

    assert len(wall_clock_reads(source, "sample.py")) == 2


@pytest.mark.parametrize(
    ("function", "argument"),
    [(clock, "on"), (assess, "on"), (build_dossier, "on"), (render, "on")],
    ids=lambda value: getattr(value, "__name__", str(value)),
)
def test_the_date_has_no_default_so_a_caller_must_state_it(function, argument):
    parameter = inspect_mod.signature(function).parameters[argument]

    assert parameter.default is inspect_mod.Parameter.empty


def test_calling_the_clock_without_a_date_is_an_error_not_today():
    with pytest.raises(TypeError):
        clock()  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# 5. assess: who is bound, and what counts as evidence
# ---------------------------------------------------------------------------

def assessed_ids(assessment) -> set[str]:
    return {item.obligation.id for item in assessment.assessments}


def test_a_deployer_is_not_handed_the_gpai_provider_obligations(readable_reports):
    ids = assessed_ids(assess(readable_reports, on=TODAY, role=Role.DEPLOYER))

    assert ids & set(CHAPTER_V) == set()
    assert {"AIA-50-3", "AIA-50-4"} <= ids, "the deployer's own transparency duties"
    assert set(CHAPTER_I) <= ids, "Art. 4 and Art. 5 bind everybody"


def test_a_gpai_provider_is_not_handed_the_deployer_obligations(readable_reports):
    ids = assessed_ids(assess(readable_reports, on=TODAY, role=Role.PROVIDER_GPAI))

    assert "AIA-50-3" not in ids
    assert "AIA-50-4" not in ids
    assert set(CHAPTER_V_NON_SYSTEMIC) <= ids


def test_a_gpai_provider_is_not_handed_the_chapter_iv_provider_obligations(readable_reports):
    """This asserted the opposite until a hostile review of the catalogue.

    The old rule was "a GPAI provider is also a provider for the purposes of
    Chapter IV", justified by a GPAI provider that also places a system on the
    market. That premise is true of some providers and the inference is not:
    Art. 3(63) defines the provider of a general-purpose AI *model* and
    Art. 3(3) the provider of an AI *system*, and Chapter IV binds the second.
    Publishing weights is not placing a system on the market, so the rule
    handed Art. 50(1) and 50(2) to people who may owe neither. Someone who is
    both declares both roles.
    """
    ids = assessed_ids(assess(readable_reports, on=TODAY, role=Role.PROVIDER_GPAI))

    assert ids & set(CHAPTER_IV) == set()
    assert ids & set(AUGUST_2026) == set(), "Art. 49 and Art. 73 bind a system provider too"
    assert set(CHAPTER_V_NON_SYSTEMIC) <= ids, "the Chapter V duties are still theirs"
    assert set(CHAPTER_I) <= ids, "and so is everything that binds anybody"


def test_article_55_needs_the_systemic_risk_role_declared(readable_reports):
    """Art. 55 binds providers of models classified under Art. 51, which is a
    narrower group than providers of general-purpose AI models.

    The catalogue used to give it to every PROVIDER_GPAI, which told a
    provider of a small open-weights model that it owed adversarial testing,
    systemic risk mitigation and incident reporting to the AI Office. Nothing
    in a weight file says which side of the Art. 51(2) presumption a model
    falls on, so the tool cannot infer it and the user has to declare it.
    """
    plain = assessed_ids(assess(readable_reports, on=TODAY, role=Role.PROVIDER_GPAI))
    systemic = assessed_ids(
        assess(readable_reports, on=TODAY, role=Role.PROVIDER_GPAI_SYSTEMIC)
    )

    assert "AIA-55" not in plain, "nobody is handed Art. 55 by default"
    assert "AIA-55" in systemic
    # Art. 55 is additional to the rest of Chapter V, not a substitute: the
    # systemic-risk provider still owes Art. 52 to 54.
    assert set(CHAPTER_V) <= systemic
    assert systemic - plain == {"AIA-55"}
    assert by_id("AIA-55").role is Role.PROVIDER_GPAI_SYSTEMIC


def test_the_systemic_role_is_a_real_choice_the_interfaces_can_carry():
    """A role nobody can select is a role that silently never applies. The CLI
    and the web layer both derive their accepted values from this enum, so
    membership is what makes the declaration reachable."""
    assert Role.PROVIDER_GPAI_SYSTEMIC.value == "provider_gpai_systemic"
    assert Role("provider_gpai_systemic") is Role.PROVIDER_GPAI_SYSTEMIC
    assert Role.PROVIDER_GPAI_SYSTEMIC is not Role.PROVIDER_GPAI


def test_a_plain_provider_gets_neither_the_gpai_nor_the_deployer_set(readable_reports):
    ids = assessed_ids(assess(readable_reports, on=TODAY, role=Role.PROVIDER))

    assert ids & set(CHAPTER_V) == set()
    assert ids & {"AIA-50-3", "AIA-50-4"} == set()
    assert {"AIA-50-1", "AIA-50-2"} <= ids
    assert set(AUGUST_2026) <= ids, "registration and incident reporting bind the provider"


def test_role_any_is_given_every_obligation(readable_reports):
    ids = assessed_ids(assess(readable_reports, on=TODAY, role=Role.ANY))

    assert ids == {obligation.id for obligation in ALL_OBLIGATIONS}


def test_without_evidence_the_state_is_no_evidence_not_outside_this_tool():
    """The two states mean different things. `outside_this_tool` says Actaira
    can never help; `no_evidence_supplied` says nobody has supplied anything
    yet. Collapsing them would tell a user to stop looking."""
    # Role.ANY, because AIA-11 binds a provider of a high-risk system and a
    # GPAI model provider is no longer given that row.
    assessment = assess([], on=TODAY, role=Role.ANY, has_bom=True)
    states = {item.obligation.id: item.state for item in assessment.assessments}

    assert states["AIA-53-1a"] == "no_evidence_supplied"
    assert states["AIA-53-1b"] == "no_evidence_supplied"
    assert states["AIA-53-1c"] == "outside_this_tool"
    assert states["AIA-11"] == "not_yet_applicable"


def test_with_evidence_the_same_obligations_change_state(readable_reports):
    """Negative control for the test above: the states are not simply fixed.

    AIA-53-1b reads `evidence_partial` where it used to read
    `evidence_supports`: the coverage verdict dropped when the catalogue was
    corrected, and the state string follows the verdict rather than the other
    way round.
    """
    assessment = assess(readable_reports, on=TODAY, role=Role.PROVIDER_GPAI, has_bom=True)
    states = {item.obligation.id: item.state for item in assessment.assessments}

    assert states["AIA-53-1a"] == "evidence_partial"
    assert states["AIA-53-1b"] == "evidence_partial"
    assert states["AIA-53-1c"] == "outside_this_tool", "evidence cannot cover a copyright policy"
    assert "evidence_supports" not in set(states.values())


def test_an_artifact_that_was_not_read_produces_no_evidence(readable_reports, unread_report):
    """An inconclusive read must not quietly become a supporting document.
    It is named in `unread_artifacts` and it contributes nothing."""
    reports = [*readable_reports, unread_report]

    assessment = assess(reports, on=TODAY, role=Role.PROVIDER_GPAI, has_bom=True)
    subjects = {
        item.subject
        for row in assessment.assessments
        for item in row.evidence
        if item.kind == "artifact_inspection"
    }

    assert unread_artifacts(reports) == ["cut.pkl"]
    assert unread_report.sha256 not in subjects
    assert subjects == {report.sha256 for report in readable_reports}
    assert assessment.artifacts == 3, "the unread file is still counted as supplied"


def test_an_artifact_that_was_read_does_produce_evidence(readable_reports):
    """Negative control: the filter above is about readability, not about
    refusing every artifact."""
    assessment = assess(readable_reports, on=TODAY, role=Role.PROVIDER_GPAI, has_bom=True)
    subjects = {
        item.subject
        for row in assessment.assessments
        for item in row.evidence
        if item.kind == "artifact_inspection"
    }

    assert unread_artifacts(readable_reports) == []
    assert subjects == {report.sha256 for report in readable_reports}


def test_a_set_of_only_unread_artifacts_yields_no_evidence_at_all(unread_report):
    assessment = assess([unread_report], on=TODAY, role=Role.PROVIDER_GPAI, has_bom=True)

    assert all(item.evidence == [] for item in assessment.assessments)
    assert assessment.to_dict()[DENIAL_KEY]["with_evidence"] == 0


def test_a_failing_artifact_is_still_evidence(write_artifact):
    """A gadget pickle is read through and its finding is an observation, so
    it bears on the obligations that ask what is inside the file."""
    report = inspect_artifact(
        write_artifact("gadget.pkl", corpus_build.craft_reduce("posix", "system", ("id",), 2))
    )
    assert report.verdict is Verdict.FAIL and report.metadata.get("fully_read")

    assessment = assess([report], on=TODAY, role=Role.PROVIDER_GPAI, has_bom=True)
    row = next(item for item in assessment.assessments if item.obligation.id == "AIA-53-1a")

    assert [item.kind for item in row.evidence] == ["artifact_inspection", "ml_bom"]


def test_gaps_lists_what_applies_and_this_evidence_does_not_address(readable_reports):
    assessment = assess(readable_reports, on=TODAY, role=Role.PROVIDER_GPAI, has_bom=True)
    missing = {obligation.id for obligation in gaps(assessment)}

    assert "AIA-4" in missing, "staff training is not in a weight file"
    assert "AIA-53-1d" in missing, "nor is the training-data summary"
    assert "AIA-53-1b" not in missing, "a signed BOM does address the integrator's question"
    assert all(by_id(identifier).applies_from <= TODAY for identifier in missing)


def test_evidence_kinds_are_only_the_ones_actually_supplied(readable_reports):
    """`has_attestation=False` must not produce attestation evidence; this is
    what stops the map from asserting a package that was never written.

    Role.ANY, where this used to say PROVIDER_GPAI. The ledger kinds,
    `consistency_proof` and `time_anchor`, used to reach AIA-12 and now reach
    only AIA-15, which binds a provider of a high-risk system; since a GPAI
    model provider no longer inherits the provider rows, those two kinds are
    correctly invisible to that role. Asserting the full set therefore needs a
    role that sees every obligation.
    """
    assessment = assess(
        readable_reports, on=TODAY, role=Role.ANY,
        has_attestation=False, has_consistency_proof=False, has_time_anchor=False, has_bom=False,
    )
    kinds = {item.kind for row in assessment.assessments for item in row.evidence}

    assert kinds == {"artifact_inspection"}

    richer = assess(
        readable_reports, on=TODAY, role=Role.ANY,
        has_attestation=True, has_consistency_proof=True, has_time_anchor=True, has_bom=True,
    )
    assert {item.kind for row in richer.assessments for item in row.evidence} == {
        "artifact_inspection", "ml_bom", "attestation", "consistency_proof", "time_anchor",
    }


def test_the_ledger_kinds_do_not_reach_a_gpai_provider(readable_reports):
    """Negative control for the role change above: a kind that is supplied is
    still only mapped where the catalogue says it bears, and Chapter V has no
    row a consistency proof speaks to."""
    assessment = assess(
        readable_reports, on=TODAY, role=Role.PROVIDER_GPAI,
        has_attestation=True, has_consistency_proof=True, has_time_anchor=True, has_bom=True,
    )
    kinds = {item.kind for row in assessment.assessments for item in row.evidence}

    assert "consistency_proof" not in kinds
    assert "time_anchor" not in kinds
    assert {"artifact_inspection", "ml_bom", "attestation"} <= kinds


# ---------------------------------------------------------------------------
# 6. The dossier, bound to the artifacts it describes
# ---------------------------------------------------------------------------

def test_the_dossier_names_exactly_the_artifacts_it_was_computed_from(readable_reports):
    dossier = build_dossier(readable_reports, on=TODAY, role=Role.PROVIDER_GPAI)

    assert dossier["subjects"] == sorted(report.sha256 for report in readable_reports)
    assert dossier["kind"] == DOSSIER_KIND
    assert dossier["framework"] == "Regulation (EU) 2024/1689"


def test_the_dossier_records_the_artifacts_it_could_not_read(readable_reports, unread_report):
    dossier = build_dossier(
        [*readable_reports, unread_report], on=TODAY, role=Role.PROVIDER_GPAI
    )

    assert dossier["artifacts_not_fully_read"] == ["cut.pkl"]
    assert unread_report.sha256 in dossier["subjects"], "it is still one of the files supplied"


def test_a_dossier_carries_no_score_either(readable_reports):
    dossier = build_dossier(readable_reports, on=TODAY, role=Role.PROVIDER_GPAI)

    assert score_like_keys(dossier) == []
    assert floats_in(dossier) == []


def test_changing_one_artifact_changes_the_dossier_digest(
    tmp_path, readable_reports, other_reports, keypair
):
    """The dossier entry's subject is the digest of the set it covers, so two
    dossiers over different files cannot be confused for one another."""
    first, _ = write_evidence_package(
        tmp_path / "a.zip", readable_reports, keypair, on=TODAY, role=Role.PROVIDER_GPAI
    )
    mixed = [readable_reports[0], other_reports[1]]
    second, _ = write_evidence_package(
        tmp_path / "b.zip", mixed, keypair, on=TODAY, role=Role.PROVIDER_GPAI
    )

    digest_a = package_entries(first.path)[-1]["subject_sha256"]
    digest_b = package_entries(second.path)[-1]["subject_sha256"]

    assert digest_a != digest_b
    # And the same set produces the same digest, so the difference above is
    # the artifacts changing rather than the digest being unstable.
    third, _ = write_evidence_package(
        tmp_path / "c.zip", list(reversed(readable_reports)), keypair,
        on=TODAY, role=Role.PROVIDER_GPAI,
    )
    assert package_entries(third.path)[-1]["subject_sha256"] == digest_a


def test_the_package_verifies_and_holds_one_entry_per_artifact_plus_the_dossier(
    tmp_path, readable_reports, keypair
):
    result, dossier = write_evidence_package(
        tmp_path / "evidence.zip", readable_reports, keypair, on=TODAY, role=Role.PROVIDER_GPAI
    )

    verified = verify_package(result.path)
    assert verified.ok is True, verified.problems
    assert verified.entry_count == len(readable_reports) + 1
    assert result.entry_count == len(readable_reports) + 1

    entries = package_entries(result.path)
    assert [entry["payload"].get("kind") for entry in entries] == [None, None, DOSSIER_KIND]
    assert entries[-1]["payload"]["subjects"] == dossier["subjects"]


def test_the_dossier_in_a_package_names_the_artifacts_the_package_inspected(
    tmp_path, readable_reports, keypair
):
    """The property a reader depends on: the assessment and the inspections
    in one package are about the same files."""
    result, _ = write_evidence_package(
        tmp_path / "evidence.zip", readable_reports, keypair, on=TODAY, role=Role.PROVIDER_GPAI
    )
    entries = package_entries(result.path)

    inspected = sorted(entry["subject_sha256"] for entry in entries[:-1])
    assert entries[-1]["payload"]["subjects"] == inspected


def test_a_dossier_cannot_be_reattached_to_a_different_set_of_artifacts(
    tmp_path, readable_reports, other_reports, keypair
):
    """The control that matters most.

    A forger with the signing key rebuilds the package around another set of
    inspections and keeps the dossier entry that was written for the first
    set. Everything they can recompute, they do: the manifest, the Merkle
    root, the head hash and the signature all check out. What they cannot
    reach is the link the dossier entry carries to the entry before it, so
    the package fails on `chain_intact` and on nothing else.
    """
    genuine, _ = write_evidence_package(
        tmp_path / "genuine.zip", readable_reports, keypair, on=TODAY, role=Role.PROVIDER_GPAI
    )
    other, _ = write_evidence_package(
        tmp_path / "other.zip", other_reports, keypair, on=TODAY, role=Role.PROVIDER_GPAI
    )

    genuine_entries = chain.load_entries(package_entries(genuine.path))
    other_entries = chain.load_entries(package_entries(other.path))
    forged = [*other_entries[:-1], genuine_entries[-1]]

    # The forgery is what it claims to be: this dossier names one set of
    # artifacts while the inspections beside it are the other set.
    assert forged[-1].payload["subjects"] == sorted(r.sha256 for r in readable_reports)
    assert [entry.subject_sha256 for entry in forged[:-1]] == [
        r.sha256 for r in other_reports
    ]

    package.write_package(tmp_path / "forged.zip", forged, keypair, {})
    result = verify_package(tmp_path / "forged.zip")

    assert result.ok is False
    assert result.checks["chain_intact"] is False
    assert result.checks["files_match_manifest"] is True
    assert result.checks["head_matches"] is True
    assert result.checks["merkle_root_matches"] is True
    assert result.checks["signature_valid"] is True
    assert any("prev_hash" in problem for problem in result.problems), result.problems


def test_a_relinked_dossier_is_caught_even_when_every_hash_recomputes(
    tmp_path, readable_reports, other_reports, keypair
):
    """The forgery the test above does not reach, and the reason `subjects`
    exists at all.

    The naive attack keeps the genuine dossier entry verbatim and so breaks
    `prev_hash`. A forger who holds a signing key has no reason to be that
    clumsy: they re-link it, appending the dossier's own subject digest and
    payload onto the other package's inspections through the same
    `chain.append` the writer uses. Every link recomputes, the Merkle root
    recomputes, the head matches, the signature is theirs and verifies - and
    the assessment now sits at the end of a chain of inspections it was never
    computed from. Nothing read `subjects` or the digest the entry was filed
    under, so this verified clean.
    """
    genuine, _ = write_evidence_package(
        tmp_path / "genuine.zip", readable_reports, keypair, on=TODAY, role=Role.PROVIDER_GPAI
    )
    other, _ = write_evidence_package(
        tmp_path / "other.zip", other_reports, keypair, on=TODAY, role=Role.PROVIDER_GPAI
    )
    stolen = chain.load_entries(package_entries(genuine.path))[-1]

    forged = chain.load_entries(package_entries(other.path))[:-1]
    chain.append(forged, stolen.subject_sha256, stolen.payload)
    package.write_package(tmp_path / "relinked.zip", forged, keypair, {})

    result = verify_package(tmp_path / "relinked.zip")

    # Everything a forger can recompute has been recomputed.
    assert result.checks["chain_intact"] is True
    assert result.checks["head_matches"] is True
    assert result.checks["merkle_root_matches"] is True
    assert result.checks["signature_valid"] is True
    # And the one thing they cannot: the dossier still names the other set.
    assert result.checks["dossier_covers_its_inspections"] is False
    assert result.ok is False
    assert any("does not describe the artifacts" in p for p in result.problems), result.problems


def test_editing_the_subjects_list_to_match_breaks_the_digest_it_is_filed_under(
    tmp_path, readable_reports, other_reports, keypair
):
    """Closing the obvious next move: rewrite `subjects` so it matches the
    inspections. The entry is filed under the digest of the set it covers, so
    the two halves of the entry then contradict each other."""
    genuine, _ = write_evidence_package(
        tmp_path / "genuine.zip", readable_reports, keypair, on=TODAY, role=Role.PROVIDER_GPAI
    )
    other, _ = write_evidence_package(
        tmp_path / "other.zip", other_reports, keypair, on=TODAY, role=Role.PROVIDER_GPAI
    )
    stolen = chain.load_entries(package_entries(genuine.path))[-1]
    payload = dict(stolen.payload)
    payload["subjects"] = sorted(report.sha256 for report in other_reports)

    forged = chain.load_entries(package_entries(other.path))[:-1]
    chain.append(forged, stolen.subject_sha256, payload)
    package.write_package(tmp_path / "relabelled.zip", forged, keypair, {})

    result = verify_package(tmp_path / "relabelled.zip")

    assert result.checks["chain_intact"] is True
    assert result.checks["dossier_covers_its_inspections"] is False
    assert result.ok is False
    assert any("but its `subjects` hash to" in p for p in result.problems), result.problems


def test_a_package_with_no_dossier_is_not_asked_about_one(tmp_path, readable_reports, keypair):
    """Negative control: `actaira attest` writes inspections and no dossier,
    and must not acquire a check it cannot satisfy."""
    entries = []
    for report in readable_reports:
        chain.append(entries, report.sha256, report.to_dict())
    package.write_package(tmp_path / "plain.zip", entries, keypair, {})

    result = verify_package(tmp_path / "plain.zip")

    assert result.ok is True, result.problems
    assert "dossier_covers_its_inspections" not in result.checks


def test_the_same_rebuild_without_the_swap_verifies(
    tmp_path, readable_reports, keypair
):
    """Negative control for the forgery test: rewriting a package around its
    own entries is not what fails, the substitution is."""
    genuine, _ = write_evidence_package(
        tmp_path / "genuine.zip", readable_reports, keypair, on=TODAY, role=Role.PROVIDER_GPAI
    )
    entries = chain.load_entries(package_entries(genuine.path))

    package.write_package(tmp_path / "rebuilt.zip", entries, keypair, {})
    result = verify_package(tmp_path / "rebuilt.zip")

    assert result.ok is True, result.problems
    assert result.checks["chain_intact"] is True


def test_an_evidence_package_continues_an_existing_chain(
    tmp_path, readable_reports, other_reports, keypair
):
    """`previous_entries` is how a second dossier extends the first log
    rather than starting a new one, which is what makes a consistency proof
    between the two mean anything."""
    first, _ = write_evidence_package(
        tmp_path / "first.zip", readable_reports, keypair, on=TODAY, role=Role.PROVIDER_GPAI
    )
    previous = chain.load_entries(package_entries(first.path))

    second, dossier = write_evidence_package(
        tmp_path / "second.zip", other_reports, keypair, on=TODAY, role=Role.PROVIDER_GPAI,
        previous_entries=previous,
    )

    assert verify_package(second.path).ok is True
    assert second.entry_count == len(previous) + len(other_reports) + 1
    entries = package_entries(second.path)
    assert entries[: len(previous)] == package_entries(first.path)
    assert dossier["subjects"] == sorted(report.sha256 for report in other_reports)


# ---------------------------------------------------------------------------
# 7. The prose lives in the message catalogue, the facts do not
# ---------------------------------------------------------------------------

TEXT_FIELDS = ("title", "summary", "evidence_expected", "actaira_provides",
               "actaira_does_not_provide", "note")
FACT_FIELDS = ("id", "article", "applies_from", "grace_until", "status", "role",
               "coverage", "citation")


@pytest.mark.parametrize("obligation", ALL_OBLIGATIONS, ids=lambda o: o.id)
def test_a_translation_cannot_move_a_date_or_a_coverage_verdict(obligation):
    english = localized(obligation, "en")
    spanish = localized(obligation, "es")

    for name in FACT_FIELDS:
        assert english[name] == spanish[name], name


@pytest.mark.parametrize("obligation", ALL_OBLIGATIONS, ids=lambda o: o.id)
def test_every_line_of_prose_is_actually_translated(obligation):
    english = localized(obligation, "en")
    spanish = localized(obligation, "es")

    for name in TEXT_FIELDS:
        if not english[name]:
            continue
        assert spanish[name] != english[name], f"{obligation.id}.{name} is still English"
        if isinstance(english[name], list):
            assert len(spanish[name]) == len(english[name]), f"{obligation.id}.{name}"


def test_the_python_objects_keep_the_english_text(readable_reports):
    """The public API did not change when the text moved into the catalogue:
    `Obligation` still carries English, and `to_dict` still emits it."""
    obligation = by_id("AIA-4")

    assert obligation.title == "AI literacy"
    assert obligation.to_dict()["title"] == "AI literacy"
    assert localized(obligation, "en") == obligation.to_dict()


def test_an_unknown_language_falls_back_to_english():
    obligation = by_id("AIA-53-1b")

    assert localized(obligation, "tlh") == localized(obligation, "en")


def test_the_spanish_catalogue_has_no_em_dashes():
    """House rule, and a practical one: an em dash in a legal summary is a
    tell that the text came out of a machine translator."""
    def has_dash(value: object) -> bool:
        return "—" in json.dumps(value, ensure_ascii=False)

    offenders = [
        f"{obligation.id}.{name}"
        for obligation in ALL_OBLIGATIONS
        for name, value in localized(obligation, "es").items()
        if has_dash(value)
    ]

    assert offenders == []
    assert has_dash(["una frase — con guion largo"]), "the detector must find one"


# ---------------------------------------------------------------------------
# 8. The two web routes
#
# The panel in the browser is only as honest as what it is served, so these
# ask the running server the same questions the library was asked above and
# require the same answers. The server is started on a port the OS picks, in
# this process, and torn down with the fixture.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def server():
    from actaira.web.server import build_server

    httpd = build_server("127.0.0.1", 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def http_get(base: str, path: str) -> tuple[int, dict, dict]:
    request = urllib.request.Request(base + path)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read()), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read()), dict(exc.headers)


def http_post_file(base: str, path: str, name: str, blob: bytes, fields: dict) -> tuple[int, dict]:
    """A multipart body, written by hand: the server parses it, not a library."""
    boundary = "----actairatest"
    parts: list[bytes] = []
    for key, value in fields.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode()
        )
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n".encode()
    )
    parts.append(blob)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    body = b"".join(parts)

    request = urllib.request.Request(
        base + path, data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_the_clock_route_answers_for_the_date_it_was_asked_about(server):
    status, payload, headers = http_get(server, "/api/governance/clock?on=2026-09-10&role=deployer")

    assert status == 200
    assert payload["on"] == "2026-09-10"
    assert payload["role"] == "deployer"
    # What applies on 2026-09-10: everything that had started by 2026-12-01,
    # which is the nearest date the table above pins.
    applicable = {row["id"] for row in payload["obligations"] if row["applicable"]}
    assert applicable == set(APPLICABLE_ON[date(2026, 12, 1)])

    # Who is bound, and each state, must be what the library says. A second
    # copy of that rule living in the web layer is the failure this checks for.
    library = assess([], on=date(2026, 9, 10), role=Role.DEPLOYER)
    assert {row["id"] for row in payload["obligations"] if row["binds"]} == assessed_ids(library)
    assert {row["id"]: row["state"] for row in payload["obligations"] if row["binds"]} == {
        item.obligation.id: item.state for item in library.assessments
    }
    assert "Content-Security-Policy" in headers


def test_the_clock_route_serves_nothing_that_reads_as_a_grade(server):
    """The panel in the browser is the surface most people see, and it was
    outside the guard entirely."""
    for lang in SUPPORTED_LANGS:
        status, payload, _ = http_get(
            server, f"/api/governance/clock?on={TODAY.isoformat()}&lang={lang}"
        )
        assert status == 200
        assert score_like(payload) == []


@pytest.mark.parametrize(
    "raw",
    ["notadate", "2026-09-10T10:00", "20260910", "2026-W37-4", "1999-01-01", "2026-02-30"],
)
def test_the_clock_route_refuses_a_date_it_cannot_pin_down(server, raw):
    """`date.fromisoformat` accepts week dates and timestamps. Two clients
    asking the same question in two spellings would get answers nobody can
    line up, so the shape is pinned before anything is parsed."""
    status, payload, _ = http_get(server, "/api/governance/clock?on=" + urllib.parse.quote(raw))

    assert status == 400
    assert payload["error"]["code"] in ("bad_date", "date_out_of_range")


def test_the_clock_route_accepts_the_shape_it_asks_for(server):
    """Negative control for the refusals above."""
    status, payload, _ = http_get(server, "/api/governance/clock?on=2027-12-02")

    assert status == 200
    assert payload["on"] == "2027-12-02"


def test_the_clock_route_refuses_a_role_it_does_not_know(server):
    status, payload, _ = http_get(server, "/api/governance/clock?role=auditor")

    assert status == 400
    assert payload["error"]["code"] == "bad_role"


def test_the_assess_route_returns_what_the_library_returns(server, tmp_path):
    name, blob = _safetensors("web.safetensors", 4)
    status, payload = http_post_file(
        server, "/api/governance/assess", name, blob,
        {"role": "provider_gpai", "on": "2026-09-10", "lang": "en"},
    )

    assert status == 200
    assert payload["assessed_on"] == "2026-09-10"
    assert payload["artifact"]["name"] == name
    assert payload["artifact"]["fully_read"] is True

    report = inspect_artifact(write_bytes(tmp_path, name, blob))
    expected = assess([report], on=date(2026, 9, 10), role=Role.PROVIDER_GPAI, has_bom=True)
    assert [row["id"] for row in payload["obligations"]] == [
        item.obligation.id for item in expected.assessments
    ]
    assert [row["state"] for row in payload["obligations"]] == [
        item.state for item in expected.assessments
    ]
    assert payload[DENIAL_KEY] == expected.to_dict()[DENIAL_KEY]
    assert score_like(payload) == []
    assert floats_in(payload) == []


def test_the_assess_route_serves_spanish_without_moving_a_date(server):
    name, blob = _safetensors("web.safetensors", 4)
    _, english = http_post_file(server, "/api/governance/assess", name, blob,
                                {"role": "provider", "on": "2026-09-10", "lang": "en"})
    _, spanish = http_post_file(server, "/api/governance/assess", name, blob,
                                {"role": "provider", "on": "2026-09-10", "lang": "es"})

    assert [row["id"] for row in spanish["obligations"]] == [row["id"] for row in english["obligations"]]
    assert [row["applies_from"] for row in spanish["obligations"]] == [
        row["applies_from"] for row in english["obligations"]
    ]
    assert all(
        es["title"] != en["title"]
        for es, en in zip(spanish["obligations"], english["obligations"], strict=True)
    )


def test_the_assess_route_serves_nothing_that_reads_as_a_grade_in_either_language(server):
    """The whole payload, prose included, in both languages."""
    name, blob = _safetensors("web.safetensors", 4)
    for lang in SUPPORTED_LANGS:
        _, payload = http_post_file(server, "/api/governance/assess", name, blob,
                                    {"role": "provider", "on": "2026-09-10", "lang": lang})
        assert score_like(payload) == []


def test_the_assess_route_says_when_it_could_not_read_the_artifact(server):
    truncated = corpus_build.craft_reduce("posix", "system", ("id",), 2)[:12]
    status, payload = http_post_file(
        server, "/api/governance/assess", "cut.pkl", truncated,
        {"role": "provider_gpai", "on": "2026-09-10"},
    )

    assert status == 200
    assert payload["artifact"]["verdict"] == "inconclusive"
    assert payload["artifacts_not_fully_read"] == ["cut.pkl"]
    assert payload[DENIAL_KEY]["with_evidence"] == 0
    assert all(row["evidence"] == [] for row in payload["obligations"])


def test_the_assess_route_refuses_a_role_it_does_not_know(server):
    name, blob = _safetensors("web.safetensors", 4)
    status, payload = http_post_file(
        server, "/api/governance/assess", name, blob, {"role": "auditor"}
    )

    assert status == 400
    assert payload["error"]["code"] == "bad_role"


def test_the_assess_route_needs_a_file(server):
    request = urllib.request.Request(
        server + "/api/governance/assess", data=b"{}",
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(request, timeout=30)
        raise AssertionError("a JSON body must not reach the assessment route")
    except urllib.error.HTTPError as exc:
        assert exc.code == HTTPStatus.UNSUPPORTED_MEDIA_TYPE
