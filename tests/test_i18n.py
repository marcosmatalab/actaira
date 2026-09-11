"""The bilingual catalogue, and one guard about identifiers.

D-07 says rule identifiers are the stable interface and text is not. That only
holds if both catalogues actually carry every rule the code can emit, so the
list of rules is recovered from the source rather than from the catalogue
itself: asserting a catalogue against itself proves nothing.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from actaira.i18n.catalog import SUPPORTED, Catalog, load
from conftest import REPO_ROOT, SRC_DIR

# Sections whose values are plain strings. `governance` is nested (an
# obligation id maps to a row of strings and lists of strings) and gets its
# own tests further down rather than a shape exception here.
SECTIONS = ("ui", "rules", "rule_help")
GOVERNANCE = "governance"
CATALOGUES = {lang: json.loads((SRC_DIR / "actaira" / "i18n" / f"{lang}.json").read_text("utf-8")) for lang in SUPPORTED}

# `grep -rn 'ACT-...' src/`, done in-process so the failure message can name the
# file and line. The pattern is deliberately wider than `rule_id="ACT-`: in
# pickle_scan the rule is chosen by a conditional and assigned to a variable
# before it reaches `rule_id=`, so a narrower grep would silently miss
# ACT-PKL-002 and ACT-PKL-007, the two most important rules in the project.
# The trailing guard was added when the controls layer arrived: a control
# identifier such as `ACT-C-53-ANNEX-XI` or `ACT-C-50-1-DISCLOSE` starts with
# something this pattern reads as a rule id and then keeps going. Without the
# guard the scan reported `ACT-C-53` and `ACT-C-50` as rules with no
# catalogue entry, which they are not: they are prefixes of identifiers that
# never reach `Finding.rule_id`. A rule id is the whole token or it is not one.
RULE_LITERAL = re.compile(r"ACT-[A-Z0-9]+-\d+(?![-\w])")
# The same trick for the EU AI Act catalogue: obligation ids are literals in
# `governance/catalog.py`, the prose is in the message catalogues, and the two
# must describe the same set.
#
# The pattern was `AIA-\d+(?:-\d+[a-z]?)?`, which assumed every id segment
# after the first was digits and at most one letter. Two entries added when
# the catalogue was corrected break that assumption: AIA-4a, for the Art. 4a
# inserted by Regulation (EU) 2026/1744, has a letter glued to the first
# segment, and AIA-5-1ba, for the Art. 5(1)(ba) and (bb) prohibitions, has two
# letters in the second. Under the old pattern both would have been scanned as
# a shorter id and then reported as orphan prose, so the pattern now takes any
# hyphen-separated run of digits and lowercase letters.
OBLIGATION_LITERAL = re.compile(r"AIA-[0-9a-z]+(?:-[0-9a-z]+)*")


def python_files(*roots: Path) -> list[Path]:
    found: list[Path] = []
    for root in roots:
        found.extend(
            path
            for path in sorted(root.rglob("*.py"))
            if "__pycache__" not in path.parts
        )
    return found


def rule_ids_in_source() -> dict[str, list[str]]:
    """rule_id -> the source locations that mention it."""
    found: dict[str, list[str]] = {}
    for path in python_files(SRC_DIR):
        for number, line in enumerate(path.read_text("utf-8").splitlines(), start=1):
            for rule_id in RULE_LITERAL.findall(line):
                found.setdefault(rule_id, []).append(f"{path.relative_to(REPO_ROOT)}:{number}")
    return found


SOURCE_RULES = rule_ids_in_source()


# ---------------------------------------------------------------------------
# The two catalogues describe the same world
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("section", SECTIONS)
def test_english_and_spanish_carry_exactly_the_same_keys(section):
    english = set(CATALOGUES["en"][section])
    spanish = set(CATALOGUES["es"][section])

    assert english - spanish == set(), f"missing from es.{section}"
    assert spanish - english == set(), f"present in es.{section} only"
    assert english, f"{section} is empty; the assertion above is vacuous"


@pytest.mark.parametrize("section", SECTIONS)
def test_no_spanish_string_is_just_the_english_one(section):
    """A filler detector. Copying the English string is how a second language
    passes a key-set test while being untranslated."""
    untranslated = [
        key
        for key, text in CATALOGUES["es"][section].items()
        if text == CATALOGUES["en"][section].get(key)
    ]

    assert untranslated == []


@pytest.mark.parametrize("section", SECTIONS)
def test_no_catalogue_entry_is_empty(section):
    for lang, catalogue in CATALOGUES.items():
        blank = [key for key, text in catalogue[section].items() if not text.strip()]
        assert blank == [], f"{lang}.{section}"


# ---------------------------------------------------------------------------
# The governance section: nested, and the part a Spanish consultant reads
# ---------------------------------------------------------------------------

def governance_leaves(catalogue: dict) -> dict[str, str]:
    """`AIA-4.title` -> text, flattening the lists so each line is comparable."""
    leaves: dict[str, str] = {}
    for obligation_id, row in catalogue.get(GOVERNANCE, {}).items():
        for field, value in row.items():
            if isinstance(value, list):
                for index, line in enumerate(value):
                    leaves[f"{obligation_id}.{field}[{index}]"] = line
            else:
                leaves[f"{obligation_id}.{field}"] = value
    return leaves


GOVERNANCE_LEAVES = {lang: governance_leaves(CATALOGUES[lang]) for lang in SUPPORTED}


def obligation_ids_in_source() -> dict[str, list[str]]:
    """obligation id -> the source locations that mention it."""
    found: dict[str, list[str]] = {}
    for path in python_files(SRC_DIR):
        for number, line in enumerate(path.read_text("utf-8").splitlines(), start=1):
            for obligation_id in OBLIGATION_LITERAL.findall(line):
                found.setdefault(obligation_id, []).append(f"{path.relative_to(REPO_ROOT)}:{number}")
    return found


SOURCE_OBLIGATIONS = obligation_ids_in_source()


def test_the_source_actually_yielded_obligations_to_check():
    assert len(SOURCE_OBLIGATIONS) >= 10, "the scan for obligation ids found almost nothing"
    assert "AIA-53-1a" in SOURCE_OBLIGATIONS, "the compound ids were missed"
    assert "AIA-4" in SOURCE_OBLIGATIONS
    # The two shapes the previous pattern truncated. Asserted as whole ids,
    # because truncation is silent: it yields a real id that happens to be a
    # prefix of the one in the source, and the orphan check fires somewhere
    # else entirely.
    assert "AIA-4a" in SOURCE_OBLIGATIONS, "a letter on the first segment was truncated"
    assert "AIA-5-1ba" in SOURCE_OBLIGATIONS, "two letters on a later segment were truncated"


@pytest.mark.parametrize("lang", SUPPORTED)
def test_every_obligation_in_the_source_has_prose_in_every_language(lang):
    missing = {
        obligation_id: locations
        for obligation_id, locations in sorted(SOURCE_OBLIGATIONS.items())
        if obligation_id not in CATALOGUES[lang][GOVERNANCE]
    }

    assert missing == {}


@pytest.mark.parametrize("lang", SUPPORTED)
def test_no_translated_obligation_is_one_the_catalogue_dropped(lang):
    """The other direction, as for rules: prose for an obligation the code no
    longer carries is text that gets translated and reviewed forever."""
    orphans = set(CATALOGUES[lang][GOVERNANCE]) - set(SOURCE_OBLIGATIONS)

    assert orphans == set()


def test_both_languages_describe_each_obligation_with_the_same_fields():
    """Field for field and line for line: a Spanish row with one fewer item
    in `actaira_does_not_provide` is a limitation that vanished in
    translation, which is the one thing this catalogue must not do."""
    english = set(GOVERNANCE_LEAVES["en"])
    spanish = set(GOVERNANCE_LEAVES["es"])

    assert english - spanish == set(), "missing from es.governance"
    assert spanish - english == set(), "present in es.governance only"
    assert len(english) > 100, "the governance section is too small to be complete"


def test_no_spanish_obligation_text_is_just_the_english_one():
    untranslated = [
        key for key, text in GOVERNANCE_LEAVES["es"].items()
        if text == GOVERNANCE_LEAVES["en"].get(key)
    ]

    assert untranslated == []


@pytest.mark.parametrize("lang", SUPPORTED)
def test_no_obligation_text_is_blank(lang):
    blank = [key for key, text in GOVERNANCE_LEAVES[lang].items() if not str(text).strip()]

    assert blank == []


@pytest.mark.parametrize("lang", SUPPORTED)
def test_every_obligation_row_has_at_least_a_title_a_summary_and_an_expectation(lang):
    for obligation_id, row in CATALOGUES[lang][GOVERNANCE].items():
        assert row.get("title"), f"{lang}.{obligation_id}"
        assert len(row.get("summary", "")) > 40, f"{lang}.{obligation_id}"
        assert row.get("evidence_expected"), f"{lang}.{obligation_id}"
        assert row.get("actaira_provides") or row.get("actaira_does_not_provide"), (
            f"{lang}.{obligation_id} says neither what Actaira gives nor what it does not"
        )


def test_the_spanish_governance_text_carries_no_em_dash():
    """An em dash in this section is the signature of a machine translation
    pasted in, and this is the text a Spanish consultant actually reads."""
    offenders = [key for key, text in GOVERNANCE_LEAVES["es"].items() if "\u2014" in str(text)]

    assert offenders == []


# Function words that appear in almost any English sentence and in no Spanish
# one. Matched as whole words, so `de` inside `modelo` cannot trip them.
ENGLISH_TELLS = re.compile(r"\b(the|and|of|with|which|from|their|does not)\b", re.IGNORECASE)


def test_no_spanish_governance_line_still_carries_english():
    """A partial translation is worse than none: it passes the key-set test,
    it differs from the English string, and it still reads as English to the
    consultant who has to sign under it."""
    left_in_english = [
        key for key, text in GOVERNANCE_LEAVES["es"].items()
        if ENGLISH_TELLS.search(str(text))
    ]

    assert left_in_english == []


def test_the_english_tell_detector_fires_on_the_english_catalogue():
    """Negative control for the test above, run against real text of exactly
    the kind being checked: most English lines here trip the detector, so a
    Spanish set that trips it zero times is a result rather than an accident
    of the pattern being too narrow to match anything."""
    caught = [
        key for key, text in GOVERNANCE_LEAVES["en"].items()
        if ENGLISH_TELLS.search(str(text))
    ]

    assert len(caught) > len(GOVERNANCE_LEAVES["en"]) // 2
    assert not ENGLISH_TELLS.search(
        "registros de la finalidad prevista y del contexto de despliegue"
    )


# ---------------------------------------------------------------------------
# Every rule the code can emit has text in both languages
# ---------------------------------------------------------------------------

def test_the_source_actually_yielded_rules_to_check():
    assert len(SOURCE_RULES) >= 30, "the source scan found almost nothing; it is not scanning"
    assert "ACT-PKL-002" in SOURCE_RULES, "the conditional rule assignment was missed"
    assert "ACT-PKL-007" in SOURCE_RULES


@pytest.mark.parametrize("lang", SUPPORTED)
def test_every_rule_id_in_the_source_has_a_catalogue_entry(lang):
    missing = {
        rule_id: locations
        for rule_id, locations in sorted(SOURCE_RULES.items())
        if rule_id not in CATALOGUES[lang]["rules"]
    }

    assert missing == {}


@pytest.mark.parametrize("lang", SUPPORTED)
def test_no_catalogue_entry_describes_a_rule_the_code_cannot_emit(lang):
    """The other direction: a rule that was removed from the code but left in
    the catalogue is dead text that will be translated and reviewed forever."""
    orphans = set(CATALOGUES[lang]["rules"]) - set(SOURCE_RULES)

    assert orphans == set()


@pytest.mark.parametrize("rule_id", sorted(SOURCE_RULES))
def test_catalog_lookup_returns_real_text_for_every_rule(rule_id):
    """Through the public API, in both languages, because that is what the CLI
    and the web UI call."""
    for lang in SUPPORTED:
        text = Catalog(lang).rule(rule_id)
        assert text != rule_id, f"{lang} fell back to the identifier"
        assert len(text) > 10


def test_an_unknown_rule_falls_back_to_its_identifier_rather_than_raising():
    assert Catalog("es").rule("ACT-XXX-999") == "ACT-XXX-999"
    assert Catalog("es").rule_help("ACT-XXX-999") == ""


def test_an_unsupported_language_falls_back_to_english():
    assert load("tlh") == load("en")
    assert Catalog("tlh").lang == "en"


def test_ui_templates_render_with_the_arguments_the_cli_passes():
    """A `{path}` left in a template that the caller does not fill would print
    a brace to the user; a renamed placeholder would print the raw template."""
    catalog = Catalog("es")
    rendered = catalog.line("attest.written", path="/tmp/x.zip")

    assert "/tmp/x.zip" in rendered
    assert "{" not in rendered


# ---------------------------------------------------------------------------
# Identifiers stay ASCII
# ---------------------------------------------------------------------------

def non_ascii_identifiers(path: Path) -> list[str]:
    """Every name this file binds, checked for characters outside ASCII.

    This is the `grep -rn` the design notes ask for, done over the AST so it
    covers what a grep for `def `, `class ` and module-level assignment would
    catch plus function arguments, and so it cannot be fooled by a line break.
    Comments and strings are not identifiers and are left alone: `src/` is full
    of legitimate accents and em dashes in prose.
    """
    tree = ast.parse(path.read_text("utf-8"), filename=str(path))
    offenders: list[str] = []

    def report(name: str, node: ast.AST) -> None:
        if not name.isascii():
            offenders.append(f"{path}:{getattr(node, 'lineno', '?')}: {name}")

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            report(node.name, node)
        elif isinstance(node, ast.arg):
            report(node.arg, node)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            report(node.id, node)
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
            report(node.attr, node)
        elif isinstance(node, ast.keyword) and node.arg:
            report(node.arg, node)
        elif isinstance(node, ast.alias):
            report(node.asname or node.name, node)
    return offenders


ALL_PYTHON_FILES = python_files(SRC_DIR, REPO_ROOT / "evals", REPO_ROOT / "tests")


@pytest.mark.parametrize(
    "path", ALL_PYTHON_FILES, ids=lambda path: str(path.relative_to(REPO_ROOT))
)
def test_no_python_identifier_carries_an_accent(path):
    """Python 3 allows `configuración` as a name, and a find-and-replace that
    translates a codebase will happily produce one. It compiles, so nothing
    complains until something that reads names by string (a migration tool, a
    serialiser, a `getattr`) fails somewhere else entirely. This guard is here
    because that has already cost this author a silent breakage once.
    """
    assert non_ascii_identifiers(path) == []


def test_the_identifier_guard_catches_an_accented_name(tmp_path):
    """Control for the test above: it must actually detect one."""
    sample = tmp_path / "spanish.py"
    sample.write_text(
        "# comentario con acentos: esto no es un identificador\n"
        "UMBRAL = 1\n"
        "configuración = {'clave': 'año'}\n"
        "def revisión(parámetro):\n"
        "    return parámetro\n",
        encoding="utf-8",
    )

    offenders = non_ascii_identifiers(sample)

    assert len(offenders) == 3, offenders
    assert any("revisión" in offender for offender in offenders)
    assert any("configuración" in offender for offender in offenders)
    assert any("parámetro" in offender for offender in offenders)
    assert not any("comentario" in offender for offender in offenders)
    assert not any("año" in offender for offender in offenders), "a string is not an identifier"
