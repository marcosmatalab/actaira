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

# Sections whose values are plain strings. The `governance` and `controls`
# sections went to archive/model-scanner with the modules whose ids keyed
# own tests further down rather than a shape exception here.
SECTIONS = ("ui", "rules", "rule_help")
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
# Every rule the code can emit has text in both languages
# ---------------------------------------------------------------------------

def test_the_source_actually_yielded_rules_to_check():
    assert len(SOURCE_RULES) >= 30, "the source scan found almost nothing; it is not scanning"
    assert "ACT-PKL-002" in SOURCE_RULES, "the conditional rule assignment was missed"
    assert "ACT-PATH-002" in SOURCE_RULES, "the conformance package was missed"


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
