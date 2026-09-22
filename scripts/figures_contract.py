"""Every figure the prose is allowed to state, and where each one comes from.

Design note D-230. `sync_readme_figures.py` wrote five figures into the two
READMEs and `release_check.py` compared one of them, and both scripts held
their own copy of what a figure was. Everything outside that overlap was typed
by hand, and by 2.2.0 the result was a README that said "sixty-six defects
across 11 mechanisms" three lines below a synced line saying 109, "seven
schemas" when fourteen families ship, "eight capability rules" when there are
nine, and "four states" above a table with five rows. Every one of those was
true when it was typed.

So the figures live here, once, derived from the code and the measurement
files, and both scripts import this module. The sync script writes them; the
release gate refuses a tree where any of them is wrong. A figure that is
derivable is never maintained by hand again, which is the whole of §2.1 of the
closing plan.

Two rules keep this honest as it grows.

**A figure is only in this table if it can be derived.** Nothing here reads a
number out of prose to "check" it against prose. Every entry ends at an enum,
a registry, a JSON file written by a harness, or a count of files on disk.

**The prose writes figures as digits.** "sixty-six" is not something a regex
can keep current, and the version that tried would have had to carry a
number-to-words table in two languages. `release_check.py` refuses the
spelled-out forms of the figures in this table, so the failure mode is a
build error rather than a sentence that quietly stops being true.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

# The pages this contract guards, and the thousands separator each one writes.
#
# It was the two READMEs only, which was fine while every derived figure lived
# there. It stopped being fine when the defect ledger's counts moved into
# `docs/ENGINEERING.md`: a figure that leaves the guarded set is not moved, it
# is unguarded, and the whole argument of this module is that a derivable
# number is never maintained by hand again. So the document that now carries
# them is guarded too.
SEPARATORS = {"README.md": ",", "README.es.md": ".", "docs/ENGINEERING.md": ","}
PAGES = tuple(SEPARATORS)

# Figures that must agree across the two languages. A figure stated in English
# and missing in Spanish is the drift this module exists for; a figure that
# lives in an English-only document is not, because there is no second copy to
# disagree with.
BILINGUAL_PAGES = ("README.md", "README.es.md")

def thousands(value: int, separator: str) -> str:
    return f"{value:,}".replace(",", separator)

@dataclass(frozen=True)
class Figure:
    """One number, its source, and how it is spelled in each language.

    `pattern` is anchored on the words around the figure rather than on the
    digits, so a version number or an article number is never rewritten by
    accident. Each language gets its own pattern because the anchor words are
    the translated ones.
    """

    name: str
    value: int | str
    source: str
    patterns: dict[str, str]
    thousands_separated: bool = False

    def rendered(self, readme: str) -> str:
        if not self.thousands_separated:
            return str(self.value)
        assert isinstance(self.value, int)
        return thousands(self.value, SEPARATORS[readme])

def derive() -> dict[str, Any]:
    """Read every canonical source once. Raises rather than guessing."""
    from actaira import __version__, schemas
    from actaira.cli import build_parser

    def harness(relative: str, how: str) -> dict[str, Any]:
        path = ROOT / relative
        if not path.is_file():
            raise FileNotFoundError(f"{relative} is missing. Run `{how}`.")
        return json.loads(path.read_text(encoding="utf-8"))

    figures_path = ROOT / "figures.json"
    if not figures_path.is_file():
        raise FileNotFoundError("figures.json is missing. Run `make figures`.")
    measured = json.loads(figures_path.read_text(encoding="utf-8"))
    if not measured.get("tests", {}).get("available"):
        raise ValueError("figures.json records no test count. Run `make figures`.")

    # `evals/` and `fuzz/` went to tag v2.3.0, and with them the
    # judged-retrieval, marking-survival and benchmark figures. Nothing here
    # falls back to a literal: a figure with no command that measures it is a
    # figure this file does not carry. See CLAUDE.md, work rule 6.
    defects = measured["defects"]
    parser = build_parser()
    commands: set[str] = set()
    for action in parser._subparsers._group_actions:  # noqa: SLF001 - argparse has no public API
        commands.update(action.choices)

    design = (ROOT / "docs" / "DESIGN.md").read_text(encoding="utf-8")

    return {
        "version": __version__,
        "tests": measured["tests"]["collected"],
        "lines": measured["code"]["total"]["lines"],
        # The product is `src/`, and the tree is `src/` plus the suite plus the
        # scripts. `measure_areas` partitions those three and raises on a file
        # no area claimed, so this subtraction is exact rather than an estimate.
        # Rejected: a tenth entry in AREAS, which would count `src/` twice in a
        # table whose whole guarantee is that every file is counted once.
        "product_lines": (
            measured["code"]["total"]["lines"]
            - measured["code"]["tests"]["lines"]
            - measured["code"]["scripts"]["lines"]
        ),
        "rules": measured["catalog"]["rules"],
        "defects": defects["defects"],
        "defects_pinned": defects["pinned_by_a_named_test"],
        "defects_by_note": len(defects["pinned_by_a_note_instead"]),
        "defect_mechanisms": defects["mechanisms"],
        "defects_not_shipped": defects["defects"] - defects["in_the_shipped_tool"],
        "defects_open": defects["still_open"],
        "schema_families": len(schemas.VERSIONS),
        "schema_documents": len(schemas.names()),
        "schemas_superseded": sum(len(item) for item in schemas.SUPERSEDED.values()),
        "commands": len(commands),
        "design_notes": len(set(re.findall(r"^\| (D-\d+[a-z]?) \|", design, re.M))),
        "runtime_dependencies": 1,
    }

def figures() -> list[Figure]:
    """The table, with one pattern per language for each figure.

    The patterns are lookaheads on the words that follow the number, so the
    replacement never has to reconstruct the sentence. Where a figure appears
    in a sentence with no distinctive following word, the anchor goes in
    front instead - see `defects_by_note`, which sits at the end of a clause.
    """
    value = derive()

    def figure(name: str, source: str, en: str, es: str, thousands_separated: bool = False) -> Figure:
        return Figure(
            name=name,
            value=value[name],
            source=source,
            patterns={"README.md": en, "README.es.md": es},
            thousands_separated=thousands_separated,
        )

    def doc_figure(name: str, source: str, pattern: str) -> Figure:
        """A figure that lives in `docs/ENGINEERING.md` and in no README.

        The defect ledger's counts are the case this exists for. A landing
        page is not where a reader meets a defect count, and the page that
        argues about how the repository is held up is. What made the move
        worth doing carefully is that a figure leaving the guarded set is not
        moved, it is *unguarded*, and the whole argument of this module is
        that a derivable number is never maintained by hand again. So the page
        it moved to is guarded too, and this is how a figure says which page
        it is on.
        """
        return Figure(name=name, value=value[name], source=source,
                      patterns={"docs/ENGINEERING.md": pattern})

    def measured_only(name: str, source: str, why: str) -> Figure:
        """Measured into `figures.json`, stated on no page, with the reason why.

        DEF-122. A page in `patterns` is a DECLARATION that the figure lives
        there, and the gate now refuses a declaration that matches nothing. So a
        figure no page states says so here instead of keeping patterns nothing
        can satisfy - which is what `design_notes` did, appearing to be guarded
        by three checks while only `figures_match` ever saw it. `why` is prose
        and the code never reads it: writing it is the cost of the empty dict.
        """
        assert why, f"{name} states no reason for living on no page"
        return Figure(name=name, value=value[name], source=source, patterns={})

    return [
        # The release version, wherever the prose states it - the header strip
        # and the closing line. It is here rather than in `release_check.py`
        # alone because it is the same thing as every other figure: derived
        # once, written by the sync script, refused by the gate when it
        # drifts. README.md said `v2.1.0` in its status line through the whole
        # of 2.2 development.
        #
        # There used to be a second entry for `release-2.2.0-7C3AED` inside a
        # shields.io badge. The badges are gone: they were images fetched from
        # a third party, so a README opened without a network showed six broken
        # ones, and one of them pointed at CI on a repository this tree does
        # not have. The header is text now, in the same `**Actaira x.y.z**`
        # shape the closing line already used, so one pattern covers both.
        figure("version", "actaira.__version__",
               r"(?<=\*\*Actaira )\d+\.\d+\.\d+(?=\*\*)", r"(?<=\*\*Actaira )\d+\.\d+\.\d+(?=\*\*)"),
        figure("tests", "figures.json: pytest --collect-only",
               r"\b[\d,.]+(?= tests\b)", r"\b[\d,.]+(?= tests\b)", True),
        figure("lines", "figures.json: line count over src, tests and scripts",
               r"\b[\d,.]+(?= lines of Python)", r"\b[\d,.]+(?= líneas de Python)", True),
        # `lines` was published as if it were the size of the product. It is the
        # size of the tree, and the suite and the scripts are most of it. Both
        # are stated now, each anchored on its own noun, so neither sentence can
        # be read as the other. Rejected: narrowing `lines` to src/, which would
        # have moved the ambiguity rather than removed it.
        figure("product_lines", "figures.json: code.total minus tests and scripts",
               r"\b[\d,.]+(?= lines of product code)",
               r"\b[\d,.]+(?= líneas de código de producto)", True),
        figure("rules", "i18n catalogue",
               r"\b\d+(?= documented rules)", r"\b\d+(?= reglas documentadas)"),
        # The ledger's counts live in `docs/ENGINEERING.md`. A landing page is
        # not where a reader meets a defect count, and the page that argues
        # about how the repository is held up is. Guarded there rather than
        # unguarded here: see `doc_figure`.
        doc_figure("defects", "docs/defects.json",
                   r"\b\d+(?= defects have been found)"),
        doc_figure("defect_mechanisms", "docs/defects.json: distinct found_by",
                   r"\b\d+(?= distinct mechanisms)"),
        doc_figure("defects_not_shipped", "docs/defects.json: shipped_defect false",
                   r"\b\d+(?= were never in a released)"),
        figure("schema_families", "actaira.schemas.VERSIONS",
               r"\b\d+(?= versioned contracts)", r"\b\d+(?= contratos versionados)"),
        figure("schema_documents", "src/actaira/schemas/*.json",
               r"\b\d+(?= schema documents)", r"\b\d+(?= documentos de esquema)"),
        figure("schemas_superseded", "actaira.schemas.SUPERSEDED",
               r"\b\d+(?= superseded versions)", r"\b\d+(?= versiones sustituidas)"),
        figure("commands", "cli.build_parser",
               r"\b\d+(?= CLI commands)", r"\b\d+(?= comandos de CLI)"),
        # The ledger sentence's third figure, which the sync script writes
        # through its own regex and the gate never looked at.
        doc_figure("defects_by_note", "docs/defects.json: pinned_by_a_note_instead",
                   r"\b\d+(?= by a written note)"),
        # DEF-122. This one had no row at all: `sync_readme_figures.py` rewrote
        # the whole ledger sentence with a regex of its own, on the argument that
        # the figure "never appears on its own". A second mechanism writing a
        # number the table does not know about is how that sentence came to carry
        # markup which made every OTHER figure in it unmatchable.
        doc_figure("defects_pinned", "docs/defects.json: pinned_by_a_named_test",
                   r"\b\d+(?= pinned by a named test)"),
        # DEF-121. The page said "all fixed", hand-written prose the sync script
        # captured and re-emitted without ever checking it. A ledger that can
        # only say "all" is a ledger that can only hold closed defects.
        doc_figure("defects_open", "docs/defects.json: entries with fixed false",
                   r"\b\d+(?= still open)"),
        measured_only(
            "design_notes", "docs/DESIGN.md table",
            "Neither README has stated a design-note count since phase A rewrote "
            "both around what the seven commands do. The figure kept an English "
            "and a Spanish pattern anyway, matching nothing in either page, and "
            "the bilingual check was satisfied because the absence was symmetric.",
        ),
    ]

# The spelled-out forms of figures this table owns. A number written as a word
# is one no regex can keep current, and every stale figure the 2.2.0 audit
# found in prose was written as a word: "sixty-six defects", "seven schemas",
# "eight capability rules", "sesenta y seis", "siete esquemas". The gate
# refuses them rather than trying to parse them.
FORBIDDEN_NUMBER_WORDS = {
    "README.md": (
        "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
        "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen",
        "eighteen", "nineteen", "twenty", "thirty", "forty", "fifty", "sixty",
    ),
    "README.es.md": (
        "uno", "una", "dos", "tres", "cuatro", "cinco", "seis", "siete", "ocho", "nueve",
        "diez", "once", "doce", "trece", "catorce", "quince", "dieciséis", "diecisiete",
        "dieciocho", "diecinueve", "veinte", "treinta", "cuarenta", "cincuenta", "sesenta",
    ),
}

# What each number word must not be followed by: nouns this table once counted
# and no longer does. `one runtime dependency` is fine and `seven schemas` is
# not, so the check is on the pair rather than on the word.
#
# This list is ADDITIVE ONLY, and that is the whole of its job. The nouns a
# figure actually anchors on are read off the patterns by `anchor_nouns`, so
# there is one definition of "a noun this table counts" and not two. What is
# left here is the retired ones - `connectors`, `executable controls`,
# `obligations`, `corpus artifacts`, `fuzz targets` - whose figures went to tag
# v2.3.0 and whose spelled-out forms must still not come back.
#
# Rule 10. It was not additive before, and that is how `lines of Python` came
# to be a figure the markup guard had never looked at: the guard read this
# hand-typed tuple, `lines` was never in it, and the shape that unhooks a
# figure went unreported on the one figure most likely to be rewrapped.
RETIRED_NOUNS = {
    "README.md": (
        "defects", "mechanisms", "distinct mechanisms", "schemas",
        "connectors", "executable controls", "obligations", "design notes",
        "corpus artifacts", "fuzz targets",
    ),
    "README.es.md": (
        "defectos", "mecanismos", "mecanismos distintos", "esquemas",
        "conectores", "controles ejecutables", "obligaciones",
        "notas de diseño", "artefactos de corpus", "objetivos de fuzz",
    ),
}

def anchor_nouns(readme: str) -> tuple[str, ...]:
    """The words each pattern for this page anchors on, read off the patterns.

    A pattern in this table looks like `\\b[\\d,.]+(?= lines of Python)`, so the
    noun it depends on is written there already. Reading it back is the only
    way the two guards below can be about the same thing as the sync script.
    Rejected: a second hand-typed tuple, which is what `COUNTED_NOUNS` was and
    what let `lines` stay outside both guards for three releases.
    """
    nouns: list[str] = []
    for figure in figures():
        pattern = figure.patterns.get(readme)
        if pattern is None:
            continue
        match = re.search(r"\(\?= (.+?)\)$", pattern)
        if match is None:
            # A figure anchored some other way - the version string looks
            # ahead at `**`, not at a noun. Nothing to guard, and saying so
            # here is cheaper than a reader wondering which ones are missing.
            continue
        nouns.append(match.group(1).removesuffix(r"\b"))
    return tuple(dict.fromkeys(nouns))


def _guarded_nouns(readme: str) -> tuple[str, ...]:
    """Every noun a number must not be separated from, on this page."""
    return tuple(dict.fromkeys(anchor_nouns(readme) + tuple(RETIRED_NOUNS.get(readme, ()))))


def number_word_problems(readme: str, text: str) -> list[str]:
    """Figures written as words, where this table owns the figure."""
    problems: list[str] = []
    # The two word lists are per language, and `docs/ENGINEERING.md` is an
    # English document with no list of its own: it carries four figures and no
    # prose this rule is about. No list means nothing to check, not a crash.
    words = "|".join(FORBIDDEN_NUMBER_WORDS.get(readme, ()))
    nouns = "|".join(re.escape(noun) for noun in sorted(_guarded_nouns(readme), key=len, reverse=True))
    if not words or not nouns:
        return problems
    for match in re.finditer(rf"\b({words})[\s-]+({nouns})\b", text, re.IGNORECASE):
        problems.append(f"{readme}: {match.group(0)!r} - write the figure as digits so it can be synced")
    return problems

def markup_split_problems(readme: str, text: str) -> list[str]:
    r"""Figures this table owns that markup has separated from their noun.

    Every pattern above anchors on the words that follow the number, so a
    figure only stays current while the digits and the noun are adjacent.
    Put anything between them and the regex stops matching: the sync script
    never writes it, the gate never compares it, and the figure sits there
    going quietly out of date while every other number on the page is
    maintained.

    That is not hypothetical. The hero of both READMEs carried

        <td align="center"><b>3,226</b><br><sub>tests</sub></td>

    for a release in which the suite collected 3,233, three lines above a
    `make test  # 3,233 tests` that was correct, because the first was
    invisible to `\b[\d,.]+(?= tests\b)` and the second was not.

    So the rule is: **between a figure and the noun it counts, exactly one
    space**. `**80 documented rules**` is fine and `**80** documented rules`
    is not, which looks pedantic until you notice that the second one is
    exactly the shape that drifted.

    "Exactly one space" and not "only whitespace" because every pattern above
    spells the gap as a literal space, so a line break unhooks a figure just
    as completely as a `<br>` does. That is how a rewrapped paragraph on
    README.md left `lines of Python` on its own line while README.es.md, whose
    wrap fell elsewhere, stayed current.
    """
    problems: list[str] = []
    guarded = _guarded_nouns(readme)
    if not guarded:
        # Rule 11: a guard with nothing to look for has not passed, it has
        # stopped looking. Every guarded page states at least one figure.
        raise ValueError(f"{readme} is guarded by this table and no figure anchors on a noun in it")
    nouns = "|".join(re.escape(noun) for noun in sorted(guarded, key=len, reverse=True))
    # What may sit between a figure and its noun and still be markup rather
    # than prose: whitespace, Markdown emphasis, a table pipe, or a complete
    # HTML tag. Nothing else. Prose in between means the two are not a pair
    # and there is nothing to report, which is what keeps "7 of the 21
    # obligations" and a table header two rows away out of this.
    separator = r"(?:\s|[*`|]|</?[A-Za-z][^>]*>)"
    pattern = rf"(\d[\d,.]*)({separator}{{1,60}}?)({nouns})\b"
    for match in re.finditer(pattern, text):
        between = match.group(2)
        if not set(between) & set("*`|<"):
            # Whitespace, which is the form the patterns read - but every
            # pattern above spells it as one literal space, so a line break or
            # a run of spaces unhooks the figure exactly as markup does. That
            # is not the same defect twice: a figure left at the end of one
            # line with its noun at the start of the next is what a paragraph
            # rewrap produces, and it produced it on this page. A figure stated
            # twice hides it, because the other occurrence keeps the match
            # count non-zero and the gate green.
            if between == " ":
                continue
            problems.append(
                f"{readme}: {match.group(0)!r} puts {between!r} between the figure "
                "and the noun it counts. Every pattern in this table spells that "
                "gap as one space, so a line break or a double space is as "
                "invisible to it as markup. Keep the figure and its noun on one "
                "line, separated by one space."
            )
            continue
        problems.append(
            f"{readme}: {match.group(0)!r} puts {between!r} between the figure and "
            "the noun it counts, so no pattern in this table can keep it current. "
            "Put the markup around the whole phrase instead."
        )
    return problems
