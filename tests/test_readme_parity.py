"""The two READMEs have to say the same thing.

A repository with a translated README acquires a second way to be wrong: the
English one gets a correction and the Spanish one keeps the old figure, and a
Spanish-speaking reader is shown a number that stopped being true. That has
happened here, which is why this file exists.

What is checked, precisely, because a test that claims more than it does is
the same defect one level up: that both files have the same sequence of
heading LEVELS (not the same heading text, which differs by language), the
same images in the same order, links that resolve, and the figures that
`make figures` measured. Prose is left alone on purpose, and so are the
comparison tables: a translation that tracks the English sentence by sentence
reads like a translation, and the benchmark tables are checked by the
benchmark's own tests instead.

The no-dash rule is here too. Both files use commas and colons rather than em
or en dashes, which is a house style for documents in this project and is
easier to keep with a test than with discipline.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

from conftest import REPO_ROOT

ENGLISH = (Path(REPO_ROOT) / "README.md").read_text(encoding="utf-8")
SPANISH = (Path(REPO_ROOT) / "README.es.md").read_text(encoding="utf-8")
BOTH = {"README.md": ENGLISH, "README.es.md": SPANISH}


def headings(text: str) -> list[str]:
    return [line.split(" ", 1)[0] for line in text.splitlines() if line.startswith("#")]


def images(text: str) -> list[str]:
    return re.findall(r'(?:!\[[^\]]*\]\(|<img src=")(docs/img/[^")\s]+)', text)


def image_slots(text: str) -> list[str]:
    """Image references with the language suffix removed.

    A localised README should show the localised screenshot: pointing the
    Spanish page at an English screenshot of the interface is a worse document,
    and this test previously forced exactly that. What the test means to check
    is that both files illustrate the same things in the same order, so
    `06-governance-es.png` and `04-governance.png` are the same slot and the
    comparison is made on the slot rather than on the file name.
    """
    return [re.sub(r"^\d+-|-es(?=\.)|\.(png|svg)$", "", name.split("/")[-1]) for name in images(text)]


@pytest.mark.parametrize("name", sorted(BOTH))
def test_no_em_or_en_dashes(name):
    text = BOTH[name]
    assert "—" not in text, f"{name} contains an em dash"
    assert "–" not in text, f"{name} contains an en dash"


def test_the_two_files_have_the_same_section_structure():
    assert headings(ENGLISH) == headings(SPANISH), (
        "one README has gained or lost a section the other does not have"
    )


def test_the_two_files_show_the_same_images():
    assert image_slots(ENGLISH) == image_slots(SPANISH)


@pytest.mark.parametrize("name", sorted(BOTH))
def test_every_image_referenced_exists(name):
    for relative in images(BOTH[name]):
        assert (Path(REPO_ROOT) / relative).exists(), f"{name} references a missing image: {relative}"


@pytest.mark.parametrize("name", sorted(BOTH))
def test_every_repository_link_resolves(name):
    """Links into the repository, which are the ones a move can break.

    External URLs are not checked: a test that needs the network is a test
    that fails for reasons that have nothing to do with this repository.
    """
    targets = re.findall(r"\]\((?!https?:|#)([^)#]+)", BOTH[name])
    for target in targets:
        assert (Path(REPO_ROOT) / target).exists(), f"{name} links to a missing path: {target}"


def test_the_headline_figures_are_the_ones_the_harnesses_measured():
    """The numbers at the top, which are the ones a reader remembers.

    These were three hardcoded pairs in this file until 2.2.0 closed, which is
    a second hand-maintained copy rather than a source: the test asserted the
    README still said what the test said, and would have kept passing while
    both drifted from the harness together. `evals/benchmark.json` is tracked
    now, so all three derive, and `scripts/figures_contract.py` owns them
    alongside every other figure the prose may state.
    """
    import sys

    sys.path.insert(0, str(Path(REPO_ROOT) / "scripts"))
    from figures_contract import derive  # noqa: PLC0415

    value = derive()
    headline = (
        (f"{value['unknown_gadgets_strict']} of {value['unknown_gadgets_total']}",
         f"{value['unknown_gadgets_strict']} de {value['unknown_gadgets_total']}"),
        (f"{value['marking_naive_survived']} of {value['marking_naive_trials']}",
         f"{value['marking_naive_survived']} de {value['marking_naive_trials']}"),
        (f"{value['marking_aware_survived']} of {value['marking_aware_trials']}",
         f"{value['marking_aware_survived']} de {value['marking_aware_trials']}"),
    )
    for english, spanish in headline:
        assert english in ENGLISH, f"README.md lost the headline figure {english!r}"
        assert spanish in SPANISH, f"README.es.md lost the headline figure {spanish!r}"


# ---------------------------------------------------------------------------
# Figures against the files that produce them
# ---------------------------------------------------------------------------
#
# Hand-syncing these was the actual failure mode. Every time a defect was
# fixed the count moved, and the READMEs were updated by hand in two languages
# and two places each; twice they were not. `figures.json` is written by
# `make figures` from the repository itself, so these assertions are the
# README checking itself against a measurement rather than against memory.

FIGURES_PATH = Path(REPO_ROOT) / "figures.json"
FIGURES = json.loads(FIGURES_PATH.read_text(encoding="utf-8")) if FIGURES_PATH.exists() else {}


def thousands(value: int, separator: str) -> str:
    return f"{value:,}".replace(",", separator)


@pytest.mark.skipif(not FIGURES, reason="figures.json is absent; run make figures")
def test_the_defect_counts_match_the_measured_ledger():
    """The ledger's counts, where they now live.

    They used to be asserted against both READMEs. They are not on a README
    any more: a defect count says how hard the tool has been looked at, which
    is a fact about the engineering rather than about the product, and a
    landing page is not where a reader should meet it.

    Moving a figure out of the guarded set would have been the wrong half of
    that change, because a figure nobody compares is a figure that goes stale.
    `scripts/figures_contract.py` guards `docs/ENGINEERING.md` too, and this
    asserts the same thing about the page they moved to.
    """
    defects = FIGURES["defects"]
    engineering = (Path(REPO_ROOT) / "docs" / "ENGINEERING.md").read_text(encoding="utf-8")
    assert f"**{defects['defects']}**" in engineering, (
        f"docs/ENGINEERING.md must state {defects['defects']} defects, the count make figures measured"
    )
    assert f"**{defects['pinned_by_a_named_test']}**" in engineering

    # And they must not have crept back onto a landing page.
    for name, text in BOTH.items():
        assert "defects have been found" not in text, (
            f"{name} states a defect count again; that page reports what the tool "
            "measures, not how hard it has been looked at"
        )


@pytest.mark.skipif(not FIGURES, reason="figures.json is absent; run make figures")
def test_the_test_count_matches_what_pytest_collects():
    collected = FIGURES["tests"]["collected"]
    assert thousands(collected, ",") in ENGLISH
    assert thousands(collected, ".") in SPANISH


@pytest.mark.skipif(not FIGURES, reason="figures.json is absent; run make figures")
def test_the_line_count_and_rule_count_match_the_measurement():
    lines = FIGURES["code"]["total"]["lines"]
    rules = FIGURES["catalog"]["rules"]
    assert thousands(lines, ",") in ENGLISH
    assert thousands(lines, ".") in SPANISH
    for text in (ENGLISH, SPANISH):
        assert str(rules) in text


@pytest.mark.skipif(not FIGURES, reason="figures.json is absent; run make figures")
def test_the_corpus_size_matches_the_built_corpus():
    cases = FIGURES["corpus"]["cases"]
    for text in (ENGLISH, SPANISH):
        assert str(cases) in text


# ---------------------------------------------------------------------------
# The pictures, against the code and the measurements that produce them
# ---------------------------------------------------------------------------
# Every figure scripts/diagrams.py writes. Listed here rather than imported
# so that adding a generator without committing its output fails.
DIAGRAMS = (
    "banner.svg",
    "overview.svg",
    "pipeline.svg",
    "architecture.svg",
    "coverage-ladder.svg",
    "marking-survival.svg",
)


@pytest.mark.parametrize("name", DIAGRAMS)
def test_every_generated_diagram_is_committed(name):
    assert (Path(REPO_ROOT) / "docs" / "img" / name).is_file(), (
        f"{name} is referenced by the READMEs and missing; run `make diagrams`"
    )


def test_the_survival_chart_shows_the_figures_the_harness_measured():
    """The picture cannot say something the measurement does not.

    This repository has published a stale figure twice, and a picture is the
    worst place for it because a reader has no way to check it against the
    prose. The chart is generated from `evals/marking/results.json`, so this
    test only has to prove the generated file agrees with that file today.
    """
    results_path = Path(REPO_ROOT) / "evals" / "marking" / "results.json"
    if not results_path.is_file():
        pytest.skip("evals/marking/results.json is absent; run make eval-marking")
    measured = json.loads(results_path.read_text(encoding="utf-8"))
    chart = (Path(REPO_ROOT) / "docs" / "img" / "marking-survival.svg").read_text(encoding="utf-8")
    naive = measured["naive_pipeline"]
    aware = measured["metadata_aware_pipeline"]
    assert f'{naive["survived"]} of {naive["trials"]}' in chart
    assert f'{aware["survived"]} of {aware["trials"]}' in chart
    for text in (ENGLISH, SPANISH):
        assert f'{naive["survived"]} of {naive["trials"]}'.replace(" of ", " de ") in text or (
            f'{naive["survived"]} of {naive["trials"]}' in text
        )


def test_the_coverage_ladder_shows_the_tier_counts_the_catalogue_holds():
    from actaira.governance.catalog import ALL_OBLIGATIONS, Checkability

    chart = (Path(REPO_ROOT) / "docs" / "img" / "coverage-ladder.svg").read_text(encoding="utf-8")
    for tier in Checkability:
        count = sum(1 for o in ALL_OBLIGATIONS if o.checkability is tier)
        assert f">{count}</text>" in chart, (
            f"the ladder does not show {count} for {tier.value}; run `make diagrams`"
        )
        for text in (ENGLISH, SPANISH):
            assert f"| **{count}** |" in text, (
                f"a README tier row lost the count {count} for {tier.value}"
            )


# ---------------------------------------------------------------------------
# The console blocks, against the tool
# ---------------------------------------------------------------------------
def test_the_example_fixtures_build_to_the_digests_the_readmes_print():
    """The blocks labelled "real output" have to be output anybody can get.

    Before 2.2.0 they were produced from an ad-hoc `models/` directory that is
    not in this repository, so the digests in them were unreproducible: a
    reader could run the command and get different bytes, with nothing saying
    why. `docs/CONCEPTS.md` now carries the recipe, this runs it, and the two
    digests it produces are asserted against the two the READMEs show.
    """
    import hashlib
    import shutil
    import subprocess
    import tempfile

    # The recipe is a bash block that calls `python3`. `/bin/bash` was
    # hardcoded, which made this test - the one that proves the READMEs'
    # digests are reproducible - unrunnable anywhere that keeps bash somewhere
    # else. Both are looked up now, and the interpreter running the suite is
    # put in front of whatever `python3` would otherwise resolve to, so the
    # digests are produced by the Python this repository is being tested with
    # rather than by whichever one happens to be first on PATH.
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("the fixture recipe is a bash block and this machine has no bash")

    recipe = re.search(
        r"## The two files every example uses.*?```bash\n(.*?)```",
        (Path(REPO_ROOT) / "docs" / "CONCEPTS.md").read_text(encoding="utf-8"),
        re.S,
    )
    assert recipe, "docs/CONCEPTS.md no longer carries the fixture recipe"

    with tempfile.TemporaryDirectory() as scratch:
        shim = Path(scratch) / "bin"
        shim.mkdir()
        (shim / "python3").write_text(
            f'#!/bin/sh\nexec "{Path(sys.executable).as_posix()}" "$@"\n', encoding="utf-8"
        )
        (shim / "python3").chmod(0o755)
        environment = dict(os.environ, PATH=os.pathsep.join([str(shim), os.environ.get("PATH", "")]))
        subprocess.run(  # noqa: S603 - a block from a file in this repository
            [bash, "-c", recipe.group(1)], cwd=scratch, check=True,
            capture_output=True, timeout=120, env=environment,
        )
        built = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()[:16]
            for path in sorted((Path(scratch) / "models").iterdir())
        }

    assert set(built) == {"clean.safetensors", "trojan.pkl"}, built
    for name, digest in built.items():
        for readme, text in BOTH.items():
            assert f"sha256:{digest}" in text, (
                f"{readme} prints a digest for {name} that the recipe does not produce; "
                f"the recipe gives sha256:{digest}"
            )


def test_the_localised_screenshots_are_not_the_same_image():
    """DEF-108. Two files claiming to show two languages have to differ.

    `scripts/screenshots.py` selected the language only when it was not
    English, on the assumption that an unprimed page shows English - and it
    does not, it follows `navigator.language`. So every capture came out in
    whatever language the capturing browser preferred, and the two governance
    pairs were byte-identical: one README showed a screenshot in the other's
    language, and the only thing that would have noticed was a reader who
    speaks both.

    Asserted on the bytes rather than on the generator, because the generator
    is not what the READMEs display.
    """
    import hashlib

    images = Path(REPO_ROOT) / "docs" / "img"
    pairs = [
        ("04-governance.png", "06-governance-es.png"),
        ("05-governance-dark.png", "08-governance-dark-es.png"),
    ]
    for english, spanish in pairs:
        left, right = images / english, images / spanish
        assert left.is_file() and right.is_file(), f"{english} or {spanish} is missing"
        assert hashlib.sha256(left.read_bytes()).digest() != hashlib.sha256(right.read_bytes()).digest(), (
            f"{english} and {spanish} are the same image. They are the same panel in "
            "two languages; if they are identical the capture never switched language, "
            "and one README is showing the other's screenshot."
        )


# ---------------------------------------------------------------------------
# The guard that keeps a figure visible to the contract
# ---------------------------------------------------------------------------
#
# Every pattern in `scripts/figures_contract.py` anchors on the words that
# follow the number, so a figure is only maintainable while the digits and the
# noun are adjacent. Put markup between them and the sync script never writes
# it and the gate never compares it: the figure is not wrong yet, it is simply
# no longer connected to anything, and it goes stale at the next measurement
# with nothing to notice.
#
# That is not a hypothetical. Both READMEs carried a hero strip reading
# `<b>3,226</b><br><sub>tests</sub>` for a release whose suite collected
# 3,233, three lines above a `make test  # 3,233 tests` that was correct,
# because the first was invisible to the pattern and the second was not.
#
# The guard that closes it is only worth having if it can fail, so these
# assert both directions.


def _markup_split(readme: str, text: str):
    import sys

    sys.path.insert(0, str(Path(REPO_ROOT) / "scripts"))
    from figures_contract import markup_split_problems  # noqa: PLC0415

    return markup_split_problems(readme, text)


@pytest.mark.parametrize("name", sorted(BOTH))
def test_no_figure_is_separated_from_its_noun_by_markup(name):
    assert _markup_split(name, BOTH[name]) == []


@pytest.mark.parametrize(
    "broken",
    [
        '<td align="center"><b>3,226</b><br><sub>tests</sub></td>',
        "**80** documented rules",
        "| **15** | executable controls |",
        "`21` obligations",
    ],
)
def test_the_markup_guard_catches_a_figure_it_cannot_keep_current(broken):
    """The shapes that hide a figure from the contract, and must be refused."""
    assert _markup_split("README.md", broken), (
        f"{broken!r} puts markup between a figure and its noun, which is the shape "
        "no pattern in the table can match, and the guard did not report it"
    )


@pytest.mark.parametrize(
    "fine",
    [
        "**80 documented rules**",
        "make test            # 3,233 tests",
        "7 of the 21 obligations are organizational",
        "| Tier | What it means | Obligations |",
    ],
)
def test_the_markup_guard_leaves_a_usable_figure_alone(fine):
    """The forms the patterns can read, which must not be reported.

    A guard that fires on the correct shape is a guard people route around.
    """
    assert _markup_split("README.md", fine) == []
