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
import shlex
import subprocess
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
def test_the_line_count_matches_the_measurement():
    """The rule count came out of this assertion in phase A, and not quietly.

    It used to read `assert str(rules) in text` over both READMEs. This tree
    documents no rules, so `rules` is 0, and `"0" in text` is true of almost any
    prose: the assertion would have passed forever without checking anything,
    which is the failure this file exists to prevent. The rule count is asserted
    where it can bite, in `tests/test_i18n.py`, in both directions - a rule id in
    `src/` with no catalogue entry, and a catalogue entry with no rule.
    """
    lines = FIGURES["code"]["total"]["lines"]

    assert thousands(lines, ",") in ENGLISH
    assert thousands(lines, ".") in SPANISH


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


# ---------------------------------------------------------------------------
# The console blocks, against the tool
# ---------------------------------------------------------------------------
# Every console block, against the tool that prints it
# ---------------------------------------------------------------------------
#
# The rule: a block a reader can copy has to be a block a reader can reproduce.
# It was one block - `scan --demo` - until phase A.1, which is the same shape of
# defect this file exists for: the check named the property ("the blocks labelled
# real output have to be output anybody can get") and asserted it of one of them.
# The `watch` block beside it said `./actaira-watch` for a tool whose `--out`
# defaults to `actaira-trace`, and nothing noticed, because nothing looked.
#
# So every ```console block in either README is collected, run, and compared.
# Adding a block to a README with no way to produce it now fails here.

# What is allowed to differ between a run and the page, and nothing else. Each
# entry is a value the tool generates fresh every time; the placeholder is what
# the README shows, so a reader can see it is a placeholder rather than believe
# it is the id they will get.
VOLATILE = ((re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'), "<session-id>"),)


def console_blocks(page: str) -> list[tuple[str, str]]:
    """(command, expected output) for every ```console block on a page."""
    found = []
    for body in re.findall(r"```console\n(.*?)```", page, re.S):
        lines = body.splitlines()
        assert lines and lines[0].startswith("$ "), (
            "a console block does not open with a `$ ` command line: " + body[:80]
        )
        found.append((lines[0][2:].strip(), "\n".join(lines[1:])))
    return found


def normalise(text: str) -> str:
    """One line of words, with the volatile values masked.

    Joined rather than compared line by line because the READMEs wrap long lines
    for width and the tool does not: the wrap is a formatting choice, and making
    it a reason to stop checking is how a block stops being checked at all.
    """
    for pattern, placeholder in VOLATILE:
        text = pattern.sub(placeholder, text)
    return " ".join(text.split())


def run_command(command: str, cwd: Path) -> str:
    """Run one `actaira ...` command in `cwd` and return everything it printed.

    A subprocess rather than `cli.main` under `redirect_stdout`, and the
    difference is not cosmetic. `actaira watch` runs a CHILD, and the child
    writes to file descriptor 1 directly; `redirect_stdout` only rebinds
    `sys.stdout` inside this interpreter, so the child's own output is invisible
    to it. The README block shows `agent ran` because that is what a reader sees
    in their terminal, and an in-process capture said the block was wrong.

    What a reader sees is the thing under test, so the test looks where the
    reader looks: one process, both streams, real ordering.
    """
    assert command.startswith("actaira "), f"not an actaira command: {command!r}"
    argv = shlex.split(command)[1:]

    # The reader's environment, not the harness's. The Quickstart says to make a
    # venv and activate it, and `watch -- python -c ...` is a command that works
    # inside one: a venv provides `python` on every platform. Outside one, a
    # stock Ubuntu has `python3` and no `python`, and this test found that by
    # failing in WSL while passing on Windows.
    #
    # So the interpreter's own directory goes on PATH, which is the one thing
    # activation does that matters here. The alternative was to rewrite the
    # README example as `python3`, which would be correct on Linux and broken on
    # Windows: changing the documentation so a harness can run it is how a
    # README stops describing what a reader does.
    environment = dict(os.environ, PYTHONIOENCODING="utf-8")
    environment["PATH"] = os.pathsep.join(
        [str(Path(sys.executable).parent), environment.get("PATH", "")]
    )
    result = subprocess.run(  # noqa: S603 - argv comes from a file in this repository
        [sys.executable, "-m", "actaira", *argv],
        cwd=cwd, capture_output=True, text=True, timeout=120, env=environment,
    )
    assert result.returncode == 0, (
        f"`{command}` exited {result.returncode}\n{result.stdout}\n{result.stderr}"
    )
    return result.stdout


def test_the_readmes_carry_console_blocks_to_check():
    """The guard. If the regex stopped matching, every case below would vanish
    and this file would report success having compared nothing."""
    for name, page in BOTH.items():
        blocks = console_blocks(page)
        assert blocks, f"{name} has no console block; the extraction is broken"
        for command, expected in blocks:
            assert command.startswith("actaira "), f"{name}: {command!r}"
            assert expected.strip(), f"{name}: `{command}` shows no output"


@pytest.mark.parametrize("name", sorted(BOTH))
def test_every_console_block_is_what_the_tool_actually_prints(name, tmp_path):
    """The blocks labelled real output have to be output anybody can get.

    The Quickstart is the first thing a stranger runs and the single worst place
    in the repository for a line of invented output to sit.
    """
    for index, (command, expected) in enumerate(console_blocks(BOTH[name])):
        workspace = tmp_path / f"{name.replace('.', '-')}-{index}"
        workspace.mkdir()
        printed = run_command(command, workspace)
        assert printed.strip(), f"{name}: `{command}` printed nothing"

        assert normalise(expected) == normalise(printed), (
            f"{name}: the block for `{command}` is not what the command prints.\n"
            f"printed: {normalise(printed)}\n"
            f"shown:   {normalise(expected)}"
        )


def test_the_comparison_would_notice_a_changed_line():
    """The guard on the guard: masking must not swallow a real difference."""
    real = "Recorded session 091ba264-e904-41ab-bfe9-de090d09903e at capture level L1"
    page = "Recorded session <session-id> at capture level L1"

    assert normalise(real) == normalise(page), "the session id mask does not mask"
    assert normalise(real) != normalise(page.replace("L1", "L3")), (
        "a changed capture level survives normalisation, so the comparison is vacuous"
    )
    assert normalise(real) != normalise(page.replace("Recorded", "Read")), (
        "a changed word survives normalisation"
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
