"""The gate itself: it has to pass, and it has to be able to fail.

Design note D-180. A consistency gate that cannot fail is a green tick with
nothing behind it, and this repository has had the exact drift the gate looks
for - a stale figure, a stale threat model, a version with no changelog entry.
So each check is exercised against a working tree that has been broken on
purpose, in a copy.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import REPO_ROOT

SCRIPT = Path(REPO_ROOT) / "scripts" / "release_check.py"


def run(cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(cwd / "scripts" / "release_check.py")],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=600,
    )


@pytest.fixture(scope="module")
def working_tree(tmp_path_factory) -> Path:
    """A copy of the repository, so a broken check cannot break the checkout.

    Copied rather than mutated in place because these tests edit CHANGELOG.md
    and figures.json, and a test that corrupts the working tree when it fails
    partway through is worse than no test.
    """
    destination = tmp_path_factory.mktemp("tree") / "seamark"
    shutil.copytree(
        REPO_ROOT,
        destination,
        ignore=shutil.ignore_patterns(
            "__pycache__", ".git", "*.pyc", ".pytest_cache", "evals/artifacts", "fuzz/runs",
            # A coverage data file is a record of a session in ANOTHER tree:
            # it holds absolute paths, and `coverage json` over it here either
            # reports about files somewhere else or cannot find them at all.
            # `figures.py` is loud about a data file it cannot read, which is
            # right - a broken measurement is not an absent one - so the copy
            # must not carry one.
            ".coverage", ".coverage.*",
        ),
    )
    return destination


def test_the_gate_passes_on_this_repository(working_tree):
    result = run(working_tree)

    assert result.returncode == 0, result.stdout
    match = re.search(r"all (\d+) checks passed", result.stdout)
    assert match, result.stdout
    # Counted from the script rather than written here. A literal would make
    # adding a check fail this test, which is the treadmill D-181 removed from
    # the figure check - and the thing worth asserting is that every check ran
    # and none failed, not that there are exactly nine of them.
    assert int(match.group(1)) == result.stdout.count("  ok    ")


def test_a_version_with_no_changelog_entry_fails(working_tree, tmp_path):
    """The drift the gate found on its own first run: 2.0.0 was released and
    this file never got an entry."""
    broken = tmp_path / "no-changelog"
    shutil.copytree(working_tree, broken)
    changelog = broken / "CHANGELOG.md"
    from seamark import __version__

    changelog.write_text(
        changelog.read_text(encoding="utf-8").replace(f"[{__version__}]", "[9.9.9]"), encoding="utf-8"
    )

    result = run(broken)

    assert result.returncode == 1
    assert "CHANGELOG.md has no entry" in result.stdout


def test_a_stale_figure_fails(working_tree, tmp_path):
    """The drift that happened twice, and the second time it was the defect
    count itself."""
    broken = tmp_path / "stale-figures"
    shutil.copytree(working_tree, broken)
    figures = json.loads((broken / "figures.json").read_text(encoding="utf-8"))
    figures["tests"]["collected"] = 1
    (broken / "figures.json").write_text(json.dumps(figures), encoding="utf-8")

    result = run(broken)

    assert result.returncode == 1
    assert "Run `make figures`" in result.stdout


def test_an_undocumented_rule_fails(working_tree, tmp_path):
    """A rule that can appear in a SARIF document and is in no table is a rule
    whose link goes nowhere."""
    broken = tmp_path / "undocumented-rule"
    shutil.copytree(working_tree, broken)
    for lang in ("en", "es"):
        path = broken / "src" / "seamark" / "i18n" / f"{lang}.json"
        catalogue = json.loads(path.read_text(encoding="utf-8"))
        catalogue["rules"]["ACT-NEW-001"] = "a rule nobody documented"
        path.write_text(json.dumps(catalogue, ensure_ascii=False), encoding="utf-8")

    result = run(broken)

    assert result.returncode == 1
    assert "ACT-NEW-001" in result.stdout


def test_a_rule_with_no_spanish_text_fails(working_tree, tmp_path):
    """The normal fate of a second language is to rot. This is what stops it."""
    broken = tmp_path / "untranslated"
    shutil.copytree(working_tree, broken)
    path = broken / "src" / "seamark" / "i18n" / "en.json"
    catalogue = json.loads(path.read_text(encoding="utf-8"))
    catalogue["rules"]["ACT-NEW-002"] = "english only"
    path.write_text(json.dumps(catalogue, ensure_ascii=False), encoding="utf-8")

    result = run(broken)

    assert result.returncode == 1
    assert "no Spanish text" in result.stdout


def test_a_second_copy_of_a_schema_version_fails(working_tree, tmp_path):
    """A version written anywhere but the registry is a second copy.

    This used to plant a disagreement between `coverage-v1.json` and
    `seamark.coverage.SCHEMA_VERSION` and assert the gate refereed between them.
    Phase A removed the referee along with the second copies: the version lives
    in `schemas.VERSIONS`, `trace/model.py` reads it, and the check now fails on
    a version literal under `src/` rather than on two that disagree.

    So the planted defect moved with it. A literal is written back into a module
    that had stopped writing one - which is exactly how the second copy would
    return - and the gate has to name the file and the line.
    """
    broken = tmp_path / "second-copy"
    shutil.copytree(working_tree, broken)
    path = broken / "src" / "seamark" / "trace" / "model.py"
    source = path.read_text(encoding="utf-8")
    planted = source.replace(
        'SCHEMA_VERSION = schemas.VERSIONS["trace"]',
        'SCHEMA_VERSION = "trace/v3"',
    )
    assert planted != source, "the reader no longer takes its version from the registry"
    path.write_text(planted, encoding="utf-8")

    result = run(broken)

    assert result.returncode == 1
    assert "trace/v3" in result.stdout
    # Separator-agnostic: the gate prints a path relative to the tree it ran in,
    # and that is a backslash on Windows.
    assert "model.py" in result.stdout


def test_a_command_the_documentation_never_mentions_fails(working_tree, tmp_path):
    """A command nobody can find is a command nobody uses.

    The index lived in `docs/CONCEPTS.md` from 2.2.0 until phase A.1 archived
    that page with the scanner. There are four commands now rather than
    twenty-two, so it is back on the pages a reader opens first, and the planted
    defect moved with the check: breaking the English README is enough, because
    all three pages are checked and a gate that only noticed the one the author
    reads is the parity failure this repository already had.
    """
    broken = tmp_path / "undocumented-command"
    shutil.copytree(working_tree, broken)
    page = broken / "README.md"
    page.write_text(
        page.read_text(encoding="utf-8").replace("seamark verify", "seamark verfiy"),
        encoding="utf-8",
    )

    result = run(broken)

    assert result.returncode == 1
    assert "verify" in result.stdout


def test_the_gate_names_what_it_compared_on_every_check(working_tree):
    """A gate whose failure message is "release check failed" gets skipped
    with --no-verify the first time somebody is in a hurry."""
    result = run(working_tree)

    for line in result.stdout.splitlines():
        if line.strip().startswith("ok "):
            continue
    # Every ok line is followed by a detail line saying what was compared.
    oks = [index for index, line in enumerate(result.stdout.splitlines()) if line.strip().startswith("ok ")]
    lines = result.stdout.splitlines()

    assert oks
    for index in oks:
        assert lines[index + 1].strip(), f"check at line {index} passed with no detail"


# ---------------------------------------------------------------------------
# DEF-100: a dead function whose docstring named callers that do not exist
# ---------------------------------------------------------------------------
# `handle_error`, `do_HEAD` and `do_OPTIONS` are overrides on
# `BaseHTTPRequestHandler`. The framework calls them by name from code that is
# not in this repository, so no reference to them can exist here and their
# absence is not evidence of anything. Every other entry would be.
FRAMEWORK_CALLBACKS = frozenset({"do_HEAD", "do_OPTIONS", "handle_error"})

SEARCHED = ("src", "tests", "evals", "fuzz", "scripts")
SEARCHED_SUFFIXES = (".py", ".md", ".json", ".yaml", ".yml", ".toml")


def _identifier_counts() -> dict[str, int]:
    """Every identifier-shaped word in the repository, with how often it appears.

    Tokenising Python and word-splitting everything else, because a function
    can legitimately be reached by name from a string: a registry keyed on
    `"art50"`, a `getattr`, a dispatch table in YAML. Counting words rather
    than resolving calls therefore under-reports rather than over-reports,
    which is the direction a gate like this has to err in.
    """
    import collections
    import io
    import tokenize

    counts: collections.Counter[str] = collections.Counter()
    word = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    for root in SEARCHED:
        for path in (Path(REPO_ROOT) / root).rglob("*"):
            if path.suffix not in SEARCHED_SUFFIXES or "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if path.suffix != ".py":
                counts.update(word.findall(text))
                continue
            try:
                for token in tokenize.generate_tokens(io.StringIO(text).readline):
                    if token.type == tokenize.NAME:
                        counts[token.string] += 1
                    elif token.type == tokenize.STRING:
                        counts.update(word.findall(token.string))
            except (tokenize.TokenError, IndentationError, SyntaxError):
                counts.update(word.findall(text))
    return counts


def test_no_source_function_is_unreachable_from_the_package_or_its_tests():
    """A function nothing names is either dead or wired wrong, and both matter.

    `statecli.record_evidence_for_report` was the case that produced this
    test: nothing called it, and its own docstring said it was "used by
    `scan --state` and by `receipt issue`". `scan` has no `--state` flag and
    `receipt issue` never called it. Dead code is weight; dead code that
    documents a wiring a reader will then look for is a false statement about
    how the tool works, which is the thing this repository is least allowed
    to ship.
    """
    import ast
    import collections

    counts = _identifier_counts()
    definitions: dict[str, list[str]] = collections.defaultdict(list)
    for path in (Path(REPO_ROOT) / "src").rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                definitions[node.name].append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")

    unreachable = {
        name: places
        for name, places in definitions.items()
        if not (name.startswith("__") and name.endswith("__"))
        and name not in FRAMEWORK_CALLBACKS
        and counts[name] <= len(places)
    }
    assert not unreachable, (
        "function(s) never named anywhere but their own definition:\n  "
        + "\n  ".join(f"{name}: {', '.join(places)}" for name, places in sorted(unreachable.items()))
        + "\nDelete them, or wire them to the caller their docstring claims."
    )


def test_an_image_no_document_displays_fails(working_tree, tmp_path):
    """`docs/img/` held two captures of v1.0.0 next to six of v2.2.0.

    They were untracked, on the argument that an image nothing displays is not
    documentation - which was right, and did nothing, because untracked is not
    absent and a delivered copy of the tree carried them anyway. The captures
    that are only a smoke test go to `.screenshots/` now, and this is the check
    that keeps the documentation directory holding documentation.

    Written as a property of the directory, not a list of two file names: any
    file that lands there and is not shown fails, whatever it is called.
    """
    broken = tmp_path / "orphan-image"
    shutil.copytree(working_tree, broken)
    # `docs/img/` is empty at 3.0.0 - the scanner's captures went with the
    # interface they showed - so the fixture creates the directory it is a
    # property of. The check is about what lands there, not about what is
    # there today.
    images = broken / "docs" / "img"
    images.mkdir(parents=True, exist_ok=True)
    (images / "01-welcome.png").write_bytes(b"\x89PNG" + b"\x00" * 32)

    result = run(broken)

    assert result.returncode == 1
    assert "no document displays" in result.stdout
    assert "01-welcome.png" in result.stdout


def test_a_document_pointing_at_a_missing_image_fails(working_tree, tmp_path):
    """The other direction, which is the one a reader meets: a README showing a
    broken image is worse than one showing none."""
    broken = tmp_path / "missing-image"
    shutil.copytree(working_tree, broken)
    # A README that points at an image, and no image: the direction a reader
    # meets. Written here rather than deleted from the tree, because the tree
    # displays none at 3.0.0.
    readme = broken / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8") + "\n![a picture](docs/img/02-inspect.png)\n",
        encoding="utf-8",
    )

    result = run(broken)

    assert result.returncode == 1
    assert "not there" in result.stdout


def test_a_dropped_ignore_rule_for_another_tool_s_run_log_fails(working_tree, tmp_path):
    """DEF-53. `make benchmark` runs fickling as a subprocess, the way a user
    would, and fickling appends its scan output to `safety_results.json` in
    the working directory. That file was tracked, so every benchmark run put
    a 300 KB diff of another tool's output on top of the previous run's.

    The repair was one line in `.gitignore`, and one line is exactly what a
    later rewrite of that file drops without anyone noticing: nothing goes
    wrong until the next benchmark run quietly stages somebody else's JSON.
    So the rule is asserted rather than assumed, and this is the test that
    proves the assertion can fail.
    """
    broken = tmp_path / "unignored-run-log"
    shutil.copytree(working_tree, broken)
    ignore_file = broken / ".gitignore"
    kept = [
        line for line in ignore_file.read_text(encoding="utf-8").splitlines()
        if line.strip() != "safety_results.json"
    ]
    ignore_file.write_text("\n".join(kept) + "\n", encoding="utf-8")

    result = run(broken)

    assert result.returncode == 1
    assert "safety_results.json" in result.stdout
    assert "no longer in .gitignore" in result.stdout


# ---------------------------------------------------------------------------
# The claim blocks, the flags and the exit codes, each planted with its defect
# ---------------------------------------------------------------------------
#
# These four are the check phase S2 asked for by name, and the reason it asked
# is worth keeping in front of whoever reads this file: after phase S1 shipped
# `seamark check`, both READMEs went on publishing "Does not exist" under the
# claim that command implements, for a whole phase, and the gate was green the
# entire time. `readme_documents_the_commands` asked only whether the command was
# NAMED somewhere on the page. What it could not ask is whether what the page
# SAID about it was true.
#
# Each test below reproduces one of the shapes that defect can take, in a copy of
# the tree, and requires the check to refuse it. A check that cannot be made to
# fail is a green tick with nothing behind it, which is what D-180 is about.
#
# The FIRST one runs the whole gate as a subprocess, because it is the one that
# also has to show the check is registered in it: a check nothing calls refuses
# nothing. The rest load the gate module out of the broken copy and call one
# function, and that is a deliberate trade rather than a shortcut. A gate run
# takes about a minute; six of them would put six minutes on every `make test`,
# and what those five are about is whether the PREDICATE bites, which is
# answerable in a tenth of a second. `test_the_gate_passes_on_this_repository`
# and `test_the_gate_names_what_it_compared_on_every_check` keep the
# registration half honest between them.


def gate_of(tree: Path, edits: list[tuple[str, str, str]]):
    """Apply each (file, before, after) edit to `tree` and load its gate module.

    Every plant asserts that it APPLIED. A replacement whose left-hand side has
    moved silently changes nothing, and the test that follows it then passes over
    an unbroken tree - which is the failure mode this whole section exists to
    make unreachable.
    """
    import importlib.util

    for name, before, after in edits:
        page = tree / name
        text = page.read_text(encoding="utf-8")
        assert before in text, f"the plant did not apply to {name}; the text moved"
        page.write_text(text.replace(before, after, 1), encoding="utf-8")

    specification = importlib.util.spec_from_file_location(
        f"gate_under_test_{tree.name}", tree / "scripts" / "release_check.py"
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_a_claim_block_that_says_a_built_command_does_not_exist_fails(working_tree, tmp_path):
    """The phase S1 defect, planted. The Change claim is flipped back to "Does
    not exist" while `seamark diff` is in the parser."""
    broken = tmp_path / "false-claim"
    shutil.copytree(working_tree, broken)
    page = broken / "README.md"
    page.write_text(
        page.read_text(encoding="utf-8").replace(
            "> **Built.** Commands: `seamark diff`, `seamark seal`.",
            "> **Does not exist.** Commands: none.",
            1,
        ),
        encoding="utf-8",
    )

    result = run(broken)

    assert result.returncode == 1, result.stdout
    assert "claim" in result.stdout.lower()
    assert "diff" in result.stdout or "seal" in result.stdout


def test_a_claim_block_with_no_commands_line_fails(working_tree, tmp_path):
    """"If it cannot be checked mechanically, it is not asserted." A block that
    names no command is a claim nothing can resolve against the tree, which is
    exactly the shape the phase S1 sentence had."""
    broken = tmp_path / "unresolvable-claim"
    shutil.copytree(working_tree, broken)
    gate = gate_of(broken, [(
        "README.md",
        "> **Built.** Commands: `seamark check`.",
        "> **Built.** It reads everything worth reading.",
    )])

    with pytest.raises(gate.DriftError) as raised:
        gate.readme_claims_resolve_against_the_tree()

    assert "Commands:" in str(raised.value)


def test_a_command_no_claim_block_accounts_for_fails(working_tree, tmp_path):
    """The other direction, and the one that closes the hole. A command that
    works while no block on the page says its claim is built - or says the
    command implements none of the three - is the drift the gate missed."""
    broken = tmp_path / "unclaimed-command"
    shutil.copytree(working_tree, broken)
    gate = gate_of(broken, [(
        "README.md",
        "> **Built.** Commands: `seamark check`.",
        "> **Built.** Commands: `seamark seal`.",
    )])

    with pytest.raises(gate.DriftError) as raised:
        gate.readme_claims_resolve_against_the_tree()

    assert "check" in str(raised.value)


def test_a_flag_the_command_does_not_have_fails(working_tree, tmp_path):
    """`.pre-commit-hooks.yaml` published `--fail-on high` for two releases in
    which it did not parse. This is that, planted."""
    broken = tmp_path / "invented-flag"
    shutil.copytree(working_tree, broken)
    gate = gate_of(broken, [(
        "README.md", "seamark check --json", "seamark check --fail-on high",
    )])

    with pytest.raises(gate.DriftError) as raised:
        gate.documented_flags_exist()

    assert "--fail-on" in str(raised.value)


def test_an_exit_code_the_cli_does_not_define_fails(working_tree, tmp_path):
    """A pipeline branches on these. A table that publishes a code the CLI never
    returns is a branch nobody will ever take, written down as a promise."""
    broken = tmp_path / "invented-exit-code"
    shutil.copytree(working_tree, broken)
    gate = gate_of(broken, [(
        "docs/COMPATIBILITY.md",
        "| 3 | Nothing objected, and something could not be resolved |",
        "| 3 | Nothing objected, and something could not be resolved |\n"
        "| 7 | Something else entirely |",
    )])

    with pytest.raises(gate.DriftError) as raised:
        gate.exit_codes_are_the_published_ones()

    assert "7" in str(raised.value)


def test_a_package_description_missing_a_command_fails(working_tree, tmp_path):
    """The one sentence a stranger reads before they install. It said "the
    commands this release ships are scan, watch, verify and keygen" for two
    phases after `check` shipped, and nothing compared it with anything."""
    broken = tmp_path / "stale-description"
    shutil.copytree(working_tree, broken)
    gate = gate_of(broken, [(
        "pyproject.toml",
        "Seven commands: check, diff, seal, verify, keygen, scan and watch.",
        "Five commands: check, verify, keygen, scan and watch.",
    )])

    with pytest.raises(gate.DriftError) as raised:
        gate.package_metadata_names_real_commands()

    assert "diff" in str(raised.value) and "seal" in str(raised.value)


def test_a_figure_pattern_that_matches_nothing_fails(working_tree, tmp_path):
    """DEF-122, and the twin that proves the new refusal bites.

    The gate used to `continue` past a pattern that found nothing, so a figure
    could declare a page, live on none, and be reported as neither wrong nor
    missing. Four on `docs/ENGINEERING.md` sat that way under a paragraph
    claiming they were gate-refused, two of them stale by 8 and by 4, and
    `design_notes` declared both READMEs while appearing in neither.

    The break is done in the PROSE and not in the table, because that is the
    direction it happens: somebody rewords a sentence, the lookahead stops
    matching, and nothing says so. Bolding the digits is the exact shape that
    did it - `**136** defects` instead of `136 defects`.
    """
    broken = tmp_path / "unmatchable-pattern"
    shutil.copytree(working_tree, broken)
    page = broken / "docs" / "ENGINEERING.md"
    text = page.read_text(encoding="utf-8")
    before, hit, after = text.partition(" defects have been found")
    assert hit, "the sentence this test breaks is not on the page any more"
    digits = re.search(r"(\d+)$", before)
    assert digits, before[-40:]
    page.write_text(
        before[: digits.start()] + f"**{digits.group(1)}**" + hit + after,
        encoding="utf-8",
    )

    result = run(broken)

    assert result.returncode == 1, result.stdout
    assert "defects declares this page" in result.stdout, result.stdout
    assert "matches nothing in it" in result.stdout, result.stdout


def test_a_figure_on_no_page_says_so_rather_than_keeping_a_dead_pattern(working_tree):
    """The other half of DEF-122: the door the refusal above leaves open.

    A figure that no page states can satisfy the new check in two ways - by
    being written into a page, or by declaring no page at all. The second is
    legitimate and is what `design_notes` needed, so it exists; what it must
    not become is the quiet way to switch the check off for a figure that
    really is published. `measured_only` refuses an empty reason, and every
    figure that declares no page still goes through `figures_match`.
    """
    sys.path.insert(0, str(working_tree / "scripts"))
    for module in ("figures_contract",):
        sys.modules.pop(module, None)
    from figures_contract import figures  # noqa: PLC0415

    stated = [figure for figure in figures() if figure.patterns]
    silent = [figure for figure in figures() if not figure.patterns]

    assert stated, "no figure declares a page; the pattern check would compare nothing"
    assert [figure.name for figure in silent] == ["design_notes"], (
        "a figure stopped declaring a page. That is allowed, and it is also how "
        "the check above gets switched off one figure at a time, so it is "
        "asserted here rather than noticed later"
    )


def test_a_per_file_ignore_for_a_module_that_is_gone_fails(working_tree, tmp_path):
    """The shape ten entries in `pyproject.toml` had after phase A.

    Ruff does not complain about a per-file-ignores key it cannot match: it
    applies nothing and says nothing, so the configuration goes on describing
    a tree that is not there. In a repository whose product is refusing
    exactly that, it was the cheapest possible thing to be caught doing.
    """
    broken = tmp_path / "dead-ignore"
    shutil.copytree(working_tree, broken)
    pyproject = broken / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            '[tool.ruff.lint.per-file-ignores]',
            '[tool.ruff.lint.per-file-ignores]\n"src/seamark/coverage.py" = ["UP042"]',
            1,
        ),
        encoding="utf-8",
    )

    result = run(broken)

    assert result.returncode == 1
    assert "src/seamark/coverage.py" in result.stdout
    assert "not in the tree" in result.stdout


def test_a_manifest_line_pruning_a_directory_that_is_gone_fails(working_tree, tmp_path):
    """`prune evals` and `prune fuzz` outlived the directories by a release.

    setuptools reports it as a warning, and only `make package` would print
    it, and `make package` is deliberately not in `make all`. So the line sat
    there being false in the one file that decides what a stranger downloads.
    """
    broken = tmp_path / "dead-prune"
    shutil.copytree(working_tree, broken)
    manifest = broken / "MANIFEST.in"
    manifest.write_text(
        manifest.read_text(encoding="utf-8") + "\nprune evals\n", encoding="utf-8"
    )

    result = run(broken)

    assert result.returncode == 1
    assert "evals" in result.stdout
    assert "not in the tree" in result.stdout


# ---------------------------------------------------------------------------
# `make figures` has to be a function of the tree
# ---------------------------------------------------------------------------
#
# `python scripts/figures.py && git diff --exit-code` is a CI gate: it catches
# a figure that has drifted from what the code measures. It can only be that
# while running the script twice over one tree produces one answer. It did not:
# `generated_at` was a wall clock and the `git` block followed HEAD, so every
# run left `M docs/FIGURES.md` and `M figures.json` behind and the gate would
# have gone red on every commit, which is the fastest way to have a gate
# deleted.


def _stamp_keeper():
    sys.path.insert(0, str(Path(REPO_ROOT) / "scripts"))
    from figures import keep_the_stamps_when_nothing_was_measured_differently  # noqa: PLC0415

    return keep_the_stamps_when_nothing_was_measured_differently


def test_the_stamp_is_carried_over_when_nothing_was_measured_differently():
    keep = _stamp_keeper()
    existing = {"generated_at": "2026-01-01T00:00:00+00:00", "git": {"commits": 1},
                "code": {"total": {"lines": 10}}}
    measured = {"generated_at": "2026-09-22T12:00:00+00:00", "git": {"commits": 2},
                "code": {"total": {"lines": 10}}}

    keep(measured, existing)

    assert measured["generated_at"] == existing["generated_at"]
    assert measured["git"] == existing["git"]


def test_the_stamp_moves_as_soon_as_one_measured_figure_moves():
    """The twin. A carry-over that never stops carrying would freeze the file
    against the tree, which is a worse defect than the one it replaced."""
    keep = _stamp_keeper()
    existing = {"generated_at": "2026-01-01T00:00:00+00:00", "git": {"commits": 1},
                "code": {"total": {"lines": 10}}}
    measured = {"generated_at": "2026-09-22T12:00:00+00:00", "git": {"commits": 2},
                "code": {"total": {"lines": 11}}}

    keep(measured, existing)

    assert measured["generated_at"] == "2026-09-22T12:00:00+00:00"
    assert measured["git"] == {"commits": 2}


def _coverage_figure():
    sys.path.insert(0, str(Path(REPO_ROOT) / "scripts"))
    import coverage_figure  # noqa: PLC0415

    return coverage_figure


def test_the_published_floor_is_the_one_the_makefile_enforces():
    """DEF-134. The README stated the floor and the Makefile enforced it, and
    nothing compared them. It is read from the target that applies it, so the
    day it is lowered to keep a build green the page says so too."""
    module = _coverage_figure()
    makefile = (Path(REPO_ROOT) / "Makefile").read_text(encoding="utf-8")

    assert module.floor() == module.floor_in(makefile)
    assert module.floor_in("COVERAGE_FLOOR ?= 71\n") == 71


def test_a_makefile_with_no_floor_fails_rather_than_defaulting():
    """The twin. A default would be a third copy of the number, agreeing with
    the other two until somebody moved one of them."""
    module = _coverage_figure()

    with pytest.raises(SystemExit, match="not enforced by anything"):
        module.floor_in("test:\n\tpytest tests\n")


def test_the_measured_coverage_is_absent_rather_than_zero_when_nothing_ran():
    """The third negative, in the measuring apparatus: a figure whose source
    is missing says so instead of reporting a number."""
    module = _coverage_figure()
    sys.path.insert(0, str(Path(REPO_ROOT) / "scripts"))
    import figures  # noqa: PLC0415

    recorded = json.loads((Path(REPO_ROOT) / "figures.json").read_text(encoding="utf-8"))
    assert recorded["coverage"]["available"] is True
    assert recorded["coverage"]["floor"] == module.floor()

    carried = {"coverage": {"available": False, "reason": "no data"}}
    figures.keep_the_coverage_when_the_suite_did_not_run(carried, recorded)
    assert carried["coverage"] == recorded["coverage"]

    fresh = {"coverage": {"available": True, "percent": "12", "floor": 88}}
    figures.keep_the_coverage_when_the_suite_did_not_run(fresh, recorded)
    assert fresh["coverage"]["percent"] == "12", (
        "a run that measured coverage must write what it measured, or a drop "
        "would be carried over by the figure that is supposed to report it"
    )


def test_the_stamp_is_not_carried_when_it_names_a_commit_the_branch_lost():
    """The history rewrite, and the reason the carry needed a second condition.

    Rewriting the commit messages changes nothing this script measures: the
    trees are identical by construction. So every measured block agrees, the
    stamp is carried, and `figures.json` goes on naming a commit that is not
    on the branch any more - which `release_check.py` refuses and which
    `make figures` could not fix, because it would carry the same stamp again.
    """
    keep = _stamp_keeper()
    existing = {"generated_at": "2026-01-01T00:00:00+00:00",
                "git": {"commits": 1, "head": "c3a5cf7"},
                "code": {"total": {"lines": 10}}}
    measured = {"generated_at": "2026-09-22T12:00:00+00:00",
                "git": {"commits": 1, "head": "189c383"},
                "code": {"total": {"lines": 10}}}

    keep(measured, existing, False)

    assert measured["git"]["head"] == "189c383"
    assert measured["generated_at"] == "2026-09-22T12:00:00+00:00"


def test_a_stamp_naming_a_commit_on_the_branch_is_still_carried():
    """The other direction, so the condition cannot be satisfied by never
    carrying anything."""
    keep = _stamp_keeper()
    existing = {"generated_at": "2026-01-01T00:00:00+00:00",
                "git": {"commits": 1, "head": "c3a5cf7"},
                "code": {"total": {"lines": 10}}}
    measured = {"generated_at": "2026-09-22T12:00:00+00:00",
                "git": {"commits": 1, "head": "c3a5cf7"},
                "code": {"total": {"lines": 10}}}

    keep(measured, existing, True)

    assert measured["generated_at"] == existing["generated_at"]


def test_the_stamp_condition_reads_the_repository_it_is_run_in():
    """Non-vacuity: the predicate has to answer yes about this checkout's own
    HEAD and no about a commit that is not in it."""
    sys.path.insert(0, str(Path(REPO_ROOT) / "scripts"))
    import figures  # noqa: PLC0415

    head = subprocess.run(  # noqa: S603 - a fixed argv, no shell
        ["git", "rev-parse", "HEAD"],  # noqa: S607 - git from PATH, as every script here
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout.strip()

    assert figures.the_stamp_still_names_this_history({"git": {"head": head}})
    assert not figures.the_stamp_still_names_this_history(
        {"git": {"head": "0123456789abcdef0123456789abcdef01234567"}}
    )
    assert not figures.the_stamp_still_names_this_history({})


def test_a_tree_that_is_not_a_checkout_keeps_its_stamp(tmp_path, monkeypatch):
    """The case that broke the measurement being repeatable, found by the test
    that was already there.

    An unpacked sdist has no `.git`, and neither does the copy this suite
    makes to run `figures.py` twice over one tree. Asking git about ancestry
    there answers `not a repository`, which read as `that commit is gone`: the
    stamp moved on every run and the file stopped being a function of the
    tree. What cannot be answered is not answered no.
    """
    sys.path.insert(0, str(Path(REPO_ROOT) / "scripts"))
    import figures  # noqa: PLC0415

    monkeypatch.setattr(figures, "ROOT", tmp_path)

    assert figures.the_stamp_still_names_this_history(
        {"git": {"head": "0123456789abcdef0123456789abcdef01234567"}}
    )


def test_running_the_measurement_twice_over_one_tree_writes_the_same_bytes(working_tree):
    """The property the CI step actually depends on, end to end.

    Asserted on the script and not on the helper, because the helper being
    right and the script not calling it is exactly the shape work rule 12 is
    about.
    """
    def measure():
        result = subprocess.run(
            [sys.executable, str(working_tree / "scripts" / "figures.py")],
            cwd=working_tree, capture_output=True, text=True, timeout=900,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return (
            (working_tree / "figures.json").read_bytes(),
            (working_tree / "docs" / "FIGURES.md").read_bytes(),
        )

    first = measure()
    second = measure()

    assert first == second, (
        "two runs of scripts/figures.py over one tree wrote different bytes, so "
        "`git diff --exit-code` after it can never mean what CI says it means"
    )


def _section(stdout: str, title: str) -> str:
    """The lines one check printed, so a twin asserts on its check and no other.

    Planting a file under `tests/fixtures/` adds a parametrized case to
    `test_every_fixture_file_is_in_the_index`, which moves the collected test
    count, which makes `figures_match` red as well. Asserting on the exit code
    alone would therefore pass with the check under test green, which is the
    shape work rule 12 names.
    """
    lines = stdout.splitlines()
    for index, line in enumerate(lines):
        if line.strip().endswith(title):
            body = []
            for following in lines[index + 1:]:
                if following.startswith(("  ok    ", "  FAIL  ")):
                    break
                body.append(following)
            return "\n".join([line, *body])
    raise AssertionError(f"the gate printed no line for {title!r}:\n{stdout}")


ORPHAN_CHECK = "every fixture under tests/fixtures is one the suite names"


def test_a_fixture_nothing_in_the_suite_names_fails(working_tree, tmp_path):
    """The 262 KB CycloneDX schema, reconstructed as the shape rather than the file.

    It survived two releases because the only test that looked at
    `tests/fixtures/` asked whether git had it, not whether anything read it.

    The directory name is assembled at run time on purpose. Written as a
    literal it would appear in this file, this file is part of what the check
    reads, and the plant would vouch for itself - which is how the first
    version of this test passed while the check under it did nothing.
    """
    folder = "zz" + "unreferenced"
    broken = tmp_path / "orphan-fixture"
    shutil.copytree(working_tree, broken)
    orphan = broken / "tests" / "fixtures" / folder / "payload.json"
    orphan.parent.mkdir(parents=True, exist_ok=True)
    orphan.write_text('{"unread": true}\n', encoding="utf-8")

    section = _section(run(broken).stdout, ORPHAN_CHECK)

    assert section.startswith("  FAIL"), section
    assert f"{folder}/payload.json" in section, section


def test_a_fixture_a_test_names_only_by_its_directory_passes(working_tree, tmp_path):
    """And the other direction, which is what keeps the check survivable.

    A corpus of 54 repositories is walked by one loop that names the directory
    once. A check that demanded every file be named by hand would fail on all
    of them, and a gate that fails on the correct shape gets switched off.
    """
    folder = "zz" + "planted"
    fine = tmp_path / "named-fixture"
    shutil.copytree(working_tree, fine)
    added = fine / "tests" / "fixtures" / "surface" / "corpus" / folder / "CLAUDE.md"
    added.parent.mkdir(parents=True, exist_ok=True)
    added.write_text("# planted by the suite\n", encoding="utf-8")

    section = _section(run(fine).stdout, ORPHAN_CHECK)

    assert section.startswith("  ok"), section


MAKE_CHECK = "every make target a document names is one the Makefile defines"


def test_a_document_naming_a_make_target_that_does_not_exist_fails(working_tree, tmp_path):
    """docs/ENGINEERING.md listed six of them for two releases.

    make only complains when somebody types one, so a page can go on telling
    readers to run a target that left with the product it measured.
    """
    broken = tmp_path / "dead-target"
    shutil.copytree(working_tree, broken)
    page = broken / "docs" / "ENGINEERING.md"
    page.write_text(
        page.read_text(encoding="utf-8") + "\n" + "Run `make benchmark` first." + "\n",
        encoding="utf-8",
    )

    section = _section(run(broken).stdout, MAKE_CHECK)

    assert section.startswith("  FAIL"), section
    assert "make benchmark" in section, section


def test_prose_that_happens_to_say_make_is_left_alone(working_tree, tmp_path):
    """The other direction. "make a decision" is not a target.

    The first version of this check read every `make <word>` in the page and
    reported `make a`, `make the` and `make you`, which is a gate failing on
    English. Only code counts now, and this is what holds that.
    """
    fine = tmp_path / "prose-make"
    shutil.copytree(working_tree, fine)
    page = fine / "docs" / "ENGINEERING.md"
    page.write_text(
        page.read_text(encoding="utf-8")
        + "\n"
        + "Somebody has to make a decision, and make the gate green afterwards."
        + "\n",
        encoding="utf-8",
    )

    section = _section(run(fine).stdout, MAKE_CHECK)

    assert section.startswith("  ok"), section


LICENCE_CHECK = "the licence is the same one everywhere it is stated"


def test_a_page_that_names_the_other_licence_fails(working_tree, tmp_path):
    """The relicensing reached four files and not the READMEs, once."""
    broken = tmp_path / "two-licences"
    shutil.copytree(working_tree, broken)
    page = broken / "README.md"
    page.write_text(
        page.read_text(encoding="utf-8") + "\n" + "Also available under MIT." + "\n",
        encoding="utf-8",
    )

    section = _section(run(broken).stdout, LICENCE_CHECK)

    assert section.startswith("  FAIL"), section
    assert "MIT" in section, section


def test_a_word_that_merely_contains_a_licence_name_is_not_one(working_tree, tmp_path):
    """`docs/LIMITS.md` spells L-I-M-I-T-S, and the check read MIT out of it.

    It compared by substring, so the day the landing page grew a link to the
    limits page the gate announced that README.md names MIT. A check that finds
    a licence inside an unrelated word is not stricter, it is wrong in the
    direction that gets a gate switched off.
    """
    fine = tmp_path / "limits-link"
    shutil.copytree(working_tree, fine)
    page = fine / "README.md"
    page.write_text(
        page.read_text(encoding="utf-8")
        + "\n"
        + "See [the limits](docs/LIMITS.md), and the SUMMIT of what it will not claim."
        + "\n",
        encoding="utf-8",
    )

    section = _section(run(fine).stdout, LICENCE_CHECK)

    assert section.startswith("  ok"), section


# --------------------------------------------------------------------------
# Commit SHAs cited in the documentation
# --------------------------------------------------------------------------
#
# These read the check's own functions rather than running the script, because
# `working_tree` copies the repository WITHOUT `.git` and this check's whole
# subject is what a git repository can answer about a commit. A twin that
# planted a dead SHA in a copy with no history would be watching the check
# decline to look, which is the failure it is written against.


def _release_check():
    sys.path.insert(0, str(Path(REPO_ROOT) / "scripts"))
    import release_check  # noqa: PLC0415

    return release_check


OURS = "marcosmatalab/seamark"
DEAD = "0123456789abcdef0123456789abcdef01234567"


def test_a_cited_commit_of_this_repository_that_is_not_on_the_branch_fails():
    """The rewrite hazard, which is the reason this check exists: 45 messages
    replayed move every SHA, and the README pins two of them."""
    module = _release_check()
    citations = module.sha_citations(
        "README.md", f"      - uses: {OURS}@{DEAD}\n"
    )

    problems = module.sha_problems(
        citations, OURS, lambda sha: "is not a commit in this repository"
    )

    assert problems, "a dead SHA of this repository was accepted"
    assert DEAD in problems[0] and "README.md:1" in problems[0]


def test_a_cited_commit_that_exists_but_is_not_an_ancestor_is_the_case_that_survives_a_rewrite():
    """`git cat-file -e` answers yes on the machine that did the rewrite,
    because the backup ref keeps the old commits reachable. Ancestry is what a
    fresh clone would ask."""
    module = _release_check()
    citations = module.sha_citations("README.md", f"rev: {DEAD}\n")

    assert citations[0]["repository"] is None, (
        "a `rev:` with no `repo:` above it was attributed to something"
    )


def test_a_forty_hex_string_nobody_can_attribute_fails_rather_than_being_skipped():
    """Work rule 11. The first version of this check looked only at `uses:`
    lines, which means a SHA written into a sentence would have been read by
    nothing and reported as nothing."""
    module = _release_check()
    citations = module.sha_citations(
        "docs/DESIGN.md", f"The fix landed in {DEAD}, which is where it is argued.\n"
    )

    problems = module.sha_problems(citations, OURS, lambda sha: None)

    assert problems, "an unattributable commit SHA was passed over"
    assert "nothing on the line says which repository" in problems[0]


def test_somebody_else_s_pinned_action_is_not_this_repository_s_to_resolve():
    """`actions/checkout@<sha>` is pinned correctly and is not a commit in this
    repository. A check that demanded it resolve here would fail on the one
    thing the workflow does right."""
    module = _release_check()
    text = (
        f"      - uses: actions/checkout@{DEAD}  # v5\n"
        f"      - uses: {OURS}@{DEAD}\n"
    )

    citations = module.sha_citations(".github/workflows/ci.yml", text)
    problems = module.sha_problems(
        citations, OURS, lambda sha: "is not a commit in this repository"
    )

    assert [row["repository"] for row in citations] == ["actions/checkout", OURS]
    assert len(problems) == 1, problems


def test_a_pre_commit_rev_is_attributed_to_the_repo_line_above_it():
    module = _release_check()
    text = (
        "repos:\n"
        f"  - repo: https://github.com/{OURS}\n"
        f"    rev: {DEAD}\n"
        "    hooks:\n"
        "      - id: seamark-check\n"
    )

    citations = module.sha_citations("README.md", text)

    assert [row["repository"] for row in citations] == [OURS]


def test_the_check_finds_the_citations_that_are_really_on_the_pages():
    """Non-vacuity, over the tree as it stands. A classifier that found
    nothing would pass every twin above and guard nothing at all."""
    module = _release_check()
    found = []
    for relative in ("README.md", "README.es.md"):
        found += module.sha_citations(
            relative, (Path(REPO_ROOT) / relative).read_text(encoding="utf-8")
        )

    mine = [row for row in found if row["repository"] == OURS]
    assert len(mine) == 4, (
        "both READMEs pin this repository twice, in a `uses:` and in a `rev:`; the "
        f"reader found {[row['where'] for row in mine]}"
    )
    assert all(len(row["sha"]) == 40 for row in found)


def test_the_check_passes_on_this_repository_and_says_what_it_read():
    module = _release_check()

    detail = module.cited_commits_exist()

    assert "of this repository" in detail
    assert "0 commit SHAs" not in detail


# --------------------------------------------------------------------------
# One way to build the distributions
# --------------------------------------------------------------------------

BUILD_CHECK = "the distributions are built by one command, and CI runs that command"


def _ci(tree: Path) -> Path:
    return tree / ".github" / "workflows" / "ci.yml"


@pytest.mark.parametrize(
    ("planted", "expected"),
    [
        # The shape that cost a release: the job built with `python -m build`
        # and asserted its own two resource paths while `make package`
        # asserted five that had left with the scanner. Each was green on its
        # own terms.
        ("        run: python -m build\n", "python -m build"),
        # The subtler one, and the one that was actually here: calling the
        # script the target calls. The list is shared, the command is not, and
        # a step added to the target never reaches the runner.
        ("        run: python scripts/build_package.py\n", "scripts/build_package.py"),
    ],
)
def test_a_workflow_that_builds_the_package_its_own_way_is_named(planted, expected):
    module = _release_check()

    problems, through = module.build_problems({"ci.yml": planted})

    assert through == 0
    assert any(expected in problem for problem in problems), problems


def test_a_workflow_that_goes_through_the_target_is_accepted():
    """The other direction, so the check cannot be satisfied by refusing every
    workflow that builds anything."""
    module = _release_check()

    problems, through = module.build_problems({"ci.yml": "        run: make package\n"})

    assert (problems, through) == ([], 1)


def test_a_comment_naming_the_other_way_is_not_a_second_builder():
    """The step's own comment explains why it does not use `python -m build`,
    and a check that read comments would fail on the sentence documenting it."""
    module = _release_check()

    problems, through = module.build_problems(
        {"ci.yml": "        # not python -m build, see above\n        run: make package\n"}
    )

    assert (problems, through) == ([], 1)


def test_a_workflow_set_that_builds_nothing_fails_rather_than_passing_empty(working_tree, tmp_path):
    """Work rule 11. A check for "nothing builds it the wrong way" is
    satisfied by nothing building it at all, which is the same green as a
    pattern that matches nothing.

    EVERY workflow, not just `ci.yml`. The first version of this twin blinded
    one file, and the day a second workflow started building the package the
    twin went on passing while asserting the opposite - the check found the
    other one and said so, and the test read that as the failure it planted.
    """
    broken = tmp_path / "no-builder"
    shutil.copytree(working_tree, broken)
    blinded = 0
    for workflow in sorted((broken / ".github" / "workflows").glob("*.yml")):
        current = workflow.read_text(encoding="utf-8")
        if "make package" not in current:
            continue
        workflow.write_text(current.replace("make package", "true"), encoding="utf-8")
        blinded += 1
    assert blinded >= 1, "no workflow in the copy builds the package at all"

    section = _section(run(broken).stdout, BUILD_CHECK)

    assert section.startswith("  FAIL"), section
    assert "no workflow builds the distributions" in section, section




# --------------------------------------------------------------------------
# The demo picture, as somebody else's renderer will see it
# --------------------------------------------------------------------------

PICTURE = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="980" height="60" '
    'viewBox="0 0 980 60" role="img" aria-label="a picture">'
    '<rect width="980" height="60" fill="#11151c"/>'
    '<g font-family="Menlo, monospace" font-size="14">'
    '<text x="22" y="30" fill="#c9d1d9">seamark check</text>'
    "</g></svg>"
)


def test_the_picture_this_repository_publishes_is_accepted():
    """Non-vacuity in the direction that matters: a check that refuses
    everything is as useless as one that refuses nothing."""
    module = _release_check()

    assert module.svg_problems(PICTURE) == []


@pytest.mark.parametrize(
    ("planted", "expected"),
    [
        # The one a sanitiser strips, and the reason SVG is treated as code.
        (PICTURE.replace("<rect", "<script>alert(1)</script><rect"), "<script"),
        # The one that is silently blank: a font fetched from a third party
        # under a policy that allows no fetch at all.
        (
            PICTURE.replace("<rect", '<image href="https://example.invalid/f.png"/><rect'),
            "is blank wherever the fetch is blocked",
        ),
        # A stack with no generic family at the end: every column stops lining
        # up on a machine without the named face.
        (PICTURE.replace("Menlo, monospace", "Menlo"), "does not end at one of"),
        # No box to size the image with.
        (PICTURE.replace(' width="980" height="60" viewBox', " viewBox"), "no width and height"),
        # An element nobody thought of, which is why this is an allowlist.
        (PICTURE.replace("<rect", "<animate/><rect"), "not in the set of elements"),
    ],
)
def test_a_picture_that_would_not_survive_being_published_is_refused(planted, expected):
    module = _release_check()

    problems = module.svg_problems(planted)

    assert any(expected in problem for problem in problems), problems


def test_a_line_wider_than_the_canvas_is_refused_at_a_strangers_glyph_width():
    """The defect this check found on its first run: the canvas was measured
    at the advance width of the font it was written with, so the longest line
    of the report fitted to the pixel here and was clipped on any machine
    whose monospace is wider."""
    module = _release_check()
    long_line = "x" * 120
    planted = PICTURE.replace("seamark check", long_line)

    problems = module.svg_problems(planted)

    assert any("reaches" in problem for problem in problems), problems


def test_the_published_pictures_are_the_ones_this_check_reads(working_tree, tmp_path):
    """Work rule 11, end to end: an empty `docs/img` is a green tick."""
    broken = tmp_path / "no-pictures"
    shutil.copytree(working_tree, broken)
    for picture in (broken / "docs" / "img").glob("*.svg"):
        picture.unlink()

    section = _section(run(broken).stdout, "the demo picture uses only what every renderer of it will keep")

    assert section.startswith("  FAIL"), section
    assert "holds no .svg" in section, section


# --------------------------------------------------------------------------
# The shape of the landing page
# --------------------------------------------------------------------------

LANDING_CHECK = "each landing page opens with what it is and stays under its ceiling"


def test_a_landing_page_that_grew_past_its_ceiling_is_named():
    module = _release_check()
    grown = (Path(REPO_ROOT) / "README.md").read_text(encoding="utf-8") + "\npadding" * 200

    problems = module.landing_problems("README.md", grown)

    assert any("the ceiling is" in problem for problem in problems), problems


@pytest.mark.parametrize(
    ("planted", "expected"),
    [
        ("# Seamark\n\n**What it is.**\n\n```bash\nx\n```\n", "badges above the fold"),
        (
            "# Seamark\n\n[![a](x)](http://a)\n[![b](x)](http://b)\n[![c](x)](http://c)\n"
            "\n```bash\nx\n```\n",
            "one bold sentence",
        ),
        (
            "**What it is, in one sentence that is long enough.**\n"
            "[![a](x)](http://a)\n[![b](x)](http://b)\n[![c](x)](http://c)\n```bash\nx\n```\n",
            "no H1",
        ),
        (
            "# Seamark\n\n**What it is, in one sentence that is long enough.**\n"
            "[![a](x)](http://a)\n[![b](x)](http://b)\n[![c](x)](http://c)\n",
            "no command to run",
        ),
    ],
)
def test_a_first_screen_missing_one_of_the_four_things_fails(planted, expected):
    """The four things a reader needs before deciding whether to read on. Each
    is planted missing, one at a time, because a check that only ever sees the
    page as it is cannot tell the property from the page."""
    module = _release_check()

    problems = module.landing_problems("README.md", planted)

    assert any(expected in problem for problem in problems), problems


def test_the_first_screen_contract_passes_on_both_pages_as_they_are():
    module = _release_check()
    for page in ("README.md", "README.es.md"):
        text_of = (Path(REPO_ROOT) / page).read_text(encoding="utf-8")
        assert module.landing_problems(page, text_of) == [], page


# --------------------------------------------------------------------------
# The commands the landing pages tell a reader to run
# --------------------------------------------------------------------------

PUBLISHED_CHECK = (
    "every command the landing pages publish as runnable prints what the row promises"
)


def test_the_row_with_a_pipeline_in_it_is_read_as_one_row():
    """DEF-135's neighbour. A markdown cell escapes a pipe as `\\|`, and
    splitting the row on every pipe turned the one row with a pipeline in it
    into five cells, which the parser then skipped - so the check would have
    reported that it compared everything while silently dropping the row most
    worth running."""
    module = _release_check()

    rows = module.held_up_rows(
        "README.md", (Path(REPO_ROOT) / "README.md").read_text(encoding="utf-8")
    )
    commands = [command for _, command, _ in rows]

    assert "find src -name '*.py' | xargs cat | wc -l" in commands
    assert len(rows) == 7, commands


def test_every_published_command_is_either_run_or_says_why_not():
    """The explicitness the whole check rests on: the set that is executed is
    a decision, not the remainder after the easy ones."""
    module = _release_check()

    rows = module.held_up_rows(
        "README.md", (Path(REPO_ROOT) / "README.md").read_text(encoding="utf-8")
    )
    unaccounted = [
        command for _, command, _ in rows
        if command not in module.HELD_UP_RUN and command not in module.HELD_UP_NOT_RUN
    ]

    assert not unaccounted, unaccounted
    assert set(module.HELD_UP_RUN) & set(module.HELD_UP_NOT_RUN) == set(), (
        "a command cannot be both run and not run"
    )
    for command, reason in module.HELD_UP_NOT_RUN.items():
        assert len(reason) > 40, f"{command} is not run and the reason is a shrug"


@pytest.mark.parametrize(
    ("reader", "output", "expected"),
    [
        ("_collected", "tests/test_a.py: 3\n2606 tests collected in 0.30s\n", 2606),
        # The phrase inside a collected node id, which is where the first
        # version of this reader found its answer: the parametrised cases of
        # this very test are printed in the collection listing, and one of
        # them carries the words. A node id is never at the start of a line.
        (
            "_collected",
            "tests/test_x.py::test_y[2606 tests collected in 0.30s]\n"
            "\n2639 tests collected in 16.02s\n",
            2639,
        ),
        # The defect itself: the form the page published prints per-file
        # totals and no grand total, so the reader finds nothing and the check
        # says so rather than passing over it.
        ("_collected", "tests/test_a.py: 3\ntests/test_b.py: 4\n\n", None),
        ("_only_number", "15969\n", 15969),
        ("_only_number", "no number here\n", None),
        ("_commands_in_help", "usage: seamark [--lang {en,es}]\n {a,b,c} ...\n", 3),
        # Two different groups of the same width: the shape changed and this
        # has stopped knowing which one is the commands.
        ("_commands_in_help", "{a,b} and {c,d}\n", None),
    ],
)
def test_each_reader_finds_its_number_or_says_it_did_not(reader, output, expected):
    module = _release_check()

    assert getattr(module, reader)(output) == expected


def test_a_row_whose_figure_is_off_by_one_fails(working_tree, tmp_path):
    """The proof that the comparison is against what the command PRINTS and
    not against another recorded figure: one digit, and the gate is red."""
    broken = tmp_path / "off-by-one"
    shutil.copytree(working_tree, broken)
    # Read the figure off the page rather than writing it here. A literal
    # would make this twin fail every time a test is added, which is the
    # treadmill D-181 took out of the figure checks, and it would fail in a
    # way that looks like the check being broken.
    collected = json.loads((broken / "figures.json").read_text(encoding="utf-8"))["tests"]["collected"]
    for name, separator in (("README.md", ","), ("README.es.md", ".")):
        page = broken / name
        current = page.read_text(encoding="utf-8")
        row = f"| {collected:,}".replace(",", separator) + " tests |"
        assert row in current, f"{name} does not state the test count as `{row}`"
        wrong = f"| {collected + 1:,}".replace(",", separator) + " tests |"
        page.write_text(current.replace(row, wrong, 1), encoding="utf-8")

    section = _section(run(broken).stdout, PUBLISHED_CHECK)

    assert section.startswith("  FAIL"), section
    assert f"printed {collected} tests collected" in section, section


def test_a_command_the_check_does_not_know_is_refused_rather_than_skipped(working_tree, tmp_path):
    """Work rule 11, and the direction that actually caught the defect: the
    page went back to publishing the command that prints nothing, and the
    check refuses it because it is not in either table."""
    broken = tmp_path / "unknown-command"
    shutil.copytree(working_tree, broken)
    for name in ("README.md", "README.es.md"):
        page = broken / name
        current = page.read_text(encoding="utf-8")
        page.write_text(
            current.replace(
                "`python -m pytest --collect-only -q -o addopts=`",
                "`python -m pytest --collect-only -q`", 1,
            ),
            encoding="utf-8",
        )

    section = _section(run(broken).stdout, PUBLISHED_CHECK)

    assert section.startswith("  FAIL"), section
    assert "neither runs it nor says why not" in section, section


# --------------------------------------------------------------------------
# The commit bodies
# --------------------------------------------------------------------------


def _history_check():
    sys.path.insert(0, str(Path(REPO_ROOT) / "scripts"))
    import history_check  # noqa: PLC0415

    return history_check


def test_the_history_gate_passes_on_the_bodies_this_branch_will_carry():
    """Non-vacuity, over the real thing: it reads the commits and finds them.

    `resulting_bodies` measures the body each commit WILL carry, which is why
    this is green before the rewrite as well as after it. A reader who wants
    to know which is the case reads the count that comes back.
    """
    module = _history_check()

    bodies, from_the_map = module.resulting_bodies("HEAD")

    assert len(bodies) > 40, f"only {len(bodies)} commits were read"
    assert module.problems_in(bodies) == []
    assert from_the_map >= 0


@pytest.mark.parametrize(
    ("planted", "expected"),
    [
        ({"aaaaaaaa": "Subject\n\n" + "\n".join(["body"] * 14)}, "the cap is 15"),
        ({"bbbbbbbb": "Subject\n\nThis closes the work rule 9 twin."}, "'work rule'"),
        ({"cccccccc": "Subject\n\nThe BUDGET for this phase was four hours."}, "'budget'"),
        ({"dddddddd": "Subject\n\nFound in the adversarial pass."}, "'adversarial pass'"),
        ({"eeeeeeee": "Subject\n\nLeft for a later session."}, "'a later session'"),
    ],
)
def test_a_body_the_rewrite_would_not_have_allowed_is_refused(planted, expected):
    """Work rule 9. Each way the criterion of phase 6 can be broken, planted.

    The cap counts as `wc -l` over `git log --format=%B` counts: fourteen
    lines of message plus the newline the format adds.
    """
    module = _history_check()

    problems = module.problems_in(planted)

    assert any(expected in problem for problem in problems), problems


def test_a_body_at_the_cap_exactly_is_allowed():
    """The other direction: a rule that refuses the boundary is a rule nobody
    can satisfy, and the twins above would all pass under it."""
    module = _history_check()

    at_the_cap = {"ffffffff": "Subject\n\n" + "\n".join(["body"] * 12)}

    assert len(at_the_cap["ffffffff"].split("\n")) + 1 == module.MAX_LINES
    assert module.problems_in(at_the_cap) == []


def test_the_replay_and_the_gate_hold_the_same_cap():
    """Two checks over one property share their definition or they cancel:
    with two copies of the cap, the replay would build a history the gate
    refuses, and the failure would arrive after the branch had moved."""
    module = _history_check()
    sys.path.insert(0, str(Path(REPO_ROOT) / ".github" / "history-rewrite"))
    import replay  # noqa: PLC0415

    assert replay.MAX_LINES is module.MAX_LINES
    assert replay.FORBIDDEN is module.FORBIDDEN
    assert replay.problems_in is module.problems_in


def test_the_words_the_gate_refuses_are_the_ones_the_documentation_names():
    """A list of refused words that only exists in code is one nobody can
    argue with, and the page that argues for it is the second copy that goes
    stale first."""
    module = _history_check()
    page = (Path(REPO_ROOT) / "docs" / "ENGINEERING.md").read_text(encoding="utf-8").lower()

    for word in module.FORBIDDEN:
        assert word in page, (
            f"{word!r} is refused by the gate and docs/ENGINEERING.md does not name it"
        )
    assert str(module.MAX_LINES) in page


# --------------------------------------------------------------------------
# The notes for the version that has not been released yet
# --------------------------------------------------------------------------

MEASURED = {"tests": {"collected": 2606}, "coverage": {"percent": "90"}}


def test_the_notes_this_tree_would_publish_state_what_it_measures():
    """Non-vacuity over the real file: the check reads the notes that are
    about to be pasted into a release, and finds both figures in them."""
    module = _release_check()
    notes = (
        Path(REPO_ROOT) / ".github" / "release-notes" / "v3.0.0.md"
    ).read_text(encoding="utf-8")
    measured = json.loads((Path(REPO_ROOT) / "figures.json").read_text(encoding="utf-8"))

    problems, compared = module.note_problems(notes, measured)

    assert problems == []
    assert compared == 2


@pytest.mark.parametrize(
    ("planted", "expected"),
    [
        # The state these notes were actually in: written once, true once, and
        # never compared with anything again.
        ("Beta. 2,487 tests, 90% coverage.", "and this tree measures 2606"),
        ("Beta. 2,606 tests, 88% coverage.", "and this tree measures 90"),
        # A figure taken out of the notes is not a figure that stopped being
        # checked: it is one nothing is holding.
        ("Beta. 2,606 tests, green on three interpreters.", "state no coverage figure"),
        ("Beta. 90% coverage, green everywhere.", "state no tests figure"),
    ],
)
def test_notes_that_say_something_the_tree_does_not_are_refused(planted, expected):
    module = _release_check()

    problems, _ = module.note_problems(planted, MEASURED)

    assert any(expected in problem for problem in problems), problems


def test_notes_for_a_version_already_released_are_left_alone():
    """The v2.3.0 notes record what was true when the scanner was archived.
    Holding them to this tree would be falsifying a record, which is the same
    argument that keeps a published tag where it is."""
    module = _release_check()
    old = (
        Path(REPO_ROOT) / ".github" / "release-notes" / "v2.3.0.md"
    ).read_text(encoding="utf-8")

    from seamark import __version__  # noqa: PLC0415

    assert __version__ != "2.3.0"
    # The check reads only the file named after the current version, and this
    # is the file it therefore never opens.
    assert module.note_problems(old, MEASURED)[0], (
        "the archived notes happen to agree with this tree, so this test proves "
        "nothing; pick another figure"
    )


# --------------------------------------------------------------------------
# The publication happens once, the rehearsal as often as it takes
# --------------------------------------------------------------------------

# A workflow with the shape of the real one and nothing else in it: two
# triggers, a build both can reach, and two uploads that one each can reach.
WORKFLOW = """on:
  release:
    types: [published]
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make package

  attach:
    needs: build
    if: github.event_name == 'release'
    runs-on: ubuntu-latest
    steps:
      - run: gh release upload

  testpypi:
    needs: build
    if: github.event_name == 'workflow_dispatch'
    runs-on: ubuntu-latest
    steps:
      - uses: pypa/gh-action-pypi-publish@abc
        with:
          repository-url: https://test.pypi.org/legacy/
          skip-existing: true

  pypi:
    needs: [build, attach]
    if: github.event_name == 'release'
    runs-on: ubuntu-latest
    steps:
      - uses: pypa/gh-action-pypi-publish@abc
        with:
          packages-dir: dist
"""


def test_the_release_workflow_has_one_of_each_and_this_check_reads_them():
    """Non-vacuity over the real file: four jobs, two of them uploads, and
    one event reaching each."""
    module = _release_check()
    workflow = (
        Path(REPO_ROOT) / ".github" / "workflows" / "release.yml"
    ).read_text(encoding="utf-8")

    assert sorted(module.workflow_jobs(workflow)) == ["attach", "build", "pypi", "testpypi"]
    assert sorted(module.publishing_jobs(workflow)) == ["pypi", "testpypi"]
    assert module.triggering_events(workflow) == {
        "release": ["published"], "workflow_dispatch": [],
    }

    reaching = module.events_reaching(
        module.workflow_jobs(workflow), set(module.triggering_events(workflow))
    )

    assert reaching["testpypi"] == {"workflow_dispatch"}
    assert reaching["pypi"] == {"release"}
    assert module.publish_problems(workflow) == []


def test_the_shape_this_repository_publishes_with_is_accepted():
    """The other direction over the fixture, so every twin below is planted
    against something that passes."""
    module = _release_check()

    assert module.publish_problems(WORKFLOW) == []


def test_a_rehearsal_that_cannot_be_repeated_is_refused():
    """The upload succeeds, the install fails, and the second run dies at the
    step the first one passed."""
    module = _release_check()

    problems = module.publish_problems(WORKFLOW.replace("          skip-existing: true\n", ""))

    assert any("cannot upload" in problem for problem in problems), problems


def test_a_publication_that_can_be_repeated_is_refused():
    """`skip-existing` on the PyPI job turns publishing a version twice into a
    green build."""
    module = _release_check()

    planted = WORKFLOW.replace(
        "          packages-dir: dist\n", "          packages-dir: dist\n          skip-existing: true\n"
    )

    problems = module.publish_problems(planted)

    assert any("already there is a mistake" in problem for problem in problems), problems


def test_a_dispatch_that_could_reach_pypi_is_refused():
    """The one that cannot be undone: a condition deleted, and step 9 of the
    runbook - a dispatch meant for TestPyPI - publishes 3.0.0 for real."""
    module = _release_check()

    planted = WORKFLOW.replace(
        "    needs: [build, attach]\n    if: github.event_name == 'release'\n",
        "    needs: build\n",
    )

    problems = module.publish_problems(planted)

    assert any("spent for good" in problem for problem in problems), problems
    assert any("workflow_dispatch" in problem for problem in problems), problems


def test_a_pypi_job_reachable_through_a_loosened_dependency_is_refused():
    """The subtler half of the same thing: the condition stays and the
    `needs:` chain that also held it is loosened. `attach` is what makes a
    dispatch unable to reach PyPI even if somebody edits the `if:`."""
    module = _release_check()

    planted = WORKFLOW.replace(
        "    needs: [build, attach]\n    if: github.event_name == 'release'\n",
        "    needs: build\n    if: github.event_name == 'workflow_dispatch'\n",
    )

    problems = module.publish_problems(planted)

    assert any("spent for good" in problem for problem in problems), problems


def test_a_rehearsal_reachable_from_a_release_is_refused():
    """The other job, the other direction. A rehearsal that runs on a release
    uploads to TestPyPI every time one is cut, which is noise rather than
    damage - and it means the two jobs are no longer what their names say."""
    module = _release_check()

    planted = WORKFLOW.replace(
        "    if: github.event_name == 'workflow_dispatch'\n", ""
    )

    problems = module.publish_problems(planted)

    assert any("is the rehearsal and can be reached from" in problem
               for problem in problems), problems


def test_a_release_trigger_without_an_activity_type_is_refused():
    """Without `types: [published]` GitHub also sends `edited`, so fixing a
    typo in the notes of a release that is already out would start the
    publication again."""
    module = _release_check()

    planted = WORKFLOW.replace("  release:\n    types: [published]\n", "  release:\n")

    problems = module.publish_problems(planted)

    assert any("Editing the notes" in problem for problem in problems), problems


def test_a_condition_this_check_cannot_read_is_refused_rather_than_guessed():
    """Work rule 11, where guessing is expensive. A parser that shrugs answers
    "every event" or "no event", and both are a confident wrong answer about
    the only step here that cannot be undone."""
    module = _release_check()

    planted = WORKFLOW.replace(
        "    if: github.event_name == 'release'\n",
        "    if: always() && github.event_name == 'release'\n",
    )

    with pytest.raises(Exception, match="cannot read"):
        module.publish_problems(planted)


def test_the_job_reader_stays_inside_the_jobs_block():
    """It did not, at first: `release:` and `workflow_dispatch:` under `on:`
    are two more names at the same indentation, and it read them as jobs. Every
    assertion downstream stayed true, because neither uploads anything and
    nothing needs them - a reader right by luck."""
    module = _release_check()

    assert sorted(module.workflow_jobs(WORKFLOW)) == ["attach", "build", "pypi", "testpypi"]


# --------------------------------------------------------------------------
# The name this product had until 3.0.0
# --------------------------------------------------------------------------
#
# Built from halves here too. A test file that named the old product would have
# to be in the table it is testing, and an entry for the test is the same hole
# as an entry for the checker.

OLD = "act" + "aira"
NAME_CHECK = "the old product name appears nowhere the tree has not written down"


def test_the_tree_keeps_the_old_name_only_where_the_table_says():
    """Non-vacuity, over the tree as it stands: the check reads every tracked
    file, finds the name in the ones the table names, and in no others."""
    module = _release_check()

    detail = module.the_rename_is_not_half_done()

    assert "not a checkout" not in detail, detail
    assert "files read" in detail
    assert module.NAME_IN_FILES, "the table is empty, so the check compares nothing"


def test_a_new_occurrence_outside_the_table_fails():
    """One rename left half done, in a file nobody thought about."""
    module = _release_check()

    problems = module.name_problems({"src/seamark/cli.py": 1}, {})

    assert any("rename left half done" in problem for problem in problems), problems


def test_an_entry_that_has_stopped_being_true_fails():
    """The other direction, and the one an allowlist dies of: the file was
    cleaned up and the exemption stayed, so the next occurrence in it would be
    invisible."""
    module = _release_check()

    problems = module.name_problems({"CHANGELOG.md": 0}, {"CHANGELOG.md": (56, "history")})

    assert any("stale exemption" in problem for problem in problems), problems


def test_an_entry_for_a_file_that_is_gone_fails():
    module = _release_check()

    problems = module.name_problems({}, {"docs/GONE.md": (3, "history")})

    assert any("guards nothing" in problem for problem in problems), problems


def test_a_count_that_moved_fails_and_says_which_way():
    """The ratchet. A file that may say it four times may not say it five, and
    one that has stopped saying it four times is an entry to update."""
    module = _release_check()

    grew = module.name_problems({".gitignore": 5}, {".gitignore": (4, "filenames")})
    shrank = module.name_problems({".gitignore": 3}, {".gitignore": (4, "filenames")})

    assert any("Something new was written" in problem for problem in grew), grew
    assert any("Fewer is not better" in problem for problem in shrank), shrank


def test_an_exemption_with_no_reason_fails():
    module = _release_check()

    problems = module.name_problems({"CHANGELOG.md": 1}, {"CHANGELOG.md": (1, "   ")})

    assert any("states no reason" in problem for problem in problems), problems


@pytest.mark.parametrize(
    ("line", "free"),
    [
        (f"Recover it from `v2.3.0:src/{OLD}/model.py` if you need it.", True),
        (f'PREDICATE_TYPE = "https://{OLD}.dev/predicates/inspection/v1"', True),
        ('assert name.startswith("CN=' + "Act" + 'aira Fixture TSA")', True),
        (f"printf '{OLD} rfc3161 test subject'", True),
        (f"from {OLD} import cli", False),
        (f"pip install {OLD}", False),
        (f"# {OLD.capitalize()} reads the configuration your agents load", False),
    ],
)
def test_only_the_four_kinds_of_line_carry_the_name_for_free(line, free):
    """Each pattern is a shape of line where renaming breaks something. A line
    that merely mentions the product is not one of them, whatever its case."""
    module = _release_check()

    assert (module.name_occurrences(line) == 0) is free, line


def test_the_reader_is_blind_to_case():
    """The lower, the capitalised and the shouted spelling are one name, and a
    sweep that missed one of them is the half-done rename this refuses."""
    module = _release_check()

    for spelling in (OLD, OLD.capitalize(), OLD.upper()):
        assert module.name_occurrences(f"the {spelling} package") == 1, spelling


def test_a_line_pattern_that_matches_nothing_any_more_fails():
    """Work rule 11 over the allowances themselves. Planted rather than
    described: the allowance is kept and the case it was written for is gone."""
    module = _release_check()

    problems = module.unused_line_patterns(
        ((OLD + r" rfc3161 test subject", "the bytes a timestamp authority signed"),),
        {"a.py": "nothing in here says it"},
    )

    assert any("matches nothing" in problem for problem in problems), problems


def test_the_line_patterns_in_use_all_match_something_in_this_tree():
    """And the other direction, over the real files, so the twin above cannot
    be satisfied by a pattern set that never matched anything."""
    module = _release_check()
    tracked = module.tracked_files()
    assert tracked, "this tree is not a checkout, so this test would prove nothing"
    texts = {}
    for name in tracked:
        try:
            texts[name] = (Path(REPO_ROOT) / name).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

    assert module.unused_line_patterns(module.NAME_ON_LINES, texts) == []
