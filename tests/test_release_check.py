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
    destination = tmp_path_factory.mktemp("tree") / "actaira"
    shutil.copytree(
        REPO_ROOT,
        destination,
        ignore=shutil.ignore_patterns(
            "__pycache__", ".git", "*.pyc", ".pytest_cache", "evals/artifacts", "fuzz/runs"
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
    from actaira import __version__

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
        path = broken / "src" / "actaira" / "i18n" / f"{lang}.json"
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
    path = broken / "src" / "actaira" / "i18n" / "en.json"
    catalogue = json.loads(path.read_text(encoding="utf-8"))
    catalogue["rules"]["ACT-NEW-002"] = "english only"
    path.write_text(json.dumps(catalogue, ensure_ascii=False), encoding="utf-8")

    result = run(broken)

    assert result.returncode == 1
    assert "no Spanish text" in result.stdout


def test_a_second_copy_of_a_schema_version_fails(working_tree, tmp_path):
    """A version written anywhere but the registry is a second copy.

    This used to plant a disagreement between `coverage-v1.json` and
    `actaira.coverage.SCHEMA_VERSION` and assert the gate refereed between them.
    Phase A removed the referee along with the second copies: the version lives
    in `schemas.VERSIONS`, `trace/model.py` reads it, and the check now fails on
    a version literal under `src/` rather than on two that disagree.

    So the planted defect moved with it. A literal is written back into a module
    that had stopped writing one - which is exactly how the second copy would
    return - and the gate has to name the file and the line.
    """
    broken = tmp_path / "second-copy"
    shutil.copytree(working_tree, broken)
    path = broken / "src" / "actaira" / "trace" / "model.py"
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
        page.read_text(encoding="utf-8").replace("actaira verify", "actaira verfiy"),
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
# `actaira check`, both READMEs went on publishing "Does not exist" under the
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
    not exist" while `actaira diff` is in the parser."""
    broken = tmp_path / "false-claim"
    shutil.copytree(working_tree, broken)
    page = broken / "README.md"
    page.write_text(
        page.read_text(encoding="utf-8").replace(
            "> **Built.** Commands: `actaira diff`, `actaira seal`.",
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
        "> **Built.** Commands: `actaira check`.",
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
        "> **Built.** Commands: `actaira check`.",
        "> **Built.** Commands: `actaira seal`.",
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
        "README.md", "actaira check --json", "actaira check --fail-on high",
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
            '[tool.ruff.lint.per-file-ignores]\n"src/actaira/coverage.py" = ["UP042"]',
            1,
        ),
        encoding="utf-8",
    )

    result = run(broken)

    assert result.returncode == 1
    assert "src/actaira/coverage.py" in result.stdout
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
