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
