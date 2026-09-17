"""One gate that refuses a release whose parts disagree with each other.

Design note D-180. This repository has drifted three times, and each time the
drift was invisible because nothing compared the two things that disagreed.
The README's figures went stale against the code. The website published a
return on investment the tool had no way to compute. The threat model went on
saying "exactly one outbound connection" for a whole release after the
connectors shipped.

The pattern is always the same: a fact recorded in two places, changed in one.
So this walks the pairs and fails on any that have come apart. It is not a
style checker and it does not lint - `make lint` and `make test` already run -
it only compares derived facts with their sources.

    make release-check

Every check names what it compared and where, because a gate whose failure
message is "release check failed" gets skipped with `--no-verify` the first
time somebody is in a hurry.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


class DriftError(Exception):
    """Two places recorded one fact and they no longer agree."""


CHECKS: list = []


def check(title: str):
    def register(function):
        CHECKS.append((title, function))
        return function

    return register


# --------------------------------------------------------------------------
# Version, in every place it is written
# --------------------------------------------------------------------------


@check("the package version is the same number everywhere it appears")
def version_is_consistent() -> str:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    declared = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    if not declared:
        raise DriftError("pyproject.toml declares no version")
    version = declared.group(1)

    init = (ROOT / "src" / "actaira" / "__init__.py").read_text(encoding="utf-8")
    module = re.search(r'__version__\s*=\s*"([^"]+)"', init)
    if not module:
        raise DriftError("src/actaira/__init__.py declares no __version__")
    if module.group(1) != version:
        raise DriftError(
            f"pyproject.toml says {version}, src/actaira/__init__.py says {module.group(1)}"
        )

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"[{version}]" not in changelog and f"## {version}" not in changelog:
        raise DriftError(
            f"CHANGELOG.md has no entry for {version}. A release with no changelog entry is "
            "a release nobody can read the diff of."
        )

    citation = ROOT / "CITATION.cff"
    if citation.is_file():
        cited = re.search(r"^version:\s*(.+)$", citation.read_text(encoding="utf-8"), re.M)
        if cited and cited.group(1).strip().strip('"') != version:
            raise DriftError(f"CITATION.cff says {cited.group(1).strip()}, the package says {version}")

    # What the user actually sees. `actaira --version` reads the installed
    # distribution's metadata, not `__version__`, so an editable install left
    # over from an earlier release reports the earlier number while every file
    # above says the new one. That is the exact drift §2.1 asks the gate to
    # refuse, and it is invisible to a check that only reads files.
    spoken = subprocess.run(  # noqa: S603 - a fixed argv, no shell
        [sys.executable, "-m", "actaira", "--version"],
        capture_output=True, text=True, cwd=ROOT, timeout=120,
    )
    if spoken.returncode != 0:
        raise DriftError(f"`actaira --version` exited {spoken.returncode}: {spoken.stderr.strip()}")
    said = spoken.stdout.strip().split()[-1]
    if said != version:
        raise DriftError(
            f"`actaira --version` says {said}, the package says {version}. "
            "Reinstall with `pip install -e .` if this is a stale editable install."
        )

    # The two places that pin a tag for somebody else's CI. A pre-commit
    # `rev:` two majors old is an example that installs a tool without the
    # rules it documents; the composite action's comment is read the same way.
    pinned = {".pre-commit-hooks.yaml": r"rev:\s*v([\d.]+)"}
    checked_pins = 0
    for name, pattern in pinned.items():
        path = ROOT / name
        if not path.is_file():
            continue
        for found in re.findall(pattern, path.read_text(encoding="utf-8")):
            checked_pins += 1
            if found != version:
                raise DriftError(f"{name} pins v{found}, the package says {version}")

    # Counted rather than typed. This line said "the two tag pins" for a commit
    # after `.github/actions/actaira-scan` was deleted, which is a gate reporting
    # a comparison it did not make - the defect this whole script exists to
    # refuse, in the script's own success message.
    return (
        f"{version}, in pyproject.toml, __init__.py, CHANGELOG.md, CITATION.cff, "
        f"`actaira --version` and {checked_pins} tag pin(s)"
    )


# --------------------------------------------------------------------------
# Figures, rules, schemas
# --------------------------------------------------------------------------


@check("the licence is the same one everywhere it is stated")
def licence_is_consistent() -> str:
    """One licence, five files, and nothing compared them until phase A.

    The repository was MIT and became Apache-2.0, which is four files plus both
    READMEs, and a relicensing that reaches some of them is worse than one that
    reaches none: a reader who opens `LICENSE` and a reader who reads the
    README's footer come away with different rights.

    `docs/GOVERNANCE.md` states the boundary rule as "if it is in this
    repository, it is <licence>, and it is free forever". That sentence is the
    business boundary of an open core, so it is checked rather than trusted.
    """
    declared = re.search(r'^license\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M)
    if not declared:
        raise DriftError("pyproject.toml declares no licence")
    licence = declared.group(1)

    body = (ROOT / "LICENSE").read_text(encoding="utf-8")
    heads = {"Apache-2.0": "Apache License", "MIT": "MIT License"}
    if licence not in heads:
        raise DriftError(f"pyproject.toml declares {licence!r}, which this check does not know how to read")
    if heads[licence] not in body:
        raise DriftError(f"pyproject.toml says {licence} and LICENSE does not carry the {heads[licence]} text")

    stated = {"pyproject.toml": licence, "LICENSE": licence}
    citation = re.search(r"^license:\s*(\S+)", (ROOT / "CITATION.cff").read_text(encoding="utf-8"), re.M)
    if not citation:
        raise DriftError("CITATION.cff declares no licence")
    stated["CITATION.cff"] = citation.group(1)

    # The Dockerfile states the licence in an OCI label, which is metadata a
    # registry and every scanner downstream will read and nothing here compared
    # until phase A.1. It said MIT for a whole commit after the relicensing.
    for page in ("README.md", "README.es.md", "docs/GOVERNANCE.md", "Dockerfile"):
        text_of = (ROOT / page).read_text(encoding="utf-8")
        found = {name for name in heads if name in text_of}
        if found != {licence}:
            raise DriftError(
                f"{page} names {sorted(found) or 'no licence'} and pyproject.toml says {licence}"
            )
        stated[page] = licence

    wrong = sorted(name for name, value in stated.items() if value != licence)
    if wrong:
        raise DriftError(f"{', '.join(wrong)} disagree with pyproject.toml's {licence}")
    return f"{licence}, in {len(stated)} files that all agree"


@check("every figure the READMEs state is the one the code and the harnesses report")
def readme_figures_are_current() -> str:
    """Design note D-230, and the check the 2.2.0 audit showed was missing.

    The gate used to compare exactly one figure - the test count - and
    `sync_readme_figures.py` wrote five. Everything else in the prose was
    typed by hand and stayed as it was typed, so by 2.2.0 the README said
    "sixty-six defects across 11 mechanisms" three lines below a synced line
    saying 109, and "seven schemas" when fourteen families ship.

    Both scripts now read one table, `scripts/figures_contract.py`. This is
    the half that refuses a tree, and it names the command that fixes it,
    because a gate whose only remedy is a manual edit gets routed around
    (D-181).
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    from figures_contract import figures, markup_split_problems, number_word_problems

    table = figures()
    problems: list[str] = []
    checked = 0
    from figures_contract import BILINGUAL_PAGES, PAGES

    for name in PAGES:
        text = (ROOT / name).read_text(encoding="utf-8")
        problems.extend(number_word_problems(name, text))
        # A figure separated from its noun by markup is invisible to every
        # pattern in the table, so it is never written and never compared.
        # That is how the hero of both READMEs kept saying 3,226 tests for a
        # release that collected 3,233, three lines above a `make test`
        # comment that was right.
        problems.extend(markup_split_problems(name, text))
        for figure in table:
            pattern = figure.patterns.get(name)
            if pattern is None:
                continue  # this figure does not live on this page
            found = re.findall(pattern, text)
            if not found:
                continue
            expected = figure.rendered(name)
            checked += len(found)
            wrong = sorted({item for item in found if item != expected})
            if wrong:
                problems.append(
                    f"{name}: {figure.name} is written as {', '.join(wrong)} and "
                    f"{figure.source} says {expected}"
                )
    # §2.1 asks for the two languages to fail CI when they diverge on a
    # critical metric. Checking each against its source catches a wrong
    # figure; it does not catch a figure one language states and the other
    # dropped, which is how README.es.md lost the `docs/FIGURES.md`
    # paragraph and kept everything around it.
    for figure in table:
        if not all(page in figure.patterns for page in BILINGUAL_PAGES):
            continue  # an English-only page has no second copy to disagree with
        present = {
            name: bool(re.search(figure.patterns[name], (ROOT / name).read_text(encoding="utf-8")))
            for name in BILINGUAL_PAGES
        }
        if len(set(present.values())) > 1:
            stated = [name for name, yes in present.items() if yes]
            missing = [name for name, yes in present.items() if not yes]
            problems.append(
                f"{figure.name} is stated in {stated[0]} and not in {missing[0]}: "
                "the two languages must carry the same figures"
            )

    if problems:
        raise DriftError("\n".join([*problems, "Run `make figures`."]))
    if not checked:
        # A valid state, deliberately. Phase A rewrote both READMEs around what
        # the four commands do rather than around counts of things, and a page
        # that states no figure has no figure to drift. This is said out loud
        # rather than reported as "0 figures", because a gate that passes having
        # compared nothing should announce that it compared nothing. What keeps
        # it honest is `figures_match` below, which re-measures the tree against
        # figures.json whatever the prose says.
        return f"no figure is stated on any of the {len(PAGES)} guarded pages"
    return f"{checked} figures across {len(PAGES)} pages, each matching its source"


# Everything `figures.json` records, and how each block is measured again.
# `generated_at` is a stamp rather than a figure and is excluded by name; `git`
# is checked separately, against the commit it names rather than against HEAD.
REMEASURED = ("package", "tests", "defects", "code", "docs", "catalog")


@check("every figure in the measurement file matches the working tree")
def figures_match() -> str:
    """All of them, because it used to be one of them.

    This check was titled "the measurement file itself matches the working
    tree" and re-measured `tests.collected` and nothing else. Everything the
    prose publishes off the other blocks - lines of Python, design notes, the
    per-area table, the documentation totals - drifted freely, and did: the
    commit that closed phase 1 published `code.total.lines = 34942` over a
    tree with 34951 in it, with every check in this file green.

    `readme_figures_are_current` does not cover it either. That one compares
    the READMEs against `figures.json`, so a stale measurement file makes both
    sides agree on the same wrong number. This is the side that has to be
    pinned to the code.

    Rule 6 of CLAUDE.md is that no published figure lacks a command that
    measures it. A gate that measured one of them was that rule's own
    machinery breaking it.
    """
    figures_path = ROOT / "figures.json"
    if not figures_path.is_file():
        raise DriftError("figures.json is missing. Run `make figures`.")
    recorded = json.loads(figures_path.read_text(encoding="utf-8"))

    sys.path.insert(0, str(ROOT / "scripts"))
    import figures as figures_module

    tests = figures_module.measure_tests()
    if not tests.get("available") or not tests.get("collected"):
        # `_collect_count` exists for this: a checker that cannot find what it
        # audits has not passed, it has stopped looking. Both sides agreeing
        # that the suite could not be collected is not agreement.
        raise DriftError(
            f"the suite would not collect, so nothing here was measured "
            f"(pytest reports {_collect_count()} tests). Fix the suite first."
        )
    node_ids = set(tests.pop("_node_ids", [])) if tests.get("available") else None
    measured = {
        "package": figures_module.measure_package(),
        "tests": tests,
        "defects": figures_module.measure_defects(node_ids),
        "code": figures_module.measure_areas(),
        "docs": figures_module.measure_docs(),
        "catalog": figures_module.measure_catalog(),
    }

    drifted = [
        line
        for block in REMEASURED
        for line in _differences(block, recorded.get(block), measured[block])
    ]
    git_drift, git_note = _git_figures_drift(recorded.get("git") or {})
    drifted += git_drift
    if drifted:
        raise DriftError("\n".join([*sorted(drifted)[:20], "Run `make figures`."]))
    counted = sum(1 for block in REMEASURED for _ in _leaves(block, measured[block]))
    return (
        f"{counted} measured figures across {len(REMEASURED)} blocks, each matching the tree"
        f"{git_note}"
    )


def _leaves(trail: str, value: Any):
    """Every scalar in a measured block, with the path that reaches it."""
    if isinstance(value, dict):
        for key in sorted(value):
            yield from _leaves(f"{trail}.{key}", value[key])
    elif isinstance(value, list):
        yield trail, tuple(value)
    else:
        yield trail, value


def _differences(block: str, recorded: Any, measured: Any) -> list[str]:
    was = dict(_leaves(block, recorded if recorded is not None else {}))
    now = dict(_leaves(block, measured))
    lines = []
    for trail in sorted(set(was) | set(now)):
        if was.get(trail, "<absent>") != now.get(trail, "<absent>"):
            lines.append(f"figures.json {trail} is {was.get(trail, '<absent>')}, the tree measures {now.get(trail, '<absent>')}")
    return lines


def _git_figures_drift(recorded: dict) -> tuple[list[str], str]:
    """The git block, against the commit it names rather than against HEAD.

    `make figures` runs before the commit it is committed in, so a check that
    compared these to HEAD would fail on every tree by construction. What is
    checkable is that the commit named exists, is an ancestor of HEAD, and
    really has the count and the date recorded beside it - which is what makes
    "12 commits, most recent 2026-09-15" a measured figure rather than a
    sentence nobody can regenerate.
    """
    if not recorded.get("available"):
        return [], ""
    head = recorded.get("head")
    if not head:
        return ["figures.json records git as available with no commit named"], ""

    executable = shutil.which("git")

    def git(*arguments: str) -> str | None:
        if executable is None:  # pragma: no cover - no git on the machine
            return None
        try:
            completed = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
                [executable, *arguments], cwd=ROOT, capture_output=True, text=True, timeout=30
            )
        except (OSError, subprocess.SubprocessError):  # pragma: no cover - no git
            return None
        return completed.stdout.strip() if completed.returncode == 0 else None

    # `test_the_gate_passes_on_this_repository` copies the tree somewhere with
    # no `.git`, and so does an unpacked sdist. A figure that cannot be
    # re-measured THERE is not a figure that is wrong; it is one this copy
    # cannot check, and the summary line says which of the two happened rather
    # than letting a silent skip read as a pass.
    # "Is this a checkout" is not "is this inside one". The first version asked
    # `--is-inside-work-tree`, and on a machine whose HOME is itself a
    # repository every temp directory answers yes - so the copy that
    # `test_the_gate_passes_on_this_repository` makes was asked about a commit
    # belonging to a repository it is not in. The question is whether this tree
    # is the ROOT of its own, which is what `make source-archive` already asks.
    top = git("rev-parse", "--show-toplevel")
    if top is None or Path(top).resolve() != ROOT.resolve():
        return [], ", and the git figures were not re-measured: this tree is not a checkout"
    if git("rev-parse", "--verify", f"{head}^{{commit}}") is None:
        return [f"figures.json names commit {head}, which is not in this repository"], ""
    if git("merge-base", "--is-ancestor", head, "HEAD") is None:
        return [f"figures.json names commit {head}, which is not an ancestor of HEAD"], ""
    lines = []
    for field, arguments in (
        ("commits", ("rev-list", "--count", head)),
        ("head_date", ("log", "-1", "--format=%ad", "--date=short", head)),
    ):
        actual = git(*arguments)
        if actual is not None and str(recorded.get(field)) != actual:
            lines.append(f"figures.json git.{field} is {recorded.get(field)}, {head} has {actual}")
    return lines, ""


def _collect_count() -> int:
    """Ask pytest how many tests exist, and refuse to guess if it cannot say.

    An earlier version returned None when collection failed and the caller
    skipped the comparison, so a tree where the suite would not even import
    passed this check with a green tick. A checker that cannot find what it
    audits has not passed; it has stopped looking.
    """
    # `-o addopts=` clears the `-q` this project sets in pyproject.toml, so
    # `-q --collect-only` prints one node id per line. With two `-q` pytest
    # prints per-file totals and no grand total, which is what the first
    # version of this function tried to parse - it found nothing, returned
    # None, and the caller skipped the comparison. The check passed on every
    # tree, including one where the suite would not import. Counting node ids
    # is the same method `scripts/figures.py` uses, so the two cannot disagree
    # about what a test is.
    try:
        result = subprocess.run(  # noqa: S603 - a fixed argv, no shell
            [sys.executable, "-m", "pytest", "tests", "--collect-only", "-q",
             "-p", "no:cacheprovider", "-o", "addopts="],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=900,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DriftError(f"pytest could not be run to count the tests: {exc}") from exc
    collected = sum(
        1 for line in result.stdout.splitlines() if line.startswith("tests/") and "::" in line
    )
    if not collected:
        tail = "\n".join((result.stdout + result.stderr).strip().splitlines()[-5:])
        raise DriftError(f"pytest collected nothing:\n{tail}")
    return collected


@check("every rule the catalogue defines is translated, and none is undocumented")
def rules_are_documented() -> str:
    """Two directions, and a third that has no page to point at yet.

    This read `docs/FORMATS.md` for the rule table until phase A.1 archived it
    with the scanner that owned those rules. A live gate reading an archived
    document is the same defect one level up, so the table half is not re-pointed
    at the archive - it is held open.

    This tree emits no rule identifiers: the forty-one in the catalogue belonged
    to the scanner and to the conformance package, and both left in phase A. So
    the catalogue must be empty, and that is asserted here rather than letting an
    empty catalogue make the two loops below pass over nothing.

    When phase B lands the rule packages, each rule carries its own id, version,
    package and author, and the page that documents them does not exist yet. The
    `documented` half comes back with it, pointed at whatever that page turns out
    to be; `docs/BACKLOG.md` carries the line.
    """
    en = json.loads((ROOT / "src" / "actaira" / "i18n" / "en.json").read_text(encoding="utf-8"))
    es = json.loads((ROOT / "src" / "actaira" / "i18n" / "es.json").read_text(encoding="utf-8"))

    missing_es = sorted(set(en["rules"]) - set(es["rules"]))
    if missing_es:
        raise DriftError(f"rules with no Spanish text: {', '.join(missing_es)}")
    extra_es = sorted(set(es["rules"]) - set(en["rules"]))
    if extra_es:
        raise DriftError(f"rules with Spanish text and no English: {', '.join(extra_es)}")

    undocumented = sorted(set(en["rules"]) | set(es["rules"]))
    if undocumented:
        raise DriftError(
            "the catalogue carries rule text again and the page that documents a rule "
            f"does not exist yet: {', '.join(undocumented)}. Add the page, and re-point "
            "this check at it: a rule with no documentation is a rule id whose link "
            "goes nowhere."
        )
    return "0 rules, and both catalogues agree that there are none"


@check("no module writes a schema version of its own")
def the_version_is_recorded_once() -> str:
    """Five pairs of copies until phase A, with this check as their referee.

    It asserted that a module constant and a schema `const` agreed. A check that
    arbitrates between two copies of one fact passes for exactly as long as
    somebody keeps them in step, and the thing it is really protecting is that
    there should be one copy. So it is inverted: the registry is the only place a
    version may be written, `trace/model.py` reads `schemas.VERSIONS`, and this
    fails on a version literal anywhere else under `src/`.
    """
    from actaira import schemas
    from actaira.trace import model as trace_model

    literal = re.compile(r"""['"][a-z-]+/v\d+['"]""")
    offenders = []
    for path in sorted((ROOT / "src" / "actaira").rglob("*.py")):
        if "__pycache__" in path.parts or path.parent.name == "schemas":
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            for hit in literal.findall(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {hit}")
    if offenders:
        raise DriftError(
            "a schema version is written outside src/actaira/schemas/, so two places "
            "record one fact:\n" + "\n".join(offenders)
            + "\nRead it from `schemas.VERSIONS` instead."
        )

    if trace_model.SCHEMA_VERSION != schemas.VERSIONS["trace"]:
        raise DriftError("the reader does not take its version from the registry")
    published = schemas.load(schemas.stem(trace_model.SCHEMA_VERSION))
    if published["properties"]["schema_version"]["const"] != trace_model.SCHEMA_VERSION:
        raise DriftError("the schema file disagrees with the registry entry that names it")
    return f"{len(schemas.VERSIONS)} live contract, its version written in one place"


# --------------------------------------------------------------------------
# Documents that describe the code
# --------------------------------------------------------------------------


@check("every design-note row points at the line that argues it")
def design_note_lines_are_current() -> str:
    """Both READMEs say each note "names the file and line that implements it".

    The suite checks the file and not the line, because a row three lines off
    is still a working reference and a test that failed on every edit would be
    noise. That tolerance is right and it is not unbounded: by 2.2.0 fifteen
    rows were between 28 and 412 lines off, several landing on a blank line,
    and one pointed into a different function entirely. A number that wrong is
    not a stale reference, it is a wrong one, and the README's sentence was a
    claim the file did not keep.

    The line is derivable, so `scripts/design_notes.py` derives it and this
    refuses a tree where it has not been run. See D-237.
    """
    import subprocess as sp

    run = sp.run(  # noqa: S603 - a fixed argv, no shell
        [sys.executable, "scripts/design_notes.py", "--check"],
        cwd=ROOT, capture_output=True, text=True, timeout=180,
    )
    if run.returncode != 0:
        raise DriftError(run.stderr.strip() or run.stdout.strip())
    return run.stdout.strip()


@check("every design note written in the code is in the table")
def design_notes_are_listed() -> str:
    design = (ROOT / "docs" / "DESIGN.md").read_text(encoding="utf-8")
    listed = set(re.findall(r"^\| (D-\d+[a-z]?) \|", design, re.M))
    written: set[str] = set()
    for directory in ("src", "evals", "fuzz", "scripts"):
        for path in (ROOT / directory).rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            written.update(re.findall(r"[Dd]esign note (D-\d+[a-z]?)", path.read_text(encoding="utf-8")))
    orphans = sorted(written - listed)
    if orphans:
        raise DriftError(f"notes argued in the code and absent from the table: {', '.join(orphans)}")
    return f"{len(written)} notes, all listed"


@check("the CLI's commands are the ones the documentation lists")
def readme_documents_the_commands() -> str:
    """A command nobody can find is a command nobody uses.

    This followed the index into `docs/CONCEPTS.md`, which phase A.1 archived
    with the scanner. There are four commands now rather than twenty-two, so the
    index is back where a reader looks first: both READMEs list them, and
    `docs/COMPATIBILITY.md` states them as a surface with a promise attached.

    Three pages rather than two, and both languages, because a command named in
    English and missing in Spanish is the parity failure this repository already
    had once.
    """
    from actaira.cli import build_parser

    parser = build_parser()
    commands: set[str] = set()
    for action in parser._subparsers._group_actions:  # noqa: SLF001 - argparse has no public API
        commands.update(action.choices)

    pages = {
        name: (ROOT / name).read_text(encoding="utf-8")
        for name in ("README.md", "README.es.md", "docs/COMPATIBILITY.md")
    }
    for page, text in pages.items():
        undocumented = sorted(name for name in commands if f"actaira {name}" not in text)
        if undocumented:
            raise DriftError(
                f"commands {page} never mentions: {', '.join(undocumented)}. "
                "A command nobody can find is a command nobody uses."
            )
    return f"{len(commands)} commands, each named on all {len(pages)} pages that list them"


@check("the published contract index is the one the package ships")
def contracts_index_is_current() -> str:
    """`docs/CONTRACTS.md` is generated, so the only question is whether the
    generated file on disk is the one this tree would produce. Regenerating
    into a temporary path and comparing is the whole check: a page that is
    merely *checked* against the registry drifts in its prose, and a page
    nobody regenerates is the fourth stale copy D-232 exists to prevent.
    """
    import subprocess as sp
    import tempfile

    page = ROOT / "docs" / "CONTRACTS.md"
    if not page.is_file():
        raise DriftError("docs/CONTRACTS.md is missing. Run `make contracts`.")
    before = page.read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory():
        run = sp.run(  # noqa: S603 - a fixed argv, no shell
            [sys.executable, "scripts/contracts_doc.py"],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )
    if run.returncode != 0:
        raise DriftError(f"scripts/contracts_doc.py failed: {run.stderr.strip()}")
    after = page.read_text(encoding="utf-8")
    if after != before:
        raise DriftError(
            "docs/CONTRACTS.md was not the page this tree produces; it has been "
            "rewritten. Commit the change."
        )
    return run.stdout.strip().split(": ", 1)[-1] + ", and the page on disk matches"


@check("the CLI prints the same bytes twice")
def cli_output_is_deterministic() -> str:
    """Design note D-234. The READMEs show console blocks, and a console block
    is a screenshot in text.

    This used to be checked by regenerating `site-data.json` - an export whose
    only consumer was a website outside this repository - and comparing it
    byte for byte. The export is gone with the website it fed; the property it
    carried was real and stayed.

    Three commands are run twice, in two subprocesses, under different
    `PYTHONHASHSEED` values, against artifacts written from literal bytes with
    the decision date pinned. Anything that differs between the two runs is
    something that reached the terminal from a set, a dict ordering, a clock
    or an address, and a tool whose report is signed into an attestation does
    not get to print a different report for the same bytes.
    """
    import os
    import subprocess as sp

    outputs = []
    for seed in ("0", "1"):
        environment = dict(os.environ, PYTHONHASHSEED=seed)
        run = sp.run(  # noqa: S603 - a fixed argv, no shell
            [sys.executable, "scripts/cli_transcripts.py"],
            cwd=ROOT, capture_output=True, text=True, timeout=180, env=environment,
        )
        if run.returncode != 0:
            raise DriftError(f"scripts/cli_transcripts.py failed: {run.stderr.strip()}")
        outputs.append(run.stdout)

    if outputs[0] != outputs[1]:
        first = outputs[0].splitlines()
        second = outputs[1].splitlines()
        for index, (left, right) in enumerate(zip(first, second, strict=False)):
            if left != right:
                raise DriftError(
                    "the same command printed different bytes under two hash seeds, "
                    f"first at line {index + 1}:\n"
                    f"  PYTHONHASHSEED=0: {left[:160]}\n"
                    f"  PYTHONHASHSEED=1: {right[:160]}"
                )
        raise DriftError("the two runs differ in length; one printed more than the other")

    transcripts = json.loads(outputs[0])
    return f"{len(transcripts)} command(s), byte-identical under two hash seeds"


@check("every image in docs/img is one a document displays")
def every_image_is_displayed() -> str:
    """An image nothing shows is not documentation, and this is how one gets in.

    `make screenshots` used to write all eight captures into `docs/img/` and
    keep two of them out of git, on the argument that an image nothing displays
    is not documentation. Both halves of that were right and the arrangement
    was still wrong: untracked is not absent, so a delivered copy of this tree
    carried `01-welcome.png` and `07-mobile.png` showing v1.0.0 next to six
    images showing v2.2.0, and nothing anywhere compared them.

    The captures nothing displays go to `.screenshots/` now. This is the check
    that keeps it that way, and it is a check about the directory rather than
    about those two names: any file that lands in `docs/img/` and is not shown
    by a README or a document fails, whatever it is called.
    """
    shown: set[str] = set()
    for page in [ROOT / "README.md", ROOT / "README.es.md", *sorted((ROOT / "docs").glob("*.md"))]:
        text = page.read_text(encoding="utf-8")
        prefix = "" if page.parent == ROOT else "docs/"
        for reference in re.findall(
            r'(?:!\[[^\]]*\]\(|<img src="|<source[^>]*srcset=")([^")\s]+)', text
        ):
            name = reference.split("/")[-1]
            if reference.startswith(("docs/img/", "img/")) or f"{prefix}img/" in reference:
                shown.add(name)

    images = ROOT / "docs" / "img"
    on_disk = {path.name for path in images.iterdir() if path.is_file()} if images.is_dir() else set()
    orphans = sorted(on_disk - shown)
    if orphans:
        raise DriftError(
            "docs/img/ holds image(s) no document displays: " + ", ".join(orphans) + "\n"
            "An image nothing shows is not documentation. `make screenshots` writes "
            "the captures that are only a smoke test into .screenshots/; move these "
            "there, or display them."
        )
    missing = sorted(shown - on_disk)
    if missing:
        raise DriftError("a document displays image(s) that are not there: " + ", ".join(missing))
    if not on_disk:
        # Not a hole in the check: the scanner's 26 captures and six diagrams
        # went with the interface they showed, and phase 5 draws the two this
        # product needs. Zero displayed images is the honest state until then.
        return "no images in docs/img, and no document displays one"
    return f"{len(on_disk)} image(s) in docs/img, every one of them displayed"


@check("the two READMEs have the same shape")
def readmes_match() -> str:
    english = (ROOT / "README.md").read_text(encoding="utf-8")
    spanish = (ROOT / "README.es.md").read_text(encoding="utf-8")

    def slots(text: str) -> list[str]:
        """Local images only, with the ordinal and the language suffix gone.

        Badges are excluded because their labels are translated - `licence`
        against `licencia` - and comparing those would force one language to
        carry the other's wording. `06-governance-es.png` and
        `04-governance.png` are the same slot: a localised README should show
        the localised screenshot, and what matters is that both files
        illustrate the same things in the same order.
        """
        names = re.findall(
            r'(?:!\[[^\]]*\]\(|<img src="|<source[^>]*srcset=")(docs/img/[^")\s]+)', text
        )
        return [re.sub(r"^\d+-|-es(?=\.)|\.(png|svg)$", "", name.split("/")[-1]) for name in names]

    if slots(english) != slots(spanish):
        raise DriftError(
            "the two READMEs show different pictures:\n"
            f"  en: {slots(english)}\n  es: {slots(spanish)}"
        )

    def headings(text: str) -> list[int]:
        return [len(match) for match in re.findall(r"^(#+) ", text, re.M)]

    if headings(english) != headings(spanish):
        raise DriftError(
            f"the two READMEs have different section structures: "
            f"{len(headings(english))} headings in English, {len(headings(spanish))} in Spanish"
        )
    return f"{len(slots(english))} images and {len(headings(english))} headings in both"


@check("every defect id written anywhere in the tree is in the ledger")
def defect_ids_are_real() -> str:
    """The ledger was only ever checked in one direction.

    `defects_point_at_real_tests` walks ledger to tests; nothing walked tests
    to ledger, so a comment naming an id two digits past the end of the file
    sat above the regression test for a real one. A reader following that id
    finds nothing and concludes the ledger is incomplete, which is the
    opposite of true.

    This docstring deliberately names no id: the check reads every tracked
    Python and Markdown file including this one, so an example here would be
    a finding about itself.
    """
    import subprocess as sp

    ledger = {
        item["id"]
        for item in json.loads((ROOT / "docs" / "defects.json").read_text(encoding="utf-8"))["defects"]
    }
    git = shutil.which("git")
    if git is None:
        raise DriftError("git is not on PATH, so the tracked file list cannot be read")
    tracked = sp.run(  # noqa: S603 - a resolved path and a fixed argv, no shell
        [git, "ls-files"], cwd=ROOT, capture_output=True, text=True, timeout=120,
    ).stdout.split()
    unknown: dict[str, list[str]] = {}
    for name in tracked:
        path = ROOT / name
        if path.suffix not in (".py", ".md", ".yaml", ".yml", ".toml") or name == "docs/defects.json":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for found in set(re.findall(r"\bDEF-\d+\b", text)):
            if found not in ledger:
                unknown.setdefault(found, []).append(name)
    if unknown:
        raise DriftError(
            "defect id(s) referenced in the tree that the ledger does not have: "
            + "; ".join(f"{item} in {', '.join(where)}" for item, where in sorted(unknown.items()))
        )
    return f"{len(ledger)} entries, and no reference anywhere to an id outside them"


@check("the defect ledger names tests that exist")
def defects_point_at_real_tests() -> str:
    ledger = json.loads((ROOT / "docs" / "defects.json").read_text(encoding="utf-8"))
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "tests").rglob("test_*.py")
    )
    missing: list[str] = []
    for defect in ledger["defects"]:
        for reference in defect.get("pinned_by", []):
            name = reference.rsplit("::", 1)[-1]
            if f"def {name}(" not in sources:
                missing.append(f"{defect['id']} -> {name}")
    if missing:
        raise DriftError("defects naming tests that do not exist:\n  " + "\n  ".join(missing))
    return f"{len(ledger['defects'])} defects, every pinning test present"


# --------------------------------------------------------------------------
# 2.2: state, contracts and the vocabulary the UI shows
# --------------------------------------------------------------------------


@check("every published contract is still on disk and nothing emits a superseded one")
def superseded_contracts_are_kept_and_not_written() -> str:
    """The compatibility promise, in both directions.

    A published contract stays published, because a consumer written against
    it is old rather than wrong. And nothing here may still emit one: a
    producer that can write the old shape will, on some branch nobody
    exercised, and the reader on the other end will take the old meaning out
    of a new document.
    """
    import importlib

    from actaira import schemas

    for versions in schemas.SUPERSEDED.values():
        for version in versions:
            if schemas.stem(version) not in schemas.names():
                raise DriftError(f"{version} was published and its schema file is gone")

    emitters = {"trace": ("actaira.trace.model", "SCHEMA_VERSION")}
    for family, (module_path, constant) in emitters.items():
        stated = getattr(importlib.import_module(module_path), constant)
        if stated in schemas.SUPERSEDED.get(family, ()):
            raise DriftError(f"{module_path}.{constant} still emits the superseded {stated}")
        if stated != schemas.VERSIONS[family]:
            raise DriftError(f"{module_path}.{constant} is {stated}, the registry says {schemas.VERSIONS[family]}")
    # And the other direction: the count the prose states comes from a glob
    # over this directory, so a file dropped in it that no registry entry
    # names would raise the published figure without publishing anything.
    registered = {schemas.stem(version) for version in schemas.VERSIONS.values()}
    registered |= {
        schemas.stem(version)
        for versions in schemas.SUPERSEDED.values()
        for version in versions
    }
    orphans = sorted(set(schemas.names()) - registered)
    if orphans:
        raise DriftError(
            "schema file(s) on disk that neither VERSIONS nor SUPERSEDED names, so the "
            "published contract count counts them and no consumer can reach them: "
            + ", ".join(orphans)
        )

    superseded = sum(len(versions) for versions in schemas.SUPERSEDED.values())
    return f"{len(schemas.names())} contracts on disk, {superseded} superseded and still readable"


@check("no document introduces a score, a grade or a percentage")
def nothing_scores() -> str:
    """The refusal, checked against the shapes a summary hides in.

    Property names rather than prose: the receipt's own description says "not
    a score", and an earlier version of this check read that sentence as a
    violation of itself.
    """
    from actaira import schemas

    forbidden = ("score", "grade", "rating", "percent")
    offenders: list[str] = []
    for name in schemas.names():
        schema = schemas.load(name)
        stack = [("", schema)]
        while stack:
            prefix, node = stack.pop()
            if not isinstance(node, dict):
                continue
            for key, value in (node.get("properties") or {}).items():
                if any(word in key.lower() for word in forbidden):
                    offenders.append(f"{name}.{prefix}{key}")
                stack.append((f"{prefix}{key}.", value))
            items = node.get("items")
            if isinstance(items, dict):
                stack.append((prefix, items))
    if offenders:
        raise DriftError(
            "properties that would let a summary stand in for evidence: " + ", ".join(offenders)
        )
    return f"{len(schemas.names())} contracts, none carrying a score-shaped field"


@check("no third-party run output is tracked, so a benchmark leaves no diff")
def run_output_stays_out_of_the_index() -> str:
    """DEF-53, held down where it happened.

    `make benchmark` invokes fickling as a subprocess, the way a user would,
    and fickling *appends* its own scan output to `safety_results.json` in the
    working directory. That file was tracked, so every benchmark run produced
    a 300 KB diff of another tool's output stacked on the previous run's.
    Reviewing it told a reader nothing, and it was the only run artifact in
    the repository that was not ignored.

    The fix was one line in `.gitignore`, which is exactly the kind of fix a
    later edit undoes by accident: rewrite the ignore file, drop a line, and
    nothing goes wrong until the next benchmark run quietly stages 300 KB of
    somebody else's JSON. So both halves are asserted, the ignore rule and the
    index itself, rather than trusting the rule to still be there.

    `evals/benchmark.json` is deliberately the other way round: it is tracked,
    because `docs/FIGURES.md` and the READMEs derive figures from it.
    """
    import subprocess as sp

    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    # Written by a third party into the working directory, never by this repo.
    foreign = ("safety_results.json",)
    missing = [name for name in foreign if name not in {line.strip() for line in ignored}]
    if missing:
        raise DriftError(
            f"{', '.join(missing)} is no longer in .gitignore, so the next benchmark "
            "run will stage another tool's output"
        )

    # The index half only means something inside a checkout. `tests/
    # test_release_check.py` runs this gate against a copy of the tree with
    # `.git` left out, and a check that reported "untracked" from an empty
    # `git ls-files` there would be passing on no evidence, which is the
    # failure mode this whole script exists to refuse. So it says which half
    # it managed to run.
    git = shutil.which("git")
    if git is None:
        raise DriftError("git is not on PATH, so the tracked file list cannot be read")
    listing = sp.run(  # noqa: S603 - a resolved path and a fixed argv, no shell
        [git, "ls-files"], cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    if listing.returncode != 0:
        return (
            f"{len(foreign)} foreign run artifact(s), ignored; the index was not read "
            "because this tree is not a checkout"
        )
    staged = [name for name in foreign if name in set(listing.stdout.split())]
    if staged:
        raise DriftError(
            f"{', '.join(staged)} is tracked again. It is another tool's append-only "
            "log, and a diff of it says nothing about this repository."
        )
    return f"{len(foreign)} foreign run artifact(s), ignored and untracked"


@check("the test suite runs behind an armed network guard")
def the_network_guard_is_armed() -> str:
    """Design note D-267, and the half of it that is not a test.

    `tests/netguard.py` refuses every outbound connection that is not loopback,
    and `tests/conftest.py` installs it for the whole suite. Both of those are
    files somebody can edit. A suite that passes under a guard which has quietly
    stopped biting reads exactly like a suite that is clean, which is the shape
    phase 0.1 took out of `verify` - so this runs the guard's own meta-test in a
    subprocess and fails if it does not pass.

    It CANNOT pass in the empty: `test_the_guard_is_armed_for_this_whole_suite`
    asserts `netguard.armed()`, so a conftest that no longer installs it makes
    this check red rather than vacuously green. Rejected: reading conftest.py
    for the word `netguard`, which is a check on a spelling rather than on a
    behaviour and passes over an install that raises.
    """
    import subprocess as sp

    meta = ROOT / "tests" / "test_netguard.py"
    if not meta.is_file():
        raise DriftError(
            "tests/test_netguard.py is gone, so nothing proves the network guard still "
            "refuses anything and the whole suite's offline claim rests on nobody having "
            "edited tests/netguard.py"
        )
    run = sp.run(  # noqa: S603 - a fixed argv, no shell
        [sys.executable, "-m", "pytest", str(meta), "-q", "-p", "no:cacheprovider",
         "-o", "addopts="],
        cwd=ROOT, capture_output=True, text=True, timeout=300,
    )
    if run.returncode != 0:
        tail = "\n".join((run.stdout + run.stderr).strip().splitlines()[-8:])
        raise DriftError(f"the network guard's own test does not pass:\n{tail}")
    passed = [line for line in run.stdout.splitlines() if "passed" in line]
    return (passed[-1].strip() if passed else "the guard's meta-test passes") + (
        ", so the suite ran with the guard armed"
    )


def main() -> int:
    failures = 0
    print("release-check\n")
    for title, function in CHECKS:
        try:
            detail = function()
        except DriftError as problem:
            failures += 1
            print(f"  FAIL  {title}")
            for line in str(problem).splitlines():
                print(f"        {line}")
        except Exception as exc:  # noqa: BLE001 - a check that crashes is a failed check
            failures += 1
            print(f"  FAIL  {title}")
            print(f"        the check itself raised: {type(exc).__name__}: {exc}")
        else:
            print(f"  ok    {title}")
            print(f"        {detail}")
    print()
    if failures:
        print(f"{failures} of {len(CHECKS)} checks failed. The release is not consistent with itself.")
        return 1
    print(f"all {len(CHECKS)} checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
