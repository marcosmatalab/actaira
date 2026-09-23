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


def tracked_files() -> list[str] | None:
    """What git tracks here, or None when this tree is not a checkout.

    None and not an empty list, and the difference is the whole point:
    `tests/test_release_check.py` runs this gate against a copy of the tree
    with `.git` left out, and a check that read an empty listing there as "no
    files match" would pass on no evidence. Every caller says which of the two
    happened.
    """
    git = shutil.which("git")
    if git is None:
        return None
    listing = subprocess.run(  # noqa: S603 - a resolved path and a fixed argv, no shell
        [git, "ls-files"], cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    if listing.returncode != 0:
        return None
    names = listing.stdout.splitlines()
    return names or None


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

    init = (ROOT / "src" / "seamark" / "__init__.py").read_text(encoding="utf-8")
    module = re.search(r'__version__\s*=\s*"([^"]+)"', init)
    if not module:
        raise DriftError("src/seamark/__init__.py declares no __version__")
    if module.group(1) != version:
        raise DriftError(
            f"pyproject.toml says {version}, src/seamark/__init__.py says {module.group(1)}"
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

    # What the user actually sees. `seamark --version` reads the installed
    # distribution's metadata, not `__version__`, so an editable install left
    # over from an earlier release reports the earlier number while every file
    # above says the new one. That is the exact drift §2.1 asks the gate to
    # refuse, and it is invisible to a check that only reads files.
    spoken = subprocess.run(  # noqa: S603 - a fixed argv, no shell
        [sys.executable, "-m", "seamark", "--version"],
        capture_output=True, text=True, cwd=ROOT, timeout=120,
    )
    if spoken.returncode != 0:
        raise DriftError(f"`seamark --version` exited {spoken.returncode}: {spoken.stderr.strip()}")
    said = spoken.stdout.strip().split()[-1]
    if said != version:
        raise DriftError(
            f"`seamark --version` says {said}, the package says {version}. "
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
    # after `.github/actions/seamark-scan` was deleted, which is a gate reporting
    # a comparison it did not make - the defect this whole script exists to
    # refuse, in the script's own success message.
    return (
        f"{version}, in pyproject.toml, __init__.py, CHANGELOG.md, CITATION.cff, "
        f"`seamark --version` and {checked_pins} tag pin(s)"
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
        # On a word boundary, not as a substring. `docs/LIMITS.md` contains the
        # letters M, I and T in that order, so a substring test reported that
        # the README names MIT the moment a link to the limits page appeared on
        # it. A check that reads a licence out of an unrelated word is not
        # stricter, it is wrong in the direction that gets a gate switched off.
        found = {
            name for name in heads
            if re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w-])", text_of)
        }
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
                # DEF-122. This branch used to `continue`, and that is the whole
                # defect: a pattern that matches nothing was written by nobody,
                # compared against nothing, and reported as nothing. Four figures
                # on `docs/ENGINEERING.md` sat unguarded that way, two of them
                # stale by 8 and 4, under a paragraph claiming all four were
                # measured and gate-refused.
                #
                # A page in `figure.patterns` is a DECLARATION that the figure
                # lives there. Declared and absent is a contradiction, and the
                # only honest answer to it is red. Adjusting the four regexes
                # without this would have set the same trap for the fifth time:
                # any rewording breaks a lookahead, and a broken lookahead was
                # silent.
                problems.append(
                    f"{name}: {figure.name} declares this page, and its pattern "
                    f"{pattern} matches nothing in it. Either the prose moved away "
                    f"from the pattern - between a figure and the noun it counts "
                    f"there may be only whitespace, and no line break inside the "
                    f"phrase the pattern anchors on - or the figure no longer "
                    f"belongs on this page and should stop declaring it."
                )
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

    Work rule 6 is that no published figure lacks a command that
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
    """Three directions, and the page the third one needed finally exists.

    This read `docs/FORMATS.md` until phase A.1 archived it with the scanner that
    owned those rules, and phase A left it asserting that the catalogue was
    EMPTY - which was the honest thing to assert about a tree that emitted no
    rule identifiers, and was explicitly a placeholder: "when phase B lands the
    rule packages [...] the `documented` half comes back with it, pointed at
    whatever that page turns out to be."

    Phase S1 landed them. The page is `docs/RULES.md`, it is generated by
    `scripts/rules_doc.py`, and the three directions are now all askable:

    * every rule the packs define has English text,
    * and Spanish text,
    * and a row on the page.

    The source of truth is the PACKS, not the catalogue. Asserting a catalogue
    against itself proves nothing, which is the argument `tests/test_i18n.py`
    makes at the top of its own file.
    """
    sys.path.insert(0, str(ROOT / "src"))
    from seamark.surface import rules as rule_module

    en = json.loads((ROOT / "src" / "seamark" / "i18n" / "en.json").read_text(encoding="utf-8"))
    es = json.loads((ROOT / "src" / "seamark" / "i18n" / "es.json").read_text(encoding="utf-8"))
    defined = {rule.id for rule in rule_module.load()}
    if not defined:
        raise DriftError(
            "the rule packs define nothing, so every check below passes over an empty set. "
            "src/seamark/surface/packs/ ships with the package; if it is genuinely empty, "
            "this check has to be held open again rather than passing."
        )

    # The catalogues against each other first, then both against the packs.
    # Against each other because that direction catches a rule that was added to
    # one language and not the other whether or not a pack defines it, which is
    # the normal way a second language rots; against the packs because two
    # catalogues that agree with each other and with nothing else are two copies
    # of the same mistake.
    missing_es = sorted(set(en["rules"]) - set(es["rules"]))
    if missing_es:
        raise DriftError(f"rules with no Spanish text: {', '.join(missing_es)}")
    missing_en = sorted((set(es["rules"]) | defined) - set(en["rules"]))
    if missing_en:
        raise DriftError(f"rules with no English text: {', '.join(missing_en)}")
    untranslated = sorted(defined - set(es["rules"]))
    if untranslated:
        raise DriftError(f"rules with no Spanish text: {', '.join(untranslated)}")

    orphans = sorted((set(en["rules"]) | set(es["rules"])) - defined)
    if orphans:
        raise DriftError(
            f"catalogue text for rules no pack defines: {', '.join(orphans)}. Dead text is "
            "translated and reviewed forever."
        )

    page = ROOT / "docs" / "RULES.md"
    if not page.is_file():
        raise DriftError("docs/RULES.md is missing. Run `make rules`.")
    body = page.read_text(encoding="utf-8")
    undocumented = sorted(rule_id for rule_id in defined if f"### {rule_id}" not in body)
    if undocumented:
        raise DriftError(
            f"rules with no row on docs/RULES.md: {', '.join(undocumented)}. Run `make rules`."
        )

    run = subprocess.run(  # noqa: S603 - a fixed argv, no shell
        [sys.executable, "scripts/rules_doc.py", "--check"],
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    if run.returncode != 0:
        raise DriftError(run.stderr.strip() or "scripts/rules_doc.py --check failed")

    return f"{len(defined)} rules, each translated twice and each on the generated page"


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
    from seamark import schemas
    from seamark.trace import model as trace_model

    literal = re.compile(r"""['"][a-z-]+/v\d+['"]""")
    offenders = []
    for path in sorted((ROOT / "src" / "seamark").rglob("*.py")):
        if "__pycache__" in path.parts or path.parent.name == "schemas":
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            for hit in literal.findall(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {hit}")
    if offenders:
        raise DriftError(
            "a schema version is written outside src/seamark/schemas/, so two places "
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
    from seamark.cli import build_parser

    parser = build_parser()
    commands: set[str] = set()
    for action in parser._subparsers._group_actions:  # noqa: SLF001 - argparse has no public API
        commands.update(action.choices)

    pages = {
        name: (ROOT / name).read_text(encoding="utf-8")
        for name in ("README.md", "README.es.md", "docs/COMPATIBILITY.md")
    }
    for page, text in pages.items():
        undocumented = sorted(name for name in commands if f"seamark {name}" not in text)
        if undocumented:
            raise DriftError(
                f"commands {page} never mentions: {', '.join(undocumented)}. "
                "A command nobody can find is a command nobody uses."
            )
    return f"{len(commands)} commands, each named on all {len(pages)} pages that list them"



# --------------------------------------------------------------------------
# What the pages CLAIM, against what the parser can do
# --------------------------------------------------------------------------
#
# Design note D-301. `readme_documents_the_commands` above asks one direction and
# one direction only: is every command that exists NAMED somewhere on the page.
# It cannot ask whether what the page SAYS about it is true, and that gap let a
# real defect stand for a whole phase: after phase S1 built `seamark check`, both
# READMEs went on publishing "Does not exist. No reader, no resolver and no rule
# package in this tree" under the claim that command implements. `check` was
# named further down, so the check above was green while the page said the thing
# did not exist. Phase S2 found it by reading, which is exactly the mechanism
# this project does not accept as a gate.
#
# The criterion, and it is the whole of it: every claim a page makes about a
# command, a flag or an exit code has to resolve against the TREE. What cannot be
# resolved mechanically is not asserted. So each of the three claim blocks
# carries a `Commands:` line naming the commands it rests on, and this check
# reads it in both directions - a block may not name a command that contradicts
# its own status, and a command may not exist without appearing in a block whose
# status says it works.
#
# Rejected: inferring which claim a command belongs to from prose. That is the
# reading the defect survived, performed by a program instead of a person.

# The status words each page is allowed to use, and what they mean here. Per
# language, because a Spanish page that had to write "Built" to satisfy a checker
# is a page bent around its gate.
CLAIM_STATUS = {
    "README.md": {
        "Built": "works",
        "Partly built": "works",
        "Does not exist": "absent",
        "Outside the three claims": "outside",
    },
    "README.es.md": {
        "Construido": "works",
        "Construido en parte": "works",
        "No existe": "absent",
        "Fuera de las tres afirmaciones": "outside",
    },
}
COMMANDS_LABEL = ("Commands:", "Comandos:")
NO_COMMANDS = ("none", "ninguno")


def _claim_blocks(page: str, text: str) -> list[tuple[str, str, list[str]]]:
    """(status, block, commands named on its `Commands:` line) for every claim block."""
    found: list[tuple[str, str, list[str]]] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        opened = re.match(r"^> \*\*([^*]+?)\.?\*\*", line)
        if not opened:
            continue
        word = opened.group(1).strip().rstrip(".")
        if word not in CLAIM_STATUS[page]:
            continue
        block = [line]
        for following in lines[index + 1:]:
            if not following.startswith(">"):
                break
            block.append(following)
        body = "\n".join(block)
        named: list[str] = ["<no Commands: line>"]
        for label in COMMANDS_LABEL:
            if label not in body:
                continue
            # Up to the first full stop, not up to the first newline: the list
            # wraps like every other line of these pages, and cutting at the
            # newline silently dropped whatever came after it - which then read
            # as a command nothing on the page accounts for.
            tail = body.split(label, 1)[1].split(".", 1)[0]
            if any(spelling in tail.lower() for spelling in NO_COMMANDS):
                named = []
            else:
                named = re.findall(r"`seamark (\w+)`", tail)
            break
        found.append((CLAIM_STATUS[page][word], body, named))
    return found


@check("every claim the READMEs make resolves against what the tree can do")
def readme_claims_resolve_against_the_tree() -> str:
    from seamark.cli import build_parser

    parser = build_parser()
    subparsers = parser._subparsers._group_actions[0]  # noqa: SLF001 - argparse has no public API
    commands = set(subparsers.choices)

    claimed_to_work: dict[str, set[str]] = {}
    blocks_seen = 0
    for page in CLAIM_STATUS:
        text = (ROOT / page).read_text(encoding="utf-8")
        blocks = _claim_blocks(page, text)
        claims = [row for row in blocks if row[0] != "outside"]
        outside = [row for row in blocks if row[0] == "outside"]
        if len(claims) != 3 or len(outside) != 1:
            raise DriftError(
                f"{page}: parsed {len(claims)} claim blocks and {len(outside)} "
                "outside-the-claims blocks; there are three claims and one block for "
                "the commands that implement none of them. Either a block lost its "
                "status word, or the vocabulary in CLAIM_STATUS is stale. A check "
                "that parses nothing reports success."
            )
        blocks_seen += len(blocks)
        works: set[str] = set()
        for status, body, named in blocks:
            if named == ["<no Commands: line>"]:
                raise DriftError(
                    f"{page}: a claim block carries no `Commands:` line, so what it "
                    "claims cannot be resolved against the tree. Name the commands it "
                    "rests on, or `Commands: none`. What cannot be checked is not asserted."
                )
            if status in ("works", "outside"):
                missing = sorted(set(named) - commands)
                if not named or missing:
                    raise DriftError(
                        f"{page}: a claim block says it is built and names "
                        f"{named or 'no command'}; the parser has no "
                        f"{', '.join(missing) or 'command at all there'}."
                    )
                works.update(named)
            else:
                present = sorted(set(named) & commands)
                if present:
                    raise DriftError(
                        f"{page}: a claim block says it does not exist and names "
                        f"{', '.join(present)}, which the parser has."
                    )
                spelt = re.search(r"`seamark (" + "|".join(sorted(commands)) + r")`", body)
                if spelt:
                    raise DriftError(
                        f"{page}: a claim block says it does not exist and its prose "
                        f"names `seamark {spelt.group(1)}`, which does. That is the "
                        "phase S1 defect exactly."
                    )
        claimed_to_work[page] = works

    for page, works in claimed_to_work.items():
        orphans = sorted(commands - works)
        if orphans:
            raise DriftError(
                f"{page}: {', '.join(orphans)} exist and no block names them - neither a "
                "claim that says it is built nor the block for the commands that "
                "implement none of the three. A command that works while the page says "
                "its claim is unbuilt is the drift this check exists for, and a command "
                "nothing on the page accounts for is the same hole one step along."
            )
    return (
        f"{blocks_seen} claim blocks across {len(CLAIM_STATUS)} pages, "
        f"each resolved against the parser, and all {len(commands)} commands accounted for"
    )


@check("every flag the documentation shows is a flag the command has")
def documented_flags_exist() -> str:
    """The other half of D-301, and the half with the longest history here.

    `.pre-commit-hooks.yaml` published `seamark scan --fail-on high` for a
    release in which neither `--fail-on` nor the artefact scanning existed, and
    the README advertised `--dsse` for a flag that had never been implemented in
    any commit. Both were prose nothing compared with anything.
    """
    from seamark.cli import build_parser

    parser = build_parser()
    subparsers = parser._subparsers._group_actions[0]  # noqa: SLF001
    options = {
        name: {
            string
            for action in sub._actions  # noqa: SLF001
            for string in action.option_strings
        }
        for name, sub in subparsers.choices.items()
    }

    pages = ("README.md", "README.es.md", "docs/COMMANDS.md", "docs/COMPATIBILITY.md",
             ".pre-commit-hooks.yaml")
    checked = 0
    for page in pages:
        path = ROOT / page
        if not path.is_file():
            raise DriftError(f"{page} is missing, and this check reads it")
        for command, tail in re.findall(
            r"seamark (\w+)([^\n`]*)", path.read_text(encoding="utf-8")
        ):
            if command not in options:
                continue
            for flag in re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", tail):
                checked += 1
                if flag not in options[command]:
                    raise DriftError(
                        f"{page} shows `seamark {command} {flag}` and that command has "
                        f"no such option. Known: {', '.join(sorted(options[command]))}"
                    )
    if checked < 10:
        raise DriftError(
            f"only {checked} flag mentions were found across {len(pages)} pages, which "
            "is fewer than this documentation has. The extraction is broken, and a "
            "check that finds nothing reports success."
        )
    return f"{checked} flag mentions across {len(pages)} pages, each an option the command has"


@check("the exit codes the contract publishes are the ones the CLI defines")
def exit_codes_are_the_published_ones() -> str:
    """The third thing D-301 names. A pipeline branches on these.

    `EXIT_SIGPIPE` is deliberately not in the table and the document says why, so
    it is required to be ABSENT from the table and PRESENT in the prose: a code
    left out by accident and one left out on purpose look identical otherwise.
    """
    from seamark import cli

    published = {
        value
        for name, value in vars(cli).items()
        if name.startswith("EXIT_") and name != "EXIT_SIGPIPE"
    }
    page = (ROOT / "docs" / "COMPATIBILITY.md").read_text(encoding="utf-8")
    table = page.split("## Exit codes", 1)[-1].split("\n## ", 1)[0]
    rows = {int(match) for match in re.findall(r"^\| (\d+) \|", table, re.M)}
    if rows != published:
        raise DriftError(
            f"docs/COMPATIBILITY.md publishes exit codes {sorted(rows)} and the CLI "
            f"defines {sorted(published)}."
        )
    if f"| {cli.EXIT_SIGPIPE} |" in table:
        raise DriftError(
            f"{cli.EXIT_SIGPIPE} is in the exit-code table, and the document states it "
            "is not part of the contract."
        )
    if str(cli.EXIT_SIGPIPE) not in table:
        raise DriftError(
            f"{cli.EXIT_SIGPIPE} is neither in the table nor named in the prose beside "
            "it, so a reader cannot tell a deliberate omission from a forgotten one."
        )
    return (
        f"{len(rows)} exit codes, the set the CLI defines, plus "
        f"{cli.EXIT_SIGPIPE} named as outside it"
    )


@check("the package description names only commands that exist")
def package_metadata_names_real_commands() -> str:
    """`pyproject.toml`'s description is published to every index that reads metadata.

    It said "the commands this release ships are scan, watch, verify and keygen"
    for two phases after `check` shipped. Nothing compared it with anything, and
    it is the one sentence a stranger reads before they install.
    """
    from seamark.cli import build_parser

    commands = set(build_parser()._subparsers._group_actions[0].choices)  # noqa: SLF001
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    description = re.search(r'^description = "(.*)"$', text, re.M)
    if not description:
        raise DriftError("pyproject.toml has no single-line `description`, and this check reads it")
    named = {
        word
        for word in re.findall(r"\b([a-z]+)\b", description.group(1))
        if word in commands
    }
    missing = sorted(commands - named)
    if missing:
        raise DriftError(
            f"pyproject.toml's description lists the commands this release ships and "
            f"leaves out {', '.join(missing)}. A partial list reads as a complete one."
        )
    return f"{len(named)} commands named in the package description, all of them real"

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


def identifier_problems(repository: str, ids: dict[str, str]) -> list[str]:
    """Pure, so a twin can plant a contract published under a rented name.

    Design note D-303. A `$id` is an identity and nothing here fetches one, so
    what it has to be is unambiguous and ours. Held as a prefix rather than as
    a list of known identifiers, because the failure to catch is the schema
    added next year, not the six on disk today.
    """
    namespace = repository.rstrip("/") + "/schemas/"
    problems: list[str] = []
    for name, identifier in sorted(ids.items()):
        if not identifier:
            problems.append(
                f"{name}.json declares no `$id`, so the document it describes has no identity "
                "at all and two of them could not be told apart by a consumer."
            )
        elif not identifier.startswith(namespace):
            problems.append(
                f"{name}.json is published as {identifier}, which is outside "
                f"{namespace}. An identifier under a name this project does not hold is one "
                "somebody else can answer for, and ACT-S003 is this tool refusing exactly that "
                "in other people's trees."
            )
        elif identifier != f"{namespace}{name}.json":
            problems.append(
                f"{name}.json is published as {identifier}, which is in the right namespace "
                "under another document's name. An identifier that does not name its own "
                "file resolves to the wrong contract or to nothing at all."
            )
    return problems


@check("every contract is published under a name this project holds")
def contract_identifiers_are_ours() -> str:
    """Design note D-303, and the sentence `docs/CONTRACTS.md` publishes.

    These documents used to carry a `$id` on a domain named after the product,
    which nobody here had registered. Nothing broke, which is the point: the
    identifier would have gone on reading correctly right up to the day
    somebody else took the name, and then every contract this tool publishes
    would have been in a stranger's namespace with no diff to show for it.

    The namespace is derived and never typed here. It comes from the
    `Repository` URL in `pyproject.toml`, which is the same string the package
    publishes to every index; `docs/CONTRACTS.md` states the namespace it reads
    off the schemas themselves. One chain, in one direction: the page cannot
    print a namespace the documents do not carry, and the documents cannot
    carry one the packaging does not declare.
    """
    declared = re.search(
        r'^Repository\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
        re.M,
    )
    if not declared:
        raise DriftError(
            "pyproject.toml declares no Repository URL, and this check has nothing to hold "
            "the contract identifiers against."
        )
    folder = ROOT / "src" / "seamark" / "schemas"
    ids = {
        path.stem: json.loads(path.read_text(encoding="utf-8")).get("$id", "")
        for path in sorted(folder.glob("*.json"))
    }
    if not ids:
        raise DriftError(f"no schemas under {folder.relative_to(ROOT)}, so this checked nothing")
    problems = identifier_problems(declared.group(1), ids)
    if problems:
        raise DriftError("\n".join(problems))
    return (
        f"{len(ids)} contracts, every one published under "
        f"{declared.group(1).rstrip('/')}/schemas/, which is the URL pyproject.toml "
        "declares for this repository"
    )


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


@check("the demo picture is the output the demo command produces")
def the_demo_image_is_current() -> str:
    """A picture is a figure that a reader cannot run a command against.

    Work rule 6 says no published number without a command that measures it,
    and the argument does not stop at numbers: a screenshot of a release that
    has gone is a claim about the tool, made on the page a reader meets first,
    and nothing would notice it going stale. So the demo picture is TEXT,
    drawn from the command by `scripts/terminal_svg.py`, and this re-draws it
    and refuses a difference.

    `docs/img/02-report.png` is not checked this way and cannot be: it is a
    browser rendering the HTML report, and the pixels belong to a font and a
    browser version rather than to this tree. What holds it is that it is
    produced by `scripts/report_image.py` from one run of the same demo, and
    that `every image in docs/img is one a document displays` refuses a
    `docs/img/` that has quietly grown a picture nothing shows.
    """
    import subprocess as sp

    script = ROOT / "scripts" / "terminal_svg.py"
    if not script.is_file():
        raise DriftError("scripts/terminal_svg.py is gone, so the picture is unchecked")
    run = sp.run(  # noqa: S603 - a fixed argv, no shell
        [sys.executable, str(script), "--check"],
        cwd=ROOT, capture_output=True, text=True, timeout=900,
    )
    if run.returncode != 0:
        raise DriftError((run.stdout + run.stderr).strip() or "the demo picture has drifted")
    return run.stdout.strip() or "docs/img/01-demo.svg is what the command produces"


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

    from seamark import schemas

    for versions in schemas.SUPERSEDED.values():
        for version in versions:
            if schemas.stem(version) not in schemas.names():
                raise DriftError(f"{version} was published and its schema file is gone")

    emitters = {"trace": ("seamark.trace.model", "SCHEMA_VERSION")}
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
    from seamark import schemas

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


# Documents that tell a reader to run something. A page that names a command
# the tree does not have is the defect phase A.1 spent itself removing.
COMMAND_PAGES = (
    "README.md", "README.es.md", "CONTRIBUTING.md",
    "docs/ENGINEERING.md", "docs/DESIGN.md", "docs/GOVERNANCE.md",
    "docs/COMPATIBILITY.md", "SECURITY.md",
    # The runbook is the page with the most at stake: it is followed once,
    # by a person, with a credential in hand, and a target that does not
    # exist is found in the middle of publishing.
    ".github/release-notes/RUNBOOK.md",
)


def _make_targets_named_in(text: str) -> list[str]:
    """`make x` where the page means the command, not the English verb.

    Only inside code: an inline span between backticks, or a line of a fenced
    block. Without that, "make a decision" and "make the gate green" are read
    as targets, which is a gate failing on prose - and a gate that fails on
    the correct shape is one people switch off.
    """
    found: list[str] = []
    for span in re.findall(r"`([^`\n]+)`", text):
        match = re.match(r"make ([a-z][a-z0-9-]*)", span.strip())
        if match:
            found.append(match.group(1))
    fenced = False
    for line in text.splitlines():
        if line.startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            match = re.match(r"\s*make ([a-z][a-z0-9-]*)", line)
            if match:
                found.append(match.group(1))
    return found


@check("every make target a document names is one the Makefile defines")
def documented_make_targets_exist() -> str:
    """`docs/ENGINEERING.md` listed six targets that left with the scanner.

    `make eval`, `make eval-marking`, `make benchmark`, `make fuzz`, `make
    screenshots` and `make diagrams`, on the page that argues how this
    repository is held up, for two releases. Nothing noticed, because make
    only complains when somebody types one.

    `docs/BACKLOG.md` is excluded and it is the one exclusion here: it is the
    record of what is wrong, so it quotes the broken command on purpose, and a
    check that refused that would be refusing the page for doing its job.
    """
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    defined = set(re.findall(r"^([A-Za-z][A-Za-z0-9_-]*):", makefile, re.M))
    phony = re.search(r"^\.PHONY:((?:.*\\\n)*.*)$", makefile, re.M)
    if phony:
        defined.update(phony.group(1).replace("\\", " ").split())
    if not defined:
        raise DriftError("no target was read out of the Makefile, so this compared nothing")

    problems: list[str] = []
    counted = 0
    for name in COMMAND_PAGES:
        path = ROOT / name
        if not path.is_file():
            raise DriftError(f"{name} is named by this check and is not in the tree")
        for target in _make_targets_named_in(path.read_text(encoding="utf-8")):
            counted += 1
            if target not in defined:
                problems.append(
                    f"{name} tells a reader to run `make {target}`, which the Makefile does not define"
                )
    if not counted:
        raise DriftError("no document names a make target, so this check compared nothing")
    if problems:
        raise DriftError("\n".join(sorted(set(problems))))
    return f"{counted} mention(s) of a make target across {len(COMMAND_PAGES)} pages, all defined"


@check("every fixture under tests/fixtures is one the suite names")
def no_fixture_is_an_orphan() -> str:
    """The 262 KB CycloneDX schema nothing had read since phase A.

    `tests/test_fixtures_are_published.py` requires every fixture to be in
    git's index, which is the right rule and says nothing at all about whether
    anything reads it. So the largest tracked file in the repository survived
    two releases after the module that consumed it left, held in place by a
    test whose subject was the opposite question.

    WHAT THIS ASSERTS, EXACTLY, because a check that claims more than it does
    is the failure mode this repository keeps meeting: that for every file
    under `tests/fixtures/`, the suite or the scripts NAME it or name one of
    the directories it sits in. It does not assert that a test opens it. A
    fixture directory walked by a loop is named once and every file under it
    is then accounted for, which is correct - the loop is what reads them -
    and it is also the limit of what this can see.

    Rejected: executing the suite under an open() trace, which would be exact
    and would make this check cost a full test run inside a gate that already
    runs one.
    """
    fixtures = ROOT / "tests" / "fixtures"
    if not fixtures.is_dir():
        raise DriftError("tests/fixtures is not there, so this check has nothing to read")

    haystack = []
    for folder in ("tests", "scripts", "src"):
        for path in sorted((ROOT / folder).rglob("*.py")):
            if "__pycache__" in path.parts or path.parts[-2:] == ("tests", "fixtures"):
                continue
            if fixtures in path.parents:
                continue  # a fixture cannot vouch for itself
            haystack.append(path.read_text(encoding="utf-8", errors="replace"))
    text = "\n".join(haystack)
    if not text:
        raise DriftError("no Python was read, so this check compared nothing")

    def named(relative: Path) -> bool:
        """Is this path, or a directory above it, written down in the suite?

        Segments are joined by a loose separator so that `FIXTURES / "surface"
        / "keyv-august"` and `"tests/fixtures/surface/keyv-august"` both count.
        """
        parts = relative.parts
        for depth in range(len(parts), 0, -1):
            pattern = r"[^A-Za-z0-9]{1,8}".join(re.escape(part) for part in parts[:depth])
            if re.search(pattern, text):
                return True
        return False

    files = [
        path for path in sorted(fixtures.rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts
    ]
    if not files:
        raise DriftError("tests/fixtures holds no files, so this check compared nothing")

    orphans = [
        path.relative_to(ROOT).as_posix()
        for path in files
        if not named(path.relative_to(fixtures))
    ]
    if orphans:
        raise DriftError(
            "nothing in tests/, scripts/ or src/ names these fixtures or any directory "
            "they sit in, so they are tracked weight rather than evidence:\n  "
            + "\n  ".join(orphans)
        )
    return f"{len(files)} fixture file(s), every one named by the suite or the scripts"


@check("every path the build configuration names is a path that exists")
def the_build_configuration_names_real_paths() -> str:
    """Two files that name paths and are read by tools that shrug at a miss.

    `per-file-ignores` in `pyproject.toml` carried ten entries for modules
    deleted in phase A - `coverage.py`, `policy/model.py`, `state/watch.py` and
    the rest - and ruff simply does not apply a rule it cannot match. `prune`
    in `MANIFEST.in` named `evals` and `fuzz`, which went to tag v2.3.0;
    setuptools prints a warning that only `make package` would show, and
    `make package` is not in `make all`. Both were configuration asserting a
    tree that is not there, in a repository whose product is refusing exactly
    that.

    Rejected: a test per file. The property is one property, and work rule 10
    says two checks over one property share a definition or they cancel.
    """
    problems: list[str] = []
    counted = 0

    import tomllib

    ignores = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    per_file = ignores["tool"]["ruff"]["lint"]["per-file-ignores"]
    for key in per_file:
        if "*" in key:
            continue  # a glob names a shape, not a path
        counted += 1
        if not (ROOT / key).exists():
            problems.append(f"pyproject.toml per-file-ignores names {key}, which is not in the tree")

    manifest = ROOT / "MANIFEST.in"
    for number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        words = line.split()
        if len(words) != 2 or words[0] not in {"prune", "exclude", "include"}:
            continue
        target = words[1]
        if any(character in target for character in "*?["):
            continue
        counted += 1
        if not (ROOT / target).exists():
            problems.append(f"MANIFEST.in:{number} names {target}, which is not in the tree")

    if problems:
        raise DriftError("\n".join(problems))
    if not counted:
        # Work rule 11: a check that matched nothing has not passed.
        raise DriftError(
            "no path was read out of pyproject.toml or MANIFEST.in, so this check "
            "compared nothing. Their shape has changed."
        )
    return f"{counted} path(s) named by the build configuration, all present"


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


# --------------------------------------------------------------------------
# The shape of the landing page
# --------------------------------------------------------------------------

# The ceiling each landing page is held to, and the reason it is a ceiling rather
# than a target is in `docs/ENGINEERING.md`. Each one sits about two sections
# above the page it holds, where a section is the 18 lines the last legitimate one
# cost. That slack is the same decision as the coverage floor of 88 against a
# measured 90: a gate pegged to today's value goes red on the first honest edit,
# and a gate that breaks on its own gets switched off. What it still refuses is
# the direction these pages have grown in twice before, which is a chapter at a
# time and never back down. What they measure today is in this check's own output
# rather than written here, because a figure written here is what went stale last
# time and left six lines of room.
LANDING_CEILING = {"README.md": 530, "README.es.md": 540}

# What has to be above the fold, and the depth a fold is taken to be. Nothing
# here is about beauty: it is the four things a reader needs before they decide
# whether to keep reading - what it is called, what it does in one sentence,
# whether it is alive, and a command they can run.
FIRST_SCREEN = 40


def landing_problems(page: str, text_of: str) -> list[str]:
    """Pure, so a twin can plant a page with its badges below the fold."""
    problems: list[str] = []
    lines = text_of.splitlines()
    if len(lines) > LANDING_CEILING[page]:
        problems.append(
            f"{page} is {len(lines)} lines and the ceiling is {LANDING_CEILING[page]}. "
            "Move a section to docs/ and leave a pointer, the way the limits and the "
            "five smaller commands went."
        )
    opening = lines[:FIRST_SCREEN]
    heading = [line for line in opening if line.startswith("# ")]
    if not heading:
        problems.append(f"{page}: no H1 in the first {FIRST_SCREEN} lines")
    sentence = [
        line for line in opening
        if line.startswith("**") and line.rstrip().endswith("**") and len(line) > 20
    ]
    if not sentence:
        problems.append(
            f"{page}: nothing in the first {FIRST_SCREEN} lines says in one bold "
            "sentence what this is"
        )
    badges = [line for line in opening if "![" in line and "](http" in line]
    if len(badges) < 3:
        problems.append(
            f"{page}: {len(badges)} badges above the fold. A reader decides whether a "
            "repository is alive before reading a word of it."
        )
    fenced = None
    for number, line in enumerate(opening):
        if line.startswith("```bash") or line.startswith("```console"):
            fenced = number + 1
            break
    if fenced is None:
        problems.append(
            f"{page}: no command to run in the first {FIRST_SCREEN} lines. The page "
            "argues that every claim on it is checkable, so the first screen is where "
            "the first check goes."
        )
    return problems


@check("each landing page opens with what it is and stays under its ceiling")
def the_landing_pages_keep_their_shape() -> str:
    """The phase 4 criterion, as the part of it that can be measured.

    The plan asked for a landing page of about 300 lines. Neither page reached
    it, the reason is written up in `docs/ENGINEERING.md`, and what is held
    here is the two halves of that criterion that a command can answer: the
    page does not grow, and the first screen carries the name, the sentence,
    the badges and a command.

    What it deliberately does NOT assert is that the picture is above the
    fold. The demo picture sits beside the paragraph that reads it, four
    screens down, because a picture of a report is worth nothing to a reader
    who has not yet been told what the report is of - and a check that forced
    it upwards would be this file having an opinion about the page rather than
    holding a claim about it.
    """
    problems: list[str] = []
    for page in LANDING_CEILING:
        problems += landing_problems(page, (ROOT / page).read_text(encoding="utf-8"))
    # The prose that argues the exception states the ceilings, and prose about
    # a number is the second copy that goes stale first.
    engineering = (ROOT / "docs" / "ENGINEERING.md").read_text(encoding="utf-8")
    for page, ceiling in LANDING_CEILING.items():
        if f"{ceiling} " not in engineering:
            problems.append(
                f"docs/ENGINEERING.md does not state the ceiling of {ceiling} lines it "
                f"argues for {page}"
            )
    if problems:
        raise DriftError("\n".join(problems))
    sizes = ", ".join(
        f"{page} {len((ROOT / page).read_text(encoding='utf-8').splitlines())}/"
        f"{ceiling}" for page, ceiling in LANDING_CEILING.items()
    )
    return f"{sizes} lines, each opening with its name, a sentence, badges and a command"


# --------------------------------------------------------------------------
# The demo picture, as somebody else's renderer will see it
# --------------------------------------------------------------------------

# The elements and attributes the picture is allowed to use. It is an
# ALLOWLIST, like every other contract here, because the failure to guard
# against is the element nobody thought of: a renderer that drops what it does
# not recognise shows a reader a blank rectangle and says nothing to anybody.
#
# The set is deliberately smaller than what any sanitiser permits. These are
# shapes and text with presentation attributes, which is the subset that
# survives every path a picture takes to a reader: an `<img>` on a rendered
# README, where no script runs and no stylesheet applies; a raw file served
# under `default-src 'none'`, where an external font or image would be
# blocked; and a sanitiser that strips what it cannot read.
SVG_ELEMENTS = frozenset({"svg", "rect", "path", "circle", "g", "text"})
SVG_ATTRIBUTES = frozenset({
    "xmlns", "width", "height", "viewBox", "role", "aria-label",
    "fill", "rx", "cx", "cy", "r", "d", "x", "y",
    "font-family", "font-size",
    "{http://www.w3.org/XML/1998/namespace}space",
})

# The generic families a browser can always resolve. The stack may name
# whatever it likes as long as it ENDS at one of these, or a machine without
# the named fonts draws the picture in a proportional face and every column in
# it stops lining up.
GENERIC_FAMILIES = ("monospace", "sans-serif", "serif")

def svg_problems(source: str) -> list[str]:
    """Everything about one picture that would make it render somewhere else.

    Pure, and over the text rather than over a path, so the twins can plant a
    script element without writing one into `docs/img/`.
    """
    import xml.etree.ElementTree as ET  # noqa: PLC0415, S405 - parsing our own output

    # The advance width the picture was measured with, from the script that
    # measured it. A second copy of that number here would be two definitions
    # of "wide enough" that agree until one of them is tuned (work rule 10).
    sys.path.insert(0, str(ROOT / "scripts"))
    from terminal_svg import WIDEST_GLYPH  # noqa: PLC0415

    problems: list[str] = []
    for hostile in ("<script", "<foreignObject", "<style", "@import", "url(", "javascript:"):
        if hostile in source:
            problems.append(
                f"the picture contains `{hostile}`, which a renderer will strip or refuse"
            )
    try:
        root = ET.fromstring(source)  # noqa: S314 - our own generated file
    except ET.ParseError as broken:
        return [*problems, f"the picture is not well-formed XML: {broken}"]

    for element in root.iter():
        tag = element.tag.split("}")[-1]
        if tag not in SVG_ELEMENTS:
            problems.append(f"<{tag}> is not in the set of elements this picture may use")
        for name, value in element.attrib.items():
            if name.split("}")[-1].lower().startswith("on"):
                problems.append(f"<{tag}> carries the event handler {name}")
            elif name.split("}")[-1] in ("href", "xlink:href", "src"):
                problems.append(
                    f"<{tag}> references {value}: a picture that fetches anything is a "
                    "picture that is blank wherever the fetch is blocked"
                )
            elif name not in SVG_ATTRIBUTES:
                problems.append(f"<{tag}> carries {name}, which is not in the allowed set")

    if not (root.get("width") and root.get("height")):
        problems.append(
            "the root <svg> has no width and height, so an `<img>` that loads it has "
            "nothing to size the box with until it has been parsed"
        )
    stack = [
        element.get("font-family") for element in root.iter()
        if element.get("font-family")
    ]
    if not stack:
        problems.append("nothing in the picture names a font family")
    for family in stack:
        if family.strip().rsplit(",", 1)[-1].strip().strip("'\"") not in GENERIC_FAMILIES:
            problems.append(
                f"the font stack `{family}` does not end at one of "
                f"{', '.join(GENERIC_FAMILIES)}, so a machine without the named faces "
                "draws this in whatever it likes"
            )

    width = float(root.get("width", "0"))
    for element in root.iter():
        if element.tag.split("}")[-1] != "text" or not element.text:
            continue
        right = float(element.get("x", "0")) + len(element.text) * WIDEST_GLYPH
        if right > width:
            problems.append(
                f"a line of {len(element.text)} characters reaches {right:.0f}px in a "
                f"{width:.0f}px picture if a stranger's monospace is wider than the one "
                f"this was measured with: {element.text[:40]!r}..."
            )
    return problems


@check("the demo picture uses only what every renderer of it will keep")
def the_demo_image_renders_anywhere() -> str:
    """The half of a published picture that `--check` cannot see.

    `scripts/terminal_svg.py --check` proves the picture is what the command
    produces. It says nothing about whether a reader can SEE it: the landing
    page is read on github.com, where the file is served to an `<img>` under a
    policy that blocks every outbound fetch, and a picture that quietly needs
    one is a blank rectangle at the top of the page with nothing anywhere
    saying so.

    This is a check on the bytes and not a rendering, and the difference is
    stated rather than papered over: it can prove the picture asks nothing of
    the network, uses no element a sanitiser strips and fits its own box at a
    generous glyph width. It cannot prove what a particular browser draws. The
    part that no command can answer is in `.github/release-notes/RUNBOOK.md`,
    as a step somebody performs with their eyes before the repository is
    public.
    """
    directory = ROOT / "docs" / "img"
    pictures = sorted(directory.glob("*.svg"))
    if not pictures:
        raise DriftError(
            f"{directory.relative_to(ROOT).as_posix()} holds no .svg, and this check "
            "looked for the demo pictures `make demo-image` writes"
        )
    problems: list[str] = []
    for picture in pictures:
        for problem in svg_problems(picture.read_text(encoding="utf-8")):
            problems.append(f"{picture.relative_to(ROOT).as_posix()}: {problem}")
    if problems:
        raise DriftError("\n".join(problems))
    return (
        f"{len(pictures)} pictures, each drawn with shapes and text alone, fetching "
        "nothing and fitting its own box"
    )


# --------------------------------------------------------------------------
# The name this product had until 3.0.0
# --------------------------------------------------------------------------

# Built from two halves so that this file does not match itself. The same trick
# holds the orphan-fixture twin, and for the same reason: a checker that counts
# its own vocabulary needs an exemption for itself, and an exemption for the
# checker is the first hole in the wall.
OLD_NAME = "act" + "aira"

# Where the old name may appear ON A LINE, anywhere in the tree, because
# renaming it there breaks something rather than renaming it. Each of these is
# a byte somebody else signed, matched, or will look up.
NAME_ON_LINES = (
    (r"v2\.3\.0:[^\s`\"']*" + OLD_NAME,
     "a locator into the tag v2.3.0, whose tree has that path. Renaming it "
     "would point it at a file that does not exist in that commit."),
    (OLD_NAME + r"\.dev/predicates/",
     "the predicateType this tree VERIFIES and never writes. Renaming it would "
     "not rename anything: it would make this refuse every envelope the "
     "archived product signed."),
    (r"Act" + r"aira (?:Fixture|Test Fixtures)",
     "a distinguished name inside a certificate OpenSSL issued once. The "
     "recorded token is signed over it, and the tests that read the name out "
     "of it are reading that certificate."),
    (OLD_NAME + r" rfc3161 test subject",
     "the first line of the bytes a timestamp authority signed. Change them "
     "and every recorded token stops verifying."),
)

# Where it may appear IN A FILE, how many times, and why. The count is the
# ratchet: one more occurrence is a rename left half done, and one fewer is an
# entry that has stopped being about anything.
NAME_IN_FILES: dict[str, tuple[int, str]] = {
    # Records. A record renamed afterwards is a record of something that did
    # not happen.
    "CHANGELOG.md": (
        56,
        "every entry below 3.0.0 is a release that went out under the old name, "
        "and the header says so: a published version keeps the name it was "
        "published under, because its tag and its artifacts cannot be renamed.",
    ),
    "docs/archive/ARCHITECTURE.md": (8, "the archived scanner's own documentation"),
    "docs/archive/CONCEPTS.es.md": (77, "the archived scanner's own documentation"),
    "docs/archive/CONCEPTS.md": (86, "the archived scanner's own documentation"),
    "docs/archive/DESIGN-scanner.md": (147, "the archived scanner's own documentation"),
    "docs/archive/EVALUATION.md": (10, "the archived scanner's own documentation"),
    "docs/archive/FORMATS.md": (177, "the archived scanner's own documentation"),
    "docs/archive/THREAT-MODEL.md": (123, "the archived scanner's own documentation"),
    ".github/release-notes/v2.3.0.md": (
        4,
        "the note pasted onto the release of the archived product. It went out "
        "under that name and the note says which name, because the alternative "
        "is a page describing a release nobody made.",
    ),
    ".github/history-rewrite/messages.json": (
        3,
        "three of the forty-five rewritten messages cite a path or a command as "
        "it was in the commit they belong to. The replay keeps each commit's "
        "tree, and those trees carry the old package directory: renaming the "
        "message would make it describe a file that is not in the commit.",
    ),
    # Explanations. The word is the subject of the sentence.
    "README.md": (2, "the section that says where this repository comes from"),
    "README.es.md": (2, "the section that says where this repository comes from"),
    ".github/release-notes/v3.0.0.md": (
        1, "the paragraph of the release note that announces the rename"
    ),
    "docs/ENGINEERING.md": (
        1, "the section that writes down where history stops and the product starts"
    ),
    # Instructions about the old thing.
    ".github/release-notes/RUNBOOK.md": (
        2,
        "the step that renames the directory on this machine, which has to name "
        "what it is renaming.",
    ),
    ".gitignore": (
        4,
        "four planning documents on the author's disk whose filenames contain "
        "the old name. The pattern is not about the product: changing it would "
        "stop ignoring a file that exists and is not part of the tree.",
    ),
}


def name_occurrences(text_of: str) -> int:
    """How many times the old name appears on lines no pattern allows."""
    allowed = [re.compile(pattern, re.I) for pattern, _ in NAME_ON_LINES]
    total = 0
    for line in text_of.splitlines():
        masked = line
        for pattern in allowed:
            masked = pattern.sub("", masked)
        total += len(re.findall(OLD_NAME, masked, re.I))
    return total


def unused_line_patterns(patterns, texts: dict[str, str]) -> list[str]:
    """Patterns that allow the old name and no longer match anything.

    Pure, and separate from the file table, because the two go stale for
    different reasons: a file is cleaned up, a shape of line disappears. An
    allowance kept after its case has gone is one nobody would notice widening.
    """
    problems: list[str] = []
    for pattern, reason in patterns:
        if not reason.strip():
            problems.append(f"the line pattern `{pattern}` states no reason")
        if not any(re.search(pattern, text_of, re.I) for text_of in texts.values()):
            problems.append(
                f"the line pattern `{pattern}` allows the old name and matches nothing "
                "in the tree any more. An allowance for a case that has gone is one "
                "nobody will notice widening."
            )
    return problems


def name_problems(counted: dict[str, int], allowed: dict[str, tuple[int, str]]) -> list[str]:
    """Pure, over a mapping of file to occurrences, so the twins can plant one."""
    problems: list[str] = []
    for name, count in sorted(counted.items()):
        if not count:
            continue
        if name not in allowed:
            problems.append(
                f"{name} names the old product {count} time(s). Either it is a rename "
                "left half done, or it is a record and belongs in NAME_IN_FILES with "
                "the reason it is one."
            )
            continue
        expected, reason = allowed[name]
        if not reason.strip():
            problems.append(f"{name} keeps the old name and states no reason")
        if count != expected:
            problems.append(
                f"{name} names the old product {count} time(s) and the table records "
                f"{expected}. " + ("Something new was written with the old name."
                                   if count > expected else
                                   "Fewer is not better here: update the table, or the "
                                   "next one that arrives will be invisible.")
            )
    for name in sorted(allowed):
        if name not in counted:
            problems.append(
                f"NAME_IN_FILES names {name}, which is not a file in this tree. An "
                "exemption for a file that is not there guards nothing."
            )
        elif not counted[name]:
            problems.append(
                f"NAME_IN_FILES keeps {name} for the old name and it does not appear "
                "in it any more. A stale exemption is where the next one hides."
            )
    return problems


@check("the old product name appears nowhere the tree has not written down")
def the_rename_is_not_half_done() -> str:
    """3.0.0 renamed this product, and a rename is the kind of change that ends
    up nine tenths done.

    The name belongs to a different product by the same author, which lives
    somewhere else; `README.md` says which and where. Two things with one name
    is a confusion a reader cannot resolve from the inside, so what is left
    here is only what would be a different kind of wrong if it were changed:
    bytes somebody signed, identifiers something else matches on, locators into
    a tag, and the records that say what happened. Each is in one of the two
    tables below, with its reason, and both tables fail when they stop being
    true in either direction.

    This file names the old product nowhere, which is why `OLD_NAME` is built
    from two halves: a checker that needs an exemption for itself has opened
    the first hole in its own wall.
    """
    tracked = tracked_files()
    if tracked is None:
        return (
            "the old name was not looked for: this tree is not a checkout, so there is "
            "no list of what belongs to it"
        )
    texts: dict[str, str] = {}
    for name in tracked:
        try:
            texts[name] = (ROOT / name).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    counted = {name: name_occurrences(text_of) for name, text_of in texts.items()}

    problems = unused_line_patterns(NAME_ON_LINES, texts)
    problems += name_problems(counted, NAME_IN_FILES)
    if problems:
        raise DriftError("\n".join(problems))

    kept = sum(counted.values())
    return (
        f"{len(counted)} files read; the old name is left in {len(NAME_IN_FILES)} of "
        f"them, {kept} times, each one recorded with its reason, and on "
        f"{len(NAME_ON_LINES)} kinds of line that are somebody else's bytes"
    )


# --------------------------------------------------------------------------
# The publication happens once, the rehearsal as often as it takes
# --------------------------------------------------------------------------

RELEASE_WORKFLOW = ".github/workflows/release.yml"
PUBLISH_ACTION = "pypa/gh-action-pypi-publish"
TEST_INDEX = "test.pypi.org"
REPEATABLE = "skip-existing"

# Which event is allowed to reach which upload, and this is the half that is
# irreversible. `skip-existing` decides what a second run does; this decides
# whether a second run can happen at all. The rehearsal is started by hand, so
# only `workflow_dispatch` may reach it; the publication follows a release a
# person wrote, so only `release` may reach that. If the rehearsal could reach
# PyPI - one `if:` deleted, one `needs:` loosened - step 9 of the runbook would
# publish 3.0.0 for real, and a version on PyPI is spent for good.
REACHABLE_FROM = {"rehearsal": "workflow_dispatch", "publication": "release"}

# The release activity type that may start it. Without `types:` GitHub sends
# `created`, `edited`, `deleted`, `prereleased` and more, so editing a typo in
# the notes after publishing would start the whole thing again.
RELEASE_ACTIVITY = "published"


def workflow_jobs(text_of: str) -> dict[str, str]:
    """job name -> its block.

    Read as text and not as YAML on purpose: `make all` runs with the `dev`
    extra and nothing else, and a gate that needs a parser the package does
    not depend on is a gate that stops running the day somebody installs
    exactly what the project asks for.
    """
    if not re.search(r"^jobs:\s*$", text_of, re.M):
        raise DriftError(f"{RELEASE_WORKFLOW} has no `jobs:` block")
    jobs: dict[str, str] = {}
    current: str | None = None
    lines: list[str] = []
    # INSIDE `jobs:` and nowhere else. Without the bound, `release:` and
    # `workflow_dispatch:` in the `on:` block are two more names at the same
    # indentation, and this answered with two jobs that do not exist. Nothing
    # needed them and neither uploads anything, so every assertion downstream
    # stayed true - a reader finding something adjacent to what it was looking
    # for and being right by luck.
    inside = False
    for line in text_of.splitlines():
        if re.match(r"^jobs:\s*$", line):
            inside = True
            continue
        if inside and line and not line.startswith((" ", "#")):
            break
        if not inside:
            continue
        started = re.match(r"^  ([a-z][a-z0-9_-]*):\s*$", line)
        if started:
            if current is not None:
                jobs[current] = "\n".join(lines)
            current, lines = started.group(1), []
            continue
        if current is not None:
            lines.append(line)
    if current is not None:
        jobs[current] = "\n".join(lines)
    return jobs


def publishing_jobs(text_of: str) -> dict[str, str]:
    """The jobs that upload to an index, by name."""
    return {
        name: body for name, body in workflow_jobs(text_of).items()
        if PUBLISH_ACTION in body
    }


def triggering_events(text_of: str) -> dict[str, list[str]]:
    """event -> its activity types, from the `on:` block."""
    events: dict[str, list[str]] = {}
    inside = False
    current: str | None = None
    for line in text_of.splitlines():
        if re.match(r"^on:\s*$", line):
            inside = True
            continue
        if inside and line and not line.startswith(" ") and not line.startswith("#"):
            break
        if not inside:
            continue
        named = re.match(r"^  ([a-z_]+):\s*$", line)
        if named:
            current = named.group(1)
            events[current] = []
            continue
        activity = re.match(r"^    types:\s*\[([^\]]*)\]", line)
        if activity and current:
            events[current] = [word.strip() for word in activity.group(1).split(",")]
    return events


def gated_to(body: str) -> set[str] | None:
    """The events a job's own `if:` admits, or None for "no condition".

    One shape of condition is understood, `github.event_name == 'x'`, and
    anything else raises rather than being read as "no condition". A parser
    that shrugs at what it cannot read answers "reachable from everything" or
    "reachable from nothing", and both are a wrong answer stated confidently
    about the one thing here that cannot be undone.
    """
    found = re.search(r"^    if:\s*(.+?)\s*$", body, re.M)
    if found is None:
        return None
    condition = found.group(1)
    shape = re.fullmatch(r"github\.event_name\s*==\s*['\"]([a-z_]+)['\"]", condition)
    if shape is None:
        raise DriftError(
            f"{RELEASE_WORKFLOW} has a job condition this check cannot read: "
            f"`{condition}`. It understands `github.event_name == 'x'` and nothing "
            "else, and it refuses rather than guessing which events reach a job that "
            "uploads to an index."
        )
    return {shape.group(1)}


def needed_by(body: str) -> list[str]:
    found = re.search(r"^    needs:\s*(.+?)\s*$", body, re.M)
    if found is None:
        return []
    return [word.strip() for word in found.group(1).strip("[]").split(",") if word.strip()]


def events_reaching(jobs: dict[str, str], events: set[str]) -> dict[str, set[str]]:
    """Which of `events` can actually start each job.

    A job runs for an event when its own condition admits it AND every job it
    needs also ran: GitHub skips a job whose dependency was skipped. That is
    the whole of the analysis, and it is why `needs: [build, attach]` on the
    PyPI job is a second lock rather than an ordering detail.
    """
    reaching: dict[str, set[str]] = {}

    def resolve(name: str, seen: tuple[str, ...]) -> set[str]:
        if name in reaching:
            return reaching[name]
        if name in seen:
            raise DriftError(f"{RELEASE_WORKFLOW}: `needs:` goes in a circle at `{name}`")
        if name not in jobs:
            raise DriftError(
                f"{RELEASE_WORKFLOW}: a job needs `{name}`, which is not a job in it"
            )
        own = gated_to(jobs[name])
        answer = set(events) if own is None else set(events) & own
        for required in needed_by(jobs[name]):
            answer &= resolve(required, (*seen, name))
        reaching[name] = answer
        return answer

    return {name: resolve(name, ()) for name in jobs}


def publish_problems(text_of: str) -> list[str]:
    """Everything that can be wrong about how the two uploads are reached.

    Pure, over the text of a workflow, so a twin can delete a condition and
    watch the rule refuse it without a workflow file to delete it from.
    """
    problems: list[str] = []
    events = triggering_events(text_of)
    jobs = workflow_jobs(text_of)
    reaching = events_reaching(jobs, set(events))
    uploads = {name: body for name, body in jobs.items() if PUBLISH_ACTION in body}

    activity = events.get("release")
    if activity is not None and activity != [RELEASE_ACTIVITY]:
        problems.append(
            f"the `release` trigger fires on {activity or 'every activity type'} and not "
            f"on `{RELEASE_ACTIVITY}` alone. Editing the notes of a release that is "
            "already out would start the publication again."
        )

    for name, body in sorted(uploads.items()):
        kind = "rehearsal" if TEST_INDEX in body else "publication"
        repeatable = REPEATABLE in body
        if kind == "rehearsal" and not repeatable:
            problems.append(
                f"the `{name}` job publishes to the test index and does not carry "
                f"`{REPEATABLE}`. A rehearsal that has uploaded once cannot upload "
                "again, so its second run dies at the step the first one passed and "
                "the error names the index rather than the cause."
            )
        if kind == "publication" and repeatable:
            problems.append(
                f"the `{name}` job publishes to the real index and carries "
                f"`{REPEATABLE}`, which turns publishing 3.0.0 twice into a green "
                "build. A version that is already there is a mistake and has to say so."
            )
        allowed = {REACHABLE_FROM[kind]}
        actual = reaching[name]
        if actual != allowed:
            problems.append(
                f"the `{name}` job is the {kind} and can be reached from "
                f"{sorted(actual) or 'no event at all'}; it may be reached from "
                f"{sorted(allowed)} and nothing else"
                + (". A rehearsal that reaches PyPI publishes the version for real, "
                   "and a version on PyPI is spent for good."
                   if kind == "publication" and "workflow_dispatch" in actual else ".")
            )
    return problems


@check("the rehearsal can be repeated and the publication cannot")
def publishing_happens_once() -> str:
    """The asymmetry the whole release order rests on.

    Everything reversible is done before everything that is not, and the last
    irreversible step is the upload to PyPI. `skip-existing` is what makes the
    TestPyPI job survivable - a rehearsal that fails after its upload is run
    again, and the second run gets past the step the first one already did -
    and it is the one thing that must never reach the job beside it, where it
    would make a second publication of the same version look like a success.

    The other half is which event can reach which job, and it is the half that
    cannot be undone. `skip-existing` decides what a second run does; this
    decides whether a second run can happen at all. One `if:` deleted from the
    rehearsal's neighbour and step 9 of the runbook - a `workflow_dispatch`
    meant for TestPyPI - would publish to PyPI for real. So the condition and
    the `needs:` chain are read here and the answer is compared against one
    event per job, rather than against nothing.
    """
    path = ROOT / RELEASE_WORKFLOW
    if not path.is_file():
        raise DriftError(
            f"{RELEASE_WORKFLOW} is not in the tree, and it is what builds, attests and "
            "publishes the distributions"
        )
    workflow = path.read_text(encoding="utf-8")
    jobs = publishing_jobs(workflow)
    if len(jobs) != 2:
        raise DriftError(
            f"{RELEASE_WORKFLOW} has {len(jobs)} job(s) using `{PUBLISH_ACTION}` and this "
            f"check knows two, a rehearsal and a publication: {sorted(jobs) or 'none'}"
        )
    problems = publish_problems(workflow)
    if problems:
        raise DriftError("\n".join(problems))
    reaching = events_reaching(workflow_jobs(workflow), set(triggering_events(workflow)))
    return (
        "2 publishing jobs: the rehearsal is reachable only from "
        f"{sorted(reaching[next(n for n, b in jobs.items() if TEST_INDEX in b)])} and may "
        "repeat itself, and the publication only from "
        f"{sorted(reaching[next(n for n, b in jobs.items() if TEST_INDEX not in b)])} and "
        "may not"
    )


# --------------------------------------------------------------------------
# The notes for the version that has not been released yet
# --------------------------------------------------------------------------

# What a figure in a release note is read out of, and what it is compared with.
# Two, because two is what the notes state: everything else in them is prose
# about what the release contains, which no command can check.
NOTE_FIGURES = (
    (re.compile(r"\b([\d,]+) tests\b"), "tests", lambda measured: measured["tests"]["collected"]),
    (re.compile(r"\b(\d+)% coverage\b"), "coverage",
     lambda measured: int(measured["coverage"]["percent"])),
)


def note_problems(text_of: str, measured: dict) -> tuple[list[str], int]:
    """(what is wrong, how many figures were compared). Pure, so a twin can
    plant a note without writing one into `.github/release-notes/`."""
    problems: list[str] = []
    compared = 0
    for pattern, what, source in NOTE_FIGURES:
        found = pattern.search(text_of)
        if found is None:
            problems.append(
                f"the notes state no {what} figure, and this check looked for "
                f"`{pattern.pattern}`. A figure that leaves the guarded set is not "
                "removed, it is unguarded."
            )
            continue
        compared += 1
        stated = int(found.group(1).replace(",", ""))
        if stated != source(measured):
            problems.append(
                f"the notes say {found.group(0)} and this tree measures {source(measured)}"
            )
    return problems, compared


@check("the notes for the version being released state the figures this tree measures")
def release_notes_are_current() -> str:
    """Only the notes for the version in `pyproject.toml`, and that is the rule.

    A release note is a record of a moment. Once `v2.3.0` is out, its note is
    what was true when it was cut and rewriting it later would be falsifying a
    record - which is the same argument that keeps a published tag where it is.
    So the notes for the version that has NOT been released yet are held to the
    tree, and every other file in that directory is left alone.

    It exists because the 3.0.0 notes said "2,487 tests" for as long as they
    sat unpublished, while the tree moved past 2,600. Nothing compared them:
    the figures contract guards the pages a reader lands on, and this file is
    the one a reader lands on ONCE, from an email, at the moment it matters
    most.

    The remedy is a hand edit and that is deliberate, against D-181. The
    treadmill argument applies to a page that changes on every commit forever;
    this one is edited once, at the release, and stops being read by this check
    the moment the version moves past it. What the failure prints is the number
    to write.
    """
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    declared = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    if not declared:
        raise DriftError("pyproject.toml declares no version")
    notes = ROOT / ".github" / "release-notes" / f"v{declared.group(1)}.md"
    if not notes.is_file():
        raise DriftError(
            f"{notes.relative_to(ROOT).as_posix()} does not exist, so the version this "
            "tree is at has no notes to publish. Write them before the tag, not after."
        )
    measured = json.loads((ROOT / "figures.json").read_text(encoding="utf-8"))
    problems, compared = note_problems(notes.read_text(encoding="utf-8"), measured)
    if problems:
        raise DriftError("\n".join(problems))
    return (
        f"{compared} figures in {notes.name}, each the one measured; the notes for "
        "versions already released are records and are not read"
    )


# --------------------------------------------------------------------------
# The commands the landing pages tell a reader to run
# --------------------------------------------------------------------------

# The heading of the table each page publishes, and the sentence under it says
# "run any of them and disagree". Everything below exists because one of those
# commands, copied as it was written, printed nothing at all: `addopts = -q` in
# `pyproject.toml` means `--collect-only -q` prints per-file totals and no
# grand total, which `scripts/release_check.py` had known and worked around
# inside `_collect_count` since the day it was written, while the page went on
# publishing the form that does not work. A figure this file compares is not
# the same thing as a command a reader can run.
HELD_UP_SECTIONS = {"README.md": "How the repository is held up",
                    "README.es.md": "Cómo se sostiene el repositorio"}

# The commands that are NOT run here, each with the reason. It is written down
# rather than implied by what the code happens to handle: an unlisted command
# is a failure below, so the set that is executed is a decision somebody made
# and not the remainder after the easy ones.
HELD_UP_NOT_RUN = {
    "python scripts/figures.py": (
        "it re-measures the whole tree, which runs the collection again, and it "
        "WRITES docs/FIGURES.md and figures.json. A gate that rewrites the tree it "
        "is checking is not a gate. `make all` runs it one step before this one."
    ),
    "python scripts/rules_doc.py": (
        "it writes docs/RULES.md. The page is already held against the packs by "
        "`every rule the catalogue defines is translated, and none is undocumented`, "
        "which compares without writing."
    ),
    "make test-cov": (
        "the whole suite with coverage, minutes rather than seconds. `make all` runs "
        "it before this, and CI compares the published percentage against what the "
        "runner measured."
    ),
    "python scripts/release_check.py": (
        "this file. Running it here is a recursion and not a check."
    ),
}


def _first_number(text_of: str) -> int | None:
    found = re.search(r"\b([\d][\d,.]*)\b", text_of)
    return int(found.group(1).replace(",", "").replace(".", "")) if found else None


def _collected(output: str) -> int | None:
    """pytest's own summary line, which is not the only place that phrase appears.

    The first version read the first `N tests collected` anywhere in the
    output and got 2606 where the answer was 2639: the listing of collected
    node ids includes the parametrised twins of this very check, and one of
    them carries `2606 tests collected` inside its id. A reader that matches
    something adjacent to what it is looking for is the shape this repository
    keeps finding in itself, and it found it here in the check written to stop
    a page from publishing a command that prints nothing.

    So: anchored at the start of a line, which a node id never is, and the
    last one, which is the summary.
    """
    found = re.findall(r"^(\d+) tests? collected", output, re.M)
    return int(found[-1]) if found else None


def _only_number(output: str) -> int | None:
    found = re.search(r"^\s*(\d+)\s*$", output.strip(), re.M)
    return int(found.group(1)) if found else None


def _commands_in_help(output: str) -> int | None:
    """The subcommand list in `--help`, which is not the first brace group.

    `[--lang {en,es}]` comes first in the usage line, so reading the first one
    counted two commands and the check reported the page as wrong about a
    number the page had right. The subcommand list is the widest group, and a
    tie means the shape changed and this has stopped knowing which is which.
    """
    groups = {tuple(found.split(",")) for found in re.findall(r"\{([a-z,_-]+)\}", output)}
    if not groups:
        return None
    widest = max(len(group) for group in groups)
    # DISTINCT groups: argparse prints the subcommand list twice, once in the
    # usage line and once above the descriptions, and counting the repetition
    # as a tie made this answer "I cannot tell" about a help text that says it
    # perfectly clearly.
    if sum(1 for group in groups if len(group) == widest) != 1:
        return None
    return widest


# command -> (how to read a number out of its output, what that number is).
HELD_UP_RUN = {
    "python -m pytest --collect-only -q -o addopts=": (_collected, "tests collected"),
    "find src -name '*.py' | xargs cat | wc -l": (_only_number, "lines of product code"),
    "seamark --help": (_commands_in_help, "commands in the parser"),
}


def held_up_rows(page: str, text_of: str) -> list[tuple[str, str, str]]:
    """(claim, command, result) for the table that says to run them.

    Bounded to that one section: the pages carry other tables, and a check
    that reads them all would be about something the section does not promise.
    """
    heading = HELD_UP_SECTIONS[page]
    start = text_of.find(f"## {heading}")
    if start < 0:
        raise DriftError(
            f"{page} has no section `## {heading}`, and this check exists to run the "
            "commands that section publishes"
        )
    end = text_of.find("\n## ", start + 1)
    section = text_of[start: end if end > 0 else len(text_of)]
    rows: list[tuple[str, str, str]] = []
    for line in section.splitlines():
        # Split on the pipes that separate cells and not on the ones inside
        # them. A command with a pipe in it is written `\\|` in markdown, and
        # splitting on every pipe turned the one row with a pipeline in it into
        # five cells and dropped it - which is the row most worth running, and
        # the check would have gone on saying it had compared everything.
        cells = [cell.strip() for cell in re.split(r"(?<!\\)\|", line.strip().strip("|"))]
        if len(cells) != 3 or not cells[1].startswith("`") or not cells[1].endswith("`"):
            continue
        rows.append((cells[0], cells[1].strip("`").replace("\\|", "|"), cells[2]))
    if not rows:
        raise DriftError(f"{page}: the `{heading}` table has no rows with a command in it")
    return rows


def run_published(command: str) -> tuple[str, str]:
    """Run one published command and hand back (output, what was substituted).

    Through `bash -c` and as written, because the check is about the bytes on
    the page. Rewriting `find … | xargs cat | wc -l` as three Python calls
    would be checking something adjacent: a pipeline this file invented, which
    can agree with the figure while the published one does not run at all.

    Two substitutions, both named in the summary rather than made quietly:
    `python` becomes the interpreter running this check, because which name
    python has on a machine is not what the page is claiming; and `seamark`
    becomes `python -m seamark` where the console script is not on PATH, which
    is every checkout that has not been installed.
    """
    shell = shutil.which("bash")
    if shell is None:
        raise DriftError(
            "there is no bash on this machine, and the commands this section publishes "
            "are shell pipelines. Nothing was run, which is not the same as nothing "
            "being wrong."
        )
    spelled = command
    substituted = ""
    if spelled.startswith("python "):
        spelled = f'"{sys.executable}" ' + spelled[len("python "):]
        substituted = "python -> the interpreter running this check"
    if spelled.startswith("seamark ") and shutil.which("seamark") is None:
        spelled = f'"{sys.executable}" -m seamark ' + spelled[len("seamark "):]
        substituted = "seamark -> python -m seamark, the console script is not on PATH"
    done = subprocess.run(  # noqa: S603 - a fixed argv, and the command is a tracked file of this repository
        [shell, "-c", spelled], cwd=ROOT, capture_output=True, text=True, timeout=900,
    )
    return done.stdout + done.stderr, substituted


@check("every command the landing pages publish as runnable prints what the row promises")
def published_commands_run() -> str:
    """The other half of a page that says "run any of them and disagree".

    Every other check here compares two recorded facts. This one executes what
    the page tells a stranger to type and reads what comes back, because the
    two can come apart in a direction no comparison sees: the figure in the
    row was right, the command beside it printed nothing, and both of those
    were true for as long as the page existed.
    """
    problems: list[str] = []
    ran = 0
    commands_per_page: dict[str, list[str]] = {}
    claims: dict[str, dict[str, str]] = {}
    for page, _ in HELD_UP_SECTIONS.items():
        rows = held_up_rows(page, (ROOT / page).read_text(encoding="utf-8"))
        commands_per_page[page] = [command for _, command, _ in rows]
        claims[page] = {command: claim for claim, command, _ in rows}

    pages = list(commands_per_page)
    if commands_per_page[pages[0]] != commands_per_page[pages[1]]:
        raise DriftError(
            "the two landing pages publish different commands in this table, so one of "
            "them is telling a reader to run something the other does not: "
            f"{set(commands_per_page[pages[0]]) ^ set(commands_per_page[pages[1]])}"
        )

    for command in commands_per_page[pages[0]]:
        if command in HELD_UP_NOT_RUN:
            continue
        if command not in HELD_UP_RUN:
            problems.append(
                f"`{command}` is published as something to run and this check neither "
                "runs it nor says why not. Add it to HELD_UP_RUN with how to read its "
                "output, or to HELD_UP_NOT_RUN with the reason."
            )
            continue
        read, what = HELD_UP_RUN[command]
        output, substituted = run_published(command)
        printed = read(output)
        if printed is None:
            tail = "\n          ".join(output.strip().splitlines()[-4:])
            problems.append(
                f"`{command}` was run and nothing in its output is {what}. That is the "
                f"defect this check exists for: the row promises it. The last lines "
                f"were:\n          {tail}"
            )
            continue
        ran += 1
        for page in pages:
            stated = _first_number(claims[page][command])
            if stated is None:
                problems.append(f"{page}: the claim beside `{command}` states no figure")
            elif stated != printed:
                problems.append(
                    f"{page}: the row says {stated} and `{command}` printed {printed} "
                    f"{what}" + (f" ({substituted})" if substituted else "")
                )
    if problems:
        raise DriftError("\n".join(problems))
    if not ran:
        raise DriftError(
            "no published command was run at all, so this check compared nothing. It "
            f"looked for {', '.join(HELD_UP_RUN)}"
        )
    return (
        f"{ran} of {len(commands_per_page[pages[0]])} published commands run and their "
        f"output compared against both pages; {len(HELD_UP_NOT_RUN)} named as not run, "
        "each with its reason"
    )


# --------------------------------------------------------------------------
# One way to build the distributions
# --------------------------------------------------------------------------

# The spellings that build or inspect a distribution. `make package` is the
# one that is allowed; the other two are the second definition.
BUILDERS = (
    (re.compile(r"\bmake\s+package\b"), "make package"),
    (re.compile(r"python\s+-m\s+build\b"), "python -m build"),
    (re.compile(r"\bscripts/build_package\.py"), "scripts/build_package.py"),
)


def build_commands(text_of: str) -> list[str]:
    """Every distribution-building command written in a workflow."""
    found: list[str] = []
    for line in text_of.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pattern, name in BUILDERS:
            if pattern.search(stripped):
                found.append(name)
    return found


def build_problems(workflows: dict[str, str]) -> tuple[list[str], int]:
    """(what is wrong, how many steps go through the target). Pure, so the
    twins can plant a workflow without writing one into `.github/`."""
    problems: list[str] = []
    through_the_target = 0
    for name, text_of in sorted(workflows.items()):
        for command in build_commands(text_of):
            if command == "make package":
                through_the_target += 1
            else:
                problems.append(f"{name} runs `{command}`")
    return problems, through_the_target


@check("the distributions are built by one command, and CI runs that command")
def the_package_is_built_one_way() -> str:
    """Work rule 10, at the level above the one it was already fixed at.

    `make package` asserted five resources that left with the model scanner
    while the CI job asserted a different two, so the target failed on every
    laptop run from the pivot onwards and the job stayed green over the same
    distributions. The list became one definition - every non-Python file
    under `src/seamark/`, read from the tree - and the COMMAND was still in
    two places: the Makefile called `scripts/build_package.py` and so did the
    workflow. A step added to the target would not have reached CI, and the
    two would have come apart again one level up.

    So the workflows build through the target or they do not build. This is
    not a style rule: it is the assertion that there is one answer to "how is
    the package built", which is the only thing that makes `make package`
    green mean anything about what CI uploaded.
    """
    found = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    if not found:
        raise DriftError(".github/workflows holds no workflow, so nothing builds anything")
    workflows = {
        path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in [*found, ROOT / "action.yml"] if path.is_file()
    }
    offenders, through_the_target = build_problems(workflows)
    if offenders:
        raise DriftError(
            "these build the distributions without going through `make package`, so the "
            "target and CI can come apart the way they did before the pivot:\n  "
            + "\n  ".join(offenders)
        )
    if not through_the_target:
        raise DriftError(
            "no workflow builds the distributions at all, so `it installs` is a claim "
            "nothing on a runner checks. This check looked for "
            + ", ".join(name for _, name in BUILDERS)
        )
    return (
        f"{through_the_target} workflow step(s) across {len(workflows)} files build "
        "through `make package`, and nothing builds them another way"
    )


# --------------------------------------------------------------------------
# Commit SHAs written into the documentation
# --------------------------------------------------------------------------

# `.github/workflows/` is in the list because a workflow pins actions the same
# way the documentation does. `docs/archive/` is NOT: it is the model
# scanner's documentation, kept unedited on purpose, and a gate that forces an
# edit to an archived page is a gate that rewrites the past.
SHA_PAGES = (
    "README.md", "README.es.md", ".pre-commit-hooks.yaml", "action.yml",
)
SHA_DIRECTORIES = ("docs", ".github/workflows")
SHA_EXCLUDED = ("docs/archive",)

FULL_SHA = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])")
USES_FORM = re.compile(r"([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)@$")
REV_FORM = re.compile(r"^\s*rev:\s*$")
REPO_FORM = re.compile(r"^\s*(?:-\s*)?repo:\s*(\S+)")


def _this_repository() -> str:
    """`owner/name`, from the package metadata and not from a git remote.

    The remote is the wrong source twice over: the gate is meant to run on a
    clone made from a local path, which has no owner in its URL, and a fork's
    remote would make this check ask a different repository about the same
    commit.
    """
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    found = re.search(r'^Repository\s*=\s*"https://github\.com/([^/"]+/[^/"]+?)/?"',
                      pyproject, re.M)
    if not found:
        raise DriftError(
            "pyproject.toml declares no [project.urls] Repository, so there is no way "
            "to tell a commit of this repository from one of somebody else's"
        )
    return found.group(1)


def sha_citations(relative: str, text: str) -> list[dict]:
    """Every 40-hex string on a page, with the repository it refers to.

    Two forms are recognised, which are the two that exist in this tree:
    `owner/name@<sha>`, as `uses:` writes it, and a `rev: <sha>` under the
    `repo:` line of a pre-commit block. Anything else comes back with
    `repository` set to None and is a failure rather than a pass - a 40-hex
    string nobody can attribute is exactly the citation this check exists to
    catch, and skipping it would be the check looking sideways (work rule 11).
    """
    found: list[dict] = []
    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        for match in FULL_SHA.finditer(line):
            sha = match.group(0)
            before = line[: match.start()]
            uses = USES_FORM.search(before)
            repository: str | None = None
            if uses:
                repository = uses.group(1)
            elif REV_FORM.match(before):
                for previous in reversed(lines[: number - 1]):
                    owner = REPO_FORM.match(previous)
                    if owner:
                        repository = owner.group(1).rstrip("/").removeprefix(
                            "https://github.com/"
                        ).removesuffix(".git")
                        break
            found.append({
                "sha": sha, "repository": repository,
                "where": f"{relative}:{number}", "line": line.strip(),
            })
    return found


def sha_problems(citations: list[dict], ours: str, resolve) -> list[str]:
    """What is wrong with a list of citations. Pure, so the twins can plant one.

    `resolve(sha)` returns None when the commit is on this branch and a
    sentence saying why not when it is not. It is injected rather than called
    here so that a test can plant a dead SHA without a repository to plant it
    in.
    """
    problems: list[str] = []
    for citation in citations:
        if citation["repository"] is None:
            problems.append(
                f"{citation['where']}: {citation['sha']} is a commit SHA and nothing on "
                "the line says which repository it belongs to, so nothing can check it. "
                f"The line is: {citation['line']}"
            )
            continue
        if citation["repository"].lower() != ours.lower():
            continue
        reason = resolve(citation["sha"])
        if reason:
            problems.append(f"{citation['where']}: {citation['sha']} {reason}")
    return problems


@check("every commit of this repository that the documentation cites is on this branch")
def cited_commits_exist() -> str:
    """The rewrite hazard, held where it lands.

    `README.md` tells a reader to write `uses: marcosmatalab/seamark@<sha>` and
    `.pre-commit-hooks.yaml` is used with a `rev:`, so this repository
    publishes commit SHAs of its own as instructions. A history rewrite moves
    every one of them, and a reader who copies a dead SHA gets a checkout error
    from a repository that audits other people's configuration for pinning.

    ANCESTOR OF HEAD, not merely present. After a rewrite the old commits are
    still in the local object database - the backup ref holds them - so
    `git cat-file -e` goes on answering yes on the machine that did the rewrite
    and no on every fresh clone. A check that passes on the one machine where
    the answer does not matter is the characteristic failure this repository
    keeps finding in itself, so the question asked here is the one a stranger's
    clone would ask.
    """
    ours = _this_repository()
    pages: list[str] = [page for page in SHA_PAGES if (ROOT / page).is_file()]
    for directory in SHA_DIRECTORIES:
        for path in sorted((ROOT / directory).rglob("*")):
            if not path.is_file() or path.suffix not in (".md", ".yml", ".yaml"):
                continue
            relative = path.relative_to(ROOT).as_posix()
            if any(relative.startswith(skip) for skip in SHA_EXCLUDED):
                continue
            pages.append(relative)

    citations: list[dict] = []
    for relative in pages:
        citations += sha_citations(
            relative, (ROOT / relative).read_text(encoding="utf-8")
        )

    mine = [row for row in citations if (row["repository"] or "").lower() == ours.lower()]
    executable = shutil.which("git")

    def git(*arguments: str) -> tuple[int, str]:
        if executable is None:  # pragma: no cover - no git on the machine
            return 1, ""
        completed = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
            [executable, *arguments], cwd=ROOT, capture_output=True, text=True, timeout=30
        )
        return completed.returncode, completed.stdout.strip()

    code, top = git("rev-parse", "--show-toplevel")
    a_checkout = code == 0 and Path(top).resolve() == ROOT.resolve()

    def resolve(sha: str) -> str | None:
        if git("rev-parse", "--verify", f"{sha}^{{commit}}")[0] != 0:
            return "is not a commit in this repository"
        if git("merge-base", "--is-ancestor", sha, "HEAD")[0] != 0:
            return (
                "is a commit in this repository and is not an ancestor of HEAD, so a "
                "fresh clone would not have it"
            )
        return None

    problems = sha_problems(citations, ours, resolve if a_checkout else lambda _: None)
    if problems:
        raise DriftError("\n".join(problems))

    external = len(citations) - len(mine)
    if not a_checkout:
        return (
            f"{len(citations)} commit SHAs across {len(pages)} pages, {len(mine)} of this "
            f"repository, and none of them resolved: this tree is not a checkout"
        )
    return (
        f"{len(citations)} commit SHAs across {len(pages)} pages: {len(mine)} of this "
        f"repository, each on this branch, and {external} pinning somebody else's action"
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
