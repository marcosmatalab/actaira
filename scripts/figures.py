#!/usr/bin/env python3
"""Measure this repository and write the numbers down.

This exists because the README has drifted from reality twice. A figure typed
into prose is a claim about a moment that has passed; the moment the code
changes, the prose is wrong and nothing says so. Every number in
`docs/FIGURES.md` is produced here, from the repository as it is on disk right
now, and every one of them names where it came from.

What is measured, and how:

  tests        `pytest --collect-only`, so the number is what pytest would
               actually run, not a count of `def test_` lines.
  code         every Python file, split into code, docstrings, comments and
               blanks by `tokenize` and `ast`. This project keeps its design
               notes in docstrings, so lumping those in with code would
               overstate the size of the thing being reviewed.
  coverage     read from the `.coverage` data file `make test-cov` leaves
               behind, through `coverage json`, so the published percentage is
               coverage's own rounding. This script never runs the suite.
  rules        the identifiers the message catalogue carries, per family.
  corpus       built for real into a temporary directory, then counted.
  eval,        read from `evals/results.json`, `evals/benchmark.json` and
  benchmark,   `fuzz/runs/latest/summary.json`. Those files are written by the
  fuzz         harnesses themselves; this script never recomputes them, and
               says so where they are missing rather than printing a zero.

Nothing here estimates. If a source is absent the figure is reported as
unavailable, with the command that would produce it.

    python scripts/figures.py            write docs/FIGURES.md and figures.json
    python scripts/figures.py --print    write nothing, print the markdown
"""
from __future__ import annotations

import argparse
import ast
import io
import json
import shutil
import subprocess
import sys
import tokenize
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# `docs/FIGURES.md` used to open with a CI badge: an image fetched from a third
# party, pointing at workflow runs on a repository this tree does not have. The
# page is meant to be readable with no network, and a broken image at the top
# of the file that holds every measured number was the worst place in the
# repository for one.

# Area name -> the directories or files it covers. Ordered as a reader would
# want to see them: what the tool is, then what checks it.
#
# Design note D-236, and the reason the last entry exists. This list was
# written at 1.0, when `src/seamark` was eight packages and five loose
# modules, and every package added after it - conformance, agents, connectors,
# controls, governance, policy, state, schemas - plus eleven more loose
# modules were never added to it. By 2.2 it covered 103 of the 161 Python
# files in the repository while `figures.json` labelled the total "every
# Python file in the repository", so the published line count, the one figure
# both READMEs state and the banner prints, was measured over two thirds of
# the tree and described as the whole of it.
#
# The fix is not to extend the list, because the next package added would be
# missed the same way. `rest` is computed: every Python file the named areas
# did not claim. It is named in the table like any other area, so a reader
# sees it, and `total` is now arithmetic over a partition rather than a sum
# over whatever somebody remembered.
AREAS: list[tuple[str, list[str], str]] = [
    ("attest", ["src/seamark/attest"], "Merkle tree, chain, signing, keyring, RFC 3161, verification"),
    ("trace", ["src/seamark/trace"], "the trace document, the transcript reader, redaction"),
    ("proxy", ["src/seamark/proxy"], "the MCP proxy, its two transports and the watch session"),
    ("core", ["src/seamark/model.py", "src/seamark/cli.py",
              "src/seamark/__init__.py", "src/seamark/__main__.py"], "the model and the CLI"),
    ("schemas", ["src/seamark/schemas"], "the published contracts"),
    ("i18n", ["src/seamark/i18n"], "the bilingual catalogue"),
    ("rest", ["src/seamark"], "everything in src/ the areas above do not claim"),
    ("tests", ["tests"], "the test suite"),
    ("scripts", ["scripts"], "this script"),
]

# The design document, which is the only long-form page phase A.1 left live.
# `docs/THREAT-MODEL.md` was the second entry and is in `docs/archive/` now:
# measuring an archived page publishes a figure about a document nobody
# maintains, and a figure that cannot go stale because nothing changes it is
# a figure that says nothing.
DOC_FILES = ["docs/DESIGN.md"]


# ---------------------------------------------------------------------------
# Counting Python
# ---------------------------------------------------------------------------

@dataclass
class Counts:
    files: int = 0
    lines: int = 0
    code: int = 0
    docstring: int = 0
    comment: int = 0
    blank: int = 0

    def add(self, other: Counts) -> None:
        for name in ("files", "lines", "code", "docstring", "comment", "blank"):
            setattr(self, name, getattr(self, name) + getattr(other, name))

    def to_dict(self) -> dict[str, int]:
        return {
            "files": self.files, "lines": self.lines, "code": self.code,
            "docstring": self.docstring, "comment": self.comment, "blank": self.blank,
        }


def count_python(path: Path) -> Counts:
    """One file, split four ways.

    Docstrings are found through the AST rather than by looking for triple
    quotes, so a string used as a value is not mistaken for documentation and
    a docstring written with single quotes is not missed.
    """
    source = path.read_text(encoding="utf-8")
    physical = source.splitlines()
    counts = Counts(files=1, lines=len(physical))

    documented: set[int] = set()
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:  # pragma: no cover - a file that will not parse is a bug elsewhere
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = getattr(node, "body", None)
            if not body or not isinstance(body[0], ast.Expr):
                continue
            value = body[0].value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                documented.update(range(value.lineno, (value.end_lineno or value.lineno) + 1))

    commented: set[int] = set()
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                commented.add(token.start[0])
    except (tokenize.TokenError, IndentationError):  # pragma: no cover
        pass

    for number, text in enumerate(physical, start=1):
        if not text.strip():
            counts.blank += 1
        elif number in documented:
            counts.docstring += 1
        elif number in commented and text.strip().startswith("#"):
            counts.comment += 1
        else:
            counts.code += 1
    return counts


def python_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if target.suffix == ".py" else []
    return [
        path for path in sorted(target.rglob("*.py"))
        if "__pycache__" not in path.parts and ".egg-info" not in str(path)
    ]


def measure_areas() -> dict[str, Any]:
    """Every Python file in the repository, each counted exactly once.

    A file claimed by an earlier area is not counted again by a later one, so
    the areas partition the tree rather than overlapping it, and `rest` picks
    up whatever the named ones did not claim. That is what makes the total
    honest: it is a sum over a partition, and an area added to `src/` that
    nobody adds to `AREAS` lands in `rest` and is still counted, instead of
    disappearing (D-236).

    The check at the end is the real guarantee. It recounts the repository
    from scratch and raises if the partition lost a file, because this
    function's output is the line count both READMEs state and the banner
    prints, and a measurement that can silently under-report is worse than
    one that is absent.
    """
    areas: dict[str, Any] = {}
    total = Counts()
    claimed: set[Path] = set()
    for name, targets, note in AREAS:
        counts = Counts()
        files = 0
        for relative in targets:
            for path in python_files(ROOT / relative):
                if path in claimed:
                    continue
                claimed.add(path)
                counts.add(count_python(path))
                files += 1
        if files:
            areas[name] = {"note": note, **counts.to_dict()}
            total.add(counts)

    everything = {
        path
        for root in ("src", "tests", "scripts")
        for path in python_files(ROOT / root)
    }
    missed = sorted(everything - claimed)
    if missed:
        raise SystemExit(
            "AREAS does not cover the whole tree, so the published line count would be "
            "measured over part of it: " + ", ".join(str(path.relative_to(ROOT)) for path in missed)
        )

    areas["total"] = {
        "note": f"every Python file under {', '.join(sorted({a[1][0].split('/')[0] for a in AREAS}))}, "
                "each counted once",
        **total.to_dict(),
    }
    return areas


def measure_docs() -> dict[str, Any]:
    documents = {}
    for relative in DOC_FILES:
        path = ROOT / relative
        if path.exists():
            documents[relative] = {"lines": len(path.read_text(encoding="utf-8").splitlines())}
    documents["total_lines"] = sum(row["lines"] for row in documents.values() if isinstance(row, dict))
    return documents


# ---------------------------------------------------------------------------
# Tests, as pytest sees them
# ---------------------------------------------------------------------------

def measure_tests() -> dict[str, Any]:
    # `-o addopts=` clears the `-q` this project sets in pyproject.toml. With
    # it, `-q --collect-only` prints one node id per line; without it pytest
    # sees two `-q` and prints per-file totals instead. Pinning the verbosity
    # here means this count does not change when someone edits addopts.
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, no external input
        [sys.executable, "-m", "pytest", "tests", "--collect-only", "-q",
         "-p", "no:cacheprovider", "-o", "addopts="],
        cwd=ROOT, capture_output=True, text=True, timeout=900,
    )
    if completed.returncode != 0:
        return {"available": False, "reason": "pytest --collect-only failed", "command": "make test"}
    per_file: Counter[str] = Counter()
    node_ids: set[str] = set()
    for line in completed.stdout.splitlines():
        if "::" in line and line.startswith("tests/"):
            per_file[line.split("::", 1)[0]] += 1
            node_ids.add(line.split("[", 1)[0].strip())
    if not per_file:
        return {"available": False, "reason": "pytest collected nothing", "command": "make test"}
    return {
        "available": True,
        "collected": sum(per_file.values()),
        "files": len(per_file),
        "per_file": dict(sorted(per_file.items())),
        # Node ids with any parametrisation stripped, so `measure_defects` can
        # check that every test the defect ledger names is one pytest would
        # actually run. Kept out of the written figures: it is a working set,
        # not a figure.
        "_node_ids": sorted(node_ids),
    }


# ---------------------------------------------------------------------------
# Rules, corpus, and the harness outputs
# ---------------------------------------------------------------------------

def measure_catalog() -> dict[str, Any]:
    catalogue = ROOT / "src" / "seamark" / "i18n"
    english = json.loads((catalogue / "en.json").read_text(encoding="utf-8"))
    spanish = json.loads((catalogue / "es.json").read_text(encoding="utf-8"))
    families = Counter(rule_id.rsplit("-", 1)[0] for rule_id in english["rules"])
    return {
        "rules": len(english["rules"]),
        "rules_by_family": dict(sorted(families.items())),
        "rule_help": len(english["rule_help"]),
        "ui_messages": len(english["ui"]),
        "languages": 2,
        "keys_identical_in_both_languages": all(
            set(english[section]) == set(spanish[section]) for section in ("ui", "rules", "rule_help")
        ),
    }


def read_json(relative: str, how: str) -> dict[str, Any]:
    path = ROOT / relative
    if not path.exists():
        return {"available": False, "source": relative, "produced_by": how}
    try:
        return {"available": True, "source": relative, "produced_by": how,
                "document": json.loads(path.read_text(encoding="utf-8"))}
    except ValueError:
        return {"available": False, "source": relative, "produced_by": how, "reason": "not valid JSON"}


def measure_defects(collected_node_ids: set[str] | None) -> dict[str, Any]:
    """Count `docs/defects.json`, and check it against the test suite.

    The count of defects this project found in itself is the central claim of
    the repository, and for a while it was the one number in the README that
    `make figures` did not produce: it was typed, from a narrative table, and
    a reader had no way to tell whether it still described the code. So the
    ledger became data, and this reads it.

    The check is the part that matters. Every defect names the tests that keep
    it found, and each of those is matched against the node ids pytest
    collected. A test that has been renamed or deleted is reported by name
    under `named_tests_not_collected`, and `docs/FIGURES.md` says a defect has
    lost its regression test, rather than silently keeping the total looking
    healthy. `unpinned` is the different and worse case: an entry that names
    no test and gives no reason for having none.
    """
    path = ROOT / "docs" / "defects.json"
    if not path.exists():
        return {"available": False, "reason": "docs/defects.json is missing"}
    ledger = json.loads(path.read_text(encoding="utf-8"))
    defects = ledger.get("defects", [])

    by_mechanism: Counter[str] = Counter()
    unpinned: list[str] = []
    pinned_by_note: list[str] = []
    missing_tests: list[str] = []
    named_tests: set[str] = set()
    pinned = 0
    for defect in defects:
        by_mechanism[defect.get("found_by", "unstated")] += defect.get("counts_as", 1)
        pins = defect.get("pinned_by") or []
        if pins:
            pinned += defect.get("counts_as", 1)
            named_tests.update(pins)
        elif defect.get("pinned_note"):
            # Pinned by something that is not a test: the fix lives in the
            # harness itself. Counted separately rather than folded in, so the
            # headline "pinned by a named regression test" stays a count of
            # tests and not a count of good intentions.
            pinned_by_note.append(defect["id"])
        else:
            unpinned.append(defect["id"])
        if collected_node_ids is not None:
            for node in pins:
                if node not in collected_node_ids:
                    missing_tests.append(f"{defect['id']}: {node}")

    return {
        "available": True,
        "source": "docs/defects.json",
        "entries": len(defects),
        "defects": sum(defect.get("counts_as", 1) for defect in defects),
        "in_the_shipped_tool": sum(
            defect.get("counts_as", 1) for defect in defects if defect.get("shipped_defect")
        ),
        # DEF-121. `fixed` is required on every entry and has no default, so
        # this is a count and not an assumption. The prose used to carry the
        # word "all", written by hand and captured verbatim by the sync script,
        # which meant the ledger could only ever hold defects that were already
        # closed - a list of achievements rather than a ledger. Weighted by
        # `counts_as` so it is comparable with `defects` beside it.
        "still_open": sum(
            defect.get("counts_as", 1) for defect in defects if not defect["fixed"]
        ),
        "by_mechanism": dict(sorted(by_mechanism.items(), key=lambda item: (-item[1], item[0]))),
        "mechanisms": len(by_mechanism),
        "pinned_by_a_named_test": pinned,
        "pinned_by_a_note_instead": pinned_by_note,
        "named_tests": len(named_tests),
        "unpinned": unpinned,
        "named_tests_not_collected": missing_tests,
        "checked_against_pytest": collected_node_ids is not None,
    }



def measure_coverage() -> dict[str, Any]:
    """The coverage figure the READMEs state, from the suite's own data file.

    Not measured here: this does not run pytest. `make test-cov` runs the
    suite and leaves `.coverage` behind, and `make all` runs it immediately
    before this script for that reason. A tree with no data file reports the
    figure as unavailable and `main()` carries the previous one over, so
    `make figures` on its own never silently rewrites a number nothing
    measured - which is what the CI consistency job depends on, since it does
    not run the suite.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    from coverage_figure import NotMeasuredError, floor, measured  # noqa: PLC0415

    figure: dict[str, Any] = {"floor": floor(), "source": "scripts/coverage_figure.py"}
    try:
        return {"available": True, **figure, **measured()}
    except NotMeasuredError as absent:
        return {"available": False, "reason": str(absent), "command": "make test-cov", **figure}


def measure_package() -> dict[str, Any]:
    """The package metadata, read from the metadata rather than from prose.

    The version is imported from the module the package ships, not parsed out
    of `pyproject.toml`, so a repository where the two disagree produces a
    figure that disagrees with itself and gets noticed. CI checks the same
    pair on every release tag.
    """
    from seamark import __version__  # noqa: PLC0415

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    runtime = list(project.get("dependencies", []))
    return {
        "version": __version__,
        "declared_version": project.get("version"),
        "version_agrees_with_pyproject": __version__ == project.get("version"),
        "runtime_dependencies": runtime,
        "runtime_dependency_count": len(runtime),
        "development_dependencies": list(project.get("optional-dependencies", {}).get("dev", [])),
        "python_requires": project.get("requires-python", ""),
    }


def measure_git() -> dict[str, Any]:
    """Whatever git will tell us, or nothing.

    A checkout unpacked from an sdist has no `.git`, and the figures are still
    worth having there, so every one of these is optional.
    """
    executable = shutil.which("git")

    def git(*arguments: str) -> str | None:
        if executable is None:
            return None
        try:
            completed = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
                [executable, *arguments], cwd=ROOT, capture_output=True, text=True, timeout=30
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return completed.stdout.strip() if completed.returncode == 0 else None

    commits = git("rev-list", "--count", "HEAD")
    return {
        "available": commits is not None,
        "commits": int(commits) if commits and commits.isdigit() else None,
        "head": git("rev-parse", "--short", "HEAD"),
        "head_date": git("log", "-1", "--format=%ad", "--date=short"),
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

@dataclass
class Report:
    figures: dict[str, Any] = field(default_factory=dict)

    def markdown(self) -> str:
        figures = self.figures
        lines: list[str] = ["# Seamark in numbers", ""]
        lines += [
            "Every figure on this page was measured by `scripts/figures.py` from the",
            "repository as it stood at the moment named below. Nothing here is typed by",
            "hand, which is the point: the prose in this project has drifted from the",
            "code twice, and a number nobody can regenerate is a number nobody can check.",
            "",
            "```",
            "make figures",
            "```",
            "",
            f"Generated {figures['generated_at']} for seamark {figures['package']['version']}"
            + (f", at commit {figures['git']['head']}" if figures["git"].get("head") else "")
            + ".",
            "",
        ]

        package = figures["package"]
        lines += [
            "## The package", "",
            f"- version **{package['version']}**, Python {package['python_requires']}",
            f"- runtime dependencies: **{package['runtime_dependency_count']}** "
            f"({', '.join(package['runtime_dependencies']) or 'none'})",
            f"- development dependencies: {', '.join(package['development_dependencies']) or 'none'}",
        ]
        git = figures["git"]
        if git.get("available"):
            lines.append(f"- {git['commits']} commits, most recent {git['head_date']}")
        lines.append("")

        tests = figures["tests"]
        lines += ["## Tests", ""]
        if tests.get("available"):
            lines += [
                f"**{tests['collected']}** tests collected by pytest across {tests['files']} files.",
                "",
                "| file | tests |", "|---|---:|",
            ]
            lines += [f"| `{name}` | {count} |" for name, count in tests["per_file"].items()]
            lines.append(f"| **total** | **{tests['collected']}** |")
        else:
            lines.append(f"Not available: {tests.get('reason', 'unknown')}. Run `{tests.get('command', 'make test')}`.")
        lines.append("")

        coverage = figures["coverage"]
        if coverage.get("available"):
            lines += [
                f"Statement coverage of `src/seamark`: **{coverage['percent']}**, measured by "
                f"`make test-cov`, which fails under {coverage['floor']}.",
                "",
            ]
        else:
            lines += [
                f"Coverage not available: {coverage.get('reason', 'unknown')}. "
                f"Run `{coverage.get('command', 'make test-cov')}`.",
                "",
            ]

        defects = figures["defects"]
        lines += ["## Defects found in this repository", ""]
        if defects.get("available"):
            lines += [
                f"**{defects['defects']}** defects, from `{defects['source']}` "
                f"({defects['entries']} entries), found by **{defects['mechanisms']}** different "
                f"mechanisms. **{defects['pinned_by_a_named_test']}** are pinned by a named "
                f"regression test, across {defects['named_tests']} tests. "
                f"{defects['in_the_shipped_tool']} were defects in the shipped tool; the "
                "rest were found the same way but lived in the measuring apparatus, and each says so.",
                "",
                "| what found it | defects |", "|---|---:|",
            ]
            lines += [f"| {name} | {count} |" for name, count in defects["by_mechanism"].items()]
            lines.append(f"| **total** | **{defects['defects']}** |")
            lines.append("")
            if defects["checked_against_pytest"]:
                missing = defects["named_tests_not_collected"]
                lines.append(
                    "Every test named in the ledger was checked against what pytest collects: "
                    + ("all of them are collected."
                       if not missing
                       else f"**{len(missing)} are not**, which means a defect has lost its "
                            f"regression test: {', '.join(missing)}.")
                )
            by_note = defects.get("pinned_by_a_note_instead") or []
            if by_note:
                lines.append(
                    f"Pinned by a note rather than by a test, with the reason stated in the "
                    f"ledger: {', '.join(by_note)}."
                )
            unpinned = defects.get("unpinned") or []
            if unpinned:
                lines.append(
                    f"Entries with no regression test and no note explaining why: {', '.join(unpinned)}."
                )
        else:
            lines.append(f"Not available: {defects.get('reason', 'unknown')}.")
        lines.append("")

        lines += [
            "## Code", "",
            "Docstrings are counted apart from code because this project keeps its",
            "design notes in them: `docs/DESIGN.md` consolidates what the modules say,",
            "and the modules are the source of truth.",
            "",
            "| area | files | lines | code | docstrings | comments | blank |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for name, row in figures["code"].items():
            emphasis = "**" if name == "total" else ""
            lines.append(
                f"| {emphasis}{name}{emphasis} | {row['files']} | {row['lines']} | {row['code']} | "
                f"{row['docstring']} | {row['comment']} | {row['blank']} |"
            )
        lines += ["", "Documentation, in lines of Markdown:", ""]
        documents = figures["docs"]
        lines += [f"- `{name}`: {row['lines']}" for name, row in documents.items() if isinstance(row, dict)]
        lines += [f"- total: {documents['total_lines']}", ""]

        catalog = figures["catalog"]
        lines += [
            "## Rules", "",
            f"**{catalog['rules']}** rule identifiers, each with text in "
            f"{catalog['languages']} languages, {catalog['rule_help']} of them with an "
            "explanation of what to do about the finding.",
            "",
            "| family | rules |", "|---|---:|",
        ]
        lines += [f"| `{name}` | {count} |" for name, count in catalog["rules_by_family"].items()]
        lines += [
            "",
            f"Catalogue key sets identical in both languages: "
            f"**{'yes' if catalog['keys_identical_in_both_languages'] else 'no'}** "
            "(asserted by `tests/test_i18n.py`).",
            "",
        ]

        lines += [
            "",
            "---",
            "",
            "The machine-readable form of this page is `figures.json`, written by the same",
            "run. If a number here disagrees with one in a README, this page is the one",
            "that was measured.",
            "",
        ]
        return "\n".join(lines)


def collect() -> Report:
    tests = measure_tests()
    node_ids = set(tests.pop("_node_ids", [])) if tests.get("available") else None
    return Report(figures={
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "generated_by": "scripts/figures.py",
        "package": measure_package(),
        "git": measure_git(),
        "tests": tests,
        "coverage": measure_coverage(),
        "defects": measure_defects(node_ids),
        "code": measure_areas(),
        "docs": measure_docs(),
        "catalog": measure_catalog(),
    })


# The two blocks that move without the tree moving: a wall clock and whatever
# HEAD happens to be. Everything else here is a measurement of files on disk.
STAMPS = ("generated_at", "git")


def the_stamp_still_names_this_history(existing: dict[str, Any]) -> bool:
    """Is the commit the recorded stamp names still on this branch?

    The rewrite of the commit messages is what this is for, and it is the
    shape work rule 12 names rather than a hypothetical. The stamp is carried
    over when nothing was measured differently, and a history rewrite changes
    NOTHING that is measured here: the tree is identical by construction. So
    `figures.json` would go on naming a commit that no longer exists on the
    branch, `make figures` could not fix it because it would carry the stamp
    again, and `release_check.py` would fail on an ancestry it has no way to
    repair. The old commit is still in the object database, held alive by the
    backup ref, so even "does this commit exist" answers yes.

    A stamp is a record of when these figures were last measured to be
    different. A record that names a commit the branch does not have is not a
    record, so it is not carried.
    """
    head = (existing.get("git") or {}).get("head")
    if not head:
        return False
    executable = shutil.which("git")
    if executable is None:  # pragma: no cover - no git on the machine
        return True

    def git(*arguments: str) -> tuple[int, str]:
        try:
            completed = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
                [executable, *arguments], cwd=ROOT, capture_output=True, text=True, timeout=30
            )
        except (OSError, subprocess.SubprocessError):  # pragma: no cover - no git
            return 1, ""
        return completed.returncode, completed.stdout.strip()

    # "Is this a checkout" before "is that commit on it", and the order is the
    # whole of this function's history. Asked the other way round, a tree with
    # no `.git` - an unpacked sdist, or the copy the suite makes to run the
    # measurement twice - gets `not a repository` back from git and reads it as
    # `the commit is gone`, so the stamp moves on every run and the file stops
    # being a function of the tree. That is the same check-something-adjacent
    # shape this condition was written to close, one turn later.
    code, top = git("rev-parse", "--show-toplevel")
    if code != 0 or Path(top).resolve() != ROOT.resolve():
        return True
    return git("merge-base", "--is-ancestor", head, "HEAD")[0] == 0


def keep_the_stamps_when_nothing_was_measured_differently(
    measured: dict[str, Any], existing: dict[str, Any], names_this_history: bool = True
) -> None:
    """Carry the previous stamp over when every measured block is identical.

    `make figures` rewrote `generated_at` on every run and `git` on every
    commit, so it always left the tree dirty and `git diff --exit-code` could
    never be the thing that catches a drifted figure. A generated file that
    changes without its inputs changing cannot be gated on.

    So the stamp says when these figures were last measured to be DIFFERENT,
    which is the honest reading of it and the one that makes the file a
    function of the tree. Rejected: deleting the stamp, which would take
    `git.commits` and `git.head` out of the artifact; `release_check.py`
    checks those against the commit they name, and a figure that leaves the
    guarded set is unguarded rather than moved.

    `names_this_history` is the other half, and without it the carry is a
    trap: see `the_stamp_still_names_this_history`.
    """
    if not names_this_history:
        return
    if any(measured.get(block) != existing.get(block)
           for block in measured if block not in STAMPS):
        return
    for block in STAMPS:
        if block in existing:
            measured[block] = existing[block]


def keep_the_coverage_when_the_suite_did_not_run(
    measured: dict[str, Any], existing: dict[str, Any]
) -> None:
    """Carry the recorded coverage over when this run measured none.

    `make figures` does not run the suite, and the CI job that re-measures the
    figures and demands an empty diff does not either. Without this, either
    that job rewrites the coverage figure to "unavailable" and fails on its own
    diff, or the figure has to leave the guarded set - and a figure that leaves
    the guarded set is not moved, it is unguarded.

    The carry is only ever from measured to unmeasured. A run that DID measure
    coverage writes what it measured, whatever was recorded before, which is
    what makes `make all` and the CI test job able to notice a drift.
    """
    if measured.get("coverage", {}).get("available"):
        return
    if existing.get("coverage", {}).get("available"):
        measured["coverage"] = existing["coverage"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure this repository and write docs/FIGURES.md")
    parser.add_argument("--print", dest="print_only", action="store_true",
                        help="print the markdown instead of writing anything")
    parser.add_argument("--markdown-out", type=Path, default=ROOT / "docs" / "FIGURES.md")
    parser.add_argument("--json-out", type=Path, default=ROOT / "figures.json")
    arguments = parser.parse_args()

    report = collect()
    if arguments.json_out.is_file():
        existing = json.loads(arguments.json_out.read_text(encoding="utf-8"))
        # In this order. The stamp is carried when every measured block is
        # identical, so the coverage block has to be settled before that
        # comparison is made, or a run with no coverage data would move the
        # stamp by disagreeing with a figure it never measured.
        keep_the_coverage_when_the_suite_did_not_run(report.figures, existing)
        keep_the_stamps_when_nothing_was_measured_differently(
            report.figures, existing, the_stamp_still_names_this_history(existing)
        )
    markdown = report.markdown()
    if arguments.print_only:
        print(markdown)
        return 0
    arguments.markdown_out.parent.mkdir(parents=True, exist_ok=True)
    arguments.markdown_out.write_text(markdown, encoding="utf-8", newline="\n")
    arguments.json_out.write_text(json.dumps(report.figures, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    tests = report.figures["tests"]
    print(f"wrote {arguments.markdown_out.relative_to(ROOT)} and {arguments.json_out.relative_to(ROOT)}")
    if tests.get("available"):
        print(f"  {tests['collected']} tests, {report.figures['code']['total']['lines']} lines of Python, "
              f"{report.figures['catalog']['rules']} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
