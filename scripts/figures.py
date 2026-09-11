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
import tempfile
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
# written at 1.0, when `src/actaira` was eight packages and five loose
# modules, and every package added after it - agentgov, agents, connectors,
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
    ("formats", ["src/actaira/formats"], "the parsers, one per artifact format"),
    ("attest", ["src/actaira/attest"], "Merkle tree, chain, signing, keyring, RFC 3161, verification"),
    ("core", ["src/actaira/model.py", "src/actaira/inspect.py", "src/actaira/cli.py",
              "src/actaira/__init__.py", "src/actaira/__main__.py"], "the model, the verdict rules, the CLI"),
    ("scan", ["src/actaira/scan"], "the import policy"),
    ("agentgov", ["src/actaira/agentgov"], "agents, tools, MCP servers, capabilities, attack paths"),
    ("agents", ["src/actaira/agents"], "the judged pipeline: provider, retriever, judge, verifier"),
    ("controls", ["src/actaira/controls"], "the executable EU AI Act controls"),
    ("governance", ["src/actaira/governance"], "the obligation catalogue, the clock, the dossier"),
    ("policy", ["src/actaira/policy"], "the policy document and the decision engine"),
    ("state", ["src/actaira/state"], "the SQLite store, watch, evidence, graph"),
    ("connectors", ["src/actaira/connectors"], "the discovery layer"),
    ("schemas", ["src/actaira/schemas"], "the published contracts"),
    ("bom", ["src/actaira/bom"], "CycloneDX 1.6 ML-BOM"),
    ("report", ["src/actaira/report"], "SARIF and JUnit"),
    ("i18n", ["src/actaira/i18n"], "the bilingual catalogue"),
    ("web", ["src/actaira/web"], "the local review interface"),
    ("rest", ["src/actaira"], "everything in src/ the areas above do not claim"),
    ("tests", ["tests"], "the test suite"),
    ("evals", ["evals"], "corpus builder, evaluation harness, benchmark"),
    ("fuzz", ["fuzz"], "the fuzzing harness"),
    ("scripts", ["scripts"], "this script"),
]

DOC_FILES = ["docs/DESIGN.md", "docs/FORMATS.md", "docs/THREAT-MODEL.md", "fuzz/README.md"]


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
        for root in ("src", "tests", "evals", "fuzz", "scripts")
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
    catalogue = ROOT / "src" / "actaira" / "i18n"
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


def measure_corpus() -> dict[str, Any]:
    sys.path.insert(0, str(ROOT / "evals"))
    from corpus.build import build  # type: ignore  # noqa: PLC0415

    with tempfile.TemporaryDirectory(prefix="actaira-figures-") as scratch:
        cases = build(Path(scratch))
    families = Counter(case.family for case in cases)
    labels = Counter(case.label for case in cases)
    # Every label, not two of them. The page said "64 artifacts: 16 benign, 47
    # malicious", which is 63, because one case carries a third label,
    # `hostile-but-inconclusive`: an artifact whose hostility is real and whose
    # verdict is INCONCLUSIVE rather than FAIL, which is the whole point of the
    # third verdict and exactly the case that should not be rounded away on a
    # page whose first line is that nothing here is typed by hand.
    return {
        "cases": len(cases),
        "families": dict(sorted(families.items())),
        "labels": dict(sorted(labels.items())),
        "benign": labels.get("benign", 0),
        "malicious": labels.get("malicious", 0),
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


def measure_eval() -> dict[str, Any]:
    raw = read_json("evals/results.json", "make eval")
    if not raw.get("available"):
        return raw
    document = raw.pop("document")
    policies = document.get("policy_comparison", {})
    raw["figures"] = {
        "cases": document.get("corpus", {}).get("cases"),
        "expectations_met": document.get("expectations", {}).get("met"),
        "expectations_checked": document.get("expectations", {}).get("checked"),
        "strict": policies.get("strict", {}),
        "known_bad": policies.get("known-bad", {}),
        "caught_only_by_strict": policies.get("caught_only_by_strict", {}).get("count"),
        "median_ms": document.get("timing_ms", {}).get("median_ms"),
        "max_ms": document.get("timing_ms", {}).get("max_ms"),
        "determinism": document.get("determinism", {}),
        "tamper_detection": document.get("tamper_detection", {}),
    }
    return raw


def measure_benchmark() -> dict[str, Any]:
    raw = read_json("evals/benchmark.json", "make benchmark")
    if not raw.get("available"):
        return raw
    document = raw.pop("document")
    raw["figures"] = {
        "python": document.get("python"),
        "tools": [{"name": tool["name"], "version": tool["version"]} for tool in document.get("tools", [])],
        "artifacts": len(document.get("rows", [])),
        "scoreboard": document.get("scoreboard"),
    }
    return raw


def measure_fuzz() -> dict[str, Any]:
    raw = read_json("fuzz/runs/latest/summary.json", "make fuzz")
    if not raw.get("available"):
        return raw
    document = raw.pop("document")
    targets = document.get("targets", [])
    raw["figures"] = {
        "seed": document.get("seed"),
        "iters_per_target": document.get("iters_per_target"),
        "targets": len(targets),
        # Cases the workers actually ran, not the budget the command line
        # asked for. Summing `iters` published the argument as though it were
        # a measurement, so a run whose workers died after a few hundred cases
        # still reported the full figure. A summary written before `executed`
        # existed has no honest number to offer and reports zero, which is the
        # right way for a stale figure to fail.
        "total_cases": sum(target.get("executed", 0) for target in targets),
        "cases_requested": sum(target.get("iters", 0) for target in targets),
        "seconds": document.get("seconds"),
        "findings": sum(len(target.get("findings", [])) for target in targets),
        "hard_failures": sum(len(target.get("hard_failures", [])) for target in targets),
        "target_names": sorted(target.get("target", "?") for target in targets),
        # What the run could NOT hold the parsers to. Two of the fuzzer's four
        # promises - bounded memory and per-case termination - are enforced by
        # `RLIMIT_AS` and `SIGALRM`, which are POSIX. Publishing "0 findings"
        # from a run that could not enforce them, with no mention of it, is
        # exactly the shape of claim this page exists to refuse: a measurement
        # reported without what it was measured with. Empty on POSIX.
        "unenforced_oracles": sorted(document.get("unenforced_oracles", [])),
    }
    return raw



# ---------------------------------------------------------------------------
# The defect ledger
# ---------------------------------------------------------------------------

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
        "by_mechanism": dict(sorted(by_mechanism.items(), key=lambda item: (-item[1], item[0]))),
        "mechanisms": len(by_mechanism),
        "pinned_by_a_named_test": pinned,
        "pinned_by_a_note_instead": pinned_by_note,
        "named_tests": len(named_tests),
        "unpinned": unpinned,
        "named_tests_not_collected": missing_tests,
        "checked_against_pytest": collected_node_ids is not None,
    }



def measure_governance() -> dict[str, Any]:
    """The obligation catalogue, counted from the catalogue itself.

    The README spends two sections on this module and quotes four numbers from
    it: how many obligations, how many the tool contributes nothing to, how
    many it claims full support for, and how the roles split. None of them was
    produced by anything, which for the module whose entire argument is "do not
    take a number on trust" was the wrong place to leave a gap.

    `zero fully supported` is the one to read. It is not an aspiration: an
    obligation reaches `SUPPORTS` only if the tool can carry it on its own, and
    reading model files never can.
    """
    try:
        from actaira.governance.catalog import ALL_OBLIGATIONS, Coverage
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        return {"available": False, "reason": f"{type(exc).__name__}: {exc}"}

    by_coverage: Counter[str] = Counter()
    by_role: Counter[str] = Counter()
    with_grace = 0
    for obligation in ALL_OBLIGATIONS:
        by_coverage[obligation.coverage.value] += 1
        by_role[obligation.role.value] += 1
        if obligation.grace_until is not None:
            with_grace += 1

    return {
        "available": True,
        "source": "src/actaira/governance/catalog.py",
        "obligations": len(ALL_OBLIGATIONS),
        "by_coverage": dict(sorted(by_coverage.items())),
        "by_role": dict(sorted(by_role.items(), key=lambda item: (-item[1], item[0]))),
        "not_covered": by_coverage[Coverage.NOT_COVERED.value],
        "fully_supported": by_coverage[Coverage.SUPPORTS.value],
        "with_grace_period": with_grace,
        "earliest_applies_from": min(o.applies_from for o in ALL_OBLIGATIONS).isoformat(),
        "latest_applies_from": max(o.applies_from for o in ALL_OBLIGATIONS).isoformat(),
    }


def measure_package() -> dict[str, Any]:
    """The package metadata, read from the metadata rather than from prose.

    The version is imported from the module the package ships, not parsed out
    of `pyproject.toml`, so a repository where the two disagree produces a
    figure that disagrees with itself and gets noticed. CI checks the same
    pair on every release tag.
    """
    from actaira import __version__  # noqa: PLC0415

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
        lines: list[str] = ["# Actaira in numbers", ""]
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
            f"Generated {figures['generated_at']} for actaira {figures['package']['version']}"
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

        governance = figures["governance"]
        lines += ["## The obligation catalogue", ""]
        if governance.get("available"):
            lines += [
                f"**{governance['obligations']}** obligations, from "
                f"`{governance['source']}`. **{governance['not_covered']}** are marked as "
                f"outside what this tool can show and **{governance['fully_supported']}** as "
                "fully supported, which is the number that matters: an obligation reaches "
                "that rating only if reading model files could carry it alone, and none can.",
                "",
                "| coverage | obligations |", "|---|---:|",
            ]
            lines += [f"| {name} | {count} |" for name, count in governance["by_coverage"].items()]
            lines.append(f"| **total** | **{governance['obligations']}** |")
            lines += ["", "| binds | obligations |", "|---|---:|"]
            lines += [f"| {name} | {count} |" for name, count in governance["by_role"].items()]
            lines.append("")
            lines.append(
                f"{governance['with_grace_period']} carry a transitional grace period. Dates of "
                f"application run from {governance['earliest_applies_from']} to "
                f"{governance['latest_applies_from']}."
            )
        else:
            lines.append(f"Not available: {governance.get('reason', 'unknown')}.")
        lines.append("")

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

        corpus = figures["corpus"]
        lines += [
            "## Corpus", "",
            f"**{corpus['cases']}** artifacts, built from code at measurement time and never "
            "committed: "
            + ", ".join(f"{count} {label}" for label, count in corpus["labels"].items())
            + ".",
            "",
            "| family | cases |", "|---|---:|",
        ]
        lines += [f"| {name} | {count} |" for name, count in corpus["families"].items()]
        lines.append("")

        lines += ["## Evaluation", ""]
        evaluation = figures["eval"]
        if evaluation.get("available"):
            numbers = evaluation["figures"]
            strict = numbers["strict"]
            known_bad = numbers["known_bad"]
            tamper = numbers["tamper_detection"]
            lines += [
                f"From `{evaluation['source']}`, written by `{evaluation['produced_by']}`.",
                "",
                f"- expectations met: **{numbers['expectations_met']}/{numbers['expectations_checked']}**",
                f"- strict (allowlist): caught **{strict.get('malicious_caught')}/{strict.get('malicious_total')}** "
                f"malicious, **{strict.get('benign_wrongly_failed')}** benign artifacts wrongly failed",
                f"- known-bad (denylist): caught **{known_bad.get('malicious_caught')}/{known_bad.get('malicious_total')}** "
                f"malicious, **{known_bad.get('benign_wrongly_failed')}** benign artifacts wrongly failed",
                f"- caught only by the allowlist: **{numbers['caught_only_by_strict']}**",
                f"- per artifact: median **{numbers['median_ms']} ms**, max {numbers['max_ms']} ms",
                f"- identical output over two runs: "
                f"**{numbers['determinism'].get('identical')}/{numbers['determinism'].get('cases')}**",
                f"- tampered packages rejected: "
                f"**{tamper.get('tampered_packages_rejected')}/{tamper.get('packages_verified_before_tampering')}**",
            ]
        else:
            lines.append(f"Not available. Run `{evaluation.get('produced_by')}`.")
        lines.append("")

        lines += ["## Against the other scanners", ""]
        benchmark = figures["benchmark"]
        if benchmark.get("available"):
            numbers = benchmark["figures"]
            lines += [
                f"From `{benchmark['source']}`, written by `{benchmark['produced_by']}` "
                f"on Python {numbers['python']}, over {numbers['artifacts']} artifacts.",
                "",
                "| tool | version |", "|---|---|",
            ]
            lines += [f"| {tool['name']} | {tool['version']} |" for tool in numbers["tools"]]
            scoreboard = numbers.get("scoreboard") or {}
            for board, title, note in (
                ("head_to_head_pickle", "Head to head, on the artifacts every tool reads",
                 "pickle-bearing formats only, so nobody is scored on a format they never claimed"),
                ("whole_corpus", "The whole corpus",
                 "everything, with what each tool declined to read reported beside what it caught"),
            ):
                rows = scoreboard.get(board)
                if not isinstance(rows, dict):
                    continue
                lines += ["", f"### {title}", "", note, "",
                          "| tool | caught | false alarms | declined | median ms |",
                          "|---|---:|---:|---:|---:|"]
                for name, row in rows.items():
                    if not isinstance(row, dict):
                        continue
                    lines.append(
                        f"| {name} | {row.get('malicious_caught')}/{row.get('malicious_total')} "
                        f"| {row.get('false_alarms')} | {row.get('declined')} | {row.get('median_ms')} |"
                    )
            losses = scoreboard.get("losses")
            if isinstance(losses, dict):
                beaten = {tool: cases for tool, cases in losses.items() if cases}
                lines += [
                    "",
                    "Artifacts another tool catches and Actaira misses: "
                    + (", ".join(f"{tool} ({len(cases)})" for tool, cases in beaten.items())
                       if beaten else "**none**")
                    + ". The harness computes this every run and prints it either way, because "
                    "\"nobody beats us\" is only information if you can see it was checked.",
                ]
            family = scoreboard.get("by_family")
            if isinstance(family, dict) and family:
                tools = sorted({tool for rows in family.values() for tool in rows})
                lines += ["", "Caught, by corpus family:", "",
                          "| family | " + " | ".join(tools) + " |",
                          "|---" * (len(tools) + 1) + "|"]
                for name, rows in sorted(family.items()):
                    cells = []
                    for tool in tools:
                        row = rows.get(tool, {})
                        cells.append(f"{row.get('caught', '-')}/{row.get('total', '-')}")
                    lines.append(f"| {name} | " + " | ".join(cells) + " |")
        else:
            lines.append(
                f"Not available in this checkout: `{benchmark['source']}` is not committed, "
                "because it names versions of other people's tools and would go stale. "
                f"Run `{benchmark.get('produced_by')}` to produce it."
            )
        lines.append("")

        lines += ["## Fuzzing", ""]
        fuzz = figures["fuzz"]
        if fuzz.get("available"):
            numbers = fuzz["figures"]
            lines += [
                f"From `{fuzz['source']}`, written by `{fuzz['produced_by']}`.",
                "",
                f"- **{numbers['total_cases']}** cases over **{numbers['targets']}** targets, "
                f"seed {numbers['seed']}, {numbers['seconds']} s",
                f"- findings: **{numbers['findings']}**, hard failures: **{numbers['hard_failures']}**",
                f"- targets: {', '.join(numbers['target_names'])}",
            ]
            unenforced = numbers.get("unenforced_oracles") or []
            if unenforced:
                lines += [
                    "",
                    f"**This run enforced {4 - len(set(item.split(')')[0] for item in unenforced))} "
                    "of the four promises.** The host it ran on does not provide what the "
                    "other(s) are enforced with, so the finding count above is a weaker "
                    "result than the same count from a POSIX run:",
                    "",
                    *[f"- {item}" for item in unenforced],
                ]
        else:
            lines.append(
                f"Not available in this checkout: fuzzing output is not committed "
                f"(`fuzz/runs/` is ignored). Run `{fuzz.get('produced_by')}`."
            )
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
        "defects": measure_defects(node_ids),
        "governance": measure_governance(),
        "code": measure_areas(),
        "docs": measure_docs(),
        "catalog": measure_catalog(),
        "corpus": measure_corpus(),
        "eval": measure_eval(),
        "benchmark": measure_benchmark(),
        "fuzz": measure_fuzz(),
    })


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure this repository and write docs/FIGURES.md")
    parser.add_argument("--print", dest="print_only", action="store_true",
                        help="print the markdown instead of writing anything")
    parser.add_argument("--markdown-out", type=Path, default=ROOT / "docs" / "FIGURES.md")
    parser.add_argument("--json-out", type=Path, default=ROOT / "figures.json")
    arguments = parser.parse_args()

    report = collect()
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
              f"{report.figures['catalog']['rules']} rules, {report.figures['corpus']['cases']} corpus artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
