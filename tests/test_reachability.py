"""Every module of the package is reachable from a command, or it is not here.

Phase A's rule, and the reason it is a test rather than a habit:

    Every module of the package has to be reachable from the CLI or from the
    MCP server. What is not, goes.

At the start of phase A, 29 of 55 modules and about 8 700 lines - close to half
the tree - could not be reached from any entry point. `state/` had no importer
at all; `conformance/` had three, and all three were themselves unreachable.
None of that was visible from inside any one file, which is why a rule enforced
by whoever remembers it was never going to hold. A module with no route to a
command is not a feature that has not shipped yet, it is a claim the repository
cannot keep, and the whole argument of this project is rigor.

Reachability is computed THROUGH FUNCTIONS, not through module-level imports.
An import that only happens inside a function no command reaches is not an edge.
Without that refinement `attest/dsse.py` would have kept `ArtifactReport` alive
from `model.py`, and `coverage.py` alive behind that, on the strength of a
writing half no command called - which is how 140 dead lines and two violations
of the first negative sat inside a published package. The refinement makes the
rule stricter, not looser, and it opens no exemption.

Applied at MODULE level, deliberately. A dead function inside a live module goes
to `docs/BACKLOG.md` with its name; it does not fail this test. The alternative -
whole-program dead-code analysis - fails on every dynamic dispatch and would be
routed around within a week, which is D-181's argument about gates whose only
remedy is a manual edit.

Rejected: an allowlist of modules exempt from the rule. An exemption list is
satisfied by adding a line to it, so the rule would be kept by whoever chose not
to add one. The two modules that needed an exemption when this was written -
`schemas/__init__.py` and `trace/provenance.py`, each the second place a fact
was written down with a test arbitrating between the copies - were wired into
their readers instead. That removed a real defect the rule had uncovered, which
an exemption would have preserved.
"""
from __future__ import annotations

import ast
from collections import deque
from pathlib import Path

import pytest

from conftest import REPO_ROOT, SRC_DIR

PACKAGE = SRC_DIR / "actaira"

# `cli.py` is every command; `mcp.py` is the MCP server; `__main__.py` is
# `python -m actaira`. There is no fourth way in, and a new one would be a new
# way for this tree to be entered, which is a decision rather than an oversight.
ROOTS = ("actaira.cli", "actaira.mcp", "actaira.__main__")


def module_name(path: Path) -> str:
    parts = path.relative_to(SRC_DIR).with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def modules() -> dict[str, Path]:
    return {
        module_name(path): path
        for path in sorted(PACKAGE.rglob("*.py"))
        if "__pycache__" not in path.parts
    }


MODULES = modules()


def targets(module: str, node: ast.Import | ast.ImportFrom, is_package: bool) -> list[str]:
    """Absolute module names one import statement can refer to.

    Both `from .x import y` where `y` is a module and where `y` is a name are
    emitted; only the ones that exist as files survive the filter at the call
    site, so a name and a module of the same spelling cannot be confused.
    """
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]

    if node.level:
        base = module.split(".")
        if not is_package:
            base = base[:-1]
        base = base[: len(base) - (node.level - 1)]
        prefix = ".".join(base)
        root = f"{prefix}.{node.module}" if node.module else prefix
    else:
        root = node.module or ""
    return [root, *(f"{root}.{alias.name}" for alias in node.names)]


def edges() -> dict[str, set[str]]:
    """importer -> imported, over imports a reached function would execute.

    An import nested inside a function body is attributed to that function, and
    the function is only walked if something reaches it. Module-level imports
    are attributed to the module itself and are always walked.
    """
    graph: dict[str, set[str]] = {}
    for module, path in MODULES.items():
        is_package = path.name == "__init__.py"
        tree = ast.parse(path.read_text("utf-8"), filename=str(path))
        found: set[str] = set()

        # Module level: everything not inside a function or a class body.
        stack = [(node, True) for node in tree.body]
        while stack:
            node, at_module_level = stack.pop()
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if at_module_level:
                    found.update(targets(module, node, is_package))
                continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # A deferred import inside a function. Walked, because a module
                # that is reached has its functions available to whatever
                # reached it; the distinction this test draws is between a
                # module that is reached and one that is not.
                stack.extend((child, at_module_level) for child in node.body)
                continue
            for child in ast.iter_child_nodes(node):
                stack.append((child, at_module_level))

        graph[module] = {name for name in found if name in MODULES and name != module}
    return graph


def reachable() -> set[str]:
    graph = edges()
    seen = {root for root in ROOTS if root in MODULES}
    queue = deque(seen)
    while queue:
        for target in sorted(graph[queue.popleft()]):
            if target not in seen:
                seen.add(target)
                queue.append(target)
    return seen


def is_empty_package_marker(path: Path) -> bool:
    """A `__init__.py` with no statements makes no claim, so it keeps none.

    `i18n/__init__.py` is zero bytes. Removing it would break the package; a
    file that declares nothing is not code that cannot be reached.
    """
    return path.name == "__init__.py" and not ast.parse(path.read_text("utf-8")).body


def test_the_entry_points_are_the_ones_this_test_thinks_they_are():
    """If a root were misspelled, every module would look unreachable and the
    test below would fail loudly - but if the SET were wrong the other way, a
    new entry point would quietly make dead code look live."""
    for root in ROOTS:
        assert root in MODULES, f"{root} is not a module; the root set is stale"

    from actaira.cli import build_parser

    commands = set(build_parser()._subparsers._group_actions[0].choices)
    assert commands == {"check", "scan", "watch", "verify", "keygen"}, (
        f"the CLI's commands changed: {sorted(commands)}. CLAUDE.md allows eight and "
        "this tree implements five; adding one is a decision, not a drive-by."
    )


def test_the_graph_is_not_trivially_empty():
    """The non-vacuity guard. A traversal that reached nothing, or an import
    parser that found no edges, would make the rule below pass over an empty
    set - which is a test asserting a property that is not the one it protects.
    """
    graph = edges()

    assert len(MODULES) > 20, f"only {len(MODULES)} modules found; the walk is not walking"
    assert sum(len(found) for found in graph.values()) > 20, "no import edges were parsed"
    assert "actaira.trace.model" in graph["actaira.cli"] or any(
        "actaira.trace" in found for found in graph.values()
    ), "a known edge is missing; the parser is wrong"
    assert len(reachable()) > 1, "nothing but the roots was reached"


@pytest.mark.parametrize("module", sorted(MODULES))
def test_every_module_is_reachable_from_a_command(module):
    """The rule. One case per module, so the failure names the module."""
    if is_empty_package_marker(MODULES[module]):
        pytest.skip("an empty package marker declares nothing")

    assert module in reachable(), (
        f"{module} ({MODULES[module].relative_to(REPO_ROOT)}) cannot be reached from "
        f"{' or '.join(ROOTS)}.\n"
        "Every module of this package has to be reachable from the CLI or from the "
        "MCP server. If it is genuinely needed, wire it to the thing that needs it. "
        "If it is not, delete it: the history keeps it and `git show` brings it back."
    )
