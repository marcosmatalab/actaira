"""What each package of `seamark` is allowed to import, written down once.

The graph was already a clean DAG when this was written: nothing under
`src/seamark/` imports `cli` or `mcp`, and there were exactly three edges that
cross between sibling packages. So this is not a refactor, it is the assertion
that was missing. An architecture nobody can fail is one that holds until the
first afternoon somebody is in a hurry.

The contract is an ALLOWLIST OF EDGES and not a list of prohibitions, because
the two are not equally safe to get wrong. A prohibition list is silent about
the package nobody thought of: add `report/pdf.py` importing `attest` and a
matrix of "what must not be imported" passes unless somebody remembered to
extend it. An allowlist fails on the edge it has never seen, which is the one
worth failing on.

It is also not an exemption list, which this repository refuses elsewhere for
good reason. An exemption list is satisfied by adding a line to it, so the rule
would be kept by whoever chose not to add one. Here there is nothing to exempt:
every edge is in the contract or it is a failure, and widening the contract is
a visible edit to the sentence that says what the architecture is.

The three crossing edges, each named where it is allowed:

  * `attest/seal.py` imports `trace.redact`. A seal carries salted references
    and no content, and redaction is where that is defined; a second copy of it
    inside `attest` is the two-definitions shape work rule 10 refuses.
  * `report/sarif.py` imports `surface.diff`. SARIF reports a finding against
    what changed, and what changed is `surface-diff/v1`.
  * `report/html.py` imports `i18n.catalog`. The report is the one output a
    human reads, so it is the one output that is translated.

`edges()` comes from `tests/test_reachability.py` rather than being written
again here. Two checks over one property share a definition or they cancel:
with two readers of the import graph, one can go on passing over a tree the
other would refuse, and the disagreement is invisible from either side.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from conftest import REPO_ROOT
from test_reachability import MODULES, edges

# The loose modules at the root of the package: the data model, the published
# schemas, and the package marker. Everything may see these, and they may see
# only each other. `cli`, `mcp` and `__main__` live at the root too and are the
# entry points, which is why they are named separately below.
CORE = frozenset({"", "model", "schemas"})

# The entry points. Nothing below them may import one, and they may import
# anything: a command is the top of the graph by definition. They may import
# each other, which is not a loophole but what they are: `__main__` is
# `python -m seamark` and `mcp` exposes the same commands over a protocol, so
# both are thin fronts on `cli` rather than layers of their own.
ENTRY_POINTS = frozenset({"cli", "mcp", "__main__"})

# package -> what that package's modules may import, beyond their own package.
# A package absent from this table may import nothing outside CORE.
ALLOWED: dict[str, frozenset[str]] = {
    "": CORE,
    "model": CORE,
    "schemas": CORE,
    "i18n": CORE,
    "trace": CORE,
    "surface": CORE,
    # `attest/seal.py` -> `trace.redact`, the one edge out of attest.
    "attest": CORE | {"trace"},
    "proxy": CORE | {"trace"},
    # `report/sarif.py` -> `surface.diff`, `report/html.py` -> `i18n.catalog`.
    "report": CORE | {"surface", "i18n"},
    "cli": CORE | {"attest", "i18n", "proxy", "report", "surface", "trace"},
    "mcp": CORE | {"attest", "i18n", "proxy", "report", "surface", "trace", "cli"},
    "__main__": CORE | {"attest", "i18n", "proxy", "report", "surface", "trace", "cli"},
}


def package_of(module: str) -> str:
    """The package a module belongs to, as this contract names packages.

    `seamark.surface.resolve` is in `surface`; `seamark.model` is in `model`,
    which is its own name because a loose module at the root is not part of
    anything; `seamark` itself is the empty string.
    """
    parts = module.split(".")
    assert parts[0] == "seamark", module
    return parts[1] if len(parts) > 1 else ""


def violations(graph: dict[str, set[str]]) -> list[str]:
    """Every import in `graph` that the table above does not allow.

    A pure function over the graph, so the twin below can plant an edge and
    watch this refuse it without writing to `src/`.
    """
    problems: list[str] = []
    for importer in sorted(graph):
        source = package_of(importer)
        for imported in sorted(graph[importer]):
            target = package_of(imported)
            if target == source:
                continue  # a package may always see itself
            if target in ENTRY_POINTS and source not in ENTRY_POINTS:
                problems.append(
                    f"{importer} imports {imported}: nothing below an entry point may "
                    f"import one, because a command is the top of the graph"
                )
                continue
            permitted = ALLOWED.get(source, CORE)
            if target not in permitted:
                problems.append(
                    f"{importer} imports {imported}: {source or 'the package root'} may "
                    f"import {', '.join(sorted(name or 'the package root' for name in permitted))} "
                    f"and not {target}"
                )
    return problems


def test_the_table_names_every_package_that_exists():
    """Work rule 11: a contract that has stopped covering the tree is not a
    contract that passes, it is one that has stopped looking.

    A package added under `src/seamark/` and never added here would fall
    through to `CORE` and be silently held to the strictest rule, which sounds
    safe and is not: the day it legitimately needs an edge, the failure reads
    as a layering violation rather than as a contract nobody updated.
    """
    present = {package_of(module) for module in MODULES}
    missing = sorted(present - set(ALLOWED))
    assert not missing, (
        "these packages exist under src/seamark and the layering contract does not "
        "name them: " + ", ".join(missing)
    )
    stale = sorted(set(ALLOWED) - present)
    assert not stale, (
        "the layering contract names packages that are not in the tree: " + ", ".join(stale)
    )


def test_the_graph_is_not_trivially_empty():
    """The other half of work rule 11. A reader that silently found nothing
    passes this test forever, and it is the same disease as a pattern that
    matches nothing."""
    graph = edges()
    assert len(graph) > 20, f"only {len(graph)} modules were read; the reader found nothing"
    assert sum(len(value) for value in graph.values()) > 30, "the import graph has almost no edges"


def test_no_module_imports_across_a_layer_the_contract_forbids():
    problems = violations(edges())
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize(
    "planted",
    [
        # The example the acceptance script uses, and the one that would hurt
        # most: configuration resolution reaching into signing.
        {"seamark.surface.resolve": {"seamark.attest.seal"}},
        # The direction that turns a DAG into a cycle.
        {"seamark.trace.model": {"seamark.surface.diff"}},
        # A subpackage reaching up into a command.
        {"seamark.surface.rules": {"seamark.cli"}},
        # `report` is allowed `surface` and not `attest`, which is the pair
        # most likely to be confused by somebody adding a signed report.
        {"seamark.report.html": {"seamark.attest.verify"}},
    ],
)
def test_the_contract_would_notice_a_forbidden_import(planted):
    """Work rule 9's twin: the check has to be seen refusing something.

    Planted into the graph rather than into `src/`, so the assertion is about
    the contract and not about whether a test remembered to clean up after
    itself.
    """
    assert violations(planted), (
        f"{planted} is an edge the contract forbids and `violations` said nothing"
    )


def test_the_contract_is_not_so_wide_that_everything_passes():
    """A guard that allows everything is a green tick with nothing behind it."""
    everything = {
        module: {other for other in MODULES if other != module}
        for module in MODULES
    }
    assert violations(everything), "the contract allows every edge in the package"


def test_the_source_of_the_three_crossing_edges_is_where_this_file_says_it_is():
    """The three edges are named in the docstring, so they have to be real.

    A comment naming a file that stopped importing what the comment says is
    the sort of documentation this repository's own gate exists to refuse.
    """
    expected = {
        "src/seamark/attest/seal.py": "from ..trace.redact import",
        "src/seamark/report/sarif.py": "from ..surface.diff import",
        "src/seamark/report/html.py": "from ..i18n.catalog import",
    }
    for relative, fragment in expected.items():
        text = (Path(REPO_ROOT) / relative).read_text(encoding="utf-8")
        assert fragment in text, (
            f"{relative} no longer contains `{fragment}`, so the layering contract "
            "is widened for an edge that is not there any more"
        )
