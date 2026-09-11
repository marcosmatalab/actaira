"""Which capabilities the interface reaches, and which are CLI only.

The engine is ahead of the interface. That is a true statement about this
release, it is written in both READMEs, and the risk with a statement like
that is not that it is wrong today: it is that it is maintained by hand and
quietly stops being true in either direction. A capability gains a panel and
nobody updates the prose; or a route is renamed in a refactor and a panel that
the README promises silently stops working.

So the matrix below is the source, and this file holds it to the code from
both ends:

  * every command in the table has to exist in `cli.build_parser()`, and
    every command the parser defines has to be in the table. A new command
    must be classified rather than appearing unlisted.
  * every route in the table has to exist in `web/server.py`, and every
    `/api/` route the server answers has to be in the table. A new route must
    be claimed by a capability rather than appearing unlisted.
  * a capability whose `ui` is empty must have **no** route. That is the half
    that stops this becoming a wish list: the entry cannot say "CLI only"
    while a panel quietly exists, which is exactly how an exemption list rots
    (the same argument the type ratchet makes about a stale exemption).

What this file deliberately does not do is assert that the interface *should*
cover everything. It records what is true and refuses to let it drift.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from actaira.cli import build_parser
from conftest import REPO_ROOT

SERVER = (Path(REPO_ROOT) / "src" / "actaira" / "web" / "server.py").read_text(encoding="utf-8")

# capability -> (CLI commands, UI routes). An empty route tuple means the
# capability is reachable from the terminal only, today.
CAPABILITIES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "scan":        (("scan",),        ("/api/scan", "/api/scan-sample", "/api/disassemble")),
    "bom":         (("bom",),         ("/api/bom",)),
    "agent":       (("agent",),       ("/api/agent/check", "/api/agent/bom",
                                       "/api/agent/paths", "/api/agent/diff")),
    "attest":      (("attest",),      ("/api/attest",)),
    "verify":      (("verify",),      ("/api/verify",)),
    "governance":  (("governance",),  ("/api/governance/clock", "/api/governance/assess")),
    "policy":      (("policy",),      ("/api/policy/show", "/api/policy/check")),
    "graph":       (("graph",),       ("/api/graph", "/api/graph/node", "/api/workspace")),
    "impact":      (("impact",),      ("/api/impact",)),

    # Reachable from the terminal only. Each one is a panel the interface does
    # not have yet, and the README says so rather than implying otherwise.
    #
    # `source`, `watch`, `snapshot` and `evidence` stay here on purpose, and
    # the temptation to move them is exactly what this matrix is against: the
    # graph panel reads what they wrote and shows an evidence count beside a
    # node, and none of that is a way to add a source, run a watch, or look at
    # a snapshot. A capability is reachable when the interface can *do* it,
    # not when something else displays its output.
    "bundle":      (("bundle",),      ()),
    "controls":    (("controls",),    ()),
    "discover":    (("discover",),    ()),
    "source":      (("source",),      ()),
    "watch":       (("watch",),       ()),
    "snapshot":    (("snapshot",),    ()),
    "evidence":    (("evidence",),    ()),
    "trust":       (("trust",),       ()),
    "receipt":     (("receipt",),     ()),
    "keygen":      (("keygen",),      ()),
    "schema":      (("schema",),      ()),

    # Not capabilities: the workspace root and the server itself.
    "init":        (("init",),        ()),
    "serve":       (("serve",),       ()),
}

# Routes that belong to the interface's plumbing rather than to a capability:
# a health probe and the catalogue the language switch reads.
#
# `/api/workspace` is deliberately NOT here. It looks like a probe and it is
# not one: it opens the state database and reports what is in it, which is the
# graph capability answering a question about itself. Filing a route that
# reads workspace state under "plumbing" is how a capability surface stops
# being counted.
INFRASTRUCTURE_ROUTES = ("/api/health", "/api/samples")


def cli_commands() -> set[str]:
    parser = build_parser()
    commands: set[str] = set()
    for action in parser._subparsers._group_actions:  # noqa: SLF001 - argparse has no public API
        commands.update(action.choices)
    return commands


def server_routes() -> set[str]:
    """Every `/api/` path the server names, read as text.

    Read rather than imported and introspected, because the routes live in two
    dicts and a chain of comparisons inside two methods, and a regex over the
    file is honest about being a textual check in a way that reaching into
    `do_POST.__code__` would not be.
    """
    found = set(re.findall(r'"(/api/[a-z0-9/-]*)"', SERVER))
    # `/api/i18n/` is matched by prefix rather than compared, so it arrives
    # here as the prefix itself.
    return {route for route in found if not route.startswith("/api/i18n")}


def declared_routes() -> set[str]:
    return {route for _, routes in CAPABILITIES.values() for route in routes}


# ---------------------------------------------------------------------------
# The CLI half
# ---------------------------------------------------------------------------


def test_every_command_in_the_matrix_exists():
    declared = {command for commands, _ in CAPABILITIES.values() for command in commands}
    missing = sorted(declared - cli_commands())
    assert not missing, f"the matrix names commands the CLI does not define: {', '.join(missing)}"


def test_every_command_the_cli_defines_is_classified():
    declared = {command for commands, _ in CAPABILITIES.values() for command in commands}
    unlisted = sorted(cli_commands() - declared)
    assert not unlisted, (
        "these commands are in the CLI and in no row of the matrix, so nothing "
        f"records whether the interface reaches them: {', '.join(unlisted)}"
    )


# ---------------------------------------------------------------------------
# The interface half, in both directions
# ---------------------------------------------------------------------------


def test_every_route_in_the_matrix_is_one_the_server_answers():
    missing = sorted(declared_routes() - server_routes())
    assert not missing, (
        "the matrix claims the interface reaches these and the server has no "
        f"route for them, so a panel the README promises is broken: {', '.join(missing)}"
    )


def test_every_route_the_server_answers_is_claimed_by_a_capability():
    unlisted = sorted(server_routes() - declared_routes() - set(INFRASTRUCTURE_ROUTES))
    assert not unlisted, (
        "the server answers these and no capability claims them, so the matrix "
        f"under-reports what the interface can do: {', '.join(unlisted)}"
    )


@pytest.mark.parametrize(
    "capability",
    sorted(name for name, (_, routes) in CAPABILITIES.items() if not routes),
)
def test_a_capability_recorded_as_cli_only_really_has_no_panel(capability):
    """The half that stops this becoming a wish list.

    A row saying "CLI only" while a route quietly exists is a stale exemption,
    and a stale exemption is how a list like this stops being read.
    """
    commands, _ = CAPABILITIES[capability]
    prefixes = tuple(f"/api/{command}" for command in commands)
    surprises = sorted(route for route in server_routes() if route.startswith(prefixes))
    assert not surprises, (
        f"{capability} is recorded as reachable from the terminal only, and the "
        f"server answers {', '.join(surprises)}. Move it to the covered half."
    )


def test_the_readmes_do_not_claim_a_panel_that_does_not_exist():
    """Both READMEs name the sections the interface covers. This is the check
    that the sentence stays true as panels are added."""
    covered = sorted(name for name, (_, routes) in CAPABILITIES.items() if routes)
    # The four the interface had before agents, plus agents, policy, and the
    # graph pair. Named here so that adding a panel fails this test until the
    # prose is updated with it.
    assert covered == ["agent", "attest", "bom", "governance", "graph", "impact",
                       "policy", "scan", "verify"], (
        "the set of capabilities with a panel has changed; update the sentence "
        "in both READMEs that lists what the interface covers, then update this "
        f"expectation: {covered}"
    )
    for name in ("README.md", "README.es.md"):
        text = (Path(REPO_ROOT) / name).read_text(encoding="utf-8").lower()
        assert "agent" in text, f"{name} does not mention the agent panel"
        assert "graph" in text or "grafo" in text, f"{name} does not mention the graph panel"


def test_the_readmes_do_not_promise_a_panel_for_a_capability_that_has_none():
    """The half that keeps the sentence from drifting the other way.

    A capability recorded as terminal-only must not be named as something the
    interface covers. `source`, `watch`, `snapshot` and `evidence` are the
    four at risk: the graph panel reads their output, which makes it easy to
    write a sentence that implies it reaches them.
    """
    claims = {
        "source": ("add a source", "añadir una fuente"),
        "watch": ("run a watch", "ejecutar un watch"),
        "snapshot": ("browse snapshots", "explorar instantáneas"),
        "evidence": ("the evidence explorer", "el explorador de evidencia"),
    }
    for name in ("README.md", "README.es.md"):
        text = (Path(REPO_ROOT) / name).read_text(encoding="utf-8").lower()
        for capability, phrases in claims.items():
            assert not CAPABILITIES[capability][1], (
                f"{capability} gained a route; this test's premise needs revisiting"
            )
            for phrase in phrases:
                assert phrase not in text, (
                    f"{name} implies the interface can {phrase}, and "
                    f"{capability} is recorded as reachable from the terminal only"
                )
