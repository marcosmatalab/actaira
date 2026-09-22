"""Nothing this tree emits may go unnamed.

The invariant: every capability the resolvers can produce is named by at least
one rule, or is in `resolve.EMITTED_WITHOUT_A_RULE` with a written reason.

This is deliberately NOT a rule about how many rules there are. The rule count
is a budget - fifteen, thirty-one or ninety would all serve - and no test here
asserts one. What must not happen is that `check` prints a capability no rule
can ever fire on: that is a line a reader cannot act on and cannot appeal, and a
report made of those is noise wearing the shape of rigour. It is the same
argument `tests/test_reachability.py` makes about a module no command reaches,
applied to the other end of the pipe.

The set of capabilities is recovered from the SOURCE of every module under
`surface/`, by walking every `emit` call, rather than from running the resolvers
over the fixtures. Fixtures only show what some repository happened to configure; a
capability nothing in the corpus triggers is exactly the one that would slip
through, and it is the one this file exists to catch. `hook.mcp_tool` was
precisely that: emitted since phase S1, named by nothing, and invisible to every
test until this one was written.

It reads the whole package and not one file. It read `resolve.py` alone while
all seven resolvers lived there, and the day six of them moved beside their
readers that walk would have gone on passing over the one that stayed: a
shrinking set satisfies "every capability is named" without anybody noticing
what left it. `test_every_emitting_function_is_accounted_for` is what makes that
fail instead, because a resolver that emits and is not in `VENDOR_OF_FUNCTION`
is refused by name.

That static walk imposes one constraint on the resolvers, and it is a constraint
worth having: a capability NAME must be a literal in the source. It used to be
built as `f"hook.{kind}"` from the `type` string in the settings file, so a
repository could put `"type": "made-up"` in a settings file and name a
capability in Seamark's own document - unnameable by any rule, by construction.
That is D-290, and it was found by trying to write this test.
"""
from __future__ import annotations

import ast

import pytest

from conftest import SRC_DIR
from seamark.surface import resolve, rules

SURFACE = SRC_DIR / "seamark" / "surface"

# Read, but not resolvers: `emit` is the machinery every resolver calls and
# names no capability of its own, and the readers and parsers below it emit
# nothing at all. Naming them here rather than filtering on whether a file
# happens to contain an `emit(` call, because that filter passes silently the
# day a resolver stops emitting.
NOT_A_RESOLVER = ("emit.py", "merge.py")

# Which vendor each emitting function speaks for. Claude Code's resolver is
# split into six helpers that `resolve()` calls, so the mapping is by function
# rather than by module. `test_every_emitting_function_is_accounted_for` fails
# on a function that emits and is not here, so a new vendor cannot be added and
# silently left out of the invariant.
VENDOR_OF_FUNCTION = {
    "_hooks": "claude-code",
    "_permissions": "claude-code",
    "_helpers": "claude-code",
    "_sandbox": "claude-code",
    "_approvals": "claude-code",
    "_mcp": "claude-code",
    "vscode_surface": "vscode",
    "devcontainer_surface": "devcontainer",
    "codex_surface": "codex",
    "cursor_surface": "cursor",
    "gemini_surface": "gemini-cli",
    "instructions_surface": "instructions",
}


def _names_in(node: ast.AST) -> set[str]:
    """Every capability name one `emit` call can pass, or a marker if computed.

    A plain constant, or a subscripted dict literal - the shape `_hooks` uses to
    map a documented handler type to its capability name. Anything else comes
    back as the sentinel below, and the test on it fails: a name this walk
    cannot read is a name that escapes the invariant.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Dict):
        found = set()
        for value in node.value.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                found.add(value.value)
            else:
                found.add(COMPUTED)
        return found
    return {COMPUTED}


COMPUTED = "<computed at runtime>"


def emitted() -> dict[str, set[str]]:
    """function name -> the capability names its `emit` calls can produce."""
    found: dict[str, set[str]] = {}
    read = 0
    for path in sorted(SURFACE.glob("*.py")):
        if path.name in NOT_A_RESOLVER:
            continue
        read += 1
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for call in ast.walk(node):
                if not isinstance(call, ast.Call):
                    continue
                if not (isinstance(call.func, ast.Name) and call.func.id == "emit"):
                    continue
                for keyword in call.keywords:
                    if keyword.arg == "name":
                        found.setdefault(node.name, set()).update(_names_in(keyword.value))
    assert read >= 8, f"only {read} module(s) were read; the walk is not walking"
    return found


EMITTED = emitted()


def pairs() -> set[tuple[str, str]]:
    return {
        (VENDOR_OF_FUNCTION[function], name)
        for function, names in EMITTED.items()
        if function in VENDOR_OF_FUNCTION
        for name in names
    }


def named_by_rules() -> set[tuple[str, str]]:
    return {
        (rule.vendor, capability)
        for rule in rules.load()
        for capability in rule.capability
    }


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------


def test_every_capability_is_named_by_a_rule_or_excused_in_writing():
    """The whole point of the file.

    A capability with no rule and no written reason fails here, and the message
    says both ways out: write the rule, or write down why naming it would be
    wrong. "Not got to yet" is neither - that is a backlog line with a phase.
    """
    unnamed = sorted(pairs() - named_by_rules() - set(resolve.EMITTED_WITHOUT_A_RULE))

    assert unnamed == [], (
        f"these capabilities are emitted and nothing names them: {unnamed}. "
        "Either add a rule naming each - with the two tests `docs/PRINCIPLES.md` requires, on a "
        "real configuration - or add it to resolve.EMITTED_WITHOUT_A_RULE with a "
        "reason saying why naming it would be WRONG. A capability nobody names is a "
        "line in a report that a reader can neither act on nor appeal."
    )


def test_the_invariant_would_notice_a_capability_nobody_named():
    """The guard on the guard, and the reason this file is worth reading.

    A capability is planted that no rule names and no entry excuses, and the
    check above has to reject it. Without this, the assertion could be passing
    because `pairs()` returns nothing at all - which is the failure mode every
    static analysis over a source file eventually has.
    """
    planted = pairs() | {("claude-code", "hook.invented_by_this_test")}

    unnamed = planted - named_by_rules() - set(resolve.EMITTED_WITHOUT_A_RULE)

    assert unnamed == {("claude-code", "hook.invented_by_this_test")}


def test_the_invariant_would_notice_an_excuse_being_withdrawn():
    """And the other direction: the excuse list is what is doing the work.

    If `EMITTED_WITHOUT_A_RULE` were empty, or its keys were spelled so that they
    matched nothing, the first test would fail. So the excused set must be
    non-empty AND must be exactly what stands between the tree and a failure.
    """
    assert resolve.EMITTED_WITHOUT_A_RULE, "nothing is excused; the list asserts nothing"

    without = sorted(pairs() - named_by_rules())

    assert without == sorted(resolve.EMITTED_WITHOUT_A_RULE), (
        "the excuse list and the unnamed set have come apart. Every entry must "
        "correspond to a capability that is actually emitted and actually unnamed"
    )


# ---------------------------------------------------------------------------
# The three things that keep the list from becoming a rubber stamp
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pair", sorted(resolve.EMITTED_WITHOUT_A_RULE), ids=lambda pair: f"{pair[0]}:{pair[1]}"
)
def test_every_excuse_is_argued_rather_than_asserted(pair):
    """A reason is prose, so writing one means making the argument.

    The length floor is not a style rule. Every entry has to say why NAMING the
    capability would be wrong, and no sentence that does that fits in a dozen
    words. `docs/RULES.md` publishes the rules; this list is the other half of
    the same promise and is held to the same standard.
    """
    reason = resolve.EMITTED_WITHOUT_A_RULE[pair]

    assert len(reason) >= 120, f"{pair} is excused in {len(reason)} characters"
    assert not reason.lower().startswith("no rule yet"), (
        f"{pair}: 'no rule yet' is a backlog line with a phase, not a reason"
    )


def test_no_excuse_outlives_the_capability_it_excuses():
    """A stale entry is a defect, not a leftover.

    An entry naming a capability nothing emits any more would keep excusing a
    rule that nobody needs, and the next person to read the list would take it
    as a live decision. So it fails rather than being ignored.
    """
    stale = sorted(set(resolve.EMITTED_WITHOUT_A_RULE) - pairs())

    assert stale == [], (
        f"{stale} are excused and nothing emits them. Delete the entries: a list that "
        "outlives what it excuses stops describing this tree"
    )


def test_every_emitting_function_is_accounted_for():
    """A vendor cannot be added and left out of the invariant by omission.

    The mapping from function to vendor is written here, so the way to escape
    this file is to add an emitting function and not map it. That fails.
    """
    unmapped = sorted(set(EMITTED) - set(VENDOR_OF_FUNCTION))

    assert unmapped == [], (
        f"{unmapped} emit capabilities and name no vendor in VENDOR_OF_FUNCTION, so "
        "whatever they emit escapes the coverage invariant"
    )


def test_no_capability_name_is_built_at_runtime():
    """D-290, kept shut.

    A capability name assembled from a value in the file being read is a name
    the audited repository chose, in Seamark's document, and no rule can name it
    because its spelling is not known until somebody's settings file supplies
    it. Names are literals, and a handler type this release does not know
    becomes a gap instead.
    """
    computed = sorted(
        function for function, names in EMITTED.items() if COMPUTED in names
    )

    assert computed == [], (
        f"{computed} build a capability name at runtime. A name the input can choose "
        "is one no rule can name and one this file cannot see (D-290)"
    )


def test_an_unknown_handler_type_is_a_gap_and_not_a_capability(tmp_path):
    """The behaviour D-290 put in place of the f-string, over a real read."""
    import json

    from seamark.surface import claude_code

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {"matcher": "*", "hooks": [{"type": "invented", "command": "x"}]}
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    surface = resolve.resolve(claude_code.read(tmp_path))

    assert surface.capabilities == (), "a handler type nobody documents named a capability"
    assert len(surface.unresolved) == 1
    assert "'invented'" in surface.unresolved[0].cause
    assert "command, http, mcp_tool" in surface.unresolved[0].cause


# ---------------------------------------------------------------------------
# The other direction: a rule that names nothing
# ---------------------------------------------------------------------------


def test_every_rule_names_a_capability_something_emits():
    """A rule whose capability nothing produces can never fire.

    It would sit in `docs/RULES.md` looking like coverage and never answer. That
    is the mirror image of the invariant above and costs nothing to hold.
    """
    emitted_pairs = pairs()
    orphans = sorted(
        (rule.id, rule.vendor, capability)
        for rule in rules.load()
        for capability in rule.capability
        if (rule.vendor, capability) not in emitted_pairs
    )

    assert orphans == [], (
        f"{orphans} name a vendor and capability no resolver emits, so they can never "
        "fire and publish coverage that does not exist"
    )
