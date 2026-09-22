"""Gate point 1 of phase S3.1: the two views of what the resolver decides on,
and the guards that keep either of them from answering with silence.

WHY TWO VIEWS AND WHY THEY ARE COMPARED OVER PAIRS. The static reader was
right about ten keys, then twenty, then sixteen, then fifteen, and never once
said it was missing anything. A guard that fails when the count DROPS protects
against a regression, not against a blindness, and would have passed at ten.
So a second view is derived by RUNNING the resolver over the corpus, and the
two are compared over PAIRS OF KEY AND LINE.

THE PAIR IS THE UNIT, NOT THE KEY, and that was learned twice. `_sandbox` binds
`entry` for `excludedCommands` and again for `allowedDomains`; a reader with
one mark per name lost the first and credited its decision to the second. The
total looked right, thirteen keys, and both views agreed. A CORRECT TOTAL AND
TWO AGREEING VIEWS CAN COEXIST WITH A LOST KEY AND A PHANTOM SITE. Comparing
sets of key names cannot see that; comparing pairs sees it immediately.

AND THE SENTENCE THAT GOVERNS EVERY COMPARISON HERE, said once because it is
one thing: TWO VIEWS AGREEING PROVE NOTHING WHERE THEIR SCOPES DO NOT COINCIDE,
NOR WHERE BOTH ARE BLIND. Both halves have already happened. Both blind: the
frozenset membership in `_widens`, which the instrument cannot see and the
static reader missed, so the two agreed about a key that was gone. Scopes not
coinciding: the runtime view watches the RESOLVER, and a decision taken inside
a READER - `command_strings`, the codex `notify` read - is outside it entirely,
so agreement there is agreement between one view and an absence.
"""
from __future__ import annotations

import pathlib

import pytest

from conftest import REPO_ROOT
from seamark.surface import resolve
from support.value_runtime import Recorder, leaf, watched
from support.value_sites import (
    SYNTHESISED_AT,
    inventory,
    ours,
    rebound_names,
)

CORPUS = pathlib.Path(REPO_ROOT) / "tests" / "fixtures" / "surface" / "corpus"

# Pairs the static view claims and the runtime view cannot observe, each with
# the cause MEASURED rather than guessed, and no residual bucket. A pair that
# has no cause here fails the test rather than falling into a category called
# "other": the whole point of this file is that silence is not an answer.
DECLARED_UNOBSERVED = {
    # The corpus runs without `--machine`, so no user-scope file is read.
    ("allowAutomaticTasks", "vscode.py:331"): "user scope, corpus has no --machine",
    ("allowAutomaticTasks", "vscode.py:338"): "user scope, corpus has no --machine",
    ("trust_level", "codex.py:194"): "user scope, corpus has no --machine",
    # `x in frozenset` resolves by hashing; `__eq__` is never called.
    ("allowedDomains", "resolve.py:312"): "membership over a frozenset, resolved by hash",
    ("excludedCommands", "resolve.py:312"): "membership over a frozenset, resolved by hash",
    # `entry.get("url") or entry.get("httpUrl")` picks a transport and compares
    # nothing.
    ("type", "resolve.py:370"): "truthiness, no comparison",
    ("type", "emit.py:127"): "truthiness, no comparison",
    ("url", "emit.py:127"): "truthiness, no comparison",
    ("httpUrl", "emit.py:127"): "truthiness, no comparison",
    # `urlparse(...).hostname` hands back a plain str and the watch is lost.
    ("host", "emit.py:90"): "the value leaves the instrumented type",
    # Decided while READING, before `watched()` is applied. One view, not two.
    ("type", "claude_code.py:186"): "decided in a reader, outside the runtime view",
    ("notify", "codex.py:230"): "decided in a reader, outside the runtime view",
}


def _pairs(sites: dict[str, set[tuple[str, int]]]) -> set[tuple[str, str]]:
    """Both views reduced the same way, or the comparison is between spellings."""
    return {
        (leaf(key), f"{module}:{line}")
        for key, where in sites.items()
        for module, line in where
    }


@pytest.fixture(scope="module")
def views():
    recorder = Recorder()
    roots = [
        path for path in sorted(CORPUS.iterdir()) if (path / "expected.json").is_file()
    ]
    for root in roots:
        for _vendor, reader, resolver in resolve.vendor_registry():
            resolver(watched(reader.read(root), recorder))
    return _pairs(inventory()), _pairs(recorder.sites()), recorder, len(roots)


def test_the_runtime_view_saw_the_corpus(views):
    """Work rule 11. An empty instrument reads exactly like a clean resolver.

    A recorder built on `Mapping` instead of `dict` fails every
    `isinstance(x, dict)` in the resolver, sees nothing, and every comparison
    below then passes over two empty sets.
    """
    _static, runtime, recorder, roots = views
    assert roots >= 50, f"the corpus shrank to {roots} fixtures"
    assert len(recorder.consulted) >= 20, sorted(recorder.consulted)
    assert len(runtime) >= 10, sorted(runtime)


def test_the_static_view_is_blind_to_nothing_the_corpus_exercises(views):
    """runtime MINUS static. The defect this whole arrangement hunts.

    A pair here is a decision the resolver demonstrably takes and the reader
    cannot see. It is never declared away: the reader is taught the shape.
    Five shapes arrived this way, the last of them `{...}[kind]` at
    resolve.py:938, which picks the capability's NAME.
    """
    static, runtime, _recorder, _roots = views
    blind = sorted(runtime - static)
    assert not blind, (
        "the runtime view observed decisions the static reader does not know: "
        f"{blind}. Teach the reader the shape; do not declare it."
    )


def test_every_unobserved_pair_has_a_measured_cause(views):
    """static MINUS runtime, one cause each and no residual bucket."""
    static, runtime, _recorder, _roots = views
    unobserved = static - runtime
    missing = sorted(pair for pair in unobserved if pair not in DECLARED_UNOBSERVED)
    assert not missing, (
        f"these pairs have no cause: {missing}. Measure why the runtime view "
        "does not see them and write it down. 'Other' is not a cause."
    )
    stale = sorted(pair for pair in DECLARED_UNOBSERVED if pair not in unobserved)
    assert not stale, (
        f"these declarations describe pairs that no longer exist: {stale}. A "
        "declaration that outlives what it declared is a comment."
    )


def test_the_comparison_would_notice_a_misattributed_site(views):
    """The twin that would have caught the defect, work rule 9.

    NOT the same twin as taking a set away: that one shows the guard sees an
    ABSENCE. This plants what actually happened - one key's decision credited
    to another - and demands BOTH halves of the claim this file rests on: a
    comparison over key NAMES is blind to it, and a comparison over PAIRS is
    not.

    It plants over a site the runtime view really observes. That is deliberate.
    The misattribution that started all of this sat on `_widens`, where BOTH
    views are blind, and no comparison between them could have caught it -
    which is the second half of the sentence at the top of this file and the
    reason the declaration of causes exists as well.
    """
    static, runtime, _recorder, _roots = views
    real = ("allowedDomains", "resolve.py:352")
    assert real in static and real in runtime, (
        "this twin plants over a site both views see, and that site is gone"
    )

    planted = {pair for pair in static if pair != real}
    planted.add(("excludedCommands", "resolve.py:352"))

    assert {key for key, _ in planted} == {key for key, _ in static}, (
        "the plant has to leave the set of key NAMES untouched, or it proves "
        "nothing about why pairs are the unit"
    )
    assert not (runtime - static), "the real tree is not clean; fix that first"
    assert runtime - planted == {real}, (
        "the pair comparison did not notice a decision credited to another key"
    )


def test_the_synthesised_sites_are_where_the_declaration_says(views):
    """Gate point 9's shape: the declaration is of SITES and derives the names.

    `ours()` raises if a declared line no longer builds a document, so this
    asserts the derivation produced something and that it is anchored.
    """
    owned = ours()
    assert owned, "no key is declared ours; the sites stopped resolving"
    declared = {f"{module}:{line}" for module, line, _why in SYNTHESISED_AT}
    # A subset, not equality: two sites can synthesise the same key names -
    # `_managed_sandbox` returns the same two keys from both of its returns -
    # and the later one wins the mapping. `ours()` raises for a site that
    # stopped building a document, which is the half that matters.
    assert set(owned.values()) <= declared, sorted(set(owned.values()) - declared)
    assert "imports" in owned, (
        "`imports` is synthesised by instructions.py because a CLAUDE.md has no "
        "keys; if it stopped being ours, the runtime view will report it as a "
        "vendor key"
    )


def test_a_synthesised_name_does_not_collide_with_a_vendor_key(views):
    """Belt over braces, and it is NOT what makes the exclusion safe.

    What makes it safe is the ANCHOR TO THE SITE: a vendor key called
    `imports` would arrive through different code and would not be covered.
    This guard exists to catch the day somebody weakens that anchor back into
    a list of names. ITS SCOPE IS THE CORPUS, which is a sample: a collision
    that is not in these fixtures can still be in a user's repository.
    """
    _static, _runtime, recorder, _roots = views
    owned = set(ours())
    seen = set(recorder.consulted) | {key for key, _ in _pairs(inventory())}
    collisions = sorted(owned & seen)
    assert not collisions, (
        f"a name this tool synthesises is also read as a vendor key: {collisions}. "
        "Do not fix this by renaming the exclusion: anchor it to the site."
    )


def test_the_declared_limits_are_measured(views):
    """The two limits a mark-per-binding leaves, counted rather than assumed."""
    rebound = rebound_names()
    assert rebound, (
        "no name is bound twice in any resolver function, which would mean the "
        "mark-per-binding-site correction is unexercised and this suite cannot "
        "tell it from the defect it replaced"
    )
    assert any("_sandbox" in where for _module, where, _line in rebound), (
        "`_sandbox` no longer binds `entry` twice; that is the site the whole "
        "correction came from"
    )
