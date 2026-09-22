"""The first negative, asserted forward over every document this tree emits.

These three properties were `xfail(strict=True)` markers in `tests/test_receipt.py`
until phase A. Each named a real defect, by file and line, in code that has now
been removed:

  * `format_confidence` reached the signed bytes from `ArtifactReport`
    (`src/actaira/model.py`) through `receipt.build` (`src/actaira/receipt.py`),
    putting the sixth word of the first negative inside a signed document.
  * `dsse._aggregate_rules` folded the severities one rule fired at across
    artifacts and kept the worst, using `Severity.rank`.
  * `ArtifactReport.max_severity` was a maximum over the severities of every
    finding, emitted into the signed DSSE predicate as `max_severity`.

`receipt.py`, `ArtifactReport` and the writing half of `dsse.py` all left in
phase A, so all three xfails were about to turn red for PASSING, which is what
`strict=True` is for and is the honest outcome: the xfail was met, not relaxed.

They are not deleted with their code, because the first negative is not a
property of `receipt.py` or of `dsse.py`. It is a property of the PRODUCT.
`check`, `diff`, the seal and the collector are each a fresh opportunity to
fold two authors of labels into one, or to slip a confidence into signed bytes,
and an xfail that dies with its code leaves nothing watching for that. A
property over every emitted document watches it for free, because the assertion
was already written - only its subject changed, from "the receipt" to
"everything this tree emits".

the first negative, in full, is what these enforce: no score, grade,
rating, percent, confidence or ranking in any emitted document; and a rule's
author-written `severity` is an attributed label that is never aggregated or
summed with another.

The load-bearing part of this file is `test_the_enumeration_is_not_empty` and
the guard inside each property. An enumeration of emitted documents that came
back empty would make every assertion here pass without reading a byte, which
is a test asserting a property that is not the one it protects - the failure
mode this project has now hit four times. So the list is checked before it is
walked, checked against the emitters the tree actually has, and every assertion
is additionally run against a document that violates it.
"""
from __future__ import annotations

import pytest

from support.reports import emitted_documents, every_string

# The first negative's word list. `confidence` is the sixth and was the one the
# old list omitted, which is how `format_confidence` reached signed bytes.
FORBIDDEN_WORDS = ("score", "grade", "rating", "percent", "confidence", "ranking")

# Keys that would be a fold Actaira computed rather than a label an author
# wrote. `max_severity` is the one that actually shipped.
FORBIDDEN_KEYS = (
    "max_severity", "worst_severity", "highest_severity", "severity_rank",
    "aggregate_severity", "overall_severity", "severity_score", "total_severity",
)

# A severity is an attributed label or it is nothing. These are the sibling keys
# that carry the attribution: which rule fired, and who wrote the rule.
NAMES_A_RULE = ("rule_id", "rule", "id")
NAMES_AN_AUTHOR = ("author", "pack", "package", "source")


def siblings_of(document: dict, path: str) -> set[str]:
    """The keys sitting beside `path`, one level down from its parent."""
    owner = path.rsplit(".", 1)[0]
    return {
        key.rsplit(".", 1)[-1]
        for key, _ in every_string(document)
        if key.startswith(owner + ".") and key.count(".") == owner.count(".") + 1
    }


def unattributed_severities(name: str, document: dict) -> list[str]:
    """Every `severity` in this document that names no rule or no author."""
    found = []
    for path, text in every_string(document):
        if not path.endswith(".severity"):
            continue
        carried = siblings_of(document, path)
        if not set(NAMES_A_RULE) & carried:
            found.append(f"{name}{path} ({text}) names no rule")
        if not set(NAMES_AN_AUTHOR) & carried:
            found.append(f"{name}{path} ({text}) names no author")
    return found


@pytest.fixture
def emitted(tmp_path):
    return emitted_documents(tmp_path)


# ---------------------------------------------------------------------------
# The guards, before anything is asserted over the enumeration
# ---------------------------------------------------------------------------


def test_the_enumeration_is_not_empty(emitted):
    """The guard every property below rests on.

    If `emitted_documents` returned nothing, each test in this file would walk
    an empty list and pass having asserted nothing about anything.
    """
    assert emitted, "no emitted document was collected; every property here is vacuous"
    for name, document in emitted:
        assert isinstance(document, dict) and document, f"{name} emitted an empty document"
        assert every_string(document), f"{name} has no keys or strings to walk"


def test_the_enumeration_names_every_emitter_this_tree_has(emitted):
    """A document written by a command nobody added here is a document nothing
    in this file ever checks. Seven commands; four of them emit."""
    from actaira.cli import build_parser

    parser = build_parser()
    commands = set(parser._subparsers._group_actions[0].choices)

    assert commands == {"check", "diff", "seal", "scan", "watch", "verify", "keygen"}, (
        "a command was added or removed; decide whether it emits a document and "
        f"whether `emitted_documents` has to name it. Now: {sorted(commands)}"
    )
    assert {name.split()[0] for name, _ in emitted} == {"check", "diff", "seal", "scan", "watch"}


def test_these_properties_would_catch_the_defects_they_replaced():
    """The guard on the guards: each assertion is run against a document that
    violates it, so none of them can be passing because it never looks.

    Without this, all three properties below pass trivially on a tree whose
    emitted documents happen to carry no severities at all - which was exactly
    this tree's situation until phase S1 landed the rule packs, and `surface/v1`
    is the first emitted document that carries one.
    """
    planted = {
        "schema_version": "trace/v3",
        "events": [{"format_confidence": "magic", "max_severity": "high"}],
        "rules_fired": [{"severity": "critical", "count": 2}],
    }

    assert [t for _, t in every_string(planted) if "confidence" in t.lower()], (
        "the word walk would not have caught format_confidence"
    )
    assert [t for _, t in every_string(planted) if t in FORBIDDEN_KEYS] == ["max_severity"], (
        "the key walk would not have caught max_severity"
    )
    assert unattributed_severities("planted", planted), (
        "the attribution walk would not have caught an unattributed severity"
    )


# ---------------------------------------------------------------------------
# The three properties
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("word", FORBIDDEN_WORDS)
def test_no_emitted_document_carries_a_number_shaped_word(emitted, word):
    """The first negative's word list, over keys and string values alike.

    Was: `test_the_word_confidence_does_not_appear_in_a_receipt`, xfail because
    `format_confidence` travelled from `ArtifactReport` into `receipt.build`.
    """
    assert emitted, "nothing walked"
    offenders = [
        f"{name}{path}: {text!r}"
        for name, document in emitted
        for path, text in every_string(document)
        if word in text.lower()
    ]

    assert offenders == [], (
        f"an emitted document carries {word!r}, which the first negative "
        "forbids in any published document: " + "; ".join(offenders)
    )


def test_no_emitted_document_carries_a_maximum_over_severities(emitted):
    """An aggregate Actaira computed, not a label an author wrote.

    Was: `test_no_emitted_document_carries_a_maximum_over_severities`, xfail
    because `ArtifactReport.max_severity` was emitted into the DSSE predicate.
    """
    assert emitted, "nothing walked"
    offenders = [
        f"{name}{path}"
        for name, document in emitted
        for path, text in every_string(document)
        if text in FORBIDDEN_KEYS
    ]

    assert offenders == [], (
        "an emitted document carries a fold over severities: " + ", ".join(offenders)
    )


def test_no_emitted_document_folds_two_authors_labels_into_one(emitted):
    """A rule's `severity` travels attributed, or it does not travel.

    Was: the `dsse._aggregate_rules` xfail. That function kept the worst
    severity a rule fired at across artifacts, using `Severity.rank`. The
    general shape is a severity published without the rule and the author it
    belongs to, because a severity standing on its own is one somebody computed.
    """
    assert emitted, "nothing walked"
    offenders = [
        problem
        for name, document in emitted
        for problem in unattributed_severities(name, document)
    ]

    assert offenders == [], (
        "a severity is published without the rule and author it is attributed to, "
        "which is what an aggregate looks like from outside: " + "; ".join(offenders)
    )
