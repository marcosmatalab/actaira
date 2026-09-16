"""The published contracts, and what promising them costs.

Design note D-150. Until these files existed the only stable thing this tool
emitted was `rule_id`. Its own threat model said so, which was honest and also
a ceiling: nothing could be built on the output, because any field could move
in any release. A GitHub Action, an SDK, a dashboard, another team's script -
each of those is a promise, and a promise you have not written down is one you
break by accident.

So the documents are versioned as `<name>/vN` and the version is in the
document, not in the URL alone. A consumer reads `schema_version` first and
refuses what it does not understand, which is what `receipt.verify` does: a
future receipt may mean something different by a field this reader thinks it
knows, and a partial check reported as a pass is worse than no check.

What a version promises, stated precisely so it can be kept:

* A field that is required in vN stays required in every vN.
* A field's type and enum values do not narrow within vN. Adding an enum
  member narrows nothing for a producer and everything for a consumer that
  switches exhaustively, so it is a minor-version note in CHANGELOG rather
  than a silent change.
* New optional fields may be added within vN. `additionalProperties` is true
  in every schema here for exactly that reason.
* Removing a field, making an optional field required, or changing what a
  field means is vN+1. There is no other way to do it, including "nobody was
  using that one".

`tests/test_schemas.py` enforces the first of those against a frozen list, so
dropping a required field fails the build rather than a customer's parser.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent

# The schema each module's documents are written against. The constant in the
# module and the `const` in the schema must agree, and a test asserts it: two
# places recording one version number is how a document ends up declaring a
# version whose shape it does not have.
VERSIONS = {
    "coverage": "coverage/v1",
    "policy": "policy/v1",
    "policy-decision": "policy-decision/v1",
    "assurance-receipt": "assurance-receipt/v2",
    "evidence-record": "evidence-record/v1",
    "trace": "trace/v3",
}

# The versions this release still reads, per family, oldest first. Emitting is
# the asymmetric half: this tool writes `VERSIONS` and reads everything here.
#
# The scanner's contracts are not here, and that is a break rather than a
# tidy-up: report, model-bundle, agent-bom, asset-graph, attack-paths,
# source-snapshot, subject-manifest, trust-policy, state-export and
# assurance-receipt/v1 describe documents nothing in this tree can produce any
# more. They stay readable at tag v2.3.0 and on archive/model-scanner.
# Rejected: shipping the files with no emitter, which publishes a contract the
# tool cannot honour and reads to a consumer as still supported.
#
# `trace/v1` is the one entry, and the first this pivot has had. MCP revision 2026-07-28
# removed the session every correlation in v1 rested on, so the facts that used
# to be established once per session are per event now and seven gap reasons
# came with them - and widening a closed enum narrows nothing for a producer
# and everything for a consumer that switches exhaustively. That is the rule in
# the module docstring above, and it says vN+1. `trace/v1` stays on disk, stays
# frozen in `tests/test_schemas.py`, and `trace.model.READS` still parses it.
# `trace/v2` joined it one commit later, and that is the rule working rather
# than the rule failing. Six fields stopped carrying a third-party value and
# started carrying a salted reference to it (D-268), which is a change to what
# a field MEANS, and the paragraph above says there is no other way to do that
# "including 'nobody was using that one'". v2 had been published for twenty
# minutes and had no consumer. The exemption was still not taken, because the
# first time a rule is bent is the last time it is a rule.
SUPERSEDED: dict[str, tuple[str, ...]] = {"trace": ("trace/v1", "trace/v2")}


def stem(version: str) -> str:
    """`model-bundle/v2` -> `model-bundle-v2`, the name of the file on disk."""
    return version.replace("/", "-")


def accepted(family: str) -> tuple[str, ...]:
    """Every version of one family this release can read, oldest first."""
    return (*SUPERSEDED.get(family, ()), VERSIONS[family])


def names() -> list[str]:
    return sorted(path.stem for path in HERE.glob("*.json"))


@lru_cache(maxsize=16)
def load(name: str) -> dict[str, Any]:
    """Load one schema by file stem, for example `report-v1`."""
    path = HERE / f"{name}.json"
    if not path.is_file():
        raise KeyError(f"no schema named {name!r}; known: {', '.join(names())}")
    return json.loads(path.read_text(encoding="utf-8"))


def registry() -> dict[str, dict[str, Any]]:
    """Every schema by its `$id`, for a resolver that has to follow `$ref`.

    The schemas reference each other - a report embeds a coverage matrix, a
    receipt embeds a policy decision - and a validator handed one document
    with no way to resolve the others will either fetch over the network or
    fail. Neither is acceptable in a tool that promises to work offline, so
    callers get the whole set and resolve locally.
    """
    return {document["$id"]: document for document in (load(name) for name in names())}
