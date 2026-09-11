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
    "report": "report/v1",
    "policy": "policy/v1",
    "policy-decision": "policy-decision/v1",
    "assurance-receipt": "assurance-receipt/v2",
    "agent-bom": "agent-bom/v2",
    "model-bundle": "model-bundle/v2",
    "source-snapshot": "source-snapshot/v1",
    "evidence-record": "evidence-record/v1",
    "asset-graph": "asset-graph/v1",
    "trust-policy": "trust-policy/v1",
    "state-export": "state-export/v1",
    "attack-paths": "attack-paths/v1",
    "subject-manifest": "subject-manifest/v1",
}

# The versions this release still reads, per family, oldest first. A major is
# a change of meaning, and a consumer that was written against the old meaning
# is not wrong - it is old. `docs/COMPATIBILITY.md` promises that a published
# contract stays published, so the file stays on disk, `actaira schema` keeps
# listing it, and the reader that accepts it keeps working.
#
# Emitting is the asymmetric half: this tool writes `VERSIONS` and reads
# everything in here. Nothing in the codebase may emit a superseded version,
# because a producer that can still write the old shape is a producer that
# will, in some branch nobody tested.
SUPERSEDED = {
    "assurance-receipt": ("assurance-receipt/v1",),
    "agent-bom": ("agent-bom/v1",),
    "model-bundle": ("model-bundle/v1",),
}


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
