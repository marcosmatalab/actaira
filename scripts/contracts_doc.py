#!/usr/bin/env python3
"""Write `docs/CONTRACTS.md` from the schemas the package actually ships.

Design note D-232. §5 of the closing plan asks for one index of the published
contracts, marked current or superseded. An index typed by hand is a fourth
place a contract can be recorded, after the registry, the file on disk and the
module that emits it, and it is the one nothing would notice going stale: a
schema added in 2.3 would simply be missing from a page that still looked
complete.

So the page is generated. `VERSIONS` gives what is current, `SUPERSEDED` gives
what is still readable and never emitted again, the files on disk give the
required fields, and the prose for each family lives in the table below,
keyed by family name. A family with no prose fails this script rather than
producing a row with a blank cell: an index with a hole in it is what this
whole exercise is meant to stop.

    make contracts        regenerate docs/CONTRACTS.md
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

OUT = ROOT / "docs" / "CONTRACTS.md"
REPOSITORY = re.compile(r'^Repository\s*=\s*"([^"]+)"', re.MULTILINE)

# What each family is for, and the command that produces one. Prose, because
# no amount of reading a JSON Schema tells a reader when they would want the
# document it describes.
FAMILIES: dict[str, tuple[str, str]] = {
    "surface": (
        "What an agent CAN do in one root: every capability resolved across scopes, "
        "naming the file it came from, the documented merge rule that settled it and "
        "how far it resolved. Three lists that are never merged - what resolved, what "
        "could not, and what this release does not read.",
        "seamark check",
    ),
    "surface-diff": (
        "Which capability appears, disappears, widens, narrows or changes between two "
        "surfaces, each entry carrying both sides' digests and the rules that fired on "
        "what arrived. Five lists, plus a sixth for what could not be resolved on one "
        "side or the other, which is never folded into the five.",
        "seamark diff",
    ),
    "seal": (
        "A signed baseline of one surface, carrying no content: paths and the names "
        "somebody else chose are salted references whose salt stays with the operator, "
        "and everything a capability observed is one digest of its facts. An approval "
        "keyed on the surface digest expires by itself when the surface changes.",
        "seamark seal",
    ),
    "trace": (
        "What an agent did, in one shape whatever observed it: an ordered list of tool "
        "calls with the digest of each call's arguments and result, the capture level "
        "that produced every one, and the holes that level did not cover.",
        "seamark scan, seamark watch",
    ),
    "report": (
        "What one scan found in one artifact: the findings, the detected format, "
        "the digest, and the coverage matrix that bounds the claim.",
        "seamark scan --format json",
    ),
    "coverage": (
        "The per-surface matrix on its own, so a consumer can read the scope of a "
        "claim without parsing the claim.",
        "embedded in every report",
    ),
    "policy": (
        "A decision document: rules, their verdicts, exceptions with an owner and an "
        "expiry, and the digest the decision will cite.",
        "seamark policy show",
    ),
    "policy-decision": (
        "What a policy decided about one run, with the rule and the evidence behind "
        "every verdict, including the ones that could not be evaluated.",
        "seamark policy check --json",
    ),
    "assurance-receipt": (
        "The one document meant to leave the organisation that produced it: subjects "
        "by digest, coverage, findings, the policy decision and the supply-chain "
        "state, signed over the canonical JSON of itself minus the signature.",
        "seamark receipt issue",
    ),
    "agent-bom": (
        "An agent's bill of materials: model, tools with declared effects, MCP "
        "servers, sub-agents, and the digest that covers the system prompt too.",
        "seamark agent bom",
    ),
    "model-bundle": (
        "A model repository resolved into members, relations and gaps, with "
        "`content_identity` kept separate from `structural_digest`.",
        "seamark bundle --json",
    ),
    "attack-paths": (
        "The routes found through an agent declaration, each with what it carries, "
        "what would break it, and any control that already closes it.",
        "seamark agent paths --json",
    ),
    "source-snapshot": (
        "What a connector listed for one source at one moment: members, digests, "
        "the revision, and whether the listing was complete.",
        "seamark snapshot",
    ),
    "evidence-record": (
        "One observation, bound to the digest of what was observed, with its state "
        "and the collector that made it.",
        "seamark evidence show --json",
    ),
    "asset-graph": (
        "Assets and the declared relations between them, every edge carrying the "
        "manifest, declaration or snapshot that stated it.",
        "seamark graph export",
    ),
    "trust-policy": (
        "What this environment accepts from a signer, kept apart from what "
        "cryptography proved about the bytes.",
        "written by hand, read by seamark trust check",
    ),
    "subject-manifest": (
        "What a policy or a receipt is about when it is not a list of files: the "
        "subjects, their kinds, and the relations the document itself declares.",
        "written by hand, read by --subjects",
    ),
    "state-export": (
        "The whole store as one deterministic document, so two states can be "
        "diffed. Two runs over the same observation are byte-identical.",
        "seamark graph export, seamark snapshot",
    ),
}

HEADER = """# Contracts

Every JSON document Seamark publishes, what it is for, and whether it is
current or superseded.

**Generated by `scripts/contracts_doc.py` from the schemas the package ships.**
Editing this file by hand is pointless: `make contracts` overwrites it, and
the release gate compares it with the registry. See design note D-232.

A document declares its own version in `schema_version`, always first. A
consumer reads that field and refuses what it does not understand, rather than
guessing from the shape. What a version promises, and what is deliberately not
stable, is in [`COMPATIBILITY.md`](COMPATIBILITY.md).

```bash
seamark schema                 # list every contract on disk
seamark schema report-v1       # print one
```

"""

# The prose about the namespace. The URL in it is not typed here: it is read
# off the schemas and checked against the repository this package declares, so
# the page cannot state a namespace the documents do not use.
NAMESPACE = """## Where the identifiers point

Every contract's `$id` is under the repository's own URL:

```
{namespace}<name>.json
```

A `$id` is an identity, not an address. Nothing in this package fetches one -
`seamark` validates offline, against the schemas it ships, and the registry
resolves every reference locally - so what the identifier has to do is name one
contract for as long as that contract exists, and name it for this project and
no other. That is a question of who holds the name, not of how the name reads.

A domain named after the product reads better and is rented. The day it lapses,
or the day somebody else registers it first, these documents are published in a
namespace this project cannot speak for, and a consumer that resolves the
identifier resolves it against a stranger. That is the mistake
[`ACT-S003`](RULES.md#act-s003) refuses in somebody else's hooks - a reference
to a name another party can change under you - and a tool that raises it while
committing it would be arguing with itself. The repository URL is held by the
account that publishes the releases, and a rename does not strand it: GitHub
answers the old path with a redirect to the new one. That is not an idle
detail here - this project changes its name in the release this page ships
with, and the namespace came through it.

Rejected: a raw URL pinned to a branch or a tag. It resolves in a browser, which
is the whole of its advantage, and it changes the identifier every time the file
moves in the tree or the release advances - so one contract would carry as many
identities as it had versions, which is the opposite of what a `$id` is for.

The release gate refuses any `$id` outside this namespace, so a schema added
later cannot quietly reintroduce a rented one.

"""


def namespace_of(ids: list[str]) -> str:
    """The one namespace every `$id` shares, or a failure naming the split.

    Pure and tiny, and apart from the page it writes, because the page and the
    release gate hold one property and have to hold it from one definition
    rather than from two spellings of it.
    """
    prefixes = {identifier.rsplit("/", 1)[0] + "/" for identifier in ids}
    if len(prefixes) != 1:
        raise ValueError(
            "the schemas do not share one namespace: " + ", ".join(sorted(prefixes))
        )
    return prefixes.pop()


def main() -> int:
    from seamark import schemas

    missing = sorted(set(schemas.VERSIONS) - set(FAMILIES))
    if missing:
        print(
            "families with no prose in scripts/contracts_doc.py: " + ", ".join(missing),
            file=sys.stderr,
        )
        return 1

    try:
        namespace = namespace_of([schemas.load(name)["$id"] for name in schemas.names()])
    except (KeyError, ValueError) as problem:
        print(problem, file=sys.stderr)
        return 1
    repository = REPOSITORY.search((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    if not repository:
        print("pyproject.toml declares no Repository URL", file=sys.stderr)
        return 1
    if not namespace.startswith(repository.group(1).rstrip("/") + "/"):
        print(
            f"the contracts are published under {namespace}, which is not under "
            f"{repository.group(1)}, the repository this package declares",
            file=sys.stderr,
        )
        return 1

    lines = [HEADER, NAMESPACE.format(namespace=namespace), "## Current\n", "| Contract | What it is | Produced by |", "|---|---|---|"]
    for family in sorted(schemas.VERSIONS):
        what, produced = FAMILIES[family]
        lines.append(f"| `{schemas.VERSIONS[family]}` | {what} | `{produced}` |")

    superseded = sorted(
        (version, family)
        for family, versions in schemas.SUPERSEDED.items()
        for version in versions
    )
    lines += [
        "",
        "## Superseded",
        "",
        "Still on disk, still readable, never emitted again. A consumer written "
        "against one of these is old rather than wrong, and the release gate fails "
        "if a producer in this package can still write one.",
        "",
        "| Contract | Replaced by |",
        "|---|---|",
    ]
    for version, family in superseded:
        lines.append(f"| `{version}` | `{schemas.VERSIONS[family]}` |")

    lines += [
        "",
        "## Required fields",
        "",
        "Each contract's required fields are frozen in the test suite, so dropping "
        "one fails the build here rather than a consumer's parser somewhere else.",
        "",
        "| Contract | Required |",
        "|---|---|",
    ]
    for name in sorted(schemas.names()):
        required = schemas.load(name).get("required") or []
        cell = ", ".join(f"`{field}`" for field in required) if required else "none declared"
        lines.append(f"| `{name}` | {cell} |")

    lines.append("")
    OUT.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print(
        f"wrote {OUT.relative_to(ROOT)}: "
        f"{len(schemas.VERSIONS)} current, {len(superseded)} superseded, "
        f"{len(schemas.names())} files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
