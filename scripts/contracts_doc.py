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

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

OUT = ROOT / "docs" / "CONTRACTS.md"

# What each family is for, and the command that produces one. Prose, because
# no amount of reading a JSON Schema tells a reader when they would want the
# document it describes.
FAMILIES: dict[str, tuple[str, str]] = {
    "surface": (
        "What an agent CAN do in one root: every capability resolved across scopes, "
        "naming the file it came from, the documented merge rule that settled it and "
        "how far it resolved. Three lists that are never merged - what resolved, what "
        "could not, and what this release does not read.",
        "actaira check",
    ),
    "trace": (
        "What an agent did, in one shape whatever observed it: an ordered list of tool "
        "calls with the digest of each call's arguments and result, the capture level "
        "that produced every one, and the holes that level did not cover.",
        "actaira scan, actaira watch",
    ),
    "report": (
        "What one scan found in one artifact: the findings, the detected format, "
        "the digest, and the coverage matrix that bounds the claim.",
        "actaira scan --format json",
    ),
    "coverage": (
        "The per-surface matrix on its own, so a consumer can read the scope of a "
        "claim without parsing the claim.",
        "embedded in every report",
    ),
    "policy": (
        "A decision document: rules, their verdicts, exceptions with an owner and an "
        "expiry, and the digest the decision will cite.",
        "actaira policy show",
    ),
    "policy-decision": (
        "What a policy decided about one run, with the rule and the evidence behind "
        "every verdict, including the ones that could not be evaluated.",
        "actaira policy check --json",
    ),
    "assurance-receipt": (
        "The one document meant to leave the organisation that produced it: subjects "
        "by digest, coverage, findings, the policy decision and the supply-chain "
        "state, signed over the canonical JSON of itself minus the signature.",
        "actaira receipt issue",
    ),
    "agent-bom": (
        "An agent's bill of materials: model, tools with declared effects, MCP "
        "servers, sub-agents, and the digest that covers the system prompt too.",
        "actaira agent bom",
    ),
    "model-bundle": (
        "A model repository resolved into members, relations and gaps, with "
        "`content_identity` kept separate from `structural_digest`.",
        "actaira bundle --json",
    ),
    "attack-paths": (
        "The routes found through an agent declaration, each with what it carries, "
        "what would break it, and any control that already closes it.",
        "actaira agent paths --json",
    ),
    "source-snapshot": (
        "What a connector listed for one source at one moment: members, digests, "
        "the revision, and whether the listing was complete.",
        "actaira snapshot",
    ),
    "evidence-record": (
        "One observation, bound to the digest of what was observed, with its state "
        "and the collector that made it.",
        "actaira evidence show --json",
    ),
    "asset-graph": (
        "Assets and the declared relations between them, every edge carrying the "
        "manifest, declaration or snapshot that stated it.",
        "actaira graph export",
    ),
    "trust-policy": (
        "What this environment accepts from a signer, kept apart from what "
        "cryptography proved about the bytes.",
        "written by hand, read by actaira trust check",
    ),
    "subject-manifest": (
        "What a policy or a receipt is about when it is not a list of files: the "
        "subjects, their kinds, and the relations the document itself declares.",
        "written by hand, read by --subjects",
    ),
    "state-export": (
        "The whole store as one deterministic document, so two states can be "
        "diffed. Two runs over the same observation are byte-identical.",
        "actaira graph export, actaira snapshot",
    ),
}

HEADER = """# Contracts

Every JSON document Actaira publishes, what it is for, and whether it is
current or superseded.

**Generated by `scripts/contracts_doc.py` from the schemas the package ships.**
Editing this file by hand is pointless: `make contracts` overwrites it, and
the release gate compares it with the registry. See design note D-232.

A document declares its own version in `schema_version`, always first. A
consumer reads that field and refuses what it does not understand, rather than
guessing from the shape. What a version promises, and what is deliberately not
stable, is in [`COMPATIBILITY.md`](COMPATIBILITY.md).

```bash
actaira schema                 # list every contract on disk
actaira schema report-v1       # print one
```

"""


def main() -> int:
    from actaira import schemas

    missing = sorted(set(schemas.VERSIONS) - set(FAMILIES))
    if missing:
        print(
            "families with no prose in scripts/contracts_doc.py: " + ", ".join(missing),
            file=sys.stderr,
        )
        return 1

    lines = [HEADER, "## Current\n", "| Contract | What it is | Produced by |", "|---|---|---|"]
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
