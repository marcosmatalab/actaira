"""A signed baseline of a surface, carrying no content at all.

`seamark verify` has been a reader with no writer since 3.0.0: `write_package`
was reachable only from the test suite, and a tool that verifies a format
nothing in it produces is half a claim. This is the producer, and the thing it
produces is the one this product needs - the surface a security reviewer
approved, bound to its digest so the approval expires by itself when the digest
moves (published limit 14).

THE CABLE RULE, which `docs/GOVERNANCE.md` states and this is the first command
to be held to. What leaves the machine is digests, rule identifiers, states and
counts. Never a path, never a command, never a URL, never a server's name.

Design note D-296. Two different mechanisms, because the two kinds of value need
different things:

* A value the operator or a vendor CHOSE - a file path, a server alias - becomes
  a salted reference through `trace/redact`. Salted, because `sha256(".env")` is
  the same sixteen hex digits on every machine that has ever existed and a
  reader with a word list recovers it (D-263). The salt stays with the operator,
  in `--out`, and the package says so.
* Everything a capability observed becomes ONE digest of the whole `facts`
  mapping. Not a digest per fact: `command_sha256` is already an unsalted digest
  of a command, and publishing it would hand a guesser a dictionary attack on
  the command line rather than on the path. One digest over the mapping is what
  an approval has to bind to anyway, and it is the only shape that leaks nothing
  by construction.

Rejected: sealing the `surface/v1` document itself and relying on `check`
running without `--with-content`. That makes the privacy property depend on a
flag somebody remembered not to pass, and the document still carries every path
and every domain in the clear. The seal is a separate, narrower document for the
same reason `--with-content` is a decision made once at the reader.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from ..model import canonical_json
from ..trace.redact import file_ref, label_ref, new_salt

# Facts whose value is a name somebody else chose: an MCP server's alias, a VS
# Code task's label. They travel as `label_ref`, which is the function written
# for exactly this - a stable handle the operator can resolve from their own map
# and nobody else can guess. Everything else a capability observed is inside the
# one `facts` digest and is not published at all.
NAMED_BY_A_THIRD_PARTY = ("server", "label")


class References:
    """Every reference this seal published, and what the operator can undo it to.

    The same bargain `scan` strikes in `index.json` and `watch` in
    `interposition.json`: the map is what lets the operator read their own seal,
    it lives beside the package on their disk, and it is never inside one.
    """

    def __init__(self, salt: str) -> None:
        self.salt = salt
        self.map: dict[str, str] = {}

    def file(self, path: str) -> str:
        reference = file_ref(path, self.salt)
        self.map[reference] = path
        return reference

    def label(self, name: str) -> str:
        reference = label_ref(name, self.salt)
        self.map[reference] = name
        return reference


def facts_digest(facts: dict[str, Any]) -> str:
    """sha256 over one capability's whole `facts` mapping, unsalted on purpose.

    Unsalted because this digest exists to be COMPARED - between two seals, two
    machines and two moments, which is what an expiring approval is made of - and
    a per-seal salt would make every such comparison impossible. It leaks
    nothing: it is a digest of a mapping whose shape is ours and whose values
    were never published beside it, so there is no dictionary to run it against.
    """
    return hashlib.sha256(canonical_json(facts or {})).hexdigest()


def _named(facts: dict[str, Any], references: References) -> dict[str, str]:
    """`name_ref` for the one value in this capability a third party chose, if any.

    A reviewer approving a surface has to be able to tell two MCP servers in one
    file apart; the `facts` digest already does that, and it does it in a way
    nobody, including the operator, can read back. This gives them the handle
    without giving anybody the name.
    """
    for key in NAMED_BY_A_THIRD_PARTY:
        value = facts.get(key)
        if isinstance(value, str) and value:
            return {"name_ref": references.label(value)}
    return {}


def seal_document(surface: dict[str, Any], references: References) -> dict[str, Any]:
    """The `seal/v1` document for one `surface/v1` document.

    A pure function of the surface and the salt: the same repository sealed
    twice with the same salt produces the same bytes, which is what makes two
    seals comparable at all.
    """
    from ..schemas import VERSIONS

    surfaces = []
    for entry in surface.get("surfaces", []):
        capabilities = []
        for capability in entry.get("capabilities", []):
            capabilities.append({
                "capability": capability["capability"],
                "vendor": capability["vendor"],
                "scope": capability["scope"],
                "resolution": capability["resolution"],
                "merge_rule": capability["merge_rule"],
                "source_ref": references.file(capability["source"]),
                "facts_sha256": facts_digest(capability.get("facts", {})),
                **_named(capability.get("facts", {}), references),
            })
        surfaces.append({
            "vendor": entry["vendor"],
            "agent_version": entry.get("agent_version"),
            "capabilities": capabilities,
        })

    findings = [
        {
            "rule_id": finding["rule_id"],
            "rule_version": finding["rule_version"],
            "author": finding["author"],
            "pack": finding["pack"],
            # The author's label, verbatim, exactly as `surface/v1` carries it.
            # Not ordered, not summed, and not turned into a count per label:
            # counting by severity is the fold the first negative forbids with
            # an extra step.
            "severity": finding["severity"],
            "location_ref": references.file(finding["location"]),
        }
        for finding in surface.get("findings", [])
    ]

    return {
        "schema_version": VERSIONS["seal"],
        # What was sealed, by its digest. An approval keyed on this expires the
        # day the surface changes, which is the whole product claim.
        "surface_sha256": hashlib.sha256(canonical_json(surface)).hexdigest(),
        "surface_schema_version": surface["schema_version"],
        "machine": surface["machine"],
        "root_ref": references.file(surface["root"]),
        "surfaces": surfaces,
        "findings": findings,
        # Counts, not lists: what could not be resolved and what was not read
        # are facts about this seal's completeness, and their prose carries
        # paths and causes written by somebody else's files.
        "unresolved": len(surface.get("unresolved", [])),
        "not_read": len(surface.get("not_read", [])),
        "salt_travels": False,
        "salt_note": (
            "The references in this document are salted digests. The salt and the map "
            "back to what they stand for stay with the operator, beside this package, "
            "and are not in it."
        ),
    }


def write_seal(
    surface: dict[str, Any],
    out: Path,
    keypair: Any,
    *,
    salt: str | None = None,
    package_name: str = "surface-seal.zip",
    index_name: str = "index.json",
) -> tuple[Path, dict[str, Any]]:
    """Write the package and the operator's own reference map beside it.

    Beside and not inside, which is the same placement `_write_traces` argues
    for: a digest cannot live inside the thing it is the digest of, and a salt
    cannot travel with the references it protects.
    """
    import json

    from .chain import Entry, append
    from .package import write_package

    references = References(salt or new_salt())
    document = seal_document(surface, references)

    entries: list[Entry] = []
    append(entries, document["surface_sha256"], document)

    out.mkdir(parents=True, exist_ok=True)
    package_path = out / package_name
    write_package(package_path, entries, keypair)

    (out / index_name).write_text(
        json.dumps(
            {
                "package": package_name,
                "redaction_salt": references.salt,
                "references": dict(sorted(references.map.items())),
                "note": (
                    "This file resolves the references in the package back to the paths "
                    "and names they stand for. It is yours and it does not travel: "
                    "publishing it undoes the redaction the package is built on."
                ),
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return package_path, document


__all__ = ["References", "facts_digest", "seal_document", "write_seal"]
