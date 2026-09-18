"""SARIF 2.1.0 for the findings a diff raised on something new. Minimal, and new.

`report/sarif.py` existed in phase A, shaped around the model scanner: its
results were artifacts with formats and tensors, and its `level` came from a
fold over the severities one artifact's findings carried. That module went to
`archive/model-scanner` and is not resurrected; this is a new one whose whole
job is to carry what `surface-diff/v1` already says into the one format a code
host reads without being taught anything.

Design note D-298. TWO THINGS IT DOES NOT DO, both of which the archived one did.

It never takes a maximum. Every finding becomes one SARIF `result` with its own
`level`, transliterated from the `severity` the rule's author wrote, one at a
time. There is no run-level, file-level or rule-group level severity anywhere in
the output, because that is the fold CLAUDE.md's first negative forbids and
SARIF offers three convenient places to commit it.

It never invents a level. `LEVEL` below is a TRANSLITERATION table, not an
order: it maps the labels this tree's packs use into the four words the SARIF
enum allows, so a host can colour a line. A label the table does not know keeps
its own word in `properties.severity` and is rendered `warning`, which is what
SARIF itself defaults to - dropping the result would hide a finding because we
did not recognise somebody's vocabulary, and guessing a rank for it would be
inventing the order this table exists not to be.

Rejected: emitting `rank`, which SARIF defines as a number from 0 to 100. It is
the first negative spelled in somebody else's schema, and a field being optional
in a standard is not permission to compute one.
"""
from __future__ import annotations

from typing import Any

SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
VERSION = "2.1.0"

# The labels this tree's packs use today, each written to one SARIF word. The
# mapping is published here rather than derived, so adding a label is a decision
# somebody makes in a diff rather than a rank a function computed.
LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
UNKNOWN_LEVEL = "warning"


def _rules(findings: list[dict[str, Any]], catalog: Any) -> list[dict[str, Any]]:
    """One `reportingDescriptor` per rule that fired, in a stable order.

    Deduplicated by id and sorted, so two runs over one diff emit the same
    bytes - the property `cli_output_is_deterministic` holds the console to and
    a signed document depends on.
    """
    seen: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rule_id = str(finding.get("rule_id"))
        if rule_id in seen:
            continue
        evidence = finding.get("evidence", {}) or {}
        descriptor: dict[str, Any] = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": catalog.rule(rule_id)},
            "properties": {
                # Who said it. A finding that named no author would be Actaira
                # holding the opinion, and a SARIF consumer that shows only the
                # message would otherwise show ours.
                "author": finding.get("author"),
                "pack": finding.get("pack"),
                "version": finding.get("rule_version"),
                "severity": finding.get("severity"),
            },
        }
        if evidence.get("remediation"):
            descriptor["help"] = {"text": str(evidence["remediation"])}
        references = [str(item) for item in evidence.get("references", []) or []]
        if references:
            descriptor["helpUri"] = references[0]
        if evidence.get("atr"):
            descriptor["properties"]["atr"] = list(evidence["atr"])
        seen[rule_id] = descriptor
    return [seen[key] for key in sorted(seen)]


def _result(finding: dict[str, Any], index: dict[str, int], catalog: Any) -> dict[str, Any]:
    rule_id = str(finding.get("rule_id"))
    severity = str(finding.get("severity", ""))
    evidence = finding.get("evidence", {}) or {}
    location = str(finding.get("location") or "")
    return {
        "ruleId": rule_id,
        "ruleIndex": index[rule_id],
        "level": LEVEL.get(severity, UNKNOWN_LEVEL),
        "message": {"text": catalog.rule(rule_id)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": location, "uriBaseId": "%SRCROOT%"}
                }
            }
        ],
        "properties": {
            "capability": evidence.get("capability"),
            "vendor": evidence.get("vendor"),
            "scope": evidence.get("scope"),
            "resolution": evidence.get("resolution"),
            "mergeRule": evidence.get("merge_rule"),
            # The author's word, kept beside the transliterated level so nothing
            # is lost when the table does not know a label.
            "severity": severity,
            "author": finding.get("author"),
            "pack": finding.get("pack"),
        },
    }


def from_diff(document: dict[str, Any], catalog: Any, *, tool_version: str) -> dict[str, Any]:
    """A SARIF log for every rule that fired on something added or widened.

    The same set the exit code is computed from, and for the same reason: `diff`
    answers what changed, so what it reports to a code host is what arrived. A
    finding that was already there and is still there belongs to `check`.
    """
    from ..surface.diff import fired_on_new_capability

    findings = fired_on_new_capability(document)
    descriptors = _rules(findings, catalog)
    index = {descriptor["id"]: position for position, descriptor in enumerate(descriptors)}
    return {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Actaira",
                        "version": tool_version,
                        "informationUri": "https://github.com/marcosmatalab/actaira",
                        "rules": descriptors,
                    }
                },
                "results": [_result(finding, index, catalog) for finding in findings],
            }
        ],
    }


__all__ = ["LEVEL", "SCHEMA", "UNKNOWN_LEVEL", "VERSION", "from_diff"]
