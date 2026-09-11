"""SARIF 2.1.0, the format GitHub code scanning ingests.

Three decisions worth arguing with.

**`rules[]` carries only the rules that produced a result in this run**, not
the whole catalogue. A rule with no result is a row no consumer displays, and
a document that grows with the catalogue instead of with the evidence is
harder to diff between two runs. Each result also carries `ruleIndex`, so a
consumer never has to match rules by string.

**`partialFingerprints` is what makes an alert survive a re-scan.** GitHub
deduplicates on it, so the value is computed from the things that identify a
finding and from nothing else: the rule, the digest of the artifact, the
location the inspector reported, and the evidence. The directory is
deliberately excluded, so moving `model.pt` from `models/` to `models/v2/`
does not reopen every alert on it. The evidence is deliberately included: a
pickle that imports four denied callables produces four ACT-PKL-001 findings
at one location, and without the evidence those four alerts would collapse
into one and three gadgets would disappear from the UI.

**A binary artifact has no lines.** Code scanning anchors an alert to a line,
so a file-level finding is anchored at line 1. That number is a placeholder
for the UI, not an offset into the file, and it is never used as evidence:
where a byte offset is known it travels in the finding's evidence, which is
reproduced verbatim in the result's property bag.
"""
from __future__ import annotations

import hashlib
from typing import Any

from .. import __version__
from ..i18n.catalog import Catalog
from ..model import ArtifactReport, Finding, Severity, canonical_json
from . import artifact_uri

SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "actaira"
# `informationUri` and `helpUri` used to point at a repository this tree does
# not have. Both fields are optional in SARIF 2.1.0 and both are rendered as
# links by the viewers that read this format, so a URL nobody can fetch is a
# dead link inside a security report - the one document where a reader most
# needs what they are shown to be real. They are omitted instead, and the rule
# text that would have been behind the link is already inline in
# `fullDescription` and `help`, where a consumer does not have to leave the
# document to read it.
#
# If this tree is ever published, set these two to the published location and
# the links come back. Until then, nothing here claims one exists.
INFORMATION_URI: str | None = None
RULE_HELP_URI: str | None = None
FINGERPRINT_KEY = "actairaFinding/v1"

# The line a file-level finding is anchored to. See the module docstring: it
# is a UI convention, not a measurement.
PLACEHOLDER_LINE = 1

# SARIF has four levels and this project has five severities, so the mapping
# is lossy in one place and only one: LOW and INFO both become "note". The
# original severity is kept in the result's property bag, so a consumer that
# cares can still tell a hygiene finding from an observation.
LEVEL_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

SARIF_LEVELS = ("none", "note", "warning", "error")


def level_for(severity: Severity | str) -> str:
    """The SARIF level for one Actaira severity."""
    return LEVEL_BY_SEVERITY[Severity(severity)]


def fingerprint(report: ArtifactReport, finding: Finding) -> str:
    """Stable identity of one finding, for cross-run deduplication.

    Computed over canonical JSON, the same serialisation the attestation chain
    hashes, so two runs over the same bytes agree byte for byte.
    """
    payload = {
        "rule_id": finding.rule_id,
        "artifact_sha256": report.sha256,
        "location": finding.location,
        "evidence": finding.evidence,
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def build_sarif(
    reports: list[ArtifactReport],
    base: str | None = None,
    catalog: Catalog | None = None,
) -> dict[str, Any]:
    """One SARIF log with one run, whatever the reports contain."""
    catalog = catalog or Catalog("en")

    worst_by_rule: dict[str, Severity] = {}
    for report in reports:
        for finding in report.findings:
            known = worst_by_rule.get(finding.rule_id)
            if known is None or finding.severity.rank > known.rank:
                worst_by_rule[finding.rule_id] = finding.severity

    rule_ids = sorted(worst_by_rule)
    index_of_rule = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    rules = [_rule(rule_id, worst_by_rule[rule_id], catalog) for rule_id in rule_ids]

    artifacts: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    notifications: list[dict[str, Any]] = []

    for report in reports:
        uri = artifact_uri(report.path, base)
        artifact_index = len(artifacts)
        artifacts.append(_artifact(report, uri))
        for finding in sorted(report.findings, key=lambda item: -item.severity.rank):
            results.append(
                _result(report, finding, uri, artifact_index, index_of_rule[finding.rule_id], catalog)
            )
        # An inspector that crashed is a fact about the tool, not about the
        # artifact, so it belongs in the invocation rather than in a result.
        # Dropping it would leave a run that looks complete and is not.
        for error in report.inspector_errors:
            notifications.append({"level": "error", "message": {"text": f"{uri}: {error}"}})

    invocation: dict[str, Any] = {"executionSuccessful": not notifications}
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    return {
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "semanticVersion": __version__,
                        **({"informationUri": INFORMATION_URI} if INFORMATION_URI else {}),
                        "rules": rules,
                    }
                },
                "artifacts": artifacts,
                "results": results,
                "invocations": [invocation],
            }
        ],
    }


def _rule(rule_id: str, severity: Severity, catalog: Catalog) -> dict[str, Any]:
    """One rule descriptor.

    `defaultConfiguration.level` is derived from the worst severity this rule
    reached in this run. Every rule in this project has a fixed severity in the
    source, so in practice that is the rule's severity; deriving it rather than
    hard-coding a second table means the two can never drift apart.
    """
    short = catalog.rule(rule_id)
    detail = catalog.rule_help(rule_id) or short
    family = rule_id.split("-")[1].lower() if rule_id.count("-") >= 2 else "unknown"
    return {
        "id": rule_id,
        "shortDescription": {"text": short},
        "fullDescription": {"text": detail},
        "help": {"text": detail},
        **({"helpUri": RULE_HELP_URI} if RULE_HELP_URI else {}),
        "defaultConfiguration": {"level": level_for(severity)},
        "properties": {
            "actaira:severity": severity.value,
            "tags": ["security", "ml-supply-chain", f"actaira:{family}"],
        },
    }


def _artifact(report: ArtifactReport, uri: str) -> dict[str, Any]:
    return {
        "location": {"uri": uri},
        "length": report.size_bytes,
        "hashes": {"sha-256": report.sha256},
        "roles": ["analysisTarget"],
        "properties": {
            "actaira:format": report.detected_format,
            "actaira:format_confidence": report.format_confidence,
            "actaira:verdict": report.verdict.value,
            "actaira:fully_read": bool(report.metadata.get("fully_read", False)),
        },
    }


def _result(
    report: ArtifactReport,
    finding: Finding,
    uri: str,
    artifact_index: int,
    rule_index: int,
    catalog: Catalog,
) -> dict[str, Any]:
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": level_for(finding.severity),
        "message": {"text": catalog.rule(finding.rule_id)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "index": artifact_index},
                    "region": {"startLine": PLACEHOLDER_LINE},
                },
                "logicalLocations": [{"name": finding.location, "kind": "member"}],
            }
        ],
        "partialFingerprints": {FINGERPRINT_KEY: fingerprint(report, finding)},
        "properties": {
            "actaira:severity": finding.severity.value,
            "actaira:artifact_sha256": report.sha256,
            "actaira:location": finding.location,
            "actaira:evidence": finding.evidence,
        },
    }
