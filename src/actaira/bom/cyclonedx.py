"""CycloneDX 1.6 ML-BOM emission.

Design note D-16. CycloneDX rather than SPDX because CycloneDX has a
first-class `machine-learning-model` component type and a `modelCard`
object, so tensor shapes and quantisation have somewhere to live that a
downstream tool already understands. SPDX 3.0 has an AI profile but the
tooling around it is thinner today.

The rule that matters: every field emitted here comes from bytes that were
actually parsed. Nothing is copied from a sidecar config, a model card or a
filename, because a BOM that repeats what the publisher claims adds no
information to the supply chain. Where a value is unknown it is omitted,
never guessed.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from .. import __version__
from ..model import ArtifactReport, artifact_name

SPEC_VERSION = "1.6"


def build_bom(reports: list[ArtifactReport], serial: str | None = None) -> dict[str, Any]:
    components = [_component(report, index) for index, report in enumerate(reports)]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "tools": {
                "components": [
                    {"type": "application", "name": "actaira", "version": __version__}
                ]
            },
        },
        "components": components,
    }


def _component(report: ArtifactReport, index: int = 0) -> dict[str, Any]:
    name = artifact_name(report.path)
    # `bom-ref` must be unique within a document (CycloneDX 1.6 requires it,
    # and every consumer resolves dependencies through it). Deriving it from
    # the digest alone collided the moment one BOM covered the same bytes
    # twice, which is not exotic: two paths to one checkpoint, a file and a
    # copy of it, a directory walk that reaches a symlink. Two components
    # under one ref make a document whose graph is ambiguous, so the position
    # in this document is part of the ref. The digest stays in it because a
    # reader should be able to see what the ref points at without following
    # it, and `hashes` remains the place a tool matches on.
    component: dict[str, Any] = {
        "type": "machine-learning-model",
        "bom-ref": f"urn:actaira:artifact:{index}:{report.sha256}",
        "name": name,
        "hashes": [{"alg": "SHA-256", "content": report.sha256}],
        "properties": _properties(report),
    }
    model_card = _model_card(report)
    if model_card:
        component["modelCard"] = model_card
    return component


def _properties(report: ArtifactReport) -> list[dict[str, str]]:
    rows = [
        {"name": "actaira:format", "value": report.detected_format},
        {"name": "actaira:format_confidence", "value": report.format_confidence},
        {"name": "actaira:size_bytes", "value": str(report.size_bytes)},
        {"name": "actaira:verdict", "value": report.verdict.value},
        {"name": "actaira:fully_read", "value": str(report.metadata.get("fully_read", False)).lower()},
    ]
    if report.max_severity is not None:
        rows.append({"name": "actaira:max_severity", "value": report.max_severity.value})
    for finding in report.findings:
        rows.append({"name": "actaira:finding", "value": f"{finding.rule_id}:{finding.severity.value}"})
    for qualified in report.imported_callables:
        rows.append({"name": "actaira:imported_callable", "value": qualified})
    return rows


def _model_card(report: ArtifactReport) -> dict[str, Any]:
    """Only observed quantities. Absent fields mean "not observed"."""
    parameters = report.metadata.get("total_parameters")
    if parameters is None and report.tensors:
        parameters = sum(tensor.n_elements for tensor in report.tensors)

    properties: list[dict[str, Any]] = []
    if report.tensors:
        properties.append({"name": "tensor_count", "value": str(len(report.tensors))})
        dtypes = sorted({tensor.dtype for tensor in report.tensors})
        properties.append({"name": "dtypes_observed", "value": ",".join(dtypes)})
    if parameters:
        properties.append({"name": "parameters_observed", "value": str(parameters)})

    kv = report.metadata.get("kv") or {}
    for key in ("general.architecture", "general.name", "general.quantization_version"):
        if key in kv:
            properties.append({"name": key, "value": str(kv[key])})
    for key in ("producer_name", "producer_version", "ir_version", "node_count"):
        if key in report.metadata:
            properties.append({"name": f"onnx.{key}", "value": str(report.metadata[key])})

    if not properties:
        return {}
    # `properties` sits on the model card itself, not under `modelParameters`.
    # The 1.6 schema declares `modelParameters` with
    # `"additionalProperties": false` and a closed field list that does not
    # include `properties`, so every document this emitted was invalid against
    # the specVersion it declared - accepted by tools that do not validate and
    # rejected outright by those that do. `modelCard.properties` is the field
    # the schema provides for exactly this, and it takes the same shape, so
    # nothing is lost but the invalidity.
    return {"properties": properties}
