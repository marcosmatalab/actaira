"""Keras / HDF5 inspector.

Design note D-09, and an honest one. A full HDF5 reader is out of scope for
a zero-dependency tool: the format is a B-tree filesystem, and a partial
reader that silently misses a group is worse than no reader at all.

What this module does instead is bounded and says so: it confirms the magic
number, then scans the raw bytes for the Keras `model_config` JSON blob and
for the markers of the two constructs that make a Keras file executable, a
`Lambda` layer (whose body is a marshalled code object, run at load) and a
registered custom object. When the config cannot be located, the result is
INCONCLUSIVE, never PASS. An artifact this tool cannot fully read is
reported as unread.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..model import Finding, Severity

MAGIC = b"\x89HDF\r\n\x1a\n"
# Keras stores the topology as a JSON string attribute; the blob is locatable
# without walking the B-tree because it is stored contiguously.
_CONFIG_RE = re.compile(rb'\{"(?:class_name|module|keras_version)"[^\x00]{20,2000000}')
MAX_SCAN_BYTES = 256 * 1024 * 1024


def inspect(path: Path) -> tuple[list[Finding], dict[str, Any], bool]:
    """Returns (findings, metadata, config_was_read)."""
    findings: list[Finding] = []
    metadata: dict[str, Any] = {}
    size = path.stat().st_size

    with path.open("rb") as handle:
        head = handle.read(8)
        if head != MAGIC:
            findings.append(
                Finding(
                    rule_id="ACT-H5-004",
                    severity=Severity.MEDIUM,
                    location=path.name,
                    evidence={"reason": "bad_magic"},
                )
            )
            return findings, metadata, False
        handle.seek(0)
        data = handle.read(min(size, MAX_SCAN_BYTES))

    metadata["scanned_bytes"] = len(data)
    metadata["truncated_scan"] = len(data) < size

    match = _CONFIG_RE.search(data)
    if match is None:
        findings.append(
            Finding(
                rule_id="ACT-H5-003",
                severity=Severity.MEDIUM,
                location=path.name,
                evidence={"reason": "model_config_not_located", "consequence": "inconclusive"},
            )
        )
        return findings, metadata, False

    blob = match.group(0)
    config = _best_effort_json(blob)
    if config is None:
        findings.append(
            Finding(
                rule_id="ACT-H5-003",
                severity=Severity.MEDIUM,
                location=path.name,
                evidence={"reason": "model_config_not_parseable", "consequence": "inconclusive"},
            )
        )
        return findings, metadata, False

    layers = _collect_class_names(config)
    metadata["layer_class_names"] = sorted(set(layers))
    metadata["layer_count"] = len(layers)

    lambda_count = sum(1 for name in layers if name == "Lambda")
    if lambda_count:
        findings.append(
            Finding(
                rule_id="ACT-H5-001",
                severity=Severity.CRITICAL,
                location=path.name,
                evidence={
                    "lambda_layers": lambda_count,
                    "reason": "lambda_body_is_a_marshalled_code_object_executed_on_load",
                },
            )
        )
    unknown = [name for name in set(layers) if name not in _KNOWN_LAYERS and name != "Lambda"]
    if unknown:
        findings.append(
            Finding(
                rule_id="ACT-H5-002",
                severity=Severity.HIGH,
                location=path.name,
                evidence={"custom_classes": sorted(unknown)[:32]},
            )
        )
    # A file past MAX_SCAN_BYTES was read up to the cap and no further, so a
    # second `model_config` in the unscanned tail - a Lambda layer, say - was
    # never looked at. Returning True here said "fully read" about a file this
    # module had deliberately stopped reading, which is the PASS-on-unread
    # failure D-04 exists to forbid. `metadata["truncated_scan"]` already
    # recorded the fact; nothing consumed it.
    return findings, metadata, not metadata["truncated_scan"]


def _best_effort_json(blob: bytes) -> Any:
    """Trim the blob to the outermost balanced object and parse it."""
    text = blob.decode("utf-8", errors="replace")
    depth = 0
    for index, char in enumerate(text):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[: index + 1])
                except Exception:
                    return None
    return None


def _collect_class_names(node: Any, out: list[str] | None = None) -> list[str]:
    """Every `class_name` anywhere in the parsed config, walked iteratively.

    The recursive version borrowed the caller's remaining Python stack, and
    the depth it needed was chosen by the file. `json.loads` has its own
    recursion guard, but it is a different budget: a config that parses at
    depth 980 from a shallow stack overflows this walk when
    `inspect_artifact` is called from a deep one - from the web server, or
    from inside a test runner. An explicit stack removes the coupling
    entirely, so how deep this can go stops depending on who called.
    """
    if out is None:
        out = []
    pending: list[Any] = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            value = current.get("class_name")
            if isinstance(value, str):
                out.append(value)
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return out


_KNOWN_LAYERS = frozenset(
    {
        "Sequential", "Functional", "Model", "InputLayer", "Dense", "Dropout",
        "Conv1D", "Conv2D", "Conv3D", "SeparableConv2D", "DepthwiseConv2D",
        "MaxPooling1D", "MaxPooling2D", "MaxPooling3D", "AveragePooling2D",
        "GlobalAveragePooling1D", "GlobalAveragePooling2D", "GlobalMaxPooling2D",
        "BatchNormalization", "LayerNormalization", "Activation", "ReLU", "LeakyReLU",
        "ELU", "PReLU", "Softmax", "Flatten", "Reshape", "Permute", "RepeatVector",
        "Embedding", "LSTM", "GRU", "SimpleRNN", "Bidirectional", "TimeDistributed",
        "Add", "Subtract", "Multiply", "Average", "Maximum", "Minimum", "Concatenate",
        "Dot", "ZeroPadding2D", "Cropping2D", "UpSampling2D", "SpatialDropout2D",
        "GaussianNoise", "GaussianDropout", "AlphaDropout", "MultiHeadAttention",
        "Attention", "AdditiveAttention", "Normalization", "Rescaling", "Resizing",
        "RandomFlip", "RandomRotation", "RandomZoom", "CategoryEncoding",
        "StringLookup", "IntegerLookup", "TextVectorization", "Identity",
        "GlorotUniform", "Zeros", "Ones", "RandomNormal", "VarianceScaling",
        "Adam", "SGD", "RMSprop", "Constant", "TruncatedNormal", "Orthogonal",
    }
)
