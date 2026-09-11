"""A model is a repository, not a file.

Design note D-130. Everything upstream of this module inspects one artifact at
a time, and for a 2019 checkpoint that was the whole story. A 2026 model is a
directory: four safetensors shards, an index that says how they fit together,
a `config.json`, a tokenizer, an `adapter_config.json` pointing at a base
model somewhere else, a `requirements.txt`, and - the part that matters most -
`modeling_custom.py`, which `transformers` will import and execute the moment
somebody passes `trust_remote_code=True`.

Scanning those files one by one finds nothing, and it is not a gap in the
parsers. Every one of them is individually benign. The risk is in the
relations: that the config nominates a Python module, that the module is in
the repository, that the index promises a shard nobody shipped, that the
adapter names a base model whose digest is not recorded anywhere. A file-level
scanner cannot see a relation, so this module is the level above it.

What it does not do is decide. It resolves the bundle, records what it found,
and emits findings; the policy layer decides whether a repository that carries
executable Python is acceptable here. `trust_remote_code` in particular is a
legitimate feature that a great deal of real work depends on, and a tool that
refused it outright would be a tool people stop pointing at their models.
What it must never be is invisible.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .coverage import (
    REASON_PARSE_FAILED,
    REASON_READ_IN_FULL,
    Coverage,
    CoverageState,
    Surface,
    SurfaceCoverage,
    baseline,
)
from .model import Finding, Severity, artifact_name

SCHEMA_VERSION = "model-bundle/v2"

# Why v2 and not a field added to v1: the meaning of a digest changed, and
# `docs/COMPATIBILITY.md` says that is a major. A consumer written against v1
# read `bundle_digest` and could reasonably have taken it for the identity of
# the model; in v2 that field is gone and `structural_digest` is what replaced
# it, under a name that cannot be misread.
LEGACY_SCHEMA_VERSION = "model-bundle/v1"


class ContentIdentity(str, Enum):
    """How firmly this resolution can say WHICH model these bytes are.

    Design note D-200, and the correction ACT22-P0-01 asks for. The v1 digest
    was computed over paths, sizes, roles and whatever sha256 values had been
    computed - and members over 64 MiB were not hashed, so their entry was
    `null`. Two 8 GB weight files with the same name and the same size and
    completely different bytes therefore produced the same `bundle_digest`.
    The docstring said "a digest over the bundle's shape", which was true and
    which nobody reads before trusting a field called `bundle_digest`.

    So the two questions are now two fields. `structural_digest` answers "is
    this the same layout" and is honest about being only that. This enum
    answers "can anything here be taken as the identity of the weights", and
    the answer is usually not COMPLETE, because hashing 30 GB on every
    resolution is not a default anybody would keep.

    EXTERNALLY_BOUND is the case that makes the whole thing usable: a
    connector that published a digest for a file it served has bound that
    file's identity without this tool reading 30 GB, and a receipt may rely on
    it as long as it says whose word it is taking.
    """

    COMPLETE = "complete"
    PARTIAL = "partial"
    EXTERNALLY_BOUND = "externally_bound"
    UNAVAILABLE = "unavailable"

# The files a bundle is recognised by. Presence of any one of these means the
# directory is a model repository rather than a folder that happens to contain
# a model.
BUNDLE_MARKERS = (
    "config.json",
    "model.safetensors.index.json",
    "pytorch_model.bin.index.json",
    "adapter_config.json",
    "tokenizer_config.json",
)

# Extensions whose contents execute when a loader imports them. This is the
# list the `trust_remote_code` path actually reaches, plus the native ones a
# wheel or an extension module brings.
EXECUTABLE_SUFFIXES = (".py", ".pyc", ".pyx", ".so", ".dylib", ".dll", ".pyd")
PACKAGING_SUFFIXES = (".whl", ".egg", ".tar.gz", ".zip")

# Hash budget. A shard is gigabytes and a bundle is several of them, so a
# resolver that digested everything would take minutes on a normal model.
# Digests are computed for the small files that define relations and recorded
# as absent, explicitly, for the large ones.
MAX_DIGEST_BYTES = 64 * 1024 * 1024

_JINJA_CALL = re.compile(r"\{\{-?\s*[\w.]+\s*\(|\{%-?\s*(?:set|for|if)\b")


@dataclass
class Member:
    """One file in the bundle, and what it is."""

    path: str
    size_bytes: int
    role: str  # weights | index | config | tokenizer | code | packaging | other
    sha256: str | None = None
    digest_reason: str = ""
    # A digest somebody else published for this file. Kept in its own field
    # and never merged into `sha256`: one is a measurement this process made
    # and the other is a claim by whoever served the bytes, and a BOM that
    # could not tell them apart would let a registry decide what this tool
    # says it verified.
    declared_sha256: str | None = None
    declared_by: str = ""

    @property
    def identity_known(self) -> bool:
        return bool(self.sha256 or self.declared_sha256)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"path": self.path, "size_bytes": self.size_bytes, "role": self.role}
        if self.sha256:
            payload["sha256"] = self.sha256
        elif self.digest_reason:
            # An absent digest is stated, never omitted. A BOM with a missing
            # field reads as "nobody looked"; one that says why reads as a
            # measurement with a bound.
            payload["sha256"] = None
            payload["digest_not_computed"] = self.digest_reason
        if self.declared_sha256:
            payload["declared_sha256"] = self.declared_sha256
            payload["declared_by"] = self.declared_by or "unknown"
        return payload


@dataclass
class Bundle:
    """A resolved model repository: its members, its relations, its gaps."""

    root: str
    members: list[Member] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    base_model: str | None = None
    adapters: list[str] = field(default_factory=list)
    custom_code: list[str] = field(default_factory=list)
    remote_code_entrypoints: dict[str, str] = field(default_factory=dict)
    shards: dict[str, Any] = field(default_factory=dict)
    architectures: list[str] = field(default_factory=list)
    coverage: Coverage = field(default_factory=baseline)

    source_uri: str = ""
    source_revision: str = ""
    connector: str = ""
    # False when the listing that produced this directory could not be read in
    # full. Set by `remote.resolve_remote`; a local resolution walks the disk
    # and always sees everything that is there.
    listing_complete: bool = True

    @property
    def structural_digest(self) -> str:
        """A digest over the bundle's LAYOUT. Never over its weights.

        Design note D-200. This is what the v1 field `bundle_digest` actually
        was, under a name that says so. It moves when a file appears, when one
        is renamed, when a role changes, when a size changes - which is exactly
        the set of changes a layout drift check needs - and it does not move
        when the bytes inside an unhashed member change, because nothing here
        read them.

        The rename is the fix. A field called `bundle_digest` reads as the
        identity of the model, and two 8 GB weight files with the same name
        and size and different bytes produced the same value.
        """
        shape = json.dumps(
            [
                [member.path, member.size_bytes, member.role, member.sha256, member.declared_sha256]
                for member in self.members
            ],
            sort_keys=True,
            separators=(",", ":"),
        )
        return "sha256:" + hashlib.sha256(shape.encode("utf-8")).hexdigest()

    # Kept so nothing that imported it breaks, and deliberately pointing at
    # the renamed property rather than at a copy of the old computation.
    @property
    def digest(self) -> str:
        return self.structural_digest

    def content_identity(self) -> dict[str, Any]:
        """Whether anything here identifies WHICH weights these are.

        Four states, and the middle two are the interesting ones. COMPLETE
        means every member was hashed by this process. EXTERNALLY_BOUND means
        the ones that were not carry a digest somebody else published, and the
        document says whose. PARTIAL means some member has neither. UNAVAILABLE
        means none of them do.

        A receipt may say "the same model" on COMPLETE or EXTERNALLY_BOUND and
        must not on the other two, which is what `bundle_content_identity`
        exists for in the policy language.
        """
        weights = [member for member in self.members if member.role in ("weights", "index")]
        subject = weights or self.members
        hashed = [member for member in subject if member.sha256]
        declared_only = [member for member in subject if not member.sha256 and member.declared_sha256]
        unknown = [member for member in subject if not member.identity_known]

        if not subject:
            state = ContentIdentity.UNAVAILABLE
        elif unknown:
            state = ContentIdentity.PARTIAL if (hashed or declared_only) else ContentIdentity.UNAVAILABLE
        elif declared_only:
            state = ContentIdentity.EXTERNALLY_BOUND
        else:
            state = ContentIdentity.COMPLETE

        if hashed and declared_only:
            binding = "mixed"
        elif declared_only:
            binding = "connector_declared_digest"
        elif hashed:
            binding = "local_stream_hash"
        else:
            binding = "none"

        payload: dict[str, Any] = {
            "state": state.value,
            "members_hashed": len(hashed),
            # `members_unhashed` is the count this process did not read, however
            # their identity was otherwise established. It is kept alongside the
            # two finer counts because "how much did you actually read" is a
            # different question from "how much do you claim to know".
            "members_unhashed": len(declared_only) + len(unknown),
            "members_externally_bound": len(declared_only),
            "members_unidentified": len(unknown),
            "binding_source": binding,
            "digest": None,
            "covers": "weights and shard indexes" if weights else "every member",
        }
        if state is ContentIdentity.COMPLETE:
            # Only computable when every member in scope was hashed here. A
            # digest over a set that includes "unknown" would be a digest of a
            # gap, and it would look exactly like a digest of the model.
            payload["digest"] = "sha256:" + hashlib.sha256(
                json.dumps(
                    sorted((member.path, member.sha256) for member in subject),
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
        if declared_only:
            payload["declared_by"] = sorted({member.declared_by or "unknown" for member in declared_only})
        if unknown:
            payload["unidentified"] = sorted(member.path for member in unknown)[:20]
        return payload

    def to_dict(self) -> dict[str, Any]:
        provenance: dict[str, Any] = {}
        for key, value in (
            ("uri", self.source_uri),
            ("revision", self.source_revision),
            ("connector", self.connector),
        ):
            if value:
                provenance[key] = value
        document: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "root": self.root,
            "structural_digest": self.structural_digest,
            "content_identity": self.content_identity(),
            "members": [member.to_dict() for member in self.members],
            "architectures": self.architectures,
            "base_model": self.base_model,
            "adapters": self.adapters,
            "custom_code": self.custom_code,
            "remote_code_entrypoints": self.remote_code_entrypoints,
            "shards": self.shards,
            "findings": [finding.to_dict() for finding in self.findings],
            "coverage": self.coverage.to_dict(),
        }
        if provenance:
            document["provenance"] = provenance
        return document


def looks_like_bundle(root: Path) -> bool:
    return any((root / marker).is_file() for marker in BUNDLE_MARKERS)


def resolve(
    root: Path,
    *,
    hash_weights: bool = False,
    declared_digests: dict[str, tuple[str, str]] | None = None,
    source_uri: str = "",
    source_revision: str = "",
    connector: str = "",
) -> Bundle:
    """Walk a model repository and record what its files say about each other.

    `hash_weights` lifts the per-member digest budget, so every member is
    hashed however large it is. It is off by default and that is the right
    default: hashing 30 GB takes minutes, most resolutions do not need it, and
    a tool whose default resolution is slow is a tool people stop running.
    Turning it on is how a caller buys `content_identity: complete`.

    `declared_digests` maps a member path to `(sha256, who said so)`. A
    connector that published a digest for a file it served has bound that
    file's identity without anything here reading 30 GB. It is kept in its own
    field, never merged into the measured one.
    """
    root = Path(root)
    bundle = Bundle(
        root=str(root),
        source_uri=source_uri,
        source_revision=source_revision,
        connector=connector,
    )
    declared = declared_digests or {}
    bundle.coverage.set(
        SurfaceCoverage(Surface.ARCHIVE_STRUCTURE, CoverageState.COMPLETE, REASON_READ_IN_FULL)
    )
    bundle.coverage.set(
        SurfaceCoverage(Surface.ARTIFACT_METADATA, CoverageState.COMPLETE, REASON_READ_IN_FULL)
    )

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in (".git", "__pycache__", ".cache") for part in path.parts):
            continue
        relative = str(path.relative_to(root))
        size = path.stat().st_size
        member = _member(path, relative, size, hash_weights=hash_weights)
        if relative in declared:
            member.declared_sha256, member.declared_by = declared[relative]
        bundle.members.append(member)

    _read_config(root, bundle)
    _read_adapter(root, bundle)
    _read_index(root, bundle)
    _read_tokenizer(root, bundle)
    _flag_code(bundle)
    return bundle


def _member(path: Path, relative: str, size: int, *, hash_weights: bool = False) -> Member:
    role = _role_of(relative)
    if size > MAX_DIGEST_BYTES and not hash_weights:
        return Member(
            path=relative,
            size_bytes=size,
            role=role,
            digest_reason=(
                f"over the {MAX_DIGEST_BYTES}-byte budget for bundle resolution; "
                "pass --hash-weights to compute it"
            ),
        )
    return Member(path=relative, size_bytes=size, role=role, sha256=_stream_digest(path))


def _stream_digest(path: Path) -> str:
    """Hash a file without holding it. D-160 applies here as much as anywhere.

    `read_bytes()` was fine while nothing over 64 MiB was ever hashed.
    `--hash-weights` is exactly the flag that makes it not fine: it exists to
    be pointed at 30 GB of shards.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _role_of(relative: str) -> str:
    lowered = relative.lower()
    if lowered.endswith(".index.json"):
        return "index"
    if lowered.endswith((".safetensors", ".bin", ".pt", ".pth", ".gguf", ".onnx", ".h5", ".ckpt", ".npz")):
        return "weights"
    if lowered.endswith(EXECUTABLE_SUFFIXES):
        return "code"
    if lowered.endswith(PACKAGING_SUFFIXES) or lowered.endswith(("requirements.txt", "pyproject.toml")):
        return "packaging"
    if "tokenizer" in lowered or lowered.endswith(("vocab.json", "merges.txt", "spiece.model")):
        return "tokenizer"
    if lowered.endswith(".json") or lowered.endswith((".yaml", ".yml")):
        return "config"
    return "other"


def _load_json(path: Path, bundle: Bundle, rule_id: str) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        bundle.findings.append(
            Finding(
                rule_id=rule_id,
                severity=Severity.MEDIUM,
                location=path.name,
                evidence={"error": f"{type(exc).__name__}: {exc}"},
            )
        )
        bundle.coverage.set(
            SurfaceCoverage(Surface.ARTIFACT_METADATA, CoverageState.PARTIAL, REASON_PARSE_FAILED,
                            rules=(rule_id,))
        )
        return None


def _read_config(root: Path, bundle: Bundle) -> None:
    path = root / "config.json"
    if not path.is_file():
        return
    config = _load_json(path, bundle, "ACT-BDL-001")
    if config is None:
        return
    architectures = config.get("architectures")
    if isinstance(architectures, list):
        bundle.architectures = [str(item) for item in architectures]

    # `auto_map` is the mechanism, and it is worth stating plainly because it
    # is easy to read `trust_remote_code` as the dangerous part. It is not:
    # the flag is a consent prompt the caller answers. `auto_map` is the list
    # of Python modules in this repository that the flag consents TO, and a
    # repository carrying one is a repository that expects to run its own code
    # inside the loading process.
    auto_map = config.get("auto_map")
    if isinstance(auto_map, dict) and auto_map:
        entries = {str(key): str(value) for key, value in auto_map.items()}
        bundle.remote_code_entrypoints.update(entries)
        modules = sorted({str(value).split(".")[0] for value in entries.values()})
        bundle.findings.append(
            Finding(
                rule_id="ACT-BDL-002",
                severity=Severity.HIGH,
                location="config.json",
                evidence={
                    "auto_map": entries,
                    "modules": modules,
                    "executes_when": "the loader is called with trust_remote_code=True",
                },
            )
        )

    if config.get("trust_remote_code") is True:
        # A repository that ships the flag pre-answered. The consent prompt
        # exists so the caller decides; a config that answers it for them has
        # removed the only step where a human was in the loop.
        bundle.findings.append(
            Finding(
                rule_id="ACT-BDL-003",
                severity=Severity.HIGH,
                location="config.json",
                evidence={"trust_remote_code": True, "set_by": "the repository, not the caller"},
            )
        )


def _read_adapter(root: Path, bundle: Bundle) -> None:
    path = root / "adapter_config.json"
    if not path.is_file():
        return
    config = _load_json(path, bundle, "ACT-BDL-001")
    if config is None:
        return
    base = config.get("base_model_name_or_path")
    if base:
        bundle.base_model = str(base)
    bundle.adapters = sorted(
        member.path for member in bundle.members if "adapter" in member.path.lower() and member.role == "weights"
    )
    # An adapter is a diff against a base model. Without the base model's
    # digest the pair is unidentifiable: the same adapter over a different
    # base is a different model, and nothing in the repository records which
    # base was used. This is a gap, not a fault, and it is stated as one.
    if bundle.base_model and not config.get("base_model_sha256"):
        bundle.findings.append(
            Finding(
                rule_id="ACT-BDL-004",
                severity=Severity.MEDIUM,
                location="adapter_config.json",
                evidence={
                    "base_model": bundle.base_model,
                    "base_model_digest": None,
                    "consequence": "the adapter cannot be bound to the base model it was trained against",
                },
            )
        )


def _read_index(root: Path, bundle: Bundle) -> None:
    """Check the shard index against the shards actually present.

    A missing shard is not a security finding on its own - the loader will
    fail loudly - but an EXTRA weight file the index does not mention is a
    file nobody accounted for, and a repository whose index and contents
    disagree is one whose digest nobody can reproduce.
    """
    indexes = [member for member in bundle.members if member.role == "index"]
    if not indexes:
        return
    for index_member in indexes:
        document = _load_json(root / index_member.path, bundle, "ACT-BDL-001")
        if document is None:
            continue
        weight_map = document.get("weight_map")
        if not isinstance(weight_map, dict):
            continue
        promised = sorted(set(str(value) for value in weight_map.values()))
        present = {member.path for member in bundle.members if member.role == "weights"}
        missing = sorted(name for name in promised if name not in present)
        extra = sorted(
            name for name in present
            if name not in promised and not name.startswith("adapter")
        )
        bundle.shards[index_member.path] = {
            "promised": promised,
            "missing": missing,
            "unlisted": extra,
            "tensors": len(weight_map),
        }
        if missing:
            bundle.findings.append(
                Finding(
                    rule_id="ACT-BDL-005",
                    severity=Severity.MEDIUM,
                    location=index_member.path,
                    evidence={"missing": missing[:20], "count": len(missing)},
                )
            )
            bundle.coverage.set(
                SurfaceCoverage(
                    Surface.ARCHIVE_STRUCTURE,
                    CoverageState.PARTIAL,
                    REASON_PARSE_FAILED,
                    rules=("ACT-BDL-005",),
                )
            )
        if extra:
            bundle.findings.append(
                Finding(
                    rule_id="ACT-BDL-006",
                    severity=Severity.MEDIUM,
                    location=index_member.path,
                    evidence={"unlisted": extra[:20], "count": len(extra)},
                )
            )


def _read_tokenizer(root: Path, bundle: Bundle) -> None:
    """A chat template is a Jinja program that runs on every request.

    It does not run inside the loader, so it is not the same class of risk as
    `auto_map`, and it is reported at MEDIUM rather than HIGH. But it is code
    shipped with a model, rendered over untrusted input, and a repository that
    carries one should not be able to do so without the report saying so.
    """
    path = root / "tokenizer_config.json"
    if not path.is_file():
        return
    config = _load_json(path, bundle, "ACT-BDL-001")
    if config is None:
        return
    template = config.get("chat_template")
    templates = template if isinstance(template, list) else ([template] if template else [])
    for item in templates:
        text = item.get("template") if isinstance(item, dict) else item
        if not isinstance(text, str) or not _JINJA_CALL.search(text):
            continue
        bundle.findings.append(
            Finding(
                rule_id="ACT-BDL-007",
                severity=Severity.MEDIUM,
                location="tokenizer_config.json",
                evidence={
                    "chat_template_bytes": len(text),
                    "contains": "jinja control flow or a call",
                    "renders_over": "whatever text the caller passes at inference time",
                },
            )
        )
        break


def _flag_code(bundle: Bundle) -> None:
    """Executable files in a model repository, named.

    Not a finding about their contents - `scan` inspects artifacts, and a
    `.py` file is source, not a serialised object. This is a finding about
    their presence: a directory a loader will import from, with importable
    modules in it. Whether that is acceptable is a policy question, and the
    policy cannot ask it if the report never mentioned them.
    """
    code = sorted(member.path for member in bundle.members if member.role == "code")
    packaging = sorted(member.path for member in bundle.members if member.role == "packaging")
    bundle.custom_code = code
    if not code:
        return
    reachable = sorted(
        name for name in code
        if any(name.startswith(entry.split(".")[0]) for entry in bundle.remote_code_entrypoints.values())
    )
    bundle.findings.append(
        Finding(
            rule_id="ACT-BDL-008",
            severity=Severity.HIGH if reachable else Severity.MEDIUM,
            location=artifact_name(bundle.root),
            evidence={
                "files": code[:20],
                "count": len(code),
                "named_by_auto_map": reachable,
                "packaging": packaging[:10],
            },
        )
    )
