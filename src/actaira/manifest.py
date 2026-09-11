"""A list of things to decide about, when they are not all files on disk.

Design note D-213. `actaira policy check` took paths, scanned them, and
decided. That works while every subject is an artifact and stops working the
moment one is not: a model repository is a directory, an agent is a
declaration, and a system is a name for a group of both. A command whose only
input is a path cannot express "decide about this agent, this bundle and the
source they came from, under one policy".

So there is a small document that names subjects and their kinds. It is
deliberately thin - it points at things, it does not describe them - because
everything it points at already has a loader that knows how to read it, and a
manifest that restated what a declaration says would be a second place for the
same fact to go stale.

    schema_version: subject-manifest/v1
    system: fraud-review
    subjects:
      - kind: artifact
        path: models/fraud.pt
      - kind: bundle
        path: models/fraud/
        hash_weights: true
      - kind: agent
        path: agents/fraud-review.yaml
      - kind: source
        uri: huggingface://acme/fraud-model
        revision: 7f91a2c
      - kind: system
        name: fraud-review
        uses:
          - agent:fraud-review
          - bundle:fraud

`uses` is the one relation this document declares itself, and it is declared
rather than inferred on purpose (design note D-224). Two subjects being in the
same manifest does not make one depend on the other, and an impact report built
on that assumption would list everything in the file - technically complete,
practically useless, and exactly the kind of answer that teaches people to
ignore impact reports.

What it does not do is accept a subject with no loader. An unknown `kind` is
refused rather than skipped: a manifest listing four subjects and governing
three is the failure mode this file exists to prevent.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .miniyaml import loads as parse_yaml
from .subject import SubjectKind

SCHEMA_VERSION = "subject-manifest/v1"


class ManifestError(ValueError):
    """A manifest that cannot be loaded. Never a warning."""


@dataclass(frozen=True)
class Entry:
    kind: SubjectKind
    path: Path | None = None
    uri: str = ""
    revision: str = ""
    connector: str = ""
    name: str = ""
    hash_weights: bool = False
    uses: tuple[str, ...] = ()
    facts: dict[str, Any] = field(default_factory=dict)


@dataclass
class Manifest:
    system: str = ""
    entries: list[Entry] = field(default_factory=list)
    source: str = ""


def load(path: Path) -> Manifest:
    return load_text(Path(path).read_text(encoding="utf-8"), source=str(path), base=Path(path).parent)


def load_text(text: str, source: str = "", base: Path | None = None) -> Manifest:
    try:
        document = parse_yaml(text)
    except ValueError as exc:
        raise ManifestError(f"manifest does not parse: {exc}") from exc
    if not isinstance(document, dict):
        raise ManifestError("a subject manifest must be a mapping at the top level")

    declared = str(document.get("schema_version", SCHEMA_VERSION))
    if declared != SCHEMA_VERSION:
        raise ManifestError(
            f"this manifest declares {declared!r} and this release reads {SCHEMA_VERSION!r}. "
            "Reading a document whose version you do not know is how a field quietly changes meaning."
        )

    raw = document.get("subjects")
    if not isinstance(raw, list) or not raw:
        raise ManifestError("a subject manifest needs a non-empty `subjects:` list")

    base = base or Path()
    entries: list[Entry] = []
    for index, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            raise ManifestError(f"subject {index} is not a mapping")
        try:
            kind = SubjectKind(str(item.get("kind", "")))
        except ValueError:
            raise ManifestError(
                f"subject {index}: {item.get('kind')!r} is not a kind. Known: "
                f"{', '.join(member.value for member in SubjectKind)}"
            ) from None
        path = item.get("path")
        entry = Entry(
            kind=kind,
            path=(base / str(path)) if path else None,
            uri=str(item.get("uri", "")),
            revision=str(item.get("revision", "")),
            connector=str(item.get("connector", "")),
            name=str(item.get("name", "")),
            hash_weights=bool(item.get("hash_weights", False)),
            uses=_names(item.get("uses"), index),
            facts=dict(item.get("facts") or {}),
        )
        _check(entry, index)
        entries.append(_named(entry))

    manifest = Manifest(system=str(document.get("system", "")), entries=entries, source=source)
    _check_references(manifest)
    return manifest


def _check_references(manifest: Manifest) -> None:
    """A `uses` edge must point at something in this manifest.

    Same argument as the agent loader's intra-document references (D-204): the
    target is a few lines away, so a dangling one is a typo the author can
    see, and accepting it would put an edge in the graph pointing at a node
    that does not exist - which reads, downstream, as a dependency nobody can
    find rather than as a misspelling.
    """
    known = {handle(entry, manifest.system) for entry in manifest.entries}
    for entry in manifest.entries:
        dangling = sorted(name for name in entry.uses if name not in known)
        if dangling:
            raise ManifestError(
                f"{handle(entry, manifest.system)} uses {', '.join(dangling)}, which this manifest "
                f"does not declare. Declared: {', '.join(sorted(known))}."
            )


def _names(value: Any, index: int) -> tuple[str, ...]:
    """A list of handles, and never a string iterated letter by letter.

    Part of defect DEF-94. `tuple(str(name) for name in value)` over a string
    produces one entry per CHARACTER, so a `uses:` line this parser had not
    understood became a claim to depend on ":", "[", "]", "a", "b"... and the
    reference check refused the document with a message listing single
    letters. A string here is a mistake worth naming, not one to iterate.
    """
    if value is None:
        return ()
    if isinstance(value, str):
        raise ManifestError(
            f"subject {index}: `uses:` must be a list of handles, not the string {value!r}. "
            "Write it as `uses: [agent:x]` or as a block list."
        )
    if not isinstance(value, list):
        raise ManifestError(f"subject {index}: `uses:` must be a list, got {type(value).__name__}")
    return tuple(str(name) for name in value)


def handle(entry: Entry, fallback_system: str = "") -> str:
    """The stable node name for one manifest entry.

    The same `kind:id` spelling `SubjectRef.handle` uses, so a manifest, a
    graph, a policy proof and a receipt all name the same thing the same way.
    Three spellings for one asset is how an impact report ends up reporting
    that nothing depends on a model that three things depend on.

    Defect DEF-84: this used `Path(entry.path).stem`, which agreed with
    `SubjectRef` for neither of the two kinds that have a path.
    `models/fraud.pt` became `artifact:fraud` where the reference says
    `artifact:fraud.pt`, so `models/fraud.pt` and `models/fraud.onnx`
    collided onto one node; and an agent in `agents/fraud-review-v2.yaml`
    declaring `agent: fraud-review` became `agent:fraud-review-v2`, so the
    correct handle in a `uses:` line was refused as undeclared and a
    `delegates_to` edge could never reach a manifest node. The declared name
    wins where there is one, and the file name - extension and all - where
    there is not.
    """
    if entry.kind is SubjectKind.SYSTEM:
        return f"system:{entry.name or fallback_system}"
    if entry.kind is SubjectKind.SOURCE:
        return f"source:{entry.uri}"
    if entry.name:
        return f"{entry.kind.value}:{entry.name}"
    return f"{entry.kind.value}:{Path(entry.path).name if entry.path else ''}"


def _named(entry: Entry) -> Entry:
    """Fill in an agent's declared name, so its handle matches its reference.

    Part of DEF-84. An agent is identified by the `agent:` line inside its
    declaration, not by what somebody called the file, and `SubjectRef` uses
    the first. Reading it here - once, at load - is what keeps `uses:`,
    `delegates_to` and a policy proof talking about the same node.
    """
    if entry.kind is not SubjectKind.AGENT or entry.name or entry.path is None:
        return entry
    try:
        document = parse_yaml(entry.path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # Not this function's error to raise. The agent loader will read the
        # same file, with a message that says what is wrong with it.
        return entry
    declared = document.get("agent") if isinstance(document, dict) else None
    return replace(entry, name=str(declared)) if declared else entry


def _check(entry: Entry, index: int) -> None:
    """Each kind needs what its loader needs, and says so at load time.

    A manifest that parsed and then failed halfway through the run would have
    already produced half a decision, and a half-evaluated policy is worse
    than an unloadable manifest: it looks like an answer.
    """
    if entry.kind in (SubjectKind.ARTIFACT, SubjectKind.BUNDLE, SubjectKind.AGENT):
        if entry.path is None:
            raise ManifestError(f"subject {index}: a {entry.kind.value} needs a `path:`")
        if not entry.path.exists():
            raise ManifestError(f"subject {index}: {entry.path} does not exist")
    elif entry.kind is SubjectKind.SOURCE and not entry.uri:
        raise ManifestError(f"subject {index}: a source needs a `uri:`")
    elif entry.kind is SubjectKind.SYSTEM and not entry.name:
        raise ManifestError(f"subject {index}: a system needs a `name:`")
