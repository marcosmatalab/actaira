"""Resolving a model repository that is not on this disk yet.

Design note D-229. `actaira bundle` took a local path and `actaira discover`
knew how to reach Hugging Face, GitHub, S3, OCI, MLflow and a plain URL, and
nothing joined the two. An operator who wanted to ask "what does this published
model's repository say about itself" had to download it by hand, remember where
they put it, and lose the one fact that makes the answer auditable: which
revision of which source those bytes came from.

This is the join, and it has three properties worth the module.

**Provenance survives into the document.** The bundle carries the URI, the
revision and the connector, so a receipt about it can say where the bytes came
from rather than naming a temporary directory on somebody's laptop.

**A digest the registry published is carried as a declaration, never as a
measurement.** It reaches `Bundle.declared_digests` and comes out the other
side under `declared_sha256` with the connector's name beside it. That is what
makes `content_identity: externally_bound` possible on a 30 GB repository
without reading 30 GB - and what stops it from ever being reported as
`complete`, which would be this tool claiming it did the reading.

**An incomplete listing cannot produce a complete identity.** A connector that
could not enumerate the whole source has not shown you the whole model, so the
resolution is marked and the identity state is capped. A repository resolved
from half a listing that reported `complete` would be the same class of error
as a digest over a gap.

The cache is content-addressed and optional. Nothing is ever read from it
without a digest to check it against: a cache entry trusted by its filename is
a cache entry an attacker with write access to `.actaira/` gets to choose.
"""
from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .bundle import Bundle, resolve
from .coverage import REASON_BUDGET_EXHAUSTED, CoverageState, Surface, SurfaceCoverage
from .model import Finding, Severity

CACHE_DIRECTORY = ".actaira/cache"


class RemoteBundleError(RuntimeError):
    """The repository could not be brought here. Never a partial resolution."""


@dataclass
class Fetched:
    """Where the bytes landed, and what the source said about them."""

    root: Path
    uri: str
    connector: str
    revision: str
    declared: dict[str, tuple[str, str]]
    listing_complete: bool
    incomplete_because: str = ""
    hosts_contacted: tuple[str, ...] = ()
    from_cache: bool = False
    # Everything the connector said that is not a failure. Carried because
    # "--revision was ignored" is exactly the kind of remark that used to be
    # dropped on the floor when the listing happened to be complete (DEF-86).
    notes: tuple[str, ...] = ()


def cache_key(uri: str, revision: str) -> str:
    """A directory name derived from what was asked for, not from what came back.

    Both halves are in it, because the same URI at two revisions is two
    different sets of bytes and a cache keyed on the URI alone would serve the
    first one forever.
    """
    return hashlib.sha256(f"{uri}@{revision}".encode()).hexdigest()[:32]


def fetch(
    uri: str,
    *,
    revision: str | None = None,
    destination: Path,
    offline: bool = False,
    cache: Path | None = None,
) -> Fetched:
    """Bring a remote repository here, keeping what the source declared.

    Everything the connector could not promise is carried out rather than
    smoothed over: `listing_complete` and the reason behind it travel into the
    bundle resolution, because a repository assembled from half a listing is
    not the repository.
    """
    from .connectors import registry as connector_registry
    from .connectors.model import ConnectorError, Http, stage

    try:
        connector = connector_registry.for_uri(uri)
    except ConnectorError as exc:
        raise RemoteBundleError(str(exc)) from exc

    if offline and connector.needs_network:
        raise RemoteBundleError(
            f"{connector.name} needs the network and --offline was given. The contradiction is "
            "refused here rather than reported as a connector that happened to fail."
        )

    http = Http(offline=offline)
    try:
        discovery = connector.discover(uri, http=http, revision=revision)
    except ConnectorError as exc:
        raise RemoteBundleError(f"{connector.name} could not list {uri}: {exc}") from exc

    # The connector's answer only. Defect DEF-86: this used to fall back to
    # `revision or ""`, so `actaira bundle file:///models/x --revision 7f91a2c`
    # wrote `7f91a2c` into the provenance of a plain directory - and the
    # filesystem connector had said, in a note this code discarded, that a
    # directory has no revisions and the flag was ignored. Feeding that
    # provenance to `source_revision_pinned` then satisfied an immutability
    # requirement on the strength of a string the operator typed.
    resolved_revision = str(discovery.revision or "")
    notes = list(discovery.notes)
    if revision and not resolved_revision:
        notes.append(
            f"--revision {revision} was ignored: {connector.name} did not resolve a revision for "
            "this source"
        )

    declared_all = {
        artifact.path: (artifact.declared_sha256.lower(), connector.name)
        for artifact in discovery.artifacts
        if artifact.declared_sha256
    }

    if not connector.needs_network:
        # A local source is already here. Copying it into a staging directory
        # to resolve it would double the disk cost of the largest thing this
        # tool touches, and it would make the bundle's `root` a temporary
        # path in every report about a model on this machine.
        local = _local_root(uri, discovery)
        if local is None:
            raise RemoteBundleError(
                f"{connector.name} listed {uri} and none of its artifacts are readable as local files"
            )
        return Fetched(
            root=local,
            uri=uri,
            connector=connector.name,
            revision=resolved_revision,
            # Whatever this connector published, even though the only local
            # connector today publishes nothing. A hard-coded `{}` would drop
            # them silently the day one does.
            declared=declared_all,
            listing_complete=bool(discovery.complete),
            incomplete_because="; ".join(notes) if not discovery.complete else "",
            notes=tuple(notes),
            hosts_contacted=tuple(discovery.hosts_contacted),
        )

    declared = declared_all

    if cache is not None:
        cached = Path(cache) / cache_key(uri, resolved_revision)
        if cached.is_dir() and _cache_is_intact(cached, declared):
            # Only ever accepted when every file it holds matches a digest the
            # source published. A cache entry trusted by its filename is an
            # entry that whoever can write to `.actaira/` gets to choose.
            return Fetched(
                root=cached,
                uri=uri,
                connector=connector.name,
                revision=resolved_revision,
                declared=declared,
                listing_complete=bool(discovery.complete),
                incomplete_because="; ".join(notes) if not discovery.complete else "",
                notes=tuple(notes),
                hosts_contacted=tuple(discovery.hosts_contacted),
                from_cache=True,
            )

    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    result = stage(discovery.artifacts, destination, http, connector.fetch_headers)
    problems = result.get("problems") or []
    if problems:
        # A repository missing files is not a repository, and resolving one
        # anyway would produce a bundle document that looks like a model with
        # pieces deliberately left out.
        detail = "; ".join(f"{row['path']}: {row.get('detail', row.get('rule', ''))}" for row in problems[:5])
        raise RemoteBundleError(f"{len(problems)} artifact(s) could not be staged: {detail}")

    if cache is not None:
        target = Path(cache) / cache_key(uri, resolved_revision)
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(destination, target)

    return Fetched(
        root=destination,
        uri=uri,
        connector=connector.name,
        revision=resolved_revision,
        declared=declared,
        listing_complete=bool(discovery.complete),
        incomplete_because="; ".join(notes) if not discovery.complete else "",
        notes=tuple(notes),
        hosts_contacted=tuple(discovery.hosts_contacted),
    )


def _local_root(uri: str, discovery: Any) -> Path | None:
    """The directory a local listing came out of, from the URI or its artifacts.

    The URI first, because that is what the operator typed and what the report
    should name. The artifacts are the fallback for a connector whose URI is
    not itself a path.
    """
    candidate = uri
    for prefix in ("file://", "filesystem://"):
        if candidate.startswith(prefix):
            candidate = candidate[len(prefix):]
            break
    path = Path(candidate).expanduser()
    if path.is_dir():
        return path
    if path.is_file():
        return path.parent
    for artifact in discovery.artifacts:
        local = Path(str(artifact.uri).removeprefix("file://"))
        if local.is_file():
            return local.parent
    return None


def _cache_is_intact(root: Path, declared: dict[str, tuple[str, str]]) -> bool:
    if not declared:
        # Nothing to check it against. A cache with no digests is a directory
        # somebody could have edited, and serving it would be trusting the
        # filesystem to be the source.
        return False
    for relative, (digest, _who) in declared.items():
        path = root / relative
        if not path.is_file():
            return False
        if _stream_digest(path) != digest:
            return False
    return True


def _stream_digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def resolve_remote(fetched: Fetched, *, hash_weights: bool = False) -> Bundle:
    """Resolve the staged repository, carrying everything the source said.

    The one rule this function adds on top of `bundle.resolve`: an incomplete
    listing caps what the resolution may claim. See D-229 - a bundle assembled
    from half a listing that reported `complete` would be a digest over a gap,
    wearing the name of a digest over a model.
    """
    bundle = resolve(
        fetched.root,
        hash_weights=hash_weights,
        declared_digests=fetched.declared,
        source_uri=fetched.uri,
        source_revision=fetched.revision,
        connector=fetched.connector,
    )
    if not fetched.listing_complete:
        bundle.findings.append(
            Finding(
                rule_id="ACT-BDL-009",
                severity=Severity.MEDIUM,
                location=fetched.uri,
                evidence={
                    "connector": fetched.connector,
                    "reason": fetched.incomplete_because or "the connector did not say",
                    "consequence": (
                        "files this listing did not reach are not in this resolution, so the "
                        "relations it reports are over part of the repository"
                    ),
                },
            )
        )
        bundle.coverage.set(
            SurfaceCoverage(
                Surface.ARCHIVE_STRUCTURE,
                CoverageState.PARTIAL,
                REASON_BUDGET_EXHAUSTED,
                rules=("ACT-BDL-009",),
            )
        )
        bundle.listing_complete = False
    return bundle


def capped_identity(bundle: Bundle, listing_complete: bool) -> dict[str, Any]:
    """`content_identity`, with the cap an incomplete listing imposes applied.

    Separate from `Bundle.content_identity` on purpose. That method answers
    "what do I know about the members I have", which is a question about this
    directory and should not need to know how the directory was assembled.
    This one answers "what may a receipt claim", which does.
    """
    identity = dict(bundle.content_identity())
    if listing_complete:
        return identity
    if identity["state"] == "complete":
        identity["state"] = "partial"
        identity["digest"] = None
        identity["capped_because"] = (
            "the source listing was incomplete, so every member present was identified and the "
            "set of members was not"
        )
    return identity
