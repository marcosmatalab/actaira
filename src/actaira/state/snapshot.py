"""What a source looked like at one moment, written so two of them can be compared.

Design note D-222. A discovery run produces a list of artifacts and, today,
prints it. Printing is enough to answer "what is there" and useless for "what
changed", because comparing two runs then means parsing two logs and hoping the
ordering was stable.

So a snapshot is a document with three properties, and each one is load-bearing.

**It is canonical.** Artifacts are sorted by URI and every field is emitted in
a fixed order, so the same listing in a different order produces the same
digest. Without that, a connector that paginated differently on Tuesday would
report that every artifact had changed.

**It distinguishes an incomplete listing from an empty one.** `listing_complete`
is false when the connector could not enumerate everything - a page that failed,
a budget that ran out, a permission that was refused. A snapshot that recorded
"nine artifacts" in both cases would let a failed listing look like eight
deletions, which is the single worst thing a change detector can do.

**It carries no secrets.** Tokens, signed URLs and headers never enter it. The
snapshot is the thing an operator commits to a repository or attaches to a
receipt, and a document that might contain a credential is one nobody can share.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "source-snapshot/v1"

# Field names that never reach a snapshot, matched case-insensitively as
# substrings. Deliberately broad: a snapshot missing a field is a smaller
# problem than a snapshot carrying a bearer token into a receipt.
_SECRET_HINTS = ("token", "secret", "password", "authorization", "auth", "credential", "signature",
                 "sig", "key", "cookie", "session")


@dataclass(frozen=True)
class SnapshotArtifact:
    """One thing the source is serving, and how firmly it is identified.

    `declared_sha256` is exactly that - declared. It is what the registry
    published, never something this process computed, and it feeds
    `Bundle.declared_digests` under the same name so the distinction survives
    all the way into the model bundle document (D-200).

    `measured_sha256` is the opposite: bytes this process read. Only a local
    source can produce one, and `watch` does, because the alternative was
    DEF-74 - a local model directory is the default case, the filesystem
    connector publishes no digests by design, and comparison fell back to file
    size. A weight file replaced with different bytes of the same length came
    back UNCHANGED, exit 0, with nothing saying the comparison had been weak.

    `identity_basis` says which of the three was used, and it is emitted on
    every artifact rather than only on the weak ones. A field that appears
    only when something is wrong is a field readers learn to stop looking for.
    """

    uri: str
    size_bytes: int = 0
    declared_sha256: str = ""
    measured_sha256: str = ""
    revision: str = ""
    path: str = ""

    @property
    def identity_basis(self) -> str:
        if self.measured_sha256:
            return "measured_digest"
        if self.declared_sha256:
            return "declared_digest"
        return "size_only"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "uri": self.uri,
            "size_bytes": self.size_bytes,
            "identity_basis": self.identity_basis,
        }
        for key, value in (
            ("declared_sha256", self.declared_sha256),
            ("measured_sha256", self.measured_sha256),
            ("revision", self.revision),
            ("path", self.path),
        ):
            if value:
                payload[key] = value
        return payload


@dataclass
class Snapshot:
    """One observation of one source."""

    source_id: str
    uri: str
    connector: str
    observed_at: str
    revision: str = ""
    listing_complete: bool = True
    artifacts: list[SnapshotArtifact] = field(default_factory=list)
    incomplete_because: str = ""
    hosts_contacted: list[str] = field(default_factory=list)

    @property
    def digest(self) -> str:
        """Over the content, never over the observation time.

        Two observations of an unchanged source must produce the same digest,
        or `watch` would report a change every time it ran. So `observed_at`
        is in the document and out of the digest, and the digest answers "is
        this the same listing" rather than "is this the same run".
        """
        body = {
            "source": self.uri,
            "connector": self.connector,
            "revision": self.revision,
            "listing_complete": self.listing_complete,
            "artifacts": [artifact.to_dict() for artifact in self._sorted()],
        }
        blob = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _sorted(self) -> list[SnapshotArtifact]:
        return sorted(self.artifacts, key=lambda artifact: (artifact.uri, artifact.path))

    def by_uri(self) -> dict[str, SnapshotArtifact]:
        return {artifact.uri: artifact for artifact in self._sorted()}

    def to_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "source": self.uri,
            "source_id": self.source_id,
            "connector": self.connector,
            "revision": self.revision,
            "listing_complete": self.listing_complete,
            "observed_at": self.observed_at,
            "artifacts": [artifact.to_dict() for artifact in self._sorted()],
            "snapshot_digest": self.digest,
        }
        if not self.listing_complete:
            # Never omitted when the listing is partial. "Incomplete" with no
            # reason reads as a bug in Actaira rather than as a fact about the
            # source, and an operator cannot act on it.
            document["incomplete_because"] = self.incomplete_because or "the connector did not say"
        if self.hosts_contacted:
            document["hosts_contacted"] = sorted(set(self.hosts_contacted))
        return document


def _text(value: Any) -> str:
    """`str(value)` with `None` mapped to empty, which `str(None)` does not.

    Defect DEF-75. `str(clean.get("revision", ""))` returns the default only
    when the key is ABSENT, and `RemoteArtifact.to_dict()` always emits
    `revision`, set to `None` by the filesystem and S3 connectors. So every
    snapshot carried the literal string `"None"` - inside the digest, and
    inside the document D-222 calls the thing an operator commits to a
    repository.
    """
    return "" if value is None else str(value)


def _size(*candidates: Any) -> int:
    """A size, or zero, and never an exception.

    A connector reading an operator's index file can hand over `"12 MB"` or a
    list. `int()` on either raises, and it raised outside `_list_source`'s
    careful "every failure ends in an incomplete listing" guard, so the whole
    command died with a traceback rather than reporting a source it could not
    read.
    """
    for value in candidates:
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return max(0, value)
        if isinstance(value, str):
            try:
                return max(0, int(value.strip()))
            except ValueError:
                continue
    return 0


def _local_path(uri: str, path: str) -> Path:
    """The file a `file:` URI names, on the platform this is running on.

    Defect DEF-114, and it is the reason DEF-74's fix has never once worked on
    Windows. The old line was `uri[len("file://"):]`, which turns
    `file:///home/u/m.pt` into `/home/u/m.pt` and is right, and turns
    `file:///C:/Users/u/m.pt` into `/C:/Users/u/m.pt`, which is not a path
    Windows has. `is_file()` then returned False, `_measure` returned "", no
    digest was ever measured, and every local `watch` on Windows silently fell
    back to comparing sizes.

    That is exactly the failure DEF-74 exists to prevent - a weight file
    replaced by different bytes of the same length reads as UNCHANGED, exit 0 -
    reintroduced on one platform by a string slice. Nothing caught it because
    the fix was correct on the platform CI runs on, which is the shape of bug
    a hand-rolled URI parse produces: right on the developer's machine,
    quietly wrong on somebody else's.

    `url2pathname` is the stdlib function for this and it is per-platform by
    construction. Percent-escapes are decoded too, so a directory with a space
    in it stops being a file this tool cannot find.
    """
    if not uri.startswith("file:"):
        return Path(path or uri)

    from urllib.parse import urlparse
    from urllib.request import url2pathname

    parsed = urlparse(uri)
    candidates = [Path(url2pathname(parsed.path))]
    if parsed.netloc:
        # `file://C:\dir\w.bin`: two slashes and a Windows path, which puts
        # the drive in the authority. Not what `Path.as_uri()` emits and very
        # much what a hand-written URI looks like, including the one in this
        # repository's own DEF-74 fixture - which is how DEF-114 survived a
        # regression test written for it. Accepted, because the alternative is
        # `_measure` returning "" and the comparison silently falling back to
        # a byte count, which is the failure being defended against.
        candidates.append(Path(uri[len("file://"):]))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def _measure(uri: str, path: str) -> str:
    """Hash a local artifact, because the bytes are right there.

    DEF-74. The filesystem connector does not publish digests - it is a
    directory, nobody signed it - and comparison then fell back to size, which
    cannot see a weight file replaced with different bytes of the same length.
    A remote source has to be taken at its word; a local one does not, and
    reading it is the difference between a watch that works on the default
    case and one that does not.
    """
    local = _local_path(uri, path)
    if not local.is_file():
        return ""
    digest = hashlib.sha256()
    try:
        with local.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        # A file that disappeared between listing and hashing is a file this
        # snapshot cannot identify, which is what an empty digest means.
        return ""
    return digest.hexdigest()


def scrub(payload: dict[str, Any]) -> dict[str, Any]:
    """Drop anything whose name suggests it is a credential.

    Broad on purpose, and applied to connector output before it becomes a
    snapshot. The cost of dropping a field named `key` that was not a key is
    a missing line in a document; the cost of keeping one that was is a
    credential in a file somebody commits.
    """
    clean: dict[str, Any] = {}
    for name, value in payload.items():
        if any(hint in name.lower() for hint in _SECRET_HINTS):
            continue
        clean[name] = scrub(value) if isinstance(value, dict) else value
    return clean


def snapshot_of(
    source_id: str,
    uri: str,
    connector: str,
    artifacts: list[dict[str, Any]],
    *,
    revision: str = "",
    listing_complete: bool = True,
    incomplete_because: str = "",
    hosts_contacted: list[str] | None = None,
    observed_at: str | None = None,
    measure_local: bool = False,
) -> Snapshot:
    """Build a snapshot from whatever a connector's listing looked like.

    The mapping is deliberately forgiving about field names, because the
    connectors predate this module and each one names things the way its
    service does. It is not forgiving about secrets: every row goes through
    `scrub` first.
    """
    rows: list[SnapshotArtifact] = []
    for raw in artifacts:
        clean = scrub(raw)
        uri_value = _text(clean.get("uri") or clean.get("url") or clean.get("path"))
        if not uri_value:
            continue
        measured = ""
        if measure_local:
            measured = _measure(uri_value, _text(clean.get("path")))
        rows.append(
            SnapshotArtifact(
                uri=uri_value,
                size_bytes=_size(clean.get("size"), clean.get("size_bytes")),
                declared_sha256=_text(
                    raw.get("declared_sha256") or raw.get("sha256") or raw.get("digest")
                ),
                measured_sha256=measured,
                revision=_text(clean.get("revision")),
                path=_text(clean.get("path")),
            )
        )
    return Snapshot(
        source_id=source_id,
        uri=uri,
        connector=connector,
        observed_at=observed_at or datetime.now(UTC).isoformat(),
        revision=revision,
        listing_complete=listing_complete,
        artifacts=rows,
        incomplete_because=incomplete_because,
        hosts_contacted=list(hosts_contacted or []),
    )
