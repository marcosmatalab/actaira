"""A local manifest of URLs: the last-resort connector, and the honest one.

Design note D-91, and why a tool with six real connectors still needs this one.

The six sources in this package cover most of where model artifacts live, and
they will never cover all of it. Somebody's models are on an internal Artifactory,
or behind a signed CDN, or on a vendor portal that has no API worth the name. The
choice for that operator is between waiting for a connector nobody is writing and
having no supply-chain tooling at all, and this file is the third option: write
the URLs in a file, point Actaira at the file, and get the same enumeration, the
same digest check and the same report as a HuggingFace repository would give.

It is also the connector that makes the rest of the package auditable, because
it is the one whose behaviour an operator can predict completely. Every other
file here trusts a remote index; this one trusts a file the operator wrote.

Design note D-91b, on the one sentence `complete` is allowed to mean here.

The manifest is read from disk in full, so the listing is complete *as a
reading of the manifest*: nothing was paginated, nothing was hidden by a
permission, and if a line was rejected then `complete` is False and the note
names how many. What it cannot mean, and the note says this on every run, is
that the manifest lists everything the upstream source holds. Nobody knows that
except the person who wrote the file, and the tool has no way to check it. This
distinction is the entire reason the field is called `complete` and not
`everything`, and stating it here rather than assuming the reader infers it is
the difference between a note and a disclaimer.

Design note D-91c, on the two formats and what each one gives up.

Plain lines are the format somebody produces with `grep` and a pipe: one URL
per line, `#` for a comment, blank lines ignored. There is nowhere to put a
digest, so nothing is checked, and the notes say how many artifacts arrived
that way.

JSON is the format with a digest in it: a list of objects with `uri`, an
optional `path` and an optional `sha256`, or the same list under an
`artifacts` key. A `sha256` here goes straight into `declared_sha256`, which
means the operator's file becomes the source that makes a claim, and a fetch
that disagrees with it is `ACT-CON-002` exactly as a fetch that disagrees with
HuggingFace is. That is the point: a digest somebody wrote down before the
download is the only digest in this whole package that was not supplied by the
same party that supplied the bytes.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path

from ..io_budget import read_at_most
from .model import Connector, ConnectorError, Discovery, Http, RemoteArtifact
from .registry import register

NAME = "url"
PREFIXES = ("manifest:", "urls:")
# A manifest is a text file somebody wrote. This is not a security bound so
# much as a "you pointed me at a checkpoint" bound.
MAX_MANIFEST_BYTES = 4 << 20
MAX_LINES = 100_000
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def accepts(uri: str) -> bool:
    """An explicit `manifest:` prefix, or the path of an existing file.

    A *file*, never a directory: that is the line that keeps this predicate
    disjoint from the filesystem connector's, which accepts directories only.
    See design note D-84.
    """
    if uri.lower().startswith(PREFIXES):
        return True
    return _as_file(uri) is not None


def _as_file(uri: str) -> Path | None:
    candidate = uri
    for prefix in PREFIXES:
        if candidate.lower().startswith(prefix):
            candidate = candidate[len(prefix):]
            break
    if candidate.startswith("file://"):
        candidate = candidate[len("file://"):]
    try:
        path = Path(candidate).expanduser()
        return path if path.is_file() else None
    except (OSError, ValueError):
        return None


def discover(uri: str, *, http: Http, revision: str | None = None) -> Discovery:
    """Read the manifest and turn every usable line into an artifact.

    `http` is accepted and unused: this connector reads a local file and
    contacts nothing. The URLs it lists are fetched later, by `stage()`, which
    is where the network appears and where `--offline` bites.
    """
    path = _as_file(uri)
    if path is None:
        raise ConnectorError(f"{uri!r} is not a manifest file this process can read")
    try:
        # D-160: bounded at the read. The slice was applied to a buffer
        # that already held the whole file.
        blob, over_budget = read_at_most(path, MAX_MANIFEST_BYTES)
    except OSError as exc:
        raise ConnectorError(f"{path} could not be read: {exc}") from exc
    if over_budget:
        raise ConnectorError(f"{path} is larger than the {MAX_MANIFEST_BYTES} byte manifest cap")
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConnectorError(f"{path} is not UTF-8 text; a manifest is a text file") from exc

    notes: list[str] = []
    rejected: list[str] = []
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        rows, form = _from_json(text, path, rejected), "json"
    else:
        rows, form = _from_lines(text, rejected), "lines"

    artifacts: list[RemoteArtifact] = []
    seen: set[str] = set()
    used_paths: set[str] = set()
    for index, row in enumerate(rows):
        target = row["uri"]
        scheme = urllib.parse.urlsplit(target).scheme.lower()
        if scheme != "https":
            # Refused here, at read time, rather than at fetch time. The
            # operator finds out that line 12 is plaintext while looking at
            # the listing, not twenty artifacts into a download.
            rejected.append(f"{target}: only https is accepted, not {scheme or 'a relative path'}")
            continue
        if target in seen:
            rejected.append(f"{target}: listed more than once")
            continue
        seen.add(target)
        declared = row.get("sha256")
        if declared is not None and not SHA256_HEX.match(declared):
            rejected.append(f"{target}: {declared!r} is not a 64 character hex sha256")
            declared = None
        local = row.get("path") or _default_path(target, index)
        if local in used_paths:
            # Two URLs whose last segment is the same word would otherwise
            # land on one file, and the second download would silently
            # overwrite the first. The index makes it visible instead.
            local = f"{index:04d}-{local}"
        used_paths.add(local)
        artifacts.append(
            RemoteArtifact(
                path=local,
                uri=target,
                size_bytes=row.get("size_bytes"),
                declared_sha256=declared,
                media_type=row.get("media_type"),
                revision=revision,
                source=NAME,
                extra={"manifest": str(path), "form": form},
            )
        )

    complete = not rejected
    if rejected:
        notes.append(
            f"{len(rejected)} entr(y/ies) in the manifest were rejected, so this listing is smaller than the "
            f"file: {'; '.join(rejected[:5])}"
        )
    undeclared = sum(1 for artifact in artifacts if artifact.declared_sha256 is None)
    if undeclared:
        notes.append(
            f"{undeclared} of {len(artifacts)} entr(y/ies) declare no sha256, so nothing will be checked when "
            "they are fetched. The JSON form of this manifest has a place to put one (design note D-91c)"
        )
    notes.append(
        "listing_complete here means the manifest was read in full. It does not mean the manifest lists "
        "everything the upstream source holds, which only its author knows (design note D-91b)"
    )
    notes.append("nothing was contacted to build this listing; the manifest is a local file")

    return Discovery(
        source=f"{NAME}:{path}",
        artifacts=tuple(artifacts),
        complete=complete,
        hosts_contacted=(),
        notes=tuple(notes),
        revision=revision,
    )


def _from_lines(text: str, rejected: list[str]) -> list[dict]:
    rows: list[dict] = []
    for number, raw in enumerate(text.splitlines()[:MAX_LINES], start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 1:
            rows.append({"uri": parts[0]})
            continue
        if len(parts) == 2 and SHA256_HEX.match(parts[0].lower()):
            # `sha256sum`-shaped: digest first, then the target. Accepted
            # because it is what somebody with a checksum file already has.
            rows.append({"uri": parts[1], "sha256": parts[0].lower()})
            continue
        if len(parts) == 2:
            rows.append({"uri": parts[0], "sha256": parts[1].lower()})
            continue
        rejected.append(f"line {number}: {len(parts)} fields, expected a URL or a digest and a URL")
    return rows


def _from_json(text: str, path: Path, rejected: list[str]) -> list[dict]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConnectorError(f"{path} starts like JSON and is not JSON: {exc}") from exc
    entries = payload.get("artifacts") if isinstance(payload, dict) else payload
    if not isinstance(entries, list):
        raise ConnectorError(f"{path} carries no list of artifacts; expected a list or an 'artifacts' key")
    rows: list[dict] = []
    for index, entry in enumerate(entries):
        if isinstance(entry, str):
            rows.append({"uri": entry})
            continue
        if not isinstance(entry, dict):
            rejected.append(f"entry {index}: not an object or a string")
            continue
        target = entry.get("uri") or entry.get("url")
        if not isinstance(target, str) or not target:
            rejected.append(f"entry {index}: no uri")
            continue
        digest = entry.get("sha256")
        size = entry.get("size_bytes") or entry.get("size")
        rows.append(
            {
                "uri": target,
                "path": entry.get("path") if isinstance(entry.get("path"), str) else None,
                "sha256": digest.strip().lower() if isinstance(digest, str) else None,
                "size_bytes": size if isinstance(size, int) else None,
                "media_type": entry.get("media_type") if isinstance(entry.get("media_type"), str) else None,
            }
        )
    return rows


def _default_path(target: str, index: int) -> str:
    """A local name for an entry that did not choose one.

    The URL's last path segment, which is what the operator expects, with the
    index in front when there is nothing usable, so two entries from different
    hosts with the same basename cannot land on one file. `_safe_relative` in
    `model.py` still neutralises whatever comes out of here: this decides what
    the file is called, not whether it stays inside the destination.
    """
    name = urllib.parse.unquote(urllib.parse.urlsplit(target).path).rsplit("/", 1)[-1]
    return name or f"artifact-{index:04d}"


CONNECTOR = register(
    Connector(
        name=NAME,
        summary_key="connector.url",
        needs_network=True,
        discover=discover,
        accepts=accepts,
    )
)
