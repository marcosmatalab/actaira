"""HuggingFace Hub: the source most model artifacts in the wild actually come from.

Design note D-86, and the two digests on the same file.

The Hub tree API returns, for every entry, an `oid`. For a small file that
`oid` is the git blob hash, which is SHA-1 over `blob <len>\\0` plus the
contents: not SHA-256, not a hash of the file's bytes alone, and useless for
the comparison `stage()` makes. For a file stored in LFS, which is every weight
file worth fetching, the entry also carries `lfs.oid`, and *that* one is a
SHA-256 of the bytes, because it is the key LFS stores the object under.

So this connector puts `lfs.oid` in `declared_sha256` and the git `oid` in
`extra`, and the distinction is load-bearing rather than tidy. Putting the git
oid in `declared_sha256` would make `stage()` compare a SHA-256 it measured
against a SHA-1 the Hub published, which never matches, which would report
every small file in every repository as `ACT-CON-002`: a digest-mismatch alarm
that fires on correct data is worse than no alarm, because the first thing an
operator does with an alarm that always fires is switch it off.

The `lfs.oid` is validated before it is believed. Git-lfs writes pointers as
`sha256:<hex>` and the API has returned both that form and the bare hex; a
value that is neither 64 hex characters nor `sha256:` followed by 64 hex
characters is dropped with a note rather than passed through to become a
mismatch against bytes that are fine.

Design note D-86b, on what this listing cannot promise.

The tree endpoint paginates with an HTTP `Link` header. `Http` returns bodies,
not headers, and giving it a header-returning door for this one case was
rejected: the code that would follow the cursor is code that would be exercised
only against repositories with more than a thousand files, which is to say
almost never, and an unexercised pagination loop is a way to *silently* list
part of a repository. Instead the listing asks for the maximum page and, when
the page comes back full, says `complete = False` and names the reason. An
operator who needs the tail of a 1 200 file repository is told they are not
seeing it, which is the outcome D-80 asks for; an operator who needs it fetched
can point `actaira discover` at a manifest instead.

The other two ways this listing is short of the repository are stated in the
notes on every run, because they are invisible in the response: a gated repo
answers an anonymous request with an error rather than with a shorter tree, and
a repository can change under a mutable revision between the listing and the
fetch. Passing an immutable commit SHA to `--revision` is the only way to close
the second one, and the note says so.
"""
from __future__ import annotations

import re
import urllib.parse

from .model import (
    Connector,
    ConnectorError,
    Discovery,
    Http,
    RemoteArtifact,
    token_with_source,
)
from .registry import register

NAME = "huggingface"
HOST = "huggingface.co"
DEFAULT_REVISION = "main"
TOKEN_VARIABLES = ("HF_TOKEN", "HUGGINGFACE_TOKEN")
# The Hub caps `limit` at 1000. Asking for exactly the cap makes a full page an
# unambiguous signal that there is a next one, which is what decides `complete`.
PAGE_LIMIT = 1000
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def accepts(uri: str) -> bool:
    lowered = uri.lower()
    return (
        lowered.startswith(("hf://", "huggingface://"))
        or lowered.startswith(f"https://{HOST}/")
        or lowered.startswith(f"https://www.{HOST}/")
    )


def _parse(uri: str) -> tuple[str, str, str | None]:
    """`(kind, repo, revision)` from any of the shapes this connector accepts.

    Recognised: `hf://org/name`, `hf://datasets/org/name`, either with a
    trailing `@revision`, and the browser URL `https://huggingface.co/org/name`
    with an optional `/tree/<revision>` on the end, which is what an operator
    gets by copying the address bar.
    """
    remainder = uri
    for prefix in ("hf://", "huggingface://", f"https://{HOST}/", f"https://www.{HOST}/"):
        if remainder.lower().startswith(prefix):
            remainder = remainder[len(prefix):]
            break
    remainder = remainder.strip("/")
    revision: str | None = None
    if "@" in remainder:
        remainder, _, revision = remainder.partition("@")

    parts = [segment for segment in remainder.split("/") if segment]
    kind = "models"
    if parts and parts[0] in ("datasets", "spaces"):
        kind = parts[0]
        parts = parts[1:]
    # The browser URL carries the view after the repository: `.../tree/main`,
    # `.../blob/main/config.json`. The revision in it is authoritative when the
    # caller did not give one explicitly.
    # Searched from index 2, past owner and name. An organisation called
    # `tree` is unlikely and not impossible, and `hf://tree/model` read as a
    # view marker resolves to no repository at all.
    for marker in ("tree", "blob", "resolve"):
        if marker in parts[2:]:
            index = parts.index(marker, 2)
            if len(parts) > index + 1 and revision is None:
                revision = parts[index + 1]
            parts = parts[:index]
            break
    if len(parts) < 2:
        raise ConnectorError(
            f"{uri!r} does not name a HuggingFace repository; expected owner/name, for example hf://openai/whisper-tiny"
        )
    if kind == "spaces":
        raise ConnectorError("Spaces are applications rather than artifact repositories; this connector lists models and datasets")
    return kind, "/".join(parts[:2]), revision


def _declared_digest(entry: dict, path: str, notes: list[str]) -> str | None:
    """The SHA-256 this entry publishes, or None, with anything odd reported.

    See design note D-86: only the LFS oid is a SHA-256 of the bytes, and it is
    checked for shape before it is believed, because a malformed digest passed
    through here becomes an ACT-CON-002 against a file that is fine.
    """
    lfs = entry.get("lfs")
    if not isinstance(lfs, dict):
        return None
    raw = lfs.get("oid") or lfs.get("sha256")
    if not isinstance(raw, str):
        return None
    candidate = raw[len("sha256:"):] if raw.lower().startswith("sha256:") else raw
    candidate = candidate.strip().lower()
    if SHA256_HEX.match(candidate):
        return candidate
    notes.append(f"{path}: the LFS oid {raw!r} is not a SHA-256; it was dropped rather than checked against the bytes")
    return None


def discover(uri: str, *, http: Http, revision: str | None = None) -> Discovery:
    kind, repo, uri_revision = _parse(uri)
    reference = revision or uri_revision or DEFAULT_REVISION
    token, variable = token_with_source(*TOKEN_VARIABLES)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    notes: list[str] = []

    quoted = urllib.parse.quote(reference, safe="")
    listing_url = f"https://{HOST}/api/{kind}/{repo}/tree/{quoted}?recursive=1&limit={PAGE_LIMIT}"
    payload = http.get_json(listing_url, headers)
    if not isinstance(payload, list):
        raise ConnectorError(f"{listing_url} did not return a tree listing")

    artifacts: list[RemoteArtifact] = []
    prefix = f"{kind}/" if kind != "models" else ""
    for entry in payload:
        if not isinstance(entry, dict) or entry.get("type") != "file":
            continue
        path = str(entry.get("path") or "")
        if not path:
            continue
        size = entry.get("size")
        artifacts.append(
            RemoteArtifact(
                path=path,
                uri=f"https://{HOST}/{prefix}{repo}/resolve/{quoted}/{urllib.parse.quote(path)}",
                size_bytes=size if isinstance(size, int) else None,
                declared_sha256=_declared_digest(entry, path, notes),
                media_type=None,
                revision=reference,
                source=NAME,
                extra={
                    # The git oid, kept and labelled. It is a SHA-1 over a
                    # git blob header plus the contents, so it is evidence
                    # about the revision and not about the bytes on their own.
                    "git_oid": entry.get("oid"),
                    "lfs": bool(entry.get("lfs")),
                },
            )
        )

    complete = len(payload) < PAGE_LIMIT
    if not complete:
        notes.append(
            f"the tree endpoint returned a full page of {PAGE_LIMIT} entries, so there is at least one more "
            "page that this client does not follow: the listing is a prefix of the repository (design note D-86b)"
        )
    notes.append(f"listed as {'the identity in ' + variable if variable else 'an anonymous caller'}")
    notes.append(
        "a gated or private repository answers an anonymous request with an error rather than a shorter tree, "
        "so a listing with no token is not evidence that no such repository exists"
    )
    if reference == DEFAULT_REVISION or not _looks_immutable(reference):
        notes.append(
            f"{reference!r} is a mutable reference: the repository can change between this listing and any "
            "fetch. Pass --revision <commit sha> for a listing that stays true"
        )
    non_lfs = sum(1 for artifact in artifacts if artifact.declared_sha256 is None)
    if non_lfs:
        notes.append(
            f"{non_lfs} of {len(artifacts)} file(s) publish no SHA-256; only LFS entries do, and the git oid "
            "on the others is a SHA-1 over a blob header (design note D-86)"
        )

    return Discovery(
        source=f"{NAME}:{prefix}{repo}",
        artifacts=tuple(artifacts),
        complete=complete,
        hosts_contacted=tuple(http.hosts),
        notes=tuple(notes),
        revision=reference,
    )


def _looks_immutable(reference: str) -> bool:
    """A 40 character hex string is a commit; anything else is a moving target.

    Tags are excluded on purpose even though most people never move one: a tag
    is mutable by design in git, and this note is the one place the operator
    finds out that the thing they pinned to can be repointed.
    """
    return len(reference) == 40 and all(character in "0123456789abcdef" for character in reference.lower())


def headers_for_fetch(_artifact: RemoteArtifact) -> dict[str, str]:
    """The credential travels with the download as well as with the listing.

    A repository that needed a token to list needs one to resolve, and without
    this the fetch of a gated model fails with a 401 after a listing that
    worked, which reads as a bug in the tool rather than as the credential it
    is.
    """
    token, _variable = token_with_source(*TOKEN_VARIABLES)
    return {"Authorization": f"Bearer {token}"} if token else {}


CONNECTOR = register(
    Connector(
        name=NAME,
        summary_key="connector.huggingface",
        needs_network=True,
        discover=discover,
        accepts=accepts,
        fetch_headers=headers_for_fetch,
    )
)
