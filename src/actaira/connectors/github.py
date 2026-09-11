"""GitHub: release assets and the tree of a ref, which are two different things.

Design note D-87, and the one field in the response that decides everything.

The git tree endpoint answers `?recursive=1` with every blob under a ref, and
with a boolean called `truncated`. When it is true the response is a prefix:
GitHub stopped, the array is shorter than the tree, and nothing else in the
payload says so. A connector that ignored that field would return a listing
that looks exactly like a complete one, for a repository large enough that
nobody would notice a missing file, which is precisely the failure D-80 exists
to prevent. So `truncated` maps straight onto `complete = False` and into a
note that names it, and that mapping is what `tests/test_connectors.py` pins.

Design note D-87b, on listing two things at once and keeping them apart.

A GitHub repository publishes artifacts in two places that have almost nothing
in common. Release assets are uploaded binaries: a `.safetensors` or a `.gguf`
somebody built and attached, which is what a supply-chain tool cares about. The
git tree is source. Both are listed here, because an operator asking "what does
this repository ship" means both, and each artifact carries `extra["kind"]`
saying which it came from, because they answer different questions and a
listing that blurred them would invite scanning a repository's `.py` files and
calling it an artifact review.

Design note D-87c, on the digests.

A tree entry's `sha` is a git blob SHA-1, not a SHA-256 of the file, and it
lands in `extra` for exactly the reason the HuggingFace git oid does (D-86). A
release asset may carry a `digest` field of the form `sha256:<hex>`; when it
does, that is a SHA-256 of the uploaded bytes and it goes in
`declared_sha256`. Most assets, especially older ones, carry nothing, and the
notes say how many, because "no digest was checked" and "the digest checked
out" must never look the same in a report.

Limitations, stated rather than discovered later:

  * releases are read one page deep. GitHub paginates with a `Link` header,
    which `Http` does not expose (see D-86b for the same decision on the Hub),
    so a repository with more than `PAGE_LIMIT` releases yields the newest page
    and `complete = False`.
  * an anonymous caller gets 60 requests an hour from an IP. A 403 here is far
    more often that budget than a permission, and the error says so, because a
    tool that reports "forbidden" for a rate limit sends its operator looking
    for a credential they do not need.
  * private repositories, and public ones under an org with SSO enforced,
    require a token whose scopes this connector cannot inspect. It reports the
    variable it read and nothing about what that token can reach.
"""
from __future__ import annotations

import urllib.parse

from .model import (
    Connector,
    ConnectorError,
    Discovery,
    Http,
    HttpStatusError,
    RemoteArtifact,
    token_with_source,
)
from .registry import register

NAME = "github"
API_HOST = "api.github.com"
RAW_HOST = "raw.githubusercontent.com"
TOKEN_VARIABLES = ("GITHUB_TOKEN", "GH_TOKEN")
PAGE_LIMIT = 100
DEFAULT_REF = "HEAD"
API_VERSION = "2022-11-28"


def accepts(uri: str) -> bool:
    lowered = uri.lower()
    return (
        lowered.startswith(("github://", "gh://"))
        or lowered.startswith("https://github.com/")
        or lowered.startswith(f"https://{API_HOST}/repos/")
    )


def _parse(uri: str) -> tuple[str, str, str | None]:
    remainder = uri
    for prefix in ("github://", "gh://", "https://github.com/", f"https://{API_HOST}/repos/"):
        if remainder.lower().startswith(prefix):
            remainder = remainder[len(prefix):]
            break
    remainder = remainder.strip("/")
    if remainder.lower().endswith(".git"):
        remainder = remainder[: -len(".git")]
    revision: str | None = None
    if "@" in remainder:
        remainder, _, revision = remainder.partition("@")
    parts = [segment for segment in remainder.split("/") if segment]
    # A browser URL carries a view after the repository: `/tree/main`,
    # `/releases/tag/v1.2`. The ref in it is used when the caller gave none.
    for marker in ("tree", "blob"):
        if marker in parts[2:]:
            index = parts.index(marker, 2)
            if len(parts) > index + 1 and revision is None:
                revision = parts[index + 1]
            parts = parts[:index]
            break
    if len(parts) < 2:
        raise ConnectorError(f"{uri!r} does not name a GitHub repository; expected owner/repo")
    return parts[0], parts[1], revision


def _headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        # Pinned, so a future default at GitHub cannot change the shape of the
        # payload this parser reads without the pin being edited here first.
        "X-GitHub-Api-Version": API_VERSION,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _asset_digest(asset: dict) -> str | None:
    """The `sha256:<hex>` a release asset may publish, validated. See D-87c."""
    raw = asset.get("digest")
    if not isinstance(raw, str) or not raw.lower().startswith("sha256:"):
        return None
    candidate = raw[len("sha256:"):].strip().lower()
    if len(candidate) == 64 and all(character in "0123456789abcdef" for character in candidate):
        return candidate
    return None


def discover(uri: str, *, http: Http, revision: str | None = None) -> Discovery:
    owner, repo, uri_revision = _parse(uri)
    reference = revision or uri_revision or DEFAULT_REF
    token, variable = token_with_source(*TOKEN_VARIABLES)
    headers = _headers(token)
    notes: list[str] = []
    artifacts: list[RemoteArtifact] = []
    complete = True

    releases_url = f"https://{API_HOST}/repos/{owner}/{repo}/releases?per_page={PAGE_LIMIT}"
    releases = _get(http, releases_url, headers, token)
    if not isinstance(releases, list):
        raise ConnectorError(f"{releases_url} did not return a list of releases")
    if len(releases) >= PAGE_LIMIT:
        complete = False
        notes.append(
            f"the releases endpoint returned a full page of {PAGE_LIMIT}; older releases are on pages this "
            "client does not follow, so the asset listing is a prefix"
        )
    undigested = 0
    for release in releases:
        if not isinstance(release, dict):
            continue
        tag = str(release.get("tag_name") or "")
        for asset in release.get("assets") or []:
            if not isinstance(asset, dict):
                continue
            name = str(asset.get("name") or "")
            download = asset.get("browser_download_url")
            if not name or not isinstance(download, str):
                continue
            digest = _asset_digest(asset)
            if digest is None:
                undigested += 1
            size = asset.get("size")
            artifacts.append(
                RemoteArtifact(
                    path=f"releases/{tag}/{name}" if tag else f"releases/{name}",
                    uri=download,
                    size_bytes=size if isinstance(size, int) else None,
                    declared_sha256=digest,
                    media_type=asset.get("content_type"),
                    revision=tag or None,
                    source=NAME,
                    extra={"kind": "release_asset", "tag": tag, "id": asset.get("id")},
                )
            )

    tree_url = (
        f"https://{API_HOST}/repos/{owner}/{repo}/git/trees/"
        f"{urllib.parse.quote(reference, safe='')}?recursive=1"
    )
    tree = _get(http, tree_url, headers, token)
    if not isinstance(tree, dict):
        raise ConnectorError(f"{tree_url} did not return a tree")
    if tree.get("truncated") is True:
        # Design note D-87. The one field that decides this listing.
        complete = False
        notes.append(
            "the tree response carries truncated: true, so GitHub stopped before the end of the tree and "
            "this listing is a prefix of the ref (design note D-87)"
        )
    resolved = str(tree.get("sha") or reference)
    for entry in tree.get("tree") or []:
        if not isinstance(entry, dict) or entry.get("type") != "blob":
            continue
        path = str(entry.get("path") or "")
        if not path:
            continue
        size = entry.get("size")
        artifacts.append(
            RemoteArtifact(
                path=f"tree/{path}",
                uri=(
                    f"https://{RAW_HOST}/{owner}/{repo}/{urllib.parse.quote(resolved, safe='')}/"
                    f"{urllib.parse.quote(path)}"
                ),
                size_bytes=size if isinstance(size, int) else None,
                # A git blob sha is a SHA-1 over a header plus the contents.
                # It is not a digest of these bytes and must not be compared
                # with one: design note D-87c, and D-86 for the same trap.
                declared_sha256=None,
                revision=resolved,
                source=NAME,
                extra={"kind": "tree_blob", "git_sha": entry.get("sha"), "mode": entry.get("mode")},
            )
        )

    notes.append(f"listed as {'the identity in ' + variable if variable else 'an anonymous caller'}")
    if token is None:
        notes.append(
            "anonymous GitHub API calls are limited to 60 an hour per address; a 403 from this connector is "
            "usually that budget rather than a permission"
        )
    tree_blobs = sum(1 for artifact in artifacts if artifact.extra.get("kind") == "tree_blob")
    notes.append(
        f"{len(artifacts) - tree_blobs} release asset(s) and {tree_blobs} tree blob(s); the two are different "
        "kinds of thing and carry extra.kind saying which (design note D-87b)"
    )
    if undigested:
        notes.append(
            f"{undigested} release asset(s) publish no sha256 digest, so nothing about their bytes was claimed "
            "and nothing will be checked when they are fetched"
        )

    return Discovery(
        source=f"{NAME}:{owner}/{repo}",
        artifacts=tuple(artifacts),
        complete=complete,
        hosts_contacted=tuple(http.hosts),
        notes=tuple(notes),
        revision=resolved,
    )


def _get(http: Http, url: str, headers: dict[str, str], token: str | None) -> object:
    """A GET whose 403 says what a 403 from this API usually means.

    Reported rather than swallowed. The rate limit is by far the most common
    reason an anonymous run fails here, and "HTTP 403" on its own sends the
    operator looking for a credential when what they need is to wait or to set
    one they already have.
    """
    try:
        return http.get_json(url, headers)
    except HttpStatusError as exc:
        if exc.status in (403, 429):
            remaining = exc.headers.get("x-ratelimit-remaining")
            if remaining == "0" or token is None:
                raise ConnectorError(
                    f"{url} returned HTTP {exc.status}; the anonymous rate limit is the usual cause "
                    f"(x-ratelimit-remaining: {remaining or 'not reported'}). "
                    f"Set {' or '.join(TOKEN_VARIABLES)} to raise it"
                ) from exc
        raise


def headers_for_fetch(_artifact: RemoteArtifact) -> dict[str, str]:
    """The same credential on the download as on the listing.

    Only the Authorization header travels: the API `Accept` would be wrong on
    `raw.githubusercontent.com` and on the release CDN, both of which serve
    bytes rather than JSON.
    """
    token, _variable = token_with_source(*TOKEN_VARIABLES)
    return {"Authorization": f"Bearer {token}"} if token else {}


CONNECTOR = register(
    Connector(
        name=NAME,
        summary_key="connector.github",
        needs_network=True,
        discover=discover,
        accepts=accepts,
        fetch_headers=headers_for_fetch,
    )
)
