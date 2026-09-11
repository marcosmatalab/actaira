"""OCI and Docker distribution v2 registries, where models now ship as artifacts.

Design note D-88, and the one digest in this package that is worth something.

Everywhere else here a declared digest is a number a server typed into a JSON
field. In a distribution registry the digest *is* the address: a blob is
fetched from `/v2/<repo>/blobs/sha256:<hex>`, and a conformant registry will
not serve bytes under a digest they do not hash to. That makes the layer
digests in a manifest the strongest claim any connector in this directory
carries, and it is still a claim, which is why it still lands in
`declared_sha256` and is still recomputed by `stage()`. The reason is not
distrust of the arithmetic; it is that "the registry that served me these bytes
also told me what they hash to" is a closed loop, and the digest becomes
evidence only when it is compared against a manifest obtained somewhere else,
or signed, or written down before the pull. This connector prints what it was
told and what it measured, and leaves the loop visible.

Design note D-88b, on the anonymous token dance.

Neither Docker Hub nor GHCR answers an unauthenticated manifest request. Both
answer `401` with a `WWW-Authenticate: Bearer realm=...,service=...,scope=...`
header, and the client is expected to GET that realm, receive a token, and
retry. There is no way to skip it and no way to guess it: the realm is a
different host from the registry (`auth.docker.io`, `ghcr.io/token`), and
hardcoding the two would break on the third registry and would be a guess
presented as support.

So `Http` was given a refusal that carries the response headers (design note
D-83) and this connector reads the challenge from them. Three properties are
worth naming because they are what makes this safe to do automatically:

  * the realm goes through the same `_guard` as everything else, so a registry
    that answers with a plaintext realm gets a refusal rather than a token
    request over http;
  * the token host appears in `hosts_contacted` like any other, so the operator
    sees that a second service was involved in their listing;
  * the challenge is followed exactly once. A registry that answers the retry
    with another 401 gets an error, not a loop, because a token endpoint that
    keeps sending you back is either misconfigured or fishing.

What this connector does not do, stated plainly:

  * no credential is ever sent to a realm. The anonymous flow is implemented;
    for a private repository, set `OCI_TOKEN` to a bearer token you obtained
    yourself and it is sent to the registry, not to the challenge endpoint.
    There is no docker login, no `~/.docker/config.json`, no keychain: an
    ambient credential chain is exactly what D-80 refuses.
  * no implicit registry and no implicit `library/`. `oci://alpine` is an
    error rather than Docker Hub's official image, because a supply-chain tool
    that silently expands a short name is a supply-chain tool that can be
    pointed somewhere the operator did not read. The one rewrite that does
    happen, `docker.io` to `registry-1.docker.io`, is the API host for the same
    service and is stated in the notes.
  * the listing is of one reference. `complete = True` here means "these are
    the blobs this manifest names", which it can prove; it says nothing about
    the other tags in the repository, and the note says so.
"""
from __future__ import annotations

import re
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

NAME = "oci"
TOKEN_VARIABLES = ("OCI_TOKEN", "REGISTRY_TOKEN")

MANIFEST_TYPES = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
ACCEPT = ", ".join(MANIFEST_TYPES)
# An index for a widely built image carries a handful of platforms. The cap is
# here so that a hostile or broken index cannot turn one listing into hundreds
# of requests; hitting it sets complete = False rather than truncating quietly.
MAX_CHILD_MANIFESTS = 12
DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
# `key="value"` or `key=value`, which is what RFC 7235 auth-param allows. The
# quoted form has to come first: a scope like "repository:a/b:pull,push" has a
# comma inside the quotes and an unquoted-first pattern would cut it in half.
AUTH_PARAM = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))')
DOCKER_HUB_REWRITE = {"docker.io": "registry-1.docker.io", "index.docker.io": "registry-1.docker.io"}


def accepts(uri: str) -> bool:
    return uri.lower().startswith(("oci://", "docker://"))


def _parse(uri: str) -> tuple[str, str, str]:
    """`(registry_host, repository, reference)`.

    A reference is a tag or a `sha256:` digest. Splitting on the last colon
    only counts when that colon is after the last slash, so a registry on a
    non-default port (`localhost:5000/model:v1`) is not read as a tagged
    repository called `localhost`.
    """
    remainder = uri.split("://", 1)[1].strip("/")
    if "/" not in remainder:
        raise ConnectorError(
            f"{uri!r} names no registry. Write the host explicitly, for example "
            "oci://ghcr.io/owner/model:tag; this connector does not expand short names"
        )
    host, _, path = remainder.partition("/")
    reference = "latest"
    if "@" in path:
        path, _, reference = path.partition("@")
    else:
        slash = path.rfind("/")
        colon = path.rfind(":")
        if colon > slash:
            reference = path[colon + 1:]
            path = path[:colon]
    if not path:
        raise ConnectorError(f"{uri!r} names no repository")
    return DOCKER_HUB_REWRITE.get(host.lower(), host), path, reference


def _parse_challenge(value: str) -> dict[str, str]:
    """The parameters of a `Bearer` challenge, or an empty dict.

    Anything that is not a Bearer challenge is treated as no challenge at all:
    a `Basic` realm means the registry wants a password, which this connector
    has no way to supply and would not read from the environment of the
    process without being told to.
    """
    if not value.strip().lower().startswith("bearer"):
        return {}
    return {
        key.lower(): (quoted if quoted is not None else bare)
        for key, quoted, bare in AUTH_PARAM.findall(value.split(None, 1)[1] if " " in value else "")
    }


def _token_for(http: Http, challenge: dict[str, str], notes: list[str]) -> str | None:
    """Follow a bearer challenge once, anonymously. See design note D-88b."""
    realm = challenge.get("realm")
    if not realm:
        return None
    query = []
    for key in ("service", "scope"):
        if challenge.get(key):
            query.append(f"{key}={_quote(challenge[key])}")
    url = realm + (("&" if "?" in realm else "?") + "&".join(query) if query else "")
    # `_guard` inside `get_json` refuses a plaintext realm, which is the point:
    # a registry that sends one is asking for a token over a channel anybody
    # on the path can read.
    payload = http.get_json(url)
    if not isinstance(payload, dict):
        raise ConnectorError(f"the token endpoint {realm} did not return a token document")
    token = payload.get("token") or payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise ConnectorError(f"the token endpoint {realm} returned no token")
    notes.append(f"an anonymous pull token was obtained from {realm} for scope {challenge.get('scope', '(none)')!r}")
    return token


def _quote(value: str) -> str:
    """A scope or service, as a query parameter.

    `:`, `/`, `*` and `,` are left alone: a scope is
    `repository:owner/name:pull,push` and a registry that gets it percent
    encoded answers with a token for a scope nobody asked for, or with nothing.
    """
    return urllib.parse.quote(value, safe=":/*,")


def _manifest(http: Http, host: str, repository: str, reference: str,
              headers: dict[str, str], notes: list[str]) -> tuple[dict, dict[str, str]]:
    """One manifest, following a bearer challenge at most once."""
    url = f"https://{host}/v2/{repository}/manifests/{reference}"
    request_headers = {"Accept": ACCEPT, **headers}
    try:
        return _as_manifest(http.get_json(url, request_headers), url), headers
    except HttpStatusError as exc:
        if exc.status != 401 or headers.get("Authorization"):
            # Already authenticated and still refused, or refused for a reason
            # a token cannot fix. Retrying would be a loop, not a protocol.
            raise
        challenge = _parse_challenge(exc.headers.get("www-authenticate", ""))
        token = _token_for(http, challenge, notes)
        if token is None:
            raise ConnectorError(
                f"{url} returned 401 with no Bearer challenge this connector can follow "
                f"(www-authenticate: {exc.headers.get('www-authenticate', 'absent')!r})"
            ) from exc
        headers = {**headers, "Authorization": f"Bearer {token}"}
        return _as_manifest(http.get_json(url, {"Accept": ACCEPT, **headers}), url), headers


def _as_manifest(payload: object, url: str) -> dict:
    if not isinstance(payload, dict):
        raise ConnectorError(f"{url} did not return a manifest document")
    return payload


def _blob(host: str, repository: str, descriptor: dict, kind: str, platform: str | None) -> RemoteArtifact | None:
    digest = str(descriptor.get("digest") or "")
    if not digest:
        # A descriptor with no digest is not a blob anybody can fetch: the
        # digest is the address. Dropped rather than listed as unfetchable.
        return None
    # A registry may address a blob with sha512. This connector compares
    # SHA-256 and nothing else, so an algorithm it cannot check is listed with
    # no declared digest rather than with one that will be silently ignored.
    match = DIGEST.match(digest)
    size = descriptor.get("size")
    name = digest.replace(":", "-")
    return RemoteArtifact(
        path=f"blobs/{platform}/{name}" if platform else f"blobs/{name}",
        uri=f"https://{host}/v2/{repository}/blobs/{digest}",
        size_bytes=size if isinstance(size, int) else None,
        declared_sha256=match.group(1) if match else None,  # never the sha512, see above
        media_type=descriptor.get("mediaType"),
        revision=digest,
        source=NAME,
        extra={"kind": kind, "platform": platform, "digest": digest,
               "annotations": descriptor.get("annotations") or {}},
    )


def discover(uri: str, *, http: Http, revision: str | None = None) -> Discovery:
    host, repository, reference = _parse(uri)
    if revision:
        reference = revision
    token, variable = token_with_source(*TOKEN_VARIABLES)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    notes: list[str] = []
    complete = True

    manifest, headers = _manifest(http, host, repository, reference, headers, notes)
    media_type = str(manifest.get("mediaType") or "")

    documents: list[tuple[dict, str | None]] = []
    if media_type in INDEX_TYPES or "manifests" in manifest:
        children = [child for child in manifest.get("manifests") or [] if isinstance(child, dict)]
        notes.append(
            f"{reference} resolves to a multi-platform index naming {len(children)} manifest(s); each one was "
            "followed and its blobs listed with the platform in extra.platform"
        )
        if len(children) > MAX_CHILD_MANIFESTS:
            complete = False
            notes.append(
                f"only the first {MAX_CHILD_MANIFESTS} of {len(children)} manifests were followed, so the blob "
                "listing is a prefix of the index"
            )
        for child in children[:MAX_CHILD_MANIFESTS]:
            child_digest = str(child.get("digest") or "")
            if not child_digest:
                continue
            platform_row = child.get("platform") or {}
            platform = "/".join(
                str(platform_row.get(key)) for key in ("os", "architecture") if platform_row.get(key)
            ) or child_digest[:19]
            child_manifest, headers = _manifest(http, host, repository, child_digest, headers, notes)
            documents.append((child_manifest, platform))
    else:
        documents.append((manifest, None))

    artifacts: list[RemoteArtifact] = []
    for document, document_platform in documents:
        config = document.get("config")
        if isinstance(config, dict):
            entry = _blob(host, repository, config, "config", document_platform)
            if entry is not None:
                artifacts.append(entry)
        for layer in document.get("layers") or []:
            if isinstance(layer, dict):
                entry = _blob(host, repository, layer, "layer", document_platform)
                if entry is not None:
                    artifacts.append(entry)

    unchecked = sum(1 for artifact in artifacts if artifact.declared_sha256 is None)
    if unchecked:
        notes.append(
            f"{unchecked} blob(s) are addressed by a digest algorithm other than sha256; this connector "
            "compares sha256 and nothing else, so nothing will be checked for them"
        )
    notes.append(
        f"pulled as {'the bearer token in ' + variable if variable else 'an anonymous caller'}; no docker "
        "credential store, keychain or config file is read (design note D-88b)"
    )
    notes.append(
        "a registry digest is content-addressed, which makes it the strongest claim in this package and still "
        "a claim: the registry that served the bytes is the same party that stated the digest (design note D-88)"
    )
    notes.append(
        f"this listing covers the blobs of {reference}; it says nothing about the other tags in {repository}"
        if complete
        else "this listing is a prefix; see the note above"
    )

    return Discovery(
        source=f"{NAME}:{host}/{repository}:{reference}",
        artifacts=tuple(artifacts),
        complete=complete,
        hosts_contacted=tuple(http.hosts),
        notes=tuple(notes),
        revision=reference,
    )


def headers_for_fetch(_artifact: RemoteArtifact) -> dict[str, str]:
    """Only an explicit token. A blob fetch that needs the anonymous dance will
    fail with a 401 rather than repeat it here, because `stage()` fetches many
    artifacts and a token flow hidden inside a download loop is a credential
    exchange nobody sees. The fix is to pass `OCI_TOKEN`, and the failure says
    which artifact it was and what the registry answered."""
    token, _variable = token_with_source(*TOKEN_VARIABLES)
    return {"Authorization": f"Bearer {token}"} if token else {}


CONNECTOR = register(
    Connector(
        name=NAME,
        summary_key="connector.oci",
        needs_network=True,
        discover=discover,
        accepts=accepts,
        fetch_headers=headers_for_fetch,
    )
)
