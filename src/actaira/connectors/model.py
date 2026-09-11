"""Discovery: finding the artifacts, before anything is said about them.

Design note D-80, and the boundary this whole package exists to hold.

Every other module in Actaira answers a question about bytes it already has.
This one goes and gets them, which means it is the only part of the tool that
opens a socket, and that changes what it is allowed to claim. Three rules, and
they are the reason a connector is a small thing rather than an integration:

**A connector enumerates. It does not conclude.** `discover()` returns a list of
artifacts a source says it holds, each with the digest the source published if
it published one. Nothing downstream treats that list as complete, because no
remote API can promise it: a repository can hide a file behind a permission, a
registry can paginate, a bucket can be listed by a key with partial access. So
a `Discovery` carries `complete`, and it is False whenever the connector cannot
prove otherwise. A tool that reported "12 artifacts, all clean" over a listing
it could not vouch for would be making the same class of claim this repository
was built in reaction to.

**A digest a source publishes is a claim, not a measurement.** HuggingFace
publishes a SHA-256 for every LFS file, and it is useful, and it is also
something the server said. It lands in `declared_sha256`, never in `sha256`.
`sha256` is filled by Actaira after reading the bytes, and `fetch()` compares
the two and reports a mismatch as `ACT-CON-002` rather than trusting either.
The two fields exist separately for the same reason `verify` answers integrity
and identity separately.

**The network is opt-in, per command, and visible.** Nothing in `actaira scan`,
`actaira controls` or `actaira verify` reaches the network. `actaira discover`
does, it is the only command that does, and it prints the host it contacted for
every request it made. `--offline` turns the whole package into an error rather
than a silent no-op, because a supply-chain tool that quietly skipped the
network would be worse than one that refused.

Design note D-81, on why this is stdlib.

Every connector here speaks its protocol over `urllib.request` from the
standard library. The obvious alternative is the vendor SDK for each source,
which would be better code and would also mean that a tool arguing it has one
runtime dependency arrives with boto3, huggingface_hub and an OCI client. What
that costs is real and is stated rather than hidden: no automatic credential
chain, no retry policy anyone has tuned, and no support for the parts of each
API this file does not implement. What it buys is that installing this package
still pulls exactly one other, and that a reader auditing what this tool can
reach only has to read this directory.
"""
from __future__ import annotations

import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import __version__

# Derived, not typed. It said `actaira/2.0` from the 2.0 release through
# 2.2, so every remote host this tool identified itself to was told the
# wrong version for two minor releases (D-231).
#
# The `(+url)` half is gone with the repository it named. That convention
# exists so an operator seeing this agent in their logs can find out who is
# reaching them, and a URL that resolves to nothing does the opposite of that:
# it looks like an answer and is not one. Name and version is what this tool
# can honestly tell a host it contacts.
USER_AGENT = f"actaira/{__version__}"
DEFAULT_TIMEOUT = 20.0
MAX_RESPONSE_BYTES = 8 << 20
# A single artifact this package will pull. Above it, `fetch` refuses and says
# so: a discovery tool that streams a 40 GB weight file because a remote index
# listed it is a denial of service the operator did not ask for.
MAX_FETCH_BYTES = 2 << 30
MAX_PAGES = 50


class ConnectorError(RuntimeError):
    """A connector could not do what it was asked. Always carries the source."""


class OfflineError(ConnectorError):
    """`--offline` was set and a connector needed the network."""


class HttpStatusError(ConnectorError):
    """A response the server refused, carrying the status line and the headers.

    Design note D-83. Every other failure in this package is a sentence, and
    that was enough until the OCI connector arrived. A Docker distribution
    registry answers an unauthenticated manifest request with `401` and a
    `WWW-Authenticate` header naming the realm, the service and the scope of
    the token it wants, and that header *is* the protocol: without reading it
    there is no anonymous pull from Docker Hub or from GHCR at all. Throwing
    the headers away and reconstructing the token endpoint from what registries
    are known to do would be a guess dressed as support, and the guess would be
    invisible the day a registry changed it.

    So a refusal carries what the server actually said. It stays a
    `ConnectorError`, so every existing `except ConnectorError` keeps working
    and no caller has to learn about this class to be correct; the one caller
    that needs the challenge asks for it by name. `headers` is a plain dict
    with lower-cased keys, because HTTP header names are case-insensitive and
    a connector comparing `"WWW-Authenticate"` against `"Www-Authenticate"` is
    a bug waiting for a different server.
    """

    def __init__(self, message: str, *, status: int, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.headers = {key.lower(): value for key, value in (headers or {}).items()}


@dataclass(frozen=True)
class RemoteArtifact:
    """One artifact a source says it holds.

    `path` is the identifier within the source, `uri` is how to fetch it, and
    the two digests are kept apart on purpose: see design note D-80.
    """

    path: str
    uri: str
    size_bytes: int | None = None
    declared_sha256: str | None = None
    media_type: str | None = None
    revision: str | None = None
    source: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "uri": self.uri,
            "size_bytes": self.size_bytes,
            "declared_sha256": self.declared_sha256,
            "media_type": self.media_type,
            "revision": self.revision,
            "source": self.source,
            "extra": self.extra,
        }


@dataclass(frozen=True)
class Discovery:
    """What one connector found, and what it could not promise.

    `complete` is the field that matters. A connector sets it True only when it
    walked the whole listing and the protocol let it know it had: a filesystem
    walk can say so, a paginated API that stopped at the page cap cannot, and
    an anonymous bucket listing never can. `notes` carries the reason.
    """

    source: str
    artifacts: tuple[RemoteArtifact, ...]
    complete: bool
    hosts_contacted: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    revision: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "count": len(self.artifacts),
            "listing_complete": self.complete,
            "hosts_contacted": list(self.hosts_contacted),
            "notes": list(self.notes),
            "revision": self.revision,
        }


@dataclass(frozen=True)
class Connector:
    """A discovery source. Data, so `actaira discover --list` can print them.

    `fetch_headers` is optional and exists because a source that needed a
    credential to list needs the same credential to serve the bytes. Without
    it, a gated repository lists cleanly and then fails every download with a
    401, which reads as a bug in the tool rather than as the permission it is.
    A connector that needs no header leaves it None and `stage()` sends none.
    """

    name: str
    summary_key: str
    needs_network: bool
    discover: Callable[..., Discovery]
    accepts: Callable[[str], bool]
    fetch_headers: Callable[[RemoteArtifact], dict[str, str]] | None = None


# ---------------------------------------------------------------------------
# The one HTTP client every connector uses
# ---------------------------------------------------------------------------
def verified_context(context: ssl.SSLContext | None) -> ssl.SSLContext:
    """The TLS context an `Http` will use, and the one thing it will not accept.

    Design note D-82, on the honest way to make a network client testable.

    The test suite for this package must not touch the network, which means it
    has to serve canned API responses from a server it starts itself, which
    means that server presents a certificate no public CA signed. There are two
    ways to let a client reach it. The common one is a switch that turns
    verification off, usually spelt `verify=False` or `--insecure`, defended as
    "only in tests". The other is this: the caller may supply the context, and
    the context still has to verify.

    The first is rejected because the switch does not stay in the tests. It is
    one attribute away from a connector, one flag away from the CLI, and the
    day it appears in someone's CI as a workaround for a corporate middlebox,
    this tool is fetching supply-chain artifacts over a connection it declined
    to authenticate while still printing the host it thinks it contacted. A
    tool that exists to say what it actually observed cannot ship that switch,
    not even off by default.

    What this function gives up, stated rather than hidden: an operator behind
    an internal CA cannot point this client at their root from the command
    line, because there is no flag for it. That is deliberate for now; the
    library entry point exists, and a future flag would have to argue for
    itself and would still come through here. What it buys is that the only
    way to reach a server this machine does not trust is to hand the client a
    context that trusts it *and still checks it*, which is what the tests do:
    they generate a CA, trust exactly that CA, and keep hostname checking on.

    So: a context is accepted only if it still requires a certificate and still
    checks the hostname. A context with `check_hostname = False` or
    `verify_mode = CERT_NONE` is refused here, at construction, rather than
    quietly used for the rest of the process.
    """
    if context is None:
        return ssl.create_default_context()
    if context.verify_mode is not ssl.CERT_REQUIRED or not context.check_hostname:
        raise ConnectorError(
            "an injected TLS context must still verify the certificate chain and the hostname; "
            "this client has no way to turn verification off"
        )
    return context


def _host_of(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()


class HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Redirects that stay on HTTPS, and that are recorded like any other hop.

    Design note D-93, and a defect this package shipped for exactly as long as
    it took to write a test for the sentence above it.

    `Http` claims two things about itself: HTTPS only, and a record of every
    host contacted. `urlopen` quietly breaks both. Its default redirect handler
    follows a `302` to an `http://` URL without comment, so a source that
    answers a manifest request with a plaintext redirect gets its bytes fetched
    over a channel anybody on the path can read and rewrite, from a client whose
    docstring says it refuses to do that. And the host it ends up talking to is
    not the host `_guard` recorded, so `hosts_contacted` names the redirector
    and not the server that actually served the artifact. For a tool whose one
    network command exists to print what it touched, that is the whole claim
    going wrong quietly.

    Both are fixed here rather than in the connectors, because a rule that has
    to be remembered by seven modules is a rule that will be forgotten by the
    eighth. A redirect to anything but https is refused as an error naming the
    URL; every hop that is followed is recorded before it is taken.

    Design note D-93b, on the credential that used to travel with it.

    `HTTPRedirectHandler` copies the original request's headers onto the new
    one, `Authorization` included, and the two connectors most likely to carry
    a credential are exactly the two whose downloads redirect across a host
    boundary: a GitHub release asset redirects to `objects.githubusercontent.com`
    and a HuggingFace `resolve` URL redirects to the LFS CDN. So a token the
    operator set for `api.github.com` was being handed to a different service on
    every asset fetch, silently, because a stdlib default said so.

    It is dropped here on any hop that changes host, which is what `curl` has
    done by default for twenty years and for the same reason. Nothing is lost
    by it: both of those redirect targets serve presigned URLs that carry their
    own authorisation in the query string. A redirect that stays on the same
    host keeps the header, because that is one service talking about its own
    paths.
    """

    def __init__(self, record: Callable[[str], None]) -> None:
        self._record = record

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N803 - urllib's own signature
        if urllib.parse.urlsplit(newurl).scheme != "https":
            # A `ConnectorError` rather than an `HTTPError`, so that the reason
            # survives. `Http.get` turns an HTTPError into "returned HTTP 302",
            # which is true and tells the operator nothing about the downgrade
            # that was refused, and the downgrade is the whole point.
            fp.close()
            raise ConnectorError(
                f"refusing a redirect from {req.full_url} to a non-HTTPS URL: {newurl}"
            )
        self._record(newurl)
        request = super().redirect_request(req, fp, code, msg, headers, newurl)
        if request is not None and _host_of(newurl) != _host_of(req.full_url):
            # Design note D-93b. Removed from both mappings: urllib keeps
            # headers added by a caller in `headers` and headers it added
            # itself in `unredirected_hdrs`, and a credential in either one is
            # still a credential on the wire.
            for mapping in (request.headers, request.unredirected_hdrs):
                for key in [name for name in mapping if name.lower() == "authorization"]:
                    mapping.pop(key)
        return request


class Http:
    """A deliberately small HTTP client, with the policy in one place.

    Everything a reader would want to audit about this tool's network behaviour
    is here: HTTPS only, certificate verification never disabled, a bounded
    response, a bounded number of redirects, a fixed timeout, no cookie jar, no
    credential chain, and a record of every host contacted so the caller can
    print it. A connector cannot opt out of any of it, because a connector gets
    an `Http` and has no other way to reach the network.

    `ssl_context` is the one seam, and it is narrower than it looks: it is how
    the test suite reaches a server it started itself, and `verified_context`
    refuses any context that would not still verify the certificate and the
    hostname. See design note D-82 for why the seam has that shape rather
    than the shape of an `--insecure` flag.
    """

    def __init__(
        self,
        *,
        offline: bool = False,
        timeout: float = DEFAULT_TIMEOUT,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.offline = offline
        self.timeout = timeout
        self.hosts: list[str] = []
        self.requests = 0
        self._context = verified_context(ssl_context)
        # Built by hand rather than with `build_opener`, so that this list is
        # the complete answer to "what can this client do". There is no
        # `HTTPHandler`, which means a plaintext URL cannot be opened even if
        # something got past `_guard`: the opener has nothing that speaks it.
        # There is no cookie processor and no authentication handler, so no
        # credential is ever negotiated or remembered. `ProxyHandler` stays,
        # because an operator behind a corporate proxy is a real operator and
        # `urlopen` honoured their environment before this class did.
        self._opener = urllib.request.OpenerDirector()
        for handler in (
            urllib.request.ProxyHandler(),
            urllib.request.HTTPSHandler(context=self._context),
            HttpsOnlyRedirects(self._note_host),
            urllib.request.HTTPErrorProcessor(),
            urllib.request.HTTPDefaultErrorHandler(),
            urllib.request.UnknownHandler(),
        ):
            self._opener.add_handler(handler)

    def _note_host(self, url: str) -> None:
        """Record a host this client is about to talk to, once.

        Called by `_guard` for the URL a connector asked for and by
        `HttpsOnlyRedirects` for every hop after it, so the list the CLI prints
        is the set of servers involved rather than the set a connector meant to
        involve. See design note D-93.
        """
        hostname = urllib.parse.urlsplit(url).hostname
        if hostname and hostname not in self.hosts:
            self.hosts.append(hostname)

    def _guard(self, url: str) -> str:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https":
            # http:// is refused rather than upgraded. A discovery tool that
            # silently rewrote a plaintext URL would hide that the operator
            # configured one, and the operator is the person who needs to know.
            raise ConnectorError(f"refusing a non-HTTPS URL: {url!r}")
        if not parsed.hostname:
            raise ConnectorError(f"no host in URL: {url!r}")
        if self.offline:
            raise OfflineError(f"--offline is set and {parsed.hostname} was needed")
        self._note_host(url)
        return parsed.hostname

    def get(self, url: str, headers: dict[str, str] | None = None) -> bytes:
        self._guard(url)
        # S310 asks whether this URL could carry a scheme like file:. `_guard`
        # on the line above refused everything but https before we got here,
        # which is the check the rule exists to demand.
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})  # noqa: S310
        self.requests += 1
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                return response.read(MAX_RESPONSE_BYTES + 1)[:MAX_RESPONSE_BYTES]
        except urllib.error.HTTPError as exc:
            raise HttpStatusError(
                f"{url} returned HTTP {exc.code}", status=exc.code, headers=dict(exc.headers)
            ) from exc
        except urllib.error.URLError as exc:
            raise ConnectorError(f"{url} could not be reached: {exc.reason}") from exc

    def get_json(self, url: str, headers: dict[str, str] | None = None) -> Any:
        blob = self.get(url, headers)
        try:
            return json.loads(blob.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConnectorError(f"{url} did not return JSON") from exc

    def download(self, url: str, destination: Path, headers: dict[str, str] | None = None) -> tuple[int, str]:
        """Stream one artifact to disk, hashing as it goes. Returns (bytes, sha256).

        Hashed while streaming rather than after, so the digest is of what was
        written and a truncated transfer cannot produce a digest of a complete
        file. Bounded by MAX_FETCH_BYTES, and the partial file is removed on
        the way out of a failure so a later run cannot mistake it for a
        complete download.
        """
        self._guard(url)
        # S310 asks whether this URL could carry a scheme like file:. `_guard`
        # on the line above refused everything but https before we got here,
        # which is the check the rule exists to demand.
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})  # noqa: S310
        self.requests += 1
        digest = hashlib.sha256()
        written = 0
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                with destination.open("wb") as handle:
                    while True:
                        chunk = response.read(1 << 20)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > MAX_FETCH_BYTES:
                            raise ConnectorError(
                                f"{url} exceeds the {MAX_FETCH_BYTES} byte fetch cap"
                            )
                        digest.update(chunk)
                        handle.write(chunk)
        except urllib.error.HTTPError as exc:
            destination.unlink(missing_ok=True)
            raise HttpStatusError(
                f"{url} returned HTTP {exc.code}", status=exc.code, headers=dict(exc.headers)
            ) from exc
        except urllib.error.URLError as exc:
            destination.unlink(missing_ok=True)
            raise ConnectorError(f"{url} could not be reached: {exc.reason}") from exc
        except ConnectorError:
            destination.unlink(missing_ok=True)
            raise
        return written, digest.hexdigest()


def token_from_env(*names: str) -> str | None:
    """A credential, read from the environment and from nowhere else.

    No file, no keyring, no vendor credential chain. A tool that discovered a
    token in an ambient config file would be using an authority the operator
    did not knowingly hand it, and in a supply-chain tool that is the wrong
    default. The variable that was used is reported in the discovery notes so
    the operator can see which identity did the listing.
    """
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def token_with_source(*names: str) -> tuple[str | None, str | None]:
    """The same credential, plus the name of the variable it came from.

    The doctrine in D-80 is that the identity which did the listing is visible
    in the notes, and a helper that returns only the value cannot say whether a
    listing ran as the CI service account in `GITHUB_TOKEN` or as the
    developer's personal `GH_TOKEN`. Two connectors accept two variables each,
    so the difference is real and the operator is the person it matters to.

    The value still comes from `token_from_env`, which stays the only door to a
    credential in this package; this adds the label, never a second source.
    """
    token = token_from_env(*names)
    if token is None:
        return None, None
    for name in names:
        if os.environ.get(name) == token:
            return token, name
    return token, None  # pragma: no cover - unreachable while token_from_env reads os.environ


def stage(
    artifacts: tuple[RemoteArtifact, ...],
    destination: Path,
    http: Http,
    headers_for: Callable[[RemoteArtifact], dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Fetch discovered artifacts and check each against its declared digest.

    The digest comparison is the point of this function. A source that publishes
    a digest and then serves different bytes is either broken or hostile, and
    either way the operator needs to know before the bytes reach an inspector,
    so a mismatch is a hard failure for that artifact and the file is deleted.
    """
    destination.mkdir(parents=True, exist_ok=True)
    fetched: list[dict[str, Any]] = []
    problems: list[dict[str, Any]] = []
    started = time.monotonic()

    for artifact in artifacts:
        safe = _safe_relative(artifact.path)
        target = destination / safe
        try:
            size, digest = http.download(artifact.uri, target, headers_for(artifact) if headers_for else None)
        except ConnectorError as exc:
            problems.append({"path": artifact.path, "rule": "ACT-CON-001", "detail": str(exc)})
            continue
        if artifact.declared_sha256 and artifact.declared_sha256.lower() != digest:
            target.unlink(missing_ok=True)
            problems.append(
                {
                    "path": artifact.path,
                    "rule": "ACT-CON-002",
                    "detail": "the source declared a digest the bytes do not match",
                    "declared": artifact.declared_sha256,
                    "measured": digest,
                }
            )
            continue
        fetched.append(
            {
                "path": artifact.path,
                "local": str(target.relative_to(destination)),
                "bytes": size,
                "sha256": digest,
                "declared_sha256": artifact.declared_sha256,
                "digest_confirmed": bool(artifact.declared_sha256),
            }
        )
    return {
        "fetched": fetched,
        "problems": problems,
        "hosts_contacted": list(http.hosts),
        "requests": http.requests,
        "seconds": round(time.monotonic() - started, 3),
    }


def _safe_relative(path: str) -> Path:
    """A remote path, reduced to something that cannot escape the destination.

    A remote index is attacker-controlled input, so `../../etc/passwd` and an
    absolute path both have to be neutralised here rather than trusted to the
    filesystem. Every component that is not a plain name is dropped, and an
    empty result becomes a hash of the original so two hostile paths cannot
    collide into one file.
    """
    parts = [p for p in PurePosixPathParts(path) if p not in ("", ".", "..") and not p.startswith("/")]
    cleaned = [p.replace("\\", "_").replace(":", "_") for p in parts]
    if not cleaned:
        return Path(hashlib.sha256(path.encode("utf-8")).hexdigest()[:16])
    return Path(*cleaned)


def PurePosixPathParts(path: str) -> list[str]:  # noqa: N802 - reads as a constructor at the call site
    return path.replace("\\", "/").split("/")
