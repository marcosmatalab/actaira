"""S3-compatible object storage, over HTTPS, without an AWS SDK.

Design note D-89, and the limitation that is the first thing in this file for a
reason.

**This connector does not implement SigV4.** It lists a bucket that answers
anonymous `ListObjectsV2`, and it follows a presigned URL that somebody else
signed. It cannot list a private bucket, it will not read `~/.aws/credentials`,
it will not read `AWS_ACCESS_KEY_ID`, and it does not pick up an instance
profile or a web identity token. For a private bucket, generate a presigned
listing URL with a tool that has the credentials and pass that instead.

That is a real gap and it is stated here, in the notes of every discovery, and
in the CLI output, rather than being discovered by an operator whose listing
came back empty. The alternative was worse in both directions: a partial SigV4,
which is a signature implementation that works until the request has a
session token or a non-default region or a payload hash, and then fails in a
way that looks like a permission error; or boto3, which is 50 MB of transitive
dependency inside a tool whose argument is that it has one (design note D-81).

Design note D-89b, on why `complete` is never True here.

D-80 names the anonymous bucket listing as the case that can never prove it saw
everything, and this connector obeys that literally: `complete` is False on
every run, including the run where `IsTruncated` is false and every page was
followed. The reason is that a bucket policy can grant `s3:ListBucket` scoped
to a prefix, or with a condition on the caller, and a listing scoped that way
is indistinguishable from a complete one in the response: both end with
`IsTruncated: false`. The listing that came back is everything this caller was
allowed to see, which is a different sentence from everything the bucket holds,
and only the first one is true.

Design note D-89c, on the ETag.

An ETag is not a digest. For an object uploaded in one part it happens to be
the hex MD5 of the bytes; for a multipart upload it is an MD5 of the
concatenated part MD5s with `-<count>` on the end; for a server-side encrypted
object it may be neither. None of those is a SHA-256, so the ETag goes into
`extra` where it is useful for spotting a change, and `declared_sha256` stays
empty. `ListObjectsV2` can report `ChecksumAlgorithm: SHA256` for an object
without reporting the checksum itself, which is a statement that a digest
exists somewhere this listing does not carry, and that is noted rather than
turned into a value.

Design note D-89d, on parsing XML from a stranger.

The response is XML, `xml.etree` is what stdlib offers, and expat will happily
expand an entity bomb. The response is already bounded to `MAX_RESPONSE_BYTES`
by `Http`, which caps the input but not what a DTD can turn it into, so any
document carrying a doctype or an entity declaration is refused before it
reaches the parser. Every entity expansion attack needs one, and no S3
implementation emits one.
"""
from __future__ import annotations

import urllib.parse
import xml.etree.ElementTree as ElementTree

from .model import MAX_PAGES, Connector, ConnectorError, Discovery, Http, RemoteArtifact
from .registry import register

NAME = "s3"
NAMESPACE = "{http://s3.amazonaws.com/doc/2006-03-01/}"
PAGE_KEYS = 1000
# Where an `s3://bucket/prefix` source is looked for when the operator named no
# endpoint. Virtual-hosted style against AWS, in one place rather than spelled
# into a format string halfway down the file, so that the assumption is
# readable and so that a test can point this connector at a server it started.
ENDPOINT_TEMPLATE = "https://{bucket}.s3.amazonaws.com/"
# The two markers no S3 response contains and no entity expansion can do
# without. Checked as bytes, before any parse. See design note D-89d.
FORBIDDEN_XML = (b"<!DOCTYPE", b"<!ENTITY", b"<!doctype", b"<!entity")


def accepts(uri: str) -> bool:
    lowered = uri.lower()
    if lowered.startswith("s3://"):
        return True
    if not lowered.startswith("https://"):
        return False
    # A presigned URL, which is the supported route into a private bucket. It
    # is recognised by the signature parameter rather than by the hostname,
    # because the hostname of an S3-compatible endpoint can be anything.
    return "x-amz-signature=" in lowered or "x-amz-credential=" in lowered


def _bucket_url(uri: str) -> tuple[str, str, str]:
    """`(base_url, bucket, prefix)` for an `s3://bucket/prefix` source.

    Virtual-hosted style against AWS by default. An S3-compatible endpoint
    elsewhere is reached by passing its presigned or query URL directly, which
    is also the only way to name a region or a port: guessing an endpoint from
    a bucket name is how a listing silently goes to the wrong provider.
    """
    remainder = uri[len("s3://"):].strip("/")
    bucket, _, prefix = remainder.partition("/")
    if not bucket:
        raise ConnectorError(f"{uri!r} names no bucket")
    return ENDPOINT_TEMPLATE.format(bucket=bucket), bucket, prefix


def _text(element: ElementTree.Element, tag: str) -> str | None:
    found = element.find(f"{NAMESPACE}{tag}")
    if found is None:
        found = element.find(tag)  # an endpoint that answers without the namespace
    return found.text if found is not None and found.text is not None else None


def _parse_listing(blob: bytes, url: str) -> ElementTree.Element:
    for marker in FORBIDDEN_XML:
        if marker in blob:
            raise ConnectorError(
                f"{url} answered with an XML document carrying {marker.decode()}, which no S3 listing does "
                "and which is how an entity expansion arrives; it was not parsed"
            )
    try:
        # S314 is answered by the doctype refusal above and by the 8 MiB cap in
        # `Http`: see design note D-89d. defusedxml would be a dependency added
        # to defend against a document this function already refuses.
        return ElementTree.fromstring(blob)  # noqa: S314
    except ElementTree.ParseError as exc:
        raise ConnectorError(f"{url} did not return a parsable ListBucketResult: {exc}") from exc


def discover(uri: str, *, http: Http, revision: str | None = None) -> Discovery:
    presigned = not uri.lower().startswith("s3://")
    notes: list[str] = [
        "this connector lists buckets that allow anonymous ListObjectsV2, or follows a presigned URL. It does "
        "not implement SigV4: for a private bucket, pass a presigned URL generated by a tool that holds the "
        "credentials (design note D-89)"
    ]
    if revision is not None:
        notes.append("an object listing has no revisions; --revision was ignored")

    if presigned and "list-type=2" not in uri.lower():
        return _single_presigned_object(uri, notes)

    if presigned:
        base = uri
        bucket = urllib.parse.urlsplit(uri).hostname or "presigned"
        prefix = urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query).get("prefix", [""])[0]
    else:
        base, bucket, prefix = _bucket_url(uri)

    artifacts: list[RemoteArtifact] = []
    continuation: str | None = None
    truncated = False
    pages = 0
    checksum_only: set[str] = set()

    while pages < MAX_PAGES:
        pages += 1
        url = _page_url(base, prefix, continuation, presigned)
        root = _parse_listing(http.get(url), url)
        for contents in root.findall(f"{NAMESPACE}Contents") or root.findall("Contents"):
            key = _text(contents, "Key")
            if not key or key.endswith("/"):
                # A zero-byte key ending in a slash is a console-created folder
                # marker, not an object anybody wants fetched.
                continue
            size = _text(contents, "Size")
            algorithm = _text(contents, "ChecksumAlgorithm")
            if algorithm:
                checksum_only.add(algorithm)
            artifacts.append(
                RemoteArtifact(
                    path=key,
                    uri=urllib.parse.urljoin(base, urllib.parse.quote(key)) if not presigned
                    else _object_url(base, key),
                    size_bytes=int(size) if size and size.isdigit() else None,
                    # Design note D-89c: an ETag is not a SHA-256 and sometimes
                    # not a digest of the object at all.
                    declared_sha256=None,
                    revision=None,
                    source=NAME,
                    extra={
                        "etag": (_text(contents, "ETag") or "").strip('"'),
                        "last_modified": _text(contents, "LastModified"),
                        "storage_class": _text(contents, "StorageClass"),
                        "checksum_algorithm": algorithm,
                    },
                )
            )
        truncated = (_text(root, "IsTruncated") or "false").lower() == "true"
        continuation = _text(root, "NextContinuationToken")
        if not truncated or not continuation:
            break
        if presigned:
            # A presigned URL is signed over its exact query string. Appending
            # a continuation token invalidates the signature, so the honest
            # answer is to stop and say the listing is one page deep.
            notes.append(
                "the listing is truncated and the URL is presigned: adding a continuation token would break "
                "the signature, so only the first page was read"
            )
            break

    if truncated:
        notes.append(
            f"IsTruncated is true after {pages} page(s); there are more keys under this prefix than were listed"
        )
    if pages >= MAX_PAGES and truncated:
        notes.append(f"stopped at the {MAX_PAGES} page cap")
    if checksum_only:
        notes.append(
            f"the listing reports ChecksumAlgorithm {sorted(checksum_only)} for some objects but not the "
            "checksum itself, so a digest exists that this listing does not carry"
        )
    notes.append(
        "no object publishes a sha256 here; the ETag is an MD5 for single-part uploads and something else "
        "entirely for multipart ones, so it is kept in extra and never compared (design note D-89c)"
    )
    notes.append(
        "listing_complete is false by construction: a bucket policy can scope an anonymous listing to a prefix "
        "or a caller, and a scoped listing ends exactly like a complete one (design note D-89b)"
    )

    return Discovery(
        source=f"{NAME}:{bucket}/{prefix}" if prefix else f"{NAME}:{bucket}",
        artifacts=tuple(artifacts),
        # Design note D-89b. Never True, including when nothing was truncated.
        complete=False,
        hosts_contacted=tuple(http.hosts),
        notes=tuple(notes),
        revision=None,
    )


def _page_url(base: str, prefix: str, continuation: str | None, presigned: bool) -> str:
    if presigned:
        return base
    query = {"list-type": "2", "max-keys": str(PAGE_KEYS)}
    if prefix:
        query["prefix"] = prefix
    if continuation:
        query["continuation-token"] = continuation
    return base + "?" + urllib.parse.urlencode(query)


def _object_url(listing_url: str, key: str) -> str:
    """Where a key listed through a presigned URL would be fetched from.

    The listing signature does not cover an object GET, so this URL will very
    likely be refused. It is emitted anyway, unsigned and honest, so that the
    listing is still useful and a `--fetch` fails with the registry's own 403
    rather than with a URL this tool invented and pretended would work.
    """
    parts = urllib.parse.urlsplit(listing_url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, "/" + urllib.parse.quote(key.lstrip("/")), "", ""))


def _single_presigned_object(uri: str, notes: list[str]) -> Discovery:
    """A presigned URL for one object: one artifact, and no listing at all.

    Nothing is fetched and nothing is contacted, so `hosts_contacted` stays
    empty: a host this tool is about to talk to is not a host it talked to, and
    the two must not print the same. The scheme is still checked here, because
    a presigned `http://` URL would otherwise be recorded now and refused much
    later, at the download, after the operator had read a listing. `complete` is
    false for the reason it is always false in this file plus a sharper one: a
    single object is not a listing of anything.
    """
    parts = urllib.parse.urlsplit(uri)
    if parts.scheme != "https":
        raise ConnectorError(f"refusing a non-HTTPS URL: {uri!r}")
    key = parts.path.lstrip("/") or "object"
    notes.append(
        "this URL is presigned for a single object rather than for a listing, so one artifact is reported and "
        "nothing was enumerated"
    )
    return Discovery(
        source=f"{NAME}:{parts.hostname}/{key}",
        artifacts=(
            RemoteArtifact(
                path=key,
                uri=uri,
                size_bytes=None,
                declared_sha256=None,
                source=NAME,
                extra={"presigned": True},
            ),
        ),
        complete=False,
        hosts_contacted=(),
        notes=tuple(notes),
        revision=None,
    )


CONNECTOR = register(
    Connector(
        name=NAME,
        summary_key="connector.s3",
        needs_network=True,
        discover=discover,
        accepts=accepts,
    )
)
