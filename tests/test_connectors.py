"""The discovery connectors, against a TLS server this file starts itself.

No test in this file touches the network. Every API response is canned here,
served from `127.0.0.1` on an ephemeral port, and each connector is pointed at
it by the one constant it builds its URLs from. What that buys is that the code
under test is the shipped code: the same `urllib` call, the same parsing, the
same `complete` decision, and the same certificate verification.

The certificate is the interesting part. `Http` speaks HTTPS and nothing else,
and it has no way to turn verification off, on purpose (design note D-82). So
this file generates a CA with `cryptography`, which is already the single
runtime dependency of this project, issues a `localhost` certificate from it,
and hands the client a context that trusts that CA *and still checks the
chain and the hostname*. The seam being exercised is therefore the honest one:
the tests do not weaken TLS, they extend the set of authorities the client
accepts, for one process, to include one they made.

`verified_context` refuses anything less, and
`test_a_context_that_would_not_verify_is_refused` is the negative control that
proves the refusal is real rather than a sentence in a docstring.

What is asserted here, beyond each connector listing what it was served:

  * a paginated source that stopped short reports `complete = False`. Three of
    them, three different signals: GitHub's `truncated: true`, a full page from
    the Hub, and `IsTruncated` from S3.
  * a declared digest that does not match the bytes is `ACT-CON-002` and the
    file is deleted, end to end through the CLI.
  * a remote path of `../../etc/passwd` lands inside the destination.
  * an `http://` URL is refused rather than upgraded.
  * `--offline` is an error, never an empty listing.
  * an artifact past the fetch cap is refused mid-stream and leaves nothing.
"""
from __future__ import annotations

import http.server
import ipaddress
import json
import os
import ssl
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from actaira import cli
from actaira.connectors import filesystem, github, huggingface, mlflow, oci, registry, s3, url
from actaira.connectors import model as connector_model
from actaira.connectors.model import (
    ConnectorError,
    Http,
    HttpStatusError,
    OfflineError,
    RemoteArtifact,
    _safe_relative,
    stage,
    verified_context,
)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
GIT_SHA1 = "1" * 40

# Every variable any connector in this package reads. Cleared for every test in
# this file, because a developer with a real GITHUB_TOKEN in their shell would
# otherwise run this suite in a different configuration from CI, and would send
# that token to a server this file started. Loopback and canned, but still a
# credential on a wire nobody meant to put it on.
CREDENTIAL_VARIABLES = (
    "HF_TOKEN", "HUGGINGFACE_TOKEN", "GITHUB_TOKEN", "GH_TOKEN",
    "OCI_TOKEN", "REGISTRY_TOKEN", "MLFLOW_TRACKING_TOKEN",
    "MLFLOW_TRACKING_USERNAME", "MLFLOW_TRACKING_PASSWORD",
)


@pytest.fixture(autouse=True)
def no_ambient_credentials(monkeypatch):
    """The suite runs with no credential in the environment, always."""
    for name in CREDENTIAL_VARIABLES:
        monkeypatch.delenv(name, raising=False)


# ---------------------------------------------------------------------------
# A certificate authority, and a server that presents a certificate from it
# ---------------------------------------------------------------------------

def _make_certificate(tmp: Path) -> tuple[Path, Path, str]:
    """A self-signed `localhost` certificate, and the PEM to trust it by.

    Self-signed and marked as a CA so the same PEM can be both the server's
    certificate and the client's trust anchor. One day of validity: a fixture
    certificate that outlives the test run is a fixture certificate that ends
    up somewhere else.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    certificate_path = tmp / "server.pem"
    key_path = tmp / "server.key"
    certificate_path.write_bytes(certificate_pem)
    key_path.write_bytes(key_pem)
    return certificate_path, key_path, certificate_pem.decode("ascii")


class CannedServer:
    """Canned API responses over TLS, plus a record of what was asked for.

    `routes` maps a path (without the query string) to a callable that gets the
    request handler and returns `(status, headers, body)`. A callable rather
    than a blob because two of the protocols under test are conversations: the
    OCI bearer challenge answers differently once an `Authorization` header
    arrives, and the S3 listing answers differently once a continuation token
    does.
    """

    def __init__(self) -> None:
        self.routes: dict[str, object] = {}
        self.seen: list[tuple[str, dict[str, str]]] = []
        self.base = ""

    def json(self, path: str, payload: object, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.routes[path] = lambda _handler: (status, {"Content-Type": "application/json"}, body)

    def raw(self, path: str, body: bytes, content_type: str = "application/octet-stream") -> None:
        self.routes[path] = lambda _handler: (200, {"Content-Type": content_type}, body)

    def dynamic(self, path: str, function) -> None:
        self.routes[path] = function

    def asked(self, path: str) -> list[dict[str, str]]:
        return [headers for seen_path, headers in self.seen if seen_path.split("?")[0] == path]


@contextmanager
def serving(tmp: Path):
    """A TLS server on the loopback interface for the length of the block."""
    certificate_path, key_path, certificate_pem = _make_certificate(tmp)
    canned = CannedServer()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802 - the name http.server dispatches on
            canned.seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
            route = canned.routes.get(self.path.split("?")[0])
            if route is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            status, headers, body = route(self)
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:  # keep the test output readable
            return

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_path, key_path)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    canned.base = f"localhost:{server.server_address[1]}"
    canned.trust = certificate_pem
    try:
        yield canned
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def canned(tmp_path):
    with serving(tmp_path) as server:
        yield server


@pytest.fixture
def http_client(canned):
    """An `Http` that trusts the fixture CA and nothing else about it changes.

    `create_default_context` with `cadata` keeps `check_hostname` True and
    `verify_mode` CERT_REQUIRED, which is what `verified_context` demands. A
    context built any other way is refused, which is the point of D-82.
    """
    context = ssl.create_default_context(cadata=canned.trust)
    return Http(ssl_context=context)


# ---------------------------------------------------------------------------
# The seam itself
# ---------------------------------------------------------------------------

def test_the_injected_context_still_verifies(canned, http_client):
    """The fixture context is not a weakened one; assert that rather than assume."""
    assert http_client._context.check_hostname is True
    assert http_client._context.verify_mode is ssl.CERT_REQUIRED


def test_a_context_that_would_not_verify_is_refused():
    """The negative control for design note D-82.

    Without this, "the injection point cannot disable verification" is a claim
    in a docstring. With it, the claim is the one thing in this file that would
    fail if somebody added an `--insecure` flag by the back door.
    """
    insecure = ssl.create_default_context()
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE

    with pytest.raises(ConnectorError) as caught:
        verified_context(insecure)
    assert "verify" in str(caught.value)

    with pytest.raises(ConnectorError):
        Http(ssl_context=insecure)


def test_an_untrusted_certificate_is_still_rejected(canned):
    """A client that does not trust the fixture CA cannot reach the fixture.

    This is what proves the TLS in these tests is real: the same server, the
    same URL, a default trust store, and the connection fails.
    """
    canned.json("/x", {"ok": True})
    with pytest.raises(ConnectorError) as caught:
        Http().get_json(f"https://{canned.base}/x")
    assert "could not be reached" in str(caught.value)


# ---------------------------------------------------------------------------
# The client's own rules
# ---------------------------------------------------------------------------

def test_a_plaintext_url_is_refused_rather_than_upgraded():
    with pytest.raises(ConnectorError) as caught:
        Http().get("http://huggingface.co/api/models/a/b/tree/main")
    assert "non-HTTPS" in str(caught.value)


def test_a_plaintext_url_is_refused_before_the_host_is_recorded():
    """A refused URL is not a host this tool contacted, and must not print as one."""
    client = Http()
    with pytest.raises(ConnectorError):
        client.get("http://example.invalid/x")
    assert client.hosts == []
    assert client.requests == 0


def test_offline_turns_the_whole_package_into_an_error(canned):
    client = Http(offline=True)
    with pytest.raises(OfflineError) as caught:
        client.get_json(f"https://{canned.base}/anything")
    assert "offline" in str(caught.value)
    assert canned.seen == [], "offline must refuse before the socket, not after"


def test_a_refusal_carries_the_status_and_the_headers(canned, http_client):
    """Design note D-83: the OCI challenge lives in the headers of a 401."""
    canned.dynamic(
        "/v2/acme/model/manifests/v1",
        lambda _handler: (401, {"WWW-Authenticate": 'Bearer realm="https://example.test/token"'}, b"{}"),
    )
    with pytest.raises(HttpStatusError) as caught:
        http_client.get_json(f"https://{canned.base}/v2/acme/model/manifests/v1")
    assert caught.value.status == 401
    assert caught.value.headers["www-authenticate"].startswith("Bearer")


def test_a_redirect_to_a_plaintext_url_is_refused(canned, http_client):
    """Design note D-93, and the defect that produced it.

    `urlopen` follows a 302 from https to http without a word, which would have
    this client fetching a supply-chain artifact over a channel it says it
    refuses, and reporting the host that redirected rather than the host that
    served.
    """
    canned.dynamic("/start", lambda _h: (302, {"Location": "http://example.invalid/downgraded"}, b""))

    with pytest.raises(ConnectorError) as caught:
        http_client.get(f"https://{canned.base}/start")

    assert "non-HTTPS" in str(caught.value)
    assert "example.invalid" not in http_client.hosts, "a refused hop is not a host we contacted"


def test_a_redirect_that_is_followed_is_recorded_as_a_host_contacted(canned, http_client):
    """The host that served the bytes is the host the operator needs printed.

    Both names belong to the fixture server, and the certificate carries both,
    so this is a real hop over a real connection rather than a mock: the client
    was told `localhost` and ended up talking to `127.0.0.1`.
    """
    port = canned.base.split(":")[1]
    canned.dynamic("/start", lambda _h: (302, {"Location": f"https://127.0.0.1:{port}/end"}, b""))
    canned.raw("/end", b"the artifact")

    assert http_client.get(f"https://{canned.base}/start") == b"the artifact"
    assert http_client.hosts == ["localhost", "127.0.0.1"]


def test_a_credential_does_not_travel_across_a_redirect_to_another_host(canned, http_client):
    """Design note D-93b, and the leak it closes.

    This is not a hypothetical shape. A GitHub release asset redirects to
    `objects.githubusercontent.com` and a HuggingFace resolve URL redirects to
    the LFS CDN, so before this the operator's token was handed to a second
    service on every fetch that mattered.
    """
    port = canned.base.split(":")[1]
    canned.dynamic("/start", lambda _h: (302, {"Location": f"https://127.0.0.1:{port}/end"}, b""))
    canned.raw("/end", b"the artifact")

    http_client.get(f"https://{canned.base}/start", {"Authorization": "Bearer operator-token"})

    assert canned.asked("/start")[0]["authorization"] == "Bearer operator-token"
    assert "authorization" not in canned.asked("/end")[0], "the token followed the redirect"


def test_a_credential_survives_a_redirect_that_stays_on_the_same_host(canned, http_client):
    """The other half of D-93b: one service talking about its own paths.

    Dropping the header here would break every source that answers a canonical
    URL with a redirect to a versioned one, which is most of them.
    """
    canned.dynamic("/moved", lambda _h: (302, {"Location": f"https://{canned.base}/final"}, b""))
    canned.raw("/final", b"the artifact")

    http_client.get(f"https://{canned.base}/moved", {"Authorization": "Bearer operator-token"})

    assert canned.asked("/final")[0]["authorization"] == "Bearer operator-token"


def test_the_client_has_no_handler_that_can_speak_plaintext(http_client):
    """Belt and braces for `_guard`, asserted at the opener rather than above it.

    `_guard` refuses `http://` before a request is built. This checks the layer
    under it: even handed a plaintext URL directly, the opener has nothing that
    knows how to open one, because no `HTTPHandler` was ever added to it.
    """
    import urllib.error

    with pytest.raises(urllib.error.URLError, match="unknown url type"):
        http_client._opener.open("http://example.invalid/x", timeout=5)


def test_an_artifact_past_the_fetch_cap_is_refused_and_leaves_nothing(canned, http_client, tmp_path, monkeypatch):
    """The cap is lowered rather than the file enlarged.

    `MAX_FETCH_BYTES` is 2 GiB and a test that served one would be measuring
    the machine. The bound is read from the module at call time, so lowering it
    exercises the same branch a 3 GiB weight file would.
    """
    monkeypatch.setattr(connector_model, "MAX_FETCH_BYTES", 64)
    canned.raw("/big.bin", b"\x00" * 4096)
    target = tmp_path / "out" / "big.bin"

    with pytest.raises(ConnectorError) as caught:
        http_client.download(f"https://{canned.base}/big.bin", target)

    assert "fetch cap" in str(caught.value)
    assert not target.exists(), "a refused download must not leave a partial file behind"


def test_a_response_larger_than_the_body_cap_is_truncated_rather_than_read(canned, http_client, monkeypatch):
    monkeypatch.setattr(connector_model, "MAX_RESPONSE_BYTES", 16)
    canned.raw("/huge.json", b"x" * 4096)
    assert len(http_client.get(f"https://{canned.base}/huge.json")) == 16


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

ACCEPTED = [
    ("hf://acme/model", "huggingface"),
    ("hf://datasets/acme/corpus", "huggingface"),
    ("https://huggingface.co/acme/model/tree/main", "huggingface"),
    ("github://acme/model", "github"),
    ("https://github.com/acme/model", "github"),
    ("oci://ghcr.io/acme/model:v1", "oci"),
    ("docker://registry.example.test/acme/model@sha256:" + DIGEST_A, "oci"),
    ("s3://bucket/prefix", "s3"),
    ("https://bucket.s3.amazonaws.com/?list-type=2&X-Amz-Signature=deadbeef", "s3"),
    ("mlflow://tracking.example.test/models/ranker", "mlflow"),
    ("manifest:/nonexistent/list.txt", "url"),
]


@pytest.mark.parametrize("uri, expected", ACCEPTED, ids=[uri for uri, _ in ACCEPTED])
def test_every_documented_uri_shape_reaches_exactly_one_connector(uri, expected):
    """Design note D-84. Exactly one, asserted rather than left to ordering."""
    matches = [connector.name for connector in registry.all_connectors() if connector.accepts(uri)]
    assert matches == [expected]


def test_a_directory_and_a_file_go_to_different_connectors(tmp_path):
    """The one overlap that could exist, separated by a fact about the disk."""
    directory = tmp_path / "models"
    directory.mkdir()
    manifest = tmp_path / "list.txt"
    manifest.write_text("https://example.test/a.bin\n", encoding="utf-8")

    assert registry.for_uri(str(directory)).name == "filesystem"
    assert registry.for_uri(str(manifest)).name == "url"


def test_a_uri_nobody_accepts_is_an_error_naming_it():
    with pytest.raises(ConnectorError) as caught:
        registry.for_uri("ipfs://Qm-something")
    assert "ipfs://Qm-something" in str(caught.value)


def test_a_duplicate_connector_name_is_refused():
    with pytest.raises(ValueError, match="duplicate"):
        registry.register(registry.get("filesystem"))


def test_every_connector_has_prose_in_both_catalogues():
    from actaira.i18n.catalog import SUPPORTED, Catalog

    for connector in registry.all_connectors():
        for lang in SUPPORTED:
            text = Catalog(lang).line(connector.summary_key)
            assert text != connector.summary_key, f"{lang} has no summary for {connector.name}"
            assert len(text) > 20


# ---------------------------------------------------------------------------
# filesystem
# ---------------------------------------------------------------------------

@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "models"
    (root / "nested").mkdir(parents=True)
    (root / "config.json").write_text('{"a": 1}', encoding="utf-8")
    (root / "nested" / "weights.safetensors").write_bytes(b"\x00" * 32)
    (root / ".git").mkdir()
    (root / ".git" / "objects").write_text("not an artifact", encoding="utf-8")
    return root


def test_the_filesystem_connector_lists_the_tree_and_can_prove_it(tree):
    discovery = filesystem.discover(str(tree), http=Http(offline=True))

    assert sorted(artifact.path for artifact in discovery.artifacts) == [
        "config.json",
        "nested/weights.safetensors",
    ]
    assert discovery.complete is True, "a walk is the one listing here that can say this"
    assert discovery.hosts_contacted == ()


def test_the_filesystem_connector_declares_no_digest_it_computed_itself(tree):
    """Design note D-85b: a digest checked against itself is not a check."""
    discovery = filesystem.discover(str(tree), http=Http(offline=True))

    assert all(artifact.declared_sha256 is None for artifact in discovery.artifacts)
    assert any("would be a check that cannot fail" in note for note in discovery.notes)


def test_a_symlink_is_neither_followed_nor_listed(tree, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("not part of this tree", encoding="utf-8")
    (tree / "link.safetensors").symlink_to(outside)

    discovery = filesystem.discover(str(tree), http=Http(offline=True))

    assert not any("link" in artifact.path for artifact in discovery.artifacts)
    assert any("symlink" in note for note in discovery.notes)


def test_a_walk_that_stopped_at_the_cap_is_not_complete(tree, monkeypatch):
    monkeypatch.setattr(filesystem, "MAX_ENTRIES", 1)

    discovery = filesystem.discover(str(tree), http=Http(offline=True))

    assert len(discovery.artifacts) == 1
    assert discovery.complete is False
    assert any("prefix of the tree" in note for note in discovery.notes)


def test_the_filesystem_connector_works_offline_because_it_needs_nothing(tree):
    assert registry.get("filesystem").needs_network is False
    assert filesystem.discover(str(tree), http=Http(offline=True)).artifacts


# ---------------------------------------------------------------------------
# huggingface
# ---------------------------------------------------------------------------

def _hub_tree(canned, entries, kind="models", repo="acme/model", revision="main"):
    canned.json(f"/api/{kind}/{repo}/tree/{revision}", entries)


HUB_ENTRIES = [
    {"type": "directory", "path": "nested", "oid": GIT_SHA1},
    {"type": "file", "path": "config.json", "size": 42, "oid": GIT_SHA1},
    {
        "type": "file",
        "path": "model.safetensors",
        "size": 1024,
        "oid": GIT_SHA1,
        "lfs": {"oid": DIGEST_A, "size": 1024, "pointerSize": 134},
    },
]


def test_the_hub_connector_lists_files_and_keeps_the_two_digests_apart(canned, http_client, monkeypatch):
    monkeypatch.setattr(huggingface, "HOST", canned.base)
    _hub_tree(canned, HUB_ENTRIES)

    discovery = huggingface.discover("hf://acme/model", http=http_client)

    by_path = {artifact.path: artifact for artifact in discovery.artifacts}
    assert set(by_path) == {"config.json", "model.safetensors"}, "a directory entry is not an artifact"
    # Design note D-86: the LFS oid is a sha256 of the bytes and lands in the
    # declared field; the git oid is a sha1 over a blob header and does not.
    assert by_path["model.safetensors"].declared_sha256 == DIGEST_A
    assert by_path["config.json"].declared_sha256 is None
    assert by_path["config.json"].extra["git_oid"] == GIT_SHA1
    assert by_path["model.safetensors"].uri == (
        f"https://{canned.base}/acme/model/resolve/main/model.safetensors"
    )
    assert discovery.complete is True
    assert discovery.hosts_contacted == ("localhost",)


def test_a_hub_lfs_oid_that_is_not_a_sha256_is_dropped_with_a_note(canned, http_client, monkeypatch):
    monkeypatch.setattr(huggingface, "HOST", canned.base)
    _hub_tree(canned, [{"type": "file", "path": "w.bin", "size": 8, "lfs": {"oid": "definitely-not-a-digest"}}])

    discovery = huggingface.discover("hf://acme/model", http=http_client)

    assert discovery.artifacts[0].declared_sha256 is None
    assert any("is not a SHA-256" in note for note in discovery.notes)


def test_a_prefixed_hub_lfs_oid_is_accepted(canned, http_client, monkeypatch):
    monkeypatch.setattr(huggingface, "HOST", canned.base)
    _hub_tree(canned, [{"type": "file", "path": "w.bin", "size": 8, "lfs": {"oid": f"sha256:{DIGEST_B}"}}])

    assert huggingface.discover("hf://acme/model", http=http_client).artifacts[0].declared_sha256 == DIGEST_B


def test_a_full_page_from_the_hub_is_reported_as_an_incomplete_listing(canned, http_client, monkeypatch):
    """Design note D-86b. The cursor is not followed, and that is said out loud."""
    monkeypatch.setattr(huggingface, "HOST", canned.base)
    monkeypatch.setattr(huggingface, "PAGE_LIMIT", 2)
    _hub_tree(canned, [
        {"type": "file", "path": "a.bin", "size": 1, "lfs": {"oid": DIGEST_A}},
        {"type": "file", "path": "b.bin", "size": 1, "lfs": {"oid": DIGEST_B}},
    ])

    discovery = huggingface.discover("hf://acme/model", http=http_client)

    assert len(discovery.artifacts) == 2
    assert discovery.complete is False
    assert any("full page" in note for note in discovery.notes)


def test_a_dataset_repository_uses_the_dataset_endpoints(canned, http_client, monkeypatch):
    monkeypatch.setattr(huggingface, "HOST", canned.base)
    _hub_tree(canned, [{"type": "file", "path": "train.parquet", "size": 9}], kind="datasets", repo="acme/corpus")

    discovery = huggingface.discover("hf://datasets/acme/corpus", http=http_client)

    assert discovery.artifacts[0].uri.startswith(f"https://{canned.base}/datasets/acme/corpus/resolve/main/")


def test_a_revision_flows_into_the_url_and_into_the_listing(canned, http_client, monkeypatch):
    monkeypatch.setattr(huggingface, "HOST", canned.base)
    commit = "0" * 40
    _hub_tree(canned, [{"type": "file", "path": "a.bin", "size": 1}], revision=commit)

    discovery = huggingface.discover("hf://acme/model", http=http_client, revision=commit)

    assert discovery.revision == commit
    assert not any("mutable reference" in note for note in discovery.notes)


def test_a_mutable_revision_is_named_as_one(canned, http_client, monkeypatch):
    monkeypatch.setattr(huggingface, "HOST", canned.base)
    _hub_tree(canned, [{"type": "file", "path": "a.bin", "size": 1}], revision="v1.0")

    discovery = huggingface.discover("hf://acme/model", http=http_client, revision="v1.0")

    assert any("mutable reference" in note for note in discovery.notes)


def test_the_hub_token_variable_that_was_used_is_named_in_the_notes(canned, http_client, monkeypatch):
    monkeypatch.setattr(huggingface, "HOST", canned.base)
    monkeypatch.setenv("HF_TOKEN", "secret-value")
    _hub_tree(canned, [{"type": "file", "path": "a.bin", "size": 1}])

    discovery = huggingface.discover("hf://acme/model", http=http_client)

    assert any("HF_TOKEN" in note for note in discovery.notes)
    assert not any("secret-value" in note for note in discovery.notes), "the value is not the label"
    assert canned.asked("/api/models/acme/model/tree/main")[0]["authorization"] == "Bearer secret-value"


def test_a_hub_owner_whose_name_is_a_view_marker_is_still_a_repository():
    """`hf://tree/model` names an organisation called `tree`, not a view.

    Found by reading this parser against the GitHub one, which already searched
    past the owner and the name for exactly this reason. Before the fix, this
    URI resolved to no repository at all and the operator got a message telling
    them their own URL was malformed.
    """
    assert huggingface._parse("hf://tree/model") == ("models", "tree/model", None)
    assert huggingface._parse("https://huggingface.co/acme/model/tree/dev") == ("models", "acme/model", "dev")
    assert huggingface._parse("hf://datasets/acme/corpus@v2") == ("datasets", "acme/corpus", "v2")


def test_a_uri_that_is_not_a_hub_repository_is_refused():
    with pytest.raises(ConnectorError, match="owner/name"):
        huggingface.discover("hf://onlyone", http=Http(offline=True))


# ---------------------------------------------------------------------------
# github
# ---------------------------------------------------------------------------

def _github(canned, monkeypatch, *, truncated=False, digest=f"sha256:{DIGEST_A}"):
    monkeypatch.setattr(github, "API_HOST", canned.base)
    monkeypatch.setattr(github, "RAW_HOST", canned.base)
    asset = {
        "name": "weights.safetensors",
        "browser_download_url": f"https://{canned.base}/download/weights.safetensors",
        "size": 2048,
        "content_type": "application/octet-stream",
        "id": 7,
    }
    if digest is not None:
        asset["digest"] = digest
    canned.json("/repos/acme/model/releases", [{"tag_name": "v1.0", "assets": [asset]}])
    canned.json(
        "/repos/acme/model/git/trees/HEAD",
        {
            "sha": "f" * 40,
            "truncated": truncated,
            "tree": [
                {"path": "README.md", "type": "blob", "size": 12, "sha": GIT_SHA1, "mode": "100644"},
                {"path": "src", "type": "tree", "sha": GIT_SHA1},
            ],
        },
    )


def test_the_github_connector_lists_assets_and_blobs_and_labels_which(canned, http_client, monkeypatch):
    _github(canned, monkeypatch)

    discovery = github.discover("github://acme/model", http=http_client)

    kinds = {artifact.path: artifact.extra["kind"] for artifact in discovery.artifacts}
    assert kinds == {"releases/v1.0/weights.safetensors": "release_asset", "tree/README.md": "tree_blob"}
    by_path = {artifact.path: artifact for artifact in discovery.artifacts}
    assert by_path["releases/v1.0/weights.safetensors"].declared_sha256 == DIGEST_A
    # Design note D-87c: a git blob sha is not a digest of the file's bytes.
    assert by_path["tree/README.md"].declared_sha256 is None
    assert by_path["tree/README.md"].extra["git_sha"] == GIT_SHA1
    assert discovery.complete is True


def test_a_truncated_github_tree_is_an_incomplete_listing(canned, http_client, monkeypatch):
    """Design note D-87. The one field in the response that decides this."""
    _github(canned, monkeypatch, truncated=True)

    discovery = github.discover("github://acme/model", http=http_client)

    assert discovery.complete is False
    assert any("truncated: true" in note for note in discovery.notes)


def test_a_full_page_of_releases_is_an_incomplete_listing(canned, http_client, monkeypatch):
    _github(canned, monkeypatch)
    monkeypatch.setattr(github, "PAGE_LIMIT", 1)

    discovery = github.discover("github://acme/model", http=http_client)

    assert discovery.complete is False
    assert any("full page" in note for note in discovery.notes)


def test_a_release_asset_with_no_digest_is_counted_rather_than_assumed(canned, http_client, monkeypatch):
    _github(canned, monkeypatch, digest=None)

    discovery = github.discover("github://acme/model", http=http_client)

    assert any("publish no sha256 digest" in note for note in discovery.notes)


def test_a_release_asset_digest_that_is_not_sha256_is_not_believed(canned, http_client, monkeypatch):
    _github(canned, monkeypatch, digest="md5:" + "0" * 32)

    discovery = github.discover("github://acme/model", http=http_client)

    assets = [a for a in discovery.artifacts if a.extra["kind"] == "release_asset"]
    assert assets[0].declared_sha256 is None


def test_a_github_rate_limit_says_so_instead_of_saying_forbidden(canned, http_client, monkeypatch):
    monkeypatch.setattr(github, "API_HOST", canned.base)
    canned.dynamic(
        "/repos/acme/model/releases",
        lambda _handler: (403, {"X-RateLimit-Remaining": "0"}, b'{"message":"rate limit"}'),
    )

    with pytest.raises(ConnectorError) as caught:
        github.discover("github://acme/model", http=http_client)
    assert "rate limit" in str(caught.value)
    assert "GITHUB_TOKEN" in str(caught.value)


def test_the_browser_url_form_names_the_same_repository():
    assert github._parse("https://github.com/acme/model/tree/dev") == ("acme", "model", "dev")
    assert github._parse("github://acme/model@v2") == ("acme", "model", "v2")
    assert github._parse("https://github.com/acme/model.git") == ("acme", "model", None)


# ---------------------------------------------------------------------------
# oci
# ---------------------------------------------------------------------------

MANIFEST = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
               "digest": f"sha256:{DIGEST_A}", "size": 7},
    "layers": [
        {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
         "digest": f"sha256:{DIGEST_B}", "size": 4096},
    ],
}


def _challenging_registry(canned, manifest=None, *, repo="acme/model", reference="v1"):
    """A registry that answers an unauthenticated manifest request with a 401."""
    payload = json.dumps(manifest if manifest is not None else MANIFEST).encode("utf-8")

    def route(handler):
        if not handler.headers.get("Authorization"):
            realm = f"https://{canned.base}/token"
            return (
                401,
                {"WWW-Authenticate":
                 f'Bearer realm="{realm}",service="registry.test",scope="repository:{repo}:pull"'},
                b'{"errors":[{"code":"UNAUTHORIZED"}]}',
            )
        return 200, {"Content-Type": "application/vnd.oci.image.manifest.v1+json"}, payload

    canned.dynamic(f"/v2/{repo}/manifests/{reference}", route)
    canned.json("/token", {"token": "anonymous-pull-token", "expires_in": 300})


def test_the_oci_connector_follows_the_anonymous_bearer_challenge(canned, http_client):
    """Design note D-88b: without this, neither Docker Hub nor GHCR answers."""
    _challenging_registry(canned)

    discovery = oci.discover(f"oci://{canned.base}/acme/model:v1", http=http_client)

    assert {artifact.declared_sha256 for artifact in discovery.artifacts} == {DIGEST_A, DIGEST_B}
    assert {artifact.extra["kind"] for artifact in discovery.artifacts} == {"config", "layer"}
    retried = canned.asked("/v2/acme/model/manifests/v1")
    assert len(retried) == 2, "the challenge is followed exactly once"
    assert retried[0].get("authorization") is None
    assert retried[1]["authorization"] == "Bearer anonymous-pull-token"
    assert any("anonymous pull token" in note for note in discovery.notes)


def test_the_token_endpoint_is_visible_in_the_hosts_contacted(canned, http_client):
    _challenging_registry(canned)

    discovery = oci.discover(f"oci://{canned.base}/acme/model:v1", http=http_client)

    assert "localhost" in discovery.hosts_contacted


def test_a_plaintext_token_realm_is_refused(canned, http_client):
    canned.dynamic(
        "/v2/acme/model/manifests/v1",
        lambda _handler: (401, {"WWW-Authenticate": 'Bearer realm="http://localhost:1/token"'}, b"{}"),
    )

    with pytest.raises(ConnectorError, match="non-HTTPS"):
        oci.discover(f"oci://{canned.base}/acme/model:v1", http=http_client)


def test_a_401_with_no_challenge_is_an_error_and_not_a_loop(canned, http_client):
    canned.dynamic("/v2/acme/model/manifests/v1", lambda _handler: (401, {}, b"{}"))

    with pytest.raises(ConnectorError, match="no Bearer challenge"):
        oci.discover(f"oci://{canned.base}/acme/model:v1", http=http_client)


def test_an_index_is_followed_into_each_platform_manifest(canned, http_client):
    child = f"sha256:{'c' * 64}"
    index = {
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {"digest": child, "mediaType": "application/vnd.oci.image.manifest.v1+json",
             "platform": {"os": "linux", "architecture": "amd64"}},
        ],
    }
    canned.json("/v2/acme/model/manifests/v1", index)
    canned.json(f"/v2/acme/model/manifests/{child}", MANIFEST)

    discovery = oci.discover(f"oci://{canned.base}/acme/model:v1", http=http_client)

    assert all(artifact.extra["platform"] == "linux/amd64" for artifact in discovery.artifacts)
    assert all(artifact.path.startswith("blobs/linux/amd64/") for artifact in discovery.artifacts)
    assert any("multi-platform index" in note for note in discovery.notes)


def test_an_index_larger_than_the_cap_is_an_incomplete_listing(canned, http_client, monkeypatch):
    monkeypatch.setattr(oci, "MAX_CHILD_MANIFESTS", 1)
    children = []
    for index in range(2):
        digest = f"sha256:{str(index) * 64}"
        children.append({"digest": digest, "platform": {"os": "linux", "architecture": f"arch{index}"}})
        canned.json(f"/v2/acme/model/manifests/{digest}", MANIFEST)
    canned.json(
        "/v2/acme/model/manifests/v1",
        {"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": children},
    )

    discovery = oci.discover(f"oci://{canned.base}/acme/model:v1", http=http_client)

    assert discovery.complete is False
    assert any("prefix of the index" in note for note in discovery.notes)


def test_a_short_oci_name_is_refused_rather_than_expanded():
    """Design note D-88: no implicit registry, no implicit `library/`."""
    with pytest.raises(ConnectorError, match="names no registry"):
        oci.discover("oci://alpine", http=Http(offline=True))


def test_the_oci_reference_is_parsed_around_a_port_and_a_digest():
    assert oci._parse("oci://localhost:5000/team/model:v1") == ("localhost:5000", "team/model", "v1")
    assert oci._parse(f"oci://ghcr.io/team/model@sha256:{DIGEST_A}") == (
        "ghcr.io", "team/model", f"sha256:{DIGEST_A}"
    )
    assert oci._parse("docker://docker.io/library/alpine:3")[0] == "registry-1.docker.io"


def test_the_bearer_challenge_parser_keeps_a_scope_with_a_comma_in_it():
    parsed = oci._parse_challenge(
        'Bearer realm="https://auth.test/token",service="reg",scope="repository:a/b:pull,push"'
    )
    assert parsed["scope"] == "repository:a/b:pull,push"
    assert oci._parse_challenge('Basic realm="reg"') == {}


# ---------------------------------------------------------------------------
# s3
# ---------------------------------------------------------------------------

def _listing(keys, truncated=False, continuation=None):
    rows = "".join(
        "<Contents>"
        f"<Key>{key}</Key><Size>{size}</Size><ETag>&quot;{etag}&quot;</ETag>"
        "<LastModified>2026-01-01T00:00:00.000Z</LastModified><StorageClass>STANDARD</StorageClass>"
        "</Contents>"
        for key, size, etag in keys
    )
    marker = f"<NextContinuationToken>{continuation}</NextContinuationToken>" if continuation else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        "<Name>bucket</Name>"
        f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>"
        f"{rows}{marker}</ListBucketResult>"
    ).encode()


def test_the_s3_connector_follows_the_continuation_token(canned, http_client, monkeypatch):
    monkeypatch.setattr(s3, "ENDPOINT_TEMPLATE", f"https://{canned.base}/{{bucket}}/")

    def route(handler):
        if "continuation-token=page2" in handler.path:
            return 200, {"Content-Type": "application/xml"}, _listing([("b.safetensors", 20, "e2")])
        return (
            200,
            {"Content-Type": "application/xml"},
            _listing([("a.safetensors", 10, "e1")], truncated=True, continuation="page2"),
        )

    canned.dynamic("/bucket/", route)

    discovery = s3.discover("s3://bucket/models", http=http_client)

    assert [artifact.path for artifact in discovery.artifacts] == ["a.safetensors", "b.safetensors"]
    assert discovery.artifacts[0].extra["etag"] == "e1"


def test_an_s3_listing_is_never_reported_as_complete(canned, http_client, monkeypatch):
    """Design note D-89b, and the sentence in D-80 that requires it."""
    monkeypatch.setattr(s3, "ENDPOINT_TEMPLATE", f"https://{canned.base}/{{bucket}}/")
    canned.dynamic("/bucket/", lambda _h: (200, {}, _listing([("a.bin", 1, "e")])))

    discovery = s3.discover("s3://bucket", http=http_client)

    assert discovery.complete is False, "an anonymous listing cannot prove a bucket policy did not scope it"
    assert any("scope an anonymous listing" in note for note in discovery.notes)


def test_the_s3_connector_declares_its_missing_sigv4_in_every_listing(canned, http_client, monkeypatch):
    monkeypatch.setattr(s3, "ENDPOINT_TEMPLATE", f"https://{canned.base}/{{bucket}}/")
    canned.dynamic("/bucket/", lambda _h: (200, {}, _listing([("a.bin", 1, "e")])))

    discovery = s3.discover("s3://bucket", http=http_client)

    assert any("does not implement SigV4" in note.replace("It does ", "does ") for note in discovery.notes)
    assert any("presigned URL" in note for note in discovery.notes)


def test_an_etag_never_becomes_a_declared_digest(canned, http_client, monkeypatch):
    """Design note D-89c: for a multipart upload it is not even a digest."""
    monkeypatch.setattr(s3, "ENDPOINT_TEMPLATE", f"https://{canned.base}/{{bucket}}/")
    canned.dynamic("/bucket/", lambda _h: (200, {}, _listing([("a.bin", 1, "d41d8cd98f00b204e9800998ecf8427e-3")])))

    discovery = s3.discover("s3://bucket", http=http_client)

    assert discovery.artifacts[0].declared_sha256 is None
    assert discovery.artifacts[0].extra["etag"] == "d41d8cd98f00b204e9800998ecf8427e-3"


def test_a_truncated_s3_listing_says_so(canned, http_client, monkeypatch):
    monkeypatch.setattr(s3, "ENDPOINT_TEMPLATE", f"https://{canned.base}/{{bucket}}/")
    canned.dynamic("/bucket/", lambda _h: (200, {}, _listing([("a.bin", 1, "e")], truncated=True)))

    discovery = s3.discover("s3://bucket", http=http_client)

    assert any("IsTruncated is true" in note for note in discovery.notes)


def test_an_xml_document_with_a_doctype_is_refused_before_it_is_parsed(canned, http_client, monkeypatch):
    """Design note D-89d. Every entity expansion attack needs one of these."""
    monkeypatch.setattr(s3, "ENDPOINT_TEMPLATE", f"https://{canned.base}/{{bucket}}/")
    bomb = b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><ListBucketResult/>'
    canned.dynamic("/bucket/", lambda _h: (200, {}, bomb))

    with pytest.raises(ConnectorError, match="DOCTYPE"):
        s3.discover("s3://bucket", http=http_client)


def test_a_folder_marker_is_not_an_artifact(canned, http_client, monkeypatch):
    monkeypatch.setattr(s3, "ENDPOINT_TEMPLATE", f"https://{canned.base}/{{bucket}}/")
    canned.dynamic("/bucket/", lambda _h: (200, {}, _listing([("models/", 0, "e"), ("models/a.bin", 1, "e")])))

    discovery = s3.discover("s3://bucket", http=http_client)

    assert [artifact.path for artifact in discovery.artifacts] == ["models/a.bin"]


def test_a_presigned_url_for_one_object_lists_it_and_contacts_nothing():
    uri = "https://bucket.s3.amazonaws.com/models/w.safetensors?X-Amz-Signature=deadbeef"

    discovery = s3.discover(uri, http=Http(offline=True))

    assert [artifact.path for artifact in discovery.artifacts] == ["models/w.safetensors"]
    assert discovery.hosts_contacted == (), "a host we are about to talk to is not one we talked to"
    assert discovery.complete is False


def test_a_plaintext_presigned_url_is_refused():
    with pytest.raises(ConnectorError, match="non-HTTPS"):
        s3.discover("http://bucket.s3.amazonaws.com/w.bin?X-Amz-Signature=x", http=Http(offline=True))


# ---------------------------------------------------------------------------
# mlflow
# ---------------------------------------------------------------------------

def test_the_mlflow_connector_walks_a_run_artifact_tree(canned, http_client):
    canned.json(
        "/api/2.0/mlflow/model-versions/search",
        {"model_versions": [{"name": "ranker", "version": "3", "run_id": "run-1"}]},
    )

    def artifacts(handler):
        if "path=model" in handler.path:
            body = {"files": [{"path": "model/data.pkl", "is_dir": False, "file_size": 34}]}
        else:
            body = {"files": [
                {"path": "MLmodel", "is_dir": False, "file_size": 12},
                {"path": "model", "is_dir": True},
            ]}
        return 200, {"Content-Type": "application/json"}, json.dumps(body).encode("utf-8")

    canned.dynamic("/api/2.0/mlflow/artifacts/list", artifacts)

    discovery = mlflow.discover(f"mlflow://{canned.base}/models/ranker", http=http_client)

    assert sorted(artifact.path for artifact in discovery.artifacts) == [
        "ranker/3/MLmodel",
        "ranker/3/model/data.pkl",
    ]
    assert discovery.artifacts[0].uri.startswith(f"https://{canned.base}/get-artifact?")
    assert discovery.complete is True


def test_mlflow_declares_no_digest_at_all_and_says_so(canned, http_client):
    """Design note D-90: the one source here that publishes nothing to check."""
    canned.json(
        "/api/2.0/mlflow/model-versions/search",
        {"model_versions": [{"name": "ranker", "version": "3", "run_id": "run-1"}]},
    )
    canned.json("/api/2.0/mlflow/artifacts/list", {"files": [{"path": "m.pkl", "is_dir": False, "file_size": 1}]})

    discovery = mlflow.discover(f"mlflow://{canned.base}/models/ranker", http=http_client)

    assert all(artifact.declared_sha256 is None for artifact in discovery.artifacts)
    assert any("publishes no digest" in note for note in discovery.notes)


def test_a_registered_model_stored_where_this_tool_cannot_reach_is_marked(canned, http_client):
    canned.json(
        "/api/2.0/mlflow/registered-models/search",
        {"registered_models": [
            {"name": "ranker", "latest_versions": [
                {"version": "3", "run_id": "run-1", "current_stage": "Production",
                 "source": "s3://internal/ranker/3"},
            ]},
        ]},
    )

    discovery = mlflow.discover(f"mlflow://{canned.base}", http=http_client)

    assert discovery.artifacts[0].extra["fetchable"] is False
    assert any("cannot GET" in note for note in discovery.notes)


def test_an_mlflow_artifact_tree_deeper_than_the_walk_is_incomplete(canned, http_client, monkeypatch):
    monkeypatch.setattr(mlflow, "MAX_DEPTH", 0)
    canned.json(
        "/api/2.0/mlflow/model-versions/search",
        {"model_versions": [{"name": "ranker", "version": "3", "run_id": "run-1"}]},
    )
    canned.json("/api/2.0/mlflow/artifacts/list", {"files": [{"path": "model", "is_dir": True}]})

    discovery = mlflow.discover(f"mlflow://{canned.base}/models/ranker", http=http_client)

    assert discovery.complete is False
    assert any("was not descended into" in note for note in discovery.notes)


def test_the_mlflow_token_variable_is_named_and_sent(canned, http_client, monkeypatch):
    monkeypatch.setenv("MLFLOW_TRACKING_TOKEN", "mlflow-secret")
    canned.json("/api/2.0/mlflow/registered-models/search", {"registered_models": []})

    discovery = mlflow.discover(f"mlflow://{canned.base}", http=http_client)

    assert any("MLFLOW_TRACKING_TOKEN" in note for note in discovery.notes)
    assert canned.asked("/api/2.0/mlflow/registered-models/search")[0]["authorization"] == "Bearer mlflow-secret"


def test_a_username_and_password_in_the_environment_are_not_picked_up(canned, http_client, monkeypatch):
    """Design note D-90b: an ambient credential is exactly what D-80 refuses."""
    monkeypatch.setenv("MLFLOW_TRACKING_USERNAME", "admin")
    monkeypatch.setenv("MLFLOW_TRACKING_PASSWORD", "hunter2")
    canned.json("/api/2.0/mlflow/registered-models/search", {"registered_models": []})

    mlflow.discover(f"mlflow://{canned.base}", http=http_client)

    sent = canned.asked("/api/2.0/mlflow/registered-models/search")[0]
    assert "authorization" not in sent


# ---------------------------------------------------------------------------
# url manifests
# ---------------------------------------------------------------------------

def test_a_line_manifest_lists_every_url_and_declares_nothing(tmp_path):
    manifest = tmp_path / "urls.txt"
    manifest.write_text(
        "# the weights for release 3\n"
        "\n"
        "https://example.test/models/a.safetensors\n"
        "https://example.test/models/b.safetensors\n",
        encoding="utf-8",
    )

    discovery = url.discover(str(manifest), http=Http(offline=True))

    assert [artifact.path for artifact in discovery.artifacts] == ["a.safetensors", "b.safetensors"]
    assert all(artifact.declared_sha256 is None for artifact in discovery.artifacts)
    assert discovery.complete is True
    assert any("does not mean the manifest lists everything" in note for note in discovery.notes)


def test_a_sha256sum_shaped_line_carries_its_digest(tmp_path):
    manifest = tmp_path / "urls.txt"
    manifest.write_text(f"{DIGEST_A}  https://example.test/a.bin\n", encoding="utf-8")

    assert url.discover(str(manifest), http=Http(offline=True)).artifacts[0].declared_sha256 == DIGEST_A


def test_a_json_manifest_carries_paths_and_digests(tmp_path):
    manifest = tmp_path / "urls.json"
    manifest.write_text(
        json.dumps({"artifacts": [
            {"path": "weights/model.safetensors", "uri": "https://example.test/w.bin", "sha256": DIGEST_A},
            {"uri": "https://example.test/c.json"},
        ]}),
        encoding="utf-8",
    )

    discovery = url.discover(str(manifest), http=Http(offline=True))

    assert discovery.artifacts[0].path == "weights/model.safetensors"
    assert discovery.artifacts[0].declared_sha256 == DIGEST_A
    assert discovery.artifacts[1].declared_sha256 is None
    assert any("declare no sha256" in note for note in discovery.notes)


def test_a_plaintext_url_in_a_manifest_is_rejected_at_read_time(tmp_path):
    manifest = tmp_path / "urls.txt"
    manifest.write_text(
        "https://example.test/good.bin\nhttp://example.test/bad.bin\n", encoding="utf-8"
    )

    discovery = url.discover(str(manifest), http=Http(offline=True))

    assert [artifact.path for artifact in discovery.artifacts] == ["good.bin"]
    assert discovery.complete is False, "a listing smaller than its manifest is not complete"
    assert any("only https is accepted" in note for note in discovery.notes)


def test_a_digest_that_is_not_a_sha256_is_rejected_rather_than_compared(tmp_path):
    manifest = tmp_path / "urls.json"
    manifest.write_text(
        json.dumps([{"uri": "https://example.test/a.bin", "sha256": "nope"}]), encoding="utf-8"
    )

    discovery = url.discover(str(manifest), http=Http(offline=True))

    assert discovery.artifacts[0].declared_sha256 is None
    assert discovery.complete is False


def test_two_urls_with_the_same_basename_do_not_land_on_one_file(tmp_path):
    manifest = tmp_path / "urls.txt"
    manifest.write_text(
        "https://one.test/models/config.json\nhttps://two.test/models/config.json\n", encoding="utf-8"
    )

    paths = [artifact.path for artifact in url.discover(str(manifest), http=Http(offline=True)).artifacts]

    assert len(set(paths)) == 2


def test_a_manifest_that_is_not_text_is_refused(tmp_path):
    manifest = tmp_path / "weights.safetensors"
    manifest.write_bytes(b"\x80\x02\x95 not utf-8 \xff\xfe")

    with pytest.raises(ConnectorError, match="not UTF-8"):
        url.discover(str(manifest), http=Http(offline=True))


# ---------------------------------------------------------------------------
# stage(): the digest comparison and the destination boundary
# ---------------------------------------------------------------------------

def test_a_declared_digest_that_matches_is_reported_as_confirmed(canned, http_client, tmp_path):
    import hashlib

    body = b"the real weights"
    canned.raw("/w.bin", body)
    artifact = RemoteArtifact(
        path="w.bin", uri=f"https://{canned.base}/w.bin",
        declared_sha256=hashlib.sha256(body).hexdigest(), source="test",
    )

    result = stage((artifact,), tmp_path / "out", http_client)

    assert result["problems"] == []
    assert result["fetched"][0]["digest_confirmed"] is True
    assert (tmp_path / "out" / "w.bin").read_bytes() == body


def test_a_declared_digest_that_does_not_match_is_act_con_002_and_the_file_goes(canned, http_client, tmp_path):
    """The rule this whole package is built around. See design note D-80."""
    canned.raw("/w.bin", b"not the bytes that were promised")
    artifact = RemoteArtifact(
        path="w.bin", uri=f"https://{canned.base}/w.bin", declared_sha256=DIGEST_A, source="test",
    )

    result = stage((artifact,), tmp_path / "out", http_client)

    assert result["fetched"] == []
    assert len(result["problems"]) == 1
    problem = result["problems"][0]
    assert problem["rule"] == "ACT-CON-002"
    assert problem["declared"] == DIGEST_A
    assert problem["measured"] != DIGEST_A
    assert not (tmp_path / "out" / "w.bin").exists(), (
        "a file whose provenance is contradicted must not be left where an inspector will read it"
    )


def test_an_artifact_that_will_not_come_down_is_act_con_001(canned, http_client, tmp_path):
    artifact = RemoteArtifact(path="gone.bin", uri=f"https://{canned.base}/gone.bin", source="test")

    result = stage((artifact,), tmp_path / "out", http_client)

    assert [problem["rule"] for problem in result["problems"]] == ["ACT-CON-001"]
    assert result["fetched"] == []


def test_one_bad_artifact_does_not_stop_the_others(canned, http_client, tmp_path):
    canned.raw("/good.bin", b"fine")
    artifacts = (
        RemoteArtifact(path="missing.bin", uri=f"https://{canned.base}/missing.bin", source="test"),
        RemoteArtifact(path="good.bin", uri=f"https://{canned.base}/good.bin", source="test"),
    )

    result = stage(artifacts, tmp_path / "out", http_client)

    assert len(result["fetched"]) == 1
    assert len(result["problems"]) == 1


TRAVERSALS = [
    "../../etc/passwd",
    "/etc/passwd",
    "..\\..\\windows\\system32\\config\\sam",
    "models/../../../../root/.ssh/authorized_keys",
    "./../secret",
]


@pytest.mark.parametrize("hostile", TRAVERSALS)
def test_a_hostile_remote_path_cannot_escape_the_destination(hostile, tmp_path):
    """A remote index is attacker-controlled input, so this is not hypothetical."""
    safe = _safe_relative(hostile)
    resolved = (tmp_path / safe).resolve()

    assert not safe.is_absolute()
    assert ".." not in safe.parts
    assert resolved.is_relative_to(tmp_path.resolve())


def test_a_path_that_is_only_traversal_becomes_a_hash_rather_than_nothing():
    """Two different hostile paths must not collapse onto one file."""
    first = _safe_relative("../..")
    second = _safe_relative("../../..")

    assert first != second
    assert not str(first).startswith(".")


def test_a_traversing_path_from_a_manifest_is_written_inside_the_destination(canned, http_client, tmp_path):
    """End to end: the neutralisation happens where the bytes are written."""
    canned.raw("/passwd", b"root:x:0:0:")
    artifact = RemoteArtifact(path="../../etc/passwd", uri=f"https://{canned.base}/passwd", source="test")
    destination = tmp_path / "out"

    result = stage((artifact,), destination, http_client)

    assert result["problems"] == []
    assert (destination / "etc" / "passwd").is_file()
    assert not (tmp_path.parent / "etc" / "passwd").exists()
    assert list(destination.rglob("*.bin")) == []


# ---------------------------------------------------------------------------
# The CLI
# ---------------------------------------------------------------------------

@pytest.fixture
def trusting_cli(canned, monkeypatch):
    """`actaira discover`, with its `Http` trusting the fixture CA.

    The CLI resolves `Http` from `connectors.model` when the command runs, so
    replacing the name there is enough and no production code learns about the
    tests. What is replaced is the constructor's default context and nothing
    else: the subclass still goes through `verified_context`, so a test that
    tried to smuggle an unverifying context through here would fail.
    """
    context = ssl.create_default_context(cadata=canned.trust)
    original = connector_model.Http

    class TrustingHttp(original):
        def __init__(self, **kwargs):
            super().__init__(ssl_context=context, **kwargs)

    monkeypatch.setattr(connector_model, "Http", TrustingHttp)
    return canned


def test_discover_list_prints_every_connector(capsys):
    assert cli.main(["discover", "--list"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    for connector in registry.all_connectors():
        assert connector.name in out
    assert "SigV4" in out, "the limitation is in the summary a reader sees first"


def test_discover_list_as_json(capsys):
    assert cli.main(["discover", "--list", "--json"]) == cli.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert {row["name"] for row in payload["connectors"]} == {c.name for c in registry.all_connectors()}
    assert payload["connectors"][0]["needs_network"] in (True, False)


def test_discover_with_no_source_is_a_usage_error(capsys):
    assert cli.main(["discover"]) == cli.EXIT_USAGE
    assert "--list" in capsys.readouterr().err


def test_a_source_no_connector_accepts_is_a_usage_error(capsys):
    assert cli.main(["discover", "ipfs://Qm-nope"]) == cli.EXIT_USAGE
    assert "ipfs" in capsys.readouterr().err


def test_fetch_without_out_is_a_usage_error(capsys):
    assert cli.main(["discover", "hf://acme/model", "--fetch"]) == cli.EXIT_USAGE
    assert "--out" in capsys.readouterr().err


def test_out_without_fetch_is_a_usage_error(capsys, tree):
    """Nothing else writes to `--out`, so accepting it silently promises files."""
    assert cli.main(["discover", str(tree), "--out", "/tmp/nowhere"]) == cli.EXIT_USAGE
    assert "--fetch" in capsys.readouterr().err


def test_offline_against_a_network_source_is_a_usage_error_not_an_empty_listing(capsys):
    """`--offline` must never look like "this repository has no files"."""
    assert cli.main(["discover", "hf://acme/model", "--offline"]) == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert "offline" in err and "huggingface" in err


def test_a_complete_local_listing_exits_zero_and_prints_the_two_facts(capsys, tree):
    assert cli.main(["discover", str(tree)]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "complete" in out
    assert "nothing was contacted" in out
    assert "config.json" in out


def test_a_local_source_works_under_offline(capsys, tree):
    assert cli.main(["discover", str(tree), "--offline"]) == cli.EXIT_OK


def test_an_incomplete_listing_exits_three_even_with_nothing_wrong(capsys, tmp_path):
    """Design note D-92, and design note D-80 in one number."""
    manifest = tmp_path / "urls.txt"
    manifest.write_text("http://example.test/plaintext.bin\n", encoding="utf-8")

    assert cli.main(["discover", str(manifest)]) == cli.EXIT_INCONCLUSIVE
    assert "INCOMPLETE" in capsys.readouterr().out


def test_fetch_over_a_local_source_says_it_did_nothing(capsys, tree, tmp_path):
    code = cli.main(["discover", str(tree), "--fetch", "--out", str(tmp_path / "out")])

    assert code == cli.EXIT_OK
    assert "--fetch did nothing" in capsys.readouterr().out


def test_a_skipped_fetch_is_distinguishable_from_no_fetch_in_the_json(capsys, tree, tmp_path):
    """`fetched: null` alone cannot say which of the two happened."""
    cli.main(["discover", str(tree), "--fetch", "--out", str(tmp_path / "out"), "--json"])
    skipped = json.loads(capsys.readouterr().out)

    cli.main(["discover", str(tree), "--json"])
    listed = json.loads(capsys.readouterr().out)

    assert skipped["fetched"] is None and skipped["fetch_skipped_source_is_local"] is True
    assert listed["fetched"] is None and listed["fetch_skipped_source_is_local"] is False


def _manifest_for(canned, tmp_path, entries):
    manifest = tmp_path / "urls.json"
    manifest.write_text(json.dumps({"artifacts": entries}), encoding="utf-8")
    return manifest


def test_a_fetch_whose_digests_all_match_exits_zero(capsys, trusting_cli, tmp_path):
    import hashlib

    body = b"the real weights"
    trusting_cli.raw("/w.safetensors", body)
    manifest = _manifest_for(trusting_cli, tmp_path, [
        {"uri": f"https://{trusting_cli.base}/w.safetensors", "sha256": hashlib.sha256(body).hexdigest()},
    ])
    out = tmp_path / "downloaded"

    code = cli.main(["discover", str(manifest), "--fetch", "--out", str(out)])

    printed = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert (out / "w.safetensors").read_bytes() == body
    assert "localhost" in printed, "the host contacted is printed on every run"


def test_a_fetch_whose_digest_is_contradicted_exits_one_and_deletes_the_file(capsys, trusting_cli, tmp_path):
    trusting_cli.raw("/w.safetensors", b"substituted bytes")
    manifest = _manifest_for(trusting_cli, tmp_path, [
        {"uri": f"https://{trusting_cli.base}/w.safetensors", "sha256": DIGEST_A},
    ])
    out = tmp_path / "downloaded"

    code = cli.main(["discover", str(manifest), "--fetch", "--out", str(out)])

    printed = capsys.readouterr().out
    assert code == cli.EXIT_FAIL
    assert "ACT-CON-002" in printed
    assert "does not match the bytes" in printed, "the rule text, from the catalogue"
    assert not (out / "w.safetensors").exists()


def test_a_fetch_that_could_not_get_a_file_exits_three(capsys, trusting_cli, tmp_path):
    manifest = _manifest_for(trusting_cli, tmp_path, [
        {"uri": f"https://{trusting_cli.base}/absent.safetensors"},
    ])

    code = cli.main(["discover", str(manifest), "--fetch", "--out", str(tmp_path / "out")])

    assert code == cli.EXIT_INCONCLUSIVE
    assert "ACT-CON-001" in capsys.readouterr().out


def test_the_json_output_carries_the_listing_and_what_it_does_not_promise(capsys, tree):
    assert cli.main(["discover", str(tree), "--json"]) == cli.EXIT_OK
    payload = json.loads(capsys.readouterr().out)

    assert payload["connector"] == "filesystem"
    assert payload["listing_complete"] is True
    assert payload["count"] == len(payload["artifacts"])
    assert payload["notes"], "a discovery with no notes is a discovery that promised too much"
    assert payload["fetched"] is None
    assert payload["hosts_contacted"] == []


def test_the_json_output_of_a_fetch_carries_both_digests(capsys, trusting_cli, tmp_path):
    import hashlib

    body = b"weights"
    trusting_cli.raw("/w.bin", body)
    manifest = _manifest_for(trusting_cli, tmp_path, [
        {"uri": f"https://{trusting_cli.base}/w.bin", "sha256": hashlib.sha256(body).hexdigest()},
    ])

    cli.main(["discover", str(manifest), "--fetch", "--out", str(tmp_path / "out"), "--json"])
    payload = json.loads(capsys.readouterr().out)

    row = payload["fetched"]["fetched"][0]
    assert row["sha256"] == row["declared_sha256"], "one measured, one declared, both printed"
    assert row["digest_confirmed"] is True


def test_a_listing_that_failed_still_prints_the_hosts_it_reached(capsys, trusting_cli, monkeypatch):
    """A run that gave up after contacting three services still owes the
    operator the list of three."""
    monkeypatch.setattr(huggingface, "HOST", trusting_cli.base)

    code = cli.main(["discover", "hf://acme/model"])

    assert code == cli.EXIT_FAIL
    assert "localhost" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# The credential rules
# ---------------------------------------------------------------------------

def test_a_token_comes_from_the_environment_and_from_nowhere_else(tmp_path, monkeypatch):
    """No file, no keyring, no vendor credential chain. See D-80."""
    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.delenv("HUGGINGFACE_TOKEN", raising=False)
    (tmp_path / ".huggingface").mkdir()
    (tmp_path / ".huggingface" / "token").write_text("a-token-in-a-file", encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path))

    token, variable = connector_model.token_with_source("HF_TOKEN", "HUGGINGFACE_TOKEN")

    assert token is None and variable is None


def test_the_variable_that_was_used_is_the_one_reported(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GH_TOKEN", "personal")

    assert connector_model.token_with_source("GITHUB_TOKEN", "GH_TOKEN") == ("personal", "GH_TOKEN")

    monkeypatch.setenv("GITHUB_TOKEN", "service-account")
    assert connector_model.token_with_source("GITHUB_TOKEN", "GH_TOKEN") == (
        "service-account", "GITHUB_TOKEN",
    )


def test_no_connector_reads_a_credential_file_from_the_home_directory():
    """A grep, in-process, over the package that opens sockets.

    The rule in D-80 is that a credential comes from a named environment
    variable and from nowhere else. This is the check that no future connector
    quietly adds `~/.aws/credentials` or `~/.docker/config.json` to the list of
    things this tool reads, which is the kind of change that looks like a
    convenience in review.
    """
    directory = Path(connector_model.__file__).parent
    # Shaped like code rather than like prose. Every module here *talks* about
    # keyrings and credential chains, at length, to say it does not read one;
    # a bare word would match the sentence that promises the opposite of what
    # it is looking for. `path.expanduser()` on a path the operator typed is
    # deliberately absent from this list: what is forbidden is expanding a path
    # this package chose for itself.
    forbidden = (
        "Path.home()", 'expanduser("~")', "expanduser('~')", "os.path.expanduser",
        "import netrc", "import keyring", "import boto3", "import botocore",
    )
    offenders: list[str] = []
    for path in sorted(directory.glob("*.py")):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for needle in forbidden:
                if needle in line:
                    offenders.append(f"{path.name}:{line_number}: {needle}")
    assert offenders == [], offenders


def test_every_connector_module_is_registered_exactly_once():
    directory = Path(connector_model.__file__).parent
    modules = {
        path.stem for path in directory.glob("*.py")
        if path.stem not in ("__init__", "model", "registry")
    }

    assert {connector.name for connector in registry.all_connectors()} == modules


def test_the_credential_scrubbing_fixture_actually_scrubs():
    """A guard on the fixture rather than on the code.

    `no_ambient_credentials` is what makes every token assertion in this file
    mean something. A fixture that silently stopped working, because a variable
    was renamed in a connector and not here, would leave those assertions
    passing for the wrong reason. This asserts the precondition itself.
    """
    leaked = [name for name in CREDENTIAL_VARIABLES if os.environ.get(name)]
    assert leaked == [], f"the autouse fixture did not clear {leaked}"


# ---------------------------------------------------------------------------
# DEF-98: the version this tool asserts about itself to somebody else
# ---------------------------------------------------------------------------
def test_the_user_agent_is_the_version_this_package_is():
    """It was the string `actaira/2.0` through two minor releases.

    A literal, so every request the discovery layer made in 2.1 and 2.2 told
    the remote host the wrong version: a registry rate-limiting by client
    version, or an operator reading their own access logs, was given an
    answer that had not been true since 2.0. Design note D-231.
    """
    from actaira import __version__
    from actaira.connectors.model import USER_AGENT

    assert USER_AGENT == f"actaira/{__version__}", USER_AGENT
    # The `(+url)` half is gone with the repository it named: a contact URL
    # that resolves to nothing is worse than none, because an operator reading
    # their logs takes it for an answer. Asserted, so it cannot come back as a
    # guess at where this tree might one day live.
    assert "http" not in USER_AGENT, USER_AGENT


def test_the_listing_spells_a_nested_path_the_same_way_on_every_platform(tree):
    """DEF-104, at the second of the two sites it was found at.

    `str(Path.relative_to(...))` is the platform's separator. That path goes
    into the discovery, the provenance and the subject manifest, so the same
    directory listed on two machines produced two documents that no longer
    compared equal - and the one that spells a separator backslash also spells
    it inside a JSON string, where it is an escape. The local absolute path is
    genuinely platform-shaped and stays in `extra`, where nothing compares it.
    """
    discovery = filesystem.discover(str(tree), http=Http(offline=True))

    nested = [artifact for artifact in discovery.artifacts if "weights" in artifact.path]
    assert len(nested) == 1
    assert nested[0].path == "nested/weights.safetensors"
    for artifact in discovery.artifacts:
        assert "\\" not in artifact.path, (
            f"{artifact.path!r} carries this platform's separator into a listing "
            "that another platform has to be able to compare"
        )
