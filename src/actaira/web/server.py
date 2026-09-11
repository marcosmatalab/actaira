"""Local web interface: stdlib HTTP server, no framework.

Design note D-17. Zero third-party dependencies in the web layer, and that
is an argument, not a limitation. Actaira exists to tell you what is inside
an artifact you did not build; a tool that makes that claim while pulling a
few hundred transitive packages into the machine doing the auditing has
already lost the argument. So the server is `http.server`, the UI is HTML,
CSS and JavaScript written by hand, and the only runtime dependency of the
whole project remains `cryptography`, which does the Ed25519.

Design note D-18. This server is local by default and it still treats every
request as hostile, because the files it is handed are hostile by
definition, that is the product. Concretely:

  * bind to 127.0.0.1 unless the operator asks otherwise, and say so loudly
    when they do;
  * a request with no `Content-Length` is refused (411) rather than read
    until it stops, and `Transfer-Encoding: chunked` is refused too, since
    `BaseHTTPRequestHandler` does not decode it;
  * uploads stream to a temporary file in fixed-size chunks and are capped
    at 2 GiB, the body is never materialised in memory;
  * the client's filename is used for its sanitised basename only, never to
    build a path, and the upload lands in a fresh `mkdtemp()` directory that
    is removed in a `finally`;
  * the report's `path` is rewritten to that sanitised basename before it
    leaves the process, so no server-side temporary path is ever disclosed
    to the browser or, more importantly, frozen into a signed attestation;
  * `X-Content-Type-Options: nosniff` and a CSP that allows `'self'` only,
    with no `unsafe-inline` and no `unsafe-eval`, on every response. That is
    why there is not one inline `<style>`, `<script>` or `style=` attribute
    in the static files;
  * `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and
    `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy` both at
    `same-origin`, so a page on the internet can neither frame this interface
    nor pull a response out of it as a subresource - which the origin check on
    POST does not cover, because a subresource load is a GET;
  * `Permissions-Policy` refusing every powerful browser feature, because a
    document that reads local files and draws a report uses none of them;
  * no `Strict-Transport-Security`, deliberately. This server is 127.0.0.1
    over plain HTTP, and an HSTS header from it would pin the whole of
    `localhost` to HTTPS in the operator's browser and break every other local
    development server on the machine.

Known limit, stated rather than hidden: `inspect_artifact` reads a bare
pickle fully into memory, so the practical ceiling for that one format is
set by RAM, not by the 2 GiB cap enforced here.

Design note D-22, on the routes added for the opcode view and the sample
artifacts. They inherit the rules above rather than negotiating new ones:

  * `POST /api/disassemble` takes the same streamed multipart as `/api/scan`
    and never reads more than `MAX_DISASSEMBLY_BYTES` of it into memory, so
    the opcode view cannot be turned into a memory exhaustion primitive by
    an artifact that is merely large. Which file holds a pickle is decided by
    `detect.sniff`, the function the inspector already uses, so the trace and
    the verdict can never disagree about what was read;
  * `GET /api/samples` and the JSON forms of `/api/scan-sample`, `/api/bom`
    and `/api/disassemble` serve a fixed, in-source allowlist of corpus
    artifacts. The request carries a name, that name is compared against the
    allowlist before any path is built, and the resolved path is then
    required to sit directly inside the samples directory. A name is never
    concatenated into a path and hoped for the best;
  * those JSON body routes read exactly `Content-Length` bytes, refuse
    chunked encoding and cap the body at 8 KiB. The multipart parser, the
    2 GiB cap and the temporary-directory lifecycle are untouched;
  * `/api/verify` gains a `chain` view of the entries, read back from the
    package with payloads stripped, purely so the UI can draw the links.
    A failure to read it yields an empty chain, never a failed verification.
"""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import socket
import tempfile
import zipfile
from collections.abc import Callable, Iterable
from datetime import UTC, date, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .. import __version__
from ..agentgov import DeclarationError
from ..agentgov import assess as agent_assess
from ..agentgov import load_text as load_agent_text
from ..agentgov import paths as agent_paths
from ..agentgov.model import diff as agent_diff
from ..attest import chain, merkle, package, signing
from ..attest.verify import verify_package
from ..bom.cyclonedx import build_bom
from ..formats.archive import ALWAYS_PICKLE_SUFFIXES, AMBIGUOUS_PICKLE_SUFFIXES
from ..formats.detect import PICKLE_OPCODE_BYTES, sniff
from ..formats.disassembly import disassemble
from ..governance import Role, unread_artifacts
from ..governance import assess as governance_assess
from ..governance import clock as governance_clock
from ..governance import gaps as governance_gaps
from ..governance import localized as governance_localized
from ..governance.catalog import TEXT_FIELDS
from ..governance.catalog import by_id as obligation_by_id
from ..i18n.catalog import SUPPORTED as I18N_LANGS
from ..i18n.catalog import Catalog
from ..i18n.catalog import load as load_catalog
from ..inspect import inspect_artifact
from ..model import Severity, canonical_json

STATIC_ROOT = (Path(__file__).parent / "static").resolve()
def default_key_path() -> Path:
    """The same resolution the CLI makes, and for the same reason: D-240.

    Importing this module ran `Path.home()`, so `actaira serve` could not even
    be imported in an environment that names no home - and neither could
    anything that imports it, which includes `tests/test_governance.py`.
    """
    from .. import cli

    return cli.default_key_path()

MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024   # 2 GiB, streamed, never buffered
MAX_FIELD_BYTES = 64 * 1024                 # a text field this big is an attack
MAX_HEADER_LINE = 8 * 1024
READ_CHUNK = 512 * 1024

# Three counts that had no ceiling at all. Every one of them is a loop whose
# exit condition was the client running out of bytes, which is not a limit:
# `Content-Length` is 2 GiB and a part header is four bytes, so ~500 million
# of them fit in one request.
#
#   MAX_PART_HEADERS   headers inside one multipart part. A real part has two
#                      (Content-Disposition and Content-Type); 32 leaves room
#                      for anything a client legitimately sends.
#   MAX_PARTS          parts in one request. `/api/scan` reads `file`, plus
#                      `policy` and `fail_on`; the governance routes add `on`,
#                      `role` and `lang`. 64 is an order of magnitude above
#                      what any of them use.
#   MAX_FIELDS         entries kept in the field dictionary. Distinct from
#                      MAX_PARTS because a part can be drained without being
#                      kept, and it is the dictionary that grows in memory.
MAX_PART_HEADERS = 32
MAX_PARTS = 64
MAX_FIELDS = 32

# The opcode view is a reading aid, not an inspector. It refuses to page a
# multi-gigabyte artifact through memory to produce a trace nobody can read:
# past this size it reports the refusal instead, and the verdict, which comes
# from the streaming inspector, is unaffected.
MAX_DISASSEMBLY_BYTES = 64 * 1024 * 1024
MAX_DISASSEMBLY_STEPS = 4096
MAX_JSON_BODY = 8 * 1024
MAX_CHAIN_ENTRIES_SHOWN = 256
MAX_ENTRIES_BLOB = 8 * 1024 * 1024

VALID_POLICIES = ("strict", "known-bad")
VALID_FAIL_ON = ("critical", "high", "medium", "low")
VALID_ROLES = tuple(role.value for role in Role)

# The governance clock is pure arithmetic over a table of dates, so the only
# thing worth bounding is the date itself: a year far outside the regulation's
# horizon is a typo or a probe, never a question anyone is asking.
MIN_CLOCK_DATE = date(2020, 1, 1)
MAX_CLOCK_DATE = date(2100, 1, 1)
MAX_QUERY_CHARS = 512

# The samples directory only exists in a checkout; an installed wheel has no
# `evals/`. That is not an error, it is a UI without a sample strip.
SAMPLES_ROOT = (Path(__file__).resolve().parents[3] / "evals" / "artifacts")

# A closed, ordered allowlist. Nothing outside this tuple is ever served, so
# the sample name is a key into a table rather than a path fragment.
SAMPLES: tuple[dict[str, str], ...] = (
    {"slug": "gadget", "name": "gadget_known_posix_system_p4.pkl", "kind": "danger"},
    {"slug": "trojan", "name": "trojan_checkpoint.pt", "kind": "danger"},
    {"slug": "clean_pickle", "name": "benign_state_dict_p4.pkl", "kind": "clean"},
    {"slug": "clean_tensors", "name": "benign_model.safetensors", "kind": "clean"},
)

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".txt": "text/plain; charset=utf-8",
    ".map": "application/json; charset=utf-8",
}

# The features a document that reads local files and draws a report does not
# use. Written out rather than left to the browser's defaults, because a
# default is a decision somebody else made and can change.
# Only features browsers actually recognise. `ambient-light-sensor` was in this
# list for one commit and is not implemented, so every page load logged
# "Unrecognized feature" - which `scripts/screenshots.py` collects and fails
# on, and did. A header that makes the console complain on every request is a
# header that trains a reader to ignore the console, which costs more than the
# one refusal it was buying.
PERMISSIONS_POLICY = (
    "accelerometer=(), autoplay=(), camera=(), display-capture=(), "
    "encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), "
    "magnetometer=(), microphone=(), midi=(), payment=(), "
    "publickey-credentials-get=(), screen-wake-lock=(), usb=(), xr-spatial-tracking=()"
)

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "object-src 'none'"
)

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")

# Host names that mean this machine. Anything else that is not an IP address
# literal is a DNS name, and a DNS name in the `Host` header of a request this
# server answers is the rebinding attack: the page is served from
# `evil.example`, its A record is flipped to 127.0.0.1, and the browser then
# sends same-origin requests here with every cookie and no CORS preflight.
LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain"})


def _authority_is_local(authority: str) -> bool:
    """True for `127.0.0.1:8765`, `[::1]:8765`, `localhost`, `192.168.1.5:80`.

    An IP address literal is accepted whatever it is, because the operator may
    have bound this server to a LAN address on purpose and `serve()` already
    warns them about it in the loudest terms available. What is refused is a
    *name*, which is the only thing rebinding has to work with.
    """
    authority = authority.strip()
    if not authority:
        return False
    if authority.startswith("["):  # [::1]:8765
        host = authority[1:].split("]", 1)[0]
    else:
        host = authority.rsplit(":", 1)[0] if authority.count(":") == 1 else authority
    host = host.strip().lower().rstrip(".")
    if host in LOOPBACK_NAMES:
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _origin_is_local(origin: str) -> bool:
    """`Origin` is a serialised origin, so it has a scheme and no path."""
    parts = urlsplit(origin.strip())
    if parts.scheme not in ("http", "https"):
        return False
    authority = parts.netloc
    if "@" in authority:  # userinfo is not part of an origin
        return False
    if authority.startswith("["):
        host = authority[1:].split("]", 1)[0]
    else:
        host = authority.rsplit(":", 1)[0] if authority.count(":") == 1 else authority
    host = host.strip().lower().rstrip(".")
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class RequestError(Exception):
    """A refusal we are willing to explain to the client."""

    def __init__(self, status: HTTPStatus, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


# --------------------------------------------------------------------------
# multipart/form-data, streamed
#
# `cgi.FieldStorage` is gone in 3.13 and buffered the whole body before that,
# which is exactly what must not happen here. This parser holds at most one
# chunk plus one boundary in memory regardless of upload size.
# --------------------------------------------------------------------------

class _LimitedReader:
    """Reads at most `limit` bytes from a socket file object."""

    def __init__(self, stream: Any, limit: int) -> None:
        self._stream = stream
        self.remaining = limit

    def read(self, size: int) -> bytes:
        if self.remaining <= 0:
            return b""
        chunk = self._stream.read(min(size, self.remaining))
        self.remaining -= len(chunk)
        return chunk


class MultipartReader:
    def __init__(self, stream: Any, boundary: bytes, length: int) -> None:
        self._reader = _LimitedReader(stream, length)
        self._boundary = boundary
        self._buffer = bytearray()
        self._finished = False

    # -- low level ---------------------------------------------------------

    def _pull(self) -> bool:
        chunk = self._reader.read(READ_CHUNK)
        if not chunk:
            return False
        self._buffer += chunk
        return True

    def _read_line(self) -> bytes:
        while True:
            index = self._buffer.find(b"\r\n")
            if index != -1:
                line = bytes(self._buffer[:index])
                del self._buffer[: index + 2]
                return line
            if len(self._buffer) > MAX_HEADER_LINE:
                raise RequestError(HTTPStatus.BAD_REQUEST, "malformed_multipart", "header line too long")
            if not self._pull():
                raise RequestError(HTTPStatus.BAD_REQUEST, "malformed_multipart", "body ended inside a header")

    def _consume_delimiter_tail(self) -> bool:
        """After `\\r\\n--boundary`, tell closing delimiter from another part."""
        while len(self._buffer) < 2:
            if not self._pull():
                return True  # a truncated tail is treated as the end
        if self._buffer[:2] == b"--":
            del self._buffer[:2]
            return True
        if self._buffer[:2] == b"\r\n":
            del self._buffer[:2]
            return False
        raise RequestError(HTTPStatus.BAD_REQUEST, "malformed_multipart", "bad part delimiter")

    def _start(self) -> None:
        opening = b"--" + self._boundary
        while True:
            line = self._read_line()
            if line == opening:
                return
            if line == opening + b"--":
                self._finished = True
                return
            if len(line) > MAX_HEADER_LINE:
                raise RequestError(HTTPStatus.BAD_REQUEST, "malformed_multipart", "no opening boundary")

    def _part_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        while True:
            line = self._read_line()
            if not line:
                return headers
            if len(headers) >= MAX_PART_HEADERS:
                # Each line is capped at MAX_HEADER_LINE and the body at
                # Content-Length, and neither bounds how many lines arrive:
                # a part carrying millions of four-byte headers filled this
                # dictionary until the process died. Refusing is cheap and a
                # real part never comes close.
                raise RequestError(
                    HTTPStatus.BAD_REQUEST, "malformed_multipart",
                    f"a part carries more than {MAX_PART_HEADERS} headers",
                )
            text = line.decode("utf-8", "replace")
            name, _, value = text.partition(":")
            headers[name.strip().lower()] = value.strip()

    # The sink is `file.write` in one caller, which returns a count, and
    # `bytearray.extend` in another, which returns None. This only ever
    # hands it bytes and never looks at what comes back.
    def _stream_body(self, sink: Callable[[bytes], object], max_bytes: int) -> int:
        delimiter = b"\r\n--" + self._boundary
        keep = len(delimiter) - 1
        written = 0
        while True:
            index = self._buffer.find(delimiter)
            if index != -1:
                written += len(self._buffer[:index])
                if written > max_bytes:
                    raise RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large", "part exceeds its size limit")
                sink(bytes(self._buffer[:index]))
                del self._buffer[: index + len(delimiter)]
                self._finished = self._consume_delimiter_tail()
                return written
            if len(self._buffer) > keep:
                cut = len(self._buffer) - keep
                written += cut
                if written > max_bytes:
                    raise RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large", "part exceeds its size limit")
                sink(bytes(self._buffer[:cut]))
                del self._buffer[:cut]
            if not self._pull():
                raise RequestError(HTTPStatus.BAD_REQUEST, "malformed_multipart", "body ended inside a part")

    # -- public ------------------------------------------------------------

    def parts(self) -> Iterable[tuple[str, str | None, Callable[[Callable[[bytes], object], int], int]]]:
        """Yield `(field_name, filename, stream_into)` for each part, in order."""
        self._start()
        seen = 0
        while not self._finished:
            seen += 1
            if seen > MAX_PARTS:
                raise RequestError(
                    HTTPStatus.BAD_REQUEST, "malformed_multipart",
                    f"the request carries more than {MAX_PARTS} parts",
                )
            headers = self._part_headers()
            name, filename = _parse_disposition(headers.get("content-disposition", ""))
            if name is None:
                # Unnamed part: drain it and move on.
                self._stream_body(lambda _blob: None, MAX_FIELD_BYTES)
                continue
            yield name, filename, self._stream_body


_DISPOSITION_NAME = re.compile(r'\bname="((?:[^"\\]|\\.)*)"')
_DISPOSITION_FILENAME = re.compile(r'\bfilename="((?:[^"\\]|\\.)*)"')


def _unescape_disposition(raw: str) -> str:
    """Undo RFC 2616 quoted-string escaping inside a Content-Disposition."""
    return raw.replace('\\"', '"').replace("\\\\", "\\")


def _parse_disposition(value: str) -> tuple[str | None, str | None]:
    if "form-data" not in value:
        return None, None
    name_match = _DISPOSITION_NAME.search(value)
    file_match = _DISPOSITION_FILENAME.search(value)
    name = _unescape_disposition(name_match.group(1)) if name_match else None
    filename = _unescape_disposition(file_match.group(1)) if file_match else None
    return name, filename


def safe_basename(raw: str | None, fallback: str = "artifact.bin") -> str:
    """The client's filename is a label, never a path.

    Both separators are cut because a Windows client happily sends
    `C:\\Users\\x\\model.pt`, and `os.path.basename` on POSIX would keep the
    whole thing. What survives is one path segment of `[A-Za-z0-9._-]`.
    """
    if not raw:
        return fallback
    candidate = raw.replace("\\", "/").rsplit("/", 1)[-1]
    candidate = _SAFE_NAME.sub("_", candidate).strip("._-")
    if not candidate or candidate in (".", ".."):
        return fallback
    return candidate[:120]


# --------------------------------------------------------------------------
# upload handling
# --------------------------------------------------------------------------

class Upload:
    def __init__(self, path: Path, filename: str, size: int, fields: dict[str, str]) -> None:
        self.path = path
        self.filename = filename
        self.size = size
        self.fields = fields


def _receive_upload(handler: ActairaHandler, workdir: Path) -> Upload:
    content_type = handler.headers.get("Content-Type", "")
    if "multipart/form-data" not in content_type.lower():
        raise RequestError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "bad_content_type",
                           "expected multipart/form-data with a `file` part")

    boundary = _boundary_of(content_type)
    if handler.headers.get("Transfer-Encoding", "").lower().strip() == "chunked":
        raise RequestError(HTTPStatus.LENGTH_REQUIRED, "chunked_unsupported",
                           "chunked uploads are refused; send Content-Length")

    raw_length = handler.headers.get("Content-Length")
    if raw_length is None:
        raise RequestError(HTTPStatus.LENGTH_REQUIRED, "length_required", "Content-Length is required")
    try:
        length = int(raw_length)
    except ValueError:
        raise RequestError(HTTPStatus.BAD_REQUEST, "length_invalid", "Content-Length is not a number") from None
    if length < 0:
        raise RequestError(HTTPStatus.BAD_REQUEST, "length_invalid", "Content-Length is negative")
    if length > MAX_UPLOAD_BYTES + MAX_FIELD_BYTES:
        raise RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large",
                           f"upload exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit")

    reader = MultipartReader(handler.rfile, boundary, length)
    fields: dict[str, str] = {}
    upload: Upload | None = None

    for name, filename, stream_into in reader.parts():
        if name == "file" and upload is None:
            safe = safe_basename(filename)
            target = workdir / safe
            written = 0
            with target.open("wb") as sink:
                written = stream_into(sink.write, MAX_UPLOAD_BYTES)
            upload = Upload(target, safe, written, fields)
        else:
            if name not in fields and len(fields) >= MAX_FIELDS:
                # Each field is capped at MAX_FIELD_BYTES and the number of
                # them was not, so a request could hold 64 KiB times as many
                # distinct names as it cared to send. The part is still
                # drained rather than left in the socket, because the parser
                # has to reach the delimiter to stay in sync.
                raise RequestError(
                    HTTPStatus.BAD_REQUEST, "too_many_fields",
                    f"the request carries more than {MAX_FIELDS} form fields",
                )
            collected = bytearray()
            stream_into(collected.extend, MAX_FIELD_BYTES)
            fields[name] = collected.decode("utf-8", "replace")

    if upload is None:
        raise RequestError(HTTPStatus.BAD_REQUEST, "missing_file", "no `file` part in the request")
    if upload.size == 0:
        raise RequestError(HTTPStatus.BAD_REQUEST, "empty_file", "the uploaded file is empty")
    upload.fields = fields
    return upload


def _boundary_of(content_type: str) -> bytes:
    for token in content_type.split(";")[1:]:
        key, _, value = token.strip().partition("=")
        if key.strip().lower() == "boundary":
            value = value.strip().strip('"')
            if value:
                return value.encode("ascii", "replace")
    raise RequestError(HTTPStatus.BAD_REQUEST, "no_boundary", "multipart boundary is missing")


def _scan_options(fields: dict[str, str]) -> tuple[str, Severity]:
    policy = fields.get("policy", "strict").strip() or "strict"
    if policy not in VALID_POLICIES:
        raise RequestError(HTTPStatus.BAD_REQUEST, "bad_policy",
                           f"policy must be one of {', '.join(VALID_POLICIES)}")
    fail_on = fields.get("fail_on", "high").strip() or "high"
    if fail_on not in VALID_FAIL_ON:
        raise RequestError(HTTPStatus.BAD_REQUEST, "bad_fail_on",
                           f"fail_on must be one of {', '.join(VALID_FAIL_ON)}")
    return policy, Severity(fail_on)


def _inspect_upload(upload: Upload):
    policy, fail_on = _scan_options(upload.fields)
    report = inspect_artifact(upload.path, scan_policy=policy, fail_on=fail_on)
    # Never let a server-side temporary path reach the client or a signed
    # attestation. The basename is what the user actually uploaded.
    report.path = upload.filename
    return report



# --------------------------------------------------------------------------
# agents: the declaration, its capabilities, its A-BOM and its attack paths
#
# Design note D-140b. The four routes below are the interface's half of
# `actaira agent`, and they are deliberately thin: each one loads the
# declaration with `agentgov.load_text` and hands it to the same function the
# CLI calls. A verdict must not depend on whether it was asked for from a
# browser or a terminal, and the cheapest way to guarantee that is to have one
# implementation and no second opinion about what a finding is.
#
# What is different from `/api/scan` is the size rule. A model artifact is
# allowed to be gigabytes and is streamed to disk and never buffered; an agent
# declaration is a page of YAML and has to be read into memory to be parsed at
# all. So these routes cap it at `MAX_DECLARATION_BYTES` and refuse anything
# larger by name, rather than inheriting a 2 GiB limit they would then have to
# honour by reading 2 GiB of text into a string.
# --------------------------------------------------------------------------

MAX_DECLARATION_BYTES = 512 * 1024
"""An agent declaration this big is not a declaration.

The shipped example is under 4 KiB and a large real one is tens of KiB. Half a
megabyte is generous enough that no honest declaration meets it and small
enough that reading one into memory is not a denial of service.
"""


def _declaration_text(path: Path, label: str) -> str:
    """The bytes of an uploaded declaration, as text, bounded and decoded.

    Bounded before the read rather than after: `read_text()` on a file that is
    already on disk would allocate whatever the uploader sent, and the point of
    the limit is to not do that.
    """
    size = path.stat().st_size
    if size == 0:
        raise RequestError(HTTPStatus.BAD_REQUEST, "empty_declaration",
                           f"the {label} declaration is empty")
    if size > MAX_DECLARATION_BYTES:
        raise RequestError(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "declaration_too_large",
            f"an agent declaration may be at most {MAX_DECLARATION_BYTES // 1024} KiB; "
            f"the {label} one is {size // 1024} KiB",
        )
    blob = path.read_bytes()
    try:
        return blob.decode("utf-8")
    except UnicodeDecodeError:
        # A binary file dropped on the agent panel by mistake. Saying so beats
        # a parser error about a byte nobody typed.
        raise RequestError(
            HTTPStatus.BAD_REQUEST, "declaration_not_text",
            f"the {label} declaration is not UTF-8 text, so it is not a declaration",
        ) from None


def _load_declaration(text: str, label: str):
    """`agentgov.load_text`, with its refusal turned into an HTTP answer.

    `DeclarationError` is the type the loader raises for every way a
    declaration can be wrong, and every one of them is the caller's fault
    rather than this server's, so they are 400 with the loader's own sentence
    rather than a 500 with a traceback.
    """
    try:
        return load_agent_text(text, source=label)
    except DeclarationError as exc:
        raise RequestError(HTTPStatus.BAD_REQUEST, "bad_declaration", str(exc)) from None


def _agent_summary(agent) -> dict[str, Any]:
    """What the panel puts in its header, derived from the declaration."""
    return {
        "name": agent.name,
        "version": agent.version,
        "digest": agent.digest,
        "environment": agent.environment,
        "tools": len(agent.tools),
        "mcp_servers": len(agent.mcp_servers),
        "identities": len(agent.identities),
        "data_sources": len(agent.data_sources),
        "sub_agents": len(agent.sub_agents),
    }



# --------------------------------------------------------------------------
# policy: the document, and the decision it produces
#
# Design note D-33b. Two routes, and the same rule the agent routes follow:
# each one loads with the engine's own loader and decides with `policy.decide`,
# so a browser and a terminal cannot return different verdicts about the same
# artifact under the same document.
#
# Which half is the upload is not arbitrary. A policy is a page of YAML and an
# artifact may be gigabytes, so the artifact is the streamed `file` part and
# the policy rides as a form field, bounded by `MAX_FIELD_BYTES`. That is the
# same split the agent diff makes, and for the same reason: the thing with no
# natural ceiling is the thing that gets streamed.
#
# The subject kind is stated by the caller rather than sniffed. A file that
# parses as an agent declaration and a file that is a pickle are told apart by
# content everywhere else in this tool, and could be here too; the reason not
# to is that a policy decision names its subject in the proof, and a subject
# this server guessed at is a worse thing to sign than one the operator chose.
# --------------------------------------------------------------------------

POLICY_SUBJECTS = ("artifact", "agent")


def _policy_text(fields: dict[str, str]) -> str:
    """The policy document, from the field that does not already mean something.

    Not `policy`: that field has meant the *import* policy since `/api/scan`,
    where it is `strict` or `known-bad`, and the same upload carries it when
    the subject is an artifact. A document sent under that name reaches
    `_scan_options` first and is refused as an unknown scan policy, which is a
    confusing answer to a request that was well formed.
    """
    text = fields.get("policy_document") or ""
    if not text.strip():
        raise RequestError(
            HTTPStatus.BAD_REQUEST, "missing_policy",
            "send the policy document in a `policy_document` field",
        )
    return text


def _load_policy_document(text: str, label: str):
    """`load_policy_text`, with its refusal turned into an HTTP answer.

    A policy that does not load is a usage error and never a default-allow.
    Carrying on with the rules that happened to parse is how a pipeline ends
    up governed by half a document.
    """
    from ..policy import load_policy_text
    from ..policy.engine import PolicyError

    try:
        return load_policy_text(text, source=label)
    except PolicyError as exc:
        raise RequestError(HTTPStatus.BAD_REQUEST, "bad_policy", str(exc)) from None


def _policy_summary(policy) -> dict[str, Any]:
    return {
        "id": policy.id,
        "version": policy.version,
        "description": policy.description,
        "digest": policy.digest,
        "rules": len(policy.rules),
    }


def _decision_subject(upload: Upload):
    """The claims the decision is made about, for the kind the caller stated."""
    from .. import subject as subject_mod

    kind = (upload.fields.get("subject") or "artifact").strip().lower()
    if kind not in POLICY_SUBJECTS:
        raise RequestError(
            HTTPStatus.BAD_REQUEST, "bad_subject",
            f"subject must be one of {', '.join(POLICY_SUBJECTS)}",
        )
    if kind == "agent":
        agent = _load_declaration(_declaration_text(upload.path, "uploaded"), upload.filename)
        # `with_paths` on purpose: `attack_path_severity_at_least` has to be
        # evaluable for an agent subject, and a predicate that raised
        # Unevaluable because a flag was missing would push the whole policy
        # into REVIEW for a reason that has nothing to do with the agent.
        return kind, subject_mod.for_agent(agent), {"name": agent.name, "digest": agent.digest}
    report = _inspect_upload(upload)
    return kind, subject_mod.for_artifact(report), {
        "name": report.path, "digest": f"sha256:{report.sha256}", "verdict": report.verdict.value,
    }

# --------------------------------------------------------------------------
# governance: the EU AI Act mapping
#
# Design note D-36. Two routes, and they inherit every rule D-18 already set:
# the clock is a GET with one query parameter, validated against a fixed
# shape before it reaches any code that reasons with it; the assessment is
# the same streamed multipart as `/api/scan`, with two extra text fields that
# are validated against closed sets. No new limit is negotiated and no new
# parser is written.
#
# The governance package never reads the system clock (D-30), so a request
# that names no date gets one here, once, and every response echoes the date
# it answered for. A reader must never have to guess which day a map of legal
# obligations is about.
#
# What these routes will not do is grade anything. The payload carries, per
# obligation, what the evidence touches and what it does not, and the counts
# block is named `counts_not_a_score` on the way out exactly as it is named
# in the library.
# --------------------------------------------------------------------------

_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _today() -> date:
    """The one place the web layer asks the machine what day it is."""
    return datetime.now(UTC).date()


def _governance_date(raw: str | None) -> date:
    """A date as `YYYY-MM-DD`, or today. Nothing else is accepted.

    `date.fromisoformat` also parses week dates and full timestamps, which
    would let two clients ask the same question in two spellings and get
    answers nobody can compare. The shape is pinned first.
    """
    if raw is None or not raw.strip():
        return _today()
    text = raw.strip()
    if not _ISO_DATE.match(text):
        raise RequestError(HTTPStatus.BAD_REQUEST, "bad_date",
                           "`on` must be a calendar date written as YYYY-MM-DD")
    try:
        parsed = date.fromisoformat(text)
    except ValueError:
        raise RequestError(HTTPStatus.BAD_REQUEST, "bad_date",
                           "`on` is not a real calendar date") from None
    if not MIN_CLOCK_DATE <= parsed <= MAX_CLOCK_DATE:
        raise RequestError(HTTPStatus.BAD_REQUEST, "date_out_of_range",
                           f"`on` must be between {MIN_CLOCK_DATE} and {MAX_CLOCK_DATE}")
    return parsed


def _governance_role(raw: str | None) -> Role:
    value = (raw or Role.PROVIDER.value).strip()
    if value not in VALID_ROLES:
        raise RequestError(HTTPStatus.BAD_REQUEST, "bad_role",
                           f"role must be one of {', '.join(VALID_ROLES)}")
    return Role(value)


def _governance_lang(raw: str | None) -> str:
    """An unknown language is answered in English rather than refused: the
    obligations are the point, and a 400 over a locale would hide them."""
    value = (raw or "en").strip().lower()
    return value if value in I18N_LANGS else "en"


def _clock_payload(on: date, lang: str, role: Role) -> dict[str, Any]:
    rows = governance_clock(on)
    catalog = Catalog(lang)

    # Which obligations bind this role, and what each one's state is with no
    # evidence supplied, taken from an assessment over an empty set rather
    # than reimplemented. The browser must never carry a second copy of a
    # rule about who is bound by what: one of the two copies would be wrong
    # eventually, and it would be the one on screen.
    baseline = governance_assess([], on=on, role=role)
    states = {item.obligation.id: item.state for item in baseline.assessments}

    obligations: list[dict[str, Any]] = []
    for row in rows:
        payload = governance_localized(row.obligation, lang)
        payload.update({
            "applicable": row.applicable,
            "in_grace_period": row.in_grace,
            "days_until": row.days_until,
            "binds": row.obligation.id in states,
            "state": states.get(row.obligation.id),
        })
        obligations.append(payload)
    return {
        "on": on.isoformat(),
        "today": _today().isoformat(),
        "lang": lang,
        "role": role.value,
        "obligations": obligations,
        # The notice is emitted only when a row actually carries a provisional
        # date. It used to be unconditional, which meant the panel kept warning
        # that the Digital Omnibus was unpublished for weeks after Regulation
        # (EU) 2026/1744 appeared in the Official Journal, while the rows next
        # to it already showed the corrected dates. A warning that contradicts
        # the table above it costs more credibility than it buys.
        "provisional_notice": (
            catalog.line("gov.clock.provisional")
            if any(row.get("status") == "provisional" for row in obligations)
            else None
        ),
    }


def _localized_obligations(payload: dict[str, Any], lang: str) -> dict[str, Any]:
    """Swap the prose in an assessment payload for `lang`, nothing else."""
    if lang == "en":
        return payload
    for row in payload.get("obligations", []):
        obligation = obligation_by_id(str(row.get("id")))
        if obligation is None:
            continue
        translated = governance_localized(obligation, lang)
        row.update({name: translated[name] for name in TEXT_FIELDS if name in translated})
    return payload


def _assessment_payload(upload_report: Any, on: date, role: Role, lang: str) -> dict[str, Any]:
    reports = [upload_report]
    assessment = governance_assess(
        reports, on=on, role=role, has_attestation=False, has_bom=True
    )
    payload = _localized_obligations(assessment.to_dict(), lang)
    payload["lang"] = lang
    payload["today"] = _today().isoformat()
    payload["artifact"] = {
        "name": upload_report.path,
        "sha256": upload_report.sha256,
        "format": upload_report.detected_format,
        "verdict": upload_report.verdict.value,
        "fully_read": bool(upload_report.metadata.get("fully_read", False)),
    }
    payload["artifacts_not_fully_read"] = unread_artifacts(reports)
    payload["gaps"] = [
        {"id": obligation.id, "article": obligation.article,
         "title": governance_localized(obligation, lang)["title"]}
        for obligation in governance_gaps(assessment)
    ]
    return payload


# --------------------------------------------------------------------------
# samples: a closed allowlist, resolved twice
# --------------------------------------------------------------------------

def _sample_row(name: str) -> dict[str, str]:
    for row in SAMPLES:
        if row["name"] == name:
            return row
    raise RequestError(HTTPStatus.NOT_FOUND, "unknown_sample",
                       "that is not one of the bundled sample artifacts")


def _sample_path(name: str) -> tuple[Path, dict[str, str]]:
    """Resolve a sample name to a file, refusing anything not on the list.

    The name never reaches the filesystem unless it matched the allowlist
    exactly, and the resolved path is then required to be a direct child of
    the samples directory, so a symlink planted inside `evals/artifacts`
    cannot be used to read elsewhere either.
    """
    row = _sample_row(name)
    root = SAMPLES_ROOT.resolve()
    candidate = (root / row["name"]).resolve()
    if candidate.parent != root or not candidate.is_file():
        raise RequestError(HTTPStatus.NOT_FOUND, "sample_missing",
                           "that sample is not available in this installation")
    return candidate, row


def _sample_listing() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not SAMPLES_ROOT.is_dir():
        return rows
    for row in SAMPLES:
        try:
            path, _ = _sample_path(row["name"])
        except RequestError:
            continue
        rows.append({
            "slug": row["slug"],
            "name": row["name"],
            "kind": row["kind"],
            "size_bytes": path.stat().st_size,
        })
    return rows


# --------------------------------------------------------------------------
# pickle disassembly
# --------------------------------------------------------------------------

def _looks_like_pickle(payload: bytes) -> bool:
    """Same both-ends rule the archive inspector uses, on bytes in hand."""
    if not payload:
        return False
    if payload[0] == 0x80:  # PROTO
        return True
    return payload[0] in PICKLE_OPCODE_BYTES and payload.endswith(b".")


def _pickle_source(path: Path) -> tuple[bytes | None, str | None, str | None]:
    """Return `(pickle_bytes, member_name, reason_it_is_absent)`.

    Which file holds a pickle is decided by `detect.sniff`, the same function
    the inspector uses, so the trace can never claim to disassemble something
    the report calls a safetensors file. A modern `.pt` is a zip with the
    pickle one level down, and that member is what the reader wants to see,
    so a container is opened and its member chosen by the rule
    `formats.archive` uses. Nothing is executed and nothing is written.
    """
    detected, _confidence = sniff(path)

    if detected in ("zip", "pytorch-zip"):
        try:
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                committed = [n for n in names if n.lower().endswith(ALWAYS_PICKLE_SUFFIXES)]
                ambiguous = [n for n in names if n.lower().endswith(AMBIGUOUS_PICKLE_SUFFIXES)]
                for name in committed + ambiguous:
                    try:
                        info = archive.getinfo(name)
                    except KeyError:
                        continue
                    if info.file_size > MAX_DISASSEMBLY_BYTES:
                        return None, name, "too_large"
                    with archive.open(name) as member:
                        payload = member.read(MAX_DISASSEMBLY_BYTES + 1)
                    if len(payload) > MAX_DISASSEMBLY_BYTES:
                        return None, name, "too_large"
                    if name in committed or _looks_like_pickle(payload):
                        return payload, name, None
        except (zipfile.BadZipFile, OSError):
            return None, None, "unreadable_container"
        return None, None, "no_pickle_member"

    if detected != "pickle":
        return None, None, "not_a_pickle"
    if path.stat().st_size > MAX_DISASSEMBLY_BYTES:
        return None, None, "too_large"
    return path.read_bytes(), None, None


def _disassembly_payload(path: Path, display_name: str, fields: dict[str, str]) -> dict[str, Any]:
    policy, _ = _scan_options(fields)
    payload, member, reason = _pickle_source(path)
    result: dict[str, Any] = {
        "source": {
            "artifact": display_name,
            "member": member,
            "policy": policy,
            "limit": MAX_DISASSEMBLY_STEPS,
            "max_bytes": MAX_DISASSEMBLY_BYTES,
        },
    }
    if payload is None:
        result["available"] = False
        result["reason"] = reason or "not_a_pickle"
        result["disassembly"] = None
        return result
    result["available"] = True
    result["reason"] = None
    result["disassembly"] = disassemble(payload, scan_policy=policy,
                                        limit=MAX_DISASSEMBLY_STEPS).to_dict()
    return result


# --------------------------------------------------------------------------
# attestation chain, read back for display
# --------------------------------------------------------------------------

def _chain_view(package_path: Path) -> dict[str, Any]:
    """The hash-linked entries, stripped of payloads, for the chain drawing.

    `verify_package` deliberately returns a verdict rather than a data dump,
    and it should stay that way, so the shape the drawing needs is read here
    instead. Payloads are dropped: the UI draws links, not reports, and a
    whole report per entry would be megabytes the browser never renders.
    A failure to read this is not a verification failure, it just means no
    picture, so every error path returns an empty chain.
    """
    empty = {"entries": [], "total": 0, "truncated": False}
    try:
        with zipfile.ZipFile(package_path) as archive:
            if package.ENTRIES_NAME not in set(archive.namelist()):
                return empty
            with archive.open(package.ENTRIES_NAME) as handle:
                blob = handle.read(MAX_ENTRIES_BLOB + 1)
        if len(blob) > MAX_ENTRIES_BLOB:
            return empty
    except Exception:
        return empty

    rows: list[dict[str, Any]] = []
    total = 0
    for line in blob.splitlines():
        if not line.strip():
            continue
        total += 1
        if len(rows) >= MAX_CHAIN_ENTRIES_SHOWN:
            continue
        try:
            entry = json.loads(line)
        except Exception:
            continue
        if not isinstance(entry, dict):
            continue
        payload = entry.get("payload")
        body = payload if isinstance(payload, dict) else {}
        try:
            leaf = merkle.leaf_hash(canonical_json(entry)).hex()
        except Exception:
            leaf = ""
        rows.append({
            "index": entry.get("index"),
            "timestamp": entry.get("timestamp"),
            "subject_sha256": entry.get("subject_sha256"),
            "prev_hash": entry.get("prev_hash"),
            "entry_hash": entry.get("entry_hash"),
            "payload_hash": entry.get("payload_hash"),
            "leaf_hash": leaf,
            "subject_path": body.get("path"),
            "subject_verdict": body.get("verdict"),
        })
    return {"entries": rows, "total": total, "truncated": total > len(rows)}


# --------------------------------------------------------------------------
# request handler
# --------------------------------------------------------------------------

class ActairaHandler(BaseHTTPRequestHandler):
    server_version = f"actaira/{__version__}"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    # Per-connection socket timeout. `StreamRequestHandler.setup` calls
    # `self.connection.settimeout(self.timeout)`, so this is the one that has
    # an effect; the same number on the server class is read by a method
    # `serve_forever` never calls. A client that declares a large
    # Content-Length and then trickles bytes is cut off after this, and 120 s
    # is far above any real stall on an upload that is actually moving.
    timeout = 120

    # -- plumbing ----------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        print(f"[actaira] {self.address_string()} {fmt % args}", flush=True)

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        # `same-origin`, the companion to COOP above: a page on the internet
        # cannot pull a response out of this server as a subresource - an
        # `<img src="http://127.0.0.1:8765/api/...">` that leaks through
        # timing or size, which the origin check on POST does not cover
        # because a subresource load is a GET.
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        # Every powerful browser feature, off. This interface reads files the
        # operator hands it and draws the result; it has no use for a camera,
        # a microphone, a location or a payment handler, and the shortest way
        # to say that a feature is not used is to refuse it.
        self.send_header("Permissions-Policy", PERMISSIONS_POLICY)
        # Deliberately NOT Strict-Transport-Security. This server is designed
        # for 127.0.0.1 over plain HTTP; an HSTS header from it would pin the
        # whole of `localhost` to HTTPS in the operator's browser and break
        # every other local development server on the machine, which is a real
        # harm in exchange for a protection that does not apply to loopback.

    def _respond(self, status: HTTPStatus, body: bytes, content_type: str,
                 extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK,
              extra: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self._respond(status, body, "application/json; charset=utf-8", extra)

    def _error(self, status: HTTPStatus, code: str, message: str) -> None:
        # The body was not necessarily drained, so this connection is spent.
        self.close_connection = True
        self._json({"error": {"code": code, "message": message}}, status)

    # -- routing -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        try:
            if path in ("/", "/index.html"):
                return self._serve_static("index.html")
            if path == "/api/health":
                return self._json({"ok": True, "version": __version__})
            if path == "/api/samples":
                return self._json({"samples": _sample_listing()})
            if path == "/api/governance/clock":
                query = self._query()
                return self._json(_clock_payload(
                    _governance_date(query.get("on")),
                    _governance_lang(query.get("lang")),
                    _governance_role(query.get("role")),
                ))
            if path.startswith("/api/i18n/"):
                return self._serve_catalog(path[len("/api/i18n/"):])
            if path.startswith("/static/"):
                return self._serve_static(path[len("/static/"):])
            if path == "/favicon.ico":
                return self._serve_static("favicon.svg")
            self._error(HTTPStatus.NOT_FOUND, "not_found", f"no route for GET {path}")
        except RequestError as exc:
            self._error(exc.status, exc.code, exc.message)
        except BrokenPipeError:
            self.close_connection = True
        except Exception as exc:  # never leak a traceback to the browser
            self.log_message("unhandled GET error: %s: %s", type(exc).__name__, exc)
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal", f"{type(exc).__name__}: {exc}")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def _refuse_cross_origin(self) -> None:
        """CSRF and DNS rebinding, the two ways a web page reaches localhost.

        Every route below this point mutates nothing on disk outside a
        `mkdtemp()`, but they all parse hostile formats and one of them signs
        with the operator's key, so a page on the internet must not be able to
        drive them through the operator's browser. Two headers answer that:

          Origin  present on every cross-site POST a browser makes, and
                  absent on a `curl` from the operator's own shell. If it is
                  there it has to be a loopback origin.
          Host    the rebinding defence. A browser sends the name from the
                  URL bar, so `evil.example` re-pointed at 127.0.0.1 arrives
                  here with `Host: evil.example`. An address literal cannot be
                  rebound, so a name that is not `localhost` is refused.

        Neither is authentication and this does not pretend to be: the server
        still has none, and binding it off loopback is still the operator
        saying so out loud.
        """
        if not _authority_is_local(self.headers.get("Host", "")):
            raise RequestError(
                HTTPStatus.FORBIDDEN, "bad_host",
                "this server answers to an address, not to a name it does not know",
            )
        origin = self.headers.get("Origin")
        if origin is not None and origin != "null" and not _origin_is_local(origin):
            raise RequestError(
                HTTPStatus.FORBIDDEN, "cross_origin",
                "this endpoint does not accept cross-origin requests",
            )

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        try:
            self._refuse_cross_origin()
        except RequestError as exc:
            return self._error(exc.status, exc.code, exc.message)
        upload_routes = {
            "/api/scan": self._api_scan,
            "/api/bom": self._api_bom,
            "/api/attest": self._api_attest,
            "/api/verify": self._api_verify,
            "/api/disassemble": self._api_disassemble,
            "/api/governance/assess": self._api_governance_assess,
            "/api/agent/check": self._api_agent_check,
            "/api/agent/bom": self._api_agent_bom,
            "/api/agent/paths": self._api_agent_paths,
            "/api/agent/diff": self._api_agent_diff,
            "/api/policy/show": self._api_policy_show,
            "/api/policy/check": self._api_policy_check,
        }
        # Sample routes take a tiny JSON body instead of a file. `/api/disassemble`
        # answers to both, so the client has one code path for uploads and
        # samples alike.
        body_routes = {
            "/api/scan-sample": self._api_scan_sample,
            "/api/disassemble": self._api_disassemble_sample,
            "/api/bom": self._api_bom_sample,
        }
        # The workspace reads. POST rather than GET on purpose, and the reason
        # is in the workspace-state note further down: these carry internal
        # names, source URIs, digests,
        # dependency topology, identities and tool names, and a GET is
        # reachable as a subresource from a page on the internet. Sitting
        # here puts them behind the Host and Origin checks `do_POST` has
        # already applied.
        state_routes = {
            "/api/workspace": self._api_workspace,
            "/api/graph": self._api_graph,
            "/api/graph/node": self._api_graph_node,
            "/api/impact": self._api_impact,
        }
        multipart = "multipart/form-data" in self.headers.get("Content-Type", "").lower()

        if path in state_routes:
            return self._run_post(lambda: state_routes[path](self._read_json_body()))
        if not multipart and path in body_routes:
            return self._run_post(lambda: body_routes[path](self._read_json_body()))
        if path in upload_routes:
            return self._run_upload_post(upload_routes[path])
        self._error(HTTPStatus.NOT_FOUND, "not_found", f"no route for POST {path}")

    def _run_post(self, work: Callable[[], None]) -> None:
        try:
            work()
        except RequestError as exc:
            self._error(exc.status, exc.code, exc.message)
        except BrokenPipeError:
            self.close_connection = True
        except Exception as exc:
            self.log_message("unhandled POST error: %s: %s", type(exc).__name__, exc)
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal", f"{type(exc).__name__}: {exc}")

    def _run_upload_post(self, route: Callable[[Upload, Path], None]) -> None:
        workdir = Path(tempfile.mkdtemp(prefix="actaira-web-"))
        try:
            self._run_post(lambda: route(_receive_upload(self, workdir), workdir))
        finally:
            # Guaranteed removal of the artifact and anything derived from it.
            shutil.rmtree(workdir, ignore_errors=True)

    def _query(self) -> dict[str, str]:
        """The query string as a flat mapping, bounded like everything else.

        Repeated parameters collapse to the first: a route that answers one
        question must not have to decide which of two `on` values the caller
        meant.
        """
        _, _, raw = self.path.partition("?")
        raw = raw.split("#", 1)[0]
        if len(raw) > MAX_QUERY_CHARS:
            raise RequestError(HTTPStatus.REQUEST_URI_TOO_LONG, "query_too_long",
                               "the query string is longer than this server will parse")
        parsed = parse_qs(raw, keep_blank_values=True)
        return {name: values[0] for name, values in parsed.items() if values}

    def _read_json_body(self) -> dict[str, Any]:
        """A small, exactly-sized JSON body. Same refusals as an upload."""
        if self.headers.get("Transfer-Encoding", "").lower().strip() == "chunked":
            raise RequestError(HTTPStatus.LENGTH_REQUIRED, "chunked_unsupported",
                               "chunked bodies are refused; send Content-Length")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise RequestError(HTTPStatus.LENGTH_REQUIRED, "length_required", "Content-Length is required")
        try:
            length = int(raw_length)
        except ValueError:
            raise RequestError(HTTPStatus.BAD_REQUEST, "length_invalid", "Content-Length is not a number") from None
        if length < 0:
            raise RequestError(HTTPStatus.BAD_REQUEST, "length_invalid", "Content-Length is negative")
        if length > MAX_JSON_BODY:
            raise RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large",
                               f"this endpoint accepts at most {MAX_JSON_BODY} bytes of JSON")
        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            self.close_connection = True
            raise RequestError(HTTPStatus.BAD_REQUEST, "short_body", "the body ended early")
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            raise RequestError(HTTPStatus.BAD_REQUEST, "bad_json", "the body is not valid JSON") from None
        if not isinstance(payload, dict):
            raise RequestError(HTTPStatus.BAD_REQUEST, "bad_json", "the body must be a JSON object")
        return payload

    @staticmethod
    def _sample_request(body: dict[str, Any]) -> tuple[Path, dict[str, str], dict[str, str]]:
        name = body.get("sample")
        if not isinstance(name, str) or not name:
            raise RequestError(HTTPStatus.BAD_REQUEST, "missing_sample", "`sample` must be a name from /api/samples")
        path, row = _sample_path(name)
        fields = {
            "policy": str(body.get("policy", "strict")),
            "fail_on": str(body.get("fail_on", "high")),
        }
        return path, row, fields

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self._security_headers()
        self.end_headers()

    # -- endpoints ---------------------------------------------------------

    def _serve_static(self, relative: str) -> None:
        candidate = (STATIC_ROOT / relative).resolve()
        if candidate != STATIC_ROOT and STATIC_ROOT not in candidate.parents:
            raise RequestError(HTTPStatus.FORBIDDEN, "path_escape", "path is outside the static root")
        if not candidate.is_file():
            raise RequestError(HTTPStatus.NOT_FOUND, "not_found", f"no such file: {relative}")
        content_type = CONTENT_TYPES.get(candidate.suffix.lower(), "application/octet-stream")
        self._respond(HTTPStatus.OK, candidate.read_bytes(), content_type)

    def _serve_catalog(self, lang: str) -> None:
        lang = lang.strip("/").lower()
        if lang not in I18N_LANGS:
            raise RequestError(HTTPStatus.NOT_FOUND, "unknown_language",
                               f"language must be one of {', '.join(I18N_LANGS)}")
        try:
            payload = load_catalog(lang)
        except Exception as exc:
            # The catalogue may legitimately not be on disk yet. An empty
            # catalogue is a degraded UI (raw rule ids), not a broken one, so
            # this is a 200 with empty maps rather than a 500.
            self.log_message("i18n catalogue unavailable for %s: %s", lang, exc)
            payload = {}
        payload = dict(payload)
        payload.setdefault("ui", {})
        payload.setdefault("rules", {})
        payload.setdefault("rule_help", {})
        self._json(payload)

    def _api_scan(self, upload: Upload, workdir: Path) -> None:
        report = _inspect_upload(upload)
        self._json({"reports": [report.to_dict()]})

    def _api_disassemble(self, upload: Upload, workdir: Path) -> None:
        self._json(_disassembly_payload(upload.path, upload.filename, upload.fields))

    def _api_disassemble_sample(self, body: dict[str, Any]) -> None:
        path, row, fields = self._sample_request(body)
        payload = _disassembly_payload(path, row["name"], fields)
        payload["source"]["sample"] = row["slug"]
        self._json(payload)

    def _inspect_sample(self, body: dict[str, Any]) -> tuple[Any, dict[str, str], Path]:
        path, row, fields = self._sample_request(body)
        policy, fail_on = _scan_options(fields)
        report = inspect_artifact(path, scan_policy=policy, fail_on=fail_on)
        # The corpus lives at an absolute path on this machine. Only the
        # basename leaves the process, exactly as for an upload.
        report.path = row["name"]
        return report, row, path

    def _api_bom_sample(self, body: dict[str, Any]) -> None:
        report, _row, _path = self._inspect_sample(body)
        self._json(build_bom([report]))

    def _api_scan_sample(self, body: dict[str, Any]) -> None:
        report, row, path = self._inspect_sample(body)
        self._json({
            "reports": [report.to_dict()],
            "sample": {"slug": row["slug"], "name": row["name"], "kind": row["kind"],
                       "size_bytes": path.stat().st_size},
        })

    def _api_bom(self, upload: Upload, workdir: Path) -> None:
        report = _inspect_upload(upload)
        self._json(build_bom([report]))

    def _api_attest(self, upload: Upload, workdir: Path) -> None:
        report = _inspect_upload(upload)
        keypair, created = signing.load_or_create(default_key_path())
        if created:
            self.log_message("created a new signing key at %s", default_key_path())
        entries: list[chain.Entry] = []
        chain.append(entries, report.sha256, report.to_dict())
        out_zip = workdir / f"{Path(upload.filename).stem or 'artifact'}-attestation.zip"
        result = package.write_package(out_zip, entries, keypair, {report.sha256: build_bom([report])})

        blob = out_zip.read_bytes()
        self._respond(
            HTTPStatus.OK,
            blob,
            "application/zip",
            {
                "Content-Disposition": f'attachment; filename="{out_zip.name}"',
                # Same-origin metadata so the UI can show what was signed
                # without a second inspection pass.
                "X-Actaira-Verdict": report.verdict.value,
                "X-Actaira-Subject-Sha256": report.sha256,
                "X-Actaira-Head-Hash": result.head_hash,
                "X-Actaira-Merkle-Root": result.merkle_root,
                "X-Actaira-Key-Id": result.key_id,
                "X-Actaira-Entry-Count": str(result.entry_count),
                "Access-Control-Expose-Headers": (
                    "X-Actaira-Verdict, X-Actaira-Subject-Sha256, X-Actaira-Head-Hash, "
                    "X-Actaira-Merkle-Root, X-Actaira-Key-Id, X-Actaira-Entry-Count"
                ),
            },
        )

    def _api_governance_assess(self, upload: Upload, workdir: Path) -> None:
        """The same multipart as `/api/scan`, plus `role` and `on`.

        The artifact is inspected exactly as `/api/scan` inspects it, by the
        same function and with the same rewriting of the path to a basename,
        so the evidence map is built over the report the Inspect tab would
        have shown rather than over a second, differently configured read.
        """
        on = _governance_date(upload.fields.get("on"))
        role = _governance_role(upload.fields.get("role"))
        lang = _governance_lang(upload.fields.get("lang"))
        report = _inspect_upload(upload)
        self._json(_assessment_payload(report, on, role, lang))

    # -- agents ------------------------------------------------------------
    #
    # Four routes, one loader, and the same functions the CLI calls. See the
    # module-level note above `MAX_DECLARATION_BYTES` for why these do not
    # inherit the 2 GiB upload ceiling.

    def _uploaded_agent(self, upload: Upload):
        """The declaration in the `file` part, parsed, or a 400 saying why."""
        text = _declaration_text(upload.path, "uploaded")
        return _load_declaration(text, upload.filename)

    def _api_agent_check(self, upload: Upload, workdir: Path) -> None:
        """`actaira agent check`: the capability rules over one declaration."""
        agent = self._uploaded_agent(upload)
        findings = agent_assess(agent)
        self._json({
            "agent": _agent_summary(agent),
            "findings": [finding.to_dict() for finding in findings],
        })

    def _api_agent_bom(self, upload: Upload, workdir: Path) -> None:
        """`actaira agent bom`: the A-BOM, the same document the CLI writes."""
        agent = self._uploaded_agent(upload)
        document = agent.to_bom()
        document["agent_digest"] = agent.digest
        self._json({"agent": _agent_summary(agent), "bom": document})

    def _api_agent_paths(self, upload: Upload, workdir: Path) -> None:
        """`actaira agent paths`: routes, not pairs.

        Sub-agent declarations are not resolved here. The CLI takes them as
        extra file arguments; this route has one upload, so a delegation to an
        agent whose declaration was not supplied stays in
        `unresolved_sub_agents`, which is what the engine reports and what the
        panel prints. Reporting an unresolved delegation as "no path found"
        would be the tool answering a question it did not look at.
        """
        agent = self._uploaded_agent(upload)
        report = agent_paths.find(agent)
        self._json({"agent": _agent_summary(agent), "report": report.to_dict()})

    def _api_agent_diff(self, upload: Upload, workdir: Path) -> None:
        """`actaira agent diff`: what one version gained over another.

        The `file` part is the *before* declaration and the `after` field
        carries the second one as text. A form field is capped at
        `MAX_FIELD_BYTES`, which is well above any real declaration, so the
        second file rides the path that already has a ceiling rather than
        widening the multipart reader to take two uploads.
        """
        before = self._uploaded_agent(upload)
        after_text = upload.fields.get("after")
        if not after_text:
            raise RequestError(
                HTTPStatus.BAD_REQUEST, "missing_after",
                "a diff needs both versions: send the second declaration in an `after` field",
            )
        after = _load_declaration(after_text, "after")
        self._json({
            "before": _agent_summary(before),
            "after": _agent_summary(after),
            "diff": agent_diff(before, after),
        })

    # -- policy ------------------------------------------------------------

    def _api_policy_show(self, upload: Upload, workdir: Path) -> None:
        """`actaira policy show`: the document, parsed, with its digest.

        The digest is the point. A decision names the policy it was made
        under, and a reader who cannot recompute that digest from the document
        in front of them cannot check that the two are the same policy.
        """
        text = _declaration_text(upload.path, "policy")
        policy = _load_policy_document(text, upload.filename)
        self._json({"policy": _policy_summary(policy), "document": policy.to_dict()})

    def _api_policy_check(self, upload: Upload, workdir: Path) -> None:
        """`actaira policy check`: the decision, and the proof behind it.

        The `file` part is the subject, the `policy` field is the document, and
        `subject` says which kind the file is. `on` pins the date, because a
        policy with a waiver that expires decides differently on different
        days and a decision that silently used `today()` could not be
        reproduced tomorrow.
        """
        from ..policy import decide

        policy = _load_policy_document(_policy_text(upload.fields), "policy")
        kind, claims, described = _decision_subject(upload)
        on = _governance_date(upload.fields.get("on"))

        decision = decide(policy, [claims], on=on)
        self._json({
            "policy": _policy_summary(policy),
            "subject": {"kind": kind, **described},
            "decided_on": on.isoformat(),
            "decision": decision.to_dict(),
        })

    # -- workspace state ---------------------------------------------------

    def _state_database(self) -> Path | None:
        """The workspace this server was started against, or nothing.

        `--state` wins. With none given, the conventional path is used *only
        if it is already there*: an interface that created `.actaira/` in
        whatever directory it happened to be launched from would be writing to
        the operator's disk because a tab was opened.
        """
        from ..state.store import default_path

        configured = getattr(self.server, "state_path", None)
        if configured is not None:
            return Path(configured)
        conventional = default_path()
        return conventional if conventional.is_file() else None

    def _open_state(self) -> Any:
        """A store for this request, at the version it is already at.

        Every refusal is a structured answer with a code the panel renders as
        its own empty state, because "there is no workspace", "that file is
        not a database" and "that database is newer than this release" call
        for three different things from the reader and one of them is not an
        error at all.
        """
        from ..state.store import Store

        path = self._state_database()
        status = _workspace_state(path)
        if status["state"] != WORKSPACE_READY or path is None:
            message = _WORKSPACE_MESSAGES[str(status["state"])]
            if "schema_version" in status:
                # The two numbers, because "at an earlier version" is a
                # sentence and the pair is the fact.
                message += (f" (it is at {status['schema_version']} and this release "
                            f"reads {status['reads']})")
            raise RequestError(
                HTTPStatus.CONFLICT, "workspace_" + str(status["state"]), message,
            )
        return Store(path, create=False)

    @staticmethod
    def _node_id(body: dict[str, Any], field: str) -> str:
        raw = body.get(field)
        if not isinstance(raw, str) or not raw.strip():
            raise RequestError(HTTPStatus.BAD_REQUEST, "missing_" + field,
                               f"`{field}` must be an asset id or a digest")
        text = raw.strip()
        if len(text) > MAX_NODE_ID_CHARS:
            raise RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "id_too_long",
                               f"an asset id is at most {MAX_NODE_ID_CHARS} characters")
        return text

    @staticmethod
    def _depth(body: dict[str, Any], default: int) -> int:
        from ..state.graph import MAX_DEPTH

        raw = body.get("depth", default)
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise RequestError(HTTPStatus.BAD_REQUEST, "bad_depth", "`depth` must be a whole number")
        if raw < 0 or raw > MAX_DEPTH:
            raise RequestError(HTTPStatus.BAD_REQUEST, "depth_out_of_range",
                               f"`depth` must be between 0 and {MAX_DEPTH}")
        return raw

    @staticmethod
    def _direction(body: dict[str, Any]) -> str:
        from ..state.graph import BOTH, DIRECTIONS

        value = body.get("direction", BOTH)
        if not isinstance(value, str) or value not in DIRECTIONS:
            raise RequestError(HTTPStatus.BAD_REQUEST, "bad_direction",
                               f"`direction` must be one of {', '.join(DIRECTIONS)}")
        return value

    def _api_workspace(self, body: dict[str, Any]) -> None:
        """What this server is reading, and whether there is anything to read.

        Answered whether or not a workspace exists, and never by creating one.
        """
        from ..state import graph as graph_mod

        status = _workspace_state(self._state_database())
        payload: dict[str, Any] = {"workspace": status}
        if status["state"] != WORKSPACE_READY:
            return self._json(payload)

        store = self._open_state()
        try:
            graph = graph_mod.Graph.from_store(store)
            payload["counts"] = {
                "nodes": len(graph.nodes()),
                "edges": len(graph.edges),
                "sources": len(store.sources()),
                "evidence": len(store.all_evidence()),
            }
            payload["limits"] = {"nodes": MAX_GRAPH_NODES, "edges": MAX_GRAPH_EDGES,
                                 "max_depth": graph_mod.MAX_DEPTH}
            payload["kinds"] = _kind_counts(graph)
            payload["relations"] = sorted({edge.relation for edge in graph.edges})
        finally:
            store.close()
        self._json(payload)

    def _api_graph(self, body: dict[str, Any]) -> None:
        """`actaira graph show`, with the same optional focus the CLI takes.

        The engine builds the graph, the engine walks it and the engine
        classifies it; this assembles three of its documents into one
        response. `asset-graph/v1` comes back exactly as the CLI writes it and
        everything the panel needs beyond it rides in `view`, because a
        presentation need is not a reason to version a published contract.
        """
        from ..state import graph as graph_mod

        store = self._open_state()
        try:
            recorded = graph_mod.Graph.from_store(store)
            latest = graph_mod.latest_observations(store)
            focus = body.get("focus")
            view: dict[str, Any] = {
                "mode": "recorded",
                "totals": {"nodes": len(recorded.nodes()), "edges": len(recorded.edges)},
            }
            graph = recorded
            if isinstance(focus, str) and focus.strip():
                walked = graph_mod.neighbourhood(
                    recorded, self._node_id(body, "focus"),
                    depth=self._depth(body, 2), direction=self._direction(body),
                )
                graph = graph_mod.subgraph(recorded, walked)
                view["mode"] = "focus"
                view["neighbourhood"] = walked.to_dict()
            self._refuse_a_graph_too_large_to_draw(graph, str(view["mode"]))
            projection = graph_mod.project(graph, latest)
            view["currentness"] = projection.to_dict()
            view["kinds"] = _kind_counts(graph)
            # The display name the store holds for each node, which
            # `asset-graph/v1` does not carry. In `view` rather than added to
            # the published nodes: a panel needing a label is not a reason to
            # change a contract other tools read.
            view["names"] = {
                name: str((graph.assets.get(name) or {}).get("name") or "")
                for name in graph.nodes()
                if (graph.assets.get(name) or {}).get("name")
            }
            self._json({"workspace": _workspace_state(self._state_database()),
                        "graph": graph.to_dict(), "view": view})
        finally:
            store.close()

    @staticmethod
    def _refuse_a_graph_too_large_to_draw(graph: Any, mode: str) -> None:
        """Say no rather than choose a few hundred nodes by an unstated rule.

        A subset presented as the graph is the worst of the options: it draws
        a picture that looks complete, and the reader has no way to know which
        of their assets were left out or why.
        """
        nodes, edges = len(graph.nodes()), len(graph.edges)
        if nodes <= MAX_GRAPH_NODES and edges <= MAX_GRAPH_EDGES:
            return
        raise RequestError(
            HTTPStatus.CONFLICT, "graph_too_large",
            f"this workspace records {nodes} nodes and {edges} edges, more than the "
            f"{MAX_GRAPH_NODES} and {MAX_GRAPH_EDGES} this panel will draw at once. "
            + ("Focus on one asset, or lower the hop limit."
               if mode == "focus" else "Focus on one asset to see its neighbourhood."),
        )

    def _api_graph_node(self, body: dict[str, Any]) -> None:
        """One node: what the store holds about it, its edges, and its evidence."""
        from ..state import graph as graph_mod

        store = self._open_state()
        try:
            graph = graph_mod.Graph.from_store(store)
            wanted = self._node_id(body, "id")
            resolved = graph_mod.resolve(graph, wanted)
            projection = graph_mod.project(graph, graph_mod.latest_observations(store))
            incoming = sorted(graph.incoming(resolved),
                              key=lambda edge: (edge.source, edge.relation))
            outgoing = sorted(graph.outgoing(resolved),
                              key=lambda edge: (edge.relation, edge.target))

            def described(edges: list[Any]) -> list[dict[str, Any]]:
                rows = []
                for edge in edges:
                    row = edge.to_dict()
                    row["currentness"] = projection.edges.get(
                        (edge.source, edge.relation, edge.target), graph_mod.UNDETERMINED)
                    rows.append(row)
                return rows

            self._json({
                "asked": wanted,
                # Never "0 relations" for something this workspace has never
                # seen. An unknown asset has no recorded dependents, which is
                # not a proof that it has none - the distinction `impact`
                # makes, kept here.
                "found": resolved in graph.nodes(),
                "node": _graph_node_view(graph, projection, resolved),
                "incoming": described(incoming),
                "outgoing": described(outgoing),
                "evidence": _evidence_view(store, resolved),
            })
        finally:
            store.close()

    def _api_impact(self, body: dict[str, Any]) -> None:
        """`actaira impact`, unchanged, over the graph this workspace recorded.

        The exact call the CLI makes, so the browser and the terminal cannot
        report different dependents for the same asset. Everything the engine
        says about its own limits - `found`, `truncated`, the cycles - is
        passed through rather than summarised.
        """
        from ..state import graph as graph_mod

        store = self._open_state()
        try:
            graph = graph_mod.Graph.from_store(store)
            subject = self._node_id(body, "subject")
            document = graph_mod.impact(
                graph, subject, max_depth=self._depth(body, graph_mod.MAX_DEPTH)
            )
            document["cycles_may_be_incomplete"] = graph.cycles_may_be_incomplete
            kinds: dict[str, str] = {}
            for row in document["affected"]:
                name = str(row["asset"])
                kinds[name] = (graph.assets.get(name) or {}).get("kind") or                     name.partition(":")[0] or "unknown"
            self._json({
                "workspace": _workspace_state(self._state_database()),
                "asked": subject,
                "impact": document,
                "kinds": kinds,
            })
        finally:
            store.close()

    def _api_verify(self, upload: Upload, workdir: Path) -> None:
        result = verify_package(upload.path)
        payload = result.to_dict()
        payload["package_name"] = upload.filename
        payload["package_bytes"] = upload.size
        payload["chain"] = _chain_view(upload.path)
        self._json(payload)


# --------------------------------------------------------------------------
# workspace state: the graph, its neighbourhoods, and impact
#
# Design note D-244. These are the first routes that read something other than
# the bytes the operator just handed over, and that changes three things at
# once. Each is answered here rather than inherited.
#
# **The path is chosen when the server starts, never by a request.** `actaira
# serve --state PATH` puts one path on the server object and no route accepts
# one. A browser that could name a database file would be a browser that could
# ask this process to open anything on the disk and say whether it parsed,
# which is a file-existence oracle at best and an sqlite parser fed hostile
# input at worst. The operator picks the workspace; the page reads it.
#
# **Nothing here creates or migrates anything.** Every other command in this
# tool opens a `Store`, which migrates forward on the way in - correct for a
# command somebody typed, wrong for a page that was left open in a tab. So the
# version is read first through a read-only connection, and a database older
# or newer than this release is reported as such rather than quietly rewritten.
# A read must not be able to change what it is reading.
#
# **One connection per request, and not one on the server.** This is a
# `ThreadingHTTPServer` and a `sqlite3.Connection` is not safe to hand to
# several threads; a connection cached on the server object would work in
# testing and fail under two tabs. So the path is what is stored, a store is
# opened for the request and closed in a `finally`.
#
# What the responses carry is workspace-sensitive in a way a scan report is
# not: internal names, source URIs, digests, dependency topology, identities
# and tool names. That is why they are POST behind `_refuse_cross_origin`
# rather than convenient GETs - a GET is reachable as a subresource from a
# page on the internet, which is the hole `Cross-Origin-Resource-Policy`
# narrows and the Origin check on POST closes.
# --------------------------------------------------------------------------

MAX_NODE_ID_CHARS = 512

# What a browser can be asked to draw. A workspace larger than this is not a
# picture, it is a hang, and the honest answer is to say so and offer the
# focused view rather than to pick a few hundred nodes by some rule nobody
# stated and call the result the graph.
MAX_GRAPH_NODES = 400
MAX_GRAPH_EDGES = 1200

WORKSPACE_ABSENT = "absent"
WORKSPACE_READY = "ready"
WORKSPACE_UNREADABLE = "unreadable"
WORKSPACE_OLDER = "older_schema"
WORKSPACE_NEWER = "newer_schema"


def _state_version(path: Path) -> int:
    """The schema version of a database, read without opening it for writing.

    `sqlite3` in read-only URI mode, so a file this process is only inspecting
    cannot be created, migrated or journalled by the act of inspecting it.
    """
    import sqlite3
    from urllib.request import pathname2url

    uri = "file:" + pathname2url(str(path)) + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'"
        ).fetchone()
        if row is None:
            return 0
        value = connection.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        return int(value[0]) if value else 0
    finally:
        connection.close()


def _workspace_state(path: Path | None) -> dict[str, Any]:
    """What this server can say about the configured workspace, without touching it.

    Always a description and never an exception, because "there is no
    workspace" is an ordinary thing for this interface to be in: every other
    panel works without one, and the graph panel's job when there is none is
    to say so rather than to make one.
    """
    from ..state.store import SCHEMA_VERSION as STORE_SCHEMA

    document: dict[str, Any] = {
        "configured": path is not None,
        # The file name and nothing else. A label is enough for a reader who
        # chose the path at the command line, and an absolute path in a
        # response is a disclosure of where this machine keeps things.
        "label": path.name if path is not None else None,
        "reads": STORE_SCHEMA,
    }
    if path is None or not path.is_file():
        document["state"] = WORKSPACE_ABSENT
        return document
    try:
        version = _state_version(path)
    except Exception:
        # Deliberately broad: every way a file can fail to be a database ends
        # here as one answer, and none of them reaches the browser as a
        # traceback.
        document["state"] = WORKSPACE_UNREADABLE
        return document
    document["schema_version"] = version
    if version > STORE_SCHEMA:
        document["state"] = WORKSPACE_NEWER
    elif version < STORE_SCHEMA:
        document["state"] = WORKSPACE_OLDER
    else:
        document["state"] = WORKSPACE_READY
    return document


_WORKSPACE_MESSAGES = {
    WORKSPACE_ABSENT: (
        "this interface was not started against a workspace, and it will not create one. "
        "Run `actaira init` and then `actaira serve --state .actaira/state.db`"
    ),
    WORKSPACE_UNREADABLE: (
        "the configured state file is not a readable Actaira database"
    ),
    # These two say what was observed rather than who wrote it. A file at
    # schema version 0 is most likely not an Actaira database at all, and a
    # message asserting it "was written by an earlier release" would be this
    # server stating a provenance it has no evidence for.
    WORKSPACE_OLDER: (
        "the configured state database is at an earlier schema version than this release "
        "reads. Migrations run forward only and a read must never perform one, so run any "
        "`actaira` state command against it once to bring it up to date"
    ),
    WORKSPACE_NEWER: (
        "the configured state database is at a later schema version than this release reads, "
        "and downgrading it would mean guessing what its extra columns meant"
    ),
}


def _kind_counts(graph: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name in graph.nodes():
        kind = (graph.assets.get(name) or {}).get("kind") or name.partition(":")[0] or "unknown"
        counts[kind] = counts.get(kind, 0) + 1
    return dict(sorted(counts.items()))


def _graph_node_view(graph: Any, projection: Any, node: str) -> dict[str, Any]:
    """One node as the panel shows it: what the store holds, and nothing more."""
    from ..state import graph as graph_mod

    row = dict(graph.assets.get(node) or {})
    attributes: dict[str, Any] = {}
    raw = row.get("attributes")
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            attributes = parsed if isinstance(parsed, dict) else {}
        except ValueError:
            attributes = {}
    return {
        "id": node,
        "kind": row.get("kind") or node.partition(":")[0] or "unknown",
        "name": row.get("name") or "",
        "digest": row.get("digest") or "",
        "source": row.get("source_id") or "",
        "first_seen": row.get("first_seen") or "",
        "last_seen": row.get("last_seen") or "",
        "last_snapshot": row.get("last_snapshot") or "",
        "attributes": attributes,
        "in_store": bool(row),
        "currentness": projection.nodes.get(node, graph_mod.UNDETERMINED),
    }


def _evidence_view(store: Any, node: str) -> dict[str, Any]:
    """The evidence already recorded about one subject, by state.

    Shown, not interpreted. This increment draws what `watch` and the rest of
    the engine have already written; nothing here decides that a record has
    expired, supersedes one, or re-evaluates a policy because of one. That is
    the next increment, and a badge that quietly implemented half of it would
    be a second evidence lifecycle living in a view model.
    """
    from ..state.evidence import EvidenceState

    rows = store.evidence_for(node)
    counts = {member.value: 0 for member in EvidenceState}
    for row in rows:
        if row["state"] in counts:
            counts[row["state"]] += 1
    return {
        "counts": counts,
        "total": len(rows),
        "records": [
            {
                "evidence_id": row["evidence_id"],
                "kind": row["kind"],
                "state": row["state"],
                "observed_at": row["observed_at"],
                "subject_digest": row["subject_digest"],
                "collector": row["collector"],
            }
            for row in rows
        ],
    }


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    # The workspace this server reads, chosen at the command line and never
    # by a request. A path, not a connection: this is a threading server and
    # a `sqlite3.Connection` shared between worker threads is a bug that only
    # shows up under a second tab. See D-244.
    state_path: Path | None = None
    # NOTE: the read timeout is NOT set here. `BaseServer.timeout` is only
    # consulted by `handle_request()`, which `serve_forever()` never calls, so
    # the 120 s written on this class did nothing at all and the slowloris it
    # was added for held a worker thread forever anyway. The socket timeout
    # that works is `ActairaHandler.timeout`, which `StreamRequestHandler.setup`
    # applies to the connection itself. It lives beside the handler.

    def handle_error(self, request: Any, client_address: Any) -> None:
        import sys
        import traceback

        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
            return
        traceback.print_exc()


def build_server(host: str = "127.0.0.1", port: int = 8765,
                 state_path: Path | None = None) -> ThreadingHTTPServer:
    if ":" in host:  # IPv6 literal
        _Server.address_family = socket.AF_INET6
    server = _Server((host, port), ActairaHandler)
    server.state_path = Path(state_path) if state_path is not None else None
    return server


def serve(host: str = "127.0.0.1", port: int = 8765, state_path: Path | None = None) -> None:
    """Run the local UI until interrupted.

    Binding to anything other than a loopback address exposes an endpoint
    that will happily accept a 2 GiB file and parse hostile formats for you,
    so it is allowed but never silent.

    `state_path` is optional and stays optional. Every panel that existed
    before the graph works with no workspace at all, which is the property
    that makes this tool usable on a file somebody just downloaded, and the
    graph panel's answer when there is no workspace is to say so rather than
    to create one.
    """
    httpd = build_server(host, port, state_path)
    display = f"[{host}]" if ":" in host else host
    print(f"actaira {__version__}, http://{display}:{port}")
    if state_path is not None:
        print(f"reading workspace state from {state_path}")
    if host not in ("127.0.0.1", "::1", "localhost"):
        print(f"WARNING: bound to {host}, which is not loopback. This interface "
              f"accepts uploads and has no authentication.")
        if state_path is not None:
            # Worth its own line. Everything else this server exposes is
            # something the requester supplied; the graph is a description of
            # what this machine has been told to look after.
            print("WARNING: it is also serving this workspace's asset graph, which "
                  "names sources, digests, identities and tools.")
    print("Nothing is loaded or executed. Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    serve()
