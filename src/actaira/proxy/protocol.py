"""What MCP revision 2026-07-28 took away, and what a recorder reads instead.

Design note D-264. The revision this release targets deletes the thing the
first capture was built on. From the protocol's own changelog:

    "Remove protocol-level sessions and the Mcp-Session-Id header from the
    Streamable HTTP transport." (SEP-2567)

    "Make MCP stateless: remove the initialize/notifications/initialized
    handshake. Every request now carries its protocol version and client
    capabilities in _meta (io.modelcontextprotocol/protocolVersion,
    io.modelcontextprotocol/clientCapabilities)." (SEP-2575)

So there is no session to correlate by. The substitute is `traceparent` in
`_meta`, which the same revision documents for exactly this (SEP-414), and
where that is absent the answer is a declared hole - `no_correlation_key` -
rather than a counter of our own. A counter is a position wearing an
identifier, which is the defect D-258 exists to refuse.

Rejected: keeping a synthetic session key derived from the transport (the
socket, the process, the record file). Each of those is an artefact of how
this tool happened to observe, not of what the agent did, and a correlation
key that means "the same pipe" published as though it meant "the same run" is
a wrong fact inside the evidence.

**Logging is deprecated in this same revision (SEP-2577) and the spec's own
migration advice is "log to stderr (stdio) or use OpenTelemetry instead of
Logging."** Nothing in this package is therefore built on
`notifications/message`. That matters more than it looks: the OpenTelemetry
GenAI conventions this repository takes its field names from are themselves
entirely in Development status, and their stabilisation effort excludes MCP by
name. So the two vocabularies a proxy might lean on are both moving, and this
module names the `_meta` keys verbatim from the SEPs rather than mapping them
onto an OTel attribute that may not exist next quarter. Where a name here is
not an OTel name, `trace/model.py` records why in `WHY_OUR_OWN`.

Everything below reads a message and returns a fact or None. Nothing here
opens anything, waits for anything, or decides anything.
"""
from __future__ import annotations

import re
from typing import Any

META = "_meta"
NAMESPACE = "io.modelcontextprotocol/"
PROTOCOL_VERSION_KEY = NAMESPACE + "protocolVersion"
CLIENT_INFO_KEY = NAMESPACE + "clientInfo"
SERVER_INFO_KEY = NAMESPACE + "serverInfo"
# SEP-414: OpenTelemetry trace context propagation conventions for `_meta`.
TRACEPARENT_KEY = "traceparent"

# SEP-2575: servers MUST implement this to advertise their supported protocol
# versions, capabilities and identity. It is where the tool inventory at the
# moment of the run comes from, which is what a contract is later derived
# against.
DISCOVER = "server/discover"

# The two revisions this release can be handed. The list is here rather than
# in a comment because a revision nobody enumerated is one no gap can name.
CURRENT_REVISION = "2026-07-28"
PREVIOUS_REVISION = "2025-11-25"
KNOWN_REVISIONS = (PREVIOUS_REVISION, CURRENT_REVISION)

# SEP-2322: every result carries `resultType`, "complete" for an ordinary one
# and "input_required" for the interim result of a multi round-trip request.
RESULT_COMPLETE = "complete"
RESULT_INPUT_REQUIRED = "input_required"
RESULT_TYPES = (RESULT_COMPLETE, RESULT_INPUT_REQUIRED)

# A revision is a date. A traceparent is the W3C shape, `00-<trace>-<span>-<flags>`.
# Both are matched rather than trusted: a field this reader publishes has to be
# a field whose whole value space is known, or the privacy boundary of
# `redact.py` has a fourth hole in it - a server writing a token into `_meta`.
_REVISION = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")
# A piece of software's own name, written by its author and shipped in its
# binary - the same argument that lets `redact.endpoint` keep a host. Anything
# with a space, a colon, a backslash or a path separator in it is not one of
# those, and is dropped rather than published: that character class is what
# every leak shape in `tests/test_trace_privacy.py` is made of.
_SOFTWARE_NAME = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
# `requestState` is opaque to us by design - it is the server's own handle on a
# paused request - so it is admitted by shape and length alone. The shape
# excludes `/` and `:` along with whitespace and backslashes, which is what
# stops an absolute path or a URL being published through the one field here
# whose value space nobody else constrains. A handle that needs a path
# separator is a handle carrying something other than a handle.
_REQUEST_STATE = re.compile(r"^[A-Za-z0-9._~@+=-]{1,128}$")


def _meta_of(message: Any) -> dict[str, Any]:
    """The `_meta` of a request's params or of a result, whichever this is.

    One function because a request and a result put it in different places and
    every caller here wants "the metadata of this message" rather than "the
    metadata of this shape of message".
    """
    if not isinstance(message, dict):
        return {}
    for holder in (message.get("params"), message.get("result"), message):
        if isinstance(holder, dict):
            meta = holder.get(META)
            if isinstance(meta, dict):
                return meta
    return {}


def revision_of(message: Any) -> str | None:
    """The protocol revision this message declares, or None if it declared none.

    None is not an error and not a default. A server still speaking
    2025-11-25 says so; one that says nothing produces
    `protocol_version_unknown`, because a proxy that does not know which
    revision it is interposing does not know what it is looking at.
    """
    declared = _meta_of(message).get(PROTOCOL_VERSION_KEY)
    if isinstance(declared, str) and _REVISION.match(declared):
        return declared
    return None


def correlation_of(message: Any) -> str | None:
    """The `traceparent` that replaced the session id, or None."""
    carried = _meta_of(message).get(TRACEPARENT_KEY)
    if isinstance(carried, str) and _TRACEPARENT.match(carried):
        return carried
    return None


def _software(meta: dict[str, Any], key: str) -> str | None:
    entry = meta.get(key)
    if not isinstance(entry, dict):
        return None
    name = entry.get("name")
    version = entry.get("version")
    if not isinstance(name, str) or not _SOFTWARE_NAME.match(name):
        return None
    if isinstance(version, str) and _SOFTWARE_NAME.match(version):
        return f"{name}@{version}"
    return name


def client_of(message: Any) -> str | None:
    """Which client software sent this, as its author spells it (SEP-2575)."""
    return _software(_meta_of(message), CLIENT_INFO_KEY)


def server_of(message: Any) -> str | None:
    """Which server software answered, as its author spells it (SEP-2575)."""
    return _software(_meta_of(message), SERVER_INFO_KEY)


def result_type_of(response: Any) -> tuple[str | None, bool]:
    """`(resultType, whether this reader supplied it)`.

    SEP-2322 makes the field required, and the spec's own compatibility rule
    is that a result without one is an ordinary complete result. So that is
    what is returned - AND THE SECOND MEMBER SAYS IT WAS ASSUMED. A reader
    that silently filled the field in would be publishing this tool's default
    as the server's statement, which is the third negative: what was not
    observed is declared, never assumed away in silence.
    """
    if not isinstance(response, dict):
        return None, False
    payload = response.get("result")
    if not isinstance(payload, dict):
        return None, False
    declared = payload.get("resultType")
    if isinstance(declared, str) and declared in RESULT_TYPES:
        return declared, False
    return RESULT_COMPLETE, True


def request_state_of(response: Any) -> str | None:
    """The handle that pairs an `input_required` result with its retry.

    SEP-2322 replaced server-initiated requests with multi round-trip
    requests: the server answers `input_required`, the client asks the human,
    and the client re-issues. Those two round trips are ONE logical call seen
    twice, and the only thing that says so is this handle. When the server
    does not supply one, the pairing is a hole - never the arrival order,
    which is the bug phase 1 paid for.
    """
    if not isinstance(response, dict):
        return None
    payload = response.get("result")
    if not isinstance(payload, dict):
        return None
    state = payload.get("requestState")
    if isinstance(state, str) and _REQUEST_STATE.match(state):
        return state
    return None


def tools_in_discover(response: Any) -> list[str] | None:
    """The tool names a `server/discover` result advertised, or None.

    None means this was not a usable discover result. An empty list means the
    server advertised no tools, which is a different fact and stays different.
    """
    if not isinstance(response, dict):
        return None
    payload = response.get("result")
    if not isinstance(payload, dict):
        return None
    advertised = payload.get("tools")
    if not isinstance(advertised, list):
        return None
    names: list[str] = []
    for entry in advertised:
        name = entry.get("name") if isinstance(entry, dict) else entry
        if isinstance(name, str) and _SOFTWARE_NAME.match(name):
            names.append(name)
    return sorted(set(names))
