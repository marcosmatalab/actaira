"""The privacy boundary, in one place so it can be argued about in one place.

Design note D-252. `actaira scan` reads files that hold somebody's whole
conversation with an agent: their prompts, their home directory, the contents
of whatever they asked it to open, and sooner or later a key. The trace this
tool emits is meant to be shown to a third party, so the default is that none
of that leaves the machine in it.

What travels: the name of the tool, the shape of the call, and the sha256 of
the arguments and of the result. What a rule in phase 2 needs in order to say
"this run wrote outside its declared paths" is the tool name and the digest to
compare against - not the bytes.

Rejected: shipping a redactor that greps for key-shaped strings and keeps the
rest. That is a filter with a false-negative rate, and a false negative here
is somebody's credential in a document built to be handed to an auditor. A
digest has no false negatives. `--with-content` is the explicit opt-in, and it
is the only route by which literal content is written.
"""
from __future__ import annotations

import hashlib
from typing import Any

from ..model import canonical_json


def digest(payload: Any) -> str:
    """sha256 over the canonical bytes of whatever the tool was passed.

    Canonical rather than `repr` or `str` so that two runs over the same call
    produce the same digest on two machines, which is the property that lets a
    digest be compared at all.
    """
    return hashlib.sha256(canonical_json(_plain(payload))).hexdigest()


def _plain(payload: Any) -> Any:
    """Whatever came out of somebody else's JSON, made canonicalisable.

    A transcript is a document written by another tool, so it can hold shapes
    `canonical_json` refuses - a set from a lax reader, bytes, a float NaN.
    They become strings rather than exceptions: a digest this function cannot
    compute is a trace this tool cannot emit, and refusing to read a session
    because one argument was odd is a worse failure than digesting its
    repr and saying so in the trace's own terms.
    """
    if isinstance(payload, dict):
        return {str(key): _plain(value) for key, value in payload.items()}
    if isinstance(payload, (list, tuple)):
        return [_plain(item) for item in payload]
    if isinstance(payload, bool) or payload is None or isinstance(payload, (str, int)):
        return payload
    if isinstance(payload, float):
        # `canonical_json` is allow_nan=False, and a NaN in somebody's
        # transcript must not become a traceback out of `scan`.
        return payload if payload == payload and abs(payload) != float("inf") else repr(payload)
    return repr(payload)


def content_or_none(payload: Any, keep: bool) -> Any:
    """The literal content, but only because the caller asked for it.

    One function rather than an `if` at each call site: the boundary is easier
    to defend when there is exactly one door through it.
    """
    return _plain(payload) if keep else None


# ---------------------------------------------------------------------------
# The second half of the boundary: what a FAILURE is allowed to say
# ---------------------------------------------------------------------------
#
# Design note D-257. The digest rule above covers arguments and results, and
# every leak the phase-1 review found went round it: they came out through a
# gap's `detail`, which is prose nobody had drawn a boundary around. An
# absolute path carries the user's home and the name of their project - under
# `~/.claude/projects` the directory name IS their working directory - a
# server URL carries the token that MCP directories hand out in its query, and
# `str(OSError)` carries the path a second time.
#
# Rejected: scrubbing the sentence after it is built, with patterns for paths
# and for query strings. Same argument as the redactor above: a filter with a
# false-negative rate, protecting a document built to be handed to an auditor.
# These three functions are what a detail may be built FROM, and the test
# greps every emitted document for the shapes they cannot produce.


def failure_kind(exc: BaseException) -> str:
    """The class of a failure, never its message.

    `str(OSError)` is `[Errno 13] Permission denied: '<absolute path>'`. The
    class name says which of the nine gap reasons applies and nothing about
    whose machine it happened on. A `ValueError` from `json` carries a line
    and column of somebody's transcript, which is a position in their
    conversation, so it goes the same way.
    """
    return type(exc).__name__


def endpoint(url: str) -> str:
    """A server URL cut back to which server it is.

    Scheme, host and port: enough for a reader to know which of their servers
    did not answer. The path, the query and any userinfo are dropped whole,
    because that is where the credential lives and picking the safe parameters
    out of a query is the false-negative filter this module refuses to ship.
    """
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return "an endpoint whose URL would not parse"
    if not parts.scheme or not parts.hostname:
        return "an endpoint that is not an absolute URL"
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{parts.hostname}{port}"


def label_ref(label: str) -> str:
    """A stable reference to a name the operator chose, which is not the name.

    The alias of an MCP server is a third field carrying whatever the operator
    typed into `.mcp.json`, and since `_interposition` an uninterposed one is
    NAMED in `authenticity.reason` - the most widely read sentence this tool
    emits. People put client names, project code names and, sooner or later, a
    token in there.

    Rejected: letting the alias through because the operator wrote it rather
    than the agent. `endpoint` keeps a host on exactly that argument, and a
    host is a public name in a public namespace; an alias is a private string
    in a private file. Rejected too: truncating or stripping it to a safe
    character class, which is the false-negative filter this module exists to
    refuse. The alias-to-reference map stays in `interposition.json`, on the
    operator's own machine and out of the acta, so they can still read their
    own trace and a third party learns which server without learning its name.
    """
    reference = hashlib.sha256(label.encode("utf-8")).hexdigest()[:16]
    return f"server:{reference}"


def file_ref(path: Any) -> str:
    """A stable name for a file that is not the file's location.

    The digest of the absolute path, truncated: two gaps about the same file
    carry the same reference, a reader who has the machine can regenerate it,
    and the document itself says nothing about where anybody keeps anything.
    The suffix travels because it says what kind of file failed and is not
    private.
    """
    from pathlib import Path

    resolved = Path(path)
    try:
        absolute = str(resolved.resolve())
    except OSError:  # pragma: no cover - resolve() on a path the OS refuses
        absolute = str(resolved)
    reference = hashlib.sha256(absolute.encode("utf-8")).hexdigest()[:16]
    return f"{reference}{resolved.suffix}"
