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
import secrets
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


# ---------------------------------------------------------------------------
# The third part: a reference that is a reference rather than an encoding
# ---------------------------------------------------------------------------
#
# Design note D-263. `label_ref` published `server:<sha256(alias)[:16]>` and
# `file_ref` the same over an absolute path. Neither is a redaction. The MCP
# server aliases people type come from a small public set - github, slack,
# postgres, filesystem, sentry, notion, linear, stripe - and
# `sha256(b"github")[:16]` is `c0b0109d9439de57` on every machine that has
# ever existed. A reader with eight words and one line of Python recovers the
# alias out of the acta. A home directory is three guesses, not eight.
#
# The property that was supposed to catch this could not: it seeded
# HIGH-entropy secrets and asserted the literal string did not come out, and a
# reversible digest passes that test while protecting nothing. So the guard
# was rewritten at the same time as the function - see the guessable-alias
# corpus in `tests/test_trace_privacy.py`, which asserts the literal AND the
# digest anybody can recompute.
#
# Rejected: a salt fixed in the source, or derived from the host name. Both are
# constants with extra steps - the first is in the wheel everybody downloads,
# the second is one `hostname` away and additionally CORRELATES every acta a
# machine ever emitted, which is the property a per-session salt exists to
# deny. Rejected too: keeping the digest and documenting that it is reversible,
# because the sentence carrying it is `authenticity.reason`, the most widely
# read line this tool emits.

SALT_BYTES = 16


def new_salt() -> str:
    """128 bits from the system CSPRNG, as hex. One per recorded session.

    Per session rather than per machine or per install: two actas from one
    operator must not be correlatable by a third party who notices the same
    reference in both. It is written beside the records, in the operator's own
    file, and it never enters an emitted document.
    """
    return secrets.token_hex(SALT_BYTES)


def _reference(salt: str, domain: str, value: str) -> str:
    """H(salt || domain || value), truncated.

    The domain tag is why a server called `x` and a file called `x` do not
    collide into one reference that reads as though they were the same thing.
    The separator is NUL because it cannot occur in either input.
    """
    material = f"{salt}\x00{domain}\x00{value}".encode()
    return hashlib.sha256(material).hexdigest()[:16]


NO_SALT = (
    "this session recorded no redaction salt, so there is no reference that names it"
)


def label_ref(label: str, salt: str | None) -> str:
    """A stable reference to a name the operator chose, which is not the name.

    The alias of an MCP server is a third field carrying whatever the operator
    typed into `.mcp.json`, and since `_interposition` an uninterposed one is
    NAMED in `authenticity.reason`. People put client names, project code
    names and, sooner or later, a token in there.

    Rejected: letting the alias through because the operator wrote it rather
    than the agent. `endpoint` keeps a host on exactly that argument, and a
    host is a public name in a public namespace; an alias is a private string
    in a private file. The salt-to-alias map stays in `interposition.json`, on
    the operator's own machine, so they can still read their own trace and a
    third party learns which server without learning its name - and without
    being able to guess it, which is what `salt` buys over D-263's predecessor.

    `salt` of None is the session that has lost its own resolution table. It
    publishes no reference at all rather than an unsalted one, and the trace is
    already declaring the hole that made the table unreadable.
    """
    if salt is None:
        return NO_SALT
    return f"server:{_reference(salt, 'server-alias', label)}"


def file_ref(path: Any, salt: str | None) -> str:
    """A stable name for a file that is not the file's location.

    The salted digest of the absolute path: two gaps about the same file carry
    the same reference within one session, the operator who holds the salt can
    regenerate it, and the document itself says nothing about where anybody
    keeps anything. The suffix travels because it says what kind of file
    failed and is not private.
    """
    from pathlib import Path

    if salt is None:
        return NO_SALT
    resolved = Path(path)
    try:
        absolute = str(resolved.resolve())
    except OSError:  # pragma: no cover - resolve() on a path the OS refuses
        absolute = str(resolved)
    return f"{_reference(salt, 'file-path', absolute)}{resolved.suffix}"
