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
