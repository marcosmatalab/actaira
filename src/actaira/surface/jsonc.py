"""JSON with comments and trailing commas, and nothing else forgiven.

`.vscode/tasks.json`, `.vscode/settings.json` and `devcontainer.json` are all
documented as JSON with Comments, so a strict `json.loads` reports "invalid
JSON" about files that are valid for their own vendor - and an INDETERMINATE
with a wrong cause is worse than a right one, because the reader of the report
goes and looks at a file that turns out to be fine.

Design note D-280. Two things are forgiven and they are exactly the two the
specifications name: `//` and `/* */` comments, and a comma before a closing
`}` or `]`. Everything else - a single quote, an unquoted key, a hex number, a
`NaN` - is a load error with a cause, and the capability that needed the file
comes back INDETERMINATE. A permissive parser is the fail-open shape of a
configuration reader: it turns a file somebody hand-edited into a confident
answer about a document nobody can agree on the meaning of.

Rejected: a JSON5 dependency (`json5`, `pyjson5`). `docs/PRINCIPLES.md` caps the runtime
dependencies at one, `cryptography`, and JSON5 is a strictly larger language
than either specification here allows - it would accept unquoted keys and
single-quoted strings in a `tasks.json` that VS Code itself refuses, so Actaira
would resolve a capability out of a file the vendor does not load.

Rejected: a regular expression over the whole document. A `//` inside a string
literal - `"command": "curl https://example.test"` - is not a comment, and a
regex that does not track string state deletes the rest of that line. The scan
below is a character walk for that reason, which is also why it can report the
offset where it stopped.
"""
from __future__ import annotations

import json
from typing import Any


class JsoncError(ValueError):
    """A document this reader will not turn into a value, with the cause named."""


def strip(text: str) -> str:
    """The same document with comments blanked and trailing commas removed.

    Comments are replaced by spaces rather than deleted, so every offset in the
    result is the offset in the original: a `json.loads` failure downstream
    points at the character the author actually typed.
    """
    out: list[str] = []
    at = 0
    size = len(text)
    while at < size:
        char = text[at]

        if char == '"':
            start = at
            at += 1
            while at < size:
                if text[at] == "\\":
                    at += 2
                    continue
                if text[at] == '"':
                    at += 1
                    break
                at += 1
            else:
                raise JsoncError(f"a string literal opened at character {start} never closes")
            out.append(text[start:at])
            continue

        if char == "/" and at + 1 < size and text[at + 1] == "/":
            while at < size and text[at] not in "\r\n":
                out.append(" ")
                at += 1
            continue

        if char == "/" and at + 1 < size and text[at + 1] == "*":
            start = at
            end = text.find("*/", at + 2)
            if end == -1:
                raise JsoncError(f"a /* comment opened at character {start} never closes")
            # Newlines are kept so a line number computed downstream is right.
            out.append("".join(" " if c not in "\r\n" else c for c in text[start : end + 2]))
            at = end + 2
            continue

        if char in "}]":
            # The only comma a closing bracket can legally follow is a trailing
            # one. Walking back over whitespace to find it needs no depth
            # counter: whatever is between them, if the nearest earlier
            # character outside a string is a comma, that comma is trailing.
            back = len(out) - 1
            while back >= 0 and out[back].isspace():
                back -= 1
            if back >= 0 and out[back] == ",":
                out[back] = " "

        out.append(char)
        at += 1

    return "".join(out)


def loads(text: str) -> Any:
    """Parse, or raise `JsoncError` with the cause. Never a bare `ValueError`.

    The cause travels because it becomes an `Unresolved.cause` in the report,
    and "invalid JSON" about a file whose only sin is a comment is a cause that
    sends somebody to look at the wrong thing.
    """
    def refuse(token: str) -> Any:
        # `json.loads` accepts `NaN`, `Infinity` and `-Infinity` by default.
        # JSON has none of them, and neither specification this reader serves
        # widens to them, so accepting one would be this module forgiving a
        # third thing it never said it would.
        raise JsoncError(f"`{token}` is not a JSON value")

    try:
        return json.loads(strip(text), parse_constant=refuse)
    except JsoncError:
        raise
    except ValueError as exc:
        raise JsoncError(
            f"not JSON even once comments and trailing commas are allowed for: {exc}"
        ) from exc


__all__ = ["JsoncError", "loads", "strip"]
