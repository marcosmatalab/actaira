"""The frontmatter subset, and a load error for everything outside it.

Skills, subagents and path-scoped rules carry a YAML block between two `---`
lines. Phase S1 had no reader and reported every one of them INDETERMINATE with
"frontmatter has no reader in this release", which was honest and blind: a
subagent's frontmatter can carry a `hooks` key, and a capability nobody can see
is the one thing this tool exists to refuse.

Design note D-281. This reads a NAMED SUBSET and refuses the rest: block maps,
block sequences, inline `[a, b]` and `{a: b}` flows, plain and quoted scalars,
`#` comments, and the booleans, nulls and numbers YAML 1.2 core spells. Anchors,
aliases, tags, multi-document streams, block scalars (`|`, `>`), complex keys
and merge keys are each a load error naming itself. The report then says
INDETERMINATE with that cause, which is a true sentence about a file we declined
to guess at.

Rejected: PyYAML, or ruamel. CLAUDE.md caps the runtime dependencies at one and
neither is `cryptography`. The cost of the cap is this file; the cost of lifting
it is that the cap stops being one.

Rejected: reading the block with a regular expression for the handful of keys a
rule needs - `hooks:`, `allowed-tools:`, `paths:`. That is what phase S1's
`"hooks:" in head[1]` already was, and it cannot tell a key from the same text
inside a quoted value or a comment, so it answers about a document it has not
parsed. A subset with a stated boundary is smaller than a heuristic AND says
where it stops.

Why not YAML 1.1 booleans (`yes`, `no`, `on`, `off`). YAML 1.2 core dropped
them, every vendor here documents its frontmatter as YAML without pinning 1.1,
and the Norway problem is a real defect: reading `country: NO` as `False`
invents a fact. They stay plain strings, which is what 1.2 says they are.
"""
from __future__ import annotations

import re
from typing import Any


class YamlError(ValueError):
    """A document outside the subset, with the construct that put it there."""


# Constructs that are valid YAML and are not read here. Each is refused BY NAME
# rather than by falling through to "unexpected character", because the cause
# travels into the report and a person has to be able to act on it.
_REFUSED = (
    ("&", "an anchor (`&name`)"),
    ("*", "an alias (`*name`)"),
    ("!", "a tag (`!name`)"),
    ("|", "a block scalar (`|`)"),
    (">", "a folded block scalar (`>`)"),
    ("? ", "a complex mapping key (`? `)"),
)

_NUMBER = re.compile(r"^[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?$")
_KEY = re.compile(r"^(?P<key>[^:#]+?)\s*:(?:\s+(?P<value>.*))?$")


def _scalar(spoken: str) -> Any:
    """One plain or quoted scalar, in YAML 1.2 core's reading of it."""
    spoken = spoken.strip()
    if len(spoken) >= 2 and spoken[0] == spoken[-1] and spoken[0] in "\"'":
        body = spoken[1:-1]
        return body.replace("''", "'") if spoken[0] == "'" else _unescape(body)
    if spoken in ("true", "True", "TRUE"):
        return True
    if spoken in ("false", "False", "FALSE"):
        return False
    if spoken in ("null", "Null", "NULL", "~", ""):
        return None
    if _NUMBER.match(spoken):
        return float(spoken) if any(c in spoken for c in ".eE") else int(spoken)
    return spoken


def _unescape(body: str) -> str:
    out: list[str] = []
    at = 0
    while at < len(body):
        if body[at] == "\\" and at + 1 < len(body):
            out.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}.get(
                body[at + 1], body[at + 1]
            ))
            at += 2
            continue
        out.append(body[at])
        at += 1
    return "".join(out)


def _flow(spoken: str) -> Any:
    """`[a, b]` and `{a: b}`, one level of nesting at a time, no quotes split.

    Split by hand rather than by `str.split(",")`: a comma inside a quoted
    scalar is part of the scalar, and a splitter that does not know that turns
    one entry into two.
    """
    spoken = spoken.strip()
    closing = {"[": "]", "{": "}"}[spoken[0]]
    if not spoken.endswith(closing):
        raise YamlError(f"a flow collection opened with `{spoken[0]}` never closes")
    parts = _split(spoken[1:-1])
    if spoken[0] == "[":
        return [_value(part) for part in parts if part.strip()]
    found: dict[str, Any] = {}
    for part in parts:
        if not part.strip():
            continue
        key, sep, value = part.partition(":")
        if not sep:
            raise YamlError(f"`{part.strip()}` in a flow mapping has no `:`")
        found[str(_scalar(key))] = _value(value)
    return found


def _split(body: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    quote = ""
    current: list[str] = []
    for char in body:
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return parts


def _value(spoken: str) -> Any:
    spoken = spoken.strip()
    if spoken[:1] in ("[", "{"):
        return _flow(spoken)
    return _scalar(spoken)


def _strip_comment(line: str) -> str:
    """Drop a `#` comment, unless the `#` is inside a quoted scalar."""
    quote = ""
    for at, char in enumerate(line):
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
        elif char == "#" and (at == 0 or line[at - 1].isspace()):
            return line[:at]
    return line


def loads(text: str) -> dict[str, Any]:
    """The subset, or `YamlError`. The top level must be a mapping.

    A frontmatter block whose top level is a list or a scalar is not
    frontmatter, and reading one as `{}` would report "no hooks" about a file
    nobody parsed - the exact lie `SettingsFile.problem` exists to prevent.
    """
    if "\n---" in "\n" + text.strip():
        raise YamlError("a multi-document stream (`---`) is not read here")
    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        body = _strip_comment(raw).rstrip()
        if not body.strip():
            continue
        if body.lstrip().startswith("---") or body.lstrip().startswith("..."):
            raise YamlError("a document marker (`---` or `...`) is not read here")
        lines.append((len(body) - len(body.lstrip()), body.strip()))
        stripped = lines[-1][1]
        for mark, name in _REFUSED:
            spot = stripped.partition(": ")[2] if ": " in stripped else stripped
            if spot.startswith(mark) or stripped.startswith(mark):
                raise YamlError(f"{name} is not read here")

    value, at = _block(lines, 0, lines[0][0] if lines else 0)
    if at != len(lines):
        raise YamlError(f"line {at + 1} is indented less than the block it is inside")
    if not isinstance(value, dict):
        raise YamlError("the top level of a frontmatter block must be a mapping")
    return value


def _block(lines: list[tuple[int, str]], at: int, indent: int) -> tuple[Any, int]:
    """One block collection at `indent`, and the line after it."""
    if at >= len(lines):
        return None, at
    if lines[at][1].startswith("- "):
        return _sequence(lines, at, indent)
    return _mapping(lines, at, indent)


def _sequence(lines: list[tuple[int, str]], at: int, indent: int) -> tuple[list[Any], int]:
    found: list[Any] = []
    while at < len(lines) and lines[at][0] == indent and lines[at][1].startswith("- "):
        body = lines[at][1][2:].strip()
        if not body:
            at += 1
            if at < len(lines) and lines[at][0] > indent:
                item, at = _block(lines, at, lines[at][0])
                found.append(item)
            else:
                found.append(None)
            continue
        if body[:1] not in ("[", "{") and _KEY.match(body):
            # `- key: value`, which is a MAPPING that happens to start on the
            # dash's line, and whose remaining keys are indented to where that
            # first key began. Reading it as the scalar `'key: value'` is what
            # this branch exists to prevent: a hook handler would arrive as a
            # string and every fact about it would be invented.
            inner = indent + 2
            rest = [(inner, body), *lines[at + 1 :]]
            item, taken = _mapping(rest, 0, inner)
            found.append(item)
            at += taken
            continue
        found.append(_value(body))
        at += 1
    return found, at


def _mapping(lines: list[tuple[int, str]], at: int, indent: int) -> tuple[dict[str, Any], int]:
    found: dict[str, Any] = {}
    while at < len(lines) and lines[at][0] == indent:
        matched = _KEY.match(lines[at][1])
        if not matched:
            raise YamlError(f"`{lines[at][1]}` is not `key: value`")
        key = str(_scalar(matched.group("key")))
        spoken = (matched.group("value") or "").strip()
        at += 1
        if spoken:
            found[key] = _value(spoken)
            continue
        if at < len(lines) and (
            lines[at][0] > indent or (lines[at][0] == indent and lines[at][1].startswith("- "))
        ):
            # A sequence under a key may sit at the key's own indent, which is
            # legal YAML and the spelling every vendor's examples use.
            found[key], at = _block(lines, at, lines[at][0])
        else:
            found[key] = None
    return found, at


__all__ = ["YamlError", "loads"]
