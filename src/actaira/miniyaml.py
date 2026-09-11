"""The smallest YAML subset this tool's own files need, in the standard library.

Design note D-110, and it is the same trade-off D-30 made for control
declarations, now stated once instead of twice. PyYAML would parse more, and
it would be the second runtime dependency of a tool whose whole argument is
that it has one. The files this parser reads - control declarations, policy
bundles - are written by an operator and are a few dozen lines of scalars,
mappings and lists, which is the subset below: two-space nesting, `key: value`,
`key:` opening a block, `- item` and `- key: value` sequences, quoted or bare
scalars, `|` and `>` block scalars, `#` comments.

Anything outside the subset raises, and that is the important half. A line this
parser does not understand becomes a `ValueError` the caller turns into a
visible parse error, never a key silently dropped. A policy file half-read is
how an operator ends up believing they denied something they did not.

Two defects are pinned in the history of this code and both were the same
mistake - guessing a block's shape before seeing it. The first version could
not parse a block sequence at all: it pushed a placeholder mapping for `key:`
and raised on the following `- item`. The fix was to decide by looking at the
first child. The second could parse `- item` but not `- key: value`, so a
policy file's list of rules was read as a list of the string "id: no-criticals"
and every rule after the first line of each was dropped in silence. Both are
covered by tests that feed the exact shapes back in.
"""
from __future__ import annotations

import re
from typing import Any


def loads(text: str) -> dict[str, Any]:
    """Parse a document, which must be a mapping at the top level."""
    lines = _significant_lines(text)
    if not lines:
        return {}
    value, index = _parse_block(lines, 0, lines[0][0])
    if index != len(lines):
        raise ValueError(f"could not parse from line {index + 1}: {lines[index][1]!r}")
    return value if isinstance(value, dict) else {"_root": value}


def _significant_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        without_comment = re.sub(r"\s+#.*$", "", raw_line).rstrip()
        if not without_comment.strip() or without_comment.lstrip().startswith("#"):
            continue
        indent = len(without_comment) - len(without_comment.lstrip())
        lines.append((indent, without_comment.strip()))
    return lines


def _parse_block(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    """Parse every line at `indent`, returning the value and the next index."""
    if index >= len(lines):
        return {}, index
    if lines[index][1].startswith("- "):
        return _parse_sequence(lines, index, indent)
    return _parse_mapping(lines, index, indent)


def _mapping_colon(text: str) -> int | None:
    """Where this line's key ends, or None when it has no key at all.

    Defect DEF-66. This used to be `":" in text` and `text.partition(":")`,
    which reads `- jira:write` as the mapping `{"jira": "write"}`. YAML does
    not: a colon only opens a value when it is followed by a space or ends the
    line, which is exactly why `jira:write`, `http://example.com` and
    `sha256:aaaa` are scalars in every real parser.

    The consequence was not cosmetic. Every scope in the shipped example
    declaration - `jira:write`, `github:write` - was parsed into a one-key
    dictionary and then stringified by the loader, so the A-BOM published
    `"{'jira': 'write'}"` where the file said `jira:write`. Nothing noticed,
    because no test asserted on a scope's value, and a scope is precisely the
    field a reviewer compares between two releases.

    A colon inside a quoted region does not open a value either, which is what
    the quote tracking is for: `- "a: b"` is one scalar.
    """
    quote = ""
    for position, character in enumerate(text):
        if quote:
            if character == quote:
                quote = ""
            continue
        if character in "\"'":
            quote = character
            continue
        if character == ":" and (position + 1 == len(text) or text[position + 1] in " \t"):
            return position
    return None


def _parse_sequence(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[list[Any], int]:
    """A block sequence, whose items may be scalars or mappings.

    `- key: value` is the case the first version of this parser dropped. The
    item's own mapping starts on the same physical line as the dash, so its
    effective indent is the dash's indent plus two, and the continuation lines
    of that mapping sit at exactly that column. Rewriting the line as if the
    dash were spaces and handing it to the mapping parser is what keeps the
    two shapes from needing two implementations.
    """
    items: list[Any] = []
    while index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("- "):
        body = lines[index][1][2:].strip()
        child_indent = indent + 2
        if _mapping_colon(body) is not None and not _is_quoted(body):
            # Splice the item's first line back in at the child indent, then
            # let the mapping parser consume it together with any
            # continuation lines that follow at the same column.
            spliced = [(child_indent, body)] + lines[index + 1 :]
            mapping, consumed = _parse_mapping(spliced, 0, child_indent)
            items.append(mapping)
            index += consumed
            continue
        items.append(_scalar(body))
        index += 1
    return items, index


def _parse_mapping(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    while index < len(lines) and lines[index][0] == indent:
        stripped = lines[index][1]
        if stripped.startswith("- "):
            break
        at = _mapping_colon(stripped)
        if at is None:
            raise ValueError(f"not a key: {stripped!r}")
        key = stripped[:at].strip()
        rest = stripped[at + 1 :].strip()
        index += 1
        if rest in ("|", "|-", ">", ">-"):
            # A block scalar. Operators write descriptions this way and a
            # parser that choked on one would push every explanation onto a
            # single 200-column line, which is how policy files stop carrying
            # explanations at all.
            block, index = _parse_block_scalar(lines, index, indent, rest)
            mapping[key] = block
            continue
        if rest:
            mapping[key] = _scalar(rest)
            continue
        if index < len(lines) and lines[index][0] > indent:
            child, index = _parse_block(lines, index, lines[index][0])
            mapping[key] = child
        elif index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("- "):
            # A sequence written flush with its key, which is legal YAML and
            # the shape most people type. Without this branch the key came
            # back None and the list became a sibling of its own parent.
            child, index = _parse_sequence(lines, index, indent)
            mapping[key] = child
        else:
            mapping[key] = None
    return mapping, index


def _parse_block_scalar(
    lines: list[tuple[int, str]], index: int, indent: int, style: str
) -> tuple[str, int]:
    """`|` keeps the newlines, `>` folds them into spaces; `-` strips the last.

    Comments are already gone by the time this runs, which is a real loss of
    fidelity - a `#` inside a literal block is text, not a comment - and it is
    recorded rather than fixed because nothing this parser reads needs one.
    A file that does would be a file that needs a real YAML library.
    """
    body: list[str] = []
    while index < len(lines) and lines[index][0] > indent:
        body.append(lines[index][1])
        index += 1
    joined = ("\n" if style.startswith("|") else " ").join(body)
    return (joined.rstrip() if style.endswith("-") else joined), index


def _is_quoted(raw: str) -> bool:
    return len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'"


def _flow_sequence(raw: str) -> list[Any]:
    """`[read, write]`, the inline list everybody writes.

    Defect DEF-94. This parser only read block sequences, so `effects: [read,
    write]` came back as the STRING "[read, write]" - and every caller then
    did something different and wrong with it. `agentgov._as_list` raised
    "expected a list, got str", which is at least an error;
    `manifest.load_text` did `tuple(str(name) for name in value)` and iterated
    the string CHARACTER BY CHARACTER, producing a manifest that claimed to
    use ":", "[", "]", "a", "b", "d"... and refused to load with a message
    listing single letters. Found by writing a declaration the way a person
    would rather than the way the tests do.

    Empty and nested cases are handled because leaving them out is how the
    next person meets the same class of surprise: `[]` is the empty list, and
    a nested `[a, [b, c]]` parses rather than splitting on the inner comma.
    """
    body = raw[1:-1].strip()
    if not body:
        return []
    items: list[str] = []
    depth, quote, current = 0, "", []
    for character in body:
        if quote:
            current.append(character)
            if character == quote:
                quote = ""
            continue
        if character in "\"'":
            quote = character
            current.append(character)
            continue
        if character in "[{":
            depth += 1
        elif character in "]}":
            depth -= 1
        if character == "," and depth == 0:
            items.append("".join(current).strip())
            current = []
            continue
        current.append(character)
    items.append("".join(current).strip())
    return [_scalar(item) for item in items if item != ""]


def _scalar(raw: str) -> Any:
    if _is_quoted(raw):
        return raw[1:-1]
    if raw.startswith("[") and raw.endswith("]"):
        return _flow_sequence(raw)
    lowered = raw.lower()
    if lowered in ("true", "yes"):
        return True
    if lowered in ("false", "no"):
        return False
    if lowered in ("null", "~", ""):
        return None
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw
