"""Capture levels, and the interface every source of a trace arrives through.

Design note D-251. The level is not a label on the document, it is the thing
that decides what the document may claim. `docs/PRINCIPLES.md` gives four:

    L0  the agent's own transcript. Complete tool calls, written by the
        audited party. Cannot assert authenticity - not because it failed,
        but because there is nothing captured at the edge to assert about.
    L1  an MCP proxy. Tool calls seen from outside the agent.
    L2  a network proxy. The provider's traffic as well.
    L3  a seccomp sandbox. Files, network and execution.

Only L0 and L1 are reachable in this phase; L2 and L3 are declared here
because a rule states the level it needs, and a level that does not exist as a
name cannot be refused by name.

The reader interface is three methods and a registry. Cursor and Cline are
registered and raise on use: a source that is absent from the registry looks
like a source nobody thought about, and one that is present and explicit about
being unwritten is a promise nobody can mistake for a feature. Cursor keeps
its sessions in SQLite (`state.vscdb`, tables `ItemTable` and `cursorDiskKV`)
and Cline in flat JSON under `globalStorage`; both are phase-later work.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:  # pragma: no cover - import cycle, types only
    from .model import Trace


class CaptureLevel(str, Enum):
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"

    @classmethod
    def parse(cls, value: Any) -> CaptureLevel:
        try:
            return cls(value)
        except ValueError:
            raise ValueError(
                f"{value!r} is not a capture level; this release knows {[level.value for level in cls]}"
            ) from None


@dataclass(frozen=True)
class Summary:
    """What a source found, before anything is read in full."""

    sessions: int
    first: str | None
    last: str | None


class TraceReader(Protocol):
    """Every source of an L0 trace looks like this from the outside."""

    def summary(self) -> Summary: ...

    def read_all(self) -> list[Trace]: ...


class _Unwritten:
    """A source that is named, and says what it would take to write it."""

    def __init__(self, name: str, where: str) -> None:
        self.name = name
        self.where = where

    def __call__(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError(
            f"{self.name} transcripts are not read yet. They live in {self.where}. "
            "Declared here rather than omitted so a caller gets this sentence instead of a KeyError."
        )


def _claude_code() -> type:
    from .claude_code import ClaudeCodeReader

    return ClaudeCodeReader


SOURCES: dict[str, Any] = {
    "claude-code": _claude_code,
    "cursor": _Unwritten("cursor", "SQLite at state.vscdb, tables ItemTable and cursorDiskKV"),
    "cline": _Unwritten("cline", "flat JSON under the extension's globalStorage directory"),
}


def reader_for(name: str) -> Any:
    """The reader class for one source, or the reason there is not one yet."""
    if name not in SOURCES:
        raise KeyError(f"no source named {name!r}; known: {', '.join(sorted(SOURCES))}")
    entry = SOURCES[name]
    if isinstance(entry, _Unwritten):
        entry()
    return entry()
