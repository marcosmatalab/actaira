"""What an agent CAN do, in the three states `docs/PRINCIPLES.md` allows an answer to have.

Design note D-270. The four capture levels govern what a RUN can be said to
have done; these three govern what a FILE can be said to permit, and mixing the
two vocabularies is how "a hook is written" turns into "a hook ran". So they are
separate enums in separate modules and nothing converts between them.

    DECLARED       written in a file, and the file is cited
    EFFECTIVE      resolved across scopes, with the agent's version known
    INDETERMINATE  not resolved, with the cause named

Rejected: a two-state model where anything not EFFECTIVE is DECLARED. It cannot
express the case the whole phase exists for - `bypassPermissions` in a project
file is declared, and whether it is effective depends on a version we may not
have - and a tool that answers "declared" there is answering a question nobody
asked.

Nothing here reads a clock, a socket or a file. `readers/` touch disk and do
nothing else; `resolve` is a pure function of what they read; rules are pure
functions of what `resolve` returned. That split is what lets the whole decision
path be replayed from a fixture.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Resolution(StrEnum):
    """How much can be said about one capability.

    `INDETERMINATE` is where design note D-04 ended up. That note was argued
    about `Verdict.INCONCLUSIVE` - "an inspector that cannot parse an artifact
    must say so instead of returning PASS, because a silent PASS on an unparsed
    file is exactly the failure mode that makes a supply-chain tool worthless" -
    and `Verdict` left with the conformance product in phase S0. The argument did
    not leave with it: the subject changed from an inspection to a capability,
    and a silent "not declared" about a file nobody could parse is the same
    worthlessness with a different noun.
    """

    DECLARED = "declared"
    EFFECTIVE = "effective"
    INDETERMINATE = "indeterminate"


class Scope(StrEnum):
    """Where a value came from, spelled as the vendor's documentation spells it.

    Ordered highest-precedence first, and `rank` is the only thing that reads
    the order. The command line is in the list and is never populated by a
    reader: Actaira reads files, and a flag somebody typed in a terminal left no
    file. It exists so the table of merge rules can state the full ladder the
    documentation states, rather than a subset that silently redefines it.
    """

    MANAGED = "managed"
    COMMAND_LINE = "command-line"
    PROJECT_LOCAL = "project-local"
    PROJECT = "project"
    USER = "user"

    @property
    def rank(self) -> int:
        return _SCOPE_RANK[self]


_SCOPE_RANK: dict[Scope, int] = {
    Scope.MANAGED: 0,
    Scope.COMMAND_LINE: 1,
    Scope.PROJECT_LOCAL: 2,
    Scope.PROJECT: 3,
    Scope.USER: 4,
}

# The scopes a repository supplies, which is the set an attacker who sends you a
# pull request controls. `check` treats these differently from the two above
# them, and SECURITY.md's threat model is written about exactly this set.
REPOSITORY_SCOPES = (Scope.PROJECT, Scope.PROJECT_LOCAL)


@dataclass(frozen=True)
class Capability:
    """One thing an agent can do, with where it was read and what resolved it.

    `facts` never holds a literal command, URL or header. The reader reduces a
    literal to a type, a digest and whether its target is inside the tree before
    it ever reaches this shape, so `--with-content` is a decision made once at
    the edge rather than a flag every consumer has to remember to respect.
    """

    name: str
    vendor: str
    scope: Scope
    source: str
    resolution: Resolution
    merge_rule: str
    facts: dict[str, Any] = field(default_factory=dict)
    # Why it is not EFFECTIVE. For DECLARED, the condition still outstanding -
    # "the folder has not been trusted". For INDETERMINATE, the cause.
    condition: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.name,
            "vendor": self.vendor,
            "scope": self.scope.value,
            "source": self.source,
            "resolution": self.resolution.value,
            "merge_rule": self.merge_rule,
            "condition": self.condition,
            "facts": self.facts,
        }


@dataclass(frozen=True)
class Unresolved:
    """Something seen and not resolved, with the cause written out.

    The third negative in one shape: a predicate with no information returns
    this, never False. It is counted apart from everything else and never
    distributed among the answers that could be given, which is why `Surface`
    keeps it in its own list rather than as a `Capability` with a flag.
    """

    subject: str
    cause: str
    source: str

    def to_dict(self) -> dict[str, Any]:
        return {"subject": self.subject, "cause": self.cause, "source": self.source}


@dataclass(frozen=True)
class NotRead:
    """A file on disk this release does not read, named rather than skipped.

    Silence about `.vscode/tasks.json` would read as absence, and absence is the
    one thing a configuration reader must never imply: the second half of both
    2026 worms lives in that file and phase S2 is what reads it.
    """

    path: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "reason": self.reason}


@dataclass(frozen=True)
class Surface:
    """The resolved answer for one root, and the three lists it is made of."""

    vendor: str
    agent_version: str | None
    capabilities: tuple[Capability, ...] = ()
    unresolved: tuple[Unresolved, ...] = ()
    not_read: tuple[NotRead, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "agent_version": self.agent_version,
            "capabilities": [item.to_dict() for item in self.capabilities],
            "unresolved": [item.to_dict() for item in self.unresolved],
            "not_read": [item.to_dict() for item in self.not_read],
        }


def document(
    root: str,
    surfaces: tuple[Surface, ...],
    findings: tuple[Any, ...],
    gaps: tuple[Unresolved, ...],
    *,
    machine: bool,
    merge_rules: tuple[Any, ...] = (),
) -> dict[str, Any]:
    """The `surface/v1` document. Same input, same bytes.

    The three lists stay three lists. A single list with a `kind` field would be
    smaller and would let a consumer add them up, and the one thing this document
    must not allow is an INDETERMINATE quietly counted as a finding that did not
    fire. `schemas.VERSIONS` is the only place the version string is written -
    the registry is the single source and a module literal would be the second
    (see `schemas/__init__.py`).
    """
    from ..schemas import VERSIONS

    return {
        "schema_version": VERSIONS["surface"],
        "root": root,
        "machine": machine,
        "surfaces": [item.to_dict() for item in surfaces],
        "findings": [item.to_dict() for item in findings],
        "unresolved": [item.to_dict() for item in gaps],
        "not_read": [
            entry.to_dict() for item in surfaces for entry in item.not_read
        ],
        "merge_rules": [row.to_dict() for row in merge_rules],
    }
