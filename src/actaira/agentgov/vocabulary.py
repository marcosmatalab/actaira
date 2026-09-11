"""The words a declaration is allowed to use, and the escape hatch for the rest.

Design note D-201. `classification: internal` and `access: read_write` were
free strings. That is fine right up to the first time two teams write
`confidential` and `CONFIDENTIAL`, or `rw` and `read_write`, and a rule that
compares classifications quietly stops matching. A vocabulary that is not
enumerated is a vocabulary that cannot be checked, translated, or reasoned
over, and the rules in `capability.py` reason over exactly these two fields.

So there is a closed list, and a way out of it that is explicit rather than
accidental: a value outside the list is accepted when it carries a namespace,
`acme:pci-cardholder`. The namespace is the author saying "this word is ours,
we know Actaira does not understand it". A bare word Actaira does not know is
refused, because it is almost always a typo for one it does.

Both lists are versioned, and the version is emitted in the A-BOM. Adding a
member is a minor change for a producer and a breaking one for a consumer that
switches exhaustively, which is the same rule the JSON schemas follow.
"""
from __future__ import annotations

from enum import Enum

VOCABULARY_VERSION = "actaira-agent-vocabulary/v1"


class Classification(str, Enum):
    """How sensitive the contents of a data source are.

    Ordered by how much a disclosure costs, which is the order the rules use
    when they ask "is this at least as sensitive as".
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PERSONAL = "personal"
    SECRET = "secret"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return _CLASSIFICATION_RANK[self]


# UNKNOWN deliberately does not rank as harmless. A source nobody classified
# is not a public source; it is a source nobody looked at, and the rules must
# not treat the two the same. It sits above internal and below confidential:
# high enough that ignoring it is a decision, low enough that it does not
# fabricate a severity nobody has evidence for.
_CLASSIFICATION_RANK = {
    Classification.PUBLIC: 0,
    Classification.INTERNAL: 1,
    Classification.UNKNOWN: 2,
    Classification.CONFIDENTIAL: 3,
    Classification.PERSONAL: 4,
    Classification.RESTRICTED: 5,
    Classification.SECRET: 6,
}


class Access(str, Enum):
    """What the agent may do to a data source."""

    NONE = "none"
    READ = "read"
    APPEND = "append"
    WRITE = "write"
    READ_WRITE = "read_write"
    ADMIN = "admin"

    @property
    def mutates(self) -> bool:
        return self in (Access.APPEND, Access.WRITE, Access.READ_WRITE, Access.ADMIN)

    @property
    def reads(self) -> bool:
        return self in (Access.READ, Access.READ_WRITE, Access.ADMIN)


CLASSIFICATIONS = tuple(item.value for item in Classification)
ACCESS_MODES = tuple(item.value for item in Access)


def namespaced(value: str) -> bool:
    """`acme:pci` yes, `confidential` no, `a:` no, `:b` no."""
    head, separator, tail = value.partition(":")
    return bool(separator) and bool(head.strip()) and bool(tail.strip())
