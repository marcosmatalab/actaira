"""The connector registry, and the one property that keeps `for_uri` honest.

Design note D-84. This file is the same shape as `controls/registry.py` and for
the same reason (see design note D-43): registration is explicit, a duplicate
name is refused rather than silently shadowing, and the modules are imported
once, lazily, so that a command which never touches the network does not pay
for the package that can.

What is different here is `for_uri`, and it deserves its own rule. The controls
registry is looked up by an identifier the caller typed. This one is looked up
by *guessing*: the operator writes `hf://org/model` or `s3://bucket/prefix` or
a bare directory path, and something has to decide which connector that string
belongs to. A wrong guess is not a crash, which is the problem: it is a
different source being listed than the one the operator named.

So the rule is that `accepts` predicates are disjoint, and it is a rule rather
than an aspiration because `tests/test_connectors.py` asserts it over a table
of every URI shape this package documents. Exactly one connector accepts each
of them, and a URI that two connectors accept is a test failure rather than a
tie broken by whichever module happened to be registered first.

The two accepts that could plausibly overlap are `filesystem` and `url`, and
they are separated by a fact about the disk rather than by a pattern: the
filesystem connector accepts an existing *directory*, the manifest connector
accepts an existing *file*. A path that is neither is accepted by no connector
and the CLI says so, which is better than a connector that reports zero
artifacts for a directory the operator misspelt.
"""
from __future__ import annotations

from .model import Connector, ConnectorError

_REGISTRY: dict[str, Connector] = {}


def register(connector: Connector) -> Connector:
    if connector.name in _REGISTRY:
        raise ValueError(f"duplicate connector name {connector.name!r}")
    _REGISTRY[connector.name] = connector
    return connector


def get(name: str) -> Connector:
    _ensure_loaded()
    return _REGISTRY[name]


def all_connectors() -> tuple[Connector, ...]:
    _ensure_loaded()
    return tuple(_REGISTRY[key] for key in sorted(_REGISTRY))


def for_uri(uri: str) -> Connector:
    """The connector that accepts this URI, or an error naming the URI.

    Every candidate is asked, not just the first one that answers, so an
    overlap is visible as an error here rather than as a silent precedence
    rule. A source string that two connectors both claim is a defect in one of
    the two predicates, and the operator finding out about it from a listing
    of the wrong repository is the failure this refusal exists to prevent.
    """
    matches = [connector for connector in all_connectors() if connector.accepts(uri)]
    if not matches:
        raise ConnectorError(f"no connector accepts {uri!r}")
    if len(matches) > 1:
        names = ", ".join(connector.name for connector in matches)
        raise ConnectorError(f"{uri!r} is claimed by more than one connector: {names}")
    return matches[0]


_LOADED = False


def _ensure_loaded() -> None:
    """Import every connector module exactly once.

    Deferred rather than done at package import, for the reason `controls`
    defers its own: these modules import the contract in `model.py` and this
    file, and a circular import resolved at definition time is resolved by
    luck. The second reason is specific to this package: `actaira scan` must
    not import a directory full of network clients in order to read a file.
    """
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    from . import (  # noqa: F401
        filesystem,
        github,
        huggingface,
        mlflow,
        oci,
        s3,
        url,
    )
