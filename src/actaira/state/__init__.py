"""Local memory: what was here last time, and what has changed since.

Design note D-220. Everything in 2.1 answered one question - "what is true
about this artifact right now" - and answered it from nothing but the bytes in
front of it. That is the right shape for a scanner and it cannot answer the
question an operator actually has after the first week, which is "what changed,
what evidence that produced is no longer good, and what else is affected".

Answering that needs memory, and memory needs a store. The store is SQLite from
the standard library, and the choice is deliberate in both directions. It gives
transactions, indexes, a query language and deterministic migrations, so the
state is something you can reason about rather than a directory of JSON files
that half-write on a crash. And it adds nothing to the runtime supply chain of
a tool whose whole argument is that it has one dependency: a scanner that made
you run Postgres to find out what changed would not be run.

The store is optional. Every 2.1 command still works with no `.actaira/` at
all, because a tool that required initialisation before it would tell you
anything about a file would have lost what made it useful.
"""
from .evidence import EvidenceRecord, EvidenceState
from .graph import RELATIONS, Edge, Graph, impact
from .snapshot import Snapshot, SnapshotArtifact, snapshot_of
from .store import MIGRATIONS, SCHEMA_VERSION, Store, StoreError
from .watch import Observation, ObservationState, observe

__all__ = [
    "MIGRATIONS",
    "RELATIONS",
    "SCHEMA_VERSION",
    "Edge",
    "EvidenceRecord",
    "EvidenceState",
    "Graph",
    "Observation",
    "ObservationState",
    "Snapshot",
    "SnapshotArtifact",
    "Store",
    "StoreError",
    "impact",
    "observe",
    "snapshot_of",
]
