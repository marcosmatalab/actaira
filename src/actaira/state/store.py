"""The database, its schema, and the one direction migrations run in.

Design note D-221. Three decisions are worth the paragraphs.

**Migrations are forward-only and numbered, and each one is a function, not a
file of SQL that happens to be in a directory.** A migration set discovered by
globbing is one where a rename, a merge conflict or an unsorted filesystem
changes what "version 4" means, and the failure is silent because every
individual statement succeeds. Here the list is written out, `MIGRATIONS[n]`
is the step from n to n+1, and `tests/test_state.py` migrates a fixture
database of every earlier version and asserts the digests and relations
survived.

**Nothing is written outside a transaction, and a snapshot is not marked
complete until everything it refers to is in.** A `watch` that died halfway
through would otherwise leave a row saying a source was fully observed
alongside half its artifacts, and the next run would compare against that and
report that the missing half had been deleted. The `complete` flag is set in
the same transaction as the last insert or not at all.

**Identity is a digest, not a row id.** Every table an operator can reach is
keyed on something reproducible - an artifact's sha256, a policy's digest, a
snapshot's canonical digest - so two machines that observed the same thing
agree without coordinating, and `state-export/v1` is a file you can diff rather
than a dump full of autoincrements.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import __version__

SCHEMA_VERSION = 3

DEFAULT_DIRECTORY = ".actaira"
DEFAULT_FILENAME = "state.db"


class StoreError(RuntimeError):
    """The store cannot be opened or is at a version this release cannot read."""


def default_path(root: Path | None = None) -> Path:
    return Path(root or Path.cwd()) / DEFAULT_DIRECTORY / DEFAULT_FILENAME


# --------------------------------------------------------------------------
# Migrations
# --------------------------------------------------------------------------


def _migration_1(connection: sqlite3.Connection) -> None:
    """The initial schema.

    Column choices worth naming. `sources.config_digest` covers everything
    about how a source is observed that could change what is observed, so a
    snapshot taken under different settings is not compared with one taken
    under the old ones. `snapshots.complete` is the listing-completeness flag
    that keeps "we saw nothing new" apart from "we could not see all of it".
    `edges.evidence_id` is nullable and that is the point: an edge with
    evidence behind it and an edge somebody declared are different claims and
    the graph has to be able to show which is which.
    """
    connection.executescript(
        """
        CREATE TABLE meta (
            key           TEXT PRIMARY KEY,
            value         TEXT NOT NULL
        );

        CREATE TABLE sources (
            source_id     TEXT PRIMARY KEY,
            connector     TEXT NOT NULL,
            uri           TEXT NOT NULL,
            revision      TEXT NOT NULL DEFAULT '',
            config_digest TEXT NOT NULL DEFAULT '',
            added_at      TEXT NOT NULL,
            last_seen     TEXT NOT NULL DEFAULT ''
        );
        CREATE UNIQUE INDEX sources_by_uri ON sources (uri);

        CREATE TABLE snapshots (
            snapshot_id   TEXT PRIMARY KEY,
            source_id     TEXT NOT NULL REFERENCES sources (source_id),
            observed_at   TEXT NOT NULL,
            revision      TEXT NOT NULL DEFAULT '',
            complete      INTEGER NOT NULL DEFAULT 0,
            digest        TEXT NOT NULL,
            document      TEXT NOT NULL
        );
        CREATE INDEX snapshots_by_source ON snapshots (source_id, observed_at);

        CREATE TABLE assets (
            asset_id      TEXT PRIMARY KEY,
            kind          TEXT NOT NULL,
            digest        TEXT NOT NULL DEFAULT '',
            name          TEXT NOT NULL,
            source_id     TEXT REFERENCES sources (source_id),
            first_seen    TEXT NOT NULL,
            last_seen     TEXT NOT NULL,
            attributes    TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX assets_by_kind ON assets (kind);
        CREATE INDEX assets_by_digest ON assets (digest);

        CREATE TABLE edges (
            from_asset    TEXT NOT NULL,
            relation      TEXT NOT NULL,
            to_asset      TEXT NOT NULL,
            evidence_id   TEXT,
            stated_by     TEXT NOT NULL DEFAULT 'declaration',
            first_seen    TEXT NOT NULL,
            PRIMARY KEY (from_asset, relation, to_asset)
        );
        CREATE INDEX edges_forward ON edges (from_asset);
        CREATE INDEX edges_backward ON edges (to_asset);

        CREATE TABLE evidence (
            evidence_id   TEXT PRIMARY KEY,
            subject_id    TEXT NOT NULL,
            subject_digest TEXT NOT NULL DEFAULT '',
            kind          TEXT NOT NULL,
            collector     TEXT NOT NULL,
            collector_version TEXT NOT NULL,
            observed_at   TEXT NOT NULL,
            valid_until   TEXT,
            state         TEXT NOT NULL,
            supersedes    TEXT,
            digest        TEXT NOT NULL,
            document      TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX evidence_by_subject ON evidence (subject_id, observed_at);
        CREATE INDEX evidence_by_state ON evidence (state);

        CREATE TABLE policies (
            policy_digest TEXT PRIMARY KEY,
            policy_id     TEXT NOT NULL,
            version       INTEGER NOT NULL,
            document      TEXT NOT NULL,
            first_seen    TEXT NOT NULL
        );

        CREATE TABLE decisions (
            decision_id   TEXT PRIMARY KEY,
            policy_digest TEXT NOT NULL,
            observed_at   TEXT NOT NULL,
            decision      TEXT NOT NULL,
            proof_digest  TEXT NOT NULL,
            subjects      TEXT NOT NULL DEFAULT '[]',
            document      TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX decisions_by_policy ON decisions (policy_digest, observed_at);

        CREATE TABLE receipts (
            receipt_digest TEXT PRIMARY KEY,
            path          TEXT NOT NULL DEFAULT '',
            signer        TEXT NOT NULL DEFAULT '',
            observed_at   TEXT NOT NULL
        );
        """
    )


def _migration_2(connection: sqlite3.Connection) -> None:
    """Record which snapshot an asset was last confirmed by.

    Written as a migration rather than folded into the first schema on
    purpose: this repository ships a migration test that needs a real one to
    exercise, and a migration path that has never run once is a migration path
    that does not work. The column is nullable, so every row written under
    version 1 stays valid and the store does not have to rewrite history to
    upgrade.
    """
    connection.execute("ALTER TABLE assets ADD COLUMN last_snapshot TEXT")


def _migration_3(connection: sqlite3.Connection) -> None:
    """What a decision relied on, as rows rather than as a sentence.

    Design note D-247. Until this migration the `decisions` table recorded
    that a decision happened and under which policy, and nothing recorded
    what it rested on. That is enough to file a decision and not enough to
    ever ask the question this release exists to answer: does the state that
    decision was made from still describe the subject in front of me.

    Two roles and no more. A `subject` row says the decision was made about
    this asset at this digest; an `evidence` row says it read this evidence
    record. They are separate because they fail differently - a subject's
    digest moving and an evidence record being revoked are two different
    reasons to look again, and a reader has to be able to tell which
    happened.

    Deliberately a table and not a column. A comma-separated list of ids in a
    TEXT field is a join waiting to be written by hand in three places, it
    cannot be indexed, and the first id containing a comma ends the
    arrangement silently.

    Additive and nullable-by-absence: every decision written under version 2
    keeps its row and simply has no inputs, which is why
    `decision.validity()` answers UNDETERMINED for it rather than CURRENT.
    An old decision is not a decision that was checked and found fine.
    """
    connection.executescript(
        """
        CREATE TABLE decision_inputs (
            decision_id    TEXT NOT NULL,
            role           TEXT NOT NULL,
            ref            TEXT NOT NULL,
            subject_id     TEXT NOT NULL DEFAULT '',
            subject_digest TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (decision_id, role, ref)
        );
        CREATE INDEX decision_inputs_by_decision ON decision_inputs (decision_id);
        """
    )


MIGRATIONS: tuple[Callable[[sqlite3.Connection], None], ...] = (
    _migration_1,
    _migration_2,
    _migration_3,
)


# --------------------------------------------------------------------------
# The store
# --------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _observation_id(snapshot: Any) -> str:
    """A key for one OBSERVATION, not for one listing. See DEF-70.

    The content digest answers "is this the same listing" and is kept in its
    own column for exactly that comparison. The primary key has to answer "is
    this the same observation", or a source that returns to an earlier state
    cannot record having done so.
    """
    seed = f"{snapshot.source_id}|{snapshot.observed_at}|{snapshot.digest}"
    return "snap_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


class Store:
    """The local state, opened at a path and closed when you are done.

    Use it as a context manager. Every write goes through `transaction()`,
    which either commits the whole thing or rolls all of it back - see D-221
    on why a half-written snapshot is worse than no snapshot.
    """

    def __init__(self, path: Path, *, create: bool = True) -> None:
        self.path = Path(path)
        if not self.path.exists() and not create:
            raise StoreError(
                f"{self.path} does not exist. `actaira init` creates it; every other command "
                "works without it."
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        # Everything from here can fail on a file that is not a database, or
        # on one written by a newer release. Each of those is a `StoreError`
        # with a message, and each closes the connection on the way out: an
        # `__init__` that raises leaves no object for `__exit__` to clean up,
        # so a caller that retries leaks a descriptor and a `-wal` file every
        # time. Defect DEF-69.
        try:
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys = ON")
            # Durability over speed: this is a tool that writes rarely and
            # whose whole value is that what it recorded is what was there.
            self.connection.execute("PRAGMA journal_mode = WAL")
            self.connection.execute("PRAGMA synchronous = FULL")
            self._migrate()
        except StoreError:
            self.connection.close()
            raise
        except sqlite3.Error as exc:
            self.connection.close()
            raise StoreError(
                f"{self.path} is not a readable Actaira state database: {exc}. "
                "`actaira init` creates one; every other command works without it."
            ) from exc

    # -- lifecycle ------------------------------------------------------

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """All of it or none of it. See D-221."""
        try:
            with self.connection:
                yield self.connection
        except sqlite3.Error as exc:  # pragma: no cover - surfaced as a store error
            raise StoreError(f"{self.path}: {exc}") from exc

    # -- schema ---------------------------------------------------------

    def _version(self) -> int:
        row = self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'"
        ).fetchone()
        if row is None:
            return 0
        value = self.connection.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()
        return int(value["value"]) if value else 0

    def _migrate(self) -> None:
        current = self._version()
        if current > SCHEMA_VERSION:
            raise StoreError(
                f"{self.path} is at schema version {current} and this release reads "
                f"{SCHEMA_VERSION}. Migrations run forward only: a newer store was written by a "
                "newer Actaira, and downgrading it would mean guessing what its extra columns meant."
            )
        for step in range(current, SCHEMA_VERSION):
            with self.transaction() as connection:
                MIGRATIONS[step](connection)
                if step == 0:
                    connection.execute(
                        "INSERT INTO meta (key, value) VALUES ('created_at', ?)", (_now(),)
                    )
                connection.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
                    "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                    (str(step + 1),),
                )
                connection.execute(
                    "INSERT INTO meta (key, value) VALUES ('tool_version', ?) "
                    "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                    (__version__,),
                )

    @property
    def schema_version(self) -> int:
        return self._version()

    def meta(self) -> dict[str, str]:
        return {row["key"]: row["value"] for row in self.connection.execute("SELECT key, value FROM meta")}

    # -- sources --------------------------------------------------------

    def add_source(self, source_id: str, connector: str, uri: str, config_digest: str = "") -> None:
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO sources (source_id, connector, uri, config_digest, added_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (source_id) DO UPDATE SET connector = excluded.connector, "
                "uri = excluded.uri, config_digest = excluded.config_digest",
                (source_id, connector, uri, config_digest, _now()),
            )

    def source(self, source_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM sources WHERE source_id = ? OR uri = ?", (source_id, source_id)
        ).fetchone()
        return dict(row) if row else None

    def sources(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute("SELECT * FROM sources ORDER BY source_id")
        ]

    # -- snapshots ------------------------------------------------------

    def latest_snapshot(self, source_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM snapshots WHERE source_id = ? ORDER BY observed_at DESC, rowid DESC LIMIT 1",
            (source_id,),
        ).fetchone()
        return dict(row) if row else None

    def snapshots(self, source_id: str) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM snapshots WHERE source_id = ? ORDER BY observed_at, rowid",
                (source_id,),
            )
        ]

    def record_snapshot(self, snapshot: Any, connection: sqlite3.Connection | None = None) -> bool:
        """Write a snapshot, and say whether the source's state moved.

        Two things this gets right that the first version did not, and both
        were found by reading it rather than by a test.

        Defect DEF-70: the row is keyed on a per-observation id rather than on
        the content digest. Keying on the digest meant a source that went
        A -> B -> A could not record the return: the insert collided with the
        row from the first observation, was skipped, and `latest_snapshot`
        went on returning B. Every subsequent run then reported the same
        artifact as changed, forever, and `sources.last_seen` froze. A
        rollback, a re-pinned tag or a load balancer alternating between two
        mirrors all produce that sequence.

        Idempotence is now where it belongs: an observation whose content
        digest equals the CURRENT baseline's writes nothing, so a watch in
        cron does not grow the store by a row an hour, and one that differs
        always writes, whether or not those bytes were seen before.

        Defect DEF-71: `connection` is accepted so the caller can put this in
        the same transaction as the assets, edges and evidence that belong to
        it. Committing the snapshot on its own left a row saying a source had
        been fully observed next to nothing at all - permanently, because the
        next run compared against that row, found no change, and never filled
        in what was missing.
        """
        document = snapshot.to_dict()
        latest = self.latest_snapshot(snapshot.source_id)
        if latest and latest["digest"] == snapshot.digest:
            return False

        statement_snapshot = (
            "INSERT INTO snapshots (snapshot_id, source_id, observed_at, revision, complete, "
            "digest, document) VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (snapshot_id) DO NOTHING"
        )
        values_snapshot = (
            _observation_id(snapshot),
            snapshot.source_id,
            snapshot.observed_at,
            snapshot.revision,
            1 if snapshot.listing_complete else 0,
            snapshot.digest,
            json.dumps(document, ensure_ascii=False, sort_keys=True),
        )
        statement_source = "UPDATE sources SET last_seen = ?, revision = ? WHERE source_id = ?"
        values_source = (snapshot.observed_at, snapshot.revision, snapshot.source_id)

        if connection is not None:
            connection.execute(statement_snapshot, values_snapshot)
            connection.execute(statement_source, values_source)
            return True
        with self.transaction() as own:
            own.execute(statement_snapshot, values_snapshot)
            own.execute(statement_source, values_source)
        return True

    def touch_source(self, source_id: str, observed_at: str, connection: sqlite3.Connection | None = None) -> None:
        """Record that a source was looked at, even when nothing had moved.

        Part of DEF-70. `source list` reads `last_seen`, and a source watched
        every hour with no changes would otherwise show the date of its last
        CHANGE - which reads as a watch that has stopped running.
        """
        statement = "UPDATE sources SET last_seen = ? WHERE source_id = ?"
        if connection is not None:
            connection.execute(statement, (observed_at, source_id))
            return
        with self.transaction() as own:
            own.execute(statement, (observed_at, source_id))

    # -- assets and edges -----------------------------------------------

    def upsert_asset(
        self,
        asset_id: str,
        kind: str,
        name: str,
        *,
        digest: str = "",
        source_id: str | None = None,
        attributes: dict[str, Any] | None = None,
        snapshot_id: str | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        payload = json.dumps(attributes or {}, ensure_ascii=False, sort_keys=True)
        statement = (
            "INSERT INTO assets (asset_id, kind, digest, name, source_id, first_seen, last_seen, "
            "attributes, last_snapshot) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (asset_id) DO UPDATE SET last_seen = excluded.last_seen, "
            "digest = excluded.digest, name = excluded.name, attributes = excluded.attributes, "
            "last_snapshot = excluded.last_snapshot"
        )
        # One `_now()`, not two. Calling it twice made `first_seen` and
        # `last_seen` differ by microseconds on a fresh insert, which reads as
        # a row that was already updated once.
        moment = _now()
        values = (asset_id, kind, digest, name, source_id, moment, moment, payload, snapshot_id)
        if connection is not None:
            connection.execute(statement, values)
            return
        with self.transaction() as own:
            own.execute(statement, values)

    def asset(self, asset_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM assets WHERE asset_id = ? OR digest = ?", (asset_id, asset_id)
        ).fetchone()
        return dict(row) if row else None

    def assets(self, kind: str | None = None) -> list[dict[str, Any]]:
        if kind:
            rows = self.connection.execute(
                "SELECT * FROM assets WHERE kind = ? ORDER BY asset_id", (kind,)
            )
        else:
            rows = self.connection.execute("SELECT * FROM assets ORDER BY asset_id")
        return [dict(row) for row in rows]

    def add_edge(
        self,
        from_asset: str,
        relation: str,
        to_asset: str,
        *,
        evidence_id: str | None = None,
        stated_by: str = "declaration",
        connection: sqlite3.Connection | None = None,
    ) -> None:
        statement = (
            "INSERT INTO edges (from_asset, relation, to_asset, evidence_id, stated_by, first_seen) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (from_asset, relation, to_asset) DO UPDATE SET "
            "evidence_id = excluded.evidence_id, stated_by = excluded.stated_by"
        )
        values = (from_asset, relation, to_asset, evidence_id, stated_by, _now())
        if connection is not None:
            connection.execute(statement, values)
            return
        with self.transaction() as own:
            own.execute(statement, values)

    def edges(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM edges ORDER BY from_asset, relation, to_asset"
            )
        ]

    # -- evidence -------------------------------------------------------

    def record_evidence(self, record: Any, connection: sqlite3.Connection | None = None) -> None:
        """Write one observation, or refresh the one that says the same thing.

        Defect DEF-72. The conflict clause used to be
        `DO UPDATE SET state = excluded.state`, and every record this module
        builds is VALID. An evidence id is the digest of what the evidence
        says, so re-observing an unchanged artifact produces the same id -
        and overwrote whatever state an operator, a revocation or a stale
        sweep had set. Observing a sibling artifact was enough: a REVOKED
        attestation came back VALID on the next unrelated `watch`, and
        `EvidenceState.counts` gates every policy decision on VALID.

        What a re-observation genuinely establishes is that the same thing was
        still true a moment ago. That clears STALE - "nobody has looked
        lately" is answered by somebody looking - and it clears nothing else.
        REVOKED, UNTRUSTED and SUPERSEDED are not statements about when
        anybody last looked, and no amount of looking again changes any of
        them.
        """
        statement = (
            "INSERT INTO evidence (evidence_id, subject_id, subject_digest, kind, collector, "
            "collector_version, observed_at, valid_until, state, supersedes, digest, document) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (evidence_id) DO UPDATE SET observed_at = excluded.observed_at, "
            "valid_until = excluded.valid_until, state = 'valid' "
            "WHERE evidence.state IN ('valid', 'stale')"
        )
        values = (
            record.evidence_id,
            record.subject_id,
            record.subject_digest,
            record.kind,
            record.collector,
            record.collector_version,
            record.observed_at,
            record.valid_until,
            record.state.value,
            record.supersedes,
            record.digest,
            json.dumps(record.to_dict(), ensure_ascii=False, sort_keys=True),
        )
        if connection is not None:
            connection.execute(statement, values)
            return
        with self.transaction() as own:
            own.execute(statement, values)

    def evidence_for(self, subject_id: str) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM evidence WHERE subject_id = ? ORDER BY observed_at, rowid",
                (subject_id,),
            )
        ]

    def all_evidence(self, state: str | None = None) -> list[dict[str, Any]]:
        if state:
            rows = self.connection.execute(
                "SELECT * FROM evidence WHERE state = ? ORDER BY observed_at, rowid", (state,)
            )
        else:
            rows = self.connection.execute("SELECT * FROM evidence ORDER BY observed_at, rowid")
        return [dict(row) for row in rows]

    def set_evidence_state(
        self, evidence_id: str, state: str, connection: sqlite3.Connection | None = None
    ) -> None:
        statement = "UPDATE evidence SET state = ? WHERE evidence_id = ?"
        if connection is not None:
            connection.execute(statement, (state, evidence_id))
            return
        with self.transaction() as own:
            own.execute(statement, (state, evidence_id))

    # -- policies, decisions, receipts ----------------------------------

    def record_decision(
        self, decision: Any, proof_digest: str, inputs: Any = None
    ) -> str:
        """File a decision, and file what it rested on in the same transaction.

        `inputs` is a sequence of `DecisionInput` (see `state.decide`), and it
        goes in here rather than through a second call on purpose: a decision
        whose dependency rows were written by a later statement can be read
        between the two as a decision that depended on nothing, which is the
        one shape `decide.validity` reports as UNDETERMINED. A crash would
        make that permanent.
        """
        document = decision.to_dict()
        decision_id = proof_digest
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO policies (policy_digest, policy_id, version, document, first_seen) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT (policy_digest) DO NOTHING",
                (
                    decision.policy_digest,
                    decision.policy_id,
                    decision.policy_version,
                    json.dumps({"id": decision.policy_id, "version": decision.policy_version}),
                    _now(),
                ),
            )
            connection.execute(
                "INSERT INTO decisions (decision_id, policy_digest, observed_at, decision, "
                "proof_digest, subjects, document) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (decision_id) DO NOTHING",
                (
                    decision_id,
                    decision.policy_digest,
                    decision.decided_on.isoformat(),
                    decision.decision.value,
                    proof_digest,
                    json.dumps(list(decision.subjects), ensure_ascii=False),
                    json.dumps(document, ensure_ascii=False, sort_keys=True),
                ),
            )
            for item in inputs or ():
                connection.execute(
                    "INSERT INTO decision_inputs (decision_id, role, ref, subject_id, "
                    "subject_digest) VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT (decision_id, role, ref) DO NOTHING",
                    (
                        decision_id,
                        item.role,
                        item.ref,
                        item.subject_id,
                        item.subject_digest,
                    ),
                )
        return decision_id

    def decisions(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute("SELECT * FROM decisions ORDER BY observed_at, rowid")
        ]

    def decision(self, decision_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM decisions WHERE decision_id = ?", (decision_id,)
        ).fetchone()
        return dict(row) if row else None

    def decision_inputs(self, decision_id: str) -> list[dict[str, Any]]:
        """What one decision recorded as its inputs, in a stable order.

        Empty is a meaningful answer and not an error: it is what every
        decision filed before schema version 3 looks like, and
        `decide.validity` is required to read it as "this store cannot tell"
        rather than as "this decision depended on nothing and is therefore
        still fine".
        """
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM decision_inputs WHERE decision_id = ? ORDER BY role, ref",
                (decision_id,),
            )
        ]

    def evidence(self, evidence_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)
        ).fetchone()
        return dict(row) if row else None

    def record_receipt(self, receipt_digest: str, path: str, signer: str, observed_at: str) -> None:
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO receipts (receipt_digest, path, signer, observed_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT (receipt_digest) DO UPDATE SET path = excluded.path",
                (receipt_digest, path, signer, observed_at),
            )

    def receipts(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute("SELECT * FROM receipts ORDER BY observed_at, rowid")
        ]

    # -- export ---------------------------------------------------------

    def export(self) -> dict[str, Any]:
        """The whole store as one canonical document.

        Deterministic by construction: every table is ordered by its key, and
        nothing autoincrementing is emitted. Two machines that observed the
        same things produce the same export, which is what makes `watch`
        testable at all - the gate in `scripts/release_check.py` runs it twice
        over fixtures and compares bytes.
        """
        return {
            "schema_version": "state-export/v1",
            "store_schema_version": self.schema_version,
            "tool_version": __version__,
            "sources": self.sources(),
            "snapshots": [
                {key: value for key, value in row.items() if key != "document"}
                for source in self.sources()
                for row in self.snapshots(source["source_id"])
            ],
            "assets": self.assets(),
            "edges": self.edges(),
            "evidence": [
                {key: value for key, value in row.items() if key != "document"}
                for row in self.all_evidence()
            ],
            "decisions": [
                {key: value for key, value in row.items() if key != "document"}
                for row in self.decisions()
            ],
            # Beside the decisions rather than nested inside them: a v1
            # consumer reads `decisions` by iterating it, and an array whose
            # rows grew a nested array is a shape it was not written against.
            # D-247.
            "decision_inputs": [
                row
                for decision in self.decisions()
                for row in self.decision_inputs(decision["decision_id"])
            ],
            "receipts": self.receipts(),
        }
