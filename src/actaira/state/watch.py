"""Observe a source now, compare it with what was here last time, say what moved.

Design note D-225. The command this module implements is the reason the store
exists, and almost all of its design is in four distinctions that a naive
implementation collapses.

**First observation is not "no change".** A source nobody has watched before
has no baseline, and reporting "nothing changed" the first time is how an
operator concludes the watch is working when it has never compared anything.
The first run says BASELINE and records one.

**A revision that moved is not content that moved.** Registries re-tag, mirrors
re-upload and a commit can touch a README. When the revision differs and every
digest is the same, this reports SOURCE_DRIFT: worth recording, worth no
re-analysis, and specifically not the alarm that a weight file changing is.

**Content that moved is not the whole source moving.** Only the artifacts whose
digest changed are re-analysed, and only the evidence bound to those digests is
superseded. Evidence about a sibling nobody touched stays valid - see D-223.

**A listing that failed is not an empty source.** When the connector could not
enumerate everything, the result is INCOMPLETE and no baseline is written from
it. Treating a failed page as a set of deletions would produce the most
destructive possible false report: every artifact gone, every piece of evidence
superseded, on a source where nothing happened at all.

There is a fifth, and it is about failure rather than change: a network error
does not invalidate what was observed before. Evidence goes stale on the
policy's freshness terms, on its own schedule, and not because a TLS handshake
failed this morning.

`watch` is idempotent and stateless between runs - a check against stored
state, suitable for cron or a scheduled workflow. It is deliberately not a
daemon: a tool that has to stay running to notice anything is a tool that stops
noticing when it is restarted.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from . import evidence as evidence_mod
from .graph import snapshot_marker
from .snapshot import Snapshot

# How an artifact's digest came to be known, carried beside the digest rather
# than folded into it. D-85b: a digest the source published and a digest this
# process computed are two different claims, and the whole of D-200 is about
# not letting one wear the other's name.
MEASURED = "measured"
DECLARED = "declared"
UNIDENTIFIED = "size_only"


def artifact_digest(artifact: Any) -> tuple[str, str]:
    """The strongest digest a snapshot holds for one artifact, and its basis.

    Defect DEF-113. `_write` and `_record_evidence` both read
    `declared_sha256` alone, and the filesystem connector deliberately
    publishes none (D-85b) - so on a local source, which is the commonest
    workspace there is, `watch` read the bytes, computed `measured_sha256`,
    compared against it, correctly reported CONTENT_DRIFT, and then stored an
    asset row with an empty digest and no per-artifact evidence at all.

    Everything downstream rested on that digest: supersession is bound to it
    (D-223), `record.resolve` finds a scanned artifact by it, and the graph
    panel shows it. The measurement existed and was thrown away one line
    before it was written down.

    Measured first, because bytes this process read beat a digest somebody
    published about them. The basis travels with it so no reader can mistake
    one for the other.
    """
    if artifact.measured_sha256:
        return f"sha256:{artifact.measured_sha256}", MEASURED
    if artifact.declared_sha256:
        return f"sha256:{artifact.declared_sha256}", DECLARED
    return "", UNIDENTIFIED


class ObservationState(str, Enum):
    """What this observation found, relative to the last one."""

    BASELINE = "baseline"
    UNCHANGED = "unchanged"
    SOURCE_DRIFT = "source_drift"
    CONTENT_DRIFT = "content_drift"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class ChangedSubject:
    """One artifact that moved, named by the id the store knows it under.

    The asset id rather than the URI, because that is what `impact` walks from
    and what evidence is filed against. Carrying the URI too costs nothing and
    is what an operator reads.

    `before` and `after` are the digests on either side of the change, and
    either may be empty: an added artifact has no before, a removed one has no
    after, and an artifact whose source publishes no digest and whose bytes
    are not local has neither - which is what `basis` is for. A subject
    compared on size alone is a subject whose "changed" and "unchanged" are
    both weak, and DEF-74 is the cost of not saying so.
    """

    asset_id: str
    uri: str
    how: str
    before: str = ""
    after: str = ""
    basis: str = UNIDENTIFIED

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset_id,
            "uri": self.uri,
            "how": self.how,
            "before": self.before or None,
            "after": self.after or None,
            "identity_basis": self.basis,
        }


@dataclass
class Observation:
    """The result of one `watch`: what changed, and what that invalidated."""

    state: ObservationState
    source_id: str
    uri: str
    snapshot: Snapshot
    previous_digest: str = ""
    previous_revision: str = ""
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    superseded_evidence: list[str] = field(default_factory=list)
    recorded: bool = False
    note: str = ""
    # Artifacts whose "unchanged" rests on nothing stronger than a byte count.
    # Never empty and unmentioned: see DEF-74.
    weakly_compared: list[str] = field(default_factory=list)
    # The same facts as `added`/`changed`/`removed`, resolved to the asset ids
    # the rest of the store uses and carrying the digests on either side. The
    # URI lists stay because they are what an operator reads; this is what the
    # engine walks from, and computing it here is what makes exact
    # per-artifact impact possible without a second pass over the snapshots.
    subjects: list[ChangedSubject] = field(default_factory=list)

    @property
    def changed_anything(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def to_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "state": self.state.value,
            "source_id": self.source_id,
            "source": self.uri,
            "snapshot": {
                "from": self.previous_digest or None,
                "to": self.snapshot.digest,
            },
            "revision": {
                "from": self.previous_revision or None,
                "to": self.snapshot.revision or None,
            },
            "added": sorted(self.added),
            "removed": sorted(self.removed),
            "changed": sorted(self.changed),
            "superseded_evidence": sorted(self.superseded_evidence),
            "listing_complete": self.snapshot.listing_complete,
            "recorded": self.recorded,
            "weakly_compared": sorted(self.weakly_compared),
            "subjects": [item.to_dict() for item in
                         sorted(self.subjects, key=lambda row: (row.how, row.uri))],
        }
        if self.note:
            document["note"] = self.note
        return document


def _asset_id(uri: str) -> str:
    """A stable id for an artifact inside a source.

    Over the URI, so the same artifact keeps one id across observations even
    when its bytes change - which is the point: an asset whose id moved with
    its content would have no history, and "what changed about this file"
    would be unanswerable.
    """
    return "artifact:" + hashlib.sha256(uri.encode("utf-8")).hexdigest()[:24]


def observe(store: Any, snapshot: Snapshot, *, source_id: str | None = None) -> Observation:
    """Compare a fresh snapshot with the stored baseline and update the state.

    Everything this function writes happens in one transaction: the snapshot,
    the assets it saw, the evidence it superseded and the source's last-seen
    stamp go in together or not at all. A `watch` killed halfway through
    otherwise leaves a store that says a source was fully observed next to half
    its artifacts, and the next run reads that as a pile of deletions.
    """
    source = source_id or snapshot.source_id
    previous = store.latest_snapshot(source)

    if not snapshot.listing_complete:
        # No baseline is written from a listing that failed. The observation
        # is returned so a caller can report it, and the stored state is left
        # exactly as it was - which is the only safe thing to do with partial
        # information about what exists.
        return Observation(
            state=ObservationState.INCOMPLETE,
            source_id=source,
            uri=snapshot.uri,
            snapshot=snapshot,
            previous_digest=previous["digest"] if previous else "",
            previous_revision=previous["revision"] if previous else "",
            note=snapshot.incomplete_because
            or "the connector could not enumerate the whole source, so no baseline was written",
        )

    if previous is None:
        observation = Observation(
            state=ObservationState.BASELINE,
            source_id=source,
            uri=snapshot.uri,
            snapshot=snapshot,
            added=sorted(snapshot.by_uri()),
            note="first observation of this source; there was nothing to compare it with",
            weakly_compared=sorted(
                uri
                for uri, artifact in snapshot.by_uri().items()
                if artifact.identity_basis == "size_only"
            ),
            subjects=[
                _subject(uri, "added", after=snapshot.by_uri()[uri])
                for uri in sorted(snapshot.by_uri())
            ],
        )
        _write(store, snapshot, observation)
        return observation

    before = _artifacts_of(previous)
    after = {uri: artifact.to_dict() for uri, artifact in snapshot.by_uri().items()}

    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = sorted(
        uri
        for uri in set(before) & set(after)
        if _identity(before[uri]) != _identity(after[uri])
    )

    if added or removed or changed:
        state = ObservationState.CONTENT_DRIFT
        note = ""
    elif snapshot.revision and previous["revision"] and snapshot.revision != previous["revision"]:
        # The distinction registries make necessary. The revision moved and
        # every digest is the same, so nothing needs re-reading and the fact
        # is still worth a row: it is how a re-tag or a mirror re-upload looks,
        # and an operator chasing a provenance question will want it.
        state = ObservationState.SOURCE_DRIFT
        note = "the revision moved and every artifact digest is unchanged"
    else:
        state = ObservationState.UNCHANGED
        note = ""

    observation = Observation(
        state=state,
        source_id=source,
        uri=snapshot.uri,
        snapshot=snapshot,
        previous_digest=previous["digest"],
        previous_revision=previous["revision"],
        added=added,
        removed=removed,
        changed=changed,
        note=note,
        weakly_compared=sorted(
            uri
            for uri in set(before) & set(after)
            if _identity(after[uri])[0] == "size"
        ),
        subjects=(
            [_subject(uri, "added", after=snapshot.by_uri()[uri]) for uri in added]
            + [_subject(uri, "changed", after=snapshot.by_uri()[uri], before=before[uri])
               for uri in changed]
            # A removed artifact has a before and no after, and it keeps the
            # asset id it always had. The row stays in the store: the recorded
            # graph remembers what was there, which is the point of recording
            # it, and impact from a deletion starts from that same id.
            + [_subject(uri, "removed", before=before[uri]) for uri in removed]
        ),
    )
    _write(store, snapshot, observation)
    return observation


def _subject(uri: str, how: str, *, after: Any = None, before: Any = None) -> ChangedSubject:
    """Assemble one changed subject from either side of the comparison.

    The two sides arrive in different shapes - a live `SnapshotArtifact` for
    what is there now, a stored mapping for what was - so each is read by the
    reader that understands it rather than by one function that guesses.
    """
    after_digest, basis = artifact_digest(after) if after is not None else ("", UNIDENTIFIED)
    before_digest = _stored_digest(before) if before is not None else ""
    if after is None and before is not None:
        basis = _stored_basis(before)
    return ChangedSubject(
        asset_id=_asset_id(uri),
        uri=uri,
        how=how,
        before=before_digest,
        after=after_digest,
        basis=basis,
    )


def _stored_digest(row: dict[str, Any]) -> str:
    """The digest a previous snapshot recorded for an artifact, strongest first.

    The same precedence `artifact_digest` applies to a live artifact, over the
    stored mapping a snapshot document holds. Two spellings of one rule would
    agree until one of them was changed.
    """
    if row.get("measured_sha256"):
        return f"sha256:{row['measured_sha256']}"
    if row.get("declared_sha256"):
        return f"sha256:{row['declared_sha256']}"
    return ""


def _stored_basis(row: dict[str, Any]) -> str:
    if row.get("measured_sha256"):
        return MEASURED
    if row.get("declared_sha256"):
        return DECLARED
    return UNIDENTIFIED


def _identity(row: dict[str, Any]) -> tuple[Any, ...]:
    """What has to match for an artifact to count as unchanged.

    Bytes this process read first, a digest the source published second, and
    size only when there is neither. Size alone cannot see a file replaced by
    different bytes of the same length, so it is not a fallback this module is
    quiet about: `Observation.weakly_compared` names every artifact judged that
    way, `to_dict` carries the list, and the CLI prints it. See DEF-74 - the
    version that fell back silently reported UNCHANGED, exit 0, on a weight
    file whose contents had been replaced.
    """
    if row.get("measured_sha256"):
        return ("measured", row["measured_sha256"])
    if row.get("declared_sha256"):
        return ("declared", row["declared_sha256"])
    return ("size", row.get("size_bytes", 0))


def _artifacts_of(snapshot_row: dict[str, Any]) -> dict[str, dict[str, Any]]:
    import json

    document = json.loads(snapshot_row["document"])
    return {row["uri"]: row for row in document.get("artifacts", [])}


def _write(store: Any, snapshot: Snapshot, observation: Observation) -> None:
    """One transaction: the snapshot, its assets, and what it invalidated.

    Defect DEF-71. This used to call `record_snapshot`, which opened and
    committed a transaction of its own, and only then open a second one for
    the assets, edges and evidence. A failure in between left a row saying the
    source had been fully observed next to nothing at all - and left it there
    permanently, because the next run compared against that committed row,
    found no change, took the early return, and never wrote what was missing.

    So `record_snapshot` now takes the connection and everything lands
    together. The supersession pass follows it, outside, because it reads what
    was just committed: a transaction that both wrote and re-read its own
    uncommitted rows would have to be reasoned about at a level SQLite makes
    no promises at.
    """
    latest = store.latest_snapshot(observation.source_id)
    moved = not latest or latest["digest"] != snapshot.digest

    with store.transaction() as connection:
        observation.recorded = store.record_snapshot(snapshot, connection) if moved else False
        if not moved:
            # Same listing as the baseline. The assets and edges are already
            # there and identical, so only two things are worth writing: that
            # the source was looked at, and that the evidence behind it was
            # observed again. Both are what "nothing has changed" actually
            # establishes, and leaving them out was DEF-73 - a source watched
            # every hour with no changes went stale after thirty days and
            # re-observing could never clear it, because the timestamp nobody
            # refreshed was the one the freshness check reads.
            store.touch_source(observation.source_id, snapshot.observed_at, connection)
            _record_evidence(store, snapshot, observation, connection)
            return

        for uri, artifact in snapshot.by_uri().items():
            digest, basis = artifact_digest(artifact)
            store.upsert_asset(
                _asset_id(uri),
                "artifact",
                uri,
                # DEF-113. Measured before declared, and never neither when
                # one of them exists: this column is what supersession, the
                # graph panel and `record.resolve` all read.
                digest=digest,
                source_id=observation.source_id,
                attributes={
                    "size_bytes": artifact.size_bytes,
                    "revision": artifact.revision,
                    # Kept beside the digest, not folded into it. D-85b.
                    "identity_basis": basis,
                },
                snapshot_id=snapshot.digest,
                connection=connection,
            )
        store.upsert_asset(
            f"source:{observation.source_id}",
            "source",
            snapshot.uri,
            digest=snapshot.digest,
            source_id=observation.source_id,
            attributes={"connector": snapshot.connector, "revision": snapshot.revision},
            snapshot_id=snapshot.digest,
            connection=connection,
        )
        for uri in snapshot.by_uri():
            store.add_edge(
                f"source:{observation.source_id}",
                "contains",
                _asset_id(uri),
                # One spelling, defined beside the reader that parses it
                # back: `state.graph.project` decides whether an observed
                # edge is still current by comparing this marker with the
                # source's latest snapshot, and two copies of the format
                # would agree until one of them was widened.
                stated_by=snapshot_marker(snapshot.digest),
                connection=connection,
            )
        _record_evidence(store, snapshot, observation, connection)

    for uri in observation.changed + observation.removed:
        # Bound to the digest that is gone, not to the source's name. See
        # D-223: this is what keeps an invalidation something an operator can
        # act on rather than a wall of red.
        after = snapshot.by_uri().get(uri)
        new_digest = artifact_digest(after)[0] if after is not None else ""
        observation.superseded_evidence.extend(
            evidence_mod.supersede(store, _asset_id(uri), new_digest)
        )


def _record_evidence(store: Any, snapshot: Snapshot, observation: Observation, connection: Any) -> None:
    record = evidence_mod.for_subject(
        f"source:{observation.source_id}",
        "source_snapshot",
        subject_digest=snapshot.digest,
        payload={
            "artifacts": len(snapshot.artifacts),
            "revision": snapshot.revision,
            "listing_complete": snapshot.listing_complete,
        },
    )
    record.observed_at = snapshot.observed_at
    store.record_evidence(record, connection)

    # One record per artifact whose identity the source published, and none
    # for the ones it did not. The digest is what supersession is bound to
    # (D-223), so an artifact with no declared digest has nothing to bind and
    # gets no record rather than a record that could never be invalidated
    # correctly.
    for uri, artifact in snapshot.by_uri().items():
        digest, basis = artifact_digest(artifact)
        if not digest:
            continue
        per_artifact = evidence_mod.for_subject(
            _asset_id(uri),
            "source_snapshot",
            subject_digest=digest,
            payload={
                "uri": uri,
                "size_bytes": artifact.size_bytes,
                "observed_by": snapshot.connector,
                # Which of the two this digest is. `declared_by` used to name
                # the connector for a digest the connector had published, and
                # DEF-113's fix makes a measured digest reach here too - so
                # the field that says which is not optional decoration.
                "identity_basis": basis,
            },
        )
        per_artifact.observed_at = snapshot.observed_at
        store.record_evidence(per_artifact, connection)


def stale_sweep(store: Any, *, max_age_days: int, on: datetime | None = None) -> list[str]:
    """Move evidence past its freshness to STALE. Separate from `observe` on purpose.

    Freshness is a policy question and observation is a fact-gathering one, so
    they are two calls. A watch that also expired evidence would make "how old
    may this be" depend on how often somebody ran the watch.
    """
    return evidence_mod.expire(store, max_age_days=max_age_days, on=on or datetime.now(UTC))
