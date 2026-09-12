"""One observation, assembled into everything that follows from it.

Design note D-249. The loop this release exists to close is

    observe -> state -> change -> invalidate -> impact -> decide -> prove

and until now the last four steps were assembled by whoever was asking. The
CLI printed the observation, then called `impact` from the source, then
printed a count of superseded records; a browser panel would have had to make
four requests and put the meaning together in JavaScript. Two surfaces
assembling one answer is two answers, and the one that drifts is whichever is
read less often.

So the assembly happens once, here, in Python, and both surfaces render what
this returns. `AssuranceChange` carries:

  the observation             what `watch` found, unchanged
  the changed subjects        each with the digest on either side
  what stopped counting       the evidence those exact digests invalidated
  what went stale             only when a freshness sweep was asked for
  impact                      from each changed asset, causes kept apart
  decision validity           which stored decisions now need a second look
  unknowns                    everything the store could not answer

The last field is not decoration and it is not a placeholder either. What it
carries today is the one thing that is genuinely unanswerable here: a subject
whose "changed" rests on a byte count, because neither the source published a
digest nor were the bytes local enough to read. Every consequence drawn from
such a comparison inherits its weakness, and DEF-74 is what it costs to let
that stop at the observation instead of travelling with the answer.

Deliberately not carried: an unknown for a changed subject with no recorded
dependents. It reads well and it cannot happen - `watch` writes a `contains`
edge for every artifact it observes, so an observed artifact always has at
least the source above it - and a branch that cannot be reached is a comment
pretending to be code.

**This is not a published schema, and that is deliberate.** §11 of the
specification is explicit: `assurance-state/v1` gets published when the engine
can honestly identify the subject, its digest, the graph state, the relevant
evidence, the relevant decision, that decision's validity and every unknown -
and one of those is still missing. A declared edge's currentness is
UNDETERMINED because nothing in the store says which declaration run is live
(D-243), so a state document would have to either omit provenance currentness
or assert it. `to_dict` here is deterministic and stable enough for the CLI's
`--json` and for the interface, and it carries no `schema_version` because
nothing outside this repository should pin to it yet. The seam is named in
docs/CONTRACTS.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import decide as decide_mod
from . import graph as graph_mod


@dataclass
class AssuranceChange:
    """What one observation changed, and everything that follows from it."""

    observation: dict[str, Any]
    subjects: list[dict[str, Any]] = field(default_factory=list)
    superseded: list[dict[str, Any]] = field(default_factory=list)
    stale: list[dict[str, Any]] = field(default_factory=list)
    impact: dict[str, Any] = field(default_factory=dict)
    decisions: list[dict[str, Any]] = field(default_factory=list)
    unknowns: list[dict[str, Any]] = field(default_factory=list)

    @property
    def changed_anything(self) -> bool:
        return bool(self.subjects)

    def counts(self) -> dict[str, int]:
        """The sizes, every key present even at zero.

        A summary whose missing keys mean zero cannot be told apart from one
        whose missing keys mean "this build did not compute it", and a panel
        rendering the second as the first is how an empty answer reads as a
        clean one.
        """
        return {
            "subjects": len(self.subjects),
            "superseded": len(self.superseded),
            "stale": len(self.stale),
            "affected": len(self.impact.get("targets", [])),
            "decisions_requiring_reassessment": sum(
                1
                for row in self.decisions
                if row["validity"] == decide_mod.REQUIRES_REASSESSMENT
            ),
            "unknowns": len(self.unknowns),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation": self.observation,
            "subjects": self.subjects,
            "superseded_evidence": self.superseded,
            "stale_evidence": self.stale,
            "impact": self.impact,
            "decisions": self.decisions,
            "unknowns": self.unknowns,
            "counts": self.counts(),
        }


def of_observation(
    store: Any, observation: Any, *, stale: list[str] | None = None
) -> AssuranceChange:
    """Assemble the whole consequence of one `watch` run.

    Reads only. `observe` has already written everything it is going to write
    by the time this runs, and a function that both derived meaning and
    mutated state would be one whose output depended on how many times it had
    been called.
    """
    change = AssuranceChange(observation=observation.to_dict())
    change.subjects = [item.to_dict() for item in
                       sorted(observation.subjects, key=lambda row: (row.how, row.uri))]
    change.superseded = _evidence_rows(store, observation.superseded_evidence)
    change.stale = _evidence_rows(store, stale or [])

    # Nothing moved: no impact to compute and no decision whose inputs this
    # observation touched. Reporting an empty impact document would be true
    # and would invite a reader to think a walk had happened.
    if not observation.changed_anything:
        return change

    graph = graph_mod.Graph.from_store(store)
    change.impact = graph_mod.impact_of_changes(
        graph, [item.asset_id for item in observation.subjects]
    )

    for item in observation.subjects:
        if item.basis == "size_only":
            # DEF-74, carried through the whole chain rather than stopping at
            # the observation. A subject compared on a byte count alone
            # produced a "changed" this tool cannot stand behind, and every
            # consequence drawn from it inherits that.
            change.unknowns.append(
                {
                    "reason": "weak_comparison",
                    "asset": item.asset_id,
                    "uri": item.uri,
                    "detail": "neither this source nor this machine produced a digest for "
                    "this artifact, so it was compared on size alone",
                }
            )

    change.decisions = [row.to_dict() for row in decide_mod.review(store)]
    return change


def _evidence_rows(store: Any, ids: list[str]) -> list[dict[str, Any]]:
    """The records behind a list of ids, in the order the ids were given.

    The whole row rather than the id alone. A reader asked to accept that a
    piece of evidence stopped counting needs to see what it was about and
    which digest it was bound to, and an id is a lookup somebody has to
    perform before they can check the claim.
    """
    rows: list[dict[str, Any]] = []
    for evidence_id in ids:
        record = store.evidence(evidence_id)
        if record is None:  # pragma: no cover - only if a row vanished mid-run
            continue
        rows.append(
            {
                "evidence_id": record["evidence_id"],
                "subject": record["subject_id"],
                "subject_digest": record["subject_digest"],
                "kind": record["kind"],
                "state": record["state"],
                "observed_at": record["observed_at"],
            }
        )
    return rows


def history(store: Any, *, limit: int = 0) -> list[dict[str, Any]]:
    """Every observation this workspace has recorded, newest last.

    Derived from the stored snapshots rather than from a second table. A
    snapshot row is the observation - `record_snapshot` writes one only when
    the source's listing actually moved, so the sequence is already the
    history of changes and a parallel log would be a second copy that could
    disagree with it.

    Two things this deliberately does not show, because the store does not
    hold them and inventing either would be worse than the gap.

    **An unchanged observation leaves no row.** `record_snapshot` writes only
    when the listing actually moved - that is DEF-70's fix and it is what
    stops a watch in cron growing the store by a row an hour. So a source
    watched hourly for a month with nothing happening has one entry here, not
    seven hundred, and the timeline is a history of CHANGES rather than a
    history of runs. `sources.last_seen` is where "when did anybody last look"
    lives.

    **An incomplete observation leaves no row either**, by the same design and
    for a stronger reason: `observe` writes no baseline from a listing that
    failed, because treating a failed page as a set of deletions is the most
    destructive false report this tool could produce (D-225).

    What each observation superseded at the time is also not reconstructible.
    Supersession is a state on the evidence row and the row keeps only its
    current state, so an old entry can say what changed and not what that
    invalidated. Every entry carries `supersession_known: false` for exactly
    that reason - a panel must not render the absence as a zero.
    """
    import json

    rows: list[dict[str, Any]] = []
    for source in store.sources():
        snapshots = store.snapshots(source["source_id"])
        previous: dict[str, Any] | None = None
        for row in snapshots:
            document = json.loads(row["document"])
            entry = {
                "snapshot_id": row["snapshot_id"],
                "source_id": row["source_id"],
                "source": source["uri"],
                "observed_at": row["observed_at"],
                "revision": row["revision"],
                "listing_complete": bool(row["complete"]),
                "digest": row["digest"],
                "previous_digest": previous["digest"] if previous else None,
                "state": _state_of(previous, row, document),
                "artifacts": len(document.get("artifacts", [])),
                # Never a zero standing in for a gap. See the docstring: what
                # an old observation invalidated is not in this store.
                "supersession_known": False,
            }
            if previous is not None:
                entry.update(_difference(json.loads(previous["document"]), document))
            else:
                entry.update({"added": sorted(_by_uri(document)), "removed": [], "changed": []})
            rows.append(entry)
            previous = row

    rows.sort(key=lambda item: (str(item["observed_at"]), str(item["snapshot_id"])))
    if limit and len(rows) > limit:
        rows = rows[-limit:]
    return rows


def _by_uri(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["uri"]: row for row in document.get("artifacts", [])}


def _identity(row: dict[str, Any]) -> tuple[Any, ...]:
    """The same comparison `watch._identity` makes, over a stored row.

    Imported rather than rewritten would be better and is not possible
    without a cycle: `watch` imports this module's neighbours. So it is one
    function whose only job is to stay equal to that one, and
    `tests/test_state_change.py` asserts the two agree over the same input
    rather than trusting the comment.
    """
    if row.get("measured_sha256"):
        return ("measured", row["measured_sha256"])
    if row.get("declared_sha256"):
        return ("declared", row["declared_sha256"])
    return ("size", row.get("size_bytes", 0))


def _difference(before_document: dict[str, Any], after_document: dict[str, Any]) -> dict[str, Any]:
    before, after = _by_uri(before_document), _by_uri(after_document)
    return {
        "added": sorted(set(after) - set(before)),
        "removed": sorted(set(before) - set(after)),
        "changed": sorted(
            uri for uri in set(before) & set(after) if _identity(before[uri]) != _identity(after[uri])
        ),
    }


# What a stored pair of consecutive snapshots can be shown to be. Three of
# `watch`'s five states, plus one this reconstruction needs and `watch` does
# not have a name for.
#
# UNCHANGED and INCOMPLETE are absent and cannot be added: neither writes a
# snapshot row, so no pair of rows can ever exhibit one. Listing them here
# with a branch that cannot be reached would be a vocabulary that promises a
# timeline this store cannot draw.
TIMELINE_STATES = ("baseline", "content_drift", "source_drift", "listing_recorded")


def _state_of(previous: Any, row: Any, document: dict[str, Any]) -> str:
    """Which comparison two consecutive stored snapshots exhibit.

    `listing_recorded` is the fourth value and it is not a `watch` state. It
    is what remains when a snapshot differs from the one before it in neither
    its artifacts nor its revision, which happens when the source itself was
    re-registered under a different URI or connector: the snapshot digest
    covers those, so the listing is recorded again and nothing about the
    artifacts moved. Naming it is cheaper than folding it into SOURCE_DRIFT,
    whose meaning is specifically that the revision moved.
    """
    import json

    if previous is None:
        return "baseline"
    difference = _difference(json.loads(previous["document"]), document)
    if difference["added"] or difference["removed"] or difference["changed"]:
        return "content_drift"
    if row["revision"] and previous["revision"] and row["revision"] != previous["revision"]:
        return "source_drift"
    return "listing_recorded"
