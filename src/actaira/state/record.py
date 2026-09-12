"""Persisting what an engine already established, when a workspace was asked for.

Design note D-246. Until this release the evidence ledger had seven kinds and
one producer. `watch` wrote `source_snapshot` records and nothing wrote the
other six, so `artifact_scan`, `agent_assessment`, `policy_decision`,
`bundle`, `governance` and `attestation` were vocabulary rather than data: a
closed enum, translated, documented, asserted over by the release check, and
impossible to obtain. That was measured before it was fixed - `grep` for
`record_evidence` in `src/` returned `watch.py` and the store method itself -
and it is the reason this module exists rather than an Evidence panel over an
almost-empty table.

Four rules shape everything here.

**Nothing in this module decides anything.** Every function takes a result an
engine already produced - an `ArtifactReport`, an assessment, a
`PolicyDecision` - and files it. A second verdict derived here for storage
would be a second opinion that can disagree with the first, and the first is
the one the operator saw.

**State stays optional, and a read never creates one.** Every entry point
takes an already-open `Store`, and every caller in `cli.py` opens one only
when `--state` was given, with `create=False`. `actaira scan model.pt` on a
machine with no workspace behaves exactly as it did in 2.2, which is the
local-first property the tool is worth anything for.

**Identity comes from the workspace, never from a filename.** This is the
hard one and §3 of the specification is explicit about it: a basename is not
an identity, two teams have a `model.pt`, and evidence filed against
`artifact:model.pt` would be evidence about whichever one was scanned last.
So a subject is bound to an asset this workspace already recorded, found by
the digest that was scanned or by the handle a manifest declared, and when no
such asset exists this module records nothing and says so. See `resolve`.

**Evidence is bound to the digest, not to the name.** That is D-223 and it is
what makes the rest of the release work: `watch` supersedes by digest, so a
scan record filed against the same asset id `watch` uses is superseded
automatically the moment those bytes change, and a scan of a sibling nobody
touched stays VALID.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import evidence as evidence_mod

# Why an identity could be established, or why it could not. Returned rather
# than raised: a caller in `cli.py` prints it, and a scan whose evidence could
# not be filed is still a scan whose findings the operator needs.
FROM_DIGEST = "recorded_asset_digest"
FROM_HANDLE = "recorded_asset_id"
UNRECORDED = "not_recorded_in_this_workspace"


@dataclass(frozen=True)
class Identity:
    """Which recorded asset a subject is, or a statement that it is none."""

    asset_id: str
    basis: str

    @property
    def known(self) -> bool:
        return bool(self.asset_id)

    def to_dict(self) -> dict[str, Any]:
        return {"asset": self.asset_id or None, "basis": self.basis}


def resolve(store: Any, *, digest: str = "", handle: str = "") -> Identity:
    """The asset this workspace already holds for this subject, or nothing.

    Two ways in and both are provenance-backed.

    By digest first, because it is the stronger of the two: `watch` records an
    artifact under an id derived from its URI and stores the digest it
    observed, so a file scanned on this machine whose bytes match one of those
    rows is that artifact - and filing evidence under the same id is what lets
    a later `watch` supersede it when those bytes change.

    By handle second, for the kinds that have no bytes of their own. `graph
    build --subjects` records `agent:ticket-triage` and `system:checkout` from
    a manifest, so an agent assessment has somewhere to attach.

    And when neither matches, an `Identity` with no asset. Not an exception
    and not an invented id: a subject this workspace has never observed has no
    stable identity here, and the honest answer is to say that rather than to
    mint `artifact:<basename>` and file evidence about the wrong model.
    """
    if digest:
        for row in store.assets():
            if row["digest"] and row["digest"] == digest:
                return Identity(str(row["asset_id"]), FROM_DIGEST)
    if handle and store.asset(handle) is not None:
        return Identity(handle, FROM_HANDLE)
    return Identity("", UNRECORDED)


@dataclass
class Recorded:
    """What one persistence attempt wrote, or why it wrote nothing."""

    written: bool
    identity: Identity
    evidence_id: str = ""
    kind: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "recorded": self.written,
            "identity": self.identity.to_dict(),
        }
        if self.evidence_id:
            payload["evidence_id"] = self.evidence_id
        if self.kind:
            payload["kind"] = self.kind
        if self.note:
            payload["note"] = self.note
        return payload


_UNKNOWN_SUBJECT = (
    "this workspace records no asset with that digest, so there is nothing to bind the "
    "evidence to. Observe the source that serves it (`actaira source add` then `actaira "
    "watch`), or declare it in a subject manifest and run `actaira graph build`"
)


def artifact_scan(store: Any, report: Any, *, scan_policy: str = "", fail_on: str = "") -> Recorded:
    """File what a scan established about one artifact's exact bytes.

    The report is the authority. Its `verdict` is copied, not recomputed: a
    `verdict` derived here would be a second opinion, and the release grep for
    a second verdict path exists because that is exactly the kind of drift
    nobody notices until two documents about one file disagree.

    What goes in the payload is the shape of the answer, never the artifact.
    Rule ids and counts, not opcodes, not a disassembly and not the bytes -
    an evidence row is read by a panel, and a store that holds hostile input
    is a store that has to be handled as hostile input.
    """
    digest = f"sha256:{report.sha256}"
    identity = resolve(store, digest=digest)
    if not identity.known:
        return Recorded(False, identity, note=_UNKNOWN_SUBJECT)

    findings = sorted({finding.rule_id for finding in report.findings})
    payload: dict[str, Any] = {
        "verdict": report.verdict.value if hasattr(report.verdict, "value") else str(report.verdict),
        "format": report.detected_format or "",
        "findings": findings,
        "finding_count": len(report.findings),
    }
    coverage = getattr(report, "coverage", None)
    if coverage is not None:
        # The coverage matrix as surface -> state, which is the fact a later
        # reader needs: a verdict from a run that never opened the weights is
        # a different claim from the same verdict with them read.
        payload["coverage"] = {
            str(row["surface"]): str(row["state"]) for row in coverage.to_dict()["surfaces"]
        }
    if scan_policy:
        payload["scan_policy"] = scan_policy
    if fail_on:
        payload["fail_on"] = fail_on

    record = evidence_mod.for_subject(
        identity.asset_id, "artifact_scan", subject_digest=digest, payload=payload
    )
    store.record_evidence(record)
    return Recorded(True, identity, record.evidence_id, "artifact_scan")


def agent_assessment(
    store: Any, agent: Any, findings: list[Any], paths: Any, *, fail_on: str = ""
) -> Recorded:
    """File one assessment of one declared agent shape.

    One record, not two, and that is a decision §4 asks to be made explicitly.
    `agent check` and `agent paths` read the same declaration and answer two
    halves of one question - which capability combinations are dangerous, and
    which routes an untrusted input can take to reach them - and two records
    of the same kind about the same digest would be two documents a reader has
    to reconcile without being told they are halves. So the capability
    findings and the path counts go in one payload with separate keys.

    Bound to `Agent.digest`, which is the whole point. A later reader asking
    "was this produced about the agent in front of me?" compares one string;
    an assessment bound to the agent's name would answer yes for a declaration
    that had since grown a filesystem-writing tool.
    """
    identity = resolve(store, digest=agent.digest, handle=f"agent:{agent.name}")
    if not identity.known:
        return Recorded(False, identity, note=_UNKNOWN_SUBJECT)

    open_paths = paths.open_paths
    payload: dict[str, Any] = {
        "agent": agent.name,
        "agent_version": agent.version,
        "findings": sorted({finding.rule_id for finding in findings}),
        "finding_count": len(findings),
        # Counts and severities, not the routes themselves. An attack path
        # carries every node it passes through and a ledger row that inlined
        # them would be a graph pasted into a cell - §4 says not to, and
        # `actaira agent paths` is where the routes belong.
        "attack_paths": {
            "total": len(paths.paths),
            "open": len(open_paths),
            "closed": len(paths.paths) - len(open_paths),
            # Said rather than implied by the list being non-empty. An agent
            # with no untrusted input has no routes, and "searched and found
            # none" has to stay distinguishable from "nobody searched" -
            # DEF-81, one layer further out.
            "searched": True,
            # What the walk could not see. A route count from a search that
            # could not resolve a sub-agent is a count with a hole in it, and
            # a ledger row that hid the hole would be the more confident of
            # two documents about the same run.
            "unresolved_sub_agents": sorted(paths.unresolved_sub_agents),
        },
        "severities": sorted({str(getattr(item.severity, "value", item.severity))
                              for item in paths.paths}),
    }
    if fail_on:
        payload["fail_on"] = fail_on

    record = evidence_mod.for_subject(
        identity.asset_id, "agent_assessment", subject_digest=agent.digest, payload=payload
    )
    store.record_evidence(record)
    return Recorded(True, identity, record.evidence_id, "agent_assessment")


def policy_decision(store: Any, decision: Any, decision_id: str, claims: list[Any]) -> list[Recorded]:
    """File one evidence record per subject a decision was made about.

    A reference, not a copy. §7 is explicit that the decision document stays
    in one place, so the payload names the decision id, the policy digest and
    the answer, and nothing else about it. The authoritative decision is the
    `decisions` row; a second copy inside the evidence ledger is a second
    version that can disagree with it.

    One record per subject rather than one per decision, because of what it
    then does on its own. The record is bound to that subject's digest, so
    when `watch` next observes those bytes changed it is superseded by the
    same rule that supersedes a scan - and the ledger then shows, without
    anybody deriving it, that a policy decision was made about a digest that
    is gone. The decision itself is untouched: an ALLOW stays an ALLOW, and
    whether it still applies is `state.decide`'s question.
    """
    written: list[Recorded] = []
    for item in claims:
        reference = getattr(item, "ref", None)
        handle = reference.handle if reference is not None else ""
        digest = (reference.digest if reference is not None else "") or ""
        identity = resolve(store, digest=digest, handle=handle)
        if not identity.known:
            written.append(Recorded(False, identity, note=_UNKNOWN_SUBJECT))
            continue
        record = evidence_mod.for_subject(
            identity.asset_id,
            "policy_decision",
            subject_digest=digest,
            payload={
                "decision": decision.decision.value,
                "decision_id": decision_id,
                "policy": decision.policy_id,
                "policy_version": decision.policy_version,
                "policy_digest": decision.policy_digest,
                "decided_on": decision.decided_on.isoformat(),
            },
        )
        store.record_evidence(record)
        written.append(Recorded(True, identity, record.evidence_id, "policy_decision"))
    return written


# Evidence a decision is never recorded as depending on. A `policy_decision`
# record is the note that a decision happened; it is not something a decision
# rested on, and a run that took it as an input would make every decision
# after the first depend on the ones before it - so replacing a model would
# report the newest decision as needing reassessment partly because an older
# decision's note about the same model had been superseded. True, circular,
# and useless as a reason to act on.
NOT_AN_INPUT = ("policy_decision",)


def decision_inputs(store: Any, claims: list[Any]) -> list[Any]:
    """What the decision rested on, as rows `state.decide` can check later.

    Two kinds, and nothing inferred. Each subject the decision was made about,
    at the digest it had then; and each evidence record attached to those
    subjects that was VALID at the time, because that is what the policy
    language's `evidence_state` and `evidence_max_age_days` predicates read.

    Evidence in `NOT_AN_INPUT` is excluded by kind rather than by identity.
    Excluding only the records THIS run is about to write would have been
    enough on a first run and wrong on every one after it: the second decision
    about a subject would take the first decision's note as an input.
    """
    from .decide import evidence_input, subject_input

    inputs: list[Any] = []
    seen: set[tuple[str, str]] = set()
    for item in claims:
        reference = getattr(item, "ref", None)
        handle = reference.handle if reference is not None else ""
        digest = (reference.digest if reference is not None else "") or ""
        identity = resolve(store, digest=digest, handle=handle)
        if not identity.known:
            continue
        key = ("subject", identity.asset_id)
        if key not in seen:
            seen.add(key)
            inputs.append(subject_input(identity.asset_id, digest))
        for row in store.evidence_for(identity.asset_id):
            if row["kind"] in NOT_AN_INPUT:
                continue
            if row["state"] != evidence_mod.EvidenceState.VALID.value:
                # A decision does not rest on evidence that had already
                # stopped counting when it was made. Recording it as an input
                # would make the decision permanently REQUIRES_REASSESSMENT
                # for a reason that was true before it ran.
                continue
            key = ("evidence", str(row["evidence_id"]))
            if key in seen:
                continue
            seen.add(key)
            inputs.append(
                evidence_input(
                    str(row["evidence_id"]),
                    str(row["subject_id"]),
                    str(row["subject_digest"] or ""),
                )
            )
    return inputs
