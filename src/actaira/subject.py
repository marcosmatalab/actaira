"""One shape for everything a policy can decide about.

Design note D-211. In 2.1 the policy engine was general in concept and
artifact-centric in practice: `Claims` wrapped an `ArtifactReport`, every
predicate began by checking `claims.report is None`, and the CLI could only
build claims out of a path it had scanned. Bundles and agents produced findings
of their own and no policy could see them, so two worlds existed - a policy
language that could express "deny a critical finding" and a set of commands
whose most interesting findings it could not reach.

That is what this fixes, and the fix is a shape rather than a feature. A
subject is a reference and a set of claims about it. The reference says what
kind of thing it is, what identifies it, and where it came from. The claims are
what this run observed: findings, coverage, relations, evidence, provenance,
and a payload whose meaning depends on the kind. A predicate then reads a
field, not a class, and adding one is a decision about the policy language
rather than an accident of which dataclass was to hand.

Two properties are kept from 2.1 because they are the reason the engine is
worth anything. Nothing here executes user code or accepts an arbitrary
expression: the vocabulary stays small, enumerable and documentable. And
nothing here turns absence into falsehood - a subject nobody searched for
routes makes `attack_path_severity_at_least` unevaluable, never unsatisfied.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from pathlib import Path
from typing import Any

from .coverage import Coverage
from .model import ArtifactReport, Finding


class SubjectKind(str, Enum):
    """What sort of thing a decision is about.

    Five, and deliberately not more. `system` is the one that does not
    correspond to a file: it is a declared grouping - "the fraud review
    service" - that owns agents and models, and it exists so a receipt can be
    about the thing an auditor asks about rather than about one of its parts.
    """

    ARTIFACT = "artifact"
    BUNDLE = "bundle"
    AGENT = "agent"
    SYSTEM = "system"
    SOURCE = "source"


@dataclass(frozen=True)
class SubjectRef:
    """What this subject is, and what identifies it.

    `digest` is the identity where there is one. It is allowed to be empty and
    that is not a defect: a source is identified by its URI and a revision, and
    a bundle whose weights were never hashed has a layout digest that must not
    be mistaken for one (D-200). Whether a digest is strong enough for a
    particular claim is a question the claim asks, not one this dataclass
    answers by refusing to be built.
    """

    kind: SubjectKind
    id: str
    digest: str = ""
    source: str = ""
    version: str = ""
    # What `digest` IS. Defect DEF-80: a bundle's reference carried the
    # content digest when there was one and the layout digest otherwise, under
    # one unlabelled field - so a receipt and a proof could not tell a hash of
    # the weights from a hash of the directory listing, which is D-200
    # reintroduced one layer up. Worse in practice: `claims.subject` is this
    # digest and waivers match on it, so turning on `--hash-weights` silently
    # invalidated every subject-scoped waiver on a bundle.
    digest_kind: str = "content"

    @property
    def handle(self) -> str:
        """`agent:ticket-triage`. The stable name used in graphs and proofs."""
        return f"{self.kind.value}:{self.id}"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"kind": self.kind.value, "id": self.id, "handle": self.handle}
        for key, value in (("digest", self.digest), ("source", self.source), ("version", self.version)):
            if value:
                payload[key] = value
        if self.digest:
            payload["digest_kind"] = self.digest_kind
        return payload


@dataclass
class SubjectClaims:
    """Everything a policy is allowed to see about one subject.

    A deliberate narrowing: the predicates receive this, not the underlying
    report or agent. The payload slots stay separate because findings are
    read per kind - a single merged `findings` list would have made a policy
    unable to say which subject a rule fired on.

    Backwards compatible on purpose: `SubjectClaims(report)` is the 2.1
    `Claims(report)` call, with the same keyword arguments, so every policy
    written against 2.1 keeps working and the CLI paths that built claims from
    a scan did not have to be rewritten to be correct.
    """

    report: ArtifactReport | None = None
    subject: str = ""
    attestation: dict[str, Any] | None = None
    evidence_observed_on: date | None = None
    facts: dict[str, Any] = field(default_factory=dict)

    ref: SubjectRef | None = None
    bundle: Any = None
    agent: Any = None
    attack_paths: list[Any] = field(default_factory=list)
    # Whether anything actually searched for routes. An empty `attack_paths`
    # means two different things - "searched, found none" and "nobody looked" -
    # and DEF-81 was reading the second as the first, so a deny rule on an open
    # HIGH route silently passed.
    paths_searched: bool = False
    relations: list[dict[str, str]] = field(default_factory=list)
    # Same distinction one field along. A declaration that states no relations
    # is a fact; an artifact that never had any gathered is a gap. DEF-82.
    relations_known: bool = False
    evidence: list[dict[str, Any]] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    trust: dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        report: ArtifactReport | None = None,
        *,
        subject: str = "",
        attestation: dict[str, Any] | None = None,
        evidence_observed_on: date | None = None,
        facts: dict[str, Any] | None = None,
        ref: SubjectRef | None = None,
        bundle: Any = None,
        agent: Any = None,
        attack_paths: list[Any] | None = None,
        paths_searched: bool | None = None,
        relations: list[dict[str, str]] | None = None,
        evidence: list[dict[str, Any]] | None = None,
        provenance: dict[str, Any] | None = None,
        trust: dict[str, Any] | None = None,
    ) -> None:
        self.report = report
        self.bundle = bundle
        self.agent = agent
        self.attestation = attestation
        self.evidence_observed_on = evidence_observed_on
        self.facts = facts or {}
        self.evidence = list(evidence or [])
        self.provenance = dict(provenance or {})
        self.trust = dict(trust or {})
        self.ref = ref or _infer_ref(report, agent, subject)
        self.subject = subject or (self.ref.digest or self.ref.handle if self.ref else "")
        self.relations = list(relations) if relations is not None else _infer_relations(agent)
        # An agent's relations are always gathered, because `Agent.relations()`
        # is exhaustive over the declaration. Anything else has them only if a
        # caller supplied them.
        self.relations_known = agent is not None or relations is not None
        self.attack_paths = list(attack_paths) if attack_paths is not None else []
        self.paths_searched = (
            bool(paths_searched) if paths_searched is not None else attack_paths is not None
        )

    # ----------------------------------------------------------------
    # What the predicates read
    # ----------------------------------------------------------------

    @property
    def kind(self) -> SubjectKind | None:
        return self.ref.kind if self.ref else None

    @property
    def label(self) -> str:
        if self.report is not None:
            return Path(self.report.path).name
        if self.ref is not None:
            return self.ref.id or self.ref.handle
        return self.subject or "(no subject)"

    def findings_of(self, kind: SubjectKind) -> list[Finding]:
        """The findings belonging to one payload, never a merged list.

        Merging them would make `deny ACT-BDL-008` and `deny ACT-AGT-001`
        indistinguishable in a proof, and a proof that cannot say which
        subject a rule fired on is not a proof anybody can act on.
        """
        if kind is SubjectKind.ARTIFACT and self.report is not None:
            return list(self.report.findings)
        if kind is SubjectKind.BUNDLE and self.bundle is not None:
            return list(self.bundle.findings)
        if kind is SubjectKind.AGENT and self.agent is not None:
            from .conformance import assess

            return assess(self.agent)
        return []

    @property
    def coverage(self) -> Coverage | None:
        """The matrix, from whichever payload has one.

        Artifact first, then bundle. They are the two kinds that read bytes,
        and an agent declaration has no surfaces to cover - asking about
        coverage on one is a question with no answer rather than a failing
        one, which is why this returns None instead of an empty matrix.
        """
        if self.report is not None:
            return self.report.coverage
        if self.bundle is not None:
            return self.bundle.coverage
        return None

    def to_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = {"ref": self.ref.to_dict() if self.ref else None, "subject": self.subject}
        if self.provenance:
            document["provenance"] = self.provenance
        if self.relations:
            document["relations"] = self.relations
        if self.evidence:
            document["evidence"] = [
                {key: item[key] for key in ("evidence_id", "kind", "state") if key in item}
                for item in self.evidence
            ]
        if self.trust:
            document["trust"] = self.trust
        return document


def _infer_ref(report: ArtifactReport | None, agent: Any, subject: str) -> SubjectRef | None:
    """Work out the reference from whatever payload was supplied.

    The bundle branch went to archive/model-scanner with the resolver that
    fed it. Rejected: keeping it against a duck-typed object, which would
    leave a code path nothing in the tree can reach or test.
    """
    if report is not None:
        return SubjectRef(
            kind=SubjectKind.ARTIFACT,
            id=Path(report.path).name,
            digest=f"sha256:{report.sha256}",
            source=report.path,
        )
    if agent is not None:
        return SubjectRef(
            kind=SubjectKind.AGENT,
            id=agent.name,
            digest=agent.digest,
            source=agent.source,
            version=agent.version,
        )
    if subject:
        return SubjectRef(kind=SubjectKind.SYSTEM, id=subject, digest=subject if ":" in subject else "")
    return None


def _infer_relations(agent: Any) -> list[dict[str, str]]:
    if agent is None:
        return []
    return [edge.to_dict() for edge in agent.relations()]


def for_artifact(report: ArtifactReport, **kwargs: Any) -> SubjectClaims:
    return SubjectClaims(report, **kwargs)


def for_agent(agent: Any, **kwargs: Any) -> SubjectClaims:
    """Claims about an agent. Routes are passed in, never computed here.

    Rejected: computing them by importing the conformance path engine, which
    is what this did. That made the subject layer depend on a rule package.
    DEF-81 still holds - `paths_searched` follows from whether the caller
    passed `attack_paths` at all, so "found none" stays distinct from
    "nobody looked", which is `Unevaluable` rather than False.
    """
    return SubjectClaims(agent=agent, **kwargs)


def for_system(name: str, **kwargs: Any) -> SubjectClaims:
    return SubjectClaims(ref=SubjectRef(SubjectKind.SYSTEM, name), **kwargs)


def for_source(uri: str, revision: str = "", connector: str = "", **kwargs: Any) -> SubjectClaims:
    provenance = {"uri": uri, "revision": revision, "connector": connector}
    return SubjectClaims(
        ref=SubjectRef(SubjectKind.SOURCE, uri, source=uri, version=revision),
        provenance={key: value for key, value in provenance.items() if value},
        **kwargs,
    )


