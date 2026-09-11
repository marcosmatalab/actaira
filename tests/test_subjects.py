"""One policy language over artifacts, bundles, agents, systems and sources.

Design notes D-211 to D-213. Two properties are asserted over and over here
because they are the ones that make the language worth having.

A predicate with no information raises `Unevaluable`, which becomes REVIEW.
Never False. A policy that requires a complete weight identity and is handed
an agent has not found a compliant agent; it has asked a question with no
answer, and the difference between those two is the whole design.

And nothing merges. A bundle's findings and an agent's findings are reachable
through different predicates, because a proof that could not say which subject
a rule fired on is not a proof anybody can act on.
"""
from __future__ import annotations

import json
import pickle
from datetime import date

import pytest

from actaira import subject as subject_mod
from actaira.agentgov import load_text as load_agent
from actaira.bundle import resolve
from actaira.inspect import inspect_artifact
from actaira.policy import decide, load_policy_text
from actaira.policy.engine import Claims, PolicyError, Unevaluable
from actaira.policy.model import Decision
from actaira.subject import SubjectClaims, SubjectKind, SubjectRef

ON = date(2026, 9, 11)


AGENT_TEXT = """
agent: demo
version: "3"
model: anthropic/claude-sonnet-4-5
model_digest: sha256:1111
prompt_sha256: 2222
tools:
  - name: read_web
    effects:
      - read
      - untrusted_input
    identity: reader
  - name: pay_invoice
    effects:
      - pay
    identity: payer
identities:
  - name: reader
  - name: payer
"""


@pytest.fixture
def agent():
    return load_agent(AGENT_TEXT)


@pytest.fixture
def bundle(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "config.json").write_text(
        json.dumps({"architectures": ["X"], "auto_map": {"AutoModel": "modeling.X"}}), encoding="utf-8"
    )
    (root / "modeling.py").write_text("import os\n", encoding="utf-8")
    (root / "model.safetensors").write_text("{}", encoding="utf-8")
    return resolve(root)


@pytest.fixture
def report(tmp_path):
    path = tmp_path / "clean.pkl"
    path.write_bytes(pickle.dumps({"w": [1.0]}))
    return inspect_artifact(path)


def run(policy_text: str, subjects: list, on: date = ON):
    return decide(load_policy_text(policy_text), subjects, on=on)


# --------------------------------------------------------------------------
# The reference
# --------------------------------------------------------------------------


def test_a_reference_is_inferred_from_whichever_payload_was_given(report, bundle, agent):
    assert subject_mod.for_artifact(report).ref.kind is SubjectKind.ARTIFACT
    assert subject_mod.for_bundle(bundle).ref.kind is SubjectKind.BUNDLE
    assert subject_mod.for_agent(agent).ref.kind is SubjectKind.AGENT
    assert subject_mod.for_system("fraud-review").ref.kind is SubjectKind.SYSTEM
    assert subject_mod.for_source("hf://a/b").ref.kind is SubjectKind.SOURCE


def test_a_handle_names_the_kind_and_the_id(agent):
    assert subject_mod.for_agent(agent).ref.handle == "agent:demo"


def test_a_bundle_reference_carries_the_content_digest_when_there_is_one(bundle):
    """Small repository, every member hashed: the reference names the weights."""
    ref = subject_mod.for_bundle(bundle).ref

    assert bundle.content_identity()["state"] == "complete"
    assert ref.digest == bundle.content_identity()["digest"]


def test_a_bundle_reference_falls_back_to_the_layout_digest_and_says_so(tmp_path, monkeypatch):
    """D-200, one layer up. When nothing identified the weights the reference
    carries the layout digest, and `bundle_content_identity` is the predicate
    a policy asks before treating that as the identity of a model."""
    import actaira.bundle as bundle_module

    monkeypatch.setattr(bundle_module, "MAX_DIGEST_BYTES", 4)
    root = tmp_path / "big"
    root.mkdir()
    (root / "config.json").write_text(json.dumps({"architectures": ["X"]}), encoding="utf-8")
    (root / "model.safetensors").write_bytes(b"\x00" * 512)
    unhashed = resolve(root)

    ref = subject_mod.for_bundle(unhashed).ref

    assert unhashed.content_identity()["state"] == "unavailable"
    assert ref.digest == unhashed.structural_digest


def test_the_2_1_constructor_still_builds_the_same_claims(report):
    """Every policy and every caller written against 2.1 keeps working."""
    old = Claims(report, subject="sha256:abc", facts={"a": 1})

    assert isinstance(old, SubjectClaims)
    assert old.subject == "sha256:abc"
    assert old.facts == {"a": 1}
    assert old.report is report


def test_findings_are_never_merged_across_kinds(bundle, agent, report):
    claims = SubjectClaims(report, bundle=bundle, agent=agent)

    artifact_rules = {finding.rule_id for finding in claims.findings_of(SubjectKind.ARTIFACT)}
    bundle_rules = {finding.rule_id for finding in claims.findings_of(SubjectKind.BUNDLE)}
    agent_rules = {finding.rule_id for finding in claims.findings_of(SubjectKind.AGENT)}

    assert "ACT-BDL-002" in bundle_rules
    assert "ACT-BDL-002" not in agent_rules and "ACT-BDL-002" not in artifact_rules
    assert any(rule.startswith("ACT-AGT") for rule in agent_rules)


def test_coverage_comes_from_the_payload_that_read_bytes(report, bundle, agent):
    assert subject_mod.for_artifact(report).coverage is report.coverage
    assert subject_mod.for_bundle(bundle).coverage is bundle.coverage
    assert subject_mod.for_agent(agent).coverage is None, (
        "a declaration has no surfaces, so asking about coverage has no answer rather than a bad one"
    )


# --------------------------------------------------------------------------
# subject_kind
# --------------------------------------------------------------------------


KIND_POLICY = """
policy: kinds
version: 1
rules:
  - id: agents-must-not-pay
    effect: deny
    when:
      subject_kind: agent
      agent_effect: pay
"""


def test_a_rule_gated_on_kind_fires_on_that_kind(agent):
    assert run(KIND_POLICY, [subject_mod.for_agent(agent)]).decision is Decision.DENY


def test_the_same_rule_is_simply_not_matched_by_another_kind(report):
    """Not REVIEW: `subject_kind` is evaluable on any subject with a
    reference, and it answered no. The rule did not apply, which is different
    from the rule being unable to decide."""
    decision = run(KIND_POLICY, [subject_mod.for_artifact(report)])

    assert decision.decision is Decision.ALLOW


def test_a_kind_guard_stops_the_rest_of_the_rule_from_running(report):
    """Design note D-212a, and a bug that would have made every multi-kind
    policy permanently inconclusive.

    Predicates run in sorted order, so `bundle_content_identity` runs before
    `subject_kind`. Without the guard short-circuiting, a bundle rule handed
    an artifact would evaluate the bundle predicate first, raise
    `Unevaluable`, and send the decision to REVIEW because a rule correctly
    did not apply.
    """
    decision = run("""
policy: guarded
version: 1
rules:
  - id: bundles-only
    effect: require
    when:
      subject_kind: bundle
      bundle_content_identity: complete
""", [subject_mod.for_artifact(report)])

    assert decision.decision is Decision.ALLOW
    outcome = decision.outcomes[0]
    assert outcome.applicable is False
    assert "bundle_content_identity" not in outcome.evidence


def test_a_requirement_that_does_not_apply_is_not_a_denial(report):
    """The asymmetry a single `matched` boolean would have got wrong: a
    requirement that was not met denies, and one that is not about this kind
    of subject is nothing at all."""
    decision = run("""
policy: guarded
version: 1
rules:
  - id: agents-declare-an-owner
    effect: require
    when:
      subject_kind: agent
      relation_exists:
        relation: runs_as
""", [subject_mod.for_artifact(report)])

    assert decision.decision is Decision.ALLOW


def test_an_unknown_kind_is_refused_when_the_document_loads():
    """Defect DEF-83. A misspelt predicate NAME was a clean load error and a
    misspelt predicate VALUE was a traceback at evaluation time, exiting 1 -
    which is EXIT_FAIL and therefore indistinguishable from a policy DENY.
    Both halves of "this rule is well formed" now fail in one place."""
    with pytest.raises(PolicyError) as problem:
        load_policy_text("""
policy: bad
version: 1
rules:
  - id: x
    effect: deny
    when:
      subject_kind: spaceship
""")

    assert "spaceship" in str(problem.value)
    assert "agent" in str(problem.value), "the message lists the kinds that exist"


@pytest.mark.parametrize(
    "condition",
    [
        "subject_kind: spaceship",
        "finding_severity_at_least: criticl",
        "attack_path_severity_at_least: severe",
        "bundle_content_identity: totally",
        "agent_effect: payy",
        "evidence_state: fine",
        "trust_state: maybe",
        "verdict_is: probably",
        "evidence_max_age_days: soon",
        "evidence_max_age_days: -3",
    ],
)
def test_every_closed_vocabulary_is_checked_at_load_time(condition):
    with pytest.raises(PolicyError):
        load_policy_text(
            f"policy: bad\nversion: 1\nrules:\n  - id: x\n    effect: deny\n    when:\n      {condition}\n"
        )


# --------------------------------------------------------------------------
# bundle predicates
# --------------------------------------------------------------------------


BUNDLE_POLICY = """
policy: bundles
version: 1
rules:
  - id: no-executable-code
    effect: deny
    when:
      subject_kind: bundle
      bundle_finding: ACT-BDL-002
  - id: weights-must-be-identified
    effect: require
    when:
      subject_kind: bundle
      bundle_content_identity:
        - complete
        - externally_bound
"""


def test_a_bundle_finding_can_deny(bundle):
    decision = run(BUNDLE_POLICY, [subject_mod.for_bundle(bundle)])

    assert decision.decision is Decision.DENY
    outcome = next(item for item in decision.outcomes if item.rule_id == "no-executable-code")
    assert outcome.evidence["bundle_finding"]["present"] == ["ACT-BDL-002"]


def test_an_unhashed_bundle_fails_the_identity_requirement(tmp_path, monkeypatch):
    import actaira.bundle as bundle_module

    monkeypatch.setattr(bundle_module, "MAX_DIGEST_BYTES", 4)
    root = tmp_path / "repo"
    root.mkdir()
    (root / "config.json").write_text(json.dumps({"architectures": ["X"]}), encoding="utf-8")
    (root / "model.safetensors").write_bytes(b"\x00" * 512)

    decision = run(BUNDLE_POLICY, [subject_mod.for_bundle(resolve(root))])

    assert decision.decision is Decision.DENY
    outcome = next(item for item in decision.outcomes if item.rule_id == "weights-must-be-identified")
    assert outcome.matched is False
    assert outcome.evidence["bundle_content_identity"]["state"] == "unavailable"


def test_hashing_the_weights_satisfies_it(tmp_path, monkeypatch):
    import actaira.bundle as bundle_module

    monkeypatch.setattr(bundle_module, "MAX_DIGEST_BYTES", 4)
    root = tmp_path / "repo"
    root.mkdir()
    (root / "config.json").write_text(json.dumps({"architectures": ["X"]}), encoding="utf-8")
    (root / "model.safetensors").write_bytes(b"\x00" * 512)

    claims = subject_mod.for_bundle(resolve(root, hash_weights=True))
    outcome = next(
        item
        for item in run(BUNDLE_POLICY, [claims]).outcomes
        if item.rule_id == "weights-must-be-identified"
    )

    assert outcome.matched is True


def test_a_bundle_predicate_on_an_agent_is_unevaluable_not_false(agent):
    """The property this whole layer rests on.

    A policy that requires a complete weight identity and is handed an agent
    has not found a compliant agent. It has asked a question with no answer,
    and returning False there would make a `require` rule silently fail and a
    `deny` rule silently pass.
    """
    decision = run("""
policy: mixed
version: 1
rules:
  - id: weights
    effect: require
    when:
      bundle_content_identity: complete
""", [subject_mod.for_agent(agent)])

    assert decision.decision is Decision.REVIEW
    outcome = decision.outcomes[0]
    assert "no bundle resolution" in outcome.evidence["bundle_content_identity"]["unevaluable"]


# --------------------------------------------------------------------------
# agent predicates
# --------------------------------------------------------------------------


def test_an_agent_effect_can_send_a_decision_to_review(agent):
    decision = run("""
policy: agents
version: 1
rules:
  - id: paying-agents-get-a-look
    effect: review
    when:
      agent_effect:
        - pay
        - exec
""", [subject_mod.for_agent(agent)])

    assert decision.decision is Decision.REVIEW
    outcome = decision.outcomes[0]
    assert outcome.evidence["agent_effect"]["present"] == ["pay"]
    assert outcome.evidence["agent_effect"]["tools"] == ["pay_invoice"]


def test_an_agent_finding_can_deny(agent):
    decision = run("""
policy: agents
version: 1
rules:
  - id: no-injection-to-action
    effect: deny
    when:
      agent_finding: ACT-AGT-001
""", [subject_mod.for_agent(agent)])

    assert decision.decision is Decision.DENY


def test_an_open_attack_path_can_deny_and_a_closed_one_cannot():
    """Closed routes must not deny. A policy that denied on a mitigation
    working is how a team learns to remove the mitigation."""
    open_agent = load_agent("""
agent: open
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: read_web
    effects:
      - read
      - untrusted_input
  - name: send_mail
    effects:
      - send
""")
    closed_agent = load_agent("""
agent: closed
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: read_web
    effects:
      - read
      - untrusted_input
  - name: send_mail
    effects:
      - send
    requires_approval: true
""")
    policy = """
policy: paths
version: 1
rules:
  - id: no-open-high-routes
    effect: deny
    when:
      attack_path_severity_at_least: high
"""

    assert run(policy, [subject_mod.for_agent(open_agent)]).decision is Decision.DENY
    assert run(policy, [subject_mod.for_agent(closed_agent)]).decision is Decision.ALLOW


# --------------------------------------------------------------------------
# relation_exists
# --------------------------------------------------------------------------


def test_a_required_relation_is_satisfied_by_a_declared_edge(agent):
    decision = run("""
policy: relations
version: 1
rules:
  - id: secret-tools-name-an-identity
    effect: require
    when:
      relation_exists:
        from: tool:pay_invoice
        relation: runs_as
""", [subject_mod.for_agent(agent)])

    assert decision.decision is Decision.ALLOW


def test_a_missing_relation_fails_the_requirement(agent):
    decision = run("""
policy: relations
version: 1
rules:
  - id: tools-read-declared-sources
    effect: require
    when:
      relation_exists:
        from: tool:read_web
        relation: reads
""", [subject_mod.for_agent(agent)])

    assert decision.decision is Decision.DENY


def test_a_subject_with_no_relations_at_all_is_unevaluable(report):
    decision = run("""
policy: relations
version: 1
rules:
  - id: any
    effect: require
    when:
      relation_exists:
        relation: runs_as
""", [subject_mod.for_artifact(report)])

    assert decision.decision is Decision.REVIEW


def test_an_unknown_key_in_a_relation_pattern_is_refused_at_load_time():
    with pytest.raises(PolicyError) as problem:
        load_policy_text("""
policy: relations
version: 1
rules:
  - id: any
    effect: require
    when:
      relation_exists:
        source: tool:x
""")

    assert "source" in str(problem.value)


# --------------------------------------------------------------------------
# evidence_state, source_revision_pinned, trust_state
# --------------------------------------------------------------------------


EVIDENCE_POLICY = """
policy: evidence
version: 1
rules:
  - id: evidence-must-be-valid
    effect: require
    when:
      evidence_state: valid
"""


def test_every_record_has_to_be_accepted_not_merely_one():
    """Universally quantified on purpose: one valid record among five revoked
    ones is exactly the situation the rule exists to catch."""
    mixed = SubjectClaims(
        ref=SubjectRef(SubjectKind.SYSTEM, "s"),
        evidence=[{"evidence_id": "a", "state": "valid"}, {"evidence_id": "b", "state": "revoked"}],
    )

    decision = run(EVIDENCE_POLICY, [mixed])

    assert decision.decision is Decision.DENY
    assert decision.outcomes[0].evidence["evidence_state"]["not_accepted"] == ["revoked"]


def test_all_valid_satisfies_it():
    claims = SubjectClaims(
        ref=SubjectRef(SubjectKind.SYSTEM, "s"),
        evidence=[{"evidence_id": "a", "state": "valid"}, {"evidence_id": "b", "state": "valid"}],
    )

    assert run(EVIDENCE_POLICY, [claims]).decision is Decision.ALLOW


def test_no_evidence_at_all_is_unevaluable():
    claims = SubjectClaims(ref=SubjectRef(SubjectKind.SYSTEM, "s"))

    assert run(EVIDENCE_POLICY, [claims]).decision is Decision.REVIEW


@pytest.mark.parametrize(
    "revision,pinned",
    [
        ("7f91a2c", True),
        ("sha256:" + "a" * 64, True),
        ("main", False),
        ("v2.1.0", False),
        ("", False),
    ],
)
def test_a_revision_is_pinned_only_when_it_names_bytes(revision, pinned):
    claims = subject_mod.for_source("hf://acme/fraud", revision, "huggingface")
    policy = """
policy: sources
version: 1
rules:
  - id: pin-the-revision
    effect: require
    when:
      source_revision_pinned: true
"""

    decision = run(policy, [claims])

    assert (decision.decision is Decision.ALLOW) is pinned


def test_trust_state_is_separate_from_a_signature_verifying():
    """A signature verifying is a fact about bytes. Whether this environment
    accepts the signer is a local decision, and merging them is the oldest
    mistake in supply-chain tooling."""
    claims = SubjectClaims(
        ref=SubjectRef(SubjectKind.SYSTEM, "s"),
        attestation={"signature_verified": True},
        trust={"state": "untrusted", "reasons": ["no trusted signer matched"]},
    )

    decision = run("""
policy: trust
version: 1
rules:
  - id: must-be-trusted
    effect: require
    when:
      trust_state: trusted
""", [claims])

    assert decision.decision is Decision.DENY
    assert decision.outcomes[0].evidence["trust_state"]["state"] == "untrusted"


def test_no_trust_policy_applied_is_unknown_rather_than_untrusted():
    """The spec's rule, and the honest one: absence of a trust policy must
    not be read as a refusal to trust."""
    claims = SubjectClaims(ref=SubjectRef(SubjectKind.SYSTEM, "s"), attestation={"signature_verified": True})

    decision = run("""
policy: trust
version: 1
rules:
  - id: must-be-trusted
    effect: require
    when:
      trust_state: trusted
""", [claims])

    assert decision.decision is Decision.REVIEW


# --------------------------------------------------------------------------
# freshness over evidence records
# --------------------------------------------------------------------------


def test_freshness_reads_the_oldest_attached_record():
    """A decision resting on six records is only as fresh as the one taken
    longest ago. Picking the newest would let re-observing one part make a
    stale whole look current."""
    claims = SubjectClaims(
        ref=SubjectRef(SubjectKind.SYSTEM, "s"),
        evidence=[
            {"evidence_id": "a", "state": "valid", "observed_at": "2026-09-10T00:00:00+00:00"},
            {"evidence_id": "b", "state": "valid", "observed_at": "2026-01-01T00:00:00+00:00"},
        ],
    )

    decision = run("""
policy: freshness
version: 1
rules:
  - id: recent
    effect: require
    when:
      evidence_max_age_days: 30
""", [claims])

    assert decision.decision is Decision.DENY
    detail = decision.outcomes[0].evidence["evidence_max_age_days"]
    assert detail["observed_on"] == "2026-01-01"
    assert "oldest" in detail["from"]


def test_an_explicit_observation_date_still_wins():
    claims = SubjectClaims(
        ref=SubjectRef(SubjectKind.SYSTEM, "s"),
        evidence_observed_on=date(2026, 9, 10),
        evidence=[{"evidence_id": "b", "state": "valid", "observed_at": "2020-01-01T00:00:00+00:00"}],
    )

    decision = run("""
policy: freshness
version: 1
rules:
  - id: recent
    effect: require
    when:
      evidence_max_age_days: 30
""", [claims])

    assert decision.decision is Decision.ALLOW


# --------------------------------------------------------------------------
# One policy, several kinds, one proof
# --------------------------------------------------------------------------


def test_one_policy_decides_over_an_artifact_a_bundle_and_an_agent(report, bundle, agent):
    """The thing 2.1 could not do at all."""
    decision = run("""
policy: everything
version: 1
rules:
  - id: no-critical-artifacts
    effect: deny
    when:
      subject_kind: artifact
      finding_severity_at_least: critical
  - id: no-remote-code
    effect: deny
    when:
      subject_kind: bundle
      bundle_finding: ACT-BDL-002
  - id: no-paying-agents
    effect: deny
    when:
      subject_kind: agent
      agent_effect: pay
""", [
        subject_mod.for_artifact(report),
        subject_mod.for_bundle(bundle),
        subject_mod.for_agent(agent),
    ])

    assert decision.decision is Decision.DENY
    denied = {outcome.rule_id for outcome in decision.reasons}
    assert denied == {"no-remote-code", "no-paying-agents"}
    # Three subjects, three distinct handles in the proof.
    assert len({outcome.subject for outcome in decision.outcomes}) == 3


def test_the_proof_says_which_subject_each_rule_fired_on(report, bundle, agent):
    decision = run("""
policy: everything
version: 1
rules:
  - id: no-remote-code
    effect: deny
    when:
      bundle_finding: ACT-BDL-002
""", [
        subject_mod.for_artifact(report),
        subject_mod.for_bundle(bundle),
        subject_mod.for_agent(agent),
    ])

    fired = [outcome for outcome in decision.outcomes if outcome.matched and outcome.effect.value == "deny"]

    assert len(fired) == 1
    assert fired[0].subject == subject_mod.for_bundle(bundle).subject


def test_unevaluable_is_an_exception_type_a_reader_can_find():
    assert issubclass(Unevaluable, Exception)



# --------------------------------------------------------------------------
# Absence is never falsehood, in the two places it nearly was
# --------------------------------------------------------------------------


def test_an_agent_whose_routes_were_never_searched_is_unevaluable(agent):
    """Defect DEF-81. `SubjectClaims(agent=...)` leaves `attack_paths` empty,
    and the guard read "an agent is attached" as "routes were searched". A
    deny rule on an open HIGH route came back ALLOW with `count: 0` beside an
    agent that had one."""
    open_agent = load_agent("""
agent: open
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: read_web
    effects:
      - read
      - untrusted_input
  - name: send_mail
    effects:
      - send
""")
    policy = """
policy: paths
version: 1
rules:
  - id: no-open-high-routes
    effect: deny
    when:
      attack_path_severity_at_least: high
"""

    assert run(policy, [SubjectClaims(agent=open_agent)]).decision is Decision.REVIEW
    assert run(policy, [subject_mod.for_agent(open_agent, with_paths=False)]).decision is Decision.REVIEW
    assert run(policy, [subject_mod.for_agent(open_agent)]).decision is Decision.DENY


def test_searched_and_found_nothing_is_not_unevaluable():
    """The other half. An agent with no untrusted input has no routes, and
    that is an answer rather than a gap."""
    quiet = load_agent("""
agent: quiet
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: read_config
    effects:
      - read
""")

    decision = run("""
policy: paths
version: 1
rules:
  - id: no-open-high-routes
    effect: deny
    when:
      attack_path_severity_at_least: high
""", [subject_mod.for_agent(quiet)])

    assert decision.decision is Decision.ALLOW


def test_a_declaration_that_states_no_relations_can_fail_a_requirement():
    """Defect DEF-82. An agent that loads cleanly and declares no `identity:`
    on anything is exactly what `relation_exists` exists to catch, and it came
    back REVIEW rather than DENY because empty meant "nobody gathered them"."""
    unbound = load_agent("""
agent: unbound
tools:
  - name: read_deploy_key
    effects:
      - secrets
  - name: post_http
    effects:
      - network
""")

    decision = run("""
policy: relations
version: 1
rules:
  - id: secret-tools-name-an-identity
    effect: require
    when:
      subject_kind: agent
      relation_exists:
        from: tool:read_deploy_key
        relation: runs_as
""", [subject_mod.for_agent(unbound)])

    assert decision.decision is Decision.DENY
    assert unbound.relations() == [], "the fixture really does declare none"


def test_a_bundle_reference_says_which_kind_of_digest_it_carries(tmp_path, monkeypatch):
    """Defect DEF-80. `claims.subject` is this digest and waivers match on it,
    so an unlabelled field meant turning on `--hash-weights` silently
    invalidated every subject-scoped waiver on a bundle."""
    import actaira.bundle as bundle_module

    monkeypatch.setattr(bundle_module, "MAX_DIGEST_BYTES", 4)
    root = tmp_path / "repo"
    root.mkdir()
    (root / "config.json").write_text(json.dumps({"architectures": ["X"]}), encoding="utf-8")
    (root / "model.safetensors").write_bytes(b"\x00" * 512)

    unhashed = subject_mod.for_bundle(resolve(root)).ref
    hashed = subject_mod.for_bundle(resolve(root, hash_weights=True)).ref

    assert unhashed.digest_kind == "structural"
    assert hashed.digest_kind == "content"
    assert unhashed.to_dict()["digest_kind"] == "structural"
