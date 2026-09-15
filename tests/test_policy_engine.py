"""Policy-as-code: the decision, the proof, and the ways both can lie.

Design notes D-111 to D-114. A policy engine is a small amount of code with a
large amount of responsibility, because whatever it returns is what a pipeline
does. Everything here is written against one question: could a reader who was
not present re-derive this decision from what the document says?

The failure modes being defended against, in order of how quietly they fail:

1. A condition that cannot be evaluated returning False. `deny: when a
   signature is untrusted` over a run with no attestation would pass.
2. An exception with no expiry. A permanent policy change written where the
   temporary ones go.
3. A misspelt predicate matching nothing. A rule that looks present in the
   file and is absent in effect.
4. Short-circuiting. A proof whose contents depend on rule order.
"""
from __future__ import annotations

import pickle
from datetime import date

import pytest

from actaira.coverage import CoverageState, Surface
from actaira.policy import Decision, Effect, decide, load_policy_text
from actaira.policy.engine import Claims, PolicyError
from support.reports import write_flagged_report, write_report, write_unread_report

TODAY = date(2026, 9, 11)


@pytest.fixture
def clean_report(tmp_path):
    return write_report(tmp_path / "clean.pkl", payload=pickle.dumps({"w": [1.0, 2.0]}),
                        detected_format="pickle")


@pytest.fixture
def gadget_report(tmp_path):
    return write_flagged_report(tmp_path / "gadget.pkl", "ACT-PKL-001")


MINIMAL = """
policy: minimal
version: 1
rules:
  - id: no-high
    effect: deny
    when:
      finding_severity_at_least: high
"""


# --------------------------------------------------------------------------
# The decision
# --------------------------------------------------------------------------


def test_a_clean_artifact_is_allowed_and_a_gadget_is_denied(clean_report, gadget_report):
    policy = load_policy_text(MINIMAL)

    allowed = decide(policy, [Claims(clean_report)], on=TODAY)
    denied = decide(policy, [Claims(gadget_report)], on=TODAY)

    assert allowed.decision is Decision.ALLOW
    assert denied.decision is Decision.DENY


def test_one_denied_subject_denies_the_whole_run(clean_report, gadget_report):
    """A release contains every artifact in it. A decision that allowed the
    set because most of it was fine would be a decision about the average."""
    policy = load_policy_text(MINIMAL)

    result = decide(policy, [Claims(clean_report), Claims(gadget_report)], on=TODAY)

    assert result.decision is Decision.DENY


def test_deny_beats_review_beats_allow_whatever_order_the_rules_are_in(clean_report, gadget_report):
    forward = load_policy_text(
        """
policy: ordering
version: 1
rules:
  - id: review-unknown
    effect: review
    when:
      detected_format: unknown
  - id: no-high
    effect: deny
    when:
      finding_severity_at_least: high
"""
    )
    backward = load_policy_text(
        """
policy: ordering
version: 1
rules:
  - id: no-high
    effect: deny
    when:
      finding_severity_at_least: high
  - id: review-unknown
    effect: review
    when:
      detected_format: unknown
"""
    )

    first = decide(forward, [Claims(gadget_report)], on=TODAY)
    second = decide(backward, [Claims(gadget_report)], on=TODAY)

    assert first.decision is second.decision is Decision.DENY


def test_a_requirement_that_is_not_met_denies(tmp_path):
    """The asymmetry between `require` and `deny`, and the easiest thing in
    this file to get backwards. A `require` rule that does NOT match is the
    failure; a `deny` rule that does not match is fine."""
    report = write_unread_report(tmp_path / "mystery.pkl", detected_format="pickle")
    assert report.coverage.state(Surface.LOAD_TIME_EXECUTION) is CoverageState.FAILED

    policy = load_policy_text(
        """
policy: needs-coverage
version: 1
rules:
  - id: execution-surface-complete
    effect: require
    when:
      coverage:
        surface: load_time_execution
        at_least: complete
"""
    )

    result = decide(policy, [Claims(report)], on=TODAY)

    assert result.decision is Decision.DENY
    outcome = result.outcomes[0]
    assert outcome.matched is False
    assert outcome.evidence["coverage"]["actual"] == "failed"


def test_a_not_assessed_surface_never_satisfies_a_requirement(clean_report):
    """The coverage model's promise, enforced where it costs something. A
    policy that demanded raw tensor content would be asking a static scanner
    for something it never claimed, and must not be told it got it."""
    policy = load_policy_text(
        """
policy: impossible
version: 1
rules:
  - id: weights-were-examined
    effect: require
    when:
      coverage:
        surface: raw_tensor_content
        at_least: complete
"""
    )

    result = decide(policy, [Claims(clean_report)], on=TODAY)

    assert result.decision is Decision.DENY
    assert result.outcomes[0].evidence["coverage"]["actual"] == "not_assessed"


# --------------------------------------------------------------------------
# What cannot be evaluated
# --------------------------------------------------------------------------


def test_a_condition_with_no_information_is_review_not_false(clean_report):
    """The failure mode that fails silently.

    `deny: when the signer is untrusted` over a run with no attestation would
    pass if an unevaluable predicate returned False, and the pipeline would
    read that pass as a decision. It is not one: nothing was checked.
    """
    policy = load_policy_text(
        """
policy: needs-a-signature
version: 1
rules:
  - id: trusted-signer
    effect: require
    when:
      signer_trusted: true
"""
    )

    result = decide(policy, [Claims(clean_report)], on=TODAY)

    assert result.decision is Decision.REVIEW
    outcome = result.outcomes[0]
    assert outcome.effect is Effect.REVIEW
    assert "unevaluable" in outcome.evidence["signer_trusted"]
    assert "attestation" in outcome.evidence["signer_trusted"]["unevaluable"]


def test_a_verified_signature_is_not_a_trusted_signer(clean_report):
    """The oldest mistake in supply-chain tooling, refused explicitly.

    A signature that verifies says the bytes were not altered. Whether the key
    belongs to anyone this environment accepts is a separate question, and a
    run that answered the first and not the second must not satisfy a rule
    that asked for both.
    """
    policy = load_policy_text(
        """
policy: two-questions
version: 1
rules:
  - id: signed-and-trusted
    effect: require
    when:
      signature_verified: true
      signer_trusted: true
"""
    )

    verified_only = decide(
        policy, [Claims(clean_report, attestation={"signature_verified": True})], on=TODAY
    )
    both = decide(
        policy,
        [Claims(clean_report, attestation={"signature_verified": True, "signer_trusted": True})],
        on=TODAY,
    )

    assert verified_only.decision is Decision.REVIEW
    assert both.decision is Decision.ALLOW


def test_evidence_older_than_the_limit_fails_the_requirement(clean_report):
    policy = load_policy_text(
        """
policy: freshness
version: 1
rules:
  - id: fresh-evidence
    effect: require
    when:
      evidence_max_age_days: 30
"""
    )

    fresh = decide(policy, [Claims(clean_report, evidence_observed_on=date(2026, 9, 1))], on=TODAY)
    stale = decide(policy, [Claims(clean_report, evidence_observed_on=date(2026, 1, 1))], on=TODAY)

    assert fresh.decision is Decision.ALLOW
    assert stale.decision is Decision.DENY
    assert stale.outcomes[0].evidence["evidence_max_age_days"]["age_days"] > 30


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


WITH_WAIVER = """
policy: waived
version: 1
rules:
  - id: no-high
    effect: deny
    when:
      finding_severity_at_least: high
exceptions:
  - rule: no-high
    owner: marcos@example.com
    reason: known legacy artifact, replacement scheduled
    ticket: SEC-1201
    expires: 2026-10-01
"""


def test_a_live_exception_allows_and_records_who_granted_it(gadget_report):
    policy = load_policy_text(WITH_WAIVER)

    result = decide(policy, [Claims(gadget_report)], on=TODAY)

    assert result.decision is Decision.ALLOW
    waiver = result.outcomes[0].waived_by
    assert waiver is not None
    assert waiver["owner"] == "marcos@example.com"
    assert waiver["days_remaining"] == 20
    assert result.outcomes[0].matched is True, "the rule still fired; it was waived, not disproved"


def test_an_expired_exception_stops_allowing_and_says_so(gadget_report):
    """The entire risk of a waiver is that it outlives its reason. The run
    that stops honouring one has to announce it, or the change looks like the
    artifact got worse."""
    policy = load_policy_text(WITH_WAIVER)

    result = decide(policy, [Claims(gadget_report)], on=date(2026, 10, 2))

    assert result.decision is Decision.DENY
    assert result.expired_exceptions
    assert result.expired_exceptions[0]["rule"] == "no-high"
    assert result.outcomes[0].waived_by is None


def test_a_waiver_also_covers_a_requirement_that_was_not_met(tmp_path):
    """The path the first implementation missed.

    `contributes` checked the waiver only on the `matched` branch, so every
    exception granted against a `require` rule was ignored while every
    exception against a `deny` rule worked. A requirement that is NOT met is
    exactly the case an exception exists to cover.
    """
    report = write_unread_report(tmp_path / "mystery.pkl", detected_format="pickle")

    policy = load_policy_text(
        """
policy: waived-requirement
version: 1
rules:
  - id: execution-surface-complete
    effect: require
    when:
      coverage:
        surface: load_time_execution
        at_least: complete
exceptions:
  - rule: execution-surface-complete
    owner: marcos@example.com
    reason: this format is being added next release
    expires: 2026-10-01
"""
    )

    result = decide(policy, [Claims(report)], on=TODAY)

    assert result.decision is Decision.ALLOW
    assert result.outcomes[0].waived_by is not None


def test_a_waiver_scoped_to_one_digest_does_not_cover_another(clean_report, gadget_report):
    policy = load_policy_text(
        f"""
policy: scoped
version: 1
rules:
  - id: no-high
    effect: deny
    when:
      finding_severity_at_least: high
exceptions:
  - rule: no-high
    subject: sha256:{clean_report.sha256}
    owner: marcos@example.com
    reason: not this one
    expires: 2026-10-01
"""
    )

    result = decide(policy, [Claims(gadget_report)], on=TODAY)

    assert result.decision is Decision.DENY, "the waiver names a different artifact"


@pytest.mark.parametrize("missing", ["owner", "reason", "expires"])
def test_an_exception_without_an_owner_a_reason_or_an_expiry_does_not_load(missing):
    """Refused at load, not honoured-and-warned. An exception missing any of
    these is a permanent policy change written in the place reserved for
    temporary ones, and the document should not load at all rather than load
    with the waiver silently dropped."""
    fields = {
        "owner": "marcos@example.com",
        "reason": "because",
        "expires": "2026-10-01",
    }
    fields.pop(missing)
    body = "\n".join(f"    {key}: {value}" for key, value in fields.items())

    with pytest.raises(PolicyError) as caught:
        load_policy_text(
            f"""
policy: broken
version: 1
rules:
  - id: no-high
    effect: deny
    when:
      finding_severity_at_least: high
exceptions:
  - rule: no-high
{body}
"""
        )

    assert missing in str(caught.value)


# --------------------------------------------------------------------------
# The document itself
# --------------------------------------------------------------------------


def test_a_misspelt_condition_is_refused_rather_than_never_matching():
    """A rule that looks present in the file and is absent in effect is the
    worst failure mode a policy language has, because the file reads as
    though the protection is there."""
    with pytest.raises(PolicyError) as caught:
        load_policy_text(
            """
policy: typo
version: 1
rules:
  - id: no-high
    effect: deny
    when:
      finding_severity_atleast: high
"""
        )

    assert "finding_severity_atleast" in str(caught.value)
    assert "finding_severity_at_least" in str(caught.value), "the error names the real one"


def test_two_rules_with_one_id_are_refused():
    """It makes an exception ambiguous: waiving the id would waive whichever
    of them the loop reached last."""
    with pytest.raises(PolicyError):
        load_policy_text(
            """
policy: duplicate
version: 1
rules:
  - id: same
    effect: deny
    when:
      finding_severity_at_least: high
  - id: same
    effect: review
    when:
      detected_format: unknown
"""
        )


def test_an_exception_for_a_rule_that_does_not_exist_is_refused():
    with pytest.raises(PolicyError):
        load_policy_text(
            """
policy: orphan
version: 1
rules:
  - id: no-high
    effect: deny
    when:
      finding_severity_at_least: high
exceptions:
  - rule: a-rule-that-was-renamed
    owner: marcos@example.com
    reason: stale
    expires: 2026-10-01
"""
        )


def test_the_digest_changes_when_any_rule_changes():
    """The digest is what makes "which rules applied" answerable later. If an
    edit did not move it, two different policies would cite the same one."""
    first = load_policy_text(MINIMAL)
    second = load_policy_text(MINIMAL.replace("high", "medium"))

    assert first.digest != second.digest
    assert load_policy_text(MINIMAL).digest == first.digest, "and it is stable across loads"


def test_the_decision_carries_everything_needed_to_re_derive_it(clean_report):
    policy = load_policy_text(MINIMAL)

    document = decide(policy, [Claims(clean_report)], on=TODAY).to_dict()

    assert document["policy"]["digest"] == policy.digest
    assert document["policy"]["version"] == 1
    assert document["decided_on"] == "2026-09-11"
    assert document["subjects"] == [f"sha256:{clean_report.sha256}"]
    assert document["proof"], "a decision with no proof is an assertion"
    assert "schema_version" in document


def test_every_rule_is_evaluated_against_every_subject_even_after_a_denial(clean_report, gadget_report):
    """No short-circuiting. A proof whose contents depend on rule order would
    make two runs over the same artifacts incomparable."""
    policy = load_policy_text(
        """
policy: complete-proof
version: 1
rules:
  - id: no-high
    effect: deny
    when:
      finding_severity_at_least: high
  - id: known-format
    effect: require
    when:
      detected_format:
        - pickle
        - safetensors
"""
    )

    result = decide(policy, [Claims(clean_report), Claims(gadget_report)], on=TODAY)

    assert len(result.outcomes) == 4, "two rules times two subjects, every one recorded"
    assert result.decision is Decision.DENY


def test_a_decision_needs_at_least_one_subject():
    """DEF-92. `decide` over an empty list evaluated against a reference-less
    subject, so the proof carried outcomes naming `"subject": ""` beside a
    `"subjects": []` list. A document that contradicts itself is worse than an
    error, because it looks like a decision."""
    import pytest

    from actaira.policy import load_policy_text
    from actaira.policy.engine import PolicyError, decide

    policy = load_policy_text("""
policy: p
version: 1
rules:
  - id: r
    effect: deny
    when:
      finding_severity_at_least: critical
""")

    with pytest.raises(PolicyError, match="at least one subject"):
        decide(policy, [], on=date(2026, 9, 11))
