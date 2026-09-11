"""The assurance receipt: what it proves, and the four ways it could lie.

Design note D-120. This is the one output meant to leave the organisation that
produced it, read by someone with neither the artifacts nor this tool. Every
test here is a way that reader could be misled:

1. A document edited after signing that still verifies.
2. A verified signature read as a trusted signer.
3. A receipt that lists what it covered and omits what it did not.
4. A valid signature over a document about different files.
"""
from __future__ import annotations

import copy
import json
import pickle
from datetime import UTC, date, datetime

import pytest

from actaira import receipt
from actaira.attest import signing
from actaira.coverage import CoverageState, Surface
from actaira.inspect import inspect_artifact
from actaira.policy import decide, load_policy_text
from actaira.policy.engine import Claims

OBSERVED = datetime(2026, 9, 11, 10, 0, tzinfo=UTC)


@pytest.fixture
def keypair():
    return signing.generate()


@pytest.fixture
def clean_report(tmp_path):
    path = tmp_path / "clean.pkl"
    path.write_bytes(pickle.dumps({"w": [1.0, 2.0]}))
    return inspect_artifact(path)


@pytest.fixture
def gadget_report(tmp_path):
    from evals.corpus import build as corpus_build

    path = tmp_path / "gadget.pkl"
    path.write_bytes(corpus_build.craft_reduce("posix", "system", ("id",), 2))
    return inspect_artifact(path)


@pytest.fixture
def signed(clean_report, keypair):
    document = receipt.build([clean_report], observed_at=OBSERVED)
    return receipt.sign(document, keypair)


# --------------------------------------------------------------------------
# 1. Integrity
# --------------------------------------------------------------------------


def test_a_receipt_verifies_when_nothing_has_been_touched(signed, keypair):
    result = receipt.verify(signed)

    assert result.ok
    assert result.signature_verified
    assert result.key_fingerprint == keypair.fingerprint


@pytest.mark.parametrize(
    "path",
    [
        ("findings_by_severity", "critical"),
        ("subjects", 0, "verdict"),
        ("observed_at",),
        ("tool_version",),
    ],
)
def test_any_edit_after_signing_breaks_the_signature(signed, path):
    """Every field, not a sample of them. The signature covers the canonical
    JSON of the whole document, so a field nobody thought to protect would be
    a field an editor could change."""
    tampered = copy.deepcopy(signed)
    target = tampered
    for step in path[:-1]:
        target = target[step]
    current = target[path[-1]]
    target[path[-1]] = 999 if isinstance(current, int) else "edited"

    result = receipt.verify(tampered)

    assert not result.ok
    assert not result.signature_verified


def test_a_receipt_signed_by_one_key_does_not_verify_under_another(signed):
    """The obvious attack: keep the document, swap in your own public key.
    The digest still matches - nothing in the body changed - and only the
    signature check catches it."""
    other = signing.generate()
    forged = copy.deepcopy(signed)
    forged["signature"]["public_key_b64"] = other.public_b64
    forged["signature"]["fingerprint_sha256"] = other.fingerprint

    result = receipt.verify(forged)

    assert not result.ok
    assert not result.signature_verified


def test_a_fingerprint_that_is_not_the_key_s_own_is_caught(signed):
    """A block claiming a well-known fingerprint over an attacker's key would
    let a human reading the printout believe it came from someone else."""
    forged = copy.deepcopy(signed)
    forged["signature"]["fingerprint_sha256"] = "0" * 64

    result = receipt.verify(forged)

    assert not result.ok
    assert any("fingerprint" in problem for problem in result.problems)


def test_a_receipt_with_no_signature_block_is_not_a_receipt(clean_report):
    document = receipt.build([clean_report], observed_at=OBSERVED)

    result = receipt.verify(document)

    assert not result.ok
    assert not result.signature_verified


def test_a_schema_this_verifier_does_not_know_is_refused_not_best_effort(signed):
    """A future receipt may mean something different by a field this verifier
    thinks it understands. A partial check reported as a pass is worse than no
    check."""
    future = copy.deepcopy(signed)
    future["schema_version"] = "assurance-receipt/v99"

    result = receipt.verify(future)

    assert not result.ok
    assert "v99" in result.problems[0]


# --------------------------------------------------------------------------
# 2. Verified is not trusted
# --------------------------------------------------------------------------


def test_without_anchors_the_signer_is_neither_trusted_nor_untrusted(signed):
    """The third state, and the reason it exists. Collapsing "nobody vouched
    for this key" into False would make an unchecked receipt look rejected;
    collapsing it into True would make a self-signed one look endorsed."""
    result = receipt.verify(signed)

    assert result.signature_verified is True
    assert result.signer_trusted is None
    assert result.ok, "not having an opinion is not a failure"


def test_with_anchors_a_known_key_is_trusted_and_an_unknown_one_is_not(signed, keypair):
    trusted = receipt.verify(signed, trusted_fingerprints={keypair.fingerprint})
    stranger = receipt.verify(signed, trusted_fingerprints={"0" * 64})

    assert trusted.signer_trusted is True and trusted.ok
    assert stranger.signer_trusted is False and not stranger.ok
    assert stranger.signature_verified is True, "the bytes are intact; the signer is not accepted"


def test_the_supply_chain_block_keeps_the_two_questions_apart(clean_report):
    verified_only = receipt.build(
        [clean_report], observed_at=OBSERVED, attestation={"signature_verified": True}
    )
    both = receipt.build(
        [clean_report],
        observed_at=OBSERVED,
        attestation={"signature_verified": True, "signer_trusted": True},
    )
    neither = receipt.build([clean_report], observed_at=OBSERVED)

    assert verified_only["supply_chain"]["signature_verified"] is True
    assert verified_only["supply_chain"]["signer_trusted"] is None
    assert "note" in verified_only["supply_chain"], "the gap is stated, not left to inference"
    assert both["supply_chain"]["signer_trusted"] is True
    assert neither["supply_chain"]["attestation"] == "none"


# --------------------------------------------------------------------------
# 3. It states what it does not cover
# --------------------------------------------------------------------------


def test_the_surfaces_that_were_not_covered_are_listed_not_omitted(clean_report):
    """The most common way an assurance document misleads is by being read as
    exhaustive. A reader who sees only the covered surfaces assumes the rest
    were fine."""
    document = receipt.build([clean_report], observed_at=OBSERVED)

    surfaces = {row["surface"] for row in document["states_what_it_does_not_cover"]}

    assert Surface.BEHAVIORAL_SAFETY.value in surfaces
    assert Surface.RAW_TENSOR_CONTENT.value in surfaces
    assert Surface.ORGANIZATIONAL_FACTS.value in surfaces
    for row in document["states_what_it_does_not_cover"]:
        assert row["reason"], f"{row['surface']} is excluded with no stated reason"


def test_every_severity_appears_including_the_zeroes(clean_report):
    """"critical: 0" and an absent "critical" read differently, and the
    difference between "none found" and "not reported" is the whole point."""
    document = receipt.build([clean_report], observed_at=OBSERVED)

    assert set(document["findings_by_severity"]) == {"critical", "high", "medium", "low", "info"}


def test_the_coverage_of_a_set_is_the_weakest_coverage_in_it(clean_report, tmp_path):
    """One unreadable file must not hide behind nine clean ones. It is the
    unreadable one the reader needs to know about."""
    broken = tmp_path / "mystery.pkl"
    broken.write_bytes(b"\x11\x22\x33\x44 not a known format")
    broken_report = inspect_artifact(broken)

    merged = receipt.merge_coverage([clean_report, broken_report])

    assert clean_report.coverage.state(Surface.LOAD_TIME_EXECUTION) is CoverageState.COMPLETE
    assert merged.state(Surface.LOAD_TIME_EXECUTION) is CoverageState.FAILED


def test_no_percentage_grade_or_score_appears_anywhere_in_a_receipt(clean_report, gadget_report, keypair):
    """The refusal the whole product rests on, asserted over the actual bytes.

    A receipt is the document most likely to be asked for a single number, by
    the reader least able to check one. Anything named like a score is a
    defect here even if it would have been accurate.
    """
    policy = load_policy_text(
        """
policy: demo
version: 1
rules:
  - id: no-high
    effect: deny
    when:
      finding_severity_at_least: high
"""
    )
    decision = decide(policy, [Claims(gadget_report)], on=date(2026, 9, 11))
    document = receipt.sign(
        receipt.build(
            [clean_report, gadget_report],
            observed_at=OBSERVED,
            policy_decision=decision.to_dict(),
        ),
        keypair,
    )

    blob = json.dumps(document).lower()

    for forbidden in ("score", "grade", "rating", "percent", "compliance_level", "risk_score"):
        assert forbidden not in blob, f"a receipt must not carry a {forbidden}"


# --------------------------------------------------------------------------
# 4. A signature over a document about different files
# --------------------------------------------------------------------------


def test_a_valid_receipt_about_other_artifacts_is_reported_as_such(signed, gadget_report):
    """A valid signature over a document about different files is a valid
    signature about nothing. This is the check that closes the loop when the
    artifacts are to hand."""
    problems = receipt.subject_digests_match(signed, [gadget_report])

    assert problems
    assert any("not among the artifacts supplied" in problem for problem in problems)


def test_a_receipt_about_exactly_these_artifacts_reports_nothing(signed, clean_report):
    assert receipt.subject_digests_match(signed, [clean_report]) == []


def test_an_extra_artifact_the_receipt_never_mentions_is_reported(signed, clean_report, gadget_report):
    """The quieter direction. A receipt covering one of the two files you are
    about to deploy is not a receipt about your deployment."""
    problems = receipt.subject_digests_match(signed, [clean_report, gadget_report])

    assert any("does not mention it" in problem for problem in problems)


# --------------------------------------------------------------------------
# Reproducibility
# --------------------------------------------------------------------------


def test_the_same_run_produces_the_same_document(clean_report, keypair):
    """Everything variable is an argument. If two builds of the same inputs
    differed, the digest would be meaningless and so would the signature."""
    first = receipt.build([clean_report], observed_at=OBSERVED)
    second = receipt.build([clean_report], observed_at=OBSERVED)

    assert receipt.signing_subject(first) == receipt.signing_subject(second)
    assert receipt.sign(first, keypair)["signature"]["receipt_sha256"] == (
        receipt.sign(second, keypair)["signature"]["receipt_sha256"]
    )


def test_the_signing_subject_is_the_document_without_its_signature(signed):
    """The transformation a third party has to reimplement, asserted so it
    cannot drift into something undocumented."""
    from actaira.model import canonical_json

    without = {key: value for key, value in signed.items() if key != "signature"}

    assert receipt.signing_subject(signed) == canonical_json(without)


def test_a_policy_decision_travels_with_the_receipt(clean_report, gadget_report, keypair):
    policy = load_policy_text(
        """
policy: travelling
version: 7
rules:
  - id: no-high
    effect: deny
    when:
      finding_severity_at_least: high
"""
    )
    decision = decide(policy, [Claims(gadget_report)], on=date(2026, 9, 11))

    document = receipt.sign(
        receipt.build([gadget_report], observed_at=OBSERVED, policy_decision=decision.to_dict()),
        keypair,
    )
    result = receipt.verify(document)

    assert result.decision == "deny"
    assert document["policy_decision"]["policy"]["version"] == 7
    assert document["policy_decision"]["policy"]["digest"] == policy.digest
    assert document["policy_decision"]["proof"], "the decision travels with its reasons or not at all"


def test_a_receipt_names_the_artifact_and_not_the_directory_it_was_built_in(clean_report, keypair):
    """DEF-104. `report.path.rsplit("/", 1)[-1]` is a basename only on POSIX.

    Six documents were built with that spelling - the ML-BOM component name,
    these receipt rows, the governance dossier's `artifacts_not_fully_read`,
    the assessed-artifact list, the bundle location and the CLI summary line -
    and on Windows every one of them carried the producer's absolute path
    instead of a filename. A signed receipt is the document least allowed to
    say where it was made, and two machines scanning the same bytes have to be
    able to compare what came out.

    The separator is written into the fixture rather than taken from the host,
    so this fails on POSIX too if the helper ever goes back to one separator.
    """
    from actaira.model import artifact_name

    assert artifact_name(r"C:\Users\someone\models\clean.pkl") == "clean.pkl"
    assert artifact_name("/srv/models/clean.pkl") == "clean.pkl"
    assert artifact_name("clean.pkl") == "clean.pkl"

    document = receipt.sign(receipt.build([clean_report], observed_at=OBSERVED), keypair)
    names = [row["name"] for row in document["subjects"]]

    assert names, "a receipt with no subject rows is not a receipt"
    for name in names:
        assert "/" not in name and "\\" not in name, (
            f"{name!r} is a path, not an artifact name; the receipt is carrying "
            "the directory it was produced in"
        )
