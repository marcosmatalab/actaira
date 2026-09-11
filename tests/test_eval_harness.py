"""The eval harness's own exit gate.

`evals/harness.py` is the measuring apparatus, and a measuring apparatus that
cannot report a failure is worth less than none: it prints numbers that read
as evidence and are not. `make eval` acts on one bit, the exit code, and this
file is about that bit and nothing else.

The defect it was written for: the tamper check has a positive control - "how
many packages verified *before* anything was tampered with" - which was
computed, printed, and never asserted. The gate asked only that no tampered
package be accepted, which is trivially true when no package is accepted
either. A signing layer that rejected everything, including untouched
packages, exited 0 with `0/50` on the line above.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from conftest import CORPUS_DIR, REPO_ROOT, _load_module_by_path

harness = _load_module_by_path("actaira_eval_harness", REPO_ROOT / "evals" / "harness.py")

TESTED = 50


def summary(**overrides: Any) -> dict[str, Any]:
    """A summary of a run in which everything went right."""
    document: dict[str, Any] = {
        "corpus": {"cases": TESTED, "benign": 10, "malicious": 40},
        "expectations": {"checked": TESTED, "met": TESTED, "misses": []},
        "determinism": {"checked": TESTED, "identical": TESTED, "mismatches": []},
        "policies": {},
        "tamper_detection": {
            "artifacts_tested": TESTED,
            "subject_digest_changed": TESTED,
            "subject_digest_unchanged": [],
            "packages_verified_before_tampering": TESTED,
            "tampered_packages_rejected": TESTED,
            "tampered_packages_accepted": [],
        },
        "timing_ms": {"median_ms": 0.1, "max_ms": 1.0},
    }
    for key, value in overrides.items():
        document["tamper_detection"][key] = value
    return document


@pytest.fixture
def gate(monkeypatch, tmp_path):
    """`main()` with the measuring replaced and only the gate left."""

    def run_with(document: dict[str, Any]) -> int:
        monkeypatch.setattr(harness, "run", lambda _corpus: document)
        monkeypatch.setattr(harness, "render", lambda _summary: "")
        monkeypatch.setattr(
            harness.sys, "argv",
            ["harness.py", "--corpus", str(CORPUS_DIR), "--json-out", str(tmp_path / "out.json")],
        )
        return harness.main()

    return run_with


def test_a_run_in_which_everything_worked_exits_zero(gate, tmp_path):
    """Negative control first: the gate has to be able to pass, or every
    assertion below is satisfied by a gate that always fails."""
    assert gate(summary()) == 0
    assert json.loads((tmp_path / "out.json").read_text())["tamper_detection"]["artifacts_tested"] == TESTED


def test_a_signing_layer_that_verifies_nothing_at_all_fails_the_gate(gate):
    """The defect, exactly.

    No tampered package was accepted, because no package was accepted: every
    one of them failed verification before it was touched. The old gate read
    that as success.
    """
    assert gate(summary(packages_verified_before_tampering=0)) == 1


def test_one_package_that_did_not_verify_before_tampering_fails_the_gate(gate):
    assert gate(summary(packages_verified_before_tampering=TESTED - 1)) == 1


def test_a_tampered_package_that_was_not_rejected_still_fails_the_gate(gate):
    assert gate(summary(tampered_packages_rejected=TESTED - 1,
                        tampered_packages_accepted=["one.pkl"])) == 1


def test_a_tamper_check_that_rejected_fewer_than_it_tested_fails_the_gate(gate):
    """`tampered_packages_accepted` is a list of names and can be empty for a
    reason other than success - a case that was skipped, say. The count is
    what the gate compares."""
    assert gate(summary(tampered_packages_rejected=TESTED - 3)) == 1


def test_a_digest_that_did_not_move_under_a_flipped_byte_fails_the_gate(gate):
    assert gate(summary(subject_digest_changed=TESTED - 1,
                        subject_digest_unchanged=["one.pkl"])) == 1


def test_a_tamper_check_over_nothing_fails_the_gate(gate):
    """Zero of zero satisfies every equality above, so the count itself has to
    be positive: an empty corpus is not a passing run."""
    assert gate(summary(artifacts_tested=0, subject_digest_changed=0,
                        packages_verified_before_tampering=0,
                        tampered_packages_rejected=0)) == 1


def test_the_other_two_halves_of_the_gate_still_bite(gate):
    document = summary()
    document["expectations"]["met"] = TESTED - 1
    assert gate(document) == 1

    document = summary()
    document["determinism"]["mismatches"] = ["one.pkl"]
    assert gate(document) == 1


# ---------------------------------------------------------------------------
# The mutation the tamper check depends on
# ---------------------------------------------------------------------------
#
# DEF-03. The tamper check attests an artifact, edits one entry inside the
# signed package, and asserts the edit is caught. The edit used to set the
# verdict to the constant `"fail"`, so for the 8 artifacts already recorded as
# failing it changed nothing: the "tampered" package was byte-identical to the
# original, verification passed, and the harness counted 50 out of 50 while 8
# of those 50 had tested nothing at all.
#
# The repair was to flip the verdict rather than assign it. That is one line,
# and it is the kind of line a later edit reverts without noticing, because
# nothing downstream looks different when it is wrong: the count stays at
# 50/50 either way. So the property is asserted here directly.


@pytest.mark.parametrize("verdict", ["pass", "fail", "inconclusive", None, ""])
def test_the_tamper_mutation_changes_the_entry_whatever_it_started_as(verdict):
    """No starting verdict may leave the entry as it was.

    A no-op mutation is the worst possible outcome for this check, and it is
    also the quietest: the package still verifies, so the harness records a
    pass for a case where nothing was tampered with.
    """
    payload: dict[str, Any] = {"findings": [{"rule": "ACT-PKL-002"}]}
    if verdict is not None:
        payload["verdict"] = verdict
    before = json.dumps({"payload": dict(payload)}, sort_keys=True)

    after = json.dumps(harness.tampered_entry({"payload": payload}), sort_keys=True)

    assert after != before, (
        f"a package whose entry records verdict {verdict!r} would be rewritten to "
        "itself, so verification would pass and the harness would count a tamper "
        "case that tampered with nothing"
    )


def test_the_tamper_mutation_moves_the_verdict_off_whatever_it_was():
    """Flipped, not assigned. The distinction is the whole defect."""
    for verdict in ("pass", "fail", "inconclusive"):
        result = harness.tampered_entry({"payload": {"verdict": verdict, "findings": []}})
        assert result["payload"]["verdict"] != verdict, (
            f"verdict {verdict!r} survived the mutation, which is how DEF-03 happened"
        )
