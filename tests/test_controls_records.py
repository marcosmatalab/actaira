"""The deterministic record-keeping and artifact controls.

Three things are being tested and they are not the same thing: that a
satisfied case is recognised, that an unsatisfied case is recognised, and
that the cases in between never quietly become one of the first two. The
third is the one that matters, because a control whose INCONCLUSIVE branch
degrades to SATISFIED reports a clean compliance file for a target it could
not read, which is the failure mode this whole layer exists to avoid (D-04,
D-40).

Targets are built through `engine.load_target`, the same function the CLI
calls, so the declaration files below are parsed by the real parser rather
than handed in as a dictionary the test invented.
"""
from __future__ import annotations

import json

import pytest

from actaira.controls.engine import load_target
from actaira.controls.model import Method, Outcome
from actaira.controls.records import (
    ARTIFACT_CONTROL,
    LOG_CONTROL,
    REQUIRED_FIELDS,
    discover_artifacts,
)
from actaira.governance import catalog
from conftest import corpus_build

GOOD_ENTRY = {
    "timestamp": "2027-12-02T09:00:00Z",
    "system_id": "triage-classifier-v3",
    "input_ref": "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
}


def write_log(root, name: str, entries: list[dict]) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(entry) for entry in entries) + "\n", encoding="utf-8")


def run_log(root):
    return LOG_CONTROL(load_target(root, role="provider"))


def run_artifacts(root):
    return ARTIFACT_CONTROL(load_target(root, role="provider"))


# ---------------------------------------------------------------------------
# ACT-C-12-LOG, the satisfied case
# ---------------------------------------------------------------------------

def test_a_json_lines_log_with_every_field_is_satisfied(tmp_path):
    write_log(tmp_path, "logs/audit.jsonl", [GOOD_ENTRY, GOOD_ENTRY])

    result = run_log(tmp_path)

    assert result.outcome is Outcome.SATISFIED
    assert result.method is Method.DETERMINISTIC
    assert result.evidence["entries_read"] == 2
    assert result.evidence["entries_missing_fields"] == 0
    assert result.abstained_on == ()


def test_a_csv_log_is_read_and_its_header_supplies_the_field_names(tmp_path):
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "audit.csv").write_text(
        "time,system,input_data\n"
        "2027-12-02T09:00:00Z,triage-v3,row-17\n"
        "2027-12-02T09:00:01Z,triage-v3,row-18\n",
        encoding="utf-8",
    )

    result = run_log(tmp_path)

    assert result.outcome is Outcome.SATISFIED
    assert result.evidence["logs"][0]["format"] == "csv"
    assert result.evidence["entries_read"] == 2


def test_the_format_is_decided_from_the_content_and_not_from_the_extension(tmp_path):
    """A file called .csv whose lines are JSON objects is a JSON Lines log.
    Reading it as CSV would report every field missing, which is a false
    NOT_SATISFIED: the most expensive wrong answer this control can give."""
    write_log(tmp_path, "logs/audit.csv", [GOOD_ENTRY])

    result = run_log(tmp_path)

    assert result.evidence["logs"][0]["format"] == "jsonl"
    assert result.outcome is Outcome.SATISFIED


def test_the_accepted_spellings_are_published_in_the_evidence(tmp_path):
    """A generous matcher that does not say what it accepted is a matcher
    nobody can audit. See design note D-52."""
    write_log(tmp_path, "logs/audit.jsonl", [GOOD_ENTRY])

    accepted = run_log(tmp_path).evidence["accepted_names"]

    assert set(accepted) == set(REQUIRED_FIELDS)
    assert "systemid" in accepted["system_identifier"]


def test_a_column_the_operator_declared_is_accepted_alongside_the_built_in_names(tmp_path):
    (tmp_path / "actaira.yaml").write_text(
        "logs:\n  field_names:\n    reference_input_data: expediente\n", encoding="utf-8"
    )
    write_log(
        tmp_path,
        "logs/audit.jsonl",
        [{"timestamp": "2027-12-02T09:00:00Z", "system_id": "v3", "expediente": "E-17"}],
    )

    result = run_log(tmp_path)

    assert result.outcome is Outcome.SATISFIED
    assert result.evidence["declared_field_names"] == {"reference_input_data": "expediente"}


# ---------------------------------------------------------------------------
# ACT-C-12-LOG, the unsatisfied case
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("dropped", sorted(REQUIRED_FIELDS))
def test_an_entry_missing_any_required_field_is_not_satisfied(tmp_path, dropped):
    key = {"timestamp": "timestamp", "system_identifier": "system_id", "reference_input_data": "input_ref"}[dropped]
    entry = {name: value for name, value in GOOD_ENTRY.items() if name != key}
    write_log(tmp_path, "logs/audit.jsonl", [GOOD_ENTRY, entry])

    result = run_log(tmp_path)

    assert result.outcome is Outcome.NOT_SATISFIED
    assert result.evidence["missing_by_field"][dropped] == 1
    assert result.evidence["examples"][0]["missing"] == [dropped]
    assert result.evidence["examples"][0]["entry"] == 2


def test_a_field_that_is_present_but_empty_counts_as_absent(tmp_path):
    """A log with a timestamp column that is blank on every row passes a
    key-presence check and records nothing, and what got recorded is the
    entire subject of Article 12."""
    write_log(tmp_path, "logs/audit.jsonl", [{**GOOD_ENTRY, "timestamp": "   "}])

    result = run_log(tmp_path)

    assert result.outcome is Outcome.NOT_SATISFIED
    assert result.evidence["missing_by_field"]["timestamp"] == 1


def test_an_observed_absence_outranks_a_remainder_that_could_not_be_read(tmp_path):
    """Design note D-53. The opposite rule would let one unparseable byte
    suppress every real finding in a target, which is a suppression mechanism
    an attacker can trigger on purpose."""
    path = tmp_path / "logs" / "audit.jsonl"
    path.parent.mkdir()
    path.write_text(
        json.dumps({k: v for k, v in GOOD_ENTRY.items() if k != "input_ref"}) + "\n"
        + "{ this line is not json\n",
        encoding="utf-8",
    )

    result = run_log(tmp_path)

    assert result.outcome is Outcome.NOT_SATISFIED
    assert result.evidence["logs"][0]["unreadable_lines"] == 1
    assert result.abstained_on == (str(path),)


# ---------------------------------------------------------------------------
# ACT-C-12-LOG, the inconclusive cases
# ---------------------------------------------------------------------------

def test_a_target_with_no_logs_is_inconclusive_and_never_not_satisfied(tmp_path):
    """"I found no logs" and "this system does not log" are different claims
    and only one of them is usually true."""
    (tmp_path / "model.safetensors").write_bytes(
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}, b"\x00" * 16
        )
    )

    result = run_log(tmp_path)

    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.evidence["reason"] == "no_logs_found"


def test_a_log_that_is_not_text_is_inconclusive(tmp_path):
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "audit.log").write_bytes(b"\xff\xfe\x00\x01binary")

    result = run_log(tmp_path)

    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.evidence["reason"] == "logs_unreadable"
    assert "utf-8" in result.evidence["logs"][0]["error"]


def test_complete_entries_next_to_an_unreadable_line_are_inconclusive_not_satisfied(tmp_path):
    path = tmp_path / "logs" / "audit.jsonl"
    path.parent.mkdir()
    path.write_text(json.dumps(GOOD_ENTRY) + "\n[1, 2, 3]\n", encoding="utf-8")

    result = run_log(tmp_path)

    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.evidence["reason"] == "logs_partially_read"
    assert result.evidence["entries_missing_fields"] == 0


def test_a_log_declared_outside_the_target_is_not_read(tmp_path):
    """The declaration file lives inside the target, so on a target that came
    from somewhere else it is attacker-controlled input. A path that escapes
    the root must not make this tool read a file elsewhere on the machine and
    copy what it found into an evidence document."""
    outside = tmp_path / "outside.jsonl"
    outside.write_text(json.dumps(GOOD_ENTRY) + "\n", encoding="utf-8")
    root = tmp_path / "target"
    root.mkdir()
    (root / "actaira.yaml").write_text('logs: "../outside.jsonl"\n', encoding="utf-8")

    result = run_log(root)

    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.evidence["reason"] == "no_logs_found"
    assert str(outside) not in json.dumps(result.to_dict())


# ---------------------------------------------------------------------------
# ACT-C-12-LOG, the boundary of the claim
# ---------------------------------------------------------------------------

def test_the_result_says_it_checked_the_form_and_not_the_truth(tmp_path):
    write_log(tmp_path, "logs/audit.jsonl", [GOOD_ENTRY])

    result = run_log(tmp_path)

    assert "form of the log entries" in result.covers
    assert "complete" in result.does_not_cover
    assert "true" in result.does_not_cover


# ---------------------------------------------------------------------------
# ACT-C-15-ARTIFACT
# ---------------------------------------------------------------------------

def test_a_clean_artifact_is_satisfied(tmp_path):
    (tmp_path / "model.safetensors").write_bytes(
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}, b"\x00" * 16
        )
    )

    result = run_artifacts(tmp_path)

    assert result.outcome is Outcome.SATISFIED
    assert result.findings == ()
    assert result.evidence["artifacts"][0]["fully_read"] is True


def test_an_artifact_with_a_gadget_is_not_satisfied_and_carries_the_scanner_finding(tmp_path):
    (tmp_path / "checkpoint.pkl").write_bytes(corpus_build.craft_reduce("posix", "system", ("id",)))

    result = run_artifacts(tmp_path)

    assert result.outcome is Outcome.NOT_SATISFIED
    assert "ACT-PKL-002" in {finding.rule_id for finding in result.findings}
    assert result.evidence["artifacts_with_serious_findings"] == 1


def test_the_control_emits_no_rule_identifier_of_its_own(tmp_path):
    """Design note D-54: the findings carried up are the scanner's, so every
    rule id in this result already has text in both message catalogues."""
    (tmp_path / "checkpoint.pkl").write_bytes(corpus_build.craft_reduce("posix", "system", ("id",)))

    result = run_artifacts(tmp_path)

    assert {finding.rule_id.split("-")[1] for finding in result.findings} == {"PKL"}


def test_a_gadget_next_to_a_clean_artifact_still_fails(tmp_path):
    """The clean file is not an average; it is another file."""
    (tmp_path / "clean.safetensors").write_bytes(
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}, b"\x00" * 16
        )
    )
    (tmp_path / "checkpoint.pkl").write_bytes(corpus_build.craft_reduce("posix", "system", ("id",)))

    result = run_artifacts(tmp_path)

    assert result.outcome is Outcome.NOT_SATISFIED
    assert result.evidence["artifacts_inspected"] == 2


def test_an_artifact_that_could_not_be_fully_read_is_inconclusive(tmp_path):
    """Not SATISFIED: nothing above medium was found, and the reason nothing
    was found is that the file was never parsed."""
    (tmp_path / "broken.gguf").write_bytes(b"GGUF" + b"\x03\x00\x00\x00" + b"\xff" * 8)

    result = run_artifacts(tmp_path)

    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.evidence["reason"] == "artifacts_partially_read"
    assert result.abstained_on == (str(tmp_path / "broken.gguf"),)


def test_a_target_with_no_artifacts_is_inconclusive(tmp_path):
    (tmp_path / "README.md").write_text("nothing to inspect here\n", encoding="utf-8")

    result = run_artifacts(tmp_path)

    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.evidence["reason"] == "no_artifacts_found"


def test_artifacts_are_discovered_by_content_even_when_the_name_lies(tmp_path):
    """Selecting candidates by extension would let an attacker keep a file
    out of the scan by renaming it, which is the same trick the extension
    check inside the scanner exists to catch (D-06)."""
    (tmp_path / "notes.txt").write_bytes(corpus_build.craft_reduce("posix", "system", ("id",)))

    found, declared, _truncated = discover_artifacts(load_target(tmp_path))

    assert [path.name for path in found] == ["notes.txt"]
    assert declared is False
    assert run_artifacts(tmp_path).outcome is Outcome.NOT_SATISFIED


def test_the_scan_policy_the_outcome_was_computed_under_is_recorded(tmp_path):
    (tmp_path / "actaira.yaml").write_text("scan:\n  policy: known-bad\n", encoding="utf-8")
    (tmp_path / "model.safetensors").write_bytes(
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}, b"\x00" * 16
        )
    )

    evidence = run_artifacts(tmp_path).evidence

    assert evidence["scan_policy"] == "known-bad"
    assert evidence["scan_policy_declared"] is True


def test_a_declared_artifact_list_is_used_and_marked_as_declared(tmp_path):
    (tmp_path / "actaira.json").write_text(
        json.dumps({"artifacts": ["weights/*.safetensors"]}), encoding="utf-8"
    )
    (tmp_path / "weights").mkdir()
    (tmp_path / "weights" / "a.safetensors").write_bytes(
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}, b"\x00" * 16
        )
    )
    (tmp_path / "checkpoint.pkl").write_bytes(corpus_build.craft_reduce("posix", "system", ("id",)))

    result = run_artifacts(tmp_path)

    assert result.evidence["declared_artifacts"] is True
    assert result.evidence["artifacts_inspected"] == 1
    assert result.outcome is Outcome.SATISFIED


def test_the_result_says_article_15_is_mostly_about_something_else(tmp_path):
    (tmp_path / "model.safetensors").write_bytes(
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}, b"\x00" * 16
        )
    )

    result = run_artifacts(tmp_path)

    assert "accuracy" in result.does_not_cover
    assert "poisoning" in result.does_not_cover
    assert "cybersecurity of the artifact" in result.does_not_cover


# ---------------------------------------------------------------------------
# Identifiers, against the catalogue rather than against ourselves
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "control, obligation_id",
    [(LOG_CONTROL, "AIA-12"), (ARTIFACT_CONTROL, "AIA-15")],
    ids=lambda item: getattr(item, "id", item),
)
def test_each_control_id_is_the_one_the_catalogue_declares(control, obligation_id):
    """Both directions of the edge (D-43). An obligation that names a control
    nobody registered renders as covered with nothing behind it, and a control
    that names an obligation that does not exist is a mapping into thin air."""
    obligation = catalog.by_id(obligation_id)

    assert obligation is not None
    assert control.id in obligation.controls
    assert control.obligation_ids == (obligation_id,)
    assert obligation.checkability is catalog.Checkability.MACHINE_CHECKABLE
    assert control.method is Method.DETERMINISTIC
