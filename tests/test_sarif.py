"""SARIF 2.1.0, the document GitHub code scanning ingests.

Two properties carry the whole format. The document has to be *valid*, or the
upload is rejected and the scan silently stops protecting anything; and the
fingerprints have to be *stable*, or every re-scan closes yesterday's alerts
and opens the same ones again, which trains a team to ignore them.

The required-field check below is written by hand rather than against the
published schema on purpose: the test suite runs with no network and with the
project's one runtime dependency, so downloading a schema at test time is out
and vendoring 110 KB of JSON to assert on 20 fields is worse. The document
produced by this module was validated against the canonical OASIS schema for
SARIF 2.1.0 during development, and what that validation covers is asserted
here field by field.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

from actaira.coverage import CoverageState
from actaira.i18n.catalog import Catalog
from actaira.model import ArtifactReport, Severity, Verdict
from actaira.report.sarif import (
    FINGERPRINT_KEY,
    SARIF_LEVELS,
    SARIF_VERSION,
    TOOL_NAME,
    build_sarif,
    fingerprint,
    level_for,
)
from support.reports import (
    finding,
    full_coverage,
    write_flagged_report,
    write_report,
    write_unread_report,
)

HEX = "0123456789abcdef"


# ---------------------------------------------------------------------------
# Artifacts with known findings
# ---------------------------------------------------------------------------

def denied_imports(*qualified: str) -> bytes:
    """A pickle that imports several callables and calls none of them.

    Built here rather than in the corpus because the corpus has no case with
    two findings of one rule in one file, and that is exactly the case a
    fingerprint can collapse.
    """
    body = b""
    for name in qualified:
        module, _, attribute = name.rpartition(".")
        body += b"c" + module.encode() + b"\n" + attribute.encode() + b"\n"
    return b"\x80\x02" + body + b"\x86" + b"."


@pytest.fixture
def models(tmp_path):
    """A directory with one artifact per verdict, plus a nested one."""
    root = tmp_path / "models"
    (root / "nested").mkdir(parents=True)
    return {
        "gadget.pkl": write_flagged_report(root / "gadget.pkl", location="gadget.pkl"),
        "clean.safetensors": write_report(root / "clean.safetensors"),
        # The extension says npy and the bytes say otherwise. One medium
        # finding, which is what the "exactly the rules that fired" tests read.
        "renamed.npy": write_report(
            root / "renamed.npy",
            detected_format="npy",
            findings=[finding("ACT-FMT-001", severity=Severity.MEDIUM, location="renamed.npy")],
        ),
        # Empty, so nothing could be read: a different rule and a different
        # coverage state from the unknown-format case below.
        "empty.pkl": write_report(
            root / "empty.pkl",
            payload=b"",
            detected_format="unknown",
            format_confidence="unknown",
            verdict=Verdict.INCONCLUSIVE,
            metadata={"fully_read": False},
            findings=[finding("ACT-FMT-003", severity=Severity.LOW, location="empty.pkl")],
            coverage=full_coverage(state=CoverageState.FAILED, reason="artifact_is_empty"),
        ),
        "nested/mystery.model": write_unread_report(
            root / "nested" / "mystery.model",
            findings=[finding("ACT-FMT-001", severity=Severity.MEDIUM, location="mystery.model")],
        ),
    }


@pytest.fixture
def models_root(tmp_path):
    """Where the fixture above wrote. Separate, because `models` is now the
    reports themselves and a directory is a different question."""
    return tmp_path / "models"


def scan(models, *names, base=None):
    root = Path(models["clean.safetensors"].path).parent
    return build_sarif([models[name] for name in names], base=str(base or root))


def results_by_rule(document) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for result in document["runs"][0]["results"]:
        grouped.setdefault(result["ruleId"], []).append(result)
    return grouped


def fingerprints(document) -> list[str]:
    return [result["partialFingerprints"][FINGERPRINT_KEY] for result in document["runs"][0]["results"]]


# ---------------------------------------------------------------------------
# The fields a consumer rejects the upload over
# ---------------------------------------------------------------------------

def assert_required_fields(document) -> None:
    """Every field SARIF 2.1.0 marks required on the objects this writer emits.

    Kept as a function rather than a test so that every scenario below can run
    it: a document that is valid with findings and invalid without them is a
    document nobody validated in the case that matters.
    """
    assert document["version"] == SARIF_VERSION
    assert document["$schema"].startswith("https://")
    assert isinstance(document["runs"], list) and len(document["runs"]) == 1

    run = document["runs"][0]
    driver = run["tool"]["driver"]          # `tool` and `tool.driver` are required
    assert driver["name"] == TOOL_NAME      # `name` is the only required driver field
    # `informationUri` is optional in SARIF 2.1.0 and is omitted here rather
    # than pointed at a repository this tree does not have: viewers render it
    # as a link, and a dead link inside a security report is the worst place
    # in the document for one. If it is present it has to be a real URL.
    if "informationUri" in driver:
        assert driver["informationUri"].startswith("https://")
    assert driver["version"]

    rules = driver["rules"]
    for index, rule in enumerate(rules):
        assert rule["id"], f"rule {index} has no id"
        assert rule["shortDescription"]["text"].strip()
        assert rule["fullDescription"]["text"].strip()
        assert rule["help"]["text"].strip()
        assert rule["defaultConfiguration"]["level"] in SARIF_LEVELS

    for artifact in run["artifacts"]:
        assert artifact["location"]["uri"]
        digest = artifact["hashes"]["sha-256"]
        assert len(digest) == 64 and set(digest) <= set(HEX)
        assert isinstance(artifact["length"], int)

    for result in run["results"]:
        assert result["message"]["text"].strip()      # `message` is required
        assert result["level"] in SARIF_LEVELS
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"]
        assert run["artifacts"][location["artifactLocation"]["index"]]["location"]["uri"] == (
            location["artifactLocation"]["uri"]
        )
        assert location["region"]["startLine"] >= 1
        for key, value in result["partialFingerprints"].items():
            assert isinstance(key, str) and isinstance(value, str) and value

    invocation = run["invocations"][0]
    assert isinstance(invocation["executionSuccessful"], bool)  # required by the schema


def test_a_run_with_findings_carries_every_required_field(models):
    document = scan(models, "gadget.pkl", "renamed.npy", "empty.pkl")

    assert_required_fields(document)
    assert document["runs"][0]["results"], "the assertion above would be vacuous with no results"


def test_a_directory_with_nothing_to_report_is_still_a_valid_document(models):
    """The empty case is the one a CI runs on a good day, and the one a writer
    that only ever gets exercised on failures gets wrong."""
    document = scan(models, "clean.safetensors")

    assert_required_fields(document)
    assert document["runs"][0]["results"] == []
    assert document["runs"][0]["tool"]["driver"]["rules"] == []
    assert len(document["runs"][0]["artifacts"]) == 1, "the artifact was scanned, it just had nothing wrong"


def test_the_document_survives_a_round_trip_through_json(models):
    """Every value has to be JSON-native: a Severity or a Path that reached the
    document would raise here rather than in somebody's pipeline."""
    document = scan(models, "gadget.pkl", "empty.pkl")

    assert json.loads(json.dumps(document)) == document


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def test_the_rules_carried_are_exactly_the_rules_that_fired(models):
    document = scan(models, "renamed.npy", "clean.safetensors")

    rule_ids = [rule["id"] for rule in document["runs"][0]["tool"]["driver"]["rules"]]

    assert rule_ids == ["ACT-FMT-001"]
    assert set(rule_ids) == set(results_by_rule(document))


def test_a_rule_that_did_not_fire_is_not_advertised(models):
    """Negative control for the rule list: the catalogue has 40 rules and a
    document that ships all of them describes the tool, not the scan."""
    document = scan(models, "clean.safetensors", "renamed.npy")

    rule_ids = {rule["id"] for rule in document["runs"][0]["tool"]["driver"]["rules"]}

    assert "ACT-PKL-002" not in rule_ids
    assert len(rule_ids) == 1


def test_each_result_points_at_its_own_rule_by_index(models):
    document = scan(models, "gadget.pkl", "empty.pkl")
    rules = document["runs"][0]["tool"]["driver"]["rules"]

    for result in document["runs"][0]["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
    assert len(rules) >= 3, "several distinct rules, so the indices are not all zero"


def test_a_rule_carries_the_help_text_from_the_catalogue(models):
    """`fullDescription` is what a consumer shows under the alert. A rule with
    no help entry falls back to its short text rather than to an empty box."""
    document = scan(models, "gadget.pkl")
    rules = {rule["id"]: rule for rule in document["runs"][0]["tool"]["driver"]["rules"]}
    catalog = Catalog("en")

    with_help = rules["ACT-PKL-002"]
    without_help = rules["ACT-PKL-008"]

    assert with_help["fullDescription"]["text"] == catalog.rule_help("ACT-PKL-002")
    assert with_help["fullDescription"]["text"] != with_help["shortDescription"]["text"]
    assert catalog.rule_help("ACT-PKL-008") == "", "this rule has no help entry, which is the case under test"
    assert without_help["fullDescription"]["text"] == catalog.rule("ACT-PKL-008")


# ---------------------------------------------------------------------------
# Severity to level
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("severity", "level"),
    [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ],
)
def test_every_severity_maps_to_the_level_it_should(severity, level):
    assert level_for(severity) == level
    assert level_for(severity.value) == level, "a plain string from a JSON report maps the same way"


def test_the_five_severities_do_not_collapse_into_one_level():
    """Control for the mapping above: a table that returned "error" for
    everything would satisfy any single row of it."""
    levels = {level_for(severity) for severity in Severity}

    assert levels == {"error", "warning", "note"}


def test_the_level_a_result_carries_is_the_level_of_its_own_finding(models):
    document = scan(models, "gadget.pkl", "renamed.npy", "empty.pkl")
    grouped = results_by_rule(document)

    assert grouped["ACT-PKL-002"][0]["level"] == "error"     # critical
    assert grouped["ACT-FMT-001"][0]["level"] == "warning"   # medium
    assert grouped["ACT-FMT-003"][0]["level"] == "note"      # low
    assert grouped["ACT-PKL-008"][0]["level"] == "note"      # info


def test_the_rule_default_level_follows_the_severity_that_fired(models):
    document = scan(models, "gadget.pkl", "empty.pkl")
    rules = {rule["id"]: rule for rule in document["runs"][0]["tool"]["driver"]["rules"]}

    assert rules["ACT-PKL-002"]["defaultConfiguration"]["level"] == "error"
    assert rules["ACT-FMT-003"]["defaultConfiguration"]["level"] == "note"
    assert rules["ACT-PKL-002"]["properties"]["actaira:severity"] == "critical"


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------

def test_the_uri_is_the_path_relative_to_the_root_that_was_scanned(models):
    document = scan(models, "gadget.pkl", "nested/mystery.model")

    uris = [artifact["location"]["uri"] for artifact in document["runs"][0]["artifacts"]]

    assert uris == ["gadget.pkl", "nested/mystery.model"]
    for uri in uris:
        assert not uri.startswith("/"), "an absolute runner path matches no file in the repository"
        assert "\\" not in uri


def test_an_artifact_outside_the_scanned_root_keeps_its_real_path(models_root, tmp_path):
    """Negative control for the relative rule: a relative path is only emitted
    when one exists. Inventing `../../elsewhere.pkl` would name a file the
    annotation layer cannot resolve, so the absolute path is kept instead."""
    outside = tmp_path / "elsewhere.pkl"
    report = write_flagged_report(outside, "ACT-PKL-001")

    document = build_sarif([report], base=str(models_root))

    uri = document["runs"][0]["artifacts"][0]["location"]["uri"]
    # `as_posix`, not `str`: a SARIF uri is always POSIX-separated, which is
    # what `artifact_uri` produces and what a consumer expects. Comparing
    # against the host's spelling asserted the host, not the product.
    assert uri == Path(outside).as_posix()
    assert Path(uri).is_absolute(), "an absolute path was kept rather than a fabricated relative one"


def test_the_location_inside_the_artifact_travels_with_the_result(models):
    """A zip member is a location inside one file, and the physical location is
    the file. The member name is what tells a reader which shard it was in."""
    document = scan(models, "gadget.pkl")
    result = results_by_rule(document)["ACT-PKL-002"][0]

    assert result["locations"][0]["logicalLocations"][0]["name"] == "gadget.pkl"
    assert result["properties"]["actaira:location"] == "gadget.pkl"


def test_the_artifact_entry_carries_the_digest_and_size_of_the_file(models, models_root):
    document = scan(models, "gadget.pkl")
    artifact = document["runs"][0]["artifacts"][0]
    on_disk = (models_root / "gadget.pkl").read_bytes()

    assert artifact["hashes"]["sha-256"] == hashlib.sha256(on_disk).hexdigest()
    assert artifact["length"] == len(on_disk)
    assert artifact["properties"]["actaira:verdict"] == "fail"
    assert artifact["properties"]["actaira:fully_read"] is True


# ---------------------------------------------------------------------------
# Fingerprints, which decide what GitHub shows twice
# ---------------------------------------------------------------------------

def test_the_same_file_scanned_twice_produces_the_same_fingerprints(models):
    first = scan(models, "gadget.pkl")
    second = scan(models, "gadget.pkl")

    assert fingerprints(first) == fingerprints(second)
    assert len(fingerprints(first)) == 2, "two findings, so the equality is not between two empty lists"


def test_two_different_artifacts_do_not_share_a_fingerprint(models, tmp_path):
    models["second.pkl"] = write_flagged_report(tmp_path / "models" / "second.pkl",
                                               location="second.pkl")

    document = scan(models, "gadget.pkl", "second.pkl")
    same_rule = [result for result in document["runs"][0]["results"] if result["ruleId"] == "ACT-PKL-002"]

    assert len(same_rule) == 2, "the same rule fired on both files, which is the case that could collide"
    assert len({result["partialFingerprints"][FINGERPRINT_KEY] for result in same_rule}) == 2


def test_moving_an_artifact_to_another_directory_keeps_its_fingerprint(models, tmp_path):
    """The directory is deliberately outside the fingerprint. A repository that
    reorganises `models/` must not reopen every alert it already triaged."""
    original = models["gadget.pkl"]
    moved = tmp_path / "vendored" / "models" / "gadget.pkl"
    moved.parent.mkdir(parents=True)
    moved.write_bytes(Path(original.path).read_bytes())
    # The same bytes under a new path: same digest, same findings, new location.
    relocated = dataclasses.replace(original, path=str(moved))

    before = scan(models, "gadget.pkl")
    after = build_sarif([relocated], base=str(moved.parent))

    assert fingerprints(before) == fingerprints(after)
    assert before["runs"][0]["artifacts"][0]["location"]["uri"] == "gadget.pkl"


def test_two_findings_of_one_rule_in_one_file_stay_two_alerts(tmp_path):
    """The reason the evidence is part of the fingerprint. Both findings share
    a rule, a file and a location, and they name different gadgets."""
    path = tmp_path / "two.pkl"
    report = write_report(
        path,
        payload=denied_imports("vendorlib.tasks.run_shell", "otherlib.util.spawn"),
        detected_format="pickle",
        verdict=Verdict.FAIL,
        findings=[
            finding("ACT-PKL-001", severity=Severity.HIGH, location="two.pkl", callable=name)
            for name in ("vendorlib.tasks.run_shell", "otherlib.util.spawn")
        ],
    )

    document = build_sarif([report], base=str(tmp_path))
    results = results_by_rule(document)["ACT-PKL-001"]

    assert len(results) == 2
    assert {result["properties"]["actaira:evidence"]["callable"] for result in results} == {
        "vendorlib.tasks.run_shell",
        "otherlib.util.spawn",
    }
    assert len({result["partialFingerprints"][FINGERPRINT_KEY] for result in results}) == 2


def test_editing_the_artifact_changes_the_fingerprint(models):
    """The other direction: the digest is in the fingerprint, so a file that
    changed is not the file that was triaged."""
    report = models["gadget.pkl"]
    fired = report.findings[0]
    tampered = ArtifactReport(**{**report.__dict__, "sha256": "0" * 64})

    assert fingerprint(report, fired) != fingerprint(tampered, fired)
    assert len(fingerprint(report, fired)) == 64


# ---------------------------------------------------------------------------
# Message text and language
# ---------------------------------------------------------------------------

def test_the_message_is_the_catalogue_text_for_the_rule(models):
    document = scan(models, "gadget.pkl")
    result = results_by_rule(document)["ACT-PKL-002"][0]

    assert result["message"]["text"] == Catalog("en").rule("ACT-PKL-002")
    assert result["message"]["text"] != "ACT-PKL-002", "a bare identifier is not a message"


def test_the_document_is_written_in_the_language_the_cli_was_asked_for(models):
    reports = [models["gadget.pkl"]]

    spanish = build_sarif(reports, base=str(models), catalog=Catalog("es"))
    english = build_sarif(reports, base=str(models), catalog=Catalog("en"))

    spanish_text = spanish["runs"][0]["results"][0]["message"]["text"]
    assert spanish_text == Catalog("es").rule("ACT-PKL-002")
    assert spanish_text != english["runs"][0]["results"][0]["message"]["text"]
    assert fingerprints(spanish) == fingerprints(english), "the language must not move an alert"


# ---------------------------------------------------------------------------
# Things that are not findings
# ---------------------------------------------------------------------------

def test_an_inspector_crash_is_reported_as_a_tool_failure_not_as_silence():
    """An inspector that raised produced no findings. If that only showed up as
    an empty result list, a SARIF upload would look like a clean scan."""
    broken = ArtifactReport(
        path="models/broken.pt",
        size_bytes=10,
        sha256="a" * 64,
        detected_format="pytorch-zip",
        format_confidence="magic",
        verdict=Verdict.INCONCLUSIVE,
        inspector_errors=["BadZipFile: file is not a zip file"],
    )

    invocation = build_sarif([broken], base="models")["runs"][0]["invocations"][0]

    assert invocation["executionSuccessful"] is False
    assert "BadZipFile" in invocation["toolExecutionNotifications"][0]["message"]["text"]
    assert invocation["toolExecutionNotifications"][0]["level"] == "error"


def test_a_scan_with_no_crash_reports_a_successful_execution(models):
    invocation = scan(models, "gadget.pkl")["runs"][0]["invocations"][0]

    assert invocation["executionSuccessful"] is True
    assert "toolExecutionNotifications" not in invocation


def test_the_evidence_reaches_the_result_unchanged(models):
    document = scan(models, "gadget.pkl")
    result = results_by_rule(document)["ACT-PKL-002"][0]
    fired = next(f for f in models["gadget.pkl"].findings if f.rule_id == "ACT-PKL-002")

    assert result["properties"]["actaira:evidence"] == fired.evidence
    assert result["properties"]["actaira:evidence"]["callable"] == "posix.system"


# ---------------------------------------------------------------------------
# Through the command line
# ---------------------------------------------------------------------------


