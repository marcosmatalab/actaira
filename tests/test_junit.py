"""JUnit XML, which is how every CI that is not GitHub learns what happened.

The interesting part of this format is not the XML, it is the mapping from
three verdicts onto JUnit's two outcomes. A writer that reports an unread
artifact as a passing test hands a pipeline the silent PASS the whole project
exists to prevent, so the three verdicts are asserted to produce three
distinguishable shapes, and the inconclusive one is asserted not to look like
either of the others.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path
from xml.etree import ElementTree

import pytest

from actaira.i18n.catalog import Catalog
from actaira.model import ArtifactReport, Finding, Severity, Verdict
from actaira.report.junit import build_junit
from support.reports import finding, write_flagged_report, write_report, write_unread_report


@pytest.fixture
def models(tmp_path):
    """One artifact per verdict: fail, pass, inconclusive."""
    root = tmp_path / "models"
    root.mkdir()
    return {
        "gadget.pkl": write_flagged_report(root / "gadget.pkl"),
        "clean.safetensors": write_report(root / "clean.safetensors"),
        "mystery.model": write_unread_report(root / "mystery.model"),
    }


def build(models, *names, **kwargs):
    root = Path(next(iter(models.values())).path).parent
    return build_junit([models[name] for name in names], base=str(root), **kwargs)


def cases(xml_text) -> dict[str, ElementTree.Element]:
    root = ElementTree.fromstring(xml_text)
    return {case.get("name"): case for case in root.iter("testcase")}


# ---------------------------------------------------------------------------
# The document
# ---------------------------------------------------------------------------

def test_the_output_is_xml_a_runner_can_parse(models):
    document = build(models, "gadget.pkl", "clean.safetensors", "mystery.model")

    root = ElementTree.fromstring(document)

    assert document.startswith("<?xml version=")
    assert root.tag == "testsuites"
    assert [suite.tag for suite in root] == ["testsuite"]


def test_the_counts_report_what_the_verdicts_were(models):
    document = build(models, "gadget.pkl", "clean.safetensors", "mystery.model")
    root = ElementTree.fromstring(document)
    suite = root.find("testsuite")

    for element in (root, suite):
        assert element.get("tests") == "3"
        assert element.get("failures") == "1"    # the gadget
        assert element.get("errors") == "1"      # the unread artifact
        assert element.get("skipped") == "0"


def test_no_test_is_given_a_duration_that_was_never_measured(models):
    """A fabricated `time="0.000"` is a measurement nobody took. Leaving the
    attribute out says so; a zero would not."""
    root = ElementTree.fromstring(build(models, "gadget.pkl"))

    assert root.find("testsuite").get("time") is None
    assert root.find(".//testcase").get("time") is None


def test_two_runs_over_the_same_artifacts_produce_the_same_bytes(models):
    first = build(models, "gadget.pkl", "clean.safetensors")
    second = build(models, "gadget.pkl", "clean.safetensors")

    assert first == second
    assert "gadget.pkl" in first, "the equality above would hold for two empty documents"


def test_an_empty_scan_is_still_a_document(models):
    """A JUnit consumer that gets malformed XML usually reports nothing at all,
    so the zero case has to parse as well as the interesting one."""
    root = ElementTree.fromstring(build_junit([]))

    assert root.get("tests") == "0"
    assert root.findall(".//testcase") == []


# ---------------------------------------------------------------------------
# Three verdicts, three shapes
# ---------------------------------------------------------------------------

def test_a_failing_artifact_becomes_a_failure(models):
    case = cases(build(models, "gadget.pkl"))["gadget.pkl"]
    failure = case.find("failure")

    assert failure is not None
    assert case.find("error") is None
    assert failure.get("type") == "ACT-PKL-002"
    assert "ACT-PKL-002" in failure.get("message")
    assert Catalog("en").rule("ACT-PKL-002") in failure.get("message")


def test_an_unread_artifact_becomes_an_error_and_never_a_silent_pass(models):
    case = cases(build(models, "mystery.model"))["mystery.model"]
    error = case.find("error")

    assert error is not None, "an inconclusive artifact reported as a passing test is the failure mode"
    assert case.find("failure") is None
    assert case.find("skipped") is None
    assert error.get("type") == "inconclusive"
    assert error.get("message") == Catalog("en").line("report.inconclusive")


def test_a_passing_artifact_carries_no_problem_element(models):
    """Negative control for the two above: the writer does not decorate
    everything."""
    case = cases(build(models, "clean.safetensors"))["clean.safetensors"]

    assert case.find("failure") is None
    assert case.find("error") is None
    assert case.find("system-out") is not None


def test_the_headline_of_an_unread_artifact_names_the_inspector_error():
    """When an inspector raised, the reason the artifact is unread is the
    crash, and that is what belongs in the one line a runner shows."""
    broken = ArtifactReport(
        path="models/broken.pt",
        size_bytes=10,
        sha256="a" * 64,
        detected_format="pytorch-zip",
        format_confidence="magic",
        verdict=Verdict.INCONCLUSIVE,
        inspector_errors=["BadZipFile: file is not a zip file"],
    )

    error = cases(build_junit([broken], base="models"))["broken.pt"].find("error")

    assert "BadZipFile" in error.get("message")
    assert "BadZipFile" in error.text


# ---------------------------------------------------------------------------
# What the detail carries
# ---------------------------------------------------------------------------

def test_the_failure_body_carries_every_finding_and_its_evidence(models):
    failure = cases(build(models, "gadget.pkl"))["gadget.pkl"].find("failure")

    assert '"callable": "posix.system"' in failure.text
    assert "[critical] ACT-PKL-002" in failure.text
    assert "[info] ACT-PKL-008" in failure.text, "the lower-severity finding is reported too"
    assert "fully_read: true" in failure.text


def test_the_test_name_and_class_say_which_file_and_which_format(models):
    document = build(models, "gadget.pkl", "clean.safetensors")
    parsed = cases(document)

    assert parsed["gadget.pkl"].get("classname") == "actaira.pickle"
    assert parsed["clean.safetensors"].get("classname") == "actaira.safetensors"


def test_the_digest_travels_with_the_test(models):
    case = cases(build(models, "gadget.pkl"))["gadget.pkl"]
    report = models["gadget.pkl"]

    assert report.sha256 in case.find("system-out").text
    assert "findings: 2" in case.find("system-out").text


def test_a_nested_artifact_keeps_its_relative_path_as_the_test_name(tmp_path):
    nested = tmp_path / "models" / "shards" / "part.pkl"
    report = write_flagged_report(nested)

    parsed = cases(build_junit([report], base=str(tmp_path / "models")))

    assert "shards/part.pkl" in parsed


# ---------------------------------------------------------------------------
# XML that stays XML
# ---------------------------------------------------------------------------

def test_markup_in_a_file_name_is_escaped_and_survives_the_round_trip(tmp_path):
    """A file name is attacker-controlled input in this tool's threat model,
    and it reaches both an attribute and the element body. An unescaped `<`
    would make the whole report unparseable, which a runner reports as no
    tests at all."""
    # The bytes are written under a name every filesystem accepts and the
    # hostile name is put on the report, rather than on the file. `<` and `>`
    # are illegal in a filename on some hosts, so a test that needs the
    # filesystem to accept them is a test that does not run there - and this
    # property has nothing to do with the filesystem. What it is about is a
    # name reaching an XML attribute and an element body, which is what the
    # report carries and what a zip member name can be regardless of host.
    written = tmp_path / "hostile.pkl"
    report = write_flagged_report(written)
    import dataclasses

    hostile_name = "we<ird&name>.pkl"
    report.path = str(tmp_path / hostile_name)
    report.findings = [
        dataclasses.replace(finding, location=hostile_name) for finding in report.findings
    ]
    assert report.findings, "the fixture has to produce a finding for the body to carry a name"

    document = build_junit([report], base=str(tmp_path))
    parsed = cases(document)

    assert "&lt;" in document and "&amp;" in document
    assert "<we<ird" not in document
    assert "we<ird&name>.pkl" in parsed
    assert "we<ird&name>.pkl" in parsed["we<ird&name>.pkl"].find("failure").text


def test_a_control_character_in_a_member_name_does_not_destroy_the_report():
    """XML 1.0 cannot represent a C0 control at all, escaped or otherwise.

    `ElementTree` writes the byte out verbatim and every parser then rejects
    the document, so one member called `weights\x01.bin` inside one artifact
    cost the entire report, not one line of it - and a runner shows a report
    it cannot parse as no tests at all, which is the silent pass this format
    mapping exists to prevent. Member names are attacker-controlled by
    definition: that is the product.
    """
    report = ArtifactReport(
        path="hostile\x01.pt", size_bytes=64, sha256="a" * 64,
        detected_format="zip", format_confidence="high", verdict=Verdict.FAIL,
    )
    report.findings.append(
        Finding(rule_id="ACT-ZIP-001", severity=Severity.HIGH,
                location="hostile.pt!weights\x00\x01\x1f.bin",
                evidence={"member": "weights\x07.bin"})
    )

    document = build_junit([report])
    parsed = ElementTree.fromstring(document)  # the assertion: it parses at all

    assert "\x01" not in document and "\x00" not in document and "\x07" not in document
    testcase = parsed.find(".//testcase")
    assert testcase.get("name") == "hostile\\x01.pt", "the byte is shown, not deleted"
    assert "weights\\x00\\x01\\x1f.bin" in testcase.find("failure").text


def test_the_three_whitespace_controls_xml_does_allow_are_left_alone():
    """Negative control on the sanitiser: tab, newline and carriage return are
    legal in XML 1.0 and escaping them would mangle every multi-line body."""
    report = ArtifactReport(
        path="plain.pkl", size_bytes=8, sha256="b" * 64,
        detected_format="pickle", format_confidence="high", verdict=Verdict.FAIL,
    )
    report.findings.append(
        Finding(rule_id="ACT-PKL-002", severity=Severity.CRITICAL, location="plain.pkl",
                evidence={"note": "a\tb"})
    )

    document = build_junit([report])
    ElementTree.fromstring(document)

    assert "\\x09" not in document and "\\x0a" not in document
    assert "\n" in document


def test_a_lone_surrogate_from_an_undecodable_path_does_not_destroy_the_report():
    """A path the filesystem hands back with `surrogateescape` carries code
    points no XML document may contain and no UTF-8 encoder will emit."""
    report = ArtifactReport(
        path="bad\udcff.pkl", size_bytes=8, sha256="c" * 64,
        detected_format="pickle", format_confidence="high", verdict=Verdict.PASS,
    )

    document = build_junit([report])
    ElementTree.fromstring(document)

    assert document.encode("utf-8"), "the document has to survive being written to a file"
    assert "\\xdcff" in document or "\\xdc" in document


# ---------------------------------------------------------------------------
# The threshold and the language
# ---------------------------------------------------------------------------

def test_the_document_is_written_in_the_language_that_was_asked_for(models):
    spanish = cases(build(models, "gadget.pkl", catalog=Catalog("es")))["gadget.pkl"]
    english = cases(build(models, "gadget.pkl", catalog=Catalog("en")))["gadget.pkl"]

    assert Catalog("es").rule("ACT-PKL-002") in spanish.find("failure").get("message")
    assert spanish.find("failure").get("message") != english.find("failure").get("message")
    assert spanish.get("name") == english.get("name"), "identifiers and paths are not translated"


def test_the_document_follows_the_verdict_and_not_the_findings(tmp_path):
    """The same finding, two verdicts. A MEDIUM finding passes under one
    threshold and fails under another, and the threshold is the caller's; this
    writer has to report the verdict it was handed rather than re-deciding it
    from the rule table."""
    findings = [finding("ACT-FMT-001", severity=Severity.MEDIUM, location="array.npy")]
    lenient_report = write_report(tmp_path / "array.npy", findings=findings, verdict=Verdict.PASS)
    strict_report = dataclasses.replace(lenient_report, verdict=Verdict.FAIL)

    lenient = cases(build_junit([lenient_report], base=str(tmp_path)))["array.npy"]
    strict = cases(build_junit([strict_report], base=str(tmp_path)))["array.npy"]

    assert lenient.find("failure") is None
    assert strict.find("failure") is not None
    assert "ACT-FMT-001" in strict.find("failure").text


# ---------------------------------------------------------------------------
# Through the command line
# ---------------------------------------------------------------------------


