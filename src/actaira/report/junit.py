"""JUnit XML, which is what every CI that is not GitHub reads.

JUnit has two outcomes that matter, `failure` and `error`,
and this project has three verdicts. The mapping is the whole design of this
module:

  FAIL          -> <failure>, the artifact has a finding at or above the
                   threshold the scan ran with.
  INCONCLUSIVE  -> <error>, the artifact could not be fully read.
  PASS          -> a bare <testcase>.

`INCONCLUSIVE` becoming `error` rather than `skipped` is the same argument
that gives the CLI a third exit code (D-04): a runner that shows an unread
artifact as skipped shows it as "nothing to see here", which is precisely the
silent pass the three-verdict model exists to prevent. A runner that shows it
as an error makes somebody look.

Nothing here is timed. A JUnit file usually carries a duration per test, and
this writer emits none, because the number would have to be invented: the
scan measures bytes, not wall clock, and a fabricated `time="0.000"` is a
measurement that was never taken.
"""
from __future__ import annotations

import json
import re
from typing import Any
from xml.etree import ElementTree

from .. import __version__
from ..i18n.catalog import Catalog
from ..model import ArtifactReport, Finding, Verdict
from . import artifact_uri

SUITE_NAME = "actaira"

# Characters XML 1.0 has no way to represent, escaped or otherwise: the C0
# controls except tab, newline and carriage return, plus lone surrogates and
# the two non-characters at the end of the BMP. `ElementTree` writes them out
# verbatim, and every parser then refuses the document - so one archive member
# called "weights\x01.bin" cost the whole report, not one line of it. The
# artifact is hostile by definition, its member names are attacker-controlled,
# and a report a CI cannot parse is the same outcome as no report at all.
#
# They are replaced with a visible `\xNN` escape rather than dropped, because
# the byte is evidence: a member name with a control character in it is worth
# seeing, and silently deleting it would make two different members print the
# same.
_XML_FORBIDDEN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _xml_safe(text: str) -> str:
    return _XML_FORBIDDEN.sub(lambda match: f"\\x{ord(match.group()):02x}", text)


def build_junit(
    reports: list[ArtifactReport],
    base: str | None = None,
    catalog: Catalog | None = None,
) -> str:
    """A JUnit XML document, as text, ready to write to a file."""
    catalog = catalog or Catalog("en")

    failed = sum(1 for report in reports if report.verdict is Verdict.FAIL)
    unread = sum(1 for report in reports if report.verdict is Verdict.INCONCLUSIVE)
    counts = {
        "name": SUITE_NAME,
        "tests": str(len(reports)),
        "failures": str(failed),
        "errors": str(unread),
        "skipped": "0",
    }

    root = ElementTree.Element("testsuites", counts)
    suite = ElementTree.SubElement(root, "testsuite", counts)
    properties = ElementTree.SubElement(suite, "properties")
    ElementTree.SubElement(properties, "property", {"name": "actaira:version", "value": __version__})

    for report in reports:
        case = ElementTree.SubElement(
            suite,
            "testcase",
            {
                "name": artifact_uri(report.path, base),
                "classname": f"{SUITE_NAME}.{report.detected_format}",
            },
        )
        if report.verdict is not Verdict.PASS:
            tag = "failure" if report.verdict is Verdict.FAIL else "error"
            problem = ElementTree.SubElement(
                case,
                tag,
                {"message": _headline(report, catalog), "type": _type_of(report)},
            )
            problem.text = _detail(report, catalog)
        ElementTree.SubElement(case, "system-out").text = _system_out(report)

    # One pass over the finished tree rather than a call at each of the seven
    # places a string enters it: a field added later cannot forget to sanitise,
    # which is how the member name got through in the first place.
    for element in root.iter():
        if element.text is not None:
            element.text = _xml_safe(element.text)
        for key, value in element.attrib.items():
            element.attrib[key] = _xml_safe(value)

    ElementTree.indent(root, space="  ")
    return ElementTree.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


def _worst_finding(report: ArtifactReport) -> Finding | None:
    if not report.findings:
        return None
    return max(report.findings, key=lambda finding: finding.severity.rank)


def _headline(report: ArtifactReport, catalog: Catalog) -> str:
    """One line, because a runner shows the message attribute and little else.

    An inconclusive artifact is headlined by the fact that it was not fully
    read, not by its worst finding: on an empty `.pkl` the worst finding is
    the extension mismatch, which is a symptom and not the reason the tool
    could say nothing about the file.
    """
    if report.verdict is Verdict.INCONCLUSIVE:
        unread = catalog.line("report.inconclusive")
        return f"{unread}: {report.inspector_errors[0]}" if report.inspector_errors else unread
    worst = _worst_finding(report)
    if worst is not None:
        return f"{worst.rule_id} ({worst.severity.value}): {catalog.rule(worst.rule_id)}"
    return report.verdict.value


def _type_of(report: ArtifactReport) -> str:
    """What a runner groups by: the rule that failed, or the verdict."""
    worst = _worst_finding(report)
    if report.verdict is Verdict.INCONCLUSIVE or worst is None:
        return report.verdict.value
    return worst.rule_id


def _detail(report: ArtifactReport, catalog: Catalog) -> str:
    """Every finding, in full, for whoever opens the failed test.

    The evidence is reproduced as the canonical JSON the report carries rather
    than reworded, so what a CI shows and what `--json` shows are the same
    values.
    """
    lines = [
        f"verdict:   {report.verdict.value}",
        f"format:    {report.detected_format} ({report.format_confidence})",
        f"sha256:    {report.sha256}",
        f"size:      {report.size_bytes} bytes",
        f"fully_read: {str(bool(report.metadata.get('fully_read', False))).lower()}",
        "",
    ]
    for finding in sorted(report.findings, key=lambda item: -item.severity.rank):
        lines.append(f"[{finding.severity.value}] {finding.rule_id}  {catalog.rule(finding.rule_id)}")
        lines.append(f"    location: {finding.location}")
        if finding.evidence:
            lines.append(f"    evidence: {_evidence(finding.evidence)}")
    for error in report.inspector_errors:
        lines.append(f"[inspector error] {error}")
    return "\n".join(lines) + "\n"


def _evidence(evidence: dict[str, Any]) -> str:
    return json.dumps(evidence, sort_keys=True, ensure_ascii=False)


def _system_out(report: ArtifactReport) -> str:
    return (
        f"format: {report.detected_format} ({report.format_confidence})\n"
        f"sha256: {report.sha256}\n"
        f"findings: {len(report.findings)}\n"
    )
