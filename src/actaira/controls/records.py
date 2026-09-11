"""Deterministic controls over record-keeping and artifact robustness.

Design note D-52, on the difference between checking a record and checking
what the record is about.

Article 12 asks that a high-risk system technically allow the automatic
recording of events over its lifetime, and that the log be appropriate to the
intended purpose. Nothing readable from a directory of files can establish
that. What *is* readable is whether the log entries that exist carry the
fields the article names, and that is a smaller claim by a distance worth
stating in the output rather than in a footnote: `ACT-C-12-LOG` reports the
FORM of the record. It cannot see an event that was never written, it cannot
tell a timestamp from a plausible-looking lie, and a log the operator
generated an hour ago with a script looks exactly like one written by the
system over a year. `covers` and `does_not_cover` on every result say so, and
they are part of the result rather than of the documentation because the
result is what gets pasted into somebody's evidence folder.

The field-name problem, and the trade-off taken. A log written by a real
system does not have a column called `system_identifier`; it has `svc`, or
`instance`, or `deployment_id`. A control that demands one exact spelling
reports NOT_SATISFIED on every real log in existence, and a control that is
always red is a control that gets switched off, which is strictly worse than
one that is slightly generous. So each required field has a list of accepted
names, matched case-insensitively and ignoring separators, and the list is
copied into the evidence of every result so that a reader can see exactly
what was accepted rather than trusting that the match was sensible. An
operator whose columns are named something else declares the mapping in
`actaira.yaml`, and that declaration surfaces as `declared_field_names`,
labelled, because it is a statement about their schema and not a measurement.

Design note D-53, on the precedence between an absence observed and a
remainder unread.

These controls can hit both at once: a log file with a line missing its
timestamp and a second file that would not decode, or an artifact with a
gadget in it next to one that hit the read budget. The rule taken, and it is
the opposite of the usual conservatism: an observed absence wins over an
unread remainder, so the outcome is NOT_SATISFIED and the part that was not
read is recorded in `abstained_on`. The reasoning is that D-40's INCONCLUSIVE
means "I could not decide", and here the control did decide - it saw an entry
without a timestamp, and reading the rest of the file cannot unsee it. The
opposite rule would let one unreadable byte anywhere in a target suppress
every real finding in it, which is a suppression mechanism an attacker can
trigger on purpose by making one file unparseable.

Design note D-54, on `ACT-C-15-ARTIFACT` being a bridge and not a new scanner.

The scanner is the part of this project that has evals, a corpus, a
benchmark against three other tools and published numbers. A control that
re-implemented any of that judgement would be a second opinion with none of
the evidence behind it. So this control runs `inspect.inspect_artifact` and
translates: artifacts in, findings up, outcome from the severity threshold
the rest of the tool already uses. It emits no rule identifier of its own -
the findings it carries are the scanner's, with the rule ids that already
have text in both message catalogues (D-07) - because inventing a rule id
here would put an untranslated identifier in front of a reader for no
information gained: the outcome and the artifact rows already say everything
a new rule would have said.

And the scope, which is where most of Article 15 is: the article covers
accuracy, robustness and cybersecurity of the SYSTEM. Accuracy metrics,
resilience to faults, resistance to adversarial input and data poisoning,
fallback plans. This control reads weight files. It answers one third of one
of those words, and `does_not_cover` says which third.
"""
from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..inspect import inspect_artifact
from ..model import ArtifactReport, Finding, Severity
from . import registry
from .model import Control, ControlResult, Method, Outcome, Target, inconclusive

# ---------------------------------------------------------------------------
# Budgets. Every one of them exists so that a hostile or merely enormous
# target cannot turn a control run into an unbounded read, and every one of
# them is reported when it bites: a budget that silently truncates is how a
# scan of 600 shards reports clean on the 519 it managed to open.
# ---------------------------------------------------------------------------
MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_ENTRIES_PER_LOG = 5_000
MAX_LOG_FILES = 64
MAX_ARTIFACTS = 256
MAX_EXAMPLES = 10

LOG_SUFFIXES = frozenset({".jsonl", ".ndjson", ".log", ".csv", ".tsv"})
LOG_DIRECTORY_NAMES = frozenset({"logs", "log", "audit", "audit-logs", "audit_logs"})

# The three things Article 12 names that a line of a log can actually carry,
# and the spellings accepted for each. Names are compared after lowercasing
# and dropping every character that is not a letter or a digit, so `@timestamp`,
# `Timestamp` and `time_stamp` are one name. See design note D-52 for why this
# list is generous and why it is published in the evidence.
REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    # Art. 12(3)(a): the period of each use, which starts with a moment.
    "timestamp": (
        "timestamp", "time", "ts", "datetime", "date", "eventtime", "occurredat",
        "loggedat", "starttime", "startedat", "periodstart",
    ),
    # Art. 12(1) and 12(2): the record has to be attributable to a system.
    "system_identifier": (
        "systemid", "system", "systemidentifier", "systemname", "aisystemid",
        "instanceid", "deploymentid", "modelid", "serviceid", "componentid",
    ),
    # Art. 12(3)(b) and (c): the reference data checked against and the input
    # for which a match was returned.
    "reference_input_data": (
        "inputref", "inputreference", "inputdata", "inputdataref", "inputdigest",
        "inputhash", "inputid", "referencedata", "referencedatabase", "reference",
    ),
}

COVERS_LOG = (
    "the form of the log entries that were read: every entry carries a moment, an "
    "identifier of the system, and a reference to the input data, under one of the "
    "names listed in evidence.accepted_names."
)
DOES_NOT_COVER_LOG = (
    "whether the log is complete, whether anything in it is true, whether the "
    "recording is automatic rather than assembled afterwards, whether the retention "
    "period of Art. 12(1) is met, and the rest of Art. 12(3), including the period of "
    "each use and the identification of the natural persons who verified the results. "
    "An event that was never written leaves nothing here to read."
)
COVERS_ARTIFACT = (
    "the artifact files that were read: none of them carries a finding this tool rates "
    "high or critical, which is its threshold for a path to code execution or a "
    "structural defect."
)
DOES_NOT_COVER_ARTIFACT = (
    "Art. 15 is about the accuracy, robustness and cybersecurity of the SYSTEM: "
    "declared accuracy metrics, resilience to errors, faults and inconsistencies, "
    "resistance to adversarial manipulation and to data poisoning, and backup or "
    "fail-safe plans. None of that is readable from a weight file. This control looks "
    "at the cybersecurity of the artifact and at nothing else."
)


# ---------------------------------------------------------------------------
# Locating what to read
# ---------------------------------------------------------------------------

def _declared_paths(target: Target, *keys: str) -> list[str]:
    """Paths the operator declared, under `key` or `key.paths`, as strings.

    A bare string is accepted as a one-element list, and not only for
    convenience: the YAML subset the engine parses (`engine._mini_yaml`) does
    not currently accept a block sequence, so `logs: "audit/*.jsonl"` is the
    only way to say this in `actaira.yaml`. A JSON declaration carries a real
    list. Accepting both here means neither file format silently declares
    nothing.
    """
    for key in keys:
        value = target.declared(key)
        if isinstance(value, dict):
            value = value.get("paths")
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(item) for item in value if item]
    return []


def _resolve(target: Target, patterns: Sequence[str]) -> list[Path]:
    """Turn declared paths and globs into files inside the target.

    The defence here is against the declaration file, not against the
    operator. `actaira.yaml` is read out of the target directory, so on a
    target that came from somewhere else it is attacker-controlled input, and
    an entry of `../../../etc/shadow` would otherwise make this tool read a
    file outside the directory it was pointed at and copy what it found into
    an evidence document. Everything is resolved and anything that lands
    outside the target root is dropped.
    """
    root = target.root.resolve()
    found: list[Path] = []
    for pattern in patterns:
        if any(ch in pattern for ch in "*?["):
            try:
                candidates = sorted(root.glob(pattern))
            except (ValueError, NotImplementedError, OSError):
                # An absolute pattern, or one with `..` in it, is refused by
                # pathlib on some versions and silently walks upwards on
                # others. Either way it is a declaration asking to read
                # outside the target, which is the thing this function exists
                # to refuse, so it yields nothing rather than raising.
                continue
        else:
            candidates = [root / pattern]
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            if not resolved.is_file():
                continue
            if root != resolved and root not in resolved.parents:
                continue
            if resolved not in found:
                found.append(resolved)
    return found


def discover_logs(target: Target) -> tuple[list[Path], bool]:
    """The log files to read, and whether the declaration named them.

    Returns (paths, declared). The flag is carried into the evidence because
    "the operator told me where the logs are" and "I found some files that
    look like logs" are different provenances for the same list, and a
    control that could not tell them apart would report the second as if it
    were the first.
    """
    declared = _declared_paths(target, "logs", "log")
    if declared:
        return _resolve(target, declared)[:MAX_LOG_FILES], True
    found = [
        path
        for path in target.files
        if path.suffix.lower() in LOG_SUFFIXES
        or any(part.lower() in LOG_DIRECTORY_NAMES for part in path.parts[:-1])
    ]
    return sorted(set(found))[:MAX_LOG_FILES], False


def discover_artifacts(target: Target) -> tuple[list[Path], bool, bool]:
    """The model artifacts to inspect: (paths, declared, truncated).

    Undeclared discovery sniffs every file and keeps the ones whose bytes are
    a format this tool knows, which is D-06 applied one layer up: selecting
    candidates by extension would let an attacker keep an artifact out of the
    scan by renaming it, and that is the same trick the extension check
    inside the scanner exists to catch.

    Shared with `controls/documentation.py`, which needs the same inventory to
    draft an Annex IV. Two copies of a discovery rule drift, and a drafted
    document that lists different artifacts from the control that inspected
    them would be worse than either.
    """
    from ..formats import detect  # local: keeps the control modules import-light

    declared = _declared_paths(target, "artifacts", "models", "artefacts")
    if declared:
        resolved = _resolve(target, declared)
        return resolved[:MAX_ARTIFACTS], True, len(resolved) > MAX_ARTIFACTS

    found: list[Path] = []
    for path in target.files:
        try:
            detected, _confidence = detect.sniff(path)
        except OSError:
            continue
        if detected not in ("unknown", "empty"):
            found.append(path)
    return sorted(found)[:MAX_ARTIFACTS], False, len(found) > MAX_ARTIFACTS


# ---------------------------------------------------------------------------
# Reading a log
# ---------------------------------------------------------------------------

@dataclass
class LogReading:
    """One log file, as far as it could be read."""

    path: str
    format: str = "unrecognised"
    entries: list[dict[str, Any]] = field(default_factory=list)
    unreadable_lines: int = 0
    truncated: bool = False
    error: str = ""

    @property
    def fully_read(self) -> bool:
        return not self.truncated and not self.error and self.unreadable_lines == 0


def _normalise(name: str) -> str:
    return "".join(ch for ch in name.lower() if ch.isalnum())


def _accepted_names(target: Target) -> dict[str, tuple[str, ...]]:
    """The accepted spellings, plus anything the operator declared.

    A declared name is added to the list, never substituted for it: an
    operator who declares `logs.field_names.timestamp: when` is telling us
    what their column is called, which is a fact about their schema we cannot
    read anywhere else. What they are not doing is deciding what counts as a
    timestamp, so the built-in names stay in force alongside.
    """
    accepted = {name: tuple(_normalise(n) for n in names) for name, names in REQUIRED_FIELDS.items()}
    declared = target.declared("logs", "field_names")
    if isinstance(declared, dict):
        for field_name, column in declared.items():
            key = _normalise(field_name)
            for canonical in accepted:
                if _normalise(canonical) == key and isinstance(column, str):
                    accepted[canonical] = (*accepted[canonical], _normalise(column))
    return accepted


def _read_log(path: Path) -> LogReading:
    """Read one log file as JSON Lines or CSV, within the budget.

    Format is decided from the content and not from the extension, on D-06's
    argument: a file called `audit.csv` whose lines are JSON objects is a
    JSON Lines log, and reading it as CSV would report every field missing,
    which is a false NOT_SATISFIED and the most expensive kind of wrong
    answer a compliance control can give.
    """
    reading = LogReading(path=str(path))
    try:
        with path.open("rb") as handle:
            blob = handle.read(MAX_LOG_BYTES + 1)
    except OSError as exc:
        reading.error = f"{type(exc).__name__}: {exc}"
        return reading

    if len(blob) > MAX_LOG_BYTES:
        blob = blob[:MAX_LOG_BYTES]
        reading.truncated = True
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError as exc:
        reading.error = f"not utf-8 text: {exc}"
        return reading

    lines = text.splitlines()
    if reading.truncated and lines:
        # The budget cut somewhere inside the last line; a half line is not
        # an entry and counting it as one would invent a missing field.
        lines = lines[:-1]
    body = [line for line in lines if line.strip()]
    if not body:
        reading.error = "empty"
        return reading

    if body[0].lstrip().startswith("{"):
        reading.format = "jsonl"
        _read_jsonl(body, reading)
        return reading
    if any(sep in body[0] for sep in (",", ";", "\t")):
        reading.format = "csv"
        _read_csv(body, reading)
        return reading
    reading.error = "neither json lines nor delimited text"
    return reading


def _read_jsonl(body: list[str], reading: LogReading) -> None:
    for line in body:
        if len(reading.entries) >= MAX_ENTRIES_PER_LOG:
            reading.truncated = True
            return
        try:
            parsed = json.loads(line)
        except ValueError:
            reading.unreadable_lines += 1
            continue
        if isinstance(parsed, dict):
            reading.entries.append(parsed)
        else:
            reading.unreadable_lines += 1


def _read_csv(body: list[str], reading: LogReading) -> None:
    try:
        dialect: Any = csv.Sniffer().sniff(body[0])
    except csv.Error:
        dialect = csv.excel
    rows = csv.reader(body, dialect)
    try:
        header = next(rows)
    except (StopIteration, csv.Error):
        reading.error = "no header row"
        return
    for row in rows:
        if len(reading.entries) >= MAX_ENTRIES_PER_LOG:
            reading.truncated = True
            return
        if not any(cell.strip() for cell in row):
            continue
        if len(row) != len(header):
            # A row with a different width than the header cannot be mapped
            # onto it without guessing which column is missing, and guessing
            # here would decide the outcome.
            reading.unreadable_lines += 1
            continue
        reading.entries.append(dict(zip(header, row, strict=True)))


def _missing_fields(entry: dict[str, Any], accepted: dict[str, tuple[str, ...]]) -> list[str]:
    """Which required fields this entry does not carry, with a value.

    A key present and empty counts as absent. A log with a `timestamp` column
    that is blank on every row satisfies a key-presence check and records
    nothing, and the whole point of the article is what got recorded.
    """
    present = {_normalise(str(key)): value for key, value in entry.items()}
    missing: list[str] = []
    for canonical, names in accepted.items():
        value = next((present[name] for name in names if name in present), None)
        if value is None or (isinstance(value, str) and not value.strip()):
            missing.append(canonical)
    return missing


# ---------------------------------------------------------------------------
# ACT-C-12-LOG
# ---------------------------------------------------------------------------

def run_log_control(target: Target) -> ControlResult:
    paths, declared = discover_logs(target)
    accepted = _accepted_names(target)
    published = {name: list(names) for name, names in accepted.items()}

    if not paths:
        return inconclusive(
            LOG_CONTROL_ID,
            ("AIA-12",),
            Method.DETERMINISTIC,
            "no_logs_found",
            searched=str(target.root),
            declared_logs=declared,
            accepted_names=published,
            hint="declare the log files under `logs:` in actaira.yaml",
        )

    readings = [_read_log(path) for path in paths]
    entries_read = sum(len(reading.entries) for reading in readings)
    if entries_read == 0:
        return inconclusive(
            LOG_CONTROL_ID,
            ("AIA-12",),
            Method.DETERMINISTIC,
            "logs_unreadable",
            accepted_names=published,
            logs=[_log_row(reading, {}) for reading in readings],
        )

    per_file: list[dict[str, Any]] = []
    examples: list[dict[str, Any]] = []
    missing_by_field = {name: 0 for name in REQUIRED_FIELDS}
    entries_missing = 0

    for reading in readings:
        file_missing = 0
        for position, entry in enumerate(reading.entries, start=1):
            missing = _missing_fields(entry, accepted)
            if not missing:
                continue
            file_missing += 1
            entries_missing += 1
            for name in missing:
                missing_by_field[name] += 1
            if len(examples) < MAX_EXAMPLES:
                examples.append({"path": reading.path, "entry": position, "missing": missing})
        per_file.append(_log_row(reading, {"entries_missing_fields": file_missing}))

    not_fully_read = [reading.path for reading in readings if not reading.fully_read]
    evidence: dict[str, Any] = {
        "logs": per_file,
        "entries_read": entries_read,
        "entries_missing_fields": entries_missing,
        "missing_by_field": missing_by_field,
        "examples": examples,
        "accepted_names": published,
        "declared_logs": declared,
    }
    declared_names = target.declared("logs", "field_names")
    if isinstance(declared_names, dict):
        evidence["declared_field_names"] = declared_names

    if entries_missing:
        # Design note D-53: an entry observed without its fields is a decision
        # the control made, and an unreadable line elsewhere does not undo it.
        outcome = Outcome.NOT_SATISFIED
    elif not_fully_read:
        outcome = Outcome.INCONCLUSIVE
        evidence["reason"] = "logs_partially_read"
    else:
        outcome = Outcome.SATISFIED

    return ControlResult(
        control_id=LOG_CONTROL_ID,
        obligation_ids=("AIA-12",),
        outcome=outcome,
        method=Method.DETERMINISTIC,
        evidence=evidence,
        covers=COVERS_LOG,
        does_not_cover=DOES_NOT_COVER_LOG,
        inspected=tuple(reading.path for reading in readings),
        abstained_on=tuple(not_fully_read),
    )


def _log_row(reading: LogReading, extra: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "path": reading.path,
        "format": reading.format,
        "entries_read": len(reading.entries),
        "unreadable_lines": reading.unreadable_lines,
        "truncated": reading.truncated,
        "fully_read": reading.fully_read,
    }
    if reading.error:
        row["error"] = reading.error
    row.update(extra)
    return row


# ---------------------------------------------------------------------------
# ACT-C-15-ARTIFACT
# ---------------------------------------------------------------------------

def _serious(findings: Iterable[Finding]) -> list[Finding]:
    return [f for f in findings if f.severity.rank >= Severity.HIGH.rank]


def _artifact_row(report: ArtifactReport, serious: Sequence[Finding]) -> dict[str, Any]:
    return {
        "path": report.path,
        "sha256": report.sha256,
        "format": report.detected_format,
        "format_confidence": report.format_confidence,
        "verdict": report.verdict.value,
        "fully_read": bool(report.metadata.get("fully_read", False)),
        "max_severity": report.max_severity.value if report.max_severity else None,
        "serious_findings": sorted({finding.rule_id for finding in serious}),
        "inspector_errors": list(report.inspector_errors),
    }


def run_artifact_control(target: Target) -> ControlResult:
    paths, declared, truncated = discover_artifacts(target)
    if not paths:
        return inconclusive(
            ARTIFACT_CONTROL_ID,
            ("AIA-15",),
            Method.DETERMINISTIC,
            "no_artifacts_found",
            searched=str(target.root),
            declared_artifacts=declared,
            hint="declare the artifacts under `artifacts:` in actaira.yaml",
        )

    policy = target.declared("scan", "policy", default="strict")
    if policy not in ("strict", "known-bad"):
        policy = "strict"

    rows: list[dict[str, Any]] = []
    findings: list[Finding] = []
    unread: list[str] = []
    for path in paths:
        report = inspect_artifact(path, scan_policy=str(policy), fail_on=Severity.HIGH)
        serious = _serious(report.findings)
        findings.extend(serious)
        rows.append(_artifact_row(report, serious))
        if not report.metadata.get("fully_read", False) or report.inspector_errors:
            unread.append(report.path)

    evidence: dict[str, Any] = {
        "artifacts": rows,
        "artifacts_inspected": len(rows),
        "artifacts_with_serious_findings": sum(1 for row in rows if row["serious_findings"]),
        "declared_artifacts": declared,
        "threshold": Severity.HIGH.value,
        "scan_policy": policy,
        # Labelled, because the policy is the operator's choice and it changes
        # what counts as a finding: a result that does not carry the setting it
        # was computed under is not reproducible.
        "scan_policy_declared": bool(target.declared("scan", "policy")),
    }
    if truncated:
        evidence["truncated_at"] = MAX_ARTIFACTS

    if findings:
        outcome = Outcome.NOT_SATISFIED
    elif unread or truncated:
        outcome = Outcome.INCONCLUSIVE
        evidence["reason"] = "artifacts_partially_read"
    else:
        outcome = Outcome.SATISFIED

    return ControlResult(
        control_id=ARTIFACT_CONTROL_ID,
        obligation_ids=("AIA-15",),
        outcome=outcome,
        method=Method.DETERMINISTIC,
        evidence=evidence,
        # The scanner's own findings, carried up rather than restated. Their
        # rule ids already have text in both catalogues; see design note D-54.
        findings=tuple(findings),
        covers=COVERS_ARTIFACT,
        does_not_cover=DOES_NOT_COVER_ARTIFACT,
        inspected=tuple(row["path"] for row in rows),
        abstained_on=tuple(unread),
    )


LOG_CONTROL_ID = "ACT-C-12-LOG"
ARTIFACT_CONTROL_ID = "ACT-C-15-ARTIFACT"

LOG_CONTROL = registry.register(
    Control(
        id=LOG_CONTROL_ID,
        obligation_ids=("AIA-12",),
        method=Method.DETERMINISTIC,
        run=run_log_control,
    )
)

ARTIFACT_CONTROL = registry.register(
    Control(
        id=ARTIFACT_CONTROL_ID,
        obligation_ids=("AIA-15",),
        method=Method.DETERMINISTIC,
        run=run_artifact_control,
    )
)

CONTROLS: tuple[Control, ...] = (LOG_CONTROL, ARTIFACT_CONTROL)
