"""Article 50 controls: the transparency duties, decided from bytes.

Design note D-61. Article 50 is four separate duties on two different actors,
and most tooling collapses them into one row called "transparency". They are
kept apart here because they bind different people and are satisfied by
different artifacts:

  50(1)  provider of a system that interacts with natural persons: the person
         must be informed they are dealing with an AI system, unless it is
         obvious to a reasonably observant person.
  50(2)  provider of a system generating synthetic audio, image, video or
         text: the output is marked in a machine-readable format and
         detectable as artificially generated or manipulated.
  50(3)  deployer of an emotion recognition or biometric categorisation
         system: inform the people exposed to it.
  50(4)  deployer of a system producing deep fakes: disclose that the content
         is artificially generated or manipulated.

Two of the four are decidable from an artifact, and those are here.
50(2) and 50(4) both come down to "is the content marked", which
`actaira.marking` answers deterministically, and 50(1) comes down to "does
the system's own surface say so", which is decidable over a transcript or a
system prompt the operator supplies. 50(3) is a notice given to people in a
physical or product context and lives on the judged tier instead.

Design note D-62, on the boundary that keeps these controls honest. A control
that reads twelve files and finds all twelve marked has established that
twelve files are marked. Article 50(2) binds the provider for the output of
the system, which is a set this control never sees and cannot enumerate. So
`covers` says "the files supplied" and `does_not_cover` says "output not
supplied to this run", in the result itself, every time. The obligation is
never reported as met; what is reported is what was observed.

Design note D-63, the grace period, which is a real trap. Article 111(4),
inserted by the Digital Omnibus, gives systems placed on the market before
2 August 2026 until 2 December 2026 for the 50(2) marking duty. A control
that ignored this would report a true fact ("unmarked") that leads to a false
conclusion ("in breach"). The control reads the date under assessment and the
operator's declared placing-on-the-market date, and when the grace applies it
returns NOT_APPLICABLE with the grace named, rather than NOT_SATISFIED. The
date is an argument, never the system clock, for the same reason the
governance clock takes one: an answer that changes tomorrow without the input
changing is not reproducible and cannot be tested.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

from ..io_budget import read_text_at_most
from ..marking import MarkingState, detect
from ..model import Finding, Severity
from . import registry
from .model import Control, ControlResult, Method, Outcome, Target, inconclusive

# Containers whose marking this repository can actually read. A file outside
# this set is counted as `unreadable`, never as unmarked: see D-60.
READABLE_CONTAINERS = ("png", "jpeg", "bmff", "webp", "pdf")
MEDIA_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff",
    ".mp4", ".mov", ".webm", ".m4v", ".pdf", ".mp3", ".wav", ".flac",
)

# Article 111(4): the transitional for the 50(2) marking duty.
ART_50_2_GRACE_UNTIL = date(2026, 12, 2)
CHAPTER_IV_APPLIES_FROM = date(2026, 8, 2)


def _media_files(target: Target) -> tuple[Path, ...]:
    """The files a marking control should look at.

    Selection is by suffix, and that is a compromise worth naming: content
    sniffing would be more faithful, and it would also mean opening every file
    in a directory that may hold gigabytes of weights. The suffix list decides
    what to *open*; `marking.detect` then decides what the file *is* from its
    magic number, so a mislabelled file is still classified by content. What a
    wrong suffix costs is that a marked file with no extension is not looked
    at, and that shows up as a smaller `inspected` list rather than as a wrong
    answer.
    """
    declared = target.declared("outputs", default=None)
    if isinstance(declared, str):
        declared = [declared]
    if isinstance(declared, list) and declared:
        paths: list[Path] = []
        for entry in declared:
            candidate = target.root / str(entry)
            if candidate.is_dir():
                paths.extend(sorted(p for p in candidate.rglob("*") if p.is_file()))
            elif candidate.is_file():
                paths.append(candidate)
        return tuple(paths)
    return tuple(p for p in target.files if p.suffix.lower() in MEDIA_SUFFIXES)


def _assessment_date(target: Target) -> date:
    raw = target.declared("assessment_date", default=None)
    if isinstance(raw, str):
        try:
            return date.fromisoformat(raw)
        except ValueError:
            pass
    return CHAPTER_IV_APPLIES_FROM


def _grace_applies(target: Target, on: date) -> tuple[bool, str]:
    """Article 111(4), and the two declarations it depends on."""
    if on >= ART_50_2_GRACE_UNTIL:
        return False, ""
    placed_raw = target.declared("placed_on_market", default=None)
    if not isinstance(placed_raw, str):
        return False, ""
    try:
        placed = date.fromisoformat(placed_raw)
    except ValueError:
        return False, ""
    if placed < CHAPTER_IV_APPLIES_FROM:
        return True, (
            "Art. 111(4): a system placed on the market before 2 August 2026 has "
            "until 2 December 2026 for the Art. 50(2) marking duty"
        )
    return False, ""


def _marking_outcome(
    control_id: str,
    obligation_ids: tuple[str, ...],
    target: Target,
) -> ControlResult:
    # The boundary of the answer is attached by the engine from the message
    # catalogue, in the caller's language. See design note D-45: a control that
    # had to remember it forgot it on every inconclusive path.
    files = _media_files(target)
    if not files:
        return inconclusive(
            control_id,
            obligation_ids,
            Method.DETERMINISTIC,
            "no_output_files_supplied",
            hint=(
                "point the control at generated output, either by putting it under the "
                "target directory or by naming it in actaira.yaml under `outputs`"
            ),
        )

    on = _assessment_date(target)
    graced, grace_reason = _grace_applies(target, on)

    marked: list[str] = []
    unmarked: list[str] = []
    other: list[str] = []
    unreadable: list[str] = []
    reports: list[dict[str, Any]] = []
    findings: list[Finding] = []

    for path in files:
        report = detect(path)
        reports.append(report.to_dict())
        if report.state is MarkingState.MARKED:
            marked.append(report.path)
        elif report.state is MarkingState.MARKED_OTHER:
            other.append(report.path)
            findings.append(
                Finding(
                    rule_id="ACT-MRK-002",
                    severity=Severity.MEDIUM,
                    location=report.path,
                    evidence={"terms": list(report.terms), "reason": report.reason},
                )
            )
        elif report.state is MarkingState.UNMARKED:
            unmarked.append(report.path)
            findings.append(
                Finding(
                    rule_id="ACT-MRK-001",
                    severity=Severity.HIGH if not graced else Severity.INFO,
                    location=report.path,
                    evidence={
                        "container": report.container,
                        "mechanisms_searched": [m.value for m in report.mechanisms_searched],
                        "grace": grace_reason or None,
                    },
                )
            )
        else:
            unreadable.append(report.path)
            findings.append(
                Finding(
                    rule_id="ACT-MRK-003",
                    severity=Severity.MEDIUM,
                    location=report.path,
                    evidence={"container": report.container, "reason": report.reason},
                )
            )

    evidence = {
        "assessed_on": on.isoformat(),
        "files_read": len(files),
        "marked": marked,
        "marked_but_not_synthetic": other,
        "unmarked": unmarked,
        "unreadable": unreadable,
        "grace_applied": bool(graced),
        "grace_reason": grace_reason,
        "reports": reports,
    }

    if graced and unmarked:
        outcome = Outcome.NOT_APPLICABLE
    elif unmarked or other:
        outcome = Outcome.NOT_SATISFIED
    elif unreadable and not marked:
        outcome = Outcome.INCONCLUSIVE
    elif unreadable:
        # Some files marked, some unreadable. Reporting SATISFIED here would be
        # the exact failure this repository keeps finding in other tools: a
        # partial read presented as a clean result.
        outcome = Outcome.INCONCLUSIVE
    else:
        outcome = Outcome.SATISFIED

    return ControlResult(
        control_id=control_id,
        obligation_ids=obligation_ids,
        outcome=outcome,
        method=Method.DETERMINISTIC,
        evidence=evidence,
        findings=tuple(findings),
        inspected=tuple(r["path"] for r in reports),
        abstained_on=tuple(unreadable),
    )


def _run_50_2(target: Target) -> ControlResult:
    return _marking_outcome(
        "ACT-C-50-2-MARK",
        ("AIA-50-2",),
        target,
    )


def _run_50_4(target: Target) -> ControlResult:
    return _marking_outcome(
        "ACT-C-50-4-DEEPFAKE",
        ("AIA-50-4",),
        target,
    )


# ---------------------------------------------------------------------------
# 50(1): the system tells the person it is an AI system
# ---------------------------------------------------------------------------
DISCLOSURE_MARKERS_EN = (
    "ai assistant", "automated assistant", "i am an ai", "i'm an ai", "am an ai",
    "artificial intelligence", "ai system", "generated by ai", "virtual assistant",
    "chatbot", "not a human", "automated system",
)
DISCLOSURE_MARKERS_ES = (
    "asistente de ia", "soy una ia", "inteligencia artificial", "sistema de ia",
    "asistente virtual", "no soy una persona", "no soy humano", "generado por ia",
    "sistema automatizado",
)
DISCLOSURE_FILES = ("system_prompt", "disclosure", "greeting", "transcript", "welcome")
MAX_DISCLOSURE_BYTES = 1 << 20


def _run_50_1(target: Target) -> ControlResult:
    """Look for the disclosure in the surface the operator points at.

    Design note D-64. This is a lexical check and it is deliberately not more
    than that. A model could be asked "does this greeting disclose that the
    user is talking to an AI", and it would be right more often on unusual
    phrasings. It would also make a deterministic obligation depend on a model,
    and turn a check that reproduces byte for byte into one that has an
    abstention rate. The marker list is published in the evidence of every
    result, so a reader can see exactly what was searched for and add to it;
    a hidden heuristic would be the worse half of both designs.

    The lexical route has a real cost and it is stated rather than hidden: a
    disclosure this list does not phrase-match reads as absent. That is why a
    negative is NOT_SATISFIED with the searched terms attached, and why the
    judged tier exists for the obligations where phrasing is the whole
    question.
    """
    control_id = "ACT-C-50-1-DISCLOSE"
    obligations = ("AIA-50-1",)

    declared = target.declared("interaction_surface", default=None)
    candidates: list[Path] = []
    if isinstance(declared, str):
        declared = [declared]
    if isinstance(declared, list):
        for entry in declared:
            candidate = target.root / str(entry)
            if candidate.is_file():
                candidates.append(candidate)
    if not candidates:
        candidates = [
            p
            for p in target.files
            if p.suffix.lower() in (".txt", ".md", ".json", ".yaml", ".yml")
            and any(token in p.stem.lower() for token in DISCLOSURE_FILES)
        ]

    if not candidates:
        return inconclusive(
            control_id,
            obligations,
            Method.DETERMINISTIC,
            "no_interaction_surface_supplied",
            hint=(
                "name the greeting, system prompt or transcript in actaira.yaml under "
                "`interaction_surface`, or place a file whose name contains one of "
                f"{list(DISCLOSURE_FILES)}"
            ),
        )

    markers = DISCLOSURE_MARKERS_EN + DISCLOSURE_MARKERS_ES
    found: dict[str, list[str]] = {}
    silent: list[str] = []
    for path in candidates:
        try:
            # D-160: the slice ran after the whole file was in memory.
            text, _ = read_text_at_most(path, MAX_DISCLOSURE_BYTES)
            text = text.lower()
        except OSError:
            continue
        hits = [m for m in markers if m in text]
        if hits:
            found[path.name] = hits
        else:
            silent.append(path.name)

    findings = tuple(
        Finding(
            rule_id="ACT-MRK-004",
            severity=Severity.HIGH,
            location=name,
            evidence={"markers_searched": len(markers)},
        )
        for name in silent
    )
    outcome = Outcome.SATISFIED if found and not silent else Outcome.NOT_SATISFIED
    return ControlResult(
        control_id=control_id,
        obligation_ids=obligations,
        outcome=outcome,
        method=Method.DETERMINISTIC,
        evidence={
            "surfaces_read": [p.name for p in candidates],
            "disclosing": found,
            "silent": silent,
            "markers_searched": list(markers),
        },
        findings=findings,
        inspected=tuple(p.name for p in candidates),
    )


# ---------------------------------------------------------------------------
# The robustness measurement, exposed as a control under Article 15
# ---------------------------------------------------------------------------
def _run_15_robustness(target: Target) -> ControlResult:
    """Does the marking survive what the content will actually go through?

    Design note D-65. Article 15 asks for accuracy, robustness and
    cybersecurity, and a marking that dissolves the first time an image is
    re-encoded is not a robust implementation of Art. 50(2) whatever the file
    says today. This control re-runs the transformation battery from
    `evals/marking/` over the target's own files and reports how many
    survived, which is the difference between "we mark our output" and "our
    marking is still there when the user sees it".

    It needs Pillow, which is a development dependency and not a runtime one.
    A missing Pillow yields INCONCLUSIVE naming the dependency, never a pass:
    the whole point of the control is that an unmeasured claim is not evidence.
    """
    control_id = "ACT-C-15-MARK-ROBUSTNESS"
    obligations = ("AIA-15",)
    try:
        from ..evals_support.robustness import survival_matrix  # noqa: PLC0415
    except ImportError:
        return inconclusive(
            control_id,
            obligations,
            Method.DETERMINISTIC,
            "robustness_battery_unavailable",
            needs="Pillow (dev extra), for the transformation battery",
        )

    files = [p for p in _media_files(target) if p.suffix.lower() in (".png", ".jpg", ".jpeg")]
    if not files:
        return inconclusive(
            control_id, obligations, Method.DETERMINISTIC, "no_image_output_supplied"
        )

    matrix = survival_matrix(files)
    survived = matrix["survived"]
    total = matrix["trials"]
    findings = tuple(
        Finding(
            rule_id="ACT-MRK-005",
            severity=Severity.MEDIUM,
            location=name,
            evidence={"transformation": transformation},
        )
        for name, transformation in matrix["losses"]
    )
    if total == 0:
        outcome = Outcome.INCONCLUSIVE
    elif survived == total:
        outcome = Outcome.SATISFIED
    else:
        outcome = Outcome.NOT_SATISFIED
    return ControlResult(
        control_id=control_id,
        obligation_ids=obligations,
        outcome=outcome,
        method=Method.DETERMINISTIC,
        evidence=matrix,
        findings=findings,
        inspected=tuple(p.name for p in files),
    )


registry.register(
    Control(
        id="ACT-C-50-2-MARK",
        obligation_ids=("AIA-50-2",),
        method=Method.DETERMINISTIC,
        run=_run_50_2,
        summary_key="controls.ACT-C-50-2-MARK",
    )
)
registry.register(
    Control(
        id="ACT-C-50-4-DEEPFAKE",
        obligation_ids=("AIA-50-4",),
        method=Method.DETERMINISTIC,
        run=_run_50_4,
        summary_key="controls.ACT-C-50-4-DEEPFAKE",
    )
)
registry.register(
    Control(
        id="ACT-C-50-1-DISCLOSE",
        obligation_ids=("AIA-50-1",),
        method=Method.DETERMINISTIC,
        run=_run_50_1,
        summary_key="controls.ACT-C-50-1-DISCLOSE",
    )
)
registry.register(
    Control(
        id="ACT-C-15-MARK-ROBUSTNESS",
        obligation_ids=("AIA-15",),
        method=Method.DETERMINISTIC,
        run=_run_15_robustness,
        summary_key="controls.ACT-C-15-MARK-ROBUSTNESS",
    )
)
