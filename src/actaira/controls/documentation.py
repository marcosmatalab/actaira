"""Controls that draft a document instead of judging one.

Design note D-55, and the three words that are the whole product here.

Article 11 and Annex IV, and Article 53(1) with Annexes XI and XII, ask a
provider for a technical file. Most of what they ask for is not in any
artifact: intended purpose, design rationale, human oversight measures, the
declaration of conformity. A tool that generated those sections would be
generating text that nobody measured, which is the failure mode this project
was built against. A tool that refused to touch the file at all would leave
the provider with a blank page, which is not better, only quieter.

So these controls produce the skeleton and mark every point with where its
content came from:

  filled_from_evidence   Actaira parsed bytes and this point is answered from
                         them. Reserved: a point is only ever marked this way
                         when the evidence really answers the question the
                         Annex asks, and every filled point carries a `note`
                         saying which part of the ask the evidence covers and
                         which part it does not.
  declared_by_operator   the operator wrote it in `actaira.yaml`. It is a
                         statement, it is labelled as one everywhere it
                         surfaces, and no control turns it into a finding.
  missing                neither. Nobody has written it and nothing can read
                         it.

Those three states are the deliverable. A drafted Annex IV where eight of
nine sections say `missing` is a more useful artifact than a generated one
that reads as complete, because it is a work list with the evidence already
attached to the two lines that have any, and because the person who signs
under it can see exactly which sentences they are personally asserting.

Design note D-56, on why the outcome is never SATISFIED and where that is
enforced.

`Method.GENERATED` carries the rule from D-40: a draft nobody signed is not
evidence. These controls therefore return INCONCLUSIVE with the draft in
`evidence`, on every input, including the input where every point is filled.
The engine refuses a GENERATED control that returns SATISFIED (it raises,
rather than downgrading, so the bug cannot ship quietly), and
`tests/test_controls_documentation.py` asserts the property from the other
side by running every control here against targets designed to tempt it.

The thing that would break this is subtle and worth naming: it is not that
someone writes `Outcome.SATISFIED` on purpose. It is that a future version
adds an "all points filled" shortcut because the drafted file looks finished.
A file being finished is a fact about the file. Whether the provider has
discharged Article 11 is a fact about the provider, and the control has never
seen the provider.

Design note D-57, on the legal text in this module.

The section headings and the `asks` lines are paraphrases of the Annexes,
each carrying its citation, and they live in Python rather than in
`i18n/<lang>.json` where D-33 puts prose. Two reasons, and the second is the
one that decides it. First, they are structure: the list of points in Annex
IV is the document's shape, not its wording, and a translation must not be
able to add or drop a point. Second, official translations of these Annexes
exist in every EU language, in the Official Journal. Shipping our own
Spanish rendering of Annex IV would put a worse text in front of a Spanish
consultant than the citation they can look up, and it would be the text they
paste into a file they sign. So the draft carries the citation, always, and
the paraphrase is marked as such rather than dressed up as a quotation.

The declaration schema
----------------------
Every point has a slug, and the operator fills it in `actaira.yaml` under the
document's key. Nothing here is required and nothing here is validated
beyond being a scalar or a list, because it is the operator's statement and
this control is not the place where a statement gets checked:

    annex_iv:
      intended_purpose: "Triage of inbound support tickets"
      instructions_for_use: "docs/deployer-guide.pdf"
    annex_xi:
      licence: "Apache-2.0"
    annex_xii:
      acceptable_use_policy: "https://example.invalid/aup"
    training_summary:
      publicly_available_datasets:
        - "example-corpus-v2"
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from .. import __version__
from ..bom.cyclonedx import build_bom
from ..inspect import inspect_artifact
from ..model import ArtifactReport, Severity, artifact_name
from . import registry
from .model import Control, ControlResult, Method, Outcome, Target
from .records import discover_artifacts

FILLED = "filled_from_evidence"
DECLARED = "declared_by_operator"
MISSING = "missing"
STATES = (FILLED, DECLARED, MISSING)

PARAPHRASE_NOTE = (
    "The `asks` lines are paraphrases written for a reader of this document. "
    "The citation is authoritative; the Official Journal text is not reproduced here."
)
DRAFT_WARNING = (
    "This is a skeleton generated from the evidence Actaira holds. It is not a "
    "technical file, it has not been reviewed, and no part of it is evidence of "
    "compliance until a person who can answer for it has written and signed the "
    "points marked missing."
)


# ---------------------------------------------------------------------------
# Evidence Actaira actually holds
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DraftEvidence:
    """What the fillers below are allowed to read. Observations only.

    Deliberately not the `Target`: a filler that could reach the declarations
    could quietly promote a statement to `filled_from_evidence`, and the
    distinction between those two states is the only thing this module sells.
    """

    reports: tuple[ArtifactReport, ...]
    bom: dict[str, Any] | None
    not_fully_read: tuple[str, ...]
    truncated: bool

    @property
    def inventory(self) -> list[dict[str, Any]]:
        return [
            {
                "name": artifact_name(report.path),
                "path": report.path,
                "sha256": report.sha256,
                "format": report.detected_format,
                "size_bytes": report.size_bytes,
            }
            for report in self.reports
        ]


def gather(target: Target) -> DraftEvidence:
    """Inspect the target once, so every point is drafted from one reading.

    Drafting each section from its own scan would let two sections of the
    same document disagree about which artifacts exist, which is a way of
    being wrong that a reader has no way to detect.
    """
    paths, _declared, truncated = discover_artifacts(target)
    reports = [inspect_artifact(path, fail_on=Severity.HIGH) for path in paths]
    unread = tuple(
        report.path
        for report in reports
        if not report.metadata.get("fully_read", False) or report.inspector_errors
    )
    return DraftEvidence(
        reports=tuple(reports),
        bom=build_bom(reports) if reports else None,
        not_fully_read=unread,
        truncated=truncated,
    )


Filler = Callable[[DraftEvidence], Any]


def _fill_inventory(evidence: DraftEvidence) -> Any:
    """The files that make up this distribution, by digest."""
    return evidence.inventory or None


def _fill_parameters(evidence: DraftEvidence) -> Any:
    """Parameter and tensor counts, only where a header actually declared them."""
    rows = []
    for report in evidence.reports:
        parameters = report.metadata.get("total_parameters")
        tensors = report.tensors
        if parameters is None and not tensors:
            continue
        row: dict[str, Any] = {"name": artifact_name(report.path)}
        if parameters is not None:
            row["total_parameters"] = parameters
        if tensors:
            row["tensor_count"] = len(tensors)
            row["dtypes"] = sorted({tensor.dtype for tensor in tensors})
        rows.append(row)
    return rows or None


def _fill_static_inspection(evidence: DraftEvidence) -> Any:
    """The result of the static inspection, findings and all."""
    if not evidence.reports:
        return None
    findings = sorted(
        {
            (finding.rule_id, finding.severity.value)
            for report in evidence.reports
            for finding in report.findings
        }
    )
    return {
        "tool": f"actaira {__version__}",
        "artifacts_inspected": len(evidence.reports),
        "artifacts_not_fully_read": list(evidence.not_fully_read),
        "findings": [{"rule_id": rule_id, "severity": severity} for rule_id, severity in findings],
        "loaded_or_executed_anything": False,
    }


def _fill_bom(evidence: DraftEvidence) -> Any:
    """The ML-BOM, which is the machine-readable half of a component list."""
    if not evidence.bom:
        return None
    return {
        "bomFormat": evidence.bom.get("bomFormat"),
        "specVersion": evidence.bom.get("specVersion"),
        "serialNumber": evidence.bom.get("serialNumber"),
        "components": len(evidence.bom.get("components", [])),
    }


# ---------------------------------------------------------------------------
# The skeletons
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Point:
    """One point of an Annex, and where its content can come from.

    `slug` is both the key the operator declares under and the stable
    identifier of the point inside the document. Stable, because the gap list
    from one run gets compared with the next one, and a point that changed
    name between versions reads as a gap that was closed and a new one that
    opened.
    """

    slug: str
    citation: str
    asks: str
    fill: Filler | None = None
    fill_note: str = ""


@dataclass(frozen=True)
class Section:
    number: str
    citation: str
    title: str
    points: tuple[Point, ...]


@dataclass(frozen=True)
class Skeleton:
    """One document, its sections, and what it deliberately does not draft.

    `not_drafted` exists so that a part of an Annex this control stays out of
    is visible in the output without becoming a point with a status. A
    section listed as a gap reads as work the operator has to do; a section
    listed here reads as work this tool refused to start, which is a
    different sentence and the honest one where the reason is that nothing in
    an artifact bears on it.
    """

    key: str
    title: str
    citation: str
    sections: tuple[Section, ...]
    not_drafted: tuple[tuple[str, str], ...] = ()


ANNEX_IV = Skeleton(
    key="annex_iv",
    title="Technical documentation (Annex IV)",
    citation="Regulation (EU) 2024/1689, Art. 11(1) and Annex IV",
    sections=(
        Section(
            number="1",
            citation="Annex IV(1)",
            title="General description of the AI system",
            points=(
                Point("intended_purpose", "Annex IV(1)(a)",
                      "the intended purpose, the name of the provider, and the version of the "
                      "system and its relation to previous versions"),
                Point("interaction_with_other_systems", "Annex IV(1)(b)",
                      "how the system interacts, or can be used to interact, with hardware or "
                      "software that is not part of it, including other AI systems"),
                Point("software_versions", "Annex IV(1)(c)",
                      "the versions of relevant software or firmware, and any requirements "
                      "related to version updates"),
                Point("forms_of_distribution", "Annex IV(1)(d)",
                      "every form in which the system is placed on the market or put into "
                      "service: embedded in hardware, downloadable, an API",
                      fill=_fill_inventory,
                      fill_note="the artifacts found in the target and their digests, which is "
                                "the downloadable form as it exists on disk. Whether the system "
                                "is also shipped embedded or served as an API is not readable "
                                "from a file."),
                Point("target_hardware", "Annex IV(1)(e)",
                      "the hardware the system is intended to run on"),
                Point("product_illustrations", "Annex IV(1)(f)",
                      "where the system is a component of a product, photographs or "
                      "illustrations of external features, marking and internal layout"),
                Point("user_interface", "Annex IV(1)(g)",
                      "a basic description of the user interface provided to the deployer"),
                Point("instructions_for_use", "Annex IV(1)(h)",
                      "the instructions for use for the deployer"),
            ),
        ),
        Section(
            number="2",
            citation="Annex IV(2)",
            title="The elements of the system and the process of its development",
            points=(
                Point("development_methods", "Annex IV(2)(a)",
                      "the methods and steps performed for development, including any recourse "
                      "to pre-trained systems or tools supplied by third parties"),
                Point("design_specifications", "Annex IV(2)(b)",
                      "the design specifications: general logic, algorithms, key design choices "
                      "with their rationale and assumptions, and what the system is designed to "
                      "optimise for",
                      fill=_fill_parameters,
                      fill_note="the parameter and tensor counts declared in the artifact "
                                "headers. The logic, the design choices and the rationale are "
                                "not in the weights."),
                Point("architecture", "Annex IV(2)(c)",
                      "the system architecture, how the software components build on or feed "
                      "into each other, and the computational resources used",
                      fill=_fill_bom,
                      fill_note="the ML-BOM, which lists the artifact components and their "
                                "digests. It is not an architecture: it says what the files are, "
                                "not how the system is put together."),
                Point("data_requirements", "Annex IV(2)(d)",
                      "the data requirements: datasheets describing training methodologies, the "
                      "datasets used, their provenance, scope and characteristics, how the data "
                      "was obtained and selected, labelling and cleaning procedures"),
                Point("human_oversight", "Annex IV(2)(e)",
                      "an assessment of the human oversight measures needed under Art. 14, "
                      "including the technical measures that facilitate interpretation of the "
                      "outputs by deployers"),
                Point("predetermined_changes", "Annex IV(2)(f)",
                      "where applicable, the predetermined changes to the system and its "
                      "performance, with the technical solutions that keep it compliant"),
                Point("validation_and_testing", "Annex IV(2)(g)",
                      "the validation and testing procedures, the data used, the metrics for "
                      "accuracy, robustness and compliance, potentially discriminatory impacts, "
                      "and the dated test logs and reports"),
                Point("cybersecurity_measures", "Annex IV(2)(h)",
                      "the cybersecurity measures put in place",
                      fill=_fill_static_inspection,
                      fill_note="a static inspection of the artifacts: what was parsed, what "
                                "was found, and what could not be read. One measure, evidenced. "
                                "The measures themselves - access control, key management, "
                                "update policy - are organisational and are not here."),
            ),
        ),
        Section(
            number="3",
            citation="Annex IV(3)",
            title="Monitoring, functioning and control",
            points=(
                Point("capabilities_and_limitations", "Annex IV(3)",
                      "the capabilities and limitations of the system, the expected level of "
                      "accuracy and the degrees of accuracy for specific persons or groups, the "
                      "foreseeable unintended outcomes and sources of risk to health, safety, "
                      "fundamental rights and non-discrimination, the human oversight measures, "
                      "and the specifications on input data"),
            ),
        ),
        Section(
            number="4",
            citation="Annex IV(4)",
            title="Appropriateness of the performance metrics",
            points=(
                Point("performance_metrics", "Annex IV(4)",
                      "why the chosen performance metrics are appropriate for this particular "
                      "system"),
            ),
        ),
        Section(
            number="5",
            citation="Annex IV(5)",
            title="Risk management system",
            points=(
                Point("risk_management", "Annex IV(5)",
                      "a detailed description of the risk management system required by Art. 9"),
            ),
        ),
        Section(
            number="6",
            citation="Annex IV(6)",
            title="Changes through the lifecycle",
            points=(
                Point("lifecycle_changes", "Annex IV(6)",
                      "the relevant changes made by the provider to the system through its "
                      "lifecycle"),
            ),
        ),
        Section(
            number="7",
            citation="Annex IV(7)",
            title="Standards applied",
            points=(
                Point("standards_applied", "Annex IV(7)",
                      "the harmonised standards applied in full or in part, or, where none were "
                      "applied, the other technical specifications used to meet the requirements "
                      "of Chapter III Section 2"),
            ),
        ),
        Section(
            number="8",
            citation="Annex IV(8)",
            title="EU declaration of conformity",
            points=(
                Point("declaration_of_conformity", "Annex IV(8)",
                      "a copy of the EU declaration of conformity referred to in Art. 47"),
            ),
        ),
        Section(
            number="9",
            citation="Annex IV(9)",
            title="Post-market monitoring",
            points=(
                Point("post_market_monitoring", "Annex IV(9)",
                      "the system in place to evaluate performance in the post-market phase "
                      "under Art. 72, including the post-market monitoring plan"),
            ),
        ),
    ),
)


ANNEX_XI = Skeleton(
    key="annex_xi",
    title="Technical documentation for a general-purpose AI model (Annex XI, Section 1)",
    citation="Regulation (EU) 2024/1689, Art. 53(1)(a) and Annex XI Section 1",
    sections=(
        Section(
            number="1",
            citation="Annex XI, Section 1, point 1",
            title="General description of the model",
            points=(
                Point("tasks_and_integration", "Annex XI, s.1, 1(a)",
                      "the tasks the model is intended to perform and the type and nature of AI "
                      "systems it can be integrated into"),
                Point("acceptable_use_policy", "Annex XI, s.1, 1(b)",
                      "the acceptable use policies that apply"),
                Point("release_and_distribution", "Annex XI, s.1, 1(c)",
                      "the date of release and the methods of distribution"),
                Point("architecture_and_parameters", "Annex XI, s.1, 1(d)",
                      "the architecture and the number of parameters",
                      fill=_fill_parameters,
                      fill_note="the parameter and tensor counts read from the artifact headers, "
                                "which is the number of parameters this point asks for. The "
                                "architecture is not declared in the headers of every format and "
                                "is not inferred here."),
                Point("modality_and_format", "Annex XI, s.1, 1(e)",
                      "the modality (text, image, audio) and the format of inputs and outputs"),
                Point("licence", "Annex XI, s.1, 1(f)",
                      "the licence"),
            ),
        ),
        Section(
            number="2",
            citation="Annex XI, Section 1, point 2",
            title="The elements of the model and the process of its development",
            points=(
                Point("technical_means_for_integration", "Annex XI, s.1, 2(a)",
                      "the technical means required to integrate the model into AI systems: "
                      "instructions for use, infrastructure, tools"),
                Point("design_and_training_specifications", "Annex XI, s.1, 2(b)",
                      "the design specifications of the model and of the training process, the "
                      "training methodologies and techniques, the key design choices with their "
                      "rationale and assumptions, and what the model is designed to optimise for"),
                Point("training_data", "Annex XI, s.1, 2(c)",
                      "the data used for training, testing and validation: type and provenance, "
                      "curation methodologies, number of data points, scope and characteristics, "
                      "how it was obtained and selected, and the measures used to detect "
                      "unsuitable sources and identifiable biases"),
                Point("computational_resources", "Annex XI, s.1, 2(d)",
                      "the computational resources used to train the model, such as the number "
                      "of floating point operations, the training time and other relevant detail"),
                Point("energy_consumption", "Annex XI, s.1, 2(e)",
                      "the known or estimated energy consumption of the model"),
            ),
        ),
    ),
    not_drafted=(
        (
            "Annex XI, Section 2",
            "Section 2 binds only providers of models classified as having systemic risk "
            "under Art. 51. Nothing in an artifact decides that classification - the "
            "Art. 51(2) presumption is about training compute, which no weight file "
            "records - so this control neither drafts Section 2 nor implies it does not "
            "apply here.",
        ),
    ),
)


ANNEX_XII = Skeleton(
    key="annex_xii",
    title="Transparency information for downstream providers (Annex XII)",
    citation="Regulation (EU) 2024/1689, Art. 53(1)(b) and Annex XII",
    sections=(
        Section(
            number="1",
            citation="Annex XII, point 1",
            title="General description of the model",
            points=(
                Point("tasks_and_integration", "Annex XII, 1(a)",
                      "the tasks the model is intended to perform and the type and nature of AI "
                      "systems it can be integrated into"),
                Point("acceptable_use_policy", "Annex XII, 1(b)",
                      "the acceptable use policies that apply"),
                Point("release_and_distribution", "Annex XII, 1(c)",
                      "the date of release and the methods of distribution"),
                Point("interaction_with_other_software", "Annex XII, 1(d)",
                      "how the model interacts with hardware or software that is not part of it, "
                      "where applicable"),
                Point("software_versions", "Annex XII, 1(e)",
                      "the versions of relevant software related to the use of the model"),
                Point("architecture_and_parameters", "Annex XII, 1(f)",
                      "the architecture and the number of parameters",
                      fill=_fill_parameters,
                      fill_note="the parameter and tensor counts read from the artifact headers. "
                                "The architecture is not inferred."),
                Point("modality_and_format", "Annex XII, 1(g)",
                      "the modality and the format of inputs and outputs"),
                Point("licence", "Annex XII, 1(h)",
                      "the licence for the model"),
            ),
        ),
        Section(
            number="2",
            citation="Annex XII, point 2",
            title="The elements of the model and the process of its development",
            points=(
                Point("technical_means_for_integration", "Annex XII, 2(a)",
                      "the technical means required to integrate the model into AI systems"),
                Point("input_output_size", "Annex XII, 2(b)",
                      "the modality and format of the inputs and outputs and their maximum size, "
                      "such as the context window length"),
                Point("training_data", "Annex XII, 2(c)",
                      "the data used for training, testing and validation, where applicable, "
                      "including type, provenance and curation methodologies"),
                Point("distribution_integrity", "Annex XII, 2",
                      "the artifacts a downstream provider receives, so that what they integrate "
                      "can be checked against what was documented",
                      fill=_fill_inventory,
                      fill_note="the artifacts and their digests. Annex XII does not ask for a "
                                "digest; this is offered to the downstream provider as the "
                                "identity of what they were given, not as an item the Annex "
                                "requested."),
            ),
        ),
    ),
)


TRAINING_SUMMARY = Skeleton(
    key="training_summary",
    title="Sufficiently detailed summary of the content used for training",
    citation="Regulation (EU) 2024/1689, Art. 53(1)(d)",
    sections=(
        Section(
            number="1",
            citation="Art. 53(1)(d)",
            title="General information",
            points=(
                Point("model_identification", "Art. 53(1)(d)",
                      "which model this summary is about",
                      fill=_fill_inventory,
                      fill_note="the artifacts and their digests, which identify the bytes the "
                                "summary is about. Identifying the model is not summarising what "
                                "it was trained on, and nothing else in this document can be "
                                "filled from an artifact."),
                Point("modalities_and_size", "Art. 53(1)(d)",
                      "the modalities covered and the overall size of the training content"),
            ),
        ),
        Section(
            number="2",
            citation="Art. 53(1)(d)",
            title="Sources of the training content",
            points=(
                Point("publicly_available_datasets", "Art. 53(1)(d)",
                      "the large publicly available datasets used, named"),
                Point("licensed_private_data", "Art. 53(1)(d)",
                      "private data licensed from third parties, described by category"),
                Point("user_data", "Art. 53(1)(d)",
                      "data originating from users of the provider's own services"),
                Point("crawled_data", "Art. 53(1)(d)",
                      "data crawled or scraped from online sources: the crawlers used, their "
                      "behaviour, and the period of collection"),
                Point("synthetic_data", "Art. 53(1)(d)",
                      "synthetic data, and how it was generated"),
            ),
        ),
        Section(
            number="3",
            citation="Art. 53(1)(d), read with Art. 53(1)(c)",
            title="Processing of the training content",
            points=(
                Point("tdm_reservations", "Art. 53(1)(d)",
                      "the measures taken to identify and respect reservations of rights "
                      "expressed under Art. 4(3) of Directive (EU) 2019/790"),
                Point("illegal_content_removal", "Art. 53(1)(d)",
                      "the measures taken to remove illegal content from the training data"),
                Point("other_processing", "Art. 53(1)(d)",
                      "any other processing of the training content relevant to the summary: "
                      "deduplication, filtering, quality selection"),
            ),
        ),
    ),
)


# ---------------------------------------------------------------------------
# Drafting
# ---------------------------------------------------------------------------

def _declared_value(target: Target, document_key: str, slug: str) -> Any:
    value = target.declared(document_key, slug)
    if value is None or value == "" or value == [] or value == {}:
        return None
    return value


def _draft_point(point: Point, skeleton: Skeleton, target: Target, evidence: DraftEvidence) -> dict[str, Any]:
    """One point, with its status and everything that bears on it.

    The declaration is attached whenever it exists, including on a point that
    evidence already filled. Dropping it would hide a disagreement between
    what the operator says the model is and what its bytes say, and that
    disagreement is one of the more interesting things this document can
    surface.
    """
    declared = _declared_value(target, skeleton.key, point.slug)
    content = point.fill(evidence) if point.fill is not None else None

    if content is not None:
        status = FILLED
    elif declared is not None:
        status = DECLARED
    else:
        status = MISSING

    row: dict[str, Any] = {
        "key": f"{skeleton.key}.{point.slug}",
        "citation": point.citation,
        "asks": point.asks,
        "status": status,
    }
    if content is not None:
        row["from_evidence"] = content
        row["note"] = point.fill_note
    if declared is not None:
        row["declared_by_operator"] = declared
    return row


def build_draft(skeleton: Skeleton, target: Target, evidence: DraftEvidence) -> dict[str, Any]:
    sections: list[dict[str, Any]] = []
    for section in skeleton.sections:
        points = [_draft_point(point, skeleton, target, evidence) for point in section.points]
        sections.append(
            {
                "number": section.number,
                "citation": section.citation,
                "title": section.title,
                "points": points,
                "counts_not_a_score": _counts(points),
            }
        )
    return {
        "document": skeleton.title,
        "citation": skeleton.citation,
        "generated_by": f"actaira {__version__}",
        "is_a_draft": True,
        "warning": DRAFT_WARNING,
        "paraphrase_note": PARAPHRASE_NOTE,
        "sections": sections,
        "not_drafted": [
            {"citation": citation, "reason": reason} for citation, reason in skeleton.not_drafted
        ],
    }


def _counts(points: Sequence[dict[str, Any]]) -> dict[str, int]:
    """A count by state. Never divided by anything: design note D-41."""
    tally = {state: 0 for state in STATES}
    for point in points:
        tally[point["status"]] += 1
    return tally


def _all_points(draft: dict[str, Any]) -> list[dict[str, Any]]:
    return [point for section in draft["sections"] for point in section["points"]]


COVERS = (
    "the skeleton of the document, point by point with its citation, and the "
    "provenance of every point: filled from parsed bytes, declared by the operator, "
    "or missing."
)
DOES_NOT_COVER_TEMPLATE = (
    "whether the document is adequate, whether anything declared in it is true, and "
    "whether {obligation} is met. A draft is not a technical file: the points marked "
    "missing have no author yet, and the points marked declared_by_operator are "
    "statements this control did not check. The outcome of this control is "
    "INCONCLUSIVE on every input, by construction."
)


def _make_runner(
    skeleton: Skeleton,
    control_id: str,
    obligation_ids: tuple[str, ...],
    obligation_text: str,
) -> Callable[[Target], ControlResult]:
    def run(target: Target) -> ControlResult:
        evidence = gather(target)
        draft = build_draft(skeleton, target, evidence)
        points = _all_points(draft)
        gaps = [point["key"] for point in points if point["status"] == MISSING]
        # INCONCLUSIVE is built here rather than through `model.inconclusive`
        # because that helper carries no `covers` / `does_not_cover`, and for a
        # generated document the boundary statement is the most important line
        # in the result: it is what stops the draft being filed as evidence.
        return ControlResult(
            control_id=control_id,
            obligation_ids=obligation_ids,
            outcome=Outcome.INCONCLUSIVE,
            method=Method.GENERATED,
            evidence={
                "reason": "draft_generated_for_review",
                "draft": draft,
                "gaps": gaps,
                "counts_not_a_score": _counts(points),
                "artifacts_inspected": len(evidence.reports),
                "artifacts_not_fully_read": list(evidence.not_fully_read),
            },
            covers=COVERS,
            does_not_cover=DOES_NOT_COVER_TEMPLATE.format(obligation=obligation_text),
            inspected=tuple(report.path for report in evidence.reports),
            # Every point nobody wrote is a point this control declined to
            # invent. `abstained_on` is where a control says what it did not
            # answer, and a generated document has more of those than anything
            # else in this tool.
            abstained_on=tuple(gaps),
        )

    return run


ANNEX_IV_CONTROL_ID = "ACT-C-11-ANNEX-IV"
ANNEX_XI_CONTROL_ID = "ACT-C-53-ANNEX-XI"
ANNEX_XII_CONTROL_ID = "ACT-C-53-ANNEX-XII"
TRAINING_SUMMARY_CONTROL_ID = "ACT-C-53-TRAINING-SUMMARY"

ANNEX_IV_CONTROL = registry.register(
    Control(
        id=ANNEX_IV_CONTROL_ID,
        obligation_ids=("AIA-11",),
        method=Method.GENERATED,
        run=_make_runner(ANNEX_IV, ANNEX_IV_CONTROL_ID, ("AIA-11",), "Art. 11"),
    )
)

ANNEX_XI_CONTROL = registry.register(
    Control(
        id=ANNEX_XI_CONTROL_ID,
        obligation_ids=("AIA-53-1a",),
        method=Method.GENERATED,
        run=_make_runner(ANNEX_XI, ANNEX_XI_CONTROL_ID, ("AIA-53-1a",), "Art. 53(1)(a)"),
    )
)

ANNEX_XII_CONTROL = registry.register(
    Control(
        id=ANNEX_XII_CONTROL_ID,
        obligation_ids=("AIA-53-1b",),
        method=Method.GENERATED,
        run=_make_runner(ANNEX_XII, ANNEX_XII_CONTROL_ID, ("AIA-53-1b",), "Art. 53(1)(b)"),
    )
)

TRAINING_SUMMARY_CONTROL = registry.register(
    Control(
        id=TRAINING_SUMMARY_CONTROL_ID,
        obligation_ids=("AIA-53-1d",),
        method=Method.GENERATED,
        run=_make_runner(
            TRAINING_SUMMARY, TRAINING_SUMMARY_CONTROL_ID, ("AIA-53-1d",), "Art. 53(1)(d)"
        ),
    )
)

CONTROLS: tuple[Control, ...] = (
    ANNEX_IV_CONTROL,
    ANNEX_XI_CONTROL,
    ANNEX_XII_CONTROL,
    TRAINING_SUMMARY_CONTROL,
)
SKELETONS: tuple[Skeleton, ...] = (ANNEX_IV, ANNEX_XI, ANNEX_XII, TRAINING_SUMMARY)
