"""EU AI Act obligations, as data, with citations and application dates.

Design note D-29, and the one that decides whether this module is worth
anything. Compliance tooling fails in a specific and well documented way: it
generates a number. A percentage of completeness, a green tick, a score. The
number is fabricated, because nothing in the artifact can support it, and it
is then shown to a client as evidence.

This catalogue is built so that outcome is unavailable. It records, for each
obligation:

  * the article and paragraph, and the date it applies from, sourced from
    Article 113 and from the Commission's own guidance rather than from a
    vendor blog;
  * who it binds, provider or deployer, because most compliance tools blur
    this and it changes who has to act;
  * what evidence the obligation actually asks for;
  * and, separately, what Actaira can contribute to that evidence.

That last field is the point. Its default is NOT_COVERED, and most entries
keep it, because Actaira inspects model artifacts and nothing else. It says
nothing about staff training, nothing about copyright policy, nothing about
what a system does at runtime. An obligation this tool cannot help with is
listed with that stated plainly, rather than omitted from the catalogue,
because an omitted obligation reads as a satisfied one.

There is no score anywhere in this module, and there will not be one. A
count of obligations touched by evidence is not a percentage of compliance,
and the moment it is rendered as one it becomes the thing this project was
built in reaction to.

Design note D-33, added when the second language arrived. What stays in this
file is the part that is not language: the identifier, the article, the date,
who it binds, the coverage verdict and the citation. Every line of prose
(title, summary, expected evidence, what Actaira provides and what it does
not, the note, the scope of a grace period) lives in `i18n/<lang>.json` under
`governance`, keyed by obligation id, and is loaded from there. The English
catalogue is what populates the frozen `Obligation` objects, so the Python
API is unchanged; `localized()` serves any other language, falling back to
English field by field. The alternative, Spanish strings inline next to the
English ones, puts a translation review inside a file whose review is about
legal dates, and the two rot at different rates.

Design note D-34, written after a hostile read of this file by someone who
knows the Regulation. Three things came out of it and they are why the
catalogue looks the way it does now.

First, no entry carries SUPPORTS any more. The definition below is "a
substantial part of what the obligation asks for", and nothing this tool
emits meets it: Annex XII does not ask for a hash, a bill of materials or a
signature, so the evidence Actaira is best at is evidence the Regulation
never requested. It is still useful to the integrator, and PARTIAL says so
without claiming the obligation is largely discharged. An empty SUPPORTS tier
is a more honest catalogue than one entry promoted to fill it.

Second, the deferred high-risk dates are law, not a rumour. They were
PROVISIONAL here while the Digital Omnibus was a political agreement; it has
since been adopted and published, so nothing in this catalogue is provisional
today. The status stays in the enum because the next amendment will need it.

Third, an obligation that binds nobody in the catalogue is safer than one
attributed to the wrong role. Article 55 binds providers of models *with
systemic risk*, which is a narrower group than PROVIDER_GPAI, so it has its
own role that the user has to declare. Nobody is handed Article 55 by
default.

Sources for the dates, checked against the legal texts rather than restated
from secondary coverage:
  * Regulation (EU) 2024/1689, Article 113 (entry into application).
  * Regulation (EU) 2026/1744 of 8 July 2026, the Digital Omnibus on AI,
    published in the Official Journal on 24 July 2026 and in force since
    27 July 2026. It replaces Article 4, inserts Article 4a and
    Article 5(1), points (ba) and (bb) with paragraphs 1a and 1b, amends
    Articles 6, 10, 11(1), 25, 27, 49 and 50(7), inserts Article 111(4) and
    rewrites Article 113.
  * Article 113(a): Chapters I and II from 2 February 2025, except the new
    Article 5 prohibitions, which apply from 2 December 2026.
  * Article 113(b): Chapter III Section 4, Chapter V, Chapter VII,
    Chapter XII and Article 78 from 2 August 2025, Article 101 excepted.
  * Article 113(c) as rewritten: Chapter III Sections 1, 2 and 3 from
    2 December 2027 for Article 6(2) and Annex III systems, and from
    2 August 2028 for Article 6(1) and Annex I systems.
  * The general date in Article 113, 2 August 2026, for everything the
    points above do not move: Chapter IV (Article 50), Chapter III Section 5
    (Article 49) and Chapter IX (Articles 72 and 73). Article 101, the fines
    for providers of general-purpose AI models, also bites from that date.
  * Article 111(3) for the 2 August 2027 transitional for general-purpose AI
    models already on the market on 2 August 2025.
  * Article 111(4), inserted by the Digital Omnibus, for the 2 December 2026
    transitional on Article 50(2) marking.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import Enum
from typing import Any

from ..i18n.catalog import load as _load_catalog

# The section of the message catalogue this module owns, and the fields it
# takes from there. Anything not on this list is structure and stays in Python.
TEXT_SECTION = "governance"
TEXT_FIELDS = (
    "title",
    "summary",
    "evidence_expected",
    "actaira_provides",
    "actaira_does_not_provide",
    "grace_scope",
    "note",
    "why_not",
)


class Role(str, Enum):
    """Who an obligation binds, kept separate because the Regulation does.

    PROVIDER_GPAI is the provider of a general-purpose AI *model*
    (Art. 3(63)). It is not the provider of an AI *system* (Art. 3(3)), and
    the two are not interchangeable: Chapter IV binds the latter. Publishing
    weights does not by itself place a system on the market.

    PROVIDER_GPAI_SYSTEMIC is the narrower group Article 55 binds, the
    providers of models classified under Article 51. It has to be declared:
    no default puts anyone in it, because a model below the Article 51(2)
    presumption carries none of those duties and no property of a weight file
    tells you which side of it a model falls on.
    """

    PROVIDER = "provider"
    DEPLOYER = "deployer"
    PROVIDER_GPAI = "provider_gpai"
    PROVIDER_GPAI_SYSTEMIC = "provider_gpai_systemic"
    ANY = "any"


class Coverage(str, Enum):
    """What Actaira contributes to an obligation's evidence.

    SUPPORTS is deliberately hard to reach. It means the tool produces, from
    the artifact's own bytes, a substantial part of what the obligation asks
    for. PARTIAL means it produces some. NOT_COVERED is the default and the
    honest answer for most of the regulation.

    No entry currently holds SUPPORTS, and that is a result rather than an
    oversight: see design note D-34. The tier stays because the bar it
    describes is the right bar, not because something has to sit on it.
    """

    SUPPORTS = "supports"
    PARTIAL = "partial"
    NOT_COVERED = "not_covered"


class Checkability(str, Enum):
    """How, if at all, software can bear on an obligation. Design note D-42.

    `Coverage` answers "what does Actaira contribute to this obligation's
    evidence". This answers a different and prior question: "what kind of
    thing would ever be able to contribute". They are separate because a tool
    that conflates them ends up claiming that the obligations it happens to
    implement are the obligations that matter.

    The tiers, and the rule each one carries:

    MACHINE_CHECKABLE   a deterministic control parses bytes and decides. No
                        model, no judgement, reproducible on any machine. The
                        control may only answer for what it read: Article
                        50(2) is machine-checkable over the files handed to
                        it, and says nothing about content it never saw.
    GENERATABLE         the tool can draft the artifact the obligation asks
                        for, from evidence it holds. The outcome is never
                        SATISFIED, because a draft nobody signed is not
                        evidence and the obligation binds a person.
    EVIDENCE_JUDGED     the obligation asks for a document, and whether a
                        supplied document addresses it is a judgement. A
                        model makes it, a verifier checks every span it
                        cited, and it abstains when it cannot ground the
                        answer. The abstention rate is published.
    ORGANIZATIONAL      nothing readable from a system can show it. Staff
                        training happened or it did not; a registration was
                        filed or it was not. Every obligation on this tier
                        carries `why_not`, a written reason, because "not
                        covered" with no reason is indistinguishable from
                        "not implemented yet" and the two should not look
                        alike in a compliance tool.

    Moving an obligation up a tier is a code change plus a measurement, never
    an edit to this field alone: `tests/test_controls.py` fails if an
    obligation claims MACHINE_CHECKABLE with no control bound to it, and
    fails if an ORGANIZATIONAL one carries no reason.
    """

    MACHINE_CHECKABLE = "machine_checkable"
    GENERATABLE = "generatable"
    EVIDENCE_JUDGED = "evidence_judged"
    ORGANIZATIONAL = "organizational"


class Status(str, Enum):
    IN_FORCE = "in_force"
    # Agreed by the co-legislators but not yet published in the Official
    # Journal. No obligation in this catalogue is provisional today: the
    # Digital Omnibus deferrals it once described were published on
    # 24 July 2026 as Regulation (EU) 2026/1744. Kept because the next
    # amendment will spend time in exactly this state.
    PROVISIONAL = "provisional"


@dataclass(frozen=True)
class Obligation:
    id: str
    article: str
    title: str
    applies_from: date
    role: Role
    summary: str
    evidence_expected: tuple[str, ...]
    coverage: Coverage
    actaira_provides: tuple[str, ...] = ()
    actaira_does_not_provide: tuple[str, ...] = ()
    grace_until: date | None = None
    grace_scope: str | None = None
    status: Status = Status.IN_FORCE
    citation: str = ""
    note: str = ""
    checkability: Checkability = Checkability.ORGANIZATIONAL
    why_not: str = ""
    controls: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "article": self.article,
            "title": self.title,
            "applies_from": self.applies_from.isoformat(),
            "grace_until": self.grace_until.isoformat() if self.grace_until else None,
            "grace_scope": self.grace_scope,
            "status": self.status.value,
            "role": self.role.value,
            "summary": self.summary,
            "evidence_expected": list(self.evidence_expected),
            "coverage": self.coverage.value,
            "actaira_provides": list(self.actaira_provides),
            "actaira_does_not_provide": list(self.actaira_does_not_provide),
            "citation": self.citation,
            "note": self.note,
            "checkability": self.checkability.value,
            "why_not": self.why_not,
            "controls": list(self.controls),
        }


CELEX = "Regulation (EU) 2024/1689 (CELEX 32024R1689)"
# The amending act, named in full wherever it moved a date, so a reader can
# check the deferral against the Official Journal rather than against us.
OMNIBUS = (
    "as amended by Regulation (EU) 2026/1744 of 8 July 2026 (Digital Omnibus "
    "on AI, CELEX 32026R1744), OJ L, 24 July 2026, in force 27 July 2026"
)
# Article 111(3): models already on the market when Chapter V started
# applying get until 2 August 2027. Same date on every Chapter V row, so it
# is written once.
GPAI_LEGACY_GRACE = date(2027, 8, 2)


def _text(lang: str, obligation_id: str) -> dict[str, Any]:
    """The prose for one obligation in one language, or an empty mapping.

    `i18n.catalog.load` already falls back to English for a language it does
    not carry, so an unknown language yields the English row rather than a
    blank one.
    """
    section = _load_catalog(lang).get(TEXT_SECTION, {})
    row = section.get(obligation_id, {})
    return row if isinstance(row, dict) else {}


def _obligation(
    obligation_id: str,
    article: str,
    applies_from: date,
    role: Role,
    coverage: Coverage,
    citation: str,
    grace_until: date | None = None,
    status: Status = Status.IN_FORCE,
    checkability: Checkability = Checkability.ORGANIZATIONAL,
    controls: tuple[str, ...] = (),
) -> Obligation:
    """Assemble one obligation from its structure here and its prose from en.json.

    A missing English row would silently produce an obligation with no text,
    which reads on screen as an obligation that asks nothing and is refused
    here instead: the catalogue is the product, and a blank row in it is
    worse than an import error.
    """
    text = _text("en", obligation_id)
    if not text.get("title") or not text.get("summary"):
        raise ValueError(
            f"{obligation_id} has no English text in i18n/en.json under {TEXT_SECTION!r}"
        )
    return Obligation(
        id=obligation_id,
        article=article,
        title=str(text["title"]),
        applies_from=applies_from,
        role=role,
        summary=str(text["summary"]),
        evidence_expected=tuple(text.get("evidence_expected", ())),
        coverage=coverage,
        actaira_provides=tuple(text.get("actaira_provides", ())),
        actaira_does_not_provide=tuple(text.get("actaira_does_not_provide", ())),
        grace_until=grace_until,
        grace_scope=text.get("grace_scope"),
        status=status,
        citation=citation,
        note=str(text.get("note", "")),
        checkability=checkability,
        why_not=str(text.get("why_not", "")),
        controls=controls,
    )


def localized(obligation: Obligation, lang: str = "en") -> dict[str, Any]:
    """`obligation.to_dict()` with its prose in `lang`.

    The fallback is per field, not per obligation: a half-translated entry
    renders the translated lines it has and English for the rest, rather than
    dropping back to English wholesale and hiding the gap. Structure
    (identifier, article, dates, role, coverage, citation) is never touched,
    because it is the same fact in every language and a translation must not
    be able to move a deadline.
    """
    payload = obligation.to_dict()
    english = _text("en", obligation.id)
    translated = _text(lang, obligation.id)
    for name in TEXT_FIELDS:
        value = translated.get(name, english.get(name))
        if value is None:
            continue
        payload[name] = list(value) if isinstance(value, list) else value
    return payload


OBLIGATIONS: tuple[Obligation, ...] = (
    # -- Chapter I and II, applicable since 2 February 2025 -----------------
    _obligation(
        "AIA-4",
        article="Art. 4",
        applies_from=date(2025, 2, 2),
        role=Role.ANY,
        coverage=Coverage.NOT_COVERED,
        checkability=Checkability.EVIDENCE_JUDGED,
        controls=("ACT-C-JUDGE-AIA-4",),
        citation=(
            f"{CELEX}, Art. 4 {OMNIBUS}; applicable per Art. 113(a), current "
            "wording since 27 July 2026"
        ),
    ),
    _obligation(
        "AIA-4a",
        article="Art. 4a",
        # Inserted into Chapter I, which was already applicable, so it binds
        # from the day the amending Regulation entered into force.
        applies_from=date(2026, 7, 27),
        role=Role.ANY,
        coverage=Coverage.NOT_COVERED,
        checkability=Checkability.ORGANIZATIONAL,
        controls=(),
        citation=(
            f"{CELEX}, Art. 4a, inserted {OMNIBUS}; Chapter I is applicable "
            "per Art. 113(a), so this binds from entry into force"
        ),
    ),
    _obligation(
        "AIA-5",
        article="Art. 5",
        applies_from=date(2025, 2, 2),
        role=Role.ANY,
        coverage=Coverage.NOT_COVERED,
        checkability=Checkability.ORGANIZATIONAL,
        controls=(),
        citation=f"{CELEX}, Art. 5; applicable per Art. 113(a)",
    ),
    _obligation(
        "AIA-5-1ba",
        article="Art. 5(1)(ba)-(bb)",
        applies_from=date(2026, 12, 2),
        role=Role.ANY,
        coverage=Coverage.NOT_COVERED,
        checkability=Checkability.ORGANIZATIONAL,
        controls=(),
        citation=(
            f"{CELEX}, Art. 5(1)(ba)-(bb) and Art. 5(1a)-(1b), inserted "
            f"{OMNIBUS}; Art. 113(a) excepts them to 2 December 2026"
        ),
    ),
    # -- Chapter V, GPAI, applicable since 2 August 2025 --------------------
    _obligation(
        "AIA-52",
        article="Art. 52",
        applies_from=date(2025, 8, 2),
        grace_until=GPAI_LEGACY_GRACE,
        role=Role.PROVIDER_GPAI,
        coverage=Coverage.NOT_COVERED,
        checkability=Checkability.ORGANIZATIONAL,
        controls=(),
        citation=(
            f"{CELEX}, Art. 52(1); applicable per Art. 113(b); transitional "
            "for legacy models in Art. 111(3)"
        ),
    ),
    _obligation(
        "AIA-53-1a",
        article="Art. 53(1)(a)",
        applies_from=date(2025, 8, 2),
        grace_until=GPAI_LEGACY_GRACE,
        role=Role.PROVIDER_GPAI,
        coverage=Coverage.PARTIAL,
        checkability=Checkability.GENERATABLE,
        controls=("ACT-C-53-ANNEX-XI",),
        citation=(
            f"{CELEX}, Art. 53(1)(a) and Annex XI Section 1; applicable per "
            "Art. 113(b); transitional for legacy models in Art. 111(3)"
        ),
    ),
    _obligation(
        "AIA-53-1b",
        article="Art. 53(1)(b)",
        applies_from=date(2025, 8, 2),
        grace_until=GPAI_LEGACY_GRACE,
        role=Role.PROVIDER_GPAI,
        coverage=Coverage.PARTIAL,
        checkability=Checkability.GENERATABLE,
        controls=("ACT-C-53-ANNEX-XII",),
        citation=(
            f"{CELEX}, Art. 53(1)(b) and Annex XII; applicable per "
            "Art. 113(b); transitional for legacy models in Art. 111(3)"
        ),
    ),
    _obligation(
        "AIA-53-1c",
        article="Art. 53(1)(c)",
        applies_from=date(2025, 8, 2),
        grace_until=GPAI_LEGACY_GRACE,
        role=Role.PROVIDER_GPAI,
        coverage=Coverage.NOT_COVERED,
        checkability=Checkability.EVIDENCE_JUDGED,
        controls=("ACT-C-JUDGE-AIA-53-1c",),
        citation=(
            f"{CELEX}, Art. 53(1)(c); transitional for legacy models in "
            "Art. 111(3)"
        ),
    ),
    _obligation(
        "AIA-53-1d",
        article="Art. 53(1)(d)",
        applies_from=date(2025, 8, 2),
        grace_until=GPAI_LEGACY_GRACE,
        role=Role.PROVIDER_GPAI,
        coverage=Coverage.NOT_COVERED,
        checkability=Checkability.GENERATABLE,
        controls=("ACT-C-53-TRAINING-SUMMARY",),
        citation=(
            f"{CELEX}, Art. 53(1)(d); transitional for legacy models in "
            "Art. 111(3)"
        ),
    ),
    _obligation(
        "AIA-54",
        article="Art. 54",
        applies_from=date(2025, 8, 2),
        grace_until=GPAI_LEGACY_GRACE,
        role=Role.PROVIDER_GPAI,
        coverage=Coverage.NOT_COVERED,
        checkability=Checkability.ORGANIZATIONAL,
        controls=(),
        citation=(
            f"{CELEX}, Art. 54(1) to (3); open-source exception in Art. 54(6); "
            "applicable per Art. 113(b); transitional in Art. 111(3)"
        ),
    ),
    _obligation(
        "AIA-55",
        article="Art. 55",
        applies_from=date(2025, 8, 2),
        grace_until=GPAI_LEGACY_GRACE,
        role=Role.PROVIDER_GPAI_SYSTEMIC,
        coverage=Coverage.PARTIAL,
        checkability=Checkability.EVIDENCE_JUDGED,
        controls=("ACT-C-JUDGE-AIA-55",),
        citation=(
            f"{CELEX}, Art. 55(1); classification and the 10^25 FLOP "
            "presumption in Art. 51(1) and 51(2); transitional in Art. 111(3)"
        ),
    ),
    # -- Chapter IV, transparency, applicable since 2 August 2026 ----------
    _obligation(
        "AIA-50-1",
        article="Art. 50(1)",
        applies_from=date(2026, 8, 2),
        role=Role.PROVIDER,
        coverage=Coverage.NOT_COVERED,
        checkability=Checkability.MACHINE_CHECKABLE,
        controls=("ACT-C-50-1-DISCLOSE",),
        citation=f"{CELEX}, Art. 50(1); applicable per the general date in Art. 113",
    ),
    _obligation(
        "AIA-50-2",
        article="Art. 50(2)",
        applies_from=date(2026, 8, 2),
        grace_until=date(2026, 12, 2),
        role=Role.PROVIDER,
        coverage=Coverage.PARTIAL,
        checkability=Checkability.MACHINE_CHECKABLE,
        controls=("ACT-C-50-2-MARK",),
        citation=(
            f"{CELEX}, Art. 50(2); applicable per the general date in "
            f"Art. 113; transitional period in Art. 111(4), inserted {OMNIBUS}"
        ),
    ),
    _obligation(
        "AIA-50-3",
        article="Art. 50(3)",
        applies_from=date(2026, 8, 2),
        role=Role.DEPLOYER,
        coverage=Coverage.NOT_COVERED,
        checkability=Checkability.EVIDENCE_JUDGED,
        controls=("ACT-C-JUDGE-AIA-50-3",),
        citation=f"{CELEX}, Art. 50(3); applicable per the general date in Art. 113",
    ),
    _obligation(
        "AIA-50-4",
        article="Art. 50(4)",
        applies_from=date(2026, 8, 2),
        role=Role.DEPLOYER,
        coverage=Coverage.NOT_COVERED,
        checkability=Checkability.MACHINE_CHECKABLE,
        controls=("ACT-C-50-4-DEEPFAKE",),
        citation=f"{CELEX}, Art. 50(4); applicable per the general date in Art. 113",
    ),
    # -- Chapter III Section 5 and Chapter IX, 2 August 2026 ---------------
    # Neither section is in the Art. 113(c) deferral, so both apply on the
    # general date even though their subject, a high-risk system, does not
    # exist until Section 1 starts applying. Each note says so.
    _obligation(
        "AIA-49",
        article="Art. 49",
        applies_from=date(2026, 8, 2),
        role=Role.PROVIDER,
        coverage=Coverage.NOT_COVERED,
        checkability=Checkability.ORGANIZATIONAL,
        controls=(),
        citation=(
            f"{CELEX}, Art. 49, amended {OMNIBUS}; Chapter III Section 5 is "
            "not deferred by Art. 113(c) and applies on the general date"
        ),
    ),
    _obligation(
        "AIA-73",
        article="Art. 73",
        applies_from=date(2026, 8, 2),
        role=Role.PROVIDER,
        coverage=Coverage.NOT_COVERED,
        checkability=Checkability.ORGANIZATIONAL,
        controls=(),
        citation=(
            f"{CELEX}, Art. 73(1) to (4); Chapter IX is not deferred by "
            "Art. 113(c) and applies on the general date"
        ),
    ),
)

# In force as law, application date not yet reached. Kept separate so the
# clock can show what is coming without ever presenting a future date as a
# current duty. Everything here moved under Art. 113(c) as rewritten by the
# Digital Omnibus: 2 December 2027 for Art. 6(2) and Annex III systems, and
# 2 August 2028 for Art. 6(1) and Annex I systems. The catalogue carries the
# Annex III date, which is the earlier of the two and the one a deployer of a
# stand-alone system is bound by; each note names the later one.
FORTHCOMING: tuple[Obligation, ...] = (
    _obligation(
        "AIA-11",
        article="Art. 11 + Annex IV",
        applies_from=date(2027, 12, 2),
        role=Role.PROVIDER,
        coverage=Coverage.PARTIAL,
        checkability=Checkability.GENERATABLE,
        controls=("ACT-C-11-ANNEX-IV",),
        citation=(
            f"{CELEX}, Art. 11 and Annex IV; Chapter III Section 2 deferred "
            f"by Art. 113(c) {OMNIBUS}"
        ),
    ),
    _obligation(
        "AIA-12",
        article="Art. 12",
        applies_from=date(2027, 12, 2),
        role=Role.PROVIDER,
        coverage=Coverage.NOT_COVERED,
        checkability=Checkability.MACHINE_CHECKABLE,
        controls=("ACT-C-12-LOG",),
        citation=(
            f"{CELEX}, Art. 12; Chapter III Section 2 deferred by "
            f"Art. 113(c) {OMNIBUS}"
        ),
    ),
    _obligation(
        "AIA-15",
        article="Art. 15",
        applies_from=date(2027, 12, 2),
        role=Role.PROVIDER,
        coverage=Coverage.PARTIAL,
        checkability=Checkability.MACHINE_CHECKABLE,
        controls=("ACT-C-15-ARTIFACT", "ACT-C-15-MARK-ROBUSTNESS"),
        citation=(
            f"{CELEX}, Art. 15; Chapter III Section 2 deferred by "
            f"Art. 113(c) {OMNIBUS}"
        ),
    ),
    _obligation(
        "AIA-26",
        article="Art. 26",
        applies_from=date(2027, 12, 2),
        role=Role.DEPLOYER,
        coverage=Coverage.NOT_COVERED,
        checkability=Checkability.EVIDENCE_JUDGED,
        controls=("ACT-C-JUDGE-AIA-26",),
        citation=(
            f"{CELEX}, Art. 26, in particular 26(5) and 26(6); Chapter III "
            f"Section 3 deferred by Art. 113(c) {OMNIBUS}"
        ),
    ),
)

ALL_OBLIGATIONS: tuple[Obligation, ...] = OBLIGATIONS + FORTHCOMING


def by_id(obligation_id: str) -> Obligation | None:
    for obligation in ALL_OBLIGATIONS:
        if obligation.id == obligation_id:
            return obligation
    return None
