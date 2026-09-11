"""What applies today, and what does not yet.

Design note D-30. The AI Act applies in stages, and the stages moved: the
Digital Omnibus on AI, Regulation (EU) 2026/1744, deferred the Annex III
high-risk obligations to 2 December 2027 and the Annex I ones to 2 August
2028. It was published in the Official Journal on 24 July 2026 and has been
in force since 27 July 2026. Plenty of published material still shows the old
dates, and a tool that hardcodes any of them silently ages.

So dates are data, every row carries the provision it comes from, and a
deferral that has been agreed but not yet published in the Official Journal
is marked PROVISIONAL and says so in every rendering. A provisional date is
never presented as settled law: an organisation that stops preparing because
a tool told them a deadline moved, and then finds the text was never
published, is worse off than one this tool never spoke to.

Nothing in the catalogue is provisional today. The three high-risk rows that
carried the flag lost it when the Omnibus was published, and that is the flag
working rather than the flag being pointless: it described a real state while
the deferral was a political agreement, and the next amendment will spend
time in the same state. `test_governance.py` pins both halves, that no
obligation is provisional now and that the marker still fires on one that is.

The clock takes the date as an argument rather than reading the system
clock, so its output is reproducible and testable.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

from ..i18n.catalog import Catalog
from .catalog import ALL_OBLIGATIONS, Obligation, Status, localized


@dataclass
class ClockRow:
    obligation: Obligation
    applicable: bool
    in_grace: bool
    days_until: int | None

    def to_dict(self) -> dict[str, Any]:
        payload = self.obligation.to_dict()
        payload.update(
            {
                "applicable": self.applicable,
                "in_grace_period": self.in_grace,
                "days_until": self.days_until,
            }
        )
        return payload


def clock(on: date, horizon_days: int | None = None) -> list[ClockRow]:
    """Every obligation, with whether it applies on `on`.

    `horizon_days` filters to what applies now plus what starts within the
    horizon, which is the question an organisation actually asks.
    """
    rows: list[ClockRow] = []
    for obligation in ALL_OBLIGATIONS:
        applicable = obligation.applies_from <= on
        days_until = None if applicable else (obligation.applies_from - on).days
        in_grace = bool(
            applicable
            and obligation.grace_until is not None
            and on < obligation.grace_until
        )
        if horizon_days is not None and not applicable and (days_until or 0) > horizon_days:
            continue
        rows.append(ClockRow(obligation, applicable, in_grace, days_until))
    rows.sort(key=lambda row: (not row.applicable, row.obligation.applies_from, row.obligation.id))
    return rows


def render(rows: list[ClockRow], on: date, lang: str = "en") -> str:
    """The clock as text, in `lang`.

    Titles and the scope of a grace period come from the message catalogue,
    so a Spanish reader gets Spanish. Identifiers, articles and dates do not
    move between languages: those are the facts, and a translation that could
    shift a deadline would be worse than no translation at all.
    """
    catalog = Catalog(lang)
    lines: list[str] = []
    lines.append(catalog.line("gov.clock.header", on=on.isoformat()))
    lines.append("")
    applicable = [row for row in rows if row.applicable]
    upcoming = [row for row in rows if not row.applicable]

    lines.append(f"{catalog.line('gov.clock.applies_now')} ({len(applicable)})")
    for row in applicable:
        text = localized(row.obligation, lang)
        flag = ""
        if row.in_grace and row.obligation.grace_until:
            flag = "  [" + catalog.line(
                "gov.clock.grace",
                until=row.obligation.grace_until.isoformat(),
                scope=text.get("grace_scope") or "",
            ) + "]"
        lines.append(
            f"  {row.obligation.id:12} {row.obligation.article:19} "
            f"{catalog.line('gov.clock.since')} {row.obligation.applies_from.isoformat()}  "
            f"{row.obligation.role.value:22} {text['title']}{flag}"
        )
    lines.append("")
    lines.append(f"{catalog.line('gov.clock.not_yet')} ({len(upcoming)})")
    for row in upcoming:
        mark = " PROVISIONAL" if row.obligation.status is Status.PROVISIONAL else ""
        text = localized(row.obligation, lang)
        lines.append(
            f"  {row.obligation.id:12} {row.obligation.article:19} "
            f"{catalog.line('gov.clock.from')}  {row.obligation.applies_from.isoformat()} "
            f"({catalog.line('gov.clock.days', days=row.days_until)}){mark}  {text['title']}"
        )
    if any(row.obligation.status is Status.PROVISIONAL for row in rows):
        lines.append("")
        lines.append(catalog.line("gov.clock.provisional"))
    return "\n".join(lines)
