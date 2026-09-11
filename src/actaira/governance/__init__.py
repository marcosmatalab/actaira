"""EU AI Act governance layer.

Turns technical evidence about model artifacts into a record of which
obligations that evidence touches, and, with equal prominence, which it does
not. There is no compliance score anywhere in this package: see the design
notes in `catalog.py` and `assess.py` for why that is a decision rather than
an unfinished feature.

The obligations' prose lives in `i18n/<lang>.json` under `governance`, not in
this package; `localized(obligation, lang)` is how it is served.
"""
from .assess import Assessment, assess, gaps, unread_artifacts
from .catalog import ALL_OBLIGATIONS, Coverage, Obligation, Role, Status, by_id, localized
from .clock import clock, render

__all__ = [
    "ALL_OBLIGATIONS", "Assessment", "Coverage", "Obligation", "Role", "Status",
    "assess", "by_id", "clock", "gaps", "localized", "render", "unread_artifacts",
]
