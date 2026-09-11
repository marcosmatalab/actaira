"""The control registry, and the rules that keep the mapping honest.

Design note D-43. A compliance tool's most dangerous file is the one that
maps its checks to a regulation, because a wrong edge there is invisible: the
dashboard goes green and nothing in the system disagrees. Three rules,
enforced by tests rather than by care:

  1. Registration is explicit and duplicate ids are refused. Two controls
     under one id means one of them silently never runs.
  2. Every edge is checked in both directions. A control naming an obligation
     that is not in the catalogue fails; an obligation naming a control that
     was never registered fails. `tests/test_controls.py` walks both.
  3. A control may only be bound to an obligation whose `checkability` says
     that kind of control can bear on it. A DETERMINISTIC control cannot be
     bound to an ORGANIZATIONAL obligation, because if a deterministic check
     really did decide it, the obligation was misclassified and the catalogue
     should say so.

Importing this module imports every control module, so the registry is
complete after one import and a control that fails to import is an error at
start-up rather than an obligation that quietly has nothing behind it.
"""
from __future__ import annotations

from .model import Control

_REGISTRY: dict[str, Control] = {}


def register(control: Control) -> Control:
    if control.id in _REGISTRY:
        raise ValueError(f"duplicate control id {control.id!r}")
    _REGISTRY[control.id] = control
    return control


def get(control_id: str) -> Control:
    _ensure_loaded()
    return _REGISTRY[control_id]


def all_controls() -> tuple[Control, ...]:
    _ensure_loaded()
    return tuple(_REGISTRY[key] for key in sorted(_REGISTRY))


_LOADED = False


def _ensure_loaded() -> None:
    """Import every control module exactly once.

    Deferred rather than done at module import because `model.py` and this
    file are imported by the control modules themselves, and a circular
    import at definition time would be resolved by luck.
    """
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    from . import (  # noqa: F401
        art50,
        documentation,
        judged,
        records,
    )
