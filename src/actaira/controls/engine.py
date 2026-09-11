"""Running controls over a target, and loading what the operator declared.

Design note D-44, on why a control that raises is a defect and not a failure.
The engine catches exceptions from control code and turns them into
INCONCLUSIVE with the exception in the evidence. That is deliberate and it is
the opposite of the usual advice, for one reason: the alternative is that a
malformed target file takes down a run and the operator sees nothing at all
about the other thirteen controls. An exception is a control that could not
decide, which is exactly what INCONCLUSIVE means, and it is recorded loudly
enough that it cannot pass for a clean result: the reason field names the
exception type and the rule id `ACT-CTL-001` fires.

What the engine refuses to do is aggregate. It returns a `ControlRun`, which
counts outcomes and never divides one by another. See design note D-41.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..io_budget import read_at_most
from ..miniyaml import loads as _mini_yaml
from ..model import Finding, Severity
from . import registry
from .model import Control, ControlResult, ControlRun, Method, Outcome, Target

DECLARATION_NAMES = ("actaira.yaml", "actaira.yml", "actaira.json")
MAX_DECLARATION_BYTES = 1 << 20


def load_target(root: Path, role: str = "any") -> Target:
    """Build a Target from a directory.

    The declaration file is the operator's own statement about their systems.
    It is read as data and never trusted as a measurement: every field that
    comes from it surfaces under a `declared_` prefix, so a reader can always
    tell an assertion from an observation.
    """
    root = Path(root)
    declarations: dict[str, Any] = {}
    for name in DECLARATION_NAMES:
        candidate = root / name
        if not candidate.is_file():
            continue
        # Bounded at the read, not after it. `read_bytes()[:N]` had the
        # whole file in memory before the slice ran, so the cap protected
        # nothing: design note D-160.
        raw, _ = read_at_most(candidate, MAX_DECLARATION_BYTES)
        try:
            if candidate.suffix == ".json":
                declarations = json.loads(raw.decode("utf-8"))
            else:
                declarations = _mini_yaml(raw.decode("utf-8"))
        except Exception:
            # A declaration file that does not parse is not a reason to stop.
            # It becomes an empty declaration, and ACT-CTL-002 fires below.
            declarations = {"_parse_error": candidate.name}
        break

    files: list[Path] = []
    if root.is_dir():
        files = sorted(p for p in root.rglob("*") if p.is_file())
    elif root.is_file():
        files = [root]
    return Target(root=root, role=role, declarations=declarations or {}, files=tuple(files))


def run(target: Target, control_ids: tuple[str, ...] | None = None) -> ControlRun:
    controls: tuple[Control, ...]
    if control_ids is None:
        controls = registry.all_controls()
    else:
        controls = tuple(registry.get(cid) for cid in control_ids)

    results: list[ControlResult] = []
    for control in controls:
        results.append(_run_one(control, target))
    return ControlRun(
        results=tuple(results),
        target_root=str(target.root),
        role=target.role,
    )


def _run_one(control: Control, target: Target) -> ControlResult:
    try:
        result = control(target)
    except Exception as exc:  # noqa: BLE001 - see design note D-44
        return ControlResult(
            control_id=control.id,
            obligation_ids=control.obligation_ids,
            outcome=Outcome.INCONCLUSIVE,
            method=control.method,
            evidence={"reason": "control_raised", "error": f"{type(exc).__name__}: {exc}"},
            findings=(
                Finding(
                    rule_id="ACT-CTL-001",
                    severity=Severity.MEDIUM,
                    location=control.id,
                    evidence={"error": f"{type(exc).__name__}: {exc}"},
                ),
            ),
        )
    if not isinstance(result, ControlResult):
        raise TypeError(f"{control.id} returned {type(result).__name__}, not ControlResult")
    if result.outcome is Outcome.SATISFIED and control.method is Method.GENERATED:
        # Design note D-40: a draft nobody signed is not evidence. A generated
        # control that claims SATISFIED is a bug in that control, and it is
        # caught here rather than in review.
        raise ValueError(f"{control.id} is GENERATED and may not return SATISFIED")
    return result


# `_mini_yaml` is `actaira.miniyaml.loads`, imported above rather than
# reimplemented here. Design note D-110: the policy engine needs the same
# subset, and two copies of a hand-written parser is two places for the same
# bug. The name is kept because the declaration-file tests and the design
# notes both refer to it.
