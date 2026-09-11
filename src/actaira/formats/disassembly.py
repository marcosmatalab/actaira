"""Human-readable pickle disassembly, for showing the reader the mechanism.

Design note D-21. Telling someone "this file imports os.system" is a claim
they have to take on trust. Showing them the opcode that does it, in order,
with the callable resolved, is evidence they can check. This module produces
that view: the same abstract interpretation the scanner runs, emitted as a
list of steps instead of a list of findings.

It shares `scan_pickle_bytes`'s machinery rather than reimplementing it, so
the disassembly can never disagree with the verdict. A second implementation
that drifted from the first would be worse than no disassembly at all.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..scan import policy
from .pickle_scan import (
    EXECUTION_OPCODES,
    EXTENSION_OPCODES,
    IMPORT_OPCODES,
    PERSID_OPCODES,
    _AbstractStack,
    iter_ops,
)

MAX_STEPS = 4096


@dataclass
class Step:
    index: int
    offset: int
    opcode: str
    arg: str | None
    kind: str  # import | execute | extension | persid | data | proto | stop
    resolved: str | None = None
    judgement: str | None = None  # denied | unknown | allowed | unresolved

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "offset": self.offset,
            "opcode": self.opcode,
            "arg": self.arg,
            "kind": self.kind,
            "resolved": self.resolved,
            "judgement": self.judgement,
        }


@dataclass
class Disassembly:
    steps: list[Step] = field(default_factory=list)
    total_opcodes: int = 0
    truncated: bool = False
    parse_error: str | None = None
    protocol: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": [step.to_dict() for step in self.steps],
            "total_opcodes": self.total_opcodes,
            "truncated": self.truncated,
            "parse_error": self.parse_error,
            "protocol": self.protocol,
            "counts": {
                kind: sum(1 for step in self.steps if step.kind == kind)
                for kind in ("import", "execute", "extension", "persid", "data")
            },
        }


def disassemble(data: bytes, scan_policy: str = "strict", limit: int = MAX_STEPS) -> Disassembly:
    """Walk the opcode stream and annotate every step that matters."""
    result = Disassembly()
    machine = _AbstractStack()

    try:
        for opcode, arg, position in iter_ops(data):
            result.total_opcodes += 1
            popped = machine.step(opcode, arg)
            if len(result.steps) >= limit:
                continue

            name = opcode.name
            step = Step(
                index=len(result.steps),
                offset=position,
                opcode=name,
                arg=_short(arg),
                kind="data",
            )

            if name == "PROTO":
                step.kind = "proto"
                result.protocol = int(arg) if arg is not None else None
            elif name == "STOP":
                step.kind = "stop"
            elif name in IMPORT_OPCODES:
                step.kind = "import"
                module, callable_name = _operands(name, arg, popped)
                if module is None or callable_name is None:
                    step.judgement = "unresolved"
                else:
                    step.resolved = f"{module}.{callable_name}"
                    step.judgement = _judge(module, callable_name, scan_policy)
            elif name in EXECUTION_OPCODES:
                step.kind = "execute"
            elif name in EXTENSION_OPCODES:
                step.kind = "extension"
            elif name in PERSID_OPCODES:
                step.kind = "persid"

            result.steps.append(step)

    except Exception as exc:
        result.truncated = True
        result.parse_error = f"{type(exc).__name__}: {exc}"
    return result


def _operands(name: str, arg: Any, popped: list[Any]) -> tuple[str | None, str | None]:
    if name == "GLOBAL":
        module, _, callable_name = str(arg).partition(" ")
        return module or None, callable_name or None
    if len(popped) == 2 and isinstance(popped[0], str) and isinstance(popped[1], str):
        return popped[0], popped[1]
    return None, None


def _judge(module: str, name: str, scan_policy: str) -> str:
    if policy.is_denied(module, name):
        return "denied"
    if policy.is_allowed(module, name):
        return "allowed"
    return "unknown" if scan_policy == "strict" else "tolerated"


def _short(arg: Any, limit: int = 96) -> str | None:
    if arg is None:
        return None
    text = repr(arg) if not isinstance(arg, str) else arg
    return text if len(text) <= limit else text[: limit - 1] + "…"
