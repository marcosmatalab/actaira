"""Static analysis of pickle streams. Nothing is ever executed.

Design note D-05. `pickle.load` is a code-execution primitive: the opcodes
GLOBAL/STACK_GLOBAL import a callable by name and REDUCE calls it. The only
safe way to inspect a pickle is to disassemble the opcode stream without
running it. `pickletools.genops` does exactly that, and it is in the standard
library, so this inspector adds no dependency and no attack surface.

Rejected alternative: loading with a restricted `Unpickler` subclass that
refuses unknown globals. That still runs the machine, so a bug in the
restriction (there have been several in real tools) means execution. Reading
opcodes cannot execute anything by construction, which is a much stronger
guarantee than a carefully written filter.

`STACK_GLOBAL` takes its module and name from the value stack rather than
from its own argument, so resolving it requires knowing the stack. Instead
of guessing from opcode proximity, which is what a "last two strings seen"
heuristic does and which mis-pairs on real state_dicts, this module runs an
exact abstract interpretation of the stack using the `stack_before` /
`stack_after` metadata that `pickletools` publishes for every opcode,
including mark-object semantics. Constants carry their value; everything
else is an opaque slot.

The consequence that matters: when an operand is opaque, the import is
genuinely dynamic and cannot be decided statically. That case is reported as
ACT-PKL-009 at HIGH severity, never silently passed. Failing loud on what
the analysis cannot decide is the doctrine of this project, and it is the
reason the report has three verdicts instead of two.
"""
from __future__ import annotations

import pickletools
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from pickletools import markobject
from typing import Any

from ..model import Finding, Severity
from ..scan import policy

# Opcodes that cause a call, an instantiation or a state update at load time.
EXECUTION_OPCODES: frozenset[str] = frozenset(
    {"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"}
)
# Opcodes that import a callable by name.
IMPORT_OPCODES: frozenset[str] = frozenset({"GLOBAL", "STACK_GLOBAL"})
# copyreg extension registry: resolves an integer code to a callable.
EXTENSION_OPCODES: frozenset[str] = frozenset({"EXT1", "EXT2", "EXT4"})
PERSID_OPCODES: frozenset[str] = frozenset({"PERSID", "BINPERSID"})
# Opcodes that push a string constant, tracked so STACK_GLOBAL can resolve.
STRING_PUSH_OPCODES: frozenset[str] = frozenset(
    {
        "SHORT_BINUNICODE",
        "BINUNICODE",
        "BINUNICODE8",
        "UNICODE",
        "STRING",
        "BINSTRING",
        "SHORT_BINSTRING",
    }
)

# Opcodes that fold stack values into a container or a call. After one of
# these, a previously pushed string can no longer be a STACK_GLOBAL operand.
CONSUMING_OPCODES: frozenset[str] = frozenset(
    {
        "TUPLE", "TUPLE1", "TUPLE2", "TUPLE3", "DICT", "LIST", "SET", "FROZENSET",
        "APPEND", "APPENDS", "SETITEM", "SETITEMS", "ADDITEMS", "POP", "POP_MARK",
        "DUP", "STOP",
    }
)

# Bound on work per stream. A pickle header is cheap to fake, so a malicious
# artifact could otherwise make the scanner spin. 2e6 opcodes is ~3 orders of
# magnitude above the largest legitimate state_dict measured in the corpus.
MAX_OPCODES = 2_000_000


# A pickle ends at its first STOP. Bytes after it are never read by a single
# `pickle.load`, but they ARE read by any consumer that loads more than one
# object from the same stream, and a scanner that stops at STOP reports
# nothing about them. Concatenating a benign pickle and a gadget produced
# zero findings until this was added.
MAX_CONCATENATED_STREAMS = 8

# torch's pre-1.6 format writes exactly five pickles (the magic number, the
# protocol version, `sys_info`, the object, and the storage-key list) and then
# the raw storages. The number is what bounds the parse-error exemption below
# to the region where storages actually live, and it is measured rather than
# assumed: on a checkpoint written by torch 2.14, streams 0 to 4 parse and
# stream 5 is where `pickletools` stops.
LEGACY_PICKLE_STREAMS = 5

# torch's pre-1.6 serialisation format is legitimately multi-stream: it writes
# a magic number, a protocol version, a sys_info dict and the object itself as
# four separate pickles, then the raw storages. Flagging that as suspicious
# concatenation is a false positive on every checkpoint written before 2020,
# and it is exactly the kind of thing a synthetic corpus cannot teach you.
# Found by generating the corpus with the real library (evals/corpus/real.py).
TORCH_LEGACY_MAGIC = 0x1950A86A20F9469CFC6C


@dataclass
class PickleScanResult:
    findings: list[Finding] = field(default_factory=list)
    imported_callables: set[str] = field(default_factory=set)
    opcode_count: int = 0
    protocol: int | None = None
    truncated: bool = False
    parse_error: str | None = None
    execution_opcodes: int = 0
    persid_opcodes: int = 0
    container: str | None = None
    container_tail_bytes: int | None = None


def iter_ops(data: bytes) -> Iterator[tuple[Any, Any, int]]:
    """`pickletools.genops`, with the position it always has for bytes input.

    genops types its third element as `int | None` because it also accepts a
    file object that may not support `tell()`. Every caller in this package
    hands it `bytes`, which it wraps in a BytesIO, so the position is an
    integer on every iteration. The fallback keeps that from being an
    assumption rather than a fact: a stream that somehow reported no position
    yields -1, which is out of range for a real offset and so cannot be
    mistaken for one.
    """
    for opcode, argument, position in pickletools.genops(data):
        yield opcode, argument, -1 if position is None else position


MAX_NESTED_DEPTH = 4
"""Bound on how far a nested loader is followed.

Four is above anything a real artifact does (one level is already unusual)
and stops a stream that nests loaders to make the scanner spin.
"""


def scan_pickle_bytes(
    data: bytes,
    location: str,
    scan_policy: str = "strict",
    *,
    follow_trailing: bool = True,
    depth: int = 0,
) -> PickleScanResult:
    """Disassemble one pickle stream and judge every import it performs.

    `location` is carried into every finding so that a finding coming from
    `archive/data.pkl` is distinguishable from one in the outer file.

    `follow_trailing=False` scans exactly the stream that starts at byte 0
    and stops there. `_scan_trailing_streams` uses it to walk a concatenation
    forwards, one stream at a time; see the note there for why the recursive
    version could not be kept.
    """
    result = PickleScanResult()
    machine = _AbstractStack()

    try:
        for opcode, arg, _pos in iter_ops(data):
            result.opcode_count += 1
            if result.opcode_count > MAX_OPCODES:
                result.findings.append(
                    Finding(
                        rule_id="ACT-PKL-008",
                        severity=Severity.MEDIUM,
                        location=location,
                        evidence={"opcode_limit": MAX_OPCODES},
                    )
                )
                # Hitting the budget means the rest of the stream was never
                # disassembled, so the artifact was not fully read and must
                # not be able to reach PASS. ACT-PKL-008 is MEDIUM, which on
                # its own does not fail an artifact, so without this line a
                # stream engineered to run past the budget - with its gadget
                # after opcode two million - came back clean. Found by
                # fuzzing the (d) oracle, which is what `truncated` feeds.
                result.truncated = True
                break

            name = opcode.name
            if name == "PROTO":
                result.protocol = int(arg) if arg is not None else None

            popped = machine.step(opcode, arg)

            if name == "GLOBAL":
                # `pickletools` renders GLOBAL's two newline-terminated
                # fields joined by a space, and the name is the second
                # of them, so the split is from the right. Splitting
                # from the left handed a module containing a space its
                # first token as the module and the rest as the name.
                module, _, callable_name = str(arg).rpartition(" ")
                _judge_import(result, module, callable_name, location, scan_policy)
                if machine.stack:
                    machine.stack[-1] = f"{module}.{callable_name}"
            elif name == "STACK_GLOBAL":
                # stack_before is [module, name]; _pop_operands returns them
                # in stack order, so index 0 is the module.
                # Their own names: `module` and `callable_name` above are the
                # strings GLOBAL carries inline, and these come off the value
                # stack, where anything can be sitting.
                stack_module = popped[0] if len(popped) == 2 else None
                stack_name = popped[1] if len(popped) == 2 else None
                if isinstance(stack_module, str) and isinstance(stack_name, str):
                    _judge_import(result, stack_module, stack_name, location, scan_policy)
                    if machine.stack:
                        machine.stack[-1] = f"{stack_module}.{stack_name}"
                else:
                    result.findings.append(
                        Finding(
                            rule_id="ACT-PKL-009",
                            severity=Severity.HIGH,
                            location=location,
                            evidence={"reason": "stack_global_operands_not_static"},
                        )
                    )
            elif name == "INST":
                # INST carries `module\nname` inline exactly as GLOBAL does,
                # and reaches `find_class` at load time exactly as GLOBAL
                # does, but it lived only in EXECUTION_OPCODES, where it was
                # counted and never judged. Twenty-seven bytes of protocol 0,
                # `(S'echo PWNED'\nios\nsystem\n.`, therefore ran a denylisted
                # callable and passed under both policies with one INFO line.
                # Found by a hostile review; the design note at the top of this
                # module enumerated GLOBAL, STACK_GLOBAL and REDUCE and forgot
                # this one. OBJ needs no equivalent: its class comes from a
                # preceding GLOBAL, which is judged.
                result.execution_opcodes += 1
                module, _, callable_name = str(arg).rpartition(" ")
                if module and callable_name:
                    _judge_import(result, module, callable_name, location, scan_policy)
                else:
                    result.findings.append(
                        Finding(
                            rule_id="ACT-PKL-009",
                            severity=Severity.HIGH,
                            location=location,
                            evidence={"reason": "inst_operands_not_static", "opcode": "INST"},
                        )
                    )
            elif name in EXECUTION_OPCODES:
                result.execution_opcodes += 1
                if name == "REDUCE":
                    reconstructed = _reduce_to_bytes(popped)
                    if reconstructed is not None and machine.stack:
                        machine.stack[-1] = reconstructed
                    _follow_nested_loader(result, popped, location, scan_policy, depth)
            elif name in EXTENSION_OPCODES:
                result.findings.append(
                    Finding(
                        rule_id="ACT-PKL-004",
                        severity=Severity.HIGH,
                        location=location,
                        evidence={"opcode": name, "code": arg},
                    )
                )
            elif name in PERSID_OPCODES:
                # Counted, not reported one by one. A real torch checkpoint
                # uses BINPERSID once per tensor storage, so emitting a
                # finding per occurrence buried the actual result under
                # dozens of identical lines on any genuine model. Found by
                # reading the tool's own output on a real state_dict, which
                # is a review the synthetic corpus could not prompt.
                result.persid_opcodes += 1


    except Exception as exc:  # pickletools raises ValueError and others
        result.truncated = True
        result.parse_error = f"{type(exc).__name__}: {exc}"
        result.findings.append(
            Finding(
                rule_id="ACT-PKL-006",
                severity=Severity.MEDIUM,
                location=location,
                evidence={"error": result.parse_error, "opcodes_read": result.opcode_count},
            )
        )

    if follow_trailing:
        _scan_trailing_streams(data, location, scan_policy, result)

    if result.persid_opcodes:
        # Severity depends on context. Inside a torch container a persistent
        # id is the documented mechanism for tensor storages, so it is
        # informational. Anywhere else it means the loading application gets
        # to resolve an identifier the artifact chose, which is worth a look.
        in_torch_container = result.container is not None or "!" in location
        result.findings.append(
            Finding(
                rule_id="ACT-PKL-005",
                severity=Severity.INFO if in_torch_container else Severity.MEDIUM,
                location=location,
                evidence={"persistent_ids": result.persid_opcodes},
            )
        )

    if result.execution_opcodes:
        result.findings.append(
            Finding(
                rule_id="ACT-PKL-003",
                severity=Severity.INFO,
                location=location,
                evidence={"execution_opcodes": result.execution_opcodes},
            )
        )
    return result


def _judge_import(
    result: PickleScanResult,
    module: str,
    name: str,
    location: str,
    scan_policy: str,
) -> None:
    qualified = f"{module}.{name}"
    result.imported_callables.add(qualified)

    if policy.is_denied(module, name):
        rule = "ACT-PKL-007" if _is_nested_loader(module, name) else "ACT-PKL-002"
        result.findings.append(
            Finding(
                rule_id=rule,
                severity=Severity.CRITICAL,
                location=location,
                evidence={"callable": qualified, "policy": scan_policy},
            )
        )
        return

    if scan_policy == "strict" and not policy.is_allowed(module, name):
        result.findings.append(
            Finding(
                rule_id="ACT-PKL-001",
                severity=Severity.HIGH,
                location=location,
                evidence={"callable": qualified, "policy": scan_policy},
            )
        )


_NESTED_LOADERS: frozenset[tuple[str, str]] = frozenset(
    {
        ("torch", "load"),
        ("torch.serialization", "load"),
        ("torch.storage", "_load_from_bytes"),
        ("pickle", "loads"),
        ("pickle", "load"),
        ("_pickle", "loads"),
        ("dill", "loads"),
        ("joblib", "load"),
        ("pandas", "read_pickle"),
        ("numpy", "load"),
        ("marshal", "loads"),
    }
)


def _is_nested_loader(module: str, name: str) -> bool:
    return (module, name) in _NESTED_LOADERS


# ---------------------------------------------------------------------------
# Abstract stack interpretation
# ---------------------------------------------------------------------------

_MARK = object()
"""Sentinel for the pickle MARK. Identity comparison only."""

# Opcodes whose argument IS the value they push.
_VALUE_PUSHING: frozenset[str] = frozenset(
    {
        "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
        "STRING", "BINSTRING", "SHORT_BINSTRING",
        "INT", "BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4",
        "FLOAT", "BINFLOAT",
        # Byte literals are tracked because they are how a nested loader is fed:
        # `torch.storage._load_from_bytes(b"...")` carries a whole second pickle
        # inside a BINBYTES operand. Without this the inner stream is invisible.
        "BINBYTES", "SHORT_BINBYTES", "BINBYTES8",
    }
)

# Opcodes that fold their operands into a tuple. The tuple is kept, rather
# than replaced by an opaque slot, so that REDUCE can see the arguments a
# callable is about to be given.
_TUPLE_OPCODES: frozenset[str] = frozenset({"TUPLE", "TUPLE1", "TUPLE2", "TUPLE3"})

# Opcodes that leave the stack unchanged but record the top in the memo.
_MEMO_STORE: frozenset[str] = frozenset({"MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT"})
# Opcodes that push a value previously stored in the memo.
_MEMO_LOAD: frozenset[str] = frozenset({"GET", "BINGET", "LONG_BINGET"})


class _AbstractStack:
    """Exact abstract interpretation of the pickle value stack and memo.

    Modelling the memo is not optional: from protocol 4 on, the pickler
    memoises the module string and re-pushes it with BINGET, so a scanner
    without a memo loses the operands of every repeated STACK_GLOBAL.

    Measured on this repository's own corpus, protocol 4, numpy 2.4.4 and
    CPython 3.11: dropping the memo opcodes from the model leaves all four
    imports of a two-tensor state_dict unresolved; keeping them stack-neutral
    but discarding the memo dictionary leaves one unresolved. The exact count
    depends on which library produced the stream. The direction does not:
    every variant without a memo loses imports that the modelled version
    resolves, and an unresolved import is reported as ACT-PKL-009 rather than
    passed over.
    """

    __slots__ = ("stack", "memo")

    def __init__(self) -> None:
        self.stack: list[Any] = []
        self.memo: dict[Any, Any] = {}

    def step(self, opcode: Any, arg: Any) -> list[Any]:
        """Apply one opcode. Returns the operands it consumed, bottom first."""
        name = opcode.name

        if name in _MEMO_STORE:
            top = self.stack[-1] if self.stack else None
            key = len(self.memo) if name == "MEMOIZE" else arg
            self.memo[key] = top
            return []

        if name in _MEMO_LOAD:
            self.stack.append(self.memo.get(arg))
            return []

        popped = self._pop(opcode)
        self._push(opcode, arg, popped)
        return popped

    def _pop(self, opcode: Any) -> list[Any]:
        before = list(opcode.stack_before)
        if markobject in before:
            # `stack_before` is listed bottom to top, so an opcode like
            # SETITEMS ([dict, mark, stackslice]) consumes one operand BELOW
            # the mark and everything above it. Read the other way round, the
            # entries below the mark were treated as if they sat on top: the
            # walk popped one slice item as though it were a fixed operand,
            # never popped the container underneath, and dropped the rest of
            # the slice on the floor. TUPLE, which is what a pickler emits for
            # more than three elements, therefore produced a one-element tuple
            # holding only the last item, so a nested loader called with four
            # arguments looked as though it had been called with one.
            index = before.index(markobject)
            slice_items: list[Any] = []
            while self.stack and self.stack[-1] is not _MARK:
                slice_items.append(self.stack.pop())
            slice_items.reverse()
            if self.stack and self.stack[-1] is _MARK:
                self.stack.pop()
            below: list[Any] = []
            for _ in range(index):
                below.append(self.stack.pop() if self.stack else None)
            below.reverse()
            return below + slice_items
        popped = []
        for _ in range(len(before)):
            popped.append(self.stack.pop() if self.stack else None)
        popped.reverse()
        return popped

    def _push(self, opcode: Any, arg: Any, popped: list[Any] | None = None) -> None:
        popped = popped or []
        after = list(opcode.stack_after)
        if markobject in after:
            self.stack.append(_MARK)
            return
        if not after:
            return
        if len(after) == 1 and opcode.name in _VALUE_PUSHING:
            self.stack.append(arg)
            return
        if opcode.name in _TUPLE_OPCODES:
            self.stack.append(tuple(popped))
            return
        for _ in after:
            self.stack.append(None)


def _reduce_to_bytes(popped: list[Any]) -> bytes | None:
    """The byte string a REDUCE produces, when it produces one statically.

    Protocol 2 has no opcode for a byte string. The pickler writes bytes as
    `_codecs.encode(text, "latin1")`, so at protocol 2 a payload handed to a
    nested loader arrives as the RESULT of a call rather than as a literal.
    Without this the nested-loader check saw an opaque operand and reported
    only that it could not follow the payload, which downgrades a known gadget
    to an unknown one for the price of passing `protocol=2`. Found by the eval
    corpus: the regression case for the nested-loader bypass is built with
    `pickle.dumps(args, protocol=2)`, which is what a real pickler emits.

    Nothing is executed here: the operands are already known constants and the
    latin-1 round trip is the documented inverse of what the pickler did.
    """
    if len(popped) < 2:
        return None
    callee, args = popped[0], popped[1]
    if callee not in ("_codecs.encode", "codecs.encode"):
        return None
    if not isinstance(args, tuple) or not args or not isinstance(args[0], str):
        return None
    encoding = args[1] if len(args) > 1 else "latin1"
    if not isinstance(encoding, str) or encoding.lower().replace("-", "") != "latin1":
        return None
    try:
        return args[0].encode("latin-1")
    except UnicodeEncodeError:
        return None


def _scan_trailing_streams(
    data: bytes,
    location: str,
    scan_policy: str,
    result: PickleScanResult,
) -> None:
    """Follow pickles concatenated after the first STOP.

    Reported at HIGH: a legitimate artifact holds exactly one pickle, so
    trailing streams are either a repackaging trick or a format this tool has
    misidentified. Either way the caller should look.

    Each following stream is scanned with `follow_trailing=False`, and this
    loop does the walking. That is not a stylistic preference. The first
    version called the full `scan_pickle_bytes` on the remainder, which
    scanned its trailing streams too, which scanned theirs: with a branching
    factor of `MAX_CONCATENATED_STREAMS` the work went up as 2**n in the
    number of concatenated streams, and every level allocated its own copy of
    the tail and its own findings. Twenty-four bytes of `b"."` - twenty-four
    empty pickles, each a bare STOP - took 73 seconds and produced 8.1
    million Finding objects. Found by fuzzing; `fuzz/corpus/` keeps the
    input. Walking forwards visits each stream exactly once.
    """
    if result.truncated or result.parse_error:
        return
    consumed = _stream_length(data)
    if consumed is None or consumed >= len(data):
        return

    # A legacy torch container is multi-stream by design. Its later streams
    # are still scanned, since the object pickle (and therefore any gadget)
    # lives in the fourth one; only the "unexpected trailing data" finding is
    # suppressed, and the container is recorded so the report can say why.
    legacy = _is_torch_legacy_header(data[:consumed])
    if legacy:
        result.container = "torch-legacy"
        result.findings = [
            finding for finding in result.findings if finding.rule_id != "ACT-PKL-006"
        ]

    streams = 0
    offset = consumed
    while offset < len(data) and streams < MAX_CONCATENATED_STREAMS:
        remainder = data[offset:]
        if remainder.strip(b"\x00") == b"":
            # Zero padding, not a stream. `pickle.load` stops at the STOP
            # before it, so these bytes never reach the unpickler, and failing
            # an artifact over them would be noise. They are still bytes in
            # the file that nothing else in the report accounts for, so they
            # are stated rather than dropped: silence here read as "the whole
            # file was analysed", which was true only by accident.
            result.findings.append(
                Finding(
                    rule_id="ACT-PKL-012",
                    severity=Severity.INFO,
                    location=location,
                    evidence={"offset": offset, "padding_bytes": len(remainder)},
                )
            )
            return  # trailing padding, not a stream
        nested = scan_pickle_bytes(
            remainder, f"{location}+{offset}", scan_policy, follow_trailing=False
        )
        streams += 1
        if legacy:
            # Inside a legacy container these two findings describe the
            # container, not the artifact: the last stream is followed by raw
            # tensor storages (so it reads as truncated), and the multi-stream
            # layout is the documented format rather than a repackaging trick.
            # Everything else the nested scan judged, including every import,
            # is kept: the object pickle lives in the fourth stream, so a
            # gadget hidden there is still reported. Pinned by a negative
            # control in tests/test_real_artifacts.py.
            #
            # The parse-error half of that suppression is bounded by position,
            # and the bound is not a guess: `torch._legacy_save` writes the
            # magic number, the protocol version, `sys_info`, the object and
            # the storage-key list as five pickles, and only then the raw
            # storages. Measured on a checkpoint torch wrote, streams 0 to 4
            # parse and stream 5 is the storage region.
            #
            # Without the bound a hostile review reached PASS with exit 0 on
            # 48 bytes: the magic number, then `I\x00\n.`, which real `pickle`
            # reads as the integer 0 followed by STOP while `pickletools`
            # raises on it, then an `os.system` gadget. The parse error was
            # suppressed as if it were the storage region, the walker gave up
            # on a stream length it could not compute, and the gadget behind
            # it was never disassembled or reported.
            in_storage_region = streams > LEGACY_PICKLE_STREAMS - 1
            suppressed = ("ACT-PKL-006", "ACT-PKL-010") if in_storage_region else ("ACT-PKL-010",)
            nested.findings = [
                # A persistent id is the documented way this container names a
                # tensor storage, so inside it the finding is informational.
                # The nested scan cannot know it is inside a container, so it
                # rated it MEDIUM and every pre-1.6 checkpoint carried a
                # yellow line for doing exactly what the format says. Found by
                # reading the tool's output on a checkpoint written by torch
                # itself, which is the review a synthetic corpus cannot ask
                # for.
                replace(finding, severity=Severity.INFO)
                if finding.rule_id == "ACT-PKL-005"
                else finding
                for finding in nested.findings
                if finding.rule_id not in suppressed
            ]
        else:
            result.findings.append(
                Finding(
                    rule_id="ACT-PKL-010",
                    severity=Severity.HIGH,
                    location=location,
                    evidence={"offset": offset, "trailing_bytes": len(remainder)},
                )
            )
        result.findings.extend(nested.findings)
        result.imported_callables |= nested.imported_callables
        nested_length = _stream_length(remainder)
        if nested_length is None or nested_length <= 0:
            # The length of this stream could not be computed, so the walk
            # cannot continue and whatever follows was never disassembled.
            # Inside a legacy container past the fifth stream that is the raw
            # storage region and is expected; anywhere else it is unread
            # bytes, and returning in silence was the second half of the
            # bypass described above.
            if legacy and streams >= LEGACY_PICKLE_STREAMS:
                result.container_tail_bytes = len(data) - offset
            else:
                _report_unread_tail(result, location, data, offset, "stream_length_unknown")
            return
        offset += nested_length

    if offset < len(data) and streams >= MAX_CONCATENATED_STREAMS:
        _report_unread_tail(result, location, data, offset, "stream_budget")


def _report_unread_tail(
    result: PickleScanResult,
    location: str,
    data: bytes,
    offset: int,
    reason: str,
) -> None:
    """Say that bytes were left unread, and stop them reaching PASS.

    Two paths through the trailing-stream walk end with bytes nobody
    disassembled: the stream budget runs out, or a stream's length cannot be
    computed. Both used to leave the loop in silence, and a hostile review
    reached a clean PASS with exit 0 through each of them. `truncated` is what
    `inspect.py` reads to decide the artifact was not fully read, and it is
    set here for the same reason the opcode-budget path sets it: a budget or a
    failure that was reached means bytes that were not analysed, and an
    artifact that was not analysed cannot be reported as clean.
    """
    result.truncated = True
    result.findings.append(
        Finding(
            rule_id="ACT-PKL-013",
            severity=Severity.HIGH,
            location=location,
            evidence={
                "reason": reason,
                "stream_limit": MAX_CONCATENATED_STREAMS,
                "unread_bytes": len(data) - offset,
                "offset": offset,
            },
        )
    )


def _stream_length(data: bytes) -> int | None:
    """Byte length of the first pickle in `data`, or None if it does not parse."""
    try:
        for opcode, _arg, position in iter_ops(data):
            if opcode.name == "STOP":
                return position + 1
    except Exception:
        return None
    return None


def _is_torch_legacy_header(first_stream: bytes) -> bool:
    """True when the first pickle is torch's legacy magic number.

    Matched structurally, not by loading: a stream whose only data opcode is a
    LONG carrying TORCH_LEGACY_MAGIC. Recognising the container by its own
    documented header, rather than by file extension, keeps an attacker from
    claiming the exemption just by naming a file `.pt`.
    """
    values: list[Any] = []
    try:
        for opcode, arg, _pos in pickletools.genops(first_stream):
            if opcode.name in ("PROTO", "STOP", "MEMOIZE", "FRAME"):
                continue
            if arg is None:
                return False
            values.append(arg)
    except Exception:
        return False
    return len(values) == 1 and values[0] == TORCH_LEGACY_MAGIC


def _follow_nested_loader(
    result: PickleScanResult,
    popped: list[Any],
    location: str,
    scan_policy: str,
    depth: int,
) -> None:
    """Scan the pickle a nested loader is about to be handed.

    Design note D-35, and it exists because of a specific escape.
    `torch.storage._load_from_bytes` was on the allowlist, catalogued as
    tensor reconstruction. Its body is
    `torch.load(io.BytesIO(b), weights_only=False)`: a full unpickler on
    attacker bytes, with the safe mode explicitly off. A gadget wrapped in one
    BINBYTES operand reached PASS with exit 0 under both policies, and a test
    blessed the allowlist entry.

    Denying the callable would have been the small fix. This is the right one:
    the bytes an inner loader is given are themselves a pickle, so they are
    disassembled with the same machinery and their findings are merged, with
    the location carrying the nesting so a reader can see where it came from.
    An artifact that hides a gadget one level down is now reported for the
    gadget, not merely for the wrapper.
    """
    if depth >= MAX_NESTED_DEPTH or len(popped) < 2:
        return
    callee, args = popped[0], popped[1]
    if not isinstance(callee, str) or callee not in _NESTED_LOADER_NAMES:
        return

    payloads = [item for item in (args if isinstance(args, tuple) else ()) if isinstance(item, bytes)]
    if not payloads:
        # A nested loader whose argument is not a literal cannot be followed.
        # Saying so is the point: an unfollowable inner load is not a clean one.
        result.findings.append(
            Finding(
                rule_id="ACT-PKL-011",
                severity=Severity.HIGH,
                location=location,
                evidence={"callable": callee, "reason": "nested_payload_not_static"},
            )
        )
        return

    for index, payload in enumerate(payloads):
        inner_location = f"{location}>{callee}#{index}"
        inner = scan_pickle_bytes(
            payload, inner_location, scan_policy, follow_trailing=False, depth=depth + 1
        )
        result.findings.append(
            Finding(
                rule_id="ACT-PKL-011",
                severity=Severity.HIGH,
                location=location,
                evidence={
                    "callable": callee,
                    "inner_bytes": len(payload),
                    "inner_findings": len(inner.findings),
                },
            )
        )
        result.findings.extend(inner.findings)
        result.imported_callables |= inner.imported_callables


_NESTED_LOADER_NAMES: frozenset[str] = frozenset(
    f"{module}.{name}" for module, name in _NESTED_LOADERS
)
