"""Zip-container inspector: modern PyTorch checkpoints, .npz, .keras.

A modern `.pt` is a zip holding `data.pkl` plus raw storage blobs, so the
pickle problem is still there, one level down. Anything that only sniffs the
outer file sees "zip" and stops; that is the gap this module closes.

Two container-level attacks are checked here because they are properties of
the archive rather than of any member: path traversal in member names
(a member called `../../etc/cron.d/x` writes outside the extraction root in
any tool that extracts naively) and compression ratio (a small archive that
expands without bound).
"""
from __future__ import annotations

import pickletools
import zipfile
from pathlib import Path
from typing import Any

from ..model import Finding, Severity
from .detect import PICKLE_OPCODE_BYTES
from .pickle_scan import scan_pickle_bytes

# Members whose name commits them to being a pickle. These are ALWAYS scanned,
# and a member that does not parse becomes ACT-PKL-006, never a silent skip.
# `data.pkl` is the PyTorch convention; the rest catch repackaging.
ALWAYS_PICKLE_SUFFIXES = (".pkl", ".pickle", "data.pkl")
# Members whose name is ambiguous. Inside a checkpoint, `.bin` is usually a raw
# weight blob, but `pytorch_model.bin` on a model hub is a pickle. These are
# scanned only when the bytes look like a pickle at both ends, so a multi-
# megabyte tensor blob does not produce a parse-error finding on every load.
AMBIGUOUS_PICKLE_SUFFIXES = (".bin", ".ckpt", ".pt", ".pth")

# Ratio above which an archive member is reported as a decompression bomb.
# Severity is HIGH, not MEDIUM: an artifact that expands without bound is a
# denial-of-service against whoever loads it, which is a real effect on the
# consumer rather than a hygiene note. This was raised after the eval showed
# a bomb artifact reaching verdict PASS at the default --fail-on=high.
# Chosen from measurement: raw float buffers barely compress (1.9x on the
# corpus checkpoint), while a realistic sharded weight index, which is
# repetitive JSON, reaches about 35x (tests/test_formats.py). 100 sits clear
# of both and far below the 1000x+ a padding bomb produces.
MAX_COMPRESSION_RATIO = 100
MAX_MEMBERS_INSPECTED = 512
# How many member names ACT-ZIP-007 prints before it stops naming and starts
# counting. A 600-shard checkpoint would otherwise put 600 strings into every
# report, SARIF document and attestation payload that mentions it.
MAX_NAMES_IN_EVIDENCE = 20
# Cap on the decompressed size of a single member. 256 MiB is above any
# `data.pkl` measured (a state_dict pickle holds offsets, not weights: the
# largest in the corpus is under 1 MiB) and bounded enough that a directory
# of hostile archives cannot exhaust memory.
MAX_MEMBER_BYTES = 256 * 1024 * 1024
# How many bytes of a member are decompressed to decide whether it is worth
# decompressing the rest.
#
# Design note D-102. Every earlier version of this gate decided by NAME, and
# a name is the one part of an archive an attacker fully controls. A pickle
# called `data/0` - which is exactly what a PyTorch storage blob is called -
# was never opened, never scanned and never mentioned beyond a line saying
# some members had been skipped. The archive still came back INCONCLUSIVE, so
# nothing was claimed falsely, but nothing found the gadget either, and a
# reader who passed `--allow-inconclusive` because checkpoints are always
# inconclusive got a clean exit over a live payload.
#
# So the gate reads instead. 64 KiB of a member is enough to tell a pickle
# from a float buffer: a pickle disassembles, and a buffer of little-endian
# floats stops at or near the first opcode. Cost is bounded and small - 64 KiB
# times at most 512 members, against gigabytes for a naive "open everything" -
# and the error is one-sided by construction: a prefix that disassembles gets
# the member fully scanned, so the expensive path is only taken for something
# that already looks like code.
MEMBER_PEEK_BYTES = 64 * 1024
# Opcodes a prefix must disassemble before the member is treated as code.
# One is not enough: a single byte of tensor data lands on a valid opcode
# roughly a quarter of the time, and every one of those would decompress a
# multi-gigabyte shard to prove it was not a pickle. Four consecutive valid
# opcodes over arbitrary bytes is rare, and a real pickle clears it in the
# header alone - a protocol 2+ stream opens PROTO, FRAME, EMPTY_DICT, BINPUT
# before it says anything.
MIN_PREFIX_OPCODES = 4


def inspect(path: Path, scan_policy: str = "strict") -> tuple[list[Finding], dict[str, Any], set[str]]:
    findings: list[Finding] = []
    metadata: dict[str, Any] = {}
    imported: set[str] = set()

    try:
        archive = zipfile.ZipFile(path)
    except Exception as exc:
        findings.append(
            Finding(
                rule_id="ACT-ZIP-005",
                severity=Severity.MEDIUM,
                location=path.name,
                evidence={"error": f"{type(exc).__name__}: {exc}"},
            )
        )
        return findings, metadata, imported

    with archive:
        members = archive.infolist()
        metadata["member_count"] = len(members)
        pickle_members: list[str] = []
        unreadable_members: list[str] = []

        for info in members[:MAX_MEMBERS_INSPECTED]:
            name = info.filename
            if _is_traversal(name):
                findings.append(
                    Finding(
                        rule_id="ACT-ZIP-001",
                        severity=Severity.HIGH,
                        location=f"{path.name}!{name}",
                        evidence={"member": name},
                    )
                )
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > MAX_COMPRESSION_RATIO:
                    findings.append(
                        Finding(
                            rule_id="ACT-ZIP-002",
                            severity=Severity.HIGH,
                            location=f"{path.name}!{name}",
                            evidence={
                                "ratio": round(ratio, 1),
                                "limit": MAX_COMPRESSION_RATIO,
                                "uncompressed_bytes": info.file_size,
                            },
                        )
                    )
            # Content first, name second. The name may promote a member to
            # "always scan" but may never keep one out: `data/0` whose bytes
            # disassemble is opened exactly like `data.pkl`.
            if _member_is_pickle_by_name(name) or _member_is_ambiguous(name):
                pickle_members.append(name)
                continue
            verdict, head = _peek_member(archive, name)
            if verdict == "unreadable":
                unreadable_members.append(name)
                findings.append(
                    Finding(
                        rule_id="ACT-ZIP-009",
                        severity=Severity.MEDIUM,
                        location=f"{path.name}!{name}",
                        evidence={"reason": "member_head_unreadable"},
                    )
                )
            elif verdict == "code":
                pickle_members.append(name)
                # A member whose name says storage and whose bytes say pickle
                # is not a mistake anyone makes by accident. This is the
                # in-archive twin of ACT-FMT-002, and it is HIGH because it is
                # the shape of a deliberate bypass rather than a hygiene note.
                findings.append(
                    Finding(
                        rule_id="ACT-ZIP-008",
                        severity=Severity.HIGH,
                        location=f"{path.name}!{name}",
                        evidence={
                            "member": name,
                            "name_suggests": "raw_storage",
                            "bytes_suggest": "pickle",
                            "head_bytes": len(head),
                        },
                    )
                )

        if len(members) > MAX_MEMBERS_INSPECTED:
            findings.append(
                Finding(
                    rule_id="ACT-ZIP-004",
                    severity=Severity.MEDIUM,
                    location=path.name,
                    evidence={"members": len(members), "inspected": MAX_MEMBERS_INSPECTED},
                )
            )

        metadata["pickle_members"] = pickle_members

        # Say what was not decompressed in full, and say what that limits.
        #
        # Design note D-103. Every member here had its head read and its
        # bytes classified; what was declined is the rest of a blob already
        # shown not to be code. That is a scope statement about raw tensor
        # content, which this tool never claimed to assess, and the coverage
        # matrix records it as exactly that: RAW_TENSOR_CONTENT NOT_ASSESSED,
        # with the load-time execution surface untouched.
        #
        # The previous version put this rule in a flat `UNREAD_RULE_IDS` set
        # that drove one global `fully_read` boolean, so it took the verdict
        # of every clean PyTorch checkpoint in existence down to INCONCLUSIVE
        # and made `actaira scan` exit 3 over a normal file. Teams responded
        # the only way available to them - `--allow-inconclusive` everywhere -
        # and that switch also hid the artifacts whose headers genuinely would
        # not parse. A signal that fires on every input is not a signal, and
        # this one was suppressing the ones that mattered.
        #
        # Severity stays INFO: this is scope, not a finding about the artifact,
        # and at any higher severity `--fail-on=low` would fail every
        # checkpoint ever written.
        inspected = set(pickle_members)
        not_inspected = [info.filename for info in members if info.filename not in inspected]
        if not_inspected:
            metadata["members_not_inspected"] = not_inspected
            findings.append(
                Finding(
                    rule_id="ACT-ZIP-007",
                    severity=Severity.INFO,
                    location=path.name,
                    evidence={
                        "members": not_inspected[:MAX_NAMES_IN_EVIDENCE],
                        "count": len(not_inspected),
                        "reason": "bytes are not a pickle; remainder not decompressed",
                        "classified_by": "content",
                        "limits_surface": "raw_tensor_content",
                    },
                )
            )

        not_pickle_members: list[str] = []
        if not pickle_members:
            return findings, metadata, imported

        for name in pickle_members:
            payload = _read_bounded(archive, name, path, findings)
            if payload is None:
                continue
            # No name gate and no shape gate decide whether a member is
            # analysed: every member on this list is disassembled, and the
            # decision is made on what the disassembly found. Two earlier
            # versions gated first, and both were bypassed. The first skipped
            # members whose first byte was not one of seven "pickle start"
            # opcodes, which a hostile review defeated in one line: a protocol
            # 0 stream beginning with INT ("I") carried posix.system through
            # to a clean PASS. The second kept an ambiguous member only when
            # its bytes looked like a pickle at both ends, so appending a
            # single byte after STOP made the member fail the tail check and
            # be dropped with a bare `continue`, emitting no rule and leaving
            # `fully_read` True: PASS again, one byte of work.
            #
            # A raw tensor blob is not a pickle and its disassembly says so:
            # it fails at or near the first opcode, imports nothing, and calls
            # nothing. That, and only that, is what is dropped here, and it is
            # recorded in the metadata so the report can be asked what the
            # inspector decided to ignore. Anything that imports, calls, or
            # parses far enough to matter keeps its findings, whatever the
            # member is called and however its tail looks.
            result = scan_pickle_bytes(payload, f"{path.name}!{name}", scan_policy)
            committed = _member_is_pickle_by_name(name) or _bytes_look_like_pickle(payload)
            if not committed and _is_not_a_pickle(result):
                not_pickle_members.append(name)
                continue
            findings.extend(result.findings)
            imported |= result.imported_callables

        if not_pickle_members:
            metadata["members_not_pickle"] = not_pickle_members
        if unreadable_members:
            metadata["members_unreadable"] = unreadable_members

    return findings, metadata, imported


def _is_not_a_pickle(result) -> bool:
    """True when a disassembly says the member is data, not a pickle.

    The bar is deliberately low, because the cost of the two errors is not
    symmetric. Calling a pickle "data" is the bypass this function exists to
    close; calling a blob "a pickle" costs one parse-error line in a report.
    So a member is dismissed only when its disassembly imported nothing,
    called nothing, resolved no persistent id, and failed to parse. Anything
    else is reported as found.
    """
    if result.imported_callables or result.execution_opcodes or result.persid_opcodes:
        return False
    if not result.parse_error:
        return False
    return all(finding.rule_id == "ACT-PKL-006" for finding in result.findings)


def _read_bounded(archive, name: str, path, findings: list[Finding]) -> bytes | None:
    """Read a member with a hard cap on decompressed size.

    `ZipFile.read` decompresses without limit, so a 400 KiB archive holding a
    400 MiB member made the inspector allocate 400 MiB: a denial of service
    against the machine doing the auditing, found by measuring RSS during a
    hostile review. Reading one byte past the cap is enough to detect the
    overflow without materialising it.
    """
    try:
        with archive.open(name) as handle:
            payload = handle.read(MAX_MEMBER_BYTES + 1)
    except Exception as exc:
        findings.append(
            Finding(
                rule_id="ACT-ZIP-003",
                severity=Severity.MEDIUM,
                location=f"{path.name}!{name}",
                evidence={"error": f"{type(exc).__name__}: {exc}"},
            )
        )
        return None
    if len(payload) > MAX_MEMBER_BYTES:
        findings.append(
            Finding(
                rule_id="ACT-ZIP-006",
                severity=Severity.HIGH,
                location=f"{path.name}!{name}",
                evidence={"limit_bytes": MAX_MEMBER_BYTES, "reason": "member_not_inspected"},
            )
        )
        return None
    return payload


def _is_traversal(name: str) -> bool:
    normalised = name.replace("\\", "/")
    if normalised.startswith("/"):
        return True
    if len(normalised) > 1 and normalised[1] == ":":  # windows drive letter
        return True
    return any(part == ".." for part in normalised.split("/"))


def _member_is_pickle_by_name(name: str) -> bool:
    lowered = name.lower()
    return any(lowered.endswith(suffix) for suffix in ALWAYS_PICKLE_SUFFIXES)


def _member_is_ambiguous(name: str) -> bool:
    lowered = name.lower()
    return any(lowered.endswith(suffix) for suffix in AMBIGUOUS_PICKLE_SUFFIXES)


def _peek_member(archive, name: str) -> tuple[str, bytes]:
    """Classify a member from its first bytes without decompressing the rest.

    Returns one of "code", "data" or "unreadable", plus the bytes that were
    read. "unreadable" is not "data": a member whose head could not be
    decompressed has unknown content, and unknown content is an execution
    surface gap, so it lands on ACT-ZIP-009 rather than being quietly filed
    with the tensor blobs.
    """
    try:
        with archive.open(name) as handle:
            head = handle.read(MEMBER_PEEK_BYTES)
    except Exception:
        return "unreadable", b""
    if not head:
        return "data", head
    if head[0] == 0x80:  # PROTO: no raw tensor blob opens this way
        return "code", head
    if head[0] not in PICKLE_OPCODE_BYTES:
        return "data", head
    return ("code" if _prefix_disassembles(head) else "data"), head


def _prefix_disassembles(head: bytes) -> bool:
    """Whether a prefix yields enough consecutive opcodes to be pickle-shaped.

    `pickletools.genops` is a generator that raises on the first byte it
    cannot interpret, so counting how far it gets before raising is the
    measurement. A truncated prefix of a real pickle raises at the end - it
    never reaches STOP - which is why the test is "at least N opcodes", not
    "parsed cleanly". Requiring a clean parse would reject every real member,
    since a 64 KiB prefix of a 1 MiB pickle is truncated by definition.
    """
    seen = 0
    try:
        for _ in pickletools.genops(head):
            seen += 1
            if seen >= MIN_PREFIX_OPCODES:
                return True
    except Exception:
        return False
    return seen >= MIN_PREFIX_OPCODES


def _bytes_look_like_pickle(payload: bytes) -> bool:
    """Both-ends check for members whose name does not commit them.

    Same rule as `detect._looks_like_pickle`, applied to bytes already in
    memory: a valid opcode at the front and STOP at the back, or a PROTO
    header, which no raw tensor blob starts with.
    """
    if not payload:
        return False
    if payload[0] == 0x80:
        return True
    return payload[0] in PICKLE_OPCODE_BYTES and payload.endswith(b".")
