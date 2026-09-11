"""The pickle opcode scanner.

Every stream here is either produced by CPython's own pickler or crafted
byte by byte. Nothing is ever unpickled: the point of the module under test is
that it decides these questions without running the machine, so the tests must
not run it either.
"""
from __future__ import annotations

import os
import pickle
import pickletools

import pytest

from actaira.formats.pickle_scan import MAX_OPCODES, scan_pickle_bytes
from actaira.inspect import inspect_artifact
from actaira.model import Severity, Verdict
from actaira.scan import policy


class ShellGadget:
    """Serialises as REDUCE over `os.system`.

    Defined at module level so CPython's pickler can write it at every
    protocol. `__reduce__` names the callable; the class itself never appears
    in the stream and is never reconstructed by anything in this suite.
    """

    def __reduce__(self):
        return (os.system, ("id",))


def opcode_names(data: bytes) -> list[str]:
    return [opcode.name for opcode, _arg, _pos in pickletools.genops(data)]


def rule_ids(result) -> list[str]:
    return [finding.rule_id for finding in result.findings]


def short_binunicode(text: str) -> bytes:
    raw = text.encode("utf-8")
    return b"\x8c" + bytes([len(raw)]) + raw


# ---------------------------------------------------------------------------
# The abstract stack: STACK_GLOBAL resolves, on every protocol
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("protocol", range(6))
def test_every_import_in_a_numpy_state_dict_resolves(protocol, numpy_state_dict):
    """Positive case: a real state_dict is fully resolved, with no ACT-PKL-009.

    ACT-PKL-009 is the scanner admitting it could not decide an import
    statically. On a plain numpy state_dict there is nothing undecidable, so a
    single one of them is a defect in the stack simulation, not a property of
    the artifact.
    """
    data = pickle.dumps(numpy_state_dict, protocol=protocol)
    names = opcode_names(data)
    expected_import_opcode = "STACK_GLOBAL" if protocol >= 4 else "GLOBAL"
    assert expected_import_opcode in names, (
        f"protocol {protocol} did not emit {expected_import_opcode}; "
        "this test would be asserting nothing"
    )

    result = scan_pickle_bytes(data, "state_dict.pkl", "strict")

    assert result.parse_error is None
    # ACT-PKL-003 is the INFO note that REDUCE/BUILD appear at all, which they
    # do in any real state_dict. Nothing else may fire.
    assert rule_ids(result) == ["ACT-PKL-003"]
    assert len(result.imported_callables) >= 2, result.imported_callables
    for qualified in result.imported_callables:
        module, _, name = qualified.rpartition(".")
        assert policy.is_allowed(module, name), f"{qualified} is not tensor machinery"
    assert any(
        qualified.endswith("multiarray._reconstruct")
        or qualified.endswith("numeric._frombuffer")
        for qualified in result.imported_callables
    ), result.imported_callables


@pytest.mark.parametrize("protocol", range(6))
def test_execution_gadget_is_caught_on_every_protocol(protocol):
    """Negative control for the test above: the same machinery, a real gadget.

    The pickler chooses GLOBAL below protocol 4 and STACK_GLOBAL from 4 up, so
    this also proves the resolution works on both import opcodes.
    """
    data = pickle.dumps(ShellGadget(), protocol=protocol)
    result = scan_pickle_bytes(data, "gadget.pkl", "strict")

    critical = [f for f in result.findings if f.severity is Severity.CRITICAL]
    assert [f.rule_id for f in critical] == ["ACT-PKL-002"]
    # `os.system` is `posix.system` on Linux and `nt.system` on Windows.
    assert critical[0].evidence["callable"] in {"posix.system", "nt.system", "os.system"}
    assert "ACT-PKL-003" in rule_ids(result), "the REDUCE that calls it was not noticed"
    assert result.execution_opcodes == 1

    # This gadget is on every published denylist, so both policies must catch
    # it. It is the control against which test_policy's central claim is read.
    known_bad = scan_pickle_bytes(data, "gadget.pkl", "known-bad")
    assert "ACT-PKL-002" in rule_ids(known_bad)


def test_nested_loader_gets_its_own_rule():
    """`torch.load` inside a pickle is denied *and* distinguished.

    It re-enters the unpickler on attacker-chosen data, which is a different
    failure from `os.system`, so it carries ACT-PKL-007 rather than
    ACT-PKL-002. Losing that distinction would be silent, hence the pair.
    """
    from conftest import corpus_build

    nested = scan_pickle_bytes(
        corpus_build.craft_reduce("torch", "load", ("payload.pt",), 4), "n.pkl", "strict"
    )
    plain = scan_pickle_bytes(
        corpus_build.craft_reduce("posix", "system", ("id",), 4), "p.pkl", "strict"
    )

    assert "ACT-PKL-007" in rule_ids(nested) and "ACT-PKL-002" not in rule_ids(nested)
    assert "ACT-PKL-002" in rule_ids(plain) and "ACT-PKL-007" not in rule_ids(plain)


# ---------------------------------------------------------------------------
# Truncation: an unread artifact is never a PASS
# ---------------------------------------------------------------------------

def test_truncated_pickle_reports_act_pkl_006_and_never_passes(write_artifact, numpy_state_dict):
    whole = pickle.dumps(numpy_state_dict, protocol=4)
    cut = whole[:64]

    intact = scan_pickle_bytes(whole, "whole.pkl", "strict")
    assert intact.truncated is False
    assert "ACT-PKL-006" not in rule_ids(intact)

    result = scan_pickle_bytes(cut, "truncated.pkl", "strict")
    assert result.truncated is True
    assert "ACT-PKL-006" in rule_ids(result)
    assert result.parse_error, "the parse error that caused it must be carried as evidence"
    assert 0 < result.opcode_count < intact.opcode_count

    # The verdict is what a pipeline reads, so assert it at that level too.
    assert inspect_artifact(write_artifact("truncated.pkl", cut)).verdict is Verdict.INCONCLUSIVE
    assert inspect_artifact(write_artifact("whole.pkl", whole)).verdict is Verdict.PASS


# ---------------------------------------------------------------------------
# The opcode budget
# ---------------------------------------------------------------------------

def test_opcode_budget_cuts_a_stream_that_would_otherwise_spin():
    """A real stream past the bound, not a patched constant.

    Takes a couple of seconds because the bound is 2e6 opcodes and the point is
    that the bound is real. `opcode_count == MAX_OPCODES + 1` proves it stopped
    at the limit instead of reading the remaining ~100 opcodes of the stream.
    """
    flood = pickle.dumps(list(range(MAX_OPCODES + 100)), protocol=2)

    result = scan_pickle_bytes(flood, "flood.pkl", "strict")

    assert rule_ids(result) == ["ACT-PKL-008"]
    assert result.opcode_count == MAX_OPCODES + 1
    assert result.parse_error is None, "it stopped on the budget, not on a parse error"
    assert result.findings[0].evidence["opcode_limit"] == MAX_OPCODES


def test_ordinary_stream_stays_well_under_the_budget(numpy_state_dict):
    result = scan_pickle_bytes(pickle.dumps(numpy_state_dict, protocol=4), "s.pkl", "strict")
    assert "ACT-PKL-008" not in rule_ids(result)
    assert result.opcode_count < MAX_OPCODES // 1000


# ---------------------------------------------------------------------------
# The memo
# ---------------------------------------------------------------------------

def test_memoised_module_string_resolves_both_of_its_reuses():
    """BINPUT stores the module string once; BINGET pushes it back twice.

    From protocol 4 on this is what the real pickler does, so a scanner that
    does not model the memo loses the operands of every repeated STACK_GLOBAL
    and has to report them as undecidable.
    """
    stream = (
        b"\x80\x04"                                   # PROTO 4
        + short_binunicode("collections") + b"q\x01"  # BINPUT 1
        + short_binunicode("OrderedDict") + b"\x93"   # STACK_GLOBAL
        + b"0"                                        # POP
        + b"h\x01"                                    # BINGET 1 -> "collections"
        + short_binunicode("defaultdict") + b"\x93"   # STACK_GLOBAL
        + b"."
    )
    assert opcode_names(stream).count("STACK_GLOBAL") == 2

    result = scan_pickle_bytes(stream, "memo.pkl", "strict")

    assert result.imported_callables == {"collections.OrderedDict", "collections.defaultdict"}
    assert "ACT-PKL-009" not in rule_ids(result)


@pytest.mark.parametrize(
    "operand, description",
    [
        (b"h\x07", "BINGET of a slot that was never stored"),
        (b"]", "an opaque container where the module string should be"),
    ],
)
def test_undecidable_import_is_reported_not_swallowed(operand, description):
    """Negative control for the memo test: when the operand really is dynamic,
    the scanner says so at HIGH severity instead of resolving to nothing."""
    stream = b"\x80\x04" + operand + short_binunicode("join") + b"\x93" + b"."

    result = scan_pickle_bytes(stream, "dynamic.pkl", "strict")

    assert rule_ids(result) == ["ACT-PKL-009"], description
    assert result.findings[0].severity is Severity.HIGH
    assert result.imported_callables == set()


def test_a_module_name_containing_a_space_keeps_its_callable():
    """`pickletools` joins GLOBAL's two fields with a space, so split right.

    The stream carries two newline-terminated fields and `pickletools` renders
    them as one string joined by a space. Splitting from the left gave a
    module containing a space its first token as the module and everything
    after it as the callable name, which is a misread of the file. No real
    module has a space in its name, so nothing here was exploitable; it is
    fixed because a scanner that reports a callable the file does not name is
    wrong in the direction that matters least until the day it is not.
    """
    stream = b"c" + b"weird module\n" + b"system\n" + b"(S'id'\ntR."

    result = scan_pickle_bytes(stream, "odd.pkl", "strict")

    assert result.imported_callables == {"weird module.system"}

