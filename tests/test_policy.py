"""Import policy: the allowlist, the denylist, and the difference between them.

The last test in this file is the project's central claim. Everything else
here exists to make that claim readable.
"""
from __future__ import annotations

import pickle

import pytest

from actaira.inspect import inspect_artifact
from actaira.model import Severity, Verdict
from actaira.scan import policy
from conftest import cases_in_family, corpus_path

UNKNOWN_GADGETS = cases_in_family("gadget-unknown")
BENIGN_CASES = cases_in_family("benign")


def rule_ids(report) -> set[str]:
    return {finding.rule_id for finding in report.findings}


# ---------------------------------------------------------------------------
# The allowlist admits real tensor reconstruction
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("protocol", range(6))
def test_allowlist_admits_the_callables_a_state_dict_actually_imports(protocol, numpy_state_dict):
    """Whatever CPython's pickler chooses to import, the allowlist must know.

    This is the cost side of an allowlist: if it does not cover the real
    serialisers, `strict` becomes noise and gets switched off.
    """
    from actaira.formats.pickle_scan import scan_pickle_bytes

    imports = scan_pickle_bytes(
        pickle.dumps(numpy_state_dict, protocol=protocol), "s.pkl", "strict"
    ).imported_callables
    assert imports, "nothing was imported; the fixture is not exercising the pickler"

    rejected = [
        qualified
        for qualified in imports
        if not policy.is_allowed(*qualified.rpartition(".")[::2])
    ]
    assert rejected == []


@pytest.mark.parametrize(
    "module, name",
    [
        ("torch._utils", "_rebuild_tensor_v2"),
        ("torch._utils", "_rebuild_parameter"),
        ("collections", "OrderedDict"),
        ("numpy.core.multiarray", "_reconstruct"),
    ],
)
def test_allowlist_admits_documented_reconstruction_entry_points(module, name):
    assert policy.is_allowed(module, name)


def test_load_from_bytes_is_not_a_reconstruction_entry_point():
    """It reads like tensor plumbing and it is a full unpickler.

    `torch.storage._load_from_bytes(b)` is `torch.load(io.BytesIO(b),
    weights_only=False)`. It sat on this allowlist for exactly that reason: the
    name and the module both say storage. A hostile review built a pickle whose
    only import was this callable, with a gadget inside the BINBYTES operand it
    is handed, and the file reached PASS with exit 0 under both policies while
    this test asserted the entry was correct. The test is part of the defect:
    it is kept here inverted so the entry cannot come back quietly.
    """
    assert not policy.is_allowed("torch.storage", "_load_from_bytes")


# ---------------------------------------------------------------------------
# ...and no namespace is allowed wholesale
# ---------------------------------------------------------------------------

def test_no_module_prefix_is_allowed_wholesale():
    """The allowlist holds no `.*` prefixes, and that is the point.

    `("torch.",)` lived here with a hand-written exception list underneath it.
    A hostile review walked straight past that list: `cpp_extension.load` was
    excepted, its sibling `load_inline` was not. A prefix over a namespace
    that large is allow-by-default, which is the failure mode of a denylist,
    which is the thing this policy exists to avoid.
    """
    assert policy.ALLOWED_MODULE_PREFIXES == ()
    assert policy.PREFIX_EXCEPTIONS == frozenset()


@pytest.mark.parametrize(
    "module, name",
    [
        ("torch.utils.cpp_extension", "load_inline"),
        ("torch.utils.cpp_extension", "load"),
        ("torch._C", "_TensorBase"),
        ("torch.multiprocessing", "spawn"),
        ("torch.hub", "load"),
        ("torch.jit", "load"),
        ("torch", "load"),
        ("torch.some.module.that.does.not.exist.yet", "anything"),
    ],
)
def test_executable_corners_of_the_torch_namespace_are_refused(module, name):
    assert policy.is_allowed(module, name) is False


@pytest.mark.parametrize(
    "module, name",
    [("torch", "FloatStorage"), ("torch", "HalfStorage"), ("torch.serialization", "_get_layout")],
)
def test_torch_prefix_still_admits_the_per_dtype_storage_classes(module, name):
    assert policy.is_allowed(module, name) is True


def test_torch_load_is_denied_outright_not_merely_unlisted():
    """`torch.load` is CRITICAL (denied), not HIGH (unknown). The severity is
    the whole difference between "review this" and "do not load this"."""
    assert policy.is_denied("torch", "load") is True
    assert policy.is_denied("torch", "FloatStorage") is False


# ---------------------------------------------------------------------------
# The denylist covers what it claims to cover
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module, name", sorted(policy.DENIED_CALLABLES))
def test_every_denied_callable_is_denied(module, name):
    assert policy.is_denied(module, name) is True
    assert policy.is_allowed(module, name) is False


@pytest.mark.parametrize("module", sorted(policy.DENIED_MODULES))
def test_every_denied_module_is_denied_under_any_name(module):
    assert policy.is_denied(module, "anything") is True


@pytest.mark.parametrize(
    "module", sorted(name for name in policy.DENIED_MODULES if "." not in name)
)
def test_a_denied_top_level_module_covers_its_submodules(module):
    """`os` on the list must also cover `os.path`, or the entry is trivial to
    walk around."""
    assert policy.is_denied(f"{module}.submodule", "anything") is True
    assert policy.is_denied(f"{module}.a.b", "anything") is True


@pytest.mark.parametrize(
    "module", sorted(name for name in policy.DENIED_MODULES if "." in name)
)
def test_a_dotted_denylist_entry_covers_only_itself(module):
    """The structural limit of a denylist, asserted rather than assumed.

    `http.client` is on the list; `http` is not, and neither is `http.server`.
    Matching is exact for the dotted entry and by root for the rest, so a
    dotted entry buys exactly one module and its siblings are free. This is not
    a defect to be patched by adding more names - it is the reason `strict` is
    the default policy, and it is measured in
    `test_known_bad_misses_the_gadgets_it_has_no_entry_for`.
    """
    root = module.split(".", 1)[0]
    sibling = f"{root}.a_sibling_nobody_listed"

    assert policy.is_denied(module, "anything") is True
    if root not in policy.DENIED_MODULES:
        assert policy.is_denied(sibling, "anything") is False
        assert policy.is_denied(f"{module}.deeper", "anything") is False


@pytest.mark.parametrize(
    "module, name",
    [
        ("ossaudiodev", "open"),      # starts with "os", is not "os"
        ("systemd", "journal"),       # starts with "sys", is not "sys"
        ("codecs", "encode"),         # starts with "code", is not "code"
        ("numpy", "ndarray"),
        ("collections", "OrderedDict"),
        ("torch._utils", "_rebuild_tensor_v2"),
    ],
)
def test_denylist_does_not_reach_past_a_dot_boundary(module, name):
    """Negative control: root matching must split on dots, not on characters.

    `ossaudiodev` is not `os`. A denylist that matched prefixes textually would
    fail every one of these and nobody would notice until an artifact that uses
    them got blocked.
    """
    assert policy.is_denied(module, name) is False


# ---------------------------------------------------------------------------
# The claim: strict catches gadgets a denylist has never heard of
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case", UNKNOWN_GADGETS, ids=lambda case: case.name)
def test_strict_flags_every_unknown_gadget(case):
    report = inspect_artifact(corpus_path(case), scan_policy="strict")

    assert report.verdict is Verdict.FAIL
    assert set(case.expect_rules) <= rule_ids(report)


@pytest.mark.parametrize("case", UNKNOWN_GADGETS, ids=lambda case: case.name)
def test_known_bad_misses_the_gadgets_it_has_no_entry_for(case):
    """The other half of the same claim, and the reason `strict` is the default.

    The corpus records which rule each gadget is expected to fire. A gadget
    expected as ACT-PKL-001 is one no denylist of this size enumerates: under
    `known-bad` it must come back PASS, which is the failure mode being
    measured. A gadget expected as ACT-PKL-002 (`bdb`, which happens to be on
    the denylist) must be caught by both policies; that case is the control
    that this test is not simply asserting "known-bad never fires".
    """
    report = inspect_artifact(corpus_path(case), scan_policy="known-bad")

    if case.expect_rules == ["ACT-PKL-001"]:
        assert report.verdict is Verdict.PASS
        assert rule_ids(report) <= {"ACT-PKL-003"}, "known-bad flagged an import it does not list"
    else:
        assert case.expect_rules == ["ACT-PKL-002"], case.expect_rules
        assert report.verdict is Verdict.FAIL
        assert "ACT-PKL-002" in rule_ids(report)


def test_the_gap_between_the_two_policies_is_not_empty():
    """Aggregate form of the claim, so a regression that quietly shrinks the
    corpus or widens the allowlist cannot leave the per-case tests all green
    while the difference the project publishes disappears."""
    missed = {
        case.name
        for case in UNKNOWN_GADGETS
        if inspect_artifact(corpus_path(case), scan_policy="known-bad").verdict is Verdict.PASS
    }
    caught = {
        case.name
        for case in UNKNOWN_GADGETS
        if inspect_artifact(corpus_path(case), scan_policy="strict").verdict is Verdict.FAIL
    }

    assert missed <= caught
    assert len(missed) >= 5, f"only {len(missed)} gadgets separate the two policies"
    assert caught == {case.name for case in UNKNOWN_GADGETS}


@pytest.mark.parametrize("case", BENIGN_CASES, ids=lambda case: case.name)
def test_strict_does_not_fire_on_the_benign_half_of_the_corpus(case):
    """The price of the allowlist, asserted rather than assumed.

    An allowlist that flags legitimate artifacts is an allowlist people turn
    off. Every benign case must reach PASS under the default policy, with no
    ACT-PKL-001 anywhere.
    """
    report = inspect_artifact(corpus_path(case), scan_policy="strict")

    # Every benign case passes, including the checkpoints. ACT-ZIP-007 may
    # still fire - a checkpoint's storage blobs are not decompressed in full -
    # but it is a scope statement about raw tensor content, which was never in
    # scope, and it no longer drags an otherwise clean artifact to
    # INCONCLUSIVE. Nothing worse than that note is allowed either way.
    assert report.verdict is Verdict.PASS, rule_ids(report)
    if "ACT-ZIP-007" in rule_ids(report):
        assert report.max_severity is Severity.INFO, "nothing worse than a scope note"
    assert "ACT-PKL-001" not in rule_ids(report)
    assert set(case.forbid_rules) & rule_ids(report) == set()
