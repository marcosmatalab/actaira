"""Reads that a hostile file cannot make unbounded.

Design note D-160. The bug this file pins is the one that looks fixed. Four
call sites wrote `path.read_bytes()[:LIMIT]`, which reads as a cap and is
not one: the whole file is in memory by the time the slice runs. Two parsers
had no cap at all.

The threat is specific. Actaira is pointed at files somebody else produced,
often because they might be hostile, and it is usually run in CI on a box with
a couple of gigabytes. A file that exhausts the auditor is a file that does
not get audited, and it costs an attacker nothing to produce one.
"""
from __future__ import annotations

import pickle
import struct

import pytest

from actaira import io_budget
from actaira.coverage import CoverageState, Surface
from actaira.inspect import inspect_artifact
from actaira.model import Verdict


def test_a_read_is_bounded_at_the_read_not_after_it(tmp_path, monkeypatch):
    """The measurement that distinguishes the fix from what it replaced.

    `read_bytes()[:N]` and `read(N)` return the same bytes. The difference is
    only visible in how much was asked for, so that is what this asserts:
    the call to `read` never requests more than the limit plus the one byte
    that detects an overflow.
    """
    target = tmp_path / "big.bin"
    target.write_bytes(b"x" * 100_000)

    requested: list[int] = []
    real_open = type(target).open

    def watching_open(self, *args, **kwargs):
        handle = real_open(self, *args, **kwargs)
        real_read = handle.read

        def watched(size=-1):
            requested.append(size)
            return real_read(size)

        handle.read = watched  # type: ignore[method-assign]
        return handle

    monkeypatch.setattr(type(target), "open", watching_open)
    payload, over = io_budget.read_at_most(target, 1024)

    assert len(payload) == 1024
    assert over is True
    assert requested == [1025], "one byte past the limit, and no more"


def test_a_file_exactly_at_the_limit_is_not_over_it(tmp_path):
    """The off-by-one that decides whether a legitimate file at the boundary
    is reported as unread."""
    target = tmp_path / "exact.bin"
    target.write_bytes(b"x" * 1024)

    payload, over = io_budget.read_at_most(target, 1024)

    assert len(payload) == 1024
    assert over is False


def test_a_pickle_past_the_budget_is_not_scanned_and_says_so(tmp_path, monkeypatch):
    """Over the budget nothing is disassembled and nothing is claimed. The
    execution surface comes back FAILED, which is the honest answer: the file
    was not read."""
    import actaira.inspect as inspect_module

    monkeypatch.setattr(inspect_module, "MAX_PICKLE_BYTES", 512)
    target = tmp_path / "big.pkl"
    target.write_bytes(pickle.dumps({"w": [1.0] * 2000}))
    assert target.stat().st_size > 512

    report = inspect_artifact(target)

    assert "ACT-PKL-014" in {finding.rule_id for finding in report.findings}
    assert report.coverage.state(Surface.LOAD_TIME_EXECUTION) is CoverageState.FAILED
    assert report.verdict is Verdict.INCONCLUSIVE
    assert report.inspector_errors == [], "over budget is a result, not a crash"


def test_a_pickle_under_the_budget_is_scanned_normally(tmp_path):
    """The negative control. A budget that changed the answer for ordinary
    files would be a budget somebody removes."""
    target = tmp_path / "small.pkl"
    target.write_bytes(pickle.dumps({"w": [1.0, 2.0]}))

    report = inspect_artifact(target)

    assert "ACT-PKL-014" not in {finding.rule_id for finding in report.findings}
    assert report.verdict is Verdict.PASS


def test_a_gguf_header_past_the_budget_is_not_called_malformed(tmp_path, monkeypatch):
    """Running out of bytes at the budget and running out because the file is
    corrupt raise identically and mean opposite things. Reporting the first
    as "malformed" would call a perfectly good 40 GB model damaged, which is
    the failure mode that gets a scanner removed from a pipeline."""
    from actaira.formats import gguf

    monkeypatch.setattr(gguf, "MAX_GGUF_HEADER_BYTES", 64)

    # A structurally valid GGUF header that promises more descriptors than
    # 64 bytes can hold.
    payload = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 40) + struct.pack("<Q", 0)
    # Past the budget on purpose: the header promises forty descriptors and
    # the file is larger than the prefix this parser will read, which is
    # exactly the shape of a real multi-gigabyte model.
    payload += b"\x00" * 4096
    target = tmp_path / "huge.gguf"
    target.write_bytes(payload)

    findings, _tensors, _metadata = gguf.inspect(target)
    rules = {finding.rule_id for finding in findings}

    assert "ACT-GGF-003" in rules, "over the header budget"
    assert "ACT-GGF-001" not in rules, "and not reported as a malformed file"
    over = next(item for item in findings if item.rule_id == "ACT-GGF-003")
    assert over.evidence["limit_bytes"] == 64


def test_a_genuinely_malformed_gguf_is_still_called_malformed(tmp_path):
    """The other side of the same distinction, so the test above is not
    passing because the parser stopped reporting corruption."""
    from actaira.formats import gguf

    target = tmp_path / "broken.gguf"
    target.write_bytes(b"GGUF" + b"\x00" * 8)

    findings, _tensors, _metadata = gguf.inspect(target)

    assert "ACT-GGF-001" in {finding.rule_id for finding in findings}


@pytest.mark.parametrize(
    "limit_name",
    ["MAX_PICKLE_BYTES", "MAX_GGUF_HEADER_BYTES", "MAX_TEXT_BYTES"],
)
def test_every_published_limit_is_a_positive_number_of_bytes(limit_name):
    """A limit that drifted to zero or None would disable the parser it
    protects while every test above still passed."""
    value = getattr(io_budget, limit_name)

    assert isinstance(value, int)
    assert value > 0


def test_text_is_decoded_with_replacement_rather_than_refused(tmp_path):
    """These files are read in order to say something about their contents,
    and a decode error partway through a document is not a reason to say
    nothing about the rest of it."""
    target = tmp_path / "mixed.txt"
    target.write_bytes(b"hello " + b"\xff\xfe" + b" world")

    text, over = io_budget.read_text_at_most(target)

    assert "hello" in text and "world" in text
    assert over is False


def test_a_small_file_is_not_read_with_a_large_allocation(tmp_path, monkeypatch):
    """DEF-110. The budget is a decision about the format; the allocation has
    to be a fact about the file.

    `read_at_most` used to call `handle.read(limit + 1)`, which is correct and
    was quietly expensive: CPython allocates the requested size up front and
    then shrinks the object. Every pickle therefore asked the allocator for
    512 MiB before reading its actual bytes - for a 16-byte file as much as for
    a real checkpoint. On Linux the allocation is lazy and nothing touches the
    pages, which is why it survived five releases and a Linux-only CI job. On a
    platform that commits what it allocates it cost about 78 ms per artifact,
    and `make benchmark` measured a median of 66 ms per file against 0.175 on
    the recorded Linux run.

    The module's own docstring is what makes this more than a slow path: it
    exists so that "a file that makes the auditor run out of memory" cannot
    happen, and the bound it introduced was allocating the ceiling for every
    file regardless of size.

    Asserted on the request rather than on a duration: a timing test is a flaky
    test, and the number that was wrong is the one passed to `read`.
    """
    target = tmp_path / "tiny.pkl"
    target.write_bytes(pickle.dumps({"w": 1}))

    requested: list[int] = []
    real_read = io_budget.Path(target).open

    class _Recording:
        def __init__(self, handle):
            self._handle = handle

        def read(self, size=-1):
            requested.append(size)
            return self._handle.read(size)

        def fileno(self):
            return self._handle.fileno()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return self._handle.__exit__(*exc)

    monkeypatch.setattr(
        io_budget.Path, "open", lambda self, *a, **k: _Recording(real_read(*a, **k))
    )

    payload, over = io_budget.read_at_most(target, io_budget.MAX_PICKLE_BYTES)

    assert payload == target.read_bytes()
    assert over is False
    assert requested, "the file was never read"
    assert max(requested) <= target.stat().st_size + 1, (
        f"read() was asked for {max(requested)} bytes for a "
        f"{target.stat().st_size}-byte file; the allocation follows the budget "
        "rather than the file"
    )


def test_the_budget_is_still_a_budget_for_a_file_that_exceeds_it(tmp_path):
    """The other half, so the optimisation above cannot become a hole: a file
    past the limit must still be truncated and still be reported as over."""
    target = tmp_path / "big.bin"
    target.write_bytes(b"A" * 5000)

    payload, over = io_budget.read_at_most(target, 1000)

    assert len(payload) == 1000
    assert over is True


def test_a_file_at_exactly_the_limit_is_read_in_full_and_not_called_over(tmp_path):
    """The boundary the one-byte-past read exists to distinguish."""
    target = tmp_path / "exact.bin"
    target.write_bytes(b"B" * 1000)

    payload, over = io_budget.read_at_most(target, 1000)

    assert len(payload) == 1000
    assert over is False
