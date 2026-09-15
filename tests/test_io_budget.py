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

import pytest

from actaira import io_budget


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
