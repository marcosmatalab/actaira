"""Reading a file without letting the file decide how much memory to use.

Design note D-160. Several parsers here called `path.read_bytes()`, and three
of them then sliced the result: `path.read_bytes()[:MAX_BYTES]`. That slice
looks like a bound and is not one. The whole file is in memory by the time the
slice runs, so a 4 GB declaration file allocated 4 GB and then kept 64 KiB of
it. The bound was written, reviewed and merged, and it protected nothing.

The asymmetry matters here more than in most tools. Actaira is pointed at
files somebody else produced, often by an adversary, precisely because they
might be hostile - and it is frequently run inside CI, on a box with a couple
of gigabytes, alongside whatever else that job is doing. A file that makes the
auditor run out of memory is a file that does not get audited, which is a
cheap and completely reliable way to avoid being looked at.

So reads are bounded at the call to `read`, one byte past the limit, which is
enough to know the limit was exceeded without materialising what is past it.
The caller gets `(data, over_budget)` and has to decide what an over-budget
file means: for most parsers it is a coverage gap and an INCONCLUSIVE verdict,
which is the honest answer - the tool did not read the file.
"""
from __future__ import annotations

import os
from pathlib import Path

# Per-format ceilings. Each is set from what real artifacts measure, not from
# a round number, and each is a coverage boundary rather than a refusal: over
# the limit the parser says it did not read the file.
#
# A state_dict pickle holds offsets, not weights - the largest in the eval
# corpus is under 1 MiB, and the archive member cap has been 256 MiB since
# 1.0.0. 512 MiB is far above anything legitimate and still bounded.
MAX_PICKLE_BYTES = 512 * 1024 * 1024
# GGUF puts its key-value metadata and tensor descriptors at the head and the
# tensor data after them. A 70B model is tens of gigabytes and its header is
# a few megabytes, so reading a prefix is not a compromise: it is the whole
# part this tool has anything to say about.
MAX_GGUF_HEADER_BYTES = 64 * 1024 * 1024
# Text this tool reads to judge it - a declaration, a disclosure page, a URL
# manifest. All are written by hand.
MAX_TEXT_BYTES = 4 * 1024 * 1024


def read_at_most(path: Path, limit: int) -> tuple[bytes, bool]:
    """Return up to `limit` bytes, and whether the file is larger than that.

    One byte past the limit is read and discarded. That is the cheapest way to
    distinguish "exactly at the limit" from "over it" without holding the
    excess, and the distinction is the whole point: a file at the limit was
    read in full and a file past it was not.

    Design note D-160b, and DEF-110. This used to be `handle.read(limit + 1)`,
    which is correct and was quietly expensive: `read(n)` allocates `n` bytes
    up front and then shrinks the object to what it actually read. So every
    pickle - a 16-byte one included - asked the allocator for 512 MiB before
    reading sixteen bytes. On Linux that is close to free, because the
    allocation is lazy and the pages are never touched, which is why it lived
    here through five releases and a CI job that only ever ran on Linux. On a
    platform that commits what it allocates it costs about 78 ms per artifact
    and a real 512 MiB spike, and `make benchmark` on Windows measured a
    median of 66 ms per file where the same corpus on Linux measured 0.175.

    The size of the *budget* is a decision about the format. The size of the
    *allocation* should be a fact about the file, and now it is: the handle is
    stat'ed and the read is bounded by whichever of the two is smaller.
    `fstat` on the open handle rather than `Path.stat()` before opening, so
    there is no window between the two in which the file could be replaced.
    """
    with Path(path).open("rb") as handle:
        try:
            size = os.fstat(handle.fileno()).st_size
        except OSError:
            # A pipe, a character device, anything without a length. Fall back
            # to the budget: the bound is what matters, the saving is not.
            size = limit
        payload = handle.read(min(limit + 1, size + 1))
        if len(payload) == min(limit + 1, size + 1) and size < limit:
            # The file grew between the fstat and the read. Rare, and its
            # digest is already wrong if it did - but a short read must not be
            # reported as a complete one, so keep going up to the budget.
            rest = handle.read(limit + 1 - len(payload))
            if rest:
                payload += rest
    if len(payload) > limit:
        return payload[:limit], True
    return payload, False


def read_text_at_most(path: Path, limit: int = MAX_TEXT_BYTES, encoding: str = "utf-8") -> tuple[str, bool]:
    """The same bound for text, decoding with replacement.

    Replacement rather than strict: these files are read in order to say
    something about their contents, and a decode error partway through a
    document is not a reason to say nothing about the rest of it. What the
    caller must not do is treat the result as round-trippable.
    """
    payload, over = read_at_most(path, limit)
    return payload.decode(encoding, "replace"), over
