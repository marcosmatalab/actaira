"""One definition of a tensor shape a real file could have.

Four inspectors in this package multiply a list of attacker-controlled
dimensions together to report an element count. Each of them used to do it
with a bare `for dim in dims: count *= dim`, and each of them was wrong in
the same way: nothing bounded the rank, and nothing bounded a dimension, so
a header could ask for a product of arbitrary size.

That has two consequences, and the second is the one that bites.

The obvious one is time: multiplying thousands of 70-bit numbers is
superlinear, so a 200 KiB ONNX file spent 1.5 s building a single integer,
and the cost grows with the square of the input.

The one that is easy to miss is that the number then has to be *printed*.
CPython 3.11 refuses to render an integer wider than 4300 decimal digits
(`sys.set_int_max_str_digits`), so `json.dumps` raises `ValueError` on it.
Every consumer of a report serialises it - `--json`, the ML-BOM, the
attestation - which means a five-kilobyte safetensors header was enough to
turn `actaira scan` into a stack trace. Found by fuzzing, from a header
holding a few hundred twenty-digit dimensions.

The bounds here are read off the formats, not invented:

  * every format in this package stores a dimension in 64 bits - safetensors
    (JSON shape, u64 offsets), ONNX (`TensorProto.dims` is int64), NumPy
    (`npy_intp`), GGUF (u64) - so a dimension above 2**64-1 is not a
    dimension, it is a lie about one;
  * rank 64 is already far past anything a tensor library will construct,
    and 64 dimensions of 64 bits is a product of at most 4096 bits, roughly
    1 234 decimal digits, which stays comfortably inside the interpreter's
    own printing limit.

A shape outside these is refused with `ShapeOutOfRangeError`, which each caller
turns into its own "this header is not a faithful map of a file" finding.
It is never rounded, clamped or ignored: a clamped count would be a number
the report states and the file does not.
"""
from __future__ import annotations

from collections.abc import Sequence

MAX_RANK = 64
MAX_DIM = (1 << 64) - 1


class ShapeOutOfRangeError(ValueError):
    """A declared shape is outside anything the format can represent."""


def element_count(dims: Sequence[int]) -> int:
    """Product of `dims`, refusing a shape no real tensor has.

    Raises `ShapeOutOfRangeError` rather than returning a sentinel: the callers
    all have a malformed-artifact finding for exactly this, and a sentinel
    would have to be checked, which is the check that gets forgotten.
    """
    if len(dims) > MAX_RANK:
        raise ShapeOutOfRangeError(f"rank {len(dims)} above the limit of {MAX_RANK}")
    count = 1
    for dim in dims:
        if not isinstance(dim, int):
            raise ShapeOutOfRangeError(f"dimension {dim!r} is not an integer")
        if dim < 0 or dim > MAX_DIM:
            raise ShapeOutOfRangeError(f"dimension {dim} outside 0..2**64-1")
        count *= dim
    return count
