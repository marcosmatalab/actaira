# Fuzzing the hand-written parsers

Actaira reads ML artifacts without loading them, which means it reads bytes an
attacker chose. Two of the readers are written by hand from the wire format ,
the ONNX protobuf decoder and the GGUF binary decoder, and the rest (`.npy`,
safetensors, the Keras/HDF5 byte scan, the zip container walk, the pickle
disassembler) are only a step away. The README used to list "no fuzzing" as a
known gap. This closes it.

## The property

There is one property, and it is the one the product promises. For **any**
byte sequence, `inspect_artifact(path)` must

| | | how it is checked |
|---|---|---|
| **(a)** | terminate | per-case `SIGALRM`, plus a parent-side watchdog for the C-level loops a Python signal cannot interrupt (big-integer arithmetic, mostly) |
| **(b)** | not raise an uncaught exception | any exception escaping a target |
| **(c)** | not consume memory without bound | `RLIMIT_AS` in the worker, so an allocation the parser should never have attempted surfaces as `MemoryError`; plus a per-case RSS high-water check for allocations that succeed |
| **(d)** | never answer `Verdict.PASS` for an artifact it could not fully read | `PASS` is cross-checked against `metadata["fully_read"]`, `inspector_errors`, and `UNREAD_RULE_IDS`, the set of rule ids that *mean* "not fully read". A `PASS` next to `ACT-STF-007` is a contradiction the report is already carrying, and the oracle says so |

A fifth check rides along with (b): the report must survive
`canonical_json(report.to_dict())`. That is not an extra requirement invented
for the fuzzer. Serialising the report is the only thing anything ever does
with one, `actaira scan --json`, the CycloneDX ML-BOM, the signed
attestation, so a report that cannot be serialised is an uncaught exception
in the CLI, one function call later. Three of the bugs below are only visible
through that check.

## Targets

Nine, in `fuzz_targets.py`: one per parser (`pickle`, `onnx`, `gguf`,
`safetensors`, `npy`, `keras_h5`, `archive`, `detect`) and one for
`inspect_artifact` end to end (`inspect`). The per-parser targets call the
inspector directly, so a parser that crashes is caught even when
`inspect_artifact`'s own `except Exception` would have converted it into an
INCONCLUSIVE verdict. The `inspect` target is the only one that can check (d),
because (d) is about a verdict.

## Two engines

**Atheris** (`--engine atheris`), when it is installed: libFuzzer with real
edge coverage through `atheris.instrument_all()`, and `-timeout` /
`-rss_limit_mb` enforcing (a) and (c) natively.

    pip install atheris
    python3 fuzz/fuzz_targets.py run --engine atheris --target gguf --iters 100000

**Builtin** (`--engine builtin`, the default, and what `make fuzz` runs so CI
needs no extra dependency): a small coverage-guided mutation fuzzer written
here. Seeds are generated from the helpers in `evals/corpus/build.py`, so the
starting points are the shapes the parsers actually accept; mutation is
deterministic from `--seed`; and a `sys.settrace` line-coverage signal over
`src/actaira` decides which inputs are kept as parents. Thirteen mutation
operators, of which the two that earned their place are *substitute an
extreme value into a length field* (every bug in the (c) column came from
that one) and *repeat the whole input* (which is what found the pickle
blow-up).

Cases run in a worker process under `RLIMIT_AS`. If the worker dies anyway ,
a hang inside a C loop, an OOM kill, the parent reads the input the worker
recorded before running it, writes it to `crashes/`, and restarts past it.

## Reproducing

    make fuzz                     # 5 000 cases per target, ~30 s, what CI runs
    make fuzz-long                # 50 000 cases per target, ~4 min

    # the full budget, spelled out
    python3 fuzz/fuzz_targets.py run --target all --seed 1 --iters 50000 \
        --timeout 5 --memory-mb 1024 --out fuzz/runs/long

    # one saved input against one target
    python3 fuzz/fuzz_targets.py replay --target npy --input fuzz/corpus/npy-magic-only.bin

    # shrink a fresh failure to the bytes that still reproduce it
    python3 fuzz/fuzz_targets.py reduce --target onnx --input fuzz/runs/long/onnx/crashes/x.bin

`--seed` and `--iters` determine a builtin run completely: the same command
produces the same sequence of inputs, the same kept corpus and the same
findings. Individual failures do not depend on that, they are saved as raw
bytes, and every one of them is replayable on its own.

## Budget spent, and what it found

| run | engine | cases | wall clock | result |
|---|---|---|---|---|
| discovery, seed 1, 3 000 per target | builtin | 27 000 | 3.8 min | **10 unique violations** |
| seed 1, 50 000 per target | builtin | 450 000 | 4.1 min | 0 |
| seed 2, 50 000 per target | builtin | 450 000 | 4.2 min | 0 |
| seed 3, 50 000 per target | builtin | 450 000 | 4.4 min | 0 |
| 100 000 per target | Atheris / libFuzzer | 900 000 | 3.9 min | 0 |
| | | **2 277 000** | **20 min** | |

The discovery run is slow per case precisely because of what it was finding:
`npy` managed 73 cases/s and `pickle` 14 cases/s while every third
interesting input was hitting a five-second timeout or a 1 GiB allocation.
After the fixes the same targets run at 1 500-2 700 cases/s.

**14 unique bugs were found and all 14 are fixed.** Ten came from the fuzzer
directly; four more came from pointing the same oracle at a structure the
mutator could not reach on its own (a 2 MB pickle, a 256 MiB Keras file, a
shape with 4 300 decimal digits, a zip member holding a broken pickle). Every
one has a regression test in `tests/test_fuzz_regressions.py` naming the input
and what was wrong, and the reduced input is in `corpus/`.

### (a) termination

- **`b"." * 24`, 73 seconds and 8.1 million findings.** Twenty-four
  concatenated empty pickles. `_scan_trailing_streams` called the full
  `scan_pickle_bytes` on the remainder after each STOP, and that call scanned
  *its* trailing streams, which scanned theirs; with a branching factor of
  `MAX_CONCATENATED_STREAMS` the work grew as 2ⁿ. This is the worst bug in the
  set: 24 bytes, reachable through `.pkl`, through a zip member, and through
  an object-dtype `.npy` body. Fixed by walking the concatenation forwards,
  visiting each stream once.
- **ONNX packed `dims`.** 200 KiB of maximal varints multiplied out to a
  1 400 000-bit integer in 1.5 s, growing with the square of the input.
- **GGUF nested arrays.** Twelve bytes bought one level of reader recursion.
  It was already ending in a caught `RecursionError`, so it never
  mis-reported; the bound is now the reader's decision rather than the
  interpreter's.

### (b) uncaught exceptions

- **`b"\x93NUMPY"`, six bytes, `IndexError`.** `major = handle.read(1)[0]`
  at EOF.
- **`.npy` header is a literal, not a promise.** `ast.literal_eval` returns
  whatever the header said. A header of `1` gave `.get` an int, a shape of `5`
  gave `list()` an int, a dimension of `'a'` gave `int()` a string.
- **`_collect_class_names` recursed once per level of the Keras config**,
  borrowing whatever stack the caller had left. `json.loads` guards its own
  depth, but that is a different budget: a config that parses from a shallow
  stack overflows the walk when `inspect_artifact` is called from a deep one.
  Now iterative.

### (b) at the report boundary, reports that cannot be serialised

- **`b"\r"`, one byte.** Field 1, wire type 5. The ONNX reader dispatched on
  field number and ignored the wire type, so `metadata["ir_version"]` became a
  raw `bytes` slice. `bytes` is not JSON: `actaira scan --json` died on a
  one-byte file.
- **A NaN in a GGUF metadata float.** `canonical_json` sets `allow_nan=False`
  deliberately, because NaN serialises to a token no third-party verifier
  accepts and the whole attestation rests on that JSON being standard. Roughly
  one exponent pattern in 256 is non-finite, so this is one byte flip away
  from any real GGUF file.
- **A shape whose product cannot be printed.** JSON integers have no width, so
  the product of a declared safetensors shape has no width either, and
  CPython refuses to render an integer wider than 4 300 decimal digits
  (`sys.set_int_max_str_digits`). A 5 KB header made `json.dumps` raise
  `ValueError` on a report the inspector had already called complete. The same
  hole existed in the ONNX and NumPy readers. Fixed in one place,
  `formats/shape.py`, with bounds read off the formats: every one of them
  stores a dimension in 64 bits.

### (c) unbounded memory

- **Twelve bytes, 4 GiB.** `.npy` version 2 and 3 hold the header length in
  four attacker-chosen bytes, and `handle.read(n)` allocates `n` up front. The
  file cannot hold more header than it has bytes left, which is already the
  malformed case; it is now decided from the size on disk before anything is
  allocated.

### (d) PASS on something that was not read

This is the failure mode design note D-04 exists to forbid, and the codebase
had already been bitten by it twice, the comments in `inspect.py` record the
zip branch and the ONNX branch each being fixed after the fact. Fuzzing found
it still open in three more places:

- **the safetensors branch** never derived `fully_read` at all, so any
  malformed header (`ACT-STF-007`, MEDIUM) passed;
- **the NumPy branch** never derived it either, `b"\x93NUMPY\x00"`, seven
  bytes, reported `ACT-NPY-002` and passed;
- **the zip branch** derived it only from `ACT-ZIP-*`, so a `data.pkl` member
  that would not disassemble was reported (`ACT-PKL-006`) and passed anyway;
- **the pickle opcode budget** (`ACT-PKL-008`, MEDIUM) did not set
  `truncated`, so a stream engineered to run past two million opcodes, with
  its gadget after the bound, came back clean;
- **the Keras scan cap** recorded `metadata["truncated_scan"]` and then
  returned "config was read" regardless, so a file over 256 MiB passed on the
  strength of its first 256 MiB.

The fix is not five more branch conditions. `inspect.py` now carries
`UNREAD_RULE_IDS`, and `fully_read` is derived from the findings in one place:
"I could not read this" became a property of what was reported rather than of
which branch happened to run. A new rule has to be classified there to be
forgotten.

## What the numbers do not say

Zero violations in 2.25 million cases is a statement about this fuzzer, not
about the parsers. Three honest caveats:

- **`detect` and `archive` produced no findings at all, and that is worth
  saying out loud.** Line coverage says the fuzzer was reaching them, so the
  most likely reading is that they are genuinely the two least exposed
  modules: `detect` does no arithmetic on attacker input at all (it reads 64
  bytes, compares prefixes and looks at one trailing byte), and `archive`
  delegates the parsing to `zipfile`, which is stdlib and has been fuzzed by
  people with much larger budgets than this. The bugs in the zip *path* were
  in what it did with a member once `zipfile` handed it over, and the fuzzer
  did find one of those (`ACT-PKL-006` reaching PASS) through the `inspect`
  target.
- **Coverage says where it was and was not looking.** Statements inside
  function bodies, over 6 000 mutations per target from seed 1:

  | parser | via its own target | via `inspect` |
  |---|---|---|
  | `keras_h5` | 100 % | 98 % |
  | `pickle_scan` | 97 % | 97 % |
  | `gguf` | 95 % | 92 % |
  | `onnx` | 94 % | 94 % |
  | `npy` | 93 % | 89 % |
  | `archive` | 92 % | 92 % |
  | `safetensors` | 92 % | 86 % |
  | `detect` | 91 % | 91 % |
  | `inspect` | 98 % | 98 % |

  What stays dark is consistent across the parsers and says exactly what this
  fuzzer cannot do: **it mutates bytes, it does not synthesise structure.**
  The unreached lines in `safetensors` are `entry_not_object`, `bad_shape` and
  the overlap check, all of which need a header that is *valid JSON* and
  hostile in its content, which byte flipping produces about never. Same shape
  in `archive`: the absolute-path and drive-letter arms of `_is_traversal` and
  the `ACT-ZIP-004` member budget are reached only from seeds, because a
  mutated central directory is a broken one. A structure-aware generator for
  the JSON and zip layers is the obvious next increment.
- **Inputs are capped at 64 KiB.** Everything decided by a size budget ,
  `MAX_BYTES` (512 MiB, ONNX), `MAX_SCAN_BYTES` (256 MiB, Keras),
  `MAX_MEMBER_BYTES` (256 MiB, zip), `MAX_OPCODES` (2 × 10⁶, pickle), is out
  of the mutator's reach by construction: the opcode-budget lines in
  `pickle_scan` are among the ones coverage shows dark. Two of the fourteen
  bugs lived exactly there and were found by aiming the oracle at them by
  hand. Anything else behind those budgets is still unfound.
- **The oracle only knows four things.** It cannot see a *wrong* answer: a
  parser that reports the wrong dtype, or misses a gadget it should have
  caught, satisfies all four properties. Detection coverage is what
  `evals/harness.py` measures, and the two are not substitutes.

## Layout

    fuzz/
      fuzz_targets.py   engine, targets, oracle, seed corpus, reduction, CLI
      corpus/           14 reduced inputs, 1 B to 5.8 KB, one per bug
      runs/             run output (git-ignored): crashes/, findings.jsonl, summary.json

`corpus/` is exercised by `tests/test_fuzz_regressions.py`, which asserts the
four properties over every file in it, so deleting one of them breaks the
suite.
