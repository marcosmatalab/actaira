> **Archived.** This page describes the model scanner Actaira was until 3.0.0:
> static inspection of model artifacts, executable controls, policy as code and
> the EU AI Act catalogue. **None of it is in this tree.** It is kept, unedited,
> because a document that argued a decision is worth more than a summary of it,
> and because deleting it would leave the design notes that cite it pointing at
> nothing. The code it describes is at tag `v2.3.0`. For what Actaira is now, read [`../../README.md`](../../README.md).
> Nothing below is maintained, and nothing below is checked by a gate.

# Actaira: formats and rules

One section per format: what is parsed, what is extracted into the report and
the ML-BOM, which `ACT-*` rules that inspector can emit, and what is out of
scope. Then the complete table of the 80 rules.

Format is chosen from the bytes on disk, never from the extension
(`src/actaira/formats/detect.py:53`). The declared extension is compared against
the detected format afterwards and a mismatch is itself a finding.

## 0. Detection

`sniff` returns `(format_id, confidence)`. Confidence is `"magic"` when a
documented magic number matched, `"structure"` when the format was inferred from
a parseable structure, and `"unknown"` when nothing matched. The value is
carried into the report and into the BOM as `actaira:format_confidence`
(`src/actaira/bom/cyclonedx.py:64`).

| Detected as | Test | Confidence |
|---|---|---|
| `empty` | zero bytes | `magic` |
| `hdf5` | `\x89HDF\r\n\x1a\n` | `magic` |
| `npy` | `\x93NUMPY` | `magic` |
| `gguf` | `GGUF` | `magic` |
| `zip` | `PK\x03\x04` or `PK\x05\x06` | `magic` |
| `safetensors` | plausible u64 LE header length followed by `{` (`src/actaira/formats/detect.py:82`) | `structure` |
| `onnx` | first byte `0x08`, protobuf field 1 as a varint (`src/actaira/formats/detect.py:94`) | `structure` |
| `pickle` | first byte in the set of opcodes that can legally start a stream (`src/actaira/formats/detect.py:22`) | `structure` |
| `unknown` | nothing matched | `unknown` |
| `pytorch-zip` | assigned after the fact, when a zip turned out to hold pickle members (`src/actaira/inspect.py:70`) | inherited from `zip` |

Extension expectations are declared in `_EXTENSION_EXPECTATION`
(`src/actaira/formats/detect.py:32`) and cover `.safetensors`, `.onnx`, `.gguf`,
`.ggml`, `.npy`, `.npz`, `.h5`, `.hdf5`, `.keras`, `.pt`, `.pth`, `.bin`,
`.ckpt`, `.pkl`, `.pickle`, `.joblib` and `.model`. An extension not in the map
never produces `ACT-FMT-002`, because there is nothing to contradict.
`pytorch-zip` is treated as a refinement of `zip` and does not flag when the
extension expected the generic case (`src/actaira/formats/detect.py:112`).

Only files whose suffix is in `ARTIFACT_SUFFIXES` are picked up when a directory
is walked (`src/actaira/cli.py:36`). A file named explicitly on the command line
is inspected regardless of its suffix (`src/actaira/cli.py:100`).

## 1. Pickle

### Parsed

The opcode stream, disassembled with `pickletools.genops`
(`src/actaira/formats/pickle_scan.py:90`). Nothing is executed and no
`Unpickler` is constructed. Alongside the disassembly, an abstract
interpretation of the value stack and the memo runs, driven by the
`stack_before` and `stack_after` metadata `pickletools` publishes for every
opcode, including mark-object semantics
(`src/actaira/formats/pickle_scan.py:267`).

The scanner classifies opcodes into five sets
(`src/actaira/formats/pickle_scan.py:41` to
`src/actaira/formats/pickle_scan.py:70`):

- `IMPORT_OPCODES`: `GLOBAL`, `STACK_GLOBAL`.
- `EXECUTION_OPCODES`: `REDUCE`, `INST`, `OBJ`, `NEWOBJ`, `NEWOBJ_EX`, `BUILD`.
- `EXTENSION_OPCODES`: `EXT1`, `EXT2`, `EXT4`.
- `PERSID_OPCODES`: `PERSID`, `BINPERSID`.
- `STRING_PUSH_OPCODES` and `_VALUE_PUSHING`, which carry their argument as a
  concrete value onto the abstract stack.

`GLOBAL` takes its module and name from its own argument, so it resolves
directly. `STACK_GLOBAL` takes them from the stack, so the abstract
interpretation is what resolves it. When either operand is opaque, the import is
genuinely dynamic and cannot be decided statically; that case is `ACT-PKL-009`
at HIGH, never a silent pass (`src/actaira/formats/pickle_scan.py:136`).

Each resolved import is judged against the policy
(`src/actaira/formats/pickle_scan.py:191`):

1. If denied, the finding is CRITICAL: `ACT-PKL-007` when the callable is a
   nested loader that re-enters deserialisation, otherwise `ACT-PKL-002`.
2. Otherwise, under `strict` only, if the callable is not on the allowlist the
   finding is `ACT-PKL-001` at HIGH.
3. Otherwise nothing is emitted, but the qualified name is still recorded in
   `imported_callables`.

The denylist covers 39 module names and 37 exact callables
(`src/actaira/scan/policy.py:103` and `src/actaira/scan/policy.py:147`), matched
by exact pair, by exact module, and by module root
(`src/actaira/scan/policy.py:194`). The allowlist covers 26 exact callables plus
the single module prefix `torch.`, with six explicit prefix exceptions that stay
denied (`src/actaira/scan/policy.py:36`, `src/actaira/scan/policy.py:78`,
`src/actaira/scan/policy.py:87`).

### Extracted

`imported_callables` (sorted, qualified `module.name`),
`metadata["pickle_protocol"]`, `metadata["opcode_count"]`. All three reach the
BOM: the protocol and opcode count as report metadata, and each imported
callable as an `actaira:imported_callable` property
(`src/actaira/bom/cyclonedx.py:73`).

### Rules

`ACT-PKL-001`, `ACT-PKL-002`, `ACT-PKL-003`, `ACT-PKL-004`, `ACT-PKL-005`,
`ACT-PKL-006`, `ACT-PKL-007`, `ACT-PKL-008`, `ACT-PKL-009`.

### Out of scope

- **No deserialised object.** Nothing is reconstructed, so tensor values,
  container contents and nesting are not available.
- **No tensor metadata.** A bare pickle produces no `TensorInfo` rows, so a
  pickle-only artifact has no shapes, dtypes or parameter counts in its BOM.
- **`imported_callables` is what resolved.** An import reported as
  `ACT-PKL-009` does not appear in the list, so the list is not the set of
  imports the artifact will perform.
- **The `torch.` prefix is a documented hole**, bounded by `PREFIX_EXCEPTIONS`
  (`src/actaira/scan/policy.py:87`). A torch callable not in that exception list
  is allowed under `strict`.
- **Streams past `MAX_OPCODES` are only partially analysed.** `ACT-PKL-008`
  fires and the scan stops.
- **The whole file is read into memory** (`src/actaira/inspect.py:58`).

## 2. Zip containers: PyTorch checkpoints, `.npz`, `.keras`

### Parsed

The central directory, then selected members. A modern `.pt` is a zip holding
`data.pkl` plus raw storage blobs, so the pickle problem is one level down; a
tool that sniffs the outer file and stops sees only "zip"
(`src/actaira/formats/archive.py:1`).

For each of the first `MAX_MEMBERS_INSPECTED` members
(`src/actaira/formats/archive.py:61`):

- the member name is tested for path traversal, covering a leading `/`, a
  Windows drive letter, `..` segments, and backslash separators
  (`src/actaira/formats/archive.py:129`);
- the expansion ratio is computed from `file_size / compress_size` in the
  central directory, so nothing is decompressed to measure it
  (`src/actaira/formats/archive.py:72`);
- the name is tested against `PICKLE_MEMBER_SUFFIXES`, which is `.pkl`,
  `.pickle`, `data.pkl` and `.bin` (`src/actaira/formats/archive.py:24`).

Each member identified as a pickle is then read, checked for a plausible first
opcode byte, and passed to the pickle scanner with a `location` of
`file!member` (`src/actaira/formats/archive.py:104`).

### Extracted

`metadata["member_count"]`, `metadata["pickle_members"]`, and the union of every
member's `imported_callables`. When `pickle_members` is non-empty the detected
format is refined from `zip` to `pytorch-zip`
(`src/actaira/inspect.py:70`).

### Rules

`ACT-ZIP-001` through `ACT-ZIP-009`, plus every pickle rule from the scanned
members.

Members are selected by content. Each one has its first 64 KiB decompressed
and disassembled; a prefix that yields four or more consecutive pickle opcodes
sends the member to the full scanner, whatever it is called. A member whose
name says storage and whose bytes say pickle is `ACT-ZIP-008`, HIGH, because
that is a deliberate bypass rather than a mistake. A member whose head will not
decompress at all is `ACT-ZIP-009`: its content is unknown, so the load-time
execution surface is `PARTIAL`.

`ACT-ZIP-003`, `ACT-ZIP-006` and `ACT-ZIP-009` limit the load-time execution
surface; `ACT-ZIP-004` and `ACT-ZIP-005` limit archive structure; `ACT-ZIP-007`
limits raw tensor content, which is `NOT_ASSESSED` by design. See
`src/actaira/coverage.py`.

### Out of scope

- **Members past the budget are never inspected.** A gadget in member 513 is not
  scanned. `ACT-ZIP-004` fires and the verdict is INCONCLUSIVE, so the gap is
  visible, but it is a gap.
- **Members that do not look like a pickle by name are not scanned.** A pickle
  member called `weights.dat` is not read.
- **Nested archives are not recursed.** A zip inside a zip is a member, not a
  container.
- **Encrypted zip members are not handled**; the read raises and becomes
  `ACT-ZIP-003`.
- **No extraction.** Path traversal is reported as a property of the archive.
  Actaira never extracts, so it is never itself the victim of the traversal.
- **`.npz` is a zip of `.npy` members**, and those members do not match
  `PICKLE_MEMBER_SUFFIXES`, so an object-dtype array inside a `.npz` is not
  scanned as a pickle.

## 3. safetensors

### Parsed

A u64 little-endian header length, a JSON header, then a raw tensor buffer. The
format cannot execute code, which is the point of the format, so inspection is
about structural integrity: a header that lies about where tensors live is how a
reader is walked out of bounds, and it is also how two files with the same
declared shapes can hold different weights
(`src/actaira/formats/safetensors.py:1`).

Checks, in order (`src/actaira/formats/safetensors.py:31`):

1. The header length field is present and reads as 8 bytes.
2. The declared header length is non-zero and at or below `MAX_HEADER_BYTES`.
3. `8 + header_len` does not exceed the file size.
4. The header decodes as UTF-8 and parses as JSON, and is a JSON object.
5. Each entry other than `__metadata__` is an object with an integer `shape`
   list of non-negative dimensions and a two-integer `data_offsets` pair.
6. `start >= 0`, `end >= start` and `end <= data_region`, where `data_region` is
   `file_size - 8 - header_len`.
7. The declared byte span equals `ceil(n_elements * dtype_bits / 8)` for the 15
   dtypes in `_DTYPE_BITS` (`src/actaira/formats/safetensors.py:23`). `BOOL` is
   counted as 1 bit, which is why the ceiling division is there.
8. No two tensor spans overlap, checked pairwise over the sorted spans
   (`src/actaira/formats/safetensors.py:146`).

### Extracted

One `TensorInfo` per entry with name, dtype string, shape and element count.
`metadata["__metadata__"]` verbatim from the header, `metadata["tensor_count"]`,
`metadata["total_parameters"]`. Tensor count, the sorted set of dtypes observed
and the parameter count reach the BOM model card
(`src/actaira/bom/cyclonedx.py:78`).

### Rules

`ACT-STF-001` through `ACT-STF-007`.

### Out of scope

- **Tensor bytes are never read.** Only the header is parsed. A file whose
  header is perfectly consistent and whose weights are anything at all will
  PASS.
- **No `fully_read` signal.** The safetensors branch does not set `fully_read =
  False` on a malformed header (`src/actaira/inspect.py:83`), so a header that
  fails an early check produces a HIGH or CRITICAL finding and FAIL, or a MEDIUM
  `ACT-STF-007` and PASS.
- **Gaps between tensors are not reported.** Overlap is a finding; unused space
  is not.
- **An unknown dtype suppresses the length check.** `ACT-STF-005` fires at
  MEDIUM and `ACT-STF-004` is not evaluated for that tensor
  (`src/actaira/formats/safetensors.py:112`).
- **`__metadata__` is copied, not validated.** It is publisher-supplied text and
  reaches the report unchanged.

## 4. ONNX

### Parsed

The protobuf wire format, read directly: field number, wire type, payload
(`src/actaira/formats/onnx.py:47`). The `onnx` package is not imported. Wire
types 0, 1, 2 and 5 are handled; anything else is refused. Unrecognised fields
are skipped by length, which is what makes the reader robust against fields it
has never seen.

Top-level `ModelProto` fields decoded (`src/actaira/formats/onnx.py:96`): 1
`ir_version`, 2 `producer_name`, 3 `producer_version`, 4 `domain`, 5
`model_version`, 7 `graph`, 8 `opset_import`. Inside the graph
(`src/actaira/formats/onnx.py:175`): field 1 nodes, field 5 initializers. Inside
a node (`src/actaira/formats/onnx.py:187`): field 4 `op_type`, field 7 `domain`.
Inside a `TensorProto` (`src/actaira/formats/onnx.py:198`): field 1 dims, both
packed and unpacked, field 2 `elem_type`, field 8 `name`.

The risk model for ONNX is that the graph itself is data, but operators outside
the standard domains resolve to custom native or Python kernels at session
creation. So the opset domain is the thing to surface
(`src/actaira/formats/onnx.py:11`). `STANDARD_DOMAINS` is the five domains that
ship with a standard ONNX Runtime install; `PYTHON_EXECUTING_DOMAINS` is
`ai.onnx.contrib`, `com.microsoft.pyop` and `pyop`
(`src/actaira/formats/onnx.py:22`).

### Extracted

`metadata["ir_version"]`, `producer_name`, `producer_version`, `domain`,
`model_version`, `opset_domains` (sorted), `node_count`, `op_types` (the 32 most
frequent, as `domain::op_type` when a domain is set), `initializer_count`. One
`TensorInfo` per initializer, with `elem_type` mapped through `_ELEM_TYPE`
(`src/actaira/formats/onnx.py:169`) and rendered as `type_<n>` when unknown.
`producer_name`, `producer_version`, `ir_version` and `node_count` reach the BOM
model card as `onnx.*` properties (`src/actaira/bom/cyclonedx.py:96`).

### Rules

`ACT-ONX-001` through `ACT-ONX-004`. `ACT-ONX-003` drives `fully_read = False`
(`src/actaira/inspect.py:94`).

### Out of scope

- **No model validation.** Shape inference, type checking across the graph and
  opset version compatibility are not performed. Only the domain string is
  judged, not the opset version number.
- **`external_data` is not followed.** An initializer whose bytes live in a
  separate file is counted but its data is not examined.
- **Subgraphs in node attributes are not walked.** `If` and `Loop` bodies are
  node attributes, which this reader skips by length, so their nodes are not
  counted and their domains are not judged.
- **Functions and custom function bodies are not decoded.**
- **Nodes past `MAX_NODES` are skipped silently** with no finding
  (`src/actaira/formats/onnx.py:178`), so a graph larger than 200,000 nodes can
  PASS with part of itself uncounted.
- **Files over `MAX_BYTES` are not read at all**; `ACT-ONX-004` fires at MEDIUM
  and, because it does not feed `fully_read`, the artifact reaches INCONCLUSIVE
  only by virtue of nothing having been parsed.

## 5. GGUF

### Parsed

A self-describing container: magic, u32 version, u64 tensor count, u64
key-value count, then the metadata block, then the tensor descriptors
(`src/actaira/formats/gguf.py:71`). It executes nothing, so inspection is about
provenance and about the counts being internally consistent with the file that
carries them, which is what catches a truncated or doctored download
(`src/actaira/formats/gguf.py:1`).

Every read goes through `_Reader.take`, which raises rather than reading past
the buffer (`src/actaira/formats/gguf.py:37`). Eleven scalar value types plus
strings and arrays are decoded (`src/actaira/formats/gguf.py:25`); an unknown
type raises. Arrays are recursive and bounded at `MAX_KV * 64` elements. Strings
are bounded at `MAX_STRING`. Tensor rank is bounded at 8.

### Extracted

`metadata["gguf_version"]`, `metadata["declared_tensor_count"]`,
`metadata["kv"]` (arrays longer than 16 elements are replaced by
`{"array_length": n, "sample": first four}` to keep the report bounded,
`src/actaira/formats/gguf.py:112`), `metadata["tensor_count"]`,
`metadata["total_parameters"]`. One `TensorInfo` per descriptor, with dtype
rendered as `ggml_type_<n>` because the ggml type table is not reproduced here.
`general.architecture`, `general.name` and `general.quantization_version` reach
the BOM model card when present (`src/actaira/bom/cyclonedx.py:93`).

### Rules

`ACT-GGF-001` through `ACT-GGF-004`. `ACT-GGF-001` drives `fully_read = False`
(`src/actaira/inspect.py:101`).

### Out of scope

- **Tensor data is never read.** Only the descriptors are. The declared offsets
  are read and discarded (`src/actaira/formats/gguf.py:124`), so a descriptor
  pointing outside the file is not reported.
- **ggml quantisation types are not named.** `ggml_type_2` is reported as such,
  not as `Q4_0`.
- **The whole file is read into memory** (`src/actaira/formats/gguf.py:75`),
  with no size budget on the GGUF path.
- **`ACT-GGF-004` appears to be unreachable as written.** The tensor loop is
  `for _ in range(tensor_count)` (`src/actaira/formats/gguf.py:117`), so if it
  completes then `len(tensors) == declared_tensor_count` exactly and the
  comparison at `src/actaira/formats/gguf.py:136` cannot be true; if it does not
  complete, the exception handler returns first
  (`src/actaira/formats/gguf.py:130`). The corpus case built to trigger a count
  mismatch, `count_mismatch.gguf`, reports `ACT-GGF-001` instead, and the corpus
  records that as its expectation (`evals/corpus/build.py:334`).

## 6. NumPy `.npy`

### Parsed

Magic, version, header length (2 bytes for version 1, 4 for later), then the
header dictionary (`src/actaira/formats/npy.py:26`). The header is
attacker-controlled text, so it is parsed with `ast.literal_eval` and never with
`eval` (`src/actaira/formats/npy.py:45`).

`.npy` is usually inert, with one exception that matters: an array with dtype
`object` stores its elements as a pickle, so `numpy.load` on such a file
executes code unless `allow_pickle=False`. Detecting that case is the whole job
(`src/actaira/formats/npy.py:1`). When `"O"` appears in `descr`, `ACT-NPY-001`
fires at CRITICAL and the body is passed to the pickle scanner with a `location`
of `file#body` (`src/actaira/formats/npy.py:60`).

### Extracted

`metadata["descr"]`, `metadata["fortran_order"]`, one `TensorInfo` named
`array`, and, for object arrays, the imported callables from the embedded
pickle.

### Rules

`ACT-NPY-001`, `ACT-NPY-002`, plus every pickle rule when the body is scanned.

### Out of scope

- **Array data is not read** unless the dtype is `object`.
- **No `fully_read` signal.** The `.npy` branch does not set `fully_read =
  False` (`src/actaira/inspect.py:103`), so a malformed header yields
  `ACT-NPY-002` at MEDIUM and a PASS.
- **The `"O"` test is a substring test** on the `descr` string, so it catches
  object dtype wherever it appears in a structured dtype, and it would also
  match a dtype string that merely contains the letter.
- **Structured dtypes are not decomposed** into their fields.
- **`.npz` is handled by the zip inspector**, and `.npy` members inside it are
  not scanned as pickles.

## 7. Keras and HDF5

### Parsed

The HDF5 magic number, then a bounded byte scan of the raw file for the Keras
`model_config` JSON blob (`src/actaira/formats/keras_h5.py:31`). This is
deliberately not a parser: a full HDF5 reader is a B-tree filesystem, and a
partial reader that silently misses a group is worse than no reader at all
(`src/actaira/formats/keras_h5.py:3`).

The blob is located with a regular expression anchored on
`{"class_name"`, `{"module"` or `{"keras_version"`
(`src/actaira/formats/keras_h5.py:27`), then trimmed to the outermost balanced
object and parsed as JSON (`src/actaira/formats/keras_h5.py:110`). Every
`class_name` in the resulting tree is collected recursively
(`src/actaira/formats/keras_h5.py:127`) and compared against `_KNOWN_LAYERS`, a
frozen set of 76 standard layer, initialiser and optimiser class names
(`src/actaira/formats/keras_h5.py:142`).

Two constructs make a Keras file executable and both are surfaced: a `Lambda`
layer, whose body is a marshalled Python code object Keras runs at load
(`ACT-H5-001`, CRITICAL), and any class outside the known set, which implies a
registered custom object (`ACT-H5-002`, HIGH).

### Extracted

`metadata["scanned_bytes"]`, `metadata["truncated_scan"]`,
`metadata["layer_class_names"]` (sorted, deduplicated),
`metadata["layer_count"]`.

### Rules

`ACT-H5-001` through `ACT-H5-004`. The inspector returns `config_was_read`,
which becomes `fully_read` directly (`src/actaira/inspect.py:114`), so
`ACT-H5-003` and `ACT-H5-004` both drive INCONCLUSIVE.

### Out of scope

- **The HDF5 structure is not walked.** No groups, no datasets, no attributes,
  no chunked storage, no compression filters.
- **Weights are not read.**
- **A config the regular expression cannot reach is invisible**, and the result
  is `ACT-H5-003` and INCONCLUSIVE, which is the expected outcome for a
  non-trivial share of real files.
- **A truncated scan that still finds a config returns `True`**, so a file
  larger than `MAX_SCAN_BYTES` can PASS on a partial scan;
  `metadata["truncated_scan"]` is the only signal
  (`src/actaira/formats/keras_h5.py:53`).
- **`_KNOWN_LAYERS` is a curated list.** A legitimate but less common standard
  layer produces `ACT-H5-002` at HIGH, which fails the artifact. That is the
  allowlist trade applied to Keras.
- **The `.keras` zip format is handled by the zip inspector**, not here, and its
  `config.json` member does not match `PICKLE_MEMBER_SUFFIXES`, so it is not
  read.

## 8. Unrecognised and empty files

`empty` produces `ACT-FMT-003` at LOW and sets `fully_read = False`
(`src/actaira/inspect.py:116`). An unrecognised format produces `ACT-FMT-001` at
MEDIUM with `evidence["consequence"] = "inconclusive"` and also sets `fully_read
= False` (`src/actaira/inspect.py:122`). Both therefore come back INCONCLUSIVE:
an unknown format is reported, not assumed safe.

## 9. The complete rule table

80 rules. Severities are read from the code; text is the English catalogue entry
(`src/actaira/i18n/en.json`). Both catalogues carry all 80 keys and a test
asserts the key sets are identical (`src/actaira/i18n/catalog.py:3`). Verified
in this container: no rule identifier appears in `src/` without a catalogue
entry, and none appears in the catalogue without a use in `src/`.

The **Fails?** column is for the default threshold, `--fail-on=high`: CRITICAL
and HIGH fail an artifact, MEDIUM, LOW and INFO do not. The **Unread?** column
marks the rules that force `fully_read = False`, which turns a non-failing
artifact into INCONCLUSIVE rather than PASS.

| Rule | Severity | Format | Meaning | Fails? | Unread? | Emitted at |
|---|---|---|---|---|---|---|
| `ACT-PKL-001` | HIGH | pickle | Pickle imports a callable that is not on the tensor-deserialisation allowlist | yes | no | `src/actaira/formats/pickle_scan.py:213` |
| `ACT-PKL-002` | CRITICAL | pickle | Pickle imports a callable with a documented path to code execution | yes | no | `src/actaira/formats/pickle_scan.py:201` |
| `ACT-PKL-003` | INFO | pickle | Pickle contains opcodes that call or instantiate at load time | no | no | `src/actaira/formats/pickle_scan.py:179` |
| `ACT-PKL-004` | HIGH | pickle | Pickle uses the copyreg extension registry to resolve a callable by number | yes | no | `src/actaira/formats/pickle_scan.py:147` |
| `ACT-PKL-005` | MEDIUM | pickle | Pickle uses a persistent id, resolved by the loading application | no | no | `src/actaira/formats/pickle_scan.py:156` |
| `ACT-PKL-006` | MEDIUM | pickle | Pickle stream is truncated or malformed | no | yes | `src/actaira/formats/pickle_scan.py:167` |
| `ACT-PKL-007` | CRITICAL | pickle | Pickle invokes a nested loader, re-entering deserialisation on attacker data | yes | no | `src/actaira/formats/pickle_scan.py:202` |
| `ACT-PKL-008` | MEDIUM | pickle | Pickle exceeds the opcode budget and was only partially analysed | no | no | `src/actaira/formats/pickle_scan.py:109` |
| `ACT-PKL-009` | HIGH | pickle | Pickle builds an import dynamically; the target cannot be resolved statically | yes | no | `src/actaira/formats/pickle_scan.py:136` |
| `ACT-PKL-010` | HIGH | pickle | More pickle data follows the end of the first stream | yes | no | `src/actaira/formats/pickle_scan.py:503` |
| `ACT-PKL-011` | HIGH | pickle | Pickle hands a byte string to a nested loader; the payload was disassembled as a pickle of its own | yes | no | `src/actaira/formats/pickle_scan.py:625` |
| `ACT-PKL-012` | INFO | pickle | Bytes follow the final stream and are zero padding, not a further pickle | no | no | `src/actaira/formats/pickle_scan.py:483` |
| `ACT-PKL-013` | HIGH | pickle | More streams follow than the inspection budget allows, and the tail was not read | yes | yes | `src/actaira/formats/pickle_scan.py:534` |
| `ACT-STF-001` | HIGH | safetensors | safetensors declares an implausible header length | yes | no | `src/actaira/formats/safetensors.py:44` |
| `ACT-STF-002` | HIGH | safetensors | safetensors header extends past the end of the file | yes | no | `src/actaira/formats/safetensors.py:54` |
| `ACT-STF-003` | CRITICAL | safetensors | safetensors tensor offsets fall outside the data region | yes | no | `src/actaira/formats/safetensors.py:101` |
| `ACT-STF-004` | HIGH | safetensors | safetensors tensor byte length disagrees with its dtype and shape | yes | no | `src/actaira/formats/safetensors.py:124` |
| `ACT-STF-005` | MEDIUM | safetensors | safetensors declares a dtype this version does not know | no | no | `src/actaira/formats/safetensors.py:113` |
| `ACT-STF-006` | HIGH | safetensors | safetensors tensors overlap in the data region | yes | no | `src/actaira/formats/safetensors.py:149` |
| `ACT-STF-007` | MEDIUM | safetensors | safetensors header is malformed | no | no | `src/actaira/formats/safetensors.py:165` |
| `ACT-ZIP-001` | HIGH | zip | Archive member escapes the extraction root | yes | no | `src/actaira/formats/archive.py:63` |
| `ACT-ZIP-002` | HIGH | zip | Archive member expands far beyond its compressed size | yes | no | `src/actaira/formats/archive.py:74` |
| `ACT-ZIP-003` | MEDIUM | zip | Archive member could not be read | no | yes | `src/actaira/formats/archive.py:107` |
| `ACT-ZIP-004` | MEDIUM | zip | Archive holds more members than the inspection budget allows | no | yes | `src/actaira/formats/archive.py:90` |
| `ACT-ZIP-005` | MEDIUM | zip | File is not a readable archive | no | yes | `src/actaira/formats/archive.py:45` |
| `ACT-ZIP-006` | HIGH | zip | Archive member exceeds the inspection size cap and was not inspected | yes | yes | `src/actaira/formats/archive.py:196` |
| `ACT-ZIP-007` | INFO | zip | Archive members were classified by content as data, so the rest of their bytes were not decompressed | no | no | `src/actaira/formats/archive.py:210` |
| `ACT-ZIP-008` | HIGH | zip | An archive member whose name says raw storage contains a pickle stream | yes | no | `src/actaira/formats/archive.py:159` |
| `ACT-ZIP-009` | MEDIUM | zip | An archive member's first bytes could not be read, so its content is unknown | no | yes | `src/actaira/formats/archive.py:145` |
| `ACT-CTL-002` | MEDIUM | any | A control declaration carries no controls | no | no | `src/actaira/controls/engine.py:52` |
| `ACT-NPY-001` | CRITICAL | npy | NumPy array uses object dtype, so its contents are a pickle | yes | no | `src/actaira/formats/npy.py:60` |
| `ACT-NPY-002` | MEDIUM | npy | NumPy header is malformed | no | no | `src/actaira/formats/npy.py:79` |
| `ACT-ONX-001` | CRITICAL | onnx | ONNX imports an operator domain that executes user-supplied Python | yes | no | `src/actaira/formats/onnx.py:141` |
| `ACT-ONX-002` | HIGH | onnx | ONNX imports a non-standard operator domain, resolved by a custom kernel | yes | no | `src/actaira/formats/onnx.py:150` |
| `ACT-ONX-003` | MEDIUM | onnx | ONNX protobuf could not be fully parsed | no | yes | `src/actaira/formats/onnx.py:111` and `src/actaira/formats/onnx.py:125` |
| `ACT-ONX-004` | MEDIUM | onnx | ONNX file exceeds the inspection size budget | no | no | `src/actaira/formats/onnx.py:79` |
| `ACT-GGF-001` | MEDIUM | gguf | GGUF file is truncated or malformed | no | yes | `src/actaira/formats/gguf.py:148` |
| `ACT-GGF-002` | MEDIUM | gguf | GGUF declares a version this tool does not know | no | no | `src/actaira/formats/gguf.py:87` |
| `ACT-GGF-003` | HIGH | gguf | GGUF declares implausible key-value or tensor counts | yes | no | `src/actaira/formats/gguf.py:96` |
| `ACT-GGF-004` | HIGH | gguf | GGUF tensor count disagrees with the number actually present | yes | no | `src/actaira/formats/gguf.py:136`, unreachable as written, see section 5 |
| `ACT-H5-001` | CRITICAL | hdf5 | Keras model contains a Lambda layer, whose body is executed on load | yes | no | `src/actaira/formats/keras_h5.py:85` |
| `ACT-H5-002` | HIGH | hdf5 | Keras model references classes outside the known layer set | yes | no | `src/actaira/formats/keras_h5.py:98` |
| `ACT-H5-003` | MEDIUM | hdf5 | Keras model config could not be read; the artifact is unread | no | yes | `src/actaira/formats/keras_h5.py:56` and `src/actaira/formats/keras_h5.py:70` |
| `ACT-H5-004` | MEDIUM | hdf5 | File claims HDF5 but does not carry the HDF5 magic number | no | yes | `src/actaira/formats/keras_h5.py:40` |
| `ACT-FMT-001` | MEDIUM | any | Format not recognised; the artifact was not inspected | no | yes | `src/actaira/inspect.py:123` |
| `ACT-FMT-002` | MEDIUM | any | File extension claims a format the bytes contradict | no | no | `src/actaira/formats/detect.py:115` |
| `ACT-FMT-003` | LOW | any | File is empty | no | yes | `src/actaira/inspect.py:118` |
| `ACT-MRK-001` | HIGH | marking | Output carries no machine-readable marking of synthetic origin | yes | no | `src/actaira/controls/art50.py:181` |
| `ACT-MRK-002` | MEDIUM | marking | Output carries a marking that does not state synthetic origin | yes | no | `src/actaira/controls/art50.py:168` |
| `ACT-MRK-003` | MEDIUM | marking | Marking could not be read from this container | no | yes | `src/actaira/controls/art50.py:196` |
| `ACT-MRK-004` | HIGH | marking | Interaction surface does not disclose that the counterpart is an AI system | yes | no | `src/actaira/controls/art50.py:305` |
| `ACT-MRK-005` | MEDIUM | marking | Marking did not survive a routine transformation | yes | no | `src/actaira/controls/art50.py:369` |
| `ACT-CTL-001` | MEDIUM | controls | A control raised while running and could not decide | no | yes | `src/actaira/controls/engine.py:93` |
| `ACT-CON-001` | MEDIUM | discovery | An artifact the source listed could not be fetched | no | yes | `src/actaira/connectors/model.py:410` |
| `ACT-CON-002` | HIGH | discovery | The digest the source declared does not match the bytes that arrived | yes | no | `src/actaira/connectors/model.py:417` |
| `ACT-PKL-014` | MEDIUM | pickle | A pickle stream larger than this parser will hold in memory | no | yes | `src/actaira/inspect.py:128` |
| `ACT-BDL-001` | MEDIUM | bundle | A JSON file that defines this bundle's structure did not parse | no | yes | `src/actaira/bundle.py:1` |
| `ACT-BDL-002` | HIGH | bundle | The config nominates Python modules in this repository for the loader to import | yes | no | `src/actaira/bundle.py:250` |
| `ACT-BDL-003` | HIGH | bundle | The repository answers the trust_remote_code prompt on the caller's behalf | yes | no | `src/actaira/bundle.py:267` |
| `ACT-BDL-004` | MEDIUM | bundle | An adapter names a base model but records no digest for it | no | no | `src/actaira/bundle.py:295` |
| `ACT-BDL-005` | MEDIUM | bundle | The shard index promises weight files that are not in the repository | no | yes | `src/actaira/bundle.py:341` |
| `ACT-BDL-006` | MEDIUM | bundle | The repository holds weight files the shard index does not mention | no | no | `src/actaira/bundle.py:358` |
| `ACT-BDL-007` | MEDIUM | bundle | The tokenizer ships a chat template containing Jinja control flow or a call | no | no | `src/actaira/bundle.py:388` |
| `ACT-BDL-008` | HIGH | bundle | The repository contains importable Python or native code | yes | no | `src/actaira/bundle.py:421` |
| `ACT-BDL-009` | MEDIUM | bundle | The source listing was incomplete, so this resolution covers part of the repository | no | no | `src/actaira/remote.py:214` |
| `ACT-AGT-001` | HIGH | agent | Untrusted text reaches the model beside a tool that acts without approval | yes | no | `src/actaira/conformance/capability.py:231` |
| `ACT-AGT-002` | HIGH | agent | A tool can read credentials beside a tool that can reach outside | yes | no | `src/actaira/conformance/capability.py:232` |
| `ACT-AGT-003` | HIGH | agent | A tool executes code the model composes | yes | no | `src/actaira/conformance/capability.py:233` |
| `ACT-AGT-004` | HIGH | agent | An MCP server is referenced by tag rather than by digest | yes | no | `src/actaira/conformance/capability.py:234` |
| `ACT-AGT-005` | MEDIUM | agent | An MCP server has no publisher recorded | no | no | `src/actaira/conformance/capability.py:235` |
| `ACT-AGT-006` | MEDIUM | agent | The model is named but not pinned to a digest | no | no | `src/actaira/conformance/capability.py:236` |
| `ACT-AGT-007` | MEDIUM | agent | No digest covers the system prompt | no | no | `src/actaira/conformance/capability.py:237` |
| `ACT-AGT-008` | HIGH | agent | A tool writes to production without approval | yes | no | `src/actaira/conformance/capability.py:238` |
| `ACT-AGT-009` | MEDIUM | agent | An MCP server exposes a tool the declaration does not describe | no | no | `src/actaira/conformance/declare.py:243` |
| `ACT-AGT-010` | MEDIUM | agent | A sub-agent is delegated to without a digest | no | no | `src/actaira/conformance/capability.py:260` |
| `ACT-PATH-001` | HIGH | agent | A route carries sensitive material from untrusted input to a way out | yes | no | `src/actaira/conformance/paths.py:330` |
| `ACT-PATH-002` | HIGH | agent | A route turns text an outsider wrote into an action | yes | no | `src/actaira/conformance/paths.py:318` |
| `ACT-PATH-003` | CRITICAL | agent | A route carries untrusted text into a step that runs code | yes | no | `src/actaira/conformance/paths.py:310` |
| `ACT-PATH-004` | HIGH | agent | A route reaches a delegate's capabilities from this agent's untrusted input | yes | no | `src/actaira/conformance/paths.py:355` |
| `ACT-PATH-009` | MEDIUM | agent | Delegation forms a cycle, so the reachable capability set cannot be enumerated | no | no | `src/actaira/conformance/paths.py:170` |

10 rules also carry a `rule_help` string, which the CLI and the UI show
alongside the rule text: `ACT-PKL-002`, `ACT-PKL-001`, `ACT-PKL-009`, `ACT-STF-003`, `ACT-NPY-001`, `ACT-H5-001`, `ACT-FMT-002`, `ACT-PKL-010`, `ACT-PKL-011`, `ACT-PKL-013`. The other 33 return an
empty string (`src/actaira/i18n/catalog.py:43`). This table is checked against the
message catalogue by `tests/test_formats_doc.py`, after it was found to be missing
four rules including the one the 1.0.0 release notes lead with: every SARIF finding
carries a `helpUri` pointing here, so a rule absent from this table is a link to a
page that does not mention what the reader clicked on.

## 10. Rule coverage in the eval corpus

Which rules the 64-case corpus actually exercises, from `evals/results.json`
under the default `strict` policy.

| Rule | Exercised by |
|---|---|
| `ACT-PKL-001` | 8 cases, the `gadget_unknown_*` family minus `bdb` |
| `ACT-PKL-002` | 17 cases: the 14 `gadget_known_<module>_<name>_p<n>.pkl` artifacts, plus `gadget_unknown_bdb_Bdb.pkl`, `trojan_renamed.safetensors` and `trojan_checkpoint.pt` |
| `ACT-PKL-003` | 35 cases, every artifact containing a `REDUCE` or equivalent, the seven benign pickles included |
| `ACT-PKL-004` | `gadget_extension_registry.pkl` |
| `ACT-PKL-006` | `truncated.pkl` |
| `ACT-PKL-007` | `gadget_nested_torch_load.pkl` |
| `ACT-STF-003` | `oob_offsets.safetensors` |
| `ACT-STF-006` | `overlap.safetensors` |
| `ACT-ZIP-001` | `traversal_checkpoint.pt` |
| `ACT-ZIP-002` | `bomb_checkpoint.pt` |
| `ACT-ZIP-007` | every archive in the corpus that carries a member whose bytes are not a pickle |
| `ACT-ZIP-008` | `storage_named_gadget.pt` |
| `ACT-ZIP-009` | `unreadable_member.pt` |
| `ACT-NPY-001` | `object_array.npy` |
| `ACT-ONX-001` | `custom_domain.onnx` |
| `ACT-ONX-002` | `vendor_domain.onnx` |
| `ACT-GGF-001` | `count_mismatch.gguf` |
| `ACT-H5-001` | `lambda_model.h5` |
| `ACT-FMT-001` | `mystery.model` |
| `ACT-FMT-002` | `trojan_renamed.safetensors`, `empty.pkl` |
| `ACT-FMT-003` | `empty.pkl` |

Not exercised by the corpus: `ACT-PKL-005`, `ACT-PKL-008`, `ACT-PKL-009`,
`ACT-STF-001`, `ACT-STF-002`, `ACT-STF-004`, `ACT-STF-005`, `ACT-STF-007`,
`ACT-ZIP-003`, `ACT-ZIP-004`, `ACT-ZIP-005`, `ACT-NPY-002`, `ACT-ONX-003`,
`ACT-ONX-004`, `ACT-GGF-002`, `ACT-GGF-003`, `ACT-GGF-004`, `ACT-H5-002`,
`ACT-H5-003`, `ACT-H5-004`. Most of these are covered by the unit tests instead:
`tests/test_pickle_scan.py` covers `ACT-PKL-008` and `ACT-PKL-009`,
`tests/test_formats.py:328` covers `ACT-ZIP-003`, `ACT-ZIP-004` and
`ACT-ZIP-005`. `ACT-GGF-004` is covered by neither, which is consistent with it
being unreachable.

The corpus is a detection benchmark, not a coverage suite. It measures what the
two policies do to a set of artifacts chosen to separate them, and section 4.6
of `docs/THREAT-MODEL.md` states what that does and does not license as a claim.

### Marking and control rules

The `ACT-MRK-*` family is emitted by the Article 50 controls rather than by a
format inspector, so it reaches a report through `actaira controls` and not
through `actaira scan`. They are in this table for the same reason as every
other rule: a SARIF consumer that meets one needs somewhere to look it up, and
a rule that fires with no documentation behind it is a finding the reader has
to take on trust.

### Discovery rules

The `ACT-CON-*` family is emitted by `actaira discover` and by nothing else. It
never reaches `actaira scan`, because scanning reads bytes that are already on
this disk and these two rules are about the act of getting them there.

`ACT-CON-002` is the sharpest finding this tool produces and also the rarest.
It fires when a source published a sha256 for an artifact and then served bytes
that hash to something else, which is a contradiction rather than a suspicion:
one of the two statements is false and nothing in the response says which. The
fetched file is deleted rather than left on disk, because the alternative is a
file an inspector might later read and report on as though its provenance were
settled. It is the one `ACT-CON` rule that fails a run (exit 1).

`ACT-CON-001` is its opposite in kind: a listed artifact that would not come
down at all. It marks an absence of an answer, exactly as `ACT-MRK-003` and
`ACT-CTL-001` do below, and it drives exit 3 rather than exit 1 for the same
reason. So does an incomplete listing, which is not a rule at all but the
`listing_complete: false` field every discovery carries: a connector that
cannot prove it enumerated the whole source must not report a green light to a
pipeline (design note D-80).

Neither rule is exercised by the eval corpus, which is a set of local files and
has no source to fetch from. Both are covered by `tests/test_connectors.py`,
against a TLS server the test starts itself, including the case that matters:
a canned response that declares one digest and serves bytes with another.

`ACT-MRK-003` and `ACT-CTL-001` are the two that mark an *absence of an
answer* rather than a defect. Both drive INCONCLUSIVE, never NOT_SATISFIED:
a container this repository cannot read and a control that raised are places
the tool did not reach, and reporting either as a negative finding about the
target would be asserting something about bytes nobody parsed.

## 11. The relation vocabulary

The rules above are about bytes. This section is about the edges between the
things those bytes belong to, which is what `actaira graph`, `actaira impact`
and `actaira agent paths` reason over. The vocabulary is closed, and it is
closed for the same reason the `ACT-*` ids are stable: an edge kind that
appears in a diagram under a word nobody defined is one two readers will read
differently. `scripts/release_check.py` asserts that every member of this table
is storable and documented.

Every edge carries `stated_by`, naming the declaration or snapshot it came
from. Nothing in Actaira infers an edge from two names that look alike, from
two assets sharing an organisation, or from two subjects appearing in the same
manifest. An impact report built on any of those would be technically complete,
practically useless, and would train people to ignore impact reports.

| Relation | From | To | Stated by | Meaning |
|---|---|---|---|---|
| `uses` | system, agent | agent, bundle, source | a subject manifest | The dependency an impact walk follows backwards. A system that `uses` an agent that `uses` a bundle is affected when the bundle moves. |
| `runs_as` | tool | identity | an agent declaration | Which credential this tool executes with. The relation that makes "the secret reader runs under an identity the egress path does not have" checkable rather than asserted. |
| `reads` | tool | data source | an agent declaration | Declared input. Stronger than the `scopes` convention it replaces: two fields that have to agree, not two strings that happened to match. |
| `writes` | tool | data source | an agent declaration | Declared output. |
| `exposes` | mcp server | tool | an agent declaration | A tool this server advertises. A target with no matching declaration is `ACT-AGT-009`. |
| `delegates_to` | agent | agent | an agent declaration | Whatever the delegate can do, the delegator can cause. Cycles are cut and reported as `ACT-PATH-009`. |
| `uses_model` | agent | model | an agent declaration | The model reference, pinned or not (`ACT-AGT-006`). |
| `served_by` | tool | mcp server | an agent declaration | The inverse of `exposes`, recorded when a tool names its server. |
| `governed_by` | system, agent | policy | a subject manifest | Which policy decides about this subject. |
| `evidenced_by` | any asset | evidence record | the store | Which observation supports a claim about this asset. |
| `supports` | evidence record | control, obligation | the store | Which control or EU AI Act obligation this evidence bears on. |
| `contains` | source | artifact | a source snapshot | An artifact this source was serving when it was observed. |

The five subject kinds an edge can connect are `artifact`, `bundle`, `agent`,
`system` and `source`, spelled the same way in `SubjectRef.handle`, in a
manifest, in a policy proof and in a receipt. Three spellings for one asset is
how an impact report ends up reporting that nothing depends on a model that
three things depend on.
