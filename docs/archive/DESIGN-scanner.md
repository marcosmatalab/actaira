> **Archived.** These are sections 2, 5, 6, 7, 8 and 9 of `docs/DESIGN.md`, moved
> here in phase A.1 and **not edited**. They argue the model scanner Actaira was
> until 3.0.0: how it read pickle, ONNX, HDF5 and GGUF without executing them,
> the web interface, the read budgets, the evaluation corpus, and the bugs the
> project found in itself while building all of that. **None of that code is in
> this tree.** It is at tag `v2.3.0`.
>
> They are kept because a document that argues a decision is worth more than a
> summary of it, and because the next person to build an artifact reader should
> read why this one was built the way it was rather than rediscover it.
>
> Sections 1, 3, 4 and 10 stayed in [`../DESIGN.md`](../DESIGN.md), because they
> argue code that is still here: the note index, the reporting shapes, the whole
> of attestation - Merkle, chain, signing, keyring, RFC 3161, verification - and
> what phase A removed. The numbering is not closed up on either side, so every
> cross-reference in this file still resolves.
>
> Nothing below is maintained, and nothing below is checked by a gate.

# Actaira: design, the scanner sections

## 2. Inspection

### 2.1 Static analysis, not loading in a sandbox (D-05)

**Decided.** Actaira never calls `pickle.load`, `torch.load`, `numpy.load`,
`onnx.load` or `h5py.File`. It reads bytes and decides from them. The claim is
printed on the CLI itself: "Nothing is ever loaded or executed"
(`src/actaira/cli.py:50`).

**Why.** Loading is the vulnerability. A sandbox moves the blast radius, it does
not remove the execution. Any sandbox is a second security boundary that has to
be configured, kept current, and trusted on every machine that runs the scan,
including a developer laptop and a CI runner with a mounted Docker socket. It
also imports the entire framework stack into the machine doing the auditing,
which is the same supply chain the tool exists to question.

**Rejected: load the artifact inside a container or seccomp jail and observe.**
That approach sees things static analysis cannot: what the model does at run
time, dynamic imports resolved at load, behaviour that depends on the host.

**What is given up.** Actaira cannot observe execution, so it cannot see any
behaviour that only exists at run time. Everything it reports is a property of
the bytes. An import built at run time from data the analysis cannot follow is
reported as undecidable (`ACT-PKL-009`) rather than resolved. Section 4 of
`docs/THREAT-MODEL.md` states the consequences in full.

### 2.2 `pickletools.genops`, not a restricted `Unpickler` (D-05)

**Decided.** The pickle scanner disassembles the opcode stream with
`pickletools.genops` (`src/actaira/formats/pickle_scan.py:108`). It never
constructs an `Unpickler`.

**Why.** `GLOBAL` and `STACK_GLOBAL` import a callable by name and `REDUCE`
calls it. Disassembly reads the opcodes as data. It cannot execute anything by
construction, which is a stronger property than a filter that is correct today.

**Rejected: subclass `pickle.Unpickler` and override `find_class` to refuse
unknown globals.** This is the common approach and it is what most restricted
loaders in this ecosystem do.

**What is given up.** The restricted unpickler produces the reconstructed
object, so it can inspect actual tensor values, actual container shapes and
actual nesting. Actaira gets none of that from a pickle: it reports imports,
opcode counts and protocol, not the deserialised object. The trade is
deliberate. A restricted unpickler still runs the pickle virtual machine, so a
bug in the restriction is code execution, and there have been several such bugs
in real tools. The docstring at `src/actaira/formats/pickle_scan.py:9` states
the argument.

### 2.3 Exact abstract interpretation of the stack and the memo, not proximity (D-05)

**Decided.** `STACK_GLOBAL` takes its module and name from the value stack, not
from its own argument. The scanner therefore runs an abstract interpretation of
the pickle value stack and the memo, driven by the `stack_before` and
`stack_after` metadata `pickletools` publishes for every opcode, including
mark-object semantics (`src/actaira/formats/pickle_scan.py:303` to
`src/actaira/formats/pickle_scan.py:375`). Constants carry their value.
Everything else is an opaque slot.

**Why.** From protocol 4 on, the pickler memoises the module string and
re-pushes it with `BINGET`. A scanner without a memo loses the operands of every
repeated `STACK_GLOBAL`. The docstring at
`src/actaira/formats/pickle_scan.py:310` records the measurement, taken on this
repository's own corpus at protocol 4 with numpy 2.4.4 and CPython 3.11:
dropping the memo opcodes from the model leaves all four imports of a two-tensor
state_dict unresolved, and keeping them stack-neutral while discarding the memo
dictionary leaves one unresolved. The exact count depends on which library
produced the stream; the direction does not. Unresolved is not benign: it
becomes `ACT-PKL-009` at HIGH, which fails the artifact, so a scanner without a
memo is not merely less precise, it is unusable on ordinary checkpoints.

**Rejected: the "last two strings seen" proximity heuristic.** Track the two
most recent string pushes and pair them with the next `STACK_GLOBAL`. It is
roughly ten lines and needs no opcode metadata.

**What is given up.** The exact model costs code, and it costs a hard bound on
work per stream (`MAX_OPCODES`, section 6). The proximity heuristic never
reports `ACT-PKL-009`, so it never produces the false positives an opaque
operand causes. Actaira accepts those false positives: a heuristic that
mis-pairs on a real state_dict either reports the wrong callable or silently
accepts an import it never resolved, and both failures are worse than a review.
`tests/test_pickle_scan.py:182` pins the memo case, and
`tests/test_pickle_scan.py:213` is its negative control: when an operand really
is dynamic, `ACT-PKL-009` must fire.

### 2.4 Allowlist by default, denylist implemented and measured (D-02)

**Decided.** Two policies exist. `strict` flags every import that is not on a
list of callables known to be part of legitimate tensor deserialisation.
`known-bad` flags only imports on a denylist of callables with a documented path
to code execution. `strict` is the default
(`src/actaira/cli.py:97`, `src/actaira/scan/policy.py:36`).

**Why.** A denylist fails open: an unknown gadget is silently accepted. An
allowlist fails closed: an unknown callable is reported. In a supply-chain tool
a missed detection costs more than a review. Both policies are implemented so
the harness can measure the difference on the same corpus rather than assert it.

**Measured**, `evals/results.json`, over the 64-case corpus (16 benign, 47
malicious):

| Policy | Malicious flagged FAIL | Benign wrongly failed |
|---|---|---|
| `strict` (allowlist) | 47 of 47 | 0 of 16 |
| `known-bad` (denylist) | 37 of 47 | 0 of 16 |

Ten malicious cases are caught only by the allowlist:
`pydoc.pipepager`, `logging.config.fileConfig`, `zipimport.zipimporter`,
`numpy.testing._private.utils.runstring`, `torch.utils.cpp_extension.load`,
`xml.sax.make_parser`, `venv.create`, `vendorlib.tasks.run_shell`, plus the two
regression artifacts added after the review described in section 8:
`torch.utils.cpp_extension.load_inline` and `torch._C._TensorBase`. Each is a
documented execution path that no denylist of this size enumerates.

**Rejected: denylist only.** It is the low-false-positive option, it needs no
per-framework curation, and it never asks a user to review a legitimate but
unusual artifact.

**What is given up.** The allowlist has to be curated, and every entry is a
hole. The curation is visible in the code rather than implicit. `_codecs.encode`
is allowed because protocol 0 to 2 uses it to carry numpy raw bytes, and the
entry carries risk acceptance A-02 next to it
(`src/actaira/scan/policy.py:58`); the protocol 5 out-of-band buffer path is
allowed for the same measured reason (`src/actaira/scan/policy.py:65`).

There are no module prefixes at all. `ALLOWED_MODULE_PREFIXES` is an empty
tuple and `PREFIX_EXCEPTIONS` an empty frozenset
(`src/actaira/scan/policy.py:78`, `src/actaira/scan/policy.py:95`). The prefix
`torch.` used to live there with a hand-maintained exception list underneath
it, and section 8 records why it is gone. What replaced it is narrower by
construction: a rule about one name shape in one module, `torch.FloatStorage`
and its per-dtype siblings, which is what the prefix was actually needed for
(`src/actaira/scan/policy.py:99`).

The allowlist also has a measured cost, not just a theoretical one. See section
7.4: five benign artifacts in the corpus failed until two entries were added.

### 2.5 Three verdicts, not two (D-04, D-10)

**Decided.** `PASS`, `FAIL`, `INCONCLUSIVE`
(`src/actaira/model.py:41`). The rules are in one function
(`src/actaira/inspect.py:191`):

- `FAIL` when the worst finding is at or above the `--fail-on` threshold, HIGH
  by default.
- `INCONCLUSIVE` when the artifact could not be fully read, or the format was
  not recognised, or an inspector raised, and nothing worse was found.
- `PASS` when the artifact was fully read and nothing above MEDIUM was found.

Every inspector branch feeds a `fully_read` flag, and an inspector crash sets it
false (`src/actaira/inspect.py:175`). The CLI carries the distinction into its
exit codes: 0 all passed, 1 at least one failed, 2 usage error, 3 nothing failed
but something was inconclusive (`src/actaira/cli.py:35`).

**Why.** A tool that answers a question it could not evaluate is worse than one
that abstains. "I could not read this file" and "I read this file and it is
clean" are different facts and a pipeline acts on them differently.

**Rejected: two verdicts, folding unreadable into either PASS or FAIL.** Two
verdicts make the tool trivially easy to consume: one boolean, one exit code.

**What is given up.** Consumers have to handle a third state, and CI
configuration gets more complicated. A team that does not want the distinction
can collapse it with `--allow-inconclusive`, which maps exit code 3 to 0. That
choice then lives visibly in their CI config instead of invisibly in the tool
(`src/actaira/cli.py:11`). Folding unreadable into FAIL was also rejected: it
would make every unknown file format a security incident and teach people to
ignore the tool.

MEDIUM and below do not fail an artifact because they describe hygiene
(extension mismatch, unusual dtype) rather than a path to execution. That
threshold is exposed as `--fail-on` rather than baked in, and the harness runs
both policies against it.

### 2.6 Detection by content, never by extension (D-06)

**Decided.** Every inspector is selected from the bytes on disk
(`src/actaira/formats/detect.py:54`). The declared extension is compared against
the detected format afterwards, and a mismatch is itself a finding,
`ACT-FMT-002` at MEDIUM (`src/actaira/formats/detect.py:128`).

**Why.** The attacker controls the file name. `.safetensors` is a claim, not a
fact. Renaming a pickle to a safe-looking extension is a known way past filters
that trust the name; the corpus carries the case as
`trojan_renamed.safetensors`, and it is detected as a pickle and fails on
`ACT-PKL-002` while also reporting `ACT-FMT-002`.

**Rejected: dispatch on the extension and validate afterwards.** Simpler, and it
matches what the user expects to see reported.

**What is given up.** Content sniffing is not free of ambiguity. Three of the
formats have no magic number, so `sniff` returns a confidence level of
`"structure"` rather than `"magic"`: safetensors is inferred from a plausible
u64 header length followed by `{` (`src/actaira/formats/detect.py:75`), ONNX
from a protobuf stream whose first byte is field 1 as a varint
(`src/actaira/formats/detect.py:77`), and a bare pickle from its first opcode
byte (`src/actaira/formats/detect.py:79`). A file can be misrouted to the wrong
inspector, and the reported confidence is what tells a reader that happened. The
confidence value is carried into the report and into the BOM as
`actaira:format_confidence` (`src/actaira/bom/cyclonedx.py:64`).

### 2.7 A hand-written protobuf reader for ONNX (D-08)

**Decided.** ONNX is decoded field by field with about forty lines of wire
format reader (`src/actaira/formats/onnx.py:33` and
`src/actaira/formats/onnx.py:49`). The `onnx` package is not imported. Only the
fields that matter for provenance and risk are decoded; anything unrecognised is
skipped by length.

**Why.** The project's claim is that you can inspect an artifact without
installing the ecosystem that loads it. Importing `onnx` brings protobuf and a
large native surface into the auditing machine, which contradicts the claim.

**Rejected: depend on `onnx` and call `onnx.load`.** Three lines instead of
forty, and it parses every field correctly including ones this reader has never
seen.

**What is given up.** This reader knows about `ir_version`, `producer_name`,
`producer_version`, `domain`, `model_version`, the graph and `opset_import`, and
inside the graph about nodes and initializers. Everything else is skipped. It
does not validate the model, does not check shapes across the graph, and does
not resolve `external_data` references. A malformed protobuf that this reader
skips silently would be reported by the real parser. That is why a parse failure
is `ACT-ONX-003` and feeds `fully_read = False`
(`src/actaira/inspect.py:136`), so the artifact comes back INCONCLUSIVE rather
than PASS.

### 2.8 HDF5 is a bounded byte scan, and the code says so (D-09)

**Decided.** `keras_h5.inspect` confirms the HDF5 magic number, then searches
the raw bytes for the Keras `model_config` JSON blob with a regular expression
(`src/actaira/formats/keras_h5.py:27`). It does not walk the B-tree. When the
config cannot be located or parsed, it returns `config_was_read = False` and the
artifact is INCONCLUSIVE (`src/actaira/formats/keras_h5.py:113` and
`src/actaira/inspect.py:156`).

**Why.** A full HDF5 reader is a filesystem implementation. A partial reader
that silently misses a group is worse than no reader, because it produces a PASS
on a file it did not read.

**Rejected: depend on `h5py`, or write a partial B-tree walker.** Either would
find layers this scan misses.

**What is given up.** Anything Keras stores in a way the regular expression does
not reach is invisible: a config split across chunked storage, a compressed
attribute, a group the scan does not find. Those cases come back INCONCLUSIVE,
which is honest but not useful. Files larger than `MAX_SCAN_BYTES` are scanned
only up to that bound, and `metadata["truncated_scan"]` records it
(`src/actaira/formats/keras_h5.py:53`). Note that a truncated scan that still
finds a config returns `True`, so a large file can PASS on a partial scan; the
metadata flag is the only signal.

## 5. Interfaces

### 5.1 Zero third-party dependencies in the web layer (D-17)

**Decided.** The local UI is `http.server`, with HTML, CSS and JavaScript
written by hand and served from `src/actaira/web/static/`. No framework, no
bundler, no runtime dependency (`src/actaira/web/server.py:3`).

**Why.** This is an argument, not a limitation. Actaira exists to tell you what
is inside an artifact you did not build. A tool that makes that claim while
pulling a few hundred transitive packages into the machine doing the auditing
has already lost the argument. The only runtime dependency of the whole project
remains `cryptography`, which does the Ed25519.

**Rejected: FastAPI or Flask plus a front-end framework.** Multipart parsing,
routing, validation and templating would all be solved, and the whole server
would be a fraction of its current size.

**What is given up.** The multipart parser is hand-written
(`src/actaira/web/server.py:181` to `src/actaira/web/server.py:299`), which is
new code on a hostile input path, and `cgi.FieldStorage` could not be used
anyway: it is gone in Python 3.13 and buffered the whole body before that, which
is exactly what must not happen here. There is no session handling, no
authentication, no CSRF machinery and no rate limiting. The server is loopback
by default for that reason.

### 5.2 The local server still treats every request as hostile (D-18)

**Decided.** The server is local by default and defends itself anyway
(`src/actaira/web/server.py:11`), because the files it is handed are hostile by
definition. Concretely:

- bind to `127.0.0.1` unless the operator asks otherwise, and print a warning
  when they do (`src/actaira/web/server.py:905`);
- a request with no `Content-Length` is refused with 411 rather than read until
  it stops, and `Transfer-Encoding: chunked` is refused too, because
  `BaseHTTPRequestHandler` does not decode it (`src/actaira/web/server.py:337`);
- uploads stream to a temporary file in fixed-size chunks and are capped at 2
  GiB; the body is never materialised in memory
  (`src/actaira/web/server.py:244`, `src/actaira/web/server.py:350`);
- the client's filename is used for its sanitised basename only, never to build
  a path, and both separators are cut because a Windows client sends
  `C:\Users\x\model.pt` (`src/actaira/web/server.py:302`);
- the upload lands in a fresh `mkdtemp()` directory removed in a `finally`
  (`src/actaira/web/server.py:705` and `src/actaira/web/server.py:710`);
- the report's `path` is rewritten to the sanitised basename before it leaves
  the process, so no server-side temporary path is disclosed to the browser or,
  more importantly, frozen into a signed attestation
  (`src/actaira/web/server.py:406`);
- `X-Content-Type-Options: nosniff` and a CSP allowing `'self'` only, with no
  `unsafe-inline` and no `unsafe-eval`, on every response
  (`src/actaira/web/server.py:610`). That is why there is not one inline
  `<style>`, `<script>` or `style=` attribute in the static files;
- static file serving resolves the candidate and rejects anything outside
  `STATIC_ROOT` (`src/actaira/web/server.py:764`).

**Rejected: treat a loopback server as trusted.** Common, and it would remove
most of the code above.

**What is given up.** The endpoint has no authentication, so binding it to a
non-loopback address exposes an interface that accepts a 2 GiB upload and parses
hostile formats for anyone who can reach it. That is allowed and never silent
(`src/actaira/web/server.py:906`). One limit is stated rather than hidden:
`inspect_artifact` reads a bare pickle fully into memory, so the practical
ceiling for that one format is set by RAM, not by the 2 GiB cap
(`src/actaira/web/server.py:33`).

### 5.3 Exit codes are the CLI contract

**Decided.** 0 all passed, 1 at least one failed, 2 usage or environment error,
3 nothing failed but something was inconclusive
(`src/actaira/cli.py:35`).

**Why.** The tool is meant to run in CI, where the exit code is the whole
interface.

**Rejected: fold 3 into 0.** One fewer state for pipeline authors to handle.

**What is given up.** Pipelines need an extra branch. `--allow-inconclusive`
collapses 3 to 0 for teams that decide otherwise, and that decision then lives
in their CI config rather than in the tool.

### 5.4 The corpus is generated from code, not downloaded (D-19)

**Decided.** Every corpus artifact is generated by
`evals/corpus/build.py`, so the corpus is reproducible byte for byte on any
machine and its SHA-256 values can be published. Pickles are crafted from raw
opcodes rather than by pickling a live object
(`evals/corpus/build.py:53`), so the corpus can reference callables without
importing them, and `os.system` does not pickle as `posix.system` on Linux and
`nt.system` on Windows.

**Rejected: download real models from a hub.** They would be representative in a
way a synthetic corpus can never be.

**What is given up.** Three things were traded away deliberately: reproducibility
would be lost, CI would depend on a third party, and it would mean committing
malware to a public repository. What remains is a corpus whose malicious half is
hand-crafted from documented gadget shapes. It measures detector coverage
against those shapes. It does not measure performance against real-world
malware, and the eval report says so rather than implying a broader claim
(`evals/corpus/build.py:9`). The Keras cases are the sharpest example: they
carry a real HDF5 magic number and a real Keras `model_config` blob but are not
valid HDF5 files, so they exercise the `Lambda` detector and not HDF5 parsing,
which this tool does not claim to do (`evals/corpus/build.py:138`).

### 5.5 The opcode view and the sample strip inherit the server's rules (D-22)

**Decided.** The routes added for the opcode view and the bundled samples
negotiate nothing new. `POST /api/disassemble` takes the same streamed
multipart as `/api/scan` and never reads more than `MAX_DISASSEMBLY_BYTES` into
memory (`src/actaira/web/server.py:97`). The JSON body routes read exactly
`Content-Length`, refuse chunked encoding and cap the body at `MAX_JSON_BODY`,
8 KiB (`src/actaira/web/server.py:99`, `src/actaira/web/server.py:726`).
`/api/verify` gains a `chain` view of the entries with payloads stripped, and
every failure path in it returns an empty chain rather than a failed
verification (`src/actaira/web/server.py:540`).

**Why.** Which file in a container holds a pickle is decided by `detect.sniff`,
the function the inspector already uses
(`src/actaira/web/server.py:480`), so the trace and the verdict cannot disagree
about what was read. The sample artifacts are a closed, ordered allowlist in
source (`src/actaira/web/server.py:112`): a request carries a name, the name is
compared against the allowlist before any path is built, and the resolved path
is then required to be a direct child of the samples directory, which also
refuses a symlink planted inside it (`src/actaira/web/server.py:422`). A name
is never concatenated into a path and hoped for the best.

**Rejected: serve the samples directory as static files, and let the opcode
view read whatever the user points it at.** One route instead of four, no
allowlist to keep in step with the corpus.

**What is given up.** The sample strip is a fixed tuple of four names, so it
goes stale whenever the corpus is renamed, and it disappears entirely from an
installed wheel because `evals/` is not packaged
(`src/actaira/web/server.py:108`); `_sample_listing` returns an empty list in
that case rather than an error, so the UI silently has no samples. The opcode
view is capped twice, at 64 MiB of input and 4096 rendered steps
(`src/actaira/web/server.py:98`), so a large artifact is scanned in full and
shown in part. And the `chain` view swallows every exception by design, which
means a corrupt `entries.jsonl` inside a package that otherwise verifies shows
as a page with no picture and no explanation.

The gap named in section 3.5 applies here with more force: there is no test
module for `src/actaira/web/server.py` at all. The allowlist resolution, the
multipart parser, the header refusals and the temporary-directory lifecycle are
argued for in the docstring and exercised by hand, not asserted.

### 5.6 Artifacts written by the real serialisers, alongside the generated corpus (D-23)

**Decided.** `evals/corpus/real.py` writes artifacts with torch, safetensors,
onnx and h5py when those libraries are installed
(`evals/corpus/real.py:3`), nine cases in total, each carrying the writer's
version and the verdict Actaira is expected to reach. They sit next to the
generated corpus rather than replacing it, and
`tests/test_real_artifacts.py` asserts on them.

**Why.** This is the answer to the sharpest criticism the generated corpus
attracts: you wrote both the files and the parser, so of course they agree.
Section 5.4 buys reproducibility by crafting every byte, and pays for it in
external validity. This module buys the external validity back. Where the
writing library can also serve as an oracle it does: the safetensors shapes,
the ONNX protobuf fields and the Keras layer names are compared against what
the writing library reads back, not only against literals in the test.

**Rejected: replace the generated corpus with real artifacts, or make the real
ones mandatory.** Either would make the eval representative in one step.

**What is given up.** The dependency is one-way and has to stay that way.
Actaira imports none of these libraries; they are dev extras, every generator
degrades to a skip when its library is missing
(`evals/corpus/real.py:44`), and every test is guarded per library. If this
module ever became required to run the eval, the project's central claim, that
you can inspect an artifact without installing the ecosystem that loads it,
would be false in its own repository. The price is that the real half of the
evidence is conditional: on a machine with no ML stack the suite is still
green and nine cases simply did not run. The published harness numbers in
`evals/results.json` come from the generated corpus alone
(`evals/harness.py:56`); the real cases reach the comparison table instead,
merged in by `evals/benchmark.py:209`.

### 5.7 Comparison against the other scanners, on the same corpus (D-24)

**Decided.** `evals/benchmark.py` runs Actaira, picklescan, Protect AI's
modelscan and Trail of Bits' fickling over identical artifacts, in the same
order, on the same machine, in one run, and prints what each one said
(`evals/benchmark.py:3`). Five fairness rules are written into the docstring
and each is pinned by a test in `tests/test_benchmark.py`.

**Why.** A tool that only reports its own numbers is asking to be taken on
faith. The question asked of every tool is the one a user actually asks, "does
this tool tell me the artifact is dangerous", rather than "did it fire my
rule", which only Actaira has. A tool is scored only on formats it claims to
support, and coverage is reported separately as a count of declines
(`evals/benchmark.py:277`). Every tool runs with its default configuration.
Losses are printed: an artifact another tool catches and Actaira misses is
named in the output, and an empty loss list is printed as empty rather than
omitted, because an empty list means nothing unless the reader knows it was
computed.

**Rejected: publish only Actaira's own detection counts, and describe the
others in prose.** No optional dependencies, no adapters to maintain, no risk
of misrepresenting a tool by running it wrong.

**What is given up.** Three things, all of them stated in the report rather
than argued away. The corpus is not neutral: it was built while developing
Actaira, so it contains the gadget shapes Actaira was designed around. The
adapters are this project's reading of each rival's interface, so a rival
configured differently would score differently. And the error contract is not
uniform across adapters: `_picklescan` and `_modelscan` catch `Exception` while
`_fickling` catches only `TimeoutExpired`, and `run` wraps no adapter call at
all, so anything a subprocess launch raises aborts the whole benchmark instead
of being recorded. That asymmetry is named in the test that covers the rest of
the contract (`tests/test_benchmark.py:184`); a crashed run is loud, which is a
smaller problem than a silent one, but it is not the same guarantee for all
three.

## 6. Resource budgets

Every parser here reads attacker-controlled bytes, so every loop needs a bound.
The table gives each budget, where it lives, and where the number came from.
Three of the numbers have a derivation recorded in the code. The rest are
engineering ceilings chosen to be implausible for a real artifact; the code does
not record a measurement for them, and this document does not invent one.

| Budget | Value | Location | Where the number comes from |
|---|---|---|---|
| `MAX_OPCODES` | 2,000,000 | `src/actaira/formats/pickle_scan.py:76` | About three orders of magnitude above the largest legitimate state_dict measured in the corpus. A pickle header is cheap to fake, so without a bound a malicious artifact makes the scanner spin. Exceeding it raises `ACT-PKL-008` and stops the scan. |
| `MAX_COMPRESSION_RATIO` | 100 | `src/actaira/formats/archive.py:42` | Measured against the corpus. The highest ratio on a legitimate tensor archive is 1.9, because raw float buffers barely compress. Text-heavy members compress much better: `tests/test_formats.py:271` builds a realistic `model.safetensors.index.json` and measures roughly 35x. 100 sits clear of both and far below the 1000-plus of a bomb. |
| `MAX_HEADER_BYTES` | 64 MiB | `src/actaira/formats/safetensors.py:22` | The largest legitimate header measured in the corpus is under 1 MiB. 64 MiB leaves three orders of magnitude of headroom while still refusing a header that claims to be the whole disk. |
| `MAX_MEMBERS_INSPECTED` | 512 | `src/actaira/formats/archive.py:43` | No derivation recorded. Members beyond it are not inspected, which raises `ACT-ZIP-004` and forces INCONCLUSIVE. A 600-shard checkpoint is a normal layout, so this bound is reached in practice (`src/actaira/inspect.py:115`). |
| `MAX_BYTES` (ONNX) | 512 MiB | `src/actaira/formats/onnx.py:29` | No derivation recorded. The whole file is read into memory by `onnx.inspect`, so this is the memory ceiling for that inspector. Exceeding it raises `ACT-ONX-004`. |
| `MAX_NODES` | 200,000 | `src/actaira/formats/onnx.py:30` | No derivation recorded. Nodes past the bound are skipped silently rather than reported (`src/actaira/formats/onnx.py:180`). |
| `MAX_KV` | 4096 | `src/actaira/formats/gguf.py:20` | No derivation recorded. Exceeding it raises `ACT-GGF-003` at HIGH and stops parsing. |
| `MAX_TENSORS` | 100,000 | `src/actaira/formats/gguf.py:21` | No derivation recorded. Same rule as `MAX_KV`. |
| `MAX_STRING` (GGUF) | 1 MiB | `src/actaira/formats/gguf.py:22` | No derivation recorded. A GGUF string field declares its own length as a u64, so without this a single field can claim the address space. |
| GGUF array length | `MAX_KV * 64` | `src/actaira/formats/gguf.py:85` | Derived from `MAX_KV`, not independently chosen. |
| GGUF tensor rank | 8 | `src/actaira/formats/gguf.py:147` | No derivation recorded. Above it, the reader raises "implausible tensor rank". |
| `MAX_SCAN_BYTES` (HDF5) | 256 MiB | `src/actaira/formats/keras_h5.py:28` | No derivation recorded. The scan reads up to this many bytes into memory and records `truncated_scan` when the file is larger. |
| varint shift limit | 70 bits | `src/actaira/formats/onnx.py:45` | Protobuf varints are at most 64 bits, so a stream longer than that is malformed by definition. |
| `MAX_UPLOAD_BYTES` | 2 GiB | `src/actaira/web/server.py:88` | No derivation recorded. Streamed, never buffered. |
| `MAX_FIELD_BYTES` | 64 KiB | `src/actaira/web/server.py:89` | No derivation recorded. The comment states the reasoning: a text form field this big is an attack, not a form field. |
| `MAX_HEADER_LINE` | 8 KiB | `src/actaira/web/server.py:90` | No derivation recorded. Bounds one multipart part header line. |
| `READ_CHUNK` (web) | 512 KiB | `src/actaira/web/server.py:91` | Streaming chunk size, not a security bound. |
| `READ_CHUNK` (hashing) | 1 MiB | `src/actaira/inspect.py:24` | Chunk size for `sha256_file`, not a security bound. |
| `MAX_MEMBER_BYTES` (zip) | 256 MiB | `src/actaira/formats/archive.py:48` | Above any `data.pkl` measured, since a state_dict pickle holds offsets rather than weights and the largest in the corpus is under 1 MiB. |
| `MAX_CONCATENATED_STREAMS` | 8 | `src/actaira/formats/pickle_scan.py:84` | No derivation recorded. Bounds how many pickles concatenated after the first `STOP` are scanned. This is the constant the exponential blow-up in section 8.2 was raising to a power. |
| `MAX_RANK`, `MAX_DIM` | 64, 2^64-1 | `src/actaira/formats/shape.py:43` | Read off the formats: every one of them stores a dimension in 64 bits. Added after fuzzing found a declared shape whose element count could not be rendered as decimal. |
| `MAX_STEPS` (disassembly) | 4096 | `src/actaira/formats/disassembly.py:28` | No derivation recorded. Bounds the rendered opcode view, not the scan behind it. |
| `MAX_DISASSEMBLY_BYTES` | 64 MiB | `src/actaira/web/server.py:97` | No derivation recorded. Bounds what the opcode route reads into memory, so a merely large artifact cannot become a memory exhaustion primitive. |
| `MAX_DISASSEMBLY_STEPS` | 4096 | `src/actaira/web/server.py:98` | The server's own copy of `MAX_STEPS`, passed into `disassemble`. |
| `MAX_JSON_BODY` | 8 KiB | `src/actaira/web/server.py:99` | No derivation recorded. Caps the JSON body routes, which carry a sample name and a policy and nothing else. |
| `MAX_CHAIN_ENTRIES_SHOWN` | 256 | `src/actaira/web/server.py:100` | No derivation recorded. Rows drawn in the chain view; the total is still reported so the UI can say it truncated. |
| `MAX_ENTRIES_BLOB` | 8 MiB | `src/actaira/web/server.py:101` | No derivation recorded. Above it the chain view returns empty rather than reading the file. |

Four of these budgets have a verdict consequence, not just a performance one.
`ACT-PKL-008`, `ACT-ZIP-004`, `ACT-ONX-004` and `ACT-GGF-003` all mean "part of
this artifact was not inspected", and all four now feed `fully_read = False` so
the artifact cannot come back PASS. `ACT-ONX-004` used to be the exception: the
ONNX branch keyed `fully_read` on `ACT-ONX-003` alone, so an oversized ONNX file
reached INCONCLUSIVE only because MEDIUM is below the default `--fail-on` and
nothing had been parsed. The branch now names both rules
(`src/actaira/inspect.py:136`), and the general case is derived from
`UNREAD_RULE_IDS` for every branch at once (`src/actaira/inspect.py:183`).
Section 8 records how many times that bug shipped before it was derived in one
place.

## 7. Bugs the project found in itself, in detail

Five entries, narrated because the mechanism that caught each one is the
interesting part. Section 8 is the complete list, in one table, including the
ones narrated here.

### 7.1 The zip branch never set `fully_read = False`

**Where.** `src/actaira/inspect.py`, the `zip` and `pytorch-zip` branch. The
condition now lives in one place for every branch,
`src/actaira/inspect.py:183`.

**What was wrong.** Every other inspector branch fed its "I could not read all
of this" condition into `fully_read`. The zip branch did not. So an archive that
hit the member budget, or would not open at all, or had a member that would not
decompress, fell through to PASS at the default threshold.

**Why it mattered.** `MAX_MEMBERS_INSPECTED` is 512 and a 600-shard checkpoint
is a normal layout, so the case is not exotic. An artifact with more than 512
members and a gadget in member 520 reached PASS with the gadget never scanned at
all. That is precisely the silent pass D-04 forbids.

**What caught it.** The test suite, not review. `tests/test_formats.py:331` is
parametrised over the three ways a zip can be incompletely read, `ACT-ZIP-004`,
`ACT-ZIP-005` and `ACT-ZIP-003`, and asserts for each that `fully_read` is
`False` and the verdict is not PASS. `tests/test_formats.py:303` builds the
over-budget archive with the gadget placed past the budget on purpose.

**Fix.** The same bug then turned up in six more places, so the per-branch fix
was replaced by one derivation. `UNREAD_RULE_IDS`
(`src/actaira/inspect.py:39`) lists every rule identifier that means "part of
this artifact was not read", and `src/actaira/inspect.py:183` clears
`fully_read` whenever one of them is in the findings, whatever the branch
concluded. The history is written into the code as a comment at
`src/actaira/inspect.py:30`. The ONNX branch was the second occurrence and was
fixed in between, with nothing recorded about what found it
(`src/actaira/inspect.py:134`). Section 8.2 records the five that fuzzing
found.

### 7.2 `verify.py` returned `ok=True` against non-matching trust anchors

**Where.** `src/actaira/attest/verify.py`, the tail of `verify_package`, now
`src/actaira/attest/verify.py:295`.

**What was wrong.** `ok` was computed from the five integrity checks alone.
Supplying `--trusted-keyring` with a keyring that did not contain the signing
key produced `trust_state = "untrusted"`, a problem line saying the key is not
in the supplied anchors, and `ok = True`.

**Why it mattered.** Supplying anchors is an assertion about who you accept. A
caller that supplied them and read `ok` got a green light next to "this key is
not one of yours", which is a contradiction a CI job would act on.

**What caught it.** A review of the test suite. The behaviour was consistent
with the docstring's split between integrity and identity, which is why it
survived a reading of the module in isolation; it was reading the tests for the
identity half against what a caller would do with the result that exposed it.

**Fix.** `src/actaira/attest/verify.py:295` sets `ok = False` whenever
`trust_state` is `untrusted`. Not supplying anchors at all remains the
permissive default and reports `embedded_key_only`. The reasoning is a comment
at `src/actaira/attest/verify.py:291` and the behaviour is pinned by
`tests/test_package_verify.py:188`, which asserts that every integrity check
still passes while `ok` is `False`.

### 7.3 The eval harness had a vacuous positive on 8 of 50 packages

**Where.** `evals/harness.py`, `_tampered_package_rejected`, now
`evals/harness.py:252`.

**What was wrong.** The tamper check rewrites one entry inside a signed package
and asserts that verification then fails. The rewrite set the entry's verdict to
the constant `"pass"`. For an artifact already recorded as `pass`, the
"tampered" package was byte-identical to the original, so verification failed to
fail for the right reason: it did not fail at all, and the check passed
vacuously on 8 of 50 cases.

**Why it mattered.** The harness reported 50 of 50 tampered packages rejected
while only 42 of them had actually been tampered with. The number was true and
meaningless.

**What caught it.** Running the harness and reading the figure. Nothing failed;
the count simply did not match what the check was supposed to be measuring.

**Fix.** `evals/harness.py:252` flips the verdict to its opposite rather than
setting a constant, which guarantees a real mutation on every case. The reason
is written into the code at `evals/harness.py:248`. The current result, over a
corpus that has since grown, is 55 of 55 rejected out of 55 tested, with 55
packages verifying before tampering, which is the positive control that makes
the negative control meaningful (`evals/harness.py:170`).

### 7.4 Five false positives on the benign corpus, and what they cost

Not a bug: an example of the eval measuring the cost of a policy rather than
only its benefit.

The strict allowlist initially rejected five of the fifteen benign artifacts.
Reproduced in this container by removing the two entries and re-running the
benign half:

| Case | Import that fired `ACT-PKL-001` |
|---|---|
| `benign_state_dict_p0.pkl` | `_codecs.encode` |
| `benign_state_dict_p1.pkl` | `_codecs.encode` |
| `benign_state_dict_p2.pkl` | `_codecs.encode` |
| `benign_state_dict_p5.pkl` | `numpy._core.numeric._frombuffer` |
| `benign_checkpoint.pt` | `_codecs.encode` |

All five went to FAIL, not to a warning. `_codecs.encode` fires on every
protocol 0 to 2 state_dict, because that is how those protocols carry numpy raw
bytes. `numpy._core.numeric._frombuffer` fires on the protocol 5 out-of-band
buffer path. Both were added to the allowlist, each with the reasoning written
next to the entry (`src/actaira/scan/policy.py:58` and
`src/actaira/scan/policy.py:65`). `_codecs.encode` is recorded as risk
acceptance A-02 with an explicit argument for why the hole is bounded:
`_codecs.encode(str, codec)` decodes text, it does not dispatch to arbitrary
user code.

The point is the direction of the measurement. An eval that only counts
detections tells you an allowlist is strictly better than a denylist. Counting
false positives on a benign corpus built with real serialisers is what turns
"strict is better" into "strict is better and here is the curation it costs".

### 7.5 The malicious case `strict` used to miss, and the rule that could not fire

`count_mismatch.gguf` declares four tensors and carries one
(`evals/corpus/build.py:334`). `ACT-GGF-004` exists for exactly that
disagreement, and for a long time it did not fire on the one artifact written
to trigger it.

**What was wrong.** The tensor loop ran exactly `declared_tensor_count` times
or raised. If it completed, `len(tensors)` equalled the declared count by
construction and the comparison that raises `ACT-GGF-004` could never be true;
if it did not complete, the exception handler returned first with
`ACT-GGF-001` at MEDIUM. MEDIUM is below the default `--fail-on=high` and
`ACT-GGF-001` drives `fully_read = False`, so the verdict was INCONCLUSIVE, the
corpus recorded `expect_verdict: inconclusive`, and the policy table counted
the case as `malicious_missed` for both policies
(`evals/harness.py:124`). A rule with catalogue entries in two languages could
never fire in any of them.

**What caught it.** Reading the code against its own documentation. Nothing
failed and no number moved: the rule was in `en.json` and `es.json`, in the
corpus as a `forbid_rules` entry (`evals/corpus/build.py:214`), and never once
as an expected positive. That absence is the whole signal.

**Fix.** The tensor loop now keeps what it managed to parse instead of
aborting, records where it stopped, and reports the truncation and the count
disagreement separately (`src/actaira/formats/gguf.py:142`, `src/actaira/formats/gguf.py:173`). The reason is a
comment at `src/actaira/formats/gguf.py:137`. `count_mismatch.gguf` now reaches
FAIL on `ACT-GGF-001` plus `ACT-GGF-004`, its corpus expectation was changed to
match, and `strict` misses nothing in the current run. The regression test is
`tests/test_formats.py:490`, with its negative control at
`tests/test_formats.py:510` so that a rule which fires on everything would fail
too.

The accounting rule that made the miss visible is unchanged and worth keeping:
only FAIL counts as caught. Calling INCONCLUSIVE a detection because the file
did not pass would make the detection number depend on how the tool phrases its
uncertainty rather than on what it found, and a tool could then improve its
score by getting worse at parsing.

## 8. What the project found in itself

This is the central argument of the repository, so it is collected here rather
than left scattered across the docstrings that record each one. Every defect
below was found from inside the project, by one of the project's own
mechanisms.

The column that matters is the third. Ten instruments have caught something
here: the test suite, an adversarial read of the code, an adversarial read of
the law against the Official Journal, a benign corpus, artifacts the real
serialisers wrote, a fuzzer, a benchmark's own tests, an exhaustive sweep,
running the harness, and reading the tool's own output on a real model. Each
one has caught something none of the others did. A mechanism that has never
caught anything is a mechanism nobody should trust, including the person who
built it.

Three entries are not defects in the shipped tool. The false positives on the
benign corpus are the eval measuring the cost of a policy; the benchmark
denominator and the harness tamper check were defects in the measuring
apparatus rather than in Actaira. All three are in the ledger because they
were found the same way everything else was, and all three are marked so they
do not inflate the count of defects in the tool itself.

The table below is a reading list, not the record. The record is
`docs/defects.json`: one entry per defect, with what broke, which mechanism
caught it and the node ids of the tests that keep it caught. `make figures`
counts that file and checks every test it names against what pytest actually
collects, so a renamed test surfaces as an unpinned defect instead of leaving
a total that still looks healthy, and `tests/test_defect_ledger.py` makes the
same check on every commit. The count in the README comes from there and from
nowhere else, because for one release it came from this table, which no
command produces.

| Defect | What broke | What caught it | Regression test |
|---|---|---|---|
| The zip branch never cleared `fully_read` | An archive over the member budget, or one that would not open, reached PASS with the unscanned members never looked at | The test suite | `tests/test_formats.py:331` |
| `verify_package` returned `ok=True` against non-matching anchors | A green result printed next to "this key is not one of yours" | A review of the test suite | `tests/test_package_verify.py:188` |
| The harness tamper check passed vacuously on 8 of 50 | The "tampered" package was byte-identical to the original whenever the recorded verdict was already `pass` | Running the harness and reading the figure | `evals/harness.py:252` (the fix); no unit test |
| Five false positives on the benign corpus | `_codecs.encode` and `numpy._core.numeric._frombuffer` failed five real state_dicts under the strict allowlist | The benign half of the corpus | `tests/test_policy.py:30` |
| `ACT-GGF-004` could never fire | A rule with catalogue entries in two languages, unreachable by construction | Reading the code against its own documentation | `tests/test_formats.py:490` |
| A seven-byte pickle gate let a protocol 0 gadget through | `posix.system` inside a checkpoint reached PASS under both policies | Adversarial review | `tests/test_formats.py:582` |
| The `torch.` prefix allowed its own executable siblings | `cpp_extension.load_inline`, `torch._C`, `torch.multiprocessing.spawn` and `torch.hub` were allowed by prefix | Adversarial review | `tests/test_policy.py:69`, `tests/test_formats.py:623` |
| Fourteen parser bugs, including 73 seconds and 8.1 million objects from 24 bytes | Exponential recursion, unbounded allocation, uncaught exceptions, reports that could not be serialised, and five more paths to PASS on an unread artifact | Fuzzing, 2 277 000 cases | `tests/test_fuzz_regressions.py:56` plus 18 named tests in the same file |
| The legacy torch container failed as a false positive | Every checkpoint written before torch 1.6 reached FAIL on `ACT-PKL-010` | The real-serialiser corpus | `tests/test_real_artifacts.py:411` |
| The benchmark counted declines in the detection denominator | Every rival's score was understated, always in Actaira's favour | The benchmark's own tests | `tests/test_benchmark.py:322` |
| The consistency proof failed for every power-of-two `old_size` | Prover and verifier were written from the same misunderstanding, agreed with each other, and disagreed with RFC 6962 | An exhaustive sweep over every (old, new) pair | `tests/test_consistency.py:104` |
| `torch.storage._load_from_bytes` was on the allowlist | Its body is `torch.load(BytesIO(b), weights_only=False)`. A gadget in the byte operand reached PASS with exit 0 under both policies, and a test asserted the entry was correct | Adversarial review | `tests/test_formats.py::test_a_nested_loader_payload_is_disassembled_not_trusted` |
| One byte after `STOP` removed an archive member from the analysis | An ambiguously named member was kept only if its bytes looked like a pickle at both ends, so a trailing byte dropped it with no rule at all and `fully_read` stayed True | Adversarial review | `tests/test_formats.py::test_an_ambiguous_member_with_a_trailing_byte_is_not_dropped` |
| The assessment printed a capability as though it were evidence | The catalogue's "what Actaira provides" lines were printed under the word provides for every applicable obligation, evidence or none | Adversarial review | `tests/test_cli.py::test_an_obligation_with_no_evidence_does_not_read_as_provided` |
| Two package members under one name defeated the manifest | `read` returns the last member of that name, so an unsigned one could hide behind a name the manifest covered | Adversarial review | `tests/test_package_verify.py::test_two_members_under_one_name_are_refused` |

Sections 7.1 to 7.5 narrate the first five. The rest follow.

### 8.1 The seven-byte pickle gate and the `torch.` prefix (adversarial review)

Two holes, found in one sitting by reading the code as an attacker rather than
as an author. Neither was failing a test, because neither had one.

**The gate.** `archive.inspect` skipped any zip member whose first byte was not
one of seven hand-listed "common" pickle start opcodes. A protocol 0 stream
starts with `INT`, the byte `I`, which was not in the set. A `posix.system`
reduction in `archive/data.pkl` therefore rode through untouched under both
policies, and the same stream loose on disk was not even detected as a pickle.
Any hand-written subset of an opcode table is a guess about what an attacker
will choose. The fix derives the set from `pickletools.opcodes` instead
(`src/actaira/formats/detect.py:30`), and the reason is written above it at
`src/actaira/formats/detect.py:25`. The archive inspector imports that set
rather than keeping a second copy (`src/actaira/formats/archive.py:200`).
Widening the set needs a counterweight, so detection also requires the stream to
end in `STOP`; the negative control for that is `tests/test_formats.py:612`.

**The prefix.** `ALLOWED_MODULE_PREFIXES` held `("torch.",)`, with a
hand-maintained `PREFIX_EXCEPTIONS` list underneath it to claw back the
dangerous names. `torch.utils.cpp_extension.load` was on the exception list.
Its sibling `load_inline`, which compiles and runs C++ at load time, was not.
Neither were `torch._C.*`, `torch.multiprocessing.spawn` or `torch.hub.*`. A
prefix over a namespace that large is allow-by-default over a tree that changes
every release, which is the failure mode of a denylist, which is the thing D-02
exists to avoid. Both constants are now empty
(`src/actaira/scan/policy.py:78`, `src/actaira/scan/policy.py:95`) with the
argument written next to them. What the prefix was actually needed for, torch's
per-dtype storage classes, is now one narrow shape rule
(`src/actaira/scan/policy.py:99`). Two corpus artifacts were added so the eval
counts the difference rather than the document asserting it
(`evals/corpus/build.py:356`, `evals/corpus/build.py:361`), and the negative
control that the fix did not break legitimate torch reconstruction is
`tests/test_formats.py:641`.

### 8.2 Fourteen parser bugs from fuzzing

One property, stated as the product's own promise: for any byte sequence,
`inspect_artifact` must terminate, must not raise, must not allocate without
bound, and must never answer PASS for an artifact it could not fully read.
2 277 000 cases across nine targets and two engines, about 20 minutes of
wall clock. Fourteen unique bugs, all fixed, each with a reduced input kept in
`fuzz/corpus/` and a named test in `tests/test_fuzz_regressions.py`.
`fuzz/README.md` has the full budget table and the caveats.

The worst one is worth stating in full, because its size is the argument.
`b"." * 24`, twenty-four concatenated empty pickles, took 73 seconds and built
8.1 million `Finding` objects. `_scan_trailing_streams` called the full
`scan_pickle_bytes` on the remainder after each `STOP`, and that call scanned
its own trailing streams, which scanned theirs. With a branching factor of
`MAX_CONCATENATED_STREAMS` the work grew as 2 to the power of n, and every
level allocated its own copy of the tail. Twenty-four bytes, reachable through
a `.pkl`, through a zip member, and through an object-dtype `.npy` body. The
fix walks the concatenation forwards and visits each stream exactly once
(`src/actaira/formats/pickle_scan.py:378`), with the history in the docstring
at `src/actaira/formats/pickle_scan.py:391`. The regression test is
`tests/test_fuzz_regressions.py:84`, and its companion at
`tests/test_fuzz_regressions.py:111` asserts the fix did not stop the scanner
finding a gadget hidden in a trailing stream.

Three of the fourteen were reports that could not be serialised, which is a
failure the inspector itself cannot see: a one-byte ONNX file put a raw `bytes`
slice into `metadata`, a GGUF metadata float of `NaN` hit `allow_nan=False`,
and a declared safetensors shape produced an integer wider than CPython will
render as decimal. All three are uncaught exceptions in `actaira scan --json`
one function call later, so the fuzzer's oracle checks
`canonical_json(report.to_dict())` on every case.

Five more were the same defect as section 7.1 in different branches: the
safetensors branch and the NumPy branch never derived `fully_read` at all, the
zip branch derived it only from `ACT-ZIP-*` so an unparseable `data.pkl` member
passed, the pickle opcode budget did not set `truncated`, and the Keras scan
cap reported "config was read" regardless. That is the same bug shipped five
times, which is why the fix was to stop writing it per branch: `UNREAD_RULE_IDS`
(`src/actaira/inspect.py:39`) with one derivation
(`src/actaira/inspect.py:183`), and a test that asserts the set covers every
rule that means unread (`tests/test_fuzz_regressions.py:423`).

What the numbers do not say is in `fuzz/README.md` and is not repeated here,
except for the part that bears on this section: the oracle knows four things
and cannot see a wrong answer. A parser that reports the wrong dtype, or misses
a gadget it should have caught, satisfies all four properties.

### 8.3 The legacy torch container failed as a false positive

**What was wrong.** torch's pre-1.6 format writes four pickles back to back,
magic number, protocol version, `sys_info`, then the object, followed by raw
storages. Read as a plain pickle that is a concatenation with trailing binary,
which is exactly the shape `ACT-PKL-010` and `ACT-PKL-006` exist to report.
`ACT-PKL-010` is HIGH, so every checkpoint written before 2020 came back FAIL.

**What caught it.** The real-serialiser corpus (D-23). No hand-crafted artifact
in `evals/corpus/build.py` has that layout, because the layout is torch's, not
this project's. Reproduced in this container: with the exemption disabled, a
`torch.save(..., _use_new_zipfile_serialization=False)` checkpoint reports
`ACT-PKL-003`, `ACT-PKL-005`, `ACT-PKL-006` and `ACT-PKL-010` and reaches FAIL;
with it enabled the same file reports `ACT-PKL-003` and `ACT-PKL-005` and
reaches PASS.

**Fix, and why it is narrow.** An exemption in a security tool is a hole unless
it is proven to be narrow. The container is recognised structurally, from
torch's own documented magic number, by a first stream whose only data opcode
is a `LONG` carrying `TORCH_LEGACY_MAGIC`
(`src/actaira/formats/pickle_scan.py:470`), never from the file extension. Only
two findings are suppressed, and only the ones that describe the container:
`ACT-PKL-006` and `ACT-PKL-010`. Every import in every stream is still judged,
including the object pickle in the fourth stream where a gadget would live
(`src/actaira/formats/pickle_scan.py:428`). Three tests hold the exemption in
place: that it applies (`tests/test_real_artifacts.py:411`), that it hides
nothing (`tests/test_real_artifacts.py:430`), and that a file which merely
resembles the format cannot claim it
(`tests/test_real_artifacts.py:457`).

### 8.4 The benchmark counted declines in the detection denominator

**What was wrong.** `_score` built `malicious_total` from every malicious row
in the subset, including the rows a tool had declined because the format was
outside what it claims to read. A decline was therefore counted as a miss.

**Why it mattered.** The module docstring promises the opposite in as many
words: fairness rule 3 says coverage is reported separately, "without being
smuggled into accuracy". Measured effect on the published table: fickling
appeared as 32 of 36 head to head, when 4 of those 36 are torch zip containers
it returned "could not parse" for. Its real score on what it reads is 32 of 32.
The error flattered Actaira on every row, in every run, which is exactly why it
survived a reading.

**What caught it.** `tests/test_benchmark.py`, written to test the harness
rather than the tools. The test that found it is now the test that guards it
(`tests/test_benchmark.py:322`), and it was left in the suite as a strict
`xfail` while the defect stood, so the suite reported a known defect instead of
reporting green.

**Fix.** `evals/benchmark.py:263` drops the declined rows before counting, and
`malicious_in_scope` keeps the wider figure visible next to `malicious_total`
so a reader can see how many artifacts each tool declined
(`evals/benchmark.py:271`). The current `evals/benchmark.json` shows fickling
at `malicious_in_scope` 36, `malicious_total` 32, `malicious_caught` 32.

### 8.5 The consistency proof failed for every power-of-two `old_size`

**What was wrong.** When `old_size` is a power of two the old tree is a
complete subtree, so RFC 6962's SUBPROOF bottoms out at its own root and emits
it as the first node. The reference verifier expects that node to be absent,
because the verifier already holds the old root by definition: it is the root
it is checking against. The first version of this code emitted it and expected
it, so the prover and the verifier agreed with each other and disagreed with
every other implementation of RFC 6962.

**Why it mattered.** This is the failure mode of writing a prover and a
verifier from one misunderstanding. Every round-trip test passes. Every
hand-checked example passes. The proofs are simply not consistency proofs, and
nothing inside the repository would ever say so.

**What caught it.** An exhaustive sweep. Every `(old_size, new_size)` pair up
to 64, 2080 tree pairs, which is cheaper than reasoning carefully about one.
The power-of-two cases failed and nothing else did, which named the bug
directly.

**Fix.** `build_consistency_proof` strips the leading node when `old_size` is a
power of two (`src/actaira/attest/merkle.py:132`) and `verify_consistency`
follows the reference verifier rather than a hand-derived one
(`src/actaira/attest/merkle.py:154`). The sweep is
`tests/test_consistency.py:74`. Two tests pin the shape rather than only the
outcome: `tests/test_consistency.py:104` asserts the old root is not in the
proof, and `tests/test_consistency.py:139` reconstructs the original broken
proof and requires the verifier to refuse it, so prover and verifier cannot
quietly agree again.

### 8.6 Eight defects in the governance catalogue (adversarial legal review)

The catalogue is the one part of this repository whose correctness no test can
establish. A test can assert that the catalogue says what the catalogue says;
whether Article 4 currently reads the way the catalogue teaches it is a
question about the Official Journal, and the only instrument that answers it
is a lawyer reading both. That review found eight defects, the largest count
from any single mechanism except fuzzing, and the most serious of them was not
a detail.

**The tool insisted a published regulation was not yet law.** The catalogue
described the Digital Omnibus on AI as agreed but unpublished and printed
advice to keep preparing for the deadline it had moved. Regulation (EU)
2026/1744 had been in the Official Journal for six weeks, in force since 27
July 2026. Everything downstream inherited the error: the high-risk dates, the
Article 4 wording, and a `PROVISIONAL` badge in the web panel that warned about
a status no row carried any more.

The other seven, each now a named test in `tests/test_governance.py`:

* **Article 4 in its repealed wording.** The catalogue asked for evidence of a
  level of AI literacy attained. The amended article says expressly that no
  particular level has to be guaranteed, so the evidence that carries the
  obligation is of measures offered, not of attainment.
* **Annex IV cited at the wrong point.** Point 5 is the risk management
  system; the catalogue cited it as validation and testing, which is point
  2(g). The entry was self-contradicting as well as wrong: it listed risk
  management documentation among the things Actaira does not provide, two
  lines after naming point 5 as expected evidence.
* **The new Article 5 prohibitions were missing entirely.** Points (ba) and
  (bb), inserted by the same regulation, apply from 2 December 2026. They were
  the only duty in the catalogue with a date between the review and the end of
  the year, and they were not in it.
* **The Article 111(3) transitional was missing.** General-purpose models
  placed on the market before 2 August 2025 have until 2 August 2027, and the
  catalogue applied the earlier date to all of them.
* **Article 53(1)(b) was rated `SUPPORTS`.** A signed BOM of artifacts is not
  the documentation a downstream provider needs. It was the single entry in
  the catalogue claiming full support, and the assertion in the test suite now
  reads `== 0` rather than `<= 1`.
* **Article 12 was claimed by a ledger of artifact inspections.** Article 12
  asks the high-risk system to record its own events. A record of this tool's
  inspections is not that, and the evidence map pointed three kinds of
  evidence at it.
* **A residual `PROVISIONAL` notice**, described above, now emitted only when
  a row actually carries a provisional status.

What this section is really about is that the governance layer had to be
reviewed by an instrument the repository does not contain. The dates in
`catalog.py` carry their CELEX identifiers so a reader can go and check them,
and section 9 records that no test verifies the catalogue against anything
external, because nothing in a Python process can.

## 9. Where the code and its own docstrings disagree

The code is the source of truth. Where this document and a docstring disagree,
the docstring and the code it sits on win, and the disagreement belongs here
rather than being smoothed over.

**There is nothing open in this section right now.** That is a claim with a
short shelf life, so the four entries this section used to carry are kept below
with what closed each one. An empty list is only worth reading if you can see
it was checked.

1. **`ACT-GGF-004` appeared to be unreachable.** Closed by changing the code,
   not the document. The tensor loop now keeps what it parsed and reports the
   count disagreement separately (`src/actaira/formats/gguf.py:142`,
   `src/actaira/formats/gguf.py:173`). Section 7.5 narrates it and section 8
   lists it.

2. **D-17 and D-18 were each used for two unrelated notes.** Closed by
   renumbering in the code: the generated corpus is now D-19
   (`evals/corpus/build.py:3`) and the harness note D-20
   (`evals/harness.py:3`). Section 1 follows the code.

3. **The compression ratio for text-heavy members.** The comment used to say
   about 12x while the test measured about 35x. The comment now states 35x and
   names the test (`src/actaira/formats/archive.py:38`), and the measurement is
   still asserted at `tests/test_formats.py:275`.

4. **The memo figure did not reproduce.** The docstring used to state that 3 of
   4 imports in a two-tensor state_dict become unresolved without the memo
   model. It now records what actually reproduces, and which variant produces
   which count, together with the direction that holds in every variant
   (`src/actaira/formats/pickle_scan.py:310`). Section 2.3 quotes the current
   figures.

One note about test modules, in the same place, because a reader looking here
is looking for what is missing. This section used to record two gaps - no test
module for `src/actaira/formats/disassembly.py` (section 3.5) and none for
`src/actaira/web/server.py` (section 5.5) - and by 2.2.0 both had been closed
without the sentence moving. The disassembler is asserted in
`tests/test_formats.py`; the server has `tests/test_web_limits.py`, which is
where its limits and its two request-authority checks are pinned, and
`tests/test_web_frontend.py`, which asserts the properties of the shipped
interface that no Python test can see. The front end is additionally gated by
`scripts/screenshots.py`, which loads every panel in both languages and fails
on a console error, a page error, a failed request or a CSP violation.

What remains genuinely unasserted is visual: the stylesheet's layout at a
given viewport is checked by a person looking at the captures in
`.screenshots/`, not by a test.

