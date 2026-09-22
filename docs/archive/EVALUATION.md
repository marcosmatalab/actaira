> **Archived.** This page describes the model scanner Actaira was until 3.0.0:
> static inspection of model artifacts, executable controls, policy as code and
> the EU AI Act catalogue. **None of it is in this tree.** It is kept, unedited,
> because a document that argued a decision is worth more than a summary of it,
> and because deleting it would leave the design notes that cite it pointing at
> nothing. The code it describes is at tag `v2.3.0`. For what Actaira is now, read [`../../README.md`](../../README.md).
> Nothing below is maintained, and nothing below is checked by a gate.

# How Actaira is evaluated

Four harnesses. Each one runs with no network, no API key and no downloaded
fixture, every corpus is written from code at build time, and each publishes
what it does **not** establish alongside what it does.

This page is the methodology. **The numbers are not repeated here**, and that
is deliberate: [`FIGURES.md`](FIGURES.md) is written by `make figures` from the
repository itself, the README states the headline figures under a contract
that refuses a tree where any of them has drifted, and a third hand-typed copy
on this page would be the one nobody notices going stale.

| Harness | Command | What it measures | Written to |
|---|---|---|---|
| Policy comparison | `make eval` | allowlist against denylist over the generated corpus | [`../evals/results.json`](../evals/results.json) |
| Head to head | `make benchmark` | picklescan, modelscan and fickling on the same artifacts | [`../evals/benchmark.json`](../evals/benchmark.json) |
| Marking survival | `make eval-marking` | whether an Art. 50(2) marking survives a publishing pipeline | `evals/marking/results.json` |
| Judged tier | `evals/agents/harness.py` | retrieve, judge, verify, abstain, over a gold set | `evals/agents/results.json` |

---

## The corpus, and why it is generated

Every artifact the evaluation runs against is written from code in
`evals/corpus/build.py` at build time. Downloading real models from a hub was
rejected for three reasons: it makes the eval non-reproducible, it makes CI
depend on a third party, and it would mean committing malware to a public
repository.

What that buys, and what it does not:

- The benign half exercises real serialisers, pickle protocols 0 to 5 via
  CPython and NumPy's own writer, so a false positive there is meaningful.
- The malicious half is hand-crafted from documented gadget shapes. It
  measures detector coverage against those shapes. It does **not** measure
  performance against real-world malware, which no synthetic corpus can, and
  the eval report states that rather than implying a broader claim.

`make nightly-real` closes the other half of the gap. It regenerates artifacts
with the real torch, onnx, h5py and safetensors and runs the format tests with
skipping disallowed, because a test that skips when a library is missing is a
test that passed by not running.
`.github/workflows/real-artifacts-nightly.yml` runs the same steps on a
schedule, and the job fails if a single test skipped.

---

## Counts, never rates

The corpus is closed and finite, so the right statistic is a count. Reporting
a detection percentage from a fixed set of cases would dress a count as an
estimate of a population that was never sampled. Every table in this project
reports `caught / total`, and the harness refuses to emit a rate.

---

## Detection, head to head

`make benchmark` installs picklescan, modelscan and fickling at whatever
version pip resolves on the day, and runs all three over the same artifacts.
They are not pinned on purpose: the comparison is only interesting against
what a user would install now, and the versions actually used are recorded in
the result file.

Three things make the comparison fair rather than flattering:

- **Declined is reported beside caught.** A tool that does not read a format
  has not failed at it, so what it declined to read is its own column rather
  than a miss.
- **The reverse question is computed every run.** The harness works out which
  artifacts another tool catches and Actaira misses, and prints the answer
  either way. "Nobody beats us" is only information if you can see it was
  checked.
- **fickling is asking a stricter question.** *Can this pickle execute
  anything at all* is legitimate and more conservative than *is this pickle
  malicious*, and it is why fickling also reports every ordinary `state_dict`
  in the corpus. Its false-alarm column is the cost of that question, not a
  defect, and the full table in [`FIGURES.md`](FIGURES.md) carries it.

Actaira's own false alarm is named in the output rather than explained away:
`real_full_module.pt` is `torch.save(model)` over a whole `nn.Module`, which
stores an import of the user's own class. Actaira reports it on purpose,
because loading it imports user code. By the corpus label it is a benign file,
so it is counted against Actaira here and a reviewer can decide which reading
they prefer.

The benchmark's own tests check that the comparison is fair, and one of them
is in the defect ledger because an early version counted a rival's real
detection as a decline.

---

## Marking survival under Article 50(2)

Article 50(2) requires providers of generative systems to mark output in a
machine-readable format, and names no format. Actaira reads and writes the
metadata kind: an XMP packet carrying the IPTC `digitalSourceType` term,
because that is the kind a third party can check offline with no secret.

The harness builds images, marks them, and pushes them through a battery of
transformations that an ordinary publishing pipeline performs: re-encode,
resize, crop, rotate, convert, strip metadata. Then it pushes the same images
through a pipeline that is aware of the marking and preserves it.

The claim the result supports is narrow and defensible:

> The durability of a metadata marking is a property of the pipeline, not of
> the marking.

Any Art. 50(2) implementation that does not control its own pipeline is making
a promise it cannot keep. The eval carries three negative controls that would
fail if the measurement were vacuous, and the harness refuses to publish if
any of them fails, because an earlier eval here shipped a tamper test that
passed without testing anything.

Actaira **does not** detect signal watermarks. They cannot be read without the
detector key, so a tool claiming to check for watermarks in general would be
claiming to see what it cannot.

---

## The judged tier, and how often it declines

One tier of the EU AI Act control engine needs a judgement: whether a supplied
document addresses an obligation is not something bytes decide. The pipeline
is retrieve, judge, verify, abstain:

1. Retrieval selects candidate spans from the supplied document.
2. The judge must cite spans **by exact offset**.
3. The verifier checks each cited span literally appears at that offset.
4. A hallucinated citation invalidates the whole answer, and the pipeline
   abstains rather than answering.

How often it declines is published rather than tuned away, and the abstention
count is part of the result, not a footnote.

**These figures measure the pipeline, not a language model, and the harness
says so in its own output.** They were produced by replaying cassettes
recorded from a deterministic stand-in grader. What they establish is that
retrieval, the offset checks, the verifier and the abstention policy behave as
specified over a fixed corpus. What a real model would score on this gold set
is not measured here, and no number in this repository claims it is.

The whole harness runs with no network and no API key, against recorded
transcripts indexed by the hash of the normalised prompt. A missing transcript
raises rather than inventing an answer, which is what makes the run
reproducible and also what makes it a measurement of the pipeline alone.

---

## Fuzzing

`make fuzz` runs every parser against mutated input on a deterministic seed.
The CI budget is a smoke test of the property rather than a search;
`make fuzz-long` is the one that finds things, and it is run before a release
rather than on every push.

Four properties are asserted per case:

- **(a) per-case termination.** A parser that hangs is a finding.
- **(b) no crash outside the error type the module declares.** Anything else
  escaping is a finding, including a `MemoryError` from an unbounded read.
- **(c) bounded memory.** An allocation driven by an attacker-controlled
  length field is a finding, whether or not it succeeds.
- **(d) determinism.** The same input produces the same verdict twice.

Two of those are enforced with POSIX-only primitives: `SIGALRM` for per-case
termination, and `RLIMIT_AS` and `getrusage` for memory. A run on a host that
does not provide them says so in its summary and in
[`FIGURES.md`](FIGURES.md), because the same finding count from a weaker set
of oracles is a weaker result, and printing it as though it were not would be
the quiet kind of dishonesty this project is built to avoid.

---

## Determinism, and why it is a gate

The same artifact must always produce the same report, byte for byte.
Non-determinism would make the attestation worthless: a report that varies
between runs cannot be signed into a chain that anyone can re-verify.

So it is asserted in three places:

- the eval harness inspects every corpus artifact twice and compares;
- the release gate runs three CLI commands twice under different
  `PYTHONHASHSEED` values and refuses a tree where the two runs differ;
- the state export is compared byte for byte over one fixed observation.

Anything that differs between two runs reached the terminal from a set, a dict
ordering, a clock or an address.

---

## What none of this measures

- Performance against malware in the wild.
- Whether an artifact is benign. Actaira reports that it did not find what it
  knows how to look for.
- Anything about the weights. A backdoor trained into a network is invisible
  to static inspection, by construction.
- Whether an organisation complies with anything. That is a legal question
  about a system in its context, and no tool that reads files can answer it.
