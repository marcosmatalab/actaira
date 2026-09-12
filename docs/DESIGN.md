# Actaira: design

Actaira inspects machine learning artifacts without loading or executing them,
emits a CycloneDX 1.6 ML-BOM describing only what it actually parsed, and signs
hash-linked Ed25519 attestations over those reports that a third party can
verify offline. The single runtime dependency is `cryptography`.

This document consolidates the numbered design notes that live in the module
docstrings under `src/` and `evals/`. The code is the source of truth. Where
this document and a docstring disagree, the docstring and the code it sits on
win, and the disagreement is listed in the last section.

Every decision below is stated in three parts: what was decided, why, and what
alternative was rejected together with what the chosen option gives up. A
decision without the third part is not a decision, it is a preference.

## 1. Index of design notes

| Note | Subject | Location |
|---|---|---|
| D-01 | One `Finding` shape for every inspector | `src/actaira/model.py:3` |
| D-02 | Allowlist by default, denylist available | `src/actaira/scan/policy.py:3` |
| D-03 | Canonical JSON under every hash | `src/actaira/model.py:157` |
| D-04 | `INCONCLUSIVE` is a result, not an error | `src/actaira/model.py:46` |
| D-05 | `pickletools.genops`, exact stack and memo | `src/actaira/formats/pickle_scan.py:3` |
| D-06 | Format detection by content, never extension | `src/actaira/formats/detect.py:3` |
| D-07 | Rule identifiers are the stable interface | `src/actaira/i18n/catalog.py:3` |
| D-08 | Hand-written protobuf reader for ONNX | `src/actaira/formats/onnx.py:3` |
| D-09 | HDF5 is a bounded byte scan, and says so | `src/actaira/formats/keras_h5.py:3` |
| D-10 | Verdict rules in one place | `src/actaira/inspect.py:3` |
| D-11 | RFC 6962 Merkle tree | `src/actaira/attest/merkle.py:3` |
| D-12 | Ed25519 | `src/actaira/attest/signing.py:3` |
| D-13 | Hash-linked entries, and no claim about time on their own | `src/actaira/attest/chain.py:3` |
| D-14 | Package is a plain zip, one signature | `src/actaira/attest/package.py:3` |
| D-15 | Integrity and identity kept separate | `src/actaira/attest/verify.py:3` |
| D-16 | CycloneDX rather than SPDX | `src/actaira/bom/cyclonedx.py:3` |
| D-17 | Zero third-party dependencies in the web layer | `src/actaira/web/server.py:3` |
| D-18 | The server treats every request as hostile | `src/actaira/web/server.py:11` |
| D-19 | Corpus generated from code, not downloaded | `evals/corpus/build.py:3` |
| D-20 | What the eval measures and refuses to measure | `evals/harness.py:3` |
| D-21 | Disassembly shows the mechanism instead of asserting it | `src/actaira/formats/disassembly.py:3` |
| D-22 | The opcode view and the sample strip inherit the server's rules | `src/actaira/web/server.py:48` |
| D-23 | Artifacts written by the real serialisers | `evals/corpus/real.py:3` |
| D-24 | Comparison against the other scanners, on the same corpus | `evals/benchmark.py:3` |
| D-25 | Consistency proofs, so append-only is evidence | `src/actaira/attest/merkle.py:97` |
| D-25b | The same question at the package boundary | `src/actaira/attest/verify.py:145` |
| D-26 | Resuming a chain, because a log you restart is not a log | `src/actaira/attest/chain.py:115` |
| D-27 | RFC 3161 time anchoring, optional and narrow | `src/actaira/attest/timestamp.py:3` |
| D-27b | Stamping the manifest before the manifest is finished | `src/actaira/attest/package.py:11` |
| D-28 | Several keys, with validity windows and a status | `src/actaira/attest/keyring.py:3` |
| D-29 | An obligation catalogue, and what makes it worth having | `src/actaira/governance/catalog.py:3` |
| D-30 | The clock takes the date as an argument, never the machine's | `src/actaira/governance/clock.py:3` |
| D-31 | No score, by construction | `src/actaira/governance/assess.py:3` |
| D-32 | An assessment is bound to the artifacts it was computed from | `src/actaira/governance/pack.py:3` |
| D-33 | Structure in the catalogue, prose in the message catalogues | `src/actaira/governance/catalog.py:32` |
| D-34 | What a coverage rating is allowed to claim | `src/actaira/governance/catalog.py:44` |
| D-35 | The bytes a nested loader is handed are disassembled, not trusted | `src/actaira/formats/pickle_scan.py:729` |
| D-36 | The governance routes inherit the server's rules | `src/actaira/web/server.py:752` |
| D-40 | A draft nobody signed is not evidence | `src/actaira/controls/model.py:3` |
| D-41 | No aggregate: controls are counted, never summed into a figure | `src/actaira/controls/model.py:32` |
| D-42 | How, if at all, software can bear on an obligation | `src/actaira/governance/catalog.py:157` |
| D-43 | The registry is the file a compliance tool has to be most careful with | `src/actaira/controls/registry.py:3` |
| D-44 | A control that raises is a defect, not a failing control | `src/actaira/controls/engine.py:3` |
| D-45 | What the agent layer is allowed to be, and what it is not | `src/actaira/agents/provider.py:3` |
| D-46 | The corpus answers with a citation, never with the legal text | `src/actaira/agents/corpus.py:3` |
| D-47 | BM25 over a dense retriever, argued on this corpus | `src/actaira/agents/retriever.py:3` |
| D-48 | The judge quotes the document at exact offsets | `src/actaira/agents/judge.py:3` |
| D-49 | Two questions of every citation, and how each one fails | `src/actaira/agents/verifier.py:3` |
| D-50 | DSSE and in-toto, so the report is speakable by other tools | `src/actaira/attest/dsse.py:4` |
| D-51 | PAE, and the dangling-file class the envelope removes | `src/actaira/attest/dsse.py:33` |
| D-52 | Checking the form of a record is not checking the record | `src/actaira/controls/records.py:3` |
| D-53 | An absence observed outranks a remainder unread | `src/actaira/controls/records.py:32` |
| D-54 | `ACT-C-15-ARTIFACT` is a bridge to the scanner, not a second one | `src/actaira/controls/records.py:47` |
| D-55 | filled_from_evidence, declared_by_operator, missing | `src/actaira/controls/documentation.py:3` |
| D-56 | A generated document is never SATISFIED, and where that is enforced | `src/actaira/controls/documentation.py:34` |
| D-57 | Annex text stays in Python, and is marked as a paraphrase | `src/actaira/controls/documentation.py:52` |
| D-60 | Machine-readable marking: which formats resolve to what, and what is refused | `src/actaira/marking.py:3` |
| D-61 | Article 50 is four duties on two actors, kept apart | `src/actaira/controls/art50.py:3` |
| D-62 | A marking control answers for the files it read, never for the obligation | `src/actaira/controls/art50.py:26` |
| D-63 | The Article 111(4) grace period, and why the date is an argument | `src/actaira/controls/art50.py:34` |
| D-64 | Article 50(1) is lexical on purpose, and the marker list is published | `src/actaira/controls/art50.py:271` |
| D-65 | Marking robustness is an Article 15 question, not an Article 50 one | `src/actaira/controls/art50.py:367` |
| D-66 | How often a marking survives the pipeline, and why Pillow is dev-only | `src/actaira/evals_support/robustness.py:3` |
| D-70 | Diagrams are generated from the code and the measurements, never drawn | `scripts/diagrams.py:5` |
| D-71 | The palette clears 3:1 on both GitHub surfaces, and colour is never alone | `scripts/diagrams.py:17` |
| D-80 | A connector enumerates; it never concludes | `src/actaira/connectors/model.py:3` |
| D-81 | Every connector speaks its protocol with the standard library | `src/actaira/connectors/model.py:35` |
| D-82 | An explicit TLS seam for the tests, which cannot turn verification off | `src/actaira/connectors/model.py:203` |
| D-83 | A refusal carries its status and headers, because one protocol lives in them | `src/actaira/connectors/model.py:94` |
| D-84 | One connector per source, and `accepts` predicates that do not overlap | `src/actaira/connectors/registry.py:3` |
| D-85 | The reference connector, and the digest it refuses to invent | `src/actaira/connectors/filesystem.py:3` |
| D-85c | A symlink is a claim about a path outside the tree, so it is not followed | `src/actaira/connectors/filesystem.py:31` |
| D-85b | A digest Actaira computed is not a digest the source declared | `src/actaira/connectors/filesystem.py:17` |
| D-86 | An LFS oid is a sha256; a git oid is not | `src/actaira/connectors/huggingface.py:3` |
| D-86b | The Hub cursor is not followed; a full page means the listing is a prefix | `src/actaira/connectors/huggingface.py:26` |
| D-87 | `truncated: true` is the field that decides a GitHub listing | `src/actaira/connectors/github.py:3` |
| D-87c | A release asset digest is believed only when it says sha256 | `src/actaira/connectors/github.py:25` |
| D-87b | Release assets and tree blobs are listed together and never blurred | `src/actaira/connectors/github.py:14` |
| D-88 | A registry digest is content-addressed and still a claim | `src/actaira/connectors/oci.py:3` |
| D-88b | The anonymous bearer challenge, followed once and never in a loop | `src/actaira/connectors/oci.py:18` |
| D-89 | No SigV4, stated in the docstring and in every listing | `src/actaira/connectors/s3.py:3` |
| D-89d | XML from a stranger: no doctype reaches the parser | `src/actaira/connectors/s3.py:45` |
| D-89c | An ETag is not a sha256 and sometimes not a digest at all | `src/actaira/connectors/s3.py:33` |
| D-89b | An anonymous bucket listing is never complete, even when nothing was truncated | `src/actaira/connectors/s3.py:21` |
| D-90 | The registry that knows the most and publishes no digest | `src/actaira/connectors/mlflow.py:3` |
| D-90b | Only a bearer token, never a username and password from the environment | `src/actaira/connectors/mlflow.py:20` |
| D-91 | A manifest of URLs, for every source this tool does not support | `src/actaira/connectors/url.py:3` |
| D-91c | The line format has nowhere to put a digest; the JSON one does | `src/actaira/connectors/url.py:29` |
| D-91b | What `complete` is allowed to mean when the source is a file somebody wrote | `src/actaira/connectors/url.py:17` |
| D-92 | What `discover` exits with, and why incomplete is not zero | `src/actaira/cli.py:1234` |
| D-93 | Redirects stay on HTTPS and are recorded like any other hop | `src/actaira/connectors/model.py:252` |
| D-93b | A credential does not follow a redirect to another host | `src/actaira/connectors/model.py:271` |
| D-100 | Coverage is per surface, not one boolean over the whole file | `src/actaira/coverage.py:3` |
| D-101 | Every rule says which surface it limits, so a scope note cannot fail a verdict | `src/actaira/coverage.py:255` |
| D-102 | An archive member is classified by its first bytes, never by its name | `src/actaira/formats/archive.py:57` |
| D-103 | Members left undecompressed limit raw tensor content and nothing else | `src/actaira/formats/archive.py:185` |
| D-104 | `fully_read` is derived from coverage, so the old contract still holds | `src/actaira/inspect.py:53` |
| D-105 | A surface nobody undertook to read cannot make a verdict inconclusive | `src/actaira/inspect.py:298` |
| D-106 | A directory walk classifies by content; an extension may order, never exclude | `src/actaira/cli.py:90` |
| D-110 | One hand-written YAML subset, shared by control declarations and policies | `src/actaira/miniyaml.py:3` |
| D-111 | A policy is a document with a digest, not an `if` in a CI config | `src/actaira/policy/__init__.py:3` |
| D-112 | A decision carries the proof that lets someone else re-derive it | `src/actaira/policy/model.py:3` |
| D-113 | A condition that cannot be evaluated is REVIEW, never False | `src/actaira/policy/engine.py:3` |
| D-114 | The shipped policy is a starting point to argue with, not a standard | `policies/production-model.yaml:3` |
| D-120 | A signed statement of observed state that is not a certification and not a score | `src/actaira/receipt.py:3` |
| D-130 | A model is a repository, and the risk is in the relations between its files | `src/actaira/bundle.py:3` |
| D-140 | Agents, tools and MCP servers as versioned components with digests | `src/actaira/agentgov/__init__.py:3` |
| D-140b | The interface's agent routes call the functions the CLI calls, and a declaration gets a ceiling of its own rather than an artifact's | `src/actaira/web/server.py:576` |
| D-33b | The interface's policy routes decide with the engine's own `decide`, and the subject kind is stated by the operator rather than sniffed from the bytes | `src/actaira/web/server.py:662` |
| D-141 | Effects are consequences, not implementations, so a new transport needs no new entry | `src/actaira/agentgov/model.py:3` |
| D-142 | The capability rules take the agent as their subject, because the risk is the combination | `src/actaira/agentgov/capability.py:3` |
| D-143 | A declaration that says less than it means does not load | `src/actaira/agentgov/declare.py:3` |
| D-150 | Versioned schemas, and what a version number promises | `src/actaira/schemas/__init__.py:3` |
| D-160 | A bound applied after the read is not a bound | `src/actaira/io_budget.py:3` |
| D-170 | Chain validation against anchors the caller supplied, and what it still does not check | `src/actaira/attest/trust.py:3` |
| D-180 | One gate that refuses a release whose parts disagree with each other | `scripts/release_check.py:3` |
| D-181 | A gate whose only remedy is a manual edit gets routed around | `scripts/sync_readme_figures.py:3` |
| D-200 | A digest over the shape is not the identity of the weights | `src/actaira/bundle.py:59` |
| D-201 | A vocabulary that is not enumerated is one nobody can check | `src/actaira/agentgov/vocabulary.py:3` |
| D-202 | Relations are declared and validated, not inferred from matching strings | `src/actaira/agentgov/model.py:18` |
| D-203 | A digest that moved with nothing else reported is the worst output a change review can give | `src/actaira/agentgov/model.py:497` |
| D-204 | Which gaps refuse a declaration and which are reported as findings | `src/actaira/agentgov/declare.py:18` |
| D-205 | A mitigation with nowhere to be written down is one that gets waived | `src/actaira/agentgov/capability.py:95` |
| D-210 | Not "these are dangerous together" but "here is the route, and what breaks it" | `src/actaira/agentgov/paths.py:3` |
| D-211 | One shape for every subject a policy can decide about | `src/actaira/subject.py:3` |
| D-212 | A predicate reads what was observed, and absence is never falsehood | `src/actaira/policy/engine.py:483` |
| D-212a | A kind guard short-circuits, or a rule that does not apply makes the run inconclusive | `src/actaira/policy/engine.py:830` |
| D-213 | A manifest points at subjects; it does not restate what they say | `src/actaira/manifest.py:3` |
| D-214 | Separate identities do not close a route that carries text through one model's context | `src/actaira/agentgov/paths.py:303` |
| D-220 | Memory, because "what changed" cannot be answered from the bytes in front of you | `src/actaira/state/__init__.py:3` |
| D-221 | Forward-only numbered migrations, and a snapshot that is complete or absent | `src/actaira/state/store.py:3` |
| D-222 | A canonical snapshot, and an incomplete listing that never looks like an empty one | `src/actaira/state/snapshot.py:3` |
| D-223 | Five evidence states, and supersession bound to a digest rather than a name | `src/actaira/state/evidence.py:3` |
| D-224 | An edge exists because something said so, and an answer comes with its route | `src/actaira/state/graph.py:3` |
| D-225 | First observation, source drift, content drift and a failed listing are four things | `src/actaira/state/watch.py:3` |
| D-226 | What this environment accepts, kept apart from what cryptography proved | `src/actaira/trustpolicy.py:3` |
| D-227 | The state commands live apart, so the stateless ones stay stateless | `src/actaira/statecli.py:3` |
| D-228 | A receipt about a system, not about a list of files, with v1 still verifying | `src/actaira/receipt.py:113` |
| D-229 | Provenance survives the download, and half a listing cannot be a whole identity | `src/actaira/remote.py:3` |
| D-230 | A figure that is derivable is never maintained by hand, in prose either | `scripts/figures_contract.py:3` |
| D-231 | The version this tool tells a remote host is the one it is, not the one it was | `src/actaira/connectors/model.py:66` |
| D-232 | The index of published contracts is generated, because an index with a hole in it still looks complete | `scripts/contracts_doc.py:4` |
| D-233 | A published field that nothing can populate is a claim, so the writes were wired rather than the field removed | `src/actaira/cli.py:1587` |
| D-234 | The console blocks are output this tool produced, and the gate re-runs them under two hash seeds | `scripts/cli_transcripts.py:4` |
| D-235 | A reader that stops reading is a shell convention, not an error, and never a traceback over a success code | `src/actaira/cli.py:578` |
| D-236 | The published line count is a sum over a partition of the tree, checked, not a sum over a list somebody maintained | `scripts/figures.py:61` |
| D-237 | A line number in the note table is derived, because a reference wrong by four hundred lines is not stale, it is wrong | `scripts/design_notes.py:4` |
| D-238 | One spelling of "the last path segment", because three spellings put the producer's absolute path inside signed documents | `src/actaira/model.py:135` |
| D-239 | A build writes into `dist/` and is then opened and checked, because the one artifact nobody looks at is a package | `scripts/build_package.py:4` |
| D-240 | The default key path is resolved when a parser is built, not at import, so a host with no home does not break every command | `src/actaira/cli.py:68` |
| D-241 | What this tool prints is UTF-8 when it is redirected, because the locale is not something a report should depend on | `src/actaira/cli.py:608` |
| D-242 | Type checking is a ratchet: the exemption list is empty, a new error fails, and a stale exemption fails as loudly | `scripts/type_check.py:4` |
| D-243 | Recorded is not current, and the third answer is that this store cannot tell | `src/actaira/state/graph.py:379` |
| D-244 | The workspace is chosen when the server starts, and a read never creates or migrates one | `src/actaira/web/server.py:1989` |
| D-245 | A decision is history and whether it still applies is a separate, three-valued question | `src/actaira/state/decide.py:3` |
| D-246 | Evidence is filed only against an asset the workspace already records, because a basename is not an identity | `src/actaira/state/record.py:3` |
| D-247 | What a decision depended on is rows, not a sentence, and a decision with none is undetermined rather than fine | `src/actaira/state/store.py:187` |
| D-248 | Impact from a change starts at the artifact that changed, and two causes stay two causes | `src/actaira/state/graph.py:303` |
| D-249 | One observation's whole consequence is assembled once, in Python, and rendered twice | `src/actaira/state/change.py:3` |
| D-160b | The read budget bounds the read; the file bounds the allocation | `src/actaira/io_budget.py:53` |

D-25b is numbered as a continuation rather than as a note of its own because
it decides nothing on its own: it applies D-25's argument one layer up, where
two signed packages meet instead of two Merkle roots.

D-27b is numbered the same way and for the same reason. It decides nothing
about time-stamping; it resolves the ordering problem that D-27 creates inside
`write_package`, where the manifest has to be hashed before the token exists
and has to carry what the token said afterwards.

An earlier version of this index recorded D-17 and D-18 as being used twice,
for four unrelated notes. The code has since renumbered the corpus note to
D-19 and the harness note to D-20, and the table above follows the code.

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

## 3. Reporting

### 3.1 One `Finding` shape for every inspector (D-01)

**Decided.** Every inspector returns `Finding(rule_id, severity, location,
evidence)` (`src/actaira/model.py:56`). Nothing format-specific reaches the
report, BOM or attestation layers.

**Why.** The signing layer must stay format-agnostic for the attestation to be
reproducible. If the BOM builder had to know that safetensors findings look
different from pickle findings, adding a format would change the shape of a
signed payload.

**Rejected: format-specific report objects with richer typed fields.** They
would carry more structure, and consumers could destructure them without reading
`evidence` as a free-form dict.

**What is given up.** `evidence` is an untyped dictionary. Its keys are not part
of the stable interface, only `rule_id` is (D-07). A consumer that wants the
declared header length of a bad safetensors file has to know that
`ACT-STF-001` puts it under `declared_header_bytes`, and nothing enforces that.

### 3.2 Canonical JSON under every hash (D-03)

**Decided.** One function, `canonical_json`, is used everywhere a hash is
computed: sorted keys, compact separators, UTF-8, `ensure_ascii=False`,
`allow_nan=False` (`src/actaira/model.py:125`).

**Why.** Two runs over the same artifact must produce byte-identical output or
the hash chain means nothing. `allow_nan=False` matters specifically: Python's
default emits `NaN`, which is not valid JSON and which a third-party verifier
would reject or parse differently.

**Rejected: RFC 8785 JCS, or a full canonicalisation library.** JCS is the
standard and handles number formatting rules this does not.

**What is given up.** This canonicalisation is not JCS. It does not normalise
number representation beyond what `json.dumps` does, and it does not escape
Unicode, so a verifier reimplementing it must match the same flags. The harness
checks determinism empirically instead of proving it: 64 of 64 artifacts produce
byte-identical reports across two runs (`evals/harness.py:154`,
`evals/results.json`).

### 3.3 Rule identifiers are the interface, text is not (D-07)

**Decided.** `rule_id` is stable across versions and is what tests and the eval
harness assert on. Human-readable text lives in JSON catalogues
(`src/actaira/i18n/en.json`, `src/actaira/i18n/es.json`) loaded by
`src/actaira/i18n/catalog.py:20`. The CLI, the web UI and the reports render the
same rule from one source.

**Why.** Changing wording must never change a test outcome. Two languages that
drift apart is the normal fate of a second language, so a test asserts the key
sets are identical (`tests/test_i18n.py`). Verified in this container: 38 rule
keys in each catalogue, identical key sets for `ui`, `rules` and `rule_help`,
and no rule identifier appears in `src/` without a catalogue entry or the other
way round.

**Rejected: message strings in the code next to each finding.** One place to
look, no indirection, no catalogue to keep in sync.

**What is given up.** A finding's text is now one lookup away from the code that
raises it, and the catalogue can go stale in the other direction: a rule can
have an entry describing behaviour the code no longer has, and only reading both
would show it. The parity test catches missing keys, not wrong ones.
`rule_help` is deliberately partial: only 39 of the 80 rules carry a help string,
and the catalogue returns an empty string for the rest
(`src/actaira/i18n/catalog.py:43`).

### 3.4 CycloneDX 1.6, not SPDX (D-16)

**Decided.** The BOM is CycloneDX 1.6 with `type:
"machine-learning-model"` components and a `modelCard` object
(`src/actaira/bom/cyclonedx.py:24` and `src/actaira/bom/cyclonedx.py:46`).

**Why.** CycloneDX has a first-class machine learning model component type and a
model card object, so tensor counts, dtypes and quantisation have a place a
downstream tool already understands. SPDX 3.0 has an AI profile, but the tooling
around it is thinner today.

**Rejected: SPDX 3.0 with the AI profile.** SPDX is the ISO standard and is what
several procurement and compliance processes name explicitly.

**What is given up.** Anyone whose pipeline requires SPDX has to convert. There
is no converter here, and the conversion is not lossless: the `actaira:*`
properties (`src/actaira/bom/cyclonedx.py:61`) that carry the verdict, the
findings and the imported callables have no direct SPDX equivalent.

The rule that governs BOM content is separate from the format choice and is
stricter: every field emitted comes from bytes that were actually parsed.
Nothing is copied from a sidecar config, a model card or a filename, because a
BOM that repeats what the publisher claims adds no information to the supply
chain. Where a value is unknown it is omitted, never guessed
(`src/actaira/bom/cyclonedx.py:78`).

### 3.5 Disassembly shows the mechanism instead of asserting it (D-21)

**Decided.** `disassemble` walks the opcode stream and returns an ordered list
of steps rather than a list of findings
(`src/actaira/formats/disassembly.py:75`). Every step carries its offset, its
opcode, a shortened argument, a kind (`import`, `execute`, `extension`,
`persid`, `data`, `proto`, `stop`) and, for an import, the resolved callable
and the judgement the policy passed on it
(`src/actaira/formats/disassembly.py:32`).

**Why.** "This file imports `os.system`" is a claim the reader has to take on
trust. The opcode that does it, in order, with the callable resolved and the
verdict attached, is evidence they can check against `pickletools` themselves.
The module runs the same abstract interpretation the scanner runs: it imports
`_AbstractStack` and the opcode sets from `pickle_scan` rather than
reimplementing them (`src/actaira/formats/disassembly.py:20`), so the trace and
the verdict cannot disagree about what the stream does.

**Rejected: a second, simpler pass written for display.** It would be easier to
read, free to change, and would not have to track the scanner's stack and memo
model.

**What is given up.** Sharing the machinery means the disassembly inherits the
scanner's blind spots exactly: an operand the abstract stack cannot resolve is
`judgement = "unresolved"` in the trace for the same reason it is
`ACT-PKL-009` in the report, and a reader looking at the trace to understand a
false positive sees the same gap the scanner saw. The view is also bounded at
`MAX_STEPS = 4096` steps (`src/actaira/formats/disassembly.py:28`) while the
scanner's own budget is two million opcodes, so a long stream is truncated for
display while still being scanned in full; `total_opcodes` and `truncated`
carry that distinction into the payload
(`src/actaira/formats/disassembly.py:61`). A parse failure sets `truncated` and
records the exception text rather than raising
(`src/actaira/formats/disassembly.py:118`), because a stream that stops
disassembling halfway is still worth showing up to the point where it stopped.

One gap is worth stating rather than leaving to be discovered: no test module
covers `src/actaira/formats/disassembly.py`. What stands behind it is the
sharing above. The stack model, the operand resolution and the policy calls are
all pinned by `tests/test_pickle_scan.py` and `tests/test_policy.py` through
the scanner, but the mapping from those to `Step` objects is not asserted
anywhere.

## 4. Attestation

### 4.1 Ed25519 (D-12)

**Decided.** Ed25519 signatures over the SHA-256 of the manifest, via
`cryptography` (`src/actaira/attest/signing.py:58` and
`src/actaira/attest/package.py:181`).

**Why.** Deterministic, so there is no per-signature nonce to leak. Fixed 64
byte signatures. No curve parameters, no padding mode, no hash agility, so there
is nothing to configure wrong. One implementation, in the only runtime
dependency this project has.

Key identity is the SHA-256 of the DER `SubjectPublicKeyInfo`, not of the raw 32
bytes (`src/actaira/attest/signing.py:41`), so a fingerprint computed here
matches what `openssl` prints for the same key. An auditor can check the
fingerprint without installing Actaira.

**Rejected: RSA-PSS, or ECDSA P-256.** Both have far wider hardware and HSM
support, and both are what an existing enterprise PKI already issues.

**What is given up.** Ed25519 keys cannot come from most existing certificate
authorities or HSM fleets, so an organisation with a PKI has to run this key
material separately. There is no algorithm negotiation: the manifest records
`"algorithm": "ed25519"` (`src/actaira/attest/package.py:192`) and a verifier
that wants a different algorithm has nothing to fall back to. There is also no
key rotation, revocation or expiry in v1. The private key is written unencrypted
PKCS8 at mode 0600, created with `O_EXCL` so it is never briefly world-readable
(`src/actaira/attest/signing.py:88`), which is a real improvement over
chmod-after-write and still not a password-protected key.

### 4.2 Merkle tree per RFC 6962, with domain separation and without sorting pairs (D-11)

**Decided.** Leaves are `sha256(0x00 || data)`, internal nodes are `sha256(0x01
|| left || right)` (`src/actaira/attest/merkle.py:28`). Pair order is preserved
and every proof step carries an explicit `is_right` flag
(`src/actaira/attest/merkle.py:40`). An odd node at a level is promoted
unchanged (`src/actaira/attest/merkle.py:56`).

**Why, part one, domain separation.** Without the prefixes, an attacker who
controls a leaf can supply the concatenation of two node hashes as leaf data,
and that leaf's hash equals an internal node's hash. That is a second preimage
on the tree, and it is the attack RFC 6962 section 2.1 exists to prevent.

**Why, part two, pair order.** A common shortcut sorts each pair before hashing
so the proof does not need a side bit. That throws away the position of the
leaf, so a proof for index i also verifies for a different index with the same
sibling multiset.

**Rejected: the unprefixed, sorted-pair tree.** It is what most quick
implementations do. Proofs are smaller, since no side bit is needed, and the
verifier is three lines.

**What is given up.** Proofs carry one boolean per level, so they are slightly
larger, and the verifier has to honour the flag
(`src/actaira/attest/merkle.py:85`). Both properties are asserted by
`tests/test_merkle.py`, including a negative control that constructs the second
preimage collision against an unprefixed tree and shows it failing here.

The tree carries inclusion proofs and, since D-25, consistency proofs between
two roots as well. It is still not a transparency log: there is no public
append-only publication, no witness and no gossip, so the consistency proof
answers "does this root extend that root" and nothing about who else has seen
either root. Section 4.6 states what that buys and what it does not, and
section 4.8 is the separate question of when a root existed.

### 4.3 Hash-linked entries, and no claim about time (D-13)

**Decided.** Each entry commits to its predecessor. The entry hash is over a
`|`-joined preimage of version, index, previous hash, payload hash, timestamp
and subject digest (`src/actaira/attest/chain.py:57`). The separator cannot
appear in any of the fields, which are hex, ISO timestamps and integers, so two
different field splits cannot produce the same preimage. The timestamp is inside
the hash on purpose: an attestation whose time can be edited without breaking
the chain is not evidence of when anything happened.

**Why.** Removing or reordering an entry breaks every hash after it, and
`verify_chain` reports each break separately rather than returning one boolean
(`src/actaira/attest/chain.py:86`).

**Rejected: making the chain itself carry a claim about time.** Putting a
signed timestamp in every entry, or trusting the `timestamp` field as evidence
rather than as a label, would let the chain look like proof of when.

**What is given up, stated in the code rather than left to be discovered.** A
hash chain proves internal consistency, not freshness. Whoever holds the signing
key can rebuild the whole chain with different content and different timestamps.
The manifest therefore records `"time_anchor": "none"` unless a third party has
been asked, and the verifier emits a warning saying the chain proves ordering
and not when anything happened (`src/actaira/attest/verify.py:345`).

**What changed in 1.0.0.** Section 4.8 (D-27) adds an *optional* RFC 3161
anchor. It does not change anything in this note: an unanchored package is
still exactly what it was, and still says `time_anchor: "none"`. What the
anchor adds is that a package *can* now carry a third party's word about when
its manifest existed, and the verifier reports which of the two it used as
`time_evidence: "rfc3161"` or `"self_asserted"`.

### 4.4 The package is a plain zip with one signature (D-14)

**Decided.** The package is a zip. Every member is text or JSON. The signature
covers `manifest.json`, and the manifest covers every other member by SHA-256
(`src/actaira/attest/package.py:147`). One signature check plus n hash checks
authenticates the whole package.

**Why.** A third party opens it with tools they already have and reads it
without running Actaira at all. That is the point of an offline-verifiable
artifact.

**Rejected: sign each file separately.** Per-file signatures let a verifier
check a subset, and let files be added later without re-signing.

**What is given up.** With one signature the whole package must be re-signed to
change anything, and there is no partial verification. The docstring gives the
reason for preferring that: n signatures is n opportunities for a verifier to
check some and not others. The verifier also refuses undeclared members, so a
file smuggled into the zip is a problem rather than an ignored extra
(`src/actaira/attest/verify.py:205`).

### 4.5 Integrity and identity are different questions (D-15)

**Decided.** Verification answers two questions and refuses to blur them
(`src/actaira/attest/verify.py:3`):

- **integrity**: do the bytes match the manifest, is the chain self-consistent,
  does the Merkle root recompute, does the signature check out against the key
  in the package?
- **identity**: is the signing key one the verifier already trusts?

A package always carries its own public key, so integrity can always be checked.
The three trust states are `trusted`, `embedded_key_only` and `untrusted`
(`src/actaira/attest/verify.py:261`). Integrity-only verification returns
`embedded_key_only` with a loud warning; `--require-trust` turns that state into
a failure.

**Why.** Integrity proves the package was not edited after signing. It proves
nothing about who signed it, because an attacker who rewrites the package also
replaces the embedded key. A tool that prints a green tick for that case is
lying by omission.
`tests/test_package_verify.py:291` builds exactly that forgery: re-sign a
rewritten package with a fresh key, and every internal check passes. Only an
anchor the verifier already held catches it.

**Rejected: one boolean.** One boolean is what almost every verification CLI
returns, and it is what a CI job wants.

**What is given up.** The result has a shape a caller has to read: `ok`, plus
`trust_state`, plus a `checks` dict, plus `problems` and `warnings`
(`src/actaira/attest/verify.py:61`). A caller that only reads `ok` gets a
weaker guarantee than they think when no anchors were supplied.

The verifier also shares no code path with the writer beyond the hash helpers,
so a bug in package writing cannot be cancelled out by the same bug in reading.

### 4.6 Consistency proofs, so append-only is evidence rather than a promise (D-25)

**Decided.** The Merkle layer implements RFC 6962 section 2.1.2. Given the
leaves of a tree and an older size, `build_consistency_proof` emits the nodes
that demonstrate the newer tree extends the older one
(`src/actaira/attest/merkle.py:113`), and `verify_consistency` checks them
against a pair of roots the caller already holds
(`src/actaira/attest/merkle.py:154`). One layer up, `verify_extends` asks the
same question of two signed packages
(`src/actaira/attest/verify.py:95`), and the CLI exposes it as
`actaira verify <newer> --extends <older>` (`src/actaira/cli.py:83`).

**Why.** An inclusion proof answers "is this entry in that tree". It says
nothing about whether the tree grew honestly. Whoever holds the signing key can
publish root A today and root B tomorrow with an entry quietly removed or
rewritten, sign both, and every inclusion proof against B still verifies.
Without a consistency proof, append-only is a promise from the party with the
most to gain from breaking it. With one, a verifier who kept the old root
checks the promise themselves and needs to trust nobody.

**Rejected: compare entry counts and the shared prefix by re-reading both
packages.** For two packages on one disk that is simpler, obviously correct,
and needs no proof format at all.

**What is given up.** The proof is only worth its cost when the verifier no
longer has the older package, which is exactly the transparency-log setting
this project does not otherwise implement: there is no publication endpoint, no
witness cosigning and no gossip protocol, so in practice both packages usually
are on one disk and `verify_extends` reads both anyway
(`src/actaira/attest/verify.py:122`). What is bought is the property that the
check is a proof rather than a comparison, so the same code answers the
question when only a root was kept. The implementation cost is also real: the
prover and the verifier are the two hardest functions in the repository, and
the first version of the pair was wrong in a way that agreed with itself.
Section 8 records that.

The order of operations is a decision in its own right and is stated in the
docstring: both packages are verified for integrity before any proof is built
(`src/actaira/attest/verify.py:109`). A consistency proof over a forged package
proves that the attacker's history extends the attacker's history.

### 4.7 Resuming a chain, because a log you restart is not a log (D-26)

**Decided.** `chain.load_entries` rebuilds `Entry` objects from a package's
`entries.jsonl` (`src/actaira/attest/chain.py:112`), and
`actaira attest --continue <package>` appends to that chain instead of starting
a new one (`src/actaira/cli.py:74`, `src/actaira/cli.py:214`). The previous
package is verified first, and a package that does not verify is refused with
exit code 2 rather than resumed (`src/actaira/cli.py:215`).

**Why.** Before this, every `actaira attest` produced a fresh chain from
genesis. Two runs over overlapping artifacts shared no history, so a
consistency proof between them always failed. That is not a verifier bug and
not a proof-format bug: it is the append-only property being absent. D-25 is
unreachable without D-26.

Hashes are taken from the file as written and never recomputed
(`src/actaira/attest/chain.py:135`). Resuming must not be able to rewrite
history quietly, so `load_entries` is a reader, not a builder, and the
docstring says `verify_chain` is expected to run over the result before it is
trusted.

**Rejected: keep chain state in a local database or a dotfile next to the key.**
That is how most append-only tools do it, and it makes resuming automatic
rather than an explicit flag.

**What is given up.** Continuation is manual: the operator has to name the
previous package on every run, and a forgotten `--continue` silently produces a
chain that starts again, which verifies perfectly on its own and extends
nothing. Nothing in the package says "this should have continued something", so
the mistake is invisible until someone asks for a proof.
`tests/test_consistency.py:422` is the test that pins that behaviour rather
than wishing it away. There is also no merge: two chains that diverged cannot
be reconciled, because the entry hashes commit to a single linear order.

### 4.8 An RFC 3161 time anchor, optional and narrow (D-27, D-27b)

**Decided.** `actaira attest --tsa-url URL` asks a timestamp authority to stamp
the manifest and stores the token in the package as `manifest.tsr`
(`src/actaira/attest/timestamp.py:3`). The manifest then reads
`time_anchor: "rfc3161"` and carries the authority's URL, the genTime and the
token serial. Without the flag nothing at all changes: no request is made, no
member is added, and the manifest still reads `time_anchor: "none"`. The
request is built as DER by hand and the response is parsed and checked in the
same module.

**Why by hand.** The alternatives were a dependency (`rfc3161ng`, `asn1crypto`)
or shelling out to `openssl ts`. A tool whose subject is supply-chain
provenance does not answer "why is this dependency here?" with "to check a
timestamp", and a subprocess makes the check depend on which OpenSSL happens to
be installed, which is the opposite of an offline reproducible verifier. The
DER involved is small and fully specified: a request is four fields, a response
is a status plus a CMS `SignedData` whose payload is a nine-field `TSTInfo`.

**Rejected: publication to a transparency log.** A public append-only log with
witnesses and gossip is strictly stronger, because it makes the log's history
visible to people other than its owner. It also requires infrastructure this
project does not have and cannot ask a user to run.

**What is given up.** Three separate claims, kept apart on purpose, in the same
spirit as D-15:

| claim | checked? | how |
|---|---|---|
| the token covers *this* manifest | always, offline | the imprint is compared with the manifest's own digest; a mismatch fails the package |
| the token was not edited after issuance | when the algorithms are known | the CMS signature is checked against the certificate the token carries: `signature_state = "embedded_cert_only"` |
| the authority is one you accept | **never** | Actaira ships no trust store, so `tsa_chain` stays `"not_verified"` and says so in a warning |

The parser is deliberately narrow: definite-length DER only, no
high-tag-number forms, and only the algorithms a TSA actually uses. A
conforming-but-exotic token is reported as unread rather than guessed at, which
is the safe direction. Two further offline checks are made and reported as
warnings rather than failures: whether the signer's certificate carries the
`timeStamping` extended key usage RFC 3161 requires, and whether the genTime
falls inside that certificate's validity window. What is *not* checked, and is
worth naming because a stricter verifier would: the ESS signing-certificate
attribute is not validated, because the signer is already located by issuer and
serial and the signature is checked against that certificate's key.

**D-27b, the ordering problem.** The token is issued over the manifest's
digest, and the manifest has to record what the token said. Those two chase
each other. The knot is cut by stamping the manifest with its anchor field held
at `"pending"` and then completing it
(`src/actaira/attest/package.py:76`):

```
subject = canonical_json(manifest | {"time_anchor": "pending"} - "timestamp")
token   = TSA(sha256(subject))
manifest["time_anchor"] = "rfc3161"
manifest["timestamp"]   = {gen_time, serial, tsa_name, tsa_url, over: ...}
```

The verifier applies the same transformation to recover the exact bytes the TSA
saw. Nothing is lost by stamping the pending form: it already commits to the
Merkle root, the head hash, every file digest and the signing key. The
completed manifest is what the Ed25519 signature covers, so the genTime and
serial written into it cannot be edited either. `manifest.tsr` is therefore not
listed in the manifest's `files` - it cannot be, for the same reason
`manifest.sig` is not - and the two are cross-checked instead: a swapped token
fails against the serial the manifest declares, and a swapped manifest fails
against the signature.

The property this buys is the one worth stating plainly: whoever holds the
signing key can re-sign an edited manifest, and it will verify. They cannot
re-date it. `tests/test_attest_anchor.py` pins exactly that, by editing
`created`, re-signing correctly, and requiring the package to fail.

### 4.9 Several keys, with validity windows and a status (D-28)

**Decided.** A keyring holds several keys
(`src/actaira/attest/keyring.py:3`). Each carries a status - `active`,
`retired` or `revoked` - and the window it was allowed to sign in.
`actaira keygen --rotate` retires the current key, generates a new one, and
keeps the old public key in the ring; the old private key is archived beside
the new one rather than deleted. `verify` accepts a signature from a retired
key when the moment of signing falls inside that key's window, and refuses one
from a revoked key at any moment whatsoever
(`src/actaira/attest/keyring.py:172`).

**Why the two states differ.** Retirement is routine: the key stopped being
used, and what it signed before it stopped is still good. Revocation is the
claim that the key was in the wrong hands, and the honest reading of that is
that nothing it ever signed can be relied on, including what it signed before
anybody noticed.

**Why this needed D-27 first.** A validity window is only as good as the
evidence for when signing happened. With an RFC 3161 anchor the moment is a
third party's; without one it is the package's own `created` field and the
entry timestamps under it, which are covered by the signature and the Merkle
root but were chosen by whoever holds the key. The verifier reports which it
used (`time_evidence`), and the warning for a retired key names the difference
in words rather than leaving it to be inferred.

**Rejected: expiring keys on the verifier's clock.** Refusing any signature
from a key whose window has closed *relative to now* would be simpler and would
be wrong: it invalidates history for the crime of time passing, which is the
exact failure this note exists to fix.

**What is given up.** There is no revocation distribution: no CRL, no OCSP, no
published feed. Publishing a keyring is the operator's job. And status is only
binding when it comes from a keyring the verifier supplied
(`--trusted-keyring`), because a package rewritten by an attacker rewrites the
keyring inside it too. The copy inside the package is still consulted, because
it can only ever make the verdict stricter: a package that admits its own key
was revoked is telling the truth against its own interest.

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
