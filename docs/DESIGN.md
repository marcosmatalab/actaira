# Seamark: design

Seamark inspects machine learning artifacts without loading or executing them,
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

Sections 2, 5, 6, 7, 8 and 9 were moved to
[`archive/DESIGN-scanner.md`](archive/DESIGN-scanner.md) in phase A.1. They argue
the model scanner: the artifact readers, the web interface, the read budgets, the
evaluation corpus, and the defects found while building them. None of that code
is in this tree. The numbering is left with its gaps rather than closed up,
because every cross-reference between these sections was written against the old
numbers and renumbering would have broken all of them silently.

Two subsections below are in the same position and stayed only because they sit
inside a section that is otherwise live: **3.4** (CycloneDX ML-BOM) and **3.5**
(disassembly) argue code that went to tag `v2.3.0` at 3.0.0.

## 1. Index of design notes

| Note | Subject | Location |
|---|---|---|
| D-01 | One `Finding` shape for every inspector | `src/seamark/model.py:8` |
| D-03 | Canonical JSON under every hash | `src/seamark/model.py:6` |
| D-04 | A state that means "I could not tell" is a result, not an error | `src/seamark/surface/__init__.py:33` |
| D-07 | Rule identifiers are the stable interface | `src/seamark/i18n/catalog.py:3` |
| D-11 | RFC 6962 Merkle tree | `src/seamark/attest/merkle.py:3` |
| D-12 | Ed25519 | `src/seamark/attest/signing.py:3` |
| D-13 | Hash-linked entries, and no claim about time on their own | `src/seamark/attest/chain.py:3` |
| D-14 | Package is a plain zip, one signature | `src/seamark/attest/package.py:3` |
| D-15 | Integrity and identity kept separate | `src/seamark/attest/verify.py:3` |
| D-25 | Consistency proofs, so append-only is evidence | `src/seamark/attest/merkle.py:127` |
| D-25b | The same question at the package boundary | `src/seamark/attest/verify.py:191` |
| D-26 | Resuming a chain, because a log you restart is not a log | `src/seamark/attest/chain.py:178` |
| D-27 | RFC 3161 time anchoring, optional and narrow | `src/seamark/attest/timestamp.py:3` |
| D-27b | Stamping the manifest before the manifest is finished | `src/seamark/attest/package.py:11` |
| D-28 | Several keys, with validity windows and a status | `src/seamark/attest/keyring.py:3` |
| D-50 | DSSE and in-toto, so the report is speakable by other tools | `src/seamark/attest/dsse.py:4` |
| D-51 | PAE, and the dangling-file class the envelope removes | `src/seamark/attest/dsse.py:33` |
| D-150 | Versioned schemas, and what a version number promises | `src/seamark/schemas/__init__.py:3` |
| D-170 | Chain validation against anchors the caller supplied, and what it still does not check | `src/seamark/attest/trust.py:3` |
| D-180 | One gate that refuses a release whose parts disagree with each other | `scripts/release_check.py:3` |
| D-181 | A gate whose only remedy is a manual edit gets routed around | `scripts/sync_readme_figures.py:3` |
| D-230 | A figure that is derivable is never maintained by hand, in prose either | `scripts/figures_contract.py:3` |
| D-232 | The index of published contracts is generated, because an index with a hole in it still looks complete | `scripts/contracts_doc.py:4` |
| D-234 | The console blocks are output this tool produced, and the gate re-runs them under two hash seeds | `scripts/cli_transcripts.py:4` |
| D-235 | A reader that stops reading is a shell convention, not an error, and never a traceback over a success code | `src/seamark/cli.py:1067` |
| D-236 | The published line count is a sum over a partition of the tree, checked, not a sum over a list somebody maintained | `scripts/figures.py:63` |
| D-237 | A line number in the note table is derived, because a reference wrong by four hundred lines is not stale, it is wrong | `scripts/design_notes.py:4` |
| D-239 | A build writes into `dist/` and is then opened and checked, because the one artifact nobody looks at is a package | `scripts/build_package.py:4` |
| D-240 | The default key path is resolved when a parser is built, not at import, so a host with no home does not break every command | `src/seamark/cli.py:78` |
| D-241 | What this tool prints is UTF-8 when it is redirected, because the locale is not something a report should depend on | `src/seamark/cli.py:1034` |
| D-242 | Type checking is a ratchet: the exemption list is empty, a new error fails, and a stale exemption fails as loudly | `scripts/type_check.py:4` |
| D-250 | One trace document for every source and every level, and failure is its default | `src/seamark/trace/model.py:3` |
| D-251 | The capture level is not a label on the record, it is what decides what the record may claim | `src/seamark/trace/__init__.py:3` |
| D-252 | A digest has no false negatives and a secret filter does, so the arguments do not travel | `src/seamark/trace/redact.py:3` |
| D-253 | The real shape of a Claude Code transcript, written down because it is somebody else's format and it moves | `src/seamark/trace/claude_code.py:3` |
| D-254 | Completeness is the proxy's invariant, kept above both transports so neither can forget it | `src/seamark/proxy/__init__.py:3` |
| D-255 | A server the rewriter cannot interpose on is declared, never silently passed through | `src/seamark/proxy/session.py:3` |
| D-256 | A tool is announced only if it runs, because a name in `tools/list` is read as capability and nothing downstream can unread it | `src/seamark/mcp.py:3` |
| D-257 | A digest covers the arguments; the sentence about a failure is the other half of the boundary | `src/seamark/trace/redact.py:76` |
| D-258 | A hole cites the identity of the event it follows, and says so when there is none, rather than a line number | `src/seamark/trace/model.py:171` |
| D-259 | The transcript format records no end of session, so an L0 trace is never complete and says why | `src/seamark/trace/claude_code.py:207` |
| D-260 | One call is one event however many times the source records it, and a disagreement is a hole rather than a choice | `src/seamark/trace/claude_code.py:289` |
| D-261 | What the agent was configured with, against what was observed, and the answer fails closed | `src/seamark/proxy/session.py:321` |
| D-262 | A session id is a string out of somebody's file, so it is sanitised and a collision is numbered, never overwritten | `src/seamark/cli.py:799` |
| D-263 | A reference computed as an unsalted digest of a guessable name is an encoding, not a redaction | `src/seamark/trace/redact.py:127` |
| D-264 | MCP 2026-07-28 removed the session, so every message declares itself and a missing declaration is a hole | `src/seamark/proxy/protocol.py:3` |
| D-265 | Interposing on HTTP for real, and refusing an answer whose JSON-RPC id is somebody else's | `src/seamark/proxy/http.py:14` |
| D-266 | One writer at a time, records that name their own run, and an order taken from the records rather than from the filenames | `src/seamark/proxy/__init__.py:83` |
| D-267 | A network guard that only runs when somebody remembers it is not a guard, and it needs a test that it still bites | `tests/netguard.py:3` |
| D-268 | Every field of the published document is classified by who writes its value, and a third-party value is referenced unless the table says why not | `src/seamark/trace/provenance.py:3` |
| D-269 | The subject is what an agent CAN do, not what one did, and the three products that were tried against that question first | `docs/PRINCIPLES.md:33` |
| D-270 | Three resolution states for what a FILE permits, kept apart from the four capture levels for what a RUN did | `src/seamark/surface/__init__.py:3` |
| D-271 | Every read of somebody else's repository is bounded before it is attempted, and every path is resolved before it is opened | `src/seamark/surface/disk.py:15` |
| D-272 | Finding the script a hook names is a parse, and a shape it cannot parse costs a stated gap rather than a guess | `src/seamark/surface/disk.py:301` |
| D-273 | Every merge decision is a cited row, anchored to a digest of the page because these pages publish no version | `src/seamark/surface/merge.py:3` |
| D-274 | Rule packs are TOML read with `tomllib`, because a rule has to carry its own argument and JSON has no comments | `src/seamark/surface/rules.py:3` |
| D-275 | A rule's needed facts are derived from its clauses, so INDETERMINATE happens without anybody remembering to check | `src/seamark/surface/rules.py:15` |
| D-276 | Exit code 3 comes back, because a pipeline branching on 1 alone reads "I could not tell" as a clean run | `src/seamark/cli.py:58` |
| D-277 | The agent's version is never obtained by running the agent, because asking the audited tool what it is is trusting it | `src/seamark/cli.py:372` |
| D-278 | The rule page is generated, so it cannot be the stale fourth copy of what a rule says | `scripts/rules_doc.py:4` |
| D-279 | A path that is absolute on another platform is absolute here too, or the same repository gets two answers on two machines | `src/seamark/surface/disk.py:143` |
| D-280 | JSONC forgives comments and trailing commas and nothing else, because a permissive parser is the fail-open shape of a configuration reader | `src/seamark/surface/jsonc.py:9` |
| D-281 | Frontmatter is read as a named YAML subset that refuses the rest, rather than grepped for the keys a rule wants | `src/seamark/surface/miniyaml.py:9` |
| D-282 | A `folderOpen` task is the phase's canonical declared-versus-effective case, and the documented default is not the answer when nobody read the scope that sets it | `src/seamark/surface/vscode.py:8` |
| D-283 | `initializeCommand` is read separately from the other five because it runs on the host, outside the containment that is the point of a container | `src/seamark/surface/devcontainer.py:3` |
| D-284 | Codex's project layer waits on a trust level that lives in the user's file, so a repository hook is declared until that file is read | `src/seamark/surface/codex.py:6` |
| D-285 | Cursor's team level is reported INDETERMINATE on every run, because a dashboard-synced hook is outside the filesystem by design | `src/seamark/surface/cursor.py:3` |
| D-286 | Each vendor carries its own precedence ladder, because Gemini's inverts Claude Code's and one table would have to invent a winner | `src/seamark/surface/gemini.py:3` |
| D-287 | Instruction files are read for structure and literals only, because classifying what free text means is judging intention | `src/seamark/surface/instructions.py:3` |
| D-288 | A repository's surface is the union of per-vendor surfaces and never a merge, so two vendors running one command stay two capabilities | `src/seamark/surface/merge.py:312` |
| D-289 | `check` is exposed over MCP only once it reads more than one vendor, because `tools/list` is read as capability and cannot be corrected later | `src/seamark/mcp.py:80` |
| D-290 | A capability name is a literal in our source, never assembled from the file being read, or the audited repository writes Seamark's vocabulary | `src/seamark/surface/claude_code.py:91` |
| D-291 | A setting in a vendor's superseded spelling is read and left INDETERMINATE, because inventing the migration and inventing its removal are both inventions | `src/seamark/surface/gemini.py:62` |
| D-292 | Every capability this tree emits is named by a rule or excused in writing, because a capability no rule can fire on is a line nobody can act on | `src/seamark/surface/resolve.py:482` |
| D-293 | A ref's tree is materialised whole rather than filtered to the paths the readers know, or `diff` and `check` answer about two different trees | `src/seamark/surface/diff.py:21` |
| D-294 | Two refs are read with `ls-tree` and `cat-file` and never checked out, because a checkout writes in the operator's tree and runs their hooks | `src/seamark/surface/diff.py:9` |
| D-295 | Widened and narrowed exist only where the fact's own name states which value is the wider one; everything else is CHANGED with both digests | `src/seamark/surface/diff.py:370` |
| D-296 | A seal carries one digest per facts mapping rather than one per fact, because a per-fact digest is a dictionary attack somebody else already has the words for | `src/seamark/attest/seal.py:14` |
| D-297 | The HTML report loads nothing over the network, so a security report cannot phone home while it is being read | `src/seamark/report/html.py:7` |
| D-298 | A SARIF level is a transliteration of one rule author's label, one result at a time, and never a fold across findings | `src/seamark/report/sarif.py:10` |
| D-299 | `diff` exits non-zero on what ARRIVED, not on everything in the repository, because a finding that was already there is `check`'s to report | `src/seamark/surface/diff.py:633` |
| D-300 | The bounded disk primitives live under their own name, because six readers for other vendors were importing them from a manufacturer's module | `src/seamark/surface/disk.py:3` |
| D-301 | Every claim a README makes about a command, a flag or an exit code resolves against the parser, and a claim block that names no command is refused | `scripts/release_check.py:699` |
| D-302 | The proxy sends the agent nothing when the server sent nothing, so a client with no deadline of its own waits, because fabricating a reply would put a message the server never sent into the agent's input | `src/seamark/proxy/stdio.py:373` |

Thirty-nine rows left this table in phase A, with the modules they argued
about: every note numbered for `coverage.py`, `miniyaml.py`, `io_budget.py`,
`manifest.py`, `subject.py`, `receipt.py`, `policy/`, `conformance/`, `report/`
and `state/`. A note whose file is not in the tree is a reference a reader
follows into nothing, and this table's whole promise - every note names the file
and line that implements it - is kept by removing the row rather than by
softening the promise.

The two worth rereading are re-argued in section 10 in full: D-223 on the five
evidence states, and D-245 on a decision as a historical fact. The rest are
recoverable with their code from tag `v2.3.0`, where the docstring
that argues each one sits on the line it argues about.

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

## 3. Reporting

### 3.1 One `Finding` shape for every inspector (D-01)

**Decided.** Every inspector returns `Finding(rule_id, severity, location,
evidence)` (`src/seamark/model.py:56`). Nothing format-specific reaches the
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
`allow_nan=False` (`src/seamark/model.py:125`).

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
(`src/seamark/i18n/en.json`, `src/seamark/i18n/es.json`) loaded by
`src/seamark/i18n/catalog.py:20`. The CLI, the web UI and the reports render the
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
(`src/seamark/i18n/catalog.py:43`).

### 3.4 CycloneDX 1.6, not SPDX (D-16)

**Decided.** The BOM is CycloneDX 1.6 with `type:
"machine-learning-model"` components and a `modelCard` object
(`src/seamark/bom/cyclonedx.py:24` and `src/seamark/bom/cyclonedx.py:46`).

**Why.** CycloneDX has a first-class machine learning model component type and a
model card object, so tensor counts, dtypes and quantisation have a place a
downstream tool already understands. SPDX 3.0 has an AI profile, but the tooling
around it is thinner today.

**Rejected: SPDX 3.0 with the AI profile.** SPDX is the ISO standard and is what
several procurement and compliance processes name explicitly.

**What is given up.** Anyone whose pipeline requires SPDX has to convert. There
is no converter here, and the conversion is not lossless: the `seamark:*`
properties (`src/seamark/bom/cyclonedx.py:61`) that carry the verdict, the
findings and the imported callables have no direct SPDX equivalent.

The rule that governs BOM content is separate from the format choice and is
stricter: every field emitted comes from bytes that were actually parsed.
Nothing is copied from a sidecar config, a model card or a filename, because a
BOM that repeats what the publisher claims adds no information to the supply
chain. Where a value is unknown it is omitted, never guessed
(`src/seamark/bom/cyclonedx.py:78`).

### 3.5 Disassembly shows the mechanism instead of asserting it (D-21)

**Decided.** `disassemble` walks the opcode stream and returns an ordered list
of steps rather than a list of findings
(`src/seamark/formats/disassembly.py:75`). Every step carries its offset, its
opcode, a shortened argument, a kind (`import`, `execute`, `extension`,
`persid`, `data`, `proto`, `stop`) and, for an import, the resolved callable
and the judgement the policy passed on it
(`src/seamark/formats/disassembly.py:32`).

**Why.** "This file imports `os.system`" is a claim the reader has to take on
trust. The opcode that does it, in order, with the callable resolved and the
verdict attached, is evidence they can check against `pickletools` themselves.
The module runs the same abstract interpretation the scanner runs: it imports
`_AbstractStack` and the opcode sets from `pickle_scan` rather than
reimplementing them (`src/seamark/formats/disassembly.py:20`), so the trace and
the verdict cannot disagree about what the stream does.

**Rejected: a second, simpler pass written for display.** It would be easier to
read, free to change, and would not have to track the scanner's stack and memo
model.

**What is given up.** Sharing the machinery means the disassembly inherits the
scanner's blind spots exactly: an operand the abstract stack cannot resolve is
`judgement = "unresolved"` in the trace for the same reason it is
`ACT-PKL-009` in the report, and a reader looking at the trace to understand a
false positive sees the same gap the scanner saw. The view is also bounded at
`MAX_STEPS = 4096` steps (`src/seamark/formats/disassembly.py:28`) while the
scanner's own budget is two million opcodes, so a long stream is truncated for
display while still being scanned in full; `total_opcodes` and `truncated`
carry that distinction into the payload
(`src/seamark/formats/disassembly.py:61`). A parse failure sets `truncated` and
records the exception text rather than raising
(`src/seamark/formats/disassembly.py:118`), because a stream that stops
disassembling halfway is still worth showing up to the point where it stopped.

One gap is worth stating rather than leaving to be discovered: no test module
covers `src/seamark/formats/disassembly.py`. What stands behind it is the
sharing above. The stack model, the operand resolution and the policy calls are
all pinned by `tests/test_pickle_scan.py` and `tests/test_policy.py` through
the scanner, but the mapping from those to `Step` objects is not asserted
anywhere.

## 4. Attestation

### 4.1 Ed25519 (D-12)

**Decided.** Ed25519 signatures over the SHA-256 of the manifest, via
`cryptography` (`src/seamark/attest/signing.py:58` and
`src/seamark/attest/package.py:181`).

**Why.** Deterministic, so there is no per-signature nonce to leak. Fixed 64
byte signatures. No curve parameters, no padding mode, no hash agility, so there
is nothing to configure wrong. One implementation, in the only runtime
dependency this project has.

Key identity is the SHA-256 of the DER `SubjectPublicKeyInfo`, not of the raw 32
bytes (`src/seamark/attest/signing.py:41`), so a fingerprint computed here
matches what `openssl` prints for the same key. An auditor can check the
fingerprint without installing Seamark.

**Rejected: RSA-PSS, or ECDSA P-256.** Both have far wider hardware and HSM
support, and both are what an existing enterprise PKI already issues.

**What is given up.** Ed25519 keys cannot come from most existing certificate
authorities or HSM fleets, so an organisation with a PKI has to run this key
material separately. There is no algorithm negotiation: the manifest records
`"algorithm": "ed25519"` (`src/seamark/attest/package.py:192`) and a verifier
that wants a different algorithm has nothing to fall back to. There is also no
key rotation, revocation or expiry in v1. The private key is written unencrypted
PKCS8 at mode 0600, created with `O_EXCL` so it is never briefly world-readable
(`src/seamark/attest/signing.py:88`), which is a real improvement over
chmod-after-write and still not a password-protected key.

### 4.2 Merkle tree per RFC 6962, with domain separation and without sorting pairs (D-11)

**Decided.** Leaves are `sha256(0x00 || data)`, internal nodes are `sha256(0x01
|| left || right)` (`src/seamark/attest/merkle.py:28`). Pair order is preserved
and every proof step carries an explicit `is_right` flag
(`src/seamark/attest/merkle.py:40`). An odd node at a level is promoted
unchanged (`src/seamark/attest/merkle.py:56`).

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
(`src/seamark/attest/merkle.py:85`). Both properties are asserted by
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
and subject digest (`src/seamark/attest/chain.py:57`). The separator cannot
appear in any of the fields, which are hex, ISO timestamps and integers, so two
different field splits cannot produce the same preimage. The timestamp is inside
the hash on purpose: an attestation whose time can be edited without breaking
the chain is not evidence of when anything happened.

**Why.** Removing or reordering an entry breaks every hash after it, and
`verify_chain` reports each break separately rather than returning one boolean
(`src/seamark/attest/chain.py:86`).

**Rejected: making the chain itself carry a claim about time.** Putting a
signed timestamp in every entry, or trusting the `timestamp` field as evidence
rather than as a label, would let the chain look like proof of when.

**What is given up, stated in the code rather than left to be discovered.** A
hash chain proves internal consistency, not freshness. Whoever holds the signing
key can rebuild the whole chain with different content and different timestamps.
The manifest therefore records `"time_anchor": "none"` unless a third party has
been asked, and the verifier emits a warning saying the chain proves ordering
and not when anything happened (`src/seamark/attest/verify.py:345`).

**What changed in 1.0.0.** Section 4.8 (D-27) adds an *optional* RFC 3161
anchor. It does not change anything in this note: an unanchored package is
still exactly what it was, and still says `time_anchor: "none"`. What the
anchor adds is that a package *can* now carry a third party's word about when
its manifest existed, and the verifier reports which of the two it used as
`time_evidence: "rfc3161"` or `"self_asserted"`.

### 4.4 The package is a plain zip with one signature (D-14)

**Decided.** The package is a zip. Every member is text or JSON. The signature
covers `manifest.json`, and the manifest covers every other member by SHA-256
(`src/seamark/attest/package.py:147`). One signature check plus n hash checks
authenticates the whole package.

**Why.** A third party opens it with tools they already have and reads it
without running Seamark at all. That is the point of an offline-verifiable
artifact.

**Rejected: sign each file separately.** Per-file signatures let a verifier
check a subset, and let files be added later without re-signing.

**What is given up.** With one signature the whole package must be re-signed to
change anything, and there is no partial verification. The docstring gives the
reason for preferring that: n signatures is n opportunities for a verifier to
check some and not others. The verifier also refuses undeclared members, so a
file smuggled into the zip is a problem rather than an ignored extra
(`src/seamark/attest/verify.py:205`).

### 4.5 Integrity and identity are different questions (D-15)

**Decided.** Verification answers two questions and refuses to blur them
(`src/seamark/attest/verify.py:3`):

- **integrity**: do the bytes match the manifest, is the chain self-consistent,
  does the Merkle root recompute, does the signature check out against the key
  in the package?
- **identity**: is the signing key one the verifier already trusts?

A package always carries its own public key, so integrity can always be checked.
The three trust states are `trusted`, `embedded_key_only` and `untrusted`
(`src/seamark/attest/verify.py:261`). Integrity-only verification returns
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
(`src/seamark/attest/verify.py:61`). A caller that only reads `ok` gets a
weaker guarantee than they think when no anchors were supplied.

The verifier also shares no code path with the writer beyond the hash helpers,
so a bug in package writing cannot be cancelled out by the same bug in reading.

### 4.6 Consistency proofs, so append-only is evidence rather than a promise (D-25)

**Decided.** The Merkle layer implements RFC 6962 section 2.1.2. Given the
leaves of a tree and an older size, `build_consistency_proof` emits the nodes
that demonstrate the newer tree extends the older one
(`src/seamark/attest/merkle.py:113`), and `verify_consistency` checks them
against a pair of roots the caller already holds
(`src/seamark/attest/merkle.py:154`). One layer up, `verify_extends` asks the
same question of two signed packages
(`src/seamark/attest/verify.py:95`), and the CLI exposes it as
`seamark verify <newer> --extends <older>` (`src/seamark/cli.py:83`).

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
(`src/seamark/attest/verify.py:122`). What is bought is the property that the
check is a proof rather than a comparison, so the same code answers the
question when only a root was kept. The implementation cost is also real: the
prover and the verifier are the two hardest functions in the repository, and
the first version of the pair was wrong in a way that agreed with itself.
Section 8 records that.

The order of operations is a decision in its own right and is stated in the
docstring: both packages are verified for integrity before any proof is built
(`src/seamark/attest/verify.py:109`). A consistency proof over a forged package
proves that the attacker's history extends the attacker's history.

### 4.7 Resuming a chain, because a log you restart is not a log (D-26)

**Decided.** `chain.load_entries` rebuilds `Entry` objects from a package's
`entries.jsonl` (`src/seamark/attest/chain.py:112`), and
`seamark attest --continue <package>` appends to that chain instead of starting
a new one (`src/seamark/cli.py:74`, `src/seamark/cli.py:214`). The previous
package is verified first, and a package that does not verify is refused with
exit code 2 rather than resumed (`src/seamark/cli.py:215`).

**Why.** Before this, every `seamark attest` produced a fresh chain from
genesis. Two runs over overlapping artifacts shared no history, so a
consistency proof between them always failed. That is not a verifier bug and
not a proof-format bug: it is the append-only property being absent. D-25 is
unreachable without D-26.

Hashes are taken from the file as written and never recomputed
(`src/seamark/attest/chain.py:135`). Resuming must not be able to rewrite
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

**Decided.** `seamark attest --tsa-url URL` asks a timestamp authority to stamp
the manifest and stores the token in the package as `manifest.tsr`
(`src/seamark/attest/timestamp.py:3`). The manifest then reads
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
| the authority is one you accept | **never** | Seamark ships no trust store, so `tsa_chain` stays `"not_verified"` and says so in a warning |

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
(`src/seamark/attest/package.py:76`):

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
(`src/seamark/attest/keyring.py:3`). Each carries a status - `active`,
`retired` or `revoked` - and the window it was allowed to sign in.
`seamark keygen --rotate` retires the current key, generates a new one, and
keeps the old public key in the ring; the old private key is archived beside
the new one rather than deleted. `verify` accepts a signature from a retired
key when the moment of signing falls inside that key's window, and refuses one
from a revoked key at any moment whatsoever
(`src/seamark/attest/keyring.py:172`).

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

## 10. Removed in phase A, and the reasoning kept

Phase A applied one rule to the tree: every module of the package has to be
reachable from the CLI or from the MCP server, and what is not, goes. Around
8 700 lines went. The history keeps the code and tag `v2.3.0` is
intact, so a `git show` brings any of it back.

What a `git show` does not bring back is why a thing was shaped the way it
was, once the person who argued it has moved on. `state/` is the case that
matters: its argument cannot be reconstructed by reading its SQL, and later
phases will want it. So the argument is here, in its own words where they were
well put, and the code is one command away.

**Its intended consumer now has a name and a phase: currency, in phase P1.** An
approval is granted over a surface digest, and the question "does this approval
still describe what is there" is `decide.py`'s `CURRENT` /
`REQUIRES_REASSESSMENT` / `UNDETERMINED` asked about a configuration instead of
about a model artifact. Section 11 argues the change of subject; this section is
the half of it that was already written.

Recover the code from `v2.3.0:src/actaira/state/`.

### 10.1 Five evidence states, and supersession bound to a digest (D-223)

`evidence_max_age_days` was a predicate over a date the caller passed in. That
is enough to ask "was this observed recently" and cannot answer any of the
questions that follow it: which observation was this, what replaced it, what
stopped being true when the model changed, and which decisions rested on
something that has since been revoked. Those need evidence to be an object
rather than a timestamp.

The five states are the ones that actually occur, and they are kept apart
because they call for different actions:

| State | What it means |
|---|---|
| `VALID` | still stands for exactly the subject it was taken about |
| `STALE` | older than the freshness the policy requires — re-observe |
| `SUPERSEDED` | a later observation of the same claim about the same subject |
| `REVOKED` | the key, source or attestation behind it was withdrawn |
| `UNTRUSTED` | intact, and this environment's trust policy does not accept it |

**`STALE` and `SUPERSEDED` are the pair most tools merge**, and merging them
loses the distinction between *nobody has looked lately* and *somebody looked
and this is not the current answer*. The first is a gap in attention and the
remedy is to re-observe. The second is a fact about the world and re-observing
changes nothing — the answer already moved.

**`REVOKED` and `UNTRUSTED` are the other pair.** The first is a fact about the
world: the key was withdrawn, and it is withdrawn for everyone. The second is a
decision made *here*: this environment's trust policy does not accept it, and
another environment may accept the same evidence. D-170's separation of
signature from trust runs all the way through to this distinction.

Only `VALID` counts. The other four are not degrees of confidence — they are
four different reasons the evidence has stopped answering the question, and a
policy that accepted "stale" as nearly-valid would be a policy with no
freshness requirement at all.

**The rule that shapes every transition: evidence is superseded by the digest
it was taken about, never by its subject's name.** A new scan of a model that
did not change supersedes nothing. A scan of a model that did change supersedes
only the evidence bound to the old digest, so evidence about a sibling artifact
nobody touched stays valid. That is the difference between an invalidation an
operator can act on and a wall of red. Keyed on the name instead, one touched
file invalidates every record that shares a basename, and an operator who
cannot tell which of four hundred red rows matters treats all four hundred as
noise — which is the same as having no invalidation.

### 10.2 A decision is history; whether it still applies is another question (D-245)

A policy decision is a historical fact: on a date, under a policy with a
digest, from named inputs, this tool answered ALLOW, DENY or REVIEW. **That
fact never changes**, and nothing in `state/decide.py` writes to the
`decisions` table. An ALLOW recorded in March is still an ALLOW in September
even when every artifact it was about has been replaced, because what was
decided and what is true now are two different questions, and a tool that
overwrites the first with the second destroys the only record of what was
approved.

The second question gets its own three-valued vocabulary, kept deliberately
distinct from the decision's:

| Validity | What it means |
|---|---|
| `CURRENT` | every input this decision recorded still describes the subject it described then |
| `REQUIRES_REASSESSMENT` | at least one input demonstrably no longer does, and the store can say which and why |
| `UNDETERMINED` | the store cannot tell — the decision recorded no dependencies, or an input names something this workspace does not hold |

The strings are distinct from `ALLOW`/`DENY`/`REVIEW` on purpose. A reader who
confuses "allow" with "current" has confused what was decided with whether it
still applies, and identical vocabularies are how that confusion gets made.

Three properties are load-bearing.

**`REQUIRES_REASSESSMENT` is never reached by inference.** It needs a row: an
evidence record whose state is not `VALID`, or a subject whose recorded digest
differs from the one the decision named. "The model changed recently" is not a
reason. `{"reason": "evidence_superseded", "evidence_id": "ev_...", "was":
"sha256:OLD", "now": "sha256:NEW"}` is. Every reason the module produces is a
mapping a caller can act on without reading prose — which is what a score would
destroy, and is the third negative applied to memory rather than to capture.

**An old decision is `UNDETERMINED`, never `CURRENT`.** Decisions written
before schema version 3 carry no dependency rows. Reading "no inputs" as
"nothing it depended on has changed" would mark exactly the decisions this
release knows *least* about as the ones needing no attention. The quiet answer
has to be earned by rows that were checked, not inherited from rows that were
never written.

**Absence is not falsehood one level down either.** An input naming an evidence
record this store does not hold contributes an *undetermined* reason, never a
reassessment: a record that was never here is not a record that was withdrawn.

This is not a second policy engine. It produces no verdict about the subject,
no severity and no number. It answers one question about one stored row.

### 10.3 The rest, in a line each

The code below is worth rereading when the phase that needs it arrives. None of
it is worth carrying in a tree where no command can reach it.

- **`policy/`** — the rule chassis: a policy is a file with a digest that
  consumes claims and returns a decision with the proof that lets someone else
  re-derive it, plus the inversion that matters, `Unevaluable → REVIEW`, so a
  condition that cannot be evaluated is never silently False (D-111, D-112,
  D-113). Recover from `v2.3.0:src/actaira/policy/`.
- **`receipt.py`, the signing half only** — `signing_subject`, `signed_bytes`,
  `sign` and `verify`: what exactly gets covered by a signature, and the
  separation of the document from the bytes that are signed over it (D-120).
  Recover from `v2.3.0:src/actaira/receipt.py`. The building
  half is scanner-shaped and is not worth recovering.
- **The archived front end's presentation layer** — a stylesheet with no
  framework, no build step and no external font or icon, and an inline icon
  sprite instead of an icon dependency (D-17). Recover from
  `v2.3.0:src/actaira/web/static/styles.css` and the `<svg>` sprite at the top
  of `v2.3.0:src/actaira/web/static/index.html`. Phase C's HTML report is where
  this gets read again.

## 11. The pivot to surface (D-269)

**Decided.** The subject of this tool is what an agent **can** do, read from the
configuration files it loads, resolved across scopes and vendors, and compared
between two moments. It is not what an agent **did**. `scan` and `watch` stay,
demoted from the product to a companion: they answer which sessions ran after a
configuration changed, which is a question only the new subject makes worth
asking. The doctrine this replaces is in `docs/PRINCIPLES.md`'s history and in the 3.0.0
entry of `CHANGELOG.md`.

**Why.** Three properties the old subject never had. The input is small, on
disk, and does not move while it is read, so the whole decision path is a pure
function over bytes and the third negative is cheap to keep rather than
expensive. The merge semantics are documented by each vendor, so a finding cites
somebody else's rule and the second negative is kept by construction. And the
question repeats: a configuration changes on a Tuesday and somebody has to know
what it now permits, where a run is a one-off nobody returns to.

**What is given up.** Everything that needed a run. Authenticity, in the sense
of a signed record captured at the edge of a process, stops being a product
claim; the cryptography under it does not leave, it moves to sealing a surface
baseline. A configuration that declares nothing and an agent that did nothing
look identical from here, which is limit 11 and is not recoverable by reading
harder.

### 11.1 The three products tried against this question first

Each was a real candidate, and each was dropped for a reason that is a fact
about somebody else's shipped code rather than a preference. Kept because the
next person to have one of these ideas deserves the search results rather than
the conclusion.

**Rejected: cross-vendor session forensics.**
[AgentDFIR](https://github.com/efij/AgentDFIR) already ships it whole: twelve
agents, a detection catalogue, packages signed with a chain of custody. Nothing
was left to invent, only to maintain. And Claude Code and Gemini CLI delete
transcripts after thirty days by default, so the evidence expires under the
product.

**Rejected: validating sandbox containment.**
[Promptfoo](https://www.promptfoo.dev/docs/red-team/plugins/coding-agent/), now
OpenAI's, ships sandbox-escape plugins with canaries, and Cymulate sells the
scenarios. The failures that matter are CVEs the vendor patches, so a
deterministic battery would report CLOSED on precisely the versions that were
open, which is worse than reporting nothing.

**Rejected: the five leaks between generated and shipped code.**
[Git AI](https://usegitai.com/blog/git-ai-is-joining-openai) already sells the
relation between lines an agent generated and lines that shipped, and is now
OpenAI's. Competing with an incumbent's core metric using their new owner's
distribution is not a gap, and the metric is a number, which is the first
negative.

### 11.2 What the pivot does not change

The four negatives, unchanged, and they fit the new subject better than the old
one. A finding cites a rule with an author, because the merge semantics belong
to the vendor. Nothing is ever scored. What could not be resolved is
INDETERMINATE rather than absent, which is the third negative applied to a file
that could not be read instead of to an event that was not captured. And Seamark
still never acts: an exit code informs, and whether that blocks anything is the
user's branch protection, which is theirs.

The one place the fourth negative needed a sentence rather than a translation is
the exit code, and it is in `docs/PRINCIPLES.md` rather than only here, because "leaving
CI red is acting" is the objection somebody raises in a review and the doctrine
is where a review is settled.

### 11.3 Why this note's file is `docs/PRINCIPLES.md`

The table's promise is that every note names the file and line that
**implements** its decision. For a decision about how something is built, that
file is the module, which is why almost every row points at one. For a decision
about what gets built, it is `docs/PRINCIPLES.md`: the doctrine is what decides what
exists, and reversing this decision means editing `docs/PRINCIPLES.md` and letting the
tree follow, not editing a module.

Pointing this row at a module would have meant inventing one or naming a file
that does not argue this, and `scripts/design_notes.py` fails on a file that
never names its note, which is the right failure.

**This is written as a rule and not as an exception, and the rule is narrow.**
An exception is satisfied by adding a line to a list, so the rule would be kept
by whoever chose not to add the line, which is the same objection `docs/PRINCIPLES.md`
makes to an exception list under the reachability rule. So the criterion is
stated instead, in `docs/ENGINEERING.md` where the note convention is defined:
a doctrine decision, about what gets built, may point at `docs/PRINCIPLES.md`, and
nothing else may. A note about a format, a gate, a data structure or an
algorithm points at code even when the prose explaining it sits in a document.
D-269 is the only row of that kind today.
