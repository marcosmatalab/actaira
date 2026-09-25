# Backlog

One line per thing found and not fixed, with the phase that owns it. It is not
a wish list: only what a real pass found and decided not to touch gets in here,
together with the reason for not touching it. Work rule 2 of
[`PRINCIPLES.md`](PRINCIPLES.md).

## Phase 0 — the amputation

- ~~Local `main` (f706527, 275ecf4) unpublished; it lives on
  pivot/agent-conformance until the README is rewritten.~~ **Closed in 1.1b.**
  `main` was published as a fast-forward over `origin/main` (50e6f81 was an
  ancestor), and `pivot/agent-conformance` was retired: it was behind (635532f)
  and held nothing missing from `main`, which contains it whole in its own
  history. `main` is the product line. A branch that duplicates the main line
  and then falls behind it is a branch somebody starts from without noticing.
- `README.md` and `README.es.md` still describe the whole model scanner. Every
  one of those sentences is also a positioning sentence, and phase 0's
  authorisation was mechanical, so only the image blocks were removed.
  **Closed in A**, which rewrote both whole, and again in S0, which rewrote
  them around surface, change and currency.
- Fourteen lines of each README state a figure no command measures any more,
  measured against `scripts/figures_contract.py`, which is the list of the 21
  that are measured. The two files are aligned line by line, so the numbers
  hold for both. Work rule 6. **Closed in A**; the table is kept because it
  names the mechanism, not because it is still open.

  | line | figure with no source | what it says |
  |---|---|---|
  | L27 | controls, obligations | `15 executable controls`, `21 obligations` in the header table |
  | L28 | connectors | `7 connectors` in the header table |
  | L111 | `scan` console block | `2 artifact(s): 1 passed, 1 failed, 0 inconclusive` |
  | L137 | `agent paths` console block | `8 open, 0 already closed` |
  | L150 | connectors | `7 connectors enumerate and stage and never conclude` |
  | L197 | controls, obligations | `15 executable controls over 21 obligations` |
  | L214 | checkability level | `Machine-checkable` row, count column `5` |
  | L215 | checkability level | `Generatable` row, count column `4` |
  | L216 | checkability level | `Evidence-judged` row, count column `5` |
  | L217 | checkability level | `Organizational` row, count column `7` |
  | L221 | obligations, organizational split | `7 of the 21 obligations are organizational` |
  | L292 | unknown gadgets | `allowlist mode catches 11 of 11`, `denylist mode catches 1` |
  | L296 | marking survival | `Naive pipeline: 0 of 32. Metadata-aware pipeline: 8 of 8` |
  | L298 | corpus, fuzz targets | `64 corpus artifacts`, `9 fuzz targets` |

  Another fourteen figures on those same pages DO have a command and are not
  here, one per contract figure that appears on the page: `version`, `tests`,
  `lines`, `rules`, `coverage_states`, `capability_rules`, `watch_states`,
  `evidence_states`, `relations`, `predicates`, `subject_kinds`, `surfaces`,
  `commands` and `design_notes`. `readme_figures_are_current` walks those
  fourteen, not the fourteen above: the check only looks at figures the
  contract declares, so its green says nothing about the table. **Closed in
  A**: none of the fourteen lines survived the rewrite of the two READMEs.

  The three figures in this entry are derived, not typed: 14 and 14 are
  `len(table)` and the count of patterns that match on each page, and 21 is
  `len(scripts/figures_contract.figures())`. It used to say "another four",
  which was wrong by ten, in an entry whose subject is precisely a figure with
  no source. It is measured like this:

  ```sh
  python -c "import sys,re;sys.path[:0]=['scripts','src'];\
  import figures_contract as fc;from pathlib import Path;\
  t=fc.figures();print(len(t));\
  print([len([f for f in t if f.patterns.get(p) and re.findall(f.patterns[p],\
  Path(p).read_text(encoding='utf-8'))]) for p in ('README.md','README.es.md')])"
  ```

- `docs/GOVERNANCE.md`, `docs/FORMATS.md`, `docs/EVALUATION.md` and
  `docs/CONCEPTS*.md` document archived modules. `docs/COMPATIBILITY.md`
  promises that a published contract stays published, and 3.0.0 withdraws ten.
  **Closed between A and A.1**: `GOVERNANCE.md` was rewritten, the other three
  moved to `docs/archive/` with their banner, and `COMPATIBILITY.md` documents
  the withdrawal. What is still open about `COMPATIBILITY.md` is in the S0
  section below, and it is something else.
- `conformance/model.py` declares `SCHEMA_VERSION = "agent-bom/v2"` and that
  schema is no longer published: the module emits a document against a contract
  that is not in `schemas/`. **Closed by disappearance**: `conformance/` went
  whole to tag `v2.3.0` in 3.0.0, and the product that would have needed it
  leaves the plan in S0. Reproduction: `ls src/seamark/conformance` does not
  exist.
- `statecli._record_manifest` recorded a manifest of subjects in the state
  graph. It left with `statecli.py`, and `manifest.py` and `state/` left after
  it with phase A. `seamark contract`, which was to bring it back, leaves the
  plan in S0. If it returns, it returns with currency, and its subject is a
  surface rather than an artifact. **Phase P1.**
- Three tests in `test_state_graph.py` that covered that function were deleted
  with it, and with them the only coverage of the membership edges recorded
  from a manifest. They come back with `state/` or they do not come back.
  **Phase P1.**
- ~~DEF-115 (a receipt issued from a workspace referenced no evidence) lost its
  test.~~ **Closed in S3.** The shape of the defect is "a signed document that
  does not reference what it was signed about", and `seal/v1` makes it
  impossible by construction: `surface_sha256` is required by the schema and is
  the canonical digest of the sealed `surface/v1` document, so a seal with no
  subject does not validate.
  `test_a_changed_surface_changes_the_digest_an_approval_is_keyed_on` exercises
  the side that matters, which is that the digest moves when the surface moves.
- `i18n` keeps 41 rule ids from the scanner, the ones still cited in
  `coverage.py` and in `conformance/`. **Half closed**: the catalogue has been
  empty since phase A, and `release_check.rules_are_documented` requires it
  empty rather than letting its two loops pass over nothing. What is missing is
  the vocabulary that replaces it, which is the ids of `packs/core`. **Phase
  S1.**
- `examples/subjects.yaml` documents two commands in its header that no longer
  exist (`policy check --subjects`, `graph build --subjects`). **Closed by
  disappearance** in phase A: `examples/` ended up empty and left.
  Reproduction: `ls examples` does not exist.
- `.github/actions/seamark-scan/` still points at the scanner, by instruction.
  **Closed in A.1**, which deleted it. Reproduction: `ls .github/actions` does
  not exist. The GitHub Action that arrives in S3 is a different one and
  inherits nothing from this.
- `.github/workflows/ci.yml` may still invoke `make` steps that no longer
  exist. Not touched: phase 0's gate is `make all`, not CI. **Closed in A.1**,
  which rewrote it whole: it removed the five jobs that ran commands and
  directories that are not there (`eval`, `fuzz`, `benchmark`, `attest-self`
  and `figures`) and wrote into the file's header which jobs run and which do
  not, with the reason beside each. It runs on every push to `main` and every
  pull request. **S0 reassigned this line to S3 without re-checking it**, which
  is the defect the backlog exists to avoid: an inherited line is reassigned or
  closed, and closing it requires looking.
- `figures.json` records the `git.head` of the moment it was generated, and
  committing it changes the head, so it is always one commit behind (572f86f
  records 6cec2ec). `release-check` tolerates that by design. It cannot be
  fixed inside the file itself: it is the fixed-point problem, the same one
  Merkle trees solve by anchoring the record outside the object. **No phase**:
  it is a known property tolerated by design, not pending work.

## Phase 1 — read and record the trace

- `seamark.mcp.serve` silently discards a line of stdin that is not JSON,
  instead of answering the `-32700` parse error JSON-RPC requires. The client
  that sent it waits for a reply that never comes. It is not a fail-open of the
  evidence (the server claims nothing about that line), but it is a hung
  client. **No phase assigned.**
- `ClaudeCodeReader._lines` reads with `errors="replace"`, so a transcript with
  bytes that are not UTF-8 produces digests of altered text without the trace
  saying so. None has been seen: the 420 files on the machine where this was
  written all read cleanly. When one appears, the replacement has to be a
  declared gap and not a silent substitution. **No phase.**
- `seamark scan --out` names each file by the `session_id` the transcript
  declares. Two sessions from different projects declaring the same id would
  overwrite each other without a word. Not observed; the fix is to refuse the
  second or to name by path, and both change the published file name, which is
  what makes this not a one-line fix. **No phase.**
- ~~`scripts/build_package.py` still requires `seamark/web/static/index.html`,
  `seamark/agents/cassettes/judged-gold.json` and
  `seamark/schemas/report-v1.json`, which went to tag `v2.3.0` in 3.0.0.~~
  **Closed as DEF-130.** It had been failing on every run since the pivot, and
  the CI job that builds the same distributions asserted a different pair of
  its own, so each looked like it covered the other: work rule 10 exactly. The
  list is read off `src/seamark` now, and CI calls the script instead of
  repeating it.

## Phase 1.1b — the session the protocol no longer has

- The four shape gates in `proxy/protocol.py` (`_SOFTWARE_NAME`,
  `_TRACEPARENT`, `_REVISION`, `_REQUEST_STATE`) DISCARD a value that does not
  match, and the field stays `null`. A reader cannot tell "the server declared
  nothing" from "it declared something this reader does not publish". It is the
  third negative in miniature: what is not published is declared, not passed
  over in silence. The fix is a new gap reason per discarded field, and that is
  new vocabulary, which work rule 2 forbids an adversarial pass from
  introducing. **No phase.**
- `discover_unavailable` makes any session incomplete when a server exists that
  the agent never used, because nobody asked it for its inventory. It is
  correct and it is noisy: most configurations carry servers a given session
  does not touch. The gap may belong per observed server rather than per
  configured one. The contract deriver, which was to arbitrate this, leaves the
  plan in S0. The new arbiter is `check`, which reads from disk which MCP
  servers are configured and does not have to ask anybody. **Phase S1.**
- `seamark scan` with no `--out` has nowhere to keep the salt, so a gap about
  an unreadable file names no reference at all. An operator diagnosing from the
  terminal loses which of their files failed. The obvious fix, printing the
  salt, makes it public and undoes D-263. **No phase.**
- `trace/v2` ships with no entry of its own in `CHANGELOG.md`: the package
  version is still 3.0.0 and its entry is already written, so the note belongs
  to the next version bump rather than to an edit of a published entry.
  `schemas/__init__.py` says widening a closed enum is a changelog note, and
  this is one. **Phase S3**, the first to bump the version because it is the
  first to publish something new that a third party installs.
- The network guard covers six `socket` doors. It does not cover an
  `ssl.SSLSocket` built over an already-connected descriptor, nor `os.system`,
  nor a subprocess: the probe agent in `test_proxy_http_interposition.py` is a
  subprocess and leaves the guard by definition. It goes to loopback and can be
  read, but the property "the suite does not leave the machine" is weaker than
  its name suggests. **No phase.**

## Phase 1.1c — provenance as an invariant

- `traceparent` travels in the clear (see `trace/provenance.py`). Its shape is
  fixed-length hex, so it cannot carry a sentence, but the trace-id is sixteen
  bytes the client chooses: a client that wants to encode something there can.
  It is accepted because its only use is to cross the record with the
  OpenTelemetry traces the operator already emits, and a reference nobody else
  has the map for crosses with nothing. **No phase.**
- `seamark scan` with no `--out` has nowhere to keep the salt, so the reader
  mints one per run and two runs over the same sessions produce different
  references. With `--out` the salt is kept in `index.json` and the bytes are
  stable. Whoever captures `--json` without `--out` does not get a reproducible
  document. **No phase.**
- The operator-side reference map lives in three places depending on the path:
  `interposition.json` (alias and session), `<server>.refs.json` (what each
  proxy recorded) and `index.json` (what `scan` read). Three because three
  different processes write them, and merging them would require somebody
  writing after all of them have finished. A single `seamark resolve` that read
  all three would be better than three formats the operator has to know, and it
  would be an eighth command. The list has seven of eight, so it fits without
  removing anything, which turns this from impossible into a decision. **Phase
  S4**, which joins the machine scope with the sessions that ran after it and
  therefore has all three maps in front of it at once.
- `trace/v2` is published with no possible consumer: it lived one commit.
  `schemas/__init__.py`'s rule says a published contract stays published and
  that "nobody was using it" is not an argument, so it stays on disk and
  readable. If this happens again, the question is not the rule but why a
  schema is published before the phase that uses it has finished. **No phase.**
- Nothing in the tree SAYS that `<--out>/records/` is not published. It now
  holds, besides the literal arguments when `--with-content` is used, the
  `<server>.refs.json` maps that undo every reference of D-268. An operator who
  packages `--out` whole publishes what the salt protected. **Reassigned in S3,
  with a reason.** The line assumed the packager would be `seal` and that
  `seal` would package a trace. It does not: `seal` seals a SURFACE, never
  reads `records/` and could never find it inside, so the refusal this line
  asked for has no subject. What S3 did do is the half that is its own:
  `<--out>/index.json` from `seal` carries a written note saying that file does
  not travel and that publishing it undoes the package's redaction. The `watch`
  half is still open and is its own: the one that has to say it is `records/`.
  **No phase**, until there is a command that packages a trace.
- The network guard covers six `socket` doors and its meta-test exercises them
  one by one. It still does not cover a subprocess, which is how the probe
  agent in `test_proxy_http_interposition.py` gets out. It goes to loopback and
  can be read, but the property "the suite does not leave the machine" is
  weaker than its name suggests. **No phase.**

## Phase A — the truth and the amputation

Closed in this phase and written down because the backlog asked for it: both
READMEs were rewritten whole and no longer state any figure without a source.
The fourteen lines of the table above and the "README describes the scanner"
entry stop being open.

### Dead functions inside live modules

The reachability rule applies at module level, so these did not block the
phase. Each is in a file some command does reach.

- `model.Severity`, `model.Verdict` and `model.Finding` are used by nothing in
  `src/`. They are the shape S1 is written against (the rule packs raise a
  `Finding`), which is why they are kept rather than deleted, but as of today
  they are present and unused. Reproduction:
  `grep -rn 'Severity\|Verdict\|Finding' src/ | grep -v src/seamark/model.py`
  returns nothing. **Phase S1**, which is when they get a caller or go:
  `Finding` is the natural shape of a cited finding and `check` uses it or
  replaces it. `Verdict` is conformance vocabulary and has the weakest case.
- `attest/timestamp.py` (1,129 lines) is the largest live module in the tree
  and is only entered from `verify`, to check an RFC 3161 token that almost no
  package carries. How much of it `verify` actually reaches has not been
  measured. It deserves the same function-level measurement `dsse.py` got.
  **No phase assigned.**

### Documentation that still describes the scanner

Phase A rewrote `README.md`, `README.es.md`, `docs/COMPATIBILITY.md` and
`docs/GOVERNANCE.md`, the four the scope named. These others still describe a
product this tree cannot deliver. No gate reads them, so nothing fails: that is
exactly why they have been lying for six months.

- `docs/FORMATS.md` describes reading pickle, ONNX, HDF5, GGUF and safetensors,
  and the whole table of `ACT-*` rules. None of that exists here. Reproduction:
  `grep -c 'pickle' docs/FORMATS.md`. A candidate for deletion whole, as
  `docs/CLI-OUTPUT.md` was deleted in this phase.
- `docs/EVALUATION.md` describes a corpus and a harness that live at tag
  `v2.3.0`.
- `docs/ARCHITECTURE.md` draws a directory tree with `formats/`,
  `conformance/`, `policy/` and `state/`.
- `docs/THREAT-MODEL.md` and `docs/CONCEPTS.md` / `CONCEPTS.es.md` are
  half-and-half: both concept pages do name the four commands (the gate checks
  that), and describe the scanner around them.
- `docs/DESIGN.md` keeps sections 2 to 9, which argue the scanner. They were
  left on purpose: they are the design history of code that existed and section
  10 says where to recover it. What must not happen is a reader taking them for
  a description of today's tree.

**Closed in A.1.** All six moved to `docs/archive/` unedited, with a banner
saying they describe the retired product, and sections 2, 5, 6, 7, 8 and 9 of
`DESIGN.md` with them. They were not rewritten: a document that argues a
decision is worth more than a summary of that decision, and the next person to
write an artifact reader should be able to read why this one was built the way
it was.

### Others

- `docs/defects.json` lost 27 test pins in this phase: the tests that held them
  left with the modules they covered. Each became a `pinned_note`, following
  the rule the file already used for the scanner. A defect held by a note is
  held worse than one held by a test, and the figure in `docs/ENGINEERING.md`
  reflects that now.
- `examples/` ended up empty: its two files were read by `conformance/` and
  `policy/`. If **phase S1** needs an example, it is a fixture configuration
  and not a declaration, and it arrives under the new code rule: real or
  reconstructed from a published report, cited, and with an inert script.

## Phase A.1 — what the reachability measurement does not measure

- ~~**`test_reachability` measures modules, not whether the product's chain
  closes.**~~ **Closed in S3.** `seamark seal` is the producer: it writes a
  package with a `seal/v1` document inside, and `verify` verifies it and also
  NAMES the contract it just verified rather than checking bytes and saying
  nothing about them. The check the line asked for, "for every format this tree
  verifies, there is a command that produces it", is no longer rhetorical and
  is held by
  `tests/test_seal_and_report.py::test_a_seal_verifies_offline_and_names_the_contract_it_carries`.
  Reproduction of the closure: `grep -rn 'write_package' src/ | grep -v 'def '`
  now returns the call in `attest/seal.py`. The original text is below.

  ORIGINAL:
  It asks whether every module is reachable from a command. `attest/` is:
  `verify` enters `package.py`, `merkle.py`, `chain.py`, `trust.py`,
  `timestamp.py` and `keyring.py`. What it does not ask is whether something
  this tool WRITES is something this tool can VERIFY, and today it is not:
  `attest/package.py::write_package` is the only package writer and nothing
  outside `tests/` calls it. Reproduction:

      grep -rn 'write_package' src/ | grep -v 'def write_package'

  returns only a mention in a comment in `keyring.py`. That is: 3.0 has a
  package verifier and no package producer. That is not a defect in the code,
  it is an unfinished phase, but the gate does not say so and the README does
  have to (and does). The missing check is of a different class from
  reachability: "for every format this tree verifies, there is a command that
  produces it". **Phase S3**, when `seal` writes a signed baseline and the
  question stops being rhetorical.

- **`.pre-commit-hooks.yaml` publishes two hooks that cannot run.** Both call
  `seamark scan --fail-on high` over `.pkl`, `.onnx`, `.h5` and company.
  Neither `--fail-on` nor exit code 3 has existed since 3.0, and `scan` no
  longer reads artifacts: it reads agent sessions. It is exactly the defect
  `.github/actions/seamark-scan` had, which A.1 deleted. Reproduction:
  `seamark scan --fail-on high` exits 2. It was not deleted in A.1 because the
  scope named the GitHub Action and not this file, and deciding on my own which
  integrations the project publishes is not mine to do. **Closed in S0**, with
  that decision taken: the file was deleted. The S0 entry below says how.

- **`docs/CONTRACTS.md` and `docs/FIGURES.md` are generated, and nobody checks
  that the internal links of the archived documents still resolve.** The six in
  `docs/archive/` moved with their relative links intact, so a
  `[x](CONCEPTS.md)` inside `archive/FORMATS.md` still works because both moved
  together, but a link from an archived page to something that stayed in
  `docs/` (or the reverse) is checked by nothing.
  `tests/test_readme_parity.py::test_every_repository_link_resolves` only looks
  at the two READMEs. **No phase assigned.**

- **`make all` fails on the first pass after touching code, and passes on the
  second.** The order is `lint test-cov figures release-check`, and the suite
  includes `tests/test_release_check.py::test_the_gate_passes_on_this_repository`,
  which runs the gate over a copy of the tree. If `figures.json` has not been
  re-measured (that is, whenever a `.py` file has been edited since the last
  `make figures`), that check fails inside the suite, before `make figures`
  would have fixed it. Reproduction: touch any test, run `make all` (red), run
  it again (green). It is D-181's shape: a gate whose remedy is remembering to
  run something else first is a gate people route around. The obvious answer,
  `all: lint figures test-cov release-check`, makes `make all` write in the
  tree before checking it, which is worse for another reason. It deserves a
  decision, not a blind reordering. **No phase assigned.**

## Phase S0 — what still sells the previous product

S0's adversarial pass (work rule 2) swept the whole tree outside
`docs/archive/` and `CHANGELOG.md` looking for sentences that present the old
product as a current objective. It found seven things, and a second pass, asked
for with a narrower criterion (does it make a PUBLISHED file say something
false about the current state?), found two more the first missed by sweeping
positioning sentences rather than corpus references.

Seven of the nine were fixed under an extension authorised in the phase
itself. The two still open do not meet that criterion: they are not published
documents, they are comments and docstrings.

### Fixed in S0

They are written down because each says something about why no gate caught it,
and that part is still true.

- `CITATION.cff` described the whole model scanner, with pickle, ONNX and GGUF
  protocols. **The gate reads the version and the licence out of that file, not
  the abstract**, which is exactly why it had spent two phases lying in the
  file anybody citing this work cites.
- The `Dockerfile` printed "An independent witness for AI agents" into
  `org.opencontainers.image.description` of every image built. No check reads
  that label.
- `docs/COMPATIBILITY.md` named `contract`, `verdict`, `receipt` and `fix` as
  the commands that were missing. **`readme_documents_the_commands` only checks
  that the ones that DO exist are named**, never that the missing ones are the
  real ones, so the page could name four imaginary commands indefinitely. It
  now names the three that are missing and the four retired ones in the past
  tense, with the reason a retired name deserves a line: somebody will type it.
- `docs/ENGINEERING.md` said design notes live in the modules that argue them.
  It now states the whole rule, which has two branches and is narrow in the
  second: a decision about HOW something is built is implemented by the module;
  a doctrine decision, about WHAT is built, is implemented by
  `docs/PRINCIPLES.md`, and nothing else may point there. `docs/DESIGN.md`
  §11.3 argues it and D-269 is the only row of the second class.
- `src/seamark/mcp.py` announced two tools of the retired product in
  `tools/list`. It no longer does. It was checked before touching them that
  neither did anything: both fell through to `_unbuilt`, which returned a
  constant. D-256 changes its answer and is rewritten with the change: a tool
  is announced only if it runs, because a name in `tools/list` is read by an
  agent as a capability and nothing afterwards undoes that reading.
- `SECURITY.md` had a whole section, "This repository contains malicious model
  artifacts", about `evals/corpus/build.py` writing working gadget pickles into
  `evals/artifacts/`. `evals/` has not existed since phase A, so the document
  said this repository generates malware when it does not, and contradicted the
  code rule S0 itself wrote. Cut back to what is true: how to report, which
  versions are supported, and what is in the tree. **The supported-versions
  table said 2.2.x** for a 3.0.0 package, and that was in one of the two
  sections that are kept.
- `CONTRIBUTING.md`, which the first pass missed, had "Never commit an artifact
  from the corpus" about three directories that do not exist, a `make` block
  with six targets the `Makefile` does not have, and a `dev` extra two
  dependencies short. Cut back the same way, writing nothing new.
- `.pre-commit-hooks.yaml` published two hooks that could not run
  (`seamark scan --fail-on high` over `.pkl`, `.onnx`, `.h5`). A.1 found it and
  did not delete it because deciding which integrations the project publishes
  was not its call. Deleted. `release_check` already tolerated its absence
  (`if not path.is_file(): continue`), so the pin count goes from 1 to 0
  without anything breaking, which is the same shape deleting
  `.github/actions/seamark-scan` had.

### Still open

- **"phase B" and "phase 2" survive in five code and gate files.**
  `src/seamark/model.py` (twice), `src/seamark/trace/redact.py`,
  `scripts/release_check.py`, `tests/test_i18n.py` (twice) and
  `tests/test_no_aggregate.py`. All of them mean S1, the phase that brings the
  rule packs. They do not meet S0's fix criterion: they are comments and
  docstrings, not published documents, and no reader of the product sees them.
  Reproduction: `grep -rn 'phase B\|phase 2' src/ scripts/ tests/`.
  `tests/test_cli.py` and `src/seamark/mcp.py` were on this list and left it
  when they were fixed in S0. **Phase S1**, with the phase that makes them true
  rather than rewriting them twice.

- **`MANIFEST.in` excludes `.pre-commit-hooks.yaml`, which no longer exists.**
  An `exclude` over an absent file is a setuptools warning, not an error, and
  `make package` is not in `make all`. It is the same line of work as
  `scripts/build_package.py`, which requires three archived files. They are
  fixed together. **Phase S3.**

- **The threat model for the new input is not written.** `SECURITY.md` says so
  in its header rather than anticipating it: S1 reads configuration files from
  repositories somebody else wrote, which is attacker-controlled input in the
  most literal sense, and that deserves a threat model against the code that
  reads it rather than against the code somebody intends to write. **Phase
  S1**, and it is in its gate.

## Phase S1 — what `check` leaves open

### Closed in this phase, checked against the tree

- **"phase B" and "phase 2" in five files.** Resolved. `src/seamark/model.py`
  (twice) was rewritten when `Finding` was reused and `Severity` and `Verdict`
  deleted; `tests/test_i18n.py` and `tests/test_no_aggregate.py` were
  repointed at S1 and the rule packs; `src/seamark/trace/redact.py` now says
  what a rule needs, with no phase. ONE live mention is left and it is
  deliberate: `scripts/release_check.py` QUOTES the old docstring it replaced,
  because the argument for why the check was open is what explains why it is
  not any more. Reproduction: `grep -rn 'phase B\|phase 2' src/ scripts/ tests/
  --include='*.py'` returns that one line.
- **`i18n` with no vocabulary to replace the scanner's 41 ids.** Closed:
  `packs/core` defines 15, both catalogues carry them, and
  `release_check.rules_are_documented` no longer requires an empty catalogue
  but compares it against the packs and against `docs/RULES.md`.
- **`model.Severity`, `model.Verdict` and `model.Finding` with no caller.**
  Closed. `Finding` has one: `surface/rules.py` raises one per rule that fires,
  with new `rule_version`, `author` and `pack` so the severity travels
  attributed. `Severity` and `Verdict` were deleted, each with its reason
  written in `model.py` itself.
- **`discover_unavailable` marks a session incomplete per configured server
  rather than per observed server.** Closed as far as the arbiter goes: `check`
  reads from disk which MCP servers are configured and does not need to ask the
  session. What has NOT been done is changing `proxy/session.py` to use it;
  that is `proxy/` work, which is parked, and it is reopened below with its
  phase.
- **The threat model for the new input.** Written in `SECURITY.md`, with ten
  defences and the test that holds each one.

### Open, with their phase

- ~~**`check` is not exposed by the MCP server.**~~ **Closed in S2.**
  `seamark_check` is in `TOOLS` and calls `cli.check_document`, the same
  function the command prints: a second implementation behind the tool would be
  a second place the answer is computed and the one that goes stale without
  anybody noticing. It does not expose `--with-content` or `--machine`, and the
  reason is written in `_check` (D-289): the first puts literals into a
  document another agent reads, and the second reads the developer's home
  directory. It arrives now and not in S1 for the reason the line gave: a tool
  that read one vendor would have announced "the configuration surface" and
  returned a sixth of it, and `tools/list` is the one surface where a reading
  that has already happened is not corrected further down. Reproduction:
  `test_check_over_mcp_answers_with_the_same_document_the_command_builds`.
- **Three of the fifteen rules have no REAL violating case. Closed as a
  deviation, not as debt.** `docs/PRINCIPLES.md` has carried a narrow third
  branch since that phase that admits it, and all three meet it: ACT-S013 and
  ACT-S014 compare against a managed policy, which lives at an operating-system
  path outside every repository, so no search will ever find a public sample;
  ACT-S002 records seven searches from 17 Sep 2026 that returned 67 public
  configurations between them and not one `http` hook. The mark is in the rule
  pack itself, is published in the row and in the `docs/RULES.md` entry, the
  loader refuses a mark with no citation and no search, and
  `test_a_mark_with_no_evidence_is_refused_at_load` checks that the refusal
  bites. **No phase**: ACT-S002 unmarks itself the day one of those searches
  returns a case, and the corpus script already knows how to run them. ACT-S013
  and ACT-S014 never unmark, by construction.
- **The agent version only arrives through `--agent-version`.** D-277 explains
  why `claude --version` is not executed and `~/.claude.json` is not read. What
  is unresolved is whether in `--machine` mode it is worth reading from disk
  WITH the L0 caveat written beside it, which is what `scan` does with a
  transcript. **Phase S4**, the machine-mode one.
- **`referenced_path` is a heuristic and says so.** It recognises a token
  shaped like a path and returns `None` when it recognises none, so the rule
  that wanted a target comes out INDETERMINATE. A command like
  `sh -c "$(curl ...)"` names no path and therefore produces no facts about a
  target. **No phase**: fixing it properly means writing a shell, which is
  exactly what D-272 rejects.
- ~~**The frontmatter of skills and subagents is not read.**~~ **Closed in S2.**
  `surface/miniyaml.py` reads the subset those files use (maps, lists, inline
  flows, plain and quoted scalars, comments) and REFUSES BY NAME everything
  else: anchors, aliases, tags, block scalars, complex keys and multi-document
  flows. No new dependency. The gap is not closed, it is narrowed and its cause
  changes: INDETERMINATE is no longer "there is no reader" but "this block uses
  a construct outside the subset", with the construct named, which is a cause
  somebody can act on. It deliberately does not read YAML 1.1 booleans (`NO` is
  the string `NO`, not `False`), and the reason is in D-281.
- **`enabledPlugins` only resolves if the plugin is downloaded into the tree.**
  Anything from a remote marketplace comes out INDETERMINATE. It is correct and
  it is the most frequent gap cause in the corpus (8 of 20 configurations). It
  may deserve grouping by marketplace in the console rather than one line per
  plugin. **No phase.**
- ~~**`MANIFEST.in` excludes `.pre-commit-hooks.yaml`, which no longer
  exists.**~~ **Closed in S3**, and closed from both sides: the file exists
  again, so the line is true rather than merely silent, and `action.yml` is
  excluded beside it for the same reason. Both are integration manifests read
  from a git checkout: neither `pre-commit` nor GitHub Actions ever looks
  inside a wheel.

### Open from phase S2

- ~~**The READMEs published "Does not exist" about a claim S1 had already
  built, and no check saw it.**~~ **Closed in S3**, and closed by the hole
  rather than by the instance. `readme_claims_resolve_against_the_tree` reads
  the `Commands:` line of every claim block and resolves it against the parser
  IN BOTH DIRECTIONS: a block that says "built" while naming a command nobody
  wrote breaks the gate, and a command that exists with no block claiming it
  breaks it just the same. The criterion that makes it possible is the one the
  line asked for: what cannot be checked mechanically is not asserted, so a
  block with no `Commands:` is rejected for not being resolvable rather than
  accepted for being nice prose.

  Three more arrived with it, which are the other two things a README asserts:
  `documented_flags_exist` (every flag the documentation shows beside a command
  is an option that command has, read from `docs/COMMANDS.md` and
  `.pre-commit-hooks.yaml` too), `exit_codes_are_the_published_ones` (the table
  in `COMPATIBILITY.md` is exactly the set the CLI defines, with 141
  necessarily OUTSIDE the table and named in the prose) and
  `package_metadata_names_real_commands` (the `pyproject.toml` description,
  which had spent two phases naming four commands over a tree of five).

  Six planted defects in `tests/test_release_check.py` require each shape to be
  refused.
- **`docs/RULES.md` does not say which capability each rule emits nor which
  file it lives in.** It publishes the capability name, which is our
  vocabulary; a reader who wants to know which of their files produces it has
  to read the reader. **No phase.**
- ~~**Gemini CLI publishes `mcpServers.<name>.trust` and also
  `general.defaultApprovalMode`, and only the first has a rule.**~~ **Closed in
  S2**, authorised in conversation. It is **ACT-S031**, with a real violating
  case: 65 public `.gemini/settings.json` analysed on 18 Sep 2026, 43 with an
  approval mode other than the default. The fact changed name and meaning while
  it was being written: it was `stops_asking = mode != "default"`, which
  counted `plan` as a relaxation when the reference calls it a read-only mode,
  that is a TIGHTENING. It is now `guardrail_removed = mode == "auto_edit"`,
  the same fact name the two Codex keys of ACT-S022 carry, because it is the
  same statement.
- ~~**The bounded disk primitives live in `surface/claude_code.py` and the
  other six readers import them.**~~ **Closed in S3.** They are in
  `surface/disk.py`, together with `SettingsFile` and `Reading`, which had to
  go with them because `read_json` returns the first and no reader produces
  anything that is not the second. A mechanical rename: not one signature
  changed, not one name, not one behaviour. Design note D-271 went with the
  code that implements it and is D-300 now; rows D-272 and D-279 point at the
  new file. It was done in S3 and not S4 because in S4 the machine-scope
  readers import the same thing and then there are ten of them rather than six.
- **The S1 rows of the merge table cannot be reproduced by any command in the
  tree.** The S2 ones can: their `doc_sha256` is `curl -sL <url> | sha256sum`
  over the bytes that URL served on 2026-09-18, and that is written beside the
  table. The eight from S1 were taken with another method that was not
  recorded, and recomputing them today does not reproduce them, which is
  expected because a page changes, but it means nobody can tell "the page
  changed" from "we measured it another way". They are not touched: rewriting
  them with today's date would be re-dating a reading that was not made today.
  They are taken again, with the method written down, the next time that
  documentation is reviewed. **No phase.**
- **`vendors_present` in `scripts/surface_corpus.py` lists each vendor's paths
  a second time.** The first is in each reader. A new vendor has to be added in
  both places and nothing warns if the second is forgotten: the corpus simply
  does not promote it. It is a script and not the package, so it breaks no
  negative. **No phase.**

### From the capability coverage invariant (S2, after the review)

- ~~**`hook.mcp_tool` had been emitted since S1 and no rule named it.**~~
  **Closed**: it is **ACT-S032**, with a real and abundant violating case.
  Nobody found it by reading: `test_capability_coverage` found it, which is
  exactly what it was written for.
- ~~**A capability's name was built with `f"hook.{kind}"`.**~~ **Closed
  (D-290).** A `.claude/settings.json` with `"type": "madeup"` produced the
  capability `hook.madeup`: the audited repository choosing a name in Seamark's
  vocabulary, and one no rule could ever name. Only the three documented types
  give a capability now, and anything else comes out INDETERMINATE with the
  type written into the cause.
- ~~**The Gemini reader did not see `toolDiscoveryCommand` or
  `toolCallCommand`.**~~ **Closed (D-291).** They are the v1 spelling of
  `tools.discoveryCommand` and `tools.callCommand`. Two public repositories use
  them and the report said nothing about them, which is the one failure a
  configuration reader cannot have. They are read, and they come out
  INDETERMINATE: the current schema publishes only the nested spelling, and
  whether this version of Gemini still honours the flat one is not published
  anywhere we have found. Claiming it runs invents the migration; claiming it
  does not invents its withdrawal.
- **`gemini-cli helper.command` has no rule, and is in
  `EMITTED_WITHOUT_A_RULE` with its reason.** `tools.discoveryCommand` and
  `tools.callCommand` do run a command from a project file that overrides the
  user's, so the rule would be justified. There is no real violating case: five
  recorded searches from 18 Sep 2026 analysed 56 distinct public files and none
  sets either of the two in the current spelling. Writing the rule against a
  fixture of ours would prove that we can write the fixture. **No phase**: the
  rule arrives the day a case appears, and the corpus script already knows how
  to look for it.

### From the S1 adversarial pass

- **With `--lang es`, a capability's `condition` and a rule's `remediation`
  come out in English.** The rule's text is translated; those two fields are
  not. It is correct that `remediation` is not: the rule pack's author writes
  it and translating it would be rewriting what somebody else said, which is
  the second negative. `condition` is a different thing: Seamark's resolver
  generates it, so it is our text with no catalogue entry. Fixing it properly
  requires turning every condition into a key with parameters, which touches
  `resolve.py` whole. **No phase**, and not in S1's scope: an adversarial pass
  may only produce a fix or a line here.
- ~~**The facts of a script a PLUGIN's hook points at are not computed.**~~
  **Closed in S2.** The walk that fills `Reading.scripts` now goes through
  `settings` AND `mcp_files`, which is where a downloaded plugin's
  `hooks/hooks.json` ended up, and it runs again after the plugin files and the
  frontmatter blocks have been added: an explicit second pass rather than an
  ordering rule somebody has to remember. ACT-S003, ACT-S004 and ACT-S005
  answer about a plugin hook instead of coming out INDETERMINATE about a target
  that was on disk the whole time. Reproduction:
  `test_a_plugin_hooks_script_gets_the_same_four_facts_as_any_other`.

### For the launch study

- **`task.allowAutomaticTasks` is APPLICATION-scoped, and that has two sides
  the study has to give together.** Launch-phase material, section 7 of the
  master plan, alongside the S1 finding about hooks and folder trust.

  IN FAVOUR, and it is a real finding: the value that decides whether a
  `folderOpen` task runs CANNOT live in any scope the repository controls. The
  key is `ConfigurationScope.APPLICATION` in VS Code's own code, so a committed
  `.vscode/settings.json` does not set it, and the value comes from the user's
  settings file. From which it follows that INDETERMINATE is the CORRECT
  default answer on any pull request, not a hole in the tool: whoever reviews a
  PR cannot know, from the repository, whether the machine that opens it will
  run the task. A product that answered "it runs" or "it does not run" there
  would be inventing.

  AGAINST, AND THIS IS WRITTEN SO THE HEADLINE IS NOT INFLATED: the task keyv
  planted only runs if the user ALREADY had automatic execution enabled. The
  documented default is `off`, and automatic tasks never run in an untrusted
  workspace whatever the setting. So the study's headline CANNOT say that the
  VS Code half of the worm always runs, nor that it runs on a freshly installed
  machine. What it can say is what is true: that it runs without asking on
  machines that have automatic execution enabled and the folder trusted, that
  the repository cannot know which those are, and that the other half of the
  same worm, the Claude Code hook, waits for none of that. The two halves are
  not equivalent and a study that presents them as one is selling.

- **That hooks and `env` do NOT wait for folder trust is the mechanism by which
  both 2026 worms work, and it is study material.** The "What runs before you
  trust a folder" table on the permissions page puts settings-file hooks, the
  `env` block and the helper commands in the row that says **Used** in both
  untrusted situations; only `permissions.allow`, `additionalDirectories`, the
  `.mcp.json` approvals and `extraKnownMarketplaces` wait. The intuitive
  reading, "the trust dialog protects me from a repository I have not read", is
  false exactly where it matters, and it is what turns a committed
  `.claude/settings.json` into code execution when the session opens. It is
  cited in the corresponding row of `surface/merge.MERGE_TABLE`, with the URL,
  the page digest and the date, and the condition is written into every
  affected capability in the report. **Launch phase**, section 7 of the master
  plan: it is one of the "it would have caught", and the point that explains
  why.

### Open from phase S3

- ~~**`uses: $/` is untested and is left for later, on purpose.**~~ **Closed.**
  The `action` job went green twice with `uses: ./` (runs 35382239038 and
  35384198525), and only then did the two lines become `uses: $/` in a commit
  of their own, so a red there could only be about that line. The two
  `# zizmor: ignore[self-repository]` silences went with them: zizmor now comes
  out clean with no exemption at all, "No findings to report" with no "(N
  ignored)". Isolating the variable, which is what the line asked for, worked
  exactly as planned.
- **The `Makefile` recipes are the only place with DEF-124's shape that the
  sweep does not cover.** `tests/test_workflow_shell.py` hands `bash -n` every
  piece of shell this repository puts in a file that is not a script (the
  `run:` bodies of the workflows and of `action.yml`, the `RUN` instructions of
  the `Dockerfile`) and not the recipes, because expanding them is `make -n`
  and that is a different mechanism: putting it in the same test is how a test
  stops being one thing. `make all` executes what it reaches (`lint`,
  `test-cov`, `figures`, `release-check` and whatever hangs off them), so the
  uncovered recipes are the ones it does not: `install`, `types`, `contracts`,
  `rules`, `design-notes`, `demo-image`, `report-image`, `package`,
  `source-archive`, `clean` and `help`. It is written here, and not passed over
  in silence, because passing over it would be exactly what work rule 12 added
  when DEF-124 was closed: look for what else has the shape, and say what you
  found. **No phase.**

- **The HTML report has no check that it is readable.** It is asserted that it
  loads nothing from the network, that it comes out the same twice and that it
  escapes what comes from somebody else; nothing is asserted about the result
  being legible, and that is not machine-checkable without a capture.
  `docs/img/02-report.png` is that capture and `scripts/report_image.py`
  produces it, but the capture is looked at by a person and not by a gate: what
  the gate holds is that the picture is displayed by a document and that the
  run behind it is the demo's. **No phase**: it is a known limit, not pending
  work.
- **`diff` materialises each ref's whole tree.** It is correct (filtering by
  the paths the readers know would be a second copy of each reader's path list,
  and `diff` would answer about a subset while `check` answers about
  everything) and it is expensive in a monorepo. The ceilings
  (`MAX_TREE_FILES` 50,000, `MAX_TREE_BYTES` 256 MiB) are checked against the
  listing before a byte is written, so a tree that does not fit is refused with
  the number stated rather than half-extracted. What there is not is a
  measurement of how long it takes over a genuinely large repository. **No
  phase** until somebody notices it.
- **`git_tracked` cannot answer about a materialised tree from a ref.** A
  directory extracted with `cat-file` has no `.git/index`, so the fact comes
  out `null` with its cause written, on BOTH sides of the diff. No rule reads
  that fact, so no finding changes, and because it is symmetric it produces no
  false change either. Rejected: fabricating a `.git/index` so the fact would
  read `true`, which would be Seamark writing a git artifact so that its own
  answer looked more complete, and besides the fact is not "it was in that
  ref's index" but "it was in the index of the tree that was read". **No
  phase.**
- **The `diff` report does not publish what was not materialised.**
  `Extraction` carries a `refused` field with the submodules and the paths that
  would not have fitted inside the extraction, and `to_dict` does not put it in
  the document: a submodule is a commit id and not a file, and today that does
  not reach `not_read`. It is the third negative in miniature and the fix is a
  `not_read` entry for each. Found in the phase's adversarial pass. **No
  phase.**
- **`report/html.py` prints whole `facts` and `check` on the console does
  not.** The page is more complete than the console for the same document,
  which is a difference between two outputs of one command with nobody
  arbitrating it. The page is the one that is right: a reviewer wants to see
  the fact and not only the sentence about the fact. **No phase.**
- **What `uses: $/` resolves to on a `pull_request` event has not been
  checked.** On a push to `main` it has: the log of run 35384556901 says
  `Download action repository 'marcosmatalab/seamark@bba5403...' (SHA:bba5403...)`,
  that is the commit being tested. On a pull request it has not been looked at,
  and there is a concrete reason to suspect: a `pull_request`'s workflow file
  is taken from the BASE, so if `$/` also resolved to the base, a PR that
  changes `action.yml` would be self-testing against the OLD version of the
  action and the `action` job would come out green without executing a line of
  what the PR proposes. With `uses: ./` that did not happen: it read the
  workspace, which on a `pull_request` is the PR's merge. So the syntax that is
  stricter for security may be looser for self-testing, and both can be true at
  once.

  The method, so nobody has to invent it on the day: open a PR that changes ONE
  COMMENTED LINE of `action.yml`, one that alters no behaviour, and read in the
  `action` job's log which SHA it downloads at `Download action repository`. If
  it is the PR's, there is nothing to do. If it is the base's, the self-test
  job has to go back to `uses: ./` (and with it the two
  `# zizmor: ignore[self-repository]`), leaving `$/` for the workflows that do
  not test themselves.

  **Not blocking today**, because everything that has landed has landed through
  a push to `main`. **It is blocking the day there are pull requests from
  outside**, which is exactly the day a PR can change `action.yml`.

- **WIDENED has never run end to end on a runner.** The suite covers it:
  `tests/test_diff.py` walks it in both directions over the two public
  configurations of `michaelgrosner/CoffeeMol` and
  `bybren-llc/safe-agentic-workflow`. What does not exist is a GitHub Actions
  run that has produced one. S3's point 10 gives 0, 1, 3 and 0, and the 0 of
  the fourth folder is a NARROWED, not a WIDENED. The two directions are not
  interchangeable for the exit code: `fired_on_new_capability` looks at `added`
  and `widened`, and WIDENED is the only path to 1 that does not go through a
  new capability, that is, the only one folder 2 does not exercise. It is
  covered in **phase L** over a fixture repository of our own, which also
  allows controlling the before state; over somebody else's fork the before
  side is whatever it is, and loosening somebody else's guardrail to test it is
  not done. **Phase L.**
- **The runtime view of point 1 looks at the RESOLVER and not the READERS, and
  extending it costs five places, not one.** `watched()` is applied to the
  `Reading` that `read()` already returned, so every decision a reader takes
  while reading is outside it. Two known places fall there: `type` in
  `claude_code.py` (inside `command_strings`) and `notify` in `codex.py`. Over
  those decisions there is ONE view, the static one, which is exactly the
  situation work rule 10 exists against.

  **MEASURED BEFORE DECIDING, which was the condition.** If every reader went
  through a single parse point, wrapping there would be cheap and would not
  touch `src/`. They do not: a parsed document is built in **five** places,
  `disk.read_json` (Claude Code, Cursor, Gemini), `vscode.read_jsonc` (VS Code,
  devcontainer) and `codex.read_toml`, which are shared helpers, plus two
  inline in `codex.py` and `claude_code.py`. Not six instruments, but not one
  either.

  **IT IS NOT BUILT NOW**, and the reason is priority rather than difficulty:
  it would be refining the measuring tool while points 6, 7, 2 and 3 of the
  S3.1 gate are still at zero, and 7 is where the false negative that gives the
  phase its name lives. What protects the readers' decisions meanwhile is NOT
  agreement between views (there are not two) but the planted test of point 3,
  which enters through the CLI and does not know where the decision was taken.

  **The signal to build it**: a planted test of point 3 producing a surprise
  inside a reader. **No phase.**

- **A GATE POINT FOR PHASE L, not a line on this list: every figure and every
  behavioural claim in `.launch/` material names the command that produces it,
  and is checked BEFORE it leaves the folder.** Written here so the L prompt
  picks it up, not for somebody to fix today.

  WHY IT IS A GATE POINT AND NOT A LINE. `.launch/` is the only place in the
  repository with no guard at all. It is in `.gitignore` on purpose (material
  about publishing the product, not part of it), so it is not looked at by the
  README claim check, nor by `figures_contract.py`, nor by work rule 6, nor by
  `markup_split_problems`, nor by the shell sweep DEF-124 brought, which skips
  it declaring its reason. And phase L consists precisely of FILLING it with
  publishable material. A phase whose deliverable lives in the only directory
  with no gate needs the gate before the deliverable.

  WHERE IT COMES FROM, measured and not supposed. Kit 4 of point 10 claimed the
  report showed ACT-S031 firing on the before side. Executed on 2026-09-19, run
  35468400213: exit 0, `NARROWED: 1`, zero mentions of any rule in the whole
  log. The claim was false, contradicted kit 1 (which explained the same thing
  correctly) and `fired_on_new_capability` in `surface/diff.py` answers it in
  three lines, design note D-299: findings attach to `added` and `widened` and
  to nothing else. Nobody saw it because nothing checked it and because nobody
  had run it: point 10 itself is what uncovered it. That is a finding about the
  launch material, not a typo, and the difference matters: a typo is corrected,
  a finding changes the gate.

  THE SHAPE, written so nobody implements it wrongly. A list of files to review
  by hand will not do: it would be work rule 11 again, a check satisfied by
  whoever decides not to add the line. The check has to discover the material
  (walk `.launch/`) and demand of every figure and every behavioural claim the
  command that produces it, the same way the READMEs' console blocks are
  compared today against what the command really prints. And it has to fail
  loudly when it finds no material, because an ignored directory that is here
  today and gone tomorrow is exactly the case where a silent zero would read as
  green. **Phase L, in the gate.**
- **On what documented basis is a value outside the set the vendor publishes
  ordered?** Written as a question because it is the question, and whoever
  opens it should not have to reconstruct it. The two branches:

  - If Google's documentation says an invalid value is ignored and falls back
    to `default`, then ordering it below `auto_edit` is correct, NARROWED is
    the right answer, and it goes in **cited**: URL, page digest and date, like
    any other merge rule.
  - If it does not say so, ordering it is inferring the vendor's behaviour,
    which is the third negative, and the honest answer is INDETERMINATE with
    the cause named.

  **The scenario that matters is not `yolo`.** `yolo` is answered: the schema
  Google publishes for `general.defaultApprovalMode` admits `default`,
  `auto_edit` and `plan`, and says YOLO is only enabled from the command line
  (`--yolo`, `--approval-mode=yolo`), so a settings file cannot set it and
  treating it as not-`auto_edit` invents nothing. Measured on 2026-09-18 while
  preparing point 10: `auto_edit` -> `"yolo"` comes out NARROWED and 0.

  The scenario is the day a vendor **adds a new mode wider than every known
  one** and an unknown value falls to the safe end of the order. That comes out
  NARROWED over a real widening: a false negative in the one direction where a
  false negative matters. Today `surface/gemini.py` knows a single constant,
  `AUTO_EDIT = "auto_edit"`, so anything that is not that string is "not
  auto_edit", which is exactly the safe end.

  **The test that answers it**: a Gemini file with a value outside the
  published set on both sides of a diff, and the statement of what comes out
  and why. **Phase L.**
- **Which OTHER values carry a condition their merge row does not express.**
  Found by counting, for S3.1, how many of the 16 keys have a merge rule per
  value. Two do and they enter that phase. Apart from those, a value may not
  contradict its row's `kind` and still carry a condition the row does not
  state: `hooks[].type = "http"` is bounded by `allowedHttpHookUrls`, which
  "applies to hooks from every source, including managed settings", and
  `command` and `mcp_tool` are not. That specific case IS FIXED IN S3.1, as a
  row, using the DECLARED-to-EFFECTIVE ladder that exists for it. What does NOT
  enter S3.1 is the systematic sweep: walking the 16 keys asking, value by
  value, which other key conditions it. The VS Code pair (`runOn: folderOpen`
  bounded by `task.allowAutomaticTasks`) is already modelled and is the proof
  that the pattern exists in more than one place. **No phase**, until somebody
  opens it: it is a documentation sweep over six vendors, not a fix.
- ~~**`markup_split_problems` reads its nouns from a hand-maintained list.**~~
  **Closed as DEF-125.** It was left standing in DEF-122 because the refusal of
  an unmatched pattern covered the case without anybody having to remember
  anything, and the shape of the fix was written here at the time: the nouns
  come from the figures contract, not from a separate list. That is what was
  done. `anchor_nouns` reads them off each figure's own pattern, so the set the
  guard protects and the set the sync script writes are one set by
  construction; what is left by hand is `RETIRED_NOUNS`, which is additive only
  and holds the nouns of figures that went to tag `v2.3.0`.

  It closed one release later than it should have, and the cost is recorded:
  `lines` was never in the hand-typed list, so the one figure most likely to be
  moved by a paragraph rewrap was outside the guard from the day the guard was
  written, and the guard's own tests passed because they were written from the
  same tuple. The same pass extended the guard to whitespace that is not
  exactly one space, because every pattern spells that gap as a literal space
  and a line break unhooks a figure as completely as `<br>` does.


## From the review of the closing plan

The plan's own criteria, read back against the tree after the six phases were
done, and what was decided about the ones that were not met. Each of these is
now held by something that can fail; what is here is the part that is a
decision rather than a check.

- **Two files stay over the 900-line cap and have no phase to split them.**
  `src/seamark/cli.py` (1086) and `src/seamark/attest/timestamp.py` (1129) are
  not in the plan's change inventory, and `src/seamark/attest/verify.py` (976)
  is protected by it by name. `tests/test_file_size.py` holds the cap over
  every other file in `src/` and holds these three at the size they are, so
  none of them can grow and a fourth cannot appear. Splitting `cli.py` behind
  the parser, or the RFC 3161 codec away from the verifier that uses it, is
  work somebody has to want for its own sake. **No phase.**
- **Both landing pages stay over the ~300 lines the plan asked for**, with a
  ceiling each and a contract on the first screen. The argument, the
  trade-off and the rejected alternative are in `docs/ENGINEERING.md`. **No
  phase**: it is a decision, not pending work.
- **What GitHub's renderer draws is not machine-checkable here.**
  `release_check.py` proves the demo SVG fetches nothing, uses no element a
  sanitiser strips, and fits its own box at a glyph width wider than any
  common monospace face - which is everything a command in this repository
  can answer. What it cannot answer is what a particular browser draws, and
  that is step 3 of `.github/release-notes/RUNBOOK.md`: push a preview
  branch, look at the rendered page, and only then carry on. **No phase**: it
  is a known limit with a step attached.
- **`v2.3.0` stops being an ancestor of `main` when the history is replayed.**
  The tag is the seventh commit, so a replay from the root moves everything
  after it. The tag, its tree, its release and every `v2.3.0:path`
  locator in this tree are unaffected, which is why those locators were moved
  onto the tag in the first place. The alternative - replaying only after the
  tag - leaves five commits with bodies of 50, 39, 25, 21 and 20 lines, which
  is the thing the rewrite exists to remove. Written up in the runbook, at the
  step where it happens. **No phase.**
- **The suite's slowest file is the one that runs the gate.**
  `tests/test_release_check.py` starts `scripts/release_check.py` in a
  subprocess for each twin, and the gate collects the whole suite and runs the
  network guard's meta-test on every one of those runs. It is the honest way
  to test a gate - the twin plants a defect in a copy of the tree and demands
  the real script refuse it - and it is why `make test` is minutes rather than
  seconds. What would fix it is a mode that runs one named check, which is a
  second entry point into the gate and therefore a second definition of what
  running it means. **No phase**, and it is recorded here so that the next
  person does not discover the cost and assume nobody noticed.
