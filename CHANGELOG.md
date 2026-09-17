# Changelog

All notable changes to Actaira are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Two conventions specific to this project:

* **Numbers in this file are measured, not remembered.** Test counts are what
  `pytest --collect-only` reported at that release, and detection figures come
  from `evals/results.json` and `evals/benchmark.json` as written by the
  harnesses. `make figures` regenerates the current ones into
  `docs/FIGURES.md`.
* **Defects found in the work itself are listed.** A release note that only
  contains features is a marketing document. Where a version fixed something
  its own author had got wrong, it says so under *Fixed*.

The dates below are the days the work was done. The project was built over a
short, concentrated period, so several versions share a date; that is the
history as it happened rather than a spread-out one invented for appearances.
They are the one thing in this file a reader cannot re-derive from what is in
front of them, and they are therefore the one thing in it worth the least:
everything else here is checkable against the tree it describes.

## Unreleased

**The subject changes: from what an agent did to what an agent can do.** No code
moved in phase S0 and no version is released here. What changed is the doctrine
the code is written against, and it is recorded now rather than at the release
that first ships against it, because a later session can only read the
repository.

### Changed

- `CLAUDE.md`'s three product claims are now **surface**, **change** and
  **currency**, replacing authenticity, conformance and inclusion. Surface is
  what an agent can do here, resolved across scopes and vendors, with every
  capability citing its file, the vendor's documented merge rule with the URL
  and version that states it, and the Actaira rule that names it. Change is what
  appears, disappears, widens or narrows between two moments. Currency is
  whether an approval still describes what is there, bound to digests and never
  to names or dates.
- Three resolution states are added for a capability, alongside and not
  replacing the capture levels: `DECLARADO`, `EFECTIVO`, `INDETERMINADO`. L0 to
  L3 keep governing `scan` and `watch`, which are what look at a run.
- The four negatives are unchanged as principles. Three nouns moved: a
  non-conformance is a **finding**, the *acta* is a **report**, and the fourth
  negative now states that an exit code informs while blocking is decided by the
  user's own branch protection.
- The published limits go from ten to fourteen. The first ten are about what
  watching a run cannot show; the four new ones are about what reading a
  configuration cannot show, starting with the one that governs the rest:
  configuration declares, it does not demonstrate behaviour.
- The CLI list goes from eight names to seven, with the cap left at eight.
  `check`, `diff` and `seal` arrive in phases S1 and S3 and each carries the
  phase it arrives in; `contract`, `verdict`, `receipt` and `fix` leave the list.
  Nothing in the parser changed: this release still ships `scan`, `watch`,
  `verify` and `keygen`.
- Two code rules are added. A rule's two tests are now over a **real**
  configuration, from a public repository under an OSI licence with repo, commit
  and licence cited, or reconstructed from a configuration published in an
  incident report with URL and fragment cited, and never invented; and no fixture
  carries a live payload, so the script a hook points at is an inert stub or does
  not exist. Readers touch the disk; resolution and rules are pure functions over
  what was read.
- Executing what a hook, a task or an MCP server declares is added to the
  forbidden list, in `CLAUDE.md` and in `docs/GOVERNANCE.md`.
- `docs/GOVERNANCE.md`'s wire table now carries rules that fired, resolution
  states and currency states where it carried verdicts. What never crosses is
  unchanged: content, full stop.

### Added

- `docs/DESIGN.md` section 11, design note D-269, with the three products that
  were tried against this question first and dropped, each for a fact about
  somebody else's shipped code: cross-vendor session forensics, sandbox
  containment validation, and the generated-to-shipped code metric. Section 11.3
  records why this note's file is `CLAUDE.md` rather than a module, which makes
  it the first row in the table whose location is not code.
- `tests/test_cli.py` gains a check that reads the CLI list out of `CLAUDE.md`
  and fails on a name there that neither exists in the parser nor states the
  phase it arrives in. A name on that list without a phase is a published
  promise.

### Removed

- `.pre-commit-hooks.yaml`, which published two hooks that could not run: both
  called `actaira scan --fail-on high` over `.pkl`, `.onnx` and `.h5`, and
  neither `--fail-on` nor exit code 3 has existed since 3.0.0. Phase A.1 found
  it and left it, because deciding which integrations the project publishes was
  not its call. It is the same decision A.1 made about
  `.github/actions/actaira-scan`, applied to the sibling that was left. The
  pre-commit integration returns when there is something to hook a commit to.
- `actaira_contract` and `actaira_verdict` from the MCP server's `tools/list`.
  Both were inert, returning a constant that named a phase which no longer
  exists. **Design note D-256 changes its answer with them**: it used to decide
  that an unbuilt tool is announced and refused by name, on the argument that an
  explicit refusal beats a stub inventing a verdict. That was right about the
  answer and wrong about the announcement, because an agent reads `tools/list`
  as capability and the reading has already happened by the time the refusal
  arrives. A tool is now announced only if it runs, the handler lives in the
  table entry rather than in a branch below it, and `tests/test_mcp.py` calls
  every name the server lists.

### Fixed

Seven published documents that described a product this tree does not have.
None was caught by a gate, and each says something about why:

- `CITATION.cff` still described the 2.x model scanner, pickle protocols and
  all. The release gate reads that file for the version and the licence and
  never for the abstract.
- The `Dockerfile` stamped "An independent witness for AI agents" into
  `org.opencontainers.image.description` on every image built. Nothing reads
  that label.
- `docs/COMPATIBILITY.md` named `contract`, `verdict`, `receipt` and `fix` as
  the commands still to come. `release_check.readme_documents_the_commands`
  checks only that the commands which exist are named, never that the ones said
  to be missing are the right ones, so that page could have named four
  imaginary commands indefinitely. It now names the three that are coming, and
  the four retired ones in the past tense, because somebody's script will still
  type one and what it must get is a usage error.
- `SECURITY.md` carried a section titled "This repository contains malicious
  model artifacts", describing a corpus generator that left in phase A, and a
  supported-versions table that said 2.2.x for a 3.0.0 package. Trimmed to how
  to report, which versions are supported, and what the four commands do. The
  threat model for configuration read out of other people's repositories is
  deliberately not written yet: it belongs to the phase that builds the reader.
- `CONTRIBUTING.md` told contributors never to commit an artifact from a corpus
  that does not exist, listed six `make` targets the `Makefile` does not have,
  and named a `dev` extra with two packages too many.
- `docs/ENGINEERING.md` said design notes live in the modules they argue about.
  It now states the whole rule, whose second branch is deliberately narrow: a
  decision about **how** something is built is implemented by its module; a
  doctrine decision, about **what** gets built, is implemented by `CLAUDE.md`,
  and nothing else may point there. `docs/DESIGN.md` section 11.3 argues it.
- `src/actaira/mcp.py`, above.
- `CONTRIBUTING.md` again, on a second reading: it said the repository has no
  remote and that nothing runs on its own, and that `.github/workflows/ci.yml`
  had not been rewritten since the scanner left. Phase A.1 rewrote that
  workflow and it runs on every push to `main` and every pull request. The same
  page stated the type ratchet's counts by hand, named a test file that does not
  exist, listed optional dependencies this tree does not have, and pointed at an
  entry point and a harness that left with the scanner. `MANIFEST.in` explained
  an exclusion by describing a corpus builder that writes gadget pickles, which
  has not been in the tree since phase A.
- The backlog line that reassigned `ci.yml` to phase S3. It had been closed by
  A.1 already, and this phase moved it to a new phase without rechecking it,
  which is the one thing a backlog must not do to an inherited line.

## [3.0.0] - 2026-09-15

**Why a major, decided rather than inherited.** Semantic versioning asks whether
a consumer written against the last release still works, and none does: ten
published contracts are withdrawn, twenty of twenty-two commands are gone, and
the entry hash and both signature preimages changed shape, so packages and
receipts issued by 2.3.0 no longer verify here. The alternative was 2.4.0 with a
long deprecation, rejected because there is nothing to deprecate toward - the
tool no longer reads model artifacts at all.

The subject changes from model artifacts to AI agent runs. The scanner - formats,
controls, connectors, scan, bom, agents, governance, web, the bundle resolver, the
marking and trust modules and the 2 458-line CLI - is archived whole at tag
`v2.3.0` on `archive/model-scanner`; what survives is the evidence core: attest,
state, policy, report, receipt, subject and the conformance package, renamed from
`agentgov` because it collided with the `agents` module beside it. Two
cryptographic defects found on the way out are fixed: the chain entry hash
promised length prefixes and concatenated with `|`, and a demonstrated collision
moved bytes across a field boundary undetected; the package manifest and the
receipt both signed 32 bare bytes under the same default key with no domain
separation. `actaira` is two commands, `verify` and `keygen`, until the trace
format that the other six need exists.

Phase 0.1, which closed the seven findings of an external review on top of this
release, ended at 17 authored files against an initial budget of 14. The three
extensions were authorised in conversation, each with its reason, and all three
had the same one: two of the findings were not bugs but an inverted default, and
inverting a default has a blast radius that lives in the tests which encoded the
old one. `dsse_envelope_valid` printing [FAIL] beside `Result: OK` was fixed by
making failure the default in `verify.settle`, and that reached `test_receipt`,
`test_schemas`, `test_dsse`, `test_merkle`, `test_chain_domain_separation` and
`test_package_verify` - six files that were correct about the code as it was and
wrong about the code as it had to become. That count cannot be made in advance,
which is why the budget was a real constraint and was raised rather than
quietly exceeded. Work rule 8 in `CLAUDE.md` now requires such an authorisation
to be written into the phase's commit message, because this one lived only in
the chat and the next session had no way to read it.

## [2.3.0] - 2026-09-12

The release where the pieces become a loop.

Actaira could already observe a source, record what it saw as evidence, decide
under a versioned policy and draw the graph of what depends on what. What it
could not do was join them: the evidence ledger had seven kinds and one
producer, a change reported its impact from the source rather than from the
artifact that moved, and a decision recorded nothing about what it had rested
on - so the question this tool exists to answer, *is the system we approved
still the system we are running*, had no path through the code.

It does now:

```
observe -> state -> change -> invalidate -> impact -> decide -> prove
```

A model's bytes change. The evidence bound to the digest that is gone is
superseded, and the evidence about its untouched siblings is not. The impact
walk starts at that exact artifact and keeps one route per cause. The ALLOW
that was recorded in March is still an ALLOW, and its applicability to today
becomes `requires_reassessment` with the evidence id, the digest it was taken
about, and the digest that replaced it.

This release also contains the graph and impact panel, which had been written
and never given a version of its own.

### Added

* **Three evidence producers, where there was one.** `actaira scan --state`,
  `actaira agent check --state` and `actaira policy check --state` now file
  `artifact_scan`, `agent_assessment` and `policy_decision` records. State
  stays optional in both directions: without the flag every command is exactly
  as stateless as it was, and with it the database must already exist, because
  a scan that created a workspace in whatever directory it ran in would be
  taking a liberty with somebody's disk in exchange for a convenience nobody
  asked for.
* **An identity rule that does not invent one.** Evidence is filed against an
  asset this workspace already records, found by the digest that was scanned
  or by the handle a manifest declared. A file nothing has observed records
  nothing and says why. The alternative is `artifact:<basename>`, and the
  first time two teams both have a `model.pt` that is evidence about whichever
  was scanned last.
* **Decision validity, with three values.** `current`,
  `requires_reassessment` and `undetermined`, derived fresh from the rows a
  decision recorded as its inputs. It is not a second policy engine and not a
  score: it answers whether the state an old decision rested on still
  describes the subject in front of you. `actaira decisions` prints it, and
  every reason is a mapping - `{"reason": "evidence_superseded",
  "evidence_id": ..., "was": ..., "now": ...}` - rather than a sentence.
* **`actaira changes`,** the observations this workspace has recorded.
* **Three panels:** an evidence explorer with filters by state, kind and
  subject and a timeline per subject; a change timeline; and the decisions
  with their validity. All readers, all behind the same Host and Origin
  checks as the graph routes, and the workspace is still chosen when the
  server starts and never named by a request.
* **Exact per-artifact impact.** `watch` used to ask its impact question from
  `source:<id>`, so a source holding forty files, one of which changed,
  reported every dependent of all forty. It now starts from each changed
  artifact's own asset id and keeps the causes apart: a system downstream of
  two changes shows two routes, because a deduplicated list of targets would
  have told the reader it was downstream of one.
* **One engine object for a change,** assembled in Python and rendered by both
  surfaces, so the terminal and the browser cannot describe one observation
  two ways.
* **Store schema 3,** adding `decision_inputs`: what a decision rested on, as
  typed rows rather than ids in a string. Forward-only, additive, and a
  decision written before it existed is reported `undetermined` rather than
  rewritten into a fact the old store did not know.
* **`[project.urls]`,** now that there is a repository and an issue tracker to
  point at. `Documentation` and `Homepage` are still absent, because there is
  no documentation site and a metadata field pointing at a URL that 404s is
  worse than one that is not there.

### Added, in the graph increment this release also carries


* **`actaira serve --state PATH`.** Optional, and the interface is fully
  usable without it. It is the only way to tell this server which workspace to
  read: no request can name a database, because a route that accepted a path
  would be a file-existence oracle at best and an sqlite parser fed hostile
  input at worst.
* **A graph panel.** The recorded asset graph, drawn from `asset-graph/v1`,
  with a focus mode, a hop limit, upstream and downstream, kind and relation
  filters, search by id, name or digest, a text view of the same relations,
  keyboard-reachable nodes and edges, and impact with the exact route.
  Selecting an edge shows its relation, what stated it, and the evidence
  record behind it when there is one.
* **`actaira graph show --focus ID --depth N --direction ...`.** The same
  neighbourhood walk the panel calls, in the terminal, because the traversal
  lives in Python once rather than a second time in a browser.
* **A currentness projection, with three values.** `current`,
  `not_in_latest_observation` and `undetermined`. It needed no migration:
  `assets.last_snapshot` and the snapshot digest each edge already names are
  enough for anything an observation produced, and a relation a declaration
  stated is reported as undetermined rather than guessed at, because nothing
  in the store says which run of a declaration is the live one.

### Fixed

* **DEF-111: every data source in every graph drew as an unrecognised kind.**
  The engine emits `data:<name>` and the renderer's vocabulary calls the kind
  `datasource`, so the prefix matched nothing and the neutral style was used.
  Nothing failed, there was no console error, and the picture was wrong. The
  mapping is now explicit, and the test is over the prefixes the engine can
  emit rather than over that one entry.
* **DEF-112: `impact` reported that nothing depended on an agent's tools.**
  `Agent.relations()` does not link an agent to the tools and servers it
  declares, so the shipped example contributed one edge to the stored graph
  and `actaira impact tool:fetch_url` answered that nothing was affected. The
  graph-build layer now records declaration-backed membership. `Agent.digest`
  and `agent-bom/v2` are deliberately untouched, and a test pins the digest of
  the shipped declaration so a graph improvement cannot move the number that
  answers "is this the agent that was approved?".

* **DEF-113: `watch` measured a local artifact's digest and stored neither it
  nor any evidence about it.** The filesystem connector publishes no declared
  digest by design, and both the asset write and the evidence write consulted
  only that field - so on a local source, which is the commonest workspace
  there is, every artifact row was stored with an empty digest while the same
  run used the measured digest to correctly report that the content had
  changed. The measurement existed and was discarded one line before it was
  written down. Everything rested on it: supersession is bound to a subject's
  digest, so a changed model invalidated nothing.
* **DEF-114: DEF-74's fix had never worked on Windows.** A `file:` URI was
  turned into a path with a string slice, which is right on POSIX by
  coincidence and turns `file:///C:/models/w.bin` into `/C:/models/w.bin`
  everywhere else. No local artifact was ever measured, so comparison fell
  back to size - precisely the failure DEF-74 exists to prevent, where a
  weight file replaced with different bytes of the same length comes back
  UNCHANGED, exit 0. The regression test written for DEF-74 did not catch it
  because its fixture assembled the URI by hand, and that spelling is the one
  shape the old slice happened to survive. It now uses the spelling the
  connector emits.
* **DEF-115: every receipt ever issued from a workspace referenced no
  evidence.** `assurance-receipt/v2` publishes an `evidence` array so a
  receipt can name the observations it rested on, and the lookup matched each
  record's subject against the subject's handle - `artifact:model.pkl` - and
  against its digest. Nothing is ever filed under either: `watch` files
  per-artifact records under an id derived from the artifact's URI, and so do
  this release's producers. The command exited 0 and signed a valid document
  every time, with the field a verifier would read simply absent, which is
  indistinguishable from a workspace that had recorded nothing. The third time
  this shape has been found here, after the `decisions` and `receipts` tables
  in D-233: a published field with no producer that could fill it.

### Unchanged, and checked

`asset-graph/v1`, `evidence-record/v1`, `assurance-receipt/v2`,
`SubjectKind`, `Agent.digest` and `agent-bom/v2`. `state-export/v1` gained one
optional array beside the existing ones, which is what its own compatibility
rule allows. Everything the panels need beyond the published contracts rides
in objects beside them: a presentation need is not a reason to version a
schema other tools read.

There is deliberately no `assurance-state/v1`. The name is attractive and the
semantics are not complete: a declared edge's currentness is still
`undetermined`, because nothing in the store says which run of a declaration
is the live one, so a published state document would have to either omit
provenance currentness or assert it. The representation stays internal and the
seam is written down.

## [2.2.0] - 2026-09-11

**Continuous Verifiable AI Assurance.** 2.1 answered "what is true about this
artifact right now" from the bytes in front of it. This release answers the
question that comes after it: *what changed, what evidence that produced is no
longer good, and what else is affected.* Nothing was added to the runtime
dependency list: the state store is `sqlite3` from the standard library.

### Added

* **Local state, and `actaira watch`.** `actaira init`, `source add`, `watch`,
  `snapshot`, `evidence`, `graph`, `impact`. An idempotent check against a
  stored baseline, suitable for cron rather than a daemon, distinguishing four
  things a naive implementation collapses into one: first observation, no
  change, a revision that moved with identical content, and content that moved.
  A fifth, an incomplete listing, writes no baseline at all, because treating a failed
  page as a set of deletions is the most destructive false report a change
  detector can give.
* **Evidence with a lifetime.** `evidence-record/v1`, with VALID, STALE,
  SUPERSEDED, REVOKED and UNTRUSTED. They are five different reasons rather
  than five degrees of confidence, and supersession is bound to the subject's
  digest, so re-observing a model that did not change supersedes nothing and
  evidence about a sibling nobody touched stays valid.
* **An asset graph and `actaira impact`.** Every edge carries the declaration
  or snapshot that stated it, and an answer comes with its route,
  `system:x -> USES -> agent:y -> USES -> bundle:z`, rather than as a list.
  Nothing infers an edge from two assets sharing a registry or a manifest.
  Delegation cycles are cut and reported as `ACT-PATH-009`.
* **`actaira agent paths`.** The eight capability rules report that two things
  are a bad pair; this reports the route, the material it carries, and what
  would break it. `ACT-PATH-001` to `ACT-PATH-004` and `ACT-PATH-009`. Routes an
  existing control already closes are reported as closed and are not findings.
* **A universal subject model.** `SubjectRef` and `SubjectClaims` over
  `artifact`, `bundle`, `agent`, `system` and `source`, with ten new policy
  predicates: `subject_kind`, `bundle_finding`, `bundle_content_identity`,
  `agent_effect`, `agent_finding`, `attack_path_severity_at_least`,
  `relation_exists`, `evidence_state`, `source_revision_pinned`, `trust_state`.
  `subject-manifest/v1` lets `policy check` and `receipt issue` be about a
  system rather than a list of files. The language stays small, enumerable and
  free of anything that executes.
* **`trust-policy/v1` and `actaira trust check`.** What this environment
  accepts, kept apart from what cryptography proved. No trust policy means
  UNKNOWN, never UNTRUSTED.
* **Remote bundles.** `actaira bundle huggingface://org/model --revision <r>`,
  with an optional content-addressed cache under `.actaira/cache` that is never
  read without a digest to check an entry against. Provenance survives into the
  document.
* **A nightly real-artifact matrix.** torch, onnx, h5py and safetensors on
  Python 3.11, 3.12 and 3.13, with `ACTAIRA_REQUIRE_REAL_STACK=1` turning every
  dependency guard into a failure that names the missing library. A scheduled
  job that installs the stack and then skips is a job that checked nothing.

### Changed

* **`model-bundle/v2`: `bundle_digest` is gone.** It was a digest over the
  layout, paths, sizes, roles and whatever digests had been computed, under a
  name that reads as the identity of the weights, and members over 64 MiB were
  never hashed. Two 8 GB shards with the same name and size and completely
  different bytes produced the same value. The two questions are now two
  fields: `structural_digest`, honest about being only a layout digest, and
  `content_identity` with an explicit state, `complete`, `partial`,
  `externally_bound` or `unavailable`, plus `--hash-weights` and support for
  digests a connector published.
* **`agent-bom/v2`: declared relations.** `tool.identity`, `tool.inputs`,
  `tool.outputs`, `tool.served_by` and digest-bound `sub_agents`, all validated
  against the same document. `classification` and `access` come from a
  versioned vocabulary or carry an explicit namespace. A rule can now point at
  the edge that makes a mitigation true instead of inferring it from two
  strings that happened to match.
* **`actaira agent diff` explains everything the digest covers.** MCP servers
  whose name stayed and whose reference, digest, publisher, transport or tool
  list moved; identities added, removed or re-scoped; data sources
  reclassified; sub-agents repointed; environment and owner changes with a risk
  classification. Risk-increasing changes are listed first, and the document
  says so when the digest moved and nothing explains it.
* **`assurance-receipt/v2`.** Typed subjects with per-subject provenance, plus
  references to the evidence, snapshots and graph behind them, all inside the
  signature. v1 still verifies, and nothing emits it any more.
* **ACT-AGT-002 no longer treats separate identities as a fix.** Inside one
  agent every tool writes into one model's conversation, so a second identity
  changes who may read a credential, not who may repeat it. The separation is
  recorded with the reason it does not apply. Closing a real finding with a
  control that does not cover it is the most expensive kind of wrong answer.
* **The release gate grew six checks**: superseded contracts still on disk and
  never emitted, every migration reachable one step at a time, every edge
  relation documented and storable, `watch` deterministic over a fixture, no
  score-shaped property in any contract, and the new examples still loading.

### Fixed

* **DEF-66: a colon with no space made every scope a stringified dictionary.**
  `miniyaml` split on `":"` where YAML opens a value only when the colon is
  followed by a space or ends the line. `- jira:write` became
  `{"jira": "write"}`, and the shipped agent declaration's A-BOM published
  `"{'jira': 'write'}"` where the file said `jira:write`, in every release from
  1.0.0 to 2.1.0. A scope is exactly the field a reviewer compares between two
  releases. Nothing caught it because no test had ever asserted on a scope's
  value.
* **DEF-67: `python -m actaira.cli` ran `main()` halfway through the module.**
  The `__main__` guard had drifted above a thousand lines of command handlers,
  so the module form died with `NameError`. The installed console script calls
  `main` after the import completes and was unaffected, which is why nothing
  noticed.
* **DEF-68: `policy check` without `--on` crashed, and the crash looked like a
  DENY.** `args.on or gov_clock_fn()` called `governance.clock`, which takes
  the date rather than returning it. The TypeError became exit 1, which is
  `EXIT_FAIL`, so a pipeline reading the exit code saw a clean policy denial
  rather than a broken command. Every test of `policy check` and `receipt
  issue` passed `--on`, because that is what a reproducible decision uses.

* **DEF-94: the inline list everybody writes was read as a string.**
  `effects: [read, write]` came back as the text `"[read, write]"`, because the
  parser handled block sequences and not flow ones. The agent loader at least
  raised; the manifest loader iterated the string character by character and
  refused the document with a message listing single letters. Found by writing
  a declaration the way a person writes one rather than the way the fixtures
  do.

Twenty-six more, all in this release's own new code and all found by reading it
back adversarially, or by running it end to end, before the tag rather than by
a test. The ones worth naming here, because each is a shape rather than a slip:

* **DEF-72, DEF-73: evidence that healed itself, and evidence that could not
  be healed.** An evidence id is the digest of what the evidence says, and the
  upsert overwrote its state, so observing an unrelated artifact brought a
  REVOKED record back to VALID. Meanwhile a source watched daily with no
  changes went stale after thirty days and no amount of watching cleared it,
  because the early return skipped the only write that moves the timestamp.
* **DEF-70, DEF-71: a baseline that could not come back, and one that survived
  a crash it should not have.** Keying a snapshot on its content digest meant a
  source returning to an earlier state could not record having done so, and
  reported the same change forever. And the snapshot committed ahead of the
  assets and evidence, so a failure in between left a row claiming a source had
  been fully observed, permanently, because the next run compared against it.
* **DEF-74: the default source could not detect a change.** With no declared
  digest, comparison fell back to file size, and the filesystem connector
  publishes no digests by design. A weight file replaced with different bytes
  of the same length came back UNCHANGED, exit 0, with no caveat anywhere, and
  `_identity`'s docstring claimed the weakness was "labelled as such everywhere
  it is used". Local sources are now hashed, and every artifact carries an
  `identity_basis` with the weak ones named in the observation.
* **DEF-79: cycle detection was wrong twice.** The first version
  under-reported on about a fifth of random digraphs. Repairing its colouring
  did not fix it, and that was the useful part: a three-colour walk answers
  whether a graph has a cycle, not which cycles it has. Replaced with bounded
  simple-cycle enumeration, differentially tested against brute force.
* **DEF-81, DEF-82, DEF-85: absence read as assertion, three times.** A deny
  rule on an open attack path passed when nothing had searched for one; a
  declaration that provably states no relations came back REVIEW rather than
  DENY; and a trust rule that had never been evaluated reported itself
  satisfied. All three are the failure this codebase exists to refuse, in code
  written to refuse it.
* **DEF-83: a misspelt predicate name was a message and a misspelt predicate
  value was a traceback**, and the traceback exited 1, which is
  indistinguishable from a DENY. Both halves of "this rule is well formed" now
  fail when the document loads.

* **DEF-90, DEF-95: a finding with no route, twice.** A single tool that reads
  outside text and acts on it, and a single tool that brings in both the
  instruction and the material, were each skipped by the route search while the
  set-based rules fired on them, so the command that exists to answer "how?"
  answered nothing for the shortest and usually worst form of each route.
  `trusted: false` and `classification: personal` on one source is what a
  ticket queue or a case file actually is.

`docs/defects.json` has all 38 found in this cycle, each with the sequence
that reproduces it and the test that pins it.

### New rules

`ACT-AGT-009` (an MCP server exposes a tool the declaration does not describe),
`ACT-AGT-010` (a sub-agent delegated to without a digest), `ACT-BDL-009` (the
source listing was incomplete, so the resolution covers part of the
repository), and `ACT-PATH-001` to `ACT-PATH-004` and `ACT-PATH-009`.

### Closing the branch

The last pass before the tag, whose rule was that no inconsistency survives it
and that anything derivable is never maintained by hand again.

* **`--dsse` exists now.** It had been documented since 2.0 and the flag had
  never been added: `attest/dsse.py` was 505 lines of implemented, tested,
  unreachable code. The envelope is written as an ordinary package member, so
  the manifest covers it and the manifest signature covers the manifest, and
  `verify` reports it as a separate check (DEF-96).
* **`policy check --state`, and receipts recorded.** `state-export/v1`
  published `decisions` and `receipts` arrays that nothing could ever fill,
  because `record_decision` and `record_receipt` had no callers. Wired rather
  than removed, because a v1 consumer already reads them (DEF-99).
* **A closed pipe is no longer a traceback.** `actaira schema | head -3`
  printed `BrokenPipeError` to stderr and exited 0, from every command, which
  is a stack trace shown to whoever is debugging a pipeline by the tool that
  has just reported success. It exits 141 now, the shell's own convention
  (DEF-101).
* **Pillow is declared.** Four places in the source said it was in the `dev`
  extra and `pyproject.toml` did not list it, so a clean install produced a
  checkout where ACT-C-15-MARK-ROBUSTNESS abstained for a missing library the
  documentation said was present (DEF-97).
* **The User-Agent is the version this is.** It said `actaira/2.0` for two
  minor releases (DEF-98).
* **The nightly was red and nobody had looked.** Two expectations still
  described the pre-coverage behaviour, where a benign `torch.save` zip was
  INCONCLUSIVE and the identical object in the legacy format was PASS. They
  need torch, onnx, h5py and safetensors, so only the nightly runs them
  (DEF-102).
* **Thirteen unreachable functions removed**, one of whose docstrings named
  two callers that do not exist (DEF-100), and a test that now refuses the
  next one.

### Consistency, made automatic

* `scripts/figures_contract.py` is the single table of every figure the prose
  may state, including the release version. `make figures` writes them into
  both languages; the release gate refuses a tree where any has drifted, where
  a figure is spelled as a word, or where one language states a figure the
  other dropped.
* The gate also checks the version the CLI reports and the two tag pins, the
  generated contract index, that the CLI prints the same bytes under two
  different hash seeds, and that no schema file on disk is unreachable from
  the registry.
* `docs/CONTRACTS.md` is generated from the schemas that ship. `docs/CONCEPTS.md`
  is new: the vocabulary, a five-minute tour that runs offline, and the command
  index that used to live in the README.
* Both READMEs were rebuilt as a landing page rather than a manual, with real
  CLI output captured from this release by `scripts/cli_transcripts.py`
  rather than pasted from a terminal.

### What a hostile read of the closed state found

The last thing done before the tag was to read everything again as a reviewer
looking for overstatement would. Four of the eighteen findings were claims this
project does not keep, and those are the ones worth naming.

* **The published line count was measured over two thirds of the tree.** The
  list of areas in `scripts/figures.py` was written at 1.0 and no package added
  after it was ever added to the list, so it covered 103 of 161 Python files
  while `figures.json` labelled the total "every Python file in the
  repository". The areas partition the tree now and the count is checked
  against a fresh walk. 42,821 becomes 61,736.
* **The judged-tier figures were published without the disclosure their own
  harness requires.** They measure the pipeline replaying cassettes recorded
  from a deterministic stand-in grader, not a language model.
  `evals/agents/build.py` says that has to be stated wherever the numbers are;
  it was stated nowhere. Both READMEs carry it now.
* **The console blocks labelled "real output" had been edited**: a truncated
  JSON array the tool does not emit, a "7 more routes" line it does not print,
  and a coverage block deleted three lines after the prose says coverage is
  always printed. They are verbatim now, from fixtures whose recipe is in
  `docs/CONCEPTS.md` and whose digests a test re-derives.
* **Seven of the fourteen published contracts were frozen by nothing**, while
  three documents said all of them were. All fourteen are frozen.

Plus: a threat model quoting detection figures two releases stale, a SECURITY
page still supporting 1.0.x, a corpus line that added up to 63 of 64, fifteen
design-note rows pointing up to 412 lines off, twelve figures in prose that no
gate could keep current, and a survival matrix that nothing regenerated. Each
one is either fixed and derived, or fixed and gated.

### Closing pass: the snapshot made to match its own scope

The last work under this version number was a read of the tree against what it
actually is - a local repository with no website, no remote, no package index
entry and no published image - looking for every place it said otherwise. No
capability was added or removed.

* **The fuzz harness could not be imported on a platform without `resource`,
  and the suite imports it** (DEF-103). Collection was interrupted there, all
  41 tests in `tests/test_fuzz_regressions.py` went missing, and the only
  thing that noticed was the release gate comparing 3 161 tests in
  `figures.json` against 3 120 collected without being able to say why. The
  import is conditional now; `RLIMIT_AS` and `SIGALRM` enforce two of the
  fuzzer's four promises, so every run summary names the oracles the platform
  could not enforce rather than printing "0 property violation(s)" as though
  four still held.
* **The export written for an external website is gone**, with the website it
  fed: `site-data.json`, `scripts/export_site_data.py`, the `site-data` make
  target and the release check that regenerated it. The one property that
  chain carried and nothing else did - that the CLI prints the same bytes
  twice - is now `scripts/cli_transcripts.py` plus a gate that runs it under
  two `PYTHONHASHSEED` values and diffs the results. D-190 is retired; D-234
  points at the local script.
* **Self-references to a repository, a website, a registry and a published
  image were removed** from both READMEs, `pyproject.toml`, `CITATION.cff`,
  `SECURITY.md`, `CODE_OF_CONDUCT.md`, `Dockerfile`, `docs/FIGURES.md` and
  this file. What stays is every mention of GitHub that is *product*: the
  `github` connector, its tests, the SARIF output consumers read, and the
  action definition under `.github/actions/`.
* **The tree was made buildable without polluting itself**: `make package`
  builds the wheel and sdist into `dist/` and checks what went into them,
  `make source-archive` writes a source zip from what git tracks - refusing to
  run where this directory is not the root of its own repository, because
  `git archive` would otherwise archive whatever repository contains it - and
  `make clean` removes `build/`, `dist/`, `*.egg-info` and the temporary
  captures.
* **Seven defects, found by the closing pass itself**: six entries,
  DEF-103 to DEF-108 in [`docs/defects.json`](docs/defects.json), one of which
  counts twice because it was one mistake made at two sites.

  Four of the seven were in the shipped tool. The platform separator reached
  the ML-BOM component name, the receipt's subject rows, the governance
  dossier and the connector's listing, so a signed document carried the
  producer's absolute path and two machines could not compare what they
  produced. The tensor table clipped a number mid-digit on a phone, so 65 536
  rendered as `65.5` - a truncated number that still looks like a number.
  Standard output took its encoding from the locale, so `--lang es` redirected
  to a file wrote UTF-8 on one machine and cp1252 on another.

  Three were in the apparatus rather than the product: the fuzz harness, which
  could not be imported off POSIX and took the whole suite's collection with
  it; the action entrypoint, which flattened one input out of five before
  writing them into `GITHUB_OUTPUT`; and the screenshot generator, which had
  never actually switched language, so the English and Spanish captures of the
  governance panel were byte-identical and each README was showing the
  other's.
  The screenshot pass earned its keep three times in one release: the phone
  capture nothing displays is what showed the clipped number, the console
  watcher refused a `Permissions-Policy` header added later in the same pass
  that named a feature no browser implements, and two files it wrote with
  identical sizes are what exposed the language bug.
* **Two gates that did not exist.** `make types` (D-242) holds the 79 modules
  mypy already agrees with and refuses a stale exemption as loudly as a new
  error; `tests/test_action_entrypoint.py` runs the composite action's
  entrypoint for real, which nothing had ever done.
* **The two gates that had never actually been run here were run** - `make
  benchmark` against picklescan 1.0.5, modelscan 0.8.8 and fickling 0.1.12,
  and `make nightly-real` against torch, onnx, h5py and safetensors with
  skipping disallowed - and both found something.

  Every detection figure in the comparison reproduced exactly: 42 of 42 on
  the pickle family under the allowlist, 32 under the denylist, 11 of 11 on
  the gadget shapes no denylist enumerates against 1, and the one false alarm
  this tool has on `real_full_module.pt` still counted against it. What did
  not reproduce was the timing, and the reason was a defect: `read_at_most`
  allocated its whole 512 MiB ceiling for every pickle it read (DEF-110,
  D-160b). On Linux that allocation is lazy and free, which is why five
  releases and a Linux-only CI job never saw it; here it cost 78 ms an
  artifact. The module exists so that a file cannot decide how much memory the
  auditor uses, and it was spending the ceiling on every file regardless of
  size. Median per artifact: 70.0 ms to 0.568 ms.

  The nightly found DEF-109: its only check that the trojan's callable is
  named asserted `posix.system`, which is the POSIX spelling of a name that
  belongs to whichever platform wrote the artifact - `nt.system` on Windows.
  It failed against a report that was entirely correct. The name is derived
  from the interpreter now, and the test gained the assertion that was
  missing and matters more: that the **denylist** flags it too, since the
  allowlist fails closed and would refuse it either way.

## [2.1.0] - 2026-09-11

The release that makes the output something other people can build on, and
that closes three places where the tool decided by name what it should have
decided by content.

### Added

* **A coverage matrix per surface.** `load_time_execution`,
  `archive_structure`, `artifact_metadata`, `raw_tensor_content`,
  `behavioral_safety`, `organizational_facts` - each with a state
  (COMPLETE / PARTIAL / FAILED / NOT_ASSESSED) and a written reason. A surface
  nobody undertook to read cannot make a verdict inconclusive; one that was in
  scope and failed still does. `fully_read` is derived from it, so every
  consumer written against the old contract keeps working.
* **Policy-as-code.** A versioned, digested document that consumes claims and
  returns ALLOW, DENY or REVIEW with a proof: every rule, every subject,
  whether it matched, and the evidence that made it. `actaira policy check`
  and `actaira policy show`. Exceptions carry owner, reason and expiry or the
  document does not load.
* **The assurance receipt.** A signed statement of observed state, verifiable
  offline by a third party with neither the artifacts nor this tool.
  `actaira receipt issue` and `actaira receipt verify`. Not a certification and
  not a score: a test greps the finished document for "score", "grade",
  "rating" and "percent".
* **Model bundles.** `actaira bundle` resolves a model repository and reports
  what its files say about each other: `auto_map` and the modules it names, a
  repository that answers `trust_remote_code` for you, shards the index
  promises and the repository lacks, weight files no index mentions, an
  adapter with no base digest, a chat template carrying Jinja control flow.
  Eight rules, `ACT-BDL-001` to `ACT-BDL-008`.
* **Agents, tools and MCP servers.** `actaira agent check`, `agent bom` and
  `agent diff`. Capability rules over the combinations that are the actual
  risk - untrusted input beside an unapproved action, a secret reader beside
  an egress path, an MCP server pinned to a tag. Eight rules, `ACT-AGT-001` to
  `ACT-AGT-008`.
* **Seven versioned JSON Schemas**, shipped with the package and printable
  with `actaira schema`. `docs/COMPATIBILITY.md` states what a version
  promises; `tests/test_schemas.py` enforces it against a frozen list of each
  v1's required fields.
* **TSA chain validation** against anchors the caller supplies
  (`--tsa-trust-store`). Three states: trusted, untrusted, unknown. No bundled
  trust store, because choosing roots is the verifier's decision. Revocation
  is still not checked, and the answer says so.
* **`make release-check`**, which refuses a release whose parts disagree:
  version, changelog, figures, rules, schemas, design notes, README parity and
  the shipped examples.

### Changed

* The threat model is split per component. It had gone on saying "exactly one
  outbound connection" for a whole release after the connectors shipped.
* A clean PyTorch checkpoint now PASSes. It used to be INCONCLUSIVE, because
  `ACT-ZIP-007` fires on every archive that carries storage blobs.

### Fixed

* **DEF-59.** The archive member gate opened `.pkl`, `data.pkl` and the
  ambiguous suffixes and left everything else closed, so a payload named
  `archive/data/0` - what PyTorch calls a storage blob - produced no pickle
  finding and no imported callable. Members now have their first 64 KiB
  decompressed and disassembled, and a name that says storage over bytes that
  say pickle is `ACT-ZIP-008`, HIGH.
* **DEF-60.** `collect_paths()` filtered a directory walk by file extension,
  so a pickle called `notes.txt` was not scanned, not reported and not counted.
* **DEF-61.** One `fully_read` boolean had to mean both "every parser
  finished" and "the whole file was examined", so every clean checkpoint
  exited 3 and the only available response was `--allow-inconclusive`, which
  also hid the artifacts whose headers would not parse.
* **DEF-62.** `read_bytes()[:LIMIT]` in four places, which is not a limit: the
  whole file is in memory by the time the slice runs. Two parsers had no limit
  at all.
* **DEF-63.** A self-signed certificate was returned as its own issuer, so a
  path walk looped to the depth cap and reported the wrong reason. Found
  before release by the negative-control test written alongside the module.
* A missing `2.0.0` entry in this file, which `make release-check` found on
  its first run.

## [2.0.0] - 2026-09-10

Executable controls, the Article 50 marking engine, a judged-evidence tier and
the discovery layer.

### Added

* **Compliance as code.** A control contract with four outcomes (SATISFIED,
  NOT_SATISFIED, INCONCLUSIVE, NOT_APPLICABLE) and three methods
  (DETERMINISTIC, JUDGED, GENERATED), a registry, and an engine that turns a
  control raising into `ACT-CTL-001` rather than into a crash. Every control
  carries its own boundary - what it does and does not cover - in both
  languages.
* **Article 50 marking.** Reading and writing IPTC `DigitalSourceType` in PNG
  and JPEG with the standard library alone, plus the eval that measures
  whether a marking survives a real pipeline: 0 of 32 naive transformations,
  8 of 8 metadata-aware ones.
* **A four-tier coverage ladder** over the obligation catalogue:
  machine-checkable, generatable, evidence-judged, organizational. Each
  obligation outside the first tier carries a written reason why.
* **A judged-evidence tier**: retrieve, judge, verify every citation, abstain
  when a judgement cannot be grounded. A cassette provider makes the whole
  pipeline deterministic and offline.
* **Seven connectors** - filesystem, HuggingFace, GitHub, OCI, S3, MLflow and
  a URL manifest - that enumerate and stage without concluding.
* **Bilingual everything**: two READMEs, two catalogues, generated diagrams.

### Fixed

* **DEF-54 to DEF-58**, two of them security-relevant and shipped: `urlopen`
  followed an `https:` to `http:` redirect without recording the serving host,
  and `HTTPRedirectHandler` forwarded `Authorization` across hosts - exactly
  the GitHub-asset and HuggingFace-LFS path.

## [1.0.0] - 2026-09-10

The two gaps the 0.2.0 notes named as next - time anchoring and key rotation -
are closed, and the repository is brought up to the standard the code is held
to.

A final adversarial pass over this release, by an engineer reading the code
for the call that never happens and by a reader looking at the tool's own
output, found one way past the scanner that reached `PASS` with exit 0 under
both policies, one that removed an archive member from the analysis entirely,
and two places where the project claimed more than it had measured. All of
them are fixed, pinned and in `docs/defects.json` below, and they are the
reason this release also carries a `Fixed` section about itself.

### Added

* **RFC 3161 time-stamping, optional and never required**
  (`src/actaira/attest/timestamp.py`, D-27). `actaira attest --tsa-url URL`
  asks a timestamp authority to stamp the manifest and stores the token as
  `manifest.tsr` inside the package; the manifest then reads
  `time_anchor: "rfc3161"` and carries the authority's URL, the genTime and
  the token serial. Without the flag nothing changes and the manifest still
  reads `time_anchor: "none"`.
  * The `TimeStampReq` is built as DER by hand and the `TimeStampResp` is
    parsed and checked here. No new dependency: `cryptography` is still the
    only one, used for X.509 and signature primitives rather than for ASN.1.
  * `verify` checks the imprint against the manifest it sits beside, checks
    the token's own CMS signature against the certificate the token carries,
    and checks that the genTime and serial the manifest advertises are the
    ones the token actually holds.
  * What is **not** checked is stated rather than implied: no trust store
    ships with Actaira, so the authority's certificate chain is reported as
    `tsa_chain: "not_verified"` with a warning, exactly as an unanchored
    signing key is reported as `embedded_key_only`.
* **Key rotation, retirement and revocation** (`src/actaira/attest/keyring.py`,
  D-28). A keyring now holds several keys, each with a status (`active`,
  `retired`, `revoked`) and the window it was allowed to sign in.
  * `actaira keygen --rotate` retires the current key, generates a new one and
    keeps the old public key in the ring; the old private key is archived
    beside the new one rather than deleted.
  * `actaira keygen --revoke KEY_ID` marks a key revoked.
  * `verify` accepts a signature from a retired key when the moment of signing
    falls inside that key's window, and refuses one from a revoked key at any
    moment. The moment comes from the RFC 3161 genTime where there is one and
    from the package's own timestamps otherwise; the result says which, as
    `time_evidence: "rfc3161"` or `"self_asserted"`.
  * Status from a keyring the verifier supplies overrides the copy inside the
    package, because a rewritten package rewrites its own keyring.
* **`scripts/figures.py` and `make figures`**, writing `docs/FIGURES.md` and
  `figures.json`. Every published number is measured from the repository:
  tests as pytest collects them, lines per area split into code, docstrings and
  comments, catalogue rules per family, corpus artifacts built at measurement
  time, and the eval, benchmark and fuzz figures read from the JSON their
  harnesses write. This exists because the README drifted from reality twice.
* **`CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CITATION.cff`**
  and this changelog.
* **CI that runs the gates it claims to.** Lint, tests on 3.11, 3.12 and 3.13,
  the evaluation harness, a short fuzz run and the comparison benchmark, with
  every measured JSON published as a build artifact; a job that installs from
  the built sdist in a clean environment and scans with it, so "it is
  installable" is a checked claim; and a release job on a `v*` tag that builds
  the sdist and the wheel and checks them.

* **`docs/defects.json`, the defect ledger.** One entry per defect, with what
  broke, which of ten mechanisms caught it and the node ids of the tests that
  keep it caught. `make figures` counts it and checks every test it names
  against what `pytest --collect-only` returns, and
  `tests/test_defect_ledger.py` makes the same check on every commit. This
  exists because the defect count was the one figure in the README that no
  command produced: it was typed from a narrative table, which is exactly the
  failure mode the rest of `make figures` was built to prevent.
* **`ACT-PKL-011`**, reported when a callable is handed a byte string that is
  itself a pickle. The payload is disassembled with the same machinery,
  bounded by `MAX_NESTED_DEPTH = 4`, and its findings are merged with the
  location carrying the nesting (D-35).
* **`ACT-PKL-012`**, reported when the bytes after the final `STOP` are zero
  padding. Padding never reaches the unpickler, so it is `INFO` and does not
  fail an artifact, but it is stated rather than passed over in silence.
* **A governance section in `make figures`**, so the four numbers the README
  quotes from the obligation catalogue (21 obligations, 15 outside what this
  tool can show, zero fully supported, and the split by role) are measured
  from `catalog.py` rather than typed. For the one module whose entire
  argument is "do not take a number on trust", that was the wrong place to
  leave a gap.
* **`make screenshots`** (`scripts/screenshots.py`) regenerates every image in
  the README from a running server, and fails on any console error, page error
  or failed request during the capture, which makes the screenshot pass a
  smoke test of the front end and of its Content-Security-Policy.
* **`tests/test_readme_parity.py` and `tests/test_design_notes.py`.** The two
  READMEs are checked for identical section structure, identical images, links
  that resolve and no em or en dashes; the design-note table is checked
  against the notes actually written in the code, after eight of them, D-29 to
  D-36, turned out to be missing from it.

### Fixed

* **`torch.storage._load_from_bytes` was on the allowlist**, catalogued as
  tensor reconstruction. Its body is
  `torch.load(io.BytesIO(b), weights_only=False)`: a full unpickler with the
  safe mode explicitly off. A pickle whose only import was that callable, with
  a gadget in the byte operand it is handed, reached `PASS` with exit 0 under
  both policies, and `tests/test_policy.py` asserted the entry was correct.
  The entry is gone and the test is inverted, but the shipped fix is larger:
  the abstract stack now carries byte literals and tuples, the resolved
  callable name is written onto the stack so `REDUCE` knows what it calls, and
  the bytes any nested loader is handed are disassembled as the pickle they
  are.
* **A protocol 2 payload handed to a nested loader could not be followed.**
  Protocol 2 has no byte-string opcode, so the pickler writes bytes as
  `_codecs.encode(text, "latin1")` and the payload arrives as the result of a
  call. That downgraded a known gadget to an unknown one for the price of
  passing `protocol=2`. The scanner now reconstructs the byte string from that
  call, which is the pickler's own documented inverse.
* **One byte after `STOP` removed an archive member from the analysis.** An
  ambiguously named member was kept only when its bytes looked like a pickle
  at both ends, so appending a byte made it fail the tail check and be dropped
  with a bare `continue`: no rule, `fully_read` still True, verdict `PASS`.
  Every member on the list is now disassembled and the decision is made on
  what the disassembly found, with members that import nothing, call nothing
  and fail to parse recorded in `metadata["members_not_pickle"]` instead of
  vanishing.
* **Two package members under one name defeated the manifest.** A zip may
  carry the same name twice and `read` returns the last one, so an unsigned
  member could hide behind a name the manifest covered. The verifier already
  refused it; nothing pinned that, and now
  `tests/test_package_verify.py::test_two_members_under_one_name_are_refused`
  does.
* **The assessment printed a capability as though it were evidence.** The
  catalogue's "what Actaira provides" lines were printed under the word
  *provides* for every applicable obligation, evidence or none, so a run that
  established nothing read like a run that had. Obligations with no evidence
  now say so and put the capability in the conditional; obligations with
  evidence name each artifact, its digest and its verdict, so the claim is one
  a reader can check.
* **Tensor storages inside a legacy torch container were rated MEDIUM.** A
  nested stream cannot see the container it is in, so every checkpoint written
  before torch 1.6 carried a yellow line for using the mechanism its own
  format documents.
* **The most dangerous callable in an artifact could render neutral grey.**
  The interface coloured the imported-callable chips from the outer stream's
  disassembly alone, so `posix.system` imported inside a nested payload had no
  judgement at all. The chips are now judged from the findings, which cover
  every stream, with the trace filling in what they do not name.
* **Two findings from two different streams looked like one finding reported
  twice.** The text report printed the rule and not the location; it now
  prints the part of the location that is not the artifact itself, so a
  finding from `archive/data.pkl` or from a nested payload says so.
* **The concatenated-stream budget failed open.** The trailing-stream walker
  stops after eight pickles and simply left the loop: no finding, `truncated`
  never set, `fully_read` still True. A hostile review turned that into a
  115-byte file with an empty findings list, `max_severity` None, `PASS` and
  exit 0 under both policies, whose ninth stream runs `os.system` in any
  consumer that loads more than one object: the torch legacy magic number to
  suppress the concatenation finding, eight one-byte pickles to exhaust the
  budget, and the gadget behind them. `ACT-PKL-013` now reports it and marks
  the artifact unread, which is what the `MAX_OPCODES` path a few lines above
  had been doing all along.
* **A `MARK`-built tuple kept only its last element.** `stack_before` is
  listed bottom to top, and the walk read every entry as though it sat above
  the mark. `TUPLE`, which is what a pickler emits for more than three
  arguments, therefore produced a one-element tuple holding the last argument,
  so a payload handed to a nested loader in any position but the last was
  invisible to the nested-loader check.
* **`GLOBAL`'s two fields were split from the left.** `pickletools` joins them
  with a space, so a module name containing one had its first token read as
  the module. Not exploitable, since such a module cannot be imported, and
  fixed because a scanner that reports a callable the file does not name is
  wrong in the direction that matters least until the day it is not.
* **`docs/FORMATS.md` was missing four rules**, `ACT-PKL-010` to `-012` and
  `ACT-ZIP-006`, including the one these notes lead with. Every SARIF finding
  sets its `helpUri` to that document, so a missing rule is a link that lands
  on a page which does not mention what the reader clicked on.
  `tests/test_formats_doc.py` now checks the table against the message
  catalogue in both directions.
* **`INST` imported a callable and was never judged.** It carries module and
  name inline exactly as `GLOBAL` does and reaches `find_class` at load time
  exactly as `GLOBAL` does, but it lived only in `EXECUTION_OPCODES`, where it
  was counted and never handed to the policy. Twenty-seven bytes of protocol
  0, `(S'echo PWNED'\nios\nsystem\n.`, therefore ran a denylisted callable and
  passed under both policies with a single INFO line. This is the plainest
  defect in the ledger and it survived every other mechanism: the design note
  at the top of the module enumerates the import primitives, and the list was
  short by one.
* **A tail the walker could not measure was dropped in silence.** Real
  `pickle` reads `I\x00\n.` as the integer 0 followed by `STOP`;
  `pickletools.genops` raises on it. So the trailing-stream walker could not
  compute that stream's length, gave up, and returned, while the parse error
  that would have shown it was suppressed by the torch legacy exemption. A
  48-byte file with an `os.system` gadget behind that divergence reached
  `PASS` with exit 0, and a repeated-load consumer ran it. The exemption is
  now bounded to the region where storages actually live, and that bound is
  measured rather than assumed: `torch._legacy_save` writes five pickles and
  then the raw storages, which is what a checkpoint torch wrote shows.
* **A duplicated `D-34`.** Two unrelated design notes carried the same
  identifier; the web-routes note is now `D-36`.

### Changed

* Package `format_version` is now **2**. The only difference is that a manifest
  may carry a `timestamp` block, and a package may carry `manifest.tsr`.
  Packages written by 0.1.0 and 0.2.0 still verify, and a keyring row without a
  status or a validity window is treated as unconstrained rather than refused.
* `attest` signs with the active key from the keyring beside the private key,
  and embeds the whole public keyring in the package, so a verifier reading one
  package can date what an earlier key signed.
* `keygen` prints the keyring next to the key it loaded or created.
* The verify result gained `time_anchor`, `time_evidence`, `timestamp`,
  `key_state` and `key_status_source`, and two checks:
  `timestamp_matches_manifest` and `signing_key_in_validity`.
* `make lint` covers `scripts/` as well, and `make all` ends with `figures`.
* The `Development Status` classifier moves from `4 - Beta` to
  `5 - Production/Stable`.

* The README figures are corrected and each one now names the command that
  produces it. The benchmark table gains a `declined` column, because a tool
  that declines an artifact is not wrong about it, and the corpus and test
  counts are the current measured ones. Both languages, checked by a test.
* Both READMEs gain a section on where the tool sits in an AI governance
  programme: the five-command cycle, what the evidence dossier contains, and
  the three things the governance layer refuses to do.

### Security

* A package whose manifest claims a time anchor it cannot show is now refused,
  as is one carrying a token the manifest does not declare. A claim a package
  contradicts is worse than no claim.
* Editing a manifest and re-signing it with the same key no longer produces a
  package that verifies, if that package was anchored: the timestamp covers the
  manifest independently of the signature. This is the property the anchor was
  added for, and `tests/test_attest_anchor.py` pins it.
* The one function in Actaira that opens a network connection refuses any URL
  that is not `http` or `https`, and reads a bounded number of bytes. A
  `file://` TSA URL would otherwise have turned a timestamp request into a
  local file read.

### Verified

* **1439 tests**, ruff clean over `src tests evals fuzz scripts`, one runtime
  dependency, 62/62 eval expectations met, 450,000 fuzz cases with zero
  property violations, and the benchmark re-run against picklescan 1.0.5,
  modelscan 0.8.8 and fickling 0.1.12 on the current corpus.
* The nested-loader fix is checked both ways: the crafted artifact that
  reached `PASS` now fails with the inner `posix.system` named, and
  `torch.storage._load_from_bytes` appears in no artifact the real torch
  writes, which is what made removing it from the allowlist safe.
* The RFC 3161 work is checked against implementations this project
  did not write: the request encoder is compared byte for byte against
  `openssl ts -query`, the parser against responses OpenSSL wrote, and the test
  suite's own authority is handed to `openssl ts -verify` when OpenSSL is
  installed.
* Not verified, and stated here rather than left to be discovered: no timestamp
  was obtained from a public authority during development, because the machine
  the work was done on had no route to one. Every RFC 3161 test runs against
  captured or locally issued tokens.

## [0.2.0] - 2026-09-10

Measured against the other scanners, fuzzed, and validated against artifacts the
real serialisers wrote.

### Added

* **Comparison benchmark** (`evals/benchmark.py`) against picklescan, Protect
  AI's modelscan and Trail of Bits' fickling, on identical artifacts in one
  process. Head to head on pickles: actaira 36/36 with 1 false alarm,
  picklescan 22/36, modelscan 20/36, fickling 32/32 with 10 false alarms. On
  the `gadget-unknown` family, where no tool had the callables on a list:
  actaira 11/11, its own denylist mode 1/11. The harness prints the artifacts
  another tool catches and Actaira misses on every run, empty or not.
* **Validation against real artifacts** (`evals/corpus/real.py`) written by
  torch 2.14, safetensors 0.8, onnx 1.22 and h5py 3.16, cross-checked field by
  field against those libraries' own readers.
* **Fuzzing** (`fuzz/fuzz_targets.py`): 2 277 000 cases across 9 targets on two
  engines, 86 to 100 per cent line coverage per parser.
* **RFC 6962 consistency proofs** and `attest --continue` / `verify --extends`,
  so append-only growth is something the holder of an old root can check rather
  than something the log promises (D-25, D-25b, D-26).
* **Opcode-level disassembly** surfaced in the review interface, so a pickle
  finding is evidence a reader can inspect rather than an assertion (D-21).
* SARIF and JUnit reports, a composite GitHub Action definition under
  `.github/actions/`, a pre-commit hook definition and a Dockerfile. All four
  are integration definitions shipped in the tree; none of them is a service
  running anywhere.

### Fixed

* torch's pre-1.6 format is legitimately four concatenated pickles, so the
  trailing-stream rule fired on every checkpoint written before 2020. The
  format is now recognised by its documented magic number, with a negative
  control proving the exemption hides no gadget.
* Fourteen unique bugs found by fuzzing, all fixed: a 24-byte input that took
  73 seconds and built 8.1 million objects, three that crashed `--json`, and
  five places where an artifact that could not be fully read still reached
  `PASS`.
* Two defects in this release's own work, found before it shipped: the
  benchmark counted artifacts a tool had declined inside the detection
  denominator, which flattered its author every time; and the first consistency
  prover and verifier were both hand-derived, both self-consistent, and both
  wrong for every power-of-two size.

### Verified

* 906 tests, ruff clean, one runtime dependency.

## [0.1.0] - 2026-09-10

First release. Static inspection, ML-BOM and signed attestation.

### Added

* **Inspection without loading**: pickle protocols 0 to 5, PyTorch zip
  checkpoints, safetensors, ONNX, GGUF, NumPy `.npy` and Keras/HDF5. Nothing is
  ever loaded or executed; the pickle path disassembles the opcode stream with
  `pickletools.genops` and never constructs an `Unpickler` (D-05).
* **The import policy, both ways round** (D-02). A denylist fails open, so the
  default is an allowlist of the callables tensor deserialisation actually
  needs, and the denylist is available for comparison. Over the 56-artifact
  generated corpus the allowlist caught 41 of 41 malicious artifacts with 0
  false failures on the benign half; the denylist caught 31; 10 were caught
  only by the allowlist.
* **CycloneDX 1.6 ML-BOM** built only from values actually parsed (D-16).
* **Signed attestations**: hash-linked entries, an RFC 6962 Merkle tree and
  Ed25519 signatures, in a package a third party verifies offline (D-11 to
  D-14).
* **Verification that separates integrity from identity** (D-15). A package
  always carries its own public key, so integrity can always be checked and
  proves nothing about who signed it; that case is reported as
  `embedded_key_only` with a warning, and `--require-trust` turns it into a
  failure.
* A bilingual message catalogue where rule identifiers are the stable interface
  (D-07), an evaluation harness (D-19, D-20), a local review interface (D-17,
  D-18), and a CLI whose exit codes are part of the contract, with
  `INCONCLUSIVE` kept separate from success.

### Fixed

Five defects found before release, all five by an adversarial read of the
code rather than by a test that happened to fail: a seven-byte first-byte gate
that let a protocol 0 gadget through a checkpoint as a clean `PASS`; a
`torch.*` prefix that allowed its own executable siblings; an unbounded zip
member read; duplicate zip member names defeating manifest coverage; and a
pickle concatenated after the first `STOP` going unanalysed. All fixed, and
all pinned by regression tests and corpus cases by 1.0.0: the duplicate-member
one was refused by the verifier from the start but had nothing holding that
down until then, and `docs/defects.json` records which test pins each.

### Verified

* 478 tests, ruff clean, one runtime dependency.

## On the versions in this file

Every heading above is a **project version**: a point at which the work was
consistent with itself and the release gate accepted it. The repository is now
public, at https://github.com/marcosmatalab/actaira, and there is still no package index entry and no release
page - so a version here is a point in that history and not a thing you can
download by name. Comparison links will appear when there are tags to compare;
a row of them pointing at tags that do not exist would be the first false
claim in a file whose own convention is that numbers are measured rather than
remembered.

What each version means is therefore what it says: 0.1.0 and 0.2.0 were
development milestones in one line of work, 1.0.0 was the first version the
gate accepted end to end, and 2.2.0 is the version in `pyproject.toml`,
`src/actaira/__init__.py`, `CITATION.cff` and `actaira --version`, which the
gate checks against each other. To compare two of them, compare the source
snapshots; there is no other artifact to compare.
