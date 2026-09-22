# How this repository is held up

A tool that decides whether other software is trustworthy has to answer the
question about itself first. This page is what that answer looks like from the
inside: the gates, the ledger, and five defects worth naming.

The counts are in [`FIGURES.md`](FIGURES.md), measured by `make figures`, and
in the README under a contract that refuses a tree where any of them has
drifted. They are not repeated here.

---

## The gates

```bash
make lint            # ruff
make types           # mypy, as a ratchet
make test            # the suite
make test-cov        # the suite, with the coverage floor
make types           # the mypy ratchet, outside the gate on purpose
make figures         # regenerate the measurements from the repository itself
make contracts       # the contract index, from the schemas the package ships
make rules           # docs/RULES.md, from the rule packs the package ships
make design-notes    # every design-note row against the line that argues it
make release-check   # refuse a tree whose parts disagree with each other
make package         # build the distributions and assert what is inside them
make all             # the gate a change is held against
```

No step is allowed a `|| true`. A step that cannot fail is not a check.

This list carried six more entries for two releases after the targets behind
them went to tag v2.3.0 with the scanner they measured: `eval`,
`eval-marking`, `benchmark`, `fuzz`, `screenshots` and `diagrams`. A page
naming a command the tree does not have is the defect this repository's own
gate exists to refuse, so the gate refuses it now: `release_check.py` reads
every make target written inside code on a document and fails on one the
Makefile does not define.

`.github/workflows/ci.yml` runs the same gates on every push and every pull
request, across Python 3.11, 3.12 and 3.13, plus `release-check` and a
re-measurement of the figures that has to leave no diff.

---

## The release gate is not a linter

`make release-check` compares facts recorded in two places and fails when they
have come apart. Each drift it looks for is one this repository has actually
had:

- the version against the changelog, the citation file and what
  `actaira --version` says from the installed distribution;
- every figure the READMEs state against the code or harness that produces it;
- every rule against both language catalogues and the format table;
- every schema against the module that emits it, and every schema file on disk
  against the registry that names it;
- every design note in the code against the table that indexes it, including
  the line number it points at;
- the CLI's commands against the documentation that lists them;
- the two READMEs against each other, heading structure and images;
- the defect ledger against the tests it names;
- three CLI commands run twice under different hash seeds, byte for byte;
- every image in `docs/img/` against the document that displays it;
- every finished document against the words `score`, `grade`, `rating` and
  `percent`;
- every path `pyproject.toml` and `MANIFEST.in` name against the tree, because
  ruff and setuptools both answer a miss with silence;
- every fixture under `tests/fixtures/` against the suite that is supposed to
  read it;
- every `make <target>` a document names against the Makefile.

Two gates live in the suite rather than here, because they are properties of
the code rather than agreements between documents: `tests/test_reachability.py`
fails on a module no command can reach, and `tests/test_layering.py` fails on
an import the architecture does not allow. The second is an ALLOWLIST of edges
and not a list of prohibitions: a prohibition list is silent about the package
nobody thought of, and an allowlist fails on the edge it has never seen.

---

## Type checking, as a ratchet

`make types` runs mypy over `src/` and holds every module that passes. The
exemption list is empty: all modules type-check with no errors, and there is
not one `# type: ignore` in `src/`.

That distinction is the point. Silencing a checker and satisfying it look
identical in a green build and are opposites. When the list was emptied, the
48 errors it had been hiding turned out to be four different things:

- **Eleven were one wrong declaration.** The message catalogue was annotated
  `dict[str, dict[str, str]]` while every three-level read in the tree
  contradicted it. Not a loose type: a false one.
- **Two were bugs waiting for an input nobody had sent.** A certificate whose
  `signature_hash_algorithm` is None reached a verify call that cannot take
  None. And a list append chose its target with a conditional expression, so a
  document that was present but falsy would have been filed as missing.
- **Several were one name doing two jobs** in one function: a `result` that
  was a VerifyResult in one branch and a PackageResult in another, loop
  variables reused across loops over different types.
- **The rest were the checker being right about what the code already meant,**
  and the fix was to say it: a table of hash constructors annotated as
  constructors, a function that reads its sequences annotated as reading them.

The gate fails in both directions. A module not on the list must have no
errors, and a module on the list must still have errors, because a module
cleaned up and left on the list is a stale exemption, and a stale exemption is
how an exclusion list becomes a place things go to hide.

---

## The defect ledger

[`defects.json`](defects.json) records every defect found in this repository:
what it was, what it did, what found it, and the regression test that now
holds it down. `make figures` checks every test the ledger names against what
pytest actually collects, so a renamed test is reported by name rather than
leaving a total that still looks healthy.

148 defects have been found here, by 20 distinct mechanisms, and every one of
them was found by a mechanism that can fail. 0 still open.
55 were never in a released build and are marked as such rather than dropped.
Every entry is held down: 29 pinned by a named test, and 103 by a written note,
where a named test would be a weaker copy of what the linter or the gate
already does.

Those six numbers are measured by `make figures` and refused by the release
gate if they drift, exactly as the figures on the README are. They live here
rather than there because a defect count is not what a reader should meet
first: it says how hard the tool has been looked at, which is a fact about the
engineering and not a fact about the product.

Two rules keep the ledger from flattering itself:

- **Defects found in the measuring apparatus are listed too**, marked as such.
  A defect in the eval harness is not a defect in the shipped tool, and both
  facts are recorded rather than one being dropped.
- **Defects that never reached a release are kept and marked**, not deleted.
  Dropping them quietly would be the same error as an inflated denominator.

One entry is pinned by a written note rather than by a test: a lint failure
whose regression test is ruff. `make lint` runs on every commit and is one of
the steps in `make all`, so the pin is real; a unit test asserting that a
`noqa` sits on the right line would be a second, weaker copy of what the
linter already does.

---

## Five worth naming

From [`../CHANGELOG.md`](../CHANGELOG.md).

**The seven-byte gate.** A zip member was sent to the pickle analyser only if
its first byte was in a hand-written set of "pickle start" opcodes. A protocol
0 pickle begins with `I`, which was not in the set, so a checkpoint carrying
`posix.system` came back PASS under both policies. The analyser was fine. It
was never called.

**`INST` imported a callable and was never judged.** It carries `module` and
`name` inline exactly as `GLOBAL` does, and reaches `find_class` at load time
exactly as `GLOBAL` does. It lived only in the execution-opcode set, where it
was counted and never passed to the policy.

**A time anchor reported as verified when it was not.** `ok` was computed as
"signature state is not *invalid*", which put "not verified" in the same
bucket as "verified", over a token sitting outside the signed manifest.

**`verify --extends` silently swallowed `--require-trust`.** The branch
returned before reaching the call that receives the trust flags, so a package
signed by an unknown key exited 0 with the hardening flag set.

**A cycle detector that answered the wrong question.** A three-colour walk
says *whether* a graph has a cycle, not *which*, and the repair that fixed the
colouring did not fix the report. It is now a bounded enumeration, pinned by a
differential test that compares every cycle it reports with brute force over
generated digraphs.

**One from the harness, not the tool.** The tamper check attested an artifact,
edited one entry inside the signed package, and asserted the edit was caught.
The edit set the verdict to the constant `"fail"`, so for artifacts already
recorded as failing it changed nothing: the "tampered" package was
byte-identical to the original, verification passed, and the harness counted
every case as a pass while some of them had tested nothing at all. The
mutation flips the verdict now, and a test asserts it can never rewrite an
entry to itself.

---

## The fourth form: a test that asserts a property that is not the one it protects

The section above names defects in the tool. This one names a defect in the
*checking*, and it is worth its own heading because it has now appeared four
times, always in a different subsystem, and it is the characteristic failure of
a project whose entire argument is rigor.

The shape is always the same. A test is written to protect a property. It
passes. The property it actually asserts is weaker than the one it was written
for, and often trivially satisfiable, so the test goes on passing through
exactly the change it existed to catch. It is worse than a missing test, because
a missing test is visible in a coverage gap and this one shows up green.

The four instances, because the shape is easier to recognise than to define.
The fourth is a variant the first three do not have, and it is called out at the
end: there the assertion was already exactly right, and what was wrong was the
tree it ran on.

**1. The privacy corpus, and the hash that was not a redaction.** The corpus
seeded high-entropy secrets into a session and asserted that none of them
appeared in the emitted trace. They did not appear, and the test passed. What it
was protecting was that a third-party value does not travel; what it asserted
was that a value does not travel *verbatim*. An unsalted digest of a guessable
name is an encoding, not a redaction: the value was reconstructible offline by
anyone who could guess the input, and the test could not see it because it was
looking for the plaintext. The property it should have asserted, and now does,
is that neither the value nor a digest a third party can reproduce reaches the
document (D-263).

**2. The network guard's meta-test, and the gate of six.** The guard closes six
`socket` entry points. The meta-test that proves the guard still bites exercised
one of them. It passed for as long as any one door was shut, which is to say it
would have passed with five of the six left open. The property it was protecting
was "the suite cannot reach the network"; the property it asserted was "the
suite cannot reach the network *through this one call*" (D-267).

**3. The published-contract test, and `additionalProperties`.** Every schema
here sets `additionalProperties: true`, deliberately, so a field can be added
within a major version. That makes the schema a *floor* and not a ceiling, and
it means a test that validates an emitted document against its schema cannot see
a field the contract never declared: the validator accepts it silently. The test
was written to check that the tool emits what it promises, and what it asserted
was that the tool emits *at least* what it promises. The fix walks the emitted
document rather than the schema, and fails on a key the provenance table does
not classify (D-268).

**4. The worm fixture that existed on one laptop, and the tree nobody receives.**
Phase S1's fixtures for the two 2026 npm worms carry a `.vscode/tasks.json`,
because that file is half of the attack and the report's "not read in this
release" list is what names the half `check` cannot see. A test asserted exactly
that: that `.vscode/tasks.json` appears in `not_read`. The assertion was right,
the property was the right one, and it passed - on a tree where `.gitignore`
excluded `.vscode/` everywhere and `git add -A` had silently skipped both files.
The property it was protecting was "the report names the half it does not read".
The property it asserted was "the report names the half it does not read *given
a tree that has it*", and no tree anybody else could obtain had it. Green on the
machine that wrote it; red on the first clean clone, which was CI.

This one is the variant, and the reason it gets a paragraph rather than a line.
In the first three, the fix was a stronger assertion: the person who wrote the
test could have written the better one that minute. Here the assertion could not
have been improved, because nothing was wrong with it. What was wrong was its
SUBJECT: every test in this suite reads the working directory, and the working
directory is not the artifact. No second assertion inside the suite reaches that,
because the suite is inside the thing being mis-measured. So the remedy is at a
different level, and it is two things: `tests/test_fixtures_are_published.py`
asserts that everything under `tests/fixtures/` is in git's index, which closes
the specific hole; and CLAUDE.md's rule 7 now runs the gate on a CLEAN CLONE OF
HEAD rather than on the working directory, which closes the class. The
working-directory run survives as an iteration shortcut and is explicitly not the
gate.

### What to do about it

There is no rule that prevents this, because the defect is a gap between what a
test means and what it says, and both are written by the same person in the same
minute. What works is a second assertion whose only job is to make an empty or
trivial pass impossible:

- **Assert the enumeration is not empty before walking it.** A loop over zero
  items passes every property inside it.
  `tests/test_no_aggregate.py::test_the_enumeration_is_not_empty` is this.
- **Plant the defect and assert the test catches it.** If the check cannot fail,
  it is not a check. `tests/test_release_check.py` does this for every gate,
  and `tests/test_reachability.py::test_the_graph_is_not_trivially_empty` does
  it for the import walk.
- **Ask what the test is running ON, not only what it asserts.** A suite that
  reads the working directory answers for a tree nobody else has. That is not
  fixable by a better assertion, because the suite is inside the thing being
  mis-measured; it is fixed by running the gate on a clean clone of HEAD, which
  is what rule 7 now says, and by asserting that the inputs a test reads are
  ones git will actually hand to somebody else.
- **When two places record one fact, do not write a test that referees between
  them.** That test passes for as long as somebody keeps the copies in step, and
  the property it is really protecting is that there should be one copy. Invert
  it: assert there is no second copy. Phase A did this twice, to the schema
  version and to the list of refused protocol keys, and both times the inversion
  removed the duplication instead of policing it.

One of these caught a live instance while phase A was being written. The check
that fails on a schema version written outside the registry shipped with a
regex that matched nothing, so it passed on a tree with a planted violation in
it. What found it was the planted violation, not review.

---

## Design notes

A design note names the file **and the line** that implements its decision.
[`DESIGN.md`](DESIGN.md) consolidates them into one table,
`scripts/design_notes.py` derives those line numbers, and the release gate
refuses a tree where they have drifted.

Where that file is follows from what kind of decision it is, and there are
exactly two kinds:

- **A decision about how something is built** is implemented by code, so its
  note lives in the module it argues about. This is almost every note.
- **A decision about what gets built** is implemented by `CLAUDE.md`, which is
  the only governance document and the thing that decides what exists, so its
  note points there.

That second clause is a rule and not an exception, and it is written narrowly on
purpose: it admits doctrine decisions only, and nothing else may point at
`CLAUDE.md`. A note about a data structure, a format, a gate or an algorithm
points at code even when the prose explaining it happens to sit in a document,
because what implements it is the code. The distinction is not where the
argument reads best; it is what a reader would have to change to reverse the
decision. Reverse a doctrine decision and you edit `CLAUDE.md` and the tree
follows. Reverse anything else and you edit the module.

D-269 is the only note of the second kind today: it decides that the subject of
this tool is what an agent can do rather than what one did, which is a decision
about what gets built and is argued in [`DESIGN.md`](DESIGN.md) section 11.

Two checks run in opposite directions: a note argued in the code and missing
from the table fails, and a row pointing at the wrong line fails. The suite
checks the file and not the line, because a row three lines off is still a
working reference and a test that failed on every edit would be noise. That
tolerance is right and it is not unbounded: before it was enforced, fifteen
rows were between 28 and 412 lines off, several landing on a blank line, and
one pointed into a different function entirely.

---

## What is not claimed

The suite is large and the gates are many, and neither of those is evidence of
correctness. What they are evidence of is that a specific set of properties
has been written down and is checked. The properties this project cares about
most are the refusals, and they are listed in
[`archive/THREAT-MODEL.md`](archive/THREAT-MODEL.md),
which phase A.1 archived with the scanner it was written about.
