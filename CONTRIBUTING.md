# Contributing to Actaira

The bar here is not "does it work". It is: can a stranger check that it works,
and can they see what it does not do? Everything below follows from that.

Start by reading `docs/DESIGN.md`. It consolidates the numbered design notes
that live in the module docstrings, and it explains why several obvious
approaches were rejected. A change that reverses one of those decisions is
welcome; a change that reverses one without noticing is the thing to avoid.

## The gates

Every gate takes no arguments. All but two run on a fresh copy of the tree with no
network at all, and the two exceptions say so here rather than failing
mysteriously: `benchmark` needs three third-party scanners installed, and
`eval-marking` needs Pillow, which is in the `dev` extra.

```
make install     # pip install -e ".[dev]"
make lint        # ruff over src tests evals fuzz scripts
make types       # the mypy ratchet; needs `pip install -e ".[types]"`
make test        # the whole suite
make eval        # rebuild the corpus, run the evaluation harness
make eval-marking # the Article 50(2) survival matrix; needs Pillow
make fuzz        # every parser, CI budget: 5 000 cases per target
make fuzz-long   # the same, 50 000 per target: this is the one that finds things
make benchmark   # against picklescan, modelscan and fickling; needs them installed
make diagrams    # regenerate docs/img/*.svg from the code and the measurements
make figures     # measure the repository into docs/FIGURES.md and figures.json
make contracts   # regenerate docs/CONTRACTS.md from the shipped schemas
make design-notes # point every design-note row at the line that argues it
make release-check # refuse a tree whose parts disagree with each other
make package     # build the wheel and sdist into dist/ and check what is in them
make all         # lint, test, fuzz, eval, eval-marking, diagrams, figures, release-check
```

**`make all` is the gate.** This is a local repository: there is no remote and
nothing runs anywhere on its own, so `make all` is not a rehearsal for a
pipeline, it *is* the pipeline. `.github/workflows/ci.yml` is a definition of
the same steps, kept in the tree for whoever imports it, and it should be read
as a description rather than as evidence that anything has run.

It defines `lint`; `test` on three Python versions; `eval`; `fuzz`;
`benchmark`; `figures`; an attest/verify/rotate/revoke round trip; and a
packaging job that installs the sdist and the wheel into empty environments and
uses the tool from there. It does not define `eval-marking` or `diagrams`,
because both are documentation regeneration and the results they read are
committed. `release-check` is exercised as a test rather than as a job
(`tests/test_release_check.py`), which runs it against a copy of the tree and
also against copies broken on purpose.

What each one is actually for:

* **types** is `mypy` over `src/`, run as a ratchet (D-242). The modules it
  already agrees with - 79 of 95 - must stay that way, and the 16 it does not
  are listed in `scripts/type_check.py` with what each disagreement is about.
  The gate fails in both directions: a new error in a clean module, and an
  entry on the list that has since been cleaned up and not removed. The list
  only ever shrinks; adding to it is a decision to argue for. It is not part of
  `make all`, because the close gate must not be able to go red because a
  third-party checker changed what it reports.

* **lint** is `ruff` with `E F I N W B UP S`. Every exception is a
  `per-file-ignores` entry in `pyproject.toml` with a comment explaining it, or
  an inline `# noqa` with the reason on the same line. An exception without a
  reason will be asked about.
* **test** is the suite below. It must be green before a pull request, not
  after.
* **eval** rebuilds the 64-artifact corpus from code and measures detection
  against it. If your change moves a number, the pull request should say which
  number and why. A change that improves detection and quietly costs a false
  positive is a trade, and trades get discussed rather than merged silently.
* **fuzz** asserts one property: for *any* bytes, `inspect_artifact` terminates,
  does not raise, does not allocate without bound, and never answers `PASS` for
  an artifact it could not fully read. It is deterministic - `FUZZ_SEED` and the
  case count decide the whole run - so a failure reproduces from the command
  line. Run `make fuzz-long` before a release or after touching a parser.
* **benchmark** runs the other scanners in this space over the same artifacts.
  It needs `picklescan`, `modelscan` and `fickling` installed; without them the
  columns are simply absent. Its rules are in `evals/benchmark.py` and they are
  not negotiable: same artifacts, same order, same machine, same run; nobody is
  scored on a format they never claimed to support; a tool that crashes is
  recorded as an error rather than as a clean result; and the artifacts another
  tool catches and Actaira misses are printed every time.
* **figures** regenerates `docs/FIGURES.md`. See *No hand-written numbers*
  below, which is the rule it exists to enforce.

No target in `make all` is allowed a `-` prefix or a `|| true`: a step that
cannot fail is not a check. `benchmark` is outside `all` and carries one line
with a `-`, the regeneration of the real-library corpus, because that needs
torch and the comparison is still meaningful without it. The Makefile says so
at that line.

## The test doctrine

The suite is large because of these rules, not in spite of them.

**Every capability carries its negative control.** For each test that shows the
code doing the right thing, there is one showing it is capable of doing the
wrong thing and does not. A detection test is paired with a benign artifact that
must not fire. A "the tampered package is rejected" test is paired with one
proving the untampered package is accepted, or the first proves nothing. When a
test asserts an empty list - no problems, no losses, no orphans - there is a
sibling test that makes the list non-empty on purpose, so an empty result is
evidence rather than a vacuous pass. `tests/test_i18n.py` and
`tests/test_benchmark.py` are the clearest examples: both test machinery whose
whole job is to produce an unflattering answer when there is one.

**A test that cannot fail is not a test.** If a fixture, a skip or an
overly-broad assertion means an assertion would pass on broken code, it is
noise. `pytest.importorskip` is used for genuinely optional dependencies - torch,
onnx, h5py, the rival scanners - and never to make a failure go away.

**Do not verify with the code that wrote it.** Where independence is the point,
the input comes from somewhere else. The attestation verifier shares no code
path with the writer beyond the hash helpers. The RFC 3161 parser is tested
against `.tsq` and `.tsr` files OpenSSL wrote (`tests/fixtures/rfc3161/`, with
`generate.sh` beside them so they can be remade), the test suite's own timestamp
authority (`tests/tsa.py`) is a second implementation written in the test tree,
and OpenSSL is asked to verify what that authority issues whenever it is
installed. A test that encodes and decodes with the same function proves only
that the function agrees with itself.

**Assert through the public interface.** Tests call what a user calls: the CLI,
`inspect_artifact`, `verify_package`. Reaching into a private helper is done
only when the thing under test is the helper's own contract, and then it says so.

**Determinism is not optional.** Seeds are explicit. Anything that depends on
the clock either passes the moment in, or is testing the clock on purpose.
Two runs over the same corpus must produce identical output; the eval harness
asserts exactly that.

**Name a test as a sentence.** `test_a_retired_key_is_refused_after_its_window_closed`
tells a reader what broke without opening the file. Add the *why* in a docstring
when the reason is not obvious from the name - especially when the test exists
because something once went wrong.

**Regressions get a case, not a comment.** Anything fuzzing finds is reduced,
added to `fuzz/corpus/` with a name describing the bug, and pinned by a test in
`tests/test_fuzz_regressions.py`.

## No hand-written numbers in documentation

This project has drifted from its own README twice. So:

**No figure is typed into prose.** Test counts, line counts, rule counts,
corpus sizes, policy-comparison figures, timings and fuzz totals come from
`scripts/figures.py`, which measures the repository as it is on disk and writes
`docs/FIGURES.md` and `figures.json`. If you want to state a number, run
`make figures` and let the page state it.

Two harnesses write their own results and `figures.py` does not read them: the
Article 50(2) survival matrix (`evals/marking/results.json`, regenerated by
`make eval-marking`) and the judged-tier gold set (`evals/agents/results.json`,
regenerated by `python3 evals/agents/harness.py`). Their figures are pinned by
`tests/test_readme_parity.py` and `tests/test_agents.py` against those files
instead, and both files are tracked, so a figure from either is still compared
with something on every commit. Extending `figures.py` to read them would be
the better shape and is not done.

Two consequences:

* A pull request that changes any of those things should include the
  regenerated `docs/FIGURES.md` and `figures.json`.
* If a number in a README and a number in `docs/FIGURES.md` disagree, the
  generated page is the one that was measured, and the README is a bug.

The narrative figures in `CHANGELOG.md` are the exception, and only in one
direction: they record what was measured *at that release* and are never
updated afterwards, because a changelog entry that changes is not a record.

## Design notes

Decisions live in module docstrings as numbered notes (`D-01`, `D-02`, ...) and
are consolidated in `docs/DESIGN.md`. The code is the source of truth; where the
document and a docstring disagree, the docstring and the code it sits on win,
and the disagreement is listed in the last section of `docs/DESIGN.md` rather
than smoothed over.

Every note states three things:

1. **Decided**: what the code does.
2. **Why**, and **Rejected**: the alternative that was seriously considered.
3. **What is given up**: what the chosen option costs.

A decision without the third part is not a decision, it is a preference. If you
add a note, take the next free number and add the row to the index table in
`docs/DESIGN.md`.

## Rules and the catalogue

Rule identifiers (`ACT-PKL-002` and friends) are the stable interface; the text
is not. Adding a rule means adding its text to **both** `src/actaira/i18n/en.json`
and `src/actaira/i18n/es.json`. This is enforced: `tests/test_i18n.py` recovers
the rule identifiers from the source rather than from the catalogue, so a rule
the code can emit and the catalogue does not carry fails the suite, and so does
a catalogue entry for a rule the code can no longer emit. Copying the English
string into the Spanish file also fails; that is the filler detector, and it is
there because a second language rots silently otherwise.

Identifiers stay ASCII. Python will happily accept `configuración` as a name and
this suite refuses it, because a name that reads correctly and breaks something
that looks names up by string has already cost this project a silent breakage
once.

## Dependencies

Actaira has **one** runtime dependency, `cryptography`, and that is a design
position: a tool that inspects supply chains should not have a supply chain of
its own. Adding a second is not forbidden, but the pull request has to argue for
it, and "it would be less code" is not the argument - the RFC 3161 support in
1.0.0 is several hundred lines of hand-written DER precisely because the
alternative was a new dependency.

Development dependencies are cheaper but not free. The `dev` extra is
`pytest`, `numpy`, `ruff`, `jsonschema` and `pillow`, and each one is there for
a named reason recorded beside it in `pyproject.toml`. Anything used by a
single test should be guarded with `pytest.importorskip`; a control that needs
a library reports INCONCLUSIVE naming it rather than failing, which is what
`ACT-C-15-MARK-ROBUSTNESS` does without Pillow.

## Never commit an artifact from the corpus

`evals/artifacts/`, `evals/real/` and `fuzz/runs/` are generated and ignored.
The corpus contains working gadget pickles; the repository contains the code
that builds them and nothing else. `SECURITY.md` explains why. The reduced fuzz
inputs in `fuzz/corpus/` are the deliberate exception: they are tracked, they
are tiny, and each one is a regression that must stay pinned.

## Pull requests

A short checklist, in the order that saves the most time:

1. `make all` is green.
2. New behaviour has a test, and that test has a negative control.
3. If the change touches a parser, `make fuzz-long` has been run at least once.
4. If any published figure moved, `make figures` has been run and the result is
   in the diff.
5. If a decision was made, there is a design note saying what was rejected and
   what is given up.
6. The commit message says what was found and fixed, not only what was added.
   The commits in this repository's history state the defects found in their own
   work; that convention is worth keeping.

Behaviour in the project's spaces is covered by `CODE_OF_CONDUCT.md`.
Vulnerabilities go through `SECURITY.md`, not through a pull request.
