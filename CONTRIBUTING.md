# Contributing to Seamark

The bar here is not "does it work". It is: can a stranger check that it works,
and can they see what it does not do? Everything below follows from that.

Start by reading `docs/DESIGN.md`. It consolidates the numbered design notes
that live in the module docstrings, and it explains why several obvious
approaches were rejected. A change that reverses one of those decisions is
welcome; a change that reverses one without noticing is the thing to avoid.

## The gates

Every gate takes no arguments and runs on a fresh copy of the tree with no
network at all. `make help` lists them; these are the ones a contributor uses.

```
make install     # pip install -e ".[dev]"
make lint        # ruff over src tests scripts
make types       # the mypy ratchet; needs `pip install -e ".[types]"`
make test        # the whole suite
make figures     # measure the repository into docs/FIGURES.md and figures.json
make contracts   # regenerate docs/CONTRACTS.md from the shipped schemas
make design-notes # point every design-note row at the line that argues it
make release-check # refuse a tree whose parts disagree with each other
make package     # build the wheel and sdist into dist/ and check what is in them
make all         # lint, test-cov, figures, release-check, history-check
```

**`make all` is the gate.** `.github/workflows/ci.yml` runs on every push to
`main` and every pull request, and phase A.1 rewrote it against the commands
this tree actually has. It is still not the whole gate: `make all` is what a
change is held against before it is pushed, and it is the definition when the
two disagree. That file says which jobs it runs and which it deliberately does
not, with the reason beside each.

`release-check` is exercised as a test rather than as a job
(`tests/test_release_check.py`), which runs it against a copy of the tree and
also against copies broken on purpose.

### Where you run the suite changes how long it takes, by a lot

Run it on a Linux filesystem. Not on a Windows drive, and not in WSL over
`/mnt/c`. The suite is serial - there is no `pytest-xdist` and adding one is a
dependency - so what you are watching is filesystem latency, and the spread is
wide enough that somebody meeting it for the first time assumes the run has
hung. It has not.

`tests/test_release_check.py` is where it shows worst, because those tests copy
the whole tree and run the gate over the copy. The same 18 tests, on one laptop
on 2026-09-18:

```
/tmp/seamark-gate      (WSL, Linux filesystem)      14s
/mnt/c/...             (WSL, over the Windows mount) 78s
C:\...                 (Windows Python, on C:)      332s
```

And the whole suite, on the same laptop the same day: **89s** on the Linux
filesystem, **504s** run natively on Windows.

These are the one kind of number this page's own rule about hand-written figures
does not cover, and it is worth saying why rather than leaving it to look like
an exception somebody took. A runtime *does* have a command that measures it -
`pytest` prints it at the end of every run, which is where all five of the above
came from. What it cannot have is a gate that compares it, because it is a fact
about the machine rather than about the tree, and pinning it would fail on
somebody else's laptop for a reason that is not a defect. So the numbers are
dated, attributed to one machine, and nothing in the repository checks them: run
it yourself and you will get your own.

Work rule 7 in [`docs/PRINCIPLES.md`](docs/PRINCIPLES.md) already sends the gate to a clean clone
under `/tmp` for a different and more important reason - a working directory has
ignored and untracked files that nobody who clones the repository will ever
receive. This is a second, smaller reason to be there anyway.

What each one is actually for:

* **types** is `mypy` over `src/`, run as a ratchet (D-242). The modules it
  already agrees with must stay that way, and the ones it does not are listed
  in `scripts/type_check.py` with what each disagreement is about. How many of
  each is what `make types` prints; it is not written here, because a figure
  nothing compares is a figure that goes stale.
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
* **figures** regenerates `docs/FIGURES.md`. See *No hand-written numbers*
  below, which is the rule it exists to enforce.

No target in `make all` is allowed a `-` prefix or a `|| true`: a step that
cannot fail is not a check.

## The test doctrine

The suite is large because of these rules, not in spite of them.

**Every capability carries its negative control.** For each test that shows the
code doing the right thing, there is one showing it is capable of doing the
wrong thing and does not. A detection test is paired with a benign artifact that
must not fire. A "the tampered package is rejected" test is paired with one
proving the untampered package is accepted, or the first proves nothing. When a
test asserts an empty list - no problems, no losses, no orphans - there is a
sibling test that makes the list non-empty on purpose, so an empty result is
evidence rather than a vacuous pass. `tests/test_i18n.py` is the clearest
example: it asserts in both directions, so an empty catalogue cannot pass it by
having nothing to check.

**A test that cannot fail is not a test.** If a fixture, a skip or an
overly-broad assertion means an assertion would pass on broken code, it is
noise. `pytest.importorskip` is used for genuinely optional dependencies and
never to make a failure go away.

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
`verify_package`. Reaching into a private helper is done only when the thing
under test is the helper's own contract, and then it says so.

**Determinism is not optional.** Seeds are explicit. Anything that depends on
the clock either passes the moment in, or is testing the clock on purpose. Two
runs over the same input must produce identical bytes; `release-check` asserts
that of everything the CLI prints, under two hash seeds.

**Name a test as a sentence.** `test_a_retired_key_is_refused_after_its_window_closed`
tells a reader what broke without opening the file. Add the *why* in a docstring
when the reason is not obvious from the name - especially when the test exists
because something once went wrong.

**Regressions get a case, not a comment.** A defect that has been fixed gets a
test named after it and an entry in `docs/defects.json` pinned to that test. A
defect pinned by a written note instead is worse pinned, and the count of each
is in `docs/ENGINEERING.md`.

## No hand-written numbers in documentation

This project has drifted from its own README twice. So:

**No figure is typed into prose.** Test counts, line counts, rule counts and
defect counts come from
`scripts/figures.py`, which measures the repository as it is on disk and writes
`docs/FIGURES.md` and `figures.json`. If you want to state a number, run
`make figures` and let the page state it.

Which figures are allowed in prose at all is a table,
`scripts/figures_contract.py`, and a figure is only in it if it can be derived:
every entry ends at an enum, a registry, a file a harness wrote, or a count of
files on disk. Nothing in it reads a number out of prose to check it against
prose. A figure with no command that measures it is a figure this project does
not print.

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
is not. Adding a rule means adding its text to **both** `src/seamark/i18n/en.json`
and `src/seamark/i18n/es.json`. This is enforced: `tests/test_i18n.py` recovers
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

Seamark has **one** runtime dependency, `cryptography`, and that is a design
position: a tool that inspects supply chains should not have a supply chain of
its own. Adding a second is not forbidden, but the pull request has to argue for
it, and "it would be less code" is not the argument - the RFC 3161 support in
1.0.0 is several hundred lines of hand-written DER precisely because the
alternative was a new dependency.

Development dependencies are cheaper but not free. The `dev` extra is
`pytest`, `ruff` and `jsonschema`, and each one is there for a named reason
recorded beside it in `pyproject.toml`. Anything used by a single test should
be guarded with `pytest.importorskip`.

## How this was built, and what that asks of a contribution

Seamark was built by one person with heavy use of an AI coding assistant, over
an intense stretch in September 2026. The commit dates say so. The short of
it is that the product decisions and every rejected
alternative in [`docs/DESIGN.md`](docs/DESIGN.md) are the author's, and the
assistant wrote a large share of the implementation and the tests against them.

That is why the gates here are unusually strict, and it is the one thing worth
knowing before sending a change: the checks in this repository exist because
assistance at that speed produces exactly the failure they catch. A
contribution written the same way is welcome on the same terms. Say so in the
pull request, and hold it to the same bar: a test with a negative control, a
design note with its rejected alternative, and `make all` green on a clean
clone.

## Pull requests

A short checklist, in the order that saves the most time:

1. `make all` is green.
2. New behaviour has a test, and that test has a negative control.
3. If any published figure moved, `make figures` has been run and the result is
   in the diff.
4. If a decision was made, there is a design note saying what was rejected and
   what is given up.
5. The commit message says what was found and fixed, not only what was added.
   The commits in this repository's history state the defects found in their own
   work; that convention is worth keeping.

Behaviour in the project's spaces is covered by `CODE_OF_CONDUCT.md`.
Vulnerabilities go through `SECURITY.md`, not through a pull request.
