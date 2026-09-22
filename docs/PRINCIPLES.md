# Principles

What Actaira is, what it refuses to do, and the rules the work follows. This is
the governance document, and it is the only one: a second page of principles is
a second place a principle can be written down differently.

It was [`CLAUDE.md`](../CLAUDE.md) at the repository root, in Spanish, linked
from an English README as "the only governance document". Two things were wrong
with that and only one of them was the language. A file named after an agent's
instruction format is read as instructions for an agent, and the argument of
this project belongs to the project. `CLAUDE.md` is still there and is now what
its name says: the short set of instructions for an agent working in this tree,
pointing here for everything else.

---

## What this is

Actaira is change control for what coding agents can do. It reads the
configuration Claude Code, Codex, Cursor, Gemini CLI, VS Code and the
devcontainer load; resolves across scopes and vendors what they are actually
allowed to do; says what changed between two moments; and binds approvals to the
digest of what was approved, so that they expire by themselves when that
changes.

It is not a model scanner. It is not an observability platform. It is not a
compliance tool. It is not an EDR: it does not watch at runtime and it does not
block. If a design decision only makes sense under one of those four
descriptions, it is wrong.

Why the product is this one and not the previous one, with the three
alternatives that were rejected before landing here and the source of each
rejection: [`DESIGN.md`](DESIGN.md) §11, design note D-269.

---

## The three claims

Actaira claims exactly this and nothing more:

1. **SURFACE.** What an agent can do in this repository or on this machine,
   resolved across scopes and vendors. Every capability cites the file it comes
   from, the documented merge rule that resolved it (with the URL and the
   version of the vendor's documentation), and the Actaira rule that names it.
2. **CHANGE.** Which capability appears, disappears, widens or narrows between
   two moments.
3. **CURRENCY.** Whether an approval or a piece of evidence still describes what
   is there. Bound to digests, never to names and never to dates.

Any claim outside those three is a product defect, even when it is true.

And what none of the three may claim, stated here so that nobody has to deduce
it: configuration DECLARES, it does not demonstrate behaviour. A hook that is
written is not proof that it ran, and one that is absent is not proof that
nothing ran. What could not be resolved is INDETERMINATE, is counted apart, and
is never distributed across the answers that could be given.

---

## The three resolution states of a capability

```
DECLARED        it is written in a file, and that file is cited
EFFECTIVE       resolved across scopes, with the agent's version known
INDETERMINATE   it could not be resolved, with the cause named
```

The four capture levels below do not go away: they still govern `scan` and
`watch`, which are what looks at a RUN. These three govern what looks at a FILE.
A document that mixes the two vocabularies is confusing what an agent CAN do
with what an agent DID.

---

## The four negatives

These are invariants. A change that violates one is rejected without discussion.

1. **NEVER A NUMBER.** No score, grade, rating, percent, confidence or ranking
   in any emitted document. The test that greps for those words stays and is
   only ever widened, never relaxed. A rule may carry a `severity` written by
   the author of its pack: that is an attributed label, not a calculation
   Actaira performed, and it is NEVER aggregated or summed with another.
2. **NEVER JUDGE, ONLY CITE.** Actaira has no opinion about what an agent should
   have done. It only compares what was observed against a norm WRITTEN BY
   SOMEBODY ELSE, and names it. Every finding publishes the rule's id, its
   version, its pack and its author. From which the usual follows: calling a
   model on the decision path is forbidden. An LLM may help draft a rule; it may
   not evaluate one, and it may not write its remediation.
3. **NEVER INFER THE UNOBSERVED.** If what was read did not cover something, the
   report says so. A predicate with no information returns INDETERMINATE, never
   False. Every rule declares what it needs in order to answer; below that, the
   rule returns INDETERMINATE on its own, without anybody remembering to check.
4. **NEVER ACT ON WHAT IS OBSERVED.** Actaira SUGGESTS the remediation its rule
   carries, and never applies it. A witness that also acts cannot attest to its
   own acts, and that conflict of interest is exactly what separates this from
   an observability vendor. If an `--apply` ever exists, the change is recorded
   as one more finding, attributed to Actaira, and the engine evaluates it like
   any other. Never silently. An exit code INFORMS: whether it blocks is decided
   by the user's own branch protection, which is theirs. Leaving with a non-zero
   status is not acting; writing in the user's tree is.

---

## The published limits

They are in the README, on the site and in the report itself. They do not get
softened to sell better. The sixteen of them are in [`LIMITS.md`](LIMITS.md),
with [`LIMITS.es.md`](LIMITS.es.md) beside it because `actaira --lang es` prints
the same limits. Ten are about what looking at a RUN can show, which is `scan`
and `watch`; four are about what looking at a CONFIGURATION can show, and
arrived with the surface; the last two are about `watch` again, and limit 15 is
about a platform. That sentence lives once, in `proxy/stdio.py`, and the skip it
forces in the suite prints it as its reason. Work rule 10.

---

## The four capture levels

Every record declares the level it was captured at, and the level decides what
it may claim. This is not a detail: it is the difference between evidence and
diagnosis.

```
L0  THE AGENT'S OWN TRANSCRIPT
    What Claude Code, Cursor or Cline already saved to disk by themselves.
    It carries the tool calls with their arguments, but the audited party
    produced it. An L0 record CANNOT CLAIM AUTHENTICITY. It declares it as not
    evaluated, with the reason written out. It is for diagnosis and
    retrospective analysis, not as proof for a third party.
L1  AN MCP PROXY
    Captured from outside the agent. It sees tool calls.
L2  A NETWORK PROXY
    It sees the calls to the model provider as well.
L3  A SANDBOX WITH SECCOMP
    It sees files, network and execution. The only one that can claim nothing
    else was touched.
```

A level nobody attempted cannot make a verdict inconclusive. One that was in
scope and failed, can.

---

## Work rules

1. **ONE PHASE, ONE OBJECTIVE, ONE GATE.** The gate is written before the phase
   starts and is checkable by a machine, not by an opinion.
2. **ONE ADVERSARIAL PASS PER PHASE.** That pass may only produce a fix or a
   line in [`BACKLOG.md`](BACKLOG.md). It may not produce a new criterion, a new
   pending decision or a new phase. If it finds something that seems to demand a
   new criterion, that goes in the backlog as a line and the work continues.
3. **A FILE BUDGET PER PHASE**, declared before starting. Going over it requires
   explicit authorisation in the conversation. There are THREE categories of
   file, not two:

   1. **DESIGN.** Counts against the budget.
   2. **FORCED BY THE GATE.** Does not count: documentation a release check
      demands, generators that abort without an input, and tests that assert the
      old state. Every file declared forced MUST NAME in the report the specific
      check that forces it. A forced file without its check named is scope, and
      then it counts.
   3. **SCOPE DISCOVERED MID-PHASE.** The phase's objective becomes incoherent
      without it. It does not count against the budget, BUT IT REQUIRES STOPPING
      AND ASKING BEFORE WRITING IT, and it is recorded in the commit with the
      argument for why the phase does not stand up without it.

   The third exists because phase 1.1b used 11 of 10 and the extra one was
   `cli.py`: no check of the gate forced it, what forced it was that the
   operator lost the ability to find their own session. The argument was
   correct and category 2 was not its home. Filing discovered scope as "forced
   by the gate" out of convenience is how category 2 stops meaning anything.
4. **STARTING THE NEXT PHASE BEFORE CLOSING THE CURRENT ONE IS FORBIDDEN.** Even
   when it is obvious, even when there are tokens left, even when the change is
   one line.
5. **EVERY DESIGN DECISION IS WRITTEN WITH ITS REJECTED ALTERNATIVE AND ITS
   REASON**, in the code itself, in five lines or fewer. Not fifty. A
   ninety-line docstring is a liability.
6. **NO PUBLISHED FIGURE WITHOUT A COMMAND THAT MEASURES IT.** `make figures`
   measures it and the release gate fails when it drifts. This already exists
   and is kept. It applies to pictures too: `make demo-image` draws the demo
   picture from the command's own output, and the gate redraws it and refuses a
   difference.
7. **THE GATE RUNS IN WSL AND OVER A CLEAN CLONE OF HEAD**, never over the
   working directory. In WSL because Windows has no `make`, because running the
   four commands by hand does not test the Makefile, and because the POSIX
   permission-bit test is not skipped there. Over a clone because the working
   tree holds files that are not published: phase S1 went green with two
   fixtures `.gitignore` excluded and `git add -A` skipped in silence, and the
   red arrived in the first CI run, which was the first clean clone that ever
   existed. A gate that runs where those files are does not measure what is
   delivered, it measures this machine. Ubuntu 24.04, GNU Make 4.3, a venv at
   `/tmp/actaira-venv` with `pip install -e ".[dev]"`:

   ```bash
   wsl -e bash -lc 'rm -rf /tmp/actaira-gate && git clone -q <this tree> /tmp/actaira-gate && cd /tmp/actaira-gate && PY=/tmp/actaira-venv/bin/python make all'
   ```

   The variant over the mounted directory is an ITERATION SHORTCUT and never the
   gate: it is faster and it answers for a tree nobody receives.
   `tests/test_fixtures_are_published.py` covers the specific case that exposed
   this; the clone covers the class.
8. **A BUDGET THAT ONLY LIVES IN THE CHAT DOES NOT EXIST.** When an extension of
   budget or of scope is authorised, that authorisation is written in the
   phase's commit message, with the number, the reason and which files consumed
   it. A later session can only read the repository.
9. **EVERY TEST THAT PROVES A NEGATIVE CARRIES ITS TWIN**, and the twin plants
   the case that should trigger it and DEMANDS the failure. A test that asserts
   "this does not happen" and has never seen it happen cannot tell the property
   apart from a plant that never arrives: it passes both times.
10. **TWO CHECKS OVER ONE PROPERTY SHARE THEIR DEFINITION.** One calls the
    other, or both read the same place; it is never written twice. With
    different definitions they do not add up, THEY CANCEL: each passes on its
    own terms and the failure stays invisible between them. DEF-122 is the case.
    The gate checked a figure by the contract's pattern, which anchors on the
    words after the number, and a test checked it by `f"**{value}**" in page`.
    The test DEMANDED the bold, and bold between a figure and its noun is
    exactly what makes it invisible to the pattern: the test was holding in
    place the shape that switched the gate off. Both green, the published figure
    off by eight.
11. **A CHECK THAT DOES NOT MATCH, DOES NOT FIND OR DOES NOT APPLY FAILS
    LOUDLY**, and names what it was looking for and where. It never writes zero,
    never returns an empty list, never falls to the safe end. If it genuinely
    does not apply, that is declared with its reason written and the loader
    refuses an empty reason: `measured_only` in `figures_contract.py` is the
    shape. It is one disease in every place it has appeared: DEF-120, a value
    the vendor publishes and we did not know, read as "not the dangerous one";
    DEF-122, an unmatched pattern skipped with `continue` and a `re.subn` that
    wrote zero; and the whole of phase S3.1, which exists because a value
    outside the set fell to the safe end.
12. **THE CHARACTERISTIC FAILURE OF THIS REPOSITORY IS A CHECK THAT PASSES WHILE
    CHECKING SOMETHING ADJACENT.** It is not that checks are missing: it is that
    the one that exists looks sideways, comes out green, and its green is read
    as though it had looked straight ahead. Before trusting a green, name WHAT
    IT EXERCISED, not what its name says. The ones recorded so far are DEF-120,
    DEF-122, DEF-123, DEF-124, DEF-125 and DEF-130, and the last of those is the
    plainest: a laptop check and a CI job asserted "the package carries what it
    needs" with two different lists, so the job stayed green over the same
    distributions the laptop was refusing.

    FROM THIS COMES AN OBLIGATION, not another rule: WHEN YOU BUILD A CHECK
    BECAUSE SOMETHING BROKE, IN THE SAME PASS LOOK FOR WHAT ELSE HAS THAT SHAPE,
    and whatever you find either enters the check or enters
    [`BACKLOG.md`](BACKLOG.md) by name. Never in silence. Had that been done
    when DEF-118 was closed, DEF-124 would not exist: the file next door had the
    same shape and nobody looked.

---

## The reachability rule

Every module of the package has to be reachable from the CLI or from the MCP
server. What is not, goes. The history keeps it and tag `v2.3.0` is intact; a
`git show` brings any of it back.

Reachability is computed FROM THE ROOTS THROUGH THE FUNCTIONS THAT ARE REACHED,
not through module-level imports. An import that only happens inside a function
no command reaches is not a reachability edge. That is stricter than the
previous rule, not looser: without the precision, the dead emitting half of
`attest/dsse.py` kept `ArtifactReport` alive, and `coverage.py` behind it, and
with them two violations of the first negative inside the published package.

It applies at MODULE level. A dead function inside a live module goes to
[`BACKLOG.md`](BACKLOG.md) by name; it does not block a phase.

AN EXEMPTION LIST IS FORBIDDEN. An exemption is satisfied by adding a line to
the list, so the rule would be kept by whoever decided not to add one. The two
modules that asked for an exemption when this was written,
`schemas/__init__.py` and `trace/provenance.py`, were each the second place a
fact was written down, with a test arbitrating between the copies. They were
wired into their readers instead, and that removed the real defect the rule had
uncovered.

`tests/test_reachability.py` is the gate and it runs in `make all`.
`tests/test_layering.py` is beside it and says what each package may import: an
ALLOWLIST of edges, because a prohibition list is silent about the package
nobody thought of.

---

## Code rules

- One runtime dependency: `cryptography`. Adding another requires
  authorisation and a justification in `pyproject.toml` itself.
- Every emitted document is canonical JSON. Same input, same bytes.
- Nothing on the decision path reads the clock, the network or the disk beyond
  what it was handed. Time is an argument, never a call.
- Format errors are caught at load, not at evaluation. A misspelled identifier
  is a load error with a message, not a traceback and not a DENY.
- Every new rule arrives with two tests: a conforming case and a violating one.
  Both over a REAL configuration: either from a public repository under an OSI
  licence, citing repository, commit and licence; or reconstructed from a
  configuration published in an incident report, citing the URL and the
  fragment it comes from. Never invented. A rule tested against a fixture we
  wrote ourselves proves that we can write the fixture.
- A THIRD, NARROW BRANCH FOR THE VIOLATING CASE. The configuration published by
  the vendor's own documentation is admitted, cited with URL, page digest and
  date, ONLY in two situations: when the rule's scope makes a public sample
  impossible (a managed policy lives outside every repository), or when a
  RECORDED search, with its query and its date, found none. The rule is marked
  and the mark is published in [`RULES.md`](RULES.md), not only in the fixture's
  provenance. It exists because refusing the branch does not create the sample:
  it forces inventing one or not writing the rule, and both are worse than
  saying which rule has no real violator. The loader refuses a mark without its
  citation or without its search, and a test checks that the refusal bites.
- NO FIXTURE CONTAINS A MALICIOUS PAYLOAD. We reconstruct the SHAPE of the
  configuration, not its effect: the script a hook points at is an inert stub or
  does not exist. A security repository that shipped the worm it detects is the
  worm.
- Readers touch disk and do nothing else. Scope resolution and the rules are
  pure functions over what the readers read. Actaira NEVER runs an agent binary
  or a referenced script to find something out: asking the audited tool what it
  would do is trusting it, and running what we are analysing is being the
  vector.
- Trace field names follow the OpenTelemetry GenAI conventions, which live in
  `open-telemetry/semantic-conventions-genai`. We do not invent vocabulary where
  it already exists.

---

## The CLI

Seven commands. The cap is eight: adding an eighth is a decision, and a ninth
requires removing one.

    actaira check                read this repository's and this machine's agent
                                 configuration, resolve the effective surface and
                                 apply the rules
    actaira diff A B             which capability appears, disappears, widens or
                                 narrows between two moments
    actaira seal                 seal a signed baseline of the surface, which is
                                 what `verify` verifies
    actaira verify <seal.zip>    verify a seal, offline
    actaira keygen               create, rotate or revoke a key
    actaira scan                 read sessions the agent already recorded (L0)
    actaira watch -- <command>   record a run from the edge (L1 or higher)

`tests/test_cli.py` checks that in both directions: a command on this list that
neither exists in the parser nor carries its phase breaks the gate, and one that
exists and still carries a phase breaks it just the same. A name on this list
with no phase is a published promise; a phase on a command that is built is the
same lie from the other side.

`contract`, `verdict`, `receipt` and `fix` left the list. The first three were
the conformance product, which the plan retired; `fix` printed remediations, and
the remediation is now a field `check` prints beside its finding rather than a
command of its own.

`actaira scan --demo` runs over a fixture that ships inside the package, for
somebody with no agent installed.

---

## What is forbidden

- Touching `formats/`, `controls/`, `connectors/`, `scan/`, `bom/`, `agents/`,
  `governance/`, `web/`, `evals_support/`, `bundle.py`, `marking.py`,
  `inspect.py`, `remote.py`, `trustpolicy.py` again. They are at tag `v2.3.0`
  and they stay there.
- Reintroducing the LLM-as-judge pipeline, or generating remediations with a
  model. A remediation is a field of the rule, written by a human.
- Applying a change in the user's environment without the user running it.
- Adding runtime dependencies.
- Writing a new governance document. This file is the only one.
- Building a dashboard, a server mode of our own, multi-tenancy, or anything
  that begins with "and also".
- Running what a hook, a task or an MCP server declares. It is read, cited and
  bound to its digest. It is not run, not to see what it does, not in a sandbox,
  and not on the argument that the finding would be more precise that way.
