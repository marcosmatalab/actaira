<div align="center">

**Change control for what your AI agents can do.**

Actaira reads the configuration your coding agents load, resolves what it actually lets them do, and says what changed between two moments.

**Actaira 3.0.0** · Python 3.11 · 3.12 · 3.13 · Apache-2.0 · one runtime dependency · offline, no telemetry, no account

**[Español](README.es.md)** · [Quickstart](#quickstart) · [The seven commands](#the-seven-commands) · [Capture levels](#capture-levels) · [What Actaira refuses to do](#what-actaira-refuses-to-do) · [Limits](#published-limits) · [Docs](#the-rest-of-the-documentation)

</div>

---

## What this is

An agent opens your repository. Before you type anything it has already read a
settings file that can register a hook to run at session start, a list of MCP
servers to connect to, a permission set, a sandbox policy and an instructions
file. Those files arrive from several scopes at once - managed, user, project,
local - and each vendor documents its own rules for merging them. The answer to
"what can this agent do here" is written down in none of them.

Actaira reads those files, resolves what they add up to, names each capability
with the rule that found it, and says what changed since last time.

It is not a model scanner. It is not an observability platform. It is not a
compliance tool. It is not an EDR: it does not watch at runtime, and it does
not block.

### The objective, and where it actually stands

Actaira claims exactly three things and nothing else. Anything outside those
three is a product defect, even when it is true.

Each block below says what exists, and each one names the commands its claim
rests on. That is not a formatting habit: `scripts/release_check.py` reads those
names and resolves them against the parser, in both directions. A block that says
"built" while naming a command nobody wrote fails the gate, and so does a command
that works while no block claims it. This page published "Does not exist" about
`actaira check` for a whole phase after it shipped, because the only check there
was asked whether the command was mentioned somewhere, not whether what the page
said about it was true.

**1. Surface** - what an agent can do in this repository or on this machine,
resolved across scopes and vendors. Every capability cites the file it came
from, the documented merge rule that resolved it, with the URL and version of
the vendor documentation that states it, and the Actaira rule that names it.

> **Built.** Commands: `actaira check`.
> It reads Claude Code, Codex CLI, Cursor, Gemini CLI, the VS Code task and
> settings files, `devcontainer.json`, and the AGENTS.md / CLAUDE.md / GEMINI.md
> instruction files. Each vendor is resolved against its own documented
> precedence, and the repository's surface is the union of the seven - never a
> merge of them.

**2. Change** - which capability appears, disappears, widens or narrows between
two moments.

> **Built.** Commands: `actaira diff`, `actaira seal`.
> Two git refs, or two directories, are compared without checking either of them
> out. What arrives, what goes, what widens, what narrows, what changed with both
> digests, and separately whatever could not be resolved on one side or the
> other. The GitHub Action and the pre-commit hook in this repository are the
> same command where the change arrives. Phase S4 adds the machine baseline,
> which is where a hook planted in the user scope rather than in a repository
> becomes visible at all.

**3. Currency** - whether an approval or a piece of evidence still describes
what is there. Bound to digests, never to names and never to dates.

> **Partly built.** Commands: `actaira seal`, `actaira verify`.
> `seal` signs a baseline of a surface that carries no content, bound to the
> surface's digest, and `verify` checks one offline without trusting whoever
> produced it. So an approval CAN be tied to a digest today and CAN be shown to
> have stopped describing the tree. What does not exist is the register that
> holds those approvals and expires them on your behalf:
> [`docs/DESIGN.md`](docs/DESIGN.md) §10 keeps the reasoning for the five
> evidence states and for supersession bound to a digest rather than to a
> subject's name, from the `state/` package phase A removed for being
> unreachable. Its consumer is phase P1.

And what none of the three may claim, stated here rather than left to be
inferred: **configuration declares; it does not demonstrate behaviour.** A hook
that is written is not a hook that ran, and a hook that is absent is not proof
that nothing ran. Whatever could not be resolved is INDETERMINATE, counted
apart, and never distributed across the answers that were.

**Outside the three claims**, and named here rather than left unaccounted for.
Two commands read what an agent DID rather than what it can do, and one manages
a key. They implement none of the three claims above, and a page that simply did
not mention them would be a page whose silence a reader has to interpret.

> **Outside the three claims.** Commands: `actaira scan`, `actaira watch`,
> `actaira keygen`.
> `scan` and `watch` are the [capture ladder](#capture-levels), which is about a
> run rather than a configuration; `keygen` manages the key `seal` signs with.
> They are kept because a change to a configuration and the sessions that ran
> after it are the same question asked twice.


---

## Quickstart

Five minutes, no agent installed, no network.

```bash
git clone https://github.com/marcosmatalab/actaira
cd actaira
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

One runtime dependency (`cryptography`). Then, what the product is for, on the 4
August 2026 keyv wave reconstructed from the published reports. The script builds
a throwaway repository with two commits - clean, then compromised - and diffs
them:

```console
$ python3 scripts/demo_keyv.py    # exits 1: a rule fired on something that arrived

What changed between HEAD~1 and HEAD

APPEARED: 1
  + claude-code  hook.command  .claude/settings.json  [project]
      after  effective  63a9a33e2cd93139
      ! ACT-S001  A hook runs a command on a session-start event, so opening a session runs it before anybody has read anything.
        rule written by  Actaira core core / high
        suggested by the rule: Remove the hook, or move it to ~/.claude/settings.json where it is yours rather than the repository's. A hook on a session-start event runs before you have read anything.
      ! ACT-S003  A hook runs a script inside this repository, so whoever can land a commit decides what it runs.
        rule written by  Actaira core core / medium
        suggested by the rule: Tie your approval to the script's sha256 rather than its path: the file at that path can change after you read it, and the hook will run whatever is there.

Could not be resolved on one side or the other: 2
  ? ACT-S016 on task.command
      `task.allowAutomaticTasks` decides whether this runs; it is APPLICATION-scoped, so only the user's own settings file can set it, and no scope this run read says either way (run with --machine)
  ? a change to vscode task.command
      `task.allowAutomaticTasks` decides whether this runs; it is APPLICATION-scoped, so only the user's own settings file can set it, and no scope this run read says either way (run with --machine)

Identical on both sides: 0
Seen and not read by this release: 7

Configuration DECLARES; it does not prove behaviour. A hook that is written is not a hook that ran, and one that is absent does not prove nothing ran (published limit 11).
```

Read the unresolved half, because it is the design. The worm plants two things
and this says so about both: the Claude Code hook is EFFECTIVE and named by two
rules, and the `.vscode/tasks.json` task is INDETERMINATE - whether it runs is
decided by a setting that only the user's own machine can hold, so a repository
cannot answer it and this refuses to guess. Counted apart, never folded in.

The reconstruction is in `tests/fixtures/surface/keyv-august/`, its provenance
file cites the sentence each fragment comes from, and the `setup.mjs` the hook
points at is an inert stub. A security repository that shipped the worm's
payload in order to demonstrate catching the worm would be the worm.

And with no agent installed and nothing configured:

```console
$ actaira scan --demo

Reading the synthetic demo session shipped with the package.
  1 session(s), 4 tool call(s), from 2026-03-04T09:15:00.000Z to 2026-03-04T09:15:15.000Z
  1 session(s) declare a gap: something happened that was not observed

CAPTURE LEVEL L0: this transcript was written by the agent being audited, about
itself. Authenticity is not evaluated here and cannot be. It is diagnosis and
retrospective analysis, not evidence a third party can rely on. Use `actaira
watch` to record a run from outside the agent.
```

That block is the house style in miniature. It read a session, said what it
saw, and then said - unprompted - that what it read cannot support the claim a
reader would otherwise take it for.

---

## The seven commands

```
actaira check     read this repo's agent configuration and resolve what it permits
actaira diff      say what capability changed between two moments
actaira seal      sign a baseline of the surface, carrying no content
actaira verify    verify a signed package offline
actaira keygen    create, rotate or revoke a signing key
actaira scan      read the sessions an agent already recorded on this machine (L0)
actaira watch     record a run from outside the agent, through an MCP proxy (L1)
```

That is the complete list of what works: 7 CLI commands, and `actaira --help`
prints the same seven. [`CLAUDE.md`](CLAUDE.md) lists seven and caps the set at
eight, so for the first time there is no promised name left on it;
`tests/test_cli.py` fails on a name in that list that neither exists in the
parser nor says when it will, and on one that exists and still carries a phase.

### `actaira check` - what an agent can do here

`check` reads the agent configuration in this repository, resolves what it
actually permits across scopes and across vendors, and applies the rule packs.
It reads Claude Code, Codex CLI, Cursor, Gemini CLI, `.vscode/tasks.json` and
`.vscode/settings.json`, `devcontainer.json`, and the AGENTS.md, CLAUDE.md and
GEMINI.md instruction files, against 32 documented rules.

Each vendor is resolved against the precedence its own documentation publishes,
because those ladders disagree: Claude Code puts the user's file above the
project's, Gemini CLI puts the project's above the user's, and VS Code puts the
workspace above both. A repository's surface is therefore the UNION of the seven
per-vendor surfaces, and two vendors configuring the same MCP server are two
capabilities with the same digest rather than one row belonging to neither.

What still is not read is printed, not skipped - including the two scopes that
never leave a file at all: Cursor's team hooks, configured in a dashboard and
synced to members, and Codex's MDM and cloud-delivered requirements. Those are
INDETERMINATE with the cause named, never reported as absent.

```
actaira check                                   # this repository
actaira check --machine                         # and the user and managed scopes
actaira check --agent-version claude-code=2.1.257
actaira check --json                            # a surface/v1 document
actaira check --html report.html                # one self-contained file, no network
```

Three things it will not do. It never runs what it reads: of a script a hook
names it records four facts - whether it exists, whether it is inside the tree,
whether git tracks it, and its sha256 - and never a fifth. It prints no literal
command, URL or header without `--with-content`, because a settings file can
carry a secret and this report is pasted into CI logs. And it never guesses: a
capability whose answer depends on an agent version nobody stated comes back
INDETERMINATE with the threshold named, counted apart from everything else.

Exit codes: `0` nothing fired and nothing was unresolved, `1` a rule fired, `3`
nothing fired and something could not be resolved.

### `actaira diff` - what changed

```
actaira diff main HEAD                          # two refs in this repository
actaira diff --repo ../other main feature       # somewhere else
actaira diff --from-dir a --to-dir b            # two trees, no git
actaira diff main HEAD --html report.html       # and the same report as a page
actaira diff main HEAD --sarif actaira.sarif    # SARIF 2.1.0 for a code host
```

Neither ref is checked out. The two trees are read with `git ls-tree` and
`git cat-file`, which run no hook, apply no filter and no textconv driver, and
are written into a temporary directory that is removed on the way out. Your
working tree is not touched, your HEAD does not move, and a `post-checkout` hook
in the repository being examined is never given the chance to run - which would
be executing somebody else's code in order to answer a question about somebody
else's code. A ref that starts with a dash is refused with exit code `2`.

Five kinds of change, and a sixth thing that is not one of them. A capability
APPEARED, DISAPPEARED, WIDENED, NARROWED or CHANGED; and if either side could
not be resolved, the change is INDETERMINATE, listed separately with its cause
and never counted with the five. Widened and narrowed only exist where a fact's
own name says which value is the wider one, such as `guardrail_removed` going
from false to true. Everywhere else the answer is CHANGED, with both digests, so
a reviewer can decide for themselves rather than be told what to think about a
vendor's settings.

Exit codes: `1` a rule fired on something that was added or widened, `3` no rule
fired and something could not be resolved, `0` otherwise, `2` a usage error. A
finding that was already there and is still there is not one of these: that is
what `check` is for, and a command that answers "what changed" must not object to
what did not.

### In a pull request: the Action and the pre-commit hook

The Action is this repository. `uses: marcosmatalab/actaira@<sha>` installs the
tool from the ref you pinned and runs `diff` between the pull request's base and
head:

```yaml
name: actaira
on: pull_request
permissions:
  contents: read
jobs:
  surface:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0       # diff needs both sides, so the whole history
      - uses: marcosmatalab/actaira@main
```

It writes the report into the job summary and SARIF 2.1.0 to `actaira.sarif`;
uploading that to code scanning is yours to do, with
`github/codeql-action/upload-sarif` and `security-events: write`. The exit code
passes through untouched - there is no `|| true` anywhere in it - so a rule that
fired on something new fails the job, and whether that blocks the merge is your
branch protection, which is yours.

`comment: true` posts the same summary as a pull request comment and needs
`pull-requests: write`. It is off by default, because most workflows should not
have that permission and the job summary needs none at all.

**Use it with `pull_request`. Not with `pull_request_target` checking out the
head ref.** That combination gives a fork's code a writable token and your
secrets, and no care taken inside the Action changes it. Every input reaches the
shell through `env` rather than being pasted into a script by `${{ }}`, every
third-party action in this repository's own workflows is pinned by commit SHA,
and `zizmor` runs over `action.yml` and `.github/workflows/` on every build.

For a local hook, this repository publishes one:

```yaml
repos:
  - repo: https://github.com/marcosmatalab/actaira
    rev: main
    hooks:
      - id: actaira-check
```

`check` and not `diff`, because `pre-commit` has one tree in front of it and a
diff needs two moments. The place two moments exist is the pull request.

### `actaira seal` - a signed baseline with no content in it

```bash
actaira keygen                                  # once
actaira seal --repo . --key ~/.actaira/signing-key.pem --out baseline/
actaira verify baseline/surface-seal.zip
```

`seal` writes a signed package holding a `seal/v1` document: every capability's
vendor, name, scope, resolution and merge rule, a salted reference to the file it
came from, and one sha256 over everything it observed. Plus the rules that fired,
each with its author and its pack. Plus counts of what could not be resolved and
what was not read. That is all of it.

**No paths, no commands, no URLs, no server names.** A path becomes
`H(salt || domain || path)`, and the salt stays with you in the output
directory, beside the package and never inside it - the package says so in its
own text. Everything a capability observed becomes one digest of the whole facts
mapping rather than one digest per fact, because `sha256(".env")` is the same
sixteen characters on every machine that has ever existed.

The point of it is the surface digest at the top. Approve that, and the approval
expires by itself the day the surface changes - which is published limit 14 with
the sign flipped, and the reason nothing here is keyed on a file name or a date.

### `actaira watch` - recording from outside

`watch` puts an MCP proxy between the agent and its tool servers, runs your
command, and assembles what the proxy saw into one trace.

```console
$ actaira watch -- python -c "print('agent ran')"

agent ran
Recorded session <session-id> at capture level L1
  0 tool call(s) observed from outside the agent
  ! [end_not_recorded] nothing recorded the end of this session, so what came
    after the last event was not observed
  ! [not_interposed] nothing readable recorded which MCP servers this session
    was configured with, so this tool cannot show that it observed all of them
  ! [proxy_start_failed] no proxy recorded anything for this session. Either the
    agent made no tool call, or it was never routed through the proxy, and this
    tool cannot tell which - so it declares the hole rather than publishing an
    empty clean trace.
  INCOMPLETE: the gaps above are what this run could not observe
  wrote the trace and its digest to actaira-trace
```

Read that output again, because it is the design. Nothing was observed, and the
tool said so three different ways rather than writing a clean empty trace. A
witness that reports silence as "nothing happened" is worse than no witness,
because somebody will rely on it.

`actaira-trace/` then holds the trace as JSON, a `.sha256` beside it, and an
`index.json`. `--out` puts them somewhere else. The session id is a fresh uuid
per run, which is why it is written as `<session-id>` above - every other
character of that block is compared against the real output by
`tests/test_readme_parity.py`.

Point it at a real agent with an MCP configuration and the same command records
the tool calls:

```bash
actaira watch --mcp-config .mcp.json -- claude -p "refactor the auth module"
```

`--with-content` keeps literal arguments and results. Without it, arguments
travel as salted digests: a digest has no false negatives and a secret filter
does.

### `actaira verify` - checking without trusting anyone

```bash
actaira verify baseline/surface-seal.zip
actaira verify baseline/surface-seal.zip --trusted-keyring keys.json --require-trust
```

Offline, always. Integrity and identity are separate answers: a package always
carries its own key, so integrity is always checkable, and "nobody vouched for
this key" is reported as exactly that rather than as a failure. Supply
`--trusted-keyring` or `--pubkey` to bind it to a key you already trust.

It also names what it verified. A package whose entries declare `seal/v1` is
checked against that contract's required fields and the version is reported; one
that declares a version this release does not publish fails, rather than being
reported OK with its meaning guessed at. Packages written by the 2.x model
scanner still verify, and declare no contract, which is not a defect in them.

### `actaira keygen` - the signing key

```bash
actaira keygen                      # create
actaira keygen --rotate             # retire the current key, keep verifying old packages
actaira keygen --revoke <key-id>    # nothing it ever signed is accepted again
```

Ed25519. The keyring lives beside the key. This is the key `actaira seal` signs
with; rotation and revocation are exercised end to end by the suite.

---

## Capture levels

Every record declares the level it was captured at, and **the level decides what
the record is allowed to claim**. This is the difference between evidence and
diagnosis, and it is not a detail.

| Level | What it is | What it can claim |
|---|---|---|
| **L0** | The transcript the agent wrote itself - what Claude Code, Cursor or Cline already saved to disk. Carries tool calls with their arguments. | **Cannot claim authenticity.** The audited party produced it. Declared as not evaluated, with the reason written out. Diagnosis and retrospective analysis, not evidence for a third party. |
| **L1** | An MCP proxy. Captured from outside the agent. | Sees tool calls. |
| **L2** | A network proxy. | Sees tool calls and the calls to the model provider. |
| **L3** | A sandbox with seccomp. | Sees files, network and execution. The only level that can claim nothing else was touched. |

`scan` is L0. `watch` is L1. L2 and L3 are not implemented in this tree.

A level nobody attempted cannot make a verdict inconclusive. A level that was in
scope and failed, can - and does.

---

## What Actaira refuses to do

Four invariants. They are the argument, not a style guide. A change that
violates one is rejected without discussion.

**1. Never a number.** No score, grade, rating, percent, confidence or ranking
in any emitted document. A test greps for those words over every document this
tree produces, and it is only ever widened. A rule may carry a `severity` its
package author wrote: that is an attributed label, not a calculation Actaira
performed, and it is never aggregated or summed with another.

**2. Never judge, only cite.** Actaira has no opinion about what an agent should
have done. It compares what was observed against a norm **written by somebody
else**, and names it. Every finding publishes the rule's id, version, package
and author. From which it follows: calling a model on the decision path is
forbidden. An LLM may help draft a rule; it may not evaluate one, and it may
not write a remediation.

**3. Never infer the unobserved.** If what was read did not cover something, the
report says so. A predicate with no information returns INDETERMINATE, never
False. Every rule declares what it needs in order to answer, and below that it
returns INDETERMINATE on its own, without anybody remembering to check.

**4. Never act on what is observed.** Actaira *suggests* the remediation its
rule carries; it never applies it. A witness that also acts cannot attest to its
own acts, and that conflict of interest is exactly what separates this from an
observability vendor. If an `--apply` ever exists, the change is recorded as one
more finding, attributed to Actaira, and evaluated like any other. Never
silently. An exit code **informs**: whether a pull request is blocked is decided
by the user's own branch protection, which is theirs. Leaving with a non-zero
status is not acting; writing in the user's tree is.

> **All four are enforced against code that exists.** They were not, and the
> note that used to sit here said so: until the rule packs landed there were no
> rules, no predicates and no remediations, so three of the four had nothing to
> constrain. There are now, and each has the property asserted over it - the
> first by `tests/test_no_aggregate.py` over every document this tree emits, the
> second by every finding carrying its rule's author and pack, the third by
> `Clause.holds` returning None for a fact nobody wrote down, and the fourth by
> `diff` reading two trees without checking either of them out.

---

## Published limits

These are in the README, on the site, and in the report itself. They do not get
softened to sell better. The first ten are about what watching a **run** cannot
show, which is `scan` and `watch`; the last four are about what reading a
**configuration** cannot show, and they arrive with the surface.

1. We do not reproduce the output of a hosted model. Not with a seed, not at
   temperature zero. The cause is the provider's batch size and MoE routing, and
   it is not under our control.
2. We cannot isolate a run from the load of the provider's other users.
3. We cannot detect that the provider changed backend, except via
   `system_fingerprint` on OpenAI.
4. There is no determinism in MoE models, which is all the relevant ones.
5. We cannot reproduce stateful tools without freezing the world.
6. We do not prove the absence of an action, only its presence.
7. A trace produced by the agent itself is not evidence.
8. A witness detects an inconsistency; it does not denounce it.
9. Firing no rule is not safety. A repository can produce no finding at all and
   be badly configured for a reason no rule names.
10. What is resolved inherits the errors of what it was resolved from. An
    effective surface computed over the wrong configuration is a correct answer
    to the wrong question.
11. **Configuration is not behaviour.** A capability being declared does not
    prove it was exercised, and its absence does not prove nothing happened.
12. **We see only what is on disk.** Configuration a vendor pushes from a server
    without leaving a file is invisible to us, and that gets declared rather
    than treated as absence.
13. **Merge semantics depend on the agent's version.** With no known version,
    any capability that depends on it comes out INDETERMINATE; it is not
    resolved with whichever version looks likeliest.
14. **A referenced script can change after it is read.** Which is why everything
    binds to its digest and not to its path: an approval over a file name is an
    approval over whatever is there tomorrow.

---

## The published contracts

The package ships 6 schema documents: 4 versioned contracts that are live,
and 2 superseded versions that are read and never written.

| Contract | Status | Emitted by |
|---|---|---|
| `surface/v1` | **live** | `actaira check` |
| `surface-diff/v1` | **live** | `actaira diff` |
| `seal/v1` | **live** | `actaira seal` |
| `trace/v3` | **live** | `actaira scan`, `actaira watch` |
| `trace/v2` | frozen history - read, never written | nothing |
| `trace/v1` | frozen history - read, never written | nothing |

A frozen revision stays on disk so a document an earlier build wrote still
parses. It is not a contract a consumer should expect new documents against, and
a test asserts nothing emits one. [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md)
records what superseded each and why.

**`trace/v3` is the last revision before publication.** Three revisions in three
days was the versioning rule working while nothing consumed the format. Once
this is installed somewhere, the "nobody was using it" exemption is no longer
available, because somebody is.

Field names follow the OpenTelemetry GenAI semantic conventions. We do not
invent vocabulary where it already exists.

---

## How the repository is held up

```bash
make all      # lint, test, figures, release-check
```

The release gate refuses a tree whose parts disagree with each other: a figure
that drifted from what the code measures, a design note pointing at a line that
does not argue it, a schema version written in two places, a document naming a
test that no longer exists, a flag the documentation shows that the command does
not have, and a claim on this page that the parser contradicts.

2,328 tests over 36,860 lines of Python run on every commit, and both figures are
measured by `make figures` rather than typed: the gate refuses a tree where a
number in this file disagrees with what the code reports.

One check is worth naming because it is this release's whole theme. **Every
module of the package has to be reachable from the CLI or from the MCP server,
and `tests/test_reachability.py` fails on one that is not.** Before that test
existed, close to half this tree could not be reached from any command.

---

## The rest of the documentation

| | |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | What Actaira is, the invariants, and the rules the work follows. The only governance document. |
| [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) | What is promised across versions, and what is not. |
| [`docs/RULES.md`](docs/RULES.md) | Every rule, with its author, its version, the facts it needs and its violating configuration. Generated from the packs. |
| [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md) | The boundary between this open core and the hosted platform. |
| [`docs/DESIGN.md`](docs/DESIGN.md) | Every design decision with its rejected alternative, each naming the file and line that implements it. |
| [`docs/archive/`](docs/archive/) | The model scanner's documentation, archived unedited in phase A.1: formats, evaluation, architecture, threat model, both concept pages and the design sections that argue them. None of it describes this tree. |
| [`docs/ENGINEERING.md`](docs/ENGINEERING.md) | The gates, the type ratchet, and the defect ledger. |
| [`docs/BACKLOG.md`](docs/BACKLOG.md) | Known defects and deferred work, with reproductions. |

---

## Scope

This repository is the open core: the CLI, the trace format, the rule packages,
the report, and in time the self-hostable collector. The hosted platform is a
separate product, in a separate repository, under a separate licence, which
consumes the records this produces and contains none of this. See
[`docs/GOVERNANCE.md`](docs/GOVERNANCE.md).

## Contributing and licence

[`CONTRIBUTING.md`](CONTRIBUTING.md), [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md),
[`SECURITY.md`](SECURITY.md). Licensed under [Apache-2.0](LICENSE).
