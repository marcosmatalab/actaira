<div align="center">

**Change control for what your AI agents can do.**

Actaira reads the configuration your coding agents load, resolves what it actually lets them do, and says what changed between two moments.

**Actaira 3.0.0** · Python 3.11 · 3.12 · 3.13 · Apache-2.0 · one runtime dependency · offline, no telemetry, no account

**[Español](README.es.md)** · [Quickstart](#quickstart) · [The five commands](#the-five-commands) · [Capture levels](#capture-levels) · [What Actaira refuses to do](#what-actaira-refuses-to-do) · [Limits](#published-limits) · [Docs](#the-rest-of-the-documentation)

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

**None of the three is built.** They are stated here anyway, in the place a
finished product would be described, because the alternative is a page that
describes an intention in the present tense - which is the defect this project
spent phase A.1 removing rather than a habit it kept. What the tree can do
today is further down, under [the four commands](#the-four-commands).

**1. Surface** - what an agent can do in this repository or on this machine,
resolved across scopes and vendors. Every capability cites the file it came
from, the documented merge rule that resolved it, with the URL and version of
the vendor documentation that states it, and the Actaira rule that names it.

> **Does not exist.** No reader, no resolver and no rule package in this tree.
> `actaira check` arrives in phase S1, for Claude Code and its four scopes;
> phase S2 adds Codex, Cursor, Gemini CLI, the VS Code task file, the
> devcontainer and AGENTS.md.

**2. Change** - which capability appears, disappears, widens or narrows between
two moments.

> **Does not exist.** `actaira diff`, the signed surface baseline `actaira
> seal` writes, the report and the GitHub Action arrive in phase S3. Phase S4
> adds the machine baseline, which is where a hook planted in the user scope
> rather than in a repository becomes visible at all.

**3. Currency** - whether an approval or a piece of evidence still describes
what is there. Bound to digests, never to names and never to dates.

> **Does not exist**, and it is the one of the three that already has its
> argument written down: [`docs/DESIGN.md`](docs/DESIGN.md) §10 keeps the
> reasoning for the five evidence states and for supersession bound to a digest
> rather than to a subject's name, from the `state/` package phase A removed
> for being unreachable. Its consumer is phase P1.

And what none of the three may claim, stated here rather than left to be
inferred: **configuration declares; it does not demonstrate behaviour.** A hook
that is written is not a hook that ran, and a hook that is absent is not proof
that nothing ran. Whatever could not be resolved is INDETERMINATE, counted
apart, and never distributed across the answers that were.

What this tree does today is neither: it reads what an agent recorded about a
run, and it records one from outside the agent where it can. That is the
[capture ladder](#capture-levels) below, and it is kept because a change to a
configuration and the sessions that ran after it are the same question asked
twice.

---

## Quickstart

Five minutes, no agent installed, no network.

```bash
git clone https://github.com/marcosmatalab/actaira
cd actaira
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

One runtime dependency (`cryptography`). Then:

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

If you have Claude Code, Cursor or Cline on this machine, drop the `--demo` and
`actaira scan` reads the sessions they have already written to disk.

---

## The five commands

```
actaira check     read this repo's agent configuration and resolve what it permits
actaira scan      read the sessions an agent already recorded on this machine (L0)
actaira watch     record a run from outside the agent, through an MCP proxy (L1)
actaira verify    verify an attestation package offline
actaira keygen    create, rotate or revoke a signing key
```

That is the complete list of what works, and `actaira --help` prints the same
five. [`CLAUDE.md`](CLAUDE.md) lists seven, each unbuilt one carrying the phase
it arrives in; `tests/test_cli.py` fails on a name in that list that neither
exists in the parser nor says when it will.

### `actaira check` - what an agent can do here

`check` reads the agent configuration in this repository, resolves what it
actually permits across scopes, and applies the rule packs. It reads Claude Code
today; the other vendors arrive in phase S2 and until then every one of their
files that is on disk is printed in the report's "not read" list.

```
actaira check                                   # this repository
actaira check --machine                         # and the user and managed scopes
actaira check --agent-version claude-code=2.1.257
actaira check --json                            # a surface/v1 document
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

> **Read this before you try it: no command in Actaira 3.0 produces a package.**
> `verify` reads attestation packages written by the 2.x model scanner, and the
> command that wrote them (`actaira attest`) went to `archive/model-scanner`.
> The writer is still in the tree - `attest/package.py::write_package` - and
> nothing outside the test suite calls it. So `verify` is a reader with no
> matching writer in this release: useful if you are holding a 2.x package,
> useless if you are not, and kept because the day this tree signs something
> of its own, which is the surface baseline `actaira seal` writes in phase S3,
> the verifier is the half that has to already be right.
>
> `tests/test_reachability.py` does not catch this. It asks whether every module
> is reachable from a command, and `attest/` is: `verify` reaches all of it. It
> does not ask whether the product's chain closes - whether anything this tool
> writes is anything this tool can verify. `docs/BACKLOG.md` carries the line.

```bash
actaira verify attestation.zip
actaira verify attestation.zip --trusted-keyring keys.json --require-trust
```

Offline, always. Integrity and identity are separate answers: a package always
carries its own key, so integrity is always checkable, and "nobody vouched for
this key" is reported as exactly that rather than as a failure. Supply
`--trusted-keyring` or `--pubkey` to bind it to a key you already trust.

### `actaira keygen` - the signing key

```bash
actaira keygen                      # create
actaira keygen --rotate             # retire the current key, keep verifying old packages
actaira keygen --revoke <key-id>    # nothing it ever signed is accepted again
```

Ed25519. The keyring lives beside the key. Same caveat as `verify`: this
manages the key that signs a package, and nothing in 3.0 writes one. Rotation
and revocation are exercised end to end by the suite, against packages the suite
builds itself.

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

> **Three of these four are constraints on code that is not written yet.** There
> are no rules, no predicates and no remediations in this tree, so the second
> negative has no rule to cite, the third has no predicate to return
> INDETERMINATE, and the fourth has no remediation to decline to apply. They are
> written down now, before the code exists, because a constraint adopted after
> the fact is one that gets argued with; and the third is already load-bearing
> in what does exist - `scan --demo` declares that authenticity cannot be
> evaluated at L0, and `watch` declares the holes it could not see through
> rather than reporting a clean run.
>
> The first negative is enforced today, over every document this tree emits, by
> `tests/test_no_aggregate.py`.

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

4 schema documents ship in the package: one family, one live emitter.

| Contract | Status | Emitted by |
|---|---|---|
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
test that no longer exists.

1,819 tests over 28,056 lines of Python run on every commit, and both figures are
measured by `make figures` rather than typed: the gate refuses a tree where a
number in this file disagrees with what the code reports.

One check is worth naming because it is new and it is this release's whole
theme. **Every module of the package has to be reachable from the CLI or from
the MCP server, and `tests/test_reachability.py` fails on one that is not.**
Before that test existed, close to half this tree could not be reached from any
command.

---

## The rest of the documentation

| | |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | What Actaira is, the invariants, and the rules the work follows. The only governance document. |
| [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) | What is promised across versions, and what is not. |
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
