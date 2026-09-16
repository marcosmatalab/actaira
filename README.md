<div align="center">

**An independent witness for AI agents.**

Actaira produces verifiable evidence of what an agent did, compared against what it was authorised to do.

**Actaira 3.0.0** · Python 3.11 · 3.12 · 3.13 · Apache-2.0 · one runtime dependency · offline, no telemetry, no account

**[Español](README.es.md)** · [Quickstart](#quickstart) · [The four commands](#the-four-commands) · [Capture levels](#capture-levels) · [What Actaira refuses to do](#what-actaira-refuses-to-do) · [Limits](#published-limits) · [Docs](#the-rest-of-the-documentation)

</div>

---

## What this is

An agent runs. It reads files, calls tools, talks to a model provider. Afterwards
somebody asks what it actually did - and the only account available is the one
the agent wrote about itself.

Actaira captures that account **from outside the process**, decides
deterministically whether the run departed from what it declared, and emits a
record a third party can check without trusting the operator and without
trusting Actaira.

It is not a model scanner. It is not an observability platform. It is not a
compliance tool.

An Actaira record claims exactly three things and nothing else:

1. **Authenticity.** The trace was captured at the edge of the process, not
   produced by the agent about itself. It is signed, hash-chained, and declares
   the level it was captured at.
2. **Conformance.** The run conforms, does not conform, or is indeterminate
   against a contract. Where it does not conform, the record names the event,
   its index, and the rule.
3. **Inclusion.** The record is in an append-only log co-signed by witnesses.

Anything outside those three is a product defect, even when it is true.

---

## Quickstart

Five minutes, no agent installed, no network.

```bash
git clone https://github.com/<your-fork>/actaira
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

That block is the whole product in miniature. It read a session, said what it
saw, and then said - unprompted - that what it read cannot support the claim
the tool exists to make.

If you have Claude Code, Cursor or Cline on this machine, drop the `--demo` and
`actaira scan` reads the sessions they have already written to disk.

---

## The four commands

```
actaira scan      read the sessions an agent already recorded on this machine (L0)
actaira watch     record a run from outside the agent, through an MCP proxy (L1)
actaira verify    verify an attestation package offline
actaira keygen    create, rotate or revoke a signing key
```

That is the complete list. `actaira --help` prints the same four.

### `actaira watch` - recording from outside

`watch` puts an MCP proxy between the agent and its tool servers, runs your
command, and assembles what the proxy saw into one trace.

```console
$ actaira watch -- python -c "print('agent ran')"

agent ran
Recorded session 1587a6c3-ae8f-4d5a-915c-21e763c88b44 at capture level L1
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
  wrote the trace and its digest to ./actaira-watch
```

Read that output again, because it is the design. Nothing was observed, and the
tool said so three different ways rather than writing a clean empty trace. A
witness that reports silence as "nothing happened" is worse than no witness,
because somebody will rely on it.

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

Ed25519. The keyring lives beside the key.

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
else**, and names it. Every non-conformance publishes the rule's id, version,
package and author. From which it follows: calling a model on the decision path
is forbidden. An LLM may help draft a rule; it may not evaluate one, and it may
not write a remediation.

**3. Never infer the unobserved.** If the capture level did not cover something,
the record says so. A predicate with no information returns INDETERMINATE, never
False. Every rule declares the capture level it needs, and below that level it
returns INDETERMINATE on its own, without anybody remembering to check.

**4. Never act on what is observed.** Actaira *suggests* remediations; it never
applies them. A witness that also acts cannot attest to its own acts, and that
conflict of interest is exactly what separates this from an observability
vendor. If an `--apply` ever exists, the change is recorded as one more event in
the trace, attributed to Actaira, and evaluated by the engine like any other.
Never silently.

---

## Published limits

These are in the README, on the site, and in the record itself. They do not get
softened to sell better.

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
9. Conformance is not safety. An agent can conform to a bad contract.
10. A derived contract inherits the errors of the declaration it came from.

---

## The published contracts

3 schema documents ship in the package: one family, one live emitter.

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

1,567 tests over 23,932 lines of Python run on every commit, and both figures are
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
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | What an attacker can and cannot do to a record. |
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
