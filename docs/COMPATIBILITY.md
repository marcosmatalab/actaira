# Compatibility

What this project promises not to break, and what it reserves the right to
change. Written because until 2.1.0 the only stable thing Actaira emitted was
`rule_id`, its own threat model said so, and that was both honest and a
ceiling. Nothing can be built on output that may move in any release.

This page was rewritten in phase A because it had become the thing a
compatibility document must never be. It published fourteen schemas when nine
were on disk, and it documented seven commands — `actaira receipt issue`,
`actaira policy check --json`, `actaira schema`, `actaira agent bom`, `actaira
bundle --json`, `actaira graph export`, `actaira trust check` — **none of which
parsed**. A promise about a surface that is not there is worse than no promise:
a consumer builds against it and discovers the gap at runtime.

Everything below is checked. `scripts/release_check.py` refuses a release where
the contracts on disk, the registry, and this page disagree.

## The three surfaces

| Surface | Versioned by | Promise |
|---|---|---|
| JSON Schemas in `src/actaira/schemas/` | `<name>/vN` in the document | Below |
| CLI commands, flags and exit codes | The package's SemVer | Below |
| Rule identifiers (`ACT-*`) | Never renumbered | A rule id means one thing forever |

Everything else — the wording of a message, the internal module layout, the
text of a design note — is not a contract. Two things follow, both deliberate:
prose is translated and rewritten freely, and no consumer should ever match on
it.

## Schemas

A document declares its own version in `schema_version`. Read it first and
refuse what you do not understand: a future document may mean something
different by a field you think you know, and a partial check reported as a pass
is worse than no check.

Within a major version `vN`:

- a field required in `vN` stays required;
- a field's type does not narrow;
- new optional fields may be added: every schema sets
  `additionalProperties: true` for this reason, so a consumer must tolerate
  fields it has never seen;
- an enum may gain a member. That narrows nothing for a producer and everything
  for a consumer that switches exhaustively, so it is recorded in
  `CHANGELOG.md` under the release that adds it. Handle unknown members.

Removing a field, promoting an optional field to required, or changing what a
field means is `vN+1`. The old schema stays in the package.

`tests/test_schemas.py` holds the required fields of every version as a frozen
list. Dropping one fails the build rather than a consumer's parser.

The version is written in exactly one place, `schemas.VERSIONS`. There used to
be a second copy in each emitting module and a test asserting the two agreed;
that test passes for as long as somebody keeps two copies in step, and what it
was really protecting is that there should be one copy. It is inverted now:
`release_check.py` fails on a version literal written anywhere under `src/`
outside the registry.

## Current versions

| Schema | Version | Emitted by |
|---|---|---|
| `trace` | `trace/v3` | `actaira scan`, `actaira watch` |

One family, one live revision, and it is the only document this tree writes.

**`trace/v3` is the last revision before publication.** Three revisions in three
days was the versioning rule working correctly while nothing consumed the
format — each is explained below. From the moment somebody installs this, the
"nobody was using it" exemption is not available, because somebody is. A change
that needs `trace/v4` after that needs a migration note, a deprecation window,
and a reader that accepts both.

Field names follow the OpenTelemetry GenAI semantic conventions from
`open-telemetry/semantic-conventions-genai`. Where the document leaves those
conventions, `trace/model.py` writes down which field and why.

## Still readable, no longer written

A published contract stays published. A consumer written against `trace/v1` is
not wrong, it is old, and an upgrade that broke every document the previous
build wrote would make the whole promise worthless. So these stay in the
package and this release reads them.

They are **frozen history, not live contracts.** The difference matters and
nothing used to state it: a consumer who sees a schema file ship assumes new
documents may arrive against it. None will.
`tests/test_schemas.py::test_no_document_this_tree_emits_declares_a_superseded_revision`
runs the emitters and reads the version back out of what they produced, so this
is checked against real output rather than against a constant.

| Superseded | Superseded by | Why it became a major |
|---|---|---|
| `trace/v1` | `trace/v2` | MCP revision 2026-07-28 removed the session that every correlation in v1 rested on. Facts established once per session became per-event, and seven new gap reasons came with them. Widening a closed enum narrows nothing for a producer and everything for a consumer that switches exhaustively, which the rule above calls `vN+1`. |
| `trace/v2` | `trace/v3` | Six fields stopped carrying a third-party value and started carrying a salted reference to it (D-268). That is a change to what a field **means**, and the rule says there is no other way to do that, "including *nobody was using that one*". `trace/v2` had been published for twenty minutes and had no consumer. The exemption was still not taken, because the first time a rule is bent is the last time it is a rule. |

The asymmetry runs one way only and `make release-check` enforces it: this
release **reads** every version in that table and **writes** none of them.

### What left, and where it went

`coverage/v1`, `policy/v1`, `policy-decision/v1`, `assurance-receipt/v2` and
`evidence-record/v1` were on disk with **no emitter in this tree**. Phase A
removed them with the modules that used to write them. That is a break rather
than a tidy-up, and it is recorded as one.

`report/v1`, `model-bundle/v2`, `agent-bom/v2`, `asset-graph/v1`,
`attack-paths/v1`, `source-snapshot/v1`, `subject-manifest/v1`,
`trust-policy/v1`, `state-export/v1` and `assurance-receipt/v1` went the same
way at 3.0.0.

All of them stay readable at tag `v2.3.0` and on the `archive/model-scanner`
branch. Shipping a schema file with no emitter publishes a contract the tool
cannot honour, and reads to a consumer as still supported.

## Commands

Four, and `actaira --help` prints the same four.

| Command | What it does |
|---|---|
| `actaira scan` | Read the sessions an agent already recorded on this machine (L0) |
| `actaira watch -- <command>` | Record a run from outside the agent, through an MCP proxy (L1) |
| `actaira verify <package>` | Verify an attestation package offline |
| `actaira keygen` | Create, rotate or revoke a signing key |

`tests/test_no_aggregate.py::test_the_enumeration_names_every_emitter_this_tree_has`
and `release_check.py` both fail when this list and the parser disagree.

CLAUDE.md allows eight commands and this tree implements four. `contract`,
`verdict`, `receipt` and `fix` are named there and are not built; they are not
documented here, because a command that does not parse is not a compatibility
surface.

## Exit codes

A pipeline branches on these, so they are a contract in the strictest sense: a
release that changed one would change what deployments do without changing a
line of anyone's configuration.

| Code | Meaning |
|---|---|
| 0 | The command succeeded and nothing it checked objected |
| 1 | A verification that failed |
| 2 | Usage: bad arguments, or a key operation this tool refuses to perform |

This is less than 2.3.0 published. `--fail-on` and code `3` went to
`archive/model-scanner` with the scanner: a threshold flag and an INCONCLUSIVE
verdict are things a scanner produces, and nothing here inspects an artifact.
Leaving them here would have been the one thing a compatibility document must
never do — a pipeline branching on `3` would wait for an exit this tool cannot
reach.

Code `3` is expected back. "I could not tell" has to stay distinguishable from
"I decided no", and the trace-era equivalent is a contract whose conformance is
INDETERMINATE. It returns with the command that can be indeterminate, and it
will be published here on the release that adds it and not before.

One code is deliberately absent from the table, because it is not part of this
contract: a `verify` whose stdout is closed early — `actaira verify --json |
head -3` — exits `141`, the shell's own convention for a process killed by
SIGPIPE. It reports a pipe that went away, never a verdict.

## Rule identifiers

A rule identifier means one thing forever. Rules are added, and a rule may be
widened — the same identifier over a superset of what it used to catch — but an
identifier is never reused for a different finding and never renumbered. The
prose next to it is translated and rewritten; the identifier is what a
suppression file and a defect ledger entry key on.

**This tree currently emits no rule identifiers.** The forty-one the message
catalogue carried belonged to the model scanner and to the conformance package,
both of which left, and dead text that would be translated and reviewed forever
is not a contract either. `tests/test_i18n.py` asserts both directions: a rule
id in `src/` with no catalogue entry fails, and a catalogue entry with no rule
fails. The rule packages arrive in phase B with their own identifiers, authors
and versions.

## What is not promised

- Message text, in either language.
- Module paths and function signatures inside `actaira.*`. The CLI and the
  schemas are the interface; importing an internal module and calling it is
  using a private API. Phase A moved a great deal of code out of this package
  precisely because nothing reachable used it.
- `metadata` keys on a document that are not in the schema. They are diagnostic
  output and they move.
- The local record files `watch` writes under its output directory before the
  trace is assembled. The assembled trace is the contract; the per-server
  `.jsonl` records beside it are an implementation detail.
