# Compatibility

What this project promises not to break, and what it reserves the right to
change. Written because until 2.1.0 the only stable thing Actaira emitted was
`rule_id`, its own threat model said so, and that was both honest and a
ceiling. Nothing can be built on output that may move in any release.

## The three surfaces

| Surface | Versioned by | Promise |
|---|---|---|
| JSON Schemas in `src/actaira/schemas/` | `<name>/vN` in the document | Below |
| CLI commands, flags and exit codes | The package's SemVer | Below |
| Rule identifiers (`ACT-*`) | Never renumbered | A rule id means one thing forever |

Everything else, the wording of a message, the order of findings within a
severity, the internal module layout, the text of a design note, is not a
contract. Two things follow from that and both are deliberate: prose is
translated and rewritten freely, and no consumer should ever match on it.

## Schemas

A document declares its own version in `schema_version`. Read it first and
refuse what you do not understand; `receipt.verify` does exactly that, because
a future document may mean something different by a field you think you know,
and a partial check reported as a pass is worse than no check.

Within a major version `vN`:

- a field required in `vN` stays required;
- a field's type does not narrow;
- new optional fields may be added: every schema sets
  `additionalProperties: true` for this reason, so a consumer must tolerate
  fields it has never seen;
- an enum may gain a member. That narrows nothing for a producer and
  everything for a consumer that switches exhaustively, so it is recorded in
  `CHANGELOG.md` under the release that adds it. Handle unknown members.

Removing a field, promoting an optional field to required, or changing what a
field means is `vN+1`. The old schema stays in the package and both are
emitted for at least one minor release.

`tests/test_schemas.py` holds the required fields of every `v1` as a frozen
list. Dropping one fails the build rather than a consumer's parser.

## Current versions

| Schema | Version | Emitted by |
|---|---|---|
| `coverage` | `coverage/v1` | every report, every receipt |
| `report` | `report/v1` | `actaira scan --json` |
| `policy` | `policy/v1` | `actaira policy show --json` |
| `policy-decision` | `policy-decision/v1` | `actaira policy check --json` |
| `assurance-receipt` | `assurance-receipt/v2` | `actaira receipt issue` |
| `agent-bom` | `agent-bom/v2` | `actaira agent bom` |
| `model-bundle` | `model-bundle/v2` | `actaira bundle --json` |
| `source-snapshot` | `source-snapshot/v1` | `actaira snapshot`, `actaira watch --json` |
| `evidence-record` | `evidence-record/v1` | `actaira evidence list --json` |
| `asset-graph` | `asset-graph/v1` | `actaira graph export` |
| `trust-policy` | `trust-policy/v1` | read by `actaira trust check` |
| `subject-manifest` | `subject-manifest/v1` | read by `--subjects` |
| `attack-paths` | `attack-paths/v1` | `actaira agent paths --json` |
| `state-export` | `state-export/v1` | the local store's portable export |

`actaira schema` lists them; `actaira schema report-v1` prints one. They ship
with the package, so a `pip install` carries the contract.

One note about the local interface, because it is the newest consumer and the
easiest place for this promise to erode. `POST /api/graph` returns
`asset-graph/v1` exactly as `actaira graph export` writes it, and everything
the panel needs beyond it - display names, the currentness projection, the
neighbourhood that was walked - rides in a separate `view` object beside it. A
presentation need is not a reason to version a published schema, and a field
added to `nodes` because a drawing wanted it would be a change every other
reader of that contract would have to absorb.

The same rule decided the shape of 2.3.0's additions. `state-export/v1` gained
`decision_inputs` as a new optional array beside `decisions`, which is exactly
what the rule above permits, and specifically not as a nested array inside each
decision: a v1 consumer iterates `decisions`, and a row that grew a list is a
shape it was never written against. `evidence-record/v1` did not change at all,
because what a scan or an assessment establishes goes in the `payload` object the
contract already has. And the assembled consequence of one observation - what
changed, what it invalidated, what it reaches and which decisions it leaves open -
is deliberately **not** a published schema yet. [`CONTRACTS.md`](CONTRACTS.md)
says why, and the short version is that one of its semantics is still
`undetermined` and a version number would be a promise that it is not.

## Still readable, no longer written

A published contract stays published. A consumer written against
`assurance-receipt/v1` is not wrong, it is old, and an upgrade of this tool
that broke every receipt the previous one signed would make the whole promise
worthless. So these stay in the package, `actaira schema` keeps listing them,
and this release reads them:

| Superseded | Still verified by | Why it became a major |
|---|---|---|
| `assurance-receipt/v1` | `actaira receipt verify` | v2 describes typed subjects, evidence, snapshots and a graph, not a list of artifact reports |
| `agent-bom/v1` | any reader | `sub_agents` holds objects rather than names, and two fields moved from free text to a checked vocabulary |
| `model-bundle/v1` | any reader | `bundle_digest` is gone. It was a digest over the layout under a name that reads as the identity of the weights |

The asymmetry runs one way only and it is enforced by a test and by
`make release-check`: this release **reads** every version in that table and
**writes** none of them. A producer that can still emit an old shape will, on
some branch nobody exercised, and the reader on the other end will take the old
meaning out of a new document.

## Local state

`.actaira/state.db` has its own integer schema version, separate from the
package's and from the documents'. Migrations run forward only and are numbered
functions rather than files discovered by globbing, because a set found by a glob is
one where a rename or an unsorted filesystem changes what "version 4" means,
silently, because every individual statement still succeeds. A store written by
a newer Actaira is refused rather than guessed at: downgrading would mean
inventing what its extra columns meant.

Every migration is exercised against a fixture built by all the ones before it,
in `tests/test_state.py` and again in `make release-check`. A migration that has
never run is a migration that does not work.

2.3.0 takes the store to version 3, adding a `decision_inputs` table: what a
decision rested on, as typed rows rather than ids in a string. It is additive and
it rewrites nothing, which matters here for a reason a migration usually does not
have. A decision recorded under version 2 has no dependency rows, and the correct
reading of that is "this store cannot tell whether its inputs still hold" rather
than "its inputs are fine". A migration that invented rows to fill the gap would
have turned the decisions this release knows least about into the ones it
reassures you about.

The store is optional in both directions. Every command that existed in 2.1
still runs in a directory that has never been initialised, and a workspace with
no `.actaira/` issues receipts with no state references, which is exactly what
2.1 did and remains correct.

## Exit codes

These are part of the CLI contract. A pipeline branches on them, so a release
that changed one would change what deployments do without changing a line of
anyone's configuration.

| Code | Meaning |
|---|---|
| 0 | The command succeeded and nothing it checked objected |
| 1 | A verification that failed |
| 2 | Usage: bad arguments, or a key operation this tool refuses to perform |

This table says what the two commands of 3.0.0 can actually return, which is
less than 2.3.0 published. `--fail-on` and code `3` went to
`archive/model-scanner` with `scan` and `policy check`: a threshold flag and an
INCONCLUSIVE verdict are things a scanner produces, and nothing here inspects
an artifact any more. Leaving them in this table would have been the one thing
a compatibility document must never do, which is describe a surface that is not
there - a pipeline branching on `3` would have waited for an exit this tool
cannot reach.

Code `3` is expected back. "I could not tell" has to stay distinguishable from
"I decided no", and the trace-era equivalent is a contract whose conformance is
INDETERMINADO. It returns with the command that can be indeterminate, and it
will be published here on the release that adds it and not before.

One code is deliberately absent from the table above, because it is not part of
this contract: a `verify` whose stdout is closed early - `actaira verify --json
| head -3` - exits `141`, which is the shell's own convention for a process
killed by SIGPIPE. It reports a pipe that went away, never a verdict.

## Rule identifiers

`ACT-PKL-002` means what it meant in 0.1.0 and will mean it in 3.0.0. Rules
are added, and a rule may be widened, the same identifier over a superset of
what it used to catch, but an identifier is never reused for a different
finding and never renumbered. The prose next to it is translated and rewritten;
the identifier is what a SARIF consumer, a suppression file and a defect ledger
entry all key on.

## What is not promised

- Message text, in either language.
- The order of findings within one severity.
- Module paths and function signatures inside `actaira.*`. The CLI and the
  schemas are the interface; importing `actaira.formats.archive` and calling
  its internals is using a private API.
- `metadata` keys on a report that are not in the schema. They are diagnostic
  output and they move.
