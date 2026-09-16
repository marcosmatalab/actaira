# Concepts

The vocabulary this tool uses, a tour that takes five minutes, and the full
command index. Written because every term below means something narrower here
than it does in a marketing page, and a reader who assumes the wide meaning
will read the output as a stronger claim than it is.

- [The nine nouns](#the-nine-nouns)
- [A five-minute tour](#a-five-minute-tour)
- [Every command](#every-command)
- [The state store](#the-state-store)
- [Where to go next](#where-to-go-next)

---

## The nine nouns

### Artifact

One file, identified by its SHA-256. A `.pt`, a `.onnx`, a `.safetensors`, a
`.gguf`, an `.h5`, a `.npy`, a bare `.pkl`. An artifact is the only thing
Actaira reads bytes from, and reading them never means loading them: the
pickle analyser is an exact abstract interpretation of the value stack and the
memo, not an unpickler with a filter.

### Bundle

A model *repository*, resolved into members, relations and gaps: shards, an
index, a config, a tokenizer, an `adapter_config.json` pointing at a base
model somewhere else, and whatever Python sits beside them. A bundle carries
two different digests on purpose:

| | |
|---|---|
| `structural_digest` | over the layout: paths, sizes, roles, and whatever member digests were computed. Always available. |
| `content_identity` | over the weights, with a state of its own: `complete`, `partial`, `externally_bound` or `unavailable`. |

They are separate because a digest over layout is not the identity of the
weights, and a tool that returned one digest would let a reader believe the
weights were pinned when only the file list was.

### Agent

A declaration: a model, a system prompt, a set of tools with declared effects,
MCP servers, and sub-agents. Actaira never talks to an agent. It reads what
the deployment says the agent is, and the agent digest covers the system
prompt as well as the tools, because changing the instructions changes
behaviour as thoroughly as changing a tool.

### System

Several of the above, named together as the thing an obligation actually binds:
a bundle plus an agent plus the sources they came from. Most compliance
questions are about a system, and answering them about a list of files is the
commonest category error in this space.

### Subject

The reference type that makes one policy language work over all of the above.
There are 5 kinds of subject, `artifact`, `bundle`, `agent`, `system` and
`source`, and `subject_kind` is a short-circuiting guard: a rule written about
bundles evaluates to "not applicable" against an agent rather than to false.

### Evidence

Something observed, bound to the digest of what was observed, with a state and
a lifetime. 5 evidence states:

| | |
|---|---|
| `valid` | observed, and the subject still has the digest it was observed at. |
| `stale` | older than the policy's `evidence_max_age_days` for this kind of claim. |
| `superseded` | the digest it was bound to is gone. A newer observation replaced it. |
| `revoked` | withdrawn deliberately, for example because the signing key was revoked. |
| `untrusted` | the signer is no longer accepted by this environment's trust policy. |

Supersession is bound to the digest, not to the name. A new revision of one
shard does not invalidate evidence about a sibling nobody touched, and a tool
that superseded by name would quietly throw away work that was still true.

### Trust policy

What *this environment* accepts, kept deliberately apart from what
cryptography proved. `actaira verify` answers "do these bytes match this
signature"; `actaira trust check` answers "and do we accept that signer". An
environment that has written no trust policy has refused nothing, so the
answer there is `UNKNOWN`, never `UNTRUSTED`.

### Receipt

The one output meant to leave the organisation that produced it, read by
somebody with neither the artifacts nor this tool. It carries the subjects by
digest, the coverage matrix, the findings by severity, the policy decision
with its proof and the supply-chain state, and it is signed over the canonical
JSON of itself minus the signature, which a third party can reimplement in
twenty lines.

It is not a certification and not a score. A test greps the finished document
for `score`, `grade`, `rating` and `percent` and fails on any of them, and
`states_what_it_does_not_cover` is a required field, because the commonest way
an assurance document misleads is by being read as exhaustive.

### Asset graph

Assets and the 12 relation kinds between them: `contains`, `uses`,
`uses_model`, `reads`, `writes`, `exposes`, `delegates_to`, `served_by`,
`runs_as`, `governed_by`, `supports`, `evidenced_by`.

Every edge carries `stated_by`: the manifest, agent declaration or snapshot
that asserted it. Nothing is inferred from two assets sharing a registry, an
organisation or a name. `actaira impact` walks those edges and answers with
the route:

```console
$ actaira impact source:huggingface://acme/fraud-model

  affected
    1 agent
    1 system

  re-evaluate
    agent:ticket-triage
    system:ticket-triage-service

  Why?
    agent:ticket-triage -> USES -> source:huggingface://acme/fraud-model
    system:ticket-triage-service -> USES -> agent:ticket-triage -> USES -> source:huggingface://acme/fraud-model
```

An impact report that listed everything nearby would be technically complete
and would train people to ignore impact reports.

---

## A five-minute tour

Every command below runs offline, against files this repository builds. Copy
the block; it works from a fresh copy of this tree after
`pip install -e ".[dev]"`.

**Minute 1: build a corpus and look at it.**

```bash
make eval                      # writes evals/artifacts/ from code, no download
actaira scan evals/artifacts/gadget_known_posix_system_p2.pkl
echo $?                        # 1: a finding at or above the failure threshold
```

The output names the rule, the callable, the digest and the coverage matrix.
Read the matrix: it is the scope of the claim above it, and it is printed for
clean artifacts too.

**Minute 2: ask what a policy makes of it.**

```bash
actaira policy check evals/artifacts --policy-file policies/production-model.yaml
```

DENY with the rules and the evidence that caused it. Notice the rule that came
back REVIEW: no attestation was supplied to this run, so `signature_verified`
had nothing to evaluate, and a predicate with no information goes to REVIEW
rather than quietly returning false.

**Minute 3: sign what was observed, then check it.**

```bash
actaira keygen --key key.pem
actaira attest evals/artifacts --out release.actaira.zip --key key.pem --dsse
echo $?                        # 1: the package is written, and the corpus has findings
actaira verify release.actaira.zip --trusted-keyring keyring.json --require-trust
```

Eight separate checks, printed separately. Integrity and identity are two
questions and the output never merges them. `--dsse` also writes an in-toto
Statement inside a DSSE envelope, so the same verdict can be consumed by
cosign and policy-controller instead of only by this tool.

**Minute 4: give it a memory.**

```bash
actaira init
actaira source add ./evals/artifacts --id corpus
actaira watch corpus            # BASELINE: there was nothing to compare with
actaira watch corpus            # UNCHANGED: nothing re-analysed, nothing written
touch evals/artifacts/benign_array.npy && printf '\0' >> evals/artifacts/benign_array.npy
actaira watch corpus            # CHANGED: only what moved is re-analysed
actaira evidence list
```

**Minute 5: ask what a change reaches, and what an agent could do.**

```bash
actaira graph build --subjects examples/subjects.yaml
actaira impact source:huggingface://acme/fraud-model
actaira agent check examples/agent-ticket-triage.yaml
actaira agent paths examples/agent-ticket-triage.yaml
```

`agent check` reports pairs of capabilities that are a bad combination.
`agent paths` reports the route between them and what would break it, and
reports a route an existing control already closes as closed, because a
finding that fires on a mitigation that is working is how a team learns to
ignore the output.

---

## Every command

Stateless, needs nothing but the files you point it at:

| | |
> **These two rows are the trace-era commands.** The rest of this page still
> describes the model scanner archived at `v2.3.0`; phase 5 rewrites it.
>
> | | |
> |---|---|
> | `actaira scan` | read the sessions an agent already recorded on this machine, as canonical traces. Capture level L0: the transcript was written by the audited agent, so authenticity is not evaluated and the trace is diagnosis rather than evidence. `--demo` runs on a synthetic session shipped with the package. |
> | `actaira watch -- <command>` | run an agent with an MCP proxy in front of each of its servers and record what it called, from outside it. Capture level L1. What the proxy could not observe is declared as a gap with its reason; a trace never comes out looking complete when it is not. |
>
> The MCP server is not a command. It is a second entry point, `actaira-mcp`,
> publishing `actaira_verify` plus `actaira_verdict` and `actaira_contract`,
> which return an explicit not-implemented state until phase 2.

|---|---|
| `actaira scan` | inspect artifacts, with `--format sarif`, `junit` or `json` |
| `actaira bom` | a CycloneDX 1.6 ML-BOM for what was inspected |
| `actaira bundle` | resolve a model repository into members, relations and gaps |
| `actaira agent` | `check`, `bom`, `diff` and `paths` over an agent declaration |
| `actaira controls` | `list` and `run` the executable controls, or `mark` synthetic output |
| `actaira governance` | `clock` which obligations bind, `assess` evidence against them, `pack` a signed dossier |
| `actaira policy` | `check` under a versioned policy, or `show` what one says |
| `actaira schema` | print a published JSON Schema, or list them |
| `actaira keygen` | create, rotate or revoke an Ed25519 signing key and its keyring |
| `actaira attest` | write a signed attestation package, offline |
| `actaira verify` | check one, answering integrity and identity separately |
| `actaira receipt` | `issue` and `verify` a signed statement of observed state |
| `actaira trust` | `check` a signer against this environment's trust policy |
| `actaira discover` | enumerate a remote source through a connector, staging nothing it did not name |
| `actaira serve` | a local, read-only interface on 127.0.0.1 |

Stateful, needs `.actaira/`:

| | |
|---|---|
| `actaira init` | create `.actaira/` and a versioned state database |
| `actaira source` | `add` and `list` the sources this workspace watches |
| `actaira watch` | observe a source now, compare with the baseline, record what moved |
| `actaira snapshot` | print or export the stored `source-snapshot/v1` for a source |
| `actaira evidence` | `list` what has been observed and `show` one record |
| `actaira graph` | `build`, `show` or `export` the declared relations between assets |
| `actaira impact` | what depends on this, and the exact route that reaches it |
| `actaira changes` | the observations this workspace has recorded, oldest first |
| `actaira decisions` | every recorded decision, and whether its inputs still describe its subject |

`actaira --lang es <command>` switches the output language. The flag is global,
so it goes before the subcommand, and a test fails if one language gains a
string the other does not have.

Every stateful command takes `--state` if you keep the database somewhere
else, and the commands that print a report take `--json` if you would rather
parse it; the ones that write a document take `--out` instead. Either way the
shape is a published contract: see [`CONTRACTS.md`](CONTRACTS.md).

---

## The state store

`.actaira/state.db` is SQLite from the standard library. It is optional: every
stateless command above works without it, and the state layer is memory rather
than a prerequisite.

**Migrations are forward-only and numbered.** `actaira init` creates the
current version; opening an older database applies each step in order. The
release gate applies every migration to a database built by all the ones
before it and refuses a release where any step has no fixture, because a
migration that has never run is a migration that does not work.

```bash
actaira init                            # store schema version 2
actaira snapshot corpus --out snap.json  # the stored source-snapshot/v1
actaira graph export --out graph.json    # asset-graph/v1
```

**The export is deterministic.** Two runs over the same observation produce
byte-identical documents, which the gate checks on every release: an export
that reordered rows would make every diff between two states unreadable, and
the first thing anybody does with a state export is diff it.

There is no import command and that is deliberate. A store is rebuilt by
re-observing the sources, which is cheap, offline and honest about when each
fact was established. An import would let a document assert a baseline that
nothing ever observed, and the whole point of the baseline is that something
did.

### Recorded, and what that word is doing there

The stored graph is every relation this workspace has ever recorded. It is not
a picture of what is there right now, and the distinction is not pedantic: a
source observed with two artifacts and then with one keeps both assets and
both `contains` edges. `watch` supersedes the evidence bound to the digest
that is gone, which is the invalidation an operator acts on, and it removes
nothing - which is right for a store whose purpose is to remember what was
seen when.

So nothing in this tool puts the word "current" over that graph. What can be
asked of it is a three-valued question, per node and per edge:

| | |
|---|---|
| `current` | the latest observation of this asset's source confirmed it |
| `not_in_latest_observation` | an earlier observation recorded it and the latest did not |
| `undetermined` | nothing in this workspace answers the question |

The third value is the honest one and it is not a corner case. An edge a
manifest declared carries no notion of which run of that manifest is live, so
its currentness is genuinely unknown, and calling it either of the other two
would be inventing a fact. Making it answerable needs a store that records
which declaration run is the current one - a stable declaration identity, its
digest, when it was observed, and which edges that exact run stated - which is
a change to the state layer rather than a reading trick. It is still open, and
it is named here rather than papered over with a timestamp and a
latest-write-wins guess.

```bash
actaira graph show                                  # every recorded relation
actaira graph show --focus agent:ticket-triage     --depth 2 --direction dependents                # what is within two hops
actaira impact tool:fetch_url                       # what a change reaches, with routes
```

`--direction dependents` walks towards what depends on the focus, which is the
direction `impact` walks; `--direction dependencies` walks the other way. Both
are bounded, and a view that stopped at its limit says so rather than looking
complete.

---

## When something changes

This is the loop the rest of the tool exists to serve, and each arrow is a
place a tool can quietly lie:

```
observe -> state -> change -> invalidate -> impact -> decide -> prove
```

**Invalidate.** Evidence is bound to the digest it was taken about, never to
the subject's name. So a new observation of a model that did not change
supersedes nothing, one of a model that did supersedes only the records about
the bytes that are gone, and a scan of a sibling nobody touched stays valid.
That is the difference between an invalidation somebody acts on and a page of
red nobody reads.

**Impact starts at what moved.** Not at the source that contains it. A source
holding forty files, one of which changed, has one changed artifact, and the
walk starts there. When two artifacts change and both reach the same system,
that system appears once with two causes under it: a reader asked to reassess
it needs to know it is downstream of two changes.

**Decide is two questions, not one.** What was decided is history and this
tool will not rewrite it - an ALLOW recorded in March prints as ALLOW forever,
because overwriting it destroys the only record of what was approved. Whether
it still applies is a separate question with its own three values:

| | |
|---|---|
| `current` | every input it recorded still describes its subject |
| `requires_reassessment` | at least one demonstrably does not, and here is which |
| `undetermined` | this workspace does not hold enough to say |

`requires_reassessment` is never reached by inference. It needs a row: an
evidence record whose state is not `valid`, or a subject whose recorded digest
differs from the one the decision named. "The model changed recently" is not a
reason. `{"reason": "evidence_superseded", "evidence_id": "ev_...", "was":
"sha256:...", "now": "sha256:..."}` is, and that is what the command prints
and what `--json` carries.

A decision filed before the store recorded dependencies has none, and is
`undetermined` rather than `current`. Reading "no inputs" as "nothing it
depended on has changed" would mark exactly the decisions this tool knows
least about as the ones needing no attention.

```bash
actaira scan models/model.pt --state .actaira/state.db   # files an artifact_scan record
actaira policy check --subjects examples/subjects.yaml \
    --policy-file policies/production-model.yaml --state .actaira/state.db
actaira watch corpus                                     # what moved, and what that cost
actaira decisions --state .actaira/state.db              # and which approvals that leaves open
```

`--state` is optional on every one of them, and it never creates a database.
A scan on a machine with no workspace behaves exactly as it did before any of
this existed, which is the local-first property the tool is worth having.

One thing the ledger does not do yet. Four of the seven evidence kinds have a
producer - `source_snapshot`, `artifact_scan`, `agent_assessment` and
`policy_decision`. `bundle`, `governance` and `attestation` are defined and
not yet written by anything, and that split is pinned by a test so it cannot
drift without somebody noticing.

---

## The two files every example uses

`models/` in the README's output blocks is two files, built from literal bytes
so their digests are the same everywhere: in the README, in the local
interface, and in whatever directory you build them in.

```bash
mkdir -p models
python3 - <<'PY'
import pathlib
models = pathlib.Path("models")
header = b'{"w":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]}}'
(models / "clean.safetensors").write_bytes(
    len(header).to_bytes(8, "little") + header + b"\x00" * 16
)
(models / "trojan.pkl").write_bytes(
    b"\x80\x02cposix\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03."
)
PY
```

`clean.safetensors` is a 2x2 float32 tensor named `w`: a valid file with
nothing in it to find. `trojan.pkl` is 25 bytes of protocol 2 pickle that
reduces through `posix.system`, which is the smallest thing that demonstrates
what the scanner is for. Their digests are `sha256:d1398981d27e3b57...` and
`sha256:48fc51f766e9c91b...`, and you should get exactly those.

`scripts/cli_transcripts.py` builds the same two files and runs the CLI
against them, which is where the console blocks in the README come from. The
release gate runs it twice under different hash seeds and refuses a tree where
the two runs printed different bytes.

---

## The local interface, and the one flag that changes what it can read

`actaira serve` runs a local read-only interface on 127.0.0.1. It needs
nothing: drop an artifact, an agent declaration, a policy document or an
attestation package on it and it answers with the same engine the CLI uses.

`actaira serve --state .actaira/state.db` adds one thing: the graph panel can
read that workspace. The flag is opt-in and everything else works without it.

```bash
actaira serve                                  # every panel except the graph
actaira serve --state .actaira/state.db        # and the recorded asset graph
```

Three properties of that flag are worth knowing, because they are the reason
it is a flag rather than a default.

**The path is chosen here and nowhere else.** No request can name a database.
A browser that could would be asking this process to open arbitrary files and
report whether they parsed.

**A read never writes.** Every other command migrates an older store forward
on the way in. The interface does not: it reports that the database is older
and names what would migrate it, because a page left open in a tab should not
rewrite anything.

**It is a disclosure, and it says so.** The graph names sources, digests,
identities and tool names, so binding this server off loopback with a
workspace configured warns about that as well as about the uploads.

---

## Using it somewhere other than a terminal

Three integration surfaces ship with the tool and are easy to miss, because
none of them is a command.

**As a pre-commit hook.** `.pre-commit-hooks.yaml` defines two: `actaira`
inspects the model artifacts in the commit, and `actaira-repo` inspects every
one in the working tree whenever any of them changes, which is what catches an
artifact committed before the hook existed.

This tree is not published anywhere, so the form that works today points at
an Actaira already installed in the environment:

```yaml
repos:
  - repo: local
    hooks:
      - id: actaira
        name: actaira (inspect model artifacts)
        entry: actaira scan --fail-on high
        language: system
        types: [file]
        files: '(?i)\.(pkl|pt|safetensors|onnx|gguf|npy|h5|joblib)$'
```

`.pre-commit-hooks.yaml` is the other half of that integration: the hook
definitions a `repos:` entry would point at if this tree were published, and
the file the release gate reads the version pin out of.

Both exit non-zero on an artifact that could not be fully read, not only on
one that failed, because that is the CLI contract and because "I could not
read this file" is not a reason to let it into a commit. Add
`args: [--allow-inconclusive]` if your repository decides otherwise: the
decision then lives in your config, visibly, instead of in the hook, silently.

**As a GitHub Action.** `.github/actions/actaira-scan` is a composite action,
not a Docker one, so it pins the tool to the tag the workflow asks for rather
than to whatever an image was last built with. It emits SARIF for code
scanning and fails the job on the severity you choose.

**In a container.** The `Dockerfile` at the root builds an image with the tool
and nothing else. It excludes the corpus builder, for the reason
[`SECURITY.md`](../SECURITY.md) gives: that script writes working gadget
pickles, and a published image is not where that belongs.

---

## Where to go next

| | |
|---|---|
| [`FORMATS.md`](FORMATS.md) | every rule, what it fires on, and what it does not cover |
| [`DESIGN.md`](DESIGN.md) | the design notes, each naming the file and line that implements it |
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | what this defends against, and what it does not |
| [`CONTRACTS.md`](CONTRACTS.md) | the published schemas, current and superseded |
| [`COMPATIBILITY.md`](COMPATIBILITY.md) | what a version promises not to break |
| [`FIGURES.md`](FIGURES.md) | every published number, and the command that produced it |
