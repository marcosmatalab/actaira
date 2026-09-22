# Governance

Where the line runs between this repository and a hosted product, if one is ever
built, and what would be allowed to cross it.

This page used to model obligations from Regulation (EU) 2024/1689 and describe
an `actaira governance` command. Both went with the model scanner: the
obligation catalogue had no reader in Python, the command did not parse, and a
governance page describing a surface that is not there is the same defect as a
compatibility page doing it. That material is at tag `v2.3.0`.

The model scanner itself is at that same tag, whole: `git ls-tree --name-only
v2.3.0` lists `evals/`, `fuzz/`, `policies/` and every module that went with
them. There is no archive branch to look for. A branch moves and a tag does
not, which is the argument this tool makes to everybody else in ACT-S003, and a
second pointer at one commit is a second thing that can come to disagree with
it.

---

## This repository is the open core

**Licence: [Apache-2.0](../LICENSE).** One licence, one repository, stated in
`LICENSE`, `pyproject.toml`, `CITATION.cff` and both READMEs. A release check
fails when any of those disagree, because the sentence above is the kind of
claim that is easy to write and easy to stop being true: this repository was
relicensed in phase A, which touched five files that nothing had ever compared.
CHANGELOG.md records what it was before.

What lives here, and stays here:

- **The CLI.** `scan`, `watch`, `verify`, `keygen` today; `check`, `diff` and
  `seal` as they are built. `docs/PRINCIPLES.md` lists seven and caps the list at eight.
- **The trace format, and the surface format beside it.** The `trace/vN`
  schemas, the OpenTelemetry GenAI field names, and the reader and writer for
  them; and, as they are built, the per-vendor configuration readers, the scope
  resolution with the merge rule each step cites, and the surface, diff and seal
  schemas.
- **The rule packages.** A rule's id, version, package, author, the capture
  level it requires, and its human-written remediation. A rule Actaira cannot
  show you is a rule you cannot argue with, and the second negative makes the
  norm somebody else's to write.
- **The report.** What a human reads after a check or after a run.
- **The self-hostable collector**, when it exists. Somebody who wants to run all
  of this inside their own network must be able to, with no account and no
  outbound connection.

That list is the product. None of it is a teaser for a paid tier, and none of it
is time-limited, seat-limited or telemetry-gated.

---

## If a hosted platform is ever built, it is a separate product

**There is no hosted platform today, and nothing in this page should be read as
saying there is one.** This section states the boundary in advance, because the
point of writing it now is that it is cheap now and expensive later.

The commitment, should one be built: **a separate repository, a separate
licence, and none of this in it.** It would consume the records this repository
produces. It would not extend them, fork them, or hold a privileged copy of
them: a record verified by a hosted platform and a record verified by `actaira
verify` on a laptop with no network would be checked by the same rules, and
neither answer would outrank the other.

This page is the only place that boundary is written, and it is an intention
rather than an artifact. Nothing in this tree can check it, and a document that
asserted a repository a reader cannot open would be doing what the third
negative forbids: stating what was not observed.

This matters more than it looks. The whole product argument is that a third
party can check a record **without trusting the operator and without trusting
Actaira**. A hosted service that was the only thing able to verify a record
would have quietly made itself the trusted party, which is the position this
tool exists to remove.

### Why the boundary is written down here

In an open core where the paid part lives under the same licence in the same
repository, the business gets given away by accident - not by a decision anybody
made, but by a file landing in the wrong directory on a Tuesday. Nobody notices
until it is irreversible, because the licence is irrevocable for what has
already shipped.

So the rule is structural rather than editorial: **if it is in this repository,
it is Apache-2.0, and it is free forever.** A feature that should be paid does
not get added here with a flag around it. It goes in the other repository, or it
does not get built.

---

## What crosses the wire

Decided here, implemented in phase P1, which is where the fleet collector and
the hosted platform first exist. This is the contract both are written against,
and it was decided before either, on purpose: a boundary drawn after the first
feature needs it is a boundary drawn around that feature.

**What may cross:**

| | |
|---|---|
| Rules that fired | The rule id, version, package and author of each, and nothing the rule was looking at |
| Resolution states | DECLARED, EFFECTIVE, INDETERMINATE, and for INDETERMINATE the named cause |
| Currency states | CURRENT, REQUIRES_REASSESSMENT, UNDETERMINED, and the digest an approval was granted over |
| Digests | Salted references to values, never the values |
| Counts | How many capabilities, how many events, how many rules fired |
| Gaps | Which holes a run declared, by reason code |
| Capture levels | L0 / L1 / L2 / L3, and which were in scope |
| Windows | When a session started and ended |

**What never crosses: content.** Not arguments. Not paths. Not code. Not file
names. Not prompts, results, environment variables, or the text of anything the
agent read or wrote.

The line is not "sensitive content". It is **content**, full stop, because
"sensitive" is a judgement somebody has to make correctly every time, on a
field whose value space belongs to a third party. A digest has no false
negatives and a secret filter does - the same argument `trace/redact.py` makes
one layer down, applied to the network boundary.

Three consequences worth stating, because each one is a thing the hosted product
cannot do and somebody will eventually ask for:

1. **The platform cannot show you what an agent read, or what it is configured
   to do.** It can show you that four files were read, at which capture level,
   which rules fired and over which digests. To see the file names, the hook's
   command or the script it points at, open the record on the machine that
   produced it. An approval is granted over a digest for exactly this reason:
   approving requires no content to cross.
2. **The platform cannot reproduce a run.** It never held the inputs.
3. **The platform cannot answer a question the digests do not answer.** A
   feature that needs content is a feature that needs the record, and the record
   stays where it was written.

A field added to the wire is a change to this page first and to the code second.
If those two ever disagree, this page is the one that is right and the code is a
defect.

---

## What this repository will not grow

From `docs/PRINCIPLES.md`, repeated here because this is the page somebody reads before
proposing one:

- No dashboard, no server mode, no multi-tenancy in this tree.
- No second governance document. `docs/PRINCIPLES.md` is the only one, and this page is
  subordinate to it.
- No runtime dependency beyond `cryptography` without an explicit decision
  justified in `pyproject.toml` itself.
- No model on the decision path, and no remediation written by one.
- No executing what a hook, a task or an MCP server declares. Configuration is
  read, cited and bound to its digest. A tool that runs the thing it is
  analysing to find out what it does is the delivery mechanism.

---

## Contributions

By contributing you agree your contribution is licensed under Apache-2.0, like
the rest of this repository. See [`CONTRIBUTING.md`](../CONTRIBUTING.md).

There is no contributor licence agreement and no copyright assignment. A CLA
would let this repository be relicensed later without asking, and given
everything above about the boundary, a project that reserves the right to close
its open core has not really drawn one.
