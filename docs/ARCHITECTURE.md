# The module map

Where each decision lives. The picture of how the pieces fit together, and the
boundary between the parts that may reach the network and the parts that
decide anything, is in the README under
[Architecture](../README.md#architecture); this page is the directory.

The rule the layout enforces: **a component that can reach the network never
decides a verdict, and a component that decides a verdict never reaches the
network.** That is why a compromised registry can hand Actaira the wrong file
and cannot make it say the wrong thing about the file it got.

```text
src/actaira/
  formats/     detect by content; an exact abstract interpretation of the pickle
               value stack and memo, never an unpickler
  scan/        the allowlist, the denylist, and the reasoning between them
  coverage.py  per-surface states with a written reason, merged worst-wins
  marking.py   IPTC digitalSourceType and C2PA, read and written from bytes
  bundle.py    a repository resolved into members, relations and gaps
  subject.py   one reference type over artifacts, bundles, agents, systems, sources
  controls/    4 outcomes, a registry checked in both directions, Art. 50/12/15/11/53
  governance/  the obligation catalogue, the checkability tiers, the signed dossier
  policy/      a versioned document with a digest, and a decision with its proof
  trustpolicy.py  what this environment accepts, apart from what cryptography proved
  receipt.py   a signed statement of observed state, verifiable offline
  state/       SQLite with numbered migrations: snapshots, watch, evidence, graph
  agentgov/    agents, tools, MCP servers, the A-BOM, capabilities and attack paths
  agents/      cassette provider, BM25 retriever, judge, verifier, pipeline
  attest/      Merkle (RFC 6962), chain, signing, keyring, RFC 3161, DSSE, verify
  connectors/  sources that enumerate and stage, and never conclude
  schemas/     the published contracts, shipped inside the package
  report/      SARIF 2.1.0 and JUnit XML
  web/         stdlib server, hand-written UI, zero dependencies, 127.0.0.1 only
evals/         corpus, real-library corpus, marking survival, agent gold set
fuzz/          two engines, deterministic seeds
tests/         the suite, and the regression test named by each entry in the ledger
```

Every module carries its own design notes in its docstring, and
[`DESIGN.md`](DESIGN.md) consolidates them into one table indexed to the line
that argues each one. The modules are the source of truth; the table is
generated from them and the release gate refuses a tree where a row has
drifted from the line it points at.

## Reading order, if you are new to it

1. [`CONCEPTS.md`](CONCEPTS.md) for the vocabulary: subject, evidence,
   coverage, verdict, decision, receipt.
2. `src/actaira/formats/` for the part that reads bytes, and
   [`FORMATS.md`](FORMATS.md) for what is read of each format.
3. `src/actaira/coverage.py` for the idea that makes the verdicts honest: what
   was looked at, what was not, and why.
4. `src/actaira/policy/` for how an observation becomes ALLOW, DENY or REVIEW.
5. `src/actaira/attest/` for how a decision becomes something a stranger can
   check offline.
6. [`THREAT-MODEL.md`](THREAT-MODEL.md) for what none of it assumes.
