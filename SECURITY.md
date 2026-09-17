# Security policy

Three things: how to report a vulnerability, which versions get fixes, and what
this tree actually consists of. Everything else this page used to say described
the model scanner, which left at 3.0.0, and a security policy that describes a
surface the tree does not have is the same defect as a compatibility page doing
it. The scanner's threat model, its section on the crafted artifacts its corpus
generated, and its build-attestation recipe are at tag `v2.3.0` and on
`archive/model-scanner`, unedited.

**The threat model for what comes next is deliberately not written here yet.**
Actaira is becoming a tool that reads configuration files out of repositories
other people wrote, which is attacker-controlled input in the most literal
sense. That deserves a real threat model rather than an anticipated one, so it
is written in phase S1, against the code that reads those files, and not
before. See [`CLAUDE.md`](CLAUDE.md) and [`README.md`](README.md) for what
exists today and what does not.

## Reporting a vulnerability

**This snapshot publishes no disclosure channel, and inventing one here would
be worse than saying so.** Actaira is a local repository: there is no hosted
issue tracker, no advisory page and no monitored address that belongs to the
project rather than to whoever is holding this copy. A security policy that
printed an address nobody reads would fail in exactly the way this project
exists to refuse - a green tick over something that was never checked.

So: **whoever distributes this tree is the one who has to open a channel, and
naming it is a precondition of distributing it.** Until then, report to the
person who gave you this copy, through whatever channel you already have with
them.

What helps, in rough order of usefulness:

1. The input, or a script that generates it. A generator is easier to review
   than a binary, and it lets a hostile input be described rather than
   attached. Please do not attach a working exploit against somebody else's
   repository or machine.
2. The exact command and the output you got, against the output you expected.
3. The version: `actaira --version`, and which snapshot of the source you are
   running, since there is no commit to name.

**What to expect.** This is a single-maintainer project with no company behind
it, so the honest commitment is: acknowledgement within seven days, an
assessment within thirty, and a fix released as soon as one exists. There is no
bug bounty. If you want credit in the release notes, say so; if you want none,
say that instead.

**Disclosure.** Coordinated, with a default of 90 days from the first
acknowledgement, shortened by agreement once a fix is out. If a fix takes
longer than that, the delay will be explained rather than used to postpone your
disclosure indefinitely.

## Supported versions

| Version | Supported |
|---|---|
| 3.0.x | yes |
| 2.x | no, and it is a different tool: see `archive/model-scanner` |
| 1.x, 0.x | no |

This table is about which code receives fixes, and not about documents. A
package written by an earlier version still verifies here, and a contract
published by one is still readable:
[`docs/CONTRACTS.md`](docs/CONTRACTS.md) records which schema versions are
current and which are superseded and kept.

## What is in this tree

Four commands, and the scope of a report is what they do.

- **`actaira scan`** reads session transcripts an agent already wrote to disk.
  The input is somebody's conversation, so arguments and results travel as
  salted digests unless `--with-content` is passed.
- **`actaira watch`** runs your command with an MCP proxy interposed and
  assembles what the proxy saw. It launches a child process that you named.
- **`actaira verify`** checks an attestation package offline. It opens no
  socket, and a test fails the suite if it does.
- **`actaira keygen`** creates, rotates and revokes an Ed25519 signing key on
  disk.

Three properties are worth reporting a violation of. **Nothing on the decision
path reads the clock, the network or the disk beyond what it was handed.**
**No command writes outside the output directory it was given**, and none
modifies the agent configuration or environment it read. And **no record claims
more than its capture level allows**: an L0 transcript was written by the
audited agent about itself, and it says so rather than being presented as
evidence.

A finding that is not about those, or about the offline and no-content
guarantees above, is a bug rather than a vulnerability, and
[`docs/BACKLOG.md`](docs/BACKLOG.md) is where it goes.
