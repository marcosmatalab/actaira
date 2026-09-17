# Security policy

Actaira is a tool people point at files they do not trust. That makes two
things true at once: a defect here can be reached by an attacker who only
controls a model artifact, and a false sense of safety here is itself a
security problem. Both are treated as vulnerabilities.

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
them. Please do not post a working exploit against a third party's model
repository.

What helps, in rough order of usefulness:

1. The artifact, or a script that generates it. Actaira's own corpus is
   generated from code (`evals/corpus/build.py`) precisely so that hostile
   inputs can be described rather than attached, and a generator is easier to
   review than a binary.
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
| 2.2.x | yes |
| 2.0.x, 2.1.x | no, upgrade to 2.2 |
| 1.x, 0.x | no, upgrade to 2.2 |

Two things this table is not about.

It is not about attestations. A package written by any earlier version still
verifies under 2.2.0, and a contract published by one is still readable: see
[`docs/CONTRACTS.md`](docs/CONTRACTS.md) for which schema versions are current
and which are superseded but kept. The table is about which code receives
fixes.

And 2.2.x is the closed core. What that means for a report is that a fix lands
in 2.2.x rather than in a 2.3 that does not exist: the branch is frozen for
features, not for security.

## In the threat model

`docs/archive/THREAT-MODEL.md` is the long form, archived in phase A.1 because it
was written about the model scanner. These are the classes of report that
count as vulnerabilities:

* **Anything that executes.** Actaira's central claim is that nothing is ever
  loaded or executed. Any input that causes code from the artifact to run - via
  the pickle path, the archive path, the HDF5 path, or anywhere else - is the
  most serious report this project can receive.
* **An artifact that reaches `PASS` when it should not.** A gadget the scanner
  walks past, an import it resolves to the wrong thing, a truncated stream it
  treats as fully read. `INCONCLUSIVE` exists so that "I could not read this"
  never has to be reported as success; a path that skips it is a defect.
* **A crash, a hang, or unbounded memory** from a hostile artifact. The parsers
  are fuzzed (`make fuzz`) against exactly this property: for any bytes,
  inspection terminates, does not raise, and does not allocate without bound.
* **A forged attestation that verifies.** An edited package that passes
  `actaira verify`; a Merkle inclusion or consistency proof that verifies
  against a log it does not belong to; a signature accepted under the wrong key;
  a revoked or out-of-window key accepted; an RFC 3161 token accepted over a
  manifest it does not cover.
* **A verification that overstates itself.** If Actaira prints a green result
  for something it did not actually check, that is a bug of the same weight as
  a missed gadget. The states `embedded_key_only`, `tsa_chain: "not_verified"`,
  `time_evidence: "self_asserted"` and `INCONCLUSIVE` exist to make the limits
  visible; a path that loses one of them is a security defect.
* **The review interface** (`actaira serve`). It binds `127.0.0.1` and is meant
  for local review, but path traversal, a request that reaches outside the
  workspace, or anything that turns a submitted artifact into a request to
  another host is in scope.
* **The GitHub Action definition and the pre-commit hook definition** in this
  tree. Command injection through an input, output injection into
  `GITHUB_OUTPUT`, or a path where a failing scan does not fail the job.
  Neither is a service running anywhere; both are files somebody may import
  into a pipeline, which is precisely why a defect in them is in scope.
* **Key handling.** The private key is written `0600` before any key material
  reaches the file. Anything that widens that, leaks a key path where it should
  not, or writes key material into a package is in scope.

## What the host operating system decides

Two of this document's claims are claims about a POSIX kernel, and where that
kernel is not the one running the tool, they do not hold. Saying which, and
where, is the point of this section: a security document that states a
protection without stating what it depends on is the same failure as a green
tick over something that was not checked.

* **Key file permissions.** The private key and the keyring are created with
  `os.open(..., O_CREAT, 0o600)` - the restriction is part of the create, so
  there is no window in which the file exists, holds key material and is
  readable by everyone. That is Actaira's decision and it is the same on every
  platform. What the kernel then does with the mode argument is not: on
  Windows the POSIX bits are not enforced, and the file ends up governed by the
  directory's inherited ACL like any other file. **On that platform the key is
  as protected as the directory it is in, and no more.** Put it somewhere only
  your account can read, or pass `--key` a path on an encrypted volume.
  `tests/test_keyring.py` asserts the argument everywhere and the resulting
  bits only where they mean something, and says so in the skip reason rather
  than passing quietly.

* **Fuzzing oracles.** `make fuzz` holds every parser to four promises. Two of
  them - bounded memory and per-case termination - are enforced by `RLIMIT_AS`
  and `SIGALRM`, which are POSIX. On a host without them the run still executes
  every case and still checks the other two, and every run summary carries an
  `unenforced_oracles` list naming what it could not hold the parser to.
  A fuzz run reporting no findings is only as strong as that list is empty.

Neither of these is a defect in the tool, and neither is a reason not to run it
on Windows. They are the two places where "this is protected" means "the kernel
protects it", and a reader is entitled to know which kernel.

## Not in the threat model

Saying this plainly is part of the policy, so that a report is not dismissed
quietly as "working as intended":

* **Actaira does not sandbox anything, and never claims to.** It reads bytes and
  decides from them. It cannot see behaviour that only exists at run time, and
  an import built at run time from data the analysis cannot follow is reported
  as undecidable (`ACT-PKL-009`) rather than resolved. That is a documented
  limitation (D-05), not a vulnerability.
* **A malicious artifact that Actaira reports correctly is not a
  vulnerability.** The finding is the product working.
* **No trust store ships with Actaira.** A signing key with no anchor is
  reported as `embedded_key_only`, and a timestamp authority's certificate chain
  as `tsa_chain: "not_verified"`. Those are stated limits; a report that they
  *are not stated* would be a real one.
* **Resource limits are budgets, not guarantees.** Handing the tool a very large
  file, or a directory of them, will take time and memory proportional to what
  you handed it. The documented caps (opcode budget, member counts, size caps)
  are what stop a small file from costing a lot; a large file costing a lot is
  arithmetic.
* **Findings on files you supplied.** Actaira scans what you point it at,
  including files inside its own repository.

## This repository contains malicious model artifacts

Deliberately, and they are never committed.

`evals/corpus/build.py` writes real, working gadget pickles - `posix.system`,
`subprocess.Popen`, `builtins.eval`, the copyreg extension registry, a Keras
Lambda layer carrying a marshalled code object, and about fifty more - into
`evals/artifacts/` when the eval harness or the test suite runs, and into a
temporary directory during tests. They are what the detection figures are
measured on. Three consequences worth knowing before you run anything here:

* **They are generated, not stored.** `evals/artifacts/` is in `.gitignore`,
  and no artifact from it has ever been committed. What is in the tree is the
  code that constructs them, which is easier to review than a binary and cannot
  be executed by being copied. `make package` checks the same property for the
  wheel and the sdist, and fails the build rather than warning.
* **They are never loaded.** Not by Actaira, not by the harness, not by the
  tests. They exist as bytes to be read.
* **Your scanner may flag this repository, and it is not wrong to.** A file that
  builds `REDUCE` opcodes calling `posix.system` looks exactly like what it is.
  If a corporate scanner objects to the source, that is a policy conversation,
  not a false positive.

The image built from this `Dockerfile` contains none of it: the build context
is an allowlist of four entries (`.dockerignore`), so the image carries the
package and nothing else. `make package` checks the same property for the
wheel and the sdist and fails the build rather than warning.

## Verifying what you built

There is no release to verify. Nothing here is published, so there is no
signed release package and no upstream key, and this section would be the
easiest place in the repository to imply otherwise.

What the tree does give you is reproducibility and the machinery to attest a
build yourself. `make package` builds the wheel and the sdist into `dist/`
and writes `dist/SHA256SUMS` beside them, so two builds of the same source can
be compared without trusting either:

```
make package
sha256sum -c dist/SHA256SUMS
```

To turn that into something a third party can check, sign it with the tool's
own attestation machinery, using a key you generated:

```
actaira keygen --key ./release-key.pem
actaira attest dist/ --key ./release-key.pem --out release.actaira.zip
actaira verify release.actaira.zip --trusted-keyring keyring.json --require-trust
```

Handed that package with nothing else, a verifier gets:

```
Trust state: embedded_key_only
  ! INTEGRITY VERIFIED, IDENTITY NOT VERIFIED: the package was checked against
    the public key it carries. Supply --trusted-keyring or --pubkey to bind it
    to a key you already trust.
```

That is the honest state for a package whose key the verifier has not seen
before, and the tool prints it rather than showing a tick. A key generated on
the machine that built the artifact proves the two came from the same place and
nothing more, which is exactly as much as it should be read to prove: the
verifier has to have got your public key some other way for
`--require-trust` to mean anything.
