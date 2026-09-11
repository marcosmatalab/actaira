# What Actaira prints

Every block on this page came out of the tool on this release, and every one
is reproducible. It lives here rather than in the README because a landing
page is not the right place for a hundred and fifty lines of terminal output,
and because these blocks are worth reading slowly.

`models/` is two files: a 2x2 float32 safetensors with a single tensor named
`w`, and a 25-byte protocol 2 pickle that reduces through `posix.system`. The
digests follow from those bytes, so a reader who builds the same two files
sees the same output, character for character. The exact recipe is in
[`CONCEPTS.md`](CONCEPTS.md).

`scripts/cli_transcripts.py` builds them and runs the same three commands, and
the release gate runs it twice under different hash seeds and refuses a tree
where the two runs disagree. A tool whose report is signed into an attestation
does not get to print a different report for the same bytes.

Where a block is an excerpt rather than the whole run, it says so directly
underneath. Nothing is trimmed silently.

---

**`actaira scan`** reports the finding, the digest, and the scope of the claim in the same block:

```console
$ actaira scan models/

PASS          clean.safetensors
              format: safetensors (structure)  sha256:d1398981d27e3b57
              coverage
                + artifact metadata            COMPLETE       read end to end
                . raw tensor content           NOT ASSESSED   outside the scope of a static scanner
                . behavioural safety           NOT ASSESSED   would require running the artifact
                . organizational facts         NOT ASSESSED   not a fact any file can carry

FAIL          trojan.pkl
              format: pickle (structure)  sha256:48fc51f766e9c91b
  !! ACT-PKL-002  Pickle imports a callable with a documented path to code execution
       {"callable": "posix.system", "policy": "strict"}
     ACT-PKL-003  Pickle contains opcodes that call or instantiate at load time
       {"execution_opcodes": 1}
              coverage
                + load-time execution          COMPLETE       read end to end
                . raw tensor content           NOT ASSESSED   outside the scope of a static scanner
                . behavioural safety           NOT ASSESSED   would require running the artifact
                . organizational facts         NOT ASSESSED   not a fact any file can carry

2 artifact(s): 1 passed, 1 failed, 0 inconclusive
```

**`actaira watch`** distinguishes a first observation from an unchanged one, and a re-tag from bytes that moved:

```console
$ actaira watch demo

SOURCE      ./models
STATE       = BASELINE - first observation, there was nothing to compare with
            first observation of this source; there was nothing to compare it with

  Changed subjects
    + file:///srv/models/benign_checkpoint.pt
    + file:///srv/models/trojan.pkl

$ actaira watch demo

SOURCE      ./models
STATE       ! CHANGED

  Changed subjects
    + file:///srv/models/benign_model.onnx
```

**`actaira policy check`** returns a decision with the rules and evidence that caused it, and a rule it could not evaluate becomes REVIEW:

```console
$ actaira policy check models/ --policy-file policies/production-model.yaml --on 2026-01-01

DENY      production-model v1
          policy digest: sha256:9a53c703acb078d8acb38d8fede432cec598bb2a2a0c8da80397e30359d3e535
          decided on: 2026-01-01

  because
    x no-high-severity-findings  [deny]  sha256:48fc51f766e9c91b
        finding_severity_at_least: {"threshold": "high", "findings": [{"rule": "ACT-PKL-002", "severity": "critical"}], "count": 1}
    ? signed-by-a-key-this-environment-trusts  [review]  sha256:d1398981d27e3b57
        the policy could not be evaluated against what this run observed
        signature_verified: {"unevaluable": "no attestation was supplied with this run"}
    ? signed-by-a-key-this-environment-trusts  [review]  sha256:48fc51f766e9c91b
        the policy could not be evaluated against what this run observed
        signature_verified: {"unevaluable": "no attestation was supplied with this run"}

  proof
    sha256:d1398981d27e3b57d1238517a62b94d2b4f815858c57a26b06eaec9e15515837
      + no-high-severity-findings                allow
      ? signed-by-a-key-this-environment-trusts  review
    sha256:48fc51f766e9c91b1202f8c59262e7b5b8950a4d117bd5a179ec662f3cb95a5d
      x no-high-severity-findings                deny
      ? signed-by-a-key-this-environment-trusts  review
```

Without that last rule going to REVIEW, `deny: when the signer is untrusted` would pass on a run with no attestation.

**`actaira verify`** answers two separate questions and refuses to blur them. Integrity: were the bytes changed after signing? Identity: who signed, and does this environment accept them?

```console
$ actaira verify release.actaira.zip --trusted-keyring keyring.json --require-trust

Verifying attestation package (written by actaira 2.2.0)
  [ok] every file matches the hash the manifest declares
  [ok] the attestation chain is self-consistent
  [ok] the head hash matches the last entry
  [ok] the Merkle root recomputes from the entries
  [ok] the signature verifies against a key in the package
  [ok] the in-toto Statement verifies against the same key
  [ok] the signing key was allowed to sign when this was signed
  [ok] the signing key is one you already trust

Time anchor: none (self_asserted)
Signing key: active (trusted_keyring)
Trust state: trusted
  ! NO TIME ANCHOR: the chain proves ordering, not when anything happened.

Result: OK
```

A package always carries its own public key, so integrity can always be checked and it proves nothing about identity: an attacker who rewrites a package also replaces the key inside it. A tool that prints one green tick over both is lying by omission.

**`actaira agent paths`** searches an agent declaration for routes rather than for pairs, and says what would break each one:

```console
$ actaira agent paths examples/agent-ticket-triage.yaml

ticket-triage  4

  !  ACT-PATH-001  A route carries sensitive material from untrusted input to a way out
     tool:fetch_url  (untrusted input)
       -> agent:ticket-triage  (the model's context)
       -> tool:read_deploy_key  (sensitive read)
       -> agent:ticket-triage  (the model's context)
       -> tool:fetch_url  (sink)
       carries: credentials
       break this route by:
         - require approval on fetch_url
         - stop fetch_url from returning outside text into this conversation, or remove it
         - move the sensitive read into a separate agent whose result never returns to this conversation, so the material is never in the same context as the sink

  8 open, 0 already closed
```

**That block is the first route of eight**, with the other seven cut between
the route and the count; the run prints all of them, and the count at the
bottom is the real one. Separate identities are the common case and they do not close this route: inside one agent every tool writes into one model's context, so a second identity changes who may *read* a credential, not who may *repeat* it. Reporting that as a fix would close a real finding with a control that does not apply to it.
