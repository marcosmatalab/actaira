# Actaira: threat model

This document states who Actaira defends against, what it defends, and what it
does not defend. The list of things it cannot do is the longer half and it is
not an appendix. A supply-chain tool whose limits are only discovered in
incident review is worse than no tool, because it will have been trusted.

Terminology used throughout: an **artifact** is one file the tool is pointed at,
an **inspector** is the code path selected for its detected format, and a
**verdict** is one of PASS, FAIL or INCONCLUSIVE
(`src/actaira/model.py:41`).

## 0. Components, and where the boundaries are

Until 2.1.0 this document described one thing, because there was one thing: a
scanner that read bytes and never opened a socket. That stopped being true when
the discovery layer landed, and the document did not notice: it still said
"exactly one outbound connection, and only when asked" while the package
contained connectors for GitHub, Hugging Face, S3, OCI and MLflow. A threat
model that describes a previous version of the product is worse than none: it
is trusted, and it is wrong in the direction of reassurance.

So the components are separated, and each one's network posture is a property
of the component rather than of "Actaira".

| Component | Does | Network | Executes the artifact | Writes to disk |
|---|---|---|---|---|
| `actaira.formats`, `inspect`, `bom`, `coverage` | Parses hostile bytes, decides a verdict | Never | Never | Never |
| `actaira.policy`, `receipt`, `bundle`, `agentgov` | Reads the core's output and documents the operator wrote, decides, signs | Never | Never | Only where told to (`--out`) |
| `actaira.attest` | Signs, verifies, builds the hash chain | Only `--tsa-url`, only when passed | Never | The package it is asked to write |
| `actaira.connectors` | Enumerates and stages remote artifacts | **Yes, by design** | Never | The staging directory |
| `actaira.web` | A local read-only interface. With `--state PATH` it also reads one workspace database | Listens on a loopback address | Never | Its own temporary uploads. Never the workspace: the state routes open it read-only and never create or migrate it |
| `actaira.agents` | Judged-evidence pipeline over documents | Only through a provider the caller configures; the shipped provider is a cassette and reaches nothing | Never | Never |

Two rules hold across all of them and they are the ones worth keeping:

1. **No component ever loads, deserialises or executes an artifact.** Not the
   scanner, not the connectors after staging, not the web interface.
2. **A component that can reach the network never decides a verdict, and a
   component that decides a verdict never reaches the network.** The connectors
   fetch bytes and hand them to the core; the core has no idea where they came
   from. This is why a compromised registry can give Actaira the wrong file and
   cannot give it the wrong answer about the file it got.

Section 5.5 covers the connectors' own surface, SSRF, redirects, credentials,
which is a different adversary from the one in section 1 and needs its own.

### 0.1 What `actaira serve --state` adds, stated plainly

"Read-only interface" stays true and it stops being the whole sentence. Until
the graph panel, every byte the server could disclose was a byte the requester
had just uploaded. With a workspace configured it can also disclose what this
machine has been told to look after: asset ids, source URIs, artifact digests,
the dependency topology between them, the identities and tool names an agent
declaration listed, and evidence identifiers.

2.3.0 widens that set rather than the posture. The evidence, change and decision
routes disclose what was observed and when, what each record was taken about,
which policy decided what on which date, and which of those decisions no longer
describes its subject. That last one is the most sensitive thing this interface
has ever served: it is a list of approvals that have quietly stopped applying,
which is exactly the list an attacker would want and exactly the list an operator
needs. It is served under the same rules as everything else here and under no
new ones.

That is a real change in what an attacker who reaches the port would learn, so
it is answered in four places rather than assumed away.

| Concern | Answer | Where |
|---|---|---|
| A request naming which database to open | No route accepts a path. The workspace is a value on the server object, set from `--state` when the operator starts it | `src/actaira/web/server.py:1859` |
| A page on the internet reading the graph as a subresource | Every state route is a POST behind the Host and Origin checks. A GET to any of them is a 404 | `src/actaira/web/server.py:1247` |
| A read changing the operator's database | The schema version is read through a read-only connection first; an older database is reported rather than migrated, a missing one reported rather than created | `src/actaira/web/server.py:1873` |
| The local filesystem layout leaking into the browser | Responses carry the file's name and never its path | `tests/test_web_graph.py::test_the_response_carries_a_label_and_never_a_path` |
| A filter or a search string reaching sqlite | Both filters are checked against a closed vocabulary and refused when they are not in it; the search is a Python substring test over rows already read, never a `LIKE` pattern and never concatenated into SQL | `tests/test_web_evidence.py::test_a_search_needle_is_a_substring_and_never_a_pattern` |
| The browser mutating the ledger | Nothing writes. The Store can revoke, distrust and delete a record and none of it is reachable from here: each changes what a decision may rest on, and a control with that reach is its own review | `tests/test_web_evidence.py::test_reading_leaves_the_database_byte_identical` |

The flag is opt-in and the interface is fully usable without it: every panel
that existed before the graph works with no workspace at all, and binding this
server to anything but loopback while pointing it at a workspace now warns
about both things rather than one.

## 1. The adversary

### 1.1 Who

Someone who publishes a model artifact where a consumer will fetch it: a public
model hub, an internal registry, an artifact store, a shared drive, a pull
request that adds a checkpoint to a repository.

### 1.2 What they control

- The file name and its extension. `.safetensors` is a claim, not a fact.
- Every byte of the file, including all headers, all declared lengths, all
  offsets, all counts, all metadata, and any embedded pickle streams.
- The framing around the file: the model card, the README, the config sidecar,
  the download page, the commit message. Actaira reads none of these, on
  purpose (`src/actaira/bom/cyclonedx.py:9`).
- How many artifacts they publish and how often, so they control the volume the
  inspecting machine has to process.

### 1.3 What they do not control

- The machine that runs Actaira. The inspecting host is assumed uncompromised.
- The Python installation Actaira runs on, `pickletools`, `zipfile`, `hashlib`,
  and `cryptography`.
- The private signing key. The whole attestation layer collapses if this
  assumption fails; see section 4.3.
- The verifier's trust anchors. Identity verification is only meaningful because
  the verifier already holds a fingerprint the attacker cannot change
  (`src/actaira/attest/verify.py:226`).

### 1.4 Their goals, in order of severity

1. Execute code on the consumer's machine when the artifact is loaded.
2. Execute code on the machine that inspects the artifact, that is, on Actaira
   itself.
3. Get an artifact past the inspector with a PASS so that a downstream gate
   opens.
4. Deny service to the inspector so that scanning is switched off.
5. Produce an attestation that a third party will accept for an artifact the
   attacker controls.

## 2. What Actaira defends

### 2.1 Against goal 1, execution on the consumer

Actaira reports the constructs that cause load-time execution, per format:

| Construct | Format | Rule |
|---|---|---|
| Import of a callable with a documented path to code execution | pickle | `ACT-PKL-002` |
| Import of a callable not on the tensor-deserialisation allowlist | pickle | `ACT-PKL-001` |
| Nested loader that re-enters deserialisation on attacker data | pickle | `ACT-PKL-007` |
| Callable resolved through the copyreg extension registry, no name in the stream | pickle | `ACT-PKL-004` |
| Import built dynamically, target not statically decidable | pickle | `ACT-PKL-009` |
| Object dtype, whose contents are a pickle | `.npy` | `ACT-NPY-001` |
| Operator domain that executes user-supplied Python | ONNX | `ACT-ONX-001` |
| Non-standard operator domain, resolved by a custom kernel | ONNX | `ACT-ONX-002` |
| `Lambda` layer, whose body is a marshalled code object run at load | Keras | `ACT-H5-001` |
| Class outside the known layer set | Keras | `ACT-H5-002` |

The default policy is an allowlist, so an import nobody has enumerated as
dangerous is still reported (`src/actaira/scan/policy.py:205`). Over the corpus
that is the difference between 47 of 47 malicious cases flagged and
37 of 47. The figures come from `evals/results.json`, written by
`make eval`; `docs/FIGURES.md` carries the current ones and this sentence was
two releases out of date before 2.2.0 closed.

### 2.2 Against goal 2, execution on the inspector

Nothing is loaded and nothing is executed. The pickle path disassembles opcodes
with `pickletools.genops` and never constructs an `Unpickler`
(`src/actaira/formats/pickle_scan.py:90`). The `.npy` header, which is
attacker-controlled text, is parsed with `ast.literal_eval` and never with
`eval` (`src/actaira/formats/npy.py:45`). ONNX is decoded by a hand-written
protobuf reader rather than by importing `onnx`
(`src/actaira/formats/onnx.py:47`). HDF5 is a bounded byte scan, not a parser
(`src/actaira/formats/keras_h5.py:31`). No inspector writes to the filesystem
and none opens a network socket.

An inspector that raises is caught, recorded in `inspector_errors`, and forces
`fully_read = False`, so a crash can never become a PASS
(`src/actaira/inspect.py:133`).

### 2.3 Against goal 3, slipping past with a PASS

- Format is determined from content, never from the extension, and a mismatch is
  itself reported (`src/actaira/formats/detect.py:104`).
- Any inspector that could not fully read its artifact drives INCONCLUSIVE
  rather than PASS (`src/actaira/inspect.py:142`).
- A pickle inside a zip is still scanned, one level down
  (`src/actaira/formats/archive.py:104`).
- Structural lies are reported as findings rather than as parse conveniences:
  safetensors offsets outside the data region (`ACT-STF-003`, CRITICAL),
  overlapping tensor spans (`ACT-STF-006`), a byte length that disagrees with
  dtype and shape (`ACT-STF-004`).

### 2.4 Against goal 4, denial of service on the inspector

Every loop over attacker-controlled data has a bound. The table in section 6
gives each one, the attack it bounds, and where it lives.

### 2.5 Against goal 5, forged attestations

- Any edit to any package member breaks the manifest hash for that member
  (`src/actaira/attest/verify.py:134`).
- A member added to the zip without a manifest entry is refused
  (`src/actaira/attest/verify.py:138`).
- Any edit to an entry breaks that entry's own hash and every hash after it
  (`src/actaira/attest/chain.py:86`).
- Any reordering or deletion of entries breaks the `prev_hash` link and the
  Merkle root (`src/actaira/attest/verify.py:157`).
- Any edit to the manifest breaks the signature
  (`src/actaira/attest/verify.py:175`).
- Re-signing a rewritten package with a fresh key passes every integrity check
  and is caught only by a trust anchor the verifier already held. That forgery
  is built explicitly in `tests/test_package_verify.py:291`.

Measured: 50 of 50 tampered packages rejected, with 50 of 50 verifying before
tampering, and a single flipped byte changing the subject digest in 50 of 50
cases (`evals/results.json`).

## 3. What Actaira does not defend

Nothing here is a bug. Each item is a boundary the design chose.

- **The consumer's loading behaviour.** Actaira reports. It does not intercept
  `torch.load`, does not install an import hook, and does not sit in the load
  path. An organisation that scans and then loads anyway is not protected by
  scanning.
- **The transport.** Actaira does not fetch artifacts. Whatever fetched the file
  is outside the model, including its TLS and its mirror selection.
- **The inspecting host.** Assumed uncompromised. There is no defence against an
  attacker who can edit `src/actaira/scan/policy.py` or the verifier's trust
  anchors.
- **The private key at rest.** It is written unencrypted PKCS8 at mode 0600,
  created with `O_EXCL` so it is never briefly world-readable
  (`src/actaira/attest/signing.py:88`). That is filesystem permissions, not a
  passphrase and not an HSM.
- **Key lifecycle.** No rotation, no revocation, no expiry, no certificate
  chain. A compromised key stays valid until every verifier removes its
  fingerprint by hand.
- **Availability of the web UI.** The local server has no authentication and no
  rate limiting. It is loopback by default and warns loudly otherwise
  (`src/actaira/web/server.py:569`).

## 4. What Actaira cannot do

This section is the one to read before relying on the tool.

### 4.1 It does not prove a model is benign

A PASS means: this artifact was fully read by the inspector selected for its
detected format, and nothing that inspector knows how to look for was found. It
does not mean the artifact is safe. It means the tool found nothing it knows how
to find.

The scope of "knows how to find" is exactly the 80 rules in
`docs/FORMATS.md`. A construct outside that set is not reported, and its absence
from the report is not evidence of its absence from the file.

### 4.2 It does not execute the model, so it cannot see the weights

Nothing is loaded. Actaira therefore has no view of what the model does. A model
whose weights encode a backdoor, a trigger phrase, a data-exfiltrating fine
tune, or any other behavioural property, is inert bytes to this tool and will
PASS if it is structurally clean. Tensor shapes, dtypes and counts are reported
because they were parsed from the header. Their values are not read, not
analysed and not summarised.

This is not a gap to be closed later by the same technique. Detecting a
behavioural backdoor requires running the model, which is the one thing the
design refuses to do.

### 4.3 The hash chain proves ordering, not freshness, unless it is anchored

The chain proves that entry n was written knowing entry n-1, and that nothing
was inserted, removed, reordered or edited since signing
(`src/actaira/attest/chain.py:3`). On its own it proves nothing about when
anything happened.

The consequence is concrete. Whoever holds the signing key can rebuild the
entire chain from genesis with different content and different timestamps, and
the result is indistinguishable from the original by any check inside the
package. A timestamp inside an entry is inside the hash, so it cannot be edited
without breaking the chain, but the whole chain can be re-made.

Since 1.0.0 a third party can be asked to close that gap.
`actaira attest --tsa-url URL` obtains an RFC 3161 time-stamp over the
manifest and stores it in the package; the manifest then records
`"time_anchor": "rfc3161"` with the authority, the genTime and the token
serial. An anchored package cannot be back-dated by whoever holds the signing
key: they can re-sign an edited manifest and it will verify, but the token was
issued over the manifest as it was, and the verifier checks that.

**What the anchor does not give you, and the tool says so on every run:**

* **The authority is not authenticated.** Actaira ships no trust store, so the
  token's certificate chain is reported as `tsa_chain: "not_verified"`. The
  token's own signature is checked against the certificate it carries, which
  proves it was not edited after issuance and proves nothing about who issued
  it. This is the same distinction as section 4.4, one layer out.
* **The TSA's clock is its own.** A genTime is a claim by the authority. If the
  authority is dishonest or broken, the anchor inherits that. Actaira reports
  the genTime and the authority's name rather than judging either.
* **An unanchored package is unchanged.** Without `--tsa-url` the manifest
  still reads `"time_anchor": "none"` and the verifier still warns on every
  verification (`src/actaira/attest/verify.py:204`). Nothing is required, and
  nothing is implied.
* **A verifier's own dating is reported as such.** Where a key's validity
  window has to be checked and there is no anchor, the moment comes from the
  package's own `created` field and entry timestamps. Those are covered by the
  signature and the Merkle root, so they cannot be edited afterwards, but they
  were chosen by whoever holds the key. The result says which was used, as
  `time_evidence: "rfc3161"` or `"self_asserted"`.

Publication to a public append-only log with witnesses would be stronger still,
because it makes a log's history visible to people other than its owner. That
remains out of scope.

### 4.4 A verification without trust anchors proves integrity, not identity

Every package carries its own public key, so integrity can always be checked
without any prior arrangement. That check proves the package was not edited
after signing. It proves nothing about who signed it, because an attacker who
rewrites the package also replaces the embedded key.

That case returns `trust_state = "embedded_key_only"` with a warning that says,
in the report itself, "INTEGRITY VERIFIED, IDENTITY NOT VERIFIED"
(`src/actaira/attest/verify.py:196`). `--require-trust` turns it into a failure.

| Anchors supplied | Key matches | `trust_state` | `ok` |
|---|---|---|---|
| no | not applicable | `embedded_key_only` | integrity result |
| yes | yes | `trusted` | integrity result |
| yes | no | `untrusted` | `False` |
| any | no key verified the signature | `untrusted` | `False` |

The third row is a deliberate choice made after a defect. Supplying anchors is
an assertion about who you accept, so once given they are binding
(`src/actaira/attest/verify.py:214`).

**Rotation and revocation move that question, they do not remove it.** Since
1.0.0 a keyring carries several keys, each with a status and the window it was
allowed to sign in, so retiring a key no longer invalidates what it signed
while it was in use, and revoking one invalidates everything it ever signed
(D-28). Three limits belong here rather than in the release notes:

* **Status is only binding from a keyring you supplied.** A package rewritten
  by an attacker rewrites the keyring inside it, so the embedded copy can be
  trusted only where it makes the verdict stricter. A revocation that reaches a
  verifier is one they were given out of band; there is no CRL, no OCSP and no
  feed. Publishing the keyring is the operator's job.
* **A window is only as good as the evidence for when signing happened.**
  Without an RFC 3161 anchor that evidence is the package's own timestamps,
  which the holder of the key chose. `time_evidence` says which was used, and
  the warning for a retired key says it in words.
* **Archiving the old private key is a deliberate risk.** `keygen --rotate`
  moves it aside rather than deleting it, because a rotation is not a breach
  and re-signing an old package sometimes has to be possible. If you rotated
  *because* of a breach, revoke the key and destroy the archived file yourself;
  the tool will not do it for you, and says so.

### 4.5 HDF5 reading is a byte scan, not a parser

`keras_h5.inspect` confirms the magic number and then searches raw bytes for the
Keras `model_config` blob with a regular expression
(`src/actaira/formats/keras_h5.py:27`). It does not walk the HDF5 B-tree.

Consequences:

- A file whose config the regular expression does not reach produces
  `ACT-H5-003` and INCONCLUSIVE, never PASS
  (`src/actaira/formats/keras_h5.py:55`).
- A file larger than `MAX_SCAN_BYTES` is scanned only up to that bound. If a
  config is found within the bound, the artifact can still PASS on a partial
  scan; `metadata["truncated_scan"]` is the only signal
  (`src/actaira/formats/keras_h5.py:53`).
- Anything Keras stores outside a contiguous JSON blob, including custom object
  registrations that are not named in the config, is invisible.
- The corpus HDF5 cases carry a real magic number and a real config blob but are
  not valid HDF5 files (`evals/corpus/build.py:138`), so they measure the
  `Lambda` detector and not HDF5 parsing.

INCONCLUSIVE on a Keras file is the expected outcome for a large fraction of
real files, not an error.

### 4.6 The corpus is synthetic and closed, so the numbers are counts

Every corpus artifact is generated by `evals/corpus/build.py`, which makes the
corpus reproducible byte for byte and lets its digests be published. It also
means the corpus is what the authors thought to build.

The harness states what it refuses to measure
(`evals/harness.py:3`):

> MEASURED: detection over a closed, hand-built corpus, per policy; false
> positives on the benign half; determinism across repeated runs; tamper
> detection on the attestation package.
> NOT MEASURED: performance against real-world malware, or any estimate of it.

Every published number is a count over 51 fixed cases, never a rate. Reporting
"97.3% detection" from 51 fixed cases would dress a count as an estimate of a
population that was never sampled (`evals/harness.py:118`).

The benign half is meaningful in a way the malicious half is not: it is produced
by real serialisers, CPython's own pickler across protocols 0 to 5 and numpy's
own writer, so a false positive there is a real false positive. The malicious
half is hand-crafted from documented gadget shapes, so it measures detector
coverage against those shapes and nothing more
(`evals/corpus/build.py:9`).

### 4.7 Other stated limits

- **`imported_callables` is what was resolved, not what will be imported.** An
  import the abstract interpreter could not decide is reported as
  `ACT-PKL-009` and does not appear in the list.
- **A bare pickle is read fully into memory.** `inspect_artifact` calls
  `path.read_bytes()` (`src/actaira/inspect.py:58`), so the practical ceiling
  for that one format is RAM, not any declared budget. The web layer states this
  explicitly because its 2 GiB upload cap does not bound it
  (`src/actaira/web/server.py:33`).
- **`--fail-on` is a policy dial, not a fact.** MEDIUM and below never fail an
  artifact by default. Every rule at MEDIUM or below in `docs/FORMATS.md`
  therefore produces a PASS or an INCONCLUSIVE on its own.
- **Findings from within an archive carry a `location` of `file!member`,** and a
  consumer that only reads `report.path` loses that.
- **`evidence` keys are not a stable interface.** Only `rule_id` is
  (`src/actaira/model.py:56`).
- **The Merkle tree is not a transparency log.** Since 0.2.0 it does carry
  consistency proofs, so the holder of an older root can check that a newer one
  extends it (`verify --extends`, D-25). What is still absent is everything
  that makes a transparency log a log: no public append-only publication, no
  witnesses, no gossip. The proof answers "does this root extend that root" and
  says nothing about who else has seen either. This bullet used to claim there
  were no consistency proofs at all, which stopped being true in 0.2.0; it is
  corrected here rather than quietly deleted.
- **The core opens no outbound connection, ever.** Scanning, BOM generation,
  coverage, policy evaluation, receipt issuing and verification never speak to
  the network. Two components can: `attest --tsa-url` posts a timestamp request
  (`src/actaira/attest/timestamp.py:3`), and the connectors fetch what they were
  pointed at (`src/actaira/connectors/model.py`). Both are opt-in, both are
  named on the command line, and neither decides a verdict.

  This bullet used to say "exactly one outbound connection", and it went on
  saying it for a whole release after the connectors shipped. The claim is now
  split per component in section 0 precisely so that adding a component cannot
  silently falsify a sentence about the whole tool.

## 5. Attack surface of the inspector itself

Actaira parses hostile input by definition, so the inspector is a target. Each
row gives an attack, the budget or control that bounds it, and where it lives.

| Attack | Bound | Location | Consequence when hit |
|---|---|---|---|
| Pickle with an unbounded opcode stream, to make the scanner spin | `MAX_OPCODES` = 2,000,000 | `src/actaira/formats/pickle_scan.py:75` | `ACT-PKL-008` MEDIUM, scan stops, partial analysis reported |
| Malformed or truncated pickle raising from `genops` | try/except around the whole loop | `src/actaira/formats/pickle_scan.py:167` | `ACT-PKL-006` MEDIUM, `truncated=True`, drives INCONCLUSIVE |
| Pickle stack underflow, popping from an empty abstract stack | `self.stack.pop() if self.stack else None` | `src/actaira/formats/pickle_scan.py:308` | Opaque operand, then `ACT-PKL-009` HIGH |
| Zip bomb: a member that expands without bound | `MAX_COMPRESSION_RATIO` = 100, checked from the central directory without decompressing | `src/actaira/formats/archive.py:72` | `ACT-ZIP-002` HIGH, artifact fails |
| Zip with a huge number of members, to exhaust time | `MAX_MEMBERS_INSPECTED` = 512 | `src/actaira/formats/archive.py:61` | `ACT-ZIP-004` MEDIUM, drives INCONCLUSIVE. The members past the budget are never inspected |
| Zip member name escaping the extraction root | `_is_traversal`, covering leading `/`, a Windows drive letter, `..` segments and backslash separators | `src/actaira/formats/archive.py:129` | `ACT-ZIP-001` HIGH |
| Zip that will not open, or a member that will not decompress | try/except at open and at read | `src/actaira/formats/archive.py:43` and `src/actaira/formats/archive.py:107` | `ACT-ZIP-005` or `ACT-ZIP-003` MEDIUM, drives INCONCLUSIVE |
| safetensors header claiming to be the whole disk | `MAX_HEADER_BYTES` = 64 MiB, checked before any read | `src/actaira/formats/safetensors.py:44` | `ACT-STF-001` HIGH, no allocation attempted |
| safetensors header longer than the file | `8 + header_len > file_size` | `src/actaira/formats/safetensors.py:54` | `ACT-STF-002` HIGH |
| safetensors offsets pointing outside the file | `end > data_region` and `end < start` | `src/actaira/formats/safetensors.py:101` | `ACT-STF-003` CRITICAL |
| safetensors shape claiming an implausible element count | Element count is computed but never used to allocate; only compared against the declared byte span | `src/actaira/formats/safetensors.py:123` | `ACT-STF-004` HIGH |
| Hostile protobuf: unterminated varint | Shift limit of 70 bits, past the 64-bit maximum | `src/actaira/formats/onnx.py:43` | `ValueError`, caught, `ACT-ONX-003` MEDIUM |
| Hostile protobuf: length-delimited field claiming more bytes than the message holds | `pos + length > limit` | `src/actaira/formats/onnx.py:62` | `ValueError`, caught, `ACT-ONX-003` MEDIUM |
| Hostile protobuf: unsupported wire type, including the deprecated group types | Explicit refusal | `src/actaira/formats/onnx.py:70` | `ValueError`, caught, `ACT-ONX-003` MEDIUM |
| ONNX file large enough to exhaust memory when read whole | `MAX_BYTES` = 512 MiB, checked from `stat` before reading | `src/actaira/formats/onnx.py:79` | `ACT-ONX-004` MEDIUM, file not read |
| ONNX graph with an implausible node count | `MAX_NODES` = 200,000 | `src/actaira/formats/onnx.py:178` | Further nodes skipped silently, no finding |
| GGUF declaring implausible key-value or tensor counts | `MAX_KV` = 4096, `MAX_TENSORS` = 100,000, checked before the loops | `src/actaira/formats/gguf.py:96` | `ACT-GGF-003` HIGH, parsing stops |
| GGUF string field declaring a u64 length | `MAX_STRING` = 1 MiB | `src/actaira/formats/gguf.py:52` | `ValueError`, caught, `ACT-GGF-001` MEDIUM |
| GGUF array field declaring an implausible element count | `MAX_KV * 64` | `src/actaira/formats/gguf.py:65` | `ValueError`, caught, `ACT-GGF-001` MEDIUM |
| GGUF tensor declaring an implausible rank | rank > 8 | `src/actaira/formats/gguf.py:120` | `ValueError`, caught, `ACT-GGF-001` MEDIUM |
| GGUF read past the end of the buffer | `_Reader.take` bounds every read | `src/actaira/formats/gguf.py:37` | `ValueError`, caught, `ACT-GGF-001` MEDIUM |
| HDF5 file large enough to exhaust memory when scanned | `MAX_SCAN_BYTES` = 256 MiB | `src/actaira/formats/keras_h5.py:28` | Scan truncated, recorded in `metadata["truncated_scan"]` |
| `.npy` header carrying Python code | `ast.literal_eval`, never `eval` | `src/actaira/formats/npy.py:45` | `ValueError`, caught, `ACT-NPY-002` MEDIUM |
| `.npy` declaring a header longer than the file | Short-read checks on both the length field and the header | `src/actaira/formats/npy.py:34` and `src/actaira/formats/npy.py:39` | `ACT-NPY-002` MEDIUM |
| Any unanticipated inspector crash | try/except around the whole dispatch | `src/actaira/inspect.py:133` | Recorded in `inspector_errors`, `fully_read = False`, never PASS |
| HTTP request with no `Content-Length`, or chunked | Explicit refusal with 411 | `src/actaira/web/server.py:282` | Request refused, body never read |
| HTTP upload large enough to exhaust memory | `MAX_UPLOAD_BYTES` = 2 GiB, streamed to disk in `READ_CHUNK` pieces, never buffered | `src/actaira/web/server.py:60` and `src/actaira/web/server.py:309` | 413, body never materialised |
| Multipart form field used as a memory sink | `MAX_FIELD_BYTES` = 64 KiB | `src/actaira/web/server.py:61` | Field truncated at the bound |
| Multipart part header line used as a memory sink | `MAX_HEADER_LINE` = 8 KiB | `src/actaira/web/server.py:153` and `src/actaira/web/server.py:180` | Refused |
| Upload filename used to write outside the workdir | `safe_basename`, cutting both separators and reducing to `[A-Za-z0-9._-]`, capped at 120 chars | `src/actaira/web/server.py:247` | Sanitised basename only, never a path |
| Server-side temporary path leaking into a signed attestation | `report.path` rewritten to the sanitised basename before the report leaves the process | `src/actaira/web/server.py:346` | Temporary path never disclosed or signed |
| Uploaded artifact persisting on the inspecting host | `mkdtemp` per request, `shutil.rmtree` in a `finally` | `src/actaira/web/server.py:438` and `src/actaira/web/server.py:451` | Removed on every path including errors |
| Static file request escaping the static root | Resolve and compare against `STATIC_ROOT` | `src/actaira/web/server.py:462` | 403 |
| XSS through a finding rendered in the UI | CSP with `'self'` only, no `unsafe-inline`, no `unsafe-eval`, plus `nosniff` on every response | `src/actaira/web/server.py:81` | Inline script and style are blocked by the browser; there is no inline script or style in the static files |
| Traceback disclosure to the browser | Catch-all in `do_GET` and `do_POST` returning a JSON error | `src/actaira/web/server.py:419` and `src/actaira/web/server.py:446` | Type and message only, no traceback |
| A page on the internet reading a response out of this server | `Cross-Origin-Resource-Policy: same-origin` on every response, beside `Cross-Origin-Opener-Policy` and `X-Frame-Options: DENY` | `src/actaira/web/server.py` | A subresource load - which is a GET, so the origin check on POST does not see it - is refused by the browser |
| A powerful browser feature reached from this document | `Permissions-Policy` refusing camera, microphone, geolocation, payment, USB and the rest | `src/actaira/web/server.py` | An interface that reads local files and draws a report uses none of them, and says so rather than relying on a default |
| Workspace topology read by a page on the internet | Every state route is a POST behind the Host and Origin checks, so a cross-origin request and a rebound `Host` are both 403, and a GET is a 404 | `tests/test_web_graph.py` | The graph, its nodes and impact are unreachable except from this machine's own browser |
| A browser choosing which sqlite file this process opens | The path is a server value set from `--state`; no field of any body reaches it | `src/actaira/web/server.py:1859` | A body naming a path is ignored and the configured workspace is read |
| A read migrating or creating the operator's state database | Version read through a read-only connection; older, newer, corrupt and absent are four structured refusals | `tests/test_web_graph.py::test_a_database_from_an_earlier_release_is_reported_and_not_migrated` | The file is byte-identical after a request that refused it |
| Markup in an asset id, a name, `stated_by` or an evidence id | Carried as data by the API and written with `textContent` by the renderer; nothing in the interface assigns `innerHTML` | `tests/test_web_graph.py` | The payload is displayed as the text it is |
| Markup in an evidence payload key or value | The same answer one layer in: the evidence panel renders payload keys and values, and both are text nodes. The response is `application/json` with `nosniff`, so the bytes never reach an HTML parser in the first place | `tests/test_web_evidence.py::test_hostile_text_round_trips_as_text` | Displayed as the text it is |
| An approval that has stopped applying, read by a page on the internet | The decision routes are POSTs behind the same Host and Origin checks as everything else that reads the workspace | `tests/test_web_evidence.py::test_a_cross_origin_request_is_refused` | Unreachable except from this machine's own browser |
| `localhost` pinned to HTTPS for every other local server on the machine | No `Strict-Transport-Security`, deliberately, and a test asserts its absence | `tests/test_web_limits.py::test_the_local_server_does_not_send_hsts` | This server is 127.0.0.1 over plain HTTP; HSTS here would be a real harm for a protection that does not apply to loopback |

### 5.5 The connectors: a different adversary

Everything above assumes the bytes are hostile and the network is absent. The
connectors invert both: the bytes are not read at all until they reach the
core, and the adversary is whoever answers the URL. That is a different
adversary, and it is worth stating separately rather than folding into the
section above, because the defences have nothing in common.

| Attack | Bound | Location |
|---|---|---|
| SSRF: a URL pointed at a link-local address, a metadata service, or a unix socket | HTTPS only, scheme checked before the request | `src/actaira/connectors/model.py` |
| A downgrade from `https:` to `http:` through a redirect | A custom opener with no HTTP handler, so an `http:` redirect cannot be followed at all | `src/actaira/connectors/model.py` |
| A credential following a redirect to another host | `Authorization` is dropped on a host change | `src/actaira/connectors/model.py` |
| A response large enough to fill the disk | Bounded read per response | `src/actaira/connectors/model.py` |
| A registry that serves different bytes than it listed | `declared_sha256` and `sha256` are separate fields, and a mismatch is reported rather than reconciled | `src/actaira/connectors/model.py` |
| A listing that is silently partial, so the scan looks complete | `Discovery.complete` is a flag the connector must set; the default is incomplete | `src/actaira/connectors/model.py` |

The last two are the important ones, and they are not about the network. A
connector's job is to enumerate and stage; it is never allowed to conclude. A
compromised registry can hand Actaira the wrong file and cannot make Actaira
say the wrong thing about the file it got, because the component that fetched
it has no vote on the verdict.

### 5.6 The policy and receipt layers

They read what the core produced and documents the operator wrote. Neither
parses hostile bytes, so their surface is different again: it is the
possibility of stating something stronger than was established.

| Risk | Control | Location |
|---|---|---|
| A condition that cannot be evaluated reading as "does not hold", so a `deny` rule silently passes | `Unevaluable` becomes a REVIEW outcome naming the gap | `src/actaira/policy/engine.py` |
| A misspelt predicate never matching, so a rule is present in the file and absent in effect | The document does not load | `src/actaira/policy/engine.py` |
| A waiver with no expiry becoming a permanent policy change | The document does not load without owner, reason and expiry | `src/actaira/policy/engine.py` |
| A receipt edited after signing | The signature covers the canonical JSON of the document minus the signature block | `src/actaira/receipt.py` |
| "Verified" read as "trusted" | Two separate fields, and a third state for "nobody vouched for this key" | `src/actaira/receipt.py` |
| A receipt read as exhaustive | `states_what_it_does_not_cover` is a required field | `src/actaira/receipt.py` |

Two of these bounds trade coverage for safety in a way worth calling out.
`MAX_MEMBERS_INSPECTED` means the contents of member 513 onwards are never
examined; the artifact comes back INCONCLUSIVE rather than PASS, so the gap is
visible, but it is a gap. `MAX_NODES` is the one bound that is silent: nodes past
it are skipped without a finding (`src/actaira/formats/onnx.py:178`), so an ONNX
model with more than 200,000 nodes can PASS with part of its graph uncounted.

## 6. Residual risk, in one paragraph

Actaira raises the cost of shipping a load-time execution gadget in a model
artifact, and it makes the result of an inspection something a third party can
check without trusting the inspector. It does not make a model safe to load, it
cannot see anything that only exists at run time, and its attestations prove
ordering and authorship rather than time. Used as a gate it will stop the
documented gadget shapes it knows and will abstain loudly on files it cannot
read. Used as a guarantee it will eventually be wrong, and the report it
produced will have said so.
