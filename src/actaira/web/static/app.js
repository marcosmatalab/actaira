/* Actaira, local UI logic.
 *
 * No framework. Plain DOM against a stdlib HTTP server, which is the whole
 * point: the tool that tells you what a supply chain contains does not get
 * to have a supply chain of its own.
 *
 * Three rules held throughout:
 *   1. Nothing is ever assigned to innerHTML. Every string that comes from a
 *      report, a filename, a location, an opcode argument, an evidence value
 *      or a rule id is written with textContent, so a crafted artifact
 *      cannot inject markup into the page that is reporting on it. The one
 *      place markup is generated, the chain drawing, is built node by node
 *      with createElementNS and carries no untrusted text at all beyond
 *      hashes, which are also written with textContent.
 *   2. UI strings live here, rule descriptions come from the backend
 *      catalogue at /api/i18n/<lang>. A rule with no catalogue entry renders
 *      its raw id, never an empty line.
 *   3. The only runtime style writes go through CSSOM setProperty on custom
 *      properties (--progress, --w). No style attribute is ever parsed from
 *      markup, so the CSP holds with no unsafe-inline.
 */
'use strict';

(function () {

  /* ── interface strings ────────────────────────────────────────────────
   * Both catalogues carry the same keys. `t()` falls back en -> key, so a
   * missing translation degrades to English and then to something visible.
   */

  var I18N = {
    en: {
      'app.title': 'Actaira, model artifact inspection',

      'a11y.skip': 'Skip to content',
      'a11y.language_group': 'Interface language',
      'a11y.theme': 'Change colour theme',
      'a11y.tabs': 'Sections',

      'tab.inspect': 'Inspect',
      'tab.attest': 'Attest',
      'tab.verify': 'Verify',
      'tab.govern': 'Governance',

      'tab.agents': 'Agents',

      'tab.policy': 'Policy',

      'policy.lede': 'Drop a policy document. Actaira shows what it says, then decides one artifact or one agent under it and hands back the rules and the evidence that caused the answer.',
      'policy.drop_title': 'Drop a policy document',
      'policy.choose': 'Choose a .yaml',
      'policy.hint': 'yaml · yml · the shape policies/production-model.yaml describes',
      'policy.summary': 'Policy',
      'policy.version': 'version',
      'policy.digest': 'digest',
      'policy.rules': 'Rules',
      'policy.rule.when': 'when',
      'policy.subject': 'Decide a subject under it',
      'policy.subject.lede': 'The document above is applied to one subject. An artifact is inspected first; an agent is read and its routes searched, so both arrive with the evidence the rules ask about.',
      'policy.subject.artifact': 'Artifact',
      'policy.subject.agent': 'Agent',
      'policy.subject.choose': 'Choose the subject',
      'policy.subject.kind': 'Subject kind',
      'policy.subject.name': 'subject',
      'policy.decision': 'Decision',
      'policy.decision.on': 'decided on',
      'policy.decision.because': 'because',
      'policy.decision.allow': 'Nothing in this document objected.',
      'policy.decision.deny': 'A rule refused this subject.',
      'policy.decision.review': 'A rule could not be evaluated against what this run observed.',
      'policy.proof': 'Proof',
      'policy.proof.lede': 'Every rule against every subject, including the ones that did not fire. A proof that only listed what failed would depend on rule order.',
      'policy.contributes.allow': 'allow',
      'policy.contributes.deny': 'deny',
      'policy.contributes.review': 'review',
      'policy.noscore': 'No score, no grade, no percentage. A decision is one of three words and the rules behind it.',
      'loading.policy': 'Reading the document',
      'loading.policydecide': 'Deciding',

      'graph.stated_by': 'stated by',
      'graph.unstated': 'unstated',
      'graph.evidence': 'evidence',
      'graph.provenance': 'Edges stated by',
      'graph.evidence_backed': '{n} carry a stored evidence id.',


      'tab.graph': 'Graph',

      'gr.lede': 'What this workspace has recorded, and what depends on what. Every line is a claim somebody made: the relation is on the edge, who stated it is in the panel, and nothing here is inferred from two names that look alike.',
      'gr.recorded': 'Recorded relations',
      'gr.recorded.note': 'Everything this workspace has ever recorded. A relation is not removed when a later observation stops seeing it, so this is the known graph and not a claim about what is there right now.',
      'gr.workspace': 'Workspace',
      'gr.workspace.reading': 'reading',
      'gr.workspace.nodes': 'assets',
      'gr.workspace.edges': 'relations',
      'gr.workspace.sources': 'sources',
      'gr.workspace.evidence': 'evidence records',
      'gr.empty.title': 'No workspace is configured',
      'gr.empty.text': 'This interface reads a workspace only when it is started against one, and it will never create one. Run actaira init, then actaira serve --state .actaira/state.db',
      'gr.absent.title': 'No workspace is configured',
      'gr.unreadable.title': 'That file is not a state database',
      'gr.older_schema.title': 'That workspace is older than this release',
      'gr.newer_schema.title': 'That workspace is newer than this release',
      'gr.empty_graph.title': 'This workspace has recorded nothing yet',
      'gr.empty_graph.text': 'Register a source and watch it, or record what a subject manifest declares with actaira graph build --subjects.',
      'gr.no_edges.title': 'Assets, and no relations between them',
      'gr.no_edges.text': 'This workspace knows about these assets and nothing has declared a relation between any two of them. An impact answer over this graph would be empty because nothing was stated, not because nothing depends on anything.',

      'gr.mode': 'View',
      'gr.mode.recorded': 'Everything recorded',
      'gr.mode.focus': 'Around one asset',
      'gr.mode.impact': 'Impact',
      'gr.direction': 'Direction',
      'gr.direction.both': 'Both',
      'gr.direction.dependents': 'What depends on it',
      'gr.direction.dependencies': 'What it depends on',
      'gr.depth': 'Hops',
      'gr.depth.all': 'all',
      'gr.search': 'Find an asset by id, name or digest',
      'gr.search.go': 'Find',
      'gr.search.none': 'Nothing in this workspace matches that.',
      'gr.search.results': 'Matches',
      'gr.filters': 'Show',
      'gr.filters.kinds': 'Kinds',
      'gr.filters.relations': 'Relations',
      'gr.filters.hidden': '{n} hidden by a filter.',
      'gr.fit': 'Fit',
      'gr.zoom_in': 'Zoom in',
      'gr.zoom_out': 'Zoom out',
      'gr.view.graph': 'Diagram',
      'gr.view.list': 'List',
      'gr.list.lede': 'The same relations as text, one line each, in the order the engine returned them.',
      'gr.aria.graph': 'The recorded asset graph: {nodes} assets and {edges} relations',
      'gr.aria.node': '{id}, a {kind}',
      'gr.drag_note': 'Nodes can be dragged. Where a box sits is a convenience for reading and is never written to the workspace.',

      'gr.selected.node': 'Asset',
      'gr.selected.edge': 'Relation',
      'gr.selected.none': 'Select an asset or a relation to see what this workspace records about it.',
      'gr.node.kind': 'kind',
      'gr.node.name': 'name',
      'gr.node.digest': 'digest',
      'gr.node.source': 'source',
      'gr.node.first_seen': 'first seen',
      'gr.node.last_seen': 'last seen',
      'gr.node.last_snapshot': 'last confirmed by',
      'gr.node.attributes': 'attributes',
      'gr.node.unknown': 'This workspace has no record of that asset. It has no recorded dependents, which is not the same as having none.',
      'gr.node.incoming': 'Depended on by',
      'gr.node.outgoing': 'Depends on',
      'gr.node.no_relations': 'Nothing has declared a relation to or from this asset.',
      'gr.edge.from': 'from',
      'gr.edge.to': 'to',
      'gr.edge.relation': 'relation',
      'gr.edge.stated_by': 'stated by',
      'gr.edge.evidence': 'evidence',
      'gr.edge.no_evidence': 'no stored evidence id',

      'gr.evidence': 'Evidence',
      'gr.evidence.none': 'No evidence record names this asset as its subject.',
      'gr.evidence.valid': 'valid',
      'gr.evidence.stale': 'stale',
      'gr.evidence.superseded': 'superseded',
      'gr.evidence.revoked': 'revoked',
      'gr.evidence.untrusted': 'untrusted',

      'gr.current': 'still there?',
      'gr.current.current': 'confirmed by the latest observation',
      'gr.current.not_in_latest_observation': 'recorded earlier, and the latest observation did not see it',
      'gr.current.undetermined': 'nothing in this workspace answers that',
      'gr.current.short.current': 'confirmed',
      'gr.current.short.not_in_latest_observation': 'not in the latest observation',
      'gr.current.short.undetermined': 'not established',
      'gr.current.lede': 'Recorded is not the same as current. An observed relation can be checked against the latest snapshot of its source; a declared one carries no notion of which run is live, so it is reported as undetermined rather than guessed at.',

      'gr.actions': 'Ask about this asset',
      'gr.action.focus': 'Centre on it',
      'gr.action.dependents': 'What depends on it',
      'gr.action.dependencies': 'What it depends on',
      'gr.action.impact': 'What is affected if it changes',

      'gr.impact': 'If this changes',
      'gr.impact.changed': 'Changed',
      'gr.impact.affected': 'Affected',
      'gr.impact.none': 'Nothing this workspace has recorded depends on that asset.',
      'gr.impact.unknown': 'This workspace has never seen that asset, so it has no recorded dependents. That is not a proof that nothing depends on it.',
      'gr.impact.hops': '{n} hops',
      'gr.impact.hop': '1 hop',
      'gr.impact.why': 'Why',
      'gr.impact.route': 'Route',
      'gr.impact.by_kind': 'By kind',
      'gr.impact.highlight': 'Show this route in the diagram',

      'gr.truncated': 'This view stopped at its hop limit. There are more relations beyond it.',
      'gr.impact.truncated': 'The walk stopped at its depth limit, so this list is incomplete.',
      'gr.cycles': 'Cycles',
      'gr.cycles.lede': 'A cycle is a real shape, not an error: sub-agents call each other and systems contain systems.',
      'gr.cycles.incomplete': 'Cycle enumeration reached its bound, so there may be cycles this does not list.',
      'gr.too_large': 'Too large to draw',
      'loading.graph': 'Reading the workspace',

      'agents.lede': 'Drop an agent declaration. Actaira reads the tools, the MCP servers, the identities and the data it can reach, and reports the combinations that are dangerous together even though each one is fine alone.',
      'agents.drop_title': 'Drop an agent declaration',
      'agents.choose': 'Choose a .yaml',
      'agents.hint': 'yaml · yml · json · the shape docs/CONCEPTS.md describes',
      'agents.summary': 'Declaration',
      'agents.version': 'version',
      'agents.environment': 'environment',
      'agents.digest': 'digest',
      'agents.tools': 'tools',
      'agents.mcp': 'MCP servers',
      'agents.identities': 'identities',
      'agents.sources': 'data sources',
      'agents.subagents': 'sub-agents',
      'agents.findings': 'Capability findings',
      'agents.findings.none': 'No capability rule fired. That is not the same as safe: it means no rule in this catalogue matched this declaration.',
      'agents.paths': 'Attack paths',
      'agents.paths.none': 'No route from untrusted input to a consequence was found in what this declaration states.',
      'agents.paths.open': 'open',
      'agents.paths.closed': 'closed by a control this declaration already carries',
      'agents.paths.closed_by': 'Closed by',
      'agents.paths.carries': 'carries',
      'agents.paths.break': 'Break this route by',
      'agents.paths.ineffective': 'Declared, and does not close this route',
      'agents.paths.unresolved': 'Delegations whose declaration was not supplied, so their routes were not followed:',
      'agents.paths.aria': 'Route {n}: {entry} to {sink}',
      'agents.paths.more': 'Showing {shown} of {total} routes.',
      'agents.bom': 'A-BOM',
      'agents.bom.lede': 'The agent bill of materials: every tool, server, identity and source as a component with its own digest. Diff two of these between releases to see what gained a capability.',
      'agents.bom.download': 'Download A-BOM',
      'agents.diff': 'Compare with another version',
      'agents.diff.lede': 'Drop a second declaration to see what changed. Gaining a capability is the thing a change review exists to catch.',
      'agents.diff.choose': 'Choose the second declaration',
      'agents.diff.same': 'The two declarations describe the same capabilities.',
      'agents.diff.too_big': 'That declaration is too large to compare in the browser.',
      'agents.diff.result': 'What changed',
      'loading.agents': 'Reading the declaration',
      'loading.agentpaths': 'Searching for routes',

      'tip.lang.en': 'English interface',
      'tip.lang.es': 'Interfaz en español',

      'welcome.title': 'Read a model file before it reads you.',
      'welcome.lede': 'Actaira opens pickle, PyTorch, safetensors, ONNX, GGUF, NumPy and Keras artifacts byte by byte and reports what they would do the moment somebody loads them. It never imports, deserialises or executes anything.',
      'welcome.claim.1': 'Nothing is loaded or executed',
      'welcome.claim.2': 'Nothing leaves this machine',
      'welcome.claim.3': 'One runtime dependency, for the Ed25519',
      'welcome.step1.title': 'Read the bytes',
      'welcome.step1.text': 'The format is detected from magic bytes and structure, not from the extension, and every container is opened one level down.',
      'welcome.step2.title': 'Show the mechanism',
      'welcome.step2.text': 'A pickle is a program. Actaira walks its opcodes and shows you the import and the call, so the verdict is evidence rather than a claim.',
      'welcome.step3.title': 'Sign the finding',
      'welcome.step3.text': 'The report becomes a hash-linked entry with a CycloneDX ML-BOM and an Ed25519 signature, verifiable offline by anyone.',

      'demo.title': 'What step 2 looks like',
      'demo.badge': 'example',
      'demo.caption': 'Two strings are pushed, STACK_GLOBAL resolves them to posix.system, and REDUCE is the opcode that calls it. That is the whole exploit, and it is four lines long.',

      'samples.title': 'Or inspect a sample',
      'samples.note': 'Artifacts from the eval corpus, read from disk on this machine.',
      'sample.gadget.note': 'A pickle that runs a shell command through posix.system.',
      'sample.trojan.note': 'A PyTorch checkpoint with the gadget one level down, inside the zip.',
      'sample.clean_pickle.note': 'A real numpy state_dict: imports, all of them on the allowlist.',
      'sample.clean_tensors.note': 'Two well-formed tensors and no executable path at all.',
      'sample.running': 'Inspecting {name}…',
      'sample.badge': 'sample',

      'drop.title': 'Drop an artifact here',
      'drop.hint': 'or',
      'drop.choose': 'Choose a file',
      'drop.formats': 'pickle · .pt/.pth · safetensors · onnx · gguf · .npy · keras/hdf5 · zip · up to 2 GiB',
      'drop.wrong_type': 'That looks like a folder or an empty file.',

      'attest.lede': 'Inspect an artifact, then sign the result. You get a portable .zip holding a hash-linked entry, a CycloneDX 1.6 ML-BOM and an Ed25519 signature that anyone can check offline.',
      'attest.hint': 'The artifact is inspected first. The report is what gets signed.',
      'verify.lede': 'Check an attestation package with no network at all. Integrity and identity are reported separately, because every package carries its own public key and that proves nothing about who signed it.',
      'verify.drop_title': 'Drop an attestation package',
      'verify.choose': 'Choose a .zip',
      'verify.hint': 'The .zip written by the Attest tab or by `actaira attest --out`.',

      'options.title': 'Scan options',
      'options.policy': 'Import policy',
      'options.policy.strict': 'strict, allowlist',
      'options.policy.known_bad': 'known-bad, denylist',
      'options.policy.help': 'strict flags every import outside a small allowlist. known-bad flags only imports already known to be dangerous.',
      'options.fail_on': 'Fail on',
      'options.fail_on.help': 'The lowest severity that turns the verdict into a failure.',

      'empty.attest.title': 'Nothing attested yet',
      'empty.attest.text': 'Drop an artifact to inspect it and sign the report into a portable, offline-verifiable package.',
      'empty.verify.title': 'Nothing verified yet',
      'empty.verify.text': 'Drop an attestation package to recompute its hashes, its Merkle root and its signature, entirely on this machine.',

      'loading.uploading': 'Uploading, {pct}%',
      'loading.inspecting': 'Inspecting the artifact…',
      'loading.attesting': 'Inspecting, then signing…',
      'loading.verifying': 'Verifying the package…',
      'loading.note': 'Nothing is executed. The upload is written to a temporary file and deleted as soon as the response has been sent.',
      'loading.title': 'Working',

      'error.title': 'The request did not complete',
      'error.network': 'Could not reach the Actaira server. Is it still running on this port?',
      'error.http': 'The server answered HTTP {status}.',
      'error.parse': 'The server answered with something that is not valid JSON.',
      'error.aborted': 'The request was cancelled.',
      'error.retry': 'Try again',
      'error.no_file': 'No file is selected any more. Choose one again.',

      'verdict.pass': 'PASS',
      'verdict.fail': 'FAIL',
      'verdict.inconclusive': 'INCONCLUSIVE',
      'verdict.pass.sub': 'Fully read, and nothing above medium severity was found.',
      'verdict.fail.sub': 'At least one finding at or above the failure threshold.',
      'verdict.inconclusive.sub': 'The artifact could not be fully read. That is deliberately not a pass.',

      'summary.title': 'Summary',
      'summary.file': 'File',
      'summary.size': 'Size',
      'summary.format': 'Detected format',
      'summary.severity': 'Highest severity',
      'summary.sha256': 'SHA-256',
      'summary.read': 'Coverage',
      'read.full': 'read in full',
      'read.partial': 'partially read',
      'confidence.magic': 'magic bytes',
      'confidence.structure': 'structure',
      'confidence.extension': 'extension only',
      'confidence.unknown': 'unknown',
      'confidence.label': 'confidence: {value}',
      'severity.none': 'none',
      'value.unknown': 'unknown',

      'findings.title': 'Findings',
      'findings.none': 'No findings. Every check this format supports came back clean.',
      'findings.evidence': 'Evidence',
      'findings.location': 'at',
      'findings.untranslated': 'No description for this rule in the catalogue.',

      'trace.title': 'Pickle disassembly',
      'trace.loading': 'Walking the opcode stream…',
      'trace.note': 'The same abstract interpretation the scanner runs, printed step by step instead of summarised. Nothing here was executed.',
      'trace.protocol': 'protocol {n}',
      'trace.opcodes': '{n} opcodes',
      'trace.member': 'member',
      'trace.col.kind': 'step kind',
      'trace.col.offset': 'offset',
      'trace.col.opcode': 'opcode',
      'trace.col.arg': 'argument',
      'trace.col.verdict': 'judgement',
      'trace.filter.relevant': 'What matters',
      'trace.filter.all': 'Every step',
      'trace.filter.aria': 'Which steps to show',
      'trace.hidden': '{n} steps hidden',
      'trace.hidden.none': 'showing every step',
      'trace.gap': '{n} steps',
      'trace.truncated': 'The stream stopped early: {error}',
      'trace.limited': 'Showing the first {shown} of {total} opcodes.',
      'trace.unavailable.not_a_pickle': 'This artifact holds no pickle stream, so there are no opcodes to walk.',
      'trace.unavailable.no_pickle_member': 'The container has no pickle member. Nothing in it would import anything at load time.',
      'trace.unavailable.too_large': 'The pickle stream is over the disassembly size limit. The verdict above still comes from the full scan.',
      'trace.unavailable.unreadable_container': 'The container could not be opened, so its members could not be walked.',
      'trace.error': 'The disassembly request failed. The verdict above is unaffected.',

      'kind.import': 'import',
      'kind.execute': 'execute',
      'kind.extension': 'extension',
      'kind.persid': 'persistent id',
      'kind.data': 'data',
      'judge.denied': 'denied',
      'judge.unknown': 'unknown',
      'judge.allowed': 'allowed',
      'judge.unresolved': 'unresolved',
      'judge.tolerated': 'tolerated',
      'tag.execute': 'calls it',
      'tag.extension': 'extension',
      'tag.persid': 'persid',

      'callables.title': 'Imported callables',
      'callables.note': 'Every symbol this artifact would import at load time. In a pickle, this list is the attack surface.',

      'tensors.title': 'Tensors',
      'tensors.name': 'Name',
      'tensors.dtype': 'dtype',
      'tensors.shape': 'Shape',
      'tensors.elements': 'Elements',
      'tensors.summary': '{count} tensors · {total} elements observed',
      'tensors.truncated': 'Showing the first {shown} of {total}.',

      'metadata.title': 'Parser metadata',
      'metadata.note': 'Values read out of the file itself. Nothing here comes from a sidecar config or from the filename.',
      'inspector.title': 'Inspector errors',
      'inspector.note': 'A crashed inspector never becomes a pass; it becomes this.',

      'copy': 'Copy',
      'copy.done': 'Copied to the clipboard',
      'copy.failed': 'The browser refused clipboard access',

      'actions.bom': 'Download ML-BOM',
      'actions.bom_working': 'Building the ML-BOM…',
      'actions.bom_done': 'ML-BOM downloaded',
      'actions.rescan': 'Inspect again',

      'attest.result.title': 'Attestation package',
      'attest.downloaded': 'The package has been downloaded. Drop it into the Verify tab to check it end to end.',
      'attest.subject': 'Subject SHA-256',
      'attest.head': 'Head hash',
      'attest.merkle': 'Merkle root',
      'attest.key': 'Signing key id',
      'attest.entries': 'Chain entries',
      'attest.verdict': 'Artifact verdict',
      'attest.size': 'Package size',
      'attest.again': 'Download again',
      'attest.warn_fail': 'This artifact failed inspection. The attestation records that faithfully: a signature says who reported it, never that it is safe.',
      'attest.no_anchor': 'The package has no time anchor. The chain proves ordering, not when anything happened.',

      'verify.result.ok': 'PACKAGE VERIFIED',
      'verify.result.bad': 'VERIFICATION FAILED',
      'verify.result.ok.sub': 'Every file matches the signed manifest and the chain recomputes.',
      'verify.result.bad.sub': 'At least one check did not pass. Do not rely on this package.',

      'verify.duo.lede': 'These are two different questions and Actaira refuses to blur them. A package always carries its own public key, so integrity can always be checked, and an attacker who rewrites the package replaces that key too.',
      'verify.q1.eyebrow': 'Question 1 · integrity',
      'verify.q1.question': 'Were the bytes changed after signing?',
      'verify.q1.answer.ok': 'No. All five checks recompute from the package itself.',
      'verify.q1.answer.bad': 'At least one check failed. Treat the package as tampered with.',
      'verify.q2.eyebrow': 'Question 2 · identity',
      'verify.q2.question': 'Who signed it?',
      'verify.q2.answer.trusted': 'A key you supplied as a trust anchor. This is the only case that answers the question.',
      'verify.q2.answer.embedded_key_only': 'Unknown. The signature was checked against the key the package carries, which anyone can generate.',
      'verify.q2.answer.untrusted': 'Not a key you trust. The package may be perfectly intact and still be from anyone.',
      'verify.q2.answer.unverified': 'Not established: no signature verified, so there is no key to attribute this to.',
      'verify.q2.fingerprint': 'Key fingerprint',
      'verify.q2.keyid': 'Key id',
      'verify.q2.bind': 'Bind it to a key you already trust with `actaira verify --trusted-keyring`.',

      'check.files_match_manifest': 'Every file hashes to what the manifest declares',
      'check.chain_intact': 'The hash chain is self-consistent',
      'check.head_matches': 'The head hash matches the last entry',
      'check.merkle_root_matches': 'The Merkle root recomputes from the entries',
      'check.signature_valid': 'The Ed25519 signature verifies against the embedded key',
      'check.key_trusted': 'The signing key is one you already trust',
      'check.ok': 'ok',
      'check.bad': 'fail',

      'chain.title': 'Attestation chain',
      'chain.note': 'Every entry commits to the hash of the one before it, so removing or reordering an entry breaks every hash after it. The Merkle root is computed over all the entries, RFC 6962 leaf and node prefixes included.',
      'chain.genesis': 'genesis',
      'chain.entry': 'entry',
      'chain.prev': 'prev',
      'chain.root': 'merkle root',
      'chain.leaf': 'leaves',
      'chain.aria': 'Hash-linked chain of {n} entries ending at the Merkle root {root}.',
      'chain.more': 'Showing the first {shown} of {total} entries.',

      'trust.trusted': 'trusted',
      'trust.embedded_key_only': 'embedded key only',
      'trust.untrusted': 'untrusted',
      'trust.unverified': 'unverified',
      'verify.problems': 'Problems',
      'verify.warnings': 'Warnings',
      'verify.manifest': 'Manifest',
      'verify.package': 'Package',
      'manifest.tool': 'Tool',
      'manifest.created': 'Created',
      'manifest.entries': 'Entries',
      'manifest.head': 'Head hash',
      'manifest.merkle': 'Merkle root',
      'manifest.scheme': 'Merkle scheme',
      'manifest.key_id': 'Signing key id',
      'manifest.fingerprint': 'Key fingerprint (SHA-256 of the DER SPKI)',
      'manifest.time_anchor': 'Time anchor',
      'manifest.format': 'Package format',

      /* ── governance, the fourth section ─────────────────────────────
       * Chrome only. The obligations' own text arrives from the backend
       * catalogue at /api/i18n/<lang>, exactly as rule descriptions do, so
       * switching language never asks the reader to upload the file again.
       *
       * Two of these strings are the section: the notice at the top says
       * this is not a compliance opinion and that no score exists, and the
       * count line says out loud that it is a count. They are translated
       * with the same care as the obligations themselves. */
      'gov.title': 'The evidence, mapped to the obligation it answers.',
      'gov.lede': 'Actaira reads model artifacts and nothing else. This section lines up what it observed against the EU AI Act obligations that evidence touches, and states, for each one, what it does not establish.',

      'gov.notice.title': 'Not a compliance opinion, and there is no score.',
      'gov.notice.text': 'Nothing on this page is a percentage, a grade or a traffic light, and none is computed anywhere in this tool. Most obligations are marked as outside what Actaira can show, because most of the Regulation is about people, purposes and running systems rather than about a weight file. Whether an organisation complies is a legal question about a system in its context, and no tool that reads model files can answer it.',

      'gov.controls.label': 'What to evaluate',
      'gov.controls.date': 'Obligations as of',
      'gov.controls.date.help': 'The date is an argument, never this machine\u2019s clock, so the same date always gives the same answer.',
      'gov.controls.role': 'Acting as',
      'gov.controls.role.help': 'Who an obligation binds decides who has to act, and most tools blur it.',
      'gov.role.provider': 'provider of an AI system',
      'gov.role.deployer': 'deployer',
      'gov.role.provider_gpai': 'provider of a general-purpose AI model',
      'gov.role.any': 'every role, show everything',

      'gov.timeline.label': 'Dates of application',
      'gov.timeline.note': 'Regulation (EU) 2024/1689, Article 113. Dates, not advice.',
      'gov.timeline.today': 'Today',
      'gov.timeline.today.text': 'The day this page was opened, marked so the dates around it can be read against it.',
      'gov.timeline.viewing': 'Date evaluated',
      'gov.timeline.viewing.text': 'The obligations below are evaluated on this date.',
      'gov.timeline.count': '{n} obligations',
      'gov.t.past': 'in force',
      'gov.t.next': 'next',
      'gov.t.provisional': 'provisional',

      'gov.cards.label': 'Obligations',
      'gov.cards.count': '{bound} obligations bind this role on {on}. {outside} of them are outside what Actaira can show. Counts, not a score.',
      'gov.cards.count.assessed': '{bound} obligations bind this role on {on}. This artifact touches {touched} of them; {outside} are outside what Actaira can show. Counts, not a score.',
      'gov.cards.none': 'No obligation in the catalogue binds this role on this date.',

      'gov.state.evidence_supports': 'evidence supports',
      'gov.state.evidence_partial': 'evidence in part',
      'gov.state.no_evidence_supplied': 'no evidence yet',
      'gov.state.outside_this_tool': 'outside this tool',
      'gov.state.not_yet_applicable': 'not yet applicable',

      'gov.badge.grace': 'grace period',
      'gov.badge.provisional': 'provisional date',

      'gov.detail.open': 'What this shows, and what it does not',
      'gov.detail.close': 'Close',
      'gov.detail.expects': 'What the obligation asks for',
      'gov.detail.provides': 'What Actaira provides',
      'gov.detail.would_provide': 'What Actaira would provide, given evidence',
      'gov.detail.not_provides': 'What Actaira does not provide',
      'gov.detail.nothing': 'Nothing at all.',
      'gov.detail.evidence': 'Evidence supplied',
      'gov.detail.evidence.none': 'None supplied yet.',
      'gov.detail.applies': 'Applies from',
      'gov.detail.grace': 'Grace period until {until}',
      'gov.detail.citation': 'Citation',
      'gov.detail.note': 'Note',
      'gov.detail.days': 'in {n} days',

      'gov.drop.title': 'Drop an artifact to map its evidence',
      'gov.drop.choose': 'Choose a file',
      'gov.drop.formats': 'The artifact is inspected exactly as the Inspect tab inspects it. Nothing is loaded or executed, and the file is removed as soon as the answer has been sent.',
      'gov.artifact.label': 'Artifact assessed',
      'gov.artifact.clear': 'Remove',
      'gov.unread.title': 'This artifact could not be read all the way through.',
      'gov.unread.text': 'No evidence is derived from it. An inconclusive read is evidence about nothing, so it contributes to no obligation below.',
      'gov.loading': 'Reading the artifact',
      'gov.clock.failed': 'The dates of application could not be loaded from this server.',

      'footer.never_executes': 'Actaira never loads, deserialises or executes an artifact. Uploads live in a temporary file and are removed as soon as the response has been sent.',
      'footer.deps': 'No framework, no bundler, no CDN, no external font. Hand-written HTML, CSS and JavaScript over Python’s standard-library HTTP server.',

      'theme.auto': 'Auto',
      'theme.light': 'Light',
      'theme.dark': 'Dark'
    },

    es: {
      'app.title': 'Actaira, inspección de artefactos de modelo',

      'a11y.skip': 'Saltar al contenido',
      'a11y.language_group': 'Idioma de la interfaz',
      'a11y.theme': 'Cambiar el tema de color',
      'a11y.tabs': 'Secciones',

      'tab.inspect': 'Inspeccionar',
      'tab.attest': 'Atestar',
      'tab.verify': 'Verificar',
      'tab.govern': 'Gobernanza',

      'tab.agents': 'Agentes',

      'tab.policy': 'Política',

      'policy.lede': 'Suelta un documento de política. Actaira enseña qué dice, luego decide un artefacto o un agente bajo él y devuelve las reglas y la evidencia que causaron la respuesta.',
      'policy.drop_title': 'Suelta un documento de política',
      'policy.choose': 'Elegir un .yaml',
      'policy.hint': 'yaml · yml · la forma que describe policies/production-model.yaml',
      'policy.summary': 'Política',
      'policy.version': 'versión',
      'policy.digest': 'digest',
      'policy.rules': 'Reglas',
      'policy.rule.when': 'cuando',
      'policy.subject': 'Decidir un sujeto bajo ella',
      'policy.subject.lede': 'El documento de arriba se aplica a un sujeto. Un artefacto se inspecciona primero; un agente se lee y se buscan sus rutas, así que ambos llegan con la evidencia que las reglas preguntan.',
      'policy.subject.artifact': 'Artefacto',
      'policy.subject.agent': 'Agente',
      'policy.subject.choose': 'Elegir el sujeto',
      'policy.subject.kind': 'Tipo de sujeto',
      'policy.subject.name': 'sujeto',
      'policy.decision': 'Decisión',
      'policy.decision.on': 'decidido el',
      'policy.decision.because': 'porque',
      'policy.decision.allow': 'Nada en este documento objetó.',
      'policy.decision.deny': 'Una regla rechazó este sujeto.',
      'policy.decision.review': 'Una regla no pudo evaluarse contra lo que esta ejecución observó.',
      'policy.proof': 'Prueba',
      'policy.proof.lede': 'Cada regla contra cada sujeto, incluidas las que no dispararon. Una prueba que solo listara lo que falló dependería del orden de las reglas.',
      'policy.contributes.allow': 'permite',
      'policy.contributes.deny': 'deniega',
      'policy.contributes.review': 'revisión',
      'policy.noscore': 'Sin puntuación, sin nota, sin porcentaje. Una decisión es una de tres palabras y las reglas que hay detrás.',
      'loading.policy': 'Leyendo el documento',
      'loading.policydecide': 'Decidiendo',

      'graph.stated_by': 'lo afirma',
      'graph.unstated': 'sin afirmar',
      'graph.evidence': 'evidencia',
      'graph.provenance': 'Aristas afirmadas por',
      'graph.evidence_backed': '{n} llevan un identificador de evidencia almacenada.',


      'tab.graph': 'Grafo',

      'gr.lede': 'Lo que este espacio de trabajo ha registrado, y qué depende de qué. Cada línea es una afirmación de alguien: la relación está en la arista, quién la afirmó está en el panel, y aquí no se infiere nada a partir de dos nombres que se parecen.',
      'gr.recorded': 'Relaciones registradas',
      'gr.recorded.note': 'Todo lo que este espacio de trabajo ha registrado alguna vez. Una relación no se elimina cuando una observación posterior deja de verla, así que esto es el grafo conocido y no una afirmación sobre lo que hay ahora mismo.',
      'gr.workspace': 'Espacio de trabajo',
      'gr.workspace.reading': 'leyendo',
      'gr.workspace.nodes': 'activos',
      'gr.workspace.edges': 'relaciones',
      'gr.workspace.sources': 'fuentes',
      'gr.workspace.evidence': 'registros de evidencia',
      'gr.empty.title': 'No hay ningún espacio de trabajo configurado',
      'gr.empty.text': 'Esta interfaz lee un espacio de trabajo solo cuando se arranca contra uno, y nunca crea ninguno. Ejecuta actaira init y después actaira serve --state .actaira/state.db',
      'gr.absent.title': 'No hay ningún espacio de trabajo configurado',
      'gr.unreadable.title': 'Ese fichero no es una base de datos de estado',
      'gr.older_schema.title': 'Ese espacio de trabajo es anterior a esta versión',
      'gr.newer_schema.title': 'Ese espacio de trabajo es posterior a esta versión',
      'gr.empty_graph.title': 'Este espacio de trabajo todavía no ha registrado nada',
      'gr.empty_graph.text': 'Registra una fuente y obsérvala, o registra lo que declara un manifiesto de sujetos con actaira graph build --subjects.',
      'gr.no_edges.title': 'Activos, y ninguna relación entre ellos',
      'gr.no_edges.text': 'Este espacio de trabajo conoce estos activos y nada ha declarado una relación entre dos de ellos. Una respuesta de impacto sobre este grafo saldría vacía porque nadie afirmó nada, no porque nada dependa de nada.',

      'gr.mode': 'Vista',
      'gr.mode.recorded': 'Todo lo registrado',
      'gr.mode.focus': 'Alrededor de un activo',
      'gr.mode.impact': 'Impacto',
      'gr.direction': 'Dirección',
      'gr.direction.both': 'Ambas',
      'gr.direction.dependents': 'Qué depende de él',
      'gr.direction.dependencies': 'De qué depende',
      'gr.depth': 'Saltos',
      'gr.depth.all': 'todos',
      'gr.search': 'Busca un activo por identificador, nombre o digest',
      'gr.search.go': 'Buscar',
      'gr.search.none': 'Nada en este espacio de trabajo coincide con eso.',
      'gr.search.results': 'Coincidencias',
      'gr.filters': 'Mostrar',
      'gr.filters.kinds': 'Tipos',
      'gr.filters.relations': 'Relaciones',
      'gr.filters.hidden': '{n} ocultos por un filtro.',
      'gr.fit': 'Ajustar',
      'gr.zoom_in': 'Acercar',
      'gr.zoom_out': 'Alejar',
      'gr.view.graph': 'Diagrama',
      'gr.view.list': 'Lista',
      'gr.list.lede': 'Las mismas relaciones como texto, una por línea, en el orden en que las devolvió el motor.',
      'gr.aria.graph': 'El grafo de activos registrado: {nodes} activos y {edges} relaciones',
      'gr.aria.node': '{id}, un {kind}',
      'gr.drag_note': 'Los nodos se pueden arrastrar. Dónde queda una caja es una comodidad para leer y nunca se escribe en el espacio de trabajo.',

      'gr.selected.node': 'Activo',
      'gr.selected.edge': 'Relación',
      'gr.selected.none': 'Selecciona un activo o una relación para ver qué registra este espacio de trabajo sobre ello.',
      'gr.node.kind': 'tipo',
      'gr.node.name': 'nombre',
      'gr.node.digest': 'digest',
      'gr.node.source': 'fuente',
      'gr.node.first_seen': 'visto por primera vez',
      'gr.node.last_seen': 'visto por última vez',
      'gr.node.last_snapshot': 'confirmado por última vez por',
      'gr.node.attributes': 'atributos',
      'gr.node.unknown': 'Este espacio de trabajo no tiene registro de ese activo. No tiene dependientes registrados, que no es lo mismo que no tener ninguno.',
      'gr.node.incoming': 'Depende de él',
      'gr.node.outgoing': 'Depende de',
      'gr.node.no_relations': 'Nada ha declarado una relación hacia este activo ni desde él.',
      'gr.edge.from': 'desde',
      'gr.edge.to': 'hasta',
      'gr.edge.relation': 'relación',
      'gr.edge.stated_by': 'lo afirma',
      'gr.edge.evidence': 'evidencia',
      'gr.edge.no_evidence': 'sin identificador de evidencia almacenada',

      'gr.evidence': 'Evidencia',
      'gr.evidence.none': 'Ningún registro de evidencia nombra este activo como su sujeto.',
      'gr.evidence.valid': 'válida',
      'gr.evidence.stale': 'caducada',
      'gr.evidence.superseded': 'sustituida',
      'gr.evidence.revoked': 'revocada',
      'gr.evidence.untrusted': 'no confiable',

      'gr.current': '¿sigue ahí?',
      'gr.current.current': 'confirmado por la última observación',
      'gr.current.not_in_latest_observation': 'registrado antes, y la última observación no lo vio',
      'gr.current.undetermined': 'nada en este espacio de trabajo responde a eso',
      'gr.current.short.current': 'confirmado',
      'gr.current.short.not_in_latest_observation': 'no está en la última observación',
      'gr.current.short.undetermined': 'sin establecer',
      'gr.current.lede': 'Registrado no es lo mismo que actual. Una relación observada se puede contrastar con la última instantánea de su fuente; una declarada no lleva ninguna noción de qué ejecución está viva, así que se informa como indeterminada en lugar de adivinarla.',

      'gr.actions': 'Pregunta sobre este activo',
      'gr.action.focus': 'Centrar en él',
      'gr.action.dependents': 'Qué depende de él',
      'gr.action.dependencies': 'De qué depende',
      'gr.action.impact': 'Qué se ve afectado si cambia',

      'gr.impact': 'Si esto cambia',
      'gr.impact.changed': 'Cambió',
      'gr.impact.affected': 'Afectados',
      'gr.impact.none': 'Nada de lo que este espacio de trabajo ha registrado depende de ese activo.',
      'gr.impact.unknown': 'Este espacio de trabajo nunca ha visto ese activo, así que no tiene dependientes registrados. Eso no es una prueba de que nada dependa de él.',
      'gr.impact.hops': '{n} saltos',
      'gr.impact.hop': '1 salto',
      'gr.impact.why': 'Por qué',
      'gr.impact.route': 'Ruta',
      'gr.impact.by_kind': 'Por tipo',
      'gr.impact.highlight': 'Ver esta ruta en el diagrama',

      'gr.truncated': 'Esta vista se detuvo en su límite de saltos. Hay más relaciones más allá.',
      'gr.impact.truncated': 'El recorrido se detuvo en su límite de profundidad, así que esta lista está incompleta.',
      'gr.cycles': 'Ciclos',
      'gr.cycles.lede': 'Un ciclo es una forma real, no un error: los subagentes se llaman entre sí y los sistemas contienen sistemas.',
      'gr.cycles.incomplete': 'La enumeración de ciclos alcanzó su límite, así que puede haber ciclos que no aparezcan aquí.',
      'gr.too_large': 'Demasiado grande para dibujarlo',
      'loading.graph': 'Leyendo el espacio de trabajo',

      'agents.lede': 'Suelta una declaración de agente. Actaira lee las herramientas, los servidores MCP, las identidades y los datos que alcanza, y reporta las combinaciones que juntas son peligrosas aunque cada una por separado esté bien.',
      'agents.drop_title': 'Suelta una declaración de agente',
      'agents.choose': 'Elegir un .yaml',
      'agents.hint': 'yaml · yml · json · la forma que describe docs/CONCEPTS.es.md',
      'agents.summary': 'Declaración',
      'agents.version': 'versión',
      'agents.environment': 'entorno',
      'agents.digest': 'digest',
      'agents.tools': 'herramientas',
      'agents.mcp': 'servidores MCP',
      'agents.identities': 'identidades',
      'agents.sources': 'fuentes de datos',
      'agents.subagents': 'subagentes',
      'agents.findings': 'Hallazgos de capacidades',
      'agents.findings.none': 'No disparó ninguna regla de capacidades. Eso no es lo mismo que seguro: significa que ninguna regla de este catálogo casó con esta declaración.',
      'agents.paths': 'Rutas de ataque',
      'agents.paths.none': 'No se encontró ninguna ruta desde entrada no confiable hasta una consecuencia en lo que esta declaración afirma.',
      'agents.paths.open': 'abierta',
      'agents.paths.closed': 'cerrada por un control que esta declaración ya lleva',
      'agents.paths.closed_by': 'Cerrada por',
      'agents.paths.carries': 'transporta',
      'agents.paths.break': 'Rompe esta ruta',
      'agents.paths.ineffective': 'Declarado, y no cierra esta ruta',
      'agents.paths.unresolved': 'Delegaciones cuya declaración no se aportó, así que sus rutas no se siguieron:',
      'agents.paths.aria': 'Ruta {n}: de {entry} a {sink}',
      'agents.paths.more': 'Mostrando {shown} de {total} rutas.',
      'agents.bom': 'A-BOM',
      'agents.bom.lede': 'La lista de materiales del agente: cada herramienta, servidor, identidad y fuente como un componente con su propio digest. Compara dos de estas entre versiones para ver qué ganó una capacidad.',
      'agents.bom.download': 'Descargar A-BOM',
      'agents.diff': 'Comparar con otra versión',
      'agents.diff.lede': 'Suelta una segunda declaración para ver qué cambió. Ganar una capacidad es justo lo que una revisión de cambios existe para detectar.',
      'agents.diff.choose': 'Elegir la segunda declaración',
      'agents.diff.same': 'Las dos declaraciones describen las mismas capacidades.',
      'agents.diff.too_big': 'Esa declaración es demasiado grande para compararla en el navegador.',
      'agents.diff.result': 'Qué cambió',
      'loading.agents': 'Leyendo la declaración',
      'loading.agentpaths': 'Buscando rutas',

      'tip.lang.en': 'Interfaz en inglés',
      'tip.lang.es': 'Interfaz en español',

      'welcome.title': 'Lee el fichero del modelo antes de que él te lea a ti.',
      'welcome.lede': 'Actaira abre artefactos pickle, PyTorch, safetensors, ONNX, GGUF, NumPy y Keras byte a byte y cuenta qué harían en cuanto alguien los cargue. Nunca importa, deserializa ni ejecuta nada.',
      'welcome.claim.1': 'No se carga ni se ejecuta nada',
      'welcome.claim.2': 'Nada sale de esta máquina',
      'welcome.claim.3': 'Una sola dependencia, para el Ed25519',
      'welcome.step1.title': 'Leer los bytes',
      'welcome.step1.text': 'El formato se detecta por bytes mágicos y estructura, no por la extensión, y todo contenedor se abre un nivel más abajo.',
      'welcome.step2.title': 'Enseñar el mecanismo',
      'welcome.step2.text': 'Un pickle es un programa. Actaira recorre sus opcodes y te enseña la importación y la llamada, así el veredicto es evidencia y no una afirmación.',
      'welcome.step3.title': 'Firmar el hallazgo',
      'welcome.step3.text': 'El informe se convierte en una entrada encadenada por hash con un ML-BOM CycloneDX y una firma Ed25519 que cualquiera puede comprobar sin conexión.',

      'demo.title': 'Así se ve el paso 2',
      'demo.badge': 'ejemplo',
      'demo.caption': 'Se apilan dos cadenas, STACK_GLOBAL las resuelve a posix.system y REDUCE es el opcode que lo llama. Ese es el exploit entero, y ocupa cuatro líneas.',

      'samples.title': 'O inspecciona una muestra',
      'samples.note': 'Artefactos del corpus de evaluación, leídos del disco de esta máquina.',
      'sample.gadget.note': 'Un pickle que lanza una orden de shell por posix.system.',
      'sample.trojan.note': 'Un checkpoint de PyTorch con el gadget un nivel más abajo, dentro del zip.',
      'sample.clean_pickle.note': 'Un state_dict de numpy real: importa, y todo está en la lista de permitidos.',
      'sample.clean_tensors.note': 'Dos tensores bien formados y ninguna vía de ejecución.',
      'sample.running': 'Inspeccionando {name}…',
      'sample.badge': 'muestra',

      'drop.title': 'Arrastra aquí un artefacto',
      'drop.hint': 'o',
      'drop.choose': 'Elegir un fichero',
      'drop.formats': 'pickle · .pt/.pth · safetensors · onnx · gguf · .npy · keras/hdf5 · zip · hasta 2 GiB',
      'drop.wrong_type': 'Eso parece una carpeta o un fichero vacío.',

      'attest.lede': 'Inspecciona un artefacto y firma el resultado. Obtienes un .zip portátil con una entrada encadenada por hash, un ML-BOM CycloneDX 1.6 y una firma Ed25519 que cualquiera puede comprobar sin conexión.',
      'attest.hint': 'Primero se inspecciona el artefacto. Lo que se firma es el informe.',
      'verify.lede': 'Comprueba un paquete de atestación sin red ninguna. La integridad y la identidad se informan por separado, porque todo paquete lleva su propia clave pública y eso no demuestra nada sobre quién firmó.',
      'verify.drop_title': 'Arrastra aquí un paquete de atestación',
      'verify.choose': 'Elegir un .zip',
      'verify.hint': 'El .zip que escribe la pestaña Atestar o `actaira attest --out`.',

      'options.title': 'Opciones de análisis',
      'options.policy': 'Política de importación',
      'options.policy.strict': 'strict, lista de permitidos',
      'options.policy.known_bad': 'known-bad, lista de prohibidos',
      'options.policy.help': 'strict marca toda importación fuera de una lista corta de permitidos. known-bad marca solo las importaciones ya conocidas como peligrosas.',
      'options.fail_on': 'Fallar a partir de',
      'options.fail_on.help': 'La severidad más baja que convierte el veredicto en fallo.',

      'empty.attest.title': 'Todavía no has atestado nada',
      'empty.attest.text': 'Arrastra un artefacto para inspeccionarlo y firmar el informe en un paquete portátil y verificable sin conexión.',
      'empty.verify.title': 'Todavía no has verificado nada',
      'empty.verify.text': 'Arrastra un paquete de atestación para recalcular sus hashes, su raíz de Merkle y su firma, enteramente en esta máquina.',

      'loading.uploading': 'Subiendo, {pct}%',
      'loading.inspecting': 'Inspeccionando el artefacto…',
      'loading.attesting': 'Inspeccionando y firmando…',
      'loading.verifying': 'Verificando el paquete…',
      'loading.note': 'No se ejecuta nada. La subida se escribe en un fichero temporal y se borra en cuanto se envía la respuesta.',
      'loading.title': 'Trabajando',

      'error.title': 'La petición no se completó',
      'error.network': 'No se pudo contactar con el servidor de Actaira. ¿Sigue en marcha en este puerto?',
      'error.http': 'El servidor respondió HTTP {status}.',
      'error.parse': 'El servidor respondió algo que no es JSON válido.',
      'error.aborted': 'La petición se canceló.',
      'error.retry': 'Reintentar',
      'error.no_file': 'Ya no hay ningún fichero seleccionado. Elige uno otra vez.',

      'verdict.pass': 'CORRECTO',
      'verdict.fail': 'FALLO',
      'verdict.inconclusive': 'NO CONCLUYENTE',
      'verdict.pass.sub': 'Leído por completo y sin nada por encima de severidad media.',
      'verdict.fail.sub': 'Al menos un hallazgo alcanza o supera el umbral de fallo.',
      'verdict.inconclusive.sub': 'El artefacto no se pudo leer entero. Eso, a propósito, no es un aprobado.',

      'summary.title': 'Resumen',
      'summary.file': 'Fichero',
      'summary.size': 'Tamaño',
      'summary.format': 'Formato detectado',
      'summary.severity': 'Severidad máxima',
      'summary.sha256': 'SHA-256',
      'summary.read': 'Cobertura',
      'read.full': 'leído entero',
      'read.partial': 'leído parcialmente',
      'confidence.magic': 'bytes mágicos',
      'confidence.structure': 'estructura',
      'confidence.extension': 'solo la extensión',
      'confidence.unknown': 'desconocida',
      'confidence.label': 'confianza: {value}',
      'severity.none': 'ninguna',
      'value.unknown': 'desconocido',

      'findings.title': 'Hallazgos',
      'findings.none': 'Sin hallazgos. Todas las comprobaciones que admite este formato salieron limpias.',
      'findings.evidence': 'Evidencia',
      'findings.location': 'en',
      'findings.untranslated': 'No hay descripción para esta regla en el catálogo.',

      'trace.title': 'Desensamblado del pickle',
      'trace.loading': 'Recorriendo el flujo de opcodes…',
      'trace.note': 'La misma interpretación abstracta que ejecuta el analizador, impresa paso a paso en vez de resumida. Aquí no se ha ejecutado nada.',
      'trace.protocol': 'protocolo {n}',
      'trace.opcodes': '{n} opcodes',
      'trace.member': 'miembro',
      'trace.col.kind': 'tipo de paso',
      'trace.col.offset': 'offset',
      'trace.col.opcode': 'opcode',
      'trace.col.arg': 'argumento',
      'trace.col.verdict': 'juicio',
      'trace.filter.relevant': 'Lo que importa',
      'trace.filter.all': 'Todos los pasos',
      'trace.filter.aria': 'Qué pasos mostrar',
      'trace.hidden': '{n} pasos ocultos',
      'trace.hidden.none': 'se muestran todos los pasos',
      'trace.gap': '{n} pasos',
      'trace.truncated': 'El flujo se cortó antes de tiempo: {error}',
      'trace.limited': 'Mostrando los {shown} primeros de {total} opcodes.',
      'trace.unavailable.not_a_pickle': 'Este artefacto no lleva ningún flujo pickle, así que no hay opcodes que recorrer.',
      'trace.unavailable.no_pickle_member': 'El contenedor no tiene ningún miembro pickle. Nada dentro importaría nada al cargarse.',
      'trace.unavailable.too_large': 'El flujo pickle supera el límite de tamaño del desensamblado. El veredicto de arriba sigue saliendo del análisis completo.',
      'trace.unavailable.unreadable_container': 'El contenedor no se pudo abrir, así que no se pudieron recorrer sus miembros.',
      'trace.error': 'La petición de desensamblado falló. El veredicto de arriba no se ve afectado.',

      'kind.import': 'importación',
      'kind.execute': 'ejecución',
      'kind.extension': 'extensión',
      'kind.persid': 'id persistente',
      'kind.data': 'datos',
      'judge.denied': 'denegado',
      'judge.unknown': 'desconocido',
      'judge.allowed': 'permitido',
      'judge.unresolved': 'sin resolver',
      'judge.tolerated': 'tolerado',
      'tag.execute': 'lo llama',
      'tag.extension': 'extensión',
      'tag.persid': 'persid',

      'callables.title': 'Invocables importados',
      'callables.note': 'Todos los símbolos que este artefacto importaría al cargarse. En un pickle, esta lista es la superficie de ataque.',

      'tensors.title': 'Tensores',
      'tensors.name': 'Nombre',
      'tensors.dtype': 'dtype',
      'tensors.shape': 'Forma',
      'tensors.elements': 'Elementos',
      'tensors.summary': '{count} tensores · {total} elementos observados',
      'tensors.truncated': 'Mostrando los {shown} primeros de {total}.',

      'metadata.title': 'Metadatos del analizador',
      'metadata.note': 'Valores leídos del propio fichero. Nada de esto viene de un config aparte ni del nombre del fichero.',
      'inspector.title': 'Errores del inspector',
      'inspector.note': 'Un inspector que revienta nunca se convierte en un aprobado; se convierte en esto.',

      'copy': 'Copiar',
      'copy.done': 'Copiado al portapapeles',
      'copy.failed': 'El navegador denegó el acceso al portapapeles',

      'actions.bom': 'Descargar el ML-BOM',
      'actions.bom_working': 'Construyendo el ML-BOM…',
      'actions.bom_done': 'ML-BOM descargado',
      'actions.rescan': 'Inspeccionar de nuevo',

      'attest.result.title': 'Paquete de atestación',
      'attest.downloaded': 'El paquete se ha descargado. Suéltalo en la pestaña Verificar para comprobarlo de principio a fin.',
      'attest.subject': 'SHA-256 del sujeto',
      'attest.head': 'Hash de cabeza',
      'attest.merkle': 'Raíz de Merkle',
      'attest.key': 'ID de la clave firmante',
      'attest.entries': 'Entradas de la cadena',
      'attest.verdict': 'Veredicto del artefacto',
      'attest.size': 'Tamaño del paquete',
      'attest.again': 'Descargar otra vez',
      'attest.warn_fail': 'Este artefacto no superó la inspección. La atestación lo recoge con fidelidad: una firma dice quién lo informó, nunca que sea seguro.',
      'attest.no_anchor': 'El paquete no tiene anclaje temporal. La cadena demuestra el orden, no cuándo ocurrió nada.',

      'verify.result.ok': 'PAQUETE VERIFICADO',
      'verify.result.bad': 'VERIFICACIÓN FALLIDA',
      'verify.result.ok.sub': 'Todos los ficheros coinciden con el manifiesto firmado y la cadena recalcula.',
      'verify.result.bad.sub': 'Al menos una comprobación no pasó. No te fíes de este paquete.',

      'verify.duo.lede': 'Son dos preguntas distintas y Actaira se niega a mezclarlas. Todo paquete lleva su propia clave pública, así que la integridad siempre se puede comprobar, y un atacante que reescriba el paquete también reemplaza esa clave.',
      'verify.q1.eyebrow': 'Pregunta 1 · integridad',
      'verify.q1.question': '¿Se han cambiado los bytes después de firmar?',
      'verify.q1.answer.ok': 'No. Las cinco comprobaciones recalculan a partir del propio paquete.',
      'verify.q1.answer.bad': 'Al menos una comprobación falló. Trata el paquete como manipulado.',
      'verify.q2.eyebrow': 'Pregunta 2 · identidad',
      'verify.q2.question': '¿Quién lo firmó?',
      'verify.q2.answer.trusted': 'Una clave que tú diste como ancla de confianza. Este es el único caso que responde la pregunta.',
      'verify.q2.answer.embedded_key_only': 'No se sabe. La firma se comprobó contra la clave que lleva el propio paquete, y esa la puede generar cualquiera.',
      'verify.q2.answer.untrusted': 'No es una clave en la que confíes. El paquete puede estar intacto y aun así venir de cualquiera.',
      'verify.q2.answer.unverified': 'Sin establecer: ninguna firma verificó, así que no hay clave a la que atribuir esto.',
      'verify.q2.fingerprint': 'Huella de la clave',
      'verify.q2.keyid': 'ID de la clave',
      'verify.q2.bind': 'Átalo a una clave en la que ya confíes con `actaira verify --trusted-keyring`.',

      'check.files_match_manifest': 'Cada fichero produce el hash que declara el manifiesto',
      'check.chain_intact': 'La cadena de hashes es coherente consigo misma',
      'check.head_matches': 'El hash de cabeza coincide con la última entrada',
      'check.merkle_root_matches': 'La raíz de Merkle recalcula a partir de las entradas',
      'check.signature_valid': 'La firma Ed25519 verifica contra la clave incrustada',
      'check.key_trusted': 'La clave firmante es una en la que ya confías',
      'check.ok': 'ok',
      'check.bad': 'fallo',

      'chain.title': 'Cadena de atestación',
      'chain.note': 'Cada entrada se compromete con el hash de la anterior, así que quitar o reordenar una entrada rompe todos los hashes posteriores. La raíz de Merkle se calcula sobre todas las entradas, con los prefijos de hoja y de nodo del RFC 6962.',
      'chain.genesis': 'génesis',
      'chain.entry': 'entrada',
      'chain.prev': 'prev',
      'chain.root': 'raíz merkle',
      'chain.leaf': 'hojas',
      'chain.aria': 'Cadena encadenada por hash de {n} entradas que termina en la raíz de Merkle {root}.',
      'chain.more': 'Mostrando las {shown} primeras de {total} entradas.',

      'trust.trusted': 'de confianza',
      'trust.embedded_key_only': 'solo clave incrustada',
      'trust.untrusted': 'sin confianza',
      'trust.unverified': 'sin verificar',
      'verify.problems': 'Problemas',
      'verify.warnings': 'Avisos',
      'verify.manifest': 'Manifiesto',
      'verify.package': 'Paquete',
      'manifest.tool': 'Herramienta',
      'manifest.created': 'Creado',
      'manifest.entries': 'Entradas',
      'manifest.head': 'Hash de cabeza',
      'manifest.merkle': 'Raíz de Merkle',
      'manifest.scheme': 'Esquema de Merkle',
      'manifest.key_id': 'ID de la clave firmante',
      'manifest.fingerprint': 'Huella de la clave (SHA-256 del SPKI DER)',
      'manifest.time_anchor': 'Anclaje temporal',
      'manifest.format': 'Formato de paquete',

      'gov.title': 'La evidencia, mapeada a la obligación que responde.',
      'gov.lede': 'Actaira lee artefactos de modelos y nada más. Esta sección alinea lo que ha observado con las obligaciones del Reglamento de IA que esa evidencia toca y dice, para cada una, qué no acredita.',

      'gov.notice.title': 'Esto no es una opinión de cumplimiento y no hay ninguna puntuación.',
      'gov.notice.text': 'Nada de esta página es un porcentaje, una nota ni un semáforo, y esta herramienta no calcula ninguno. La mayoría de las obligaciones aparecen marcadas como fuera de lo que Actaira puede demostrar, porque la mayor parte del Reglamento trata de personas, finalidades y sistemas en funcionamiento, no de un fichero de pesos. Si una organización cumple o no es una cuestión jurídica sobre un sistema en su contexto, y ninguna herramienta que lea ficheros de modelo puede responderla.',

      'gov.controls.label': 'Qué se evalúa',
      'gov.controls.date': 'Obligaciones a fecha de',
      'gov.controls.date.help': 'La fecha es un argumento, nunca el reloj de esta máquina, así que la misma fecha da siempre la misma respuesta.',
      'gov.controls.role': 'Actuando como',
      'gov.controls.role.help': 'A quién obliga cada artículo decide quién tiene que actuar, y casi todas las herramientas lo difuminan.',
      'gov.role.provider': 'proveedor de un sistema de IA',
      'gov.role.deployer': 'responsable del despliegue',
      'gov.role.provider_gpai': 'proveedor de un modelo de IA de uso general',
      'gov.role.any': 'todos los roles, mostrarlo todo',

      'gov.timeline.label': 'Fechas de aplicación',
      'gov.timeline.note': 'Reglamento (UE) 2024/1689, artículo 113. Fechas, no asesoramiento.',
      'gov.timeline.today': 'Hoy',
      'gov.timeline.today.text': 'El día en que se abrió esta página, marcado para poder leer las fechas de alrededor con respecto a él.',
      'gov.timeline.viewing': 'Fecha evaluada',
      'gov.timeline.viewing.text': 'Las obligaciones de abajo se evalúan en esta fecha.',
      'gov.timeline.count': '{n} obligaciones',
      'gov.t.past': 'en vigor',
      'gov.t.next': 'siguiente',
      'gov.t.provisional': 'provisional',

      'gov.cards.label': 'Obligaciones',
      'gov.cards.count': 'A este rol le obligan {bound} artículos el {on}. {outside} quedan fuera de lo que Actaira puede demostrar. Son recuentos, no una nota.',
      'gov.cards.count.assessed': 'A este rol le obligan {bound} artículos el {on}. Este artefacto toca {touched} y {outside} quedan fuera de lo que Actaira puede demostrar. Son recuentos, no una nota.',
      'gov.cards.none': 'Ninguna obligación del catálogo vincula a este rol en esta fecha.',

      'gov.state.evidence_supports': 'la evidencia aporta',
      'gov.state.evidence_partial': 'aporta en parte',
      'gov.state.no_evidence_supplied': 'sin evidencia',
      'gov.state.outside_this_tool': 'fuera de la herramienta',
      'gov.state.not_yet_applicable': 'todavía no aplica',

      'gov.badge.grace': 'periodo de gracia',
      'gov.badge.provisional': 'fecha provisional',

      'gov.detail.open': 'Lo que muestra y lo que no',
      'gov.detail.close': 'Cerrar',
      'gov.detail.expects': 'Qué pide la obligación',
      'gov.detail.provides': 'Qué aporta Actaira',
      'gov.detail.would_provide': 'Qué aportaría Actaira, con evidencia',
      'gov.detail.not_provides': 'Qué no aporta Actaira',
      'gov.detail.nothing': 'Absolutamente nada.',
      'gov.detail.evidence': 'Evidencia aportada',
      'gov.detail.evidence.none': 'Todavía no se ha aportado ninguna.',
      'gov.detail.applies': 'Se aplica desde',
      'gov.detail.grace': 'Periodo de gracia hasta el {until}',
      'gov.detail.citation': 'Cita',
      'gov.detail.note': 'Nota',
      'gov.detail.days': 'faltan {n} días',

      'gov.drop.title': 'Suelte aquí un artefacto para mapear su evidencia',
      'gov.drop.choose': 'Elegir un fichero',
      'gov.drop.formats': 'El artefacto se inspecciona igual que en la pestaña Inspeccionar. No se carga ni se ejecuta nada, y el fichero se borra en cuanto se ha enviado la respuesta.',
      'gov.artifact.label': 'Artefacto evaluado',
      'gov.artifact.clear': 'Quitar',
      'gov.unread.title': 'Este artefacto no se ha podido leer del todo.',
      'gov.unread.text': 'No se deriva ninguna evidencia de él. Una lectura no concluyente es evidencia sobre nada, así que no aporta a ninguna obligación de las de abajo.',
      'gov.loading': 'Leyendo el artefacto',
      'gov.clock.failed': 'No se han podido cargar las fechas de aplicación desde este servidor.',

      'footer.never_executes': 'Actaira nunca carga, deserializa ni ejecuta un artefacto. Las subidas viven en un fichero temporal y se borran en cuanto se ha enviado la respuesta.',
      'footer.deps': 'Sin framework, sin empaquetador, sin CDN y sin fuentes externas. HTML, CSS y JavaScript escritos a mano sobre el servidor HTTP de la biblioteca estándar de Python.',

      'theme.auto': 'Automático',
      'theme.light': 'Claro',
      'theme.dark': 'Oscuro'
    }
  };

  var SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  /* Integrity is these five and only these five. `key_trusted` is a question
   * about identity and lives in its own block; folding it in here is exactly
   * the conflation the product exists to refuse. */
  var INTEGRITY_CHECKS = [
    'files_match_manifest', 'chain_intact', 'head_matches',
    'merkle_root_matches', 'signature_valid'
  ];
  /* Tabs that own a dropzone, a result region and a renderer. */
  var TABS = ['inspect', 'agents', 'policy', 'attest', 'verify'];
  /* Tabs in the navigation. Governance is here before it has data: it is a
   * panel with an empty state, not a file workflow, so it is deliberately
   * not in TABS. */
  var NAV_TABS = ['inspect', 'agents', 'policy', 'graph', 'attest', 'verify', 'govern'];
  var THEMES = ['auto', 'light', 'dark'];
  var TRACE_FORMATS = ['pickle', 'pytorch-zip', 'zip'];
  var KIND_ORDER = ['import', 'execute', 'extension', 'persid', 'data'];
  var MAX_TENSOR_ROWS = 200;
  var MAX_CHAIN_NODES = 8;
  // A declaration with more routes than this has a structural problem the
  // panel cannot help with, and the count above the list is the real one.
  var MAX_ROUTES_SHOWN = 12;
  // The server caps a form field at 64 KiB and the second declaration of a
  // diff travels as one, so the browser refuses a bigger file with a sentence
  // rather than letting the request fail with a 400 nobody asked for.
  var MAX_DECLARATION_FIELD_BYTES = 64 * 1024;
  // Four, not two: with STACK_GLOBAL the module and the attribute are each
  // pushed as a string followed by a MEMOIZE, so two steps of context show
  // the attribute and hide where the module came from.
  var CONTEXT_STEPS = 4;
  var SVG_NS = 'http://www.w3.org/2000/svg';

  /* The verbatim disassembly of evals/artifacts/gadget_known_posix_system_p4.pkl,
   * used as the worked example on the welcome screen. It is real output, and
   * it is labelled as an example rather than presented as a live result. */
  var DEMO_STEPS = [
    { index: 0, offset: 0,  opcode: 'PROTO',            arg: '4',      kind: 'proto' },
    { index: 1, offset: 2,  opcode: 'SHORT_BINUNICODE', arg: 'posix',  kind: 'data' },
    { index: 2, offset: 9,  opcode: 'SHORT_BINUNICODE', arg: 'system', kind: 'data' },
    { index: 3, offset: 17, opcode: 'STACK_GLOBAL',     arg: null,     kind: 'import',
      resolved: 'posix.system', judgement: 'denied' },
    { index: 4, offset: 18, opcode: 'BINUNICODE',       arg: 'id',     kind: 'data' },
    { index: 5, offset: 25, opcode: 'BINPUT',           arg: '0',      kind: 'data' },
    { index: 6, offset: 27, opcode: 'TUPLE1',           arg: null,     kind: 'data' },
    { index: 7, offset: 28, opcode: 'BINPUT',           arg: '1',      kind: 'data' },
    { index: 8, offset: 30, opcode: 'REDUCE',           arg: null,     kind: 'execute' },
    { index: 9, offset: 31, opcode: 'STOP',             arg: null,     kind: 'stop' }
  ];

  var state = {
    lang: 'en',
    theme: 'auto',
    rules: {},
    tab: 'inspect',
    samples: [],
    traceFilter: 'relevant',
    files: { inspect: null, agents: null, policy: null, attest: null, verify: null, govern: null, graph: null },
    sample: { inspect: null },
    data: { inspect: null, agents: null, policy: null, attest: null, verify: null, govern: null, graph: null },
    trace: { inspect: null },
    /* The agent panel's two secondary results: the route search and a diff
     * against a second declaration. Both are separate requests, so both are
     * separate slots rather than fields on the primary payload. */
    agents: { paths: null, diff: null },
    /* The policy panel: the subject kind the operator chose, and the
     * decision, which is a second request about a second file. */
    policy: { subjectKind: 'artifact', decision: null },
    /* The graph panel. Everything about what is on screen - the focus, the
     * hop limit, the filters, where a box was dragged to - lives here and
     * nowhere else. None of it is written to the workspace: a node's
     * coordinates are a reading convenience, not an assurance claim. */
    graph: {
      workspace: null, limits: null, totals: null,
      payload: null, recorded: null, error: null, busy: false,
      focus: '', depth: 2, direction: 'both',
      search: '', matches: null,
      hiddenKinds: {}, hiddenRelations: {},
      selected: null, node: null, impact: null, route: null,
      positions: {}, zoom: 1, pan: { x: 0, y: 0 }, needsFit: true, view: 'graph'
    },
    error: { inspect: null, agents: null, policy: null, attest: null, verify: null, govern: null, graph: null },
    busy: { inspect: false, agents: false, policy: false, attest: false, verify: false, govern: false, graph: false },
    /* Obligation prose, loaded with the rule catalogue from
     * /api/i18n/<lang>, so a language switch re-renders the panel without
     * asking for the artifact again. */
    obligations: {},
    gov: { clock: null, clockFailed: false, on: null, role: 'provider', open: {} }
  };

  /* ── tiny helpers ─────────────────────────────────────────────────── */

  function store(key, value) {
    try { window.localStorage.setItem(key, value); } catch (err) { /* private mode, disabled storage */ }
  }

  function recall(key) {
    try { return window.localStorage.getItem(key); } catch (err) { return null; }
  }

  function t(key, vars) {
    var table = I18N[state.lang] || I18N.en;
    var text = table[key];
    if (text === undefined) { text = I18N.en[key]; }
    if (text === undefined) { return key; }
    if (!vars) { return text; }
    return text.replace(/\{(\w+)\}/g, function (whole, name) {
      return Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : whole;
    });
  }

  function ruleText(ruleId) {
    var text = state.rules[ruleId];
    return (typeof text === 'string' && text.length) ? text : null;
  }

  function el(tag, options, children) {
    var node = document.createElement(tag);
    var opts = options || {};
    Object.keys(opts).forEach(function (key) {
      var value = opts[key];
      if (value === null || value === undefined || value === false) { return; }
      if (key === 'class') { node.className = value; }
      else if (key === 'text') { node.textContent = value; }
      else if (key === 'onclick') { node.addEventListener('click', value); }
      else if (value === true) { node.setAttribute(key, ''); }
      else { node.setAttribute(key, String(value)); }
    });
    (children || []).forEach(function (child) {
      if (child === null || child === undefined) { return; }
      node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
    });
    return node;
  }

  function svgNode(tag, attrs, children) {
    var node = document.createElementNS(SVG_NS, tag);
    Object.keys(attrs || {}).forEach(function (key) {
      if (key === 'text') { node.textContent = attrs[key]; return; }
      node.setAttribute(key, String(attrs[key]));
    });
    (children || []).forEach(function (child) { if (child) { node.appendChild(child); } });
    return node;
  }

  function svgIcon(id, className) {
    var svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('class', className || 'icon');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    var use = document.createElementNS(SVG_NS, 'use');
    use.setAttribute('href', '#' + id);
    svg.appendChild(use);
    return svg;
  }

  function clear(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }

  function num(value) {
    if (typeof value !== 'number' || !isFinite(value)) { return String(value); }
    try { return new Intl.NumberFormat(state.lang).format(value); }
    catch (err) { return String(value); }
  }

  function bytes(value) {
    if (typeof value !== 'number' || !isFinite(value)) { return t('value.unknown'); }
    var units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    var index = 0;
    var scaled = value;
    while (scaled >= 1024 && index < units.length - 1) { scaled /= 1024; index += 1; }
    var shown;
    try {
      shown = new Intl.NumberFormat(state.lang, { maximumFractionDigits: index === 0 ? 0 : 1 }).format(scaled);
    } catch (err) { shown = String(Math.round(scaled * 10) / 10); }
    if (index === 0) { return shown + ' B'; }
    return shown + ' ' + units[index] + ' (' + num(value) + ' B)';
  }

  function shortHash(value, keep) {
    var text = String(value || '');
    var width = keep || 10;
    return text.length > width ? text.slice(0, width) + '…' : text;
  }

  function pad(value, width) {
    var text = String(value);
    while (text.length < width) { text = '0' + text; }
    return text;
  }

  function toast(message) {
    var node = document.getElementById('toast');
    node.textContent = message;
    node.hidden = false;
    window.clearTimeout(node._timer);
    node._timer = window.setTimeout(function () { node.hidden = true; }, 2600);
  }

  function copyText(value, button) {
    var restore = function (key) {
      toast(t(key));
      if (!button) { return; }
      var label = button.querySelector('.copybtn__label');
      if (!label) { return; }
      label.textContent = t(key === 'copy.done' ? 'copy.done' : 'copy');
      window.setTimeout(function () { label.textContent = t('copy'); }, 1800);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(
        function () { restore('copy.done'); },
        function () { legacyCopy(value) ? restore('copy.done') : restore('copy.failed'); }
      );
      return;
    }
    restore(legacyCopy(value) ? 'copy.done' : 'copy.failed');
  }

  function legacyCopy(value) {
    // navigator.clipboard needs a secure context; http://localhost qualifies,
    // http://192.168.x.x does not. This keeps the button honest there too.
    var area = el('textarea', { 'aria-hidden': 'true', class: 'visually-hidden' });
    area.value = value;
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (err) { ok = false; }
    document.body.removeChild(area);
    return ok;
  }

  /* ── static translation pass ──────────────────────────────────────── */

  var ATTR_KEYS = [
    ['data-i18n-aria-label', 'aria-label'],
    ['data-i18n-title', 'title'],
    ['data-i18n-tip', 'data-tip'],
    ['data-i18n-placeholder', 'placeholder']
  ];

  function applyStaticI18n() {
    document.documentElement.lang = state.lang;
    document.title = t('app.title');
    Array.prototype.forEach.call(document.querySelectorAll('[data-i18n]'), function (node) {
      node.textContent = t(node.getAttribute('data-i18n'));
    });
    ATTR_KEYS.forEach(function (pair) {
      Array.prototype.forEach.call(document.querySelectorAll('[' + pair[0] + ']'), function (node) {
        node.setAttribute(pair[1], t(node.getAttribute(pair[0])));
      });
    });
    document.getElementById('theme-label').textContent = t('theme.' + state.theme);
    TABS.forEach(function (tab) { renderChosen(tab); });
    renderDemo();
    renderSamples();
    renderGovern();
    renderGraph();
  }

  /* ── network ──────────────────────────────────────────────────────── */

  function describeHttpError(status, payload) {
    var message = t('error.http', { status: status });
    var detail = null;
    if (payload && payload.error && payload.error.message) {
      message = payload.error.message;
      detail = payload.error.code ? payload.error.code + ' · HTTP ' + status : 'HTTP ' + status;
    }
    return { message: message, detail: detail };
  }

  function attachJsonHandlers(xhr, handlers, url) {
    xhr.addEventListener('error', function () {
      handlers.onError({ message: t('error.network'), detail: url });
    });
    xhr.addEventListener('abort', function () {
      handlers.onError({ message: t('error.aborted'), detail: url });
    });
    xhr.addEventListener('load', function () {
      if (handlers.blob) { return finishBlob(xhr, handlers); }
      var payload = null;
      try { payload = JSON.parse(xhr.responseText); }
      catch (err) {
        handlers.onError({ message: t('error.parse'), detail: String(xhr.responseText || '').slice(0, 300) });
        return;
      }
      if (xhr.status < 200 || xhr.status >= 300) {
        handlers.onError(describeHttpError(xhr.status, payload));
        return;
      }
      handlers.onDone(payload, xhr);
    });
  }

  /**
   * One upload path for every endpoint. XMLHttpRequest rather than fetch,
   * for the single reason that fetch still cannot report upload progress,
   * and a UI that goes silent while a multi-gigabyte file crosses the wire
   * is a UI that looks broken.
   */
  function upload(url, file, fields, handlers) {
    var form = new FormData();
    Object.keys(fields || {}).forEach(function (key) { form.append(key, fields[key]); });
    form.append('file', file, file.name);

    var xhr = new XMLHttpRequest();
    xhr.open('POST', url, true);
    if (handlers.blob) { xhr.responseType = 'blob'; }

    xhr.upload.addEventListener('progress', function (event) {
      if (event.lengthComputable && handlers.onProgress) {
        handlers.onProgress(event.loaded / event.total);
      }
    });
    xhr.upload.addEventListener('load', function () {
      if (handlers.onUploaded) { handlers.onUploaded(); }
    });
    attachJsonHandlers(xhr, handlers, url);
    xhr.send(form);
    return xhr;
  }

  /** The sample routes take a small JSON body instead of a file. */
  function postJson(url, body, handlers) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', url, true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    attachJsonHandlers(xhr, handlers, url);
    xhr.send(JSON.stringify(body || {}));
    return xhr;
  }

  function getJson(url, onDone, onFail) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, true);
    xhr.addEventListener('load', function () {
      var payload = null;
      try { payload = JSON.parse(xhr.responseText); } catch (err) { payload = null; }
      if (payload && xhr.status >= 200 && xhr.status < 300) { onDone(payload); }
      else if (onFail) { onFail(); }
    });
    xhr.addEventListener('error', function () { if (onFail) { onFail(); } });
    xhr.send();
  }

  function finishBlob(xhr, handlers) {
    if (xhr.status >= 200 && xhr.status < 300) {
      handlers.onDone(xhr.response, xhr);
      return;
    }
    // An error body arrives as a Blob too; read it back so the user sees why.
    var blob = xhr.response;
    if (blob && typeof blob.text === 'function') {
      blob.text().then(function (text) {
        var payload = null;
        try { payload = JSON.parse(text); } catch (err) { payload = null; }
        handlers.onError(describeHttpError(xhr.status, payload));
      }, function () {
        handlers.onError(describeHttpError(xhr.status, null));
      });
      return;
    }
    handlers.onError(describeHttpError(xhr.status, null));
  }

  function download(blob, filename) {
    var href = URL.createObjectURL(blob);
    var anchor = el('a', { href: href, download: filename, class: 'visually-hidden' });
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    window.setTimeout(function () { URL.revokeObjectURL(href); }, 10000);
  }

  function filenameFromDisposition(value, fallback) {
    if (!value) { return fallback; }
    var match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(value);
    return match ? decodeURIComponent(match[1]) : fallback;
  }

  /* ── shared result states ─────────────────────────────────────────── */

  function outputOf(tab) { return document.getElementById('out-' + tab); }

  function showState(tab, node) {
    var out = outputOf(tab);
    clear(out);
    if (node) { out.appendChild(node); }
  }

  function emptyState(tab) {
    return el('div', { class: 'state' }, [
      svgIcon('i-' + (tab === 'verify' ? 'verify' : 'attest'), 'icon state__icon'),
      el('p', { class: 'state__title', text: t('empty.' + tab + '.title') }),
      el('p', { class: 'state__text', text: t('empty.' + tab + '.text') })
    ]);
  }

  function loadingState(tab, phaseKey) {
    var bar = el('div', { class: 'progress__bar' });
    bar.style.setProperty('--progress', '0');
    var track = el('div', {
      class: 'progress',
      role: 'progressbar',
      'aria-valuemin': '0',
      'aria-valuemax': '100',
      'aria-valuenow': '0',
      'aria-label': t('loading.title')
    }, [bar]);
    var label = el('p', { class: 'progress__label', text: t('loading.uploading', { pct: 0 }) });
    var node = el('div', { class: 'state' }, [
      el('p', { class: 'state__title', text: t(phaseKey) }),
      track,
      label,
      el('p', { class: 'state__text', text: t('loading.note') })
    ]);
    node._bar = bar;
    node._track = track;
    node._label = label;
    node._phaseKey = phaseKey;
    return node;
  }

  function setProgress(tab, fraction) {
    var node = outputOf(tab).firstChild;
    if (!node || !node._bar) { return; }
    var pct = Math.max(0, Math.min(1, fraction));
    node._bar.style.setProperty('--progress', String(pct));
    node._track.setAttribute('aria-valuenow', String(Math.round(pct * 100)));
    node._label.textContent = t('loading.uploading', { pct: Math.round(pct * 100) });
  }

  function setIndeterminate(tab) {
    var node = outputOf(tab).firstChild;
    if (!node || !node._bar) { return; }
    node._track.classList.add('progress--indeterminate');
    node._track.removeAttribute('aria-valuenow');
    node._label.textContent = t(node._phaseKey);
  }

  function errorState(tab) {
    var info = state.error[tab] || {};
    var retry = el('button', {
      type: 'button',
      class: 'btn',
      onclick: function () { rerun(tab); }
    }, [svgIcon('i-retry'), document.createTextNode(t('error.retry'))]);

    return el('div', { class: 'state state--error', role: 'alert' }, [
      svgIcon('i-alert', 'icon state__icon'),
      el('p', { class: 'state__title', text: t('error.title') }),
      el('p', { class: 'state__text', text: info.message || t('error.network') }),
      info.detail ? el('p', { class: 'state__detail', text: info.detail }) : null,
      el('div', { class: 'actions' }, [retry])
    ]);
  }

  /* ── generic report pieces ────────────────────────────────────────── */

  function verdictBanner(verdict, subKey) {
    var known = ['pass', 'fail', 'inconclusive'].indexOf(verdict) !== -1 ? verdict : 'inconclusive';
    var iconId = known === 'pass' ? 'i-pass' : known === 'fail' ? 'i-fail' : 'i-inconclusive';
    return el('div', { class: 'verdict verdict--' + known }, [
      svgIcon(iconId, 'icon verdict__icon'),
      el('div', { class: 'verdict__text' }, [
        el('strong', { class: 'verdict__word', text: t('verdict.' + known) }),
        el('span', { class: 'verdict__sub', text: t(subKey || ('verdict.' + known + '.sub')) })
      ])
    ]);
  }

  function kvRow(key, valueNode, mono) {
    return el('div', { class: 'kv__row' }, [
      el('span', { class: 'kv__key', text: key }),
      typeof valueNode === 'string'
        ? el('span', { class: 'kv__val' + (mono ? ' kv__val--mono' : ''), text: valueNode })
        : valueNode
    ]);
  }

  function hashRow(value) {
    var button = el('button', {
      type: 'button',
      class: 'copybtn',
      onclick: function () { copyText(value, button); }
    }, [
      svgIcon('i-copy'),
      el('span', { class: 'copybtn__label', text: t('copy') })
    ]);
    return el('div', { class: 'kv__val hashrow' }, [
      el('code', { class: 'hash', text: value }),
      button
    ]);
  }

  function hashBlock(labelKey, value) {
    return el('div', { class: 'kv__row' }, [
      el('span', { class: 'kv__key', text: t(labelKey) }),
      hashRow(value)
    ]);
  }

  /**
   * `head` accepts either a string title or an array of nodes, so a card can
   * carry a count, a badge and a question line without three variants.
   */
  function card(titleKey, countNode, bodyNode, flush, extraClass) {
    var title = el('div', { class: 'card__titlewrap' }, [
      el('h2', { class: 'card__title', text: t(titleKey) })
    ]);
    var count = countNode === null || countNode === undefined ? null
      : (typeof countNode === 'string' ? el('span', { class: 'card__count', text: countNode }) : countNode);
    return el('section', { class: 'card' + (extraClass ? ' ' + extraClass : '') }, [
      el('div', { class: 'card__head' }, [title, count]),
      el('div', { class: 'card__body' + (flush ? ' card__body--flush' : '') }, [bodyNode])
    ]);
  }

  function severityChip(severity) {
    var known = Object.prototype.hasOwnProperty.call(SEVERITY_RANK, severity) ? severity : 'info';
    return el('span', { class: 'sev sev--' + known, text: severity || 'info' });
  }

  function summaryCard(report) {
    var confidence = report.format_confidence || 'unknown';
    var confidenceText = t('confidence.label', {
      value: I18N.en['confidence.' + confidence] ? t('confidence.' + confidence) : confidence
    });
    var fullyRead = report.metadata && report.metadata.fully_read;

    var rows = [
      kvRow(t('summary.size'), bytes(report.size_bytes)),
      kvRow(t('summary.format'), el('span', { class: 'kv__val stack' }, [
        el('span', {}, [el('span', { class: 'badge badge--mono', text: report.detected_format || t('value.unknown') })]),
        el('span', { class: 'field__help', text: confidenceText })
      ])),
      kvRow(t('summary.severity'), report.max_severity
        ? el('span', { class: 'kv__val' }, [severityChip(report.max_severity)])
        : t('severity.none')),
      kvRow(t('summary.read'), fullyRead === undefined
        ? t('value.unknown')
        : (fullyRead ? t('read.full') : t('read.partial')))
    ];

    return card('summary.title', null, el('div', { class: 'stackrows' }, [
      kvRow(t('summary.file'), report.path || t('value.unknown'), true),
      el('div', { class: 'kv' }, rows),
      hashBlock('summary.sha256', report.sha256 || '')
    ]));
  }

  function findingNode(finding) {
    var described = ruleText(finding.rule_id);
    var severity = Object.prototype.hasOwnProperty.call(SEVERITY_RANK, finding.severity)
      ? finding.severity : 'info';
    var head = el('div', { class: 'finding__head' }, [
      severityChip(finding.severity),
      el('code', { class: 'finding__rule', text: finding.rule_id || '?' })
    ]);

    // No catalogue entry must never mean an empty line: the raw rule id is
    // the fallback, because a finding you cannot name is still a finding.
    var children = [head];
    children.push(el('p', {
      class: 'finding__text' + (described ? '' : ' finding__untranslated'),
      text: described || ((finding.rule_id || '?') + ', ' + t('findings.untranslated'))
    }));
    if (finding.location) {
      children.push(el('p', { class: 'finding__loc', text: t('findings.location') + ' ' + finding.location }));
    }
    var evidence = finding.evidence;
    if (evidence && typeof evidence === 'object' && Object.keys(evidence).length) {
      children.push(el('details', { class: 'evidence' }, [
        el('summary', { text: t('findings.evidence') }),
        el('pre', { class: 'code' }, [
          el('code', { text: JSON.stringify(evidence, null, 2) })
        ])
      ]));
    }
    return el('li', { class: 'finding finding--' + severity }, children);
  }

  function findingsCard(report) {
    var findings = Array.isArray(report.findings) ? report.findings.slice() : [];
    if (!findings.length) {
      return card('findings.title', null, el('p', { class: 'callables__note', text: t('findings.none') }));
    }
    findings.sort(function (a, b) {
      var left = SEVERITY_RANK[b.severity] === undefined ? -1 : SEVERITY_RANK[b.severity];
      var right = SEVERITY_RANK[a.severity] === undefined ? -1 : SEVERITY_RANK[a.severity];
      if (left !== right) { return left - right; }
      return String(a.rule_id).localeCompare(String(b.rule_id));
    });
    var list = el('ul', { class: 'findings' }, findings.map(findingNode));
    return card('findings.title', String(findings.length), list, true);
  }

  /** What the policy said about each resolved import.
   *  A symbol seen denied once stays denied, whatever a later step says.
   *
   *  Two sources, and the second is not a nicety. The trace disassembles the
   *  OUTER stream, so an import that happens inside a pickle handed to a
   *  nested loader has no step here at all: `posix.system` reached the chip
   *  row with no judgement and rendered neutral grey, which is the worst
   *  possible colour for the most dangerous symbol in the artifact. The
   *  findings cover every stream, nested ones included, so they are read
   *  first and the trace fills in what they do not name. */
  var FINDING_JUDGEMENT = {
    'ACT-PKL-002': 'denied',
    'ACT-PKL-007': 'denied',
    // Not ACT-PKL-011. That rule says a callable was handed bytes that were
    // disassembled as a pickle of their own; the wrapper itself is judged by
    // the policy, which reports it as ACT-PKL-001 when it is off the
    // allowlist. Colouring it denied here would overstate the finding and
    // make the chip disagree with the severity next to the same name above.
    'ACT-PKL-001': 'unknown'
  };

  function importJudgements() {
    var map = {};
    var report = state.data.inspect;
    var findings = (report && report.findings) || [];
    findings.forEach(function (finding) {
      var judgement = FINDING_JUDGEMENT[finding.rule_id];
      var name = finding.evidence && finding.evidence.callable;
      if (!judgement || !name) { return; }
      if (map[name] === 'denied') { return; }
      map[name] = judgement;
    });
    var trace = state.trace.inspect;
    if (!trace || trace.status !== 'done' || !trace.payload || !trace.payload.available) { return map; }
    var steps = (trace.payload.disassembly && trace.payload.disassembly.steps) || [];
    steps.forEach(function (step) {
      if (step.kind !== 'import' || !step.resolved || !step.judgement) { return; }
      if (map[step.resolved] === 'denied') { return; }
      map[step.resolved] = step.judgement;
    });
    return map;
  }

  function callablesCard(report) {
    var callables = Array.isArray(report.imported_callables) ? report.imported_callables : [];
    if (!callables.length) { return null; }
    var judged = importJudgements();
    var body = el('div', { class: 'callables' }, [
      el('p', { class: 'callables__note', text: t('callables.note') }),
      el('div', { class: 'callable-list' }, callables.map(function (name) {
        var judgement = judged[name];
        var chip = el('code', {
          class: 'callable callable--' + (judgement || 'plain'),
          text: name
        });
        if (judgement) { chip.setAttribute('title', t('judge.' + judgement)); }
        return chip;
      }))
    ]);
    return card('callables.title', String(callables.length), body);
  }

  function tensorsCard(report) {
    var tensors = Array.isArray(report.tensors) ? report.tensors : [];
    if (!tensors.length) { return null; }

    var total = tensors.reduce(function (sum, tensor) {
      return sum + (typeof tensor.n_elements === 'number' ? tensor.n_elements : 0);
    }, 0);

    var shown = tensors.slice(0, MAX_TENSOR_ROWS);
    var head = el('thead', {}, [
      el('tr', {}, [
        el('th', { scope: 'col', text: t('tensors.name') }),
        el('th', { scope: 'col', text: t('tensors.dtype') }),
        el('th', { scope: 'col', text: t('tensors.shape') }),
        el('th', { scope: 'col', class: 'col-num', text: t('tensors.elements') })
      ])
    ]);
    // `data-label` on every cell is what lets the stylesheet stack these rows
    // into cards below 560px without a second markup path. Four columns do not
    // fit a phone: the last one was clipped mid-number, so a tensor of 65 536
    // elements read as "65.5" with no scrollbar and nothing saying otherwise -
    // a truncated number that still looks like a number is worse than a
    // truncated label. The header text is the label, so it stays translated.
    var body = el('tbody', {}, shown.map(function (tensor) {
      var shape = Array.isArray(tensor.shape) ? '[' + tensor.shape.join(' × ') + ']' : t('value.unknown');
      return el('tr', {}, [
        el('td', { class: 'col-name', 'data-label': t('tensors.name'),
                   text: tensor.name === undefined ? '' : String(tensor.name) }),
        el('td', { class: 'col-mono', 'data-label': t('tensors.dtype'),
                   text: tensor.dtype === undefined ? t('value.unknown') : String(tensor.dtype) }),
        el('td', { class: 'col-mono', 'data-label': t('tensors.shape'), text: shape }),
        el('td', { class: 'col-num', 'data-label': t('tensors.elements'),
                   text: typeof tensor.n_elements === 'number' ? num(tensor.n_elements) : t('value.unknown') })
      ]);
    }));

    var wrap = el('div', { class: 'tablewrap tablewrap--stacks' }, [
      el('table', { class: 'table table--stacks' }, [head, body])
    ]);
    var children = [wrap];
    if (tensors.length > shown.length) {
      children.push(el('p', {
        class: 'table__more',
        text: t('tensors.truncated', { shown: num(shown.length), total: num(tensors.length) })
      }));
    }
    var count = t('tensors.summary', { count: num(tensors.length), total: num(total) });
    return card('tensors.title', count, el('div', {}, children), true);
  }

  function metadataCard(report) {
    var metadata = report.metadata;
    if (!metadata || typeof metadata !== 'object' || !Object.keys(metadata).length) { return null; }
    var body = el('div', { class: 'callables' }, [
      el('p', { class: 'callables__note', text: t('metadata.note') }),
      el('pre', { class: 'code' }, [el('code', { text: JSON.stringify(metadata, null, 2) })])
    ]);
    return card('metadata.title', null, body);
  }

  function inspectorErrorsCard(report) {
    var errors = Array.isArray(report.inspector_errors) ? report.inspector_errors : [];
    if (!errors.length) { return null; }
    var body = el('div', { class: 'notes' }, [el('p', { class: 'callables__note', text: t('inspector.note') })].concat(
      errors.map(function (message) {
        return el('div', { class: 'note note--bad' }, [
          svgIcon('i-alert'),
          el('span', { text: message })
        ]);
      })
    ));
    return card('inspector.title', String(errors.length), body);
  }

  /* ── opcode trace ─────────────────────────────────────────────────────
   *
   * The component that shows the mechanism. It renders the disassembly the
   * backend produced from the same abstract interpretation the scanner runs,
   * so it can never disagree with the verdict printed above it.
   */

  function judgementTag(step) {
    if (step.kind === 'import') {
      var judgement = step.judgement || 'unresolved';
      return el('span', { class: 'jm jm--' + judgement, text: t('judge.' + judgement) });
    }
    if (step.kind === 'execute') { return el('span', { class: 'jm jm--execute', text: t('tag.execute') }); }
    if (step.kind === 'extension') { return el('span', { class: 'jm jm--extension', text: t('tag.extension') }); }
    if (step.kind === 'persid') { return el('span', { class: 'jm jm--persid', text: t('tag.persid') }); }
    return null;
  }

  function stepRow(step, offsetWidth, isContext) {
    var classes = ['step', 'step--' + (step.kind || 'data')];
    if (step.kind === 'import' && step.judgement) { classes.push('step--' + step.judgement); }
    if (isContext) { classes.push('step--context'); }

    var argText = step.kind === 'import' && step.resolved ? step.resolved : (step.arg === null || step.arg === undefined ? '' : String(step.arg));
    var argCell = el('td', { class: 'step__arg', text: argText });
    if (argText) { argCell.setAttribute('title', argText); }

    return el('tr', { class: classes.join(' ') }, [
      el('td', { class: 'step__mark' }, [el('span', { class: 'step__glyph' })]),
      el('td', { class: 'step__off', text: pad(step.offset, offsetWidth) }),
      el('td', { class: 'step__op', text: step.opcode || '' }),
      argCell,
      el('td', { class: 'step__tag' }, [judgementTag(step)])
    ]);
  }

  function gapRow(count) {
    return el('tr', { class: 'step step--gap' }, [
      el('td', { colspan: '5', text: '· · ·  ' + t('trace.gap', { n: num(count) }) })
    ]);
  }

  /**
   * Which steps a reader actually needs. Anything that is not plain data is
   * kept, and so are the two steps before an import, because with
   * STACK_GLOBAL the module and the attribute are pushed by the steps just
   * before it: hiding them would hide where `posix.system` came from.
   */
  function relevanceMap(steps) {
    var keep = {};
    steps.forEach(function (step, index) {
      if (step.kind === 'data') { return; }
      keep[index] = 'main';
      if (step.kind !== 'import') { return; }
      for (var back = 1; back <= CONTEXT_STEPS; back += 1) {
        var target = index - back;
        if (target >= 0 && !keep[target]) { keep[target] = 'context'; }
      }
    });
    return keep;
  }

  function traceTable(steps, filtered) {
    var maxOffset = steps.reduce(function (top, step) {
      return Math.max(top, typeof step.offset === 'number' ? step.offset : 0);
    }, 0);
    var width = Math.max(4, String(maxOffset).length);
    var keep = filtered ? relevanceMap(steps) : null;

    var body = el('tbody', {});
    var pending = 0;
    var hidden = 0;
    steps.forEach(function (step, index) {
      if (keep && !keep[index]) { pending += 1; hidden += 1; return; }
      if (pending) { body.appendChild(gapRow(pending)); pending = 0; }
      body.appendChild(stepRow(step, width, keep && keep[index] === 'context'));
    });
    if (pending) { body.appendChild(gapRow(pending)); }

    var table = el('table', { class: 'trace' }, [
      el('thead', {}, [
        el('tr', {}, [
          el('th', { scope: 'col' }, [el('span', { class: 'visually-hidden', text: t('trace.col.kind') })]),
          el('th', { scope: 'col', text: t('trace.col.offset') }),
          el('th', { scope: 'col', text: t('trace.col.opcode') }),
          el('th', { scope: 'col', text: t('trace.col.arg') }),
          el('th', { scope: 'col', text: t('trace.col.verdict') })
        ])
      ]),
      body
    ]);
    return { node: el('div', { class: 'tracewrap' }, [table]), hidden: hidden };
  }

  function kindSummary(counts, total) {
    var bar = el('div', { class: 'kindbar' });
    KIND_ORDER.forEach(function (kind) {
      var value = counts[kind] || 0;
      if (!value) { return; }
      var seg = el('div', { class: 'kindbar__seg kindbar__seg--' + kind });
      seg.style.setProperty('--w', String(value));
      bar.appendChild(seg);
    });
    if (!bar.firstChild) {
      var filler = el('div', { class: 'kindbar__seg kindbar__seg--data' });
      filler.style.setProperty('--w', '1');
      bar.appendChild(filler);
    }

    var chips = el('div', { class: 'kindchips' }, KIND_ORDER.filter(function (kind) {
      return (counts[kind] || 0) > 0 || kind === 'import' || kind === 'execute';
    }).map(function (kind) {
      return el('span', { class: 'kindchip kindchip--' + kind }, [
        el('span', { class: 'kindchip__glyph' }),
        document.createTextNode(t('kind.' + kind) + ' '),
        el('span', { class: 'kindchip__count', text: num(counts[kind] || 0) })
      ]);
    }));

    return el('div', { class: 'trace__summary' }, [
      bar,
      chips,
      total ? el('p', { class: 'callables__note', text: t('trace.note') }) : null
    ]);
  }

  function traceControls(hidden, onFilter) {
    var group = el('div', { class: 'toggle', role: 'group', 'aria-label': t('trace.filter.aria') });
    [['relevant', 'trace.filter.relevant'], ['all', 'trace.filter.all']].forEach(function (pair) {
      var active = state.traceFilter === pair[0];
      var button = el('button', {
        type: 'button',
        class: 'toggle__btn',
        'aria-pressed': active ? 'true' : 'false',
        text: t(pair[1]),
        onclick: function () {
          if (state.traceFilter === pair[0]) { return; }
          state.traceFilter = pair[0];
          store('actaira.trace_filter', pair[0]);
          onFilter();
        }
      });
      group.appendChild(button);
    });
    return el('div', { class: 'trace__controls' }, [
      group,
      el('span', {
        class: 'trace__hidden',
        text: hidden ? t('trace.hidden', { n: num(hidden) }) : t('trace.hidden.none')
      })
    ]);
  }

  function traceCard(payload, onFilter) {
    var source = payload.source || {};

    if (!payload.available) {
      var reason = 'trace.unavailable.' + (payload.reason || 'not_a_pickle');
      var text = I18N.en[reason] ? t(reason) : t('trace.unavailable.not_a_pickle');
      return card('trace.title', null, el('p', { class: 'callables__note', text: text }));
    }

    var data = payload.disassembly || {};
    var steps = Array.isArray(data.steps) ? data.steps : [];
    var counts = data.counts || {};

    var meta = [];
    if (typeof data.protocol === 'number') { meta.push(t('trace.protocol', { n: data.protocol })); }
    meta.push(t('trace.opcodes', { n: num(data.total_opcodes || steps.length) }));
    var countNode = el('span', { class: 'card__count', text: meta.join(' · ') });

    var built = traceTable(steps, state.traceFilter === 'relevant');

    var body = el('div', {}, [
      kindSummary(counts, steps.length),
      traceControls(built.hidden, onFilter),
      built.node
    ]);

    var foots = [];
    if (source.member) {
      foots.push(t('trace.member') + ' ' + source.member);
    }
    if (steps.length < (data.total_opcodes || 0)) {
      foots.push(t('trace.limited', { shown: num(steps.length), total: num(data.total_opcodes) }));
    }
    if (data.parse_error) {
      foots.push(t('trace.truncated', { error: data.parse_error }));
    }
    if (foots.length) {
      body.appendChild(el('p', { class: 'trace__foot', text: foots.join(' · ') }));
    }

    return card('trace.title', countNode, body, true, 'card--trace');
  }

  function traceLoadingCard() {
    return card('trace.title', null, el('p', { class: 'callables__note', text: t('trace.loading') }));
  }

  function traceErrorCard() {
    return card('trace.title', null, el('div', { class: 'note note--warn' }, [
      svgIcon('i-alert'), el('span', { text: t('trace.error') })
    ]));
  }

  /* the same component, used as the worked example on the welcome screen */
  function renderDemo() {
    var figure = document.getElementById('demo-trace');
    if (!figure) { return; }
    clear(figure);
    figure.appendChild(el('div', { class: 'demo__head' }, [
      svgIcon('i-trace'),
      el('span', { class: 'card__title', text: t('demo.title') }),
      el('span', { class: 'badge badge--mono', text: t('demo.badge') }),
      el('span', { class: 'card__count', text: 'gadget_known_posix_system_p4.pkl' })
    ]));
    figure.appendChild(traceTable(DEMO_STEPS, false).node);
    figure.appendChild(el('figcaption', { class: 'demo__caption', text: t('demo.caption') }));
  }

  /* ── samples ──────────────────────────────────────────────────────── */

  function renderSamples() {
    var wrap = document.getElementById('samples-inspect');
    var grid = document.getElementById('samples-grid-inspect');
    if (!wrap || !grid) { return; }
    clear(grid);
    if (!state.samples.length) { wrap.hidden = true; return; }
    state.samples.forEach(function (sample) {
      var noteKey = 'sample.' + sample.slug + '.note';
      grid.appendChild(el('button', {
        type: 'button',
        class: 'sample sample--' + (sample.kind === 'danger' ? 'danger' : 'clean'),
        onclick: function () { runSample(sample); }
      }, [
        el('span', { class: 'sample__glyph' }),
        el('span', { class: 'sample__name', text: sample.name }),
        el('span', { class: 'sample__note', text: I18N.en[noteKey] ? t(noteKey) : '' }),
        el('span', { class: 'sample__size', text: bytes(sample.size_bytes) })
      ]));
    });
    updatePanelChrome('inspect');
  }

  function loadSamples() {
    getJson('/api/samples', function (payload) {
      state.samples = (payload && Array.isArray(payload.samples)) ? payload.samples : [];
      renderSamples();
    }, function () {
      state.samples = [];
      renderSamples();
    });
  }

  /* ── governance, the fourth section ───────────────────────────────────
   *
   * The EU AI Act mapping. Three rules hold here on top of the three at the
   * top of this file:
   *
   *   1. Nothing on screen is an aggregate. There is no percentage, no
   *      grade and no traffic light over the set of obligations, because
   *      none exists in the backend either. The count line says it is a
   *      count, and the notice at the top of the panel says the whole thing
   *      is not a compliance opinion, in whichever language is selected.
   *   2. What Actaira provides and what it does not are rendered by the
   *      same component, at the same size, side by side. Neither can be
   *      collapsed away while the other stays open, because a reader who
   *      only sees the left column has been misled.
   *   3. Whether an obligation binds a role, and what state it is in with
   *      no evidence, are computed by the backend and read from the
   *      response. This file carries no rule about who is bound by what:
   *      a second copy of that rule in JavaScript would eventually
   *      disagree with the Python one, and the wrong copy would be the one
   *      on screen.
   */

  var GOV_ROLES = ['provider', 'provider_gpai', 'deployer', 'any'];

  /* Obligation state -> the card modifier that carries its tone and shape.
   * The four states the stylesheet was designed around, plus one dim state
   * for an obligation whose date has not arrived. */
  var GOV_TONE = {
    evidence_supports: 'mapped',
    evidence_partial: 'partial',
    no_evidence_supplied: 'pending',
    outside_this_tool: 'gap',
    not_yet_applicable: 'future'
  };

  function govDate(iso) {
    var parts = String(iso || '').split('-');
    if (parts.length !== 3) { return String(iso || ''); }
    var when = new Date(Date.UTC(Number(parts[0]), Number(parts[1]) - 1, Number(parts[2])));
    try {
      return new Intl.DateTimeFormat(state.lang, {
        day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC'
      }).format(when);
    } catch (err) { return String(iso); }
  }

  /**
   * The obligation's prose, from the catalogue the app already loads for
   * rule descriptions. The row from the API carries the same text and is
   * the fallback, so a catalogue that failed to load degrades to whatever
   * language the response was fetched in rather than to blank cards.
   */
  var GOV_TEXT_LISTS = ['evidence_expected', 'actaira_provides', 'actaira_does_not_provide'];

  function obligationText(row) {
    var fromCatalog = state.obligations[row.id] || {};
    var text = {};
    ['title', 'summary', 'note', 'grace_scope'].forEach(function (key) {
      var value = fromCatalog[key] !== undefined ? fromCatalog[key] : row[key];
      text[key] = (typeof value === 'string') ? value : '';
    });
    GOV_TEXT_LISTS.forEach(function (key) {
      var value = fromCatalog[key] !== undefined ? fromCatalog[key] : row[key];
      text[key] = Array.isArray(value) ? value : [];
    });
    return text;
  }

  function govRows() {
    if (state.data.govern && Array.isArray(state.data.govern.obligations)) {
      return state.data.govern.obligations;
    }
    if (state.gov.clock && Array.isArray(state.gov.clock.obligations)) {
      return state.gov.clock.obligations.filter(function (row) { return row.binds; });
    }
    return [];
  }

  /* ── the notice, and the controls ─────────────────────────────────── */

  function govHero() {
    return el('div', { class: 'gov__hero' }, [
      svgIcon('i-scale', 'icon gov__icon'),
      el('h1', { class: 'gov__title', text: t('gov.title') }),
      el('p', { class: 'gov__text', text: t('gov.lede') }),
      el('div', { class: 'gov__notice', role: 'note' }, [
        svgIcon('i-alert', 'icon gov__notice-icon'),
        el('div', { class: 'gov__notice-body' }, [
          el('strong', { class: 'gov__notice-title', text: t('gov.notice.title') }),
          el('p', { class: 'gov__notice-text', text: t('gov.notice.text') })
        ])
      ])
    ]);
  }

  function govControls() {
    var dateInput = el('input', {
      type: 'date', class: 'field__control', id: 'gov-date',
      value: state.gov.on || (state.gov.clock ? state.gov.clock.today : '')
    });
    dateInput.addEventListener('change', function () {
      if (!dateInput.value) { return; }
      state.gov.on = dateInput.value;
      store('actaira.gov_on', state.gov.on);
      refreshGovernance();
    });

    var roleSelect = el('select', { class: 'field__control', id: 'gov-role' },
      GOV_ROLES.map(function (role) {
        return el('option', {
          value: role,
          text: t('gov.role.' + role),
          selected: role === state.gov.role
        });
      }));
    roleSelect.addEventListener('change', function () {
      state.gov.role = roleSelect.value;
      store('actaira.gov_role', state.gov.role);
      refreshGovernance();
    });

    return el('section', { class: 'gov__section' }, [
      el('div', { class: 'gov__sectionhead' }, [
        el('span', { class: 'gov__label', text: t('gov.controls.label') })
      ]),
      el('div', { class: 'gov__controls' }, [
        el('p', { class: 'field' }, [
          el('label', { class: 'field__label', for: 'gov-date', text: t('gov.controls.date') }),
          dateInput,
          el('span', { class: 'field__help', text: t('gov.controls.date.help') })
        ]),
        el('p', { class: 'field' }, [
          el('label', { class: 'field__label', for: 'gov-role', text: t('gov.controls.role') }),
          roleSelect,
          el('span', { class: 'field__help', text: t('gov.controls.role.help') })
        ])
      ])
    ]);
  }

  /* ── timeline of application dates ────────────────────────────────── */

  function govTimeline() {
    var clock = state.gov.clock;
    var groups = {};
    clock.obligations.forEach(function (row) {
      if (!groups[row.applies_from]) { groups[row.applies_from] = []; }
      groups[row.applies_from].push(row);
    });

    /* Today, and the date being evaluated when it is not today. A marker
     * that lands on an application date joins that node rather than
     * standing next to it: two nodes carrying the same date read as two
     * deadlines, which is the one misreading this row cannot afford. */
    var markers = {};
    markers[clock.today] = ['today'];
    if (clock.on !== clock.today) {
      if (!markers[clock.on]) { markers[clock.on] = []; }
      markers[clock.on].push('viewing');
    }

    var days = [];
    Object.keys(groups).concat(Object.keys(markers)).forEach(function (day) {
      if (days.indexOf(day) === -1) { days.push(day); }
    });
    days.sort();

    var nextDay = null;
    Object.keys(groups).sort().forEach(function (day) {
      if (nextDay === null && day > clock.on) { nextDay = day; }
    });

    var nodes = days.map(function (day) {
      var group = groups[day] || null;
      var marks = markers[day] || [];
      var tone = null;
      if (group) { tone = day <= clock.on ? 'past' : (day === nextDay ? 'next' : null); }

      var tags = [];
      if (tone) { tags.push(el('span', { class: 'tl__tag', text: t('gov.t.' + tone) })); }
      marks.forEach(function (mark) {
        tags.push(el('span', { class: 'tl__tag tl__tag--now', text: t('gov.timeline.' + mark) }));
      });
      if (group && group.some(function (row) { return row.status === 'provisional'; })) {
        tags.push(el('span', { class: 'tl__tag tl__tag--prov', text: t('gov.t.provisional') }));
      }

      var title = group
        ? t('gov.timeline.count', { n: num(group.length) })
        : t('gov.timeline.' + marks[0]);
      var detail = group
        ? group.map(function (row) { return row.article; }).join(' · ')
        : t('gov.timeline.' + marks[0] + '.text');

      return el('div', { class: 'tl' + (tone ? ' tl--' + tone : '') + (marks.length ? ' tl--now' : '') }, [
        el('span', { class: 'tl__date', text: govDate(day) }),
        el('span', { class: 'tl__title', text: title }),
        el('span', { class: 'tl__text', text: detail }),
        tags.length ? el('span', { class: 'tl__tags' }, tags) : null
      ]);
    });

    var section = el('section', { class: 'gov__section' }, [
      el('div', { class: 'gov__sectionhead' }, [
        el('span', { class: 'gov__label', text: t('gov.timeline.label') }),
        el('span', { class: 'gov__note', text: t('gov.timeline.note') })
      ]),
      el('div', { class: 'timeline' }, nodes)
    ]);

    if (clock.provisional_notice) {
      section.appendChild(el('div', { class: 'note note--warn' }, [
        svgIcon('i-alert'),
        el('span', { text: String(clock.provisional_notice).replace(/\s*\n\s*/g, ' ') })
      ]));
    }
    return section;
  }

  /* ── the artifact, and the dropzone that supplies it ──────────────── */

  function govDropzone() {
    var zone = el('div', { class: 'dropzone', id: 'dz-govern', 'data-target': 'govern' }, [
      svgIcon('i-upload', 'icon dropzone__icon'),
      el('p', { class: 'dropzone__title', text: t('gov.drop.title') }),
      el('p', { class: 'dropzone__hint', text: t('drop.hint') }),
      el('input', { type: 'file', id: 'file-govern', class: 'visually-hidden', tabindex: '-1' }),
      el('button', { type: 'button', class: 'btn btn--primary', text: t('gov.drop.choose') }),
      el('p', { class: 'dropzone__formats', text: t('gov.drop.formats') })
    ]);
    return zone;
  }

  function govArtifact() {
    var payload = state.data.govern;
    var artifact = payload.artifact || {};
    var unread = Array.isArray(payload.artifacts_not_fully_read) && payload.artifacts_not_fully_read.length;

    var clear = el('button', {
      type: 'button', class: 'btn btn--ghost',
      onclick: function () {
        state.data.govern = null;
        state.files.govern = null;
        state.error.govern = null;
        renderGovern();
      }
    }, [svgIcon('i-cross'), document.createTextNode(t('gov.artifact.clear'))]);

    var head = el('div', { class: 'gov__artifacthead' }, [
      svgIcon('i-file'),
      el('span', { class: 'gov__artifactname', text: artifact.name || '' }),
      el('span', { class: 'badge badge--mono', text: artifact.format || '' }),
      el('span', {
        class: 'badge badge--verdict badge--' + (artifact.verdict || 'inconclusive'),
        text: t('verdict.' + (artifact.verdict || 'inconclusive'))
      }),
      clear
    ]);

    var block = el('div', { class: 'gov__artifact' }, [
      el('div', { class: 'gov__sectionhead' }, [
        el('span', { class: 'gov__label', text: t('gov.artifact.label') })
      ]),
      head,
      artifact.sha256 ? el('div', { class: 'kv' }, [hashBlock('summary.sha256', artifact.sha256)]) : null
    ]);

    if (unread) {
      block.appendChild(el('div', { class: 'note note--bad' }, [
        svgIcon('i-alert'),
        el('div', {}, [
          el('strong', { text: t('gov.unread.title') }),
          document.createTextNode(' '),
          el('span', { text: t('gov.unread.text') })
        ])
      ]));
    }
    return block;
  }

  /* ── obligation cards ─────────────────────────────────────────────── */

  function govList(labelKey, lines, tone, emptyKey) {
    var items = lines.length
      ? lines.map(function (line) {
          return el('li', { class: 'oblig__item' }, [
            svgIcon(tone === 'yes' ? 'i-check' : 'i-cross', 'icon oblig__bullet'),
            el('span', { text: line })
          ]);
        })
      : [el('li', { class: 'oblig__item oblig__item--empty' }, [
          svgIcon(tone === 'yes' ? 'i-cross' : 'i-check', 'icon oblig__bullet'),
          el('span', { text: t(emptyKey) })
        ])];
    return el('div', { class: 'oblig__block oblig__block--' + tone }, [
      el('h4', { class: 'oblig__blockhead', text: t(labelKey) }),
      el('ul', { class: 'oblig__list' }, items)
    ]);
  }

  function govEvidence(row) {
    var evidence = Array.isArray(row.evidence) ? row.evidence : [];
    if (!evidence.length) {
      return el('p', { class: 'oblig__meta', text: t('gov.detail.evidence.none') });
    }
    return el('ul', { class: 'oblig__list' }, evidence.map(function (item) {
      return el('li', { class: 'oblig__item' }, [
        svgIcon('i-chain', 'icon oblig__bullet'),
        el('span', { class: 'oblig__ev' }, [
          el('code', { text: item.kind }),
          document.createTextNode(' · '),
          /* Name the file, not only the digest: a reader who cannot tell which
             artifact an evidence line came from cannot check it. */
          el('span', { text: (item.detail && item.detail.path) ? item.detail.path + ' · ' : '' }),
          el('code', { text: shortHash(item.subject, 16) })
        ])
      ]);
    }));
  }

  function obligationCard(row) {
    var stateKey = row.state || 'no_evidence_supplied';
    var tone = GOV_TONE[stateKey] || 'pending';
    var text = obligationText(row);
    var open = !!state.gov.open[row.id];

    var detail = el('div', { class: 'oblig__detail', id: 'oblig-detail-' + row.id }, [
      el('div', { class: 'oblig__block oblig__block--asks' }, [
        el('h4', { class: 'oblig__blockhead', text: t('gov.detail.expects') }),
        el('ul', { class: 'oblig__list' }, text.evidence_expected.map(function (line) {
          return el('li', { class: 'oblig__item' }, [
            svgIcon('i-docs', 'icon oblig__bullet'),
            el('span', { text: line })
          ]);
        }))
      ]),
      /* The two halves, same component, same size, always both rendered. */
      el('div', { class: 'oblig__pair' }, [
        /* The catalogue says what this tool CAN show. Printing that under
           "provides" on an obligation nothing was supplied for turns a
           capability into a claim, so the heading goes conditional and the
           evidence block below says, in the same card, that none arrived. */
        govList(
          stateKey === 'no_evidence_supplied' ? 'gov.detail.would_provide' : 'gov.detail.provides',
          text.actaira_provides, 'yes', 'gov.detail.nothing'
        ),
        govList('gov.detail.not_provides', text.actaira_does_not_provide, 'no', 'gov.detail.nothing')
      ]),
      el('div', { class: 'oblig__block oblig__block--ev' }, [
        el('h4', { class: 'oblig__blockhead', text: t('gov.detail.evidence') }),
        govEvidence(row)
      ]),
      el('dl', { class: 'oblig__meta' }, [
        el('dt', { text: t('gov.detail.applies') }),
        el('dd', { text: govDate(row.applies_from) + (row.days_until ? ' · ' + t('gov.detail.days', { n: num(row.days_until) }) : '') }),
        row.grace_until ? el('dt', { text: t('gov.detail.grace', { until: govDate(row.grace_until) }) }) : null,
        row.grace_until ? el('dd', { text: text.grace_scope || '' }) : null,
        el('dt', { text: t('gov.detail.citation') }),
        el('dd', { class: 'oblig__cite', text: row.citation || '' }),
        text.note ? el('dt', { text: t('gov.detail.note') }) : null,
        text.note ? el('dd', { text: text.note }) : null
      ])
    ]);
    detail.hidden = !open;

    var toggle = el('button', {
      type: 'button',
      class: 'oblig__toggle',
      'aria-expanded': open ? 'true' : 'false',
      'aria-controls': 'oblig-detail-' + row.id
    }, [
      svgIcon('i-arrow', 'icon oblig__chevron'),
      el('span', { text: t('gov.detail.open') })
    ]);
    var badges = [el('span', { class: 'ostat', text: t('gov.state.' + stateKey) })];
    if (row.in_grace_period) {
      badges.push(el('span', { class: 'badge badge--mono', text: t('gov.badge.grace') }));
    }
    if (row.status === 'provisional') {
      badges.push(el('span', { class: 'badge badge--mono badge--prov', text: t('gov.badge.provisional') }));
    }

    var card = el('article', { class: 'oblig oblig--' + tone + (open ? ' oblig--open' : '') }, [
      el('div', { class: 'oblig__head' }, [
        el('span', { class: 'oblig__ref', text: row.article }),
        el('span', { class: 'oblig__badges' }, badges)
      ]),
      el('h3', { class: 'oblig__title', text: text.title }),
      el('p', { class: 'oblig__text', text: text.summary }),
      el('div', { class: 'oblig__foot' }, [toggle]),
      detail
    ]);

    /* An open card takes the whole row. The detail is a pair of columns, and
     * a pair of columns inside one grid track is four words wide: unreadable,
     * and unreadable in a way that would quietly discourage anyone from
     * reading the second half, which is the half this module exists for. */
    toggle.addEventListener('click', function () {
      var nowOpen = detail.hidden;
      detail.hidden = !nowOpen;
      toggle.setAttribute('aria-expanded', nowOpen ? 'true' : 'false');
      card.classList.toggle('oblig--open', nowOpen);
      state.gov.open[row.id] = nowOpen;
    });
    return card;
  }

  function govCards() {
    var rows = govRows();
    var payload = state.data.govern;
    var on = govDate(state.gov.clock ? state.gov.clock.on : state.gov.on);
    var outside = rows.filter(function (row) { return row.state === 'outside_this_tool'; }).length;

    var summary;
    if (payload && payload.counts_not_a_score) {
      summary = t('gov.cards.count.assessed', {
        bound: num(rows.length),
        on: on,
        touched: num(payload.counts_not_a_score.with_evidence),
        outside: num(outside)
      });
    } else {
      summary = t('gov.cards.count', { bound: num(rows.length), on: on, outside: num(outside) });
    }

    return el('section', { class: 'gov__section' }, [
      el('div', { class: 'gov__sectionhead' }, [
        el('span', { class: 'gov__label', text: t('gov.cards.label') }),
        el('span', { class: 'gov__note', text: rows.length ? summary : t('gov.cards.none') })
      ]),
      el('div', { class: 'oblig-grid' }, rows.map(obligationCard))
    ]);
  }

  /* ── panel ────────────────────────────────────────────────────────── */

  function renderGovern() {
    var host = document.getElementById('gov-body');
    if (!host) { return; }
    clear(host);

    host.appendChild(govHero());
    host.appendChild(govControls());
    if (state.gov.clock) {
      host.appendChild(govTimeline());
    } else if (state.gov.clockFailed) {
      host.appendChild(el('div', { class: 'note note--bad' }, [
        svgIcon('i-alert'), el('span', { text: t('gov.clock.failed') })
      ]));
    }

    var upload = el('section', { class: 'gov__section' }, [govDropzone()]);
    upload.appendChild(el('div', {
      class: 'results', id: 'out-govern', 'aria-live': 'polite', 'aria-busy': state.busy.govern ? 'true' : 'false'
    }));
    host.appendChild(upload);
    if (state.data.govern) { host.appendChild(govArtifact()); }
    host.appendChild(govCards());

    wireDropzone('govern');
    renderChosen('govern');
    updatePanelChrome('govern');
    if (state.error.govern) { showState('govern', errorState('govern')); }
  }

  /* ── requests ─────────────────────────────────────────────────────── */

  function loadClock() {
    var query = '?on=' + encodeURIComponent(state.gov.on || '') +
                '&lang=' + encodeURIComponent(state.lang) +
                '&role=' + encodeURIComponent(state.gov.role);
    getJson('/api/governance/clock' + query, function (payload) {
      state.gov.clock = payload;
      state.gov.clockFailed = false;
      if (!state.gov.on) { state.gov.on = payload.on; }
      renderGovern();
    }, function () {
      state.gov.clock = null;
      state.gov.clockFailed = true;
      renderGovern();
    });
  }

  /** The date or the role changed: the clock always, the assessment only if
   *  there is an artifact, because re-answering needs the bytes again. */
  function refreshGovernance() {
    loadClock();
    if (state.files.govern) { runGovernance(state.files.govern); }
    else if (state.data.govern) { state.data.govern = null; renderGovern(); }
  }

  function runGovernance(file) {
    state.files.govern = file;
    state.data.govern = null;
    state.error.govern = null;
    state.busy.govern = true;
    renderGovern();
    showState('govern', loadingState('govern', 'gov.loading'));

    upload('/api/governance/assess', file, {
      role: state.gov.role,
      on: state.gov.on || '',
      lang: state.lang,
      policy: 'strict',
      fail_on: 'high'
    }, {
      onProgress: function (fraction) { setProgress('govern', fraction); },
      onUploaded: function () { setIndeterminate('govern'); },
      onDone: function (payload) {
        state.busy.govern = false;
        state.data.govern = payload;
        renderGovern();
      },
      onError: function (info) {
        state.busy.govern = false;
        state.error.govern = info;
        renderGovern();
      }
    });
  }

  /* ── inspect ──────────────────────────────────────────────────────── */

  function scanFields(tab) {
    var policy = document.getElementById('policy-' + tab);
    var failOn = document.getElementById('failon-' + tab);
    return {
      policy: policy ? policy.value : 'strict',
      fail_on: failOn ? failOn.value : 'high'
    };
  }

  function beginInspect() {
    state.data.inspect = null;
    state.trace.inspect = null;
    state.error.inspect = null;
    state.busy.inspect = true;
    renderChosen('inspect');
    updatePanelChrome('inspect');
    outputOf('inspect').setAttribute('aria-busy', 'true');
    showState('inspect', loadingState('inspect', 'loading.inspecting'));
  }

  function inspectHandlers() {
    return {
      onProgress: function (fraction) { setProgress('inspect', fraction); },
      onUploaded: function () { setIndeterminate('inspect'); },
      onDone: function (payload) {
        state.busy.inspect = false;
        var reports = (payload && Array.isArray(payload.reports)) ? payload.reports : [];
        state.data.inspect = reports[0] || null;
        renderInspect();
        requestTrace();
      },
      onError: function (info) {
        state.busy.inspect = false;
        state.error.inspect = info;
        renderInspect();
      }
    };
  }

  function runInspect(file) {
    state.files.inspect = file;
    state.sample.inspect = null;
    beginInspect();
    upload('/api/scan', file, scanFields('inspect'), inspectHandlers());
  }

  function runSample(sample) {
    state.files.inspect = null;
    state.sample.inspect = sample;
    beginInspect();
    var fields = scanFields('inspect');
    postJson('/api/scan-sample', {
      sample: sample.name, policy: fields.policy, fail_on: fields.fail_on
    }, inspectHandlers());
  }

  /** The disassembly is a second, cheap request, so a slow walk of a big
   *  opcode stream never delays the verdict the reader is waiting for. */
  function requestTrace() {
    var report = state.data.inspect;
    if (!report || TRACE_FORMATS.indexOf(report.detected_format) === -1) {
      state.trace.inspect = null;
      renderInspect();
      return;
    }
    state.trace.inspect = { status: 'loading' };
    renderInspect();

    var fields = scanFields('inspect');
    var handlers = {
      onDone: function (payload) {
        state.trace.inspect = { status: 'done', payload: payload };
        renderInspect();
      },
      onError: function () {
        state.trace.inspect = { status: 'error' };
        renderInspect();
      }
    };
    if (state.sample.inspect) {
      postJson('/api/disassemble', { sample: state.sample.inspect.name, policy: fields.policy }, handlers);
    } else if (state.files.inspect) {
      upload('/api/disassemble', state.files.inspect, fields, handlers);
    } else {
      state.trace.inspect = null;
      renderInspect();
    }
  }

  function traceNode() {
    var trace = state.trace.inspect;
    if (!trace) { return null; }
    if (trace.status === 'loading') { return traceLoadingCard(); }
    if (trace.status === 'error') { return traceErrorCard(); }
    return traceCard(trace.payload, function () { renderInspect(); });
  }

  function renderInspect() {
    var out = outputOf('inspect');
    out.setAttribute('aria-busy', state.busy.inspect ? 'true' : 'false');
    updatePanelChrome('inspect');
    if (state.busy.inspect) { return; }
    if (state.error.inspect) { showState('inspect', errorState('inspect')); return; }
    if (!state.data.inspect) { showState('inspect', null); return; }

    var report = state.data.inspect;
    clear(out);
    [
      verdictBanner(report.verdict),
      summaryCard(report),
      findingsCard(report),
      traceNode(),
      callablesCard(report),
      tensorsCard(report),
      inspectorErrorsCard(report),
      metadataCard(report)
    ].forEach(function (node) { if (node) { out.appendChild(node); } });

    var bomButton = el('button', { type: 'button', class: 'btn' }, [
      svgIcon('i-download'),
      document.createTextNode(t('actions.bom'))
    ]);
    bomButton.addEventListener('click', function () { downloadBom(bomButton); });

    out.appendChild(el('div', { class: 'actions' }, [
      bomButton,
      el('button', {
        type: 'button', class: 'btn btn--ghost',
        onclick: function () { rerun('inspect'); }
      }, [svgIcon('i-retry'), document.createTextNode(t('actions.rescan'))])
    ]));
  }

  function downloadBom(button) {
    var fields = scanFields('inspect');
    var base = (state.data.inspect && state.data.inspect.path) || 'artifact';
    var handlers = {
      onDone: function (payload) {
        button.disabled = false;
        var blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        download(blob, base.replace(/\.[^.]*$/, '') + '.cdx.json');
        toast(t('actions.bom_done'));
      },
      onError: function (info) {
        button.disabled = false;
        toast(info.message || t('error.network'));
      }
    };
    button.disabled = true;
    toast(t('actions.bom_working'));
    if (state.sample.inspect) {
      postJson('/api/bom', {
        sample: state.sample.inspect.name, policy: fields.policy, fail_on: fields.fail_on
      }, handlers);
    } else if (state.files.inspect) {
      upload('/api/bom', state.files.inspect, fields, handlers);
    } else {
      button.disabled = false;
      toast(t('error.no_file'));
    }
  }

  /* ── attest ───────────────────────────────────────────────────────── */

  function runAttest(file) {
    state.files.attest = file;
    state.data.attest = null;
    state.error.attest = null;
    state.busy.attest = true;
    renderChosen('attest');
    updatePanelChrome('attest');
    outputOf('attest').setAttribute('aria-busy', 'true');
    showState('attest', loadingState('attest', 'loading.attesting'));

    upload('/api/attest', file, scanFields('attest'), {
      blob: true,
      onProgress: function (fraction) { setProgress('attest', fraction); },
      onUploaded: function () { setIndeterminate('attest'); },
      onDone: function (blob, xhr) {
        state.busy.attest = false;
        var name = filenameFromDisposition(
          xhr.getResponseHeader('Content-Disposition'),
          'actaira-attestation.zip'
        );
        state.data.attest = {
          blob: blob,
          filename: name,
          size: blob.size,
          verdict: xhr.getResponseHeader('X-Actaira-Verdict') || 'inconclusive',
          subject: xhr.getResponseHeader('X-Actaira-Subject-Sha256') || '',
          head: xhr.getResponseHeader('X-Actaira-Head-Hash') || '',
          merkle: xhr.getResponseHeader('X-Actaira-Merkle-Root') || '',
          keyId: xhr.getResponseHeader('X-Actaira-Key-Id') || '',
          entries: xhr.getResponseHeader('X-Actaira-Entry-Count') || '1'
        };
        download(blob, name);
        renderAttest();
      },
      onError: function (info) {
        state.busy.attest = false;
        state.error.attest = info;
        renderAttest();
      }
    });
  }

  function renderAttest() {
    var out = outputOf('attest');
    out.setAttribute('aria-busy', state.busy.attest ? 'true' : 'false');
    updatePanelChrome('attest');
    if (state.busy.attest) { return; }
    if (state.error.attest) { showState('attest', errorState('attest')); return; }
    if (!state.data.attest) { showState('attest', emptyState('attest')); return; }

    var info = state.data.attest;
    clear(out);

    out.appendChild(verdictBanner(info.verdict));

    var hashes = el('div', { class: 'stackrows' }, [
      el('div', { class: 'kv' }, [
        kvRow(t('verify.package'), info.filename, true),
        kvRow(t('attest.size'), bytes(info.size)),
        kvRow(t('attest.entries'), num(parseInt(info.entries, 10) || 1)),
        kvRow(t('attest.key'), info.keyId || t('value.unknown'), true)
      ]),
      hashBlock('attest.subject', info.subject),
      hashBlock('attest.head', info.head),
      hashBlock('attest.merkle', info.merkle)
    ]);
    out.appendChild(card('attest.result.title', null, hashes));

    var notes = [
      el('div', { class: 'note note--ok' }, [svgIcon('i-check'), el('span', { text: t('attest.downloaded') })]),
      el('div', { class: 'note note--warn' }, [svgIcon('i-alert'), el('span', { text: t('attest.no_anchor') })])
    ];
    if (info.verdict === 'fail') {
      notes.unshift(el('div', { class: 'note note--bad' }, [
        svgIcon('i-alert'), el('span', { text: t('attest.warn_fail') })
      ]));
    }
    out.appendChild(el('div', { class: 'notes' }, notes));

    out.appendChild(el('div', { class: 'actions' }, [
      el('button', {
        type: 'button', class: 'btn',
        onclick: function () { download(info.blob, info.filename); }
      }, [svgIcon('i-download'), document.createTextNode(t('attest.again'))])
    ]));
  }

  /* ── verify ───────────────────────────────────────────────────────── */

  function runVerify(file) {
    state.files.verify = file;
    state.data.verify = null;
    state.error.verify = null;
    state.busy.verify = true;
    renderChosen('verify');
    updatePanelChrome('verify');
    outputOf('verify').setAttribute('aria-busy', 'true');
    showState('verify', loadingState('verify', 'loading.verifying'));

    upload('/api/verify', file, {}, {
      onProgress: function (fraction) { setProgress('verify', fraction); },
      onUploaded: function () { setIndeterminate('verify'); },
      onDone: function (payload) {
        state.busy.verify = false;
        state.data.verify = payload;
        renderVerify();
      },
      onError: function (info) {
        state.busy.verify = false;
        state.error.verify = info;
        renderVerify();
      }
    });
  }

  function checkLabel(name) {
    var key = 'check.' + name;
    var text = t(key);
    return text === key ? name : text;
  }

  function checkRow(name, ok, index) {
    return el('div', { class: 'check ' + (ok ? 'check--ok' : 'check--bad') }, [
      el('span', { class: 'check__num', text: pad(index, 2) }),
      svgIcon(ok ? 'i-check' : 'i-cross', 'icon check__icon'),
      el('span', { class: 'check__label', text: checkLabel(name) }),
      el('span', { class: 'check__state', text: t(ok ? 'check.ok' : 'check.bad') })
    ]);
  }

  function questionCard(eyebrowKey, questionKey, tone, bodyNode, answerText, flush) {
    return el('section', { class: 'card card--q tone--' + tone }, [
      el('div', { class: 'card__head' }, [
        el('div', { class: 'card__titlewrap' }, [
          el('h2', { class: 'card__title', text: t(eyebrowKey) }),
          el('span', { class: 'card__question', text: t(questionKey) })
        ])
      ]),
      el('div', { class: 'card__body' + (flush ? ' card__body--flush' : '') }, [bodyNode]),
      el('p', { class: 'card__answer', text: answerText })
    ]);
  }

  function integrityCard(result) {
    var checks = result.checks || {};
    // Any check the backend reports and this list does not know about is
    // still integrity, so it is appended rather than silently dropped.
    var names = INTEGRITY_CHECKS.filter(function (name) {
      return Object.prototype.hasOwnProperty.call(checks, name);
    }).concat(Object.keys(checks).filter(function (name) {
      return name !== 'key_trusted' && INTEGRITY_CHECKS.indexOf(name) === -1;
    }));
    var ok = names.length > 0 && names.every(function (name) { return !!checks[name]; });
    var list = el('div', { class: 'checks' }, names.map(function (name, index) {
      return checkRow(name, !!checks[name], index + 1);
    }));
    return questionCard('verify.q1.eyebrow', 'verify.q1.question', ok ? 'ok' : 'bad', list,
                        t(ok ? 'verify.q1.answer.ok' : 'verify.q1.answer.bad'), true);
  }

  function identityCard(result) {
    var trustState = result.trust_state || 'unverified';
    var tone = trustState === 'trusted' ? 'ok' : (trustState === 'embedded_key_only' ? 'warn' : 'bad');
    var manifest = result.manifest || {};
    var trustKey = 'trust.' + trustState;

    var rows = [
      el('div', { class: 'identity__row' }, [
        el('span', { class: 'trust trust--' + trustState, text: I18N.en[trustKey] ? t(trustKey) : trustState })
      ])
    ];
    if (manifest.signing_key_id) {
      rows.push(kvRow(t('verify.q2.keyid'), String(manifest.signing_key_id), true));
    }
    if (manifest.signing_key_fingerprint_sha256) {
      rows.push(el('div', { class: 'kv__row' }, [
        el('span', { class: 'kv__key', text: t('verify.q2.fingerprint') }),
        hashRow(String(manifest.signing_key_fingerprint_sha256))
      ]));
    }
    if (trustState === 'embedded_key_only') {
      rows.push(el('div', { class: 'note note--warn' }, [
        svgIcon('i-key'), el('span', { text: t('verify.q2.bind') })
      ]));
    }
    var answerKey = 'verify.q2.answer.' + trustState;
    return questionCard('verify.q2.eyebrow', 'verify.q2.question', tone,
                        el('div', { class: 'identity' }, rows),
                        I18N.en[answerKey] ? t(answerKey) : t('verify.q2.answer.unverified'));
  }

  /* ── the chain drawing ────────────────────────────────────────────────
   *
   * Inline SVG built node by node. Nothing here is parsed from a string, so
   * a hash that somehow contained markup would still be text.
   */

  function chainDrawing(chain, manifest) {
    var all = (chain && Array.isArray(chain.entries)) ? chain.entries : [];
    if (!all.length) { return null; }
    var entries = all.slice(0, MAX_CHAIN_NODES);

    // Phone-width geometry: narrower nodes and shorter hashes, so a chain of
    // two or three entries still reads without a long sideways scroll.
    var tight = window.innerWidth < 560;
    var HASH = tight ? 9 : 14, PREV = tight ? 8 : 12;
    var GEN_W = tight ? 58 : 76, NODE_W = tight ? 100 : 134, NODE_H = 58, GAP = tight ? 18 : 26;
    var BUS_Y = NODE_H + 20;
    var ROOT_Y = BUS_Y + 18;
    var ROOT_H = 46, ROOT_W = tight ? 150 : 196;
    var PAD = 2;

    var entryX = function (index) { return GEN_W + GAP + index * (NODE_W + GAP); };
    var lastRight = entryX(entries.length - 1) + NODE_W;
    var rootCx = (entryX(0) + lastRight) / 2;
    var rootX = Math.max(0, rootCx - ROOT_W / 2);
    var width = Math.max(lastRight, rootX + ROOT_W) + PAD;
    var height = ROOT_Y + ROOT_H + PAD;

    var svg = svgNode('svg', {
      class: 'chain',
      width: String(width),
      height: String(height),
      viewBox: '0 0 ' + width + ' ' + height,
      role: 'img',
      'aria-label': t('chain.aria', {
        n: num(chain.total || entries.length),
        root: shortHash(manifest.merkle_root, 12)
      })
    });

    function box(x, y, w, h, cls) {
      return svgNode('rect', { x: x, y: y, width: w, height: h, rx: 6, class: 'chain__box' + (cls ? ' ' + cls : '') });
    }
    function label(x, y, text, cls) {
      return svgNode('text', { x: x, y: y, class: cls || 'chain__label', text: text });
    }
    function link(fromX, toX, y) {
      var group = svgNode('g', {});
      group.appendChild(svgNode('path', { d: 'M' + fromX + ' ' + y + ' H' + (toX - 6), class: 'chain__link' }));
      group.appendChild(svgNode('path', {
        d: 'M' + (toX - 6) + ' ' + (y - 3.6) + ' L' + toX + ' ' + y + ' L' + (toX - 6) + ' ' + (y + 3.6) + ' Z',
        class: 'chain__arrow'
      }));
      return group;
    }

    // genesis
    svg.appendChild(box(1, 1, GEN_W - 2, NODE_H - 2, 'chain__box--genesis'));
    svg.appendChild(label(11, 21, t('chain.genesis').toUpperCase()));
    svg.appendChild(label(11, 38, tight ? '00…00' : '0000…0000', 'chain__hash'));

    entries.forEach(function (entry, index) {
      var x = entryX(index);
      var isHead = index === entries.length - 1;
      svg.appendChild(link(index === 0 ? GEN_W : x - GAP, x, NODE_H / 2));
      svg.appendChild(box(x + 1, 1, NODE_W - 2, NODE_H - 2, isHead ? 'chain__box--head' : ''));
      svg.appendChild(label(x + 11, 18, '#' + num(typeof entry.index === 'number' ? entry.index : index), 'chain__index'));
      svg.appendChild(label(x + 40, 18, t('chain.entry').toUpperCase()));
      svg.appendChild(label(x + 11, 34, shortHash(entry.entry_hash, HASH), 'chain__hash'));
      svg.appendChild(label(x + 11, 48, t('chain.prev') + ' ' + shortHash(entry.prev_hash, PREV)));

      // leaf line down to the Merkle bus
      var cx = x + NODE_W / 2;
      svg.appendChild(svgNode('path', {
        d: 'M' + cx + ' ' + NODE_H + ' V' + BUS_Y + ' H' + rootCx + ' V' + ROOT_Y,
        class: 'chain__leaf'
      }));
    });

    svg.appendChild(label(entryX(0) + 6, BUS_Y - 5, t('chain.leaf').toUpperCase()));

    svg.appendChild(box(rootX + 1, ROOT_Y, ROOT_W - 2, ROOT_H, 'chain__box--root'));
    svg.appendChild(label(rootX + 13, ROOT_Y + 19, t('chain.root').toUpperCase()));
    svg.appendChild(label(rootX + 13, ROOT_Y + 35, shortHash(manifest.merkle_root, tight ? 13 : 18), 'chain__hash'));

    var body = el('div', {}, [el('div', { class: 'chainwrap' }, [svg])]);
    var notes = [t('chain.note')];
    if (chain.total > entries.length) {
      notes.unshift(t('chain.more', { shown: num(entries.length), total: num(chain.total) }));
    }
    body.appendChild(el('p', { class: 'chain__note', text: notes.join(' ') }));
    return card('chain.title', String(num(chain.total || entries.length)), body, true);
  }

  function renderVerify() {
    var out = outputOf('verify');
    out.setAttribute('aria-busy', state.busy.verify ? 'true' : 'false');
    updatePanelChrome('verify');
    if (state.busy.verify) { return; }
    if (state.error.verify) { showState('verify', errorState('verify')); return; }
    if (!state.data.verify) { showState('verify', emptyState('verify')); return; }

    var result = state.data.verify;
    clear(out);

    out.appendChild(el('div', { class: 'verdict verdict--' + (result.ok ? 'pass' : 'fail') }, [
      svgIcon(result.ok ? 'i-pass' : 'i-fail', 'icon verdict__icon'),
      el('div', { class: 'verdict__text' }, [
        el('strong', { class: 'verdict__word', text: t(result.ok ? 'verify.result.ok' : 'verify.result.bad') }),
        el('span', { class: 'verdict__sub', text: t(result.ok ? 'verify.result.ok.sub' : 'verify.result.bad.sub') })
      ])
    ]));

    // Integrity and identity, side by side and never merged.
    out.appendChild(el('p', { class: 'duo__lede', text: t('verify.duo.lede') }));
    out.appendChild(el('div', { class: 'duo' }, [integrityCard(result), identityCard(result)]));

    var chain = chainDrawing(result.chain || {}, result.manifest || {});
    if (chain) { out.appendChild(chain); }

    var problems = Array.isArray(result.problems) ? result.problems : [];
    if (problems.length) {
      out.appendChild(card('verify.problems', String(problems.length),
        el('div', { class: 'notes' }, problems.map(function (message) {
          return el('div', { class: 'note note--bad' }, [svgIcon('i-cross'), el('span', { text: message })]);
        }))));
    }

    // The backend's identity caveat is already on screen, localised, in the
    // identity card above. Repeating it verbatim in English adds noise, not
    // information, so it is dropped here and every other warning is kept.
    var trustState = result.trust_state || 'unverified';
    var warnings = (Array.isArray(result.warnings) ? result.warnings : []).filter(function (message) {
      return !(trustState === 'embedded_key_only' && /IDENTITY NOT VERIFIED/i.test(message));
    });
    if (warnings.length) {
      out.appendChild(card('verify.warnings', String(warnings.length),
        el('div', { class: 'notes' }, warnings.map(function (message) {
          return el('div', { class: 'note note--warn' }, [svgIcon('i-alert'), el('span', { text: message })]);
        }))));
    }

    var manifest = result.manifest || {};
    var manifestRows = [];
    function pushRow(labelKey, value, mono) {
      if (value === undefined || value === null || value === '') { return; }
      manifestRows.push(kvRow(t(labelKey), String(value), mono));
    }
    if (result.package_name) { pushRow('verify.package', result.package_name, true); }
    if (typeof result.package_bytes === 'number') {
      manifestRows.push(kvRow(t('summary.size'), bytes(result.package_bytes)));
    }
    pushRow('manifest.tool', manifest.tool ? manifest.tool + ' ' + (manifest.tool_version || '') : null, true);
    pushRow('manifest.format', manifest.format_version, true);
    pushRow('manifest.created', manifest.created, true);
    pushRow('manifest.entries', num(typeof result.entry_count === 'number' ? result.entry_count : (manifest.entry_count || 0)));
    pushRow('manifest.scheme', manifest.merkle_scheme, true);
    pushRow('manifest.time_anchor', manifest.time_anchor, true);

    if (manifestRows.length || manifest.head_hash || manifest.merkle_root) {
      var manifestBody = el('div', { class: 'stackrows' }, [el('div', { class: 'kv' }, manifestRows)]);
      if (manifest.head_hash) { manifestBody.appendChild(hashBlock('manifest.head', manifest.head_hash)); }
      if (manifest.merkle_root) { manifestBody.appendChild(hashBlock('manifest.merkle', manifest.merkle_root)); }
      out.appendChild(card('verify.manifest', null, manifestBody));
    }
  }

  /* ── per-tab plumbing ─────────────────────────────────────────────── */


  /* ── the graph renderer ───────────────────────────────────────────────
   *
   * One renderer, many graphs. Attack routes were the first thing that needed
   * to be drawn and they are not the last: the asset graph, impact, evidence
   * lifecycle, the MCP surface, the AI Act evidence map and the attestation
   * chain are all nodes and edges over the same vocabulary. Writing a second
   * drawing function for each of them would mean six places where a node kind
   * could be styled differently and six places to fix a layout bug.
   *
   * So callers build a *model* and hand it over. A model is:
   *
   *   {
   *     nodes: [{ id, kind, label, detail, tone }],
   *     edges: [{ from, to, relation, stated_by, evidence_id }],
   *     layout: 'chain'
   *   }
   *
   * Two rules the renderer enforces rather than trusts:
   *
   *   * **An edge names its provenance.** `relation` says what the edge is and
   *     `stated_by` says who said so; `evidence_id` says which stored record
   *     carries it, when one does. An edge that arrives without `stated_by` is
   *     drawn with `unstated` in its place rather than silently, because an
   *     edge nobody claimed is exactly the thing this project refuses to draw.
   *   * **A node's kind comes from its id.** Ids are `kind:name`, which is the
   *     shape the engine already emits, so the kind is read rather than
   *     guessed from what the name looks like.
   */

  /* The subject vocabulary the graph can draw. Wider than `SubjectKind` in the
   * engine, which is the set a *policy* can be written about and is frozen in
   * published schemas. These are the things that can appear as a node: a tool
   * and a credential are not policy subjects and are certainly parts of the
   * picture. Anything outside this list draws as `unknown` rather than being
   * dropped, because a node the renderer does not recognise is still a node
   * somebody put in the graph. */
  var GRAPH_NODE_KINDS = [
    'artifact', 'model', 'bundle', 'agent', 'mcp', 'tool',
    'identity', 'credential', 'datasource', 'source', 'system', 'policy'
  ];

  /* The one place an engine id prefix is allowed to differ from the visual
   * kind it draws as, written out entry by entry.
   *
   * `data:` is the case that made this necessary. The agent engine emits data
   * sources as `data:<name>` and has done since the declaration format was
   * published; the visual vocabulary calls that kind `datasource`. Renaming
   * either one to match the other would be changing a published id or a
   * stylesheet class to settle a spelling, so the mapping is stated instead.
   *
   * It is a table and not a rule. A prefix that is in neither list stays
   * `unknown` and draws as unknown, because a renderer that guessed which
   * kind an unfamiliar prefix meant would be inventing a classification -
   * quietly, and in the one place a reader has no way to check it. */
  var GRAPH_NODE_ALIASES = { data: 'datasource' };

  function graphNodeKind(id) {
    var prefix = String(id || '').split(':')[0];
    if (Object.prototype.hasOwnProperty.call(GRAPH_NODE_ALIASES, prefix)) {
      return GRAPH_NODE_ALIASES[prefix];
    }
    return GRAPH_NODE_KINDS.indexOf(prefix) === -1 ? 'unknown' : prefix;
  }

  /** A chain: one column, each node linked to the next.
   *
   *  Vertical rather than horizontal because every node carries two lines of
   *  text, which reads as a column at any width and needs a sideways scroll as
   *  a row. Returns the geometry the drawing function consumes, so a second
   *  layout can be added here without any caller changing. */
  function graphChainLayout(model, tight) {
    var width = tight ? 250 : 420;
    var boxHeight = 44, gap = 34, pad = 2;
    return {
      width: width,
      height: model.nodes.length * boxHeight + Math.max(0, model.nodes.length - 1) * gap + pad * 2,
      boxWidth: width - 2,
      boxHeight: boxHeight,
      gap: gap,
      at: function (index) { return { x: 1, y: pad + index * (boxHeight + gap) }; },
      /* The connector between two boxes of a chain: straight down the middle,
       * and drawn only between neighbours, because a chain that drew an edge
       * from its first box to its last would be drawing a line through the
       * boxes in between. */
      edge: function (fromIndex, toIndex, from, to) {
        if (toIndex !== fromIndex + 1) { return null; }
        var top = from.y + boxHeight, bottom = to.y, mid = width / 2;
        return {
          line: 'M' + mid + ' ' + top + ' V' + (bottom - 7),
          arrow: 'M' + (mid - 3.6) + ' ' + (bottom - 7) + ' L' + mid + ' ' + bottom
            + ' L' + (mid + 3.6) + ' ' + (bottom - 7) + ' Z',
          label: { x: mid + 10, y: top + gap / 2 + 4, anchor: 'start' }
        };
      }
    };
  }

  /** Layers, for a graph that is not a line.
   *
   *  Deterministic on purpose, and that is a requirement rather than a
   *  preference. This repository generates its screenshots and fails a build
   *  on what they show, and two runs over one workspace have to draw the same
   *  picture; a force simulation would make every capture a different image
   *  and every visual regression unarguable. So: layers by longest path from
   *  the nodes nothing depends on, ties broken by sorting the ids, and the
   *  members of a cycle placed one layer below whichever of their
   *  predecessors was already placed.
   *
   *  Edges point from the thing that uses to the thing it uses, so layer 0 is
   *  what nothing depends on - the system at the top - and depth increases
   *  downwards towards the artifacts. */
  function graphLayeredLayout(model, tight) {
    var nodes = model.nodes, edges = model.edges || [];
    var boxWidth = tight ? 150 : 190, boxHeight = 42, gapX = tight ? 16 : 26, gapY = 64, pad = 10;

    var ids = nodes.map(function (node) { return node.id; });
    var known = {};
    ids.forEach(function (id) { known[id] = true; });
    var real = edges.filter(function (edge) {
      return known[edge.from] && known[edge.to] && edge.from !== edge.to;
    });

    var outgoing = {}, indegree = {};
    ids.forEach(function (id) { outgoing[id] = []; indegree[id] = 0; });
    real.forEach(function (edge) {
      outgoing[edge.from].push(edge.to);
      indegree[edge.to] += 1;
    });

    var layer = {}, remaining = {};
    ids.forEach(function (id) { remaining[id] = indegree[id]; });
    var queue = ids.filter(function (id) { return remaining[id] === 0; }).sort();
    queue.forEach(function (id) { layer[id] = 0; });
    while (queue.length) {
      var id = queue.shift();
      outgoing[id].slice().sort().forEach(function (target) {
        if (layer[target] === undefined || layer[target] < layer[id] + 1) {
          layer[target] = layer[id] + 1;
        }
        remaining[target] -= 1;
        if (remaining[target] === 0) { queue.push(target); queue.sort(); }
      });
    }
    // Whatever is left is in a cycle. Placed rather than dropped: a cycle is
    // a real shape in these graphs and a layout that refused to draw one
    // would be hiding the thing the reader most needs to see.
    ids.slice().sort().forEach(function (id) {
      if (layer[id] !== undefined) { return; }
      var above = -1;
      real.forEach(function (edge) {
        if (edge.to === id && layer[edge.from] !== undefined && layer[edge.from] > above) {
          above = layer[edge.from];
        }
      });
      layer[id] = above + 1;
    });

    var byLayer = {};
    ids.slice().sort().forEach(function (id) {
      var depth = layer[id];
      if (!byLayer[depth]) { byLayer[depth] = []; }
      byLayer[depth].push(id);
    });
    var depths = Object.keys(byLayer).map(Number).sort(function (a, b) { return a - b; });

    /* A layer wider than this wraps onto further rows. An agent declaring
     * eleven tools would otherwise put eleven boxes side by side, and fitting
     * that into the viewport shrinks every label past reading. The layer is
     * unchanged - these are still its members, in the same sorted order - and
     * only how it is drawn wraps. */
    var perRow = tight ? 2 : 6;
    var rows = [];
    depths.forEach(function (depth) {
      var members = byLayer[depth];
      for (var start = 0; start < members.length; start += perRow) {
        rows.push(members.slice(start, start + perRow));
      }
    });

    var widest = 1;
    rows.forEach(function (members) { widest = Math.max(widest, members.length); });
    var width = pad * 2 + widest * boxWidth + (widest - 1) * gapX;
    var placed = {};
    rows.forEach(function (members, row) {
      var span = members.length * boxWidth + (members.length - 1) * gapX;
      var left = Math.round((width - span) / 2);
      members.forEach(function (id, column) {
        placed[id] = { x: left + column * (boxWidth + gapX), y: pad + row * (boxHeight + gapY) };
      });
    });

    return {
      width: width,
      height: pad * 2 + rows.length * boxHeight + Math.max(0, rows.length - 1) * gapY,
      boxWidth: boxWidth,
      boxHeight: boxHeight,
      gap: gapY,
      at: function (index) {
        return placed[ids[index]] || { x: pad, y: pad };
      },
      /* A straight line between the two boxes, clipped at each border so the
       * arrow lands on the edge of the target rather than under it. Works for
       * a back edge as well as a forward one, which is what lets a cycle draw
       * as a cycle. */
      edge: function (fromIndex, toIndex, from, to) {
        var ax = from.x + boxWidth / 2, ay = from.y + boxHeight / 2;
        var bx = to.x + boxWidth / 2, by = to.y + boxHeight / 2;
        var dx = bx - ax, dy = by - ay;
        var span = Math.sqrt(dx * dx + dy * dy);
        if (!span) { return null; }
        var startAt = clipToBox(dx / span, dy / span, boxWidth / 2, boxHeight / 2);
        var endAt = clipToBox(-dx / span, -dy / span, boxWidth / 2, boxHeight / 2);
        var x1 = ax + (dx / span) * startAt, y1 = ay + (dy / span) * startAt;
        var x2 = bx - (dx / span) * endAt, y2 = by - (dy / span) * endAt;
        var tipX = x2, tipY = y2;
        var backX = x2 - (dx / span) * 8, backY = y2 - (dy / span) * 8;
        var sideX = (-dy / span) * 3.6, sideY = (dx / span) * 3.6;
        return {
          line: 'M' + round(x1) + ' ' + round(y1) + ' L' + round(backX) + ' ' + round(backY),
          arrow: 'M' + round(backX + sideX) + ' ' + round(backY + sideY)
            + ' L' + round(tipX) + ' ' + round(tipY)
            + ' L' + round(backX - sideX) + ' ' + round(backY - sideY) + ' Z',
          label: { x: round((x1 + x2) / 2), y: round((y1 + y2) / 2 - 4), anchor: 'middle' }
        };
      }
    };
  }

  function round(value) { return Math.round(value * 10) / 10; }

  /** Trim a label to what fits a box, from the middle.
   *
   *  From the middle because these are `kind:name` ids: cutting the tail
   *  leaves eight boxes reading `tool:read_...` and cutting the head loses the
   *  kind. Both ends are what tells two nodes apart. Nothing is lost - the
   *  whole string is in the box's `<title>` and in the panel beside it - but a
   *  label that overruns its box and lands on its neighbour is not a drawing
   *  anybody can read.
   *
   *  The width is estimated rather than measured, because measuring means
   *  laying text out before the SVG is in the document, and a monospaced face
   *  at a known size is the one case where an estimate is reliable. */
  function graphFit(text, boxWidth, perChar) {
    var value = String(text || '');
    var room = Math.max(6, Math.floor((boxWidth - 24) / perChar));
    if (value.length <= room) { return value; }
    var head = Math.ceil((room - 1) / 2);
    return value.slice(0, head) + '\u2026' + value.slice(value.length - (room - 1 - head));
  }

  /** How far the centre of a box is from its border in one direction. */
  function clipToBox(ux, uy, halfWidth, halfHeight) {
    var byX = ux ? Math.abs(halfWidth / ux) : Infinity;
    var byY = uy ? Math.abs(halfHeight / uy) : Infinity;
    return Math.min(byX, byY);
  }

  var GRAPH_LAYOUTS = { chain: graphChainLayout, layered: graphLayeredLayout };

  /** The drawing. Takes a model, returns an `<svg>`, and knows nothing about
   *  what the graph is about.
   *
   *  `options` is how a caller that wants an interactive graph gets one
   *  without a second renderer: `onSelect` makes the boxes and the lines
   *  selectable, `positions` overrides where a box sits, and `selected` and
   *  `highlight` mark what is chosen and what route is being explained. A
   *  caller that passes none of them - the attack-path chain - gets exactly
   *  the static drawing it got before. */
  function graphDrawing(model, ariaLabel, options) {
    var nodes = (model && Array.isArray(model.nodes)) ? model.nodes : [];
    if (!nodes.length) { return null; }
    var edges = (model && Array.isArray(model.edges)) ? model.edges : [];
    var opts = options || {};

    var tight = window.innerWidth < 560;
    var layout = (GRAPH_LAYOUTS[model.layout] || graphChainLayout)(model, tight);

    var svg = svgNode('svg', {
      class: 'graph',
      width: String(layout.width),
      height: String(layout.height),
      viewBox: '0 0 ' + layout.width + ' ' + layout.height,
      role: 'img',
      'aria-label': ariaLabel || ''
    });
    // Everything inside one group, so a viewport can zoom and pan by writing
    // one transform rather than by touching every node it drew.
    var scene = svgNode('g', { class: 'graph__scene' });
    svg.appendChild(scene);

    var index = {}, at = {};
    nodes.forEach(function (node, position) {
      index[node.id] = position;
      var placed = (opts.positions && opts.positions[node.id]) || layout.at(position);
      at[node.id] = { x: placed.x, y: placed.y };
    });

    var edgeLayer = svgNode('g', { class: 'graph__edges' });
    var nodeLayer = svgNode('g', { class: 'graph__nodes' });
    scene.appendChild(edgeLayer);
    scene.appendChild(nodeLayer);

    var drawn = [];
    edges.forEach(function (edge, position) {
      var from = index[edge.from], to = index[edge.to];
      if (from === undefined || to === undefined) { return; }
      var key = edge.from + '\u0000' + (edge.relation || '') + '\u0000' + edge.to;
      var group = svgNode('g', { class: 'graph__edge' });
      var line = svgNode('path', { class: 'graph__link', d: '' });
      var head = svgNode('path', { class: 'graph__arrow', d: '' });
      var label = edge.relation
        ? svgNode('text', { class: 'graph__relation', text: edge.relation, x: '0', y: '0' })
        : null;
      group.appendChild(line);
      group.appendChild(head);
      if (label) { group.appendChild(label); }
      // Provenance, on the edge itself. `unstated` rather than nothing: an
      // edge nobody claimed has to look different from one somebody did.
      group.appendChild(svgNode('title', {
        text: [
          edge.relation || 'edge',
          t('graph.stated_by') + ': ' + (edge.stated_by || t('graph.unstated')),
          edge.evidence_id ? (t('graph.evidence') + ': ' + edge.evidence_id) : ''
        ].filter(Boolean).join(' \u00b7 ')
      }));
      if (!edge.stated_by) { group.setAttribute('class', 'graph__edge graph__edge--unstated'); }
      if (opts.highlight && opts.highlight[key]) {
        group.setAttribute('class', group.getAttribute('class') + ' graph__edge--lit');
      }
      if (opts.selected && opts.selected.type === 'edge' && opts.selected.key === key) {
        group.setAttribute('class', group.getAttribute('class') + ' graph__edge--chosen');
      }
      if (opts.onSelect) {
        group.setAttribute('tabindex', '0');
        group.setAttribute('role', 'button');
        group.setAttribute('aria-label',
          (edge.from || '?') + ' ' + (edge.relation || '') + ' ' + (edge.to || '?'));
        group.addEventListener('click', function (event) {
          event.stopPropagation();
          opts.onSelect({ type: 'edge', key: key, edge: edge });
        });
        group.addEventListener('keydown', function (event) {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            opts.onSelect({ type: 'edge', key: key, edge: edge });
          }
        });
      }
      edgeLayer.appendChild(group);
      drawn.push({ edge: edge, from: from, to: to, line: line, head: head, label: label });
    });

    function place(record) {
      var geometry = layout.edge(record.from, record.to,
        at[record.edge.from], at[record.edge.to]);
      if (!geometry) {
        record.line.setAttribute('d', '');
        record.head.setAttribute('d', '');
        if (record.label) { record.label.setAttribute('visibility', 'hidden'); }
        return;
      }
      record.line.setAttribute('d', geometry.line);
      record.head.setAttribute('d', geometry.arrow);
      if (record.label) {
        record.label.removeAttribute('visibility');
        record.label.setAttribute('x', String(geometry.label.x));
        record.label.setAttribute('y', String(geometry.label.y));
        record.label.setAttribute('text-anchor', geometry.label.anchor || 'start');
      }
    }
    drawn.forEach(place);

    var boxes = {};
    nodes.forEach(function (node) {
      var spot = at[node.id];
      var kind = node.kind || graphNodeKind(node.id);
      var group = svgNode('g', {
        class: 'graph__nodegroup',
        transform: 'translate(' + spot.x + ' ' + spot.y + ')'
      });
      var classes = 'graph__box graph__box--' + kind + (node.tone ? ' graph__box--' + node.tone : '');
      if (opts.selected && opts.selected.type === 'node' && opts.selected.id === node.id) {
        classes += ' graph__box--chosen';
      }
      if (opts.highlight && opts.highlight[node.id]) { classes += ' graph__box--lit'; }
      group.appendChild(svgNode('rect', {
        x: 0, y: 0, width: layout.boxWidth, height: layout.boxHeight, rx: 7, class: classes
      }));
      group.appendChild(svgNode('text', {
        x: 12, y: 19, class: 'graph__node',
        text: graphFit(node.label || node.id, layout.boxWidth, 6.9)
      }));
      if (node.detail) {
        group.appendChild(svgNode('text', {
          x: 12, y: 34, class: 'graph__detail',
          text: graphFit(node.detail, layout.boxWidth, 6.1)
        }));
      }
      // The kind, as a word, inside the box. Colour is never the only thing
      // carrying it: a reader in greyscale, or one who cannot tell the two
      // washes apart, still gets the classification.
      // The whole label, never the trimmed one: this is where a reader who
      // cannot tell two boxes apart goes to find out.
      group.appendChild(svgNode('title', {
        text: (node.label || node.id) + ' \u00b7 ' + kind
          + (node.detail ? ' \u00b7 ' + node.detail : '')
      }));
      if (opts.onSelect) {
        group.setAttribute('tabindex', '0');
        group.setAttribute('role', 'button');
        group.setAttribute('aria-label', t('gr.aria.node', { id: node.label || node.id, kind: kind }));
        group.addEventListener('click', function (event) {
          event.stopPropagation();
          if (group._dragged) { group._dragged = false; return; }
          opts.onSelect({ type: 'node', id: node.id, node: node });
        });
        group.addEventListener('keydown', function (event) {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            opts.onSelect({ type: 'node', id: node.id, node: node });
          }
        });
      }
      group._nodeId = node.id;
      nodeLayer.appendChild(group);
      boxes[node.id] = group;
    });

    svg._scene = scene;
    svg._layout = layout;
    svg._positions = at;
    /* Where a box sits, changed. Presentation only: this moves a group's
     * transform and redraws the lines that reach it, and nothing here writes
     * to the workspace. A node's screen coordinates are not evidence and do
     * not belong in a database of assurance claims. */
    svg._moveNode = function (id, x, y) {
      if (!at[id] || !boxes[id]) { return; }
      at[id].x = x;
      at[id].y = y;
      boxes[id].setAttribute('transform', 'translate(' + x + ' ' + y + ')');
      drawn.forEach(function (record) {
        if (record.edge.from === id || record.edge.to === id) { place(record); }
      });
    };
    return svg;
  }

  /** The sentence under a graph that says where its edges came from.
   *
   *  Counted rather than asserted: a graph whose edges are all declared and
   *  one that mixes declared with stored evidence are different claims, and
   *  the reader is told which they are looking at. */
  function graphProvenanceNote(edges) {
    var stated = {};
    var withEvidence = 0;
    (edges || []).forEach(function (edge) {
      var key = edge.stated_by || t('graph.unstated');
      stated[key] = (stated[key] || 0) + 1;
      if (edge.evidence_id) { withEvidence += 1; }
    });
    var names = Object.keys(stated);
    if (!names.length) { return null; }
    var parts = names.map(function (name) { return name + ' (' + num(stated[name]) + ')'; });
    var text = t('graph.provenance') + ': ' + parts.join(', ');
    if (withEvidence) { text += '. ' + t('graph.evidence_backed', { n: num(withEvidence) }); }
    return el('p', { class: 'graph__note', text: text });
  }

  /* ── agents ───────────────────────────────────────────────────────────
   *
   * The panel behind `actaira agent`. Three requests, in the order a reader
   * wants them: the declaration and its capability findings first, because
   * that is the verdict; then the route search, which walks the graph and is
   * the slower of the two; then a diff, only if a second declaration arrives.
   *
   * Every label inside a route comes from the engine rather than from the
   * catalogue below. `label` and `via` are what the path search decided, in
   * one language, and the CLI prints the same strings: translating them here
   * would put two different sentences on one finding depending on which
   * surface you read it from.
   */

  function agentSummaryCard(summary) {
    if (!summary) { return null; }
    var body = el('div', { class: 'kv' }, [
      kvRow(t('agents.version'), document.createTextNode(String(summary.version)), true),
      kvRow(t('agents.environment'), document.createTextNode(summary.environment || '?')),
      kvRow(t('agents.tools'), document.createTextNode(num(summary.tools))),
      kvRow(t('agents.mcp'), document.createTextNode(num(summary.mcp_servers))),
      kvRow(t('agents.identities'), document.createTextNode(num(summary.identities))),
      kvRow(t('agents.sources'), document.createTextNode(num(summary.data_sources))),
      kvRow(t('agents.subagents'), document.createTextNode(num(summary.sub_agents)))
    ]);
    body.appendChild(hashBlock('agents.digest', summary.digest));
    return card('agents.summary', summary.name, body);
  }

  function agentFindingsCard(findings) {
    if (!findings.length) {
      return card('agents.findings', '0', el('p', { class: 'empty__text', text: t('agents.findings.none') }));
    }
    var list = el('ul', { class: 'findings' }, findings.map(findingNode));
    return card('agents.findings', String(num(findings.length)), list, true);
  }

  /** A route as a graph model. The hops are the nodes and the reason each
   *  hop follows the last is the edge: `via` is what the path search decided
   *  put it there, which is this graph's `stated_by`. */
  function agentRouteModel(path) {
    var hops = Array.isArray(path.hops) ? path.hops : [];
    var nodes = hops.map(function (hop, position) {
      var tone = '';
      if (position === 0) { tone = 'entry'; }
      else if (position === hops.length - 1) { tone = 'sink'; }
      return {
        id: hop.node + '#' + position,
        kind: graphNodeKind(hop.node),
        label: hop.node || '?',
        detail: hop.label || '',
        tone: tone
      };
    });
    var edges = [];
    for (var i = 1; i < nodes.length; i += 1) {
      edges.push({
        from: nodes[i - 1].id,
        to: nodes[i].id,
        relation: '',
        // The route search states each step, and says which declaration or
        // effect put it there. No edge here is inferred from a name.
        stated_by: hops[i].via || ''
      });
    }
    return { nodes: nodes, edges: edges, layout: 'chain' };
  }

  function agentRouteCard(path, index) {
    var open = !path.broken;
    var head = el('div', { class: 'route__head' }, [
      severityChip(path.severity),
      el('code', { class: 'finding__rule', text: path.rule_id || '?' }),
      el('span', {
        class: 'badge ' + (open ? 'badge--bad' : 'badge--good'),
        text: open ? t('agents.paths.open') : t('agents.paths.closed')
      })
    ]);

    var children = [head];
    var described = ruleText(path.rule_id);
    if (described) { children.push(el('p', { class: 'finding__text', text: described })); }
    if (path.note) { children.push(el('p', { class: 'route__note', text: path.note })); }

    var model = agentRouteModel(path);
    var drawing = graphDrawing(model, t('agents.paths.aria', {
      n: index + 1, entry: path.entry, sink: path.sink
    }));
    if (drawing) {
      children.push(el('div', { class: 'graphwrap' }, [drawing]));
      var note = graphProvenanceNote(model.edges);
      if (note) { children.push(note); }
    }

    children.push(el('p', {
      class: 'route__carries',
      text: t('agents.paths.carries') + ': ' + (path.carries || 'text')
    }));

    function bullets(labelKey, items, tone) {
      if (!items || !items.length) { return; }
      children.push(el('p', { class: 'route__subhead', text: t(labelKey) }));
      children.push(el('ul', { class: 'route__list' + (tone ? ' route__list--' + tone : '') },
        items.map(function (item) {
          var text = typeof item === 'string'
            ? item
            : [item.control, item.why].filter(Boolean).join(': ');
          return el('li', { text: text });
        })));
    }
    bullets('agents.paths.closed_by', path.closed_by, 'good');
    bullets('agents.paths.break', path.break_path_by);
    bullets('agents.paths.ineffective', path.present_but_ineffective, 'warn');

    return el('li', { class: 'route' + (open ? ' route--open' : ' route--closed') }, children);
  }

  function agentPathsCard(report) {
    if (!report) { return null; }
    var paths = Array.isArray(report.paths) ? report.paths : [];
    var unresolved = Array.isArray(report.unresolved_sub_agents) ? report.unresolved_sub_agents : [];

    if (!paths.length) {
      var empty = el('div', {}, [el('p', { class: 'empty__text', text: t('agents.paths.none') })]);
      if (unresolved.length) {
        empty.appendChild(el('p', { class: 'route__note', text: t('agents.paths.unresolved') }));
        empty.appendChild(el('ul', { class: 'route__list' },
          unresolved.map(function (name) { return el('li', { text: String(name) }); })));
      }
      return card('agents.paths', '0', empty);
    }

    var shown = paths.slice(0, MAX_ROUTES_SHOWN);
    var body = el('div', {}, [
      el('ul', { class: 'routes' }, shown.map(agentRouteCard))
    ]);
    if (paths.length > shown.length) {
      body.appendChild(el('p', { class: 'route__note',
        text: t('agents.paths.more', { shown: num(shown.length), total: num(paths.length) }) }));
    }
    if (unresolved.length) {
      body.appendChild(el('p', { class: 'route__note', text: t('agents.paths.unresolved') }));
      body.appendChild(el('ul', { class: 'route__list' },
        unresolved.map(function (name) { return el('li', { text: String(name) }); })));
    }
    var count = num(report.open_paths) + ' ' + t('agents.paths.open');
    return card('agents.paths', count, body, true);
  }

  function agentBomCard() {
    var button = el('button', { class: 'btn', type: 'button' }, [
      svgIcon('i-download'), el('span', { text: t('agents.bom.download') })
    ]);
    button.addEventListener('click', function () { downloadAgentBom(button); });
    var body = el('div', {}, [
      el('p', { class: 'card__lede', text: t('agents.bom.lede') }),
      el('div', { class: 'actions' }, [button])
    ]);
    return card('agents.bom', null, body);
  }

  function downloadAgentBom(button) {
    var file = state.files.agents;
    if (!file) { return; }
    button.disabled = true;
    upload('/api/agent/bom', file, {}, {
      onDone: function (payload) {
        button.disabled = false;
        var blob = new Blob([JSON.stringify(payload.bom, null, 2) + '\n'],
          { type: 'application/json' });
        var name = (payload.agent && payload.agent.name ? payload.agent.name : 'agent') + '.abom.json';
        download(blob, name);
      },
      onError: function (info) {
        button.disabled = false;
        toast(info && info.message ? info.message : t('error.generic'));
      }
    });
  }

  function agentDiffCard() {
    var input = el('input', { class: 'visually-hidden', type: 'file', id: 'file-agents-after' });
    input.setAttribute('accept', '.yaml,.yml,.json');
    var button = el('button', { class: 'btn', type: 'button', text: t('agents.diff.choose') });
    button.addEventListener('click', function () { input.click(); });
    input.addEventListener('change', function () {
      if (input.files && input.files[0]) { runAgentDiff(input.files[0]); }
      input.value = '';
    });

    var body = el('div', {}, [
      el('p', { class: 'card__lede', text: t('agents.diff.lede') }),
      el('div', { class: 'actions' }, [button, input])
    ]);

    var diff = state.agents.diff;
    if (diff && diff.status === 'loading') {
      body.appendChild(el('p', { class: 'route__note', text: t('loading.agents') }));
    } else if (diff && diff.status === 'error') {
      body.appendChild(el('p', { class: 'route__note', text: diff.message }));
    } else if (diff && diff.status === 'done') {
      body.appendChild(agentDiffResult(diff.payload));
    }
    return card('agents.diff', null, body);
  }

  /** The diff document, minus the keys that are always present and say
   *  nothing on their own, so a change is not buried in scaffolding. */
  function agentDiffResult(payload) {
    var document_ = (payload && payload.diff) || {};
    var interesting = Object.keys(document_).filter(function (key) {
      var value = document_[key];
      if (key === 'agent' || key === 'from_digest' || key === 'to_digest') { return false; }
      if (value === null || value === false) { return false; }
      if (Array.isArray(value)) { return value.length > 0; }
      if (typeof value === 'object') { return Object.keys(value).length > 0; }
      return true;
    });
    if (!interesting.length) {
      return el('p', { class: 'empty__text', text: t('agents.diff.same') });
    }
    var trimmed = {};
    interesting.forEach(function (key) { trimmed[key] = document_[key]; });
    return el('div', {}, [
      el('p', { class: 'route__subhead', text: t('agents.diff.result') }),
      el('pre', { class: 'code' }, [el('code', { text: JSON.stringify(trimmed, null, 2) })])
    ]);
  }

  function runAgentDiff(after) {
    var before = state.files.agents;
    if (!before || !after) { return; }
    if (after.size > MAX_DECLARATION_FIELD_BYTES) {
      state.agents.diff = { status: 'error', message: t('agents.diff.too_big') };
      renderAgents();
      return;
    }
    state.agents.diff = { status: 'loading' };
    renderAgents();

    var reader = new FileReader();
    reader.onerror = function () {
      state.agents.diff = { status: 'error', message: t('error.generic') };
      renderAgents();
    };
    reader.onload = function () {
      upload('/api/agent/diff', before, { after: String(reader.result) }, {
        onDone: function (payload) {
          state.agents.diff = { status: 'done', payload: payload };
          renderAgents();
        },
        onError: function (info) {
          state.agents.diff = {
            status: 'error',
            message: (info && info.message) ? info.message : t('error.generic')
          };
          renderAgents();
        }
      });
    };
    reader.readAsText(after);
  }

  function runAgents(file) {
    state.files.agents = file;
    state.data.agents = null;
    state.agents = { paths: null, diff: null };
    state.error.agents = null;
    state.busy.agents = true;
    renderChosen('agents');
    updatePanelChrome('agents');
    outputOf('agents').setAttribute('aria-busy', 'true');
    showState('agents', loadingState('agents', 'loading.agents'));

    upload('/api/agent/check', file, {}, {
      onProgress: function (fraction) { setProgress('agents', fraction); },
      onUploaded: function () { setIndeterminate('agents'); },
      onDone: function (payload) {
        state.busy.agents = false;
        state.data.agents = payload;
        renderAgents();
        requestAgentPaths();
      },
      onError: function (info) {
        state.busy.agents = false;
        state.error.agents = info;
        renderAgents();
      }
    });
  }

  /** The route search is its own request for the same reason the opcode trace
   *  is: it walks a graph, and the capability findings should not wait on it. */
  function requestAgentPaths() {
    var file = state.files.agents;
    if (!file) { return; }
    state.agents.paths = { status: 'loading' };
    renderAgents();
    upload('/api/agent/paths', file, {}, {
      onDone: function (payload) {
        state.agents.paths = { status: 'done', payload: payload };
        renderAgents();
      },
      onError: function () {
        state.agents.paths = { status: 'error' };
        renderAgents();
      }
    });
  }

  function renderAgents() {
    updatePanelChrome('agents');
    renderChosen('agents');
    var out = outputOf('agents');
    if (!out) { return; }
    out.setAttribute('aria-busy', state.busy.agents ? 'true' : 'false');

    if (state.busy.agents) { return; }
    if (state.error.agents) { return showState('agents', errorState('agents')); }
    var payload = state.data.agents;
    if (!payload) { return showState('agents', emptyState('agents')); }

    var findings = Array.isArray(payload.findings) ? payload.findings : [];
    var cards = [
      agentSummaryCard(payload.agent),
      agentFindingsCard(findings)
    ];

    var paths = state.agents.paths;
    if (paths && paths.status === 'loading') {
      cards.push(card('agents.paths', null,
        el('p', { class: 'empty__text', text: t('loading.agentpaths') })));
    } else if (paths && paths.status === 'done') {
      cards.push(agentPathsCard(paths.payload.report));
    }

    cards.push(agentBomCard());
    cards.push(agentDiffCard());

    showState('agents', el('div', { class: 'cards' }, cards.filter(Boolean)));
  }


  /* ── policy ───────────────────────────────────────────────────────────
   *
   * The step that turns everything else into an answer. Two requests: the
   * document, then a decision about one subject under it.
   *
   * The document is kept as a File rather than as parsed JSON, because the
   * decision needs the original text: a policy is identified by the digest of
   * what was written, and re-serialising the parsed form to send it back would
   * be deciding under a document nobody wrote.
   */

  var POLICY_SUBJECT_KINDS = ['artifact', 'agent'];

  function policySummaryCard(summary) {
    if (!summary) { return null; }
    var body = el('div', { class: 'kv' }, [
      kvRow(t('policy.version'), document.createTextNode(String(summary.version)), true),
      kvRow(t('policy.rules'), document.createTextNode(num(summary.rules)))
    ]);
    if (summary.description) {
      body.appendChild(el('p', { class: 'card__lede', text: summary.description }));
    }
    body.appendChild(hashBlock('policy.digest', summary.digest));
    return card('policy.summary', summary.id, body);
  }

  function policyRuleRow(rule) {
    var effect = String(rule.effect || '').toLowerCase();
    var head = el('div', { class: 'route__head' }, [
      el('span', { class: 'badge badge--' + (effect === 'deny' ? 'bad' : 'quiet'), text: effect }),
      el('code', { class: 'finding__rule', text: rule.id || '?' })
    ]);
    var children = [head];
    if (rule.description) {
      children.push(el('p', { class: 'finding__text', text: rule.description }));
    }
    if (rule.when && typeof rule.when === 'object') {
      children.push(el('p', { class: 'route__subhead', text: t('policy.rule.when') }));
      children.push(el('pre', { class: 'code' }, [
        el('code', { text: JSON.stringify(rule.when, null, 2) })
      ]));
    }
    return el('li', { class: 'route' }, children);
  }

  function policyRulesCard(document_) {
    var rules = (document_ && Array.isArray(document_.rules)) ? document_.rules : [];
    if (!rules.length) { return null; }
    return card('policy.rules', String(num(rules.length)),
      el('ul', { class: 'routes' }, rules.map(policyRuleRow)), true);
  }

  /** The subject chooser. Two radio buttons and a file input, because the kind
   *  is stated by the operator rather than sniffed from the bytes: a decision
   *  names its subject, and a subject this tool guessed at is a worse thing to
   *  put in a proof than one somebody chose. */
  function policySubjectCard() {
    var input = el('input', { class: 'visually-hidden', type: 'file', id: 'file-policy-subject' });
    var button = el('button', { class: 'btn btn--primary', type: 'button', text: t('policy.subject.choose') });
    button.addEventListener('click', function () { input.click(); });
    input.addEventListener('change', function () {
      if (input.files && input.files[0]) { runPolicyDecision(input.files[0]); }
      input.value = '';
    });

    var group = el('div', { class: 'segmented' });
    group.setAttribute('role', 'group');
    group.setAttribute('aria-label', t('policy.subject.kind'));
    POLICY_SUBJECT_KINDS.forEach(function (kind) {
      var chosen = state.policy.subjectKind === kind;
      var pick = el('button', {
        class: 'segmented__btn', type: 'button', text: t('policy.subject.' + kind)
      });
      pick.setAttribute('aria-pressed', chosen ? 'true' : 'false');
      pick.addEventListener('click', function () {
        state.policy.subjectKind = kind;
        renderPolicy();
      });
      group.appendChild(pick);
    });

    var body = el('div', {}, [
      el('p', { class: 'card__lede', text: t('policy.subject.lede') }),
      el('div', { class: 'actions' }, [group, button, input])
    ]);

    var decision = state.policy.decision;
    if (decision && decision.status === 'loading') {
      body.appendChild(el('p', { class: 'route__note', text: t('loading.policydecide') }));
    } else if (decision && decision.status === 'error') {
      body.appendChild(el('p', { class: 'route__note', text: decision.message }));
    }
    return card('policy.subject', null, body);
  }

  function policyProofRow(row) {
    var contributes = String(row.contributes || '').toLowerCase();
    var head = el('div', { class: 'route__head' }, [
      el('span', {
        class: 'badge badge--' + (contributes === 'deny' ? 'bad'
          : (contributes === 'allow' ? 'good' : 'quiet')),
        text: t('policy.contributes.' + contributes) || contributes
      }),
      el('code', { class: 'finding__rule', text: row.rule || '?' })
    ]);
    var children = [head];
    if (row.subject) {
      children.push(el('p', { class: 'route__carries', text: shortHash(row.subject, 24) }));
    }
    if (row.evidence && typeof row.evidence === 'object') {
      children.push(el('details', { class: 'evidence' }, [
        el('summary', { text: t('findings.evidence') }),
        el('pre', { class: 'code' }, [el('code', { text: JSON.stringify(row.evidence, null, 2) })])
      ]));
    }
    return el('li', {
      class: 'route' + (contributes === 'deny' ? ' route--open' : (contributes === 'allow' ? ' route--closed' : ''))
    }, children);
  }

  function policyDecisionCards(payload) {
    var decision = payload.decision || {};
    var verdict = String(decision.decision || '').toLowerCase();
    var banner = verdictBanner(
      verdict === 'allow' ? 'pass' : (verdict === 'deny' ? 'fail' : 'inconclusive'),
      'policy.decision.' + verdict
    );

    var head = el('div', { class: 'kv' }, [
      kvRow(t('policy.decision'), document.createTextNode(verdict.toUpperCase()), true),
      kvRow(t('policy.decision.on'), document.createTextNode(payload.decided_on || '?'), true),
      kvRow(t('policy.subject.kind'),
        document.createTextNode((payload.subject && payload.subject.kind) || '?')),
      kvRow(t('policy.subject.name'),
        document.createTextNode((payload.subject && payload.subject.name) || '?'))
    ]);
    head.appendChild(el('p', { class: 'graph__note', text: t('policy.noscore') }));

    var proof = Array.isArray(decision.proof) ? decision.proof : [];
    var cards = [banner, card('policy.decision', null, head)];
    if (proof.length) {
      var body = el('div', {}, [
        el('p', { class: 'card__lede', text: t('policy.proof.lede') }),
        el('ul', { class: 'routes' }, proof.map(policyProofRow))
      ]);
      cards.push(card('policy.proof', String(num(proof.length)), body, true));
    }
    return cards.filter(Boolean);
  }

  function runPolicyDecision(subject) {
    var document_ = state.files.policy;
    if (!document_ || !subject) { return; }
    if (document_.size > MAX_DECLARATION_FIELD_BYTES) {
      state.policy.decision = { status: 'error', message: t('agents.diff.too_big') };
      renderPolicy();
      return;
    }
    state.policy.decision = { status: 'loading' };
    renderPolicy();

    var reader = new FileReader();
    reader.onerror = function () {
      state.policy.decision = { status: 'error', message: t('error.generic') };
      renderPolicy();
    };
    reader.onload = function () {
      upload('/api/policy/check', subject, {
        policy_document: String(reader.result),
        subject: state.policy.subjectKind
      }, {
        onDone: function (payload) {
          state.policy.decision = { status: 'done', payload: payload };
          renderPolicy();
        },
        onError: function (info) {
          state.policy.decision = {
            status: 'error',
            message: (info && info.message) ? info.message : t('error.generic')
          };
          renderPolicy();
        }
      });
    };
    reader.readAsText(document_);
  }

  function runPolicy(file) {
    state.files.policy = file;
    state.data.policy = null;
    state.policy = { subjectKind: state.policy.subjectKind, decision: null };
    state.error.policy = null;
    state.busy.policy = true;
    renderChosen('policy');
    updatePanelChrome('policy');
    outputOf('policy').setAttribute('aria-busy', 'true');
    showState('policy', loadingState('policy', 'loading.policy'));

    upload('/api/policy/show', file, {}, {
      onProgress: function (fraction) { setProgress('policy', fraction); },
      onUploaded: function () { setIndeterminate('policy'); },
      onDone: function (payload) {
        state.busy.policy = false;
        state.data.policy = payload;
        renderPolicy();
      },
      onError: function (info) {
        state.busy.policy = false;
        state.error.policy = info;
        renderPolicy();
      }
    });
  }

  function renderPolicy() {
    updatePanelChrome('policy');
    renderChosen('policy');
    var out = outputOf('policy');
    if (!out) { return; }
    out.setAttribute('aria-busy', state.busy.policy ? 'true' : 'false');

    if (state.busy.policy) { return; }
    if (state.error.policy) { return showState('policy', errorState('policy')); }
    var payload = state.data.policy;
    if (!payload) { return showState('policy', emptyState('policy')); }

    var cards = [
      policySummaryCard(payload.policy),
      policyRulesCard(payload.document),
      policySubjectCard()
    ];
    var decision = state.policy.decision;
    if (decision && decision.status === 'done') {
      cards = cards.concat(policyDecisionCards(decision.payload));
    }
    showState('policy', el('div', { class: 'cards' }, cards.filter(Boolean)));
  }

  /* ── the graph ────────────────────────────────────────────────────────
   *
   * The panel behind `actaira graph` and `actaira impact`. It is the first
   * one that reads something other than the file the operator just handed
   * over: a workspace, chosen when the server was started, holding what
   * previous runs recorded.
   *
   * Three rules, and each of them is a thing the panel refuses to do.
   *
   *   * **It does not traverse.** Focus, upstream, downstream, the hop limit
   *     and impact are all calls into `state/graph.py`. A reachability walk
   *     written here would be a second implementation over the same edges,
   *     and it would agree with the engine right up until it did not.
   *   * **It does not call the recorded graph current.** A relation is not
   *     removed when a later observation stops seeing it, so the heading says
   *     recorded and the per-edge answer to "is it still there" is one of
   *     three values, the third of which is that nothing here knows.
   *   * **It does not write.** Dragging a box moves a box. Nothing on this
   *     panel changes the workspace, which is why it can be read from a
   *     browser at all.
   */

  var GRAPH_DEPTHS = [1, 2, 3, 0];
  var GRAPH_DIRECTIONS = ['both', 'dependents', 'dependencies'];
  var GRAPH_WORKSPACE_STATES = ['absent', 'unreadable', 'older_schema', 'newer_schema'];
  var EVIDENCE_STATES = ['valid', 'stale', 'superseded', 'revoked', 'untrusted'];
  var GRAPH_ZOOM_MIN = 0.3;
  var GRAPH_ZOOM_MAX = 2.5;

  function graphEdgeKey(edge) {
    return edge.from + '\u0000' + (edge.relation || '') + '\u0000' + edge.to;
  }

  /* ── requests ─────────────────────────────────────────────────────── */

  function graphPost(url, body, onDone, onError) {
    postJson(url, body, {
      onDone: onDone,
      onError: onError || function (info) {
        state.graph.busy = false;
        state.graph.error = info;
        renderGraph();
      }
    });
  }

  function loadGraph(keepSelection) {
    state.graph.busy = true;
    state.graph.error = null;
    if (!keepSelection) {
      state.graph.selected = null;
      state.graph.node = null;
      state.graph.route = null;
    }
    renderGraph();

    var body = {};
    if (state.graph.focus) {
      body.focus = state.graph.focus;
      body.direction = state.graph.direction;
      // 0 means "as far as the engine goes", which the server clamps to
      // MAX_DEPTH. The control says `all` rather than a number, because a
      // number here would be a promise about completeness the engine does
      // not make.
      body.depth = state.graph.depth || (state.graph.limits ? state.graph.limits.max_depth : 12);
    }
    graphPost('/api/graph', body, function (payload) {
      state.graph.busy = false;
      state.graph.payload = payload;
      state.graph.needsFit = true;
      state.graph.workspace = payload.workspace || state.graph.workspace;
      if (!state.graph.focus) { state.graph.recorded = payload; }
      renderGraph();
    });
  }

  function loadWorkspace() {
    state.graph.busy = true;
    renderGraph();
    graphPost('/api/workspace', {}, function (payload) {
      state.graph.workspace = payload.workspace || null;
      state.graph.limits = payload.limits || null;
      state.graph.totals = payload.counts || null;
      if (!payload.workspace || payload.workspace.state !== 'ready') {
        state.graph.busy = false;
        state.graph.payload = null;
        renderGraph();
        return;
      }
      loadGraph(false);
    });
  }

  function selectGraphNode(id) {
    state.graph.selected = { type: 'node', id: id };
    state.graph.node = { status: 'loading', id: id };
    renderGraph();
    graphPost('/api/graph/node', { id: id }, function (payload) {
      state.graph.node = { status: 'done', id: id, payload: payload };
      renderGraph();
    }, function (info) {
      state.graph.node = { status: 'error', id: id, message: info.message };
      renderGraph();
    });
  }

  function askGraphImpact(subject) {
    state.graph.impact = { status: 'loading', subject: subject };
    renderGraph();
    graphPost('/api/impact', { subject: subject }, function (payload) {
      state.graph.impact = { status: 'done', subject: subject, payload: payload };
      renderGraph();
    }, function (info) {
      state.graph.impact = { status: 'error', subject: subject, message: info.message };
      renderGraph();
    });
  }

  function focusGraphOn(id, direction) {
    state.graph.focus = id;
    if (direction) { state.graph.direction = direction; }
    state.graph.positions = {};
    state.graph.zoom = 1;
    state.graph.pan = { x: 0, y: 0 };
    loadGraph(true);
    selectGraphNode(id);
  }

  /* ── the model the renderer draws ─────────────────────────────────── */

  /** `asset-graph/v1` plus the view, as nodes and edges for `graphDrawing`.
   *
   *  The filters are applied here rather than in the engine, and they hide
   *  rather than delete: the count of what a filter is hiding is printed
   *  under the drawing, so a reader is never looking at a subset that claims
   *  to be everything. */
  function graphAssetModel(payload) {
    var doc = (payload && payload.graph) || { nodes: [], edges: [] };
    var view = (payload && payload.view) || {};
    var names = view.names || {};
    var current = {};
    ((view.currentness || {}).edges || []).forEach(function (row) {
      current[row.from + '\u0000' + row.relation + '\u0000' + row.to] = row.currentness;
    });
    var nodeCurrent = (view.currentness || {}).nodes || {};

    var visible = {};
    var hiddenNodes = 0;
    var nodes = [];
    (doc.nodes || []).forEach(function (node) {
      var kind = graphNodeKind(node.id);
      if (state.graph.hiddenKinds[kind]) { hiddenNodes += 1; return; }
      visible[node.id] = true;
      var tone = '';
      if (state.graph.focus && node.id === state.graph.focus) { tone = 'focus'; }
      else if (nodeCurrent[node.id] === 'not_in_latest_observation') { tone = 'gone'; }
      nodes.push({
        id: node.id,
        kind: kind,
        label: node.id,
        detail: names[node.id] || '',
        tone: tone
      });
    });

    var hiddenEdges = 0;
    var edges = [];
    (doc.edges || []).forEach(function (edge) {
      if (state.graph.hiddenRelations[edge.relation]) { hiddenEdges += 1; return; }
      if (!visible[edge.from] || !visible[edge.to]) { hiddenEdges += 1; return; }
      edges.push({
        from: edge.from,
        to: edge.to,
        relation: edge.relation,
        stated_by: edge.stated_by,
        evidence_id: edge.evidence_id,
        currentness: current[graphEdgeKey(edge)] || 'undetermined'
      });
    });

    return {
      nodes: nodes,
      edges: edges,
      layout: 'layered',
      hidden: hiddenNodes + hiddenEdges
    };
  }

  /* ── the interactive viewport ─────────────────────────────────────── */

  /** The graph, inside a box it cannot grow out of.
   *
   *  A workspace with three hundred assets draws several thousand pixels
   *  wide, and letting the document take that width would make the whole page
   *  scroll sideways on a phone for the sake of one panel. So the drawing
   *  lives in a bounded viewport with its own zoom and pan, and the page
   *  itself never widens. */
  function graphViewport(model, ariaLabel) {
    // A highlighted impact route lights its edges and the boxes at both ends
    // of each of them, so the chain reads as a chain rather than as a set of
    // brighter lines between unrelated boxes.
    var highlight = {};
    (state.graph.route || []).forEach(function (key) {
      highlight[key] = true;
      var ends = key.split('\u0000');
      highlight[ends[0]] = true;
      highlight[ends[2]] = true;
    });

    var svg = graphDrawing(model, ariaLabel, {
      positions: state.graph.positions,
      selected: state.graph.selected,
      highlight: highlight,
      onSelect: function (choice) {
        if (choice.type === 'node') {
          selectGraphNode(choice.id);
          return;
        }
        state.graph.selected = choice;
        state.graph.node = null;
        renderGraph();
      }
    });
    if (!svg) { return null; }

    var frame = el('div', { class: 'gr__frame' }, [svg]);
    var zoom = state.graph.zoom || 1;
    var pan = state.graph.pan || { x: 0, y: 0 };

    function apply() {
      svg._scene.setAttribute('transform',
        'translate(' + pan.x + ' ' + pan.y + ') scale(' + zoom + ')');
      state.graph.zoom = zoom;
      state.graph.pan = { x: pan.x, y: pan.y };
    }
    apply();

    frame.addEventListener('wheel', function (event) {
      event.preventDefault();
      var before = zoom;
      zoom = Math.min(GRAPH_ZOOM_MAX, Math.max(GRAPH_ZOOM_MIN,
        zoom * (event.deltaY < 0 ? 1.12 : 1 / 1.12)));
      // Keep the point under the cursor where it was, which is what makes a
      // wheel zoom feel like a magnifier rather than a jump.
      var box = frame.getBoundingClientRect();
      var x = event.clientX - box.left, y = event.clientY - box.top;
      pan.x = x - ((x - pan.x) / before) * zoom;
      pan.y = y - ((y - pan.y) / before) * zoom;
      apply();
    }, { passive: false });

    var dragging = null;
    // The distance a pointer has to travel before this is a drag rather than
    // a click. Below it nothing is captured at all, and that is the point:
    // `setPointerCapture` on the frame redirects the eventual `click` to the
    // frame, so capturing on every press made a plain click on a node land on
    // the background and deselect instead of selecting. Capture starts when a
    // drag does.
    var DRAG_SLOP = 3;
    frame.addEventListener('pointerdown', function (event) {
      var group = event.target.closest ? event.target.closest('.graph__nodegroup') : null;
      var id = group ? group._nodeId : null;
      dragging = {
        node: id,
        group: group,
        pointer: event.pointerId,
        captured: false,
        x: event.clientX,
        y: event.clientY,
        origin: id ? { x: svg._positions[id].x, y: svg._positions[id].y } : { x: pan.x, y: pan.y },
        moved: false
      };
    });
    frame.addEventListener('pointermove', function (event) {
      if (!dragging) { return; }
      var dx = event.clientX - dragging.x, dy = event.clientY - dragging.y;
      if (!dragging.moved && Math.abs(dx) <= DRAG_SLOP && Math.abs(dy) <= DRAG_SLOP) { return; }
      if (!dragging.captured) {
        dragging.moved = true;
        dragging.captured = true;
        frame.setPointerCapture(dragging.pointer);
        frame.classList.add('is-grabbing');
      }
      if (dragging.node) {
        var x = dragging.origin.x + dx / zoom;
        var y = dragging.origin.y + dy / zoom;
        svg._moveNode(dragging.node, x, y);
        // Presentation state, and nowhere else. A box's coordinates are not
        // an assurance claim and are never written to the workspace.
        state.graph.positions[dragging.node] = { x: x, y: y };
        if (dragging.group) { dragging.group._dragged = true; }
        return;
      }
      pan.x = dragging.origin.x + dx;
      pan.y = dragging.origin.y + dy;
      apply();
    });
    ['pointerup', 'pointercancel'].forEach(function (name) {
      frame.addEventListener(name, function () {
        dragging = null;
        frame.classList.remove('is-grabbing');
      });
    });
    frame.addEventListener('click', function (event) {
      if (event.target === frame || event.target === svg) {
        state.graph.selected = null;
        state.graph.node = null;
        renderGraph();
      }
    });

    /* Returns whether it could do anything, which matters more than it
     * looks: the panel is `hidden` until its tab is selected, a hidden
     * element measures zero, and a fit that silently did nothing while
     * reporting success left a wide graph opening with most of itself
     * outside its own viewport. */
    frame._fit = function () {
      var box = frame.getBoundingClientRect();
      var width = svg._layout.width, height = svg._layout.height;
      if (!width || !height || !box.width || !box.height) { return false; }
      zoom = Math.min(GRAPH_ZOOM_MAX, Math.max(GRAPH_ZOOM_MIN,
        Math.min(box.width / (width + 24), box.height / (height + 24))));
      pan.x = (box.width - width * zoom) / 2;
      pan.y = 12;
      apply();
      return true;
    };
    frame._zoomBy = function (factor) {
      zoom = Math.min(GRAPH_ZOOM_MAX, Math.max(GRAPH_ZOOM_MIN, zoom * factor));
      apply();
    };
    return frame;
  }

  /** The same relations as text.
   *
   *  Not a fallback nobody maintains: this is how the graph is read without a
   *  mouse and how a screen reader gets at the provenance that the drawing
   *  puts in a `<title>`. Every line carries the relation and who stated it,
   *  which is the whole claim. */
  function graphListView(model) {
    if (!model.edges.length) {
      return el('p', { class: 'empty__text', text: t('gr.node.no_relations') });
    }
    var rows = model.edges.map(function (edge) {
      var line = el('li', { class: 'grlist__row' }, [
        el('button', {
          type: 'button', class: 'grlist__end',
          onclick: function () { selectGraphNode(edge.from); }
        }, [document.createTextNode(edge.from)]),
        el('span', { class: 'grlist__rel', text: edge.relation }),
        el('button', {
          type: 'button', class: 'grlist__end',
          onclick: function () { selectGraphNode(edge.to); }
        }, [document.createTextNode(edge.to)])
      ]);
      var said = el('p', { class: 'grlist__said' }, [
        document.createTextNode(t('gr.edge.stated_by') + ': '),
        el('span', { class: edge.stated_by ? '' : 'grlist__unstated',
          text: edge.stated_by || t('graph.unstated') })
      ]);
      if (edge.evidence_id) {
        said.appendChild(document.createTextNode(' · ' + t('gr.edge.evidence') + ': '));
        said.appendChild(el('code', { class: 'grlist__ev', text: edge.evidence_id }));
      }
      return el('li', { class: 'grlist__item' }, [line, said]);
    });
    return el('div', {}, [
      el('p', { class: 'card__lede', text: t('gr.list.lede') }),
      el('ul', { class: 'grlist' }, rows)
    ]);
  }

  /* ── controls ─────────────────────────────────────────────────────── */

  function graphSegmented(labelKey, values, chosen, describe, onPick) {
    var group = el('div', { class: 'segmented' });
    group.setAttribute('role', 'group');
    group.setAttribute('aria-label', t(labelKey));
    values.forEach(function (value) {
      var button = el('button', {
        class: 'segmented__btn', type: 'button', text: describe(value)
      });
      button.setAttribute('aria-pressed', value === chosen ? 'true' : 'false');
      button.addEventListener('click', function () { onPick(value); });
      group.appendChild(button);
    });
    return group;
  }

  function graphSearchRow() {
    var input = el('input', {
      class: 'field__control gr__search', type: 'search', id: 'gr-search',
      value: state.graph.search || ''
    });
    input.setAttribute('aria-label', t('gr.search'));
    input.setAttribute('placeholder', t('gr.search'));
    function submit() {
      state.graph.search = input.value;
      runGraphSearch(input.value);
    }
    input.addEventListener('keydown', function (event) {
      if (event.key === 'Enter') { event.preventDefault(); submit(); }
    });
    return el('div', { class: 'gr__searchrow' }, [
      input,
      el('button', { type: 'button', class: 'btn', onclick: submit }, [
        svgIcon('i-inspect'), document.createTextNode(t('gr.search.go'))
      ])
    ]);
  }

  /** Search over what the workspace records, and nothing fuzzier.
   *
   *  A substring of an id, a name or a digest. No edit distance, no
   *  "did you mean": an asset graph is a place where two names being similar
   *  means nothing at all, and a search that guessed would be the same
   *  mistake as an edge inferred from a name. An exact id or digest is
   *  resolved by the engine, which is the only thing that knows how a digest
   *  maps to an asset. */
  function runGraphSearch(text) {
    var needle = String(text || '').trim().toLowerCase();
    state.graph.matches = null;
    if (!needle) { renderGraph(); return; }

    var source = state.graph.recorded || state.graph.payload;
    var names = ((source || {}).view || {}).names || {};
    var found = [];
    (((source || {}).graph || {}).nodes || []).forEach(function (node) {
      var id = String(node.id || '');
      var name = String(names[node.id] || '');
      var digest = String(node.digest || '');
      if (id.toLowerCase().indexOf(needle) !== -1
        || name.toLowerCase().indexOf(needle) !== -1
        || digest.toLowerCase().indexOf(needle) !== -1) {
        found.push({ id: id, name: name, digest: digest });
      }
    });
    if (found.length) {
      state.graph.matches = found.slice(0, 24);
      renderGraph();
      return;
    }
    // Nothing matched here, which does not mean the workspace has never
    // heard of it: a digest is resolved to an asset by the engine.
    graphPost('/api/graph/node', { id: String(text).trim() }, function (payload) {
      if (payload.found) {
        state.graph.matches = [{ id: payload.node.id, name: payload.node.name,
          digest: payload.node.digest }];
      } else {
        state.graph.matches = [];
      }
      renderGraph();
    }, function () {
      state.graph.matches = [];
      renderGraph();
    });
  }

  function graphMatchesCard() {
    var matches = state.graph.matches;
    if (matches === null || matches === undefined) { return null; }
    if (!matches.length) {
      return card('gr.search.results', null,
        el('p', { class: 'empty__text', text: t('gr.search.none') }));
    }
    var list = el('ul', { class: 'grmatch' }, matches.map(function (row) {
      return el('li', {}, [
        el('button', {
          type: 'button', class: 'grmatch__hit',
          onclick: function () { focusGraphOn(row.id); }
        }, [
          el('code', { class: 'grmatch__id', text: row.id }),
          row.name ? el('span', { class: 'grmatch__name', text: row.name }) : null
        ].filter(Boolean))
      ]);
    }));
    return card('gr.search.results', String(num(matches.length)), list, true);
  }

  function graphFilterRow(labelKey, values, hidden, onToggle) {
    if (!values.length) { return null; }
    var chips = values.map(function (value) {
      var on = !hidden[value];
      var chip = el('button', {
        class: 'chip' + (on ? ' chip--on' : ''), type: 'button', text: value
      });
      chip.setAttribute('aria-pressed', on ? 'true' : 'false');
      chip.addEventListener('click', function () { onToggle(value); });
      return chip;
    });
    return el('div', { class: 'gr__filter' }, [
      el('span', { class: 'gr__filterlabel', text: t(labelKey) }),
      el('div', { class: 'chips' }, chips)
    ]);
  }

  function graphControlsCard() {
    var payload = state.graph.payload;
    var view = (payload && payload.view) || {};
    var kinds = Object.keys(view.kinds || {}).sort();
    var relations = [];
    (((payload || {}).graph || {}).edges || []).forEach(function (edge) {
      if (relations.indexOf(edge.relation) === -1) { relations.push(edge.relation); }
    });
    relations.sort();

    var rows = [
      el('div', { class: 'gr__row' }, [
        graphSegmented('gr.mode', ['recorded', 'focus'], state.graph.focus ? 'focus' : 'recorded',
          function (value) { return t('gr.mode.' + value); },
          function (value) {
            if (value === 'recorded') {
              state.graph.focus = '';
              state.graph.positions = {};
              loadGraph(true);
            } else if (state.graph.selected && state.graph.selected.type === 'node') {
              focusGraphOn(state.graph.selected.id);
            }
          }),
        graphSegmented('gr.view.graph', ['graph', 'list'], state.graph.view,
          function (value) { return t('gr.view.' + value); },
          function (value) { state.graph.view = value; renderGraph(); })
      ]),
      graphSearchRow()
    ];

    if (state.graph.focus) {
      rows.push(el('div', { class: 'gr__row' }, [
        graphSegmented('gr.direction', GRAPH_DIRECTIONS, state.graph.direction,
          function (value) { return t('gr.direction.' + value); },
          function (value) { state.graph.direction = value; loadGraph(true); }),
        graphSegmented('gr.depth', GRAPH_DEPTHS, state.graph.depth,
          function (value) { return value ? String(value) : t('gr.depth.all'); },
          function (value) { state.graph.depth = value; loadGraph(true); })
      ]));
    }

    var filters = [
      graphFilterRow('gr.filters.kinds', kinds, state.graph.hiddenKinds, function (value) {
        state.graph.hiddenKinds[value] = !state.graph.hiddenKinds[value];
        renderGraph();
      }),
      graphFilterRow('gr.filters.relations', relations, state.graph.hiddenRelations,
        function (value) {
          state.graph.hiddenRelations[value] = !state.graph.hiddenRelations[value];
          renderGraph();
        })
    ].filter(Boolean);

    return card('gr.mode', null, el('div', { class: 'gr__controls' }, rows.concat(filters)));
  }

  /* ── the cards ────────────────────────────────────────────────────── */

  function graphWorkspaceCard() {
    var workspace = state.graph.workspace || {};
    var totals = state.graph.totals || {};
    var body = el('div', { class: 'kv' }, [
      kvRow(t('gr.workspace.reading'), document.createTextNode(workspace.label || '?'), true),
      kvRow(t('gr.workspace.nodes'), document.createTextNode(num(totals.nodes || 0))),
      kvRow(t('gr.workspace.edges'), document.createTextNode(num(totals.edges || 0))),
      kvRow(t('gr.workspace.sources'), document.createTextNode(num(totals.sources || 0))),
      kvRow(t('gr.workspace.evidence'), document.createTextNode(num(totals.evidence || 0)))
    ]);
    // Outside the key/value grid, not inside it: a paragraph dropped into a
    // grid cell gets one column's width and wraps into a narrow ribbon.
    return card('gr.workspace', null, el('div', {}, [
      body,
      el('p', { class: 'graph__note graph__note--wide', text: t('gr.recorded.note') })
    ]));
  }

  function graphNoWorkspaceState() {
    var workspace = state.graph.workspace || { state: 'absent' };
    var known = GRAPH_WORKSPACE_STATES.indexOf(workspace.state) === -1
      ? 'absent' : workspace.state;
    return el('div', { class: 'state' }, [
      svgIcon('i-graph', 'icon state__icon'),
      el('p', { class: 'state__title', text: t('gr.' + known + '.title') }),
      el('p', { class: 'state__text', text: t('gr.empty.text') })
    ]);
  }

  function graphCurrentnessNote(view) {
    var counts = ((view.currentness || {}).counts || {}).edges || {};
    var parts = [];
    ['current', 'not_in_latest_observation', 'undetermined'].forEach(function (name) {
      if (counts[name]) {
        parts.push(num(counts[name]) + ' ' + t('gr.current.short.' + name));
      }
    });
    if (!parts.length) { return null; }
    return el('p', { class: 'graph__note', text: parts.join(' · ') });
  }

  function graphDrawingCard(model) {
    var payload = state.graph.payload || {};
    var view = payload.view || {};
    var doc = payload.graph || { nodes: [], edges: [] };

    if (!doc.nodes.length) {
      return card('gr.recorded', null, el('div', { class: 'state' }, [
        el('p', { class: 'state__title', text: t('gr.empty_graph.title') }),
        el('p', { class: 'state__text', text: t('gr.empty_graph.text') })
      ]));
    }
    if (!doc.edges.length) {
      return card('gr.recorded', String(num(doc.nodes.length)), el('div', { class: 'state' }, [
        el('p', { class: 'state__title', text: t('gr.no_edges.title') }),
        el('p', { class: 'state__text', text: t('gr.no_edges.text') })
      ]));
    }

    var children = [];
    var aria = t('gr.aria.graph', {
      nodes: num(doc.nodes.length), edges: num(doc.edges.length)
    });

    if (state.graph.view === 'list') {
      children.push(graphListView(model));
    } else {
      var frame = graphViewport(model, aria);
      if (frame) {
        // Fitted once, when a new graph arrives. Not on every render: a
        // reader who has zoomed in on a corner and then clicks a node would
        // otherwise be thrown back out to the whole picture each time.
        graphPendingFit = state.graph.needsFit ? frame : null;
        children.push(el('div', { class: 'gr__tools' }, [
          el('button', { type: 'button', class: 'btn btn--small',
            onclick: function () { frame._fit(); }, text: t('gr.fit') }),
          el('button', { type: 'button', class: 'btn btn--small',
            onclick: function () { frame._zoomBy(1.2); }, text: t('gr.zoom_in') }),
          el('button', { type: 'button', class: 'btn btn--small',
            onclick: function () { frame._zoomBy(1 / 1.2); }, text: t('gr.zoom_out') })
        ]));
        children.push(frame);
        children.push(el('p', { class: 'graph__note', text: t('gr.drag_note') }));
      }
    }

    var provenance = graphProvenanceNote(model.edges);
    if (provenance) { children.push(provenance); }
    var current = graphCurrentnessNote(view);
    if (current) { children.push(current); }
    children.push(el('p', { class: 'graph__note', text: t('gr.current.lede') }));
    if (model.hidden) {
      children.push(el('p', { class: 'graph__note',
        text: t('gr.filters.hidden', { n: num(model.hidden) }) }));
    }
    var walked = view.neighbourhood;
    if (walked && walked.truncated) {
      children.push(el('p', { class: 'note note--warn', text: t('gr.truncated') }));
    }
    if (doc.cycles && doc.cycles.length) {
      children.push(el('p', { class: 'route__subhead', text: t('gr.cycles') }));
      children.push(el('p', { class: 'graph__note', text: t('gr.cycles.lede') }));
      children.push(el('ul', { class: 'route__list' }, doc.cycles.slice(0, 12).map(function (cycle) {
        return el('li', { text: cycle.join(' → ') });
      })));
    }
    if (doc.cycles_may_be_incomplete) {
      children.push(el('p', { class: 'note note--warn', text: t('gr.cycles.incomplete') }));
    }

    var count = String(num(doc.nodes.length)) + ' · ' + String(num(doc.edges.length));
    return card('gr.recorded', count, el('div', {}, children), true);
  }

  /** "Is this still there?", as a chip.
   *
   *  Short text on the chip and the whole sentence in its title, because the
   *  full wording of `undetermined` repeated down a list of twelve relations
   *  is noise a reader learns to skip - and the one thing this panel cannot
   *  afford is a reader who has learned to skip the uncertainty. */
  function graphCurrentChip(value) {
    var known = ['current', 'not_in_latest_observation', 'undetermined'].indexOf(value) === -1
      ? 'undetermined' : value;
    var chip = el('span', {
      class: 'grcur grcur--' + known,
      text: t('gr.current.short.' + known)
    });
    chip.setAttribute('title', t('gr.current.' + known));
    return chip;
  }

  /** A stored timestamp, to the second.
   *
   *  A display trim and nothing more: the store keeps microseconds and the
   *  panel shows `2026-09-12 12:50:58 UTC`, because six decimal places of a
   *  second is precision nobody reads and it pushes the value onto a second
   *  line. The full value is in the title. */
  function graphMoment(value) {
    var text = String(value || '');
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(text)) { return null; }
    var shown = text.slice(0, 10) + ' ' + text.slice(11, 19) + ' UTC';
    var node = el('span', { class: 'kv__val kv__val--mono', text: shown });
    node.setAttribute('title', text);
    return node;
  }

  function graphRelationRow(edge, other, incoming) {
    var children = [
      el('div', { class: 'route__head' }, [
        el('span', { class: 'badge badge--quiet', text: edge.relation }),
        el('button', {
          type: 'button', class: 'grlist__end',
          onclick: function () { selectGraphNode(other); }
        }, [document.createTextNode(other)])
      ]),
      el('p', { class: 'grlist__said' }, [
        document.createTextNode(t('gr.edge.stated_by') + ': '),
        el('span', {
          class: edge.stated_by ? '' : 'grlist__unstated',
          text: edge.stated_by || t('graph.unstated')
        })
      ])
    ];
    if (edge.evidence_id) {
      children.push(el('p', { class: 'grlist__said' }, [
        document.createTextNode(t('gr.edge.evidence') + ': '),
        el('code', { class: 'grlist__ev', text: edge.evidence_id })
      ]));
    } else {
      children.push(el('p', { class: 'grlist__said grlist__unstated',
        text: t('gr.edge.no_evidence') }));
    }
    children.push(graphCurrentChip(edge.currentness));
    return el('li', { class: 'route' + (incoming ? '' : '') }, children);
  }

  function graphEvidenceCard(evidence) {
    if (!evidence || !evidence.total) {
      return card('gr.evidence', '0',
        el('p', { class: 'empty__text', text: t('gr.evidence.none') }));
    }
    var chips = el('div', { class: 'chips' }, EVIDENCE_STATES.map(function (name) {
      var count = (evidence.counts || {})[name] || 0;
      if (!count) { return null; }
      return el('span', { class: 'ev ev--' + name,
        text: num(count) + ' ' + t('gr.evidence.' + name) });
    }).filter(Boolean));
    var rows = el('ul', { class: 'route__list' }, evidence.records.slice(0, 12).map(function (row) {
      var moment = String(row.observed_at || '');
      return el('li', { text: row.kind + ' · ' + t('gr.evidence.' + row.state)
        + ' · ' + (moment.length > 19 ? moment.slice(0, 19).replace('T', ' ') : moment) });
    }));
    return card('gr.evidence', String(num(evidence.total)),
      el('div', {}, [chips, rows]));
  }

  function graphNodeCard() {
    var chosen = state.graph.node;
    if (!chosen) { return null; }
    if (chosen.status === 'loading') {
      return card('gr.selected.node', null,
        el('p', { class: 'route__note', text: t('loading.graph') }));
    }
    if (chosen.status === 'error') {
      return card('gr.selected.node', null,
        el('p', { class: 'route__note', text: chosen.message }));
    }
    var payload = chosen.payload;
    var node = payload.node;
    if (!payload.found) {
      return card('gr.selected.node', null,
        el('p', { class: 'empty__text', text: t('gr.node.unknown') }));
    }

    var body = el('div', { class: 'kv' }, [
      kvRow(t('gr.node.kind'), document.createTextNode(node.kind), true),
      node.name ? kvRow(t('gr.node.name'), document.createTextNode(node.name)) : null,
      node.source ? kvRow(t('gr.node.source'), document.createTextNode(node.source), true) : null,
      node.first_seen ? kvRow(t('gr.node.first_seen'),
        graphMoment(node.first_seen) || document.createTextNode(node.first_seen)) : null,
      node.last_seen ? kvRow(t('gr.node.last_seen'),
        graphMoment(node.last_seen) || document.createTextNode(node.last_seen)) : null,
      node.last_snapshot
        ? kvRow(t('gr.node.last_snapshot'), document.createTextNode(shortHash(node.last_snapshot, 18)), true)
        : null,
      kvRow(t('gr.current'), graphCurrentChip(node.currentness))
    ].filter(Boolean));
    if (node.digest) { body.appendChild(hashBlock('gr.node.digest', node.digest)); }
    if (node.attributes && Object.keys(node.attributes).length) {
      body.appendChild(el('details', { class: 'evidence' }, [
        el('summary', { text: t('gr.node.attributes') }),
        el('pre', { class: 'code' }, [
          el('code', { text: JSON.stringify(node.attributes, null, 2) })
        ])
      ]));
    }

    var actions = el('div', { class: 'actions' }, [
      el('button', { type: 'button', class: 'btn btn--primary', text: t('gr.action.impact'),
        onclick: function () { askGraphImpact(node.id); } }),
      el('button', { type: 'button', class: 'btn', text: t('gr.action.focus'),
        onclick: function () { focusGraphOn(node.id, 'both'); } }),
      el('button', { type: 'button', class: 'btn', text: t('gr.action.dependents'),
        onclick: function () { focusGraphOn(node.id, 'dependents'); } }),
      el('button', { type: 'button', class: 'btn', text: t('gr.action.dependencies'),
        onclick: function () { focusGraphOn(node.id, 'dependencies'); } })
    ]);

    var cards = [card('gr.selected.node', node.id, el('div', {}, [body, actions]))];

    var incoming = payload.incoming || [];
    var outgoing = payload.outgoing || [];
    if (!incoming.length && !outgoing.length) {
      cards.push(card('gr.node.incoming', '0',
        el('p', { class: 'empty__text', text: t('gr.node.no_relations') })));
    }
    if (incoming.length) {
      cards.push(card('gr.node.incoming', String(num(incoming.length)),
        el('ul', { class: 'routes' }, incoming.map(function (edge) {
          return graphRelationRow(edge, edge.from, true);
        })), true));
    }
    if (outgoing.length) {
      cards.push(card('gr.node.outgoing', String(num(outgoing.length)),
        el('ul', { class: 'routes' }, outgoing.map(function (edge) {
          return graphRelationRow(edge, edge.to, false);
        })), true));
    }
    cards.push(graphEvidenceCard(payload.evidence));
    return cards;
  }

  /** An edge, which is a claim, shown as one.
   *
   *  Provenance is never behind a generic line here: `stated_by` is a field
   *  of its own, and an edge that arrives without one says `unstated` rather
   *  than looking like a declared edge with an empty label. */
  function graphEdgeCard() {
    var chosen = state.graph.selected;
    if (!chosen || chosen.type !== 'edge') { return null; }
    var edge = chosen.edge;
    var body = el('div', { class: 'kv' }, [
      kvRow(t('gr.edge.relation'), document.createTextNode(edge.relation || '?'), true),
      kvRow(t('gr.edge.from'), el('button', {
        type: 'button', class: 'grlist__end',
        onclick: function () { selectGraphNode(edge.from); }
      }, [document.createTextNode(edge.from)])),
      kvRow(t('gr.edge.to'), el('button', {
        type: 'button', class: 'grlist__end',
        onclick: function () { selectGraphNode(edge.to); }
      }, [document.createTextNode(edge.to)])),
      kvRow(t('gr.edge.stated_by'), el('span', {
        class: 'kv__val' + (edge.stated_by ? ' kv__val--mono' : ' grlist__unstated'),
        text: edge.stated_by || t('graph.unstated')
      })),
      kvRow(t('gr.edge.evidence'), el('span', {
        class: 'kv__val' + (edge.evidence_id ? ' kv__val--mono' : ' grlist__unstated'),
        text: edge.evidence_id || t('gr.edge.no_evidence')
      })),
      kvRow(t('gr.current'), graphCurrentChip(edge.currentness))
    ]);
    return card('gr.selected.edge', null, body);
  }

  /* ── impact ───────────────────────────────────────────────────────── */

  function graphImpactCards() {
    var asked = state.graph.impact;
    if (!asked) { return []; }
    if (asked.status === 'loading') {
      return [card('gr.impact', null, el('p', { class: 'route__note', text: t('loading.graph') }))];
    }
    if (asked.status === 'error') {
      return [card('gr.impact', null, el('p', { class: 'route__note', text: asked.message }))];
    }
    var payload = asked.payload;
    var document_ = payload.impact || {};
    var kinds = payload.kinds || {};

    if (!document_.found) {
      return [card('gr.impact', null, el('div', {}, [
        el('p', { class: 'route__subhead', text: t('gr.impact.changed') }),
        el('code', { class: 'finding__rule', text: document_.changed || asked.subject }),
        el('p', { class: 'empty__text', text: t('gr.impact.unknown') })
      ]))];
    }

    var head = el('div', {}, [
      el('p', { class: 'route__subhead', text: t('gr.impact.changed') }),
      el('code', { class: 'finding__rule', text: document_.changed })
    ]);
    var affected = document_.affected || [];
    if (!affected.length) {
      head.appendChild(el('p', { class: 'empty__text', text: t('gr.impact.none') }));
      return [card('gr.impact', '0', head)];
    }

    head.appendChild(el('p', { class: 'route__subhead', text: t('gr.impact.by_kind') }));
    head.appendChild(el('div', { class: 'chips' },
      Object.keys(document_.by_kind || {}).sort().map(function (kind) {
        return el('span', { class: 'chip chip--on', text: num(document_.by_kind[kind]) + ' ' + kind });
      })));

    var rows = affected.map(function (row) {
      var hops = row.hops === 1 ? t('gr.impact.hop') : t('gr.impact.hops', { n: num(row.hops) });
      var children = [
        el('div', { class: 'route__head' }, [
          el('span', { class: 'badge badge--quiet', text: hops }),
          el('button', {
            type: 'button', class: 'grlist__end',
            onclick: function () { selectGraphNode(row.asset); }
          }, [document.createTextNode(row.asset)]),
          el('span', { class: 'grlist__rel', text: kinds[row.asset] || graphNodeKind(row.asset) })
        ]),
        el('p', { class: 'route__subhead', text: t('gr.impact.why') })
      ];
      // The route, hop by hop, each one keeping its relation and the thing
      // that stated it. `why` alone would be a sentence; this is the claim.
      children.push(el('ul', { class: 'route__list' }, (row.route || []).map(function (hop) {
        var line = el('li', {}, [
          el('code', { class: 'grlist__ev', text: hop.from }),
          document.createTextNode(' —' + hop.relation + '→ '),
          el('code', { class: 'grlist__ev', text: hop.to }),
          el('span', { class: 'grlist__said',
            text: ' ' + t('gr.edge.stated_by') + ': ' + (hop.stated_by || t('graph.unstated')) })
        ]);
        if (hop.evidence_id) {
          line.appendChild(el('span', { class: 'grlist__said',
            text: ' · ' + t('gr.edge.evidence') + ': ' + hop.evidence_id }));
        }
        return line;
      })));
      children.push(el('button', {
        type: 'button', class: 'btn btn--small', text: t('gr.impact.highlight'),
        onclick: function () {
          state.graph.route = (row.route || []).map(graphEdgeKey);
          state.graph.view = 'graph';
          renderGraph();
        }
      }));
      return el('li', { class: 'route route--open' }, children);
    });

    var cards = [
      card('gr.impact', String(num(affected.length)), head),
      card('gr.impact.affected', null, el('ul', { class: 'routes' }, rows), true)
    ];
    if (document_.truncated) {
      cards.push(el('p', { class: 'note note--warn', text: t('gr.impact.truncated') }));
    }
    return cards;
  }

  /* ── the panel ────────────────────────────────────────────────────── */

  /* The frame waiting to be fitted, if a new graph arrived in this render.
   * A fit needs the element's laid-out size, so it happens after the panel is
   * in the document rather than while it is being built. */
  var graphPendingFit = null;

  function renderGraph() {
    var out = document.getElementById('out-graph');
    if (!out) { return; }
    out.setAttribute('aria-busy', state.graph.busy ? 'true' : 'false');

    if (state.graph.busy && !state.graph.payload) {
      clear(out);
      out.appendChild(el('div', { class: 'state' }, [
        el('p', { class: 'state__title', text: t('loading.graph') })
      ]));
      return;
    }
    if (state.graph.error) {
      clear(out);
      out.appendChild(el('div', { class: 'state state--error', role: 'alert' }, [
        svgIcon('i-alert', 'icon state__icon'),
        el('p', { class: 'state__title', text: t('error.title') }),
        el('p', { class: 'state__text', text: state.graph.error.message || t('error.network') }),
        el('div', { class: 'actions' }, [
          el('button', { type: 'button', class: 'btn', text: t('error.retry'),
            onclick: function () { loadWorkspace(); } })
        ])
      ]));
      return;
    }
    var workspace = state.graph.workspace;
    if (!workspace || workspace.state !== 'ready') {
      clear(out);
      out.appendChild(graphNoWorkspaceState());
      return;
    }

    graphPendingFit = null;
    var model = graphAssetModel(state.graph.payload);
    var cards = [graphWorkspaceCard(), graphControlsCard(), graphMatchesCard(),
      graphDrawingCard(model), graphEdgeCard()];
    var nodeCards = graphNodeCard();
    if (nodeCards) { cards = cards.concat(nodeCards); }
    if (!state.graph.node && !(state.graph.selected && state.graph.selected.type === 'edge')) {
      cards.push(card('gr.selected.node', null,
        el('p', { class: 'empty__text', text: t('gr.selected.none') })));
    }
    cards = cards.concat(graphImpactCards());

    clear(out);
    out.appendChild(el('div', { class: 'cards' }, cards.filter(Boolean)));
    if (graphPendingFit) {
      // Only cleared when the fit actually happened. A panel that is still
      // hidden measures zero, and marking it fitted anyway is how a graph
      // ends up opening at 1:1 with most of itself off the edge.
      if (graphPendingFit._fit()) { state.graph.needsFit = false; }
      graphPendingFit = null;
    }
  }

  var RUNNERS = {
    inspect: runInspect, agents: runAgents, policy: runPolicy, attest: runAttest,
    verify: runVerify, govern: runGovernance
  };
  var RENDERERS = {
    inspect: renderInspect, agents: renderAgents, policy: renderPolicy, attest: renderAttest,
    verify: renderVerify, govern: renderGovern
  };

  function rerun(tab) {
    if (tab === 'inspect' && state.sample.inspect) {
      runSample(state.sample.inspect);
      return;
    }
    var file = state.files[tab];
    if (!file) {
      state.error[tab] = { message: t('error.no_file') };
      RENDERERS[tab]();
      return;
    }
    RUNNERS[tab](file);
  }

  /** The welcome screen and the sample strip are the empty state for the
   *  Inspect tab, so they step aside the moment there is a report. */
  function updatePanelChrome(tab) {
    var panel = document.getElementById('panel-' + tab);
    if (!panel) { return; }
    var settled = !!(state.data[tab] || state.error[tab]);
    panel.classList.toggle('panel--busy', !!state.busy[tab]);
    panel.classList.toggle('panel--done', !state.busy[tab] && settled);
    if (tab !== 'inspect') { return; }
    var active = state.busy.inspect || settled;
    var welcome = document.getElementById('welcome-inspect');
    var samples = document.getElementById('samples-inspect');
    if (welcome) { welcome.hidden = active; }
    if (samples) { samples.hidden = active || !state.samples.length; }
  }

  function renderChosen(tab) {
    var node = document.getElementById('chosen-' + tab);
    if (!node) { return; }
    var file = state.files[tab];
    var sample = tab === 'inspect' ? state.sample.inspect : null;
    if (!file && !sample) { node.hidden = true; clear(node); return; }
    clear(node);
    node.hidden = false;
    node.appendChild(svgIcon('i-file'));
    if (sample) {
      node.appendChild(document.createTextNode(sample.name + ' · ' + bytes(sample.size_bytes)));
      node.appendChild(el('span', { class: 'badge badge--mono', text: t('sample.badge') }));
      return;
    }
    node.appendChild(document.createTextNode(file.name + ' · ' + bytes(file.size)));
  }

  function acceptFile(tab, file) {
    if (!file) { return; }
    if (file.size === 0) {
      state.error[tab] = { message: t('drop.wrong_type'), detail: file.name };
      state.files[tab] = null;
      RENDERERS[tab]();
      return;
    }
    RUNNERS[tab](file);
  }

  function wireDropzone(tab) {
    var zone = document.getElementById('dz-' + tab);
    var input = document.getElementById('file-' + tab);
    if (!zone || !input) { return; }

    zone.addEventListener('click', function () { input.click(); });

    input.addEventListener('change', function () {
      var file = input.files && input.files[0];
      input.value = '';           // so the same file can be chosen twice
      acceptFile(tab, file);
    });

    var depth = 0;
    zone.addEventListener('dragenter', function (event) {
      event.preventDefault();
      depth += 1;
      zone.classList.add('is-dragover');
    });
    zone.addEventListener('dragover', function (event) {
      event.preventDefault();
      if (event.dataTransfer) { event.dataTransfer.dropEffect = 'copy'; }
    });
    zone.addEventListener('dragleave', function () {
      depth = Math.max(0, depth - 1);
      if (depth === 0) { zone.classList.remove('is-dragover'); }
    });
    zone.addEventListener('drop', function (event) {
      event.preventDefault();
      depth = 0;
      zone.classList.remove('is-dragover');
      var files = event.dataTransfer && event.dataTransfer.files;
      if (files && files.length) { acceptFile(tab, files[0]); }
    });
  }

  /* ── tabs ─────────────────────────────────────────────────────────── */

  function selectTab(name, focus) {
    if (NAV_TABS.indexOf(name) === -1) { name = 'inspect'; }
    state.tab = name;
    NAV_TABS.forEach(function (tab) {
      var button = document.getElementById('tab-' + tab);
      var panel = document.getElementById('panel-' + tab);
      var active = tab === name;
      button.setAttribute('aria-selected', active ? 'true' : 'false');
      button.tabIndex = active ? 0 : -1;
      panel.hidden = !active;
    });
    if (focus) { document.getElementById('tab-' + name).focus(); }
    store('actaira.tab', name);
    // The graph panel is the one whose layout depends on its own size, and
    // this is the first moment it has one.
    if (name === 'graph' && state.graph.needsFit) { renderGraph(); }
  }

  function wireTabs() {
    NAV_TABS.forEach(function (tab) {
      var button = document.getElementById('tab-' + tab);
      if (!button) { return; }
      button.addEventListener('click', function () { selectTab(tab, false); });
      button.addEventListener('keydown', function (event) {
        var count = NAV_TABS.length;
        var index = NAV_TABS.indexOf(tab);
        var next = null;
        if (event.key === 'ArrowRight') { next = NAV_TABS[(index + 1) % count]; }
        else if (event.key === 'ArrowLeft') { next = NAV_TABS[(index - 1 + count) % count]; }
        else if (event.key === 'Home') { next = NAV_TABS[0]; }
        else if (event.key === 'End') { next = NAV_TABS[count - 1]; }
        if (next) { event.preventDefault(); selectTab(next, true); }
      });
    });
  }

  /* ── language and theme ───────────────────────────────────────────── */

  function loadRules() {
    var lang = state.lang;
    getJson('/api/i18n/' + encodeURIComponent(lang), function (payload) {
      // A catalogue that is missing or empty is a degraded UI, not a broken
      // one: findings then render their raw rule id, never a blank line.
      state.rules = (payload && payload.rules && typeof payload.rules === 'object') ? payload.rules : {};
      state.obligations = (payload && payload.governance && typeof payload.governance === 'object')
        ? payload.governance : {};
      if (state.lang === lang) { rerenderAll(); renderGovern(); }
    }, function () {
      state.rules = {};
      state.obligations = {};
      rerenderAll();
      renderGovern();
    });
  }

  function setLanguage(lang) {
    state.lang = (lang === 'es') ? 'es' : 'en';
    store('actaira.lang', state.lang);
    ['en', 'es'].forEach(function (code) {
      var button = document.getElementById('lang-' + code);
      button.setAttribute('aria-pressed', code === state.lang ? 'true' : 'false');
    });
    applyStaticI18n();
    rerenderAll();
    loadRules();
    loadClock();
  }

  function setTheme(theme) {
    state.theme = THEMES.indexOf(theme) === -1 ? 'auto' : theme;
    document.documentElement.setAttribute('data-theme', state.theme);
    document.getElementById('theme-label').textContent = t('theme.' + state.theme);
    store('actaira.theme', state.theme);
  }

  function rerenderAll() {
    TABS.forEach(function (tab) { RENDERERS[tab](); });
  }

  function loadHealth() {
    getJson('/api/health', function (payload) {
      if (payload && payload.version) {
        document.getElementById('version-pill').textContent = 'v' + payload.version;
      }
    });
  }

  /* ── boot ─────────────────────────────────────────────────────────── */

  function boot() {
    // A file dropped anywhere but a dropzone must not navigate the page away.
    ['dragover', 'drop'].forEach(function (name) {
      window.addEventListener(name, function (event) { event.preventDefault(); });
    });

    wireTabs();
    TABS.forEach(wireDropzone);

    ['en', 'es'].forEach(function (code) {
      document.getElementById('lang-' + code).addEventListener('click', function () { setLanguage(code); });
    });
    document.getElementById('theme-toggle').addEventListener('click', function () {
      setTheme(THEMES[(THEMES.indexOf(state.theme) + 1) % THEMES.length]);
    });

    setTheme(recall('actaira.theme') || 'auto');
    state.traceFilter = recall('actaira.trace_filter') === 'all' ? 'all' : 'relevant';
    var storedRole = recall('actaira.gov_role');
    if (GOV_ROLES.indexOf(storedRole) !== -1) { state.gov.role = storedRole; }
    var storedOn = recall('actaira.gov_on');
    if (storedOn && /^\d{4}-\d{2}-\d{2}$/.test(storedOn)) { state.gov.on = storedOn; }

    var storedLang = recall('actaira.lang');
    if (!storedLang) {
      storedLang = (navigator.language || 'en').toLowerCase().indexOf('es') === 0 ? 'es' : 'en';
    }
    setLanguage(storedLang);

    selectTab(recall('actaira.tab') || 'inspect', false);
    loadHealth();
    loadSamples();
    loadWorkspace();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

}());
