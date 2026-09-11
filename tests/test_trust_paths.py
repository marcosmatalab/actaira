"""Trust as a local decision, routes as a search, and a manifest that points.

Design notes D-210, D-213 and D-226. The three modules are tested together
because they share one property worth asserting from three directions: none of
them turns an absence into an assertion. No trust policy is UNKNOWN and not
UNTRUSTED, a route with no declared mitigation is open and not "probably fine",
and a manifest that names a subject with no loader does not load at all.
"""
from __future__ import annotations

import pytest

from actaira import trustpolicy
from actaira.agentgov import load_text as load_agent
from actaira.agentgov import paths as path_engine
from actaira.manifest import ManifestError, handle
from actaira.manifest import load_text as load_manifest
from actaira.model import Severity
from actaira.subject import SubjectKind
from actaira.trustpolicy import TrustPolicyError, TrustState

# --------------------------------------------------------------------------
# Trust policy
# --------------------------------------------------------------------------


POLICY = """
schema_version: trust-policy/v1
trusted_signers:
  - fingerprint: sha256:aaaa
trusted_tsa_roots:
  - ./roots/company-tsa.pem
source_rules:
  - connector: huggingface
    require_revision_pin: true
mcp_rules:
  - publisher: acme-security
    require_digest: true
"""


def test_no_trust_policy_is_unknown_and_never_untrusted():
    """An environment that has not written its rules down has not refused
    anything. Reporting UNTRUSTED there asserts a decision nobody made."""
    result = trustpolicy.check(None, signer_fingerprint="sha256:whatever")

    assert result.state is TrustState.UNKNOWN
    assert "has not said what it accepts" in result.reasons[0]


def test_a_signer_in_the_list_is_trusted():
    result = trustpolicy.check(trustpolicy.load_text(POLICY), signer_fingerprint="sha256:aaaa")

    assert result.state is TrustState.TRUSTED


def test_a_signer_outside_the_list_is_untrusted_and_says_so():
    result = trustpolicy.check(trustpolicy.load_text(POLICY), signer_fingerprint="sha256:bbbb")

    assert result.state is TrustState.UNTRUSTED
    assert "trusted_signers" in result.reasons[0]


def test_a_connector_that_requires_a_pin_refuses_a_branch_name():
    result = trustpolicy.check(
        trustpolicy.load_text(POLICY), connector="huggingface", revision="main"
    )

    assert result.state is TrustState.UNTRUSTED
    assert "immutable revision" in result.reasons[0]


def test_the_same_connector_accepts_a_commit():
    result = trustpolicy.check(
        trustpolicy.load_text(POLICY), connector="huggingface", revision="7f91a2c"
    )

    assert result.state is TrustState.TRUSTED


def test_a_rule_for_another_connector_does_not_apply():
    result = trustpolicy.check(trustpolicy.load_text(POLICY), connector="s3", revision="main")

    assert result.state is TrustState.UNKNOWN
    assert "no rule" in result.reasons[0]


def test_an_mcp_rule_reads_the_publisher_it_names():
    agent = load_agent("""
agent: demo
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: search
    effects:
      - read
mcp_servers:
  - name: scanner
    reference: ghcr.io/acme/scanner:latest
    publisher: acme-security
""")

    result = trustpolicy.check(trustpolicy.load_text(POLICY), mcp_servers=agent.mcp_servers)

    assert result.state is TrustState.UNTRUSTED
    assert "must carry a digest" in result.reasons[0]


def test_a_server_from_another_publisher_is_left_alone():
    agent = load_agent("""
agent: demo
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: search
    effects:
      - read
mcp_servers:
  - name: other
    reference: ghcr.io/somebody/else:latest
    publisher: somebody-else
""")

    assert trustpolicy.check(
        trustpolicy.load_text(POLICY), mcp_servers=agent.mcp_servers
    ).state is TrustState.UNKNOWN


def test_a_document_from_another_version_does_not_load():
    with pytest.raises(TrustPolicyError, match="reads"):
        trustpolicy.load_text("schema_version: trust-policy/v9\n")


def test_a_signer_entry_with_no_fingerprint_does_not_load():
    with pytest.raises(TrustPolicyError, match="fingerprint"):
        trustpolicy.load_text("schema_version: trust-policy/v1\ntrusted_signers:\n  - owner: me\n")


def test_the_policy_validates_against_its_schema():
    jsonschema = pytest.importorskip("jsonschema")
    from actaira import schemas

    jsonschema.Draft202012Validator(schemas.load("trust-policy-v1")).validate(
        trustpolicy.load_text(POLICY).to_dict()
    )


# --------------------------------------------------------------------------
# Attack paths
# --------------------------------------------------------------------------


def agent_with(tools: str, extra: str = ""):
    return load_agent(f"""
agent: demo
version: "1"
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
{tools}
{extra}
""")


OPEN_EXFILTRATION = """
  - name: read_web
    effects:
      - read
      - untrusted_input
  - name: read_secret
    effects:
      - secrets
  - name: post_http
    effects:
      - network
"""


def test_a_route_names_every_hop_and_the_material_it_carries():
    report = path_engine.find(agent_with(OPEN_EXFILTRATION))
    route = next(path for path in report.open_paths if path.rule_id == "ACT-PATH-001")

    assert [hop.node for hop in route.hops] == [
        "tool:read_web",
        "agent:demo",
        "tool:read_secret",
        "agent:demo",
        "tool:post_http",
    ]
    assert route.carries == "credentials"
    assert route.severity is Severity.HIGH


def test_every_hop_says_which_declaration_put_it_there():
    report = path_engine.find(agent_with(OPEN_EXFILTRATION))

    assert all(hop.via for path in report.paths for hop in path.hops)


def test_approval_on_the_sink_closes_the_route():
    report = path_engine.find(agent_with(OPEN_EXFILTRATION.replace(
        "    effects:\n      - network\n", "    effects:\n      - network\n    requires_approval: true\n"
    )))
    routes = [path for path in report.paths if path.rule_id == "ACT-PATH-001"]

    assert routes and all(path.broken for path in routes)
    assert all("approval is required" in path.closed_by[0] for path in routes)


def test_separate_identities_are_reported_as_present_and_ineffective():
    """Design note D-205 and D-210. The credential reaches the model as text
    and the same model calls the sink; a second identity changes who may fetch
    the secret, not who may repeat it. Reporting this as a fix would close a
    real finding with a control that does not apply."""
    report = path_engine.find(agent_with("""
  - name: read_web
    effects:
      - read
      - untrusted_input
    identity: reader
  - name: read_secret
    effects:
      - secrets
    identity: reader
  - name: post_http
    effects:
      - network
    identity: poster
""", """
identities:
  - name: reader
  - name: poster
"""))
    route = next(path for path in report.paths if path.rule_id == "ACT-PATH-001")

    assert not route.broken
    assert route.present_but_ineffective
    assert "already in the context that calls the sink" in route.present_but_ineffective[0]["why"]


def test_an_execution_sink_is_critical():
    report = path_engine.find(agent_with("""
  - name: read_web
    effects:
      - read
      - untrusted_input
  - name: run_shell
    effects:
      - exec
"""))
    route = next(path for path in report.paths if path.rule_id == "ACT-PATH-003")

    assert route.severity is Severity.CRITICAL
    assert any("sandbox" in suggestion for suggestion in route.break_path_by)


def test_an_agent_with_no_untrusted_input_has_no_routes():
    report = path_engine.find(agent_with("""
  - name: read_config
    effects:
      - read
  - name: post_http
    effects:
      - network
"""))

    assert report.paths == []


def test_a_classified_data_source_makes_a_reader_a_carrier():
    """`classification` had to become a vocabulary for this: a tool reading a
    `restricted` source is a sensitive read whether or not anybody remembered
    to write `secrets` in its effects."""
    report = path_engine.find(agent_with("""
  - name: read_web
    effects:
      - read
      - untrusted_input
  - name: read_cases
    effects:
      - read
    inputs:
      - cases
  - name: post_http
    effects:
      - network
""", """
data_sources:
  - name: cases
    classification: restricted
    access: read
"""))
    route = next(path for path in report.paths if "read_cases" in {hop.node.split(":")[-1] for hop in path.hops})

    assert route.carries == "sensitive data"


def test_an_unresolved_sub_agent_is_reported_rather_than_assumed_harmless():
    report = path_engine.find(agent_with("""
  - name: read_web
    effects:
      - read
      - untrusted_input
""", """
sub_agents:
  - name: researcher
"""))

    assert report.unresolved_sub_agents == ["researcher"]


def test_a_resolved_sub_agent_contributes_its_capabilities():
    """Whatever a delegate can do, the agent that calls it can cause."""
    delegate = load_agent("""
agent: researcher
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: send_mail
    effects:
      - send
""")
    report = path_engine.find(
        agent_with("""
  - name: read_web
    effects:
      - read
      - untrusted_input
""", """
sub_agents:
  - name: researcher
    digest: sha256:aa
"""),
        {"researcher": delegate},
    )
    route = next(path for path in report.paths if path.rule_id == "ACT-PATH-004")

    assert [hop.node for hop in route.hops] == [
        "tool:read_web", "agent:demo", "agent:researcher", "tool:send_mail"
    ]
    assert report.contexts == ["demo", "researcher"]


def test_a_delegation_cycle_terminates_and_is_reported():
    """A -> B -> A is a declaration people really write. The walk cuts it and
    says so rather than running out of stack."""
    left = agent_with("""
  - name: read_web
    effects:
      - read
      - untrusted_input
""", """
sub_agents:
  - name: b
    digest: sha256:bb
""")
    right = load_agent("""
agent: b
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: send_mail
    effects:
      - send
sub_agents:
  - name: demo
    digest: sha256:aa
""")

    report = path_engine.find(left, {"b": right, "demo": left})

    assert report.cycles
    assert "ACT-PATH-009" in {finding.rule_id for finding in report.findings()}


def test_a_closed_route_is_not_a_finding():
    """A finding that fires on a control that is in place is how a team learns
    to ignore the output."""
    report = path_engine.find(agent_with("""
  - name: read_web
    effects:
      - read
      - untrusted_input
  - name: send_mail
    effects:
      - send
    requires_approval: true
"""))

    assert report.paths
    assert report.findings() == []


def test_the_report_validates_against_its_schema():
    jsonschema = pytest.importorskip("jsonschema")
    from actaira import schemas

    document = path_engine.find(agent_with(OPEN_EXFILTRATION)).to_dict()

    jsonschema.Draft202012Validator(schemas.load("attack-paths-v1")).validate(document)


# --------------------------------------------------------------------------
# Subject manifest
# --------------------------------------------------------------------------


def write_workspace(tmp_path):
    (tmp_path / "models" / "fraud").mkdir(parents=True)
    (tmp_path / "models" / "fraud" / "config.json").write_text('{"architectures":["X"]}', encoding="utf-8")
    (tmp_path / "agents").mkdir()
    (tmp_path / "agents" / "review.yaml").write_text("""
agent: review
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: search
    effects:
      - read
""", encoding="utf-8")
    return tmp_path


MANIFEST = """
schema_version: subject-manifest/v1
system: fraud-review
subjects:
  - kind: bundle
    path: models/fraud
  - kind: agent
    path: agents/review.yaml
    uses:
      - bundle:fraud
  - kind: system
    name: fraud-review
    uses:
      - agent:review
"""


def test_a_manifest_loads_every_kind_it_declares(tmp_path):
    root = write_workspace(tmp_path)

    document = load_manifest(MANIFEST, base=root)

    assert [entry.kind for entry in document.entries] == [
        SubjectKind.BUNDLE, SubjectKind.AGENT, SubjectKind.SYSTEM
    ]
    assert handle(document.entries[0]) == "bundle:fraud"
    assert handle(document.entries[2], document.system) == "system:fraud-review"


def test_an_unknown_kind_is_refused_rather_than_skipped(tmp_path):
    """A manifest listing four subjects and governing three is the failure
    this file exists to prevent."""
    with pytest.raises(ManifestError, match="not a kind"):
        load_manifest(
            "schema_version: subject-manifest/v1\nsubjects:\n  - kind: spaceship\n", base=tmp_path
        )


def test_a_path_that_does_not_exist_is_refused_at_load_time(tmp_path):
    """A manifest that parsed and failed halfway through would have already
    produced half a decision, which looks like an answer."""
    with pytest.raises(ManifestError, match="does not exist"):
        load_manifest(
            "schema_version: subject-manifest/v1\nsubjects:\n  - kind: agent\n    path: nope.yaml\n",
            base=tmp_path,
        )


def test_a_uses_edge_pointing_nowhere_is_refused(tmp_path):
    root = write_workspace(tmp_path)

    with pytest.raises(ManifestError, match="which this manifest does not declare"):
        load_manifest(MANIFEST.replace("bundle:fraud", "bundle:ghost"), base=root)


def test_a_manifest_from_another_version_does_not_load(tmp_path):
    """Caught by ruff, not by pytest: this used to share a name with the trust
    policy's version test above, so one of the two silently never ran. A
    duplicate test function is a test that was deleted by accident."""
    with pytest.raises(ManifestError, match="reads"):
        load_manifest("schema_version: subject-manifest/v7\nsubjects:\n  - kind: system\n    name: x\n",
                      base=tmp_path)


def test_a_source_needs_a_uri_and_a_system_needs_a_name(tmp_path):
    with pytest.raises(ManifestError, match="needs a `uri:`"):
        load_manifest("schema_version: subject-manifest/v1\nsubjects:\n  - kind: source\n", base=tmp_path)
    with pytest.raises(ManifestError, match="needs a `name:`"):
        load_manifest("schema_version: subject-manifest/v1\nsubjects:\n  - kind: system\n", base=tmp_path)


def test_the_manifest_validates_against_its_schema(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")

    from actaira import schemas
    from actaira.miniyaml import loads

    jsonschema.Draft202012Validator(schemas.load("subject-manifest-v1")).validate(loads(MANIFEST))


# --------------------------------------------------------------------------
# The defects an adversarial read of these modules found
# --------------------------------------------------------------------------


def test_a_rule_that_could_not_be_evaluated_does_not_read_as_satisfied():
    """DEF-85. `require_declared_digest` compared against a parameter no
    caller ever passed, so it could never fail - and the result came back
    TRUSTED, naming the rule in `checked`, with the reason "every applicable
    rule was satisfied" about a rule that had never run."""
    policy = trustpolicy.load_text("""
schema_version: trust-policy/v1
source_rules:
  - connector: huggingface
    require_declared_digest: true
""")

    unknown = trustpolicy.check(policy, connector="huggingface", revision="7f91a2c")
    yes = trustpolicy.check(policy, connector="huggingface", revision="7f91a2c", declared_digests=True)
    no = trustpolicy.check(policy, connector="huggingface", revision="7f91a2c", declared_digests=False)

    assert unknown.state is TrustState.UNKNOWN
    assert unknown.unevaluated and "did not say whether" in unknown.unevaluated[0]
    assert yes.state is TrustState.TRUSTED
    assert no.state is TrustState.UNTRUSTED


def test_a_failure_still_wins_over_an_unevaluated_rule():
    policy = trustpolicy.load_text("""
schema_version: trust-policy/v1
source_rules:
  - connector: huggingface
    require_revision_pin: true
    require_declared_digest: true
""")

    result = trustpolicy.check(policy, connector="huggingface", revision="main")

    assert result.state is TrustState.UNTRUSTED
    assert "immutable revision" in result.reasons[0]


def test_a_delegated_route_names_every_declaration_it_passes_through():
    """DEF-88. Route 4 used to pair the root with every context and emit one
    `declared delegates_to` hop between them, so for A -> B -> D it asserted
    an edge A's declaration does not contain and elided B - leaving the
    reviewer unable to see which file to change."""
    middle = load_agent("""
agent: B
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: relay
    effects:
      - read
sub_agents:
  - name: D
    digest: sha256:dd
""")
    leaf = load_agent("""
agent: D
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: wire_money
    effects:
      - pay
""")
    root = agent_with("""
  - name: read_web
    effects:
      - read
      - untrusted_input
""", """
sub_agents:
  - name: B
    digest: sha256:bb
""")

    report = path_engine.find(root, {"B": middle, "D": leaf})
    route = next(path for path in report.paths if path.sink == "tool:wire_money")

    assert [hop.node for hop in route.hops] == [
        "tool:read_web", "agent:demo", "agent:B", "agent:D", "tool:wire_money"
    ]
    assert route.hops[2].via == "declared delegates_to by demo"
    assert route.hops[3].via == "declared delegates_to by B"


def test_a_delegation_chain_past_the_depth_limit_says_so():
    """DEF-89. A chain longer than MAX_DEPTH was cut silently, so an agent
    that could reach a payment tool eleven delegations away reported no
    routes, no unresolved sub-agents and no cycles - which together read as
    'there is nothing here'."""
    chain = {}
    for index in range(14):
        follows = (
            f"sub_agents:\n  - name: a{index + 1}\n    digest: sha256:aa\n" if index < 13 else ""
        )
        chain[f"a{index}"] = load_agent(f"""
agent: a{index}
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: t{index}
    effects:
      - read
{follows}""")

    report = path_engine.find(chain["a0"], chain)

    assert report.cycles, "the walk stopped, and the report has to be able to say so"
    assert any("depth limit" in " ".join(cycle) for cycle in report.cycles)


def test_one_tool_that_reads_outside_text_and_acts_is_a_route():
    """DEF-90. ACT-AGT-001 fires on this and `agent paths` reported nothing,
    so the set-based rule named a risk for which this command offered no route
    and no way to break it - the gap routes exist to fill. The EXEC route
    never skipped the case, so the two disagreed."""
    from actaira.agentgov import assess

    agent = agent_with("""
  - name: github_pr
    effects:
      - untrusted_input
      - write
""")

    report = path_engine.find(agent)

    assert "ACT-AGT-001" in {finding.rule_id for finding in assess(agent)}
    route = next(path for path in report.open_paths if path.rule_id == "ACT-PATH-002")
    assert route.entry == route.sink == "tool:github_pr"
    assert route.break_path_by


def test_a_manifest_handle_is_the_handle_a_reference_would_give(tmp_path):
    """DEF-84. `Path(path).stem` agreed with `SubjectRef` for neither kind
    that has a path: `models/fraud.pt` collided with `models/fraud.onnx`, and
    an agent declaring `agent: fraud-review` in `fraud-review-v2.yaml` got a
    node no `uses:` line or `delegates_to` edge could reach."""
    from actaira import subject as subject_mod
    from actaira.agentgov import load as load_agent_file

    (tmp_path / "agents").mkdir()
    declaration = tmp_path / "agents" / "fraud-review-v2.yaml"
    declaration.write_text("""
agent: fraud-review
tools:
  - name: search
    effects:
      - read
""", encoding="utf-8")
    (tmp_path / "fraud.pt").write_bytes(b"x")
    (tmp_path / "fraud.onnx").write_bytes(b"y")

    document = load_manifest("""
schema_version: subject-manifest/v1
subjects:
  - kind: agent
    path: agents/fraud-review-v2.yaml
  - kind: artifact
    path: fraud.pt
  - kind: artifact
    path: fraud.onnx
""", base=tmp_path)

    handles = [handle(entry, document.system) for entry in document.entries]

    assert handles == ["agent:fraud-review", "artifact:fraud.pt", "artifact:fraud.onnx"]
    assert len(set(handles)) == 3, "two artifacts in one directory are two nodes"
    assert handles[0] == subject_mod.for_agent(load_agent_file(declaration)).ref.handle


def test_a_uses_edge_may_name_the_declared_agent(tmp_path):
    (tmp_path / "review.yaml").write_text("""
agent: fraud-review
tools:
  - name: search
    effects:
      - read
""", encoding="utf-8")

    document = load_manifest("""
schema_version: subject-manifest/v1
subjects:
  - kind: agent
    path: review.yaml
  - kind: system
    name: svc
    uses:
      - agent:fraud-review
""", base=tmp_path)

    assert handle(document.entries[0]) == "agent:fraud-review"


def test_a_manifest_uses_line_that_is_not_a_list_is_refused(tmp_path):
    """Part of DEF-94. `tuple(str(name) for name in value)` over a string
    produces one entry per CHARACTER, so a `uses:` line this parser had not
    understood became a claim to depend on ":", "[", "]", "a", "b"... and the
    document was refused with a message listing single letters."""
    (tmp_path / "a.yaml").write_text(
        "agent: a\ntools:\n  - name: t\n    effects: [read]\n", encoding="utf-8"
    )

    with pytest.raises(ManifestError, match="must be a list of handles"):
        load_manifest("""
schema_version: subject-manifest/v1
subjects:
  - kind: agent
    path: a.yaml
  - kind: system
    name: s
    uses: agent:a
""", base=tmp_path)


def test_one_tool_that_supplies_both_the_instruction_and_the_material_is_a_route():
    """DEF-95, the same shape as DEF-90 one route along. `carrier is entry`
    was skipped, so an agent whose one reader brings in both outside text and
    personal data - `trusted: false` and `classification: personal` on the
    same source, which is what a ticket queue or a case file actually is -
    reported no route at all."""
    agent = agent_with("""
  - name: read_case_notes
    effects: [read, untrusted_input]
    inputs: [case-notes]
  - name: fetch_url
    effects: [network]
""", """
data_sources:
  - name: case-notes
    classification: personal
    access: read_write
    trusted: false
""")

    report = path_engine.find(agent)
    route = next(path for path in report.open_paths if path.rule_id == "ACT-PATH-001")

    assert route.entry == "tool:read_case_notes"
    assert route.sink == "tool:fetch_url"
    assert route.carries == "sensitive data"
    assert "one tool supplies both the instruction and the material" in route.note
