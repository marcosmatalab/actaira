"""Agents: the A-BOM, the diff, and the combinations that are the actual risk.

Design notes D-140 to D-143. Every capability rule here is defended from both
sides, because a rule that fires on everything and a rule that fires on
nothing fail the same way in practice: the team stops reading the output.
"""
from __future__ import annotations

import json

import pytest

from actaira.agentgov import DeclarationError, assess, load_text
from actaira.agentgov.model import Effect, diff
from actaira.model import Severity


def rules(agent) -> set[str]:
    return {finding.rule_id for finding in assess(agent)}


def finding(agent, rule_id):
    return next(item for item in assess(agent) if item.rule_id == rule_id)


PINNED_MCP = """
  - name: github
    reference: ghcr.io/example/mcp-github@sha256:aa
    publisher: example
    digest: sha256:aa
"""

BOUND = """
model: anthropic/claude-sonnet-4-5
model_digest: sha256:1111
prompt_sha256: 2222
"""


def declaration(tools: str, extra: str = "") -> str:
    return f"""
agent: demo
version: "1"
{BOUND}
tools:
{tools}
mcp_servers:
{PINNED_MCP}
{extra}
"""


# --------------------------------------------------------------------------
# Untrusted input beside an unapproved action
# --------------------------------------------------------------------------


READS_AND_ACTS = """
  - name: read_comments
    effects:
      - read
      - untrusted_input
  - name: post_comment
    effects:
      - write
"""


def test_untrusted_input_beside_an_unapproved_action_is_reported():
    """The shape of every prompt-injection incident that mattered, and one no
    per-tool check can express: each tool here is obviously fine alone."""
    agent = load_text(declaration(READS_AND_ACTS))

    assert "ACT-AGT-001" in rules(agent)
    evidence = finding(agent, "ACT-AGT-001").evidence
    assert evidence["reads_untrusted"] == ["read_comments"]
    assert evidence["acts_without_approval"] == ["post_comment"]
    assert evidence["would_be_acceptable_if"]


def test_the_same_pair_with_approval_on_the_acting_tool_is_not():
    """Approval is what breaks the chain. The concern is not that the agent
    can act - it is that it can act on instructions the outsider wrote."""
    agent = load_text(
        declaration(
            """
  - name: read_comments
    effects:
      - read
      - untrusted_input
  - name: post_comment
    effects:
      - write
    requires_approval: true
"""
        )
    )

    assert "ACT-AGT-001" not in rules(agent)


def test_a_reader_with_no_acting_tool_is_not_reported():
    agent = load_text(
        declaration(
            """
  - name: read_comments
    effects:
      - read
      - untrusted_input
  - name: summarise
    effects:
      - read
"""
        )
    )

    assert "ACT-AGT-001" not in rules(agent)


def test_an_untrusted_data_source_marks_a_reader_that_forgot_the_effect():
    """The inference exists because nobody remembers to mark the web fetcher,
    and an agent whose declaration forgot the marker is exactly the agent this
    rule is for."""
    agent = load_text(
        declaration(
            """
  - name: read_tickets
    effects:
      - read
    scopes:
      - jira
  - name: merge
    effects:
      - write
""",
            extra="""
data_sources:
  - name: jira
    trusted: false
""",
        )
    )

    assert "ACT-AGT-001" in rules(agent)
    assert finding(agent, "ACT-AGT-001").evidence["reads_untrusted"] == ["read_tickets"]


def test_a_write_only_tool_on_an_untrusted_source_is_not_inferred_as_a_reader():
    """A tool that only writes to an untrusted source does not carry its text
    back into the model. Counting it made the evidence name tools that could
    not possibly be the injection path, which is how a finding that is correct
    in substance becomes one nobody acts on."""
    agent = load_text(
        declaration(
            """
  - name: post_only
    effects:
      - write
    scopes:
      - jira
  - name: read_internal
    effects:
      - read
""",
            extra="""
data_sources:
  - name: jira
    trusted: false
""",
        )
    )

    assert "ACT-AGT-001" not in rules(agent)


# --------------------------------------------------------------------------
# Secrets beside egress
# --------------------------------------------------------------------------


def test_a_secret_reader_beside_a_network_tool_is_the_exfiltration_path():
    """They do not need to be the same tool, and that is precisely why a
    per-tool review misses it: the model sits between them."""
    agent = load_text(
        declaration(
            """
  - name: read_key
    effects:
      - secrets
      - read
  - name: fetch
    effects:
      - network
"""
        )
    )

    assert "ACT-AGT-002" in rules(agent)
    evidence = finding(agent, "ACT-AGT-002").evidence
    assert evidence["can_read_secrets"] == ["read_key"]
    assert evidence["can_reach_outside"] == ["fetch"]


def test_a_secret_reader_with_no_way_out_is_not_reported():
    agent = load_text(
        declaration(
            """
  - name: read_key
    effects:
      - secrets
      - read
"""
        )
    )

    assert "ACT-AGT-002" not in rules(agent)


# --------------------------------------------------------------------------
# Execution, pinning, binding
# --------------------------------------------------------------------------


def test_arbitrary_execution_is_reported_on_its_own():
    """It subsumes every other capability here: a shell is a write tool, a
    network tool, a secret reader and a delete tool at once."""
    agent = load_text(
        declaration(
            """
  - name: run_shell
    effects:
      - exec
"""
        )
    )

    assert "ACT-AGT-003" in rules(agent)
    assert finding(agent, "ACT-AGT-003").severity is Severity.HIGH


def test_an_mcp_server_on_a_tag_is_reported_and_one_on_a_digest_is_not():
    tagged = load_text(
        """
agent: demo
version: "1"
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: noop
    effects:
      - read
mcp_servers:
  - name: jira
    reference: ghcr.io/example/mcp-jira:latest
    publisher: example
"""
    )
    pinned = load_text(declaration("""
  - name: noop
    effects:
      - read
"""))

    assert "ACT-AGT-004" in rules(tagged)
    assert "ACT-AGT-004" not in rules(pinned)


def test_a_reference_carrying_its_digest_inline_counts_as_pinned():
    """`image@sha256:...` is how most deployments actually pin. A check that
    demanded a separate field would report every correctly pinned server."""
    agent = load_text(
        """
agent: demo
version: "1"
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: noop
    effects:
      - read
mcp_servers:
  - name: jira
    reference: ghcr.io/example/mcp-jira@sha256:abc
    publisher: example
"""
    )

    assert "ACT-AGT-004" not in rules(agent)


def test_a_model_or_prompt_with_no_digest_is_reported():
    agent = load_text(
        """
agent: demo
version: "1"
model: anthropic/claude-sonnet-4-5
tools:
  - name: noop
    effects:
      - read
"""
    )

    assert {"ACT-AGT-006", "ACT-AGT-007"} <= rules(agent)


def test_a_fully_bound_agent_with_one_harmless_tool_reports_nothing():
    """The negative control. A checker that fired on a read-only agent with a
    pinned server and a digested model would be turned off immediately."""
    agent = load_text(declaration("""
  - name: search_docs
    effects:
      - read
"""))

    assert assess(agent) == []


def test_production_writes_without_approval_are_reported():
    agent = load_text(
        """
agent: demo
version: "1"
environment: production
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: deploy
    effects:
      - write
"""
    )

    assert "ACT-AGT-008" in rules(agent)


# --------------------------------------------------------------------------
# The declaration itself
# --------------------------------------------------------------------------


def test_a_tool_with_no_effects_does_not_load():
    """"This tool does nothing" is never true. An empty list is what a
    declaration looks like when somebody filled in the names and left the
    analysis for later, and it is the one input the capability rules have."""
    with pytest.raises(DeclarationError) as caught:
        load_text(
            """
agent: demo
version: "1"
tools:
  - name: mystery
    description: we will fill this in later
"""
        )

    assert "mystery" in str(caught.value)


def test_a_misspelt_effect_does_not_load():
    """It would otherwise produce an agent with one fewer capability than it
    has, and a report that said so confidently."""
    with pytest.raises(DeclarationError) as caught:
        load_text(
            """
agent: demo
version: "1"
tools:
  - name: write_file
    effects:
      - wirte
"""
        )

    assert "wirte" in str(caught.value)
    assert "write" in str(caught.value), "the error names the effects it knows"


def test_two_tools_with_one_name_do_not_load():
    with pytest.raises(DeclarationError):
        load_text(
            """
agent: demo
version: "1"
tools:
  - name: search
    effects:
      - read
  - name: search
    effects:
      - write
"""
        )


def test_an_mcp_server_with_no_reference_does_not_load():
    with pytest.raises(DeclarationError):
        load_text(
            """
agent: demo
version: "1"
tools:
  - name: noop
    effects:
      - read
mcp_servers:
  - name: jira
    publisher: example
"""
        )


# --------------------------------------------------------------------------
# The A-BOM and the diff
# --------------------------------------------------------------------------


def test_the_a_bom_is_byte_identical_across_two_loads():
    """A BOM whose bytes moved between runs would make every diff noise."""
    text = declaration("""
  - name: b_tool
    effects:
      - read
  - name: a_tool
    effects:
      - write
""")

    first = json.dumps(load_text(text).to_bom(), sort_keys=True)
    second = json.dumps(load_text(text).to_bom(), sort_keys=True)

    assert first == second


def test_the_agent_digest_moves_when_a_tool_gains_an_effect():
    """The number that answers "is this the agent that was approved?". A tool
    quietly gaining `write` is exactly the change it has to catch, and a
    digest over names alone would miss it."""
    before = load_text(declaration("""
  - name: helper
    effects:
      - read
"""))
    after = load_text(declaration("""
  - name: helper
    effects:
      - read
      - write
"""))

    assert before.digest != after.digest


def test_the_diff_separates_a_new_tool_from_an_existing_tool_that_gained_power():
    """Two different questions. A diff that only listed names would show the
    first and miss the second, and the second is the quieter risk."""
    before = load_text(declaration("""
  - name: helper
    effects:
      - read
"""))
    after = load_text(declaration("""
  - name: helper
    effects:
      - read
      - write
  - name: newcomer
    effects:
      - read
"""))

    changes = diff(before, after)

    assert changes["tools_added"] == ["newcomer"]
    assert changes["effects_gained"] == ["write"]
    assert changes["tools_changed"] == [
        {"name": "helper", "effects_gained": ["write"], "effects_lost": []}
    ]


def test_the_diff_reports_a_changed_prompt_even_when_no_tool_moved():
    """The system prompt is the agent's policy. An agent whose instructions
    were rewritten and whose tools did not move has changed."""
    before = load_text(declaration("""
  - name: helper
    effects:
      - read
"""))
    after = load_text(
        declaration("""
  - name: helper
    effects:
      - read
""").replace("prompt_sha256: 2222", "prompt_sha256: 3333")
    )

    changes = diff(before, after)

    assert changes["prompt_changed"] is True
    assert changes["tools_added"] == []


def test_every_rule_runs_in_a_fixed_order_whatever_the_declaration_says():
    """The findings a reader gets must depend only on the agent, so two
    declarations can be compared."""
    from actaira.agentgov.capability import CAPABILITY_RULES

    agent = load_text(declaration("""
  - name: run_shell
    effects:
      - exec
  - name: read_web
    effects:
      - read
      - untrusted_input
  - name: send_mail
    effects:
      - send
"""))

    ids = [item.rule_id for item in assess(agent)]

    assert ids == sorted(ids, key=lambda item: [rule.rule_id for rule in CAPABILITY_RULES].index(item))


def test_the_shipped_example_reports_the_three_combinations_it_was_written_to_show():
    """The example in `examples/` is documentation, and documentation that
    stops matching the code is worse than none."""
    from pathlib import Path

    from actaira.agentgov import load
    from conftest import REPO_ROOT

    agent = load(Path(REPO_ROOT) / "examples" / "agent-ticket-triage.yaml")

    assert {"ACT-AGT-001", "ACT-AGT-002", "ACT-AGT-004"} <= rules(agent)
    assert Effect.UNTRUSTED_INPUT in agent.effects


# --------------------------------------------------------------------------
# Declared relations (ACT22-P0-05, design note D-202)
# --------------------------------------------------------------------------


def test_a_tool_that_runs_as_an_undeclared_identity_does_not_load():
    """A typo in one document, visible at authoring time.

    Accepting it would produce a declaration whose identity binding is
    silently absent, which is exactly the state the binding exists to rule
    out: the author believes they wrote the mitigation down and the report
    says they did not.
    """
    with pytest.raises(DeclarationError) as problem:
        load_text(declaration("""
  - name: read_secret
    effects:
      - secrets
    identity: triage-bott
""", """
identities:
  - name: triage-bot
"""))

    assert "triage-bott" in str(problem.value)
    assert "triage-bot" in str(problem.value), "the message names what was declared instead"


def test_a_tool_whose_inputs_name_no_declared_source_does_not_load():
    with pytest.raises(DeclarationError) as problem:
        load_text(declaration("""
  - name: read_tickets
    effects:
      - read
    inputs:
      - jira
"""))

    assert "jira" in str(problem.value)


def test_an_mcp_server_exposing_an_undeclared_tool_is_a_finding_not_a_refusal():
    """The other direction, and the contract for it (D-204).

    The agent's authors may not own that server's tool list. A mismatch is
    real information about the deployment rather than a typo, and refusing the
    file would leave the operator with no report at all.
    """
    agent = load_text("""
agent: demo
version: "1"
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: search
    effects:
      - read
mcp_servers:
  - name: github
    reference: ghcr.io/example/mcp@sha256:aa
    publisher: example
    digest: sha256:aa
    tools:
      - search
      - merge_pull_request
""")

    assert "ACT-AGT-009" in rules(agent)
    evidence = finding(agent, "ACT-AGT-009").evidence
    assert evidence["exposes"] == ["merge_pull_request"]
    assert evidence["server"] == "github"


def test_an_mcp_server_whose_tools_are_all_declared_reports_nothing():
    agent = load_text("""
agent: demo
version: "1"
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: search
    effects:
      - read
mcp_servers:
  - name: github
    reference: ghcr.io/example/mcp@sha256:aa
    publisher: example
    digest: sha256:aa
    tools:
      - search
""")

    assert "ACT-AGT-009" not in rules(agent)


SPLIT_IDENTITIES = ("""
  - name: read_deploy_key
    effects:
      - secrets
    identity: secrets-reader
  - name: fetch_url
    effects:
      - network
    identity: web-caller
""", """
identities:
  - name: secrets-reader
  - name: web-caller
""")


def test_separate_identities_are_recorded_and_do_not_close_the_finding():
    """Design note D-205, and the answer that took some working out.

    "Run the secret reader under an identity the egress tool does not have"
    is the mitigation everyone recommends, and inside a single agent it does
    not work: `read_deploy_key` returns the credential as text into the
    model's context and `fetch_url` is called by that same model. Nothing has
    to re-read the secret under the second identity, because it is already in
    the conversation.

    So the declaration is read, the separation is recorded, and the finding
    stands with the reason attached. Closing it here would be the most
    expensive kind of wrong answer: a real finding marked resolved by a
    control that does not apply to it.
    """
    agent = load_text(declaration(*SPLIT_IDENTITIES))

    assert "ACT-AGT-002" in rules(agent)
    evidence = finding(agent, "ACT-AGT-002").evidence
    assert evidence["declared_mitigation"] == "separate identities"
    assert "as text" in evidence["why_it_does_not_break_this"]


def test_the_separation_itself_is_still_recognised_where_it_is_real():
    """The predicate is correct even though the rule does not act on it: the
    attack-path engine uses it where a credential, not text, is the thing
    that has to cross."""
    from actaira.agentgov.capability import identity_separated

    agent = load_text(declaration(*SPLIT_IDENTITIES))
    secrets = [tool for tool in agent.tools if tool.name == "read_deploy_key"]
    egress = [tool for tool in agent.tools if tool.name == "fetch_url"]

    assert identity_separated(secrets, egress) is True


def test_one_shared_identity_is_not_separation():
    from actaira.agentgov.capability import identity_separated

    agent = load_text(declaration("""
  - name: read_deploy_key
    effects:
      - secrets
    identity: bot
  - name: fetch_url
    effects:
      - network
    identity: bot
""", """
identities:
  - name: bot
"""))

    assert identity_separated(agent.tools_with(Effect.SECRETS), agent.tools_with(Effect.NETWORK)) is False
    assert "ACT-AGT-002" in rules(agent)


def test_an_unstated_identity_is_never_read_as_a_separate_one():
    """The failure this whole module exists to avoid: a missing field that
    reads as a mitigation."""
    from actaira.agentgov.capability import identity_separated

    agent = load_text(declaration("""
  - name: read_deploy_key
    effects:
      - secrets
    identity: secrets-reader
  - name: fetch_url
    effects:
      - network
""", """
identities:
  - name: secrets-reader
"""))

    assert identity_separated(agent.tools_with(Effect.SECRETS), agent.tools_with(Effect.NETWORK)) is False
    assert "ACT-AGT-002" in rules(agent)
    assert finding(agent, "ACT-AGT-002").evidence["identities"]["unstated"] == ["fetch_url"]


def test_approval_on_every_way_out_does_break_the_exfiltration_combination():
    """The mitigation that does apply: the path needs an unattended action
    and there is not one."""
    agent = load_text(declaration("""
  - name: read_deploy_key
    effects:
      - secrets
  - name: fetch_url
    effects:
      - network
    requires_approval: true
"""))

    assert "ACT-AGT-002" not in rules(agent)


def test_approval_on_only_one_of_two_ways_out_does_not():
    agent = load_text(declaration("""
  - name: read_deploy_key
    effects:
      - secrets
  - name: fetch_url
    effects:
      - network
    requires_approval: true
  - name: send_mail
    effects:
      - send
"""))

    assert "ACT-AGT-002" in rules(agent)


def test_a_declared_input_edge_marks_a_reader_the_effects_forgot():
    """Stronger than the scope convention it replaces: two fields that have
    to agree, not two strings that happened to match."""
    agent = load_text(declaration("""
  - name: read_tickets
    effects:
      - read
    inputs:
      - jira
  - name: post_comment
    effects:
      - write
""", """
data_sources:
  - name: jira
    classification: internal
    access: read_write
    trusted: false
"""))

    assert "ACT-AGT-001" in rules(agent)
    established = finding(agent, "ACT-AGT-001").evidence["established_by"]
    assert established["read_tickets"] == "declared inputs edge to an untrusted data source"


def test_the_relations_a_declaration_states_are_the_only_ones_emitted():
    agent = load_text(declaration("""
  - name: read_tickets
    effects:
      - read
    identity: bot
    inputs:
      - jira
    outputs:
      - jira
""", """
identities:
  - name: bot
data_sources:
  - name: jira
    classification: internal
    access: read_write
    trusted: false
"""))

    edges = {(edge.source, edge.relation, edge.target) for edge in agent.relations()}

    assert ("tool:read_tickets", "runs_as", "identity:bot") in edges
    assert ("tool:read_tickets", "reads", "data:jira") in edges
    assert ("tool:read_tickets", "writes", "data:jira") in edges
    assert ("agent:demo", "uses_model", "model:anthropic/claude-sonnet-4-5") in edges
    assert not any(relation == "delegates_to" for _source, relation, _target in edges)


# --------------------------------------------------------------------------
# The versioned vocabulary (design note D-201)
# --------------------------------------------------------------------------


def test_a_word_outside_the_vocabulary_does_not_load():
    with pytest.raises(DeclarationError) as problem:
        load_text(declaration("""
  - name: search
    effects:
      - read
""", """
data_sources:
  - name: jira
    classification: CONFIDENTIAL
"""))

    assert "confidential" in str(problem.value), "the message lists the words that are known"


def test_a_namespaced_word_loads_and_ranks_as_nothing():
    """The escape hatch is explicit. A word Actaira does not understand must
    not be ranked, because ranking it would be inventing knowledge."""
    agent = load_text(declaration("""
  - name: search
    effects:
      - read
""", """
data_sources:
  - name: cards
    classification: acme:pci-cardholder
"""))

    source = agent.data_source("cards")

    assert source.classification == "acme:pci-cardholder"
    assert source.sensitivity == -1


def test_an_unclassified_source_does_not_rank_as_harmless():
    """A source nobody classified is not a public source."""
    from actaira.agentgov.vocabulary import Classification

    assert Classification.UNKNOWN.rank > Classification.PUBLIC.rank
    assert Classification.UNKNOWN.rank < Classification.CONFIDENTIAL.rank


# --------------------------------------------------------------------------
# Sub-agents (design note D-202)
# --------------------------------------------------------------------------


def test_a_sub_agent_named_without_a_digest_is_reported():
    agent = load_text(declaration("""
  - name: search
    effects:
      - read
""", """
sub_agents:
  - research-bot
"""))

    assert "ACT-AGT-010" in rules(agent)
    assert finding(agent, "ACT-AGT-010").evidence["unpinned"] == ["research-bot"]


def test_a_pinned_sub_agent_is_not():
    agent = load_text(declaration("""
  - name: search
    effects:
      - read
""", """
sub_agents:
  - name: research-bot
    digest: sha256:abcd
"""))

    assert "ACT-AGT-010" not in rules(agent)


def test_the_v1_bare_name_shape_still_loads():
    """A repository upgrading should not have to rewrite every declaration on
    the day the tool changes."""
    agent = load_text(declaration("""
  - name: search
    effects:
      - read
""", """
sub_agents:
  - research-bot
"""))

    assert [sub.name for sub in agent.sub_agents] == ["research-bot"]
    assert agent.sub_agents[0].pinned is False


# --------------------------------------------------------------------------
# The complete diff (ACT22-P0-04, design note D-203)
# --------------------------------------------------------------------------


def _versions(extra_before: str, extra_after: str):
    tools = """
  - name: search
    effects:
      - read
"""
    return load_text(declaration(tools, extra_before)), load_text(declaration(tools, extra_after))


def test_an_mcp_server_with_one_name_and_different_bytes_is_explained():
    """The gate ACT22-P0-04 names. Under 2.1 this produced an empty MCP
    section and a changed agent digest: "something changed, work out what"."""
    before = load_text("""
agent: demo
version: "1"
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: search
    effects:
      - read
mcp_servers:
  - name: github
    reference: ghcr.io/example/mcp@sha256:aaaa
    publisher: example
    digest: sha256:aaaa
    transport: stdio
""")
    after = load_text("""
agent: demo
version: "1"
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: search
    effects:
      - read
mcp_servers:
  - name: github
    reference: ghcr.io/example/mcp:latest
    publisher: someone-else
    transport: http
""")

    document = diff(before, after)

    assert document["mcp_added"] == [] and document["mcp_removed"] == []
    entry = next(item for item in document["mcp_changed"] if item["name"] == "github")
    assert entry["reference"]["to"] == "ghcr.io/example/mcp:latest"
    assert entry["digest"]["from"] == "sha256:aaaa"
    assert entry["publisher"]["to"] == "someone-else"
    assert entry["transport"] == {"from": "stdio", "to": "http"}
    assert entry["pinned"] == {"from": True, "to": False}
    assert "mcp server github is no longer pinned" in document["risk_increasing"]


def test_an_identity_that_gained_a_scope_is_explained():
    before, after = _versions(
        """
identities:
  - name: bot
    scopes:
      - jira:read
""",
        """
identities:
  - name: bot
    scopes:
      - jira:read
      - github:write
""",
    )

    entry = next(item for item in diff(before, after)["identities_changed"] if item["name"] == "bot")

    assert entry["scopes_added"] == ["github:write"]


def test_an_identity_whose_expiry_moved_is_explained():
    before, after = _versions(
        """
identities:
  - name: bot
    expires: 2026-01-01
""",
        """
identities:
  - name: bot
    expires: 2030-01-01
""",
    )

    entry = next(item for item in diff(before, after)["identities_changed"] if item["name"] == "bot")

    assert entry["expires"] == {"from": "2026-01-01", "to": "2030-01-01"}


def test_a_data_source_that_became_untrusted_is_explained_and_flagged():
    before, after = _versions(
        """
data_sources:
  - name: jira
    classification: internal
    trusted: true
""",
        """
data_sources:
  - name: jira
    classification: confidential
    access: read_write
    trusted: false
""",
    )

    document = diff(before, after)
    entry = next(item for item in document["data_sources_changed"] if item["name"] == "jira")

    assert entry["trusted"] == {"from": True, "to": False}
    assert entry["classification"] == {"from": "internal", "to": "confidential"}
    assert "data source jira is no longer trusted" in document["risk_increasing"]


def test_a_sub_agent_pointing_at_a_different_version_is_explained():
    before, after = _versions(
        """
sub_agents:
  - name: research-bot
    digest: sha256:aaaa
""",
        """
sub_agents:
  - name: research-bot
    digest: sha256:bbbb
""",
    )

    document = diff(before, after)
    entry = next(item for item in document["sub_agents_changed"] if item["name"] == "research-bot")

    assert entry["digest"] == {"from": "sha256:aaaa", "to": "sha256:bbbb"}
    assert "sub-agent research-bot points at a different version" in document["risk_increasing"]


def test_moving_an_agent_into_production_is_classified_as_an_increase():
    before = load_text("""
agent: demo
version: "1"
environment: staging
owner: platform@example.com
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: search
    effects:
      - read
""")
    after = load_text("""
agent: demo
version: "1"
environment: production
owner: platform@example.com
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: search
    effects:
      - read
""")

    entry = next(
        item for item in diff(before, after)["metadata_changed"] if item["field"] == "environment"
    )

    assert entry["risk"] == "increase"
    assert entry == {"field": "environment", "from": "staging", "to": "production", "risk": "increase"}


def test_losing_the_owner_is_classified_as_an_increase_too():
    before = load_text("""
agent: demo
owner: platform@example.com
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: search
    effects:
      - read
""")
    after = load_text("""
agent: demo
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: search
    effects:
      - read
""")

    entry = next(item for item in diff(before, after)["metadata_changed"] if item["field"] == "owner")

    assert entry["risk"] == "increase"


@pytest.mark.parametrize(
    "before_extra,after_extra",
    [
        ("", "identities:\n  - name: bot\n"),
        ("", "data_sources:\n  - name: jira\n    classification: internal\n"),
        ("", "sub_agents:\n  - name: research-bot\n    digest: sha256:aa\n"),
        (
            "identities:\n  - name: bot\n    scopes:\n      - a\n",
            "identities:\n  - name: bot\n    scopes:\n      - a\n      - b\n",
        ),
        (
            "data_sources:\n  - name: jira\n    classification: internal\n",
            "data_sources:\n  - name: jira\n    classification: restricted\n",
        ),
    ],
)
def test_every_change_that_moves_the_digest_is_explained_by_some_section(before_extra, after_extra):
    """The property the diff has to hold, stated as a property.

    A digest that moved with every section empty is the worst possible output
    of a change-review tool: it tells the reviewer that something matters and
    refuses to say what. This is the parametrised version of "did we cover
    everything", and it is the test that fails when a field is added to the
    model and forgotten here.
    """
    before, after = _versions(before_extra, after_extra)
    document = diff(before, after)

    assert document["from_digest"] != document["to_digest"], "the fixture has to change something"
    assert document["explains_digest_change"] is True


def test_a_diff_of_one_declaration_with_itself_is_empty_everywhere():
    agent = load_text(declaration("""
  - name: search
    effects:
      - read
"""))

    document = diff(agent, agent)

    assert document["from_digest"] == document["to_digest"]
    assert document["risk_increasing"] == []
    assert not any(
        document[key]
        for key in document
        if isinstance(document[key], list)
    )
