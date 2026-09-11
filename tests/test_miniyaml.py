"""The hand-written YAML subset, and the two shapes it used to drop in silence.

Design note D-110. The parser exists because PyYAML would be the second
runtime dependency of a tool whose argument is that it has one. That trade is
only defensible if the parser refuses what it cannot read, loudly. A key
silently dropped is how an operator ends up believing they denied something
they did not.
"""
from __future__ import annotations

import pytest

from actaira.miniyaml import loads


def test_a_list_of_mappings_keeps_every_key():
    """The shape the first version dropped.

    `- id: x` followed by `  effect: deny` came back as the string
    "id: x" and every continuation line was lost, so a policy file's rules
    parsed into a list of strings and only the first key of each survived.
    """
    document = loads(
        """
rules:
  - id: no-high
    effect: deny
    when:
      finding_severity_at_least: high
  - id: review-unknown
    effect: review
    when:
      detected_format: unknown
"""
    )

    assert [rule["id"] for rule in document["rules"]] == ["no-high", "review-unknown"]
    assert document["rules"][0]["effect"] == "deny"
    assert document["rules"][0]["when"] == {"finding_severity_at_least": "high"}
    assert document["rules"][1]["when"] == {"detected_format": "unknown"}


def test_a_sequence_flush_with_its_key_is_the_key_s_value():
    """Legal YAML and the shape most people type. Without the branch that
    handles it the key came back None and the list became a sibling of its
    own parent - present in the document, attached to nothing."""
    document = loads(
        """
imports_callable:
- os.
- subprocess.
after: yes
"""
    )

    assert document["imports_callable"] == ["os.", "subprocess."]
    assert document["after"] is True


def test_a_sequence_indented_under_its_key_parses_the_same_way():
    document = loads(
        """
imports_callable:
  - os.
  - subprocess.
"""
    )

    assert document["imports_callable"] == ["os.", "subprocess."]


def test_a_folded_block_scalar_becomes_one_line_and_a_literal_keeps_its_breaks():
    document = loads(
        """
folded: >-
  first line
  second line
literal: |-
  first line
  second line
"""
    )

    assert document["folded"] == "first line second line"
    assert document["literal"] == "first line\nsecond line"


def test_scalars_are_typed_the_way_a_reader_would_expect():
    document = loads(
        """
version: 3
ratio: 1.5
enabled: true
disabled: no
absent: null
quoted: "3"
bare: hello world
"""
    )

    assert document["version"] == 3
    assert document["ratio"] == 1.5
    assert document["enabled"] is True
    assert document["disabled"] is False
    assert document["absent"] is None
    assert document["quoted"] == "3", "quoting is how a reader says 'this is text'"
    assert document["bare"] == "hello world"


def test_comments_and_blank_lines_are_ignored():
    document = loads(
        """
# a leading comment
policy: demo   # a trailing one

version: 1
"""
    )

    assert document == {"policy": "demo", "version": 1}


def test_a_line_outside_the_subset_raises_rather_than_being_skipped():
    """The important half. A parser that skipped what it could not read would
    turn an unsupported construct into a missing rule, and a missing rule into
    a permission nobody granted."""
    with pytest.raises(ValueError):
        loads("this line has no colon and is not a list item\n")


def test_an_empty_document_is_an_empty_mapping():
    assert loads("") == {}
    assert loads("# only a comment\n") == {}


# --------------------------------------------------------------------------
# DEF-66: a colon is not a mapping unless YAML says it is
# --------------------------------------------------------------------------


def test_a_colon_with_no_space_after_it_is_part_of_the_scalar():
    """The defect, written as the rule that was missing.

    `- jira:write` was read as `{"jira": "write"}`, so every scope in the
    shipped agent declaration reached the A-BOM as the string
    `"{'jira': 'write'}"`. YAML opens a value only when the colon is followed
    by a space or ends the line, which is why `sha256:aaaa` and
    `http://example.com` survive every real parser intact.
    """
    assert loads("scopes:\n  - jira:write\n  - github:write\n") == {
        "scopes": ["jira:write", "github:write"]
    }


def test_a_colon_followed_by_a_space_still_opens_a_mapping():
    assert loads("items:\n  - name: a\n    kind: b\n") == {"items": [{"name": "a", "kind": "b"}]}


def test_a_url_keeps_its_scheme():
    assert loads("source: http://example.com/a\n") == {"source": "http://example.com/a"}


def test_a_digest_reference_is_one_scalar():
    assert loads("reference: ghcr.io/x/y@sha256:abcd\n") == {"reference": "ghcr.io/x/y@sha256:abcd"}


def test_a_colon_at_the_end_of_a_line_opens_a_value():
    assert loads("outer:\n  inner: 1\n") == {"outer": {"inner": 1}}


def test_a_colon_inside_quotes_opens_nothing():
    assert loads('items:\n  - "a: b"\n') == {"items": ["a: b"]}


def test_the_shipped_declaration_keeps_its_scopes_verbatim():
    """The end-to-end half. A scope is exactly the field a reviewer compares
    between two releases, so publishing a stringified dictionary there made
    the diff unreadable in the one place it mattered."""
    from pathlib import Path

    from actaira.agentgov import load
    from conftest import REPO_ROOT

    agent = load(Path(REPO_ROOT) / "examples" / "agent-ticket-triage.yaml")
    identity = next(item for item in agent.identities if item.name == "triage-bot")

    assert identity.scopes == ("jira:write", "github:write")


# --------------------------------------------------------------------------
# DEF-94: the inline list everybody writes
# --------------------------------------------------------------------------


def test_an_inline_list_is_a_list():
    """The defect, found by writing a declaration the way a person would
    rather than the way the tests do. `effects: [read, write]` came back as
    the STRING "[read, write]", and every caller then did something different
    and wrong with it."""
    assert loads("effects: [read, untrusted_input]\n") == {
        "effects": ["read", "untrusted_input"]
    }


def test_an_empty_inline_list_is_an_empty_list():
    assert loads("uses: []\n") == {"uses": []}


def test_an_inline_list_nests():
    assert loads("a: [x, [y, z]]\n") == {"a": ["x", ["y", "z"]]}


def test_a_comma_inside_quotes_does_not_split_an_inline_list():
    assert loads('a: ["x, y", z]\n') == {"a": ["x, y", "z"]}


def test_an_inline_list_of_numbers_keeps_them_as_numbers():
    assert loads("a: [1, 2, 3]\n") == {"a": [1, 2, 3]}


def test_an_inline_list_survives_inside_a_block_sequence():
    assert loads("tools:\n  - name: t\n    effects: [read]\n") == {
        "tools": [{"name": "t", "effects": ["read"]}]
    }


def test_a_declaration_written_with_inline_lists_loads():
    """End to end, because that is how the defect was found."""
    from actaira.agentgov import load_text

    agent = load_text("""
agent: demo
model: m
model_digest: sha256:1
prompt_sha256: 2
tools:
  - name: read_web
    effects: [read, untrusted_input]
""")

    assert sorted(effect.value for effect in agent.tools[0].effects) == ["read", "untrusted_input"]
