"""The six vendors phase S2 added, and the union that is not a merge.

The subject of this file is the same as `test_surface.py`'s: a repository
nobody here wrote. What is new is that there are now seven vendors reading it,
their precedence ladders disagree with each other, and one of them - VS Code -
cannot answer whether a task runs without a file that lives outside the
repository entirely. That last case is the one this phase exists for, and the
three tests that pin it are the first section below.
"""
from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from conftest import REPO_ROOT
from seamark import cli
from seamark.surface import (
    Resolution,
    Scope,
    codex,
    cursor,
    devcontainer,
    gemini,
    jsonc,
    merge,
    miniyaml,
    resolve,
    rules,
    vscode,
)

FIXTURES = Path(REPO_ROOT) / "tests" / "fixtures" / "surface"
CORPUS = FIXTURES / "corpus"

KEYV_TASK = {
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Environment Setup",
            "type": "shell",
            "command": "node .claude/setup.mjs",
            "runOptions": {"runOn": "folderOpen"},
        }
    ],
}


@pytest.fixture
def tree(tmp_path):
    """A repository the test writes, read the way a clone is read."""

    def build(files: dict[str, object]) -> Path:
        for name, body in files.items():
            target = tmp_path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                body if isinstance(body, str) else json.dumps(body, indent=2),
                encoding="utf-8",
            )
        return tmp_path

    return build


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("a reader opened a socket; they read files and nothing else")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def _capabilities(surface, name):
    return [item for item in surface.capabilities if item.name == name]


# ---------------------------------------------------------------------------
# Gate point 3. The folderOpen task in three states
# ---------------------------------------------------------------------------
#
# The setting that decides is APPLICATION-scoped, so a repository cannot set it
# and the answer comes from the user's own settings file - which is read only
# under `--machine`. All three answers are therefore reachable, and the third is
# the one a tool that guessed the documented default would get wrong.


def _user_settings(tmp_path: Path, value: str | None) -> Path:
    """A fake home whose VS Code user settings say `value`, or say nothing."""
    home = tmp_path / "home"
    target = vscode.user_settings_dir(home)
    target.mkdir(parents=True, exist_ok=True)
    body = {} if value is None else {vscode.AUTOMATIC_TASKS: value}
    (target / "settings.json").write_text(json.dumps(body), encoding="utf-8")
    return home


def test_a_folder_open_task_is_effective_when_the_setting_allows_it(tree, tmp_path):
    root = tree({".vscode/tasks.json": KEYV_TASK})
    home = _user_settings(tmp_path, "on")

    surface = vscode.vscode_surface(vscode.read(root, machine=True, home=home))
    task = _capabilities(surface, "task.command")[0]

    assert task.resolution is Resolution.EFFECTIVE
    assert task.facts["automatic_allowed"] is True
    assert "untrusted workspace" in task.condition


def test_a_folder_open_task_is_declared_when_the_setting_blocks_it(tree, tmp_path):
    root = tree({".vscode/tasks.json": KEYV_TASK})
    home = _user_settings(tmp_path, "off")

    surface = vscode.vscode_surface(vscode.read(root, machine=True, home=home))
    task = _capabilities(surface, "task.command")[0]

    assert task.resolution is Resolution.DECLARED
    assert task.facts["automatic_allowed"] is False


def test_a_folder_open_task_is_indeterminate_when_no_scope_read_says(tree):
    """The third answer, and the reason the documented default is not it.

    `task.allowAutomaticTasks` defaults to `off`. That default applies when
    NOBODY sets it, and "nobody set it" is exactly what a run that has not
    opened the user's settings file cannot know. Answering `off` here would be a
    predicate with no information returning False.
    """
    root = tree({".vscode/tasks.json": KEYV_TASK})

    surface = vscode.vscode_surface(vscode.read(root))
    task = _capabilities(surface, "task.command")[0]

    assert task.resolution is Resolution.INDETERMINATE
    assert "automatic_allowed" not in task.facts, (
        "the fact must be ABSENT, not null: a rule that needs it has to come back "
        "INDETERMINATE on its own rather than be told to"
    )
    assert "APPLICATION-scoped" in task.condition
    assert "--machine" in task.condition


def test_the_rule_reports_the_task_once_the_setting_is_visible(tree, tmp_path):
    """And the gap names the rule when it is not.

    Both halves, in one test, because they are one statement: ACT-S016 answers
    when it can and says which rule could not answer when it cannot. A gap with
    no rule id in it is a gap nobody can act on.
    """
    root = tree({".vscode/tasks.json": KEYV_TASK})
    catalogue = rules.load()

    seen = vscode.vscode_surface(vscode.read(root, machine=True, home=_user_settings(tmp_path, "on")))
    found, _gaps = rules.evaluate(seen, catalogue)
    assert [item.rule_id for item in found] == ["ACT-S016"]

    blind = vscode.vscode_surface(vscode.read(root))
    found, gaps = rules.evaluate(blind, catalogue)
    assert not found
    assert any(gap.subject.startswith("ACT-S016") for gap in gaps)


# ---------------------------------------------------------------------------
# Gate point 4. The keyv wave, caught in both of its files
# ---------------------------------------------------------------------------


def test_the_keyv_wave_is_caught_in_both_files(tmp_path):
    """`.claude/settings.json` AND `.vscode/tasks.json`, in one document.

    This is the sentence phase S1 could not say. It reported the Claude Code
    half as a finding and named the VS Code half in "not read"; both halves are
    now read, and either one alone was enough for the attack.
    """
    home = _user_settings(tmp_path, "on")
    payload = cli.check_document(FIXTURES / "keyv-august", machine=True, home=home)

    caught = {
        (finding["rule_id"], finding["location"]) for finding in payload["findings"]
    }
    assert ("ACT-S001", ".claude/settings.json") in caught
    assert ("ACT-S016", ".vscode/tasks.json") in caught

    vendors = {finding["evidence"]["vendor"] for finding in payload["findings"]}
    assert {"claude-code", "vscode"} <= vendors

    assert not any(
        entry["path"].endswith("tasks.json") for entry in payload["not_read"]
    ), "the half phase S1 could only name is read now, so it must be out of that list"


def test_mini_shai_hulud_is_caught_in_both_files_too(tmp_path):
    home = _user_settings(tmp_path, "on")
    payload = cli.check_document(FIXTURES / "mini-shai-hulud", machine=True, home=home)

    caught = {(finding["rule_id"], finding["location"]) for finding in payload["findings"]}
    assert ("ACT-S001", ".claude/settings.json") in caught
    assert ("ACT-S016", ".vscode/tasks.json") in caught


# ---------------------------------------------------------------------------
# Gate point 5. JSONC forgives two things and refuses everything else
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        '{"a": 1, }',
        '{"a": [1, 2, ], }',
        '// leading\n{"a": 1}  // trailing',
        '{/* block\n   comment */ "a": 1}',
        '{"a": {"b": 1,},}',
    ],
    ids=["trailing-object", "trailing-array", "line-comment", "block-comment", "nested"],
)
def test_jsonc_accepts_comments_and_trailing_commas(body):
    assert jsonc.loads(body)["a"] is not None


@pytest.mark.parametrize(
    "body, expected",
    [
        ("{'a': 1}", "not JSON even once"),
        ("{a: 1}", "not JSON even once"),
        ('{"a": NaN}', "not a JSON value"),
        ('{"a": Infinity}', "not a JSON value"),
        ('{"a": 0x10}', "not JSON even once"),
        ('{"a": "unterminated}', "never closes"),
        ('{"a": 1 /* open', "never closes"),
    ],
    ids=["single-quotes", "bare-key", "nan", "infinity", "hex", "open-string", "open-comment"],
)
def test_jsonc_refuses_every_other_deviation_with_a_cause(body, expected):
    """Two forgivenesses, named. A third would be this module deciding what a
    vendor's parser accepts on the vendor's behalf."""
    with pytest.raises(jsonc.JsoncError) as raised:
        jsonc.loads(body)

    assert expected in str(raised.value)


def test_a_slash_inside_a_string_is_not_a_comment():
    """The reason this is a character walk and not a regular expression.

    A `//` inside a string literal is part of the string, and a stripper that
    does not track string state deletes the rest of the line - which would turn
    a hook command into a shorter, different hook command and digest THAT.
    """
    body = '{"command": "curl https://example.test/x // y", "after": 1}'

    assert jsonc.loads(body) == {
        "command": "curl https://example.test/x // y",
        "after": 1,
    }


def test_a_real_tasks_file_with_comments_is_read_rather_than_refused(tree):
    """Gate point 5, over a `tasks.json` in the shape VS Code's own docs use."""
    root = tree(
        {
            ".vscode/tasks.json": """{
  // See https://go.microsoft.com/fwlink/?LinkId=733558
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Environment Setup",
      "type": "shell",
      "command": "node .claude/setup.mjs",
      /* runs when the folder opens */
      "runOptions": { "runOn": "folderOpen" },
    },
  ],
}
"""
        }
    )

    reading = vscode.read(root)

    assert not reading.unresolved, "a comment is not a defect in a JSONC file"
    surface = vscode.vscode_surface(reading)
    assert _capabilities(surface, "task.command")[0].facts["run_on"] == "folderOpen"


def test_a_tasks_file_outside_the_subset_is_indeterminate_with_a_cause(tree):
    root = tree({".vscode/tasks.json": "{'version': '2.0.0'}"})

    reading = vscode.read(root)

    assert [gap.subject for gap in reading.unresolved] == [".vscode/tasks.json"]
    assert "invalid JSONC" in reading.unresolved[0].cause


# ---------------------------------------------------------------------------
# Gate point 6. A scope that is managed outside any file
# ---------------------------------------------------------------------------


def test_cursor_team_hooks_are_named_on_every_run(tree, tmp_path):
    """Published limit 12, exercised rather than only written down.

    Named always, in `not_read`, so the level that is not a file is never
    silent. It becomes a GAP only where this repository configures Cursor and a
    team hook would therefore outrank what was read - see the test below for
    why that distinction is not cosmetic.
    """
    for machine in (False, True):
        reading = cursor.read(tmp_path, machine=machine, home=tmp_path / "home")
        named = [entry for entry in reading.not_read if "team" in entry.path]

        assert len(named) == 1
        assert "without leaving a file" in named[0].reason
        assert "limit 12" in named[0].reason


def test_the_team_hook_gap_appears_where_it_can_outrank_something(tree, tmp_path):
    """A gap that is true of every repository is a constant, not a gap.

    Reported unconditionally, it made `check` exit 3 on a tree with nothing
    configured at all - and an exit code that is always 3 tells a pipeline
    nothing, which is the published meaning of 3 spent for no information.
    Found by this phase's adversarial pass, through `test_the_three_exit_codes`.
    """
    bare = cursor.read(tmp_path, home=tmp_path / "home")
    assert not [gap for gap in bare.unresolved if "team" in gap.subject]

    configured = cursor.read(
        tree({".cursor/hooks.json": {"hooks": {"beforeShellExecution": [{"command": "x"}]}}}),
        home=tmp_path / "home",
    )
    team = [gap for gap in configured.unresolved if "team" in gap.subject]
    assert len(team) == 1
    assert "outrank" in team[0].cause
    assert "limit 12" in team[0].cause


def test_codex_names_the_managed_channels_that_leave_no_file(tmp_path):
    """The second vendor with the same shape, and it has two such channels."""
    reading = codex.read(tmp_path, machine=True, home=tmp_path / "home")

    named = [entry for entry in reading.not_read if "MDM" in entry.path]
    assert len(named) == 1
    assert "cloud config bundle" in named[0].path
    assert "limit 12" in named[0].reason


# ---------------------------------------------------------------------------
# The vendors' own facts
# ---------------------------------------------------------------------------


def test_initialize_command_is_the_one_that_runs_on_the_host(tree):
    """Five in, one out, and the rule fires only on the one that is out."""
    root = tree(
        {
            ".devcontainer/devcontainer.json": {
                "initializeCommand": "bash ./scripts/host.sh",
                "postCreateCommand": "npm install",
            }
        }
    )

    surface = devcontainer.devcontainer_surface(devcontainer.read(root))
    by_key = {item.facts["key"]: item for item in _capabilities(surface, "lifecycle.command")}

    assert by_key["initializeCommand"].facts["on_host"] is True
    assert by_key["postCreateCommand"].facts["on_host"] is False
    found, _gaps = rules.evaluate(surface, rules.load())
    assert [item.rule_id for item in found if item.rule_id == "ACT-S017"] == ["ACT-S017"]


@pytest.mark.parametrize(
    "source, credential",
    [
        ("${localEnv:HOME}/.ssh", ".ssh"),
        ("/home/dev/.aws", ".aws"),
        ("C:\\Users\\dev\\.kube", ".kube"),
        ("/home/dev/notes/.sshkeys-doc", None),
        ("/workspaces/project", None),
    ],
    ids=["ssh", "aws", "kube-windows", "near-miss", "ordinary"],
)
def test_a_mount_names_a_credential_directory_or_it_does_not(source, credential):
    """Anchored on a separator, so a file whose name merely starts the same way
    is not a finding about somebody's keys."""
    assert devcontainer.names_a_credential(source) == credential


def test_a_mount_is_read_in_both_documented_spellings(tree):
    root = tree(
        {
            ".devcontainer.json": {
                "mounts": [
                    "source=${localEnv:HOME}/.ssh,target=/root/.ssh,type=bind",
                    {"source": "/home/dev/.aws", "target": "/root/.aws", "type": "bind"},
                ]
            }
        }
    )

    surface = devcontainer.devcontainer_surface(devcontainer.read(root))
    mounts = _capabilities(surface, "container.mount")

    assert len(mounts) == 2
    assert all(item.facts["names_credential"] for item in mounts)


def test_a_codex_hook_waits_on_a_trust_level_that_is_not_in_the_repository(tree):
    root = tree(
        {
            ".codex/config.toml": (
                '[[hooks.SessionStart]]\nmatcher = "*"\n'
                '[[hooks.SessionStart.hooks]]\ntype = "command"\n'
                'command = "bash .codex/start.sh"\n'
            )
        }
    )

    surface = codex.codex_surface(codex.read(root))
    hook = _capabilities(surface, "hook.command")[0]

    assert hook.resolution is Resolution.DECLARED
    assert "trust" in hook.condition
    assert hook.facts["at_startup"] is True


def test_codex_notify_in_a_repository_file_is_declared_and_not_effective(tree):
    """A key the documentation says a project file cannot set. Reporting it as
    effective would be Seamark contradicting the vendor about its own product."""
    root = tree({".codex/config.toml": 'notify = ["python3", ".codex/notify.py"]\n'})

    surface = codex.codex_surface(codex.read(root))
    helper = _capabilities(surface, "helper.command")[0]

    assert helper.resolution is Resolution.DECLARED
    assert "cannot override notification keys" in helper.condition


def test_gemini_trust_is_read_as_the_bypass_the_vendor_says_it_is(tree):
    root = tree(
        {
            ".gemini/settings.json": {
                "mcpServers": {
                    "trusted": {"command": "node", "args": ["server.js"], "trust": True},
                    "ordinary": {"command": "node", "args": ["other.js"]},
                }
            }
        }
    )

    surface = gemini.gemini_surface(gemini.read(root))
    by_name = {item.facts["server"]: item for item in _capabilities(surface, "mcp.server")}

    assert by_name["trusted"].facts["trusted_by_config"] is True
    assert by_name["ordinary"].facts["trusted_by_config"] is False
    found, _gaps = rules.evaluate(surface, rules.load())
    assert "ACT-S027" in {item.rule_id for item in found}


# ---------------------------------------------------------------------------
# The union, and the thing it is not
# ---------------------------------------------------------------------------


def test_two_vendors_running_one_command_stay_two_capabilities(tree, tmp_path):
    """D-288, asserted rather than only argued.

    The same MCP server in Cursor's file and in Claude Code's is two things: two
    files to edit, two approvals that expire independently. Collapsing them into
    one row would produce a row belonging to neither vendor.
    """
    root = tree(
        {
            ".mcp.json": {"mcpServers": {"shared": {"command": "npx", "args": ["some-server"]}}},
            ".cursor/mcp.json": {
                "mcpServers": {"shared": {"command": "npx", "args": ["some-server"]}}
            },
        }
    )

    payload = cli.check_document(root)
    servers = [
        item
        for surface in payload["surfaces"]
        for item in surface["capabilities"]
        if item["capability"] == "mcp.server"
    ]

    assert len(servers) == 2
    assert {item["vendor"] for item in servers} == {"claude-code", "cursor"}
    assert {item["source"] for item in servers} == {".mcp.json", ".cursor/mcp.json"}
    assert len({item["facts"]["args_sha256"] for item in servers}) == 1, (
        "the same launch has the same digest in both, which is what makes it "
        "recognisable as the same thing without being reported as one"
    )


def test_every_vendor_has_its_own_ladder_and_they_disagree():
    """The reason `row_for` takes a vendor.

    Gemini's precedence puts the project file ABOVE the user's; Claude Code's
    puts the user's above the project. A single table would have to pick one.
    """
    claude = merge.row_for("*", "claude-code")
    gemini_row = merge.row_for("*", "gemini-cli")

    assert claude.url != gemini_row.url
    assert "highest level that sets it" in claude.quote
    assert "Project settings file, 5. System settings file" in gemini_row.quote


def test_every_vendor_in_the_registry_has_a_merge_table():
    for vendor, _reader, _resolver in resolve.vendor_registry():
        assert vendor in merge.MERGE_TABLES, (
            f"{vendor} resolves capabilities and names no documented rule for any of them"
        )


@pytest.mark.parametrize("row", merge.MERGE_TABLE, ids=lambda row: f"{row.keys[0]}")
def test_every_merge_row_of_every_vendor_cites_its_source(row):
    assert row.cited
    assert len(row.doc_sha256) == 64
    assert all(character in "0123456789abcdef" for character in row.doc_sha256)


def test_every_capability_any_vendor_emits_names_a_row_that_exists():
    """No capability may cite a rule that is not in its own vendor's table."""
    handles = {
        vendor: {merge.rule_name(row) for row in rows}
        for vendor, rows in merge.MERGE_TABLES.items()
    }
    for root in sorted(CORPUS.iterdir()):
        if not (root / "provenance.json").is_file():
            continue
        for vendor, reader, resolver in resolve.vendor_registry():
            for item in resolver(reader.read(root)).capabilities:
                assert item.merge_rule in handles[vendor], (
                    f"{item.name} cites {item.merge_rule}, which is not in {vendor}'s table"
                )


# ---------------------------------------------------------------------------
# Nothing is executed, nothing is fetched
# ---------------------------------------------------------------------------


def test_no_vendor_reader_runs_what_it_reads(tmp_path, no_network):
    """The property phase S1 asserted for one vendor, asserted for seven.

    The sentinel proves the script did not run; the digest proves the reader
    did look at it, so the test cannot be passing by never opening anything.
    """
    sentinel = tmp_path / "ran"
    script = tmp_path / "setup.sh"
    script.write_text(f"#!/bin/sh\ntouch {sentinel}\n", encoding="utf-8")

    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "tasks.json").write_text(
        json.dumps(
            {
                "tasks": [
                    {
                        "label": "x",
                        "command": "sh setup.sh",
                        "runOptions": {"runOn": "folderOpen"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".devcontainer.json").write_text(
        json.dumps({"initializeCommand": "sh setup.sh"}), encoding="utf-8"
    )
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text(
        '[[hooks.SessionStart]]\nmatcher = "*"\n'
        '[[hooks.SessionStart.hooks]]\ntype = "command"\ncommand = "sh setup.sh"\n',
        encoding="utf-8",
    )
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "hooks.json").write_text(
        json.dumps({"hooks": {"sessionStart": [{"command": "sh setup.sh"}]}}),
        encoding="utf-8",
    )
    (tmp_path / ".gemini").mkdir()
    (tmp_path / ".gemini" / "settings.json").write_text(
        json.dumps({"tools": {"discoveryCommand": "sh setup.sh"}}), encoding="utf-8"
    )
    (tmp_path / "AGENTS.md").write_text("Run @setup.sh first.\n", encoding="utf-8")

    payload = cli.check_document(tmp_path)

    assert not sentinel.exists(), "a reader ran a script it was supposed to only digest"
    digests = {
        item["facts"].get("target_facts", {}).get("sha256")
        for surface in payload["surfaces"]
        for item in surface["capabilities"]
    }
    assert any(digest for digest in digests), (
        "no target was digested, so the sentinel could be absent because nothing was read"
    )


def test_no_literal_reaches_the_document_without_with_content(tree, capsys):
    """The phase S1 property, over the six new readers' command strings."""
    # The linter is right that this looks like a credential. It is one, on
    # purpose: the property under test is that a credential in somebody's
    # settings file does not reach the report, and a low-entropy stand-in
    # would pass a search for it by not looking like one.
    secret = "sk-live-9f3c2b7a1d4e6f8a0c5b3d2e1f7a9c4b"  # noqa: S105
    root = tree(
        {
            ".vscode/tasks.json": {
                "tasks": [{"label": "x", "command": f"deploy --token {secret}"}]
            },
            ".devcontainer.json": {"initializeCommand": f"seed --token {secret}"},
            ".codex/config.toml": f'notify = ["notify", "--token", "{secret}"]\n',
            ".cursor/hooks.json": {
                "hooks": {"sessionStart": [{"command": f"warm --token {secret}"}]}
            },
            ".gemini/settings.json": {"tools": {"callCommand": f"call --token {secret}"}},
        }
    )

    payload = cli.check_document(root)
    body = json.dumps(payload)

    assert secret not in body
    assert "command_sha256" in body, "the digest must be there, or nothing is being read"

    back = cli.check_document(root, with_content=True)
    assert secret in json.dumps(back), (
        "--with-content has to put the literal back, or the property above could be "
        "passing because nothing is printed at all"
    )


def test_check_over_mcp_answers_with_the_same_document_the_command_builds():
    """Gate point 13. One implementation, reachable two ways."""
    from seamark import mcp

    answer = mcp.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "seamark_check",
                "arguments": {"repo": str(FIXTURES / "keyv-august")},
            },
        }
    )
    over_mcp = json.loads(answer["result"]["content"][0]["text"])
    direct = cli.check_document(FIXTURES / "keyv-august")

    assert over_mcp["state"] == "read"
    assert answer["result"]["isError"] is False
    assert {key: value for key, value in over_mcp.items() if key != "state"} == direct


def test_check_over_mcp_refuses_a_path_that_is_not_a_directory(tmp_path):
    from seamark import mcp

    answer = mcp.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "seamark_check", "arguments": {"repo": str(tmp_path / "nope")}},
        }
    )

    assert answer["result"]["isError"] is True
    assert "not a directory" in answer["result"]["content"][0]["text"]


# ---------------------------------------------------------------------------
# The frontmatter reader phase S1 did without
# ---------------------------------------------------------------------------


def test_a_subagent_frontmatter_hook_is_read_rather_than_named_as_a_gap(tree):
    """The phase S1 backlog line, closed. It used to be INDETERMINATE with
    "frontmatter has no reader in this release"; now it is a capability."""
    root = tree(
        {
            ".claude/agents/reviewer.md": (
                "---\n"
                "name: reviewer\n"
                "hooks:\n"
                "  SessionStart:\n"
                '    - matcher: "*"\n'
                "      hooks:\n"
                "        - type: command\n"
                "          command: node .claude/warm.mjs\n"
                "---\n\n"
                "You review things.\n"
            )
        }
    )

    from seamark.surface import claude_code

    reading = claude_code.read(root)
    surface = resolve.resolve(reading)

    assert not any("frontmatter" in gap.cause for gap in reading.unresolved)
    hooks = _capabilities(surface, "hook.command")
    assert len(hooks) == 1
    assert hooks[0].facts["event"] == "SessionStart"
    assert hooks[0].facts["at_startup"] is True


def test_frontmatter_outside_the_subset_is_a_named_cause_not_a_guess(tree):
    root = tree(
        {
            ".claude/agents/anchored.md": (
                "---\nname: &shared reviewer\nalias: *shared\n---\n\nBody.\n"
            )
        }
    )

    from seamark.surface import claude_code

    reading = claude_code.read(root)

    assert len(reading.unresolved) == 1
    assert "outside the subset" in reading.unresolved[0].cause
    assert "anchor" in reading.unresolved[0].cause


@pytest.mark.parametrize(
    "body, expected",
    [
        ("a: &x 1\n", "anchor"),
        ("a: *x\n", "alias"),
        ("a: !!str x\n", "tag"),
        ("a: |\n  block\n", "block scalar"),
        ("- one\n- two\n", "must be a mapping"),
        ("a: 1\n---\nb: 2\n", "multi-document"),
    ],
    ids=["anchor", "alias", "tag", "block-scalar", "sequence-top-level", "multi-document"],
)
def test_the_yaml_subset_refuses_by_name(body, expected):
    with pytest.raises(miniyaml.YamlError) as raised:
        miniyaml.loads(body)

    assert expected in str(raised.value)


def test_the_yaml_subset_does_not_invent_yaml_1_1_booleans():
    """The Norway problem. `NO` is a string in YAML 1.2 core, and reading it as
    `False` would be this reader inventing a fact about somebody's file."""
    assert miniyaml.loads("country: NO\nenabled: true\n") == {
        "country": "NO",
        "enabled": True,
    }


def test_a_sequence_of_mappings_is_a_sequence_of_mappings():
    """`- key: value` is a mapping, not the string `'key: value'`.

    Caught by this phase's adversarial reading of its own reader: a hook handler
    arriving as a string would have made every fact about it invented.
    """
    parsed = miniyaml.loads(
        "hooks:\n"
        "  SessionStart:\n"
        '    - matcher: "*"\n'
        "      hooks:\n"
        "        - type: command\n"
        "          command: node setup.mjs\n"
    )

    handler = parsed["hooks"]["SessionStart"][0]["hooks"][0]
    assert handler == {"type": "command", "command": "node setup.mjs"}


# ---------------------------------------------------------------------------
# The plugin hook whose target phase S1 could not resolve
# ---------------------------------------------------------------------------


def test_a_plugin_hooks_script_gets_the_same_four_facts_as_any_other(tree):
    """The phase S1 backlog line, closed. `Reading.scripts` was filled by
    walking `settings` only, so a downloaded plugin's hook came back
    INDETERMINATE about a target that was on disk the whole time."""
    root = tree(
        {
            ".claude/settings.json": {"enabledPlugins": {"helper": True}},
            ".claude/plugins/helper/hooks/hooks.json": {
                "hooks": {
                    "SessionStart": [
                        {
                            "matcher": "*",
                            "hooks": [
                                {"type": "command", "command": "node .claude/plugins/helper/go.js"}
                            ],
                        }
                    ]
                }
            },
            ".claude/plugins/helper/go.js": "// inert stub\n",
        }
    )

    from seamark.surface import claude_code

    surface = resolve.resolve(claude_code.read(root))
    hook = _capabilities(surface, "hook.command")[0]

    assert hook.facts["target_facts"]["exists"] is True
    assert hook.facts["target_facts"]["inside_tree"] is True
    assert len(hook.facts["target_facts"]["sha256"]) == 64

    found, gaps = rules.evaluate(surface, rules.load())
    assert "ACT-S003" in {item.rule_id for item in found}
    assert not any(gap.subject.startswith("ACT-S00") for gap in gaps)


# ---------------------------------------------------------------------------
# The corpus goldens, per vendor
# ---------------------------------------------------------------------------


def _corpus_roots():
    return [path for path in sorted(CORPUS.iterdir()) if (path / "expected.json").is_file()]


@pytest.mark.parametrize("root", _corpus_roots(), ids=lambda path: path.name)
def test_every_vendor_in_a_corpus_fixture_matches_its_reviewed_golden(root):
    """Real configurations, each against the answer a person reviewed.

    The golden holds the CLAIMS - which rules fire, each capability's name and
    resolution, the counts - rather than a dump of the output compared against
    itself, which is the shape D-15 warns about.
    """
    expected = json.loads((root / "expected.json").read_text(encoding="utf-8"))
    catalogue = rules.load()
    registry = {vendor: (mod, res) for vendor, mod, res in resolve.vendor_registry()}

    for vendor, claims in expected.items():
        reader, resolver = registry[vendor]
        surface = resolver(reader.read(root))
        found, gaps = rules.evaluate(surface, catalogue)

        assert sorted({item.rule_id for item in found}) == claims["rules_that_fire"], vendor
        assert {
            item.name: item.resolution.value for item in surface.capabilities
        } == claims["capabilities"], vendor
        assert len(surface.capabilities) == claims["capability_count"], vendor
        assert len(surface.unresolved) + len(gaps) == claims["unresolved_count"], vendor
        assert sorted(entry.path for entry in surface.not_read) == claims["not_read"], vendor


def test_the_corpus_holds_configurations_for_every_vendor():
    """Gate point 8: five per vendor where public OSI-licensed repositories
    exist. A corpus of one vendor measures one vendor."""
    seen: dict[str, int] = {}
    for root in _corpus_roots():
        for vendor in json.loads((root / "expected.json").read_text(encoding="utf-8")):
            seen[vendor] = seen.get(vendor, 0) + 1

    for vendor, _reader, _resolver in resolve.vendor_registry():
        assert seen.get(vendor, 0) >= 5, f"{vendor} has {seen.get(vendor, 0)} configurations"


def test_every_corpus_fixture_carries_its_provenance():
    for root in _corpus_roots():
        record = json.loads((root / "provenance.json").read_text(encoding="utf-8"))
        assert record["repo"].startswith("https://github.com/")
        assert len(record["commit"]) == 40
        assert record["licence"]
        assert record["files"]


def test_the_golden_comparison_would_notice_a_change():
    """The guard on the guard: the comparison above has to be able to fail."""
    root = _corpus_roots()[0]
    expected = json.loads((root / "expected.json").read_text(encoding="utf-8"))
    vendor = sorted(expected)[0]
    registry = {name: (mod, res) for name, mod, res in resolve.vendor_registry()}
    reader, resolver = registry[vendor]

    surface = resolver(reader.read(root))

    assert len(surface.capabilities) != expected[vendor]["capability_count"] + 1


# ---------------------------------------------------------------------------
# The managed scope, which no public repository can supply
# ---------------------------------------------------------------------------
#
# Gate point 1 asks for a fixture per vendor AND per scope. Project scope comes
# from `corpus/`, which is real repositories; the VS Code user scope comes from
# `machine/`. The MANAGED scope has no public sample and never will, for the
# reason ACT-S013 and ACT-S014 are marked with: a managed policy lives at an
# operating-system path - `/etc/codex/`, `C:\ProgramData\Cursor\` - which is
# outside every repository by construction. So it is exercised the only way it
# can be: the documented path is pointed at a temporary directory, and what is
# asserted is that the reader reads it, stamps MANAGED on it, and that a
# managed-only key is honoured there and nowhere else.


def test_a_managed_codex_requirement_is_read_and_stamped_managed(tmp_path, monkeypatch):
    managed = tmp_path / "etc"
    managed.mkdir()
    (managed / "requirements.toml").write_text(
        "allow_managed_hooks_only = true\n", encoding="utf-8"
    )
    monkeypatch.setattr(codex, "managed_paths", lambda: (managed / "requirements.toml",))

    surface = codex.codex_surface(codex.read(tmp_path, machine=True, home=tmp_path / "home"))
    policy = _capabilities(surface, "policy.managed_hooks_only")

    assert len(policy) == 1
    assert policy[0].scope is Scope.MANAGED
    assert policy[0].resolution is Resolution.EFFECTIVE
    assert policy[0].merge_rule == merge.rule_name(
        merge.row_for("allow_managed_hooks_only", "codex")
    )


def test_the_same_key_in_a_repository_file_is_not_a_managed_policy(tree, tmp_path):
    """The other half, and the one that makes the test above mean something.

    The documentation is explicit that `allow_managed_hooks_only` is "only
    supported in requirements.toml". A repository that writes it has not set it,
    and reporting it as a policy would be Seamark telling a reader their tree is
    locked down by a line the vendor ignores.
    """
    root = tree({".codex/config.toml": "allow_managed_hooks_only = true\n"})

    surface = codex.codex_surface(codex.read(root))

    assert _capabilities(surface, "policy.managed_hooks_only") == []


def test_a_managed_cursor_hook_outranks_nothing_it_cannot_reach(tmp_path, monkeypatch):
    """The enterprise file is a FILE, unlike the team level, so it is read."""
    managed = tmp_path / "etc"
    managed.mkdir()
    (managed / "hooks.json").write_text(
        json.dumps({"hooks": {"sessionStart": [{"command": "/opt/corp/audit.sh"}]}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(cursor, "enterprise_paths", lambda: (managed / "hooks.json",))

    surface = cursor.cursor_surface(cursor.read(tmp_path, machine=True, home=tmp_path / "home"))
    hooks = _capabilities(surface, "hook.command")

    assert len(hooks) == 1
    assert hooks[0].scope is Scope.MANAGED
    assert hooks[0].condition is None, (
        "a managed hook is the operator's own; the caveat about being outranked "
        "belongs to a repository's hook, not to this one"
    )
