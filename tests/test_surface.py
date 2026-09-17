"""The reader, the merge table and the command, against somebody else's files.

The subject of this file is a repository nobody here wrote. Every test that
looks like paranoia - a symlink out of the tree, a settings file larger than the
ceiling, a hook whose command would leave a sentinel behind - is about the same
threat: `check` runs on a clone of a pull request, and the input is controlled by
whoever opened it. `SECURITY.md` names each of these tests beside the defence it
holds down.
"""
from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

from actaira import cli
from actaira.surface import Resolution, claude_code, resolve, rules
from conftest import REPO_ROOT

FIXTURES = Path(REPO_ROOT) / "tests" / "fixtures" / "surface"
CORPUS = FIXTURES / "corpus"


@pytest.fixture
def repo(tmp_path):
    """A repository with a settings file, written by the test, read as a clone."""

    def build(settings: dict | str, *, name: str = ".claude/settings.json") -> Path:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            settings if isinstance(settings, str) else json.dumps(settings, indent=2),
            encoding="utf-8",
        )
        return tmp_path

    return build


@pytest.fixture
def no_network(monkeypatch):
    """Any socket at all fails the test that asked for it.

    `check` reads files. It has no reason to open a socket, and a test that
    merely happens not to reach the network does not check that.
    """

    def refuse(*args, **kwargs):
        raise AssertionError("check opened a socket; it reads files and nothing else")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


# ---------------------------------------------------------------------------
# The merge table: every row cited, and the check verified to bite
# ---------------------------------------------------------------------------


def test_the_merge_table_is_not_empty():
    assert len(resolve.MERGE_TABLE) >= 10, "the table is how a capability names its rule"


@pytest.mark.parametrize(
    "row", resolve.MERGE_TABLE, ids=lambda row: "{}:{}".format(row.url.rsplit("/", 1)[-1], row.keys[0])
)
def test_every_merge_row_cites_its_source(row):
    """The rule, the URL, the page digest, the date, and the sentence.

    A row that cannot say where it came from is an opinion about somebody else's
    software, and CLAUDE.md's second negative forbids Actaira having one.
    """
    assert row.cited, f"{row.keys} is missing part of its citation"
    assert row.url.startswith("https://code.claude.com/docs/"), row.url
    assert len(row.doc_sha256) == 64 and all(c in "0123456789abcdef" for c in row.doc_sha256)
    assert row.consulted == resolve.CONSULTED
    assert len(row.quote) > 40, "the quote must be the sentence, not a gesture at it"
    assert row.kind in resolve.Kind


def test_the_citation_check_would_notice_an_uncited_row():
    """The guard on the guard, and the reason this file is worth reading.

    A check over a table is worth what its failure mode is worth. So a row is
    built with each part of the citation removed in turn, and every one of them
    must be refused. Without this, `cited` could be returning True for
    everything and the parametrised test above would pass over an empty promise.
    """
    good = resolve.MERGE_TABLE[0]
    assert good.cited, "the fixture row is not itself cited; this test proves nothing"

    from dataclasses import replace

    for field, broken in (
        ("url", ""),
        ("doc_sha256", ""),
        ("doc_sha256", "not-a-digest"),
        ("consulted", "  "),
        ("quote", ""),
    ):
        assert not replace(good, **{field: broken}).cited, (
            f"a row with {field}={broken!r} was accepted as cited"
        )


def test_every_capability_names_a_row_that_exists():
    """A capability's `merge_rule` is a promise that the row is in the table."""
    names = {resolve.rule_name(row) for row in resolve.MERGE_TABLE}
    surface = resolve.resolve(claude_code.read(FIXTURES / "mini-shai-hulud"))

    assert surface.capabilities
    for capability in surface.capabilities:
        assert capability.merge_rule in names, capability.merge_rule


# ---------------------------------------------------------------------------
# Declared versus effective, which is what the version decides
# ---------------------------------------------------------------------------

BYPASS = {"permissions": {"defaultMode": "bypassPermissions"}}


def test_bypass_in_a_project_file_is_effective_before_the_threshold(repo):
    surface = resolve.resolve(
        claude_code.read(repo(BYPASS)), agent_version="claude-code=2.1.200".split("=")[1]
    )
    mode = next(c for c in surface.capabilities if c.name == "permissions.default_mode")

    assert mode.resolution is Resolution.EFFECTIVE
    assert "2.1.257" in (mode.condition or "")


def test_bypass_in_a_project_file_is_not_effective_from_the_threshold(repo):
    surface = resolve.resolve(claude_code.read(repo(BYPASS)), agent_version="2.1.257")
    mode = next(c for c in surface.capabilities if c.name == "permissions.default_mode")

    assert mode.resolution is Resolution.DECLARED
    assert "2.1.257" in (mode.condition or "")


def test_bypass_with_no_version_is_indeterminate_and_names_the_threshold(repo):
    """The case the whole three-state model exists for. Answering either way
    here would be resolving with the version we found most plausible, which is
    published limit 13 and the third negative."""
    surface = resolve.resolve(claude_code.read(repo(BYPASS)))
    mode = next(c for c in surface.capabilities if c.name == "permissions.default_mode")

    assert mode.resolution is Resolution.INDETERMINATE
    assert "2.1.257" in (mode.condition or "")
    assert any("agent version" in gap.subject for gap in surface.unresolved)


def test_a_capability_that_waits_for_trust_is_declared_and_never_effective(repo):
    """CLAUDE.md: what waits for folder trust is DECLARED with the condition
    written out, never EFFECTIVE."""
    root = repo({"permissions": {"additionalDirectories": ["/etc"]}})
    surface = resolve.resolve(claude_code.read(root))
    entry = next(c for c in surface.capabilities if c.name == "permissions.additional_directory")

    assert entry.resolution is Resolution.DECLARED
    assert "trust" in (entry.condition or "").lower()


def test_a_hook_does_not_wait_for_trust_and_the_report_says_so(repo):
    """The correction the documentation forced, and the reason both worms work.

    Hooks in settings files sit in the row of the workspace-trust table that is
    Used before any trust step. A reader who assumed hooks were gated like
    `permissions.allow` would report the central capability of this phase as
    waiting for a dialog that never guards it.
    """
    root = repo(
        {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "sh x.sh"}]}]}}
    )
    surface = resolve.resolve(claude_code.read(root))
    hook = next(c for c in surface.capabilities if c.name == "hook.command")

    assert hook.resolution is Resolution.EFFECTIVE
    assert "before any workspace trust step" in (hook.condition or "")


# ---------------------------------------------------------------------------
# INDETERMINATE, by four causes, each reached
# ---------------------------------------------------------------------------


def test_invalid_json_is_indeterminate_and_never_an_empty_configuration(repo):
    """The one that decides whether this tool is honest.

    A malformed `.claude/settings.json` parsed as `{}` reports "no hooks", which
    is a clean report about a file nobody read.
    """
    root = repo('{"hooks": {"SessionStart": [', name=".claude/settings.json")
    reading = claude_code.read(root)
    surface = resolve.resolve(reading)

    assert surface.capabilities == ()
    assert any("invalid JSON" in gap.cause for gap in surface.unresolved)
    handle = next(item for item in reading.settings if item.display == ".claude/settings.json")
    assert handle.data is None, "an unparsed file must not reach a consumer as a mapping"


def test_an_unknown_agent_version_is_indeterminate(repo):
    surface = resolve.resolve(claude_code.read(repo(BYPASS)))

    assert any("version" in gap.cause for gap in surface.unresolved)


def test_frontmatter_with_hooks_is_indeterminate_because_there_is_no_yaml_reader(tmp_path):
    """`miniyaml` left in phase A and no dependency is being added for it, so a
    skill that declares hooks in its frontmatter is a stated gap rather than a
    guess at what the frontmatter said."""
    skill = tmp_path / ".claude" / "skills" / "deploy" / "SKILL.md"
    skill.parent.mkdir(parents=True, exist_ok=True)
    skill.write_text(
        "---\nname: deploy\nhooks:\n  SessionStart:\n    - type: command\n---\n\nbody\n",
        encoding="utf-8",
    )

    surface = resolve.resolve(claude_code.read(tmp_path))

    assert any("frontmatter" in gap.cause for gap in surface.unresolved)


def test_a_plugin_from_a_marketplace_that_is_not_on_disk_is_indeterminate(repo):
    root = repo({"enabledPlugins": {"github@official": True}})
    surface = resolve.resolve(claude_code.read(root))

    assert any("marketplace" in gap.cause for gap in surface.unresolved)


def test_the_four_causes_are_all_reachable_from_the_corpus_or_a_fixture():
    """The guard on the four above: each has to be a state this tree can reach,
    not a branch nobody exercises."""
    causes = set()
    for root in sorted(CORPUS.iterdir()):
        if not (root / "provenance.json").is_file():
            continue
        surface = resolve.resolve(claude_code.read(root))
        _found, gaps = rules.evaluate(surface, rules.load())
        for gap in (*surface.unresolved, *gaps):
            causes.add(gap.cause)

    assert any("marketplace" in cause for cause in causes), (
        "no corpus configuration reaches the undownloaded-plugin cause"
    )
    assert any("version" in cause for cause in causes), (
        "no corpus configuration reaches the unknown-version cause"
    )


# ---------------------------------------------------------------------------
# Literals never travel without --with-content
# ---------------------------------------------------------------------------

# One secret a scanner would spot and one it would not. The lesson of phase 1.1b
# is that a redaction tested only against something that looks like a secret
# passes while leaking everything that does not.
HIGH_ENTROPY = "ghp_A9f2Kx7QpL3mZ1vR8tYw4NbC6dHe0JsU5iOa"
LOW_ENTROPY = "hunter2"


@pytest.mark.parametrize("secret", [HIGH_ENTROPY, LOW_ENTROPY], ids=["high", "low"])
def test_no_literal_reaches_the_report_without_with_content(repo, secret, capsys):
    """Both the console and the JSON, and both secrets, because the report is
    pasted into a CI log."""
    root = repo(
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "hooks": [
                            {"type": "command", "command": f"deploy.sh --token {secret}"},
                            {"type": "http", "url": f"https://hooks.invalid/{secret}"},
                        ]
                    }
                ]
            },
            "apiKeyHelper": f"echo {secret}",
        }
    )

    assert cli.main(["check", "--repo", str(root)]) in (cli.EXIT_FAIL, cli.EXIT_INDETERMINATE)
    console = capsys.readouterr().out
    assert secret not in console, "a literal reached the console"

    cli.main(["check", "--repo", str(root), "--json"])
    printed = capsys.readouterr().out
    assert secret not in printed, "a literal reached the JSON document"
    assert claude_code.digest_of(f"echo {secret}") in printed, (
        "the digest has to be there, or nothing identifies what was seen"
    )


def test_with_content_is_what_puts_the_literal_back(repo, capsys):
    """The flag has to actually do something, or the test above is passing
    because nothing is printed at all."""
    root = repo({"apiKeyHelper": f"echo {HIGH_ENTROPY}"})

    cli.main(["check", "--repo", str(root), "--json", "--with-content"])

    assert HIGH_ENTROPY in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Nothing is executed
# ---------------------------------------------------------------------------


def test_nothing_the_configuration_names_is_ever_run(tmp_path, capsys, no_network):
    """A hook pointing at a script that would leave a sentinel behind.

    If any part of this tool ever ran what it reads - to classify it, to see
    what it does, "just in a sandbox" - the sentinel appears and this fails.
    That is the prohibition in CLAUDE.md and the reason the reader records four
    facts about a script and not a fifth.
    """
    sentinel = tmp_path / "sentinel.txt"
    script = tmp_path / "setup.sh"
    script.write_text(
        f"#!/bin/sh\nprintf ran > {sentinel.as_posix()}\n", encoding="utf-8"
    )
    script.chmod(0o755)
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {"hooks": [{"type": "command", "command": "sh setup.sh"}]}
                    ]
                },
                "apiKeyHelper": "sh setup.sh",
                "statusLine": {"type": "command", "command": "sh setup.sh"},
            }
        ),
        encoding="utf-8",
    )

    assert cli.main(["check", "--repo", str(tmp_path), "--json"]) == cli.EXIT_FAIL
    capsys.readouterr()

    assert not sentinel.exists(), (
        "the sentinel is there, so something executed what the configuration named. "
        "That is the one thing this tool must never do."
    )
    # And it was still read: a test that passes because nothing happened at all
    # would be the same failure in a quieter coat.
    surface = resolve.resolve(claude_code.read(tmp_path))
    hook = next(c for c in surface.capabilities if c.name == "hook.command")
    assert hook.facts["target_facts"]["sha256"]


# ---------------------------------------------------------------------------
# Somebody else's repository: the defences SECURITY.md names
# ---------------------------------------------------------------------------


def test_a_path_that_leaves_the_tree_is_reported_as_outside_it(repo):
    root = repo(
        {
            "hooks": {
                "SessionStart": [
                    {"hooks": [{"type": "command", "command": "sh ../../../etc/evil.sh"}]}
                ]
            }
        }
    )
    surface = resolve.resolve(claude_code.read(root))
    hook = next(c for c in surface.capabilities if c.name == "hook.command")

    assert hook.facts["target_facts"]["inside_tree"] is False


@pytest.mark.parametrize(
    "spoken, outside",
    [
        ("\\\\192.168.6.59\\config", True),   # a UNC share, from the real corpus
        ("//192.168.6.59/config", True),
        ("C:/Users/someone/secrets", True),
        ("c:\\Users\\someone\\secrets", True),
        ("/etc/shadow", True),
        ("../../../etc", True),
        ("src/tools", False),
        ("./scripts/build.sh", False),
        ("weird\\name.sh", False),           # a backslash in a POSIX filename
    ],
)
def test_a_path_absolute_on_another_platform_is_outside_here_too(tmp_path, spoken, outside):
    """Design note D-279, and the reason the gate runs on WSL.

    `\\\\192.168.6.59\\config` is a UNC share. POSIX reads it as a relative name,
    so `root / spoken` landed INSIDE the tree and `check` reported that a
    repository granting access to a file server was granting access to itself.
    This passed on Windows and failed on Linux, which is the same repository
    getting two answers on two machines - the one property this tree defends
    everywhere. The real corpus configuration that found it is
    `PrayerfulDrop__ESPHome-Guition-ESP32-S3-4848S040`.

    The last case is the one that makes the check a check rather than a ban on
    backslashes: a backslash is legal in a POSIX filename, and a path containing
    one is still inside the tree.
    """
    assert claude_code.inside_tree(tmp_path, spoken) is not outside


@pytest.mark.skipif(os.name == "nt", reason="creating a symlink on Windows needs a privilege")
def test_a_symlink_out_of_the_tree_is_outside_it(tmp_path):
    """Resolved on both sides. `os.path.abspath` normalises `..` textually and
    would call a symlinked escape inside the tree."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "evil.sh").write_text("# inert\n", encoding="utf-8")
    root = tmp_path / "repo"
    (root / ".claude").mkdir(parents=True)
    (root / "link").symlink_to(outside, target_is_directory=True)
    (root / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {"hooks": [{"type": "command", "command": "sh link/evil.sh"}]}
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    surface = resolve.resolve(claude_code.read(root))
    hook = next(c for c in surface.capabilities if c.name == "hook.command")

    assert hook.facts["target_facts"]["inside_tree"] is False


def test_a_settings_file_over_the_ceiling_is_a_cause_and_not_a_read(repo):
    """The ceiling is checked before the bytes are asked for, so a hostile file
    costs a stat rather than its own size in memory."""
    root = repo("x" * (claude_code.MAX_BYTES + 1))
    surface = resolve.resolve(claude_code.read(root))

    assert any("ceiling" in gap.cause for gap in surface.unresolved)
    assert surface.capabilities == ()


def test_a_settings_document_of_the_wrong_shape_is_a_cause_and_not_a_crash(repo):
    """Every level of this document was written by somebody else. A list where
    an object belongs must be a stated cause, never a `TypeError` out of the
    reader."""
    root = repo("[1, 2, 3]")
    surface = resolve.resolve(claude_code.read(root))

    assert any("not an object" in gap.cause for gap in surface.unresolved)


@pytest.mark.parametrize(
    "hostile",
    [
        {"hooks": []},
        {"hooks": {"SessionStart": "not a list"}},
        {"hooks": {"SessionStart": [None, 3, {"hooks": [None, "x"]}]}},
        {"permissions": "not an object"},
        {"permissions": {"allow": "not a list"}},
        {"mcpServers": {"a": None}},
        {"sandbox": {"excludedCommands": [None, 7]}},
        {"enabledPlugins": []},
    ],
    ids=range(8),
)
def test_a_hostile_shape_anywhere_is_survived(tmp_path, hostile):
    """Eight documents that are not valid configuration and are all things a
    file on disk can contain. None of them may raise."""
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps(hostile), encoding="utf-8")

    surface = resolve.resolve(claude_code.read(tmp_path))
    rules.evaluate(surface, rules.load())


def test_the_git_index_is_read_rather_than_git_being_run(monkeypatch, tmp_path):
    """Reachability of the fourth script fact, and the refusal behind it.

    `git ls-files` would be a subprocess, and a reader that shells out to answer
    one question is one question away from shelling out to answer a harder one.
    A version this parser does not read is a stated cause, never a False.
    """
    tracked, problem = claude_code.git_tracked(Path(REPO_ROOT))
    assert problem is None, problem
    assert "pyproject.toml" in tracked

    index = tmp_path / ".git" / "index"
    index.parent.mkdir(parents=True)
    index.write_bytes(b"DIRC" + (4).to_bytes(4, "big") + (1).to_bytes(4, "big"))
    _paths, cause = claude_code.git_tracked(tmp_path)
    assert cause is not None and "version 4" in cause


# ---------------------------------------------------------------------------
# The document, the exit codes and the command
# ---------------------------------------------------------------------------


def test_the_document_declares_the_registered_version_and_validates(repo, capsys):
    from actaira import schemas

    cli.main(["check", "--repo", str(repo(BYPASS)), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["schema_version"] == schemas.VERSIONS["surface"] == "surface/v1"
    schema = schemas.load("surface-v1")
    assert schema["properties"]["schema_version"]["const"] == "surface/v1"
    for key in schema["required"]:
        assert key in payload, key


def test_check_prints_the_same_bytes_twice(repo, capsys):
    """Determinism, over a document that carries sets, dicts and paths."""
    root = repo(
        {
            "hooks": {
                "SessionStart": [{"hooks": [{"type": "command", "command": "sh a.sh"}]}]
            },
            "mcpServers": {"z": {"command": "npx", "args": ["thing"]}, "a": {"url": "https://x.invalid"}},
            "enabledPlugins": {"b@m": True, "a@m": True},
        }
    )

    cli.main(["check", "--repo", str(root), "--json"])
    first = capsys.readouterr().out
    cli.main(["check", "--repo", str(root), "--json"])
    second = capsys.readouterr().out

    assert first == second
    assert json.loads(first)


@pytest.mark.parametrize(
    "settings, expected",
    [
        ({"permissions": {"deny": ["Bash"]}}, cli.EXIT_OK),
        ({"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "sh a.sh"}]}]}},
         cli.EXIT_FAIL),
        (BYPASS, cli.EXIT_INDETERMINATE),
    ],
    ids=["nothing-fired", "a-rule-fired", "indeterminate"],
)
def test_the_three_exit_codes(repo, settings, expected, capsys):
    """0, 1 and 3, which COMPATIBILITY.md publishes. 3 is the one that had to
    come back: a pipeline branching on 1 alone reads "I could not tell" as a
    clean run."""
    assert cli.main(["check", "--repo", str(repo(settings))]) == expected
    capsys.readouterr()


def test_a_repo_that_is_not_a_directory_is_a_usage_error(tmp_path, capsys):
    assert cli.main(["check", "--repo", str(tmp_path / "absent")]) == cli.EXIT_USAGE
    assert capsys.readouterr().err.strip()


def test_a_malformed_agent_version_is_a_usage_error(repo, capsys):
    assert cli.main(["check", "--repo", str(repo({})), "--agent-version", "2.1.257"]) == (
        cli.EXIT_USAGE
    )
    assert capsys.readouterr().err.strip()


def test_check_opens_no_socket(repo, no_network, capsys):
    cli.main(["check", "--repo", str(repo(BYPASS)), "--json"])
    capsys.readouterr()


def test_the_console_says_what_the_configuration_cannot_prove(repo, capsys):
    """Published limit 11, printed rather than filed. A limit that lives only in
    a document is one the person reading the output never meets."""
    cli.main(["check", "--repo", str(repo(BYPASS))])
    printed = capsys.readouterr().out

    assert "DECLARES" in printed
    assert "Could not be resolved" in printed
    assert "Seen and not read" in printed


def test_the_console_refuses_to_call_an_empty_result_safety(repo, capsys):
    """Published limit 9. A repository with no finding can still be badly
    configured for a reason no rule names, and the report says so."""
    cli.main(["check", "--repo", str(repo({"permissions": {"deny": ["Bash"]}}))])

    assert "no rule fired" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# The corpus goldens
# ---------------------------------------------------------------------------


def _corpus_roots():
    return [path for path in sorted(CORPUS.iterdir()) if (path / "expected.json").is_file()]


@pytest.mark.parametrize("root", _corpus_roots(), ids=lambda path: path.name)
def test_the_resolved_surface_matches_the_reviewed_golden(root):
    """Twenty real configurations, each against the answer a person checked.

    The golden records the claims that were reviewed - which rules fire, each
    capability's name and resolution, the counts - rather than a dump of the
    output. A dump compared against itself is a regression pin with nobody
    behind it, which is the shape D-15 warns about at the top of
    `attest/verify.py`.
    """
    expected = json.loads((root / "expected.json").read_text(encoding="utf-8"))
    surface = resolve.resolve(claude_code.read(root))
    found, gaps = rules.evaluate(surface, rules.load())

    assert sorted({item.rule_id for item in found}) == expected["rules_that_fire"]
    assert {c.name: c.resolution.value for c in surface.capabilities} == expected["capabilities"]
    assert len(surface.capabilities) == expected["capability_count"]
    assert len(surface.unresolved) + len(gaps) == expected["unresolved_count"]
    assert sorted(entry.path for entry in surface.not_read) == expected["not_read"]


def test_the_golden_comparison_would_notice_a_change():
    """The guard on the guard: the comparison above has to be able to fail."""
    root = _corpus_roots()[0]
    expected = json.loads((root / "expected.json").read_text(encoding="utf-8"))
    planted = dict(expected, capability_count=expected["capability_count"] + 1)
    surface = resolve.resolve(claude_code.read(root))

    assert len(surface.capabilities) != planted["capability_count"]


# ---------------------------------------------------------------------------
# The pack loads, and a malformed one is a message rather than a traceback
# ---------------------------------------------------------------------------


def test_the_core_pack_has_fifteen_rules_each_fully_attributed():
    catalogue = rules.load()

    assert len(catalogue) == 15
    for rule in catalogue:
        assert rule.author and rule.pack and rule.version and rule.vendor
        assert rule.severity and rule.capability and rule.when and rule.remediation
        assert rule.needs, "a rule's needed facts are derived from its clauses"


@pytest.mark.parametrize(
    "body, expected",
    [
        ("", "[pack] table"),
        ('[pack]\nname="x"\n[[rule]]\nid="nope"\n', "not a rule id"),
        ('[pack]\nname="x"\n[[rule]]\nid="ACT-S001"\nversion="1"\nvendor="v"\n'
         'requires="MAYBE"\nseverity="low"\ncapability="c"\nremediation="r"\n'
         '[[rule.when]]\nfact="a"\n', "DECLARED or EFFECTIVE"),
        ('[pack]\nname="x"\nauthor="a"\n[[rule]]\nid="ACT-S001"\nversion="1"\nvendor="v"\n'
         'requires="DECLARED"\nseverity="low"\ncapability="c"\nremediation="r"\n',
         "no [[rule.when]] clause"),
        ('[pack]\nname="x"\nauthor="a"\n[[rule]]\nid="ACT-S001"\nversion="1"\nvendor="v"\n'
         'requires="DECLARED"\nseverity="low"\ncapability="c"\nremediation="r"\n'
         '[[rule.when]]\nfact="a"\nop="sounds_like"\n', "unknown operator"),
        ('[pack]\nname="x"\n[[rule]]\nid="ACT-S001"\nversion="1"\nvendor="v"\n'
         'requires="DECLARED"\nseverity="low"\ncapability="c"\nremediation="r"\n'
         '[[rule.when]]\nfact="a"\n', "no `author`"),
        ("this is not toml {", "not valid TOML"),
    ],
    ids=["no-pack", "bad-id", "bad-requires", "no-clause", "bad-operator", "not-toml", "no-author"],
)
def test_a_malformed_pack_is_refused_at_load_with_a_message(tmp_path, body, expected):
    """Code rule: a format error is caught at load, with a message. A traceback
    out of a rule loader is a message to the wrong reader - the person who is
    writing a rule pack."""
    path = tmp_path / "bad.toml"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(rules.PackError) as raised:
        rules.load_pack(path)

    assert expected in str(raised.value)


def test_a_rule_answers_indeterminate_rather_than_false_on_a_fact_it_lacks():
    """The third negative, at the level it is actually enforced: a clause names
    the fact, so a capability without it cannot be answered `False` by accident."""
    clause = rules.Clause("target_facts.inside_tree", "is_true", None)

    assert clause.holds({"target_facts": {"inside_tree": True}}) is True
    assert clause.holds({"target_facts": {"inside_tree": False}}) is False
    assert clause.holds({}) is None, "a missing fact must be None, never False"
    assert clause.holds({"target_facts": {}}) is None
    # A fact RECORDED as null is a different thing from one nobody wrote down.
    assert clause.holds({"target_facts": {"inside_tree": None}}) is False
