"""`diff`: the five changes, the sixth thing that is not one, and what git is asked.

The load-bearing test in this file is the first one. Everything else here is
about what `diff` SAYS; that one is about what it DOES to the tree it was pointed
at, which is the property the whole design of `surface/diff.py` exists to keep -
no checkout, no hook, no write outside a temporary directory this process made.

The change kinds are exercised over REAL configurations wherever a real pair
exists. WIDENED and NARROWED are the pair worth naming: they run over two public
repositories from the corpus, one setting Gemini CLI's approval mode to
`default` and one to `auto_edit`, so the direction this module claims is a
direction two strangers' repositories actually differ by rather than one we typed
into a fixture.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import REPO_ROOT
from seamark import cli
from seamark.surface import diff as diff_mod

FIXTURES = Path(REPO_ROOT) / "tests" / "fixtures" / "surface"
CORPUS = FIXTURES / "corpus"
# Two public repositories with OSI licences, whose provenance files are beside
# them. They differ in exactly one fact this module has an order for.
NARROW = CORPUS / "bybren-llc__safe-agentic-workflow"   # defaultApprovalMode: default
WIDE = CORPUS / "michaelgrosner__CoffeeMol"             # defaultApprovalMode: auto_edit

GIT_ENVIRONMENT = {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+00:00",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+00:00",
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
}


def git(where: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(where), *arguments],  # noqa: S607 - git from PATH, as diff.py runs it
        check=True, capture_output=True, env={**os.environ, **GIT_ENVIRONMENT},
    )


def copy_config(source: Path, into: Path) -> None:
    for item in sorted(source.rglob("*")):
        if item.is_dir():
            continue
        target = into / item.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(item.read_bytes().replace(b"\r\n", b"\n"))


def two_commits(where: Path, second: Path) -> Path:
    """A repository with a clean commit and `second`'s configuration on top."""
    where.mkdir(parents=True, exist_ok=True)
    git(where, "init", "-q", "-b", "main")
    (where / "README.md").write_text("# a repository\n", encoding="utf-8")
    git(where, "add", "-A")
    git(where, "commit", "-q", "-m", "clean")
    copy_config(second, where)
    git(where, "add", "-A")
    git(where, "commit", "-q", "-m", "second")
    return where


def snapshot(where: Path) -> dict[str, str]:
    """Every file under `where`, by path, with its sha256. The whole tree."""
    found: dict[str, str] = {}
    for item in sorted(where.rglob("*")):
        if item.is_file():
            found[str(item.relative_to(where)).replace("\\", "/")] = hashlib.sha256(
                item.read_bytes()
            ).hexdigest()
    return found


# ---------------------------------------------------------------------------
# What it does to the repository, which is nothing
# ---------------------------------------------------------------------------


def test_a_diff_runs_no_git_hook_and_leaves_the_tree_byte_for_byte(tmp_path, capsys):
    """Gate point 1, and the reason this command does not use `git checkout`.

    A `post-checkout` hook is planted in the repository being examined, along
    with the four other hooks a checkout or a read can fire. Each would leave a
    file behind. The whole working tree is digested before and after, `.git`
    included, so a moved HEAD, a refreshed index or a stray file all show up as
    a difference rather than having to be looked for one at a time.

    Rejected as the assertion: "the sentinel file is absent". It is necessary
    and it is not sufficient - a checkout that ran no hook would still have
    rewritten the working tree, which is the other half of the fourth negative.
    """
    repo = two_commits(tmp_path / "repo", FIXTURES / "keyv-august")
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    sentinel = tmp_path / "a-hook-ran"
    for name in ("post-checkout", "post-index-change", "pre-commit", "post-merge", "fsmonitor-watchman"):
        script = hooks / name
        script.write_text(
            f"#!/bin/sh\necho ran > '{sentinel.as_posix()}'\n", encoding="utf-8"
        )
        script.chmod(0o755)

    before = snapshot(repo)
    code = cli.main(["diff", "--repo", str(repo), "HEAD~1", "HEAD"])
    capsys.readouterr()

    assert code == cli.EXIT_FAIL, "the keyv configuration arriving should fire a rule"
    assert not sentinel.exists(), (
        "a git hook in the repository being examined ran. This command reads two trees; "
        "running the audited repository's own code to do it is the vector, not the tool."
    )
    assert snapshot(repo) == before, (
        "the working tree changed. `diff` may not write in, check out of, or refresh "
        "the repository it was pointed at."
    )


def test_the_hook_plant_would_have_fired_on_a_checkout(tmp_path):
    """The guard on the guard: if the hook could not run at all, the test above
    passes over nothing. So the same plant is given a real `git checkout` and the
    sentinel is required to appear.

    Skipped where the shell a hook needs is absent - a stock Windows git ships
    one, a stripped container may not - because a skip says "not measured" and a
    pass here would say "measured and safe".
    """
    repo = two_commits(tmp_path / "repo", FIXTURES / "keyv-august")
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    sentinel = tmp_path / "a-hook-ran"
    script = hooks / "post-checkout"
    script.write_text(f"#!/bin/sh\necho ran > '{sentinel.as_posix()}'\n", encoding="utf-8")
    script.chmod(0o755)

    git(repo, "checkout", "-q", "HEAD~1")
    git(repo, "checkout", "-q", "main")

    if not sentinel.exists():
        pytest.skip("git could not run a shell hook here, so the plant proves nothing")


# ---------------------------------------------------------------------------
# The refusals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ref", ["-x", "--upload-pack=touch /tmp/pwned", "--exec=sh"])
def test_a_ref_that_starts_with_a_dash_is_refused(ref, tmp_path, capsys):
    """Gate point 2. Refused by the module, and refused through the command line
    with exit code 2 - `--` is passed to git as well, and this is the layer that
    does not depend on somebody remembering to keep it there."""
    with pytest.raises(diff_mod.GitError):
        diff_mod.refuse_option_shaped(ref)

    repo = two_commits(tmp_path / "repo", FIXTURES / "keyv-august")
    code = cli.main(["diff", "--repo", str(repo), "--", ref, "HEAD"])

    assert code == cli.EXIT_USAGE
    assert "refused" in capsys.readouterr().err


def test_a_listed_path_that_would_escape_the_extraction_is_not_written(tmp_path):
    """Git's tree format forbids `..` and an absolute path. This does not rely on
    that: the input is a repository somebody else wrote, and "the format forbids
    it" is a statement about a producer."""
    root = tmp_path / "into"
    root.mkdir()
    for spoken in ("../escaped", "/etc/shadow", "a/../../b", "", "."):
        assert diff_mod._safe_target(root, spoken) is None, spoken
    assert diff_mod._safe_target(root, ".claude/settings.json") is not None


def test_two_directories_are_compared_without_git_at_all(tmp_path, capsys):
    """`--from-dir` and `--to-dir`, which is what the Action's own CI test uses:
    the two sides of a diff are two commits, and a job that had to build a
    repository in order to test the Action would be testing what it built."""
    empty = tmp_path / "nothing"
    empty.mkdir()

    code = cli.main([
        "diff", "--from-dir", str(empty), "--to-dir", str(FIXTURES / "keyv-august"), "--json",
    ])
    document = json.loads(capsys.readouterr().out)

    assert code == cli.EXIT_FAIL
    assert document["before"]["kind"] == "directory"
    assert document["added"], "the keyv configuration arriving is an addition"


@pytest.mark.parametrize("argv", [
    ["diff", "HEAD"],
    ["diff", "a", "b", "c"],
    ["diff", "--from-dir", "x"],
])
def test_half_a_form_is_a_usage_error(argv, tmp_path, capsys):
    repo = two_commits(tmp_path / "repo", FIXTURES / "keyv-august")
    assert cli.main([*argv, "--repo", str(repo)]) == cli.EXIT_USAGE
    assert capsys.readouterr().err.strip()


# ---------------------------------------------------------------------------
# The five kinds, and the sixth thing that is not one of them
# ---------------------------------------------------------------------------


def document_for(root: Path) -> dict:
    return cli.check_document(root)


def diff_of(before: Path, after: Path) -> dict:
    return diff_mod.surface_diff(
        document_for(before),
        document_for(after),
        before_label={"label": "before", "kind": "directory"},
        after_label={"label": "after", "kind": "directory"},
    )


def test_a_capability_that_arrives_is_added(tmp_path):
    empty = tmp_path / "nothing"
    empty.mkdir()
    found = diff_of(empty, FIXTURES / "keyv-august")

    assert [item["capability"] for item in found["added"]] == ["hook.command"]
    assert found["removed"] == []
    assert found["added"][0]["before"] is None
    assert found["added"][0]["after"]["findings"], "a rule fired on what arrived"


def test_a_capability_that_goes_is_removed(tmp_path):
    empty = tmp_path / "nothing"
    empty.mkdir()
    found = diff_of(FIXTURES / "keyv-august", empty)

    assert [item["capability"] for item in found["removed"]] == ["hook.command"]
    assert found["added"] == []
    assert found["removed"][0]["after"] is None


def test_a_real_pair_of_public_repositories_widens_and_narrows():
    """Gate point 3's two hardest kinds, over two strangers' configurations.

    One sets Gemini CLI's `general.defaultApprovalMode` to `default` and the
    other to `auto_edit`. `resolve.py` reads both into `guardrail_removed`, which
    is a fact whose own name says which value is the wider one - and that is the
    only condition under which this tool will name a direction at all.
    """
    widened = diff_of(NARROW, WIDE)
    narrowed = diff_of(WIDE, NARROW)

    assert [item["capability"] for item in widened["widened"]] == ["approval.policy"]
    assert widened["narrowed"] == []
    assert [item["capability"] for item in narrowed["narrowed"]] == ["approval.policy"]
    assert narrowed["widened"] == []

    # And the direction is what the exit code is computed from. A rule fires on
    # the widened side of this capability and none fires on the narrowed one.
    # Asserted about THIS capability rather than about the whole diff: the two
    # repositories differ in more than one setting, so a diff-wide assertion
    # would be about whatever else they happen to configure.
    assert [finding["rule_id"] for finding in widened["widened"][0]["after"]["findings"]] == [
        "ACT-S031"
    ]
    assert narrowed["narrowed"][0]["after"]["findings"] == []
    assert "ACT-S031" not in [
        finding["rule_id"] for finding in diff_mod.fired_on_new_capability(narrowed)
    ]


def test_a_difference_no_order_covers_is_changed_with_both_digests(tmp_path):
    """The default, and the one the second negative requires.

    A hook's command is replaced by another. Nothing this tool has an order for
    moved, so it does not invent one: the entry is CHANGED and carries both
    digests, which is what a reviewer can act on without being told what to think
    about somebody else's settings.
    """
    before = tmp_path / "before"
    after = tmp_path / "after"
    for where, command in ((before, "node .claude/one.mjs"), (after, "node .claude/two.mjs")):
        (where / ".claude").mkdir(parents=True)
        (where / ".claude" / "settings.json").write_text(
            json.dumps({"hooks": {"SessionStart": [
                {"matcher": "*", "hooks": [{"type": "command", "command": command}]}
            ]}}),
            encoding="utf-8",
        )

    found = diff_of(before, after)
    entry = found["changed"][0]

    assert [item["capability"] for item in found["changed"]] == ["hook.command"]
    assert found["widened"] == [] and found["narrowed"] == []
    assert entry["before"]["digest"] != entry["after"]["digest"]
    assert len(entry["before"]["digest"]) == 64 and len(entry["after"]["digest"]) == 64


def test_an_unresolved_side_makes_the_change_indeterminate_and_never_one_of_the_five(tmp_path):
    """Gate point 3's sixth entry. The `folderOpen` task keyv plants cannot be
    resolved from a repository at all - whether it runs is decided by a setting
    only the user's own machine can hold - so the change it represents is
    INDETERMINATE, listed with its cause, and counted with none of the five."""
    empty = tmp_path / "nothing"
    empty.mkdir()
    found = diff_of(empty, FIXTURES / "keyv-august")

    subjects = [item["subject"] for item in found["indeterminate"]]
    assert "a change to vscode task.command" in subjects
    everywhere = [
        item["capability"]
        for kind in ("added", "removed", "widened", "narrowed", "changed")
        for item in found[kind]
    ]
    assert "task.command" not in everywhere, (
        "an unresolved capability was counted as one of the five changes"
    )
    assert any("allowAutomaticTasks" in item["cause"] for item in found["indeterminate"])


def test_the_document_declares_its_contract_and_never_totals_the_lists(tmp_path):
    empty = tmp_path / "nothing"
    empty.mkdir()
    found = diff_of(empty, FIXTURES / "keyv-august")

    from seamark.schemas import VERSIONS

    assert found["schema_version"] == VERSIONS["surface-diff"]
    for name in ("added", "removed", "widened", "narrowed", "changed", "indeterminate"):
        assert isinstance(found[name], list)
    assert isinstance(found["unchanged"], int)


# ---------------------------------------------------------------------------
# Exit codes, and the same bytes twice
# ---------------------------------------------------------------------------


def test_the_three_exit_codes(tmp_path, capsys):
    empty = tmp_path / "nothing"
    empty.mkdir()
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "README.md").write_text("nothing configured here\n", encoding="utf-8")

    assert cli.main(["diff", "--from-dir", str(empty), "--to-dir", str(clean)]) == cli.EXIT_OK
    assert cli.main([
        "diff", "--from-dir", str(empty), "--to-dir", str(FIXTURES / "keyv-august"),
    ]) == cli.EXIT_FAIL

    # Exit 3: something could not be resolved and nothing fired. The vscode half
    # of the worm on its own is exactly that case.
    only_the_task = tmp_path / "task-only"
    (only_the_task / ".vscode").mkdir(parents=True)
    (only_the_task / ".vscode" / "tasks.json").write_text(
        (FIXTURES / "keyv-august" / ".vscode" / "tasks.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    assert cli.main([
        "diff", "--from-dir", str(empty), "--to-dir", str(only_the_task),
    ]) == cli.EXIT_INDETERMINATE
    capsys.readouterr()


def test_the_same_two_trees_produce_the_same_bytes(tmp_path):
    empty = tmp_path / "nothing"
    empty.mkdir()
    first = diff_of(empty, FIXTURES / "keyv-august")
    second = diff_of(empty, FIXTURES / "keyv-august")

    from seamark.model import canonical_json

    assert canonical_json(first) == canonical_json(second)


def test_two_refs_and_two_directories_answer_the_same_thing(tmp_path, capsys):
    """The two forms are two ways to obtain the same pair of trees, so they must
    agree about the pair. A materialisation that dropped a file, wrote a line
    ending differently or missed a directory would show up here and nowhere
    else."""
    repo = two_commits(tmp_path / "repo", FIXTURES / "keyv-august")
    cli.main(["diff", "--repo", str(repo), "HEAD~1", "HEAD", "--json"])
    from_refs = json.loads(capsys.readouterr().out)

    empty = tmp_path / "nothing"
    empty.mkdir()
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "README.md").write_text("# a repository\n", encoding="utf-8")
    copy_config(FIXTURES / "keyv-august", after := tmp_path / "after")
    (after / "README.md").write_text("# a repository\n", encoding="utf-8")
    cli.main(["diff", "--from-dir", str(plain), "--to-dir", str(after), "--json"])
    from_dirs = json.loads(capsys.readouterr().out)

    for kind in ("added", "removed", "widened", "narrowed", "changed"):
        assert [item["capability"] for item in from_refs[kind]] == [
            item["capability"] for item in from_dirs[kind]
        ], kind
    assert [item["subject"] for item in from_refs["indeterminate"]] == [
        item["subject"] for item in from_dirs["indeterminate"]
    ]


# ---------------------------------------------------------------------------
# The listing and the ceilings
# ---------------------------------------------------------------------------


def test_the_tree_digest_names_the_tree_and_two_runs_agree(tmp_path):
    repo = two_commits(tmp_path / "repo", FIXTURES / "keyv-august")
    head = diff_mod.listing(repo, "HEAD")
    parent = diff_mod.listing(repo, "HEAD~1")

    assert diff_mod.tree_digest(head) == diff_mod.tree_digest(diff_mod.listing(repo, "HEAD"))
    assert diff_mod.tree_digest(head) != diff_mod.tree_digest(parent)
    assert len(head) > len(parent)


def test_a_tree_over_the_file_ceiling_is_refused_and_nothing_is_written(tmp_path, monkeypatch):
    """The ceiling is checked from the listing, before a byte is written, so a
    refusal costs one command and leaves no half-extracted directory behind."""
    repo = two_commits(tmp_path / "repo", FIXTURES / "keyv-august")
    monkeypatch.setattr(diff_mod, "MAX_TREE_FILES", 1)
    into = tmp_path / "into"

    with pytest.raises(diff_mod.GitError) as raised:
        diff_mod.materialise(repo, "HEAD", into)

    assert "ceiling" in str(raised.value)
    assert not any(into.rglob("*")) if into.exists() else True


def test_the_git_command_line_carries_every_refusal_it_claims():
    """The flags are an argument in a comment until something reads them back."""
    argv = diff_mod._git(Path("."), "ls-tree")

    assert argv[0] == "git"
    assert "--no-pager" in argv and "--no-optional-locks" in argv
    assert "core.fsmonitor=false" in argv
    assert any(item.startswith("core.hooksPath=") for item in argv)
    assert not any(item.startswith("--textconv") for item in argv)
    environment = diff_mod._environment()
    assert environment["GIT_TERMINAL_PROMPT"] == "0"


def test_only_two_git_subcommands_are_ever_run():
    """The module's own claim, read out of its source rather than trusted.

    `ls-tree` and `cat-file` apply no filter and run no hook. Any third
    subcommand is a decision, and this is where it gets made deliberately.
    """
    source = (Path(REPO_ROOT) / "src" / "seamark" / "surface" / "diff.py").read_text("utf-8")
    called = {
        line.split('_git(repo, "', 1)[1].split('"', 1)[0]
        for line in source.splitlines()
        if '_git(repo, "' in line
    }
    assert called == {"ls-tree", "cat-file"}, called


def test_the_diff_opens_no_socket(tmp_path, monkeypatch, capsys):
    """`diff` runs git and reads files. It has no reason to reach the network and
    a test says so rather than the docstring saying so."""
    import socket

    def refuse(*args, **kwargs):
        raise AssertionError("diff opened a socket")

    repo = two_commits(tmp_path / "repo", FIXTURES / "keyv-august")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)

    assert cli.main(["diff", "--repo", str(repo), "HEAD~1", "HEAD"]) == cli.EXIT_FAIL
    capsys.readouterr()


def test_nothing_it_reads_is_executed(tmp_path, capsys):
    """The same property `check` is held to, asserted about the command that
    materialises somebody else's tree into a directory of its own."""
    marker = tmp_path / "the-script-ran"
    before = tmp_path / "before"
    before.mkdir()
    after = tmp_path / "after"
    (after / ".claude").mkdir(parents=True)
    script = after / ".claude" / "setup.mjs"
    script.write_text(
        f"import fs from 'node:fs';\nfs.writeFileSync({str(marker)!r}, 'ran');\n",
        encoding="utf-8",
    )
    (after / ".claude" / "settings.json").write_text(
        json.dumps({"hooks": {"SessionStart": [
            {"matcher": "*", "hooks": [{"type": "command", "command": "node .claude/setup.mjs"}]}
        ]}}),
        encoding="utf-8",
    )

    cli.main(["diff", "--from-dir", str(before), "--to-dir", str(after), "--json"])
    document = json.loads(capsys.readouterr().out)

    assert not marker.exists(), "diff executed the script a hook named"
    facts = document["added"][0]["after"]["facts"]
    assert facts["target_facts"]["sha256"], (
        "the script was not digested either, so this test could pass by not looking"
    )


if sys.platform == "win32":  # pragma: no cover - a note, not a branch
    # Nothing here is skipped on Windows. `git` is the only external program and
    # the hook plant is exercised by its own guard, which skips loudly when the
    # shell a hook needs is missing rather than reporting a pass.
    pass
