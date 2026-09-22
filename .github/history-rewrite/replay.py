#!/usr/bin/env python3
"""Replay every commit with the same tree and a new message.

    python3 .github/history-rewrite/replay.py            print what it would do
    python3 .github/history-rewrite/replay.py --apply    do it, one step at a time

`git commit-tree` and not `git rebase -i`, for one reason: a rebase applies
patches and can resolve them differently, and the only thing that may change
here is the message. Replaying each commit's recorded TREE OBJECT makes the
final tree identical by construction rather than by inspection afterwards.

The author and committer dates are carried over untouched. Fifty-two commits
between 12 and 22 September 2026 is what happened, and falsifying the dates
would be far worse than an intense week. `README.md` says so in "How this was
built", which is why that section was written and committed before this script
was.

WHAT `--apply` DOES BY ITSELF, because the alternative is asking somebody to
fire a command that rewrites a published branch and hope:

  1. refuses a dirty tree, a detached HEAD or a branch that is not the one
     named, before anything is built;
  2. builds the objects and refuses to move anything if the replayed tree is
     not identical to the branch's;
  3. creates `backup-pre-rewrite` AND PUSHES IT, and stops if the push fails,
     so the old history is on the remote before the new one exists anywhere;
  4. moves the branch, then compares it against the backup again - the check
     the plan asks for, run against what is actually there rather than against
     what was intended;
  5. writes the old-to-new SHA map to a file and rewrites, with it, every
     commit of this repository the documentation cites: the `uses:` and the
     `rev:` in both READMEs;
  6. prints the three commands the phase's completion criterion is written as,
     with their answers.

It does not push the rewritten branch and it does not delete the backup.
`.github/release-notes/RUNBOOK.md` has those, in the order they are safe in.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MESSAGES = json.loads((HERE / "messages.json").read_text(encoding="utf-8"))

# The message cap the acceptance script measures, as `wc -l` counts it over
# `git log --format=%B`: the message's own lines plus the newline the format
# adds. Asserted here rather than trusted, because this file is the last place
# the cap can be held before the history carries it.
MAX_LINES = 15
FORBIDDEN = ("work rule", "budget", "adversarial pass", "a later session")

# The documentation this repository publishes with a commit of its own in it.
# The list is not written twice: `release_check.py` reads the same files to
# refuse a citation that is not on the branch, and this rewrites them, so the
# check and the fix cannot come to disagree about what a citation is.
CITED_IN = ("README.md", "README.es.md", ".pre-commit-hooks.yaml", "action.yml")


def git(*arguments: str, stdin: bytes | None = None, env=None) -> str:
    return subprocess.run(  # noqa: S603 - a fixed argv, no shell
        ["git", *arguments],  # noqa: S607 - git from PATH, as every other script here
        cwd=ROOT, capture_output=True, input=stdin,
        env=env, check=True,
    ).stdout.decode("utf-8")


def git_try(*arguments: str) -> tuple[int, str, str]:
    """A question rather than an instruction: the ones that are allowed to say no."""
    done = subprocess.run(  # noqa: S603 - a fixed argv, no shell
        ["git", *arguments],  # noqa: S607 - git from PATH
        cwd=ROOT, capture_output=True, check=False,
    )
    return done.returncode, done.stdout.decode("utf-8").strip(), done.stderr.decode("utf-8").strip()


def field(sha: str, spelling: str) -> str:
    return git("log", "-1", f"--format={spelling}", sha).rstrip("\n")


def check(resulting: dict[str, str]) -> None:
    """The cap and the vocabulary, over the RESULTING history.

    It used to run over `MESSAGES` alone, which is the shape work rule 12
    names: the check looked at the map and its green was read as being about
    the branch. A commit written after the map was generated sat one line over
    the cap with the map passing its own assertion, and the commit that did it
    was the one that added the map.

    So what is measured is what the history would carry: a rewritten message
    where there is one, and the commit's own message where there is not.
    """
    problems = []
    for sha, message in sorted(resulting.items()):
        lines = message.rstrip("\n").split("\n")
        if len(lines) + 1 > MAX_LINES:
            problems.append(f"{sha}: {len(lines) + 1} lines, the cap is {MAX_LINES}")
        for word in FORBIDDEN:
            if word in message.lower():
                problems.append(f"{sha}: says {word!r}, which is the vocabulary this removes")
    if problems:
        raise SystemExit("\n".join(problems))


def citations() -> list[dict]:
    """Every commit of this repository the documentation cites, and where.

    Read with `release_check.sha_citations`, which is the function that refuses
    a citation the branch does not have. One definition of "a citation", used
    by the check and by the fix.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    from release_check import _this_repository, sha_citations  # noqa: PLC0415

    ours = _this_repository().lower()
    found: list[dict] = []
    for relative in CITED_IN:
        path = ROOT / relative
        if not path.is_file():
            continue
        found += [
            row for row in sha_citations(relative, path.read_text(encoding="utf-8"))
            if (row["repository"] or "").lower() == ours
        ]
    return found


def rewrite_citations(mapping: dict[str, str]) -> list[str]:
    """Point every cited commit at the one that replaced it. Returns what moved."""
    short = {old[:40]: new for old, new in mapping.items()}
    moved: list[str] = []
    for relative in CITED_IN:
        path = ROOT / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        original = text
        for row in citations():
            if row["where"].split(":")[0] != relative:
                continue
            replacement = short.get(row["sha"])
            if replacement is None:
                raise SystemExit(
                    f"{row['where']} cites {row['sha']}, which is not a commit this run "
                    "replayed, so it cannot be updated and would be left pointing at a "
                    "commit no clone will have"
                )
            text = text.replace(row["sha"], replacement)
        if text != original:
            path.write_text(text, encoding="utf-8", newline="\n")
            moved.append(relative)
    return moved


def refuse_a_tree_that_is_not_ready(branch: str) -> None:
    """Everything that has to be true before a single object is written."""
    code, top, _ = git_try("rev-parse", "--show-toplevel")
    if code != 0 or Path(top).resolve() != ROOT.resolve():
        raise SystemExit(f"{ROOT} is not the root of its own git repository")
    code, current, _ = git_try("symbolic-ref", "--quiet", "--short", "HEAD")
    if code != 0:
        raise SystemExit("HEAD is detached. Check out the branch you mean to rewrite.")
    if current != branch:
        raise SystemExit(
            f"the checked-out branch is {current} and this would rewrite {branch}. "
            f"Run `git switch {branch}` first, so that what moves is what you are looking at."
        )
    dirty = git("status", "--porcelain").strip()
    if dirty:
        raise SystemExit(
            "the working tree is not clean, and this rewrites the branch under it:\n"
            + dirty
            + "\n\nCommit or stash first. The one file this repository expects to see "
            "untracked is the plan, which is not part of the tree."
        )


def tag_ancestry(branch: str) -> str:
    code, _, _ = git_try("rev-parse", "--verify", "--quiet", "v2.3.0^{commit}")
    if code != 0:
        return "there is no v2.3.0 tag in this clone"
    code, _, _ = git_try("merge-base", "--is-ancestor", "v2.3.0^{commit}", branch)
    return (
        f"v2.3.0 IS an ancestor of {branch}"
        if code == 0
        else f"v2.3.0 is NOT an ancestor of {branch} (the tag still resolves, and its "
             "tree, its release and every `v2.3.0:path` locator in the tree are unaffected)"
    )


def criterion(branch: str, backup: str) -> None:
    """The three commands the phase's completion criterion is written as."""
    print("\nthe criterion, run rather than quoted:")
    scaffolding = sum(
        1 for line in git("log", "--format=%B", branch).lower().splitlines()
        for word in FORBIDDEN if word in line
    )
    print(f"  git log --format='%B' | grep -ci 'work rule|budget|adversarial pass'  -> {scaffolding}")
    longest = max(
        len(field(sha, "%B").rstrip("\n").split("\n")) + 1
        for sha in git("rev-list", branch).split()
    )
    print(f"  the longest message body                                             -> {longest}")
    code, out, _ = git_try("diff", backup, branch, "--stat")
    print(f"  git diff {backup} {branch} --stat                             -> "
          + ("empty" if not out.strip() else "NOT EMPTY, and that is a lost change"))
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    print(f"  grep -c 'How this was built' README.md                               -> "
          f"{readme.count('How this was built')}")
    print(f"  {tag_ancestry(branch)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apply", action="store_true",
                        help="move the current branch to the replayed head")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--backup", default="backup-pre-rewrite",
                        help="the ref the old history is kept at")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--no-push", action="store_true",
                        help="do not push the backup. Only for a clone with no remote.")
    parser.add_argument("--map-out", type=Path,
                        default=HERE / "rewritten-shas.tsv",
                        help="where the old-to-new SHA map is written")
    arguments = parser.parse_args()

    # Before anything is read or built, because a person with a dirty tree
    # should be told that and not handed a list of forty-five commits.
    if arguments.apply:
        refuse_a_tree_that_is_not_ready(arguments.branch)

    commits = git("rev-list", "--reverse", arguments.branch).split()
    unknown = sorted(set(MESSAGES) - {sha[:8] for sha in commits})
    if unknown:
        raise SystemExit(
            "these messages name commits that are not on the branch, so the map is "
            f"stale: {unknown}"
        )

    # Read every message first, then check the whole history, then build. A
    # check between the two would be about what this run intends rather than
    # about what it would produce.
    resulting = {sha[:8]: MESSAGES.get(sha[:8], field(sha, "%B")) for sha in commits}
    check(resulting)

    mapping: dict[str, str] = {}
    rewritten = 0
    for sha in commits:
        message = resulting[sha[:8]]
        if sha[:8] in MESSAGES:
            rewritten += 1
        environment = dict(
            os.environ,
            GIT_AUTHOR_NAME=field(sha, "%an"), GIT_AUTHOR_EMAIL=field(sha, "%ae"),
            GIT_AUTHOR_DATE=field(sha, "%aI"),
            GIT_COMMITTER_NAME=field(sha, "%cn"), GIT_COMMITTER_EMAIL=field(sha, "%ce"),
            GIT_COMMITTER_DATE=field(sha, "%cI"),
        )
        argv = ["commit-tree", field(sha, "%T")]
        for parent in field(sha, "%P").split():
            argv += ["-p", mapping[parent]]
        mapping[sha] = git(*argv, stdin=message.rstrip("\n").encode("utf-8") + b"\n",
                           env=environment).strip()

    head = mapping[commits[-1]]
    moved_at_all = sum(1 for old, new in mapping.items() if old != new)
    print(f"{len(commits)} commits replayed, {rewritten} messages rewritten, "
          f"{moved_at_all} SHAs moved")
    print(f"new head: {head}")
    print(f"documentation citations that would move: "
          f"{', '.join(row['where'] for row in citations()) or 'none'}")
    print(f"before: {tag_ancestry(arguments.branch)}")

    if not arguments.apply:
        print(f"\nthe trees are identical if this prints nothing:\n"
              f"  git diff {arguments.branch} {head} --stat")
        print("\nnothing was moved. Re-run with --apply, after reading "
              ".github/release-notes/RUNBOOK.md.")
        return 0

    before = git("rev-parse", arguments.branch).strip()
    if git("diff", before, head, "--stat").strip():
        raise SystemExit(
            "the replayed tree differs from the branch's. Nothing was moved. This "
            "should be impossible: only messages change here."
        )

    # The backup, before anything moves, and on the remote before it is needed.
    code, existing, _ = git_try("rev-parse", "--verify", "--quiet", arguments.backup)
    if code == 0 and existing != before:
        raise SystemExit(
            f"{arguments.backup} is already here and points at {existing[:8]}, which is "
            f"not the head of {arguments.branch}. That is a backup from an earlier "
            "attempt: look at it, and delete it deliberately before running this again."
        )
    git("branch", "-f", arguments.backup, before)
    print(f"\n{arguments.backup} -> {before[:8]}")
    if arguments.no_push:
        print("the backup was NOT pushed, because --no-push was given")
    else:
        code, _, error = git_try("push", arguments.remote, arguments.backup)
        if code != 0:
            git("branch", "-D", arguments.backup)
            raise SystemExit(
                f"pushing {arguments.backup} to {arguments.remote} failed, so nothing was "
                f"moved and the local backup was removed again:\n{error}"
            )
        print(f"pushed {arguments.backup} to {arguments.remote}")

    git("update-ref", f"refs/heads/{arguments.branch}", head, before)
    print(f"{arguments.branch} moved to {head[:8]}")

    still_there = git("diff", arguments.backup, arguments.branch, "--stat").strip()
    if still_there:
        raise SystemExit(
            "the branch and the backup differ AFTER the move, which means something was "
            f"lost. Recover with `git reset --hard {arguments.backup}`:\n{still_there}"
        )

    arguments.map_out.write_text(
        "# old\tnew, for every commit this rewrite replayed. Written by\n"
        "# .github/history-rewrite/replay.py --apply. The old column is a list of\n"
        "# commits no clone has any more; it is kept so that a SHA quoted anywhere\n"
        "# outside this repository can still be resolved to the commit that replaced\n"
        "# it. Not a .md and not under docs/, so the gate that refuses a dead citation\n"
        "# in the documentation does not read it as one.\n"
        + "".join(f"{old}\t{new}\n" for old, new in mapping.items()),
        encoding="utf-8", newline="\n",
    )
    print(f"wrote {arguments.map_out.relative_to(ROOT).as_posix()}")

    moved = rewrite_citations(mapping)
    print(f"rewrote the cited commits in: {', '.join(moved) or 'nothing needed it'}")

    criterion(arguments.branch, arguments.backup)

    print(
        "\nnothing was force-pushed. What is left, in order:\n"
        f"  git add {' '.join(moved)} {arguments.map_out.relative_to(ROOT).as_posix()}\n"
        '  git commit -m "Point the documented commits at the ones that replaced them"\n'
        f"  git push --force-with-lease {arguments.remote} {arguments.branch}\n"
        "and then the rest of .github/release-notes/RUNBOOK.md."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
