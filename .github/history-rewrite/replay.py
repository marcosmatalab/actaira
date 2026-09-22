#!/usr/bin/env python3
"""Replay every commit with the same tree and a new message.

    python3 .github/history-rewrite/replay.py            print what it would do
    python3 .github/history-rewrite/replay.py --apply    move the branch to it

`git commit-tree` and not `git rebase -i`, for one reason: a rebase applies
patches and can resolve them differently, and the only thing that may change
here is the message. Replaying each commit's recorded TREE OBJECT makes the
final tree identical by construction rather than by inspection afterwards.

The author and committer dates are carried over untouched. Forty-eight commits
between 12 and 22 September 2026 is what happened, and falsifying the dates
would be far worse than an intense week. `README.md` says so in "How this was
built", which is why that section was written and committed before this script
was.

WHAT IT DOES NOT DO. It does not push, it does not delete the backup, and
without `--apply` it does not move a ref: it builds the objects, prints the new
head, and stops. Everything after that is in
`.github/release-notes/RUNBOOK.md`, because a history rewrite of a published
branch is a deliberate act and a script that performed it on import would be
the opposite.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MESSAGES = json.loads((Path(__file__).parent / "messages.json").read_text(encoding="utf-8"))

# The message cap the acceptance script measures, as `wc -l` counts it over
# `git log --format=%B`: the message's own lines plus the newline the format
# adds. Asserted here rather than trusted, because this file is the last place
# the cap can be held before the history carries it.
MAX_LINES = 15
FORBIDDEN = ("work rule", "budget", "adversarial pass", "a later session")


def git(*arguments: str, stdin: bytes | None = None, env=None) -> str:
    return subprocess.run(  # noqa: S603 - a fixed argv, no shell
        ["git", *arguments],  # noqa: S607 - git from PATH, as every other script here
        cwd=ROOT, capture_output=True, input=stdin,
        env=env, check=True,
    ).stdout.decode("utf-8")


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apply", action="store_true",
                        help="move the current branch to the replayed head")
    parser.add_argument("--branch", default="main")
    arguments = parser.parse_args()

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
    print(f"{len(commits)} commits replayed, {rewritten} messages rewritten")
    print(f"new head: {head}")
    print(f"the trees are identical if this prints nothing:\n"
          f"  git diff {arguments.branch} {head} --stat")

    if not arguments.apply:
        print("\nnothing was moved. Re-run with --apply, after reading "
              ".github/release-notes/RUNBOOK.md.")
        return 0

    before = git("rev-parse", arguments.branch).strip()
    if git("diff", before, head, "--stat").strip():
        raise SystemExit(
            "the replayed tree differs from the branch's. Nothing was moved. This "
            "should be impossible: only messages change here."
        )
    git("branch", "-f", f"backup-pre-rewrite-{before[:8]}", before)
    git("update-ref", f"refs/heads/{arguments.branch}", head, before)
    print(f"\n{arguments.branch} moved to {head}")
    print(f"the previous head is at backup-pre-rewrite-{before[:8]}")
    print("nothing was pushed. The runbook has the rest.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
