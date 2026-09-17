#!/usr/bin/env python3
"""Collect real `.claude/settings.json` files from public repositories.

Outside the package and outside the test suite, deliberately. The network never
enters a test in this repository - `tests/netguard.py` is armed and a release
check asserts it still bites - so the corpus is fetched HERE, by a person, and
what the suite reads is the snapshot this script writes.

    GH_TOKEN=... python3 scripts/surface_corpus.py --limit 40
    python3 scripts/surface_corpus.py --report        # counts, from the snapshot

Every file is pinned by its blob sha, which is what git computed over those
bytes, so the snapshot says exactly which bytes were read and a re-run that gets
different bytes is visible rather than silent. Each one carries the repository,
the commit, the licence and that sha in `provenance.json` beside it - CLAUDE.md
requires a rule's tests to run on a real configuration, citing repo, commit and
licence, or on a reconstruction from a published report.

Only licences the OSI lists are kept. A repository with no licence, or one this
script does not recognise, is skipped and counted: nobody granted permission to
redistribute those bytes, and a corpus that quietly included them would be a
licensing defect inside a project whose entire argument is provenance.

The download directory is ignored by git. What is committed is the selection
under `tests/fixtures/surface/corpus/`, written by `--promote`.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOWNLOAD = ROOT / ".corpus"
PROMOTED = ROOT / "tests" / "fixtures" / "surface" / "corpus"

# SPDX identifiers the OSI lists, spelled as GitHub's licence API spells them.
# An allowlist rather than a blocklist: the question is whether somebody granted
# permission, and "not on my list of refusals" is not permission.
OSI = {
    "apache-2.0", "mit", "bsd-2-clause", "bsd-3-clause", "isc", "mpl-2.0",
    "gpl-2.0", "gpl-3.0", "lgpl-2.1", "lgpl-3.0", "agpl-3.0", "epl-2.0",
    "unlicense", "zlib", "postgresql", "artistic-2.0",
}

API = "https://api.github.com"


def token() -> str | None:
    """`GH_TOKEN`, or whatever `gh` is already signed in as.

    The second is a convenience for a developer who has the CLI configured. It
    is a subprocess and it is in `scripts/`, not in the package: the rule that
    Actaira never shells out is about the tool, and this is the operator's own
    machine doing the operator's own fetch.
    """
    found = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if found:
        return found
    try:
        # `gh` is resolved from the operator's own PATH on the operator's own
        # machine, which is the whole point: this is their CLI, already signed
        # in. Pinning an absolute path would break on every machine but the one
        # that wrote it.
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["gh", "auth", "token"],  # noqa: S607 - the operator's own PATH
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def call(path: str, auth: str, params: str = "") -> Any:
    request = urllib.request.Request(  # noqa: S310 - https, fixed host
        f"{API}{path}{params}",
        headers={
            "Authorization": f"Bearer {auth}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "actaira-surface-corpus",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


# The searches this corpus is built from. The first is the broad one, which is
# what measures how often a rule fires on configurations nobody wrote for us.
# The rest are targeted, and they exist because CLAUDE.md requires a rule's two
# tests to run on a REAL configuration: a rule with no real violating case in
# the broad sweep gets one by going to look for it, never by inventing a fixture.
QUERIES = {
    "broad": "path:.claude filename:settings.json",
    "mcp": "filename:.mcp.json mcpServers",
    "bypass": "path:.claude filename:settings.json bypassPermissions",
    "http-hook": 'path:.claude filename:settings.json "type": "http"',
    "bash-allow": 'path:.claude filename:settings.json "Bash(*)"',
    "sandbox": "path:.claude filename:settings.json sandbox excludedCommands",
    "sandbox-off": 'path:.claude filename:settings.json sandbox "enabled": false',
}


def search(auth: str, limit: int, query: str) -> list[dict[str, Any]]:
    """Code search, paged until `limit` distinct repositories."""
    found: dict[str, dict[str, Any]] = {}
    for page in range(1, 11):
        try:
            answer = call(
                "/search/code",
                auth,
                "?q=" + urllib.parse.quote(query)
                + f"&per_page=100&page={page}",
            )
        except urllib.error.HTTPError as exc:
            print(f"search page {page}: HTTP {exc.code}", file=sys.stderr)
            break
        items = answer.get("items") or []
        if not items:
            break
        for item in items:
            key = "{}:{}".format(item["repository"]["full_name"], item["path"])
            if item["path"].endswith((".claude/settings.json", ".mcp.json")):
                found.setdefault(key, item)
            if len(found) >= limit:
                return list(found.values())
    return list(found.values())


def collect(limit: int, which: tuple[str, ...]) -> dict[str, int]:
    auth = token()
    if not auth:
        print(
            "no GH_TOKEN and `gh auth token` gave nothing. The corpus is fetched by a "
            "person, not by the suite; see the module docstring.",
            file=sys.stderr,
        )
        return {"kept": 0, "no_licence": 0, "failed": 0}

    DOWNLOAD.mkdir(parents=True, exist_ok=True)
    counts = {"kept": 0, "no_licence": 0, "failed": 0}
    items: list[dict[str, Any]] = []
    for name in which:
        items.extend(search(auth, limit, QUERIES[name]))
    seen: set[str] = set()
    for item in items:
        full = item["repository"]["full_name"]
        key = "{}:{}".format(full, item["path"])
        if key in seen:
            continue
        seen.add(key)
        slug = full.replace("/", "__")
        try:
            repository = call(f"/repos/{full}", auth)
            licence = ((repository.get("license") or {}).get("spdx_id") or "").lower()
            if licence not in OSI:
                counts["no_licence"] += 1
                continue
            head = call(f"/repos/{full}/commits", auth, "?per_page=1")[0]["sha"]
            blob = call(
                "/repos/{}/contents/{}".format(full, item["path"]), auth, "?ref=" + head
            )
            body = base64.b64decode(blob["content"])
        except (urllib.error.HTTPError, urllib.error.URLError, KeyError, IndexError) as exc:
            counts["failed"] += 1
            print(f"{full}: {exc}", file=sys.stderr)
            continue

        # Laid out under the repository-relative path the file actually had, so
        # the fixture is a tree the reader walks exactly as it walks a checkout.
        target = DOWNLOAD / slug
        landing = target / item["path"]
        landing.parent.mkdir(parents=True, exist_ok=True)
        landing.write_bytes(body)
        record = {}
        if (target / "provenance.json").is_file():
            record = json.loads((target / "provenance.json").read_text(encoding="utf-8"))
        record.update(
            {
                "repo": f"https://github.com/{full}",
                "commit": head,
                "licence": licence,
            }
        )
        record.setdefault("files", {})[item["path"]] = blob["sha"]
        (target / "provenance.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        counts["kept"] += 1
    return counts


def promote(count: int) -> int:
    """Copy the downloaded snapshot into the tracked fixture directory."""
    if not DOWNLOAD.is_dir():
        print("nothing downloaded; run without --promote first", file=sys.stderr)
        return 1
    PROMOTED.mkdir(parents=True, exist_ok=True)
    taken = 0
    for source in sorted(DOWNLOAD.iterdir()):
        if taken >= count:
            break
        record = source / "provenance.json"
        if not record.is_file():
            continue
        target = PROMOTED / source.name
        target.mkdir(parents=True, exist_ok=True)
        for relative in json.loads(record.read_text(encoding="utf-8")).get("files", {}):
            origin = source / relative
            if not origin.is_file():
                continue
            landing = target / relative
            landing.parent.mkdir(parents=True, exist_ok=True)
            landing.write_bytes(origin.read_bytes())
        (target / "provenance.json").write_bytes(record.read_bytes())
        taken += 1
    print(f"promoted {taken} configurations into {PROMOTED.relative_to(ROOT)}")
    return 0


def report() -> int:
    """How many of the tracked corpus each rule fires on.

    Printed here and written into no published document. CLAUDE.md is explicit
    that publishing a figure is the study's job and that no figure is published
    without a command that measures it; this is the command, and the commit
    message is where the number goes.
    """
    sys.path.insert(0, str(ROOT / "src"))
    from actaira.surface import claude_code, resolve, rules

    catalogue = rules.load()
    counts: dict[str, int] = {rule.id: 0 for rule in catalogue}
    gaps = 0
    roots = [path for path in sorted(PROMOTED.glob("*")) if (path / "provenance.json").is_file()]
    for root in roots:
        surface = resolve.resolve(claude_code.read(root))
        found, unresolved = rules.evaluate(surface, catalogue)
        gaps += len(unresolved) + len(surface.unresolved)
        for rule_id in {item.rule_id for item in found}:
            counts[rule_id] += 1
    print(f"{len(roots)} configurations in the tracked corpus")
    for rule_id in sorted(counts):
        print(f"  {rule_id}  {counts[rule_id]}")
    print(f"  unresolved entries across the corpus: {gaps}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--limit", type=int, default=40)
    parser.add_argument("--queries", default="broad",
                        help="comma-separated names from QUERIES, or `all`")
    parser.add_argument("--promote", type=int, metavar="N",
                        help="copy N downloaded configurations into tests/fixtures")
    parser.add_argument("--report", action="store_true",
                        help="count which rules fire on the tracked corpus")
    args = parser.parse_args()
    if args.report:
        return report()
    if args.promote:
        return promote(args.promote)
    which = tuple(QUERIES) if args.queries == "all" else tuple(args.queries.split(","))
    unknown = [name for name in which if name not in QUERIES]
    if unknown:
        print("unknown query name(s): {}".format(", ".join(unknown)), file=sys.stderr)
        return 2
    counts = collect(args.limit, which)
    print(
        "kept {kept}, skipped for licence {no_licence}, failed {failed}".format(**counts)
    )
    return 0


if __name__ == "__main__":  # pragma: no cover

    raise SystemExit(main())
