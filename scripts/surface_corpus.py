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
the commit, the licence and that sha in `provenance.json` beside it - docs/PRINCIPLES.md
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
    Seamark never shells out is about the tool, and this is the operator's own
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
            "User-Agent": "seamark-surface-corpus",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


# The searches this corpus is built from. The first is the broad one, which is
# what measures how often a rule fires on configurations nobody wrote for us.
# The rest are targeted, and they exist because `docs/PRINCIPLES.md` requires a rule's two
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
    # Phase S2. One broad query per vendor, then the targeted ones a rule needs
    # when the broad sweep produces no violating case. Same argument as above: a
    # rule with no real violating case goes LOOKING for one, and if it still
    # finds none it says so with the queries and the date (docs/PRINCIPLES.md's third,
    # narrow branch) rather than getting a fixture we wrote ourselves.
    "vscode-tasks": 'path:.vscode filename:tasks.json "folderOpen"',
    "vscode-tasks-broad": "path:.vscode filename:tasks.json runOptions",
    "devcontainer": "filename:devcontainer.json initializeCommand",
    "devcontainer-broad": "filename:devcontainer.json postCreateCommand",
    "devcontainer-mounts": 'filename:devcontainer.json mounts ".ssh"',
    "devcontainer-privileged": 'filename:devcontainer.json "privileged": true',
    "codex": "path:.codex filename:config.toml",
    "codex-hooks": "path:.codex filename:hooks.json",
    "codex-sandbox": 'path:.codex filename:config.toml "danger-full-access"',
    "cursor-hooks": "path:.cursor filename:hooks.json",
    "cursor-mcp": "path:.cursor filename:mcp.json mcpServers",
    "gemini": "path:.gemini filename:settings.json mcpServers",
    "gemini-trust": 'path:.gemini filename:settings.json "trust": true',
    "agents-md": "filename:AGENTS.md",
    "instructions-import-home": 'filename:CLAUDE.md "@~/"',
    "instructions-import-abs": 'filename:AGENTS.md "@/"',
    "instructions-piped": 'filename:AGENTS.md "curl -" "| bash"',
    "instructions-piped-sh": 'filename:CLAUDE.md "curl" "| sh"',
    "instructions-script": 'filename:CLAUDE.md "@scripts/" ".sh"',
    "instructions-script-agents": 'filename:AGENTS.md "@scripts/"',
    "instructions-script-bin": 'filename:CLAUDE.md "@bin/"',
    # Added when the capability-coverage invariant (D-292) turned up two
    # capabilities this tree emitted and no rule named.
    "claude-mcp-tool-hook": 'path:.claude filename:settings.json "mcp_tool"',
    "gemini-approval": "path:.gemini filename:settings.json defaultApprovalMode",
    "gemini-tool-command": "path:.gemini filename:settings.json toolDiscoveryCommand",
}

# Which vendor each query is collecting for, so `--report` can count by vendor
# and the promotion can keep a balance rather than twenty files of one kind.
VENDOR_OF = {
    "broad": "claude-code", "mcp": "claude-code", "bypass": "claude-code",
    "http-hook": "claude-code", "bash-allow": "claude-code", "sandbox": "claude-code",
    "sandbox-off": "claude-code",
    "vscode-tasks": "vscode", "vscode-tasks-broad": "vscode",
    "devcontainer": "devcontainer", "devcontainer-broad": "devcontainer",
    "devcontainer-mounts": "devcontainer", "devcontainer-privileged": "devcontainer",
    "codex": "codex", "codex-hooks": "codex", "codex-sandbox": "codex",
    "cursor-hooks": "cursor", "cursor-mcp": "cursor",
    "gemini": "gemini-cli", "gemini-trust": "gemini-cli",
    "agents-md": "instructions",
    "instructions-import-home": "instructions", "instructions-import-abs": "instructions",
    "instructions-piped": "instructions", "instructions-piped-sh": "instructions",
    "instructions-script": "instructions",
    "instructions-script-agents": "instructions", "instructions-script-bin": "instructions",
}

# The file suffixes a search result has to end in to be kept. A code search for
# `mcpServers` matches prose in a README, and a corpus with a README in it is a
# corpus that proves nothing about a reader of configuration.
WANTED = (
    ".claude/settings.json", ".mcp.json",
    ".vscode/tasks.json", ".vscode/settings.json",
    "devcontainer.json",
    ".codex/config.toml", ".codex/hooks.json",
    ".cursor/hooks.json", ".cursor/mcp.json",
    ".gemini/settings.json",
    "AGENTS.md", "CLAUDE.md", "GEMINI.md",
)


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
            if item["path"].endswith(WANTED):
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


def vendors_present(root: Path) -> set[str]:
    """Which vendors a downloaded root has files for, by the paths it contains.

    By file layout and not by the query that found it: one repository is often
    returned by several queries, and the honest answer to "which vendor is this
    a fixture for" is "the ones whose files are in it".
    """
    found: set[str] = set()
    for relative in (
        ".claude/settings.json", ".mcp.json", ".vscode/tasks.json",
        ".vscode/settings.json", ".devcontainer/devcontainer.json",
        ".devcontainer.json", ".codex/config.toml", ".codex/hooks.json",
        ".cursor/hooks.json", ".cursor/mcp.json", ".gemini/settings.json",
        "AGENTS.md", "CLAUDE.md", "GEMINI.md",
    ):
        if not (root / relative).is_file():
            continue
        if relative.startswith(".claude") or relative == ".mcp.json":
            found.add("claude-code")
        elif relative.startswith(".vscode"):
            found.add("vscode")
        elif "devcontainer" in relative:
            found.add("devcontainer")
        elif relative.startswith(".codex"):
            found.add("codex")
        elif relative.startswith(".cursor"):
            found.add("cursor")
        elif relative.startswith(".gemini"):
            found.add("gemini-cli")
        else:
            found.add("instructions")
    return found


def promote(count: int) -> int:
    """Copy up to `count` downloaded roots PER VENDOR into the fixture directory.

    Per vendor rather than the first N alphabetically, which is what this did
    when there was one vendor and would now produce twenty Claude Code files and
    nothing else. A corpus that is unbalanced by accident measures whichever
    vendor happened to sort first.

    Within a vendor, roots that resolve to at least one capability come first: a
    fixture that produces nothing exercises the reader and not the resolver, and
    both are wanted, so the empty ones fill the remaining places rather than
    taking the first.
    """
    if not DOWNLOAD.is_dir():
        print("nothing downloaded; run without --promote first", file=sys.stderr)
        return 1
    sys.path.insert(0, str(ROOT / "src"))
    from seamark.surface import resolve as resolve_mod
    from seamark.surface import rules as rules_mod

    catalogue = rules_mod.load()
    registry = {vendor: (mod, res) for vendor, mod, res in resolve_mod.vendor_registry()}
    roots = [path for path in sorted(DOWNLOAD.iterdir()) if (path / "provenance.json").is_file()]

    # Rank 0 fires a rule nothing else in this vendor's selection has fired yet,
    # rank 1 fires a rule already covered, rank 2 resolves to a capability and
    # fires nothing, rank 3 is empty. The first rank is what makes the corpus a
    # test of the RULES rather than of the reader: without it a vendor's five
    # places go to whichever repositories sort first, and a rule with a real
    # violating case in the download can end up with none in the fixtures.
    scored: dict[str, list[tuple[Path, frozenset[str], bool]]] = {}
    for root in roots:
        for vendor in vendors_present(root):
            mod, res = registry[vendor]
            try:
                surface = res(mod.read(root))
                found, _gaps = rules_mod.evaluate(surface, catalogue)
            except Exception as exc:  # noqa: BLE001 - a bad fixture must not stop the sweep
                print(f"{root.name} [{vendor}]: {exc}", file=sys.stderr)
                continue
            scored.setdefault(vendor, []).append(
                (root, frozenset(item.rule_id for item in found), bool(surface.capabilities))
            )

    by_vendor: dict[str, list[tuple[int, Path]]] = {}
    for vendor, entries in scored.items():
        covered: set[str] = set()
        ordered: list[tuple[int, Path]] = []
        remaining = sorted(entries, key=lambda item: item[0].name)
        while remaining:
            best = min(
                range(len(remaining)),
                key=lambda index: (
                    -len(remaining[index][1] - covered),
                    0 if remaining[index][2] else 1,
                    remaining[index][0].name,
                ),
            )
            root, fired, had = remaining.pop(best)
            rank = 0 if fired - covered else (1 if fired else (2 if had else 3))
            covered |= fired
            ordered.append((rank, root))
        by_vendor[vendor] = ordered

    chosen: dict[Path, set[str]] = {}
    for vendor, entries in by_vendor.items():
        taken = 0
        for _rank, root in entries:
            if taken >= count:
                break
            chosen.setdefault(root, set()).add(vendor)
            taken += 1

    PROMOTED.mkdir(parents=True, exist_ok=True)
    for source in sorted(chosen):
        record = source / "provenance.json"
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
    print(f"promoted {len(chosen)} configurations into {PROMOTED.relative_to(ROOT)}")
    for vendor in sorted(by_vendor):
        held = sum(1 for names in chosen.values() if vendor in names)
        print(f"  {vendor:14s} {held} of {len(by_vendor[vendor])} downloaded")
    return 0


def goldens() -> int:
    """Write `expected.json` beside every promoted configuration, per vendor.

    The golden records the CLAIMS a person then reviews - which rules fire, each
    capability name and its resolution, the counts - rather than a dump of the
    output compared against itself, which is the shape D-15 warns about. This
    writes the claims; reading them is a person's job, and the phase report is
    where that reading is recorded.
    """
    sys.path.insert(0, str(ROOT / "src"))
    from seamark.surface import resolve as resolve_mod
    from seamark.surface import rules as rules_mod

    catalogue = rules_mod.load()
    registry = {vendor: (mod, res) for vendor, mod, res in resolve_mod.vendor_registry()}
    written = 0
    for root in sorted(PROMOTED.iterdir()):
        if not (root / "provenance.json").is_file():
            continue
        record: dict[str, Any] = {}
        for vendor in sorted(vendors_present(root)):
            mod, res = registry[vendor]
            surface = res(mod.read(root))
            found, gaps = rules_mod.evaluate(surface, catalogue)
            record[vendor] = {
                "rules_that_fire": sorted({item.rule_id for item in found}),
                "capabilities": {
                    item.name: item.resolution.value for item in surface.capabilities
                },
                "capability_count": len(surface.capabilities),
                "unresolved_count": len(surface.unresolved) + len(gaps),
                "not_read": sorted(entry.path for entry in surface.not_read),
            }
        (root / "expected.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        written += 1
    print(f"wrote {written} expected.json files")
    return 0


def report() -> int:
    """How many of the tracked corpus each rule fires on.

    Printed here and written into no published document. `docs/PRINCIPLES.md` is explicit
    that publishing a figure is the study's job and that no figure is published
    without a command that measures it; this is the command, and the commit
    message is where the number goes.
    """
    sys.path.insert(0, str(ROOT / "src"))
    from seamark.surface import resolve as resolve_mod
    from seamark.surface import rules as rules_mod

    catalogue = rules_mod.load()
    registry = {vendor: (mod, res) for vendor, mod, res in resolve_mod.vendor_registry()}
    counts: dict[str, int] = {rule.id: 0 for rule in catalogue}
    per_vendor: dict[str, int] = {}
    gaps = 0
    roots = [path for path in sorted(PROMOTED.glob("*")) if (path / "provenance.json").is_file()]
    for root in roots:
        for vendor in sorted(vendors_present(root)):
            per_vendor[vendor] = per_vendor.get(vendor, 0) + 1
            mod, res = registry[vendor]
            surface = res(mod.read(root))
            found, unresolved = rules_mod.evaluate(surface, catalogue)
            gaps += len(unresolved) + len(surface.unresolved)
            for rule_id in {item.rule_id for item in found}:
                counts[rule_id] += 1
    print(f"{len(roots)} configurations in the tracked corpus")
    for vendor in sorted(per_vendor):
        print(f"  {vendor:14s} {per_vendor[vendor]}")
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
                        help="copy up to N downloaded configurations PER VENDOR into "
                             "tests/fixtures")
    parser.add_argument("--report", action="store_true",
                        help="count which rules fire on the tracked corpus")
    parser.add_argument("--goldens", action="store_true",
                        help="write expected.json beside every promoted configuration")
    args = parser.parse_args()
    if args.goldens:
        return goldens()
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
