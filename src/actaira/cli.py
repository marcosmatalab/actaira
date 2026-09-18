"""The command line: seven of the eight commands CLAUDE.md caps the set at.

`check` reads the agent configuration of a repository or a machine, resolves
what it permits across scopes, and applies the rule packs. `diff` says what
changed between two moments, and `seal` signs a baseline of a surface that
`verify` can then check without a network and without trusting the operator;
`keygen` creates, rotates and revokes the key that signs one. `scan` reads the
transcripts an agent already wrote and turns them into canonical traces, and
`watch` records a run from outside the agent.

Seven of seven, so CLAUDE.md's list now has no unbuilt name on it. The cap of
eight is still the cap: an eighth is a decision and a ninth costs one of these.

Rejected: keeping the previous 2 458-line parser with the dead subcommands
hidden or stubbed. A command that parses and then says "not implemented" is a
promise in the help text, and the help text is the contract COMPATIBILITY.md
publishes.

Six of the seven never reach the network. `scan` and `check` are the strictest
and for the same reason: one reads files full of somebody's conversation and the
other files somebody else wrote, so neither opens a socket at all and a test
enforces that rather than trusting it. `watch` is the exception and says so - it
binds a loopback port when a server speaks HTTP, which is the whole mechanism by
which it interposes.

`diff` runs two programs and they are `git ls-tree` and `git cat-file`, with
argv as a list, never a shell, and never a checkout - the argument is in
`surface/diff.py`. It is the only command here that runs anything at all, and
what it runs cannot execute a hook, a filter or a textconv driver.

Nothing here ever runs what it reads. `check` records four facts about a script
a hook names - existence, whether it is inside the tree, whether git tracks it,
and its sha256 - and a test plants a script that would leave a sentinel behind
to prove the fifth fact is never obtained.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .attest import keyring
from .attest import verify as verify_mod
from .i18n.catalog import Catalog
from .surface import Resolution
from .trace import reader_for
from .trace.model import trace_digest

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
# Design note D-276. "I could not tell" has to stay distinguishable from "I
# decided no", and a pipeline that branched on 1 alone would read an unresolved
# capability as a clean run. `check` is the first command that can answer that
# way, so `check` is the command that brings the code back; COMPATIBILITY.md has
# been promising its return since phase A.1 and now publishes it.
#
# A code INFORMS. Whether a non-zero exit blocks a merge is the user's branch
# protection, which is theirs; exiting non-zero is not acting on what we
# observed, and writing in their tree would be.
EXIT_INDETERMINATE = 3
# Not part of the published contract in COMPATIBILITY.md, and deliberately so:
# it is the shell's own convention for a process killed by SIGPIPE, reported
# here because the interpreter cannot be killed by one after it has caught the
# error. See `main`.
EXIT_SIGPIPE = 141


def default_key_path() -> Path:
    """Where a key lands when nobody passed `--key`, resolved when asked.

    Design note D-240. This was a module-level `Path.home() / ".actaira" /
    "signing-key.pem"`, evaluated at import. `Path.home()` raises where the
    environment names no home directory - a container run with a scrubbed
    environment, a service unit, a CI step that clears it - and a module-level
    call meant the whole CLI died at import with a bare `RuntimeError`
    traceback, including `--help` and `--version`, neither of which touch a key.

    So it is resolved when a parser is built, and an unresolvable home becomes
    a path under the working directory plus an argparse default the user can
    see and override, rather than an exception under the import statement.
    """
    try:
        home = Path.home()
    except (RuntimeError, OSError):
        # Not a guess at where the user's home is: an explicit local fallback,
        # visible in `--help`, which the operator overrides with `--key`.
        return Path(".actaira") / "signing-key.pem"
    return home / ".actaira" / "signing-key.pem"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="actaira",
        description=(
            "Read what your coding agents can do here, say what changed between two "
            "moments, and sign a baseline anybody can verify without trusting you. "
            "Offline, except that diff asks git for two trees. Nothing is scored."
        ),
    )
    parser.add_argument("--version", action="version", version=f"actaira {__version__}")
    parser.add_argument("--lang", choices=("en", "es"), default="en", help="output language")
    sub = parser.add_subparsers(dest="command", required=True)

    ver = sub.add_parser("verify", help="verify an attestation package offline")
    ver.add_argument("package", type=Path)
    ver.add_argument("--trusted-keyring", type=Path,
                     help="JSON keyring of fingerprints you already trust")
    ver.add_argument("--pubkey", help="base64 raw Ed25519 public key you already trust")
    ver.add_argument("--tsa-trust-store", type=Path,
                     help="a PEM file or directory of PEM certificates to validate the time-stamp "
                          "authority's chain against. Without it the chain state is `unknown`: "
                          "this tool ships no trust anchors, because choosing them is the "
                          "verifier's decision and a bundled list goes stale unaudited.")
    ver.add_argument("--require-trust", action="store_true",
                     help="fail unless the signing key is trusted")
    ver.add_argument("--json", action="store_true")
    ver.add_argument("--extends", type=Path,
                     help="an older package this one must be an append-only extension of")

    check = sub.add_parser(
        "check", help="read this repository's agent configuration and resolve what it permits"
    )
    check.add_argument("--repo", type=Path, default=Path("."),
                       help="the repository to read; the working directory otherwise")
    check.add_argument("--machine", action="store_true",
                       help="also read the user and managed scopes. Off by default: a pull "
                            "request cannot change either, and reading somebody's home "
                            "directory to answer a question about a repository is a cost "
                            "with no answer attached")
    check.add_argument("--agent-version", action="append", default=[], metavar="VENDOR=X.Y.Z",
                       help="the agent version, for example claude-code=2.1.257. Never "
                            "obtained by running the agent: asking the audited tool what it "
                            "is is trusting it. Without one, every rule whose answer depends "
                            "on the version is reported INDETERMINATE with its threshold named")
    check.add_argument("--with-content", action="store_true",
                       help="keep the literal commands, URLs and headers. Off by default: "
                            "these files can carry secrets and this report is pasted into CI "
                            "logs, so what travels is a sha256 and the shape")
    check.add_argument("--json", action="store_true")
    check.add_argument("--html", type=Path, metavar="PATH",
                       help="also write the report as one self-contained HTML file. No "
                            "script and no resource loaded from the network, so it opens "
                            "on a machine that has none")

    diff = sub.add_parser(
        "diff", help="say what capability changed between two moments"
    )
    # Positional and `nargs="*"` rather than two required arguments, because the
    # directory form takes none. The count is checked in `run_diff`, where the
    # message can say which of the two forms was half-given.
    diff.add_argument("refs", nargs="*", metavar="REF",
                      help="two git refs, oldest first. Use `--` before one that starts "
                           "with a dash; it is refused either way")
    diff.add_argument("--repo", type=Path, default=Path("."),
                      help="the repository the two refs live in; the working directory "
                           "otherwise. Never checked out: the trees are read with "
                           "`git ls-tree` and `git cat-file`, which run no hook and "
                           "apply no filter, and are written to a temporary directory")
    diff.add_argument("--from-dir", type=Path, metavar="PATH",
                      help="compare two directories instead of two refs, for a tree that "
                           "is not in git")
    diff.add_argument("--to-dir", type=Path, metavar="PATH")
    diff.add_argument("--agent-version", action="append", default=[], metavar="VENDOR=X.Y.Z",
                      help="as in check, and applied to both sides")
    diff.add_argument("--with-content", action="store_true",
                      help="as in check. Off by default")
    diff.add_argument("--json", action="store_true")
    diff.add_argument("--html", type=Path, metavar="PATH",
                      help="also write the report as one self-contained HTML file")
    diff.add_argument("--sarif", type=Path, metavar="PATH",
                      help="also write SARIF 2.1.0 for the rules that fired on something "
                           "added or widened, which is the set the exit code is from")

    seal = sub.add_parser(
        "seal", help="sign a baseline of this repository's surface, carrying no content"
    )
    seal.add_argument("--repo", type=Path, default=Path("."))
    seal.add_argument("--key", type=Path, default=default_key_path(),
                      help="the Ed25519 key `actaira keygen` wrote")
    seal.add_argument("--out", type=Path, required=True, metavar="DIR",
                      help="where the package goes, and where the reference map that "
                           "resolves it stays. The map does not travel with the package")
    seal.add_argument("--machine", action="store_true",
                      help="also seal the user and managed scopes")
    seal.add_argument("--agent-version", action="append", default=[], metavar="VENDOR=X.Y.Z")
    seal.add_argument("--json", action="store_true")

    scan = sub.add_parser(
        "scan", help="read the sessions an agent already recorded on this machine (L0)"
    )
    scan.add_argument("--source", default="claude-code",
                      help="which agent's transcripts to read")
    scan.add_argument("--home", type=Path,
                      help="the agent's config directory; CLAUDE_CONFIG_DIR otherwise")
    scan.add_argument("--demo", action="store_true",
                      help="run over the synthetic session shipped with the package, for a "
                           "machine with no agent installed")
    scan.add_argument("--out", type=Path, help="write one canonical trace per session here")
    scan.add_argument("--with-content", action="store_true",
                      help="keep the literal arguments and results in the trace. Off by "
                           "default: these files hold your conversations, and what travels "
                           "without this flag is a sha256 of each call and nothing else.")
    scan.add_argument("--json", action="store_true")

    watch = sub.add_parser(
        "watch", help="record a run from outside the agent, through an MCP proxy (L1)"
    )
    watch.add_argument("--mcp-config", type=Path,
                       help="the agent's MCP configuration; ./.mcp.json otherwise")
    watch.add_argument("--out", type=Path, default=Path("actaira-trace"),
                       help="where the record files and the assembled trace are written")
    watch.add_argument("--with-content", action="store_true",
                       help="keep literal arguments and results, as in scan")
    watch.add_argument("--json", action="store_true")
    # `child` and not `command`: the subparsers themselves use dest="command",
    # and a positional by that name silently overwrote it with the remainder,
    # so `actaira watch -- claude ...` dispatched to `verify`. argparse gives no
    # warning for the collision.
    watch.add_argument("child", nargs=argparse.REMAINDER,
                       help="-- followed by the command that runs the agent")

    keygen = sub.add_parser("keygen", help="create, rotate or revoke a signing key")
    keygen.add_argument("--key", type=Path, default=default_key_path(),
                        help="Ed25519 private key; the keyring lives beside it as keyring.json")
    keygen.add_argument("--rotate", action="store_true",
                        help="retire the current key and generate a new one, keeping the old "
                             "public key in the keyring so packages it signed still verify")
    keygen.add_argument("--revoke", metavar="KEY_ID",
                        help="mark a key revoked: nothing it ever signed will be accepted again")

    return parser


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------


def _print_key(keypair, ring: keyring.Keyring, ring_path: Path, catalog: Catalog) -> None:
    print(f"key_id      {keypair.key_id}")
    print(f"fingerprint {keypair.fingerprint}")
    print(f"public_b64  {keypair.public_b64}")
    print(catalog.line("key.keyring", path=str(ring_path), count=len(ring.keys)))
    for record in ring.keys:
        window = record.not_before or "-"
        if record.not_after:
            window = f"{window} .. {record.not_after}"
        marker = "*" if record.key_id == keypair.key_id else " "
        print(f"  {marker} {record.key_id}  {record.status:<8} {window}")


def run_keygen(args: argparse.Namespace, catalog: Catalog) -> int:
    if args.rotate and args.revoke:
        print(catalog.line("key.rotate_revoke_conflict"), file=sys.stderr)
        return EXIT_USAGE

    if args.revoke:
        try:
            record = keyring.revoke(args.key, args.revoke)
        except ValueError as exc:
            print(f"{exc}", file=sys.stderr)
            return EXIT_USAGE
        print(catalog.line("key.revoked", key_id=record.key_id,
                           path=str(keyring.keyring_path_for(args.key))))
        return EXIT_OK

    if args.rotate:
        rotation = keyring.rotate(args.key)
        if rotation.retired is not None:
            print(catalog.line("key.retired", key_id=rotation.retired.key_id,
                               when=str(rotation.retired.not_after)))
        if rotation.archived_key_path is not None:
            print(catalog.line("key.archived", path=str(rotation.archived_key_path)))
        print(catalog.line("key.rotated", path=str(args.key)))
        _print_key(rotation.keypair, rotation.keyring, rotation.keyring_path, catalog)
        return EXIT_OK

    local = keyring.load_local(args.key)
    print(catalog.line("key.created" if local.created_key else "key.loaded", path=str(args.key)))
    _print_key(local.keypair, local.keyring, local.path, catalog)
    return EXIT_OK


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def _print_verify(result: verify_mod.VerifyResult, catalog: Catalog) -> None:
    print(catalog.line("verify.header", path=str(result.manifest.get("tool_version", "?"))))
    for name, ok in result.checks.items():
        print(f"  [{verify_mod.check_mark(name, ok)}] {catalog.line('check.' + name)}")
    print(f"\n{catalog.line('verify.time_anchor')}: {result.time_anchor} ({result.time_evidence})")
    token = (result.timestamp or {}).get("token") or {}
    if token:
        print(f"  gen_time  {token.get('gen_time')}")
        print(f"  tsa       {token.get('tsa_name')}")
        print(f"  token     {(result.timestamp or {}).get('signature_state')}")
        print(f"  tsa_chain {(result.timestamp or {}).get('tsa_chain')}")
    print(f"{catalog.line('verify.key_state')}: {result.key_state} ({result.key_status_source})")
    print(f"{catalog.line('verify.trust')}: {result.trust_state}")
    for warning in result.warnings:
        print(f"  ! {warning}")
    for problem in result.problems:
        print(f"  x {problem}")
    # Said once, and only when one was printed. A marker the reader cannot
    # interpret is a smaller version of the problem it was introduced to fix:
    # they still cannot tell a documented limit from something that went wrong.
    if any(
        not ok and name in verify_mod.ADVISORY_CHECKS for name, ok in result.checks.items()
    ):
        print(f"\n{catalog.line('verify.advisory_legend', mark=verify_mod.MARK_ADVISORY)}")
    print(f"\n{catalog.line('verify.result')}: {'OK' if result.ok else 'FAILED'}")


def run_verify(args: argparse.Namespace, catalog: Catalog) -> int:
    """The package is always verified in full, with whatever anchors were given.

    `--extends` adds the consistency proof on top; it used to *replace* the
    verification, so `--require-trust` was accepted, ignored and never
    mentioned again, and a package signed by a rejected key came back OK as
    long as it extended the older one. Both results are combined now, and
    either one failing fails the command.
    """
    result = verify_mod.verify_package(
        args.package,
        trusted_keyring=args.trusted_keyring,
        trusted_pubkey_b64=args.pubkey,
        require_trust=args.require_trust,
        tsa_trust_store=args.tsa_trust_store,
    )

    if args.extends is not None:
        extends_ok, problems = verify_mod.verify_extends(args.extends, args.package)
        ok = extends_ok and result.ok
        if args.json:
            payload = result.to_dict()
            payload["extends"] = {"older": str(args.extends), "ok": extends_ok, "problems": problems}
            payload["ok"] = ok
            print(json.dumps(payload, indent=2))
        else:
            _print_verify(result, catalog)
            print()
            print(catalog.line("verify.extends", older=str(args.extends)))
            for problem in problems:
                print(f"  x {problem}")
            print(f"\n{catalog.line('verify.result')}: {'OK' if ok else 'FAILED'}")
        return EXIT_OK if ok else EXIT_FAIL

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_verify(result, catalog)
    return EXIT_OK if result.ok else EXIT_FAIL


# ---------------------------------------------------------------------------
# check: the configuration surface
# ---------------------------------------------------------------------------


def _agent_versions(spoken: list[str]) -> tuple[dict[str, str], str | None]:
    """`claude-code=2.1.257` -> {"claude-code": "2.1.257"}, or a usage message.

    Design note D-277. The version is never obtained by running
    `claude --version`, and not because running it would be slow. Asking the
    audited tool what it is is trusting the audited tool, which is the same
    objection `scan` files against an L0 transcript, and this tool does not
    execute an agent binary for any reason (CLAUDE.md, "lo prohibido").

    Rejected: reading it out of `~/.claude.json`. That file is written and
    maintained by Claude Code about itself, so it is the same class of evidence
    with a filesystem in between - and it exists only on the machine, so the
    pull-request case, which is the case this command is for, would still have
    nothing. The flag is the honest channel: somebody states the version, and
    what depends on it is resolved against what they stated.
    """
    found: dict[str, str] = {}
    for item in spoken:
        vendor, sep, version = item.partition("=")
        if not sep or not vendor.strip() or not version.strip():
            return {}, f"--agent-version wants VENDOR=X.Y.Z, not {item!r}"
        found[vendor.strip()] = version.strip()
    return found, None


def _print_check(document: dict[str, Any], catalog: Catalog) -> None:
    """Capabilities, then what could not be resolved, then what was not read.

    That order, always. The three are never merged and never totalled: a reader
    who could add them up would be computing the thing CLAUDE.md's first
    negative forbids, and a reader who could not see the second list would be
    reading a clean report about a tree nobody finished looking at.

    Findings are selected by vendor rather than reprinted under each one. There
    is one vendor today and the two readings are identical; from phase S2 there
    are six, and a loop that printed the whole list under every heading would
    show each finding six times. Caught by the single adversarial pass of this
    phase, before the second vendor existed to make it visible.
    """
    spoke = False
    for surface in document["surfaces"]:
        mine = [
            finding
            for finding in document["findings"]
            if finding["evidence"].get("vendor", surface["vendor"]) == surface["vendor"]
        ]
        # A vendor nobody configured here prints nothing. Seven headings on a
        # repository with one settings file is noise, and "nothing fired" said
        # seven times reads as seven clean results rather than six absences.
        if not mine and not surface["capabilities"]:
            continue
        spoke = True
        version = surface["agent_version"] or catalog.line("surface.version_unknown")
        print(catalog.line("surface.vendor", vendor=surface["vendor"], version=version))
        by_rule: dict[str, list[dict[str, Any]]] = {}
        for finding in mine:
            by_rule.setdefault(finding["rule_id"], []).append(finding)
        stuck = sum(
            1
            for item in surface["capabilities"]
            if item["resolution"] == Resolution.INDETERMINATE.value
        )
        if not mine and stuck:
            # NOT "nothing fired". A vendor with an unresolved capability has
            # not come back clean, and the one sentence a reader takes as a
            # clean result must not appear beside it.
            print("  " + catalog.line("surface.vendor_unresolved", count=stuck))
        elif not mine:
            print("  " + catalog.line("surface.nothing_fired"))
        for rule_id in sorted(by_rule):
            for finding in by_rule[rule_id]:
                evidence = finding["evidence"]
                print(
                    "  {mark} {rule}  {capability}  {source}  [{scope}/{resolution}]".format(
                        mark="!",
                        rule=rule_id,
                        capability=evidence["capability"],
                        source=finding["location"],
                        scope=evidence["scope"],
                        resolution=evidence["resolution"],
                    )
                )
                print("      " + catalog.rule(rule_id))
                print(
                    "      {}  {} {} / {}".format(
                        catalog.line("surface.attributed"),
                        finding["author"],
                        finding["pack"],
                        finding["severity"],
                    )
                )
                print("      " + catalog.line("surface.merge", rule=evidence["merge_rule"]))
                if evidence.get("condition"):
                    print("      " + catalog.line("surface.condition", text=evidence["condition"]))
                print("      " + catalog.line("surface.remediation", text=evidence["remediation"]))

    if not spoke:
        # No vendor is configured here at all. The line still has to be said
        # once: published limit 9 is that a clean report is not safety, and a
        # report that simply prints nothing is the reassurance that limit
        # exists to refuse. Once, not once per vendor - six absences printed as
        # six clean results is the same defect from the other side.
        print(catalog.line("surface.nothing_fired"))

    print()
    print(catalog.line("surface.unresolved", count=len(document["unresolved"])))
    for gap in document["unresolved"]:
        print("  ? {}\n      {}".format(gap["subject"], gap["cause"]))

    print()
    print(catalog.line("surface.not_read", count=len(document["not_read"])))
    for entry in document["not_read"]:
        print("  - {}\n      {}".format(entry["path"], entry["reason"]))

    print()
    print(catalog.line("surface.declares"))


def check_document(
    repo: Path,
    *,
    machine: bool = False,
    with_content: bool = False,
    versions: dict[str, str] | None = None,
    home: Path | None = None,
) -> dict[str, Any]:
    """The `surface/v1` document for one root, across every vendor.

    Extracted from `run_check` in phase S2 so that `mcp.py` can answer with the
    same bytes the command prints. A second implementation behind the MCP tool
    would be a second place the answer is computed, and the one that goes stale
    without anybody noticing - which is the argument this repository makes about
    every generated page.

    The union, never a merge (D-288). Each vendor is read and resolved on its
    own and contributes its own `Surface`; nothing here reconciles two vendors'
    capabilities, because two vendors configuring the same server are two things
    that can be removed independently.
    """
    from .surface import document as build_document
    from .surface.resolve import MERGE_TABLE, vendor_registry
    from .surface.rules import evaluate, load

    versions = versions or {}
    catalogue = load()
    surfaces = []
    findings: list[Any] = []
    gaps: list[Any] = []
    for vendor, reader, resolver in vendor_registry():
        reading = reader.read(repo, machine=machine, home=home)
        surface = resolver(
            reading,
            agent_version=versions.get(vendor),
            with_content=with_content,
        )
        surfaces.append(surface)
        found, unresolved = evaluate(surface, catalogue)
        findings.extend(found)
        gaps.extend(surface.unresolved)
        gaps.extend(unresolved)

    return build_document(
        root=str(repo),
        surfaces=tuple(surfaces),
        findings=tuple(findings),
        gaps=tuple(gaps),
        machine=machine,
        merge_rules=MERGE_TABLE,
    )


def run_check(args: argparse.Namespace, catalog: Catalog) -> int:
    versions, problem = _agent_versions(args.agent_version)
    if problem:
        print(problem, file=sys.stderr)
        return EXIT_USAGE
    repo = args.repo
    if not repo.is_dir():
        print(f"{repo} is not a directory", file=sys.stderr)
        return EXIT_USAGE

    payload = check_document(
        repo,
        machine=args.machine,
        with_content=args.with_content,
        versions=versions,
    )

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        _print_check(payload, catalog)

    _write_html(args.html, payload, catalog)

    if payload["findings"]:
        return EXIT_FAIL
    if payload["unresolved"]:
        return EXIT_INDETERMINATE
    return EXIT_OK


def _write_html(where: Path | None, payload: dict[str, Any], catalog: Catalog) -> None:
    """One file, written where the operator asked, and nowhere else.

    Not a default output path: `check` writes nothing in the user's tree unless
    they name the file, which is the fourth negative applied to the one part of
    this tool that produces an artifact a reader keeps.
    """
    if where is None:
        return
    from .report.html import render

    where.parent.mkdir(parents=True, exist_ok=True)
    where.write_text(render(payload, catalog), encoding="utf-8", newline="\n")
    print(catalog.line("report.wrote", path=str(where)))


# ---------------------------------------------------------------------------
# diff: what changed between two moments
# ---------------------------------------------------------------------------


def _documents_for_dirs(
    before: Path, after: Path, **options: Any
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    return (
        check_document(before, **options),
        check_document(after, **options),
        {"label": str(before), "kind": "directory"},
        {"label": str(after), "kind": "directory"},
    )


def _print_diff(document: dict[str, Any], catalog: Catalog) -> None:
    """Five lists, then what could not be resolved, then what was not read.

    Never totalled and never merged, for the reason `_print_check` gives about
    its three: a reader who could add them up would be computing the thing the
    first negative forbids, and one who could not see the sixth would be reading
    a clean answer about a comparison nobody finished making.
    """
    from .surface.diff import Change

    print(catalog.line(
        "diff.header",
        before=document["before"]["label"],
        after=document["after"]["label"],
    ))
    marks = {
        Change.ADDED.value: "+",
        Change.REMOVED.value: "-",
        Change.WIDENED.value: ">",
        Change.NARROWED.value: "<",
        Change.CHANGED.value: "~",
    }
    for kind, mark in marks.items():
        entries = document[kind]
        if not entries:
            continue
        print()
        print(catalog.line(f"diff.{kind}", count=len(entries)))
        for entry in entries:
            print("  {mark} {vendor}  {capability}  {source}  [{scope}]".format(
                mark=mark, **{key: entry[key] for key in
                              ("vendor", "capability", "source", "scope")}))
            for side in ("before", "after"):
                state = entry[side]
                if state is None:
                    continue
                print("      {}  {}  {}".format(
                    catalog.line(f"report.{side}"), state["resolution"], state["digest"][:16]))
            for finding in (entry["after"] or {}).get("findings", []):
                print("      ! {}  {}".format(finding["rule_id"], catalog.rule(finding["rule_id"])))
                print("        {}  {} {} / {}".format(
                    catalog.line("surface.attributed"), finding["author"],
                    finding["pack"], finding["severity"]))
                print("        " + catalog.line(
                    "surface.remediation", text=finding["evidence"]["remediation"]))

    print()
    print(catalog.line("diff.indeterminate", count=len(document["indeterminate"])))
    for gap in document["indeterminate"]:
        print("  ? {}\n      {}".format(gap["subject"], gap["cause"]))

    print()
    print(catalog.line("diff.unchanged", count=document["unchanged"]))
    print(catalog.line("surface.not_read", count=len(document["not_read"])))
    print()
    print(catalog.line("surface.declares"))


def run_diff(args: argparse.Namespace, catalog: Catalog) -> int:
    """Two surfaces, compared. Nothing of the operator's is written or checked out."""
    import tempfile

    from .surface.diff import GitError, fired_on_new_capability, materialise, surface_diff

    versions, problem = _agent_versions(args.agent_version)
    if problem:
        print(problem, file=sys.stderr)
        return EXIT_USAGE
    options: dict[str, Any] = {"with_content": args.with_content, "versions": versions}

    named_dirs = args.from_dir is not None or args.to_dir is not None
    if named_dirs and args.refs:
        print(catalog.line("diff.both_forms"), file=sys.stderr)
        return EXIT_USAGE
    if named_dirs:
        if args.from_dir is None or args.to_dir is None:
            print(catalog.line("diff.half_a_form"), file=sys.stderr)
            return EXIT_USAGE
        for where in (args.from_dir, args.to_dir):
            if not where.is_dir():
                print(f"{where} is not a directory", file=sys.stderr)
                return EXIT_USAGE
        before, after, before_side, after_side = _documents_for_dirs(
            args.from_dir, args.to_dir, **options
        )
        payload = surface_diff(before, after, before_label=before_side, after_label=after_side)
    else:
        if len(args.refs) != 2:
            print(catalog.line("diff.two_refs"), file=sys.stderr)
            return EXIT_USAGE
        if not (args.repo / ".git").exists():
            print(f"{args.repo} is not a git repository", file=sys.stderr)
            return EXIT_USAGE
        with tempfile.TemporaryDirectory(prefix="actaira-diff-") as scratch:
            try:
                sides = [
                    materialise(args.repo, ref, Path(scratch) / name)
                    for ref, name in zip(args.refs, ("before", "after"), strict=True)
                ]
            except GitError as exc:
                print(str(exc), file=sys.stderr)
                return EXIT_USAGE
            payload = surface_diff(
                check_document(sides[0].root, **options),
                check_document(sides[1].root, **options),
                before_label=sides[0].to_dict(),
                after_label=sides[1].to_dict(),
            )

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        _print_diff(payload, catalog)

    _write_html(args.html, payload, catalog)
    if args.sarif is not None:
        from .report.sarif import from_diff

        args.sarif.parent.mkdir(parents=True, exist_ok=True)
        args.sarif.write_text(
            json.dumps(from_diff(payload, catalog, tool_version=__version__),
                       indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8", newline="\n",
        )
        print(catalog.line("diff.wrote_sarif", path=str(args.sarif)))

    # A rule that fired on something that ARRIVED. Not on everything in the
    # repository: this command answers what changed, and a finding that was
    # already there and is still there is `check`'s to report.
    if fired_on_new_capability(payload):
        return EXIT_FAIL
    if payload["indeterminate"]:
        return EXIT_INDETERMINATE
    return EXIT_OK


# ---------------------------------------------------------------------------
# seal: a signed baseline, with no content in it
# ---------------------------------------------------------------------------


def run_seal(args: argparse.Namespace, catalog: Catalog) -> int:
    from .attest import keyring
    from .attest.seal import write_seal

    versions, problem = _agent_versions(args.agent_version)
    if problem:
        print(problem, file=sys.stderr)
        return EXIT_USAGE
    if not args.repo.is_dir():
        print(f"{args.repo} is not a directory", file=sys.stderr)
        return EXIT_USAGE

    surface = check_document(
        args.repo, machine=args.machine, with_content=False, versions=versions
    )
    local = keyring.load_local(args.key)
    if local.created_key:
        # Said, not silent. `load_local` mints a key where there is none, which
        # is convenient and is also the operator acquiring a signing identity
        # they did not ask for: a seal signed by a key nobody knows about is a
        # seal nobody can bind to anything. `keygen` is the command that means
        # to do this; here it is reported.
        print(catalog.line("key.created", path=str(args.key)))
    package_path, document = write_seal(surface, args.out, local.keypair)

    if args.json:
        print(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(catalog.line("seal.written", path=str(package_path)))
        print(catalog.line("seal.surface", digest=document["surface_sha256"]))
        print(catalog.line("seal.key", key_id=local.keypair.key_id))
        print(catalog.line(
            "seal.counts",
            capabilities=sum(len(item["capabilities"]) for item in document["surfaces"]),
            findings=len(document["findings"]),
            unresolved=document["unresolved"],
        ))
        print()
        print(catalog.line("seal.no_content"))
        print(catalog.line("seal.salt", path=str(args.out / "index.json")))
    return EXIT_OK


# ---------------------------------------------------------------------------
# scan (L0) and watch (L1)
# ---------------------------------------------------------------------------


SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


def _file_stem(session_id: str, taken: dict[str, int]) -> str:
    """A filename from a session id, which is a string out of a transcript.

    Design note D-262. This was `f"{trace.session_id}.json"` and the id is
    whatever the file being read put in its `sessionId`. Two of those were
    true at once: a session declaring `../escaped` wrote OUTSIDE `--out`, and
    two sessions declaring the same id wrote the same file, so one of them
    silently was not there while the command said it had written both.

    Rejected: refusing to write a session whose id will not do as a filename.
    The id is not the session's fault and dropping it is the same silence in
    a different coat. It is sanitised, and a collision is NUMBERED rather than
    overwritten - what is lost is a name, never a trace.
    """
    cleaned = SAFE_NAME.sub("_", session_id).strip(".") or "unnamed-session"
    cleaned = cleaned[:120]
    taken[cleaned] = taken.get(cleaned, 0) + 1
    return cleaned if taken[cleaned] == 1 else f"{cleaned}-{taken[cleaned]}"


def _write_traces(
    traces, out: Path, salt: str | None = None, references: dict[str, str] | None = None
) -> list[Path]:
    """One canonical document per session, plus its digest beside it.

    Beside rather than inside: a digest cannot be a field of the thing it is
    the digest of. Phase 3 is what signs the pair.

    `index.json` says which file holds which session, because after sanitising
    the filename is no longer the id and a reader needs the mapping stated
    rather than guessed at.
    """
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    index: dict[str, str] = {}
    taken: dict[str, int] = {}
    resolve = references or {}
    for trace in traces:
        document = trace.to_dict()
        # D-268: `trace.session_id` is the REFERENCE now. The file is still
        # named after the id the source declared, because the operator holds
        # the map and a directory of sixteen-hex filenames is a directory
        # nobody can find anything in. The reference is what travels; the name
        # of a file on their own disk does not travel at all.
        literal = resolve.get(trace.session_id, trace.session_id)
        stem = _file_stem(literal, taken)
        target = out / f"{stem}.json"
        target.write_text(
            json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8"
        )
        (out / f"{stem}.sha256").write_text(trace_digest(document) + "\n", encoding="utf-8")
        index[target.name] = literal
        written.append(target)
    # The salt goes in beside the map for the same reason the alias map goes in
    # `interposition.json`: it is what lets the operator resolve a reference in
    # their own trace, it is what makes that reference unguessable to everybody
    # else (D-263), and it must therefore never be inside a trace document.
    document: dict[str, Any] = {"sessions": index}
    if salt is not None:
        document["redaction_salt"] = salt
    if references:
        # The map from every reference this scan published back to the value it
        # stands for. Beside the traces, on the operator's own disk, and never
        # inside one of them - D-268, and the same bargain `interposition.json`
        # strikes on the `watch` side.
        document["references"] = dict(sorted(references.items()))
    (out / INDEX_FILE).write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    return written


INDEX_FILE = "index.json"


def _scan_salt(out: Path | None) -> str | None:
    """The per-scan salt for `redact.file_ref`, kept beside what it references.

    Design note D-263 in one place on the L0 side. The salt makes a reference
    unguessable, and that costs reproducibility unless it is KEPT: so it is
    written into the output directory the first time and read back after, and
    re-scanning the same sessions into the same directory therefore produces
    the same bytes. It is the same bargain `interposition.json` strikes on the
    `watch` side, in the only other place this tool has to make one.

    It lives in `index.json`, which is already the operator-side key to this
    output - the map from filename back to session id - rather than in a file
    of its own, because a second sidecar is a second thing to copy, to ignore
    and to lose.

    A scan with no `--out` has nowhere to keep it. It gets none, and a gap
    about a file then names no reference at all - rejected: minting one
    anyway, which would publish a reference that nobody, including the
    operator, could ever resolve.
    """
    from .trace.redact import new_salt

    if out is None:
        return None
    path = out / INDEX_FILE
    if path.is_file():
        try:
            kept = json.loads(path.read_text(encoding="utf-8")).get("redaction_salt")
        except (OSError, ValueError):
            kept = None
        if isinstance(kept, str) and kept:
            return kept
    return new_salt()


def run_scan(args: argparse.Namespace, catalog: Catalog) -> int:
    """Read what the agent already wrote, and refuse to call it evidence.

    The refusal is printed, not filed. A limit that lives only in a document
    is a limit the person reading the output never meets, and this is the one
    that decides whether the whole command is honest: an L0 trace was produced
    by the audited party.
    """
    from .trace.claude_code import demo_trace

    salt: str | None = None
    if args.demo:
        traces = [demo_trace(with_content=args.with_content)]
        print(catalog.line("scan.demo"))
    else:
        try:
            reader_class = reader_for(args.source)
        except (KeyError, NotImplementedError) as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_USAGE
        salt = _scan_salt(args.out)
        reader = reader_class(home=args.home, with_content=args.with_content, salt=salt)
        traces = reader.read_all()

    documents = [trace.to_dict() for trace in traces]
    moments = [
        moment
        for document in documents
        for moment in (document.get("started_at"), document.get("ended_at"))
        if moment
    ]
    if args.json:
        print(json.dumps(documents, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        if not args.demo:
            print(catalog.line("scan.header", source=args.source))
        print(
            catalog.line(
                "scan.found",
                sessions=len(documents),
                events=sum(len(document["events"]) for document in documents),
                first=min(moments) if moments else "-",
                last=max(moments) if moments else "-",
            )
        )
        incomplete = [document for document in documents if not document["complete"]]
        if incomplete:
            print(catalog.line("scan.incomplete", count=len(incomplete)))
        print()
        print(catalog.line("scan.not_evidence"))

    if args.out is not None:
        written = _write_traces(
            traces,
            args.out,
            salt=None if args.demo else salt,
            references=None if args.demo else reader.refs.map,
        )
        print(catalog.line("scan.written", count=len(written), path=str(args.out)))
    return EXIT_OK


def run_watch(args: argparse.Namespace, catalog: Catalog) -> int:
    """Run the agent with a proxy in front of each of its MCP servers."""
    import uuid

    from .proxy.session import WatchSession

    command = [item for item in args.child if item != "--"]
    if not command:
        print(catalog.line("watch.no_command"), file=sys.stderr)
        return EXIT_USAGE

    session = WatchSession(
        record_dir=args.out / "records",
        session_id=str(uuid.uuid4()),
        with_content=args.with_content,
    )
    returncode = session.run(command, args.mcp_config)
    trace = session.assemble(child_returncode=returncode)
    document = trace.to_dict()
    # The id as the operator typed it into their own terminal, not the
    # reference the document carries. The terminal is not a published document.
    spoken = session.session_id

    if args.json:
        print(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(catalog.line("watch.header", session=spoken))
        print(catalog.line("watch.observed", events=len(document["events"])))
        for gap in document["gaps"]:
            print(f"  ! [{gap['reason']}] {gap['detail']}")
        print(catalog.line("watch.complete" if document["complete"] else "watch.incomplete"))
    _write_traces([trace], args.out, references={trace.session_id: spoken})
    print(catalog.line("watch.written", path=str(args.out)))
    # The agent's own exit code is passed through: `watch` records, it does not
    # judge, and a wrapper that swallowed a failed build would be lying about
    # the run it was there to observe.
    return returncode


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def _main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    catalog = Catalog(args.lang)
    if args.command == "check":
        return run_check(args, catalog)
    if args.command == "diff":
        return run_diff(args, catalog)
    if args.command == "seal":
        return run_seal(args, catalog)
    if args.command == "keygen":
        return run_keygen(args, catalog)
    if args.command == "scan":
        return run_scan(args, catalog)
    if args.command == "watch":
        return run_watch(args, catalog)
    return run_verify(args, catalog)


def _settle_output_encoding() -> None:
    """Decide the encoding of what this tool prints, rather than inheriting it.

    Design note D-241. Python picks the encoding of `sys.stdout` from the
    locale, so on a host whose locale is not UTF-8 - every default Windows
    install - `actaira --lang es verify ... > out.txt` wrote cp1252 bytes and
    the same command on Linux wrote UTF-8. Two machines, one command, two
    files, which is the property this repository defends everywhere else.

    Redirected or piped, the consumer is a program and UTF-8 is what a program
    can rely on, so it is reconfigured unconditionally. On a terminal the
    console has a code page of its own and forcing UTF-8 into it renders
    mojibake, so only `errors` changes, to `replace`: a character the console
    cannot draw becomes a question mark rather than a `UnicodeEncodeError`
    traceback out of a tool that had finished its work.

    `reconfigure` is missing on a replaced stream - a test capturing stdout, or
    a caller who set one - so failure here silently leaves the caller's
    encoding, which is the right precedence.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            if stream.isatty():
                reconfigure(errors="replace")
            else:
                reconfigure(encoding="utf-8", newline="\n")
        except (ValueError, OSError):  # a stream that cannot be reconfigured
            continue


def main(argv: list[str] | None = None) -> int:
    """The entry point, wrapped so a closed pipe is not a traceback.

    Design note D-235. `actaira verify --json | head -3` printed a
    `BrokenPipeError` traceback and exited 0: `head` closes the pipe, the next
    `print` raises, and the interpreter's final flush raises again on the way
    out. The traceback goes to stderr, which is where a CI job looks when
    something has gone wrong, and it arrived with an exit code saying nothing
    had. Swallow it, point stdout at the null device so the final flush has
    nothing left to fail on, and exit 141, which is what a shell reports for a
    process killed by SIGPIPE.
    """
    _settle_output_encoding()
    try:
        return _main(argv)
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return EXIT_SIGPIPE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
