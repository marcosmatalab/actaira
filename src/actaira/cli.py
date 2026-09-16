"""The command line: four of the eight commands CLAUDE.md caps the set at.

`verify` reads an attestation package and says whether it holds together;
`keygen` creates, rotates and revokes the key that signs one. `scan` reads the
transcripts an agent already wrote and turns them into canonical traces, and
`watch` records a run from outside the agent. `contract`, `verdict`, `receipt`
and `fix` arrive with the phases that make each of them mean something.

Rejected: keeping the previous 2 458-line parser with the dead subcommands
hidden or stubbed. A command that parses and then says "not implemented" is a
promise in the help text, and the help text is the contract COMPATIBILITY.md
publishes.

Three of the four never reach the network. `scan` is the strictest: it reads
files full of somebody's conversation, so it opens no socket at all and a test
enforces that rather than trusting it. `watch` is the exception and says so -
it binds a loopback port when a server speaks HTTP, which is the whole
mechanism by which it interposes.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from . import __version__
from .attest import keyring
from .attest import verify as verify_mod
from .i18n.catalog import Catalog
from .trace import reader_for
from .trace.model import trace_digest

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
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
            "Verify an Actaira attestation without trusting the operator, and manage "
            "the key that signs one. Both commands are offline. Nothing is scored."
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


def _write_traces(traces, out: Path) -> list[Path]:
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
    for trace in traces:
        document = trace.to_dict()
        stem = _file_stem(trace.session_id, taken)
        target = out / f"{stem}.json"
        target.write_text(
            json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8"
        )
        (out / f"{stem}.sha256").write_text(trace_digest(document) + "\n", encoding="utf-8")
        index[target.name] = trace.session_id
        written.append(target)
    (out / "index.json").write_text(
        json.dumps({"sessions": index}, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    return written


def run_scan(args: argparse.Namespace, catalog: Catalog) -> int:
    """Read what the agent already wrote, and refuse to call it evidence.

    The refusal is printed, not filed. A limit that lives only in a document
    is a limit the person reading the output never meets, and this is the one
    that decides whether the whole command is honest: an L0 trace was produced
    by the audited party.
    """
    from .trace.claude_code import demo_trace

    if args.demo:
        traces = [demo_trace(with_content=args.with_content)]
        print(catalog.line("scan.demo"))
    else:
        try:
            reader_class = reader_for(args.source)
        except (KeyError, NotImplementedError) as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_USAGE
        reader = reader_class(home=args.home, with_content=args.with_content)
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
        written = _write_traces(traces, args.out)
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

    if args.json:
        print(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(catalog.line("watch.header", session=trace.session_id))
        print(catalog.line("watch.observed", events=len(document["events"])))
        for gap in document["gaps"]:
            print(f"  ! [{gap['reason']}] {gap['detail']}")
        print(catalog.line("watch.complete" if document["complete"] else "watch.incomplete"))
    _write_traces([trace], args.out)
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
