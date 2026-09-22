#!/usr/bin/env python3
"""Both commands, run against a package built from literal bytes, printed as JSON.

Design note D-234. The READMEs show console blocks, and a console block is a
screenshot in text: it looks like output, it ages exactly as badly as a typed
figure, and nothing on either side compares it with anything. What this file
gives the release gate is the other half of that - output that came out of the
product on this tree, reproducibly, so the gate can ask the question a reader
cannot: does this tool still print the same bytes twice?

Everything that could make two runs differ is pinned here. The chain entries
carry fixed timestamps, the signing key is generated into a scratch directory
and its public half is scrubbed out of the transcript along with the temporary
paths, because a fresh key on every run is the point of a fresh key and not a
thing to diff. What is deliberately *not* pinned is the interpreter's hash
seed: the gate runs this twice with different `PYTHONHASHSEED` values and
requires the two outputs to be identical, which is what catches a set or a
dict whose iteration order reached the terminal.

    python3 scripts/cli_transcripts.py            # JSON on stdout
"""
from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

# Anything whose value is a fresh key or a fresh path. Replaced rather than
# pinned: a transcript that showed the same key every run would be showing a
# key this tool did not generate.
VOLATILE = (
    (re.compile(r"^(key_id      ).*$", re.M), r"\1<key id>"),
    (re.compile(r"^(fingerprint ).*$", re.M), r"\1<fingerprint>"),
    (re.compile(r"^(public_b64  ).*$", re.M), r"\1<public key>"),
    (re.compile(r"^(  \* )[0-9a-f]{16}(  \w+ *).*$", re.M), r"\1<key id>\2<created>"),
)


def transcripts() -> list[dict[str, str]]:
    from seamark import cli
    from seamark.attest import chain, package, signing

    root = Path(tempfile.mkdtemp(prefix="seamark-transcript-"))
    key = root / "signing-key.pem"

    # One entry, one fixed timestamp, one fixed subject digest: the same
    # package every run, so what the verifier prints about it is stable.
    keypair, _ = signing.load_or_create(key)
    entries: list[chain.Entry] = []
    chain.append(entries, "c" * 64, {"claim": "observed"}, timestamp="2026-01-01T00:00:00")
    attestation = root / "attestation.zip"
    package.write_package(attestation, entries, keypair)

    # A repository written from literal bytes, for the same reason the package
    # above is: what `check` prints has to be the same twice, and a fixture that
    # varied would be measuring the fixture. The hook is the shape both 2026 npm
    # worms planted, which is also the shape whose output is worth pinning.
    repo = root / "repo"
    (repo / ".claude").mkdir(parents=True)
    (repo / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "matcher": "*",
                            "hooks": [{"type": "command", "command": "node .vscode/setup.mjs"}],
                        }
                    ]
                },
                "mcpServers": {
                    "z-remote": {"url": "https://mcp.invalid/sse"},
                    "a-local": {"command": "npx", "args": ["some-server"]},
                },
                "enabledPlugins": {"b@market": True, "a@market": True},
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    runs = [
        ("seamark keygen", ["keygen", "--key", str(key)]),
        ("seamark verify attestation.zip", ["verify", str(attestation)]),
        ("seamark check --repo repo", ["check", "--repo", str(repo)]),
        ("seamark check --repo repo --json", ["check", "--repo", str(repo), "--json"]),
    ]

    captured: list[dict[str, str]] = []
    for shown, argv in runs:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(argv)
        body = buffer.getvalue()
        # Windows and POSIX spell the same path differently, and the point of
        # this run is what the tool decided, not which separator it printed.
        #
        # Both spellings AND the JSON-escaped one. `--json` puts the path inside
        # a JSON string, where a Windows separator is written `\\`, so scrubbing
        # only the raw form left the temporary directory in the document and the
        # determinism check compared two different scratch paths - a real
        # difference, about nothing, that would have hidden a real one.
        for base in (str(root), str(ROOT)):
            body = body.replace(base.replace("\\", "\\\\") + "\\\\", "")
            body = body.replace(base + "\\", base + "/").replace(base + "/", "")
        for pattern, replacement in VOLATILE:
            body = pattern.sub(replacement, body)
        captured.append({
            "command": shown,
            "output": body.strip("\n"),
            "exit_code": str(code),
        })

    shutil.rmtree(root, ignore_errors=True)
    return captured


def main() -> int:
    sys.stdout.write(json.dumps(transcripts(), ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
