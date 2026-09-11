#!/usr/bin/env python3
"""Three commands, run against artifacts written from literal bytes, printed as JSON.

Design note D-234. The READMEs show console blocks, and a console block is a
screenshot in text: it looks like output, it ages exactly as badly as a typed
figure, and nothing on either side compares it with anything. What this file
gives the release gate is the other half of that - output that came out of the
product on this tree, reproducibly, so the gate can ask the question a reader
cannot: does this tool still print the same bytes twice?

Everything that could make two runs differ is pinned here. The artifacts are
written from literal bytes, so their digests are fixed. The policy decision is
taken `--on` a fixed date. The temporary directory is scrubbed out of the
paths. What is deliberately *not* pinned is the interpreter's hash seed: the
gate runs this twice with different `PYTHONHASHSEED` values and requires the
two outputs to be identical, which is what catches a set or a dict whose
iteration order reached the terminal.

    python3 scripts/cli_transcripts.py            # JSON on stdout
"""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def transcripts() -> list[dict[str, str]]:
    from actaira import cli

    root = Path(tempfile.mkdtemp(prefix="actaira-transcript-"))
    models = root / "models"
    models.mkdir()

    # A clean safetensors file and a protocol 2 pickle that reduces through
    # `posix.system`, both written from literal bytes: the same two artifacts
    # every run, so the digests in the transcript are stable. These are the
    # two files `docs/CONCEPTS.md` builds in four lines, which is why the
    # digests here are the digests a reader sees.
    header = b'{"w":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]}}'
    (models / "clean.safetensors").write_bytes(
        len(header).to_bytes(8, "little") + header + b"\x00" * 16
    )
    (models / "trojan.pkl").write_bytes(
        b"\x80\x02cposix\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03."
    )

    policy = root / "policy.yaml"
    policy.write_text(
        "policy: production-model\n"
        "version: 1\n"
        "rules:\n"
        "  - id: no-high-severity-findings\n"
        "    effect: deny\n"
        "    when:\n"
        "      finding_severity_at_least: high\n"
        "  - id: signed-by-a-key-this-environment-trusts\n"
        "    effect: require\n"
        "    when:\n"
        "      signature_verified: true\n",
        encoding="utf-8", newline="\n",
    )

    runs = [
        ("actaira scan models/", ["scan", str(models)]),
        (
            "actaira policy check models/ --policy-file policies/production-model.yaml",
            ["policy", "check", str(models), "--policy-file", str(policy), "--on", "2026-01-01"],
        ),
        (
            "actaira agent paths examples/agent-ticket-triage.yaml",
            ["agent", "paths", str(ROOT / "examples" / "agent-ticket-triage.yaml")],
        ),
    ]

    captured: list[dict[str, str]] = []
    for shown, argv in runs:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(argv)
        body = buffer.getvalue()
        # Windows and POSIX spell the same path differently, and the point of
        # this run is what the tool decided, not which separator it printed.
        for base in (models, root, ROOT):
            body = body.replace(str(base) + "\\", str(base) + "/")
        body = body.replace(str(models) + "/", "models/").replace(str(models), "models/")
        body = body.replace(str(ROOT) + "/", "").replace(str(root) + "/", "")
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
