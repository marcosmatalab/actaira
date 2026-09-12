"""Actaira command line.

Exit codes are part of the contract, because this tool is meant to run in
CI where the exit code is the whole interface:

  0  every artifact passed
  1  at least one artifact failed
  2  usage or environment error
  3  no artifact failed but at least one was inconclusive

3 is separate from 0 on purpose. "I could not read this file" must not be
reported to a pipeline as success; `--allow-inconclusive` collapses it to 0
for teams that decide otherwise, and that decision is then visible in their
CI config instead of hidden in the tool.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import UTC, date, datetime
from datetime import date as _date
from pathlib import Path
from typing import Any

from . import __version__
from .attest import chain, keyring, package, signing
from .attest import timestamp as timestamp_mod
from .attest import verify as verify_mod
from .bom.cyclonedx import build_bom
from .coverage import CoverageState
from .formats import detect
from .governance import Role
from .governance import assess as gov_assess_fn
from .governance import clock as gov_clock_fn
from .governance import localized as gov_localized
from .governance import render as gov_render
from .governance.catalog import by_id as gov_by_id
from .governance.pack import write_evidence_package
from .i18n.catalog import Catalog
from .inspect import inspect_artifact
from .model import ArtifactReport, Severity, Verdict, artifact_name
from .report.junit import build_junit
from .report.sarif import build_sarif

SCAN_FORMATS = ("text", "json", "sarif", "junit")

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_INCONCLUSIVE = 3
# Not part of the published contract in COMPATIBILITY.md, and deliberately so:
# it is the shell's own convention for a process killed by SIGPIPE, reported
# when the reader on the other end of a pipe stopped reading. The argument is
# in `main`, where the design note that carries it lives.
EXIT_SIGPIPE = 141

def _parse_date(value: str) -> _date:
    """Dates are arguments, never the system clock, so output is reproducible."""
    return _date.fromisoformat(value)


def default_key_path() -> Path:
    """Where a key lands when nobody passed `--key`, resolved when asked.

    Design note D-240. This was a module-level `Path.home() / ".actaira" /
    "signing-key.pem"`, evaluated at import. `Path.home()` raises where the
    environment names no home directory - a container run with a scrubbed
    environment, a service unit, a CI step that clears it - and a module-level
    call meant the whole CLI died at import with a bare `RuntimeError`
    traceback. Not the signing commands: every command, including `schema`,
    `--help` and `--version`, none of which touch a key.

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
# Extensions that make a file worth looking at FIRST. They no longer decide
# whether it is looked at at all.
#
# Design note D-106, and the most consequential change in this release. This
# set used to be the security boundary: `collect_paths` walked a directory and
# kept only files whose suffix was in it. So a pickle called `notes.txt`, or
# `weights`, or `model.safetensors.bak`, was not scanned, not reported, and
# not counted - it was invisible. An attacker chooses the file name, and the
# tool was asking the attacker whether to inspect the file.
#
# The whole point of `formats/detect.py` is that an extension is a claim and
# the bytes are the fact, and D-06 has said so since the first release, while
# the directory walk one level up decided by extension anyway. The set is
# kept because ordering by likelihood is a real optimisation on a directory of
# a hundred thousand files, and because a `.pkl` whose bytes are not a pickle
# is itself worth a finding. It is no longer a filter.
LIKELY_ARTIFACT_SUFFIXES = {
    ".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".safetensors",
    ".onnx", ".gguf", ".ggml", ".npy", ".npz", ".h5", ".hdf5", ".keras", ".joblib", ".model",
}
# The old name, kept so nothing importing it breaks. It is the same set; what
# changed is that no code branches on membership to decide whether to inspect.
ARTIFACT_SUFFIXES = LIKELY_ARTIFACT_SUFFIXES

# Directory names never descended into. Not a security boundary either - a
# hostile artifact will not be in `.git` - but walking a virtualenv or a
# `node_modules` turns a scan of a model directory into a scan of a package
# index, and the resulting report is unreadable.
SKIPPED_DIRECTORIES = frozenset(
    {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"}
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="actaira",
        description=(
            "Local-first AI assurance for model artifacts and agents: static inspection, "
            "evidence lifecycle, policy-as-code, agent governance and verifiable "
            "attestations. Nothing is ever loaded or executed, and nothing is ever scored."
        ),
    )
    parser.add_argument("--version", action="version", version=f"actaira {__version__}")
    parser.add_argument("--lang", choices=("en", "es"), default="en", help="output language")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="inspect artifacts and report findings")
    _add_scan_args(scan)
    scan.add_argument("--format", choices=tuple(SCAN_FORMATS), default=None,
                      help="report format (default: text)")
    scan.add_argument("--json", action="store_true", help="shorthand for --format json")
    scan.add_argument("--out", type=Path,
                      help="write the report to this path; the human-readable report still goes to stdout")
    scan.add_argument("--allow-inconclusive", action="store_true", help="treat inconclusive as success")
    scan.add_argument("--state", type=Path, default=None, help='a state database this run may file its evidence in. Optional in both directions: without it the command is exactly as stateless as it was, and with it the database must already exist - a scan does not create a workspace')

    bom = sub.add_parser("bom", help="emit a CycloneDX 1.6 ML-BOM")
    _add_scan_args(bom)
    bom.add_argument("--out", type=Path, help="write to this path instead of stdout")

    attest = sub.add_parser("attest", help="inspect, then write a signed attestation package")
    _add_scan_args(attest)
    attest.add_argument("--out", type=Path, required=True, help="output .zip path")
    attest.add_argument("--key", type=Path, default=default_key_path(), help="Ed25519 private key (created on first use)")
    attest.add_argument("--no-bom", action="store_true", help="omit ML-BOM documents from the package")
    attest.add_argument("--dsse", action="store_true",
                        help="also write the verdict as an in-toto Statement in a DSSE envelope, "
                             "so it can be consumed by cosign and the rest of the supply-chain "
                             "ecosystem rather than only by this tool")
    attest.add_argument("--continue", dest="continue_from", type=Path,
                        help="append to the chain in this package instead of starting a new one")
    attest.add_argument("--tsa-url",
                        help="RFC 3161 timestamp authority to anchor the manifest in time "
                             "(for example https://freetsa.org/tsr). Optional; without it the "
                             "package says time_anchor: none, exactly as before.")
    attest.add_argument("--tsa-timeout", type=float, default=10.0,
                        help="seconds to wait for the timestamp authority (default: 10)")

    pol = sub.add_parser("policy", help="evaluate a versioned policy and print the proof")
    pol_sub = pol.add_subparsers(dest="policy_command", required=True)

    pol_check = pol_sub.add_parser(
        "check", help="decide ALLOW, DENY or REVIEW for these artifacts, bundles, agents and sources"
    )
    _add_scan_args(pol_check, paths_required=False)
    # Not `--policy`: every scanning command already has one, meaning the
    # import policy (allowlist or denylist), and two flags with one name on
    # the same parser is how a caller ends up passing a file path where a
    # choice was expected and getting an error about neither.
    pol_check.add_argument("--policy-file", type=Path, required=True, dest="policy_file",
                           help="the policy document to decide under")
    pol_check.add_argument("--on", type=_parse_date, default=None,
                           help="the date the decision is made on, as YYYY-MM-DD. Defaults to today. "
                                "It is an argument because a decision that depends on when it ran "
                                "cannot be reproduced by whoever checks it.")
    pol_check.add_argument("--attestation", type=Path,
                           help="an attestation package to verify first, so the policy can ask about "
                                "signatures and signer trust instead of coming back REVIEW")
    pol_check.add_argument("--trusted-keyring", type=Path,
                           help="JSON keyring of fingerprints this environment already trusts")
    pol_check.add_argument("--subjects", type=Path, dest="subjects_manifest",
                           help="a subject manifest listing artifacts, bundles, agents, systems and "
                                "sources to decide about. Without it, only the paths given are "
                                "scanned as artifacts, which is what 2.1 could express")
    pol_check.add_argument("--json", action="store_true", help="emit the decision and proof as JSON")
    pol_check.add_argument("--out", type=Path, help="write the decision document to this path")
    pol_check.add_argument("--state", type=Path, default=None,
                           help="a state database, so this decision is recorded beside the evidence "
                                "it was made on and appears in the state export")

    pol_show = pol_sub.add_parser("show", help="print a policy, its rules and its digest")
    pol_show.add_argument("policy_file", type=Path)
    pol_show.add_argument("--json", action="store_true")

    sch = sub.add_parser("schema", help="print a published JSON Schema, or list them")
    sch.add_argument("name", nargs="?", help="schema name, for example report-v1")

    bdl = sub.add_parser("bundle", help="resolve a model repository and report what its files say about each other")
    bdl.add_argument("root", help="a directory, or a source URI such as huggingface://org/model")
    bdl.add_argument("--json", action="store_true")
    bdl.add_argument("--out", type=Path, help="write the bundle document to this path")
    bdl.add_argument("--revision", default=None,
                     help="the revision to resolve, when `root` is a source URI")
    bdl.add_argument("--stage-to", type=Path, default=None,
                     help="where to put a remote repository. A temporary directory by default, "
                          "removed afterwards")
    bdl.add_argument("--cache", type=Path, default=None,
                     help="a content-addressed cache under this directory. Never read without a "
                          "digest to check an entry against")
    bdl.add_argument("--offline", action="store_true",
                     help="refuse to open a socket; a remote URI is then a usage error rather "
                          "than a connector that happened to fail")
    bdl.add_argument(
        "--hash-weights",
        action="store_true",
        help="hash every member however large, so content_identity can be complete. Off by "
        "default: hashing 30 GB of shards takes minutes, and a resolution that is slow by "
        "default is one people stop running",
    )

    agt = sub.add_parser("agent", help="read an agent declaration and report dangerous capability combinations")
    agt_sub = agt.add_subparsers(dest="agent_command", required=True)

    agt_check = agt_sub.add_parser("check", help="assess one declaration")
    agt_check.add_argument("declaration", type=Path)
    agt_check.add_argument("--json", action="store_true")
    agt_check.add_argument("--fail-on", choices=("critical", "high", "medium", "low"), default="high")
    agt_check.add_argument("--state", type=Path, default=None, help='a state database this run may file its evidence in. Optional in both directions: without it the command is exactly as stateless as it was, and with it the database must already exist - a scan does not create a workspace')

    agt_bom = agt_sub.add_parser("bom", help="emit the A-BOM for one declaration")
    agt_bom.add_argument("declaration", type=Path)
    agt_bom.add_argument("--out", type=Path)

    agt_diff = agt_sub.add_parser("diff", help="what changed between two versions of one agent")
    agt_diff.add_argument("before", type=Path)
    agt_diff.add_argument("after", type=Path)
    agt_diff.add_argument("--json", action="store_true")

    agt_paths = agt_sub.add_parser(
        "paths", help="search the declared graph for routes from untrusted input to a consequence"
    )
    agt_paths.add_argument("declaration", type=Path)
    agt_paths.add_argument("--sub-agent", type=Path, action="append", default=[], dest="sub_agents",
                           help="another declaration to resolve a sub-agent against. Repeatable. "
                                "Without it a delegation is reported as unresolved rather than "
                                "assumed harmless")
    agt_paths.add_argument("--show-closed", action="store_true",
                           help="also print routes an existing control already closes")
    agt_paths.add_argument("--json", action="store_true")
    agt_paths.add_argument("--fail-on", choices=("critical", "high", "medium", "low"), default="high")

    # The state commands. Their parsers and handlers live in `statecli.py` so
    # nothing here imports sqlite3 or assumes `.actaira/` exists - every 2.1
    # command still runs in a directory that has never been initialised.
    from .statecli import add_parsers as add_state_parsers

    add_state_parsers(sub)

    rec = sub.add_parser("receipt", help="issue or check a signed statement of what was observed")
    rec_sub = rec.add_subparsers(dest="receipt_command", required=True)

    rec_issue = rec_sub.add_parser("issue", help="inspect, decide, and sign the result as a receipt")
    _add_scan_args(rec_issue, paths_required=False)
    rec_issue.add_argument("--subjects", type=Path, dest="subjects_manifest",
                           help="a subject manifest, so the receipt can be about a system rather "
                                "than about a list of files")
    rec_issue.add_argument("--state", type=Path, default=None,
                           help="a state database, so the receipt can reference the evidence, "
                                "snapshots and relations behind its subjects")
    rec_issue.add_argument("--out", type=Path, required=True, help="write the receipt to this path")
    rec_issue.add_argument("--key", type=Path, default=default_key_path(),
                           help="Ed25519 private key (created on first use)")
    rec_issue.add_argument("--policy-file", type=Path, dest="policy_file",
                           help="decide under this policy and carry the proof in the receipt")
    rec_issue.add_argument("--attestation", type=Path,
                           help="an attestation package, so the receipt can speak about provenance")
    rec_issue.add_argument("--trusted-keyring", type=Path,
                           help="JSON keyring of fingerprints this environment already trusts")
    rec_issue.add_argument("--system", default="",
                           help="the name of the AI system these artifacts belong to")
    rec_issue.add_argument("--on", type=_parse_date, default=None,
                           help="the date the policy decision is made on, as YYYY-MM-DD")

    rec_verify = rec_sub.add_parser("verify", help="check a receipt offline")
    rec_verify.add_argument("receipt", type=Path)
    rec_verify.add_argument("--trusted-keyring", type=Path,
                            help="only then is the signer reported as trusted or not; without it the "
                                 "answer is 'verified, nobody vouched for the key'")
    rec_verify.add_argument("--against", nargs="*", type=Path, default=None,
                            help="artifacts the receipt should be about, to close the loop between "
                                 "a valid signature and the files in front of you")
    rec_verify.add_argument("--json", action="store_true")

    ver = sub.add_parser("verify", help="verify an attestation package offline")
    ver.add_argument("package", type=Path)
    ver.add_argument("--trusted-keyring", type=Path, help="JSON keyring of fingerprints you already trust")
    ver.add_argument("--pubkey", help="base64 raw Ed25519 public key you already trust")
    ver.add_argument("--tsa-trust-store", type=Path,
                     help="a PEM file or directory of PEM certificates to validate the time-stamp "
                          "authority's chain against. Without it the chain state is `unknown`: "
                          "this tool ships no trust anchors, because choosing them is the "
                          "verifier's decision and a bundled list goes stale unaudited.")
    ver.add_argument("--require-trust", action="store_true", help="fail unless the signing key is trusted")
    ver.add_argument("--json", action="store_true")
    ver.add_argument("--extends", type=Path,
                     help="an older package this one must be an append-only extension of")

    keygen = sub.add_parser("keygen", help="create, rotate or revoke a signing key")
    keygen.add_argument("--key", type=Path, default=default_key_path(),
                        help="Ed25519 private key; the keyring lives beside it as keyring.json")
    keygen.add_argument("--rotate", action="store_true",
                        help="retire the current key and generate a new one, keeping the old "
                             "public key in the keyring so packages it signed still verify")
    keygen.add_argument("--revoke", metavar="KEY_ID",
                        help="mark a key revoked: nothing it ever signed will be accepted again")

    gov = sub.add_parser("governance", help="map technical evidence to EU AI Act obligations")
    gov_sub = gov.add_subparsers(dest="governance_command", required=True)

    gov_clock = gov_sub.add_parser("clock", help="which obligations apply, and when")
    gov_clock.add_argument("--on", type=_parse_date, default=None, help="date to evaluate (default: today)")
    gov_clock.add_argument("--horizon", type=int, default=None, help="also show what starts within N days")
    gov_clock.add_argument("--json", action="store_true")

    gov_assess = gov_sub.add_parser("assess", help="what the evidence in these artifacts touches")
    _add_scan_args(gov_assess)
    gov_assess.add_argument("--role", choices=[r.value for r in Role], default=Role.PROVIDER.value)
    gov_assess.add_argument("--on", type=_parse_date, default=None)
    gov_assess.add_argument("--json", action="store_true")

    gov_pack = gov_sub.add_parser("pack", help="signed evidence dossier bound to the artifacts")
    _add_scan_args(gov_pack)
    gov_pack.add_argument("--out", type=Path, required=True)
    gov_pack.add_argument("--role", choices=[r.value for r in Role], default=Role.PROVIDER.value)
    gov_pack.add_argument("--on", type=_parse_date, default=None)
    gov_pack.add_argument("--key", type=Path, default=default_key_path())
    gov_pack.add_argument("--tsa-url", default=None, help="RFC 3161 authority to anchor the dossier in time")

    controls = sub.add_parser(
        "controls", help="run compliance-as-code controls over a target directory"
    )
    controls_sub = controls.add_subparsers(dest="controls_command", required=True)
    controls_list = controls_sub.add_parser("list", help="every registered control and what it binds")
    controls_list.add_argument("--json", action="store_true")
    controls_run = controls_sub.add_parser("run", help="run controls and report what was observed")
    controls_run.add_argument("target", type=Path, help="directory holding output, logs and actaira.yaml")
    controls_run.add_argument("--role", choices=[r.value for r in Role], default=Role.PROVIDER.value)
    controls_run.add_argument("--only", action="append", default=None, help="control id, repeatable")
    controls_run.add_argument("--json", action="store_true")
    controls_mark = controls_sub.add_parser(
        "mark", help="write an Article 50(2) machine-readable marking into an image"
    )
    controls_mark.add_argument("paths", nargs="+", type=Path)
    controls_mark.add_argument(
        "--term",
        choices=("trained", "composite"),
        default="trained",
        help="trained: wholly model-generated. composite: a model contributed part of it",
    )
    controls_mark.add_argument("--in-place", action="store_true")
    controls_mark.add_argument("--note", default="")

    discover = sub.add_parser(
        "discover", help="enumerate the artifacts a source says it holds, and optionally fetch them"
    )
    discover.add_argument("uri", nargs="?",
                          help="hf://org/model, github://owner/repo, oci://ghcr.io/owner/img:tag, "
                               "s3://bucket/prefix, mlflow://host/models/name, a directory, or a manifest file")
    discover.add_argument("--list", action="store_true", dest="list_connectors",
                          help="print the registered connectors and what each one needs, then exit")
    discover.add_argument("--out", type=Path, help="directory to fetch into; required by --fetch")
    discover.add_argument("--fetch", action="store_true",
                          help="download every listed artifact into --out and check it against the digest "
                               "its source declared")
    discover.add_argument("--offline", action="store_true",
                          help="refuse to touch the network; a source that needs it is an error, never a "
                               "silent empty listing")
    discover.add_argument("--revision", help="branch, tag, commit or reference to list, where the source has them")
    discover.add_argument("--json", action="store_true")

    serve = sub.add_parser("serve", help="run the local web interface")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--state", type=Path, default=None,
                       help="a workspace database for the graph panel to read. Optional, and "
                            "read-only: with none given the interface still runs, and it never "
                            "creates or migrates one")
    return parser


def _today() -> date:
    """The date a decision defaults to when the caller did not name one.

    Defect DEF-68. This used to read `args.on or gov_clock_fn()`, and
    `gov_clock_fn` is `governance.clock(on, horizon_days=None)` - the
    obligation-clock builder, which takes the date rather than returning it.
    So `actaira policy check` and `actaira receipt issue` without `--on`
    raised `TypeError` and argparse's caller turned that into exit 1, which is
    `EXIT_FAIL`: a pipeline reading the exit code saw a clean policy DENY. The
    name collision is the whole defect - two things called "clock", one of
    which is not one.

    Every test of those two commands passed `--on`, because `--on` is what a
    reproducible decision uses and what the README shows.
    """
    return datetime.now(UTC).date()


def _add_scan_args(parser: argparse.ArgumentParser, *, paths_required: bool = True) -> None:
    # `policy check` is the one command whose subjects may all come from a
    # manifest rather than from the command line, so its positional list is
    # optional. It is still an error to supply neither: "no subjects" is a
    # usage failure, not an empty ALLOW.
    parser.add_argument(
        "paths",
        nargs="+" if paths_required else "*",
        type=Path,
        default=[],
        help="files or directories",
    )
    parser.add_argument("--policy", choices=("strict", "known-bad"), default="strict",
                        help="import policy: allowlist (default) or denylist")
    parser.add_argument("--fail-on", choices=("critical", "high", "medium", "low"), default="high",
                        help="lowest severity that fails an artifact")
    parser.add_argument("--no-recurse", action="store_true", help="do not walk directories")


@dataclass(frozen=True)
class Discovered:
    """One file the walk found, and what its bytes turned out to be."""

    path: Path
    detected: str
    confidence: str

    @property
    def is_artifact(self) -> bool:
        """Whether this file gets inspected.

        Two ways in, and the second one matters as much as the first. Bytes
        that match a format this tool reads, obviously. But also a name that
        claims to be an artifact while the bytes match nothing: `weights.pkl`
        holding something that is not a pickle is a fact about the directory,
        and skipping it would mean the tool reported nothing about a file
        whose own name says it is a model. That case comes back as
        ACT-FMT-001 or ACT-FMT-002, which is the honest answer, rather than
        as silence.
        """
        if self.detected != "unknown":
            return True
        return self.path.suffix.lower() in LIKELY_ARTIFACT_SUFFIXES


def discover(paths: list[Path], recurse: bool = True) -> tuple[list[Discovered], list[Discovered]]:
    """Walk the inputs and classify every file by content.

    Returns (artifacts, unclassified). Nothing is dropped silently: a file
    whose bytes match no format this tool reads still comes back, in the
    second list, so the caller can say how many files it walked past. That is
    the difference between "there were no artifacts here" and "I only looked
    at the ones with the right name".

    Classification is cheap by construction. `detect.sniff` reads 64 bytes
    and, for one branch, seeks to the last byte; it never reads a file whole.
    Walking a directory of a hundred thousand files therefore costs a hundred
    thousand short reads, not a hundred thousand full ones.
    """
    artifacts: list[Discovered] = []
    unclassified: list[Discovered] = []

    def classify(child: Path) -> None:
        try:
            detected, confidence = detect.sniff(child)
        except OSError as exc:
            # A file that cannot be opened is reported, never skipped: an
            # unreadable file in a model directory is a fact about the
            # directory, and swallowing it is how a scan of nine files
            # silently becomes a scan of eight.
            unclassified.append(Discovered(child, f"unreadable:{type(exc).__name__}", "unknown"))
            return
        record = Discovered(child, detected, confidence)
        (artifacts if record.is_artifact else unclassified).append(record)

    for entry in paths:
        if entry.is_dir():
            if not recurse:
                continue
            for child in _walk(entry):
                classify(child)
        elif entry.is_file():
            # An explicitly named file is always inspected, whatever its bytes
            # say. The user pointed at it; refusing to look would be the tool
            # second-guessing an instruction rather than reporting a fact.
            try:
                detected, confidence = detect.sniff(entry)
            except OSError:
                detected, confidence = "unknown", "unknown"
            artifacts.append(Discovered(entry, detected, confidence))
    return artifacts, unclassified


def _walk(root: Path) -> list[Path]:
    """Files under `root`, likely artifacts first, skipping tool directories.

    Ordering puts the suffixes in `LIKELY_ARTIFACT_SUFFIXES` first so a large
    tree produces its interesting reports early, then falls back to sorted
    order so two runs over the same tree produce the same report. Determinism
    matters here: the report is hashed into an attestation.
    """
    files: list[Path] = []
    for child in root.rglob("*"):
        if not child.is_file():
            continue
        if any(part in SKIPPED_DIRECTORIES for part in child.parts):
            continue
        files.append(child)
    files.sort(key=lambda p: (p.suffix.lower() not in LIKELY_ARTIFACT_SUFFIXES, str(p)))
    return files


def collect_paths(paths: list[Path], recurse: bool = True) -> list[Path]:
    """Every path worth inspecting, decided by content.

    Kept as the name the rest of the CLI calls. It now returns files whose
    bytes are a format this tool reads, plus every file named explicitly on
    the command line, and no longer filters a directory walk by suffix.
    """
    artifacts, _ = discover(paths, recurse=recurse)
    return [record.path for record in artifacts]


def run_scan(args: argparse.Namespace) -> tuple[list[ArtifactReport], int]:
    artifacts, unclassified = discover(list(args.paths), recurse=not args.no_recurse)
    if not artifacts:
        # Nothing to inspect is still a result worth explaining when the walk
        # went past files. "0 artifacts" and "0 artifacts, 812 files walked
        # past" send a reader to very different places.
        if unclassified:
            print(
                Catalog(getattr(args, "lang", "en")).line(
                    "scan.none_recognised", walked=len(unclassified)
                ),
                file=sys.stderr,
            )
        return [], EXIT_USAGE
    fail_on = Severity(args.fail_on)
    reports = [
        inspect_artifact(record.path, scan_policy=args.policy, fail_on=fail_on)
        for record in artifacts
    ]
    if unclassified and getattr(args, "format", None) in (None, "text"):
        print(
            Catalog(getattr(args, "lang", "en")).line(
                "scan.walked_past", walked=len(unclassified)
            ),
            file=sys.stderr,
        )
    return reports, exit_code_for(reports, getattr(args, "allow_inconclusive", False))


def exit_code_for(reports: list[ArtifactReport], allow_inconclusive: bool = False) -> int:
    if any(report.verdict is Verdict.FAIL for report in reports):
        return EXIT_FAIL
    if any(report.verdict is Verdict.INCONCLUSIVE for report in reports) and not allow_inconclusive:
        return EXIT_INCONCLUSIVE
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """The entry point, wrapped so a closed pipe is not a traceback.

    Design note D-235. `actaira schema | head -3` printed a `BrokenPipeError`
    traceback and exited 0: `head` closes the pipe after three lines, the next
    `print` raises, and the interpreter's final flush of `sys.stdout` raises
    again on the way out. Every command here prints more lines than a reader
    piping into `head`, `less` or `grep -m` will consume, so this was every
    command.

    It is not cosmetic. The traceback goes to stderr, which is where a CI job
    looks when something has gone wrong, and it arrives with an exit code that
    says nothing did. Anyone debugging a pipeline sees a stack trace from the
    tool that just told them everything passed.

    The handling is the conventional one: swallow the error, and point
    `sys.stdout` at the null device so the interpreter's own flush has nothing
    left to fail on. The exit code is 141, which is what a shell reports for a
    process killed by SIGPIPE, so a pipeline that checks it sees the ordinary
    thing rather than a new one.
    """
    _settle_output_encoding()
    try:
        return _main(argv)
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return EXIT_SIGPIPE


def _settle_output_encoding() -> None:
    """Decide the encoding of what this tool prints, rather than inheriting it.

    Design note D-241. Python picks the encoding of `sys.stdout` from the
    locale, so on a host whose locale is not UTF-8 - every default Windows
    install - `actaira --lang es scan > report.txt` wrote cp1252 bytes. The
    same command on Linux wrote UTF-8. Two machines running one command over
    one artifact produced two different files, which is the property this
    repository spends a release gate defending everywhere else.

    Two cases, and they want opposite things:

      * **Redirected or piped.** The consumer is a program, and the thing a
        program can rely on is UTF-8. Reconfigured, unconditionally.
      * **A terminal.** The consumer is a console with a code page of its own,
        and forcing UTF-8 into one that is not expecting it renders mojibake.
        Left alone - except for `errors`, which becomes `replace` so that a
        character the console cannot draw is a question mark rather than a
        `UnicodeEncodeError` traceback out of a tool that had finished its
        work.

    `reconfigure` is not available on a replaced stream - a test capturing
    stdout, or a caller who set one - so failure here is silently the caller's
    encoding, which is the right precedence: an explicit stream beats a default
    this function is only filling in.
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


def _main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    catalog = Catalog(args.lang)

    if args.command == "keygen":
        if args.rotate and args.revoke:
            print(catalog.line("key.rotate_revoke_conflict"), file=sys.stderr)
            return EXIT_USAGE
        if args.revoke:
            try:
                record = keyring.revoke(args.key, args.revoke)
            except ValueError as exc:
                print(f"{exc}", file=sys.stderr)
                return EXIT_USAGE
            print(catalog.line("key.revoked", key_id=record.key_id, path=str(keyring.keyring_path_for(args.key))))
            return EXIT_OK
        if args.rotate:
            rotation = keyring.rotate(args.key)
            if rotation.retired is not None:
                print(catalog.line("key.retired", key_id=rotation.retired.key_id, when=str(rotation.retired.not_after)))
            if rotation.archived_key_path is not None:
                print(catalog.line("key.archived", path=str(rotation.archived_key_path)))
            print(catalog.line("key.rotated", path=str(args.key)))
            _print_key(rotation.keypair, rotation.keyring, rotation.keyring_path, catalog)
            return EXIT_OK
        local = keyring.load_local(args.key)
        print(catalog.line("key.created" if local.created_key else "key.loaded", path=str(args.key)))
        _print_key(local.keypair, local.keyring, local.path, catalog)
        return EXIT_OK

    if args.command == "governance":
        return _run_governance(args, catalog)

    if args.command == "controls":
        return _run_controls(args, catalog)

    if args.command == "discover":
        return _run_discover(args, catalog)

    from .statecli import dispatch as state_dispatch

    handled = state_dispatch(args, catalog)
    if handled is not None:
        return handled

    if args.command == "policy":
        return _run_policy(args, catalog)

    if args.command == "receipt":
        return _run_receipt(args, catalog)

    if args.command == "schema":
        from . import schemas as schemas_mod

        if args.name is None:
            for name in schemas_mod.names():
                print(f"{name}  {schemas_mod.load(name)['title']}")
            return EXIT_OK
        try:
            print(json.dumps(schemas_mod.load(args.name), ensure_ascii=False, indent=2))
        except KeyError as exc:
            print(str(exc).strip("\""), file=sys.stderr)
            return EXIT_USAGE
        return EXIT_OK

    if args.command == "bundle":
        return _run_bundle(args, catalog)

    if args.command == "agent":
        return _run_agent(args, catalog)

    if args.command == "serve":
        from .web.server import serve
        serve(host=args.host, port=args.port, state_path=args.state)
        return EXIT_OK

    if args.command == "verify":
        # The package is always verified in full, with whatever trust anchors
        # the caller supplied. `--extends` adds the consistency proof on top;
        # it used to *replace* the verification, returning before the call
        # below, so `--require-trust` and `--trusted-keyring` were accepted,
        # ignored and never mentioned again: a package signed by a key the
        # caller had explicitly said they did not accept came back OK with
        # exit 0 as long as it extended the older one. The two results are
        # combined, and either failing fails the command.
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
                payload["extends"] = {
                    "older": str(args.extends),
                    "ok": extends_ok,
                    "problems": problems,
                }
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

    # A contradiction between --json and --format is a usage error, and a
    # usage error must be reported before any work is done rather than after.
    if args.command == "scan" and _scan_format(args) is None:
        print(catalog.line("scan.format_conflict"), file=sys.stderr)
        return EXIT_USAGE

    reports, code = run_scan(args)
    if not reports:
        print(catalog.line("scan.no_artifacts"), file=sys.stderr)
        return EXIT_USAGE

    if args.command == "scan":
        # After the report exists and never instead of it. The scanner is
        # untouched: `run_scan` already produced the authoritative reports and
        # this only writes them down, so a workspace that cannot be opened
        # costs the operator a note on stderr and not the scan.
        _record_scans_in_state(args, reports, catalog)
        rendered = render_scan(reports, _scan_format(args) or "text", catalog)
        if args.out:
            args.out.write_text(rendered, encoding="utf-8", newline="\n")
            # The machine-readable report went to the file, so stdout stays
            # the human log: a CI run whose only output is a SARIF blob is a
            # CI run nobody reads.
            print(format_text(reports, catalog))
            print(catalog.line("scan.written", path=str(args.out)))
        else:
            print(rendered, end="" if rendered.endswith("\n") else "\n")
        return code

    if args.command == "bom":
        document = build_bom(reports)
        blob = json.dumps(document, indent=2)
        if args.out:
            args.out.write_text(blob, encoding="utf-8", newline="\n")
            print(catalog.line("bom.written", path=str(args.out)))
        else:
            print(blob)
        return code

    if args.command == "attest":
        local = keyring.load_local(args.key)
        keypair = local.keypair
        if local.created_key:
            print(catalog.line("key.created", path=str(args.key)), file=sys.stderr)
        entries: list[chain.Entry] = []
        if args.continue_from is not None:
            previous = verify_mod.verify_package(args.continue_from)
            if not previous.ok:
                print(catalog.line("attest.continue_invalid", path=str(args.continue_from)), file=sys.stderr)
                for problem in previous.problems[:3]:
                    print(f"  x {problem}", file=sys.stderr)
                return EXIT_USAGE
            entries = chain.load_entries(verify_mod._read_entries(args.continue_from))
            print(catalog.line("attest.continued", path=str(args.continue_from), count=len(entries)))
        boms: dict[str, dict] = {}
        for report in reports:
            chain.append(entries, report.sha256, report.to_dict())
            if not args.no_bom:
                boms[report.sha256] = build_bom([report])
        envelope_blob: bytes | None = None
        if args.dsse:
            # DEF-96: this is what `--dsse` was supposed to do since 2.0. The
            # envelope is built over the same reports, signed with the same
            # key, and written into the package as an ordinary member - so it
            # is listed in `manifest.files` with its digest and covered by the
            # manifest signature, which is the structural property the module
            # argues for.
            from .attest import dsse

            envelope_blob = dsse.to_envelope(
                reports,
                keypair,
                scan_policy=args.policy,
                fail_on=Severity(args.fail_on),
            ).to_json().encode("utf-8")
        try:
            written = package.write_package(
                args.out, entries, keypair, boms,
                keyring=local.keyring,
                envelope=envelope_blob,
                tsa_url=args.tsa_url,
                tsa_timeout=args.tsa_timeout,
            )
        except timestamp_mod.TimestampError as exc:
            # The caller asked for a time anchor. Writing the package without
            # one and mentioning it in passing would put an unanchored package
            # where an anchored one was expected, which is the kind of quiet
            # downgrade this tool exists to make impossible.
            print(catalog.line("attest.tsa_failed", detail=str(exc)), file=sys.stderr)
            return EXIT_USAGE
        print(catalog.line("attest.written", path=str(written.path)))
        print(f"entries      {written.entry_count}")
        print(f"head         {written.head_hash}")
        print(f"merkle_root  {written.merkle_root}")
        print(f"key_id       {written.key_id}")
        print(f"time_anchor  {written.time_anchor}")
        if written.timestamp is not None:
            print(catalog.line(
                "attest.stamped",
                tsa=str(written.timestamp.tsa_name),
                gen_time=written.timestamp.gen_time_iso,
            ))
        return code

    return EXIT_USAGE


_SEVERITY_MARK = {
    Severity.CRITICAL: "!!", Severity.HIGH: "! ", Severity.MEDIUM: "~ ",
    Severity.LOW: ". ", Severity.INFO: "  ",
}


def _scan_format(args: argparse.Namespace) -> str | None:
    """The format `scan` should emit, or None when the flags contradict.

    `--json` predates `--format` and stays, because it is in other people's
    pipelines. Silently letting one flag win over the other would emit a
    format the caller did not ask for, so a contradiction is a usage error.
    """
    if args.json and args.format not in (None, "json"):
        return None
    if args.json:
        return "json"
    return args.format or "text"


def render_scan(reports: list[ArtifactReport], report_format: str, catalog: Catalog) -> str:
    if report_format == "json":
        return json.dumps({"reports": [r.to_dict() for r in reports]}, indent=2)
    if report_format == "sarif":
        return json.dumps(build_sarif(reports, catalog=catalog), indent=2)
    if report_format == "junit":
        return build_junit(reports, catalog=catalog)
    return format_text(reports, catalog)


def _finding_suffix(location: str, artifact_path: str) -> str:
    """The part of a finding's location that is not the artifact itself.

    A checkpoint is a container: a finding can come from the top-level stream,
    from `archive/data.pkl` inside the zip, or from a pickle that a nested
    loader is handed. Printing only the rule text made two findings from two
    different streams look like the same finding reported twice, which is how
    a duplicated ACT-PKL-003 was read as a bug in the scanner rather than as
    two real streams. The location carries that information already; this
    shows the part of it that the artifact line does not.
    """
    name = Path(artifact_path).name
    if not location or location == name or location == artifact_path:
        return ""
    for prefix in (artifact_path, name):
        if location.startswith(prefix):
            trimmed = location[len(prefix):]
            return f"  [{trimmed.lstrip('!')}]" if trimmed else ""
    return f"  [{location}]"


_COVERAGE_MARK = {
    CoverageState.COMPLETE: "+",
    CoverageState.PARTIAL: "~",
    CoverageState.FAILED: "x",
    CoverageState.NOT_ASSESSED: ".",
}


def format_text(reports: list[ArtifactReport], catalog: Catalog) -> str:
    counts = {verdict: 0 for verdict in Verdict}
    lines: list[str] = []
    for report in reports:
        counts[report.verdict] += 1
        name = Path(report.path).name
        lines.append(f"\n{report.verdict.value.upper():13} {name}")
        lines.append(f"              {catalog.line('scan.format')}: {report.detected_format} ({report.format_confidence})  sha256:{report.sha256[:16]}")
        for finding in sorted(report.findings, key=lambda f: -f.severity.rank):
            mark = _SEVERITY_MARK[finding.severity]
            where = _finding_suffix(finding.location, report.path)
            lines.append(f"  {mark} {finding.rule_id}  {catalog.rule(finding.rule_id)}{where}")
            if finding.evidence:
                lines.append(f"       {json.dumps(finding.evidence, ensure_ascii=False)}")
        for error in report.inspector_errors:
            lines.append(f"  !! inspector error: {error}")
        # The coverage block is printed for every artifact, not only the
        # limited ones. A reader who only ever sees it when something went
        # wrong learns to read it as a warning; printing it always makes it
        # what it is - the scope of the claim above.
        lines.append(f"              {catalog.line('coverage.heading')}")
        for entry in report.coverage.ordered():
            mark = _COVERAGE_MARK[entry.state]
            surface = catalog.line(f"coverage.surface.{entry.surface.value}")
            state = catalog.line(f"coverage.state.{entry.state.value}")
            reason = catalog.line(f"coverage.reason.{entry.reason}")
            lines.append(f"                {mark} {surface:<28} {state:<14} {reason}")
    lines.append("")
    lines.append(catalog.line(
        "scan.summary",
        total=len(reports),
        passed=counts[Verdict.PASS],
        failed=counts[Verdict.FAIL],
        inconclusive=counts[Verdict.INCONCLUSIVE],
    ))
    return "\n".join(lines)


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


def _print_verify(result: verify_mod.VerifyResult, catalog: Catalog) -> None:
    print(catalog.line("verify.header", path=str(result.manifest.get("tool_version", "?"))))
    for name, ok in result.checks.items():
        print(f"  [{'ok' if ok else 'FAIL'}] {catalog.line('check.' + name)}")
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
    print(f"\n{catalog.line('verify.result')}: {'OK' if result.ok else 'FAILED'}")


def _run_controls(args: argparse.Namespace, catalog: Catalog) -> int:
    """`actaira controls`, and the exit code contract it shares with `scan`.

    0 every control that ran was satisfied or not applicable
    1 at least one control observed the thing it looks for to be absent
    3 at least one control could not decide

    Inconclusive keeps its own code here for the same reason it has one in the
    scanner: a gate that treats "I could not tell" as a pass is the failure
    mode this whole repository is a reaction to. A run with one NOT_SATISFIED
    and one INCONCLUSIVE exits 1, because a known negative is the more
    actionable of the two and an exit code carries one number.
    """
    from .controls import engine, registry
    from .controls.model import Outcome
    from .marking import COMPOSITE_WITH_TRAINED, TRAINED_ALGORITHMIC_MEDIA, mark_file

    if args.controls_command == "list":
        rows = [
            {
                "id": control.id,
                "method": control.method.value,
                "obligations": list(control.obligation_ids),
            }
            for control in registry.all_controls()
        ]
        if args.json:
            print(json.dumps({"controls": rows}, indent=2))
            return EXIT_OK
        print(catalog.line("controls.list.header"))
        for row in rows:
            print(f"  {row['id']:<28} {row['method']:<14} {', '.join(row['obligations'])}")
        print(f"\n{len(rows)} " + catalog.line("controls.list.count"))
        return EXIT_OK

    if args.controls_command == "mark":
        term = TRAINED_ALGORITHMIC_MEDIA if args.term == "trained" else COMPOSITE_WITH_TRAINED
        written = 0
        for path in args.paths:
            try:
                blob = mark_file(path, term=term, note=args.note)
            except ValueError as exc:
                print(f"  x {path.name}: {exc}")
                continue
            destination = path if args.in_place else path.with_suffix(f".marked{path.suffix}")
            destination.write_bytes(blob)
            print(f"  {catalog.line('controls.mark.written')} {destination.name}")
            written += 1
        return EXIT_OK if written else EXIT_FAIL

    target = engine.load_target(args.target, role=args.role)
    only = tuple(args.only) if args.only else None
    run_result = engine.run(target, only)

    if args.json:
        print(json.dumps(run_result.to_dict(), indent=2))
    else:
        _print_controls(run_result, catalog)

    outcomes = {result.outcome for result in run_result.results}
    if Outcome.NOT_SATISFIED in outcomes:
        return EXIT_FAIL
    if Outcome.INCONCLUSIVE in outcomes:
        return EXIT_INCONCLUSIVE
    return EXIT_OK


_OUTCOME_MARK = {
    "satisfied": "  ",
    "not_satisfied": "!!",
    "inconclusive": "? ",
    "not_applicable": "- ",
}


def _print_controls(run_result, catalog: Catalog) -> None:
    from .controls.model import localized_boundary
    print()
    for result in run_result.results:
        mark = _OUTCOME_MARK[result.outcome.value]
        label = catalog.line(f"outcome.{result.outcome.value}")
        print(f"{mark} {label:<16} {result.control_id}  [{result.method.value}]")
        print(f"     {', '.join(result.obligation_ids)}")
        # The boundary is prose, so it is resolved in the reader's language
        # from the same key the result carries. See design note D-45.
        covers, does_not_cover = localized_boundary(result.control_id, catalog.lang)
        if covers:
            print(f"     {catalog.line('controls.covers')}: {covers}")
        if does_not_cover:
            print(f"     {catalog.line('controls.does_not_cover')}: {does_not_cover}")
        for finding in result.findings:
            print(f"       {finding.rule_id}  {catalog.rule(finding.rule_id)}  [{finding.location}]")
        print()
    counts = run_result.counts()
    # A count, never a ratio. Design note D-41.
    print(
        f"{len(run_result.results)} {catalog.line('controls.ran')}: "
        + ", ".join(f"{value} {catalog.line('outcome.' + key)}" for key, value in counts.items())
    )


def _run_governance(args: argparse.Namespace, catalog: Catalog) -> int:
    on = args.on or _date.today()

    if args.governance_command == "clock":
        rows = gov_clock_fn(on, horizon_days=args.horizon)
        if args.json:
            print(json.dumps({"on": on.isoformat(), "obligations": [r.to_dict() for r in rows]}, indent=2))
        else:
            print(gov_render(rows, on, catalog.lang))
        return EXIT_OK

    reports, code = run_scan(args)
    if not reports:
        print(catalog.line("scan.no_artifacts"), file=sys.stderr)
        return EXIT_USAGE

    role = Role(args.role)

    if args.governance_command == "assess":
        assessment = gov_assess_fn(
            reports, on=on, role=role, has_attestation=False, has_bom=True
        )
        if args.json:
            print(json.dumps(assessment.to_dict(), indent=2))
        else:
            _print_assessment(assessment, reports, catalog)
        return code

    if args.governance_command == "pack":
        keypair, created = signing.load_or_create(args.key)
        if created:
            print(catalog.line("key.created", path=str(args.key)), file=sys.stderr)
        result, dossier = write_evidence_package(
            args.out, reports, keypair, on=on, role=role, tsa_url=args.tsa_url
        )
        print(catalog.line("gov.pack_written", path=str(result.path)))
        print(f"entries      {result.entry_count}  ({len(reports)} inspections + 1 dossier)")
        print(f"head         {result.head_hash}")
        print(f"merkle_root  {result.merkle_root}")
        counts = dossier["assessment"]["counts_not_a_score"]
        print(
            f"obligations  {counts['applicable']} applicable, {counts['with_evidence']} touched by this "
            f"evidence, {counts['outside_this_tool']} outside what this tool can show"
        )
        return code

    return EXIT_USAGE


_MAX_EVIDENCE_LINES = 5


def _evidence_line(item: dict) -> str:
    """One line naming a concrete piece of evidence, not a capability.

    An assessment that says "provides an inventory of the artifacts inspected"
    is describing the tool. This names the file, its digest and the verdict it
    got, so a reader can go and check the claim against the report instead of
    taking the sentence on trust.
    """
    kind = item.get("kind", "")
    subject = str(item.get("subject", ""))
    detail = item.get("detail") or {}
    if kind == "artifact_inspection":
        path = detail.get("path", "?")
        fmt = detail.get("format", "?")
        verdict = str(detail.get("verdict", "?")).upper()
        return f"{path} ({fmt}, {verdict}, sha256:{subject[:16]})"
    if kind == "ml_bom":
        return f"ML-BOM {subject} over {detail.get('components', 0)} component(s)"
    return f"{kind} {subject}".strip()


def _print_assessment(assessment, reports: list[ArtifactReport], catalog: Catalog) -> None:
    data = assessment.to_dict()
    print(catalog.line("gov.header", on=data["assessed_on"], role=data["role"], n=data["artifacts"]))
    print()
    for row in data["obligations"]:
        if not row["applicable"]:
            continue
        # Structure from the assessment, prose in the caller's language.
        obligation = gov_by_id(row["id"])
        text = gov_localized(obligation, catalog.lang) if obligation is not None else row
        mark = {"evidence_supports": "++", "evidence_partial": "+ ",
                "no_evidence_supplied": "  ", "outside_this_tool": "--"}.get(row["state"], "  ")
        print(f"  {mark} {row['id']:12} {row['article']:18} {text['title']}")
        if row["state"] == "outside_this_tool":
            for line in text["actaira_does_not_provide"]:
                print(f"       {catalog.line('gov.not_provided')}: {line}")
        elif row["state"] == "no_evidence_supplied":
            # What the catalogue says this tool CAN show is not the same claim
            # as what this run actually showed, and printing the first under
            # the word "provides" made a run over zero artifacts read like a
            # run that had established something. The capability is still
            # worth printing, in the conditional, because it tells the reader
            # what to supply; the state line above it says plainly that
            # nothing was.
            print(f"       {catalog.line('gov.no_evidence')}")
            for line in text["actaira_provides"]:
                print(f"       {catalog.line('gov.would_provide')}: {line}")
            for line in text["actaira_does_not_provide"]:
                print(f"       {catalog.line('gov.not_provided')}: {line}")
        else:
            for line in text["actaira_provides"]:
                print(f"       {catalog.line('gov.provides')}: {line}")
            for item in row["evidence"][:_MAX_EVIDENCE_LINES]:
                print(f"       {catalog.line('gov.evidence_from')}: {_evidence_line(item)}")
            hidden = len(row["evidence"]) - _MAX_EVIDENCE_LINES
            if hidden > 0:
                print(f"       {catalog.line('gov.evidence_more', n=hidden)}")
            for line in text["actaira_does_not_provide"]:
                print(f"       {catalog.line('gov.not_provided')}: {line}")
    unread = [
        artifact_name(r.path) for r in reports
        if not r.metadata.get("fully_read", False)
    ]
    if unread:
        print()
        print(catalog.line("gov.unread", files=", ".join(unread)))
    print()
    counts = data["counts_not_a_score"]
    print(catalog.line(
        "gov.counts",
        applicable=counts["applicable"],
        touched=counts["with_evidence"],
        outside=counts["outside_this_tool"],
    ))
    print()
    print(data["disclaimer"])


def _run_discover(args: argparse.Namespace, catalog: Catalog) -> int:
    """`actaira discover`, the only command in this tool that opens a socket.

    Design note D-92, on the exit codes, which are the part of this command a
    pipeline reads.

      0  every listed artifact was accounted for and the listing was complete
      1  a source declared a digest and served bytes that do not match it
      2  usage: no connector accepts the URI, --fetch without --out, or
         --offline against a source that only exists over the network
      3  the listing is incomplete, or an artifact could not be fetched

    The split between 1 and 3 is the same one `scan` makes and it is made for
    the same reason. `ACT-CON-002` is a proven contradiction: the source said
    sha256 X, the bytes hash to Y, and one of those two facts is a lie. That is
    a failure. `ACT-CON-001` and an incomplete listing are absences: a file
    would not come down, a registry paginated past where this client follows.
    Neither of those is evidence that anything is wrong, and neither is
    evidence that anything is right, which is exactly what 3 means everywhere
    else in this tool.

    Incomplete is 3 rather than 0 even when every artifact fetched cleanly, and
    that is the whole doctrine of this package in one line: a listing that
    cannot prove it saw everything must not be reported to a pipeline as a
    green light. See design note D-80.

    `--offline` is a usage error rather than a quiet no-op for the reason the
    `--json`/`--format` conflict is one: the operator asked for two things that
    cannot both happen, and a tool that resolves that silently has decided
    something on their behalf and not told them.
    """
    from .connectors import registry as connector_registry
    from .connectors.model import ConnectorError, Http, OfflineError, stage

    if args.list_connectors:
        rows = [
            {
                "name": connector.name,
                "needs_network": connector.needs_network,
                "summary": catalog.line(connector.summary_key),
            }
            for connector in connector_registry.all_connectors()
        ]
        if args.json:
            print(json.dumps({"connectors": rows}, indent=2))
            return EXIT_OK
        print(catalog.line("discover.list_header"))
        for row in rows:
            network = catalog.line("discover.network" if row["needs_network"] else "discover.local")
            print(f"  {row['name']:<14} {network:<10} {row['summary']}")
        print(f"\n{len(rows)} " + catalog.line("discover.list_count"))
        return EXIT_OK

    if not args.uri:
        print(catalog.line("discover.no_uri"), file=sys.stderr)
        return EXIT_USAGE
    if args.fetch and args.out is None:
        print(catalog.line("discover.fetch_needs_out"), file=sys.stderr)
        return EXIT_USAGE
    if args.out is not None and not args.fetch:
        # The other half of the same contradiction. `--out` names a directory
        # to write artifacts into and nothing else writes there, so accepting
        # it silently would leave an operator waiting for files this command
        # was never going to produce.
        print(catalog.line("discover.out_needs_fetch"), file=sys.stderr)
        return EXIT_USAGE

    try:
        connector = connector_registry.for_uri(args.uri)
    except ConnectorError as exc:
        print(f"{exc}", file=sys.stderr)
        print(catalog.line("discover.try_list"), file=sys.stderr)
        return EXIT_USAGE

    if args.offline and connector.needs_network:
        # Refused before anything runs, so the message names the contradiction
        # rather than reporting it as a connector that happened to fail.
        print(catalog.line("discover.offline_refused", connector=connector.name), file=sys.stderr)
        return EXIT_USAGE

    http = Http(offline=args.offline)
    try:
        discovery = connector.discover(args.uri, http=http, revision=args.revision)
    except OfflineError as exc:
        print(f"{exc}", file=sys.stderr)
        return EXIT_USAGE
    except ConnectorError as exc:
        print(f"{exc}", file=sys.stderr)
        # The hosts are printed even when the listing failed. A run that
        # contacted three services and then gave up is a run whose operator
        # needs to know which three, especially if one of them was a redirect
        # they did not expect.
        if http.hosts:
            print(f"{catalog.line('discover.hosts')}: {', '.join(http.hosts)}", file=sys.stderr)
        return EXIT_FAIL

    staged: dict[str, Any] | None = None
    if args.fetch:
        if not connector.needs_network:
            # A local source is already local. Copying it into --out would
            # produce a second copy and a digest check against nothing, so the
            # command says what it did not do instead of doing something.
            staged = None
            local_only = True
        else:
            local_only = False
            staged = stage(discovery.artifacts, args.out, http, connector.fetch_headers)
    else:
        local_only = False

    if args.json:
        payload = discovery.to_dict()
        payload["connector"] = connector.name
        payload["fetched"] = staged
        payload["offline"] = args.offline
        # A consumer must be able to tell "no fetch was asked for" from "a
        # fetch was asked for and there was nothing to do", which a null
        # `fetched` on its own does not say.
        payload["fetch_skipped_source_is_local"] = local_only
        print(json.dumps(payload, indent=2))
    else:
        _print_discovery(discovery, connector, staged, local_only, catalog)

    problems = list((staged or {}).get("problems", []))
    if any(problem["rule"] == "ACT-CON-002" for problem in problems):
        return EXIT_FAIL
    if problems or not discovery.complete:
        return EXIT_INCONCLUSIVE
    return EXIT_OK


def _print_discovery(discovery, connector, staged, local_only: bool, catalog: Catalog) -> None:
    data = discovery.to_dict()
    print()
    print(f"{catalog.line('discover.source'):<14} {data['source']}")
    print(f"{catalog.line('discover.connector'):<14} {connector.name}")
    if data["revision"]:
        print(f"{catalog.line('discover.revision'):<14} {data['revision']}")
    print(f"{catalog.line('discover.artifacts'):<14} {data['count']}")
    # Two lines that print on every run, in every mode, because they are the
    # two facts this package exists to make impossible to miss: what was
    # contacted, and whether the listing can vouch for itself.
    print(
        f"{catalog.line('discover.listing'):<14} "
        f"{catalog.line('discover.complete' if data['listing_complete'] else 'discover.incomplete')}"
    )
    # Everything this run touched, not everything the listing touched. `stage`
    # reports the same client's cumulative host list, so a `--fetch` that
    # downloaded from a CDN the listing never mentioned shows the CDN. Printing
    # `discovery.hosts_contacted` here said "nothing was contacted" after a run
    # that had just pulled two hundred megabytes over the network, which is the
    # single claim this command exists to make correctly.
    contacted = (staged or {}).get("hosts_contacted") or data["hosts_contacted"]
    hosts = ", ".join(contacted) or catalog.line("discover.hosts_none")
    print(f"{catalog.line('discover.hosts'):<14} {hosts}")

    if data["notes"]:
        print(f"\n{catalog.line('discover.notes')}")
        for note in data["notes"]:
            print(f"  - {note}")

    if data["artifacts"]:
        print()
        for artifact in data["artifacts"]:
            size = "" if artifact["size_bytes"] is None else f"{artifact['size_bytes']:>12}"
            declared = artifact["declared_sha256"]
            digest = f"declared:{declared[:16]}" if declared else catalog.line("discover.no_digest")
            print(f"  {size:>12}  {digest:<28} {artifact['path']}")

    if local_only:
        print(f"\n{catalog.line('discover.local_no_fetch')}")
    if staged is not None:
        print()
        print(catalog.line(
            "discover.fetched",
            n=len(staged["fetched"]),
            seconds=staged["seconds"],
            requests=staged["requests"],
        ))
        for row in staged["fetched"]:
            confirmed = catalog.line(
                "discover.digest_confirmed" if row["digest_confirmed"] else "discover.digest_unchecked"
            )
            print(f"  {row['sha256'][:16]}  {confirmed:<22} {row['local']}")
        for problem in staged["problems"]:
            print(f"  x {problem['rule']}  {catalog.rule(problem['rule'])}  [{problem['path']}]")
            print(f"       {problem['detail']}")


# --------------------------------------------------------------------------
# `actaira policy`
# --------------------------------------------------------------------------


def _run_policy(args: argparse.Namespace, catalog: Catalog) -> int:
    from .policy import Decision, decide, load_policy
    from .policy.engine import Claims, PolicyError

    try:
        policy = load_policy(args.policy_file)
    except PolicyError as exc:
        # A policy that does not load is a usage error, never a warning and
        # never a default-allow. The alternative - carrying on with the rules
        # that happened to parse - is how a pipeline ends up governed by half
        # a document.
        print(f"{args.policy_file}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.policy_command == "show":
        if args.json:
            print(json.dumps(policy.to_dict(), ensure_ascii=False, indent=2))
        else:
            _print_policy(policy, catalog)
        return EXIT_OK

    on = args.on or _today()
    attestation = _attestation_claims(args)
    fail_on = Severity(args.fail_on)

    subjects: list[Claims] = []
    if getattr(args, "subjects_manifest", None) is not None:
        from .manifest import ManifestError

        try:
            subjects = _subjects_from_manifest(args.subjects_manifest, args, attestation, fail_on)
        except ManifestError as exc:
            print(f"{args.subjects_manifest}: {exc}", file=sys.stderr)
            return EXIT_USAGE

    if args.paths:
        artifacts, _ = discover(list(args.paths), recurse=not args.no_recurse)
        subjects.extend(
            Claims(
                inspect_artifact(record.path, scan_policy=args.policy, fail_on=fail_on),
                attestation=attestation,
            )
            for record in artifacts
        )

    if not subjects:
        print(catalog.line("policy.no_subjects"), file=sys.stderr)
        return EXIT_USAGE

    decision = decide(policy, subjects, on=on)

    document = decision.to_dict()
    _record_decision_in_state(args, decision, document, subjects)
    if args.out is not None:
        args.out.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    if args.json:
        print(json.dumps(document, ensure_ascii=False, indent=2))
    else:
        _print_decision(decision, catalog)

    return {
        Decision.ALLOW: EXIT_OK,
        Decision.DENY: EXIT_FAIL,
        Decision.REVIEW: EXIT_INCONCLUSIVE,
    }[decision.decision]


def _record_scans_in_state(args: argparse.Namespace, reports: list, catalog: Catalog) -> None:
    """File an `artifact_scan` record per scanned artifact, when asked to.

    Design note D-246. Three things this deliberately does not do.

    It does not create a store. `--state` names one that must already exist,
    because a scan that wrote `.actaira/` into whatever directory it ran in
    would be a tool taking a liberty with somebody's disk in exchange for a
    convenience nobody asked for.

    It does not fail the scan. A workspace that is missing, unreadable or at a
    newer schema version is reported on stderr and the findings still go to
    stdout with their own exit code: turning "the ledger was unavailable" into
    "the artifact was not inspected" would be the two worst answers swapped.

    And it does not invent an identity. `record.artifact_scan` binds to the
    asset this workspace already records for those exact bytes, and when there
    is none it writes nothing and says why - see `state/record.py` on what a
    basename-derived id would mean the first time two teams both have a
    `model.pt`.
    """
    if not getattr(args, "state", None):
        return
    from .state import record as record_mod
    from .state.store import Store, StoreError

    try:
        with Store(args.state, create=False) as store:
            written, skipped = 0, 0
            for report in reports:
                result = record_mod.artifact_scan(
                    store, report,
                    scan_policy=getattr(args, "policy", ""),
                    fail_on=str(getattr(args, "fail_on", "")),
                )
                if result.written:
                    written += 1
                else:
                    skipped += 1
                    print(
                        catalog.line("state.not_recorded", subject=Path(report.path).name,
                                     detail=result.note),
                        file=sys.stderr,
                    )
            if written:
                print(catalog.line("state.recorded", n=written, kind="artifact_scan"),
                      file=sys.stderr)
    except StoreError as exc:
        print(f"{exc}", file=sys.stderr)


def _record_agent_assessment_in_state(
    args: argparse.Namespace, agent, findings: list, catalog: Catalog
) -> None:
    """File one `agent_assessment` record about one exact declared shape.

    Bound to `Agent.digest`, which is what makes the record answerable later:
    "was this produced about the agent in front of me?" is one string
    comparison, and an assessment bound to the agent's name would answer yes
    for a declaration that had since gained a shell tool.

    The attack-path search runs here because the record is about the whole
    assessment and a record carrying capability findings without route counts
    would be half an answer filed as a whole one. It is the same search
    `agent paths` runs, from the same module, over the same declaration.
    """
    if not getattr(args, "state", None):
        return
    from .agentgov import paths as path_engine
    from .state import record as record_mod
    from .state.store import Store, StoreError

    try:
        with Store(args.state, create=False) as store:
            result = record_mod.agent_assessment(
                store, agent, findings, path_engine.find(agent),
                fail_on=str(getattr(args, "fail_on", "")),
            )
            if result.written:
                print(catalog.line("state.recorded", n=1, kind="agent_assessment"),
                      file=sys.stderr)
            else:
                print(
                    catalog.line("state.not_recorded", subject=agent.name, detail=result.note),
                    file=sys.stderr,
                )
    except StoreError as exc:
        print(f"{exc}", file=sys.stderr)


def _record_decision_in_state(
    args: argparse.Namespace, decision, document: dict, subjects: list | None = None
) -> None:
    """Record a decision in the store, when there is a store.

    Design note D-233. `state-export/v1` publishes a `decisions` array and the
    store has had `policies` and `decisions` tables since 2.2.0, and nothing
    ever wrote to any of them: `record_decision` existed and had no caller, so
    every export carried an empty array that could never be anything else.

    The identifier is the digest of the canonical decision document, which
    makes the write idempotent: deciding twice about the same subjects under
    the same policy on the same date records one row, and a store is not a log
    of how many times CI ran.
    """
    if not getattr(args, "state", None):
        return
    import hashlib

    from .state.store import Store, StoreError

    canonical = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    proof_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    try:
        with Store(args.state, create=False) as store:
            from .state import record as record_mod

            # `decision_inputs` excludes `policy_decision` records by kind,
            # so the order of these three statements is not load-bearing - and
            # it was, until deciding twice about one subject showed the second
            # decision recording the first one's note as an input.
            inputs = record_mod.decision_inputs(store, subjects or [])
            store.record_decision(decision, proof_digest, inputs)
            record_mod.policy_decision(store, decision, proof_digest, subjects or [])
    except StoreError as exc:
        # The decision stands whether or not it could be filed. Failing here
        # would turn "the store is missing" into "the policy did not decide",
        # and those are not the same answer.
        print(f"{exc}", file=sys.stderr)


def _subjects_from_manifest(path: Path, args, attestation, fail_on) -> list:
    """Turn a manifest into typed claims, one loader per kind.

    Design note D-213. Every kind is loaded by the module that already knows
    how, so this function is a dispatch table and not a second parser: the
    place where a bundle's semantics live is `bundle.py`, and a manifest
    reader that reimplemented any of it would be a second copy of the same
    facts.
    """
    from . import manifest as manifest_mod
    from . import subject as subject_mod
    from .agentgov import load as load_agent
    from .bundle import resolve as resolve_bundle
    from .subject import SubjectKind

    document = manifest_mod.load(path)

    def subject_path(entry: manifest_mod.Entry) -> Path:
        """The path an artifact, bundle or agent entry is guaranteed to carry.

        `manifest.load` refuses a manifest whose artifact, bundle or agent
        entry has no `path:`, so by the time this runs the invariant holds.
        Asserting it here rather than assuming it means a future loader that
        stopped enforcing it fails on the spot instead of handing None to a
        reader that expected a file.
        """
        if entry.path is None:
            raise manifest_mod.ManifestError(
                f"a {entry.kind.value} entry reached the runner with no path"
            )
        return entry.path

    claims: list = []
    for entry in document.entries:
        if entry.kind is SubjectKind.ARTIFACT:
            report = inspect_artifact(subject_path(entry), scan_policy=args.policy, fail_on=fail_on)
            claims.append(
                subject_mod.for_artifact(report, attestation=attestation, facts=entry.facts)
            )
        elif entry.kind is SubjectKind.BUNDLE:
            bundle = resolve_bundle(
                subject_path(entry),
                hash_weights=entry.hash_weights,
                source_uri=entry.uri,
                source_revision=entry.revision,
                connector=entry.connector,
            )
            claims.append(
                subject_mod.for_bundle(
                    bundle,
                    attestation=attestation,
                    facts=entry.facts,
                    provenance={
                        key: value
                        for key, value in (
                            ("uri", entry.uri),
                            ("revision", entry.revision),
                            ("connector", entry.connector),
                        )
                        if value
                    },
                )
            )
        elif entry.kind is SubjectKind.AGENT:
            claims.append(
                subject_mod.for_agent(
                    load_agent(subject_path(entry)), attestation=attestation, facts=entry.facts
                )
            )
        elif entry.kind is SubjectKind.SOURCE:
            claims.append(
                subject_mod.for_source(
                    entry.uri, entry.revision, entry.connector, facts=entry.facts
                )
            )
        else:
            claims.append(subject_mod.for_system(entry.name or document.system, facts=entry.facts))
    return claims


def _attestation_claims(args: argparse.Namespace) -> dict[str, Any] | None:
    """Verify a package, if one was given, and reduce it to what a policy sees.

    Two separate booleans, kept separate. `signature_verified` says the bytes
    were not altered; `signer_trusted` says the key belongs to someone this
    environment accepts. A policy that wants both has to ask for both, and one
    that asks for a trust decision nobody made gets REVIEW rather than a
    silent pass.
    """
    package_path = getattr(args, "attestation", None)
    if package_path is None:
        return None
    result = verify_mod.verify_package(
        package_path,
        trusted_keyring=getattr(args, "trusted_keyring", None),
        require_trust=False,
        tsa_trust_store=getattr(args, "tsa_trust_store", None),
    )
    payload = result.to_dict()
    claims: dict[str, Any] = {"signature_verified": bool(payload.get("ok"))}

    # `trust_state` has three values, and only one of them is a yes:
    # "trusted" when a supplied anchor matched, "untrusted" when one was
    # supplied and did not, "embedded_key_only" when none was supplied at all.
    # The third is the case the policy layer must not see as False: nobody
    # vouched for the key, which is not the same as somebody declining to.
    # Reading a field name that does not exist and defaulting it to False -
    # which the first version of this function did - turned every run with a
    # keyring into a DENY, and the printout said `signer_trusted: actual
    # false` beside a package the verifier had just called trusted.
    state = str(payload.get("trust_state", "unverified"))
    if state == "trusted":
        claims["signer_trusted"] = True
    elif state == "untrusted":
        claims["signer_trusted"] = False
    # "embedded_key_only" and "unverified" leave the key out, so the predicate
    # raises Unevaluable and the rule becomes REVIEW rather than a refusal.

    timestamp_block = payload.get("timestamp") or {}
    if isinstance(timestamp_block, dict) and timestamp_block.get("tsa_chain"):
        claims["time_anchor_trust"] = timestamp_block["tsa_chain"]
    return claims


def _print_policy(policy, catalog: Catalog) -> None:
    print(f"{policy.id}  v{policy.version}")
    print(f"digest  {policy.digest}")
    if policy.description:
        print(f"        {policy.description}")
    print()
    for rule in policy.rules:
        print(f"  [{rule.effect.value:<7}] {rule.id}")
        for name, argument in sorted(rule.when.items()):
            print(f"            {name}: {json.dumps(argument, ensure_ascii=False)}")
    if policy.exceptions:
        print()
        for exception in policy.exceptions:
            print(
                f"  [waiver ] {exception.rule} until {exception.expires.isoformat()} "
                f"({exception.owner}: {exception.reason})"
            )


_DECISION_MARK = {"allow": "+", "deny": "x", "review": "?"}


def _print_decision(decision, catalog: Catalog) -> None:
    print()
    print(f"{decision.decision.value.upper():9} {decision.policy_id} v{decision.policy_version}")
    print(f"          {catalog.line('policy.digest')}: {decision.policy_digest}")
    print(f"          {catalog.line('policy.decided_on')}: {decision.decided_on.isoformat()}")
    print()
    # The reasons first, then the full proof. A proof tree with forty
    # satisfied rules and one refusal is complete and unreadable; a reader
    # needs the refusal, and then the ability to check the rest.
    if decision.reasons:
        print(f"  {catalog.line('policy.because')}")
        for outcome in decision.reasons:
            mark = _DECISION_MARK[outcome.contributes.value]
            print(f"    {mark} {outcome.rule_id}  [{outcome.effect.value}]  {outcome.subject[:23]}")
            if outcome.note:
                print(f"        {outcome.note}")
            for name, detail in sorted(outcome.evidence.items()):
                print(f"        {name}: {json.dumps(detail, ensure_ascii=False)}")
    else:
        print(f"  {catalog.line('policy.every_rule_satisfied')}")

    print()
    print(f"  {catalog.line('policy.proof')}")
    # Grouped by subject, not by rule. A flat list repeats every rule id once
    # per artifact and a reader cannot tell which of two identical lines was
    # the one that denied: the proof becomes unreadable at exactly the moment
    # it matters, which is a scan over more than one file.
    by_subject: dict[str, list] = {}
    for outcome in decision.outcomes:
        by_subject.setdefault(outcome.subject, []).append(outcome)
    for subject, outcomes in by_subject.items():
        print(f"    {subject}")
        for outcome in outcomes:
            mark = _DECISION_MARK[outcome.contributes.value]
            waived = f"  ({catalog.line('policy.waived')})" if outcome.waived_by else ""
            print(f"      {mark} {outcome.rule_id:<40} {outcome.contributes.value}{waived}")

    for expired in decision.expired_exceptions:
        print()
        print(
            f"  {catalog.line('policy.exception_expired', rule=expired['rule'], on=expired['expires'], owner=expired['owner'])}"
        )


# --------------------------------------------------------------------------
# `actaira receipt`
# --------------------------------------------------------------------------


def _run_receipt(args: argparse.Namespace, catalog: Catalog) -> int:
    from . import receipt as receipt_mod

    if args.receipt_command == "verify":
        return _verify_receipt(args, catalog, receipt_mod)
    return _issue_receipt(args, catalog, receipt_mod)


def _issue_receipt(args: argparse.Namespace, catalog: Catalog, receipt_mod) -> int:
    from datetime import UTC, datetime

    from .policy import decide, load_policy
    from .policy.engine import Claims, PolicyError

    fail_on = Severity(args.fail_on)
    attestation = _attestation_claims(args)

    typed: list[Claims] = []
    if getattr(args, "subjects_manifest", None) is not None:
        from .manifest import ManifestError

        try:
            typed = _subjects_from_manifest(args.subjects_manifest, args, attestation, fail_on)
        except ManifestError as exc:
            print(f"{args.subjects_manifest}: {exc}", file=sys.stderr)
            return EXIT_USAGE

    reports = []
    if args.paths:
        artifacts, _ = discover(list(args.paths), recurse=not args.no_recurse)
        reports = [
            inspect_artifact(record.path, scan_policy=args.policy, fail_on=fail_on)
            for record in artifacts
        ]
    # An artifact named on the command line and one named in a manifest are
    # the same kind of subject, so they end up in one list rather than two.
    # A receipt that described the same artifact twice under two headings
    # would be a document about one thing that read as a document about two.
    from . import subject as subject_mod

    named = {claims.subject for claims in typed}
    typed.extend(
        claims
        for claims in (subject_mod.for_artifact(report, attestation=attestation) for report in reports)
        if claims.subject not in named
    )

    if not typed:
        print(catalog.line("policy.no_subjects"), file=sys.stderr)
        return EXIT_USAGE

    # `reports` stays the artifact-shaped view the v1 fields are built from,
    # so a v2 receipt over an artifact is byte-identical to a v1 one in every
    # field v1 had.
    reports = [claims.report for claims in typed if claims.report is not None]

    decision_document = None
    decision = None
    if args.policy_file is not None:
        try:
            policy = load_policy(args.policy_file)
        except PolicyError as exc:
            print(f"{args.policy_file}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        on = args.on or _today()
        decision = decide(policy, typed, on=on)
        decision_document = decision.to_dict()

    evidence_rows, snapshot_rows, graph_document = _state_for_receipt(args, typed)

    document = receipt_mod.build(
        reports,
        observed_at=datetime.now(UTC),
        policy_decision=decision_document,
        attestation=attestation,
        system=args.system,
        subjects=typed,
        evidence=evidence_rows,
        snapshots=snapshot_rows,
        graph=graph_document,
    )
    keypair, created = signing.load_or_create(args.key)
    signed = receipt_mod.sign(document, keypair)
    args.out.write_text(json.dumps(signed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    _record_receipt_in_state(args, signed, keypair)

    print()
    print(catalog.line("receipt.issued", path=str(args.out)))
    print(f"          {catalog.line('receipt.digest')}: {signed['signature']['receipt_sha256']}")
    print(f"          {catalog.line('receipt.key')}: {keypair.fingerprint}")
    if created:
        print(f"          {catalog.line('key.created', path=str(args.key))}")
    print(f"          {catalog.line('receipt.subjects', n=len(typed))}")
    for row in document.get("typed_subjects", []):
        print(f"          . {row['handle']}")
    for row in document["states_what_it_does_not_cover"]:
        surface = catalog.line(f"coverage.surface.{row['surface']}")
        state = catalog.line(f"coverage.state.{row['state']}")
        reason = catalog.line(f"coverage.reason.{row['reason']}")
        print(f"          . {surface}: {state} - {reason}")

    if decision is None:
        return EXIT_OK
    from .policy import Decision

    return {
        Decision.ALLOW: EXIT_OK,
        Decision.DENY: EXIT_FAIL,
        Decision.REVIEW: EXIT_INCONCLUSIVE,
    }[decision.decision]


def _state_for_receipt(args: argparse.Namespace, typed: list) -> tuple[list, list, dict | None]:
    """The evidence, snapshots and graph a receipt may reference, when there is a store.

    Optional in both directions. A workspace with no `.actaira/` issues a
    receipt with no references, which is what 2.1 did and remains correct; one
    with a store gets a receipt that can be checked against it later. What it
    never does is embed the records - see `receipt._typed_subjects` on why a
    copy inside a signed document is a second version that can disagree with
    the first.
    """
    if not getattr(args, "state", None):
        return [], [], None
    import json as json_mod

    from .state import graph as graph_mod
    from .state.store import Store, StoreError

    try:
        with Store(args.state, create=False) as store:
            # Defect DEF-115. This used to match a record's `subject_id`
            # against the subject's HANDLE - `artifact:model.pkl` - and
            # against `claims.subject`, which for an artifact is its digest.
            # Nothing is ever filed under either. `watch` files per-artifact
            # evidence under the id it derives from the artifact's URI, and
            # `state.record` files scans and assessments under the same one,
            # so the two sets never intersected and the `evidence` array of
            # every receipt ever issued from a workspace was empty. A
            # published field that cannot be populated is a claim the tool
            # does not keep - the third time this exact shape has been found
            # here, after `decisions` and `receipts` in D-233.
            #
            # `record.resolve` is the function that already answers "which
            # recorded asset is this subject", by digest first and by handle
            # second, and it is the one the producers use. Using it here is
            # what makes the two ends agree.
            from .state import record as record_mod

            wanted = set()
            for claims in typed:
                reference = claims.ref
                if reference is None:
                    continue
                wanted.add(reference.handle)
                wanted.add(claims.subject)
                identity = record_mod.resolve(
                    store, digest=reference.digest or "", handle=reference.handle
                )
                if identity.known:
                    wanted.add(identity.asset_id)
            evidence = [row for row in store.all_evidence() if row["subject_id"] in wanted]
            # One query per source, not two. The comprehension this replaces
            # called `latest_snapshot` in the guard and again in the value, so
            # every source was read twice and the type checker could not see
            # that the second call was the one the guard had proved non-None.
            snapshots = []
            for source in store.sources():
                latest = store.latest_snapshot(source["source_id"])
                if latest is not None:
                    snapshots.append(json_mod.loads(latest["document"]))
            return evidence, snapshots, graph_mod.Graph.from_store(store).to_dict()
    except StoreError as exc:
        print(f"{exc}", file=sys.stderr)
        return [], [], None


def _record_receipt_in_state(args: argparse.Namespace, signed: dict, keypair) -> None:
    """Note in the store that this receipt was issued, when there is a store.

    Design note D-233. `state-export/v1` publishes a `receipts` array and the
    store has had a `receipts` table since 2.2.0, and nothing ever wrote to
    either: `record_receipt` existed and had no caller, so every state export
    ever produced carried an empty array that could never be anything else. A
    published contract with a field that cannot be populated is a claim the
    tool does not keep, and the fix is the write rather than removing the
    field, because a v1 consumer already reads it.

    Only the digest, the path, the signer and the time. The document itself
    stays where it was written: a copy inside the store would be a second
    version of a signed document that can disagree with the first, which is
    the argument `receipt._typed_subjects` opens with.
    """
    if not getattr(args, "state", None):
        return
    from .state.store import Store, StoreError

    try:
        with Store(args.state, create=False) as store:
            store.record_receipt(
                receipt_digest=signed["signature"]["receipt_sha256"],
                path=str(args.out),
                signer=keypair.fingerprint,
                observed_at=signed.get("observed_at", ""),
            )
    except StoreError as exc:
        # The receipt is already written and valid. Failing the command here
        # would throw away a good document because a note about it could not
        # be filed.
        print(f"{exc}", file=sys.stderr)


def _verify_receipt(args: argparse.Namespace, catalog: Catalog, receipt_mod) -> int:
    try:
        document = json.loads(args.receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"{args.receipt}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    anchors = None
    if args.trusted_keyring is not None:
        # Every key in the ring, retired ones included. Retirement means "stop
        # signing with this", not "every signature it ever made is now
        # worthless": treating a retired fingerprint as an unknown one would
        # invalidate the entire history on the day a key was rotated, which is
        # the argument keyring.py opens with.
        ring = keyring.Keyring.load(args.trusted_keyring)
        anchors = {record.fingerprint_sha256 for record in ring.keys if record.fingerprint_sha256}

    result = receipt_mod.verify(document, trusted_fingerprints=anchors)

    if args.against:
        reports = [inspect_artifact(path) for path in args.against]
        for problem in receipt_mod.subject_digests_match(document, reports):
            result.fail(problem)

    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        return EXIT_OK if result.ok else EXIT_FAIL

    print()
    print(f"{'OK' if result.ok else 'PROBLEM':9} {args.receipt}")
    print(f"          {catalog.line('receipt.digest')}: {result.receipt_sha256}")
    print(f"          {catalog.line('receipt.signature')}: "
          f"{catalog.line('receipt.verified' if result.signature_verified else 'receipt.not_verified')}")
    if result.signer_trusted is None:
        # The third state, printed as a third state. A reader who sees only
        # "signature: verified" will read it as "trusted", and that is the
        # confusion the whole layer exists to prevent.
        print(f"          {catalog.line('receipt.signer')}: {catalog.line('receipt.no_anchor')}")
    else:
        print(f"          {catalog.line('receipt.signer')}: "
              f"{catalog.line('receipt.trusted' if result.signer_trusted else 'receipt.untrusted')}")
    print(f"          {catalog.line('receipt.key')}: {result.key_fingerprint}")
    if result.decision:
        print(f"          {catalog.line('receipt.decision')}: {result.decision.upper()}")
    for problem in result.problems:
        print(f"          ! {problem}")
    return EXIT_OK if result.ok else EXIT_FAIL


# --------------------------------------------------------------------------
# `actaira bundle` and `actaira agent`
# --------------------------------------------------------------------------


def _run_bundle(args: argparse.Namespace, catalog: Catalog) -> int:
    """`actaira bundle`, over a local directory or a remote source.

    Design note D-229. The two used to be different commands' jobs and the
    join is what makes a bundle report auditable: a resolution of a remote
    repository carries the URI and the revision it came from, so a receipt
    about it names a published model rather than a directory on a laptop.
    """
    import tempfile

    from .bundle import looks_like_bundle, resolve

    root = Path(args.root)
    remote = not root.exists() and "://" in str(args.root)

    if remote:
        return _run_remote_bundle(args, catalog)

    if args.revision:
        # Refused rather than ignored, for the reason every other contradiction
        # in this CLI is refused: the operator asked for two things that cannot
        # both happen, and resolving it silently decides on their behalf.
        print(catalog.line("bundle.revision_needs_uri"), file=sys.stderr)
        return EXIT_USAGE

    if not root.is_dir():
        print(catalog.line("bundle.not_a_directory", path=str(root)), file=sys.stderr)
        return EXIT_USAGE
    if not looks_like_bundle(root):
        # Not refused: a directory of weights with no config is still a thing
        # somebody wants resolved. But saying so matters, because the
        # relations this command reads all come from the metadata files, and
        # a bundle report over a directory with none of them is a list.
        print(catalog.line("bundle.no_markers", path=str(root)), file=sys.stderr)

    bundle = resolve(root, hash_weights=getattr(args, "hash_weights", False))
    del tempfile
    document = bundle.to_dict()
    if args.out is not None:
        args.out.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    if args.json:
        print(json.dumps(document, ensure_ascii=False, indent=2))
        return EXIT_FAIL if bundle.findings else EXIT_OK

    _print_bundle(bundle, document, catalog, source=str(root))
    return EXIT_FAIL if any(f.severity.rank >= Severity.HIGH.rank for f in bundle.findings) else EXIT_OK


def _print_bundle(bundle, document: dict, catalog: Catalog, *, source: str, revision: str = "") -> None:
    print()
    print(f"{source}")
    if revision:
        print(f"  {catalog.line('bundle.revision')}: {revision}")
    identity = document["content_identity"]
    print(f"  {catalog.line('bundle.structural_digest')}: {bundle.structural_digest}")
    # Two lines, never one. The structural digest and the identity of the
    # weights are different facts and the first is the one a reader will take
    # for the second if they are printed as a single "digest" row - which is
    # precisely the confusion D-200 is about.
    print(
        f"  {catalog.line('bundle.content_identity')}: "
        f"{catalog.line('bundle.identity.' + identity['state'])}"
    )
    if identity["digest"]:
        print(f"       {identity['digest']}")
    if identity.get("capped_because"):
        print(f"       {identity['capped_because']}")
    if identity["members_unidentified"]:
        print(
            f"       {catalog.line('bundle.identity.unidentified', n=identity['members_unidentified'])}"
        )
    if identity.get("declared_by"):
        print(
            f"       {catalog.line('bundle.identity.declared_by', who=', '.join(identity['declared_by']))}"
        )
    print(f"  {catalog.line('bundle.members', n=len(bundle.members))}")
    if bundle.architectures:
        print(f"  {catalog.line('bundle.architectures')}: {', '.join(bundle.architectures)}")
    if bundle.base_model:
        print(f"  {catalog.line('bundle.base_model')}: {bundle.base_model}")
    for name, shard in bundle.shards.items():
        print(f"  {name}: {catalog.line('bundle.shards', promised=len(shard['promised']), missing=len(shard['missing']), unlisted=len(shard['unlisted']))}")
    print()
    for finding in sorted(bundle.findings, key=lambda item: -item.severity.rank):
        mark = _SEVERITY_MARK[finding.severity]
        print(f"  {mark} {finding.rule_id}  {catalog.rule(finding.rule_id)}")
        print(f"       {json.dumps(finding.evidence, ensure_ascii=False)}")
    if not bundle.findings:
        print(f"  {catalog.line('bundle.nothing')}")


def _run_remote_bundle(args: argparse.Namespace, catalog: Catalog) -> int:
    """Fetch, resolve and report, keeping the provenance in the document."""
    import tempfile

    from . import remote as remote_mod

    staged = args.stage_to
    temporary = None
    if staged is None:
        temporary = tempfile.TemporaryDirectory(prefix="actaira-bundle-")
        staged = Path(temporary.name)
    try:
        fetched = remote_mod.fetch(
            str(args.root),
            revision=args.revision,
            destination=Path(staged),
            offline=args.offline,
            cache=args.cache,
        )
    except remote_mod.RemoteBundleError as exc:
        print(f"{exc}", file=sys.stderr)
        if temporary is not None:
            temporary.cleanup()
        return EXIT_USAGE

    try:
        bundle = remote_mod.resolve_remote(fetched, hash_weights=getattr(args, "hash_weights", False))
        document = bundle.to_dict()
        # The cap, applied where a reader will see it. A repository assembled
        # from half a listing must not report `complete`, however thoroughly
        # the half that arrived was hashed.
        document["content_identity"] = remote_mod.capped_identity(bundle, fetched.listing_complete)
        if fetched.hosts_contacted:
            document["provenance"]["hosts_contacted"] = sorted(set(fetched.hosts_contacted))
        if fetched.from_cache:
            document["provenance"]["served_from_cache"] = True
        if fetched.notes:
            # Everything the connector said. A remark like "--revision was
            # ignored" reaching nobody is how a local directory ends up in a
            # document that reads as a pinned remote model (DEF-86).
            document["provenance"]["connector_notes"] = list(fetched.notes)

        if args.out is not None:
            args.out.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        if args.json:
            print(json.dumps(document, ensure_ascii=False, indent=2))
        else:
            _print_bundle(bundle, document, catalog, source=str(args.root), revision=fetched.revision)
    finally:
        if temporary is not None:
            temporary.cleanup()

    if not fetched.listing_complete:
        return EXIT_INCONCLUSIVE
    return EXIT_FAIL if any(f.severity.rank >= Severity.HIGH.rank for f in bundle.findings) else EXIT_OK


def _run_agent(args: argparse.Namespace, catalog: Catalog) -> int:
    from .agentgov import DeclarationError, assess, load
    from .agentgov.model import diff as agent_diff

    resolved: dict = {}
    try:
        if args.agent_command == "diff":
            before = load(args.before)
            after = load(args.after)
        else:
            agent = load(args.declaration)
        if args.agent_command == "paths":
            for path in args.sub_agents:
                delegate = load(path)
                resolved[delegate.name] = delegate
    except DeclarationError as exc:
        print(f"{exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.agent_command == "paths":
        return _run_agent_paths(args, catalog, agent, resolved)

    if args.agent_command == "bom":
        document = agent.to_bom()
        document["agent_digest"] = agent.digest
        blob = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
        if args.out is not None:
            args.out.write_text(blob, encoding="utf-8", newline="\n")
        else:
            print(blob, end="")
        return EXIT_OK

    if args.agent_command == "diff":
        document = agent_diff(before, after)
        if args.json:
            print(json.dumps(document, ensure_ascii=False, indent=2))
        else:
            _print_agent_diff(document, catalog)
        # Gaining a capability is the thing a change review exists to catch,
        # so it exits non-zero: a diff that always exited 0 would be a diff
        # nobody wired into anything.
        return EXIT_FAIL if document["effects_gained"] or document["tools_added"] else EXIT_OK

    findings = assess(agent)
    _record_agent_assessment_in_state(args, agent, findings, catalog)
    if args.json:
        print(json.dumps(
            {
                "agent": agent.name,
                "agent_digest": agent.digest,
                "findings": [finding.to_dict() for finding in findings],
            },
            ensure_ascii=False,
            indent=2,
        ))
    else:
        print()
        print(f"{agent.name}  {agent.version}")
        print(f"  {catalog.line('agent.digest')}: {agent.digest}")
        print(f"  {catalog.line('agent.effects')}: {', '.join(sorted(e.value for e in agent.effects))}")
        print()
        for finding in sorted(findings, key=lambda item: -item.severity.rank):
            mark = _SEVERITY_MARK[finding.severity]
            print(f"  {mark} {finding.rule_id}  {catalog.rule(finding.rule_id)}")
            for key, value in finding.evidence.items():
                print(f"       {key}: {json.dumps(value, ensure_ascii=False)}")
        if not findings:
            print(f"  {catalog.line('agent.nothing')}")

    threshold = Severity(args.fail_on)
    return EXIT_FAIL if any(f.severity.rank >= threshold.rank for f in findings) else EXIT_OK


_LIST_SECTIONS = (
    "tools_added", "tools_removed", "effects_gained", "effects_lost",
    "mcp_added", "mcp_removed",
    "identities_added", "identities_removed",
    "data_sources_added", "data_sources_removed",
    "sub_agents_added", "sub_agents_removed",
)

# Which sections are rendered as "name: from -> to" rows, and which fields of
# each carry a before/after pair. Written as data because the alternative is
# eighteen near-identical print statements, and eighteen near-identical print
# statements are where the seventeenth one gets forgotten.
_CHANGE_SECTIONS = (
    ("mcp_changed", ("reference", "digest", "publisher", "transport", "pinned")),
    ("identities_changed", ("kind", "expires")),
    ("data_sources_changed", ("classification", "access", "trusted")),
    ("sub_agents_changed", ("digest", "reference", "declaration")),
)


def _run_agent_paths(args: argparse.Namespace, catalog: Catalog, agent, resolved: dict) -> int:
    """Routes, not combinations. Design note D-210.

    The output leads with the open routes because those are the ones nothing
    stops. Closed ones are printed under `--show-closed`, and they are worth
    printing: an operator who removes an approval next quarter should be able
    to find out what it was holding up.
    """
    from .agentgov import paths as path_engine

    report = path_engine.find(agent, resolved)
    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print()
        print(f"{agent.name}  {agent.version}")
        if len(report.contexts) > 1:
            print(f"  {catalog.line('paths.contexts', names=', '.join(report.contexts))}")
        if report.unresolved_sub_agents:
            # Not silence. A delegation nobody resolved is a hole in the
            # answer, and an answer with a hole in it has to say so.
            print(
                f"  {catalog.line('paths.unresolved', names=', '.join(report.unresolved_sub_agents))}"
            )
        for cycle in report.cycles:
            print(f"  {catalog.line('paths.cycle', route=' -> '.join(cycle))}")
        print()

        shown = report.paths if args.show_closed else report.open_paths
        if not shown:
            print(f"  {catalog.line('paths.none')}")
        for path in shown:
            mark = _SEVERITY_MARK[path.severity]
            state = "" if not path.broken else f"  [{catalog.line('paths.closed')}]"
            print(f"  {mark} {path.rule_id}  {catalog.rule(path.rule_id)}{state}")
            for index, hop in enumerate(path.hops):
                lead = "     " if index == 0 else "       -> "
                print(f"{lead}{hop.node}  ({hop.label})")
            print(f"       {catalog.line('paths.carries', what=path.carries)}")
            if path.closed_by:
                for reason in path.closed_by:
                    print(f"       + {reason}")
            else:
                print(f"       {catalog.line('paths.break_by')}")
                for reason in path.break_path_by:
                    print(f"         - {reason}")
            for entry in path.present_but_ineffective:
                print(f"       ! {entry['mitigation']}: {entry['why']}")
            print()

        closed = len(report.paths) - len(report.open_paths)
        print(f"  {catalog.line('paths.summary', open=len(report.open_paths), closed=closed)}")

    threshold = Severity(args.fail_on)
    return (
        EXIT_FAIL
        if any(path.severity.rank >= threshold.rank for path in report.open_paths)
        else EXIT_OK
    )


def _print_agent_diff(document: dict, catalog: Catalog) -> None:
    print()
    print(f"{document['agent']}")
    print(f"  {document['from_digest']}")
    print(f"  {document['to_digest']}")
    print()

    # Risk-increasing first. Everything in it appears again below in its own
    # section, so this is an ordering rather than a filter - a reader who
    # reads only the top of the output sees the changes that widen what the
    # agent can do, and a reader who reads all of it misses nothing.
    if document.get("risk_increasing"):
        print(f"  {catalog.line('agent.diff.risk_increasing')}")
        for reason in document["risk_increasing"]:
            print(f"    ! {reason}")
        print()

    for key in _LIST_SECTIONS:
        if document.get(key):
            print(f"  {catalog.line('agent.diff.' + key)}: {', '.join(document[key])}")

    for change in document["tools_changed"]:
        if change["effects_gained"]:
            print(f"  {catalog.line('agent.diff.tool_gained', tool=change['name'], effects=', '.join(change['effects_gained']))}")
        if change["effects_lost"]:
            print(f"  {catalog.line('agent.diff.tool_lost', tool=change['name'], effects=', '.join(change['effects_lost']))}")
        for field in ("identity", "requires_approval", "served_by", "schema_sha256", "environment"):
            if field in change:
                print(f"  {change['name']}.{field}: {change[field]['from']!r} -> {change[field]['to']!r}")
        for field in ("scopes", "inputs", "outputs"):
            for suffix, arrow in (("_added", "+"), ("_removed", "-")):
                if change.get(field + suffix):
                    print(f"  {change['name']}.{field} {arrow} {', '.join(change[field + suffix])}")

    for section, fields in _CHANGE_SECTIONS:
        for change in document.get(section, []):
            print(f"  {catalog.line('agent.diff.' + section)}: {change['name']}")
            for field in fields:
                if field in change:
                    print(f"    {field}: {change[field]['from']!r} -> {change[field]['to']!r}")
            for field in ("tools_added", "tools_removed", "scopes_added", "scopes_removed"):
                if change.get(field):
                    print(f"    {field}: {', '.join(change[field])}")

    for change in document.get("metadata_changed", []):
        print(
            f"  {catalog.line('agent.diff.metadata_changed')}: "
            f"{change['field']} {change['from']!r} -> {change['to']!r} ({change['risk']})"
        )

    if document["model_changed"]:
        print(f"  {catalog.line('agent.diff.model_changed')}")
    if document["prompt_changed"]:
        print(f"  {catalog.line('agent.diff.prompt_changed')}")

    # The line that stops this command from being useless in its worst case.
    # A digest that moved with every section empty means the diff missed
    # something, and saying so is the only honest output: a reader who saw
    # two digests and no explanation would reasonably conclude nothing
    # relevant changed.
    if not document.get("explains_digest_change", True):
        print()
        print(f"  {catalog.line('agent.diff.unexplained')}")


# At the bottom, and it matters that it is at the bottom. Defect DEF-67: this
# guard had drifted into the middle of the file, so `python -m actaira.cli`
# executed `main()` while the module was still being defined and died with
# `NameError: _run_agent`. The console entry point in pyproject.toml calls
# `actaira.cli:main` after the import finishes, so the installed command was
# fine and the documented alternative was not.
if __name__ == "__main__":
    raise SystemExit(main())
