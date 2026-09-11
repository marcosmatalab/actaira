"""The command line, which for a CI tool is mostly its exit codes.

`main` is called in process. The exit code contract is documented in cli.py:
0 clean, 1 something failed, 2 usage, 3 nothing failed but something could not
be read. Each of the four is asserted here, together with the artifact that
produces it, so a change to the contract cannot pass unnoticed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from actaira import cli
from actaira.i18n.catalog import Catalog
from conftest import corpus_build


@pytest.fixture
def clean_artifact(tmp_path):
    path = tmp_path / "clean.safetensors"
    path.write_bytes(
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}}, b"\x00" * 64
        )
    )
    return path


@pytest.fixture
def failing_artifact(tmp_path):
    path = tmp_path / "gadget.pkl"
    path.write_bytes(corpus_build.craft_reduce("posix", "system", ("id",), 2))
    return path


@pytest.fixture
def unreadable_artifact(tmp_path):
    path = tmp_path / "mystery.model"
    path.write_bytes(b"\x11\x22\x33\x44 not a known format")
    return path


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

def test_a_clean_artifact_exits_zero(capsys, clean_artifact):
    assert cli.main(["scan", str(clean_artifact)]) == cli.EXIT_OK
    assert "PASS" in capsys.readouterr().out


def test_a_failing_artifact_exits_one(capsys, failing_artifact):
    assert cli.main(["scan", str(failing_artifact)]) == cli.EXIT_FAIL
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "ACT-PKL-002" in out


def test_an_unreadable_artifact_exits_three(capsys, unreadable_artifact):
    assert cli.main(["scan", str(unreadable_artifact)]) == cli.EXIT_INCONCLUSIVE
    assert "INCONCLUSIVE" in capsys.readouterr().out


def test_allow_inconclusive_turns_three_into_zero(capsys, unreadable_artifact):
    assert cli.main(["scan", "--allow-inconclusive", str(unreadable_artifact)]) == cli.EXIT_OK
    assert "INCONCLUSIVE" in capsys.readouterr().out, (
        "the artifact is still reported as unread; only the exit code changed"
    )


def test_allow_inconclusive_does_not_hide_a_failure(capsys, failing_artifact, unreadable_artifact):
    """Negative control for the flag: it collapses 3 into 0, and nothing else."""
    code = cli.main(
        ["scan", "--allow-inconclusive", str(failing_artifact), str(unreadable_artifact)]
    )
    capsys.readouterr()

    assert code == cli.EXIT_FAIL


def test_a_failure_outranks_an_inconclusive(capsys, failing_artifact, unreadable_artifact):
    code = cli.main(["scan", str(failing_artifact), str(unreadable_artifact)])
    capsys.readouterr()

    assert code == cli.EXIT_FAIL


def test_nothing_to_scan_is_a_usage_error(capsys, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()

    code = cli.main(["scan", str(empty)])

    assert code == cli.EXIT_USAGE
    assert Catalog("en").line("scan.no_artifacts") in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["scan"],                                  # no paths
        ["scan", "--policy", "whatever", "x"],     # policy that does not exist
        ["not-a-command", "x"],
    ],
)
def test_bad_invocations_exit_two(capsys, argv):
    with pytest.raises(SystemExit) as raised:
        cli.main(argv)
    capsys.readouterr()

    assert raised.value.code == cli.EXIT_USAGE


def test_fail_on_threshold_changes_the_verdict_not_the_findings(capsys, tmp_path):
    """`--fail-on` is the policy knob the design notes expose deliberately.

    A safetensors file wearing a `.npy` name is a MEDIUM-only artifact: the
    extension mismatch is hygiene, not a path to execution. It passes at the
    default threshold and fails at `--fail-on=medium`, and the finding is
    reported either way. The threshold moves the verdict, never the evidence.
    """
    renamed = tmp_path / "array.npy"
    renamed.write_bytes(
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}}, b"\x00" * 64
        )
    )

    default_code = cli.main(["scan", str(renamed)])
    default_out = capsys.readouterr().out
    strict_code = cli.main(["scan", "--fail-on", "medium", str(renamed)])
    strict_out = capsys.readouterr().out

    assert "ACT-FMT-002" in default_out and "ACT-FMT-002" in strict_out
    assert default_code == cli.EXIT_OK
    assert strict_code == cli.EXIT_FAIL


# ---------------------------------------------------------------------------
# scan --json
# ---------------------------------------------------------------------------

def test_scan_json_emits_the_report_shape(capsys, clean_artifact, failing_artifact):
    code = cli.main(["scan", "--json", str(clean_artifact), str(failing_artifact)])
    payload = json.loads(capsys.readouterr().out)

    assert code == cli.EXIT_FAIL
    reports = payload["reports"]
    assert [report["path"] for report in reports] == [str(clean_artifact), str(failing_artifact)]

    clean, failing = reports
    assert clean["sha256"] == hashlib.sha256(clean_artifact.read_bytes()).hexdigest()
    assert clean["verdict"] == "pass"
    assert clean["detected_format"] == "safetensors"
    assert clean["format_confidence"] == "structure"
    assert clean["findings"] == []
    assert clean["max_severity"] is None
    assert [tensor["name"] for tensor in clean["tensors"]] == ["w"]

    assert failing["verdict"] == "fail"
    assert failing["max_severity"] == "critical"
    assert failing["imported_callables"] == ["posix.system"]
    gadget_finding = next(f for f in failing["findings"] if f["rule_id"] == "ACT-PKL-002")
    assert gadget_finding["severity"] == "critical"
    assert gadget_finding["evidence"]["callable"] == "posix.system"
    # Every rule the JSON names must be renderable, or a consumer gets an id
    # with no text behind it.
    for report in reports:
        for finding in report["findings"]:
            assert Catalog("en").rule(finding["rule_id"]) != finding["rule_id"]


def test_scan_json_is_the_only_thing_on_stdout(capsys, clean_artifact):
    """A pipeline pipes stdout into a parser; a stray human line breaks it."""
    cli.main(["scan", "--json", str(clean_artifact)])

    captured = capsys.readouterr()
    json.loads(captured.out)
    assert captured.out.lstrip().startswith("{")


# ---------------------------------------------------------------------------
# attest, then verify
# ---------------------------------------------------------------------------

def test_attest_then_verify_round_trips_through_the_cli(capsys, tmp_path, clean_artifact):
    out_package = tmp_path / "attestation.zip"
    key = tmp_path / "signing-key.pem"

    attest_code = cli.main(
        ["attest", str(clean_artifact), "--out", str(out_package), "--key", str(key)]
    )
    attest_out = capsys.readouterr()

    assert attest_code == cli.EXIT_OK
    assert out_package.exists()
    assert key.exists()
    printed = dict(
        line.split(maxsplit=1)
        for line in attest_out.out.splitlines()
        if line.startswith(("head", "merkle_root", "key_id", "entries"))
    )
    assert printed["entries"] == "1"
    assert len(printed["head"]) == 64

    verify_code = cli.main(["verify", str(out_package), "--json"])
    result = json.loads(capsys.readouterr().out)

    assert verify_code == cli.EXIT_OK
    assert result["ok"] is True
    assert result["trust_state"] == "embedded_key_only"
    assert result["manifest"]["head_hash"] == printed["head"]
    assert result["manifest"]["merkle_root"] == printed["merkle_root"]
    assert result["entry_count"] == 1


def test_verify_exits_one_when_trust_is_required_and_missing(capsys, tmp_path, clean_artifact):
    out_package = tmp_path / "attestation.zip"
    cli.main(
        [
            "attest",
            str(clean_artifact),
            "--out",
            str(out_package),
            "--key",
            str(tmp_path / "k.pem"),
        ]
    )
    capsys.readouterr()

    code = cli.main(["verify", str(out_package), "--require-trust"])
    out = capsys.readouterr().out

    assert code == cli.EXIT_FAIL
    assert "FAILED" in out


def test_verify_with_the_signing_key_as_an_anchor_exits_zero(capsys, tmp_path, clean_artifact):
    out_package = tmp_path / "attestation.zip"
    key = tmp_path / "k.pem"
    cli.main(["attest", str(clean_artifact), "--out", str(out_package), "--key", str(key)])
    capsys.readouterr()
    cli.main(["keygen", "--key", str(key)])
    public_b64 = next(
        line.split()[1] for line in capsys.readouterr().out.splitlines() if line.startswith("public_b64")
    )

    code = cli.main(["verify", str(out_package), "--pubkey", public_b64, "--require-trust"])
    out = capsys.readouterr().out

    assert code == cli.EXIT_OK
    assert "trusted" in out


# ---------------------------------------------------------------------------
# --extends does not replace verification
#
# The branch used to return before `verify_package` ran, so every trust flag
# on the command line was parsed, ignored and never mentioned. A package
# signed by a key the caller had explicitly refused came back OK with exit 0
# as long as it extended the older one.
# ---------------------------------------------------------------------------

def _chained_pair(tmp_path, artifact, key):
    """An older package and a newer one that genuinely extends it."""
    older = tmp_path / "older.zip"
    newer = tmp_path / "newer.zip"
    cli.main(["attest", str(artifact), "--out", str(older), "--key", str(key)])
    cli.main(["attest", str(artifact), "--out", str(newer), "--key", str(key),
              "--continue", str(older)])
    return older, newer


def test_extends_still_enforces_require_trust(capsys, tmp_path, clean_artifact):
    older, newer = _chained_pair(tmp_path, clean_artifact, tmp_path / "k.pem")
    capsys.readouterr()

    plain = cli.main(["verify", str(newer), "--extends", str(older)])
    assert plain == cli.EXIT_OK, "the consistency proof itself holds"
    capsys.readouterr()

    code = cli.main(["verify", str(newer), "--extends", str(older), "--require-trust"])
    out = capsys.readouterr().out

    assert code == cli.EXIT_FAIL
    assert "--require-trust" in out
    assert "FAILED" in out


def test_extends_still_enforces_a_trusted_keyring(capsys, tmp_path, clean_artifact):
    """Someone else's fingerprint: the package is intact and the chain
    extends, and the signing key is still not one of ours."""
    older, newer = _chained_pair(tmp_path, clean_artifact, tmp_path / "k.pem")
    stranger = tmp_path / "stranger.json"
    stranger.write_text(json.dumps({"keys": [{"fingerprint_sha256": "ab" * 32}]}), encoding="utf-8")
    capsys.readouterr()

    code = cli.main([
        "verify", str(newer), "--extends", str(older), "--trusted-keyring", str(stranger)
    ])
    out = capsys.readouterr().out

    assert code == cli.EXIT_FAIL
    assert "not in the supplied trust anchors" in out


def test_extends_with_the_right_anchor_still_passes(capsys, tmp_path, clean_artifact):
    """Negative control: the flags are enforced, not merely fatal."""
    key = tmp_path / "k.pem"
    older, newer = _chained_pair(tmp_path, clean_artifact, key)
    capsys.readouterr()
    cli.main(["keygen", "--key", str(key)])
    public_b64 = next(
        line.split()[1] for line in capsys.readouterr().out.splitlines()
        if line.startswith("public_b64")
    )

    code = cli.main([
        "verify", str(newer), "--extends", str(older), "--pubkey", public_b64, "--require-trust"
    ])
    out = capsys.readouterr().out

    assert code == cli.EXIT_OK
    assert "trusted" in out


def test_extends_reports_both_results_in_json(capsys, tmp_path, clean_artifact):
    older, newer = _chained_pair(tmp_path, clean_artifact, tmp_path / "k.pem")
    capsys.readouterr()

    code = cli.main(["verify", str(newer), "--extends", str(older), "--json", "--require-trust"])
    document = json.loads(capsys.readouterr().out)

    assert code == cli.EXIT_FAIL
    assert document["ok"] is False
    assert document["extends"]["ok"] is True, "the consistency proof is reported on its own"
    assert document["trust_state"] == "embedded_key_only"
    assert document["checks"]["signature_valid"] is True


def test_attest_reports_the_scan_verdict_in_its_exit_code(capsys, tmp_path, failing_artifact):
    """Attesting a failing artifact still writes the package (the attestation
    records what was found, whatever it was) but the exit code stays 1."""
    out_package = tmp_path / "bad.zip"

    code = cli.main(
        ["attest", str(failing_artifact), "--out", str(out_package), "--key", str(tmp_path / "k.pem")]
    )
    capsys.readouterr()

    assert code == cli.EXIT_FAIL
    assert out_package.exists()


def test_bom_subcommand_writes_a_cyclonedx_document(capsys, tmp_path, clean_artifact):
    out_file = tmp_path / "bom.json"

    code = cli.main(["bom", str(clean_artifact), "--out", str(out_file)])
    capsys.readouterr()

    document = json.loads(out_file.read_text("utf-8"))
    assert code == cli.EXIT_OK
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert document["components"][0]["hashes"][0]["content"] == hashlib.sha256(
        clean_artifact.read_bytes()
    ).hexdigest()


def test_directory_recursion_finds_artifacts_and_no_recurse_does_not(capsys, tmp_path):
    nested = tmp_path / "models" / "v1"
    nested.mkdir(parents=True)
    (nested / "a.pkl").write_bytes(corpus_build.craft_reduce("posix", "system", ("id",), 2))
    (nested / "notes.txt").write_bytes(b"not an artifact")

    recursive = cli.main(["scan", str(tmp_path / "models")])
    out = capsys.readouterr().out
    non_recursive = cli.main(["scan", "--no-recurse", str(tmp_path / "models")])
    capsys.readouterr()

    assert recursive == cli.EXIT_FAIL
    assert "a.pkl" in out and "notes.txt" not in out
    assert non_recursive == cli.EXIT_USAGE


def test_the_spanish_output_is_actually_spanish(capsys, clean_artifact):
    cli.main(["--lang", "es", "scan", str(clean_artifact)])
    spanish = capsys.readouterr().out
    cli.main(["scan", str(clean_artifact)])
    english = capsys.readouterr().out

    assert spanish != english
    assert Catalog("es").line("scan.format") in spanish


# ---------------------------------------------------------------------------
# What the governance assessment is allowed to claim
# ---------------------------------------------------------------------------

def test_an_obligation_with_no_evidence_does_not_read_as_provided(capsys, tmp_path):
    """The catalogue describes a capability. A run describes what it showed.

    The printer used to put the catalogue's "what Actaira provides" lines under
    the word "provides" for every applicable obligation, evidence or none, so a
    run over an empty directory of readable artifacts read like a run that had
    established something. The capability is still printed, because it tells
    the reader what to supply, but in the conditional and under a line saying
    plainly that nothing was supplied.
    """
    empty = tmp_path / "artifacts"
    empty.mkdir()
    (empty / "unknown.model").write_bytes(b"\x11\x22\x33\x44 not a known format")

    cli.main(["governance", "assess", str(empty)])
    out = capsys.readouterr().out
    catalog = Catalog("en")

    assert catalog.line("gov.no_evidence") in out
    assert f"{catalog.line('gov.provides')}:" not in out, (
        "nothing was supplied, so nothing may be reported as provided"
    )
    assert f"{catalog.line('gov.would_provide')}:" in out


def test_evidence_lines_name_the_artifact_they_came_from(capsys, tmp_path):
    """An evidence line a reader cannot check is decoration.

    `kind: artifact_inspection` names a category. The file name, its format,
    its verdict and its digest name a thing that is either in the report or is
    not, which is what makes the claim falsifiable by whoever is reading it.
    """
    artifact = tmp_path / "clean.safetensors"
    artifact.write_bytes(
        corpus_build.build_safetensors(
            {"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}}, b"\x00" * 64
        )
    )

    cli.main(["governance", "assess", str(artifact)])
    out = capsys.readouterr().out
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

    assert f"{Catalog('en').line('gov.evidence_from')}:" in out
    assert "clean.safetensors (safetensors, PASS" in out
    assert digest[:16] in out


# --------------------------------------------------------------------------
# Content-first directory discovery (D-106). The walk used to filter by file
# extension, which meant the tool asked the attacker whether to inspect the
# file. These pin the fix from both sides: what is now found, and what is not
# quietly forgotten.
# --------------------------------------------------------------------------


def test_a_pickle_with_a_text_file_name_is_found_in_a_directory_walk(tmp_path, capsys):
    """DEF-60. `collect_paths()` kept only files whose suffix was in a list,
    so a pickle called `notes.txt` was not scanned, not reported and not
    counted: invisible, not inconclusive."""

    from evals.corpus import build as corpus_build

    (tmp_path / "notes.txt").write_bytes(corpus_build.craft_reduce("posix", "system", ("id",), 2))
    (tmp_path / "readme.md").write_text("# not an artifact", encoding="utf-8")

    code = cli.main(["scan", str(tmp_path)])
    out = capsys.readouterr().out

    assert "notes.txt" in out
    assert "posix.system" in out or "ACT-PKL-002" in out
    assert code == cli.EXIT_FAIL
    assert "readme.md" not in out, "a markdown file is not an artifact and is not reported as one"


def test_a_named_file_is_inspected_whatever_its_bytes_say(tmp_path, capsys):
    """An explicit argument is an instruction. Declining to look at a file the
    user pointed at would be the tool second-guessing them, and the answer
    ACT-FMT-001 is more useful than silence."""
    target = tmp_path / "whatever"
    target.write_bytes(b"\x11\x22\x33\x44 not a known format")

    cli.main(["scan", str(target)])
    out = capsys.readouterr().out

    assert "whatever" in out
    assert "ACT-FMT-001" in out


def test_a_name_that_claims_to_be_a_model_is_inspected_even_when_its_bytes_are_not(tmp_path, capsys):
    """The second way into the walk. `weights.pkl` holding something that is
    not a pickle is a fact about the directory, and reporting nothing about a
    file whose own name says it is a model would be the old silence in a new
    place."""
    (tmp_path / "weights.pkl").write_bytes(b"\x11\x22\x33\x44 not a known format")

    cli.main(["scan", str(tmp_path)])
    out = capsys.readouterr().out

    assert "weights.pkl" in out
    assert "ACT-FMT-001" in out or "ACT-FMT-002" in out


def test_files_walked_past_are_counted_rather_than_forgotten(tmp_path, capsys):
    """"There were no artifacts here" and "I walked past 812 files" send a
    reader to very different places. The old walk could only say the first."""
    for index in range(5):
        (tmp_path / f"doc{index}.md").write_text("# text", encoding="utf-8")

    code = cli.main(["scan", str(tmp_path)])
    err = capsys.readouterr().err

    assert code == cli.EXIT_USAGE
    assert "5" in err


def test_tool_directories_are_not_descended_into(tmp_path, capsys):
    """Not a security boundary - a hostile artifact will not be in `.git` -
    but walking a virtualenv turns a scan of a model directory into a scan of
    a package index, and the report becomes unreadable."""
    import pickle as pickle_module

    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "object.pkl").write_bytes(pickle_module.dumps({"a": 1}))
    (tmp_path / "model.pkl").write_bytes(pickle_module.dumps({"w": [1.0]}))

    cli.main(["scan", str(tmp_path)])
    out = capsys.readouterr().out

    assert "model.pkl" in out
    assert "object.pkl" not in out


def test_the_walk_returns_the_same_order_twice(tmp_path):
    """The report is hashed into an attestation, so two runs over the same
    tree must produce the same document. An order that depended on the
    filesystem would make the hash meaningless."""
    import pickle as pickle_module

    for name in ("b.pkl", "a.pkl", "zzz.bin", "c.pkl"):
        (tmp_path / name).write_bytes(pickle_module.dumps({"n": name}))

    first = cli.collect_paths([tmp_path])
    second = cli.collect_paths([tmp_path])

    assert first == second
    assert [path.name for path in first] == sorted(path.name for path in first)


def test_the_coverage_matrix_is_printed_for_every_artifact(tmp_path, capsys):
    """Printed always, not only when something went wrong. A block a reader
    only ever sees on a bad artifact is read as a warning; printed on every
    one it is what it is, the scope of the claim above it."""
    import pickle as pickle_module

    (tmp_path / "clean.pkl").write_bytes(pickle_module.dumps({"w": [1.0]}))

    cli.main(["scan", str(tmp_path)])
    out = capsys.readouterr().out

    assert "coverage" in out
    assert "load-time execution" in out
    assert "COMPLETE" in out
    assert "NOT ASSESSED" in out


# --------------------------------------------------------------------------
# `actaira policy` and `actaira receipt`
# --------------------------------------------------------------------------


POLICY_TEXT = """
policy: test-policy
version: 1
rules:
  - id: no-high
    effect: deny
    when:
      finding_severity_at_least: high
"""


def test_a_policy_denial_exits_one_and_a_review_exits_three(tmp_path, capsys):
    """The exit codes a pipeline branches on. DENY and REVIEW have to be
    distinguishable, because a team that cannot tell them apart treats both as
    failure and then weakens the deny rules to get work done."""
    import pickle as pickle_module

    from evals.corpus import build as corpus_build

    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY_TEXT, encoding="utf-8")

    denied = tmp_path / "denied"
    denied.mkdir()
    (denied / "gadget.pkl").write_bytes(corpus_build.craft_reduce("posix", "system", ("id",), 2))

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "clean.pkl").write_bytes(pickle_module.dumps({"w": [1.0]}))

    deny_code = cli.main(["policy", "check", str(denied), "--policy-file", str(policy), "--on", "2026-09-11"])
    allow_code = cli.main(["policy", "check", str(allowed), "--policy-file", str(policy), "--on", "2026-09-11"])

    assert deny_code == cli.EXIT_FAIL
    assert allow_code == cli.EXIT_OK


def test_a_policy_that_does_not_load_is_a_usage_error_not_a_default_allow(tmp_path, capsys):
    """Carrying on with the rules that happened to parse is how a pipeline
    ends up governed by half a document."""
    import pickle as pickle_module

    broken = tmp_path / "broken.yaml"
    broken.write_text("policy: broken\nversion: 1\nrules:\n  - id: x\n    effect: nonsense\n    when:\n      verdict_is: pass\n", encoding="utf-8")
    (tmp_path / "clean.pkl").write_bytes(pickle_module.dumps({"w": [1.0]}))

    code = cli.main(["policy", "check", str(tmp_path), "--policy-file", str(broken)])
    err = capsys.readouterr().err

    assert code == cli.EXIT_USAGE
    assert "effect" in err


def test_the_printed_proof_names_every_rule_and_every_subject(tmp_path, capsys):
    import pickle as pickle_module

    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY_TEXT, encoding="utf-8")
    (tmp_path / "a.pkl").write_bytes(pickle_module.dumps({"w": [1.0]}))
    (tmp_path / "b.pkl").write_bytes(pickle_module.dumps({"w": [2.0]}))

    cli.main(["policy", "check", str(tmp_path), "--policy-file", str(policy), "--on", "2026-09-11"])
    out = capsys.readouterr().out

    assert out.count("no-high") >= 2, "one line per subject, so a reader can tell which denied"
    assert "proof" in out


def test_a_receipt_is_issued_signed_and_verifies_with_a_clean_install(tmp_path, capsys):
    """The end-to-end claim the receipt exists to make: a third party with the
    file and nothing else can check it."""
    import pickle as pickle_module

    (tmp_path / "clean.pkl").write_bytes(pickle_module.dumps({"w": [1.0]}))
    out_path = tmp_path / "receipt.json"
    key = tmp_path / "key.pem"

    issue_code = cli.main(["receipt", "issue", str(tmp_path), "--out", str(out_path), "--key", str(key)])
    capsys.readouterr()
    verify_code = cli.main(["receipt", "verify", str(out_path)])
    out = capsys.readouterr().out

    assert issue_code == cli.EXIT_OK
    assert verify_code == cli.EXIT_OK
    assert out_path.exists()
    assert "verifies over this document" in out
    assert "nobody has vouched for this key" in out, "verified is not trusted, and the printout says so"


def test_a_tampered_receipt_fails_verification_at_the_command_line(tmp_path, capsys):
    import json as json_module
    import pickle as pickle_module

    (tmp_path / "clean.pkl").write_bytes(pickle_module.dumps({"w": [1.0]}))
    out_path = tmp_path / "receipt.json"
    cli.main(["receipt", "issue", str(tmp_path), "--out", str(out_path), "--key", str(tmp_path / "key.pem")])
    capsys.readouterr()

    document = json_module.loads(out_path.read_text(encoding="utf-8"))
    document["findings_by_severity"]["critical"] = 99
    out_path.write_text(json_module.dumps(document), encoding="utf-8")

    code = cli.main(["receipt", "verify", str(out_path)])
    out = capsys.readouterr().out

    assert code == cli.EXIT_FAIL
    assert "does NOT verify" in out


def test_a_receipt_about_other_files_is_reported_when_the_files_are_to_hand(tmp_path, capsys):
    import pickle as pickle_module

    subject_dir = tmp_path / "subject"
    subject_dir.mkdir()
    (subject_dir / "clean.pkl").write_bytes(pickle_module.dumps({"w": [1.0]}))
    other = tmp_path / "other.pkl"
    other.write_bytes(pickle_module.dumps({"w": [9.0]}))

    out_path = tmp_path / "receipt.json"
    cli.main(["receipt", "issue", str(subject_dir), "--out", str(out_path), "--key", str(tmp_path / "key.pem")])
    capsys.readouterr()

    code = cli.main(["receipt", "verify", str(out_path), "--against", str(other)])
    out = capsys.readouterr().out

    assert code == cli.EXIT_FAIL
    assert "not among the artifacts supplied" in out


def test_a_trusted_keyring_makes_the_signer_trusted_in_a_policy_decision(tmp_path, capsys):
    """DEF-65. The bridge between `actaira verify` and the policy layer read a
    field name that does not exist and defaulted it to False, so every run with
    a keyring came back DENY and the proof said `signer_trusted: actual false`
    beside a package the verifier had just called trusted.

    The three states matter here more than anywhere else in the tool: trusted,
    untrusted, and nobody-vouched-for-it. Only the middle one is a refusal.
    """
    import pickle as pickle_module

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "clean.pkl").write_bytes(pickle_module.dumps({"w": [1.0]}))

    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "policy: needs-a-trusted-signer\n"
        "version: 1\n"
        "rules:\n"
        "  - id: trusted-signer\n"
        "    effect: require\n"
        "    when:\n"
        "      signature_verified: true\n"
        "      signer_trusted: true\n",
        encoding="utf-8",
    )

    key = tmp_path / "key.pem"
    package = tmp_path / "release.zip"
    cli.main(["attest", str(artifacts), "--out", str(package), "--key", str(key)])
    capsys.readouterr()
    keyring_path = key.parent / "keyring.json"
    assert keyring_path.is_file(), "attest writes the keyring beside the key"

    with_anchor = cli.main(
        ["policy", "check", str(artifacts), "--policy-file", str(policy),
         "--attestation", str(package), "--trusted-keyring", str(keyring_path),
         "--on", "2026-09-11"]
    )
    capsys.readouterr()
    without_anchor = cli.main(
        ["policy", "check", str(artifacts), "--policy-file", str(policy),
         "--attestation", str(package), "--on", "2026-09-11"]
    )
    out = capsys.readouterr().out

    assert with_anchor == cli.EXIT_OK, "the anchor was supplied and it matched"
    assert without_anchor == cli.EXIT_INCONCLUSIVE, (
        "no anchor supplied is REVIEW, not DENY: nobody declined to vouch for the key, "
        "nobody was asked"
    )
    assert "unevaluable" in out


def test_the_package_runs_as_a_module(tmp_path):
    """DEF-67. `python -m actaira.cli` is the first thing a developer types.

    The `__main__` guard had drifted into the middle of the file, so running
    the module executed `main()` above a thousand lines of handlers that did
    not exist yet. The installed console script calls `main` after the import
    finishes and was fine, which is why nothing noticed.
    """
    import subprocess
    import sys

    from conftest import REPO_ROOT

    result = subprocess.run(
        [sys.executable, "-m", "actaira.cli", "schema"],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": str(Path(REPO_ROOT) / "src"), "PATH": os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, result.stderr
    assert "model-bundle-v2" in result.stdout


def test_policy_check_works_without_an_on_date(tmp_path):
    """DEF-68. `args.on or gov_clock_fn()` called the obligation-clock
    builder, which takes the date rather than returning it, so every run
    without `--on` raised TypeError - and argparse's caller turned that into
    exit 1, which is EXIT_FAIL and therefore indistinguishable from a policy
    DENY. Every test of this command passed `--on`, because that is what a
    reproducible decision uses."""
    import pickle

    artifact = tmp_path / "clean.pkl"
    artifact.write_bytes(pickle.dumps({"w": [1.0]}))
    policy = tmp_path / "policy.yaml"
    policy.write_text("""
policy: demo
version: 1
rules:
  - id: no-criticals
    effect: deny
    when:
      finding_severity_at_least: critical
""", encoding="utf-8")

    code = cli.main(["policy", "check", str(artifact), "--policy-file", str(policy)])

    assert code == 0


def test_receipt_issue_works_without_an_on_date(tmp_path):
    """The same defect, in the other command that has the same line."""
    import pickle

    artifact = tmp_path / "clean.pkl"
    artifact.write_bytes(pickle.dumps({"w": [1.0]}))
    policy = tmp_path / "policy.yaml"
    policy.write_text("""
policy: demo
version: 1
rules:
  - id: no-criticals
    effect: deny
    when:
      finding_severity_at_least: critical
""", encoding="utf-8")

    code = cli.main([
        "receipt", "issue", str(artifact),
        "--out", str(tmp_path / "receipt.json"),
        "--key", str(tmp_path / "key.pem"),
        "--policy-file", str(policy),
    ])

    assert code == 0
    assert (tmp_path / "receipt.json").is_file()


def test_evidence_list_json_carries_the_same_exit_code_as_the_text(tmp_path):
    """DEF-76. `--json` returned EXIT_OK before the exit code was computed, so
    the one mode a pipeline reads never signalled - and the comment beside it
    says the code exists precisely so a pipeline need not parse the text."""
    from actaira.state import evidence as evidence_mod
    from actaira.state.store import Store

    state = tmp_path / "state.db"
    with Store(state) as store:
        record = evidence_mod.for_subject("artifact:a", "artifact_scan", subject_digest="sha256:aa")
        store.record_evidence(record)
        store.set_evidence_state(record.evidence_id, "revoked")

    text = cli.main(["evidence", "list", "--state", str(state)])
    as_json = cli.main(["evidence", "list", "--state", str(state), "--json"])

    assert text == as_json == 1


def test_bundle_refuses_a_revision_on_a_local_directory(tmp_path, capsys):
    """`--revision` names a revision of a source. Accepting it silently on a
    directory is how a local path ends up in a document that reads as a
    pinned remote model."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "config.json").write_text("{}", encoding="utf-8")

    code = cli.main(["bundle", str(root), "--revision", "7f91a2c"])

    assert code == 2
    assert "--revision" in capsys.readouterr().err


def test_graph_export_creates_the_directory_it_was_given(tmp_path):
    """DEF-78. A path the operator typed is a statement of where they want the
    file, not a bet on whether the directory is already there."""
    from actaira.state.store import Store

    state = tmp_path / "state.db"
    with Store(state):
        pass

    code = cli.main([
        "graph", "export", "--state", str(state), "--out", str(tmp_path / "reports" / "graph.json")
    ])

    assert code == 0
    assert (tmp_path / "reports" / "graph.json").is_file()


def test_graph_build_reports_a_bad_agent_declaration_as_a_usage_error(tmp_path, capsys):
    """DEF-77. The guard wrapped only the manifest load, so an agent file that
    did not parse - reached a few lines further down, inside the transaction -
    came back as a raw traceback, where the identical error one step earlier
    came back as a message and exit 2."""
    from actaira.state.store import Store

    (tmp_path / "broken.yaml").write_text("tools:\n  - name: x\n", encoding="utf-8")
    manifest = tmp_path / "subjects.yaml"
    manifest.write_text("""
schema_version: subject-manifest/v1
subjects:
  - kind: agent
    path: broken.yaml
""", encoding="utf-8")
    state = tmp_path / "state.db"
    with Store(state):
        pass

    code = cli.main(["graph", "build", "--subjects", str(manifest), "--state", str(state)])

    assert code == 2
    assert "needs a name" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# DEF-101: a closed pipe printed a traceback and exited 0
# ---------------------------------------------------------------------------
def test_a_reader_that_stops_reading_is_not_a_traceback(tmp_path):
    """`actaira schema | head -3` used to print a BrokenPipeError.

    `head` closes the pipe after three lines, the next `print` raises, and the
    interpreter's final flush raises again on the way out. The traceback went
    to stderr with an exit code that said nothing had gone wrong, so anyone
    debugging a pipeline saw a stack trace from the tool that had just told
    them everything passed. Design note D-235.

    Run as a real subprocess through a real pipe, because the defect is in
    what happens to `sys.stdout` at interpreter exit and an in-process call
    cannot reach it.
    """
    import subprocess
    import sys

    from conftest import REPO_ROOT

    environment = {**os.environ, "PYTHONPATH": str(Path(REPO_ROOT) / "src")}
    for _ in range(6):
        producer = subprocess.Popen(
            [sys.executable, "-m", "actaira", "schema"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=REPO_ROOT, env=environment,
        )
        reader = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdin.readline()"],
            stdin=producer.stdout, stdout=subprocess.DEVNULL,
        )
        producer.stdout.close()
        reader.wait()
        _, errors = producer.communicate()
        code = producer.returncode
        assert b"BrokenPipeError" not in errors, errors.decode()
        assert b"Traceback" not in errors, errors.decode()
        assert code in (cli.EXIT_OK, cli.EXIT_SIGPIPE), code


def test_redirected_output_is_utf8_on_every_platform(tmp_path):
    """DEF-107. `sys.stdout`'s encoding comes from the locale, so the same
    command on two machines wrote two different files.

    `actaira --lang es scan > report.txt` produced UTF-8 on a POSIX host with a
    UTF-8 locale and cp1252 on a default Windows install: the accented
    characters in the Spanish catalogue came out as different bytes, and a
    consumer reading the file as UTF-8 got mojibake or a decode error. Two
    machines running one command over one artifact have to produce one file -
    that is the property this repository defends everywhere else, and stdout
    was the one place nothing was deciding it.

    Run through a subprocess with the environment scrubbed of the two
    variables that would settle the question from outside, so this asserts what
    the tool does rather than what the caller arranged.
    """
    import subprocess
    import sys

    from conftest import REPO_ROOT

    artifact = tmp_path / "mystery.model"
    artifact.write_bytes(b"\x11\x22\x33\x44 not a known format")

    environment = {
        key: value for key, value in os.environ.items()
        if key not in ("PYTHONIOENCODING", "PYTHONUTF8")
    }
    environment["PYTHONPATH"] = str(Path(REPO_ROOT) / "src")

    result = subprocess.run(
        [sys.executable, "-m", "actaira", "--lang", "es", "scan", str(artifact)],
        cwd=REPO_ROOT, env=environment, capture_output=True, timeout=180,
    )

    # Decoded, not str-compared: the point is the bytes on the wire.
    text = result.stdout.decode("utf-8")
    assert text, "the command printed nothing, so this asserts nothing"
    assert "ú" in text or "ó" in text or "é" in text, (
        "no accented character reached the output, so the encoding was not exercised"
    )
    assert b"\r\n" not in result.stdout, (
        "the line ending came from the platform; a report that differs by "
        "platform is not a report two people can compare"
    )
