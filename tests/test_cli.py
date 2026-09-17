"""The commands that exist, and the contract each of them publishes.

Five of the seven CLAUDE.md lists: `check`, `verify`, `keygen`, `scan` and
`watch`. That is the interesting assertion in this file and the first test makes
it - the help text is the contract, and a command that does not exist must not
appear in it. The other two arrive phase by phase, and adding one here before it
works would be publishing a promise.

Which is why the last section of this file reads that list out of `CLAUDE.md`
rather than trusting a copy kept here. Phase S0 changed the list, and a name on
it that neither parses nor says when it will is exactly the promise the
paragraph above refuses: it reads as shipped to anybody who has not tried it.

What is tested is what a caller can rely on: the exit codes, the fact that
`verify` opens no socket, and that it reports a broken package as broken
rather than as silence. The verification logic lives in
`tests/test_package_verify.py` and what `scan` and `watch` produce lives in
their own files; this one is about the command line.
"""
from __future__ import annotations

import json
import re
import socket
import zipfile
from pathlib import Path

import pytest

from actaira import cli
from actaira.attest import chain, package
from conftest import REPO_ROOT


@pytest.fixture
def entries() -> list[chain.Entry]:
    built: list[chain.Entry] = []
    chain.append(built, "c" * 64, {"claim": "observed"}, timestamp="2026-01-01T00:00:00")
    return built


@pytest.fixture
def attestation(tmp_path: Path, entries, keypair) -> Path:
    out = tmp_path / "attestation.zip"
    package.write_package(out, entries, keypair)
    return out


@pytest.fixture
def no_network(monkeypatch):
    """Any socket at all fails the test that asked for it.

    Offline is the claim `verify` rests on, and a test that merely happens not
    to reach the network does not check it. Patched at `socket.socket`, so an
    HTTP client, a DNS lookup and a raw connect are all covered.
    """

    def refuse(*args, **kwargs):
        raise AssertionError("this command opened a socket; verification is offline")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


# ---------------------------------------------------------------------------
# The surface
# ---------------------------------------------------------------------------


SHIPPED = {"check", "verify", "keygen", "scan", "watch"}
# The two CLAUDE.md names that this release still cannot mean anything by,
# the four that phase S0 removed from the list, and `serve`.
#
# The retired four stay here rather than being deleted with the doctrine that
# named them, and the reason is that this test asserts a usage error, not an
# absence: a name that used to be planned is a name somebody's script may still
# type, and the answer it gets must be an error rather than something worse.
# `serve` is in the list and is not one of the seven: the MCP server is a
# separate entry point, `actaira-mcp`, precisely so that it is not another
# command, and this is where that stays true.
NOT_BUILT_YET = ["diff", "seal"]
RETIRED = ["contract", "verdict", "receipt", "fix"]
UNSHIPPED = [*NOT_BUILT_YET, *RETIRED, "serve"]


def test_the_cli_publishes_exactly_the_commands_that_work():
    """CLAUDE.md lists seven, caps the set at eight, and this release ships five.

    Phase S1 built the configuration reader, so `check` moved from the promised
    list to this one. `diff` and `seal` are the two still outstanding; both need
    a sealed baseline, which is phase S3. A parser that accepted them and
    printed "not implemented" would be advertising them.
    """
    subparsers = [
        action
        for action in cli.build_parser()._subparsers._group_actions  # noqa: SLF001
        if hasattr(action, "choices")
    ]

    assert len(subparsers) == 1
    assert set(subparsers[0].choices) == SHIPPED


@pytest.mark.parametrize("command", UNSHIPPED)
def test_a_command_that_does_not_exist_yet_is_a_usage_error(command, capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.build_parser().parse_args([command])

    assert exit_info.value.code == cli.EXIT_USAGE
    assert "invalid choice" in capsys.readouterr().err


def test_the_help_text_names_those_commands_and_nothing_else(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])

    printed = capsys.readouterr().out

    # The command column only, and only its first token. Two naive readings
    # have already been wrong here: "attest" is a substring of "attestation
    # package" in verify's own help line, and a help string long enough to wrap
    # puts its continuation in this block too, which read `machine` and `proxy`
    # as commands. A command name sits at exactly four spaces; everything else
    # argparse writes in here is indented further or starts with a brace.
    listing = printed.split("positional arguments:", 1)[1].split("options:", 1)[0]
    named = {
        match.group(1)
        for match in (re.match(r"^ {4}(\S+)", line) for line in listing.splitlines())
        if match and not match.group(1).startswith("{")
    }

    assert named == SHIPPED, f"the help lists {sorted(named)}"


def test_version_is_the_package_version(capsys):
    from actaira import __version__

    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])

    assert exit_info.value.code == cli.EXIT_OK
    assert capsys.readouterr().out.strip() == f"actaira {__version__}"


# ---------------------------------------------------------------------------
# The list in CLAUDE.md, against this parser
# ---------------------------------------------------------------------------
#
# `release_check.readme_documents_the_commands` asks one direction: every
# command that exists is named on the pages that list commands. It cannot ask
# the other, because the other direction is only answerable for a list that
# says which of its names are promises. CLAUDE.md's is, one phase per unbuilt
# name, so it is the one list in this repository where both directions are
# checkable, and this is the check.
#
# It exists because phase S0 rewrote that list without touching a line of the
# parser. Four names left it and three arrived, and nothing in the tree would
# have noticed had the three arrived without their phases: a reader meeting
# `actaira check` in the governance document has no way to tell a shipped
# command from an intention, and the whole point of the phase before this one
# was that the tree stops describing intentions in the present tense.

CLI_SECTION = re.compile(r"^## El CLI$(.*?)^## ", re.M | re.S)
CLI_ENTRY = re.compile(r"^ {4}actaira (\S+)(.*?)(?=^ {4}actaira |\Z)", re.M | re.S)
PHASE_MARK = re.compile(r"\(fase [A-Z]\d(?:\.\d)?\)")


def doctrine_commands(text: str) -> list[tuple[str, bool]]:
    """(command name, whether its entry states the phase it arrives in).

    An entry is its `    actaira <name>` line plus the continuation lines under
    it, because the phase is written at the end of the description and the
    description wraps.
    """
    section = CLI_SECTION.search(text)
    assert section, "CLAUDE.md has no `## El CLI` section, or it is now the last one"
    return [
        (name, bool(PHASE_MARK.search(body)))
        for name, body in CLI_ENTRY.findall(section.group(1))
    ]


DOCTRINE = doctrine_commands((Path(REPO_ROOT) / "CLAUDE.md").read_text(encoding="utf-8"))


def test_the_doctrine_list_was_actually_parsed():
    """The non-vacuity guard, which is the whole risk in a test that greps a
    document: a regex that stopped matching reports success having compared
    nothing, and this file would go on passing through the next rewrite of the
    section it reads."""
    assert len(DOCTRINE) >= len(SHIPPED), f"parsed only {DOCTRINE} out of CLAUDE.md"

    names = [name for name, _phased in DOCTRINE]
    assert len(names) == len(set(names)), f"a command is listed twice: {names}"
    assert SHIPPED <= set(names), (
        f"CLAUDE.md's list is missing a command that exists: {sorted(SHIPPED - set(names))}"
    )
    assert len(names) <= 8, f"CLAUDE.md caps the list at eight and lists {len(names)}"


@pytest.mark.parametrize("name, phased", DOCTRINE, ids=lambda item: str(item))
def test_every_name_in_the_doctrine_list_either_exists_or_says_when(name, phased):
    parser_commands = set(cli.build_parser()._subparsers._group_actions[0].choices)  # noqa: SLF001

    if name in parser_commands:
        assert not phased, (
            f"CLAUDE.md marks `{name}` with a phase and the parser already has it. "
            "A shipped command described as arriving later is the same defect "
            "pointing the other way."
        )
        return

    assert phased, (
        f"CLAUDE.md lists `actaira {name}`, which this parser does not have, and "
        "does not say which phase it arrives in. A name on that list without a "
        "phase reads as a shipped command to anybody who has not typed it."
    )


def test_the_check_would_notice_a_planted_command():
    """The guard on the guard. A check over a document is worth what its
    failure mode is worth, so a command is planted into a copy of the section
    and both halves are asserted: that it is parsed at all, and that it is
    parsed as unphased."""
    real = (Path(REPO_ROOT) / "CLAUDE.md").read_text(encoding="utf-8")
    planted = real.replace(
        "    actaira keygen ",
        "    actaira publish             sube el acta al registro\n    actaira keygen ",
        1,
    )
    assert planted != real, "the plant did not apply; the fixture line moved"

    found = dict(doctrine_commands(planted))
    assert "publish" in found, "a planted command was not even parsed out"
    assert found["publish"] is False, "a command with no phase was read as phased"

    parser_commands = set(cli.build_parser()._subparsers._group_actions[0].choices)  # noqa: SLF001
    assert "publish" not in parser_commands
    assert not (found["publish"] or "publish" in parser_commands), (
        "the condition this file fails on does not hold for a planted command, "
        "so the check passes over anything"
    )

    # And the same plant WITH a phase must be accepted, or the check is just a
    # ban on adding a name.
    with_phase = real.replace(
        "    actaira keygen ",
        "    actaira publish             sube el acta al registro    (fase S9)\n    actaira keygen ",
        1,
    )
    assert dict(doctrine_commands(with_phase))["publish"] is True


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------


def test_keygen_creates_a_key_and_a_keyring_beside_it(tmp_path, capsys, no_network):
    key = tmp_path / "keys" / "signing-key.pem"

    assert cli.main(["keygen", "--key", str(key)]) == cli.EXIT_OK

    printed = capsys.readouterr().out
    assert key.is_file()
    assert (key.parent / "keyring.json").is_file()
    assert "key_id" in printed and "fingerprint" in printed and "public_b64" in printed


def test_keygen_twice_loads_the_same_key_rather_than_replacing_it(tmp_path, capsys):
    """Overwriting would orphan every package the first key signed, and the
    command a user reaches for to *see* their key must not rotate it."""
    key = tmp_path / "signing-key.pem"

    cli.main(["keygen", "--key", str(key)])
    first = capsys.readouterr().out
    cli.main(["keygen", "--key", str(key)])
    second = capsys.readouterr().out

    key_id = next(line for line in first.splitlines() if line.startswith("key_id"))
    assert key_id in second
    assert "Created" in first and "Created" not in second


def test_rotate_retires_the_old_key_and_keeps_its_public_half(tmp_path, capsys):
    """A rotation that dropped the old public key would break verification of
    everything it ever signed, which is not a rotation, it is a revocation."""
    key = tmp_path / "signing-key.pem"
    cli.main(["keygen", "--key", str(key)])
    before = capsys.readouterr().out
    old_id = next(line for line in before.splitlines() if line.startswith("key_id")).split()[-1]

    assert cli.main(["keygen", "--key", str(key), "--rotate"]) == cli.EXIT_OK

    printed = capsys.readouterr().out
    ring = json.loads((tmp_path / "keyring.json").read_text(encoding="utf-8"))
    statuses = {record["key_id"]: record["status"] for record in ring["keys"]}

    assert statuses[old_id] == "retired"
    assert "active" in statuses.values()
    assert old_id in printed


def test_revoke_marks_the_key_and_leaves_it_in_the_ring(tmp_path, capsys):
    key = tmp_path / "signing-key.pem"
    cli.main(["keygen", "--key", str(key)])
    key_id = next(
        line for line in capsys.readouterr().out.splitlines() if line.startswith("key_id")
    ).split()[-1]

    assert cli.main(["keygen", "--key", str(key), "--revoke", key_id]) == cli.EXIT_OK

    ring = json.loads((tmp_path / "keyring.json").read_text(encoding="utf-8"))
    record = next(item for item in ring["keys"] if item["key_id"] == key_id)

    assert record["status"] == "revoked"
    assert record["revoked_at"]


def test_revoking_a_key_the_ring_does_not_know_is_a_usage_error(tmp_path, capsys):
    key = tmp_path / "signing-key.pem"
    cli.main(["keygen", "--key", str(key)])
    capsys.readouterr()

    assert cli.main(["keygen", "--key", str(key), "--revoke", "deadbeef"]) == cli.EXIT_USAGE
    assert capsys.readouterr().err.strip()


def test_rotate_and_revoke_together_are_refused_before_anything_is_written(tmp_path, capsys):
    """They mean opposite things about the current key. Doing either one and
    reporting the conflict afterwards is worse than doing neither."""
    key = tmp_path / "signing-key.pem"

    assert cli.main(["keygen", "--key", str(key), "--rotate", "--revoke", "abc"]) == cli.EXIT_USAGE
    assert not key.exists()
    assert capsys.readouterr().err.strip()


def test_the_default_key_path_is_resolved_when_asked_and_never_at_import():
    """Design note D-240. `Path.home()` raises in a scrubbed environment, and
    a module-level call took `--help` down with it."""
    assert cli.default_key_path().name == "signing-key.pem"
    assert cli.default_key_path().parent.name == ".actaira"


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def test_verify_accepts_a_package_it_just_signed(attestation, capsys, no_network):
    assert cli.main(["verify", str(attestation)]) == cli.EXIT_OK

    printed = capsys.readouterr().out
    assert "OK" in printed
    assert "FAILED" not in printed


def test_verify_json_is_json_and_carries_the_same_answer(attestation, capsys, no_network):
    assert cli.main(["verify", str(attestation), "--json"]) == cli.EXIT_OK

    payload = json.loads(capsys.readouterr().out)

    assert payload["ok"] is True
    assert payload["checks"]
    # `key_trusted` is false and the document is still ok: nobody supplied a
    # trust anchor, and a verifier that read "unknown signer" as "bad
    # signature" would be making the caller's policy decision for them.
    assert payload["checks"]["chain_intact"] and payload["checks"]["files_match_manifest"]
    assert payload["checks"]["key_trusted"] is False
    assert payload["trust_state"] != "trusted"


def test_an_edited_package_fails_and_names_what_broke(attestation, tmp_path, capsys, no_network):
    """The property the whole product rests on: a change to a packaged file
    has to fail verification, and the failure has to say which file."""
    with zipfile.ZipFile(attestation) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    members[package.ENTRIES_NAME] = members[package.ENTRIES_NAME].replace(b"observed", b"invented")

    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(tampered, "w") as archive:
        for name, blob in members.items():
            archive.writestr(name, blob)

    assert cli.main(["verify", str(tampered)]) == cli.EXIT_FAIL

    printed = capsys.readouterr().out
    assert "FAILED" in printed
    assert package.ENTRIES_NAME in printed


def test_require_trust_fails_on_a_key_nobody_vouched_for(attestation, capsys, no_network):
    """Two questions kept apart: the signature verifies and the signer is
    still a stranger. `--require-trust` is how a caller says which they meant."""
    assert cli.main(["verify", str(attestation)]) == cli.EXIT_OK
    capsys.readouterr()

    assert cli.main(["verify", str(attestation), "--require-trust"]) == cli.EXIT_FAIL
    assert "FAILED" in capsys.readouterr().out


def test_verify_names_a_package_that_is_not_there(tmp_path, capsys, no_network):
    assert cli.main(["verify", str(tmp_path / "absent.zip")]) == cli.EXIT_FAIL
    assert "FAILED" in capsys.readouterr().out


def test_extends_is_checked_as_well_as_the_package_and_not_instead_of_it(
    tmp_path, entries, keypair, capsys, no_network
):
    """The defect this combination had: `--extends` returned before the
    package was verified, so `--require-trust` was accepted, ignored, and a
    package signed by a rejected key came back OK."""
    older = tmp_path / "older.zip"
    package.write_package(older, entries, keypair)
    chain.append(entries, "d" * 64, {"claim": "second"}, timestamp="2026-01-02T00:00:00")
    newer = tmp_path / "newer.zip"
    package.write_package(newer, entries, keypair)

    assert cli.main(["verify", str(newer), "--extends", str(older)]) == cli.EXIT_OK
    capsys.readouterr()

    assert cli.main(["verify", str(newer), "--extends", str(older), "--require-trust"]) == cli.EXIT_FAIL
    assert "FAILED" in capsys.readouterr().out


def test_a_package_that_does_not_extend_the_older_one_fails(tmp_path, entries, keypair, capsys, no_network):
    older = tmp_path / "older.zip"
    package.write_package(older, entries, keypair)

    unrelated: list[chain.Entry] = []
    chain.append(unrelated, "e" * 64, {"claim": "elsewhere"}, timestamp="2026-01-03T00:00:00")
    other = tmp_path / "other.zip"
    package.write_package(other, unrelated, keypair)

    assert cli.main(["verify", str(other), "--extends", str(older)]) == cli.EXIT_FAIL
    assert "FAILED" in capsys.readouterr().out


def test_verify_prints_the_same_bytes_twice(attestation, capsys, no_network):
    """Determinism, which the release gate checks for every command that has
    one. A report that differs between two runs over one input cannot be
    diffed, and diffing it is what a reviewer does with it."""
    cli.main(["verify", str(attestation), "--json"])
    first = capsys.readouterr().out
    cli.main(["verify", str(attestation), "--json"])
    second = capsys.readouterr().out

    assert first == second
