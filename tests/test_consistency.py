"""RFC 6962 consistency proofs, and the append-only claim they make checkable.

Design notes D-25 and D-26. A hash chain proves that a log is internally
consistent. It does not prove that the log only ever grew. Whoever holds the
signing key can publish one chain today and a different chain tomorrow, both
internally consistent, with an entry quietly rewritten, and every inclusion
proof against the newer one still verifies. A consistency proof is the thing a
verifier who kept the old root can check without trusting the operator.

This file is in four parts:

  * an exhaustive sweep over every (old_size, new_size) pair up to 64. Proving
    2080 tree pairs by exhaustion is cheaper than reasoning about one, and it
    is what caught the bug the third part pins;
  * the shape of the proof when `old_size` is a power of two, which is exactly
    where the first version of this prover and verifier pair was wrong;
  * the forgeries the verifier has to refuse, one test each, each named after
    the attack it represents;
  * the same machinery over real signed packages driven through the CLI. A
    proof over leaves this file invented says nothing about `attest
    --continue`, which is the feature that makes any of this reachable.
"""
from __future__ import annotations

import json
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from actaira import cli
from actaira.attest import chain, merkle, package, signing
from actaira.attest import verify as verify_mod
from actaira.attest.package import ENTRIES_NAME
from actaira.model import canonical_json
from support.reports import write_record

MAX_TREE = 64

# Pairs used by the negative controls. Chosen to cover both shapes of the
# tree: an old size that is a power of two (a complete subtree, so its root is
# omitted from the proof) and one that is not (the recursion carries a real
# first node), at several distances from the new size.
PAIRS = [
    (1, 2), (1, 5), (2, 3), (3, 5), (4, 9), (5, 8),
    (6, 7), (7, 16), (8, 17), (13, 21), (16, 32), (31, 64),
]
PAIR_IDS = [f"{old}-of-{new}" for old, new in PAIRS]

POWERS_OF_TWO = (1, 2, 4, 8, 16, 32)


def leaves_for(count: int) -> list[bytes]:
    return [merkle.leaf_hash(f"entry-{index}".encode()) for index in range(count)]


def proof_for(new_size: int, old_size: int) -> tuple[list[bytes], bytes, bytes, list[str]]:
    """`(leaves, old_root, new_root, proof)` for an honest pair of trees."""
    leaves = leaves_for(new_size)
    return (
        leaves,
        merkle.build_root(leaves[:old_size]),
        merkle.build_root(leaves),
        merkle.build_consistency_proof(leaves, old_size),
    )


# ---------------------------------------------------------------------------
# The sweep
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("new_size", range(1, MAX_TREE + 1))
def test_every_old_size_proves_its_own_extension(new_size):
    """Every (old_size, new_size) pair up to 64, parametrised by new_size so a
    failure names the tree it happened in.

    Both halves of the contract are asserted, not just the positive one. A
    tree that did not grow needs no proof at all, and a tree that did grow
    needs at least one node: a prover that returned an empty list for a real
    extension would pass a check that only looked at `verify_consistency`.
    """
    new_leaves = leaves_for(new_size)
    new_root = merkle.build_root(new_leaves)

    for old_size in range(1, new_size + 1):
        old_root = merkle.build_root(new_leaves[:old_size])
        proof = merkle.build_consistency_proof(new_leaves, old_size)

        assert merkle.verify_consistency(old_root, old_size, new_root, new_size, proof), (
            f"a tree of {new_size} leaves failed to prove it extends its own first {old_size}"
        )
        if old_size == new_size:
            assert proof == [], "a tree that did not grow has nothing to prove"
        else:
            assert proof, f"growing {old_size} -> {new_size} must cost at least one proof node"


# ---------------------------------------------------------------------------
# The bug: a power-of-two old_size
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("new_size", range(2, MAX_TREE + 1))
def test_a_power_of_two_old_size_leaves_the_old_root_out_of_the_proof(new_size):
    """The shape, pinned explicitly, because getting it wrong is silent.

    When `old_size` is a power of two the old tree is a complete subtree, so
    RFC 6962's SUBPROOF bottoms out at its own root and emits it as the first
    node. The verifier already holds that value: it is the root it is checking
    against. The reference verifier therefore expects it absent, and
    `build_consistency_proof` strips it
    (`src/actaira/attest/merkle.py:132`).

    Asserting only that the proof verifies would not catch a regression that
    put the node back and loosened the verifier to tolerate it, so the absence
    is asserted as a property of the proof itself.
    """
    new_leaves = leaves_for(new_size)
    new_root = merkle.build_root(new_leaves)
    checked = 0

    for old_size in POWERS_OF_TWO:
        if old_size >= new_size:
            continue
        old_root = merkle.build_root(new_leaves[:old_size])
        proof = merkle.build_consistency_proof(new_leaves, old_size)

        assert old_root.hex() not in proof, (
            f"the proof for old_size {old_size} of {new_size} carries the old root, "
            "which the verifier already has"
        )
        assert merkle.verify_consistency(old_root, old_size, new_root, new_size, proof)
        checked += 1

    assert checked > 0, "no power-of-two old_size fitted under this new_size"


@pytest.mark.parametrize("new_size", range(2, MAX_TREE + 1))
def test_putting_the_old_root_back_into_the_proof_breaks_every_power_of_two_case(new_size):
    """The negative control for the test above, and the bug as it happened.

    The first version of this pair emitted the old root as the leading node.
    Prover and verifier were written from the same misunderstanding, so they
    agreed with each other and disagreed with every other RFC 6962
    implementation. This test reconstructs that proof and requires the current
    verifier to refuse it, so the two can never quietly agree again.
    """
    new_leaves = leaves_for(new_size)
    new_root = merkle.build_root(new_leaves)
    checked = 0

    for old_size in POWERS_OF_TWO:
        if old_size >= new_size:
            continue
        old_root = merkle.build_root(new_leaves[:old_size])
        honest = merkle.build_consistency_proof(new_leaves, old_size)

        assert not merkle.verify_consistency(
            old_root, old_size, new_root, new_size, [old_root.hex(), *honest]
        ), f"the old root was accepted as a proof node for old_size {old_size} of {new_size}"
        checked += 1

    assert checked > 0, "no power-of-two old_size fitted under this new_size"


# ---------------------------------------------------------------------------
# Negative controls: what the verifier has to refuse
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("old_size, new_size", PAIRS, ids=PAIR_IDS)
def test_a_rewritten_leaf_below_old_size_is_refused(old_size, new_size):
    """Rewritten history. The attack the whole mechanism exists for.

    A log operator who holds the signing key edits one entry that was already
    published, then reissues the log. Every inclusion proof against the new
    root still verifies, and the chain is still internally consistent, because
    the operator recomputed it. Only a verifier holding the old root can see
    it, and only by asking for a consistency proof.
    """
    honest = leaves_for(new_size)
    old_root = merkle.build_root(honest[:old_size])

    rewritten = list(honest)
    rewritten[old_size - 1] = merkle.leaf_hash(b"an entry that was quietly edited")
    forged_root = merkle.build_root(rewritten)
    proof = merkle.build_consistency_proof(rewritten, old_size)

    assert merkle.verify_consistency(
        merkle.build_root(rewritten[:old_size]), old_size, forged_root, new_size, proof
    ), "the forged log must be internally consistent, or this test proves nothing"
    assert not merkle.verify_consistency(old_root, old_size, forged_root, new_size, proof)


@pytest.mark.parametrize("old_size, new_size", PAIRS, ids=PAIR_IDS)
def test_a_deleted_entry_is_refused(old_size, new_size):
    """A removed entry, which is rewritten history with the index shifted.

    The operator drops one published entry and appends new ones, so the log
    still grows and the entry count still rises. Every leaf after the deleted
    one moves down a position, which is exactly what the old root commits
    against.
    """
    honest = leaves_for(old_size)
    old_root = merkle.build_root(honest)
    appended = [merkle.leaf_hash(f"appended-{index}".encode()) for index in range(new_size)]

    for dropped in range(old_size):
        truncated = honest[:dropped] + honest[dropped + 1:] + appended
        proof = merkle.build_consistency_proof(truncated, old_size)

        assert not merkle.verify_consistency(
            old_root, old_size, merkle.build_root(truncated), len(truncated), proof
        ), f"a log missing entry {dropped} was accepted as an extension"


@pytest.mark.parametrize("old_size, new_size", PAIRS, ids=PAIR_IDS)
def test_a_proof_built_for_a_different_old_size_is_refused(old_size, new_size):
    """A proof that is honest about the wrong pair of trees.

    Consistency proof nodes carry no size field, so a verifier that did not
    derive its traversal from `old_size` and `new_size` would accept a proof
    generated for a neighbouring size whenever the node count happened to
    match. That would let an operator answer "does this extend the root you
    hold" with a proof about a different prefix entirely.
    """
    leaves, old_root, new_root, _ = proof_for(new_size, old_size)

    for other_size in range(1, new_size + 1):
        if other_size == old_size:
            continue
        wrong = merkle.build_consistency_proof(leaves, other_size)

        assert not merkle.verify_consistency(old_root, old_size, new_root, new_size, wrong), (
            f"a proof built for old_size {other_size} verified as one for {old_size}"
        )


@pytest.mark.parametrize("old_size, new_size", PAIRS, ids=PAIR_IDS)
def test_a_forged_new_root_is_refused(old_size, new_size):
    """A new root the proof does not reach.

    The verifier recomputes two running hashes from the same nodes: one that
    must land on the old root and one that must land on the new one. A
    verifier that checked only the first would accept any new root at all,
    which is the failure mode that would make the whole check decorative.
    """
    _leaves, old_root, new_root, proof = proof_for(new_size, old_size)

    assert merkle.verify_consistency(old_root, old_size, new_root, new_size, proof)
    assert not merkle.verify_consistency(
        old_root, old_size, merkle.leaf_hash(b"a root nobody computed"), new_size, proof
    )


@pytest.mark.parametrize("old_size, new_size", PAIRS, ids=PAIR_IDS)
def test_an_empty_proof_is_refused_when_the_tree_actually_grew(old_size, new_size):
    """The cheapest forgery: assert the extension and supply nothing.

    An empty proof is the correct answer for `old_size == new_size` and only
    then. A verifier that treated "no nodes left to consume" as success would
    accept every pair of unrelated roots for the price of an empty list.
    """
    _leaves, old_root, new_root, _proof = proof_for(new_size, old_size)

    assert not merkle.verify_consistency(old_root, old_size, new_root, new_size, [])
    assert merkle.verify_consistency(new_root, new_size, new_root, new_size, []), (
        "an empty proof stays correct for the one case where nothing grew"
    )


@pytest.mark.parametrize("old_size, new_size", PAIRS, ids=PAIR_IDS)
def test_a_proof_with_one_node_too_many_is_refused(old_size, new_size):
    """A padded proof. The verifier has to consume exactly what it needs.

    Trailing nodes are the room an attacker uses to make one proof fit several
    shapes. `verify_consistency` returns false unless the node list is
    exhausted (`src/actaira/attest/merkle.py:208`), so a proof with slack is a
    refused proof rather than an ignored suffix.
    """
    _leaves, old_root, new_root, proof = proof_for(new_size, old_size)
    padded = [*proof, merkle.leaf_hash(b"one node too many").hex()]

    assert not merkle.verify_consistency(old_root, old_size, new_root, new_size, padded)


@pytest.mark.parametrize("old_size, new_size", PAIRS, ids=PAIR_IDS)
def test_a_proof_with_one_node_too_few_is_refused(old_size, new_size):
    """A truncated proof, and the other half of the same property.

    Running out of nodes mid-traversal must be a refusal, not an early exit
    that returns whatever the running hash happened to be. Every place the
    verifier reaches for a node it first checks that one is there.
    """
    _leaves, old_root, new_root, proof = proof_for(new_size, old_size)

    assert proof, "the pair table must only contain growing trees"
    assert not merkle.verify_consistency(old_root, old_size, new_root, new_size, proof[:-1])


@pytest.mark.parametrize("new_size", [1, 4, 9, 16])
def test_an_old_size_outside_the_tree_is_refused(new_size):
    """A size that names no tree, on both sides of the interface.

    The prover raises rather than returning a proof for a tree that does not
    exist, and the verifier refuses rather than indexing into nothing. Zero
    matters on its own: an empty old tree has the same root as an empty new
    one under `build_root`, so a verifier that skipped the bound could be
    talked into comparing two empty hashes and reporting success.
    """
    leaves = leaves_for(new_size)
    new_root = merkle.build_root(leaves)

    for bad_size in (0, -1, new_size + 1):
        with pytest.raises(ValueError, match="out of range"):
            merkle.build_consistency_proof(leaves, bad_size)
        assert not merkle.verify_consistency(new_root, bad_size, new_root, new_size, [])


# ---------------------------------------------------------------------------
# The same machinery over real signed packages
# ---------------------------------------------------------------------------

@dataclass
class ContinuedChain:
    workspace: Path
    artifacts: list
    key: Path
    first: Path
    second: Path


def clean_artifact(directory: Path, index: int):
    """A record about a file that passes, distinct from its siblings by content.

    `verdict` is suite-authored payload, not something computed: the packaging
    layer never reads inside a payload, and the forgery test below flips this
    field to prove the chain notices.
    """
    return write_record(directory / f"model-{index}.safetensors",
                        payload=b"weights-" + str(index).encode("ascii"),
                        verdict="pass")


_RUN = 0


def attest(reports: list, out: Path, key: Path, continue_from: Path | None = None) -> int:
    """What `attest [--continue]` assembled, against the library that still has it.

    The command went to tag v2.3.0; `chain.load_entries` and
    `package.write_package` did not, and they are what `--continue` was. The
    resumed chain is rebuilt from the earlier package's own bytes rather than
    re-derived, which is the property D-26 is about and the one these tests
    are here to check. `verify_package` first, because continuing from a
    package that does not verify is how a forged history gets adopted.
    """
    global _RUN
    _RUN += 1
    entries: list[chain.Entry] = []
    if continue_from is not None:
        if not verify_mod.verify_package(continue_from).ok:
            print(f"refusing to continue from {continue_from}: it does not verify", file=sys.stderr)
            return cli.EXIT_USAGE
        entries = chain.load_entries(verify_mod._read_entries(continue_from))
    for report in reports:
        # A fresh stamp per run, which is what the clock gave the command. The
        # restart test depends on it: two runs over the same artifacts must not
        # produce the same entries, or "restarted" and "continued" look alike.
        chain.append(entries, report.sha256, report.to_dict(),
                     timestamp=f"2026-{_RUN:02d}-{len(entries) + 1:02d}T00:00:00")
    keypair, _ = signing.load_or_create(key)
    package.write_package(out, entries, keypair)
    return cli.EXIT_OK


def rewrite_one_entry(source: Path, destination: Path) -> Path:
    """Copy a package with one attested verdict flipped and nothing re-signed.

    This is the shape of tampering `verify_package` already rejects: the
    manifest still records the original SHA-256 of `entries.jsonl`, and the
    entry's own hash no longer matches its payload.
    """
    with zipfile.ZipFile(source) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}

    lines = [line for line in members[ENTRIES_NAME].splitlines() if line.strip()]
    first = json.loads(lines[0])
    first["payload"]["verdict"] = "fail" if first["payload"]["verdict"] == "pass" else "pass"
    lines[0] = canonical_json(first)
    members[ENTRIES_NAME] = b"".join(line + b"\n" for line in lines)

    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in sorted(members.items()):
            archive.writestr(name, payload)
    return destination


@pytest.fixture(scope="module")
def continued(tmp_path_factory) -> ContinuedChain:
    """Three artifacts attested, then two more appended to the same chain.

    Built through `cli.main` rather than through the library, because
    `--continue` is the only thing that makes a consistency proof between two
    Actaira packages possible at all (D-26): without it every run starts from
    genesis and the two logs share no history.
    """
    workspace = tmp_path_factory.mktemp("continued-chain")
    artifacts = [clean_artifact(workspace, index) for index in range(5)]
    key = workspace / "signing-key.pem"
    first = workspace / "first.zip"
    second = workspace / "second.zip"

    assert attest(artifacts[:3], first, key) == cli.EXIT_OK
    assert attest(artifacts[3:], second, key, continue_from=first) == cli.EXIT_OK
    return ContinuedChain(workspace, artifacts, key, first, second)


def test_a_continued_package_is_an_append_only_extension_of_the_one_it_resumed(continued):
    """The honest cycle, end to end: attest, attest --continue, verify.

    The entry counts are asserted as a premise. A `--continue` that silently
    started a new chain would still produce a package that verifies on its
    own, and `verify_extends` alone would then be testing the wrong thing.
    """
    older = verify_mod._read_entries(continued.first)
    newer = verify_mod._read_entries(continued.second)

    assert (len(older), len(newer)) == (3, 5)
    assert verify_mod.verify_extends(continued.first, continued.second) == (True, [])
    assert cli.main(["verify", str(continued.second), "--extends", str(continued.first)]) == cli.EXIT_OK


def test_the_first_leaves_of_the_continued_package_are_the_earlier_ones(continued):
    """What "append-only" means at the byte level, checked without the proof.

    The consistency proof is only worth running because the leaves it commits
    to are literally the earlier entries. Asserting that separately means a
    proof that verified over rewritten leaves could not hide behind a green
    `verify_extends`.
    """
    older = verify_mod._read_entries(continued.first)
    newer = verify_mod._read_entries(continued.second)

    assert [canonical_json(entry) for entry in newer[:3]] == [canonical_json(entry) for entry in older]


def test_a_chain_restarted_from_genesis_does_not_extend_the_earlier_package(continued, tmp_path):
    """The negative control for `--continue`, and the reason D-26 exists.

    The same five artifacts are attested again, in the same order, with the
    same key, and without `--continue`. The package verifies perfectly on its
    own. It is still not an extension of the earlier one, because a log you
    restart is not a log: the entries carry fresh timestamps and a chain that
    begins again at genesis.
    """
    restarted = tmp_path / "restarted.zip"
    assert attest(continued.artifacts, restarted, continued.key) == cli.EXIT_OK
    assert verify_mod.verify_package(restarted).ok is True

    ok, problems = verify_mod.verify_extends(continued.first, restarted)

    assert ok is False
    assert any("not an extension" in problem for problem in problems)


def test_a_tampered_older_package_is_refused_before_any_consistency_proof_is_built(
    continued, tmp_path, monkeypatch
):
    """Integrity first. A proof over a forged package proves nothing.

    If the older package can be rewritten, so can the old root, and a
    consistency proof against a root the attacker chose is a proof that the
    attacker's history extends the attacker's history. `verify_extends`
    therefore verifies both packages before it computes anything, and the
    prover is replaced here with a landmine to show that it is never reached.
    """
    def never_called(*_args, **_kwargs):
        raise AssertionError("a consistency proof was built over a package that does not verify")

    forged = rewrite_one_entry(continued.first, tmp_path / "forged.zip")
    assert verify_mod.verify_package(forged).ok is False
    monkeypatch.setattr(merkle, "build_consistency_proof", never_called)

    ok, problems = verify_mod.verify_extends(forged, continued.second)

    assert ok is False
    assert problems and problems[0].startswith("older package does not verify")


def test_continuing_from_a_package_that_does_not_verify_exits_two(continued, tmp_path, capsys):
    """The same refusal one layer up, where a CI job can see it.

    Resuming a chain means copying its entry hashes forward verbatim. Doing
    that from a package whose own signature or chain does not check out would
    launder a forged history into a freshly signed one. This is an environment
    error rather than a scan failure, so it is exit 2 and the output says
    which package was refused.
    """
    forged = rewrite_one_entry(continued.first, tmp_path / "forged.zip")
    capsys.readouterr()

    code = attest(
        [continued.artifacts[0]], tmp_path / "never-written.zip", continued.key, continue_from=forged
    )
    err = capsys.readouterr().err

    assert code == cli.EXIT_USAGE
    assert str(forged) in err
    assert not (tmp_path / "never-written.zip").exists()


# ---------------------------------------------------------------------------
# Resuming a chain: what `load_entries` has to preserve
# ---------------------------------------------------------------------------

def test_resumed_entries_are_rebuilt_byte_for_byte_from_the_file(continued):
    """`load_entries` rebuilds entries, it never re-derives them.

    Recomputing an entry hash while resuming would let a resumed chain quietly
    agree with itself after its content had changed, which is the one thing
    the chain exists to prevent. The assertion is on the canonical bytes, not
    on the fields, because the canonical bytes are what the Merkle leaves are
    hashed from.
    """
    with zipfile.ZipFile(continued.second) as archive:
        lines = [line for line in archive.read(ENTRIES_NAME).splitlines() if line.strip()]

    entries = chain.load_entries(verify_mod._read_entries(continued.second))

    assert [canonical_json(entry.to_dict()) for entry in entries] == lines
    assert [entry.entry_hash for entry in entries] == [json.loads(line)["entry_hash"] for line in lines]


def test_the_resumed_chain_still_verifies_as_a_chain(continued):
    """The property `load_entries` promises the caller: run `verify_chain`
    over the result before trusting it, and it comes back clean.

    The links across the join are the interesting ones. Entry 3 was appended
    in a second process, minutes after entry 2 was written by a first, and its
    `prev_hash` still has to be entry 2's hash.
    """
    entries = chain.load_entries(verify_mod._read_entries(continued.second))
    rebuilt = [entry.to_dict() for entry in entries]

    assert chain.verify_chain(rebuilt) == []
    assert rebuilt[3]["prev_hash"] == rebuilt[2]["entry_hash"]
    assert [entry["index"] for entry in rebuilt] == list(range(5))
