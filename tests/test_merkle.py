"""RFC 6962 Merkle tree: inclusion proofs and the two properties D-11 claims.

The interesting assertions are the negative ones. A proof system that only
proves what it should is easy; one that also refuses what it should not is the
whole point, so every positive case here is paired with the forgery it must
reject.
"""
from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from actaira.attest import merkle

TREE_SIZES = list(range(1, 34))


def leaves_for(count: int) -> list[bytes]:
    return [merkle.leaf_hash(f"entry-{index}".encode()) for index in range(count)]


# ---------------------------------------------------------------------------
# Inclusion proofs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("size", TREE_SIZES)
def test_every_leaf_proves_its_own_inclusion(size):
    """Covers both shapes of the tree: powers of two, and the odd levels where
    the last node is promoted unchanged."""
    leaves = leaves_for(size)
    root = merkle.build_root(leaves)

    for index in range(size):
        proof = merkle.build_proof(leaves, index)
        assert merkle.verify_proof(leaves[index], index, proof, root, size), (
            f"leaf {index} of {size} failed its own proof"
        )


@pytest.mark.parametrize("size", TREE_SIZES)
def test_a_proof_never_verifies_for_a_different_leaf(size):
    """Negative control: a proof is a statement about one position.

    A tree that sorted each pair before hashing would let a proof travel to
    another position with the same sibling multiset, which is exactly how a
    forged inclusion is smuggled past a verifier.
    """
    leaves = leaves_for(size)
    root = merkle.build_root(leaves)

    for index in range(size):
        proof = merkle.build_proof(leaves, index)
        for other in range(size):
            if other == index:
                continue
            assert not merkle.verify_proof(leaves[other], other, proof, root, size)


@pytest.mark.parametrize("size", TREE_SIZES)
def test_a_proof_never_verifies_for_a_different_position(size):
    """The half the test above does not reach, and the one that was false.

    `test_a_proof_never_verifies_for_a_different_leaf` varies the LEAF, so it
    passes on any implementation that hashes a path - which is why it stayed
    green while `verify_proof` ignored `index` entirely and a proof built for
    position 0 verified for every position in the tree. Here the leaf is held
    fixed and only the claimed position moves, which is the statement the
    module docstring makes about `is_right` carrying the position.
    """
    leaves = leaves_for(size)
    root = merkle.build_root(leaves)

    checked = 0
    for index in range(size):
        proof = merkle.build_proof(leaves, index)
        assert merkle.verify_proof(leaves[index], index, proof, root, size)
        for other in range(size):
            if other == index:
                continue
            assert not merkle.verify_proof(leaves[index], other, proof, root, size), (
                f"the proof for leaf {index} of {size} also verified at position {other}"
            )
            checked += 1
    assert checked > 0 or size == 1, "no other position was tried"


@pytest.mark.parametrize("size", TREE_SIZES)
def test_a_position_outside_the_tree_is_refused_by_the_verifier(size):
    """`build_proof` raises on one; the verifier must not accept one either."""
    leaves = leaves_for(size)
    root = merkle.build_root(leaves)
    proof = merkle.build_proof(leaves, 0)

    assert not merkle.verify_proof(leaves[0], -1, proof, root, size)
    assert not merkle.verify_proof(leaves[0], size, proof, root, size)


@pytest.mark.parametrize("size", [2, 3, 5, 8, 17])
def test_flipping_the_side_of_a_single_proof_step_breaks_it(size):
    """The `is_right` flag carries the position. If it were decorative, the
    proof would verify with it flipped."""
    leaves = leaves_for(size)
    root = merkle.build_root(leaves)

    checked = 0
    for index in range(size):
        proof = merkle.build_proof(leaves, index)
        for step_index in range(len(proof)):
            flipped = list(proof)
            flipped[step_index] = replace(
                flipped[step_index], is_right=not flipped[step_index].is_right
            )
            assert not merkle.verify_proof(leaves[index], index, flipped, root, size)
            checked += 1
    assert checked > 0, "no proof had a step to flip; the test asserted nothing"


@pytest.mark.parametrize("size", [1, 4, 9])
def test_a_proof_index_outside_the_tree_is_refused(size):
    leaves = leaves_for(size)
    with pytest.raises(IndexError):
        merkle.build_proof(leaves, size)
    with pytest.raises(IndexError):
        merkle.build_proof(leaves, -1)


# ---------------------------------------------------------------------------
# Second preimage: the reason for the 0x00 / 0x01 prefixes
# ---------------------------------------------------------------------------

def _unprefixed_root(leaves: list[bytes]) -> bytes:
    """The obvious implementation, without domain separation, for comparison."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    level = list(leaves)
    while len(level) > 1:
        nxt = [
            hashlib.sha256(level[index] + level[index + 1]).digest()
            for index in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def test_the_classic_second_preimage_collides_without_domain_separation():
    """First half of the pair: the attack is real, and it is demonstrated here
    rather than asserted in a comment.

    A tree with no prefixes hashes an internal node as sha256(left || right).
    One leaf whose data *is* `left || right` therefore hashes to the same
    value, so a one-leaf tree can claim the root of a two-leaf tree.
    """
    left, right = hashlib.sha256(b"leaf-a").digest(), hashlib.sha256(b"leaf-b").digest()

    honest_root = _unprefixed_root([left, right])
    forged_root = _unprefixed_root([hashlib.sha256(left + right).digest()])

    assert honest_root == forged_root


def test_actaira_does_not_collide_under_the_same_attack():
    """Second half: the same forgery against the real implementation.

    Leaves are sha256(0x00 || data) and nodes sha256(0x01 || l || r), so the
    forged leaf and the honest node hash different preimages and the two trees
    commit to different roots.
    """
    left, right = merkle.leaf_hash(b"leaf-a"), merkle.leaf_hash(b"leaf-b")

    honest_root = merkle.build_root([left, right])
    forged_root = merkle.build_root([merkle.leaf_hash(left + right)])

    assert honest_root != forged_root
    assert honest_root == merkle.node_hash(left, right)
    assert merkle.leaf_hash(left + right) == hashlib.sha256(b"\x00" + left + right).digest()


def test_leaf_and_node_hashing_of_the_same_bytes_differ():
    """The property the test above depends on, stated on its own so a
    regression names itself."""
    payload = b"whatever"
    assert merkle.leaf_hash(payload + payload) != merkle.node_hash(payload, payload)


# ---------------------------------------------------------------------------
# Roots
# ---------------------------------------------------------------------------

def test_root_changes_when_any_leaf_changes():
    leaves = leaves_for(7)
    root = merkle.build_root(leaves)

    for index in range(len(leaves)):
        mutated = list(leaves)
        mutated[index] = merkle.leaf_hash(b"tampered")
        assert merkle.build_root(mutated) != root


def test_root_changes_when_two_leaves_swap_places():
    """Order is part of what the root commits to."""
    leaves = leaves_for(5)
    swapped = list(leaves)
    swapped[1], swapped[3] = swapped[3], swapped[1]

    assert merkle.build_root(swapped) != merkle.build_root(leaves)


def test_single_leaf_tree_roots_at_that_leaf_and_has_an_empty_proof():
    leaf = merkle.leaf_hash(b"only")
    assert merkle.build_root([leaf]) == leaf
    assert merkle.build_proof([leaf], 0) == []
    assert merkle.verify_proof(leaf, 0, [], leaf, 1)
    assert not merkle.verify_proof(merkle.leaf_hash(b"other"), 0, [], leaf, 1)
