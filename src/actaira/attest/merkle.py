"""RFC 6962 Merkle tree over artifact attestations.

Design note D-11, written because the obvious implementation is wrong in two
specific ways and both are easy to miss.

1. Domain separation. Leaves are hashed as sha256(0x00 || data) and internal
   nodes as sha256(0x01 || left || right). Without the prefixes, an attacker
   who controls a leaf can supply the concatenation of two node hashes as
   leaf data, and that leaf's hash equals an internal node's hash: a second
   preimage on the tree. This is the attack RFC 6962 section 2.1 exists to
   prevent.

2. Pair order. A common shortcut sorts each pair before hashing so the proof
   does not need to carry a side bit. That throws away the position of the
   leaf, so a proof for index i also verifies for a different index with the
   same sibling multiset. Actaira keeps the order and carries an explicit
   `is_right` flag per proof step.

Both properties are asserted by tests (`tests/test_merkle.py`), including a
negative control that constructs the second-preimage collision against an
unprefixed tree and shows it failing here.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


@dataclass(frozen=True)
class ProofStep:
    sibling: str  # hex
    is_right: bool  # True when the sibling sits to the right of the running hash


def build_root(leaves: list[bytes]) -> bytes:
    """Merkle root of already-hashed leaves. Empty tree hashes the empty string."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    level = list(leaves)
    while len(level) > 1:
        nxt: list[bytes] = []
        for index in range(0, len(level) - 1, 2):
            nxt.append(node_hash(level[index], level[index + 1]))
        if len(level) % 2 == 1:
            # Odd node is promoted unchanged, as in RFC 6962.
            nxt.append(level[-1])
        level = nxt
    return level[0]


def build_proof(leaves: list[bytes], index: int) -> list[ProofStep]:
    if not 0 <= index < len(leaves):
        raise IndexError(f"leaf index {index} out of range for {len(leaves)} leaves")
    proof: list[ProofStep] = []
    level = list(leaves)
    position = index
    while len(level) > 1:
        nxt: list[bytes] = []
        for pair_start in range(0, len(level) - 1, 2):
            left, right = level[pair_start], level[pair_start + 1]
            if pair_start == position - (position % 2) and position < len(level) - (len(level) % 2):
                if position % 2 == 0:
                    proof.append(ProofStep(sibling=right.hex(), is_right=True))
                else:
                    proof.append(ProofStep(sibling=left.hex(), is_right=False))
            nxt.append(node_hash(left, right))
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        position //= 2
        level = nxt
    return proof


def verify_proof(leaf: bytes, index: int, proof: list[ProofStep], root: bytes) -> bool:
    running = leaf
    for step in proof:
        sibling = bytes.fromhex(step.sibling)
        running = node_hash(running, sibling) if step.is_right else node_hash(sibling, running)
    return running == root


# ---------------------------------------------------------------------------
# Consistency proofs
# ---------------------------------------------------------------------------
#
# Design note D-25. An inclusion proof answers "is this entry in that tree".
# It says nothing about whether the tree grew honestly. A log operator who
# controls the signing key can publish root A today and root B tomorrow with
# an entry quietly removed or rewritten, and every inclusion proof against B
# still verifies.
#
# A consistency proof closes that: given an older root over n entries and a
# newer root over m >= n, it demonstrates that the first n leaves of the new
# tree are exactly the old ones. Without it, "append-only" is a promise. With
# it, a verifier who kept the old root can check the promise themselves.
#
# This is RFC 6962 section 2.1.2. The implementation follows the reference
# algorithm rather than a shortcut, and the tests include the negative
# control that matters: a tree whose history was rewritten must fail.


def build_consistency_proof(leaves: list[bytes], old_size: int) -> list[str]:
    """Proof that the tree over `leaves` extends a tree over its first `old_size`.

    RFC 6962's SUBPROOF, with one adjustment. When `old_size` is a power of
    two the old tree is a complete subtree, so the recursion bottoms out at
    its own root and emits it as the first node. A verifier already holds
    that value, by definition: it is the root it is checking against. The
    reference verifier therefore expects it absent, and leaving it in makes
    every power-of-two case fail.

    The sweep over all (old, new) pairs in tests/test_merkle.py is what found
    this. The first version of this pair was hand-derived and self-consistent,
    which is the failure mode of writing a prover and a verifier from the
    same misunderstanding: both agreed, and both were wrong against any other
    implementation.
    """
    if not 0 < old_size <= len(leaves):
        raise ValueError(f"old_size {old_size} out of range for {len(leaves)} leaves")
    nodes = _consistency(leaves, old_size, True)
    if _is_power_of_two(old_size) and old_size < len(leaves):
        expected = build_root(leaves[:old_size])
        if nodes and nodes[0] == expected:
            nodes = nodes[1:]
    return [node.hex() for node in nodes]


def _consistency(leaves: list[bytes], old_size: int, is_root: bool) -> list[bytes]:
    size = len(leaves)
    if old_size == size:
        # The old tree is the whole current tree. At the top level nothing
        # needs proving; deeper in the recursion the subtree root is needed.
        return [] if is_root else [build_root(leaves)]
    split = _largest_power_of_two_below(size)
    if old_size <= split:
        return _consistency(leaves[:split], old_size, False) + [build_root(leaves[split:])]
    return [
        *_consistency(leaves[split:], old_size - split, False),
        build_root(leaves[:split]),
    ]


def verify_consistency(
    old_root: bytes, old_size: int, new_root: bytes, new_size: int, proof: list[str]
) -> bool:
    """Check that a tree of `new_size` extends the one that had `old_root`.

    Follows the reference verifier from Certificate Transparency rather than
    a hand-derived version. The first attempt here was hand-derived and
    failed for every old_size that is a power of two, which the (n, m) sweep
    in tests/test_merkle.py caught immediately: proving 29 tree pairs by
    exhaustion is cheaper than reasoning about one.
    """
    if old_size <= 0 or old_size > new_size:
        return False
    if old_size == new_size:
        return old_root == new_root and not proof

    nodes = [bytes.fromhex(step) for step in proof]
    node, last_node = old_size - 1, new_size - 1
    while node % 2 == 1:
        node //= 2
        last_node //= 2

    if node > 0:
        if not nodes:
            return False
        running_old = running_new = nodes[0]
        nodes = nodes[1:]
    else:
        # The old tree is a complete subtree, so its root is not carried in
        # the proof: the verifier already has it.
        running_old = running_new = old_root

    while node > 0:
        if node % 2 == 1:
            if not nodes:
                return False
            running_old = node_hash(nodes[0], running_old)
            running_new = node_hash(nodes[0], running_new)
            nodes = nodes[1:]
        elif node < last_node:
            if not nodes:
                return False
            running_new = node_hash(running_new, nodes[0])
            nodes = nodes[1:]
        node //= 2
        last_node //= 2

    while last_node > 0:
        if not nodes:
            return False
        running_new = node_hash(running_new, nodes[0])
        nodes = nodes[1:]
        last_node //= 2

    return not nodes and running_old == old_root and running_new == new_root


def _largest_power_of_two_below(value: int) -> int:
    power = 1
    while power * 2 < value:
        power *= 2
    return power


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0
