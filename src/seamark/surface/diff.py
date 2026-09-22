"""What changed between two surfaces, and what git is allowed to be asked for.

Two halves that never touch each other. `surface_diff` is a pure function of two
`surface/v1` documents: it pairs capabilities, names each pairing with one of
five changes, and refuses to name one when either side is INDETERMINATE.
`materialise` is the only thing here that runs a program, and the program is
`git ls-tree` and `git cat-file` and nothing else.

Design note D-294. WHY NOT CHECK OUT EACH REF. `git checkout` writes in the
operator's own working tree, moves HEAD, and runs their `post-checkout` hook -
which is somebody else's code, executed to answer a question about somebody
else's code. That is the fourth negative and the vector at once. `git worktree
add` avoids the first two and still runs hooks and smudge filters. `cat-file`
hands over the blob as it is stored, applies no filter, no textconv and no hook,
and writes where we say.

WHY NOT READ THE BLOBS IN PLACE. The seven readers take a directory. Teaching
them a virtual filesystem is seven modules of change to answer one question, and
the temporary tree costs a copy of files that are already in memory.

Design note D-293. The tree is materialised WHOLE, not filtered to the paths the
readers know about. A filter would be a second copy of each reader's path list -
and worse, `diff` would then answer about a subset of the tree while `check`
answers about all of it, so the two commands would disagree about the same
repository for a reason no output would explain. The ceilings below are a
refusal with a stated number rather than a silent subset.
"""
from __future__ import annotations

import hashlib
import os
import subprocess  # noqa: S404 - two read-only git plumbing commands, argv lists, never a shell
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from ..model import canonical_json
from . import Resolution
from .disk import inside

# Ceilings on what may be materialised, checked from the listing BEFORE a byte
# is written, so the refusal is instant and nothing is half-extracted. Generous
# for a repository whose agent configuration anybody wants to diff, and a
# stated refusal for one that is something else.
MAX_TREE_FILES = 50_000
MAX_TREE_BYTES = 256 * 1024 * 1024

# How much a single `cat-file --batch` round may be asked for, in bytes of blob.
#
# The first version of this was a count of objects, with a comment about pipe
# deadlock. Both were wrong, and the comment was the more wrong of the two:
# `subprocess.run(input=...)` goes through `communicate()`, which pumps both
# pipes at once, so there is no interleaving to deadlock. What the bound is
# actually for is MEMORY - `communicate()` buffers the whole answer - and a
# count of 256 bounds nothing when 256 objects can be a gigabyte. Sizes come
# free with `ls-tree -l`, so the budget is over the sizes.
BATCH_BYTES = 32 * 1024 * 1024

# Git's own mode for a symbolic link. Materialised as an ORDINARY file holding
# the target text, never as a link: a tree that can plant `logs -> /etc` makes
# the next write to `logs/x` land outside the extraction, and a repository that
# arrives by pull request is exactly the input this must not trust.
SYMLINK_MODE = "120000"
# A gitlink, which is a commit id and not a blob. There is nothing to extract;
# it is recorded so a submodule reads as named rather than as absent.
GITLINK_MODE = "160000"


class GitError(ValueError):
    """Git was asked for something and said no. A usage error, never a traceback."""


# Flags on every invocation, each one refusing a way git can run a program.
# They are not decoration: `ls-tree` and `cat-file` run no hook and apply no
# filter by themselves, and every line here closes a route by which the
# repository being read could still get something executed.
#
#   --no-pager            git spawns $PAGER for some commands; nothing here
#                         pages, and a pager is a program the operator's
#                         environment chooses.
#   --no-optional-locks   never touch .git/index. The gate is that the working
#                         tree is byte-identical afterwards, and an index
#                         refresh is a write.
#   core.fsmonitor=false  an fsmonitor hook is a program git STARTS, configured
#                         by the repository's own config.
#   core.hooksPath        pointed at a path inside the repository that cannot
#                         exist, so a hook cannot be found even if a future git
#                         grew one here.
#
# Not set, and deliberately: `core.attributesFile` and `diff.*.textconv`.
# textconv is applied only when `--textconv` is passed, and neither command
# below passes it; setting it would suggest the risk is handled by a flag
# rather than by not asking for it.
NO_SUCH_HOOKS_DIR = "seamark-no-hooks-directory"


def _git(repo: Path, *arguments: str) -> list[str]:
    return [
        "git",
        "-C",
        str(repo),
        "--no-pager",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={NO_SUCH_HOOKS_DIR}",
        *arguments,
    ]


def _environment() -> dict[str, str]:
    """The environment git runs in: no terminal, no credential helper, no editor.

    Nothing below needs any of them, and a repository that could make git ask
    for a password would have made this command hang in CI rather than answer.
    """
    return {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
    }


def refuse_option_shaped(ref: str) -> None:
    """A ref that starts with `-` is refused before git ever sees it.

    `--` is passed on every command line below, so git would read it as a path
    rather than as an option. This refuses it anyway and one layer earlier: the
    separator is one edit away from being dropped by somebody adding an
    argument, and the consequence of dropping it is that the repository under
    examination chooses a git flag.
    """
    if ref.startswith("-"):
        raise GitError(
            f"{ref!r} is refused: a ref that starts with `-` is an option to every "
            "program that has ever parsed a command line, and this one names the "
            "thing being examined."
        )


@dataclass(frozen=True)
class Blob:
    """One entry of a recursive tree listing."""

    mode: str
    kind: str
    object_id: str
    size: int
    path: str


@dataclass(frozen=True)
class Extraction:
    """A ref materialised into a directory, and what was not materialised."""

    root: Path
    label: str
    tree_sha256: str
    files: int
    refused: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "kind": "git-ref",
            "tree_sha256": self.tree_sha256,
            "files": self.files,
        }


def _run(argv: list[str], *, stdin: bytes | None = None) -> bytes:
    try:
        finished = subprocess.run(  # noqa: S603 - a fixed argv, a list, never a shell
            argv,
            input=stdin,
            capture_output=True,
            timeout=300,
            env=_environment(),
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git is not on PATH, so two refs cannot be compared") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError("git did not answer within 300 seconds") from exc
    if finished.returncode != 0:
        detail = finished.stderr.decode("utf-8", "replace").strip().splitlines()
        raise GitError(detail[0] if detail else f"git exited {finished.returncode}")
    return finished.stdout


def listing(repo: Path, ref: str) -> tuple[Blob, ...]:
    """Every blob one ref's tree holds, recursively, with its size.

    `-l` so the sizes arrive without reading a single object: the ceilings are
    checked against the listing, so a tree that is refused costs one command
    rather than a partially written directory.
    """
    refuse_option_shaped(ref)
    raw = _run(_git(repo, "ls-tree", "-r", "-l", "-z", ref, "--"))
    found: list[Blob] = []
    for record in raw.split(b"\x00"):
        if not record:
            continue
        head, _, path = record.decode("utf-8", "surrogateescape").partition("\t")
        parts = head.split()
        if len(parts) != 4:
            raise GitError(f"git ls-tree printed a record this reader cannot parse: {head!r}")
        mode, kind, object_id, size = parts
        found.append(
            Blob(mode=mode, kind=kind, object_id=object_id,
                 size=0 if size == "-" else int(size), path=path)
        )
    return tuple(found)


def tree_digest(blobs: tuple[Blob, ...]) -> str:
    """A name for the tree that two runs and two machines agree on.

    `git ls-tree` prints the entries, not the id of the root tree, and getting
    that id would mean a third git subcommand. This is a digest over the whole
    recursive listing - every mode, type, object id and path - which identifies
    the tree exactly as tightly and is computed from what we already asked for.
    """
    material = b"".join(
        canonical_json([blob.mode, blob.kind, blob.object_id, blob.path]) + b"\n"
        for blob in sorted(blobs, key=lambda item: item.path)
    )
    return hashlib.sha256(material).hexdigest()


def _safe_target(root: Path, spoken: str) -> Path | None:
    """Where a listed path may be written, or None if it may not be written at all.

    Git's own tree format forbids `..` and absolute paths, so this should never
    fire. It fires anyway, because "the format forbids it" is a statement about
    a producer and the input here is a repository somebody else wrote.
    """
    if not spoken or spoken.startswith("/") or "\\" in spoken:
        return None
    parts = spoken.split("/")
    if any(part in ("", "..", ".") for part in parts):
        return None
    target = root.joinpath(*parts)
    # Belt and braces over the component check above, and the one that would
    # still hold if a future git spelled a path some way not thought of here.
    return target if inside(root, target) else None


def materialise(repo: Path, ref: str, dest: Path, *, label: str | None = None) -> Extraction:
    """Write one ref's tree into `dest`, touching nothing of the operator's.

    `dest` is a fresh directory the caller owns. Nothing under the repository
    being read is written, read through a filter, or asked to run.
    """
    blobs = listing(repo, ref)
    dest.mkdir(parents=True, exist_ok=True)

    wanted = [blob for blob in blobs if blob.kind == "blob"]
    if len(wanted) > MAX_TREE_FILES:
        raise GitError(
            f"{ref} holds {len(wanted)} files and the ceiling is {MAX_TREE_FILES}. "
            "Nothing was written. Compare two directories with --from-dir and --to-dir "
            "if this is the tree you meant."
        )
    total = sum(blob.size for blob in wanted)
    if total > MAX_TREE_BYTES:
        raise GitError(
            f"{ref} holds {total} bytes and the ceiling is {MAX_TREE_BYTES}. "
            "Nothing was written."
        )

    refused: list[str] = []
    pending: list[Blob] = []
    for blob in wanted:
        if _safe_target(dest, blob.path) is None:
            refused.append(f"{blob.path}: the listed path would not stay inside the extraction")
            continue
        pending.append(blob)
    for blob in blobs:
        if blob.mode == GITLINK_MODE:
            refused.append(f"{blob.path}: a submodule, which is a commit id and not a file here")

    _extract(repo, pending, dest)
    return Extraction(
        root=dest,
        label=label or ref,
        tree_sha256=tree_digest(blobs),
        files=len(pending),
        refused=tuple(sorted(refused)),
    )


def rounds(blobs: list[Blob]) -> list[list[Blob]]:
    """Split the work so no single answer weighs more than `BATCH_BYTES` in memory.

    A blob larger than the budget still goes on its own: splitting an object is
    not something `cat-file` offers, and a tree holding one is inside
    `MAX_TREE_BYTES` or it was refused before any of this ran.
    """
    found: list[list[Blob]] = []
    current: list[Blob] = []
    weight = 0
    for blob in blobs:
        if current and weight + blob.size > BATCH_BYTES:
            found.append(current)
            current, weight = [], 0
        current.append(blob)
        weight += blob.size
    if current:
        found.append(current)
    return found


def _extract(repo: Path, blobs: list[Blob], dest: Path) -> None:
    """`cat-file --batch`, in rounds bounded by what each answer will weigh."""
    if not blobs:
        return
    argv = _git(repo, "cat-file", "--batch")
    for round_of in rounds(blobs):
        request = "".join(f"{blob.object_id}\n" for blob in round_of).encode("ascii")
        answer = _run(argv, stdin=request)
        _write_round(round_of, answer, dest)


def _write_round(blobs: list[Blob], answer: bytes, dest: Path) -> None:
    at = 0
    for blob in blobs:
        end = answer.find(b"\n", at)
        if end == -1:
            raise GitError("git cat-file stopped in the middle of its answer")
        header = answer[at:end].decode("ascii", "replace").split()
        if len(header) < 3:
            raise GitError(f"git cat-file could not produce {blob.path}: {' '.join(header)}")
        size = int(header[2])
        body = answer[end + 1:end + 1 + size]
        at = end + 1 + size + 1  # git writes a newline after the object
        target = _safe_target(dest, blob.path)
        if target is None:  # pragma: no cover - filtered before the request
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        # A symlink's blob IS the target path, written as an ordinary file.
        target.write_bytes(body)


# ---------------------------------------------------------------------------
# The comparison, which runs no program and reads no disk
# ---------------------------------------------------------------------------


class Change(StrEnum):
    """What one pairing of capabilities is. Five, and never a sixth.

    INDETERMINATE is not one of the five and is kept in its own list for the
    reason `surface/v1` keeps three lists: a consumer that could add it to the
    others would be reporting "I could not tell" as one of the answers that
    were given.
    """

    ADDED = "added"
    REMOVED = "removed"
    WIDENED = "widened"
    NARROWED = "narrowed"
    CHANGED = "changed"


# Design note D-295. The only facts over which this module claims an order, and
# the rule for admitting one: the fact's OWN NAME has to state which value is the wider one.
# `guardrail_removed` true is wider than false by what the words mean, and the
# name was minted by `resolve.py` to mean exactly that.
#
# Rejected: ordering `permissions.default_mode`, `pinned`, `loopback` and
# `inside_tree`, each of which a reader can order in their head. The vendors
# publish what those values DO and publish no ordering of them, so an order
# here would be Seamark's opinion about somebody else's software wearing the
# costume of a comparison - the second negative. They come out CHANGED, with
# both digests, which is the answer a reviewer can act on without being told
# what to think about it.
#
# Rejected also: a superset rule over list-valued facts. No capability carries
# one. `permissions.allow` and `sandbox.excludedCommands` are emitted one
# capability per entry, so a list that grows is an ADDED capability with its
# own source and its own rules - which is more precise than one row that got
# wider, not less.
#
# Each entry is `fact -> (True is the wider value, the facts it SUMMARISES)`.
# The second half is load-bearing and was missing at first, which made the whole
# table dead. `resolve.py` emits Codex's `approval_policy` as
# `{"policy": "never", "guardrail_removed": True}`: the string is the evidence
# and the boolean is the reading of it, minted for that purpose and spelled the
# same way for Codex's two keys and for Gemini's (phase S2, gate point 9). Count
# the string as an unordered difference and every such pairing comes out CHANGED,
# so nothing is ever widened and the five kinds are four. Both digests travel in
# the entry either way, so nothing is hidden by letting the summary decide.
WIDER_WHEN_TRUE: dict[str, tuple[bool, tuple[str, ...]]] = {
    "guardrail_removed": (True, ("policy", "mode")),
    "isolation_weakened": (True, ("enabled", "allowUnsandboxedCommands")),
    "widens_managed": (True, ()),
}

# The one ladder inside Seamark's own vocabulary: a capability that was written
# down and is now in force has widened. Both states are ours, both are defined
# in `surface/__init__.py`, and ordering them commits to nothing about a vendor.
_RESOLUTION_RANK = {Resolution.DECLARED.value: 1, Resolution.EFFECTIVE.value: 2}

IDENTITY = ("vendor", "capability", "scope", "source")
# Compared for equality but never ordered. `merge_rule` and `condition` are
# prose and a citation; a difference in either is a CHANGED, never a direction.
COMPARED = ("resolution", "merge_rule", "condition")


def capability_digest(capability: dict[str, Any]) -> str:
    """sha256 over the canonical bytes of one capability. What a seal binds to."""
    return hashlib.sha256(canonical_json(capability)).hexdigest()


def _identity(capability: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(capability.get(field_name, "")) for field_name in IDENTITY)


@dataclass
class Side:
    """One side of one pairing: what was there, and what fired on it."""

    capability: dict[str, Any]
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolution": self.capability.get("resolution"),
            "merge_rule": self.capability.get("merge_rule"),
            "condition": self.capability.get("condition"),
            "facts": self.capability.get("facts", {}),
            "digest": capability_digest(self.capability),
            "findings": self.findings,
        }


def _findings_by_digest(document: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Every finding, keyed by the digest of the capability it was raised about.

    A finding's `evidence` carries every field of the capability it came from -
    `rules.evaluate` puts them there - so the capability can be rebuilt from the
    finding and digested with the same function. That is why no second index is
    kept anywhere: the association is derived, not stored, and cannot drift.
    """
    index: dict[str, list[dict[str, Any]]] = {}
    for finding in document.get("findings", []):
        evidence = finding.get("evidence", {})
        rebuilt = {
            "capability": evidence.get("capability"),
            "vendor": evidence.get("vendor"),
            "scope": evidence.get("scope"),
            "source": finding.get("location"),
            "resolution": evidence.get("resolution"),
            "merge_rule": evidence.get("merge_rule"),
            "condition": evidence.get("condition"),
            "facts": evidence.get("facts", {}),
        }
        index.setdefault(capability_digest(rebuilt), []).append(finding)
    return index


def _direction(before: dict[str, Any], after: dict[str, Any]) -> int | None:
    """+1 widened, -1 narrowed, None when no order covers what differs.

    None is the default and the honest one. A direction is returned only when
    EVERY difference between the two sides is one of the ordered ones and they
    all point the same way; one unordered difference alongside makes the whole
    pairing CHANGED, because a capability that widened in one respect and moved
    in another has not simply widened.
    """
    signals: set[int] = set()
    for name in COMPARED:
        if before.get(name) == after.get(name):
            continue
        if name != "resolution":
            return None
        ranks = (_RESOLUTION_RANK.get(before.get(name)), _RESOLUTION_RANK.get(after.get(name)))
        if None in ranks:
            return None
        signals.add(1 if ranks[1] > ranks[0] else -1)

    old_facts = before.get("facts", {}) or {}
    new_facts = after.get("facts", {}) or {}
    moved = {
        key
        for key in set(old_facts) | set(new_facts)
        if old_facts.get(key) != new_facts.get(key)
        or key not in old_facts
        or key not in new_facts
    }
    summarised: set[str] = set()
    for key in moved & set(WIDER_WHEN_TRUE):
        if not isinstance(old_facts.get(key), bool) or not isinstance(new_facts.get(key), bool):
            return None
        wider_when_true, covers = WIDER_WHEN_TRUE[key]
        signals.add((1 if new_facts[key] else -1) * (1 if wider_when_true else -1))
        summarised.update(covers)
    if moved - set(WIDER_WHEN_TRUE) - summarised:
        return None

    if len(signals) != 1:
        return None
    return signals.pop()


def _indeterminate_side(capability: dict[str, Any]) -> bool:
    return capability.get("resolution") == Resolution.INDETERMINATE.value


def surface_diff(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    before_label: dict[str, Any],
    after_label: dict[str, Any],
) -> dict[str, Any]:
    """The `surface-diff/v1` document for two `surface/v1` documents.

    Pure: two mappings in, one mapping out, the same bytes every time. Nothing
    here opens a file, runs a program or reads a clock, so a diff can be replayed
    from two documents somebody kept.
    """
    from ..schemas import VERSIONS

    before_findings = _findings_by_digest(before)
    after_findings = _findings_by_digest(after)

    def sided(capability: dict[str, Any], index: dict[str, list[dict[str, Any]]]) -> Side:
        return Side(capability, index.get(capability_digest(capability), []))

    left: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    right: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for document, into in ((before, left), (after, right)):
        for surface in document.get("surfaces", []):
            for capability in surface.get("capabilities", []):
                into.setdefault(_identity(capability), []).append(capability)

    buckets: dict[str, list[dict[str, Any]]] = {member.value: [] for member in Change}
    gaps: list[dict[str, Any]] = []
    unchanged = 0

    for key in sorted(set(left) | set(right)):
        old = sorted(left.get(key, []), key=capability_digest)
        new = sorted(right.get(key, []), key=capability_digest)

        common = {capability_digest(item) for item in old} & {capability_digest(item) for item in new}
        unchanged += sum(1 for item in new if capability_digest(item) in common)
        old = [item for item in old if capability_digest(item) not in common]
        new = [item for item in new if capability_digest(item) not in common]

        head = dict(zip(IDENTITY, key, strict=True))
        for index in range(max(len(old), len(new))):
            was = old[index] if index < len(old) else None
            now = new[index] if index < len(new) else None
            entry = dict(head)
            entry["before"] = sided(was, before_findings).to_dict() if was else None
            entry["after"] = sided(now, after_findings).to_dict() if now else None

            if (was is not None and _indeterminate_side(was)) or (
                now is not None and _indeterminate_side(now)
            ):
                stuck = now if now is not None and _indeterminate_side(now) else was
                gaps.append({
                    # "a change to ..." rather than the bare capability name, so
                    # this line and the rules gap the same capability also
                    # produces read as the two different statements they are:
                    # one says the capability moved, the other says a rule could
                    # not answer about it.
                    "subject": "a change to {} {}".format(head["vendor"], head["capability"]),
                    "cause": (stuck or {}).get("condition")
                    or "one side of this change could not be resolved",
                    "source": head["source"],
                })
                continue

            if was is None:
                buckets[Change.ADDED.value].append(entry)
                continue
            if now is None:
                buckets[Change.REMOVED.value].append(entry)
                continue
            direction = _direction(was, now)
            if direction == 1:
                buckets[Change.WIDENED.value].append(entry)
            elif direction == -1:
                buckets[Change.NARROWED.value].append(entry)
            else:
                buckets[Change.CHANGED.value].append(entry)

    # A gap the second side has and the first did not: something arrived that
    # nobody could resolve, which is a change and is not one of the five.
    was_gap = {
        (item["subject"], item["cause"], item["source"]) for item in before.get("unresolved", [])
    }
    for item in after.get("unresolved", []):
        row = (item["subject"], item["cause"], item["source"])
        if row not in was_gap:
            gaps.append(dict(item))

    seen: set[tuple[str, str, str]] = set()
    unique_gaps = []
    for item in gaps:
        row = (item["subject"], item["cause"], item["source"])
        if row in seen:
            continue
        seen.add(row)
        unique_gaps.append(item)

    return {
        "schema_version": VERSIONS["surface-diff"],
        "before": before_label,
        "after": after_label,
        "added": buckets[Change.ADDED.value],
        "removed": buckets[Change.REMOVED.value],
        "widened": buckets[Change.WIDENED.value],
        "narrowed": buckets[Change.NARROWED.value],
        "changed": buckets[Change.CHANGED.value],
        "indeterminate": sorted(unique_gaps, key=lambda item: (item["subject"], item["cause"])),
        "unchanged": unchanged,
        "not_read": after.get("not_read", []),
        "merge_rules": after.get("merge_rules", []),
    }


def fired_on_new_capability(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Every finding raised on something ADDED or WIDENED, which is what exit 1 is.

    Design note D-299.

    Not every finding in the repository: `check` is the command that lists what
    is there. `diff` answers what changed, so what it can exit non-zero about is
    what arrived - and a finding that was already there and is still there is
    not a reason for this command to object to this pull request.
    """
    found: list[dict[str, Any]] = []
    for kind in (Change.ADDED.value, Change.WIDENED.value):
        for entry in document.get(kind, []):
            found.extend((entry.get("after") or {}).get("findings", []))
    return found


__all__ = [
    "BATCH_BYTES",
    "Blob",
    "Change",
    "Extraction",
    "GitError",
    "MAX_TREE_BYTES",
    "MAX_TREE_FILES",
    "WIDER_WHEN_TRUE",
    "capability_digest",
    "fired_on_new_capability",
    "listing",
    "materialise",
    "refuse_option_shaped",
    "rounds",
    "surface_diff",
    "tree_digest",
]
