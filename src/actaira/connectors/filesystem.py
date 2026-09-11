"""A local directory: the connector that documents the contract with the easy case.

Design note D-85, and the reason this file exists at all when `actaira scan`
already walks a directory.

It exists because it is the only connector that can honestly set
`complete = True`, and a contract whose hardest field is never exercised in the
affirmative is a contract nobody has read. Every other source in this package
answers a question over a wire and gets back whatever the far end chose to say;
this one asks the kernel, which has no reason to lie and no pagination. So this
is where `complete = True` is earned, and the earning is visible: the walk sets
it False the moment a directory refuses to be read, because a walk that skipped
a subtree it could not open enumerated a smaller tree than the one the operator
named, and reporting that as a complete listing would be the exact claim D-80
forbids.

Design note D-85b, on the digest this connector does not publish.

It would be trivial to hash every file here and put the result in
`declared_sha256`, and it would be wrong twice over. `declared_sha256` means
"the source said this", and the source is a directory that said nothing; a
digest this tool computed and then compared against itself is a check that
cannot fail, printed as though it had passed. Worse, it would train the reader
to read `digest_confirmed: true` as meaning something in a report where, for
this connector, it would mean only that Actaira agrees with Actaira. So the
field stays empty, `stage()` reports `digest_confirmed: false`, and the honest
answer to "was this file what it claimed to be" is that nothing claimed
anything. `actaira scan` is what measures these bytes, and it is one command
away.

Design note D-85c, on symlinks.

A symlink inside the tree is a claim about a path that may be outside it. This
connector does not follow one and does not list one: `../../../etc/shadow`
reached through a link in a model directory is not an artifact of that
directory, and enumerating it would put a path the operator never named into a
listing they are about to fetch or scan. Every skipped link is counted and
named in the notes, so the listing says what it declined to look at rather than
being quietly smaller than the tree.
"""
from __future__ import annotations

import os
import urllib.parse
import urllib.request
from pathlib import Path

from .model import Connector, ConnectorError, Discovery, Http, RemoteArtifact
from .registry import register

NAME = "filesystem"

# A directory listing is cheap, so the bound is high; it is here because a walk
# of `/` started by a typo should stop rather than enumerate a machine.
MAX_ENTRIES = 200_000
# Names that are metadata about how the tree is stored rather than artifacts in
# it. Skipped and counted, never listed: a `.git` directory in a model repo is
# thousands of loose objects that no inspector reads.
SKIPPED_DIRECTORIES = {".git", ".hg", ".svn", "__pycache__", ".ipynb_checkpoints"}


def accepts(uri: str) -> bool:
    """An existing directory, or a `file://` URL naming one.

    Deliberately narrow. A path that does not exist is accepted by nobody, so
    the CLI can say "no connector accepts this" instead of this connector
    reporting zero artifacts for a directory the operator misspelt. See design
    note D-84 for why the predicates in this package have to be disjoint.
    """
    return _as_directory(uri) is not None


def _as_directory(uri: str) -> Path | None:
    candidate = uri
    if uri.startswith("file://"):
        parts = urllib.parse.urlsplit(uri)
        # DEF-87: `file://relative/path` has no host component in the sense a
        # filesystem understands, and treating the first segment as a hostname
        # is how `file://tmp/x` silently becomes `/x`. So whatever landed in
        # the authority is folded back in front of the path rather than
        # dropped, and the result is always rooted.
        joined = f"/{parts.netloc}{parts.path}" if parts.netloc else parts.path
        if not joined.startswith("/"):
            joined = "/" + joined
        # `url2pathname`, not a hand-rolled strip: it is the only spelling that
        # turns `/C:/models` back into a drive-rooted path on Windows while
        # leaving `/srv/models` alone on POSIX, and it percent-decodes, which
        # is what a URI means. A hand-rolled strip left every `file://` URI
        # unusable off POSIX - the connector answered "not a directory" for a
        # directory that was right there.
        candidate = urllib.request.url2pathname(joined)
    try:
        path = Path(candidate).expanduser()
    except (OSError, ValueError):
        return None
    try:
        return path if path.is_dir() else None
    except OSError:
        return None


def discover(uri: str, *, http: Http, revision: str | None = None) -> Discovery:
    """Walk a directory and list the regular files under it.

    `http` is accepted and never used, so that the CLI has one call shape for
    every connector. `revision` is likewise accepted and ignored, and the note
    says so: a directory has no revisions, and silently pretending `--revision`
    did something would be worse than saying it did not.
    """
    root = _as_directory(uri)
    if root is None:
        raise ConnectorError(f"{uri!r} is not a directory this process can read")

    artifacts: list[RemoteArtifact] = []
    notes: list[str] = []
    unreadable: list[str] = []
    symlinks = 0
    complete = True

    def on_error(error: OSError) -> None:
        # os.walk swallows errors by default, which for this connector would
        # mean a subtree nobody could open vanishing from the listing without
        # a word. This is the whole reason the walk is written by hand.
        unreadable.append(str(getattr(error, "filename", "?")))

    for directory, subdirectories, filenames in os.walk(root, onerror=on_error, followlinks=False):
        subdirectories[:] = sorted(
            name for name in subdirectories
            if name not in SKIPPED_DIRECTORIES and not os.path.islink(os.path.join(directory, name))
        )
        for name in sorted(filenames):
            absolute = Path(directory) / name
            if absolute.is_symlink():
                symlinks += 1
                continue
            try:
                size = absolute.stat().st_size
            except OSError as exc:
                unreadable.append(f"{absolute}: {exc.strerror}")
                continue
            if not absolute.is_file():
                # A fifo or a device node is not an artifact and reading one
                # can block forever. Counted as unreadable rather than listed.
                unreadable.append(f"{absolute}: not a regular file")
                continue
            artifacts.append(
                RemoteArtifact(
                    # `as_posix`, not `str`: this path is written into the
                    # discovery, the provenance and the subject manifest, and
                    # a listing that spells the same tree `nested/w.pt` on one
                    # machine and `nested` + backslash + `w.pt` on another is a
                    # document two people cannot compare. See D-238; the local
                    # absolute path, which is genuinely platform-shaped, stays
                    # in `extra` where nothing compares it.
                    path=absolute.relative_to(root).as_posix(),
                    uri=absolute.resolve().as_uri(),
                    size_bytes=size,
                    declared_sha256=None,  # design note D-85b
                    revision=None,
                    source=NAME,
                    extra={"local_path": str(absolute)},
                )
            )
            if len(artifacts) >= MAX_ENTRIES:
                complete = False
                notes.append(
                    f"stopped at {MAX_ENTRIES} files; this listing is a prefix of the tree, not the tree"
                )
                break
        if not complete:
            break

    if unreadable:
        complete = False
        shown = ", ".join(sorted(unreadable)[:5])
        notes.append(
            f"{len(unreadable)} path(s) could not be read, so the walk covered less than the tree: {shown}"
        )
    if symlinks:
        notes.append(
            f"{symlinks} symlink(s) were not followed and are not listed; a link is a claim about a "
            "path outside this tree (design note D-85c)"
        )
    if revision is not None:
        notes.append("a directory has no revisions; --revision was ignored")
    notes.append(
        "this listing is complete because a walk can prove it, which is true of no other connector here"
        if complete
        else "the walk did not cover the whole tree; see the note above"
    )
    notes.append(
        "no digest is declared: nothing here published one, and a digest Actaira computed and then "
        "checked against itself would be a check that cannot fail (design note D-85b)"
    )

    return Discovery(
        source=f"{NAME}:{root}",
        artifacts=tuple(artifacts),
        complete=complete,
        hosts_contacted=(),
        notes=tuple(notes),
        revision=None,
    )


CONNECTOR = register(
    Connector(
        name=NAME,
        summary_key="connector.filesystem",
        needs_network=False,
        discover=discover,
        accepts=accepts,
    )
)
