"""Machine-readable scan reports for CI.

The scan verdict already travels in the exit code, which is
the whole interface for a shell. A CI *interface* needs more than that: GitHub
code scanning ingests SARIF 2.1.0, and every other runner reads JUnit XML. Both
formats are built here from the same `ArtifactReport` list the CLI already has,
so no inspector knows that either format exists.

One rule is shared by both writers and lives here: the path a report shows is
the artifact's path relative to the directory the scan was run from. An
absolute path from a build agent is noise in a pull request, and, for SARIF,
GitHub resolves a result's URI against the repository root, so an absolute
`/home/runner/work/...` would point at a file the annotation layer cannot find.
When the artifact is genuinely outside that root the absolute path is kept:
inventing a relative one would name a file that is not there.
"""
from __future__ import annotations

from pathlib import Path


def artifact_uri(path: str | Path, base: str | Path | None = None) -> str:
    """The artifact's path as a report should show it, POSIX separators.

    `base` defaults to the current working directory, which under a GitHub
    runner is the repository root.
    """
    target = Path(path)
    root = Path(base) if base is not None else Path.cwd()
    try:
        return target.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return target.as_posix()
