"""Read `devcontainer.json`, where one of the six lifecycle commands is not contained.

Design note D-283. The whole reason this vendor is read separately from VS Code
is one sentence in the specification: `initializeCommand` is "A command string
or list of command arguments to run on the **host machine** during
initialization". The other five lifecycle commands run inside the container,
which is a boundary somebody chose; `initializeCommand` runs outside it, before
any container exists, on the developer's own machine - so a repository that
carries one has code execution on every machine that opens it, and the container
that was supposed to be the containment is not built yet.

That is a capability, not a verdict. Repositories use `initializeCommand`
legitimately to create a directory or check a socket. Actaira says it is there,
where it runs, and the digest of what it points at; whether that is acceptable
is the reader's decision and a rule someone else wrote is what names it.

The second fact this reader is here for is `mounts`. A dev container that mounts
`~/.ssh` or `~/.aws` has handed the agent inside it the developer's credentials,
and unlike a lifecycle command it does so silently and for the whole life of
the container.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import Capability, NotRead, Resolution, Scope, Surface, Unresolved
from .disk import (
    Reading,
    SettingsFile,
    digest_of,
    git_tracked,
    referenced_path,
    script_facts,
)
from .emit import emit, referenced_target, target_facts
from .vscode import read_jsonc

VENDOR = "devcontainer"

# The locations the specification lists, in the order it lists them. The third
# is one level deep under `.devcontainer/`, and the specification says a tool
# should let the user choose when more than one exists - so all of them are
# read and each capability names the file it came from, rather than one being
# picked here on a rule the specification does not state.
WELL_KNOWN = (".devcontainer/devcontainer.json", ".devcontainer.json")

# Every lifecycle command, and whether the specification says it runs on the
# host. One `True` in this table, and it is the point of the module.
LIFECYCLE: dict[str, bool] = {
    "initializeCommand": True,
    "onCreateCommand": False,
    "updateContentCommand": False,
    "postCreateCommand": False,
    "postStartCommand": False,
    "postAttachCommand": False,
}

# Paths whose appearance in a `mounts` source hands over a credential. Matched
# on the SOURCE of the mount, spelled as a path, and never on what is inside it:
# this reader does not open the directory, it reports that the configuration
# names it.
CREDENTIAL_SOURCES = (
    ".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config/gcloud", ".azure",
    ".gitconfig", ".netrc", ".npmrc", ".pypirc",
)

_MOUNT_FIELD = re.compile(r"(?:^|,)\s*(?P<key>[a-zA-Z-]+)\s*=\s*(?P<value>[^,]*)")


def locations(root: Path) -> list[str]:
    """Every `devcontainer.json` in the tree, bounded to the documented shapes."""
    found = [name for name in WELL_KNOWN if (root / name).is_file()]
    base = root / ".devcontainer"
    if base.is_dir():
        for child in sorted(base.iterdir()):
            if child.is_dir() and (child / "devcontainer.json").is_file():
                found.append(f".devcontainer/{child.name}/devcontainer.json")
    return found


def commands_of(value: Any) -> list[str]:
    """A lifecycle command in each of its three documented shapes.

    A string, a list of argv, or an object of named commands that run in
    parallel. All three are flattened to the strings that will be run, because
    every one of them is a command and a reader that understood only the first
    would miss two thirds of the real files.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        parts = [item for item in value if isinstance(item, str)]
        # An argv list is ONE command. Joining is what makes its digest
        # comparable with the string spelling of the same command.
        return [" ".join(parts)] if parts else []
    if isinstance(value, dict):
        found: list[str] = []
        for key in sorted(value):
            found.extend(commands_of(value[key]))
        return found
    return []


def mount_source(entry: Any) -> str | None:
    """The host path a mount entry names, in either documented spelling.

    The object spelling has a `source` key. The string spelling "accepts the
    same values as the Docker CLI `--mount` flag", which is comma-separated
    `key=value` pairs, so `source=` and its `src=` alias are both read.
    """
    if isinstance(entry, dict):
        value = entry.get("source")
        return value if isinstance(value, str) else None
    if not isinstance(entry, str):
        return None
    for matched in _MOUNT_FIELD.finditer(entry):
        if matched.group("key").lower() in ("source", "src"):
            return matched.group("value").strip()
    return None


def names_a_credential(source: str) -> str | None:
    """The credential path this mount source names, or None.

    Compared against a POSIX-normalised copy so a Windows spelling of the same
    directory is not a way past the check, and anchored on a path separator so
    `notes/.sshkeys-doc` does not match `.ssh`.
    """
    spelled = source.replace("\\", "/").rstrip("/")
    for known in CREDENTIAL_SOURCES:
        if spelled.endswith("/" + known) or spelled == known or spelled.endswith("/" + known + "/"):
            return known
    return None


def read(root: Path, *, machine: bool = False, home: Path | None = None) -> Reading:
    """Every `devcontainer.json` in the tree. There is no user or managed scope.

    `machine` and `home` are accepted and unused, so every reader in this
    package has one signature and `resolve` does not need to know which vendors
    have a scope outside the repository. A dev container configuration is a
    property of the repository by construction: the specification names no user
    or system location for one, and inventing one to fill the argument would be
    a claim about a file that does not exist.
    """
    root = Path(root)
    tracked, tracked_problem = git_tracked(root)
    settings: list[SettingsFile] = []
    unresolved: list[Unresolved] = []
    not_read: list[NotRead] = []

    for relative in locations(root):
        settings.append(read_jsonc(Scope.PROJECT, root / relative, relative))

    for handle in settings:
        if handle.problem and handle.problem != "absent":
            unresolved.append(Unresolved(handle.display, handle.problem, handle.display))

    scripts: dict[str, dict[str, Any]] = {}
    for handle in settings:
        if not handle.ok:
            continue
        assert handle.data is not None
        for key in LIFECYCLE:
            for command in commands_of(handle.data.get(key)):
                spoken = referenced_path(command)
                if spoken is not None and spoken not in scripts:
                    scripts[spoken] = script_facts(root, spoken, tracked, tracked_problem)

    return Reading(
        vendor=VENDOR,
        root=root,
        settings=tuple(settings),
        unresolved=tuple(unresolved),
        not_read=tuple(not_read),
        scripts=scripts,
    )


__all__ = [
    "CREDENTIAL_SOURCES",
    "LIFECYCLE",
    "VENDOR",
    "WELL_KNOWN",
    "commands_of",
    "locations",
    "mount_source",
    "names_a_credential",
    "read",
]


# ---------------------------------------------------------------------------
# The resolver
# ---------------------------------------------------------------------------
#
# A pure function of what the reader above read. It touches no disk, no clock
# and no socket, which is what lets a fixture replay the whole decision path.
# It lived in `resolve.py` until the file reached two thousand lines holding
# seven vendors; it is beside its reader now, which is where the next person
# looking for it will look.




def devcontainer_surface(reading: Any, *, agent_version: str | None = None,
        with_content: bool = False) -> Surface:
    """A dev container's lifecycle commands, its mounts and its isolation flags."""

    found: list[Capability] = []

    for handle in reading.settings:
        if not handle.ok:
            continue
        data = handle.data
        for key, on_host in LIFECYCLE.items():
            for command in commands_of(data.get(key)):
                facts: dict[str, Any] = {
                    "key": key,
                    "on_host": on_host,
                    "command_sha256": digest_of(command),
                }
                if with_content:
                    facts["command"] = command
                spoken = referenced_target(command)
                facts["target"] = spoken
                facts.update(target_facts(reading, spoken))
                emit(
                    found,
                    name="lifecycle.command",
                    scope=handle.scope,
                    source=handle.display,
                    key=key,
                    resolution=Resolution.EFFECTIVE,
                    condition=(
                        "runs on the host during initialization, before any container exists"
                        if on_host
                        else "runs inside the container"
                    ),
                    facts=facts,
                    vendor=reading.vendor,
                )

        mounts = data.get("mounts")
        for entry in mounts if isinstance(mounts, list) else []:
            source = mount_source(entry)
            if source is None:
                continue
            credential = names_a_credential(source)
            emit(
                found,
                name="container.mount",
                scope=handle.scope,
                source=handle.display,
                key="mounts",
                resolution=Resolution.EFFECTIVE,
                facts={
                    "source": source,
                    "credential": credential,
                    "names_credential": credential is not None,
                },
                vendor=reading.vendor,
            )

        for key in ("privileged",):
            if data.get(key) is True:
                emit(
                    found, name="container.isolation", scope=handle.scope,
                    source=handle.display, key=key, resolution=Resolution.EFFECTIVE,
                    facts={"key": key, "value": True, "isolation_weakened": True},
                    vendor=reading.vendor,
                )
        for key in ("capAdd", "securityOpt"):
            entries = data.get(key)
            for entry in entries if isinstance(entries, list) else []:
                if not isinstance(entry, str):
                    continue
                emit(
                    found, name="container.isolation", scope=handle.scope,
                    source=handle.display, key=key, resolution=Resolution.EFFECTIVE,
                    facts={"key": key, "value": entry, "isolation_weakened": True},
                    vendor=reading.vendor,
                )

        features = data.get("features")
        for name in sorted(features) if isinstance(features, dict) else []:
            # `pinned` follows the same reading as an npx launch: the `@` after
            # the first character is the version. A feature is fetched at build
            # time, so an unpinned one resolves to whatever is published then.
            spelled = str(name)
            emit(
                found, name="container.feature", scope=handle.scope,
                source=handle.display, key="features", resolution=Resolution.EFFECTIVE,
                facts={"feature": spelled, "pinned": "@" in spelled[1:]},
                vendor=reading.vendor,
            )

    return Surface(
        vendor=reading.vendor,
        agent_version=None,
        capabilities=tuple(found),
        unresolved=tuple(reading.unresolved),
        not_read=tuple(reading.not_read),
    )
