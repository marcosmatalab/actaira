"""Shared test fixtures.

The project is not installed, so `src/` goes on `sys.path` here rather than in
every test file. `tests/` goes on it too, so `support.reports` imports the same
way from every test file.

The generated artifact corpus went to tag v2.3.0 with the inspector
that read it. Tests that used it as a fixture factory build an `ArtifactReport`
directly instead: see `tests/support/reports.py` for why that is the honest
replacement rather than a stand-in inspector.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SRC_DIR = REPO_ROOT / "src"

for _entry in (str(SRC_DIR), str(TESTS_DIR)):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

# Design note D-267. The permanent gate, armed before a single test imports:
# nothing in this suite may reach anything but loopback. It is here rather than
# in a fixture because a fixture is opt-in and this is not, and here rather than
# in `pytest_plugins` because pytest refuses that outside a top-level conftest.
# `tests/test_netguard.py` proves it is still biting, and `scripts/
# release_check.py` runs that file and fails if it is not armed.
import netguard  # noqa: E402 - must come after sys.path is set up

netguard.install()


def _load_module_by_path(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - environment error
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def write_artifact(tmp_path: Path) -> Callable[[str, bytes], Path]:
    """Write bytes to `tmp_path/name` and hand back the path."""

    def _write(name: str, payload: bytes) -> Path:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return target

    return _write


@pytest.fixture
def keypair(tmp_path: Path):
    """A freshly generated Ed25519 key pair, never touching the user's ~/.actaira."""
    from actaira.attest import signing

    pair, created = signing.load_or_create(tmp_path / "keys" / "signing-key.pem")
    assert created, "fixture must create the key, not reuse one from the machine"
    return pair


# ---------------------------------------------------------------------------
# What the host operating system can and cannot be asked
# ---------------------------------------------------------------------------
#
# Three properties this suite asserts are properties of a POSIX kernel rather
# than of Actaira: a file's permission bits, a descriptor table with a soft
# limit, and a filename allowed to contain `<`, `>` and `|`. Where one of them
# is unavailable the test says which property it could not observe, in the
# assertion or in the skip reason, so "passed" never quietly means "was not
# looked at". The limitations themselves are written down in `SECURITY.md`
# under *What the host operating system decides*, because one of them - key
# files not being mode-protected off POSIX - is a real weakening of a claim
# this project makes and a reader is entitled to know before trusting it.

POSIX_MODE_BITS = os.name == "posix"

requires_posix_modes = pytest.mark.skipif(
    not POSIX_MODE_BITS,
    reason=(
        "asserts POSIX permission bits; this host does not enforce them, and "
        "SECURITY.md records what that costs"
    ),
)
