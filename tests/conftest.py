"""Shared test fixtures.

The project is not installed, so `src/` goes on `sys.path` here rather than in
every test file. `evals/corpus/build.py` is loaded by path under a private
module name: it is a script, not a package, and importing it as plain `build`
would fight with anything else called that.

The corpus is built once per test session into a temporary directory. It is
cheap (~40 ms, no network, no ML frameworks) and it is the same corpus the eval
harness measures, so a test that asserts on it is asserting on the artefacts
the project publishes numbers for.
"""
from __future__ import annotations

import atexit
import importlib.util
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SRC_DIR = REPO_ROOT / "src"

for _entry in (str(SRC_DIR), str(TESTS_DIR)):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)


def _load_module_by_path(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - environment error
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


corpus_build = _load_module_by_path(
    "actaira_corpus_build", REPO_ROOT / "evals" / "corpus" / "build.py"
)

_CORPUS_TMP = tempfile.TemporaryDirectory(prefix="actaira-corpus-")
atexit.register(_CORPUS_TMP.cleanup)

CORPUS_DIR = Path(_CORPUS_TMP.name)
CORPUS_CASES = corpus_build.build(CORPUS_DIR)


def cases_in_family(family: str) -> list[Any]:
    """Corpus cases of one family, sorted by name so parametrisation is stable."""
    return sorted(
        (case for case in CORPUS_CASES if case.family == family),
        key=lambda case: case.name,
    )


def corpus_path(case: Any) -> Path:
    return CORPUS_DIR / case.name


@pytest.fixture(scope="session")
def corpus_dir() -> Path:
    return CORPUS_DIR


@pytest.fixture
def numpy_state_dict() -> dict[str, Any]:
    """The shape of a real checkpoint: two float32 arrays plus a config dict.

    Built with numpy itself, so the pickle streams under test come from
    CPython's own pickler rather than from something this repository wrote.
    """
    import numpy as np

    return {
        "encoder.weight": np.zeros((8, 8), dtype=np.float32),
        "encoder.bias": np.arange(8, dtype=np.float32),
        "config": {"hidden": 8, "layers": 2, "labels": ["a", "b"]},
    }


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
