"""What the built package has to carry, asserted without building one.

`scripts/build_package.py` opens the wheel and the sdist and checks what went
into them. It cannot run here: `build` is an extra on purpose, because a
packaging tool must not be able to break an install of the package, so `make
all` does not have it. That is the right trade and it had a cost - the script
was exercised only by somebody typing `make package`, and between the pivot
and the release nobody did. It had been failing on every run for a release,
over five resource paths that went to tag v2.3.0 with the model scanner.

So the part that can be checked without a build is checked here: the list of
what the package must carry, which is the part that rotted. DEF-130.
"""
from __future__ import annotations

import sys
from pathlib import Path

from conftest import REPO_ROOT, SRC_DIR


def _required() -> tuple[str, ...]:
    sys.path.insert(0, str(Path(REPO_ROOT) / "scripts"))
    from build_package import required  # noqa: PLC0415

    return required()


def data_files() -> set[str]:
    package = Path(SRC_DIR) / "actaira"
    return {
        path.relative_to(Path(SRC_DIR)).as_posix()
        for path in package.rglob("*")
        if path.is_file() and path.suffix != ".py" and "__pycache__" not in path.parts
    }


def test_every_data_file_in_the_package_is_required_of_the_build():
    """The rule: a non-Python file inside the package is one the package ships.

    Asserted as equality and not as a subset. A list that is merely a superset
    is how the old one survived: it named five files that had stopped existing
    and nothing compared it with the tree in the other direction.
    """
    assert set(_required()) == data_files()


def test_the_requirement_list_is_not_empty():
    """Work rule 11. A build checked against an empty list is not checked."""
    assert len(_required()) >= 5, _required()


def test_the_requirement_list_would_notice_a_resource_that_stopped_shipping(tmp_path, monkeypatch):
    """Work rule 9's twin, planted the way the defect happened.

    A data file is added to the package directory and `required()` has to see
    it. A `required()` that had gone back to a frozen literal passes every
    assertion above on the day it is written and fails this one, which is the
    difference between a list that is derived and a list that merely agrees
    with the tree right now.
    """
    package = Path(SRC_DIR) / "actaira"
    planted = package / "i18n" / "zz-planted-by-the-suite.json"
    planted.write_text("{}\n", encoding="utf-8")
    try:
        assert planted.relative_to(Path(SRC_DIR)).as_posix() in _required(), (
            "a data file was added to the package and `required()` did not name it, so "
            "the list is frozen rather than read off the tree"
        )
    finally:
        planted.unlink()

    assert planted.relative_to(Path(SRC_DIR)).as_posix() not in _required()
