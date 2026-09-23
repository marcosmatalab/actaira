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
    package = Path(SRC_DIR) / "seamark"
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
    package = Path(SRC_DIR) / "seamark"
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


def _build_package():
    sys.path.insert(0, str(Path(REPO_ROOT) / "scripts"))
    import build_package  # noqa: PLC0415

    return build_package


def _parses(argv: list[str]) -> bool:
    """Whether the CLI's own parser accepts `argv`. `--help` and `--version`
    leave through SystemExit(0), which is acceptance."""
    from seamark.cli import build_parser  # noqa: PLC0415

    try:
        build_parser().parse_args(argv)
    except SystemExit as leaving:
        return leaving.code == 0
    return True


def test_the_clean_install_runs_commands_the_cli_has(capsys):
    """`make package INSTALL=--install` ran `seamark schema`, a command that
    left with the scanner, so the step the release runbook rehearses with
    failed on every run and nothing in CI ran it. Read off the parser offline,
    because the install itself needs a network for its one dependency."""
    build_package = _build_package()

    assert build_package.SMOKE, "no command is run after the install"
    assert [argv for argv in build_package.SMOKE if not _parses(argv)] == []


def test_the_smoke_check_would_notice_a_command_that_is_gone(capsys):
    """The twin: the command it used to run."""
    assert not _parses(["schema"])


def test_the_install_probe_reads_a_rule_the_packs_ship():
    """The probe read `ACT-PKL-002`, a scanner rule, out of the catalogue."""
    build_package = _build_package()
    from seamark.surface import rules  # noqa: PLC0415

    assert build_package.PROBE_RULE in {rule.id for rule in rules.load()}
