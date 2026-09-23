"""Every option the tool's own output suggests is one the parser has.

`seamark diff` printed "(run with --machine)" over the keyv demo, on the landing
page's picture, and `diff` has no `--machine`: the hint is written by the surface
resolvers, which `check` and `diff` share, and only `check` and `seal` take the
flag. So the output of both commands is read here, and every `--option` in it is
held against the parser: against the command a hint names (`seamark check
--machine`), or against the command that printed it when the hint names none.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from conftest import REPO_ROOT
from seamark import cli

KEYV = Path(REPO_ROOT) / "tests" / "fixtures" / "surface" / "keyv-august"
SUGGESTION = re.compile(r"(?:seamark (\w+)[^`\n]*?)?(?<![\w-])(--[a-z][a-z0-9-]*)")


def _options() -> dict[str, set[str]]:
    subparsers = cli.build_parser()._subparsers._group_actions[0]  # noqa: SLF001
    return {
        name: {flag for action in sub._actions for flag in action.option_strings}  # noqa: SLF001
        for name, sub in subparsers.choices.items()
    }


def suggestion_problems(text: str, command: str) -> list[str]:
    """Every `--option` in `text` that the command it is addressed to lacks."""
    options = _options()
    problems: list[str] = []
    for line in text.splitlines():
        for match in SUGGESTION.finditer(line):
            owner = match.group(1) if match.group(1) in options else command
            if match.group(2) not in options[owner]:
                problems.append(f"`seamark {owner}` has no {match.group(2)}: {line.strip()}")
    return problems


@pytest.mark.parametrize("lang", ["en", "es"])
def test_what_diff_prints_suggests_only_options_that_exist(tmp_path, capsys, lang):
    empty = tmp_path / "before"
    empty.mkdir()
    cli.main(["--lang", lang, "diff", "--from-dir", str(empty), "--to-dir", str(KEYV)])
    printed = capsys.readouterr().out

    assert "--" in printed, "the output carries no option at all, so this checked nothing"
    assert suggestion_problems(printed, "diff") == []


def test_what_check_prints_suggests_only_options_that_exist(capsys):
    cli.main(["check", "--repo", str(KEYV)])

    assert suggestion_problems(capsys.readouterr().out, "check") == []


def test_a_hint_for_an_option_the_command_lacks_is_caught():
    """The twin: the line the landing picture carried, planted."""
    assert suggestion_problems("no scope this run read says (run with --machine)", "diff")
    assert not suggestion_problems("read only by `seamark check --machine`", "diff")


COMMAND_IN_TEXT = re.compile(r"seamark (\w+)((?:\s+--?[a-z][a-z0-9-]*(?:\s+<[^>]+>)?)*)")


def catalogue_problems(text: str) -> list[str]:
    """Every `seamark <command> --option` a string names, against the parser."""
    options = _options()
    problems: list[str] = []
    for command, tail in COMMAND_IN_TEXT.findall(text):
        if command not in options:
            problems.append(f"names `seamark {command}`, which is not a command: {text[:90]}")
            continue
        problems += [f"`seamark {command}` has no {flag}: {text[:90]}"
                     for flag in re.findall(r"--[a-z][a-z0-9-]*", tail) if flag not in options[command]]
    return problems


@pytest.mark.parametrize("lang", ["en", "es"])
def test_every_command_the_catalogue_names_is_one_the_cli_has(lang):
    """The same shape one level up: the catalogue told a reader to run
    `seamark source add` and `seamark policy check --state`, neither of which
    this tool has had since the scanner left."""
    import json  # noqa: PLC0415

    catalogue = json.loads((Path(REPO_ROOT) / "src" / "seamark" / "i18n" / f"{lang}.json")
                           .read_text(encoding="utf-8"))
    texts = [text for text in catalogue["ui"].values() if isinstance(text, str)]

    assert any("seamark watch" in text for text in texts), "no command was found to check"
    assert [problem for text in texts for problem in catalogue_problems(text)] == []


def test_every_help_page_suggests_only_what_the_parser_has():
    parser = cli.build_parser()
    subparsers = parser._subparsers._group_actions[0]  # noqa: SLF001
    pages = [parser.format_help(), *(sub.format_help() for sub in subparsers.choices.values())]

    assert [problem for page in pages for problem in catalogue_problems(page)] == []


def test_a_catalogue_line_naming_a_command_that_is_gone_is_caught():
    """The twin, with the two lines the catalogue carried."""
    assert catalogue_problems("`seamark source add` y luego `seamark watch` registra una")
    assert catalogue_problems("`seamark check --state <db>` archiva una")
    assert not catalogue_problems("`seamark check --machine` reads it")
