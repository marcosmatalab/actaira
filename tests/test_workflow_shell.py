"""Every piece of shell this repository writes into a file that is not a shell
script, handed to `bash -n`.

WHY THIS EXISTS. DEF-124. The commit that fixed DEF-123 inserted three steps
into the `action` job of `.github/workflows/ci.yml` ABOVE the line that closed a
`python -c "` string, so the closing quote ended up at the foot of the file, in
a different step. The YAML stayed valid, `zizmor` stayed green, `make all`
stayed green, and the job died on the runner with `unexpected EOF while looking
for matching '"'` before it reached the branch that commit existed to add.

WHY NOTHING CAUGHT IT, WHICH IS THE PART THAT MATTERS. `tests/test_action_yml.py`
extracts the `run:` bodies of `action.yml` and EXECUTES them - it was written for
DEF-116 to DEF-118, three defects in that same seam. It does not read
`.github/workflows/`. The check built to close a blind spot left the one in the
file next door, and its green read as if the repository's embedded shell were
covered. That is work rule 12's failure mode, and DEF-124 is the sixth instance.

WHAT IS SWEPT, because a check that covers one file and not its neighbour is the
defect above wearing a different name. Every place this repository embeds shell
in something that is not a shell script:

  action.yml                      `run:` bodies. Executed by test_action_yml.py,
                                  parsed here too - a file covered twice by two
                                  cheap checks is not the problem this had.
  .github/workflows/*.yml         `run:` bodies. Nothing read them until now.
  Dockerfile                      `RUN` instructions, continuations joined.
  .launch/**/.github/workflows    the published kits. They carry NO `run:` at
                                  all, and that is ASSERTED rather than assumed:
                                  the day one grows a `run:`, this file has to
                                  start covering it, and a silent zero is how it
                                  would not. `.launch/` is untracked on purpose,
                                  so that assertion SKIPS with its reason on a
                                  clean clone instead of failing - the first
                                  draft required the directory and went red in
                                  the gate while passing on the machine that has
                                  it, which is work rule 7's defect written into
                                  the test built for work rule 12.

The Makefile's recipes are the one place with this shape that is NOT covered
here - `make -n` expansion is a different mechanism, and mixing it in is how a
check stops being one thing. `docs/BACKLOG.md` carries the line with its name.

NO PyYAML. It is not in the dev extras, so importing it would be the phase S1.1
defect again: green here, red on a clean install. The extractor is the one
`test_action_yml.py` already wrote, imported rather than copied, because two
definitions of "a `run:` block" would not add up - they would cancel out, which
is work rule 10.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import REPO_ROOT
from test_action_yml import run_blocks

BASH = shutil.which("bash")

ACTION = Path(REPO_ROOT) / "action.yml"
DOCKERFILE = Path(REPO_ROOT) / "Dockerfile"
WORKFLOW_DIR = Path(REPO_ROOT) / ".github" / "workflows"

# `.launch/` is UNTRACKED on purpose - `.gitignore` line 96, launch material
# about publishing the product rather than part of it - so a clean clone, which
# is where the gate runs, does not have it. Swept when it is there and declared
# absent with that reason when it is not: the first draft asserted it existed
# and went red in the gate while passing here, which is a check measuring this
# machine instead of what is delivered.
KIT_DIR = Path(REPO_ROOT) / ".launch"
KIT_WORKFLOWS = sorted(KIT_DIR.glob("*/*/.github/workflows/*.yml"))

# Discovered, not typed. A workflow added tomorrow is swept without anybody
# remembering to add it, which is the only way a list like this stays true.
WORKFLOWS = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
YAML_WITH_SHELL = [*WORKFLOWS, ACTION]

# `RUN` up to the last line that does not end in a backslash. Docker joins
# continuations before handing the result to the shell, so a check that read one
# physical line would be checking something Docker never runs.
DOCKER_RUN = re.compile(r"^RUN (.*?(?<!\\)$)", re.MULTILINE | re.DOTALL)

pytestmark = pytest.mark.skipif(
    BASH is None, reason="no bash on PATH; the shell under test is bash"
)


def shell_problems(source: str, bodies: dict[str, str]) -> list[str]:
    """Every body in `bodies` that `bash -n` refuses, named by where it lives.

    ONE definition, called by the sweep below and by its twin. A twin that
    planted the defect against a second, private copy of this would prove that
    the copy bites and say nothing about the check that runs.

    `bash -n` and not execution: what is asserted is that the shell can PARSE
    what the file will hand it. Running these is a different claim and a
    different file - `test_action_yml.py` makes it for the bodies whose running
    is the contract.
    """
    problems: list[str] = []
    for label, body in bodies.items():
        parsed = subprocess.run(
            [BASH, "-n"],
            input=body,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if parsed.returncode != 0:
            problems.append(f"{source} :: {label}: {parsed.stderr.strip()}")
    return problems


def docker_run_bodies(text: str) -> dict[str, str]:
    """{first word of the instruction: shell body} for every `RUN` in a Dockerfile.

    The backslash-newlines are left exactly as written. Docker joins them before
    the shell sees them and bash joins them itself, so stripping them here would
    be this reader inventing a third thing neither of them does - the first
    draft did, and turned two valid instructions into two syntax errors.
    """
    found: dict[str, str] = {}
    for match in DOCKER_RUN.finditer(text):
        body = match.group(1)
        found[body.split()[0] + " ..."] = body + "\n"
    return found


def test_the_sweep_found_the_files_and_the_blocks_it_thinks_it_did():
    """The guard. Work rule 11: a check that matches nothing fails loudly.

    Everything below iterates over what an extractor returned. An extractor that
    quietly returned nothing - a renamed directory, a `run: >` somebody wrote
    instead of `run: |` - would make every assertion pass over an empty list,
    which is the shape of green this file exists because of.
    """
    assert WORKFLOW_DIR.is_dir(), f"{WORKFLOW_DIR} is not there any more"
    names = {path.name for path in WORKFLOWS}
    assert "ci.yml" in names, f"the workflow sweep found {sorted(names)}"

    counted = {path.name: len(run_blocks(path.read_text(encoding="utf-8")))
               for path in YAML_WITH_SHELL}
    # 16 and 4 are what is there today. The floor is the point: nine of ci.yml's
    # sixteen are `run: |` and seven are one-liners, and a reader that quietly
    # lost the one-liners is how the first draft of this file was green.
    assert counted["ci.yml"] >= 16, counted
    assert counted["action.yml"] >= 4, counted
    assert len(docker_run_bodies(DOCKERFILE.read_text(encoding="utf-8"))) >= 2


@pytest.mark.skipif(
    not KIT_DIR.is_dir(),
    reason=".launch/ is untracked launch material (.gitignore line 96) and is "
           "not in a clean clone, which is where the gate runs",
)
def test_the_published_kits_carry_no_shell_of_their_own():
    """The kits ship `uses:` and nothing else, and their LEEME files say so.

    A test of its own rather than a branch inside the guard above: skipping is
    the honest answer when the directory is deliberately not in the clone, and a
    `skip` in the middle of the guard would have hidden the block counts it had
    already checked behind a SKIPPED that looks like nothing ran.

    Work rule 11 keeps the two absences apart. No directory is declared, with
    its reason, by the marker. A directory that is here with no workflow in it
    is the glob having broken, and that fails.
    """
    assert KIT_WORKFLOWS, f"{KIT_DIR} is here but the sweep found no workflow in it"
    for kit in KIT_WORKFLOWS:
        assert not run_blocks(kit.read_text(encoding="utf-8")), (
            f"{kit} grew a `run:` block. Add it to YAML_WITH_SHELL: a kit is "
            "shell this repository publishes for other people to run."
        )


def test_every_shell_this_repository_writes_into_yaml_parses():
    """DEF-124. The one assertion: the shell in these files is shell."""
    problems: list[str] = []
    for path in YAML_WITH_SHELL:
        problems += shell_problems(
            path.relative_to(REPO_ROOT).as_posix(),
            run_blocks(path.read_text(encoding="utf-8")),
        )
    assert not problems, "\n".join(problems)


def test_the_dockerfile_shell_parses():
    """The same sweep over the instruction Docker hands to a shell."""
    problems = shell_problems(
        "Dockerfile", docker_run_bodies(DOCKERFILE.read_text(encoding="utf-8"))
    )
    assert not problems, "\n".join(problems)


def test_the_sweep_would_notice_an_unterminated_quote():
    """The twin, work rule 9, planting DEF-124 itself.

    The defect is reconstructed the way it happened rather than invented: a step
    is inserted between a `python -c "` and the line that closed it, so the
    quote ends up in a later step. A test that says "the shell parses" and has
    never seen it not parse cannot tell the property from an extractor that
    returns nothing.
    """
    planted = run_blocks(
        "jobs:\n"
        "  job:\n"
        "    steps:\n"
        "      - name: the step that opened the string\n"
        "        run: |\n"
        "          python -c \"\n"
        "          print('what the assertion was')\n"
        "      - name: the step the closing quote landed in\n"
        "        run: |\n"
        "          test -s out.txt\n"
        "          \"\n"
    )
    assert len(planted) == 2, sorted(planted)

    problems = shell_problems("planted.yml", planted)

    assert len(problems) == 2, problems
    assert all("unexpected EOF" in problem for problem in problems), problems
