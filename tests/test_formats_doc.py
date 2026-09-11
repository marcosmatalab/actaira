"""`docs/FORMATS.md` is the page every SARIF finding links to.

`report/sarif.py` sets each rule's `helpUri` to this document, so a rule that
is not in its table is a link that lands on a page which does not mention what
the reader clicked on. That happened: four rules were missing, including
`ACT-PKL-011`, the one the release notes lead with.

The table is prose and will always be written by hand. What can be automated
is the check that it is complete, and that it agrees with the code on
severity, which is the field a reader acts on.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from actaira.model import Severity
from conftest import REPO_ROOT

ROOT = Path(REPO_ROOT)
FORMATS = (ROOT / "docs" / "FORMATS.md").read_text(encoding="utf-8")
CATALOGUE = json.loads((ROOT / "src" / "actaira" / "i18n" / "en.json").read_text(encoding="utf-8"))

ROW = re.compile(r"^\| `(ACT-[A-Z0-9]+-\d+)` \| ([A-Z]+) \|", re.MULTILINE)
DOCUMENTED = dict(ROW.findall(FORMATS))


def test_every_rule_in_the_catalogue_is_in_the_table():
    missing = sorted(set(CATALOGUE["rules"]) - set(DOCUMENTED))
    assert not missing, (
        f"these rules can appear in a report and are not documented: {missing}. "
        "Every SARIF finding links here."
    )


def test_the_table_invents_no_rules():
    extra = sorted(set(DOCUMENTED) - set(CATALOGUE["rules"]))
    assert not extra, f"documented but not in the message catalogue: {extra}"


@pytest.mark.parametrize("rule_id", sorted(DOCUMENTED))
def test_every_documented_severity_is_a_real_severity(rule_id):
    assert DOCUMENTED[rule_id] in {level.name for level in Severity}
