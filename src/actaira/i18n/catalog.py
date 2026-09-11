"""Bilingual message catalogue.

Design note D-07. Rule identifiers are the stable interface; text is not.
The catalogue is loaded from JSON so the CLI, the web UI and the reports all
render the same rule from one source, and a test asserts that the English
and Spanish catalogues have identical key sets. Without that test the second
language rots silently, which is the normal fate of a second language.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
SUPPORTED = ("en", "es")

# The catalogue is one JSON document with deliberately heterogeneous sections:
# `ui` and `rules` map a key to a string, `controls` and `obligations` map an
# identifier to an object, and some of those objects carry lists. So the value
# type is `Any` and the narrowing happens at the call site, which is what the
# readers already do. It was declared `dict[str, dict[str, str]]`, which was
# not a loose type but a wrong one: every three-level read in the tree
# contradicted it, and the checker was right to say so.
CatalogDocument = dict[str, Any]


@lru_cache(maxsize=4)
def load(lang: str) -> CatalogDocument:
    if lang not in SUPPORTED:
        lang = "en"
    return json.loads((HERE / f"{lang}.json").read_text(encoding="utf-8"))


class Catalog:
    def __init__(self, lang: str = "en") -> None:
        self.lang = lang if lang in SUPPORTED else "en"
        self._data = load(self.lang)
        self._fallback = load("en")

    def line(self, key: str, **kwargs: object) -> str:
        template = self._data.get("ui", {}).get(key) or self._fallback.get("ui", {}).get(key) or key
        try:
            return template.format(**kwargs)
        except (KeyError, IndexError):
            return template

    def rule(self, rule_id: str) -> str:
        rules = self._data.get("rules", {})
        return rules.get(rule_id) or self._fallback.get("rules", {}).get(rule_id) or rule_id

    def rule_help(self, rule_id: str) -> str:
        helps = self._data.get("rule_help", {})
        return helps.get(rule_id) or self._fallback.get("rule_help", {}).get(rule_id) or ""
