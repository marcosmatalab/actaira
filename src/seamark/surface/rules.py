"""Rule packs: TOML in, cited findings out, and never an opinion of our own.

Design note D-274. The pack format is TOML, read with `tomllib` from the
standard library.

Rejected, YAML: it is what the plan maestro wrote down, and it costs either a
runtime dependency - which `docs/PRINCIPLES.md` caps at one, `cryptography` - or bringing
back the hand-written `miniyaml` that phase A deleted. A rule format is not
worth either.

Rejected, JSON: no comments. Every rule has to carry the argument for why it
exists next to itself, and a format where that argument can only live in a
string field is a format where it stops being written.

Design note D-275. A rule's predicate is DATA, and the facts it needs are
derived from that data rather than declared beside it. A clause naming
`facts.at_startup` is itself the statement that the rule needs
`facts.at_startup`, so a capability that does not carry it returns INDETERMINATE
without anybody remembering to check - which is the third negative's "the rule
returns INDETERMINATE on its own" made structural instead of conscientious.

What is NOT here, and is the whole of the second negative: no rule computes
anything about what a configuration would do. It compares observed facts against
a condition somebody wrote down, and publishes that person's name, their pack,
their rule's version and their severity label beside the answer. The severity is
theirs. It is never summed, never maximised and never compared with another.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..model import Finding
from . import Capability, Resolution, Surface, Unresolved

PACKS = Path(__file__).parent / "packs"

# `ACT-` plus one category letter plus three digits. COMPATIBILITY.md already
# promises this shape is never renumbered and never reused, so the loader is
# where a malformed one is refused - at load, with a message, which is the
# code rule about format errors.
ID_SHAPE = "ACT-"

OPERATORS = ("is", "is_not", "in", "contains", "starts_with", "is_true", "is_false")


class PackError(ValueError):
    """A rule pack that does not load. Raised with a message, never a traceback.

    Every raise names the file, the rule and the field, because the reader of
    this message is somebody writing a rule pack, and "KeyError: 'severity'" is
    not a sentence that helps them.
    """


@dataclass(frozen=True)
class Clause:
    """One comparison between a fact and a written-down value."""

    fact: str
    operator: str
    value: Any

    def holds(self, facts: dict[str, Any]) -> bool | None:
        """True, False, or None when the fact this clause needs is not there.

        None is the load-bearing return. It propagates to INDETERMINATE and is
        the reason a rule never answers False about something nobody observed.
        """
        found = _dig(facts, self.fact)
        if found is _MISSING:
            return None
        if self.operator == "is":
            return found == self.value
        if self.operator == "is_not":
            return found != self.value
        if self.operator == "in":
            return found in self.value
        if self.operator == "contains":
            return isinstance(found, str) and str(self.value) in found
        if self.operator == "starts_with":
            return isinstance(found, str) and found.startswith(str(self.value))
        if self.operator == "is_true":
            return found is True
        return found is False


_MISSING = object()


def _dig(facts: dict[str, Any], path: str) -> Any:
    """`target_facts.inside_tree` out of a nested mapping, or `_MISSING`.

    `_MISSING` and not None, because a fact whose recorded value IS null - the
    reader writes `git_tracked: null` when it could not look the answer up - is
    a different thing from a fact nobody wrote down, and both have to reach
    `holds` as different answers or the distinction dies here.
    """
    node: Any = facts
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


@dataclass(frozen=True)
class Search:
    """One recorded attempt to find a real violating configuration.

    "I found none" is a datum, and a datum has to say what was looked for. A
    rule whose violating case comes from a vendor's own documentation because a
    search found nothing publishes the searches, so a reader can run them again
    and disagree.
    """

    query: str
    date: str
    results: int
    violating: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "date": self.date,
            "results": self.results,
            "violating": self.violating,
        }


@dataclass(frozen=True)
class Rule:
    """One rule, with everything a finding has to publish about its author."""

    id: str
    version: str
    author: str
    pack: str
    vendor: str
    requires: Resolution
    severity: str
    capability: tuple[str, ...]
    when: tuple[Clause, ...]
    remediation: str
    atr: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    # The narrow third branch of `docs/PRINCIPLES.md`'s rule about a rule's two tests. A
    # rule may only be marked when a public sample is impossible by the rule's
    # own scope, or when a recorded search found none - and the mark is
    # published, on `docs/RULES.md`, rather than kept in a fixture's provenance
    # file where only somebody already looking would meet it.
    no_real_violation: str = ""
    violation_source: str = ""
    violation_source_sha256: str = ""
    violation_source_consulted: str = ""
    searches: tuple[Search, ...] = ()

    @property
    def marked(self) -> bool:
        return bool(self.no_real_violation)

    @property
    def cited(self) -> bool:
        """Whether a marked rule carries what the mark costs.

        Either the vendor page that publishes the configuration, with its digest
        and the date it was read, or at least one recorded search. A mark with
        neither is the exemption the rule was written to refuse, so it is
        refused at load and a test asserts the refusal bites.
        """
        documented = bool(
            self.violation_source.strip()
            and len(self.violation_source_sha256.strip()) == 64
            and self.violation_source_consulted.strip()
        )
        return documented or bool(self.searches)

    @property
    def needs(self) -> tuple[str, ...]:
        """The facts this rule cannot answer without. Derived, never declared."""
        return tuple(sorted({clause.fact for clause in self.when}))

    def matches(self, capability: Capability) -> bool:
        return capability.name in self.capability and capability.vendor == self.vendor


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _need(where: str, block: dict[str, Any], field: str) -> Any:
    if field not in block:
        raise PackError(f"{where}: rule is missing the required field `{field}`")
    return block[field]


def _strings(where: str, block: dict[str, Any], field: str) -> tuple[str, ...]:
    value = block.get(field) or ()
    if isinstance(value, str):
        value = (value,)
    if not all(isinstance(item, str) for item in value):
        raise PackError(f"{where}: `{field}` must be a string or a list of strings")
    return tuple(value)


def load_pack(path: Path) -> tuple[Rule, ...]:
    """Every rule in one `.toml` file, or a `PackError` naming what is wrong."""
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise PackError(f"{path.name}: not valid TOML: {exc}") from exc
    except OSError as exc:
        raise PackError(f"{path.name}: cannot read: {exc}") from exc

    pack = document.get("pack")
    if not isinstance(pack, dict) or not isinstance(pack.get("name"), str):
        raise PackError(f"{path.name}: the file needs a [pack] table with a `name`")
    pack_name = pack["name"]
    default_author = pack.get("author")

    found: list[Rule] = []
    for block in document.get("rule") or ():
        if not isinstance(block, dict):
            raise PackError(f"{path.name}: every [[rule]] must be a table")
        identifier = _need(path.name, block, "id")
        where = f"{path.name}:{identifier}"
        if not isinstance(identifier, str) or not _well_formed(identifier):
            raise PackError(
                f"{path.name}: `{identifier}` is not a rule id. The shape is ACT- plus one category "
                "letter plus three digits, for example ACT-S001."
            )
        requires = str(_need(where, block, "requires")).upper()
        if requires not in ("DECLARED", "EFFECTIVE"):
            raise PackError(
                f"{where}: `requires` is {requires!r}; it must be DECLARED or EFFECTIVE"
            )
        author = block.get("author", default_author)
        if not isinstance(author, str) or not author.strip():
            raise PackError(
                f"{where}: no `author`, and the [pack] table sets no default. Every finding "
                "publishes who wrote the rule it came from."
            )
        # Design note D-304. Every report prints the author and then the pack, so
        # an author ending in the pack's name prints it twice (`Seamark core core`).
        # Refused at load, for every pack. Rejected: dropping the pack from the
        # printed line, which hides the one field that says where a rule came from.
        if author.split()[-1].lower() == str(pack_name).lower():
            raise PackError(
                f"{where}: the author {author!r} repeats the pack name {pack_name!r}, and "
                "every report prints the author followed by the pack. Name the author alone."
            )
        clauses: list[Clause] = []
        for raw in block.get("when") or ():
            if not isinstance(raw, dict):
                raise PackError(f"{where}: every [[rule.when]] must be a table")
            operator = str(raw.get("op", "is"))
            if operator not in OPERATORS:
                raise PackError(
                    "{}: unknown operator {!r}; known: {}".format(
                        where, operator, ", ".join(OPERATORS)
                    )
                )
            if "fact" not in raw:
                raise PackError(f"{where}: a clause with no `fact`")
            clauses.append(Clause(str(raw["fact"]), operator, raw.get("value")))
        if not clauses:
            raise PackError(
                f"{where}: no [[rule.when]] clause. A rule with no condition fires on "
                "everything, which is a rule about nothing."
            )
        severity = _need(where, block, "severity")
        if not isinstance(severity, str) or not severity.strip():
            raise PackError(f"{where}: `severity` must be a non-empty string")
        searches: list[Search] = []
        for raw in block.get("searches") or ():
            if not isinstance(raw, dict) or "query" not in raw or "date" not in raw:
                raise PackError(
                    f"{where}: every [[rule.searches]] needs a `query` and a `date`. A "
                    "search nobody can run again is not a record of one."
                )
            searches.append(
                Search(
                    query=str(raw["query"]),
                    date=str(raw["date"]),
                    results=int(raw.get("results", 0)),
                    violating=int(raw.get("violating", 0)),
                )
            )
        rule = Rule(
            id=identifier,
            version=str(_need(where, block, "version")),
            author=author,
            pack=pack_name,
            vendor=str(_need(where, block, "vendor")),
            requires=Resolution[requires],
            severity=severity,
            capability=_strings(where, block, "capability"),
            when=tuple(clauses),
            remediation=str(_need(where, block, "remediation")),
            atr=_strings(where, block, "atr"),
            references=_strings(where, block, "references"),
            no_real_violation=str(block.get("no_real_violation", "")),
            violation_source=str(block.get("violation_source", "")),
            violation_source_sha256=str(block.get("violation_source_sha256", "")),
            violation_source_consulted=str(block.get("violation_source_consulted", "")),
            searches=tuple(searches),
        )
        if rule.marked and not rule.cited:
            raise PackError(
                f"{where}: `no_real_violation` is set and the rule carries neither a "
                "`violation_source` with its sha256 and consultation date, nor a single "
                "[[rule.searches]] entry. A rule may be marked when its own scope makes a "
                "public sample impossible or when a recorded search found none - and it "
                "then has to show which."
            )
        if rule.searches and not rule.marked:
            raise PackError(
                f"{where}: searches are recorded and `no_real_violation` is not set. The "
                "searches exist to justify the mark; without one they are a note."
            )
        found.append(rule)
    return tuple(found)


def _well_formed(identifier: str) -> bool:
    if not identifier.startswith(ID_SHAPE):
        return False
    tail = identifier[len(ID_SHAPE):]
    return len(tail) == 4 and tail[0].isupper() and tail[0].isalpha() and tail[1:].isdigit()


def load(directory: Path | None = None) -> tuple[Rule, ...]:
    """Every rule in every pack, sorted by id so two runs agree on the order."""
    base = PACKS if directory is None else Path(directory)
    found: list[Rule] = []
    for path in sorted(base.rglob("*.toml")):
        found.extend(load_pack(path))
    seen: dict[str, str] = {}
    for rule in found:
        if rule.id in seen:
            raise PackError(
                f"{rule.id} is defined twice, in {seen[rule.id]} and {rule.pack}. An identifier means one "
                "thing forever."
            )
        seen[rule.id] = rule.pack
    return tuple(sorted(found, key=lambda rule: rule.id))


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate(
    surface: Surface, catalogue: tuple[Rule, ...] | None = None
) -> tuple[tuple[Finding, ...], tuple[Unresolved, ...]]:
    """Apply every rule to every capability. A pure function, and the whole engine.

    Three answers per pair and no fourth: it fired, it did not, or the facts did
    not settle it. The third goes to `Unresolved` with the rule that could not
    answer and why, and is never counted with either of the others.
    """
    rules = load() if catalogue is None else catalogue
    findings: list[Finding] = []
    gaps: list[Unresolved] = []

    for capability in surface.capabilities:
        for rule in rules:
            if not rule.matches(capability):
                continue
            if capability.resolution is Resolution.INDETERMINATE:
                gaps.append(
                    Unresolved(
                        subject=f"{rule.id} on {capability.name}",
                        cause=capability.condition or "the capability could not be resolved",
                        source=capability.source,
                    )
                )
                continue
            if (
                rule.requires is Resolution.EFFECTIVE
                and capability.resolution is not Resolution.EFFECTIVE
            ):
                continue
            answers = [clause.holds(capability.facts) for clause in rule.when]
            # A clause that is definitively False settles the rule: it cannot
            # fire, and a missing fact elsewhere does not make that uncertain.
            # Without this order, a stdio MCP server made ACT-S012 - which needs
            # `remote` true AND `loopback` false - report a gap about a server
            # that plainly is not remote, and a gap nobody can act on is noise
            # dressed as rigour.
            if any(answer is False for answer in answers):
                continue
            if any(answer is None for answer in answers):
                missing = [
                    clause.fact
                    for clause, answer in zip(rule.when, answers, strict=True)
                    if answer is None
                ]
                gaps.append(
                    Unresolved(
                        subject=f"{rule.id} on {capability.name}",
                        cause="the observed configuration carries no {}".format(
                            ", ".join(missing)
                        ),
                        source=capability.source,
                    )
                )
                continue
            if all(answers):
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_version=rule.version,
                        author=rule.author,
                        pack=rule.pack,
                        severity=rule.severity,
                        location=capability.source,
                        evidence={
                            "capability": capability.name,
                            "vendor": capability.vendor,
                            "scope": capability.scope.value,
                            "resolution": capability.resolution.value,
                            "merge_rule": capability.merge_rule,
                            "condition": capability.condition,
                            "remediation": rule.remediation,
                            "atr": list(rule.atr),
                            "references": list(rule.references),
                            "facts": capability.facts,
                        },
                    )
                )
    return tuple(findings), tuple(gaps)
