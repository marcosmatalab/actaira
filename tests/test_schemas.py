"""The published contracts: every document validates, and v1 cannot shrink.

Design note D-150. A schema nobody validates against is documentation, and
documentation drifts. Two kinds of test here, and they defend different
things.

The first kind runs the tool, takes what came out, and validates it. That
catches a producer that stopped matching its own contract.

The second is a frozen list of the required fields of each v1. It catches the
change nobody notices they are making: dropping a field, or renaming it,
because it seemed internal. Someone's parser depends on it, and the only
place that can be stated is a test that fails.
"""
from __future__ import annotations

import re

import pytest

from actaira import schemas
from conftest import REPO_ROOT, SRC_DIR

jsonschema = pytest.importorskip("jsonschema", reason="the schema checks need jsonschema")


def validator_for(name: str):
    """A validator that resolves `$ref` from the local set, never the network.

    A tool that promises to work offline cannot have a test suite that fetches
    schemas over HTTP, and a validator with no resolver silently skips the
    embedded documents - so the report's coverage block would go unchecked
    while the test still passed.
    """
    schema = schemas.load(name)
    registry_source = schemas.registry()
    try:
        from referencing import Registry, Resource

        registry = Registry().with_resources(
            (uri, Resource.from_contents(document)) for uri, document in registry_source.items()
        )
        return jsonschema.Draft202012Validator(schema, registry=registry)
    except ImportError:  # pragma: no cover - older jsonschema
        resolver = jsonschema.RefResolver.from_schema(schema, store=registry_source)
        return jsonschema.Draft202012Validator(schema, resolver=resolver)


def check(name: str, document: dict) -> None:
    errors = sorted(validator_for(name).iter_errors(document), key=lambda error: error.path)
    assert not errors, "\n".join(f"{list(error.path)}: {error.message}" for error in errors)


# --------------------------------------------------------------------------
# The version number is recorded once, and there is no second place
# --------------------------------------------------------------------------


def test_no_module_writes_a_schema_version_of_its_own():
    """The version is read from `schemas.VERSIONS`. Nowhere may spell one again.

    This used to be four parametrised cases asserting that a module constant and
    a schema `const` agreed. That test passes for exactly as long as somebody
    keeps two copies in step, and the thing it was really protecting is that
    there should be one copy. So it is inverted: no module under `src/` may
    contain a version literal at all, and `trace/model.py` gets its
    `SCHEMA_VERSION` from the registry.

    Deliberately a text scan rather than an import check. A literal assigned to
    a constant, buried in a dict, or interpolated into a document all read the
    same way here, and all three are the second copy.
    """
    pattern = re.compile(r"""['"][a-z-]+/v\d+['"]""")
    offenders = []
    for path in sorted((SRC_DIR / "actaira").rglob("*.py")):
        if "__pycache__" in path.parts or path.parent.name == "schemas":
            continue  # the registry is the one place a version may be written
        for number, line in enumerate(path.read_text("utf-8").splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue  # a comment naming a version is prose, not a second copy
            for hit in pattern.findall(line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}: {hit}")

    assert offenders == [], (
        "a schema version is written outside src/actaira/schemas/:\n"
        + "\n".join(offenders)
        + "\nRead it from `schemas.VERSIONS` instead."
    )


def test_the_scan_above_would_notice_a_version_literal():
    """The non-vacuity half: an empty offender list has to mean something.

    An assertion over a scan that finds nothing passes whether the rule holds or
    the scan is broken. This pins that the pattern matches what it is for.
    """
    pattern = re.compile(r"""['"][a-z-]+/v\d+['"]""")

    assert pattern.findall('SCHEMA_VERSION = "trace/v3"') == ['"trace/v3"']
    assert pattern.findall("version = 'policy-decision/v1'") == ["'policy-decision/v1'"]
    assert pattern.findall("SCHEMA_VERSION = schemas.VERSIONS[\"trace\"]") == []


def test_the_reader_takes_its_versions_from_the_registry():
    """The other direction: the one copy is the copy the writer actually uses."""
    from actaira.trace import model as trace_model

    assert trace_model.SCHEMA_VERSION == schemas.VERSIONS["trace"]
    assert trace_model.READS == schemas.accepted("trace")
    assert schemas.load(schemas.stem(trace_model.SCHEMA_VERSION))["properties"][
        "schema_version"
    ]["const"] == trace_model.SCHEMA_VERSION


def test_every_declared_version_has_a_schema_file():
    for version in schemas.VERSIONS.values():
        assert schemas.stem(version) in schemas.names(), f"{version} is declared with no schema"


# --------------------------------------------------------------------------
# v1 cannot shrink
# --------------------------------------------------------------------------


# Frozen. Adding to a list here is fine only when the field was required in
# the first v1 release; making an existing optional field required is v2. The
# point of writing them out is that a deletion has to be typed deliberately.
FROZEN_REQUIRED = {
    "trace-v1": [
        "authenticity", "capture_level", "complete", "events", "gaps",
        "schema_version", "session_id", "source",
    ],
    "trace-v2": [
        "authenticity", "capture_level", "complete", "events", "gaps",
        "schema_version", "session_id", "source",
    ],
    "trace-v3": [
        "authenticity", "capture_level", "complete", "events", "gaps",
        "schema_version", "session_id", "source",
    ],
    # The three lists that must never be merged are three required fields. A
    # `surface/v1` document that dropped `unresolved` would be reporting a clean
    # answer about a tree nobody finished reading, and `not_read` is what keeps
    # the vendors phase S1 does not read from looking absent.
    "surface-v1": [
        "findings", "machine", "not_read", "root", "schema_version", "surfaces",
        "unresolved",
    ],
    # Five change lists and a sixth for what could not be resolved, and all six
    # required for the same reason `surface/v1` requires three: a consumer that
    # found `indeterminate` missing would read a diff with no unresolved changes
    # in it, which is the one thing this document must not be able to imply.
    # `unchanged` is required too, because "nothing moved" and "nothing was
    # compared" are the two answers a reader must be able to tell apart.
    "surface-diff-v1": [
        "added", "after", "before", "changed", "indeterminate", "narrowed",
        "removed", "schema_version", "unchanged", "widened",
    ],
    # `salt_travels` is required and is a `const: false`. A seal that could omit
    # it is a seal whose reader has to assume the redaction held, and the whole
    # document is built on the salt having stayed behind.
    "seal-v1": [
        "findings", "machine", "not_read", "root_ref", "salt_travels",
        "schema_version", "surface_schema_version", "surface_sha256", "surfaces",
        "unresolved",
    ],
}


@pytest.mark.parametrize("name", sorted(FROZEN_REQUIRED))
def test_no_required_field_has_been_dropped_from_v1(name):
    """The change nobody notices they are making.

    A field is removed or renamed because it looked internal, and somewhere
    a parser that depended on it stops working in a release that claimed
    compatibility. The only place that can be stated is here.
    """
    required = sorted(schemas.load(name).get("required", []))

    assert required == sorted(FROZEN_REQUIRED[name]), (
        f"{name}'s required fields changed. If a field genuinely has to go, that is v2: "
        "add the new schema, keep this one, and say so in CHANGELOG."
    )


@pytest.mark.parametrize("name", sorted(FROZEN_REQUIRED))
def test_every_schema_accepts_extra_properties(name):
    """New optional fields must be addable within v1, which means a strict
    consumer cannot be written against the absence of a field. Turning this
    off would make every added field a breaking change."""
    assert schemas.load(name).get("additionalProperties") is True


def property_names(node, trail=""):
    """Every property name anywhere in a schema, with the path that reaches it.

    The first version of this test read `schema["properties"]` and stopped
    there, so it saw the top level of each document and nothing below it: a
    `risk_score` inside `subjects[].items.properties`, which is where a
    per-subject field actually goes, was invisible to it. `$defs`, `items`,
    `allOf` and the rest are walked for the same reason - a consumer switches
    on the name wherever it sits, and so does a reader.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "properties" and isinstance(value, dict):
                for declared in value:
                    yield f"{trail}/{declared}", declared
            yield from property_names(value, f"{trail}/{key}")
    elif isinstance(node, list):
        for position, value in enumerate(node):
            yield from property_names(value, f"{trail}[{position}]")


def test_the_property_walk_reaches_below_the_top_level():
    """The scan itself, so this file cannot go green by scanning nothing."""
    found = {
        (name, path)
        for name in schemas.names()
        for path, _ in property_names(schemas.load(name))
    }

    assert found, "the walk found no properties at all"
    assert any(path.count("/") > 2 for _name, path in found), "the walk is still shallow"


def test_no_schema_declares_a_score_shaped_property():
    """The refusal, checked against property names rather than prose.

    An earlier version searched the whole serialised schema and failed on the
    receipt's own description, which says "not a score" - the sentence that
    states the refusal was read as a violation of it. Property names are the
    thing that matters: a consumer switches on those, and a field named
    `risk_score` in any of these documents would make the whole argument of
    this repository a slogan.

    The word list is the first negative plus `level`, which is not in
    that sentence and is kept because `compliance_level` is the shape a
    consumer would reach for first.

    `capture_level` is the one exception, named here rather than allowed by a
    looser pattern. It is not a judgement of the run: it says how the run was
    observed - a transcript, a tool proxy, a network proxy, a sandbox - and
    `docs/PRINCIPLES.md` requires every record to declare it. A field saying what method
    produced the evidence is the opposite of a field summarising the evidence,
    and renaming it to dodge four letters would cost the vocabulary the whole
    governance document uses.
    """
    forbidden = ("score", "grade", "rating", "percent", "confidence", "ranking", "level")
    allowed = {"capture_level"}
    for name in schemas.names():
        for path, declared in property_names(schemas.load(name)):
            if declared in allowed:
                continue
            assert not any(word in declared.lower() for word in forbidden), f"{name}{path}"


def test_the_one_allowed_level_field_is_still_the_only_one():
    """The exemption above is a list of one, and this is what keeps it that
    size: a second field slipping in under the same excuse would not have been
    argued for anywhere."""
    levelled = {
        declared
        for name in schemas.names()
        for _path, declared in property_names(schemas.load(name))
        if "level" in declared.lower()
    }

    assert levelled == {"capture_level"}, f"an unargued level-shaped field appeared: {levelled}"


# --------------------------------------------------------------------------
# The schemas are part of the package
# --------------------------------------------------------------------------


def test_the_schemas_ship_with_the_package():
    """A contract that is only in the repository is a contract a pip install
    does not carry, and the first thing an SDK author does is look for it."""
    import tomllib
    from pathlib import Path

    pyproject = tomllib.loads((Path(REPO_ROOT) / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = pyproject["tool"]["setuptools"]["package-data"]["actaira"]

    assert any("schemas/" in pattern for pattern in package_data), package_data


def test_the_registry_resolves_every_reference():
    """Every `$ref` in every schema has to be in the local set, or an offline
    validation silently skips the embedded document.

    The three surviving contracts are self-contained, so there is nothing to
    resolve and the old non-vacuity guard - "the schemas reference each other;
    if not, this test is vacuous" - is now the thing that is false. It was
    written when a report embedded a coverage matrix and a receipt embedded a
    policy decision; all four of those schemas left in phase A. The guard is
    inverted rather than deleted: this asserts there are no cross-references
    AND that the walk would have found one, so the day a `$ref` reappears the
    resolution check starts biting again instead of passing over nothing.
    """
    registry = schemas.registry()
    referenced = set()

    def walk(node):
        if isinstance(node, dict):
            if "$ref" in node and isinstance(node["$ref"], str) and node["$ref"].startswith("http"):
                referenced.add(node["$ref"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for name in schemas.names():
        walk(schemas.load(name))

    assert referenced <= set(registry), sorted(referenced - set(registry))

    # The non-vacuity half, in both directions.
    assert referenced == set(), (
        "a schema references another again; the assertion above is live now, and "
        "this line is the one to delete"
    )
    walk({"properties": {"x": {"$ref": "https://actaira.dev/schemas/trace-v3.json"}}})
    assert referenced == {"https://actaira.dev/schemas/trace-v3.json"}, "the walk does not walk"


def test_every_published_contract_has_its_required_fields_frozen():
    """The list has to cover the published surface, not part of it.

    `docs/COMPATIBILITY.md` and both READMEs say a frozen list of each
    version's required fields means dropping one fails the build. That was
    true of 7 of the 14 contracts on disk: every family added in 2.2 shipped
    without an entry here, so the promise was made about the whole surface and
    kept for half of it. Adding a schema and forgetting this dict is the
    obvious next instance, and this is what refuses it.
    """
    published = set(schemas.names())
    unfrozen = sorted(published - set(FROZEN_REQUIRED))
    assert not unfrozen, (
        "contract(s) shipped with no frozen required-field list, so a field could be "
        f"dropped from one without failing anything: {', '.join(unfrozen)}"
    )
    stale = sorted(set(FROZEN_REQUIRED) - published)
    assert not stale, (
        f"frozen entries for contracts that are not on disk: {', '.join(stale)}"
    )


# --------------------------------------------------------------------------
# Frozen history: two revisions this tree reads and never writes
# --------------------------------------------------------------------------


def test_the_superseded_revisions_are_read_and_never_emitted():
    """`trace/v1` and `trace/v2` are history on disk, not live contracts.

    A schema file that ships is a promise. These two are kept so a document an
    earlier build wrote still parses - not so a consumer can expect new ones -
    and the difference between those two readings is exactly what a consumer
    gets wrong when nothing states it. `docs/COMPATIBILITY.md` says which
    revision superseded each and why; this is the machine half of that.
    """
    from actaira.trace import model as trace_model

    for old in schemas.SUPERSEDED["trace"]:
        assert old in trace_model.READS, f"{old} is frozen, which means still readable"
        assert old != trace_model.SCHEMA_VERSION, f"{old} is superseded and must not be written"
        assert schemas.stem(old) in schemas.names(), f"{old} is declared with no file on disk"

    assert trace_model.SCHEMA_VERSION == "trace/v3", "v3 is the only live revision"


def test_no_document_this_tree_emits_declares_a_superseded_revision(tmp_path):
    """The direction that actually bites: run the emitters and read the result.

    Asserting on `SCHEMA_VERSION` alone would pass for a writer that
    interpolated an old version into a document by hand. This takes what the
    emitters produce and reads the field back out of it.
    """
    from support.reports import emitted_documents

    emitted = emitted_documents(tmp_path)
    assert emitted, "no emitted document was collected; this test would pass over nothing"

    # Which family each emitter writes. Named rather than inferred from the
    # string: an emitter that wrote the wrong family's version would otherwise
    # be checked against its own mistake.
    families = {
        "scan": "trace", "watch": "trace", "check": "surface",
        "diff": "surface-diff", "seal": "seal",
    }

    for name, document in emitted:
        family = families.get(name.split()[0])
        assert family, f"{name} emits a document and this test does not know its family"
        stated = document.get("schema_version")
        assert stated == schemas.VERSIONS[family], f"{name} declares {stated!r}"
        assert stated not in schemas.SUPERSEDED.get(family, ()), (
            f"{name} emits a frozen revision"
        )
