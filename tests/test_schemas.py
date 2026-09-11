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

import json
import pickle
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from actaira import receipt as receipt_mod
from actaira import schemas
from actaira.agentgov import load_text as load_agent
from actaira.attest import signing
from actaira.bundle import resolve
from actaira.inspect import inspect_artifact
from actaira.policy import decide, load_policy_text
from actaira.policy.engine import Claims

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


@pytest.fixture
def clean_report(tmp_path):
    path = tmp_path / "clean.pkl"
    path.write_bytes(pickle.dumps({"w": [1.0, 2.0]}))
    return inspect_artifact(path)


POLICY_TEXT = """
policy: schema-demo
version: 1
rules:
  - id: no-high
    effect: deny
    when:
      finding_severity_at_least: high
exceptions:
  - rule: no-high
    owner: marcos@example.com
    reason: a documented, dated waiver
    expires: 2026-12-01
"""

AGENT_TEXT = """
agent: schema-demo
version: "2"
model: anthropic/claude-sonnet-4-5
model_digest: sha256:abc
prompt_sha256: def
tools:
  - name: search
    effects:
      - read
mcp_servers:
  - name: github
    reference: ghcr.io/example/mcp@sha256:abc
    publisher: example
"""


# --------------------------------------------------------------------------
# What the tool actually emits validates
# --------------------------------------------------------------------------


def test_every_schema_file_is_itself_a_valid_schema():
    for name in schemas.names():
        jsonschema.Draft202012Validator.check_schema(schemas.load(name))


def test_an_artifact_report_validates(clean_report):
    check("report-v1", clean_report.to_dict())


def test_a_report_of_a_hostile_artifact_validates_too(tmp_path):
    """The interesting document is the one with findings in it. A schema
    exercised only on clean output describes half the format."""
    from evals.corpus import build as corpus_build

    path = tmp_path / "gadget.pkl"
    path.write_bytes(corpus_build.craft_reduce("posix", "system", ("id",), 2))

    check("report-v1", inspect_artifact(path).to_dict())


def test_a_coverage_matrix_validates(clean_report):
    check("coverage-v1", clean_report.coverage.to_dict())


def test_a_policy_validates():
    check("policy-v1", load_policy_text(POLICY_TEXT).to_dict())


def test_a_policy_decision_validates(clean_report):
    policy = load_policy_text(POLICY_TEXT)
    decision = decide(policy, [Claims(clean_report)], on=date(2026, 9, 11))

    check("policy-decision-v1", decision.to_dict())


def test_a_signed_receipt_validates(clean_report):
    document = receipt_mod.sign(
        receipt_mod.build([clean_report], observed_at=datetime(2026, 9, 11, tzinfo=UTC)),
        signing.generate(),
    )

    check("assurance-receipt-v2", document)


def test_a_receipt_carrying_a_decision_validates(clean_report):
    policy = load_policy_text(POLICY_TEXT)
    decision = decide(policy, [Claims(clean_report)], on=date(2026, 9, 11))
    document = receipt_mod.sign(
        receipt_mod.build(
            [clean_report],
            observed_at=datetime(2026, 9, 11, tzinfo=UTC),
            policy_decision=decision.to_dict(),
            attestation={"signature_verified": True, "signer_trusted": True},
        ),
        signing.generate(),
    )

    check("assurance-receipt-v2", document)


def test_an_agent_bom_validates():
    agent = load_agent(AGENT_TEXT)
    document = agent.to_bom()
    document["agent_digest"] = agent.digest

    check("agent-bom-v2", document)


def test_the_shipped_example_agent_validates():
    from actaira.agentgov import load
    from conftest import REPO_ROOT

    agent = load(Path(REPO_ROOT) / "examples" / "agent-ticket-triage.yaml")
    document = agent.to_bom()
    document["agent_digest"] = agent.digest

    check("agent-bom-v2", document)


def test_a_model_bundle_validates(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "config.json").write_text(
        json.dumps({"architectures": ["Custom"], "auto_map": {"AutoModel": "modeling.Custom"}}),
        encoding="utf-8",
    )
    (root / "modeling.py").write_text("import os\n", encoding="utf-8")

    check("model-bundle-v2", resolve(root).to_dict())


def test_the_shipped_policy_validates():
    from actaira.policy import load_policy
    from conftest import REPO_ROOT

    check("policy-v1", load_policy(Path(REPO_ROOT) / "policies" / "production-model.yaml").to_dict())


# --------------------------------------------------------------------------
# The version number is recorded once, not twice
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "module_path,constant,schema_name",
    [
        ("actaira.coverage", "SCHEMA_VERSION", "coverage-v1"),
        ("actaira.policy.model", "POLICY_SCHEMA_VERSION", "policy-v1"),
        ("actaira.policy.model", "SCHEMA_VERSION", "policy-decision-v1"),
        ("actaira.receipt", "SCHEMA_VERSION", "assurance-receipt-v2"),
        ("actaira.agentgov.model", "SCHEMA_VERSION", "agent-bom-v2"),
        ("actaira.bundle", "SCHEMA_VERSION", "model-bundle-v2"),
    ],
)
def test_the_module_and_the_schema_agree_about_the_version(module_path, constant, schema_name):
    """Two places recording one version number is how a document ends up
    declaring a version whose shape it does not have."""
    import importlib

    module = importlib.import_module(module_path)
    stated = getattr(module, constant)
    schema = schemas.load(schema_name)

    assert schema["properties"]["schema_version"]["const"] == stated


def test_every_declared_version_has_a_schema_file():
    for version in schemas.VERSIONS.values():
        assert schemas.stem(version) in schemas.names(), f"{version} is declared with no schema"


def test_every_superseded_version_is_still_on_disk():
    """A published contract stays published.

    `docs/COMPATIBILITY.md` promises it, and the promise is not rhetorical: a
    consumer written against `model-bundle/v1` is not wrong, it is old, and
    deleting the file it validates against would break it on an upgrade that
    claimed to be additive. `actaira schema` keeps listing these.
    """
    for family, versions in schemas.SUPERSEDED.items():
        for version in versions:
            assert schemas.stem(version) in schemas.names(), f"{family}: {version} was dropped"


def test_nothing_emits_a_superseded_version():
    """Reading the old shape is compatibility. Writing it is a bug.

    The asymmetry is the whole compatibility story in one test: this release
    accepts every version in `SUPERSEDED` and must produce none of them, or a
    branch nobody exercised will emit a v1 document under a v2 tool and the
    consumer on the other end will believe the old meaning.
    """
    import importlib

    emitters = {
        "agent-bom": ("actaira.agentgov.model", "SCHEMA_VERSION"),
        "model-bundle": ("actaira.bundle", "SCHEMA_VERSION"),
        "assurance-receipt": ("actaira.receipt", "SCHEMA_VERSION"),
    }
    for family, (module_path, constant) in emitters.items():
        stated = getattr(importlib.import_module(module_path), constant)

        assert stated not in schemas.SUPERSEDED[family], f"{module_path} still emits {stated}"
        assert stated == schemas.VERSIONS[family]


# --------------------------------------------------------------------------
# v1 cannot shrink
# --------------------------------------------------------------------------


# Frozen. Adding to a list here is fine only when the field was required in
# the first v1 release; making an existing optional field required is v2. The
# point of writing them out is that a deletion has to be typed deliberately.
FROZEN_REQUIRED = {
    "coverage-v1": ["schema_version", "surfaces"],
    "report-v1": [
        "coverage", "detected_format", "findings", "format_confidence",
        "path", "sha256", "size_bytes", "verdict",
    ],
    "policy-v1": ["policy", "rules", "schema_version", "version"],
    "policy-decision-v1": [
        "decided_on", "decision", "policy", "proof", "schema_version", "subjects",
    ],
    "assurance-receipt-v1": [
        "coverage", "findings_by_severity", "observed_at", "schema_version",
        "states_what_it_does_not_cover", "subjects", "supply_chain", "tool",
    ],
    "assurance-receipt-v2": [
        "coverage", "findings_by_severity", "observed_at", "schema_version",
        "states_what_it_does_not_cover", "subjects", "supply_chain", "tool",
    ],
    "agent-bom-v1": ["agent", "effects", "mcp_servers", "schema_version", "tools"],
    "agent-bom-v2": [
        "agent", "effects", "mcp_servers", "relations", "schema_version", "tools", "vocabulary",
    ],
    "model-bundle-v1": [
        "bundle_digest", "coverage", "findings", "members", "root", "schema_version",
    ],
    "model-bundle-v2": [
        "content_identity", "coverage", "findings", "members", "root", "schema_version",
        "structural_digest",
    ],
    # The seven contracts 2.2 published. They were not in this dict when they
    # shipped, so `docs/COMPATIBILITY.md` and both READMEs said "a frozen list
    # of each version's required fields means dropping one fails the build"
    # while half the published surface was frozen by nothing. A promise made
    # about fourteen contracts and kept for seven is the shape of claim this
    # repository exists to refuse.
    "asset-graph-v1": ["cycles", "edges", "nodes", "schema_version"],
    "attack-paths-v1": ["agent", "cycles", "open_paths", "paths", "schema_version"],
    "evidence-record-v1": [
        "collector", "collector_version", "digest", "evidence_id", "kind",
        "observed_at", "schema_version", "state", "subject",
    ],
    "source-snapshot-v1": [
        "artifacts", "connector", "listing_complete", "observed_at",
        "schema_version", "snapshot_digest", "source",
    ],
    "state-export-v1": [
        "assets", "edges", "evidence", "schema_version", "snapshots", "sources",
        "store_schema_version",
    ],
    "subject-manifest-v1": ["schema_version", "subjects"],
    # `trust-policy/v1` requires only its version, and that is deliberate: a
    # trust policy with no rules is an environment that has not decided
    # anything yet, which is a state the whole trust layer is built to
    # represent. Frozen anyway, so making a field required later is a visible
    # change rather than a quiet one.
    "trust-policy-v1": ["schema_version"],
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


def test_no_schema_declares_a_score_shaped_property():
    """The refusal, checked against property names rather than prose.

    The first version of this test searched the whole serialised schema and
    failed on the receipt's own description, which says "not a score" - the
    sentence that states the refusal was read as a violation of it. Property
    names are the thing that matters: a consumer switches on those, and a
    field named `risk_score` in any of these documents would make the whole
    argument of this repository a slogan.
    """
    forbidden = ("score", "grade", "rating", "percent", "level")
    for name in schemas.names():
        properties = schemas.load(name).get("properties", {})
        for key in properties:
            assert not any(word in key.lower() for word in forbidden), f"{name}.{key}"


# --------------------------------------------------------------------------
# The schemas are part of the package
# --------------------------------------------------------------------------


def test_the_schemas_ship_with_the_package():
    """A contract that is only in the repository is a contract a pip install
    does not carry, and the first thing an SDK author does is look for it."""
    import tomllib

    from conftest import REPO_ROOT

    pyproject = tomllib.loads((Path(REPO_ROOT) / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = pyproject["tool"]["setuptools"]["package-data"]["actaira"]

    assert any("schemas/" in pattern for pattern in package_data), package_data


def test_the_registry_resolves_every_reference():
    """Every `$ref` in every schema has to be in the local set, or an offline
    validation silently skips the embedded document."""
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

    assert referenced, "the schemas reference each other; if not, this test is vacuous"
    assert referenced <= set(registry), sorted(referenced - set(registry))


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
