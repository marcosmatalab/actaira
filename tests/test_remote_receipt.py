"""Remote bundles keep their provenance, and a receipt speaks about a system.

Design notes D-228 and D-229. Two properties carry most of the weight here:
half a listing can never produce a whole identity, and a v1 receipt written by
an earlier release still verifies under this one.
"""
from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from actaira import receipt as receipt_mod
from actaira import remote as remote_mod
from actaira import subject as subject_mod
from actaira.attest import signing
from actaira.bundle import resolve
from actaira.policy import decide, load_policy_text
from actaira.remote import Fetched


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "fraud"
    root.mkdir()
    (root / "config.json").write_text(
        json.dumps({"architectures": ["FraudNet"], "auto_map": {"AutoModel": "modeling.FraudNet"}}),
        encoding="utf-8",
    )
    (root / "modeling.py").write_text("import os\n", encoding="utf-8")
    (root / "model.safetensors").write_bytes(b"\x02\x00\x00\x00\x00\x00\x00\x00{}")
    return root


def fetched(root, **overrides) -> Fetched:
    defaults = {
        "root": root,
        "uri": "huggingface://acme/fraud-model",
        "connector": "huggingface",
        "revision": "7f91a2c",
        "declared": {},
        "listing_complete": True,
    }
    return Fetched(**{**defaults, **overrides})


# --------------------------------------------------------------------------
# Provenance
# --------------------------------------------------------------------------


def test_a_remote_resolution_names_where_the_bytes_came_from(repository):
    document = remote_mod.resolve_remote(fetched(repository)).to_dict()

    assert document["provenance"] == {
        "uri": "huggingface://acme/fraud-model",
        "revision": "7f91a2c",
        "connector": "huggingface",
    }


def test_declared_digests_reach_the_document_as_declarations(repository):
    document = remote_mod.resolve_remote(
        fetched(repository, declared={"model.safetensors": ("ab" * 32, "huggingface")})
    ).to_dict()
    row = next(item for item in document["members"] if item["path"] == "model.safetensors")

    assert row["declared_sha256"] == "ab" * 32
    assert row["declared_by"] == "huggingface"


def test_an_incomplete_listing_is_a_finding_and_lowers_the_surface(repository):
    from actaira.coverage import CoverageState, Surface

    bundle = remote_mod.resolve_remote(
        fetched(repository, listing_complete=False, incomplete_because="page 2 returned 503")
    )

    assert "ACT-BDL-009" in {finding.rule_id for finding in bundle.findings}
    assert bundle.coverage.state(Surface.ARCHIVE_STRUCTURE) is CoverageState.PARTIAL
    assert bundle.listing_complete is False


def test_half_a_listing_cannot_report_a_complete_identity(repository):
    """The gate the roadmap names. Every member present was identified and the
    set of members was not, which is not the same as identifying the model."""
    bundle = remote_mod.resolve_remote(fetched(repository, listing_complete=False))

    assert bundle.content_identity()["state"] == "complete", (
        "the members that arrived were all hashed; that part is true"
    )
    capped = remote_mod.capped_identity(bundle, listing_complete=False)
    assert capped["state"] == "partial"
    assert capped["digest"] is None
    assert "listing was incomplete" in capped["capped_because"]


def test_a_complete_listing_is_left_alone(repository):
    bundle = remote_mod.resolve_remote(fetched(repository))

    assert remote_mod.capped_identity(bundle, listing_complete=True) == bundle.content_identity()


def test_a_cache_key_separates_two_revisions_of_one_uri():
    assert remote_mod.cache_key("hf://a/b", "r1") != remote_mod.cache_key("hf://a/b", "r2")


def test_a_cache_entry_with_no_digest_to_check_is_never_served(tmp_path):
    """A cache entry trusted by its filename is one that whoever can write to
    `.actaira/` gets to choose."""
    entry = tmp_path / "entry"
    entry.mkdir()
    (entry / "model.safetensors").write_bytes(b"anything")

    assert remote_mod._cache_is_intact(entry, {}) is False


def test_a_cache_entry_whose_bytes_moved_is_rejected(tmp_path):
    import hashlib

    entry = tmp_path / "entry"
    entry.mkdir()
    (entry / "a.bin").write_bytes(b"original")
    digest = hashlib.sha256(b"original").hexdigest()

    assert remote_mod._cache_is_intact(entry, {"a.bin": (digest, "hf")}) is True
    (entry / "a.bin").write_bytes(b"tampered")
    assert remote_mod._cache_is_intact(entry, {"a.bin": (digest, "hf")}) is False


def test_a_local_source_is_resolved_where_it_is(repository):
    """Copying a 30 GB repository into a staging directory to read its config
    would double the disk cost of the largest thing this tool touches."""
    result = remote_mod.fetch(f"file://{repository}", destination=Path("/nonexistent"), offline=True)

    assert result.root == repository
    assert result.from_cache is False


def test_a_network_connector_under_offline_is_refused_before_anything_runs():
    with pytest.raises(remote_mod.RemoteBundleError, match="needs the network"):
        remote_mod.fetch("huggingface://acme/fraud", destination=Path("/tmp/x"), offline=True)


def test_an_unknown_uri_is_a_usage_error():
    with pytest.raises(remote_mod.RemoteBundleError, match="no connector"):
        remote_mod.fetch("nonsense://acme/fraud", destination=Path("/tmp/x"), offline=True)


# --------------------------------------------------------------------------
# Receipt v2
# --------------------------------------------------------------------------


POLICY = """
policy: prod
version: 1
rules:
  - id: no-remote-code
    effect: deny
    when:
      subject_kind: bundle
      bundle_finding: ACT-BDL-002
"""


@pytest.fixture
def signed_v2(repository, tmp_path):
    import pickle

    from actaira.inspect import inspect_artifact

    artifact = tmp_path / "clean.pkl"
    artifact.write_bytes(pickle.dumps({"w": [1.0]}))
    report = inspect_artifact(artifact)
    bundle = resolve(repository)

    subjects = [subject_mod.for_artifact(report), subject_mod.for_bundle(bundle)]
    decision = decide(load_policy_text(POLICY), subjects, on=date(2026, 9, 11))
    document = receipt_mod.build(
        [report],
        observed_at=datetime(2026, 9, 11, tzinfo=UTC),
        subjects=subjects,
        policy_decision=decision.to_dict(),
        evidence=[
            {"evidence_id": "ev_a", "kind": "bundle", "state": "valid",
             "digest": "sha256:" + "a" * 64, "observed_at": "2026-09-11T00:00:00+00:00"}
        ],
        snapshots=[{"source": "hf://acme/fraud", "revision": "7f91", "snapshot_digest": "sha256:" + "b" * 64,
                    "listing_complete": True}],
        graph={"nodes": [{"id": "bundle:fraud"}], "edges": [{"from": "a", "relation": "uses", "to": "b"}]},
    )
    return receipt_mod.sign(document, signing.generate())


def test_a_v2_receipt_names_every_kind_of_subject_it_decided_over(signed_v2):
    kinds = {row["kind"] for row in signed_v2["typed_subjects"]}

    assert kinds == {"artifact", "bundle"}
    assert all(row["handle"] for row in signed_v2["typed_subjects"])


def test_a_bundle_subject_carries_its_content_identity_state(signed_v2):
    """The field that stops a receipt claiming 'the same model' about a
    repository whose weights nobody read."""
    bundle_row = next(row for row in signed_v2["typed_subjects"] if row["kind"] == "bundle")

    assert bundle_row["content_identity"]["state"] in (
        "complete", "partial", "externally_bound", "unavailable"
    )
    assert "ACT-BDL-002" in bundle_row["findings"]


def test_the_v1_fields_are_all_still_there(signed_v2):
    for field in ("subjects", "coverage", "findings_by_severity", "supply_chain",
                  "states_what_it_does_not_cover", "observed_at", "tool"):
        assert field in signed_v2


def test_a_v2_receipt_verifies(signed_v2):
    result = receipt_mod.verify(signed_v2)

    assert result.ok, result.problems
    assert result.schema_version == "assurance-receipt/v2"


@pytest.mark.parametrize(
    "path",
    [
        ("typed_subjects", 0, "digest"),
        ("evidence", 0, "evidence_id"),
        ("snapshots", 0, "snapshot_digest"),
        ("graph", "digest"),
    ],
)
def test_editing_any_new_field_breaks_the_signature(signed_v2, path):
    """Everything v2 added is inside the signature. A graph reference or an
    evidence id that could be swapped after signing would be a reference to
    whatever the holder of the file preferred."""
    document = json.loads(json.dumps(signed_v2))
    node = document
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = "sha256:" + "0" * 64

    assert not receipt_mod.verify(document).ok


def test_a_v1_receipt_still_verifies_under_this_release(repository, tmp_path):
    """`docs/COMPATIBILITY.md` promises it, and an upgrade that broke every
    receipt the previous release signed would make the promise worthless.

    Written as a v1 document by construction rather than by calling `build`,
    because `build` does not emit v1 any more and must not.
    """
    import pickle

    from actaira.inspect import inspect_artifact

    artifact = tmp_path / "clean.pkl"
    artifact.write_bytes(pickle.dumps({"w": [1.0]}))
    report = inspect_artifact(artifact)

    document = receipt_mod.build([report], observed_at=datetime(2026, 9, 11, tzinfo=UTC))
    document["schema_version"] = "assurance-receipt/v1"
    for field in ("typed_subjects", "evidence", "snapshots", "graph", "trust"):
        document.pop(field, None)
    signed = receipt_mod.sign(document, signing.generate())

    result = receipt_mod.verify(signed)

    assert result.ok, result.problems
    assert result.schema_version == "assurance-receipt/v1"


def test_a_receipt_from_an_unpublished_version_is_refused(signed_v2):
    document = json.loads(json.dumps(signed_v2))
    document["schema_version"] = "assurance-receipt/v9"

    result = receipt_mod.verify(document)

    assert not result.ok
    assert "assurance-receipt/v1" in result.problems[0]


def test_the_builder_never_emits_a_superseded_version(repository, tmp_path):
    import pickle

    from actaira.inspect import inspect_artifact

    artifact = tmp_path / "clean.pkl"
    artifact.write_bytes(pickle.dumps({"w": [1.0]}))

    document = receipt_mod.build(
        [inspect_artifact(artifact)], observed_at=datetime(2026, 9, 11, tzinfo=UTC)
    )

    assert document["schema_version"] not in receipt_mod.LEGACY_SCHEMA_VERSIONS


def test_a_v2_receipt_validates_against_its_schema(signed_v2):
    jsonschema = pytest.importorskip("jsonschema")

    from referencing import Registry, Resource

    from actaira import schemas

    registry_source = schemas.registry()

    registry = Registry().with_resources(
        (uri, Resource.from_contents(doc)) for uri, doc in registry_source.items()
    )
    validator = jsonschema.Draft202012Validator(schemas.load("assurance-receipt-v2"), registry=registry)

    assert not list(validator.iter_errors(signed_v2))


def test_per_subject_provenance_rather_than_one_for_the_document(repository, tmp_path):
    """A receipt over four subjects from three sources has three provenances,
    and one top-level field would have to pick one."""
    bundle = remote_mod.resolve_remote(fetched(repository))
    claims = subject_mod.for_bundle(
        bundle, provenance={"uri": "huggingface://acme/fraud-model", "revision": "7f91a2c"}
    )

    document = receipt_mod.build(
        [], observed_at=datetime(2026, 9, 11, tzinfo=UTC), subjects=[claims]
    )

    assert document["typed_subjects"][0]["provenance"]["revision"] == "7f91a2c"


# --------------------------------------------------------------------------
# The defects an adversarial read of these modules found
# --------------------------------------------------------------------------


def test_a_revision_the_connector_ignored_is_not_written_into_the_provenance(tmp_path):
    """DEF-86. `--revision 7f91a2c` on a plain directory used to reach the
    provenance, and feeding that to `source_revision_pinned` then satisfied an
    immutability requirement on the strength of a string the operator typed -
    while the connector had said, in a note this code discarded, that a
    directory has no revisions."""
    root = tmp_path / "models"
    root.mkdir()
    (root / "config.json").write_text("{}", encoding="utf-8")

    result = remote_mod.fetch(
        f"file://{root}", revision="7f91a2c", destination=tmp_path / "staged", offline=True
    )

    assert result.revision == ""
    assert any("--revision 7f91a2c was ignored" in note for note in result.notes)


def test_a_local_uri_resolves_to_the_directory_the_connector_listed(tmp_path, monkeypatch):
    """DEF-87. A hand-rolled prefix strip turned `file://x/y` into the
    CWD-relative `x/y` where the connector normalises the same URI to `/x/y`,
    so the report described the bytes of one directory under the provenance of
    another."""
    real = tmp_path / "real"
    real.mkdir()
    (real / "config.json").write_text('{"architectures": ["REAL"]}', encoding="utf-8")
    decoy = tmp_path / "cwd"
    # The same path with its root taken off, so it is relative to the decoy CWD
    # on any platform. `str(real).lstrip("/")` was the POSIX-only spelling: on
    # Windows it leaves the drive letter on, the join stays absolute, and the
    # decoy is built on top of the real directory instead of beside it.
    mirrored = Path(*real.parts[1:])
    (decoy / mirrored).mkdir(parents=True)
    (decoy / mirrored / "config.json").write_text(
        '{"architectures": ["DECOY"]}', encoding="utf-8"
    )
    monkeypatch.chdir(decoy)

    result = remote_mod.fetch(f"file://{real}", destination=tmp_path / "staged", offline=True)

    assert Path(result.root).resolve() == real.resolve()
    assert resolve(result.root).architectures == ["REAL"]


def test_a_receipt_never_quietly_covers_fewer_subjects_than_it_was_given(repository):
    """DEF-93. `_typed_subjects` used to `continue` past a subject with no
    reference, so a receipt over four subjects could list three and say
    nothing about the fourth."""
    from actaira.subject import SubjectClaims

    with pytest.raises(ValueError, match="no reference"):
        receipt_mod.build(
            [],
            observed_at=datetime(2026, 9, 11, tzinfo=UTC),
            subjects=[SubjectClaims()],
        )
