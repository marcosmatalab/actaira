"""A model repository, and the relations a file-by-file scan cannot see.

Design note D-130. The premise of every test here is that each file in the
bundle is individually benign, and the risk is in what they say about each
other. If any of these could be found by pointing `scan` at one file, the
module would not need to exist.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from actaira.bundle import MAX_DIGEST_BYTES, looks_like_bundle, resolve
from actaira.coverage import CoverageState, Surface
from actaira.model import Severity


def rules(bundle) -> set[str]:
    return {finding.rule_id for finding in bundle.findings}


def finding(bundle, rule_id):
    return next(item for item in bundle.findings if item.rule_id == rule_id)


class Repo:
    """A model repository under construction.

    A plain `Path` would be tidier, but `pathlib.Path` uses `__slots__` and
    will not take an attached helper, and every test here writes four or five
    files whose only interesting property is their name. `__fspath__` keeps it
    usable anywhere a path is expected.
    """

    def __init__(self, root):
        self.root = root

    def __fspath__(self) -> str:
        return str(self.root)

    def write(self, name: str, payload):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(payload, (dict, list)):
            path.write_text(json.dumps(payload), encoding="utf-8")
        elif isinstance(payload, bytes):
            path.write_bytes(payload)
        else:
            path.write_text(payload, encoding="utf-8")
        return path


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "model-repo"
    root.mkdir()
    return Repo(root)


def test_a_directory_with_a_config_is_a_bundle_and_one_without_is_not(repo, tmp_path):
    repo.write("config.json", {"architectures": ["LlamaForCausalLM"]})
    plain = tmp_path / "just-files"
    plain.mkdir()
    (plain / "weights.safetensors").write_bytes(b"\x02\x00\x00\x00\x00\x00\x00\x00{}")

    assert looks_like_bundle(Path(repo))
    assert not looks_like_bundle(plain)


# --------------------------------------------------------------------------
# Executable code the loader will import
# --------------------------------------------------------------------------


def test_auto_map_names_the_modules_and_the_files_that_back_them(repo):
    """The mechanism, separated from the flag most people name.

    `trust_remote_code=True` is a consent prompt the caller answers.
    `auto_map` is the list of modules in this repository that the consent
    applies to, and a repository carrying one expects to run its own Python
    inside the loading process before a single weight is read.
    """
    repo.write(
        "config.json",
        {"architectures": ["Custom"], "auto_map": {"AutoModelForCausalLM": "modeling_custom.Custom"}},
    )
    repo.write("modeling_custom.py", "import os\n")

    bundle = resolve(repo)

    assert "ACT-BDL-002" in rules(bundle)
    assert bundle.remote_code_entrypoints == {"AutoModelForCausalLM": "modeling_custom.Custom"}
    code = finding(bundle, "ACT-BDL-008")
    assert code.severity is Severity.HIGH, "auto_map names it, so a documented path reaches it"
    assert code.evidence["named_by_auto_map"] == ["modeling_custom.py"]


def test_python_with_no_auto_map_is_reported_at_a_lower_severity(repo):
    """A `.py` in a model repository is worth naming and is not the same thing
    as one the config nominates. Without an entrypoint there is no documented
    path from loading the model to executing it."""
    repo.write("config.json", {"architectures": ["LlamaForCausalLM"]})
    repo.write("convert_weights.py", "print('a utility script')\n")

    bundle = resolve(repo)

    assert "ACT-BDL-002" not in rules(bundle)
    assert finding(bundle, "ACT-BDL-008").severity is Severity.MEDIUM


def test_a_repository_that_answers_the_consent_prompt_for_you_is_reported(repo):
    """The prompt exists so a human decides whether to execute code shipped
    with a model. A config that sets the flag itself removed that step."""
    repo.write("config.json", {"architectures": ["Custom"], "trust_remote_code": True})

    bundle = resolve(repo)

    assert "ACT-BDL-003" in rules(bundle)
    assert finding(bundle, "ACT-BDL-003").evidence["set_by"] == "the repository, not the caller"


def test_a_clean_repository_reports_nothing_about_its_relations(repo):
    """The negative control that decides whether any of this is usable. A
    checker that fired on a normal safetensors repository would be turned off
    in a week."""
    repo.write("config.json", {"architectures": ["LlamaForCausalLM"]})
    repo.write("tokenizer_config.json", {"model_max_length": 8192})
    repo.write("model.safetensors", b"\x02\x00\x00\x00\x00\x00\x00\x00{}")

    bundle = resolve(repo)

    assert bundle.findings == []
    assert bundle.coverage.state(Surface.ARTIFACT_METADATA) is CoverageState.COMPLETE


# --------------------------------------------------------------------------
# Shards
# --------------------------------------------------------------------------


def test_a_shard_the_index_promises_and_the_repository_lacks_is_reported(repo):
    repo.write("config.json", {"architectures": ["LlamaForCausalLM"]})
    repo.write(
        "model.safetensors.index.json",
        {"weight_map": {"a": "model-00001-of-00002.safetensors", "b": "model-00002-of-00002.safetensors"}},
    )
    repo.write("model-00001-of-00002.safetensors", b"\x02\x00\x00\x00\x00\x00\x00\x00{}")

    bundle = resolve(repo)

    assert "ACT-BDL-005" in rules(bundle)
    assert bundle.shards["model.safetensors.index.json"]["missing"] == [
        "model-00002-of-00002.safetensors"
    ]
    assert bundle.coverage.state(Surface.ARCHIVE_STRUCTURE) is CoverageState.PARTIAL


def test_a_weight_file_no_index_mentions_is_reported_too(repo):
    """The quieter direction, and the one worth more attention. An
    index-driven loader will never touch it, no manifest covers it, and a
    repository whose contents and index disagree has a digest nobody can
    reproduce."""
    repo.write("config.json", {"architectures": ["LlamaForCausalLM"]})
    repo.write("model.safetensors.index.json", {"weight_map": {"a": "model-00001-of-00001.safetensors"}})
    repo.write("model-00001-of-00001.safetensors", b"\x02\x00\x00\x00\x00\x00\x00\x00{}")
    repo.write("extra.safetensors", b"\x02\x00\x00\x00\x00\x00\x00\x00{}")

    bundle = resolve(repo)

    assert "ACT-BDL-006" in rules(bundle)
    assert bundle.shards["model.safetensors.index.json"]["unlisted"] == ["extra.safetensors"]


def test_an_index_that_matches_its_shards_reports_neither(repo):
    repo.write("config.json", {"architectures": ["LlamaForCausalLM"]})
    repo.write("model.safetensors.index.json", {"weight_map": {"a": "model-00001-of-00001.safetensors"}})
    repo.write("model-00001-of-00001.safetensors", b"\x02\x00\x00\x00\x00\x00\x00\x00{}")

    bundle = resolve(repo)

    assert rules(bundle) & {"ACT-BDL-005", "ACT-BDL-006"} == set()


# --------------------------------------------------------------------------
# Adapters and templates
# --------------------------------------------------------------------------


def test_an_adapter_with_no_base_model_digest_is_reported_as_unbound(repo):
    """The same adapter over a different base is a different model. Without
    the base's digest a report about the adapter describes half of what will
    be loaded."""
    repo.write("adapter_config.json", {"base_model_name_or_path": "meta-llama/Llama-3-8B"})
    repo.write("adapter_model.safetensors", b"\x02\x00\x00\x00\x00\x00\x00\x00{}")

    bundle = resolve(repo)

    assert "ACT-BDL-004" in rules(bundle)
    assert bundle.base_model == "meta-llama/Llama-3-8B"
    assert bundle.adapters == ["adapter_model.safetensors"]


def test_an_adapter_that_records_the_base_digest_reports_nothing(repo):
    repo.write(
        "adapter_config.json",
        {"base_model_name_or_path": "meta-llama/Llama-3-8B", "base_model_sha256": "a" * 64},
    )

    bundle = resolve(repo)

    assert "ACT-BDL-004" not in rules(bundle)


def test_a_chat_template_with_control_flow_is_reported_and_a_plain_one_is_not(repo, tmp_path):
    """Code travelling with a model, rendered over whatever a caller passes at
    inference time. MEDIUM, because unlike auto_map it does not run inside the
    loader."""
    repo.write("tokenizer_config.json", {"chat_template": "{% for m in messages %}{{ m.content }}{% endfor %}"})
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "tokenizer_config.json").write_text(
        json.dumps({"chat_template": "USER: {{ messages }}"}), encoding="utf-8"
    )

    assert "ACT-BDL-007" in rules(resolve(repo))
    assert "ACT-BDL-007" not in rules(resolve(plain))


# --------------------------------------------------------------------------
# The bundle's own properties
# --------------------------------------------------------------------------


def test_the_digest_moves_when_a_python_file_appears(repo):
    """The number that answers "is this the repository that was reviewed".
    A file appearing is exactly the change it has to catch."""
    repo.write("config.json", {"architectures": ["LlamaForCausalLM"]})
    before = resolve(repo).digest

    repo.write("modeling_custom.py", "import os\n")
    after = resolve(repo).digest

    assert before != after


def test_the_digest_is_stable_across_two_resolutions(repo):
    repo.write("config.json", {"architectures": ["LlamaForCausalLM"]})
    repo.write("model.safetensors", b"\x02\x00\x00\x00\x00\x00\x00\x00{}")

    assert resolve(repo).digest == resolve(repo).digest


def test_a_file_over_the_digest_budget_says_so_instead_of_omitting_the_field(repo, monkeypatch):
    """A BOM with a missing field reads as "nobody looked". One that states
    the bound reads as a measurement."""
    import actaira.bundle as bundle_module

    monkeypatch.setattr(bundle_module, "MAX_DIGEST_BYTES", 16)
    repo.write("config.json", {"architectures": ["LlamaForCausalLM"]})
    repo.write("model.safetensors", b"\x00" * 128)

    bundle = resolve(repo)
    row = next(item for item in bundle.to_dict()["members"] if item["path"] == "model.safetensors")

    assert row["sha256"] is None
    assert "budget" in row["digest_not_computed"]
    assert MAX_DIGEST_BYTES > 0, "the real budget is still a positive number"


def test_a_config_that_does_not_parse_lowers_the_metadata_surface(repo):
    """A relation that could not be read is not a relation that is absent."""
    repo.write("config.json", "{not json at all")

    bundle = resolve(repo)

    assert "ACT-BDL-001" in rules(bundle)
    assert bundle.coverage.state(Surface.ARTIFACT_METADATA) is CoverageState.PARTIAL


# --------------------------------------------------------------------------
# Identity: shape is not content (ACT22-P0-01, design note D-200)
# --------------------------------------------------------------------------


def test_two_unhashed_weight_files_share_a_layout_and_not_an_identity(repo, tmp_path, monkeypatch):
    """The defect the split exists to fix, written as the gate that pins it.

    Two repositories whose weight file has the same name and the same size and
    entirely different bytes. Under v1 they produced one `bundle_digest`, and a
    field by that name reads as the identity of the model. Here the layout
    digest is allowed to match - that is what a layout digest is - and
    `content_identity` is required to refuse to claim they are the same
    weights.
    """
    import actaira.bundle as bundle_module

    monkeypatch.setattr(bundle_module, "MAX_DIGEST_BYTES", 8)

    other = Repo(tmp_path / "second")
    other.root.mkdir()
    for owner, filler in ((repo, b"\xaa"), (other, b"\xbb")):
        owner.write("config.json", {"architectures": ["LlamaForCausalLM"]})
        owner.write("model.safetensors", filler * 4096)

    left, right = resolve(repo), resolve(other)

    assert left.structural_digest == right.structural_digest, (
        "the layout is genuinely identical; a digest over the layout is allowed to say so"
    )
    for bundle in (left, right):
        identity = bundle.content_identity()
        assert identity["state"] == "unavailable"
        assert identity["digest"] is None
        assert identity["members_unidentified"] == 1
    assert "bundle_digest" not in left.to_dict(), (
        "the field whose name invited the confusion is gone in v2"
    )


def test_hashing_the_weights_makes_the_same_two_repositories_distinguishable(repo, tmp_path, monkeypatch):
    """The other half: with `--hash-weights` the identity is complete and
    different, which is what the flag is for."""
    import actaira.bundle as bundle_module

    monkeypatch.setattr(bundle_module, "MAX_DIGEST_BYTES", 8)

    other = Repo(tmp_path / "second")
    other.root.mkdir()
    for owner, filler in ((repo, b"\xaa"), (other, b"\xbb")):
        owner.write("config.json", {"architectures": ["LlamaForCausalLM"]})
        owner.write("model.safetensors", filler * 4096)

    left = resolve(repo, hash_weights=True).content_identity()
    right = resolve(other, hash_weights=True).content_identity()

    assert left["state"] == right["state"] == "complete"
    assert left["binding_source"] == "local_stream_hash"
    assert left["digest"] != right["digest"]


def test_a_connector_declared_digest_binds_identity_without_reading_the_bytes(repo, monkeypatch):
    """The case that makes the model usable on a 30 GB repository.

    A registry that published a digest for a file it served has bound that
    file's identity. Actaira may rely on it and must say whose word it is
    taking, which is what `binding_source` and `declared_by` are for.
    """
    import actaira.bundle as bundle_module

    monkeypatch.setattr(bundle_module, "MAX_DIGEST_BYTES", 8)
    repo.write("config.json", {"architectures": ["LlamaForCausalLM"]})
    repo.write("model.safetensors", b"\x00" * 4096)

    bundle = resolve(repo, declared_digests={"model.safetensors": ("ab" * 32, "huggingface")})
    identity = bundle.content_identity()

    assert identity["state"] == "externally_bound"
    assert identity["binding_source"] == "connector_declared_digest"
    assert identity["declared_by"] == ["huggingface"]
    assert identity["digest"] is None, (
        "a digest over a set bound by somebody else's word would look exactly like one this "
        "process computed"
    )


def test_a_declared_digest_never_lands_in_the_measured_field(repo, monkeypatch):
    """A registry must not be able to decide what this tool says it verified."""
    import actaira.bundle as bundle_module

    monkeypatch.setattr(bundle_module, "MAX_DIGEST_BYTES", 8)
    repo.write("config.json", {"architectures": ["X"]})
    repo.write("model.safetensors", b"\x00" * 4096)

    row = next(
        item
        for item in resolve(repo, declared_digests={"model.safetensors": ("cd" * 32, "acme")}).to_dict()["members"]
        if item["path"] == "model.safetensors"
    )

    assert row["sha256"] is None
    assert row["declared_sha256"] == "cd" * 32
    assert row["declared_by"] == "acme"


def test_a_mixed_bundle_is_partial_rather_than_complete(repo, monkeypatch):
    """One weight file identified and one not is not "mostly identified"."""
    import actaira.bundle as bundle_module

    monkeypatch.setattr(bundle_module, "MAX_DIGEST_BYTES", 2048)
    repo.write("config.json", {"architectures": ["X"]})
    repo.write("model-00001.safetensors", b"\x00" * 64)
    repo.write("model-00002.safetensors", b"\x00" * 4096)

    identity = resolve(repo).content_identity()

    assert identity["state"] == "partial"
    assert identity["members_hashed"] == 1
    assert identity["members_unidentified"] == 1
    assert identity["unidentified"] == ["model-00002.safetensors"]


def test_the_structural_digest_still_moves_when_the_layout_does(repo):
    """The half of the old behaviour that was always correct, kept."""
    repo.write("config.json", {"architectures": ["X"]})
    before = resolve(repo).structural_digest

    repo.write("modeling_custom.py", "import os\n")

    assert resolve(repo).structural_digest != before


def test_provenance_is_carried_when_a_connector_produced_the_bytes(repo):
    repo.write("config.json", {"architectures": ["X"]})

    document = resolve(
        repo, source_uri="huggingface://acme/fraud", source_revision="7f91", connector="huggingface"
    ).to_dict()

    assert document["provenance"] == {
        "uri": "huggingface://acme/fraud",
        "revision": "7f91",
        "connector": "huggingface",
    }


def test_a_local_resolution_carries_no_provenance_block_at_all(repo):
    """An empty provenance block would read as "we looked and found nothing"."""
    repo.write("config.json", {"architectures": ["X"]})

    assert "provenance" not in resolve(repo).to_dict()
