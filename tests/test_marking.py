"""Tests for machine-readable marking, and for the Article 50 controls on it.

The negative controls here matter more than the positive ones. A marking
detector that answers "marked" for everything passes every happy-path test ever
written, so most of this file is about the cases where the answer must be
`unmarked`, `marked_other` or `inconclusive`, and about the boundary the
control is required to state rather than cross.
"""
from __future__ import annotations

import io
import json
import os
import struct
from pathlib import Path

import pytest

from actaira.controls import engine
from actaira.controls.model import Outcome
from actaira.marking import (
    ALGORITHMIC_MEDIA,
    COMPOSITE_WITH_TRAINED,
    TRAINED_ALGORITHMIC_MEDIA,
    MarkingState,
    Mechanism,
    build_xmp,
    container_of,
    detect,
    mark_jpeg,
    mark_png,
    strip_marking,
)

PIL = pytest.importorskip("PIL.Image", reason="the marking tests need Pillow to make images")


def _png(tmp_path, name="a.png", size=(48, 32)):
    path = tmp_path / name
    PIL.new("RGB", size, (90, 140, 200)).save(path)
    return path


def _jpeg(tmp_path, name="a.jpg", size=(48, 32)):
    path = tmp_path / name
    PIL.new("RGB", size, (200, 90, 40)).save(path, quality=92)
    return path


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
def test_an_unmarked_png_is_unmarked_and_says_what_it_looked_for(tmp_path):
    report = detect(_png(tmp_path))
    assert report.state is MarkingState.UNMARKED
    # The searched list is the difference between "not there" and "not looked
    # for", and a reader needs it to know which one they got.
    assert Mechanism.XMP_IPTC in report.mechanisms_searched
    assert Mechanism.C2PA_JUMBF in report.mechanisms_searched


def test_marking_a_png_round_trips_and_leaves_a_valid_png(tmp_path):
    path = _png(tmp_path)
    path.write_bytes(mark_png(path.read_bytes()))
    report = detect(path)
    assert report.state is MarkingState.MARKED
    assert report.terms == (TRAINED_ALGORITHMIC_MEDIA,)
    # A marking that breaks the asset is worse than no marking.
    assert PIL.open(path).size == (48, 32)


def test_marking_a_jpeg_round_trips_and_leaves_a_valid_jpeg(tmp_path):
    path = _jpeg(tmp_path)
    path.write_bytes(mark_jpeg(path.read_bytes()))
    report = detect(path)
    assert report.state is MarkingState.MARKED
    assert PIL.open(path).size == (48, 32)


def test_marking_twice_does_not_leave_two_packets(tmp_path):
    """Two XMP packets in one file is a state no reader resolves the same way."""
    path = _png(tmp_path)
    once = mark_png(path.read_bytes())
    twice = mark_png(once)
    assert twice.count(b"Iptc4xmpExt:DigitalSourceType") == 2  # open and close tag
    path.write_bytes(twice)
    assert detect(path).state is MarkingState.MARKED


def test_a_composite_term_still_counts_as_synthetic(tmp_path):
    path = _png(tmp_path)
    path.write_bytes(mark_png(path.read_bytes(), term=COMPOSITE_WITH_TRAINED))
    assert detect(path).state is MarkingState.MARKED


def test_algorithmic_media_is_marked_other_not_marked(tmp_path):
    """`algorithmicMedia` means "made by software", not "made by a model".

    Treating it as a positive would let a chart renderer's marking pass for an
    Article 50(2) one, which is the kind of near-miss that makes a compliance
    tool worse than nothing.
    """
    path = _png(tmp_path)
    path.write_bytes(mark_png(path.read_bytes(), term=ALGORITHMIC_MEDIA))
    report = detect(path)
    assert report.state is MarkingState.MARKED_OTHER
    assert report.terms == (ALGORITHMIC_MEDIA,)


def test_stripping_removes_the_marking_and_keeps_the_image(tmp_path):
    for maker, marker in ((_png, mark_png), (_jpeg, mark_jpeg)):
        path = maker(tmp_path, name=f"s{maker.__name__}.png" if maker is _png else "s.jpg")
        path.write_bytes(marker(path.read_bytes()))
        assert detect(path).state is MarkingState.MARKED
        path.write_bytes(strip_marking(path.read_bytes()))
        assert detect(path).state is MarkingState.UNMARKED
        assert PIL.open(path).size == (48, 32)


def test_a_truncated_png_is_inconclusive_not_unmarked(tmp_path):
    """The doctrine of the whole repository, applied to a new surface."""
    path = _png(tmp_path)
    blob = path.read_bytes()
    path.write_bytes(blob[: len(blob) // 2])
    assert detect(path).state is MarkingState.INCONCLUSIVE


def test_an_audio_container_is_inconclusive_because_nothing_was_looked_for(tmp_path):
    path = tmp_path / "sound.wav"
    path.write_bytes(b"RIFF" + struct.pack("<I", 36) + b"WAVEfmt " + b"\x00" * 32)
    report = detect(path)
    assert report.state is MarkingState.INCONCLUSIVE
    assert report.mechanisms_searched == ()


def test_a_c2pa_box_is_present_unverified_never_verified(tmp_path):
    """Detecting a manifest is a true fact. Calling it valid would not be."""
    path = _png(tmp_path)
    blob = path.read_bytes()
    payload = b"\x00\x00\x00\x10jumbc2pa-placeholder"
    chunk = struct.pack(">I", len(payload)) + b"caBX" + payload
    import zlib

    chunk += struct.pack(">I", zlib.crc32(b"caBX" + payload) & 0xFFFFFFFF)
    marker = blob.index(b"IDAT") - 4
    path.write_bytes(blob[:marker] + chunk + blob[marker:])
    report = detect(path)
    assert Mechanism.C2PA_JUMBF in report.mechanisms_found
    assert report.state is MarkingState.MARKED_OTHER
    assert report.reason == "c2pa_manifest_present_unverified"


def test_container_is_decided_by_bytes_not_by_extension(tmp_path):
    path = tmp_path / "lies.jpg"
    PIL.new("RGB", (8, 8)).save(path, format="PNG")
    assert container_of(path.read_bytes()[:64]) == "png"
    assert detect(path).container == "png"


def test_build_xmp_refuses_a_term_outside_the_vocabulary():
    with pytest.raises(ValueError, match="digitalSourceType"):
        build_xmp("https://example.invalid/made-up")


def test_a_note_cannot_inject_markup():
    packet = build_xmp(note="</dc:description><evil>x</evil>")
    assert b"<evil>" not in packet


# ---------------------------------------------------------------------------
# The controls
# ---------------------------------------------------------------------------
def _target(tmp_path, declarations: dict | None = None, role="provider"):
    if declarations is not None:
        (tmp_path / "actaira.json").write_text(json.dumps(declarations), encoding="utf-8")
    return engine.load_target(tmp_path, role=role)


def test_50_2_is_satisfied_when_every_supplied_file_is_marked(tmp_path):
    from actaira.controls import registry

    for index in range(3):
        path = _png(tmp_path, name=f"out{index}.png")
        path.write_bytes(mark_png(path.read_bytes()))
    result = registry.get("ACT-C-50-2-MARK")(_target(tmp_path))
    assert result.outcome is Outcome.SATISFIED
    assert len(result.evidence["marked"]) == 3


def test_50_2_states_its_boundary_in_every_result(tmp_path):
    """Design note D-62. The obligation is never reported as met."""
    from actaira.controls import registry

    path = _png(tmp_path, name="out.png")
    path.write_bytes(mark_png(path.read_bytes()))
    result = registry.get("ACT-C-50-2-MARK")(_target(tmp_path))
    assert "supplied" in result.covers
    assert "not given" in result.does_not_cover
    assert "watermark" in result.does_not_cover


def test_50_2_fails_on_one_unmarked_file_among_marked_ones(tmp_path):
    from actaira.controls import registry

    marked = _png(tmp_path, name="ok.png")
    marked.write_bytes(mark_png(marked.read_bytes()))
    _png(tmp_path, name="forgotten.png")
    result = registry.get("ACT-C-50-2-MARK")(_target(tmp_path))
    assert result.outcome is Outcome.NOT_SATISFIED
    assert result.evidence["unmarked"] == ["forgotten.png"]
    assert any(f.rule_id == "ACT-MRK-001" for f in result.findings)


def test_50_2_is_inconclusive_when_some_files_could_not_be_read(tmp_path):
    """A partial read presented as a clean result is the failure this repo hunts."""
    from actaira.controls import registry

    marked = _png(tmp_path, name="ok.png")
    marked.write_bytes(mark_png(marked.read_bytes()))
    (tmp_path / "clip.mp3").write_bytes(b"ID3\x04\x00\x00\x00\x00\x00\x00rest")
    result = registry.get("ACT-C-50-2-MARK")(_target(tmp_path))
    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.abstained_on == ("clip.mp3",)


def test_50_2_is_inconclusive_with_no_output_rather_than_satisfied(tmp_path):
    from actaira.controls import registry

    result = registry.get("ACT-C-50-2-MARK")(_target(tmp_path))
    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.evidence["reason"] == "no_output_files_supplied"


def test_the_article_111_4_grace_makes_an_unmarked_file_not_applicable(tmp_path):
    """A true fact that leads to a false conclusion is the trap here.

    Before 2 December 2026 a system placed on the market before 2 August 2026
    is inside the Art. 111(4) transitional, so "unmarked" is not "in breach".
    """
    from actaira.controls import registry

    _png(tmp_path, name="out.png")
    target = _target(
        tmp_path,
        {"assessment_date": "2026-09-10", "placed_on_market": "2026-01-15"},
    )
    result = registry.get("ACT-C-50-2-MARK")(target)
    assert result.outcome is Outcome.NOT_APPLICABLE
    assert "111(4)" in result.evidence["grace_reason"]


def test_the_grace_does_not_apply_after_it_expires(tmp_path):
    from actaira.controls import registry

    _png(tmp_path, name="out.png")
    target = _target(
        tmp_path,
        {"assessment_date": "2027-01-04", "placed_on_market": "2026-01-15"},
    )
    assert registry.get("ACT-C-50-2-MARK")(target).outcome is Outcome.NOT_SATISFIED


def test_the_grace_does_not_apply_to_a_system_placed_later(tmp_path):
    from actaira.controls import registry

    _png(tmp_path, name="out.png")
    target = _target(
        tmp_path,
        {"assessment_date": "2026-09-10", "placed_on_market": "2026-08-30"},
    )
    assert registry.get("ACT-C-50-2-MARK")(target).outcome is Outcome.NOT_SATISFIED


def test_the_date_is_an_argument_and_never_the_system_clock(tmp_path):
    """Two runs with different declared dates differ; nothing else does."""
    from actaira.controls import registry

    _png(tmp_path, name="out.png")
    early = registry.get("ACT-C-50-2-MARK")(
        _target(tmp_path, {"assessment_date": "2026-09-10", "placed_on_market": "2026-01-01"})
    )
    late = registry.get("ACT-C-50-2-MARK")(
        _target(tmp_path, {"assessment_date": "2027-06-01", "placed_on_market": "2026-01-01"})
    )
    assert early.outcome is Outcome.NOT_APPLICABLE
    assert late.outcome is Outcome.NOT_SATISFIED


def test_50_1_finds_a_disclosure_in_either_language(tmp_path):
    from actaira.controls import registry

    (tmp_path / "greeting.txt").write_text(
        "Hola, soy un asistente de IA. ¿En qué puedo ayudarte?", encoding="utf-8"
    )
    result = registry.get("ACT-C-50-1-DISCLOSE")(_target(tmp_path))
    assert result.outcome is Outcome.SATISFIED
    assert "greeting.txt" in result.evidence["disclosing"]


def test_50_1_reports_a_silent_surface_and_publishes_what_it_searched(tmp_path):
    from actaira.controls import registry

    (tmp_path / "greeting.txt").write_text("Hi! How can I help you today?", encoding="utf-8")
    result = registry.get("ACT-C-50-1-DISCLOSE")(_target(tmp_path))
    assert result.outcome is Outcome.NOT_SATISFIED
    # The marker list is in the evidence so a reader can see the check's reach
    # rather than trusting a hidden heuristic. Design note D-64.
    assert len(result.evidence["markers_searched"]) > 10


def test_50_1_is_inconclusive_when_no_surface_was_supplied(tmp_path):
    from actaira.controls import registry

    result = registry.get("ACT-C-50-1-DISCLOSE")(_target(tmp_path))
    assert result.outcome is Outcome.INCONCLUSIVE


def test_declared_outputs_win_over_the_suffix_sweep(tmp_path):
    from actaira.controls import registry

    (tmp_path / "generated").mkdir()
    inside = _png(tmp_path / "generated", name="a.png")
    inside.write_bytes(mark_png(inside.read_bytes()))
    _png(tmp_path, name="unrelated_screenshot.png")  # not declared, must be ignored
    target = _target(tmp_path, {"outputs": ["generated"]})
    result = registry.get("ACT-C-50-2-MARK")(target)
    assert result.outcome is Outcome.SATISFIED
    assert result.inspected == ("a.png",)


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------
def test_the_survival_matrix_reports_counts_and_never_a_rate(tmp_path):
    from actaira.evals_support.robustness import survival_matrix

    paths = [_png(tmp_path, name="r0.png"), _jpeg(tmp_path, name="r1.jpg")]
    matrix = survival_matrix(paths)
    assert matrix["trials"] > 0
    assert matrix["survived"] <= matrix["trials"]
    serialised = json.dumps(matrix).lower()
    for forbidden in ("percent", "score", "rate", "grade"):
        assert forbidden not in serialised


def test_a_naive_reencode_destroys_a_metadata_marking(tmp_path):
    """The finding this module exists to publish, pinned so it cannot rot."""
    from actaira.evals_support.robustness import _apply, _detect_bytes

    path = _png(tmp_path)
    blob = mark_png(path.read_bytes())
    assert _detect_bytes(blob) is MarkingState.MARKED
    assert _detect_bytes(_apply(blob, "reencode_jpeg_q85")) is not MarkingState.MARKED


def test_a_metadata_aware_pipeline_keeps_it(tmp_path):
    """And the same operation, in a pipeline written to carry the marking."""
    from actaira.evals_support.robustness import _apply, _detect_bytes

    path = _png(tmp_path)
    blob = mark_png(path.read_bytes())
    kept = _apply(blob, "reencode_jpeg_q85_metadata_aware")
    assert _detect_bytes(kept) is MarkingState.MARKED


def test_detection_over_bytes_agrees_with_detection_over_a_path(tmp_path):
    """The private byte path used by the battery must not drift from the public one."""
    from actaira.evals_support.robustness import _detect_bytes

    path = _png(tmp_path)
    path.write_bytes(mark_png(path.read_bytes()))
    assert _detect_bytes(path.read_bytes()) is detect(path).state


def test_an_empty_file_list_is_zero_trials_not_a_division(tmp_path):
    from actaira.evals_support.robustness import survival_matrix

    matrix = survival_matrix([])
    assert matrix["trials"] == 0
    assert matrix["survived"] == 0


def test_jpeg_segment_walk_stops_at_the_scan(tmp_path):
    """A JPEG's entropy-coded data is not segments, and walking into it finds noise."""
    from actaira.marking import iter_jpeg_segments

    path = _jpeg(tmp_path)
    blob = mark_jpeg(path.read_bytes())
    markers = [marker for marker, _ in iter_jpeg_segments(blob)]
    assert 0xDA not in markers


def test_png_chunk_walk_tolerates_a_lying_length(tmp_path):
    """A hostile length field must end the walk, not allocate or raise."""
    from actaira.marking import iter_png_chunks

    path = _png(tmp_path)
    blob = bytearray(path.read_bytes())
    marker = blob.index(b"IDAT") - 4
    blob[marker : marker + 4] = struct.pack(">I", 0x7FFFFFFF)
    assert list(iter_png_chunks(bytes(blob))) is not None


def test_marking_refuses_a_container_it_cannot_write(tmp_path):
    from actaira.marking import mark_file

    path = tmp_path / "clip.wav"
    path.write_bytes(b"RIFF" + struct.pack("<I", 4) + b"WAVE")
    with pytest.raises(ValueError, match="png and jpeg"):
        mark_file(path)


def test_a_packet_too_large_for_one_jpeg_segment_is_refused(tmp_path):
    path = _jpeg(tmp_path)
    with pytest.raises(ValueError, match="too large"):
        mark_jpeg(path.read_bytes(), note="x" * 70000)


def test_xmp_written_into_png_is_readable_as_bytes_without_pillow(tmp_path):
    """The reader must not depend on the writer's library. Same doctrine as verify."""
    path = _png(tmp_path)
    blob = mark_png(path.read_bytes())
    assert b"Iptc4xmpExt:DigitalSourceType" in blob
    assert TRAINED_ALGORITHMIC_MEDIA.encode() in blob


def test_detect_handles_a_file_it_cannot_open(tmp_path):
    missing = tmp_path / "nope.png"
    report = detect(missing)
    assert report.state is MarkingState.INCONCLUSIVE
    assert "unreadable" in report.reason


def test_report_serialises_to_plain_json(tmp_path):
    path = _png(tmp_path)
    path.write_bytes(mark_png(path.read_bytes()))
    payload = detect(path).to_dict()
    assert json.loads(json.dumps(payload))["state"] == "marked"


def test_an_xmp_packet_in_a_pdf_is_found_but_flagged_as_a_scan(tmp_path):
    path = tmp_path / "doc.pdf"
    path.write_bytes(b"%PDF-1.7\n" + build_xmp() + b"\n%%EOF")
    report = detect(path)
    assert report.state is MarkingState.MARKED
    assert report.detail["scan_only"] is True


def test_marking_survives_a_round_trip_through_the_stripper_and_back(tmp_path):
    path = _png(tmp_path)
    once = mark_png(path.read_bytes())
    stripped = strip_marking(once)
    again = mark_png(stripped)
    path.write_bytes(again)
    assert detect(path).state is MarkingState.MARKED


def test_png_marking_keeps_every_other_chunk(tmp_path):
    from actaira.marking import iter_png_chunks

    path = _png(tmp_path)
    before = [t for t, _, _ in iter_png_chunks(path.read_bytes())]
    after = [t for t, _, _ in iter_png_chunks(mark_png(path.read_bytes()))]
    for chunk_type in before:
        assert chunk_type in after


def test_jpeg_marking_keeps_the_image_data(tmp_path):
    path = _jpeg(tmp_path)
    original = PIL.open(io.BytesIO(path.read_bytes())).tobytes()
    marked = PIL.open(io.BytesIO(mark_jpeg(path.read_bytes()))).tobytes()
    assert original == marked


# ---------------------------------------------------------------------------
# The published measurement, re-derived rather than trusted
# ---------------------------------------------------------------------------
def test_the_published_survival_figures_are_the_ones_the_harness_produces(tmp_path):
    """`evals/marking/results.json` is a committed file nothing re-ran.

    Both READMEs call the Art. 50(2) survival matrix "the measurement this
    project exists to publish", and its figures came from a JSON file that no
    test and no CI job regenerated: `make eval-marking` is not a CI job and
    nothing imported the harness. So the strongest claim on the page rested on
    a file whose only guarantee was that somebody had run the harness once.

    This runs it end to end, into a temporary directory, and compares what it
    produces with what is committed. The corpus is drawn from code by
    `evals/marking/build.py`, the transformations are deterministic, and the
    detector reads bytes, so the two must agree exactly.

    Needs Pillow, which is in the `dev` extra; the control that needs it at
    runtime abstains rather than failing, and so does this.
    """
    import subprocess
    import sys

    pytest.importorskip("PIL", reason="the transformation battery is Pillow")
    from conftest import REPO_ROOT

    root = Path(REPO_ROOT)
    committed = json.loads((root / "evals" / "marking" / "results.json").read_text(encoding="utf-8"))

    # The harness writes beside itself, so it runs against a copy of the two
    # files it needs rather than over the committed result.
    scratch = tmp_path / "marking"
    scratch.mkdir()
    for name in ("build.py", "harness.py"):
        (scratch / name).write_text(
            (root / "evals" / "marking" / name).read_text(encoding="utf-8"), encoding="utf-8"
        )

    environment = {**os.environ, "PYTHONPATH": str(root / "src")}
    built = subprocess.run(  # noqa: S603 - a fixed argv, no shell
        [sys.executable, str(scratch / "build.py")],
        capture_output=True, text=True, env=environment, timeout=600,
    )
    assert built.returncode == 0, built.stderr
    ran = subprocess.run(  # noqa: S603 - a fixed argv, no shell
        [sys.executable, str(scratch / "harness.py")],
        capture_output=True, text=True, env=environment, timeout=900,
    )
    assert ran.returncode == 0, ran.stderr

    produced = json.loads((scratch / "results.json").read_text(encoding="utf-8"))

    assert produced["negative_controls"]["all_passed"], (
        "the harness publishes only when its three negative controls pass, and they did not"
    )
    for key in ("trials", "survived", "naive_pipeline", "metadata_aware_pipeline", "corpus_files"):
        assert produced[key] == committed[key], (
            f"evals/marking/results.json is not what the harness produces today: "
            f"{key} is {committed[key]} on disk and {produced[key]} when re-run. "
            "Run `make eval-marking`."
        )
