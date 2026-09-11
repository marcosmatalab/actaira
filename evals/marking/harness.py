"""Measure how often an Article 50(2) marking survives an ordinary pipeline.

Run with `make eval-marking`. Writes `evals/marking/results.json` and prints the
survival matrix. No network, no downloaded fixtures: the corpus is generated
from code by `build.py` in this directory, so the images are identical on every
machine and the only thing that varies between runs is nothing.

Why this eval exists, in one paragraph, because the number it produces is the
most interesting thing in this repository and it should not be mistaken for a
benchmark of Actaira.

Article 50(2) requires providers of generative systems to mark their output in
a machine-readable format. The Regulation names no format, and the two families
available differ enormously in durability: a metadata marking (an XMP packet in
the file header, which is what the IPTC vocabulary and the C2PA soft binding
both use) is trivial to write and trivial to destroy, while a signal watermark
survives re-encoding and cannot be read without the detector key. Actaira reads
and writes the metadata kind, because that is the kind a third party can verify
offline with no secret. This eval measures what that choice costs, by running
the marking through eight transformations that happen to media in the ordinary
course of being published, plus two performed by a pipeline written to carry
the marking across.

The result is a count over trials, never a rate, and never a probability of
survival in the wild. See design note D-41. What it supports is one narrow and
defensible claim: **the durability of a metadata marking is a property of the
pipeline, not of the marking**, and any Article 50(2) implementation that does
not control its own pipeline is making a claim it cannot keep.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from actaira.evals_support.robustness import (  # noqa: E402
    METADATA_AWARE,
    TRANSFORMATIONS,
    survival_matrix,
)
from actaira.marking import MarkingState, detect  # noqa: E402

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "artifacts"
RESULTS = HERE / "results.json"


def _negative_controls(corpus: list[Path]) -> dict[str, object]:
    """Checks that would fail if the measurement were vacuous.

    Every number above is only worth reading if the machinery that produced it
    can produce a negative. Three of them:

    * an unmarked file must detect as UNMARKED, or "survival" is measuring
      nothing and every trial would pass;
    * a marked file must detect as MARKED before any transformation, or the
      denominator is full of files that were never marked to begin with;
    * a stripped file must detect as UNMARKED, or the detector answers yes to
      everything and the whole matrix is noise.

    The eval harness in `evals/harness.py` shipped for a while with a tamper
    check that passed vacuously on 8 of 50 packages, and it is in the defect
    ledger. This block is that lesson applied here before it can happen again.
    """
    from actaira.marking import mark_png, strip_marking

    sample = next(p for p in corpus if p.suffix == ".png")
    blob = sample.read_bytes()
    scratch = HERE / "_control.png"
    try:
        scratch.write_bytes(strip_marking(blob))
        unmarked_reads_unmarked = detect(scratch).state is MarkingState.UNMARKED
        scratch.write_bytes(mark_png(strip_marking(blob)))
        marked_reads_marked = detect(scratch).state is MarkingState.MARKED
        scratch.write_bytes(strip_marking(mark_png(strip_marking(blob))))
        stripped_reads_unmarked = detect(scratch).state is MarkingState.UNMARKED
    finally:
        scratch.unlink(missing_ok=True)
    return {
        "unmarked_reads_unmarked": unmarked_reads_unmarked,
        "marked_reads_marked": marked_reads_marked,
        "stripped_reads_unmarked": stripped_reads_unmarked,
        "all_passed": all(
            (unmarked_reads_unmarked, marked_reads_marked, stripped_reads_unmarked)
        ),
    }


def main() -> int:
    if not CORPUS.is_dir() or not any(CORPUS.iterdir()):
        print(f"corpus missing: run `python3 {HERE / 'build.py'} {CORPUS}` first", file=sys.stderr)
        return 2

    corpus = sorted(p for p in CORPUS.rglob("*") if p.suffix.lower() in (".png", ".jpg"))
    matrix = survival_matrix(corpus)
    controls = _negative_controls(corpus)

    naive = {k: v for k, v in matrix["per_transformation"].items() if k not in METADATA_AWARE}
    aware = {k: v for k, v in matrix["per_transformation"].items() if k in METADATA_AWARE}
    naive_survived = sum(v["survived"] for v in naive.values())
    naive_trials = sum(v["trials"] for v in naive.values())
    aware_survived = sum(v["survived"] for v in aware.values())
    aware_trials = sum(v["trials"] for v in aware.values())

    payload = {
        "corpus_files": matrix["files"],
        "transformations": list(TRANSFORMATIONS),
        "trials": matrix["trials"],
        "survived": matrix["survived"],
        "naive_pipeline": {"survived": naive_survived, "trials": naive_trials},
        "metadata_aware_pipeline": {"survived": aware_survived, "trials": aware_trials},
        "per_transformation": matrix["per_transformation"],
        "losses": matrix["losses"],
        "negative_controls": controls,
    }
    RESULTS.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")

    print(f"corpus: {matrix['files']} images, {len(TRANSFORMATIONS)} transformations")
    print(f"trials: {matrix['trials']}  survived: {matrix['survived']}\n")
    print("survival by transformation (counts over the closed battery, not a rate)")
    for name in TRANSFORMATIONS:
        row = matrix["per_transformation"][name]
        tag = "  metadata-aware pipeline" if name in METADATA_AWARE else ""
        print(f"  {name:<34} {row['survived']:>3} / {row['trials']:<3}{tag}")
    print(
        f"\nnaive pipeline          {naive_survived} / {naive_trials} survived"
        f"\nmetadata-aware pipeline {aware_survived} / {aware_trials} survived"
    )
    print(f"\nnegative controls: {'all passed' if controls['all_passed'] else 'FAILED'}")
    if not controls["all_passed"]:
        print("the measurement is vacuous; not publishing", file=sys.stderr)
        return 1
    print(f"written to {RESULTS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
