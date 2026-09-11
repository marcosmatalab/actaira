"""How often does an Article 50(2) marking survive the pipeline content goes through?

Design note D-66, and the measurement this repository could not find published
anywhere.

Article 50(2) requires the marking to be machine-readable and the content to be
detectable as artificially generated. It says nothing about durability, and the
techniques the Commission's own guidance points to, metadata and watermarking,
have very different durability. A metadata marking is one XMP packet in a
header: it is trivial to write, trivial to read, and it does not survive most
of what happens to an image between generation and a viewer's screen.

That gap matters and it is measurable, so this module measures it. Each
transformation below is a thing that happens to real media in a real pipeline,
not an attack:

  reencode_jpeg_q85   a CMS or a chat app recompresses on upload
  reencode_jpeg_q60   the same, more aggressively
  resize_half         a thumbnail, or a responsive image pipeline
  crop_10pct          a crop to an aspect ratio
  rotate_90           an orientation fix
  convert_to_jpeg     a PNG served as JPEG
  convert_to_png      a JPEG re-saved as PNG
  strip_metadata      a privacy-motivated metadata strip, which many platforms
                      do on purpose and which is the honest worst case

The result is a survival matrix, not a rate dressed up as a probability. Nine
transformations over N files is N*9 trials with a count of survivals, and the
count is what gets published: `survived` and `trials`, per transformation, with
the losses named. See design note D-41 on why nothing here is divided.

Trade-off, stated because that is the rule of this repository. This module
needs Pillow, which is a *development* dependency and is not required to
install or run Actaira. The alternative was to implement JPEG recompression and
image resampling in the standard library, which would mean writing a codec in
order to measure a metadata property, and the codec would then need its own
tests and its own correctness argument. Every caller treats a missing Pillow as
INCONCLUSIVE and names the dependency, so the absence of the measurement is
never mistaken for a passing one.
"""
from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from ..marking import MarkingState, container_of, mark_jpeg, mark_png

TRANSFORMATIONS = (
    "reencode_jpeg_q85",
    "reencode_jpeg_q60",
    "resize_half",
    "crop_10pct",
    "rotate_90",
    "convert_to_jpeg",
    "convert_to_png",
    "strip_metadata",
    # The two below are the same operations performed by a pipeline that was
    # written to carry metadata across. They are in the battery on purpose: a
    # matrix containing only naive tools would be a strawman, and the finding
    # this module exists to publish is sharper with them in. See the module
    # docstring.
    "reencode_jpeg_q85_metadata_aware",
    "resize_half_metadata_aware",
)

# Transformations that model a pipeline which deliberately preserves metadata.
METADATA_AWARE = frozenset(
    {"reencode_jpeg_q85_metadata_aware", "resize_half_metadata_aware"}
)


def _pillow():
    from PIL import Image  # noqa: PLC0415

    return Image


def _apply(blob: bytes, transformation: str) -> bytes | None:
    """Apply one transformation, returning the new bytes or None if not applicable.

    Every path here goes through Pillow's decode and encode, which is the point:
    a real pipeline decodes the pixels and writes a new file, and whatever the
    encoder does not carry across is lost. Pillow is not asked to preserve
    metadata and is not prevented from preserving it; it behaves as an ordinary
    image tool, which is what an ordinary pipeline contains.
    """
    Image = _pillow()  # noqa: N806 - the Pillow class, named as Pillow names it
    try:
        image = Image.open(io.BytesIO(blob))
        image.load()
    except Exception:
        return None

    buffer = io.BytesIO()
    if transformation == "reencode_jpeg_q85":
        image.convert("RGB").save(buffer, format="JPEG", quality=85)
    elif transformation == "reencode_jpeg_q60":
        image.convert("RGB").save(buffer, format="JPEG", quality=60)
    elif transformation == "resize_half":
        width, height = image.size
        resized = image.resize((max(1, width // 2), max(1, height // 2)))
        resized.save(buffer, format=image.format or "PNG")
    elif transformation == "crop_10pct":
        width, height = image.size
        dx, dy = max(1, width // 10), max(1, height // 10)
        image.crop((dx, dy, width - dx, height - dy)).save(buffer, format=image.format or "PNG")
    elif transformation == "rotate_90":
        image.rotate(90, expand=True).save(buffer, format=image.format or "PNG")
    elif transformation == "convert_to_jpeg":
        image.convert("RGB").save(buffer, format="JPEG", quality=92)
    elif transformation == "convert_to_png":
        image.convert("RGB").save(buffer, format="PNG")
    elif transformation == "strip_metadata":
        # A copy of the pixels with none of the file's metadata. `Image.copy`
        # carries `info` across, which is exactly what a strip must not do, so
        # the pixels are moved into a fresh image through the frame buffer.
        stripped = Image.frombytes(image.mode, image.size, image.tobytes())
        stripped.save(buffer, format=image.format or "PNG")
    elif transformation in METADATA_AWARE:
        # A pipeline that was written to carry the marking across. It decodes,
        # transforms and re-encodes exactly as the naive variants do, and then
        # re-attaches the marking to the output. Modelled by re-marking rather
        # than by asking Pillow to pass XMP through, because Pillow's XMP
        # support differs by format and version and the measurement would then
        # be about Pillow rather than about the pipeline.
        if transformation == "reencode_jpeg_q85_metadata_aware":
            image.convert("RGB").save(buffer, format="JPEG", quality=85)
            return mark_jpeg(buffer.getvalue())
        width, height = image.size
        resized = image.resize((max(1, width // 2), max(1, height // 2)))
        target_format = (image.format or "PNG").upper()
        resized.save(buffer, format=target_format)
        raw = buffer.getvalue()
        return mark_png(raw) if target_format == "PNG" else mark_jpeg(raw)
    else:
        raise ValueError(f"unknown transformation {transformation!r}")
    return buffer.getvalue()


def _detect_bytes(blob: bytes) -> MarkingState:
    """Run marking detection over an in-memory blob.

    `marking.detect` takes a path because that is what every other caller has.
    Writing to a temporary file to reuse it would put filesystem behaviour in
    the middle of a measurement, so the container dispatch is repeated here
    against the private detectors, which is the only place in the repository
    that reaches past the public function and is why it is commented.
    """
    from .. import marking as marking_module  # noqa: PLC0415

    container = container_of(blob[:64])
    if container == "png":
        return marking_module._detect_png("blob", blob).state
    if container == "jpeg":
        return marking_module._detect_jpeg("blob", blob).state
    return marking_module._detect_generic("blob", container, blob).state


def survival_matrix(paths: list[Path] | tuple[Path, ...]) -> dict[str, Any]:
    """Mark each file, transform it every way, and count what still detects.

    Files that already carry a marking are used as they are; files that do not
    are marked first, because the question is about the marking's durability and
    not about whether this particular corpus happened to be marked.
    """
    per_transformation = {name: {"survived": 0, "trials": 0} for name in TRANSFORMATIONS}
    losses: list[tuple[str, str]] = []
    survived = 0
    trials = 0
    skipped: list[str] = []

    for path in paths:
        blob = Path(path).read_bytes()
        container = container_of(blob[:64])
        try:
            if _detect_bytes(blob) is not MarkingState.MARKED:
                blob = mark_png(blob) if container == "png" else mark_jpeg(blob)
        except ValueError:
            skipped.append(Path(path).name)
            continue
        if _detect_bytes(blob) is not MarkingState.MARKED:
            skipped.append(Path(path).name)
            continue

        for transformation in TRANSFORMATIONS:
            transformed = _apply(blob, transformation)
            if transformed is None:
                continue
            trials += 1
            per_transformation[transformation]["trials"] += 1
            if _detect_bytes(transformed) is MarkingState.MARKED:
                survived += 1
                per_transformation[transformation]["survived"] += 1
            else:
                losses.append((Path(path).name, transformation))

    return {
        "files": len(paths) - len(skipped),
        "skipped": skipped,
        "transformations": list(TRANSFORMATIONS),
        "trials": trials,
        "survived": survived,
        "per_transformation": per_transformation,
        "losses": losses,
    }
