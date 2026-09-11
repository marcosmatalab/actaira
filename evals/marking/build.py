"""Generate the marking corpus from code, so the eval reproduces byte for byte.

Same doctrine as `evals/corpus/build.py`: nothing is downloaded and nothing is
committed. The images are drawn deterministically from a fixed seed, so the
corpus a reader regenerates is the corpus the published numbers came from, and
the repository stays free of binary fixtures whose provenance nobody can check.

The corpus deliberately spans the shapes that change the answer: both
containers this repository can write (PNG and JPEG), a size small enough that
the eval runs in under a second and large enough that a half-resize is still a
real image, and one already-marked file so the harness exercises the path where
it uses an existing marking rather than adding its own.
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from actaira.marking import mark_png  # noqa: E402

SEED = 20260910
SIZE = (160, 120)


def _draw(seed: int):
    from PIL import Image  # noqa: PLC0415

    rng = random.Random(seed)
    image = Image.new("RGB", SIZE)
    pixels = image.load()
    # A smooth gradient plus deterministic noise. Smooth so that JPEG at
    # quality 60 does not turn it into mush (which would make the transformed
    # file undecodable and quietly shrink the denominator), noisy so that no
    # transformation is a no-op on the pixel data.
    base = (rng.randrange(40, 200), rng.randrange(40, 200), rng.randrange(40, 200))
    for y in range(SIZE[1]):
        for x in range(SIZE[0]):
            jitter = rng.randrange(-12, 13)
            pixels[x, y] = (
                max(0, min(255, base[0] + x // 3 + jitter)),
                max(0, min(255, base[1] + y // 3 + jitter)),
                max(0, min(255, base[2] + (x + y) // 6 + jitter)),
            )
    return image


def build(destination: Path) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for index in range(4):
        image = _draw(SEED + index)
        if index % 2 == 0:
            path = destination / f"generated_{index}.png"
            image.save(path, format="PNG", optimize=False)
            if index == 2:
                # One file arrives already marked, so the harness exercises the
                # branch where it reuses a marking instead of writing one.
                path.write_bytes(mark_png(path.read_bytes(), note="pre-marked corpus file"))
        else:
            path = destination / f"generated_{index}.jpg"
            image.save(path, format="JPEG", quality=92)
        written.append(path)
    return written


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / "artifacts"
    paths = build(target)
    print(f"{len(paths)} artifact(s) written to {target}")
