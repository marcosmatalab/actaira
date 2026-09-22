#!/usr/bin/env python3
"""Capture the HTML report as the picture the landing page shows.

    python3 scripts/report_image.py                 write docs/img/02-report.png
    BROWSER=/path/to/chrome python3 scripts/report_image.py

One run of `scripts/demo_keyv.py --html`, screenshotted by a Chromium in
headless mode. The report is a self-contained file with no script and nothing
fetched from the network, so the capture needs no server and no profile.

WHY THIS IS A SCRIPT AND NOT A SENTENCE IN A README. The rule this repository
applies to numbers applies to pictures for the same reason: a published
artifact nobody can regenerate is one nobody can check, and a screenshot of a
release that has gone is worse than no screenshot. This is not in `make all`
and cannot be - a browser is not a Python dependency and a gate must not need
one - so what the gate does instead is refuse a `docs/img/` holding an image no
document displays.

WHAT IS NOT DETERMINISTIC, said rather than hidden: the pixels. Font
rasterisation and the browser version decide them, so two machines produce two
files that show the same report. The CONTENT is deterministic - the demo builds
the same two commits and `actaira diff` prints the same bytes twice, which
`release_check.py` checks - and that is the part a reader is being shown.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess  # noqa: S404 - a fixed argv, no shell
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "docs" / "img" / "02-report.png"

# Where a Chromium usually is, in the order they are tried. `BROWSER` in the
# environment wins over all of them, because a list of paths is a guess about
# somebody else's machine and their answer is better than the guess.
CANDIDATES = (
    "chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)


def browser() -> str:
    chosen = os.environ.get("BROWSER")
    if chosen:
        return chosen
    for candidate in CANDIDATES:
        found = shutil.which(candidate) or (candidate if Path(candidate).is_file() else None)
        if found:
            return found
    raise SystemExit(
        "no Chromium was found. Set BROWSER to one, for example\n"
        "  BROWSER='/usr/bin/chromium' python3 scripts/report_image.py"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--width", type=int, default=900)
    parser.add_argument("--height", type=int, default=880,
                        help="how much of the report the capture shows")
    arguments = parser.parse_args()

    workspace = Path(tempfile.mkdtemp(prefix="actaira-report-"))
    try:
        report = workspace / "report.html"
        demo = subprocess.run(  # noqa: S603 - a fixed argv, no shell
            [sys.executable, str(ROOT / "scripts" / "demo_keyv.py"), "--html", str(report)],
            cwd=ROOT, capture_output=True, text=True, timeout=600,
        )
        # 0, 1 and 3 are the codes the contract publishes, and the demo exists
        # because a rule fires on it, so 1 is what it returns.
        if demo.returncode not in (0, 1, 3) or not report.is_file():
            raise SystemExit(
                f"the demo exited {demo.returncode} and wrote no report:\n"
                f"{demo.stdout}\n{demo.stderr}"
            )
        arguments.out.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(  # noqa: S603 - a fixed argv, no shell
            [
                browser(), "--headless=new", "--disable-gpu", "--hide-scrollbars",
                "--force-device-scale-factor=2",
                f"--window-size={arguments.width},{arguments.height}",
                f"--screenshot={arguments.out}", report.as_uri(),
            ],
            capture_output=True, text=True, timeout=600, check=True,
        )
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    if not arguments.out.is_file() or arguments.out.stat().st_size == 0:
        raise SystemExit(f"{arguments.out} was not written")
    print(f"wrote {arguments.out.relative_to(ROOT)}, {arguments.out.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
