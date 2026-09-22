#!/usr/bin/env python3
"""Draw a command's own output as an SVG, from the command rather than a copy.

    python3 scripts/terminal_svg.py            write docs/img/01-demo.svg
    python3 scripts/terminal_svg.py --check    fail if the file on disk differs

WHY AN SVG AND NOT A RECORDING. The obvious artifact here is an asciinema cast
rendered to a GIF, and it was rejected for one reason: nothing in this
repository could then check it. A GIF is a binary somebody produced once on
some machine with some font, and a published artifact that no command can
regenerate is exactly what work rule 6 refuses about figures. This runs the
command, wraps its bytes, and writes text. `make demo-image` regenerates it and
the release gate refuses a tree where it has drifted, so the picture on the
landing page cannot go on showing a release that has gone.

WHAT IS THE COMMAND'S AND WHAT IS THIS SCRIPT'S, said plainly because an image
is the one place a reader cannot check. The characters are
`scripts/demo_keyv.py`'s, byte for byte, with one transformation: a line longer
than the column count is wrapped, which is what a terminal does to it anyway.
The colour is this script's. `actaira` prints no escape sequence at all - it
writes plain text so that a CI log stays readable - and the palette below is
applied from the markers the tool itself puts at the start of a line: `+` for a
capability that appeared, `!` for a rule that fired, `?` for something that
could not be resolved. No line is coloured by anything except a character the
command wrote.
"""
from __future__ import annotations

import argparse
import subprocess  # noqa: S404 - a fixed argv, no shell, one script in this repository
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# One picture per language, because the demo prints in the reader's. The `-es`
# suffix is what `release_check.readmes_match` strips to decide that two images
# fill the same slot, so the two READMEs illustrate the same thing in the same
# place without either of them being shown the other's language.
OUTPUTS = {
    "en": ROOT / "docs" / "img" / "01-demo.svg",
    "es": ROOT / "docs" / "img" / "01-demo-es.svg",
}

COLUMNS = 104

# The canvas is measured at a WIDER glyph than any face in the stack below,
# and that is the whole of the reason this constant is not 8.42.
#
# The picture is served to an `<img>` on somebody else's machine, so the face
# that draws it is the reader's `monospace` and not ours: DejaVu Sans Mono and
# Menlo advance 8.43px at 14px, Courier New and Liberation Mono 8.4, Consolas
# 7.7. A canvas measured at 8.42 fits all of them to the pixel and clips the
# first one that is wider, because an `<img>` clips at the viewBox - so the
# longest line of the report, which is the line with the rule text in it, would
# lose its right-hand end on a machine nobody here owns and nothing would say
# so. The margin is 7% and it costs a strip of background on the right.
#
# `release_check.py` reads this constant rather than carrying its own copy, and
# refuses a picture whose longest line does not fit a canvas measured with it.
WIDEST_GLYPH = 9.0
LINE_HEIGHT = 20
PADDING = 22
TITLE_BAR = 34

# One colour per marker the tool writes, plus the two it does not: the prompt
# line this script adds, and the default for everything else.
INK = {
    "background": "#11151c",
    "chrome": "#1b212b",
    "default": "#c9d1d9",
    "prompt": "#7d8590",
    "heading": "#e6edf3",
    "appeared": "#3fb950",
    "fired": "#f85149",
    "unresolved": "#d29922",
    "footnote": "#8b949e",
}

def command(language: str) -> str:
    """The command line the picture shows, which is the one a reader types."""
    return ("python3 scripts/demo_keyv.py" if language == "en"
            else f"python3 scripts/demo_keyv.py --lang {language}")


def classify(line: str) -> str:
    """Which ink a line takes, from a character the command wrote.

    Deliberately shallow. A classifier that read the words would be this
    script having an opinion about the output, and the second negative is that
    Actaira does not have opinions about what it reports.
    """
    stripped = line.strip()
    if stripped.startswith("+ "):
        return "appeared"
    if stripped.startswith("! "):
        return "fired"
    if stripped.startswith("? "):
        return "unresolved"
    if line and not line.startswith(" "):
        return "heading" if line.rstrip().endswith(tuple("0123456789")) or ":" not in line else "default"
    return "default"


def wrapped(text: str) -> list[tuple[str, str]]:
    """Every output line, wrapped at COLUMNS, with its ink.

    A continuation keeps the ink of the line it continues and is indented two
    columns past it, which is what a terminal's soft wrap looks like to a
    reader and what makes the block readable at all: the widest line the
    command writes is over two hundred characters.
    """
    rows: list[tuple[str, str]] = []
    for line in text.replace("\r\n", "\n").split("\n"):
        ink = classify(line)
        if not line.strip():
            rows.append(("", ink))
            continue
        indent = " " * (len(line) - len(line.lstrip()) + 2)
        pieces = textwrap.wrap(
            line, width=COLUMNS, subsequent_indent=indent,
            break_long_words=False, break_on_hyphens=False,
        ) or [line]
        rows += [(piece, ink) for piece in pieces]
    return rows


def escape(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def svg(rows: list[tuple[str, str]], spoken: str) -> str:
    width = round(COLUMNS * WIDEST_GLYPH + PADDING * 2)
    height = TITLE_BAR + PADDING + len(rows) * LINE_HEIGHT + PADDING
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="The output of {escape(spoken)}">',
        f'  <rect width="{width}" height="{height}" rx="8" fill="{INK["background"]}"/>',
        f'  <path d="M0 8a8 8 0 0 1 8-8h{width - 16}a8 8 0 0 1 8 8v{TITLE_BAR - 8}H0z" '
        f'fill="{INK["chrome"]}"/>',
        '  <circle cx="20" cy="17" r="5" fill="#ff5f57"/>',
        '  <circle cx="38" cy="17" r="5" fill="#febc2e"/>',
        '  <circle cx="56" cy="17" r="5" fill="#28c840"/>',
        '  <g font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, '
        'DejaVu Sans Mono, monospace" font-size="14">',
    ]
    baseline = TITLE_BAR + PADDING + 14
    for index, (text, ink) in enumerate(rows):
        if not text:
            continue
        y = baseline + index * LINE_HEIGHT
        lines.append(
            f'    <text x="{PADDING}" y="{y}" fill="{INK[ink]}" '
            f'xml:space="preserve">{escape(text)}</text>'
        )
    lines += ["  </g>", "</svg>", ""]
    return "\n".join(lines)


def render(language: str) -> str:
    spoken = command(language)
    result = subprocess.run(  # noqa: S603 - a fixed argv, no shell
        [sys.executable, str(ROOT / "scripts" / "demo_keyv.py"), "--lang", language],
        cwd=ROOT, capture_output=True, text=True, timeout=600, encoding="utf-8",
    )
    # 0 nothing fired, 1 a rule fired, 3 something could not be resolved. The
    # demo exists BECAUSE a rule fires on it, so 1 is the expected code and
    # refusing it would be refusing the only interesting output. 2 is the argv
    # being rejected, and anything else is a crash.
    if result.returncode not in (0, 1, 3):
        raise SystemExit(
            f"scripts/demo_keyv.py exited {result.returncode}, which is not a finding "
            f"but a break, so there is nothing to draw:\n{result.stdout}\n{result.stderr}"
        )
    if not result.stdout.strip():
        raise SystemExit("scripts/demo_keyv.py printed nothing; the image would be empty")
    rows = [("$ " + spoken, "prompt"), ("", "default"), *wrapped(result.stdout.rstrip())]
    return svg(rows, spoken)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="fail if the file on disk is not what the command produces now")
    arguments = parser.parse_args()

    for language, out in OUTPUTS.items():
        drawn = render(language)
        if arguments.check:
            if not out.is_file():
                print(f"{out.relative_to(ROOT)} is missing. Run `make demo-image`.",
                      file=sys.stderr)
                return 1
            if out.read_text(encoding="utf-8") != drawn:
                print(
                    f"{out.relative_to(ROOT)} is not what the command produces now. "
                    "Run `make demo-image`.", file=sys.stderr,
                )
                return 1
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(drawn, encoding="utf-8", newline="\n")
        print(f"wrote {out.relative_to(ROOT)}, {drawn.count(chr(10))} lines")
    if arguments.check:
        print(f"{len(OUTPUTS)} demo pictures, each the output its command produces")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
