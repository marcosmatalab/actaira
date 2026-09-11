"""Generate every diagram in the READMEs, from code and from measurements.

Run with `make diagrams`. Writes `docs/img/*.svg`.

Design note D-70, on why these are generated rather than drawn.

A README picture is a claim like any other, and a drawn one rots in the way
this repository has already been bitten by twice: the numbers move, the prose is
updated, and the picture keeps showing last month's answer to a reader who has
no way to tell. So the survival chart reads `evals/marking/results.json` and
cannot show a figure the harness did not measure, and the coverage ladder reads
the obligation catalogue and cannot show a tier count the code does not agree
with. `make diagrams` after `make eval-marking` and the pictures are current by
construction; run it before, and it says the measurement is missing rather than
inventing one.

Design note D-71, on the palette, because "it looked nice" is not a reason.

GitHub renders a README on a white surface or on `#0d1117`, the reader chooses
which, and an SVG referenced from Markdown cannot reliably carry a media query.
So every colour here is picked to clear a 3:1 contrast ratio against *both*
surfaces, which the table below records, and no fill is ever the only carrier of
meaning: a survived trial is a filled disc and a lost one is a hollow ring, so
the chart still reads in monochrome, in print, and to a reader with any form of
colour vision deficiency.

    token      hex        on #ffffff   on #0d1117
    accent     #8B5CF6       4.23         4.47
    accent2    #A78BFA       2.72         6.95   fills and strokes only, never text
    muted      #7D8590       3.73         5.07
    ink        #6E7781       4.55         4.16
    mark0      #9D2FB0       6.06         3.12   the mark's ramp, dark end
    mark1      #B968D6       3.49         5.42   the mark's ramp, light end

The last two are the brand mark, and they are not the brand's own values. The
logo's ramp runs #2A022E to #85088F, and #2A022E is 1.03 against GitHub's dark
surface: the bottom half of the logo would be a hole for every reader who
chose dark. So the banner carries the same hue lifted until both ends clear
3:1 on both surfaces, which is the rule the rest of this palette already
follows. The local interface, which knows what it is drawn on, keeps the
unmodified brand values; `tests/test_web_frontend.py` compares its copy of the
geometry with `MARK_PATH` below, so the two cannot drift apart.

One accent, not three. The 2.1 palette had a teal, an indigo and an amber,
which is a rainbow on a banner and reads as decoration rather than as
meaning. Violet is the product's colour; everything else is a neutral, and
where two things must be told apart the difference is carried by shape or by
position, which is the rule the survival chart already followed.

Counts, never rates. The chart shows four discs because the corpus has four
images, and the label says `0 / 4`. A percentage over a closed battery of ten
transformations would be a probability of survival in the wild, which is not
what was measured. See design note D-41.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

OUT = ROOT / "docs" / "img"
MARKING_RESULTS = ROOT / "evals" / "marking" / "results.json"

ACCENT = "#8B5CF6"
# A lighter tint of the same hue, for a fill or a stroke that must sit beside
# the accent without competing with it. Never used for text: 2.72 on white.
ACCENT_SOFT = "#A78BFA"
MUTED = "#7D8590"
INK = "#6E7781"
# The Actaira mark: the outline traced from the brand original (34 cubics
# fitted to its alpha contour) and the head, which is a true circle. The
# geometry is the brand's; only the ramp is lifted, for the reason above.
MARK_PATH = (
    "M59.88 6.57c-0.21 0.6 -0.09 1.44 -0.17 2.08c-0.18 1.34 -0.38 2.69 -0.73 4c-0.28 1.06 -0.59 2.12 -0.96 3.15c-1.87 5.19 -5.53 11.08 -11.43 12.05c-1.17 0.19 -2.43 0.23 -3.61 0.1c-5.05 -0.55 -9.04 -3.79 -13.53 -5.83c-4.09 -1.86 -8.51 -3.26 -13.06 -3c-1.96 0.11 -3.88 0.48 -5.77 1c-2.65 0.74 -5.32 1.99 -7.58 3.56c-0.53 0.37 -1.04 0.73 -1.55 1.12c-0.06 0.05 -0.57 0.38 -0.56 0.43c0.02 0.11 0.64 0.04 0.73 0.04c0.76 -0.02 1.51 -0.01 2.27 0.01c1.86 0.03 3.76 0.35 5.55 0.85c5.65 1.58 11.19 5.76 12.22 11.88c0.34 2.04 0.29 4.16 -0.22 6.17c-1.42 5.66 -6.39 10.31 -11.69 12.41c-1.93 0.76 -4 1.17 -6.06 1.35c-0.75 0.06 -1.52 0.02 -2.27 0.02c-0.09 0 -0.7 -0.07 -0.74 0.04c-0.01 0.05 0.29 0.23 0.32 0.26c0.26 0.22 0.54 0.42 0.81 0.62c1.3 0.93 2.72 1.8 4.2 2.41c4.95 2.02 10.33 3.2 15.7 2.66c1.19 -0.12 2.42 -0.12 3.6 -0.35c1.2 -0.25 2.42 -0.42 3.61 -0.72c2.44 -0.59 4.88 -1.44 7.16 -2.51c6.03 -2.81 11.76 -6.85 16.12 -11.91c2.15 -2.49 3.94 -5.14 5.69 -7.92c1.51 -2.4 2.7 -5.09 3.57 -7.78c0.48 -1.48 0.97 -3.01 1.21 -4.55c0.27 -1.76 0.45 -3.47 0.54 -5.26c0.21 -4.3 -0.49 -8.53 -1.84 -12.59c-0.41 -1.23 -0.79 -2.74 -1.52 -3.82Z"
)
MARK_HEAD = (41.89, 10.38, 10.39)
MARK_RAMP = ("#9D2FB0", "#B968D6")
FONT = (
    "ui-sans-serif,-apple-system,BlinkMacSystemFont,'Segoe UI',"
    "Helvetica,Arial,sans-serif"
)
MONO = "ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,monospace"


FIGURES_PATH = ROOT / "figures.json"


def _figures() -> dict:
    if not FIGURES_PATH.is_file():
        raise SystemExit("figures.json is missing: run `make figures` first, the banner is measured")
    return json.loads(FIGURES_PATH.read_text(encoding="utf-8"))


def _controls():
    from actaira.controls import registry

    return registry.all_controls()


def _svg(width: int, height: int, body: str, title: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" role="img" aria-label="{title}">\n'
        f"<title>{title}</title>\n{body}\n</svg>\n"
    )


def _text(x, y, content, size=13, fill=INK, weight=400, anchor="start", mono=False):
    family = MONO if mono else FONT
    return (
        f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
        f'fill="{fill}" font-weight="{weight}" text-anchor="{anchor}">{content}</text>'
    )


def _mark(x: float, y: float, size: float, ident: str) -> str:
    """The Actaira mark, scaled from its 64-unit box and placed at (x, y).

    Each caller passes its own gradient id: two marks in one document sharing
    one id is one mark and one silently unpainted shape.
    """
    scale = size / 64.0
    dark, light = MARK_RAMP
    head_x, head_y, head_r = MARK_HEAD
    return (
        f'<defs><linearGradient id="{ident}" gradientUnits="objectBoundingBox" '
        f'x1="0" y1="1" x2="1" y2="0">'
        f'<stop offset="0" stop-color="{dark}"/>'
        f'<stop offset="1" stop-color="{light}"/>'
        f"</linearGradient></defs>"
        f'<g transform="translate({x} {y}) scale({scale:.6f})" fill="url(#{ident})">'
        f'<path d="{MARK_PATH}"/>'
        f'<circle cx="{head_x}" cy="{head_y}" r="{head_r}"/>'
        f"</g>"
    )


# ---------------------------------------------------------------------------
# 1. The banner
# ---------------------------------------------------------------------------
def banner() -> str:
    width, height = 1000, 210
    parts = [
        f'<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="14" '
        f'fill="none" stroke="{MUTED}" stroke-opacity="0.35"/>',
        # The mark itself, traced from the brand original. It is drawn here
        # rather than referenced as a file so the banner stays one generated
        # SVG with nothing to fetch, like every other figure in this directory.
        _mark(44, 58, 94, "banner-ramp"),
        _text(168, 100, "Actaira", size=46, fill=INK, weight=700),
        _text(
            170,
            130,
            "Continuous Verifiable AI Assurance, local-first",
            size=16,
            fill=MUTED,
        ),
        _text(
            170,
            154,
            "Nothing is ever loaded, deserialised or executed. Nothing is ever scored.",
            size=14,
            fill=MUTED,
        ),
    ]
    # The chips are measurements, not decoration, so they are read from
    # figures.json rather than typed. A banner is the most-read and
    # least-checked surface in a repository: a number typed here outlives
    # every correction made elsewhere. See design note D-70.
    figures = _figures()
    tests = figures.get("tests", {}).get("collected")
    rules = figures.get("catalog", {}).get("rules")
    # The runtime dependency set, read from the file that declares it. It is
    # one entry and has been since the first release, which is exactly why a
    # banner is the wrong place to type it.
    declared = re.search(
        r"^dependencies\s*=\s*\[(.*?)\]",
        (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
        re.S | re.M,
    )
    dependencies = len(re.findall(r'"[^"]+"', declared.group(1))) if declared else 0
    chips = [
        (f"{rules} rules" if rules else "measured", ACCENT),
        (f"{len(_controls())} controls", ACCENT),
        (f"{tests:,} tests" if tests else "measured", ACCENT),
        (f"{dependencies} runtime dependency" if dependencies == 1
         else f"{dependencies} runtime dependencies", MUTED),
    ]
    x = 170
    for label, colour in chips:
        chip_width = 12 + len(label) * 7
        parts.append(
            f'<rect x="{x}" y="166" width="{chip_width}" height="24" rx="12" '
            f'fill="none" stroke="{colour}" stroke-opacity="0.5"/>'
        )
        parts.append(_text(x + 11, 182, label, size=12, fill=colour))
        x += chip_width + 10
    return _svg(width, height, "\n".join(parts), "Actaira")


# ---------------------------------------------------------------------------
# 2. The pipeline
# ---------------------------------------------------------------------------
def pipeline() -> str:
    """The 2.2 loop, with every count read from the code rather than typed.

    The 2.1 version of this diagram was a straight line - artifact, inspect,
    controls, attest, verify - and that was the shape of the tool then. 2.2
    closed the line into a loop: the receipt is not the end, because the next
    observation of the same source is what decides whether the receipt still
    describes anything. Drawing it as a line would be drawing the previous
    product.
    """
    from actaira.controls import registry as control_registry
    from actaira.coverage import CoverageState
    from actaira.state.evidence import EvidenceState
    from actaira.state.watch import ObservationState

    controls = len(control_registry.all_controls())
    stages = [
        ("scan", "bytes parsed,\nnever loaded", ACCENT),
        ("evidence", f"{len(list(EvidenceState))} states,\none of them counts", ACCENT),
        ("watch", f"{len(list(ObservationState))} answers,\nnot one", ACCENT),
        ("graph", "declared edges,\nexact routes", ACCENT),
        ("policy", f"{controls} controls,\nALLOW/DENY/REVIEW", ACCENT),
        ("receipt", "signed, offline-\nverifiable", MUTED),
    ]
    width, height = 1000, 286
    box_width, box_height, gap = 140, 84, 32
    start_x = (width - (len(stages) * box_width + (len(stages) - 1) * gap)) / 2
    parts = [
        _text(width / 2, 34, "what happens to one source, and what happens next time",
              size=15, fill=INK, weight=600, anchor="middle")
    ]
    for index, (name, detail, colour) in enumerate(stages):
        x = start_x + index * (box_width + gap)
        y = 62
        parts.append(
            f'<rect x="{x}" y="{y}" width="{box_width}" height="{box_height}" rx="10" '
            f'fill="none" stroke="{colour}" stroke-opacity="0.55" stroke-width="1.5"/>'
        )
        parts.append(_text(x + box_width / 2, y + 31, name, size=15, fill=colour,
                           weight=600, anchor="middle", mono=True))
        for line_index, line in enumerate(detail.split("\n")):
            parts.append(
                _text(x + box_width / 2, y + 52 + line_index * 16, line,
                      size=11, fill=MUTED, anchor="middle")
            )
        if index < len(stages) - 1:
            arrow_x = x + box_width + 6
            parts.append(
                f'<path d="M{arrow_x} {y + box_height / 2} H{arrow_x + gap - 14} '
                f'm-6 -5 l6 5 l-6 5" fill="none" stroke="{MUTED}" '
                f'stroke-opacity="0.6" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>'
            )

    # The return edge. Drawn under the row rather than over it, so it reads as
    # "later" rather than as a second forward path.
    left = start_x + box_width / 2
    right = start_x + (len(stages) - 1) * (box_width + gap) + box_width / 2
    parts.append(
        f'<path d="M{right} 152 V184 H{left} V158 m-5 6 l5 -6 l5 6" fill="none" '
        f'stroke="{ACCENT}" stroke-opacity="0.5" stroke-width="1.5" stroke-dasharray="5 4" '
        f'stroke-linecap="round" stroke-linejoin="round"/>'
    )
    parts.append(
        _text(width / 2, 202, "observe again: what changed, what that invalidated, what it reaches",
              size=12, fill=ACCENT, anchor="middle")
    )
    parts.append(
        _text(width / 2, 236, "every stage answers only for what it read, and says so in its own output",
              size=12.5, fill=MUTED, anchor="middle")
    )
    parts.append(
        _text(
            width / 2,
            258,
            f"a {len(list(CoverageState))}th answer, INCONCLUSIVE, exists at every stage and is "
            "never folded into a pass",
            size=12.5,
            fill=ACCENT,
            anchor="middle",
        )
    )
    return _svg(width, height, "\n".join(parts), "The Actaira assurance loop")


# ---------------------------------------------------------------------------
# 3. The coverage ladder, read from the catalogue
# ---------------------------------------------------------------------------
def coverage_ladder() -> str:
    from actaira.governance.catalog import ALL_OBLIGATIONS, Checkability

    tiers = [
        (Checkability.MACHINE_CHECKABLE, "machine-checkable", "bytes decide, no model", ACCENT),
        (Checkability.GENERATABLE, "generatable", "drafted, never satisfied", ACCENT),
        (Checkability.EVIDENCE_JUDGED, "evidence-judged", "judged, cited, abstains", ACCENT),
        (Checkability.ORGANIZATIONAL, "organizational", "carries a written reason", MUTED),
    ]
    counted = {tier: [o for o in ALL_OBLIGATIONS if o.checkability is tier] for tier, *_ in tiers}
    width, height = 1000, 300
    parts = [
        _text(56, 40, "21 EU AI Act obligations, by what could ever decide them", size=15, fill=INK, weight=600),
        _text(56, 62, "zero are marked fully supported, and that is a result rather than an oversight", size=12.5, fill=MUTED),
    ]
    row_height, top = 52, 86
    unit = 26
    for index, (tier, label, rule, colour) in enumerate(tiers):
        y = top + index * row_height
        obligations = counted[tier]
        parts.append(_text(56, y + 17, label, size=13.5, fill=colour, weight=600, mono=True))
        parts.append(_text(56, y + 34, rule, size=11.5, fill=MUTED))
        for slot in range(len(obligations)):
            cx = 300 + slot * unit
            parts.append(
                f'<rect x="{cx}" y="{y + 4}" width="18" height="18" rx="5" '
                f'fill="{colour}" fill-opacity="0.85"/>'
            )
        parts.append(
            _text(300 + len(obligations) * unit + 8, y + 18, str(len(obligations)), size=13, fill=colour, weight=700, mono=True)
        )
        # The article numbers, so the picture is checkable against the catalogue.
        articles = ", ".join(o.article.replace("Art. ", "") for o in obligations)
        parts.append(_text(300, y + 38, articles, size=10.5, fill=MUTED, mono=True))
    return _svg(width, height, "\n".join(parts), "The Actaira coverage ladder")


# ---------------------------------------------------------------------------
# 4. The marking survival matrix, read from the measurement
# ---------------------------------------------------------------------------
def marking_survival() -> str:
    if not MARKING_RESULTS.is_file():
        raise SystemExit(
            f"{MARKING_RESULTS.relative_to(ROOT)} is missing: run `make eval-marking` first. "
            "This diagram is not drawn from memory."
        )
    data = json.loads(MARKING_RESULTS.read_text(encoding="utf-8"))
    rows = data["per_transformation"]
    aware = {"reencode_jpeg_q85_metadata_aware", "resize_half_metadata_aware"}
    labels = {
        "reencode_jpeg_q85": "re-encode JPEG q85",
        "reencode_jpeg_q60": "re-encode JPEG q60",
        "resize_half": "resize to half",
        "crop_10pct": "crop 10%",
        "rotate_90": "rotate 90",
        "convert_to_jpeg": "convert to JPEG",
        "convert_to_png": "convert to PNG",
        "strip_metadata": "strip metadata",
        "reencode_jpeg_q85_metadata_aware": "re-encode JPEG q85",
        "resize_half_metadata_aware": "resize to half",
    }
    order = [name for name in data["transformations"] if name not in aware]
    order += [name for name in data["transformations"] if name in aware]

    width = 1000
    row_height, top = 30, 118
    height = top + len(order) * row_height + 74
    parts = [
        _text(56, 42, "Does an Article 50(2) marking survive the pipeline?", size=16, fill=INK, weight=700),
        _text(
            56,
            64,
            f"one disc per corpus image, filled if the marking still detected. {data['survived']} of {data['trials']} trials survived.",
            size=12.5,
            fill=MUTED,
        ),
        _text(56, 96, "an ordinary publishing pipeline", size=12, fill=MUTED, weight=600),
    ]
    separator_drawn = False
    for index, name in enumerate(order):
        y = top + index * row_height
        row = rows[name]
        if name in aware and not separator_drawn:
            # The band break needs real air: the first attempt drew the rule
            # twelve pixels above the row and it landed on the label of the row
            # above it. Rendered and looked at, which is the only way that kind
            # of collision is ever found.
            separator_drawn = True
            parts.append(
                f'<line x1="56" y1="{y + 6}" x2="{width - 56}" y2="{y + 6}" '
                f'stroke="{MUTED}" stroke-opacity="0.3" stroke-dasharray="3 3"/>'
            )
            parts.append(
                _text(56, y + 34, "a pipeline written to carry the marking", size=12, fill=ACCENT, weight=600)
            )
            y += 48
            top += 48
            height += 48
        colour = ACCENT if row["survived"] else MUTED
        parts.append(_text(56, y + 15, labels.get(name, name), size=12.5, fill=MUTED))
        for slot in range(row["trials"]):
            cx = 320 + slot * 30
            if slot < row["survived"]:
                parts.append(f'<circle cx="{cx}" cy="{y + 10}" r="8" fill="{ACCENT}"/>')
            else:
                parts.append(
                    f'<circle cx="{cx}" cy="{y + 10}" r="7.5" fill="none" '
                    f'stroke="{MUTED}" stroke-opacity="0.55" stroke-width="1.5"/>'
                )
        parts.append(
            _text(
                320 + row["trials"] * 30 + 6,
                y + 15,
                f'{row["survived"]} / {row["trials"]}',
                size=12.5,
                fill=colour,
                weight=700,
                mono=True,
            )
        )
    naive = data["naive_pipeline"]
    smart = data["metadata_aware_pipeline"]
    parts.append(
        _text(
            56,
            height - 34,
            f'naive pipeline {naive["survived"]} of {naive["trials"]}   ·   '
            f'metadata-aware {smart["survived"]} of {smart["trials"]}   ·   '
            "durability is a property of the pipeline, not of the marking",
            size=12.5,
            fill=INK,
        )
    )
    return _svg(width, int(height), "\n".join(parts), "Article 50(2) marking survival")


# ---------------------------------------------------------------------------
# 5. The architecture, with the boundary that is the whole design
# ---------------------------------------------------------------------------
def architecture() -> str:
    """How one source becomes a receipt, and where the network is allowed to be.

    Design note D-70 applies here as much as to the survival chart: every
    count below is read from the registry, the enum or the catalogue that
    defines it, so a diagram cannot outlive the code it describes. The one
    thing in the picture that is not a number is the dashed line, and it is
    the reason the picture exists. A component that reaches the network never
    decides a verdict and a component that decides a verdict never reaches the
    network, which is what makes "a compromised registry can hand Actaira the
    wrong file and cannot make it say the wrong thing about the file it got"
    a structural property rather than a promise.
    """
    from actaira.connectors import registry as connector_registry
    from actaira.controls import registry as control_registry
    from actaira.coverage import CoverageState, Surface
    from actaira.governance.catalog import ALL_OBLIGATIONS
    from actaira.policy.engine import PREDICATES
    from actaira.state.evidence import EvidenceState
    from actaira.state.graph import RELATIONS
    from actaira.state.watch import ObservationState
    from actaira.subject import SubjectKind

    figures = _figures()
    rules = figures.get("catalog", {}).get("rules", 0)

    width, height = 1000, 478
    parts: list[str] = []

    def box(x, y, w, h, colour, opacity="0.06", dash=None):
        stroke = f' stroke-dasharray="{dash}"' if dash else ""
        return (
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" '
            f'fill="{colour}" fill-opacity="{opacity}" stroke="{colour}" '
            f'stroke-opacity="0.55"{stroke}/>'
        )

    def arrow(x1, y, x2, colour=MUTED):
        return (
            f'<path d="M{x1} {y} H{x2 - 7}" stroke="{colour}" stroke-width="1.6" '
            f'fill="none" stroke-opacity="0.75"/>'
            f'<path d="m{x2 - 8} {y - 4} 6 4 -6 4Z" fill="{colour}" fill-opacity="0.75"/>'
        )

    parts.append(_text(56, 38, "one source, from bytes to a receipt somebody else can check",
                       size=15, fill=INK, weight=600))

    # ---- the lane that is allowed to reach the network ----------------------
    parts.append(box(56, 58, 888, 62, MUTED, "0.05", dash="5 4"))
    parts.append(_text(74, 82, "DISCOVERY", size=10.5, fill=MUTED, weight=700, mono=True))
    parts.append(_text(74, 102,
                       f"{len(connector_registry.all_connectors())} connectors: a registry, a hub, a "
                       "directory, a bucket. They enumerate and stage.",
                       size=12.5, fill=MUTED))
    parts.append(_text(928, 102, "may reach the network", size=11, fill=MUTED, anchor="end"))

    # ---- the boundary -------------------------------------------------------
    parts.append(f'<path d="M56 140 H944" stroke="{ACCENT}" stroke-width="1.4" '
                 f'stroke-dasharray="7 5" stroke-opacity="0.8"/>')
    parts.append(_text(56, 134,
                       "nothing above this line decides anything, and nothing below it opens a socket",
                       size=11.5, fill=ACCENT, weight=600))

    # ---- the four stages ----------------------------------------------------
    #
    # The lines are pre-wrapped rather than measured, because an SVG has no
    # layout engine and a line that overruns its box does not wrap: it prints
    # straight across the next one, which is what the first version of this
    # picture did. `line_budget` is the number of characters that fits in a
    # box at this size, and the assertion below refuses to emit a diagram
    # where an edit has outgrown it.
    stages = [
        ("READ", "bytes, never loaded", [
            "detected by content,",
            "never by file suffix",
            f"{rules} rules over an exact",
            "abstract interpretation",
            f"{len(list(Surface))} surfaces, {len(list(CoverageState))} states",
        ]),
        ("REMEMBER", "SQLite you own", [
            f"{len(list(ObservationState))} observation states: a",
            "first sighting is not",
            "an unchanged one",
            f"{len(list(EvidenceState))} evidence states, tied",
            f"to a digest; {len(RELATIONS)} relations",
        ]),
        ("DECIDE", "and say why", [
            f"{len(PREDICATES)} predicates over",
            f"{len(list(SubjectKind))} kinds of subject",
            "ALLOW / DENY / REVIEW",
            f"{len(control_registry.all_controls())} controls, "
            f"{len(ALL_OBLIGATIONS)} obligations",
            "no information: REVIEW",
        ]),
        ("PROVE", "offline, to a stranger", [
            "RFC 6962 Merkle, with",
            "inclusion and consistency",
            "Ed25519, RFC 3161, DSSE",
            "integrity and identity",
            "answered separately",
        ]),
    ]
    box_w, gap, top, box_h = 213, 12, 168, 156
    line_budget = 27
    overlong = [line for _, _, body in stages for line in body if len(line) > line_budget]
    if overlong:
        raise SystemExit(
            "architecture(): these lines are wider than the box they go in, and SVG "
            f"will print them straight over the next one: {overlong}"
        )
    start = 56
    for index, (name, note, lines) in enumerate(stages):
        x = start + index * (box_w + gap)
        parts.append(box(x, top, box_w, box_h, ACCENT))
        parts.append(_text(x + 16, top + 26, name, size=12.5, fill=ACCENT, weight=700, mono=True))
        parts.append(_text(x + 16, top + 44, note, size=11, fill=MUTED))
        for row, line in enumerate(lines):
            parts.append(_text(x + 16, top + 70 + row * 17, line, size=11, fill=INK))
        if index < len(stages) - 1:
            parts.append(arrow(x + box_w + 2, top + box_h / 2, x + box_w + gap))

    # ---- what comes out -----------------------------------------------------
    parts.append(box(56, 352, 888, 96, MUTED, "0.04"))
    parts.append(_text(74, 378, "WHAT COMES OUT", size=10.5, fill=MUTED, weight=700, mono=True))
    outputs = [
        ("exit 0", "nothing objected"),
        ("exit 1", "a finding, or DENY"),
        ("exit 3", "inconclusive, or REVIEW"),
        ("SARIF / JUnit", "for the pipeline"),
        ("receipt", "verified without this tool"),
    ]
    x = 74
    for label, note in outputs:
        parts.append(_text(x, 406, label, size=12, fill=ACCENT, weight=650, mono=True))
        parts.append(_text(x, 424, note, size=10.5, fill=MUTED))
        x += 178
    parts.append(_text(74, 444,
                       "exit 3 is separate from 0 on purpose: an artifact the tool could not fully "
                       "read is never reported as safe.",
                       size=11, fill=INK))

    return _svg(width, height, "\n".join(parts), "How Actaira is put together")


# ---------------------------------------------------------------------------
# 6. What the tool does, in one picture
# ---------------------------------------------------------------------------
def overview() -> str:
    """The shape of the product: what goes in, what it does, what comes out.

    The first thing a reader meets, so it is the one most worth generating
    rather than drawing. Every count on the middle panel is read from the
    registry or the enum that defines it, so the picture cannot claim a
    capability the code has stopped having, and cannot keep a number the code
    has moved. The three columns are deliberately not equal: the left is what
    the tool accepts, the middle is what it does, and the right is the only
    thing it ever asserts.
    """
    from actaira.agentgov.capability import CAPABILITY_RULES
    from actaira.controls import registry as control_registry
    from actaira.governance.catalog import ALL_OBLIGATIONS
    from actaira.policy.engine import PREDICATES
    from actaira.state.evidence import EvidenceState
    from actaira.state.graph import RELATIONS
    from actaira.subject import SubjectKind

    rules = _figures().get("catalog", {}).get("rules", 0)
    width, height = 1000, 432
    parts: list[str] = []

    def panel(x, y, w, h, colour, opacity="0.05"):
        return (
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" '
            f'fill="{colour}" fill-opacity="{opacity}" stroke="{colour}" stroke-opacity="0.5"/>'
        )

    def arrow(x1, y, x2, colour=MUTED):
        return (
            f'<path d="M{x1} {y} H{x2 - 7}" stroke="{colour}" stroke-width="1.6" '
            f'fill="none" stroke-opacity="0.75"/>'
            f'<path d="m{x2 - 8} {y - 4} 6 4 -6 4Z" fill="{colour}" fill-opacity="0.75"/>'
        )

    parts.append(_text(56, 38, "what goes in, what it does, and the only thing it ever asserts",
                       size=15, fill=INK, weight=600))

    left_x, left_w = 56, 186
    mid_x, mid_w = 280, 440
    right_x, right_w = 758, 186
    top, body_h = 64, 320

    # ---- what goes in -------------------------------------------------------
    kinds = [kind.value for kind in SubjectKind]
    parts.append(panel(left_x, top, left_w, body_h, MUTED, "0.04"))
    parts.append(_text(left_x + 18, top + 28, "GOES IN", size=10.5, fill=MUTED, weight=700, mono=True))
    parts.append(_text(left_x + 18, top + 50, f"{len(kinds)} kinds of subject", size=11.5, fill=MUTED))
    for index, kind in enumerate(kinds):
        parts.append(_text(left_x + 18, top + 84 + index * 26, kind, size=12.5, fill=INK, mono=True))
    parts.append(_text(left_x + 18, top + 84 + len(kinds) * 26 + 14,
                       "read as bytes, never", size=10.5, fill=MUTED))
    parts.append(_text(left_x + 18, top + 84 + len(kinds) * 26 + 28,
                       "loaded and never run", size=10.5, fill=MUTED))
    parts.append(arrow(left_x + left_w + 4, top + body_h / 2, mid_x))

    # ---- what it does -------------------------------------------------------
    does = [
        ("Static inspection", f"{rules} rules, no unpickler"),
        ("Agent attack paths", f"{len(CAPABILITY_RULES)} capability rules, and the route"),
        ("Graph and impact", f"{len(RELATIONS)} relation kinds, each one declared"),
        ("Policy as code", f"{len(PREDICATES)} predicates, never a score"),
        ("EU AI Act evidence", f"{len(control_registry.all_controls())} controls over "
                               f"{len(ALL_OBLIGATIONS)} obligations"),
        ("Evidence lifecycle", f"{len(list(EvidenceState))} states, bound to a digest"),
        ("Attestations and receipts", "RFC 6962, Ed25519, verified offline"),
    ]
    parts.append(panel(mid_x, top, mid_w, body_h, ACCENT, "0.06"))
    parts.append(_mark(mid_x + 18, top + 16, 26, "overview-ramp"))
    parts.append(_text(mid_x + 54, top + 36, "Actaira", size=19, fill=INK, weight=700))
    for index, (name, detail) in enumerate(does):
        row_y = top + 74 + index * 34
        parts.append(
            f'<rect x="{mid_x + 18}" y="{row_y - 12}" width="4" height="22" rx="2" '
            f'fill="{ACCENT}" fill-opacity="0.55"/>'
        )
        parts.append(_text(mid_x + 32, row_y, name, size=12.5, fill=INK, weight=600))
        parts.append(_text(mid_x + 32, row_y + 15, detail, size=10.5, fill=MUTED))
    parts.append(arrow(mid_x + mid_w + 4, top + body_h / 2, right_x))

    # ---- what comes out -----------------------------------------------------
    parts.append(panel(right_x, top, right_w, body_h, ACCENT, "0.04"))
    parts.append(_text(right_x + 18, top + 28, "COMES OUT", size=10.5, fill=MUTED, weight=700, mono=True))
    for index, (verdict, note) in enumerate(
        (("ALLOW", "nothing objected"), ("DENY", "a finding, or a rule"),
         ("REVIEW", "not enough was read")),
    ):
        row_y = top + 66 + index * 46
        parts.append(_text(right_x + 18, row_y, verdict, size=13.5, fill=ACCENT, weight=700, mono=True))
        parts.append(_text(right_x + 18, row_y + 16, note, size=10.5, fill=MUTED))
    parts.append(_text(right_x + 18, top + 226, "and a signed receipt", size=11.5, fill=INK, weight=600))
    parts.append(_text(right_x + 18, top + 244, "somebody with neither", size=10.5, fill=MUTED))
    parts.append(_text(right_x + 18, top + 258, "the artifacts nor this", size=10.5, fill=MUTED))
    parts.append(_text(right_x + 18, top + 272, "tool can check", size=10.5, fill=MUTED))

    return _svg(width, height, "\n".join(parts), "What Actaira does")


DIAGRAMS = {
    "banner.svg": banner,
    "pipeline.svg": pipeline,
    "coverage-ladder.svg": coverage_ladder,
    "marking-survival.svg": marking_survival,
    "architecture.svg": architecture,
    "overview.svg": overview,
}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, builder in DIAGRAMS.items():
        (OUT / name).write_text(builder(), encoding="utf-8", newline="\n")
        print(f"  wrote docs/img/{name}")
    print(f"{len(DIAGRAMS)} diagram(s) generated from the repository and its measurements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
