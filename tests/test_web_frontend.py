"""The shipped interface, asserted where a Python test can reach it.

`src/actaira/web/static/` is three files that no Python test executes:
`index.html`, `app.js` and `styles.css`. Most of what matters about them is
visual and is gated by `scripts/screenshots.py`, which loads every panel in
both languages and fails on a console error, a page error, a failed request or
a Content-Security-Policy violation. That pass needs playwright and chromium,
so it is not part of `make test`.

What is left, and what this file holds, is the handful of properties that are
textual: a rendering path and a stylesheet rule that only work if both halves
are present, and a claim in the page that the rest of the repository also
makes. Each one here is a property that broke, or would break silently.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from conftest import REPO_ROOT

STATIC = Path(REPO_ROOT) / "src" / "actaira" / "web" / "static"
APP_JS = (STATIC / "app.js").read_text(encoding="utf-8")
STYLES = (STATIC / "styles.css").read_text(encoding="utf-8")
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")


def test_the_tensor_table_stacks_on_a_phone_instead_of_clipping_a_number():
    """DEF-105. Four columns do not fit 400px.

    `overflow-x: auto` was on the wrapper, so the table could be scrolled, but
    a horizontal scrollbar inside a card is close to invisible and nothing
    said the row continued. What a reader on a phone actually met was a
    tensor of 65 536 elements rendered as `65.5`: a number cut off mid-digit
    that still reads as a number, which is worse than a cut-off label because
    there is nothing about it to notice.

    The fix has two halves in two files and is inert if either is missing, so
    both are asserted. The renderer marks the table and puts the column name
    on every cell; the stylesheet stacks rows into cards below the breakpoint
    and reads the name back out of `data-label`.
    """
    tensors = re.search(r"function tensorsCard\(report\) \{.*?\n  \}", APP_JS, re.S)
    assert tensors, "tensorsCard is no longer a function this test can find"
    block = tensors.group(0)

    cells = re.findall(r"el\('td', \{([^}]*)\}", block)
    assert len(cells) == 4, f"expected the four tensor columns, found {len(cells)}"
    for attributes in cells:
        assert "data-label" in attributes, (
            "a tensor cell with no data-label has no heading once the rows are "
            f"stacked, and renders as a bare value: {attributes.strip()[:80]}"
        )

    assert "table--stacks" in block, "the renderer no longer opts this table into stacking"
    assert "table--stacks" in STYLES, "the stylesheet has no rule for the class the renderer sets"
    assert re.search(r"@media \(max-width: 560px\)", STYLES), "the stacking breakpoint is gone"
    assert "content: attr(data-label)" in STYLES, (
        "the stacked rows no longer print the column name, so every value loses its heading"
    )


def test_the_stacked_labels_come_from_the_catalogue_and_not_from_english_literals():
    """The column names are printed by CSS from `data-label`, which is filled
    by the renderer. If that were filled with a literal, the phone layout would
    be in English under `--lang es` while the desktop one was translated, and
    `tests/test_i18n.py` would never see it: it checks the catalogue, and a
    string that never reaches the catalogue is not something it can miss."""
    tensors = re.search(r"function tensorsCard\(report\) \{.*?\n  \}", APP_JS, re.S)
    assert tensors
    for label in re.findall(r"'data-label': ([^,]+),", tensors.group(0)):
        assert label.strip().startswith("t("), (
            f"data-label is set from {label.strip()}, which is not a catalogue lookup"
        )


def test_the_interface_loads_nothing_from_outside_this_machine():
    """The claim the footer makes - no framework, no bundler, no CDN, no
    external font - is a claim about these three files, so it is checkable
    here rather than only in the Content-Security-Policy."""
    for name, text in (("index.html", INDEX), ("app.js", APP_JS), ("styles.css", STYLES)):
        for match in re.findall(r"""(?:src|href)\s*=\s*["']([^"']+)["']""", text):
            assert not match.startswith(("http://", "https://", "//")), (
                f"{name} references {match}, which is off this machine"
            )
        assert "@import url(http" not in text.replace(" ", ""), f"{name} imports a remote stylesheet"
        assert "cdn." not in text.lower() or name != "index.html", f"{name} names a CDN"


def _mark_geometry(text: str) -> tuple[str, tuple[str, str, str]]:
    """The outline and the head circle, as they are written in a file."""
    path = re.search(r'<path d="(M59\.88[^"]+)"', text)
    head = re.search(r'<circle cx="([\d.]+)" cy="([\d.]+)" r="([\d.]+)"', text)
    assert path, "the mark's outline is not in this file in the shape this test reads"
    assert head, "the mark's head circle is not in this file in the shape this test reads"
    return path.group(1), head.groups()


def test_the_brand_mark_in_the_interface_is_the_one_the_banner_draws():
    """One logo, two files, and this is what holds them together.

    The mark is inlined twice deliberately. `index.html` carries it because
    the interface is not allowed to fetch anything, and `scripts/diagrams.py`
    carries it because the README banner is generated from the repository
    rather than pasted into it. Two copies of the same geometry with nothing
    holding them together is the exact shape of drift this repository keeps a
    ledger of, so the two are compared here: correcting the logo in one file
    and not the other fails the suite instead of shipping a tool whose
    interface and whose README disagree about what it looks like.

    Only the geometry is compared. The ramps differ on purpose and the reason
    is written where each one lives: the interface knows its own background
    and uses the brand's own values, and the banner is rendered on a surface
    GitHub chooses, where the brand's dark end is 1.03 against `#0d1117`.
    """
    import sys

    sys.path.insert(0, str(Path(REPO_ROOT) / "scripts"))
    import diagrams  # noqa: PLC0415

    interface_path, interface_head = _mark_geometry(INDEX)
    assert interface_path == diagrams.MARK_PATH, (
        "the outline in the interface and the outline the banner draws are different shapes"
    )
    assert tuple(float(value) for value in interface_head) == diagrams.MARK_HEAD, (
        "the head circle differs between the interface and the banner"
    )


def test_the_sprite_is_hidden_in_a_way_that_keeps_its_gradient_usable():
    """`display: none` on the sprite makes the mark an invisible hole.

    The sprite holds the gradient the mark is filled with, and a paint server
    inside a `display: none` subtree does not resolve: the shape is laid out
    at the right size, gets a bounding box, and paints nothing. It fails
    silently, in one of the few places this project has no automated eye on,
    because no console error is raised and the screenshot pass sees a page
    that loaded cleanly. So the hiding technique is pinned here.
    """
    rule = re.search(r"\.sprite \{([^}]*)\}", STYLES)
    assert rule, ".sprite no longer has a rule this test can find"
    body = rule.group(1)
    assert "display: none" not in body, (
        "the sprite is hidden with display: none again, which unpaints the brand mark"
    )
    assert "width: 0" in body and "height: 0" in body, (
        "the sprite is no longer collapsed, so it will take up space in the page"
    )
    assert 'id="brand-ramp"' in INDEX, "the mark's gradient is gone from the sprite"
    for stop in ("brand-ramp-a", "brand-ramp-b"):
        assert f'id="{stop}"' in INDEX, f"the {stop} stop is gone from the sprite"
        assert f"#{stop} {{ stop-color:" in STYLES, (
            f"nothing in the stylesheet gives {stop} a colour, so the mark paints black"
        )


# ---------------------------------------------------------------------------
# The interface's own catalogue
# ---------------------------------------------------------------------------
#
# `src/actaira/i18n/*.json` is the CLI's catalogue and `tests/test_i18n.py`
# holds its two languages to the same key set. The interface does not use it:
# `app.js` carries its own `I18N` object, a few hundred strings that never
# reach that file and were therefore never compared with anything.
#
# So a new panel could ship with English strings only, and the Spanish
# interface would render them in English with no error, no console warning and
# no failing test. The screenshot pass would not catch it either: it loads
# every panel in both languages and asserts that nothing threw, not that the
# words changed.

I18N_BLOCK = re.compile(r"var I18N = \{(.*?)\n  \};", re.S)
I18N_KEY = re.compile(r"^\s*'([^']+)':", re.M)


def interface_catalogue() -> dict[str, list[str]]:
    """The keys each language declares in `app.js`, in file order.

    Read as text rather than executed. Running it would need a JavaScript
    engine in the test environment for a question about which quoted names
    appear between two braces.
    """
    block = I18N_BLOCK.search(APP_JS)
    assert block, "the I18N object in app.js is no longer in a shape this test can read"
    body = block.group(1)

    english_at = body.index("en: {")
    spanish_at = body.index("es: {", english_at)
    return {
        "en": I18N_KEY.findall(body[english_at:spanish_at]),
        "es": I18N_KEY.findall(body[spanish_at:]),
    }


def test_the_interface_says_the_same_things_in_both_languages():
    """Every string the interface can render has to exist in both.

    A key present in one language only is not a crash: `t()` falls back to
    English, so the panel renders and the reader is simply shown a language
    they did not ask for. That is exactly why it needs a test rather than a
    bug report.
    """
    catalogue = interface_catalogue()
    english, spanish = set(catalogue["en"]), set(catalogue["es"])

    missing_spanish = sorted(english - spanish)
    missing_english = sorted(spanish - english)
    assert not missing_spanish, (
        "the interface has English strings with no Spanish: "
        + ", ".join(missing_spanish[:12])
    )
    assert not missing_english, (
        "the interface has Spanish strings with no English, which `t()` cannot "
        "fall back from: " + ", ".join(missing_english[:12])
    )


@pytest.mark.parametrize("lang", ["en", "es"])
def test_no_interface_string_is_declared_twice(lang):
    """A repeated key is a silent overwrite: the second wins and the first is
    dead text that a reader will never see, which is how a correction gets
    made and then does nothing."""
    keys = interface_catalogue()[lang]
    repeated = sorted({key for key in keys if keys.count(key) > 1})
    assert not repeated, f"{lang} declares these twice: {', '.join(repeated)}"


def test_every_interface_string_the_markup_asks_for_exists():
    """`data-i18n` attributes name keys, and a typo in one is invisible.

    `applyStaticI18n` writes `t(key)` into the element, and `t()` returns the
    key itself when it knows nothing about it. So a mistyped attribute renders
    the literal string `welcome.claim.4` into the page, which is ugly rather
    than fatal and survives a screenshot pass that only watches for errors.
    """
    declared = set(interface_catalogue()["en"])
    asked = set(re.findall(r'data-i18n(?:-[a-z-]+)?="([^"]+)"', INDEX))
    unknown = sorted(asked - declared)
    assert not unknown, (
        "index.html asks for interface strings that app.js does not define, so "
        "the key itself is rendered: " + ", ".join(unknown)
    )


# ---------------------------------------------------------------------------
# The graph's node vocabulary
# ---------------------------------------------------------------------------
#
# The drawing colours a node by its kind, and it reads that kind off the
# prefix of the node's id. So there are two lists that have to agree with a
# third thing neither of them can see: the set of prefixes the *engine* emits.
#
# They did not agree. The agent engine emits data sources as `data:<name>` and
# has done since the declaration format was published; the visual vocabulary
# calls that kind `datasource`. Every data source in every graph drew as
# `unknown` - silently, because an unrecognised kind is still drawn, just in
# the neutral style. Nothing failed and the picture was simply wrong.
#
# The fix is an alias table, and the test below is deliberately not a test of
# that one entry. It collects the prefixes the engine can actually produce and
# requires each of them to be classifiable, so the next id prefix somebody adds
# is caught the same way rather than needing a second test written for it.

KIND_LIST = re.compile(r"var GRAPH_NODE_KINDS = \[(.*?)\];", re.S)
ALIAS_LIST = re.compile(r"var GRAPH_NODE_ALIASES = \{(.*?)\};", re.S)


def graph_vocabulary() -> tuple[set[str], dict[str, str]]:
    kinds = KIND_LIST.search(APP_JS)
    aliases = ALIAS_LIST.search(APP_JS)
    assert kinds, "GRAPH_NODE_KINDS is no longer in a shape this test can read"
    assert aliases, "GRAPH_NODE_ALIASES is no longer in a shape this test can read"
    return (
        set(re.findall(r"'([^']+)'", kinds.group(1))),
        dict(re.findall(r"(\w+)\s*:\s*'([^']+)'", aliases.group(1))),
    )


def engine_node_prefixes() -> set[str]:
    """Every `kind:` prefix the engine can put in a graph, from the engine.

    Two sources, because there are two: the relations an agent declaration
    states about its own parts, and the asset kinds a manifest records. Read
    from the shipped example rather than from a list written here, so a new
    prefix arrives in this test by being emitted rather than by being
    remembered.
    """
    from actaira.agentgov import load as load_agent
    from actaira.subject import SubjectKind

    agent = load_agent(Path(REPO_ROOT) / "examples" / "agent-ticket-triage.yaml")
    found = {member.value for member in SubjectKind}
    for edge in agent.relations() + agent.membership_relations():
        for node in (edge.source, edge.target):
            head, separator, _ = node.partition(":")
            if separator:
                found.add(head)
    return found


def test_every_node_prefix_the_engine_emits_has_a_visual_kind():
    kinds, aliases = graph_vocabulary()
    unclassified = sorted(
        prefix for prefix in engine_node_prefixes()
        if prefix not in kinds and prefix not in aliases
    )
    assert not unclassified, (
        "the engine emits these node id prefixes and the graph renderer has no kind for "
        "them, so they draw as `unknown` with no error anywhere: " + ", ".join(unclassified)
    )


def test_the_data_prefix_is_mapped_rather_than_renamed():
    """The specific case, pinned.

    `data:` is what the published agent format emits and `datasource` is what
    the stylesheet calls the kind. Renaming either to match the other would be
    changing a published id or a class to settle a spelling, so the mapping is
    stated. This asserts the direction: the engine keeps `data`.
    """
    kinds, aliases = graph_vocabulary()
    assert aliases.get("data") == "datasource"
    assert "data" not in kinds, (
        "`data` became a kind of its own, so `data:` nodes now draw under a class the "
        "stylesheet does not have a rule for"
    )
    assert "datasource" in kinds


def test_an_unfamiliar_prefix_stays_unknown_rather_than_being_guessed_at():
    """A renderer that guessed which kind an unfamiliar prefix meant would be
    inventing a classification, quietly, in the one place a reader has no way
    to check it. The alias table is a table and not a rule, and this is what
    holds it to that."""
    body = re.search(r"function graphNodeKind\(id\) \{(.*?)\n  \}", APP_JS, re.S)
    assert body, "graphNodeKind is no longer a function this test can find"
    assert "'unknown'" in body.group(1), "an unrecognised prefix no longer falls back to unknown"
    _, aliases = graph_vocabulary()
    assert len(aliases) == 1, (
        "the alias table has grown. That may be right, and each entry has to be a published "
        f"id prefix that differs from its visual kind for a stated reason: {sorted(aliases)}"
    )


def test_every_kind_the_renderer_can_draw_has_a_style():
    """A kind with no rule falls back to the neutral box, which is a fine
    default and a bad surprise: it means two kinds look identical with nothing
    saying so. The neutral ones are listed here rather than left implicit."""
    kinds, _ = graph_vocabulary()
    # These share the base `.graph__box` deliberately: they have no panel of
    # their own yet, and a colour invented ahead of a use is a colour that will
    # mean something else later.
    neutral = {"bundle", "credential", "identity", "mcp", "policy"}
    missing = sorted(
        kind for kind in kinds - neutral
        if f".graph__box--{kind} " not in STYLES and f".graph__box--{kind}," not in STYLES
    )
    assert not missing, f"kinds the stylesheet does not style: {', '.join(missing)}"


def test_the_attack_path_chain_still_uses_the_chain_layout():
    """The route drawing is the renderer's first caller and must not have been
    changed by the asset graph becoming its second.

    Pinned at the two places it could drift: the model the agent panel builds
    still asks for `chain`, and the chain layout still produces the geometry it
    produced before a second layout existed.
    """
    model = re.search(r"function agentRouteModel\(path\) \{(.*?)\n  \}", APP_JS, re.S)
    assert model, "agentRouteModel is no longer a function this test can find"
    assert "layout: 'chain'" in model.group(1), "the attack route stopped asking for a chain"

    chain = re.search(r"function graphChainLayout\(model, tight\) \{(.*?)\n  \}", APP_JS, re.S)
    assert chain, "graphChainLayout is no longer a function this test can find"
    body = chain.group(1)
    assert "var width = tight ? 250 : 420;" in body, "the chain's width changed"
    assert "var boxHeight = 44, gap = 34, pad = 2;" in body, "the chain's geometry changed"
    assert "if (toIndex !== fromIndex + 1) { return null; }" in body, (
        "the chain draws edges between non-neighbours again, which puts a line through "
        "the boxes in between"
    )


def test_the_asset_graph_layout_is_deterministic_and_not_a_simulation():
    """Two runs over one workspace must draw the same picture.

    This repository generates its screenshots and fails a build on what they
    show, so a force-directed layout would make every capture a different
    image and every visual regression unarguable. The layout sorts; it does
    not settle.
    """
    layered = re.search(r"function graphLayeredLayout\(model, tight\) \{(.*?)\n  \}", APP_JS, re.S)
    assert layered, "graphLayeredLayout is no longer a function this test can find"
    body = layered.group(1)
    assert ".sort()" in body, "the layered layout no longer sorts, so its output is order-dependent"
    for banned in ("Math.random", "forceSimulation", "requestAnimationFrame"):
        assert banned not in body, f"the layout uses {banned}, so it is not deterministic"
    assert "Math.random" not in APP_JS, "something in the interface draws from a random source"


def test_a_dragged_node_is_never_written_anywhere_but_the_page():
    """Where a box sits is a reading convenience, not an assurance claim.

    The panel is read-only by design, and the one thing on it that a user can
    change is a node's position. That must stay in memory: a screen coordinate
    written into the workspace would be a fact about a browser window living in
    a database of claims about software.
    """
    move = re.search(r"svg\._moveNode = function \(id, x, y\) \{(.*?)\n    \};", APP_JS, re.S)
    assert move, "_moveNode is no longer in a shape this test can read"
    for banned in ("postJson", "upload(", "fetch(", "XMLHttpRequest"):
        assert banned not in move.group(1), f"moving a node reaches {banned}"

    panel = re.search(r"function graphViewport\(model, ariaLabel\) \{(.*?)\n  \}", APP_JS, re.S)
    assert panel, "graphViewport is no longer a function this test can find"
    assert "state.graph.positions[dragging.node]" in panel.group(1), (
        "a dragged position is no longer kept in page state, so it goes somewhere else"
    )
    assert "/api/" not in panel.group(1), "the viewport talks to the server while dragging"


def test_the_graph_panel_never_walks_the_graph_itself():
    """Reachability lives in Python, once, for both surfaces.

    A traversal written here would be a second implementation over the same
    edges, and it would agree with `state/graph.py` until it did not - in a
    way nobody would notice, because each looks right on its own.
    """
    start = APP_JS.index("/* ── the graph ──")
    end = APP_JS.index("var RUNNERS = {")
    panel = APP_JS[start:end]
    for banned in ("function bfs", "while (queue", "visited[", "reachable("):
        assert banned not in panel, (
            f"the graph panel contains {banned}, which looks like a traversal. Reachability "
            "belongs in state/graph.py so the CLI and the interface cannot disagree"
        )
    for route in ("/api/graph", "/api/impact", "/api/graph/node", "/api/workspace"):
        assert route in panel, f"the panel no longer calls {route}"


def test_no_shipped_static_file_carries_a_raw_control_character():
    r"""A control character in a source file is invisible and it travels.

    This was written wrong before it was written right: a separator meant as
    the escape `\u0000` went into `app.js` as an actual NUL byte. The
    interpreter accepts it, so nothing failed - the file simply became one
    that every editor renders identically to the correct version, that `grep`
    reports as binary and refuses to search, and that loses the character
    entirely if anybody copies a line out of it.

    Tab and newline are the two that legitimately appear. Everything else in
    the C0 range, plus the byte-order mark, the zero-width space and the
    bidirectional overrides, is refused: the last of those is the Trojan
    Source class, where what a reviewer reads and what the interpreter runs
    are two different programs.
    """
    forbidden = {chr(code) for code in range(0x20)} - {"\n", "\t"}
    forbidden |= {
        "\ufeff",                                          # byte-order mark
        "\u200b", "\u00a0",                                # invisible spacing
        "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",   # bidi overrides
        "\u2066", "\u2067", "\u2068", "\u2069",           # bidi isolates
    }
    for name, text in (("index.html", INDEX), ("app.js", APP_JS), ("styles.css", STYLES)):
        for number, line in enumerate(text.splitlines(), 1):
            found = sorted({f"U+{ord(character):04X}"
                            for character in line if character in forbidden})
            assert not found, (
                f"{name}:{number} carries {', '.join(found)} as a raw character. Write it "
                "as an escape: a control character here is invisible in review and does "
                "not survive a copy."
            )


def test_the_screenshot_fixture_is_built_twice_into_the_same_state(tmp_path):
    """Two runs of `make screenshots` must not produce two different pictures.

    The fixture is built by the commands an operator types, which is the point:
    one assembled by writing rows could show a panel a state the commands
    cannot produce. What it must not also inherit is `datetime.now()` in every
    row, because then every regeneration is a committed diff for a reason that
    is not a change, and a repository that commits its screenshots ends up with
    a permanent one nobody can read.

    So the story's clocks are pinned after the commands have built it, and this
    is the check that they still are. Comparing the state export rather than
    the images: an export is a document a failure can be read out of, and a
    PNG comparison would tell you only that two files differ.
    """
    import importlib.util
    import json

    from actaira.state.store import Store

    location = Path(REPO_ROOT) / "scripts" / "screenshots.py"
    spec = importlib.util.spec_from_file_location("screenshots_fixture", location)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # Twice into the SAME directory, which is what `make screenshots` does:
    # it always builds `.screenshots/graph-state.db`. Building into two
    # different directories would compare two different fixtures, because an
    # artifact's asset id is derived from its URI and the URI of a local file
    # contains the directory it is in - which is the property that gives an
    # artifact a history across observations, and is not a defect.
    exports = []
    room = tmp_path / "screenshots"
    room.mkdir()
    for _ in range(2):
        module.build_workspace(room / "state.db")
        with Store(room / "state.db", create=False) as store:
            document = store.export()
        # The tool version and the absolute paths differ by construction; what
        # has to agree is every identity and every timestamp.
        exports.append(json.dumps({
            "snapshots": [(row["digest"], row["observed_at"]) for row in document["snapshots"]],
            "evidence": sorted(
                (row["evidence_id"], row["kind"], row["state"], row["observed_at"])
                for row in document["evidence"]
            ),
            "decisions": sorted(
                (row["decision_id"], row["decision"], row["observed_at"])
                for row in document["decisions"]
            ),
            "decision_inputs": sorted(
                (row["role"], row["ref"]) for row in document["decision_inputs"]
            ),
        }, sort_keys=True))

    assert exports[0] == exports[1], (
        "two builds of the screenshot fixture disagree, so every regeneration "
        "of the captures will be a diff that is not a change"
    )
    # And the story is actually there, or the comparison above is comparing
    # two empty documents.
    assert "artifact_scan" in exports[0]
    assert "policy_decision" in exports[0]
    assert "superseded" in exports[0]
