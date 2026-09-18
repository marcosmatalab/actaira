"""One HTML file a reviewer can open, with nothing in it that reaches the network.

`--html` is a flag on `check` and on `diff`, not a command of its own: CLAUDE.md
caps the set at eight and a report is a rendering of a document those two
already produce, not a third thing to run.

Design note D-297. WHAT THIS PAGE MAY NOT DO, and each is enforced by a test
rather than by care.
No script, of any kind, inline or otherwise. No `src` or `href` that fetches
anything: no stylesheet, no font, no image, no analytics pixel. A security
report that phones home while being read is the joke that writes itself, and an
air-gapped reviewer is the reader this is for. Links to the vendor documentation
a merge rule cites ARE allowed and are the point of citing it - they are `<a>`
elements a human clicks, not resources the page loads.

WHAT IT MAY NOT SAY. Everything the console refuses to say: no score, no grade,
no percentage, no total across the three lists, no ordering of one author's
severity against another's. The page shows what the document holds and adds
nothing, which is why it is a rendering and not a summary.

Rejected: rescuing the colour tokens and the icon sprite from
`v2.3.0:src/actaira/web/static/`. That stylesheet is 41 kB written for an
application with navigation, a filter bar and a grid that JavaScript populated;
what is needed here is one column of three lists, and 60 lines of CSS that can
be read in one screen is a smaller liability than 41 kB nobody will ever audit
again. `app.js` was never a candidate.

Every string that came out of somebody else's file is escaped on the way in.
The document this renders is built from configuration an attacker may have
written, so `html.escape` with `quote=True` is applied to every value without
exception, and the one place a URL is placed in an attribute refuses any scheme
but http and https.
"""
from __future__ import annotations

from html import escape
from typing import Any
from urllib.parse import urlsplit

from ..i18n.catalog import Catalog

# Light and dark from the same tokens, so a reviewer's own setting is honoured
# without a line of script. `prefers-color-scheme` is the only mechanism that
# can do this in a file with no JavaScript, which is the constraint this page is
# built under rather than a preference.
STYLE = """
:root {
  --ink: #16191d; --dim: #5b6572; --line: #dfe3e8; --paper: #ffffff;
  --panel: #f7f8fa; --rule: #8a4b00; --gap: #44506a; --quiet: #5b6572;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --ink: #e7eaee; --dim: #9aa4b2; --line: #2a2f37; --paper: #14171b;
    --panel: #1b1f25; --rule: #e6a866; --gap: #9fb0d4; --quiet: #9aa4b2;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--paper); color: var(--ink);
       font: 15px/1.55 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
main { max-width: 52rem; margin: 0 auto; padding: 2.5rem 1.25rem 4rem; }
h1 { font-size: 1.35rem; margin: 0 0 .25rem; }
h2 { font-size: 1.05rem; margin: 2.25rem 0 .75rem; padding-bottom: .3rem;
     border-bottom: 1px solid var(--line); }
p { margin: .5rem 0; }
.sub { color: var(--dim); margin: 0 0 1.5rem; }
.item { border: 1px solid var(--line); border-left: 3px solid var(--rule);
        background: var(--panel); border-radius: 3px; padding: .7rem .9rem;
        margin: .6rem 0; }
.item.gap { border-left-color: var(--gap); }
.item.quiet { border-left-color: var(--quiet); }
.head { font-family: var(--mono); font-size: .82rem; word-break: break-all; }
.who { color: var(--dim); font-size: .82rem; margin-top: .35rem; }
.who a { color: inherit; }
dl { margin: .45rem 0 0; display: grid; grid-template-columns: max-content 1fr;
     gap: .15rem .8rem; font-size: .84rem; }
dt { color: var(--dim); }
dd { margin: 0; font-family: var(--mono); word-break: break-all; }
.limit { margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid var(--line);
         color: var(--dim); font-size: .85rem; }
.none { color: var(--dim); font-style: italic; }
""".strip()


def _safe_link(url: str) -> str | None:
    """An http or https URL, or nothing. The only attribute a document value reaches."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme in ("http", "https") and parts.netloc:
        return url
    return None


def _text(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def _rows(pairs: list[tuple[str, Any]]) -> str:
    if not pairs:
        return ""
    cells = "".join(f"<dt>{_text(key)}</dt><dd>{_text(value)}</dd>" for key, value in pairs)
    return f"<dl>{cells}</dl>"


def _facts(facts: dict[str, Any], trail: str = "") -> list[tuple[str, Any]]:
    """What was observed, flattened, so a reviewer sees the evidence and not only
    the sentence about it.

    Every value here came out of a file somebody else wrote - a path, a domain,
    a server alias, and with `--with-content` a command line - so this is the one
    place in the page where escaping is load-bearing rather than precautionary,
    and `tests/test_seal_and_report.py` plants markup in one to say so.
    """
    rows: list[tuple[str, Any]] = []
    for key in sorted(facts):
        value = facts[key]
        if isinstance(value, dict):
            rows.extend(_facts(value, f"{trail}{key}."))
        else:
            rows.append((f"{trail}{key}", value))
    return rows


def _finding(finding: dict[str, Any], catalog: Catalog) -> str:
    evidence = finding.get("evidence", {}) or {}
    who = "{} {} {} / {}".format(
        catalog.line("surface.attributed"),
        _text(finding.get("author")),
        _text(finding.get("pack")),
        _text(finding.get("severity")),
    )
    links = []
    for reference in evidence.get("references", []) or []:
        safe = _safe_link(str(reference))
        if safe:
            links.append(f'<a href="{_text(safe)}">{_text(safe)}</a>')
    pairs: list[tuple[str, Any]] = [
        (catalog.line("report.rule"), f"{finding.get('rule_id')} {finding.get('rule_version')}"),
        (catalog.line("report.capability"), evidence.get("capability")),
        (catalog.line("report.source"), finding.get("location")),
        (catalog.line("report.scope"), evidence.get("scope")),
        (catalog.line("report.resolution"), evidence.get("resolution")),
        (catalog.line("report.merge_rule"), evidence.get("merge_rule")),
    ]
    if evidence.get("condition"):
        pairs.append((catalog.line("report.condition"), evidence["condition"]))
    pairs.append((catalog.line("report.remediation"), evidence.get("remediation")))
    pairs.extend(_facts(evidence.get("facts", {}) or {}))
    body = (
        f'<div class="item"><div class="head">{_text(finding.get("rule_id"))} '
        f'{_text(evidence.get("capability"))}</div>'
        f"<p>{_text(catalog.rule(str(finding.get('rule_id'))))}</p>"
        f'<div class="who">{who}</div>{_rows(pairs)}'
    )
    if links:
        body += '<div class="who">' + " ".join(links) + "</div>"
    return body + "</div>"


def _gap(gap: dict[str, Any], catalog: Catalog) -> str:
    return (
        f'<div class="item gap"><div class="head">{_text(gap.get("subject"))}</div>'
        f"<p>{_text(gap.get('cause'))}</p>"
        + _rows([(catalog.line("report.source"), gap.get("source"))])
        + "</div>"
    )


def _unread(entry: dict[str, Any]) -> str:
    return (
        f'<div class="item quiet"><div class="head">{_text(entry.get("path"))}</div>'
        f"<p>{_text(entry.get('reason'))}</p></div>"
    )


def _section(title: str, parts: list[str], empty: str) -> str:
    inside = "".join(parts) if parts else f'<p class="none">{_text(empty)}</p>'
    return f"<h2>{_text(title)}</h2>{inside}"


def _page(title: str, subtitle: str, body: str, catalog: Catalog) -> str:
    """The whole file, assembled in one place so nothing can be added elsewhere.

    No `<script>`, no `<link>`, no `<img>`. The head carries a charset, a
    viewport and the stylesheet inline, and that is the entire set of things
    this page is made of.
    """
    return (
        "<!doctype html>\n"
        f'<html lang="{_text(catalog.lang)}"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_text(title)}</title><style>{STYLE}</style></head><body><main>"
        f"<h1>{_text(title)}</h1>"
        f'<p class="sub">{_text(subtitle)}</p>'
        f"{body}"
        f'<p class="limit">{_text(catalog.line("surface.declares"))}</p>'
        "</main></body></html>\n"
    )


def check_page(document: dict[str, Any], catalog: Catalog) -> str:
    """The `surface/v1` document as one page. The same bytes for the same document."""
    vendors = ", ".join(
        sorted(
            surface["vendor"]
            for surface in document.get("surfaces", [])
            if surface.get("capabilities")
        )
    )
    body = _section(
        catalog.line("report.findings"),
        [_finding(finding, catalog) for finding in document.get("findings", [])],
        catalog.line("surface.nothing_fired"),
    )
    body += _section(
        catalog.line("surface.unresolved", count=len(document.get("unresolved", []))),
        [_gap(gap, catalog) for gap in document.get("unresolved", [])],
        catalog.line("report.none_here"),
    )
    body += _section(
        catalog.line("surface.not_read", count=len(document.get("not_read", []))),
        [_unread(entry) for entry in document.get("not_read", [])],
        catalog.line("report.none_here"),
    )
    return _page(
        catalog.line("report.check_title"),
        catalog.line("report.check_subtitle", root=document.get("root", ""),
                     vendors=vendors or "-"),
        body,
        catalog,
    )


CHANGE_SECTIONS = ("added", "removed", "widened", "narrowed", "changed")


def _change(entry: dict[str, Any], catalog: Catalog) -> str:
    pairs: list[tuple[str, Any]] = [
        (catalog.line("report.source"), entry.get("source")),
        (catalog.line("report.scope"), entry.get("scope")),
    ]
    for side in ("before", "after"):
        state = entry.get(side)
        if state is None:
            pairs.append((catalog.line(f"report.{side}"), catalog.line("report.absent")))
            continue
        pairs.append((catalog.line(f"report.{side}"),
                      f"{state.get('resolution')}  {state.get('digest')}"))
        pairs.extend(
            (f"{catalog.line(f'report.{side}')}  {key}", value)
            for key, value in _facts(state.get("facts", {}) or {})
        )
    body = (
        f'<div class="item"><div class="head">{_text(entry.get("vendor"))} '
        f'{_text(entry.get("capability"))}</div>{_rows(pairs)}'
    )
    for finding in (entry.get("after") or {}).get("findings", []):
        body += _finding(finding, catalog)
    return body + "</div>"


def diff_page(document: dict[str, Any], catalog: Catalog) -> str:
    """The `surface-diff/v1` document as one page.

    Five sections and never a sixth, then what could not be resolved, in its own
    section and never folded into the five - the same separation the document
    itself keeps, for the same reason.
    """
    body = ""
    for kind in CHANGE_SECTIONS:
        entries = document.get(kind, [])
        body += _section(
            catalog.line(f"diff.{kind}", count=len(entries)),
            [_change(entry, catalog) for entry in entries],
            catalog.line("report.none_here"),
        )
    body += _section(
        catalog.line("diff.indeterminate", count=len(document.get("indeterminate", []))),
        [_gap(gap, catalog) for gap in document.get("indeterminate", [])],
        catalog.line("report.none_here"),
    )
    body += _section(
        catalog.line("surface.not_read", count=len(document.get("not_read", []))),
        [_unread(entry) for entry in document.get("not_read", [])],
        catalog.line("report.none_here"),
    )
    return _page(
        catalog.line("report.diff_title"),
        catalog.line(
            "report.diff_subtitle",
            before=(document.get("before") or {}).get("label", "?"),
            after=(document.get("after") or {}).get("label", "?"),
            unchanged=document.get("unchanged", 0),
        ),
        body,
        catalog,
    )


def render(document: dict[str, Any], catalog: Catalog) -> str:
    """Whichever page this document is. The version decides, never the caller."""
    version = document.get("schema_version", "")
    if version.startswith("surface-diff/"):
        return diff_page(document, catalog)
    if version.startswith("surface/"):
        return check_page(document, catalog)
    raise ValueError(f"no HTML rendering for {version!r}")


__all__ = ["STYLE", "check_page", "diff_page", "render"]
