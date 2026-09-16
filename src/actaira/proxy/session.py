"""`actaira watch`: put a proxy between the agent and each of its servers.

Design note D-255. The agent is run unmodified. What changes is the MCP
configuration it is handed: every stdio server becomes the same server behind
`python -m actaira.proxy.stdio`, and every HTTP server becomes a loopback URL
this process answers on. One proxy per server, one record file each, and one
trace assembled from the lot when the agent exits.

Three decisions worth the lines:

**A server shape the rewriter does not understand is passed through,
DECLARED, AND THE TRACE THEN REFUSES TO CLAIM AUTHENTICITY.** Rewriting it
wrongly would break the agent; dropping it quietly would leave the agent
talking to it directly with the trace saying nothing. It goes through
untouched, the manifest names it, and `assemble` turns every name in there
into a hole - see `_interposition`. Writing the name down and not reading it
back was the same bug wearing a file.

**No record file at all is a gap, not an empty trace.** A session in which
the agent made no tool calls and a session in which the agent never reached
the proxy look identical from here, and this tool cannot tell them apart - so
it says that rather than publishing something that reads as a clean run.

**The child's exit code is not the trace's completeness.** A failed build
whose every call was observed is a complete trace of a failed build. Merging
the two would let a red test run look like a lost event.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..trace import CaptureLevel
from ..trace.model import Gap, GapReason, Trace, TraceEvent
from ..trace.redact import failure_kind, file_ref, label_ref

CONFIG_ENV = "ACTAIRA_MCP_CONFIG"
# What the rewriter did to each configured server, written where `assemble`
# reads it. `uninterposed.json` said the same thing and nothing read it back.
MANIFEST = "interposition.json"
WHOLE_SESSION = "this hole is about the session as a whole, not a position in it"
THROUGH_THIS_SERVER = (
    "nothing through this server was observed, so there is no event it sits beside"
)
WHICH_SERVER = (
    f"The alias it was configured under is in {MANIFEST} beside the records, "
    "which stays on the machine that ran it."
)


def rewrite_config(
    config: dict[str, Any],
    record_dir: Path,
    http_port_for: Callable[[str], int] | None = None,
    session_id: str = "",
    with_content: bool = False,
) -> dict[str, Any]:
    """The agent's MCP configuration, with a proxy in front of every server."""
    record_dir = Path(record_dir)
    record_dir.mkdir(parents=True, exist_ok=True)
    servers = config.get("mcpServers")
    if not isinstance(servers, dict):
        return dict(config)

    rewritten: dict[str, Any] = {}
    interposed: dict[str, Any] = {}
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            rewritten[name] = entry
            interposed[name] = {
                "ref": label_ref(name),
                "interposed": False,
                "why": "the entry is not an object",
            }
            continue
        record = record_dir / f"{name}.jsonl"
        if isinstance(entry.get("command"), str):
            original = [entry["command"], *[str(item) for item in entry.get("args", [])]]
            rewritten[name] = {
                **entry,
                "command": sys.executable,
                "args": [
                    "-m", "actaira.proxy.stdio",
                    "--record", str(record),
                    "--server", name,
                    "--session", session_id,
                    # Carried through, or `actaira watch --with-content` would
                    # be a flag in the help text that changed nothing: the
                    # proxies are separate processes and the only way they hear
                    # about it is here.
                    *(["--with-content"] if with_content else []),
                    "--", *original,
                ],
            }
            interposed[name] = {
                "ref": label_ref(name), "interposed": True, "record": record.name,
            }
        elif isinstance(entry.get("url"), str) and http_port_for is not None:
            rewritten[name] = {**entry, "url": f"http://127.0.0.1:{http_port_for(name)}/mcp"}
            interposed[name] = {
                "ref": label_ref(name), "interposed": True, "record": record.name,
            }
        else:
            rewritten[name] = entry
            interposed[name] = {
                "ref": label_ref(name),
                "interposed": False,
                "why": (
                    "this release interposes on a server given as a command. This entry is "
                    "not one, so the agent reached it directly"
                ),
            }

    # Written every time, including when everything was interposed. A manifest
    # that only appears when something went wrong is a manifest whose absence
    # means two things, and `assemble` has to be able to tell them apart.
    #
    # It also holds the only alias-to-reference map there is. It lives here,
    # beside the records on the operator's machine, and never in the acta -
    # see `redact.label_ref` for why the alias itself does not travel.
    (record_dir / MANIFEST).write_text(
        json.dumps({"servers": interposed}, indent=2, sort_keys=True), encoding="utf-8"
    )
    return {**config, "mcpServers": rewritten}


class WatchSession:
    """One `watch` run: the child, its proxies, and the trace they produce."""

    def __init__(self, record_dir: Path, session_id: str, with_content: bool = False) -> None:
        self.record_dir = Path(record_dir)
        self.session_id = session_id
        self.with_content = with_content

    # -- running the agent ------------------------------------------------

    def run(self, command: list[str], config_path: Path | None) -> int:
        """Run the agent's own command with a rewritten configuration.

        The path is exported as `ACTAIRA_MCP_CONFIG` for any agent, and passed
        as `--mcp-config` when the child is Claude Code, which is the one
        agent whose flag this release knows. Knowing one is better than
        pretending to know none: without it the operator has to wire the
        variable up by hand and most will not.
        """
        self.record_dir.mkdir(parents=True, exist_ok=True)
        source = config_path or Path(".mcp.json")
        config: dict[str, Any] | None = None
        if source.is_file():
            try:
                config = json.loads(source.read_text(encoding="utf-8"))
            except ValueError as exc:
                # Swallowed and read as `{}` before. An empty configuration is
                # a configuration with no servers, and handing the agent one is
                # not a smaller version of interposing - it is taking its tools
                # away. A file the operator named and this cannot read is their
                # error to see, not ours to paper over.
                (self.record_dir / "config-error.txt").write_text(
                    f"{source} is not readable JSON: {exc}\n", encoding="utf-8"
                )
                config = None
        if not isinstance(config, dict):
            # Nothing to interpose on. The agent runs untouched - which is the
            # transparent thing to do - and `assemble` declares the hole,
            # because no record file will exist and this tool cannot tell an
            # unproxied run from one with no tool calls.
            environment = {**os.environ}
            completed = subprocess.run(command, env=environment, check=False)  # noqa: S603 - the operator's own command
            return completed.returncode

        rewritten = rewrite_config(
            config,
            record_dir=self.record_dir,
            session_id=self.session_id,
            with_content=self.with_content,
        )
        target = self.record_dir / "mcp-config.json"
        target.write_text(json.dumps(rewritten, indent=2, sort_keys=True), encoding="utf-8")

        argv = list(command)
        if argv and Path(argv[0]).stem == "claude" and "--mcp-config" not in argv:
            argv = [argv[0], "--mcp-config", str(target), *argv[1:]]
        environment = {**os.environ, CONFIG_ENV: str(target)}
        completed = subprocess.run(argv, env=environment, check=False)  # noqa: S603 - the operator's own command
        return completed.returncode

    # -- assembling the trace ---------------------------------------------

    def _interposition(self) -> list[Gap]:
        """What the agent was configured with, against what was observed.

        Design note D-261, and it is the invariant of the phase-0.1 verifier
        moved to the capture side: the answer fails closed.

        The rewriter already wrote down every server it could not interpose
        on - and NOTHING READ IT BACK. A run in which the agent talked to an
        HTTP server directly (which is every HTTP server, in this release)
        produced an acta saying `complete: true`, `authenticity: established`,
        `gaps: []`. The hole was on disk, one directory away from the document
        that denied it.

        So the manifest is evidence like everything else: a server it says was
        not interposed is a hole, a server it says was interposed with no
        record file is a hole, and no manifest at all is the biggest of the
        three, because then this tool cannot show it observed anything the
        agent was configured with. `authenticity` and `complete` follow from
        the gaps, so this method is the whole of the fix.

        Interposing on HTTP is phase 1.1b. Until then this is what honest
        looks like: not a smaller claim, a refused one.
        """
        manifest = self.record_dir / MANIFEST
        if not manifest.is_file():
            return [
                Gap(
                    reason=GapReason.NOT_INTERPOSED,
                    detail=(
                        "nothing recorded which MCP servers this session was configured with, "
                        "so this tool cannot show that it observed all of them"
                    ),
                    unanchored=WHOLE_SESSION,
                )
            ]
        try:
            declared = json.loads(manifest.read_text(encoding="utf-8")).get("servers") or {}
        except (OSError, ValueError) as exc:
            return [
                Gap(
                    reason=GapReason.NOT_INTERPOSED,
                    detail=(
                        "the record of which servers this session was configured with could "
                        f"not be read ({failure_kind(exc)}), so this tool cannot show that it "
                        "observed all of them"
                    ),
                    unanchored=WHOLE_SESSION,
                )
            ]

        gaps: list[Gap] = []
        for name in sorted(declared):
            entry = declared[name] if isinstance(declared.get(name), dict) else {}
            ref = str(entry.get("ref") or label_ref(name))
            if not entry.get("interposed"):
                gaps.append(
                    Gap(
                        reason=GapReason.NOT_INTERPOSED,
                        detail=(
                            f"the MCP server {ref} was not interposed on, so the agent "
                            "reached it directly and nothing it did through it was observed "
                            f"({entry.get('why', 'no reason recorded')}). {WHICH_SERVER}"
                        ),
                        unanchored=THROUGH_THIS_SERVER,
                    )
                )
                continue
            record = self.record_dir / str(entry.get("record", ""))
            if not record.is_file():
                gaps.append(
                    Gap(
                        reason=GapReason.PROXY_START_FAILED,
                        detail=(
                            f"a proxy was put in front of the MCP server {ref} and left no "
                            "record at all, so either the agent never reached it or the proxy "
                            f"never ran, and this tool cannot tell which. {WHICH_SERVER}"
                        ),
                        unanchored=THROUGH_THIS_SERVER,
                    )
                )
        return gaps

    def assemble(self, child_returncode: int) -> Trace:
        parts = sorted(path for path in self.record_dir.glob("*.jsonl"))
        events: list[TraceEvent] = []
        gaps: list[Gap] = []
        moments: list[str] = []
        ended: list[bool] = []

        for part in parts:
            rows, unreadable = self._rows(part)
            gaps.extend(unreadable)
            by_name: dict[tuple[str, str], TraceEvent] = {}
            saw_end = False
            for row in rows:
                kind = row.get("kind")
                if kind == "end":
                    saw_end = True
                elif kind == "gap":
                    recorded = row["gap"]
                    gaps.append(
                        Gap(
                            reason=GapReason(recorded["reason"]),
                            detail=f"{part.stem}: {recorded['detail']}",
                            after=recorded.get("after_event"),
                            unanchored=recorded.get("after_index_absent"),
                        )
                    )
                elif kind in {"call", "result"}:
                    event = TraceEvent.from_dict(row["event"])
                    key = (part.stem, str(row["event"]["index"]))
                    if key in by_name:
                        existing = by_name[key]
                        existing.result_sha256 = event.result_sha256
                        existing.error_type = event.error_type
                        existing.result = event.result
                        continue
                    event.index = len(events)
                    by_name[key] = event
                    events.append(event)
                    if event.timestamp:
                        moments.append(event.timestamp)
            ended.append(saw_end)

        gaps.extend(self._interposition())

        trace = Trace(
            session_id=self.session_id,
            source="mcp-proxy",
            capture_level=CaptureLevel.L1,
            agent_name="mcp-proxy",
            started_at=min(moments) if moments else None,
            ended_at=max(moments) if moments else None,
            events=events,
            gaps=gaps,
            end_recorded=bool(parts) and all(ended),
            child_returncode=child_returncode,
        )
        if not parts:
            trace.add_gap(
                GapReason.PROXY_START_FAILED,
                "no proxy recorded anything for this session. Either the agent made no tool "
                "call, or it was never routed through the proxy, and this tool cannot tell "
                "which - so it declares the hole rather than publishing an empty clean trace.",
                unanchored="nothing was observed, so there is no event this sits after",
            )
        trace.note_missing_results()
        return trace

    def _rows(self, part: Path) -> tuple[list[dict[str, Any]], list[Gap]]:
        rows: list[dict[str, Any]] = []
        gaps: list[Gap] = []
        try:
            text = part.read_text(encoding="utf-8")
        except OSError as exc:
            return [], [
                Gap(
                    reason=GapReason.UNPARSABLE_RECORD,
                    detail=(
                        f"the record {part.stem} wrote ({file_ref(part)}) could not be read "
                        f"({failure_kind(exc)}), so nothing that proxy observed survived"
                    ),
                    unanchored="the record file could not be opened, so no event in it was observed",
                )
            ]
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError as exc:
                # A record file cut off mid-write, which is what a killed
                # proxy leaves behind. The events before it are still true.
                gaps.append(
                    Gap(
                        reason=GapReason.UNPARSABLE_RECORD,
                        detail=(
                            f"record {number} of what {part.stem} wrote is not readable "
                            f"({failure_kind(exc)})"
                        ),
                        unanchored=(
                            "the record that will not parse names no call, so there is no "
                            "observed event this sits between"
                        ),
                    )
                )
                continue
            if isinstance(row, dict):
                rows.append(row)
        return rows, gaps
