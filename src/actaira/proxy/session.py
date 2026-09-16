"""`actaira watch`: put a proxy between the agent and each of its servers.

Design note D-255. The agent is run unmodified. What changes is the MCP
configuration it is handed: every stdio server becomes the same server behind
`python -m actaira.proxy.stdio`, and every HTTP server becomes a loopback URL
this process answers on. One proxy per server, one record file each, and one
trace assembled from the lot when the agent exits.

Three decisions worth the lines:

**A server shape the rewriter does not understand is passed through and
DECLARED.** Rewriting it wrongly would break the agent; dropping it quietly
would leave the agent talking to it directly with the trace saying nothing.
So it goes through untouched and `uninterposed.json` names it, which is what
turns an unseen server into a written-down limit of the session.

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

CONFIG_ENV = "ACTAIRA_MCP_CONFIG"


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
    uninterposed: list[str] = []
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            rewritten[name] = entry
            uninterposed.append(name)
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
        elif isinstance(entry.get("url"), str) and http_port_for is not None:
            rewritten[name] = {**entry, "url": f"http://127.0.0.1:{http_port_for(name)}/mcp"}
        else:
            rewritten[name] = entry
            uninterposed.append(name)

    if uninterposed:
        (record_dir / "uninterposed.json").write_text(
            json.dumps(
                {
                    "servers": sorted(uninterposed),
                    "why": (
                        "this rewriter did not recognise the shape of these entries, so the "
                        "agent talked to them directly and nothing it did through them was "
                        "observed. Declared rather than dropped."
                    ),
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
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
                    gaps.append(
                        Gap(
                            after_index=len(events) - 1,
                            reason=GapReason(row["gap"]["reason"]),
                            detail=f"{part.stem}: {row['gap']['detail']}",
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
                after_index=-1,
            )
        trace.note_missing_results()
        return trace

    def _rows(self, part: Path) -> tuple[list[dict[str, Any]], list[Gap]]:
        rows: list[dict[str, Any]] = []
        gaps: list[Gap] = []
        try:
            text = part.read_text(encoding="utf-8")
        except OSError as exc:
            return [], [Gap(-1, GapReason.UNPARSABLE_RECORD, f"{part.name} could not be read: {exc}")]
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
                        after_index=len(rows) - 1,
                        reason=GapReason.UNPARSABLE_RECORD,
                        detail=f"line {number} of {part.name} is not readable: {exc}",
                    )
                )
                continue
            if isinstance(row, dict):
                rows.append(row)
        return rows, gaps
