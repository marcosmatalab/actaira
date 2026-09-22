"""`seamark watch`: put a proxy between the agent and each of its servers.

Design note D-255. The agent is run unmodified. What changes is the MCP
configuration it is handed: every stdio server becomes the same server behind
`python -m seamark.proxy.stdio`, and every HTTP server becomes a loopback URL
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
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..trace import CaptureLevel
from ..trace.model import Gap, GapReason, Trace, TraceEvent
from ..trace.redact import failure_kind, file_ref, label_ref, new_salt, value_ref
from . import Recorder
from .http import HttpProxy

CONFIG_ENV = "SEAMARK_MCP_CONFIG"
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
    salt: str | None = None,
    run_id: str = "",
) -> dict[str, Any]:
    """The agent's MCP configuration, with a proxy in front of every server."""
    record_dir = Path(record_dir)
    record_dir.mkdir(parents=True, exist_ok=True)
    salt = salt or new_salt()
    servers = config.get("mcpServers")
    if not isinstance(servers, dict):
        _write_manifest(record_dir, {}, salt, run_id, session_id)
        return dict(config)

    rewritten: dict[str, Any] = {}
    interposed: dict[str, Any] = {}
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            rewritten[name] = entry
            interposed[name] = {
                "ref": label_ref(name, salt),
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
                    "-m", "seamark.proxy.stdio",
                    "--record", str(record),
                    "--server", name,
                    "--session", session_id,
                    # The salt and the run id go the same way and for the same
                    # reason as `--with-content`: the proxies are separate
                    # processes and this is the only channel they hear about
                    # the session on. The salt is an operator-side secret that
                    # never enters a document, so passing it here keeps every
                    # proxy referencing the same file the same way.
                    "--salt", salt,
                    "--run", run_id,
                    *(["--with-content"] if with_content else []),
                    "--", *original,
                ],
            }
            interposed[name] = {
                "ref": label_ref(name, salt), "interposed": True, "record": record.name,
                "references": record.with_suffix(".refs.json").name,
            }
        elif isinstance(entry.get("url"), str) and http_port_for is not None:
            rewritten[name] = {**entry, "url": f"http://127.0.0.1:{http_port_for(name)}/mcp"}
            interposed[name] = {
                "ref": label_ref(name, salt), "interposed": True, "record": record.name,
                "references": record.with_suffix(".refs.json").name,
            }
        else:
            rewritten[name] = entry
            interposed[name] = {
                "ref": label_ref(name, salt),
                "interposed": False,
                "why": (
                    "this server was given in a shape the rewriter does not know how to get "
                    "in front of, so the agent reached it directly"
                ),
            }

    _write_manifest(record_dir, interposed, salt, run_id, session_id)
    return {**config, "mcpServers": rewritten}


def _write_manifest(
    record_dir: Path,
    interposed: dict[str, Any],
    salt: str,
    run_id: str,
    session_id: str = "",
) -> None:
    """Written every time, including when everything was interposed.

    A manifest that only appears when something went wrong is a manifest whose
    absence means two things, and `assemble` has to be able to tell them apart.

    It holds the only alias-to-reference map there is, and the salt that map is
    computed under. Both live here, beside the records on the operator's own
    machine, and NEITHER ever enters an emitted document - see `redact.label_ref`
    for why the alias does not travel and D-263 for why an unsalted reference to
    it was not a redaction.
    """
    (record_dir / MANIFEST).write_text(
        json.dumps(
            {
                "servers": interposed,
                "redaction_salt": salt,
                "run_id": run_id,
                # The session id is referenced in the document like every other
                # third-party value (D-268), so the pair that resolves it lives
                # here with the alias map rather than nowhere.
                "references": (
                    {value_ref(session_id, salt): session_id} if session_id else {}
                ),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


class WatchSession:
    """One `watch` run: the child, its proxies, and the trace they produce."""

    def __init__(
        self,
        record_dir: Path,
        session_id: str,
        with_content: bool = False,
        salt: str | None = None,
        run_id: str | None = None,
    ) -> None:
        self.record_dir = Path(record_dir)
        self.session_id = session_id
        self.with_content = with_content
        self.salt = salt or new_salt()
        # What identifies THIS run's records among whatever else is in the
        # directory. A uuid rather than the session id because a caller may
        # reuse a session id and a directory must never be read as this run's
        # when it is last week's - see D-266.
        self.run_id = run_id or uuid.uuid4().hex

    # -- running the agent ------------------------------------------------

    def run(self, command: list[str], config_path: Path | None) -> int:
        """Run the agent's own command with a rewritten configuration.

        The path is exported as `SEAMARK_MCP_CONFIG` for any agent, and passed
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

        listeners = self._listen_for_http(config)
        try:
            rewritten = rewrite_config(
                config,
                record_dir=self.record_dir,
                http_port_for=(lambda name: listeners[name].address[1]) if listeners else None,
                session_id=self.session_id,
                with_content=self.with_content,
                salt=self.salt,
                run_id=self.run_id,
            )
            target = self.record_dir / "mcp-config.json"
            target.write_text(json.dumps(rewritten, indent=2, sort_keys=True), encoding="utf-8")

            argv = list(command)
            if argv and Path(argv[0]).stem == "claude" and "--mcp-config" not in argv:
                argv = [argv[0], "--mcp-config", str(target), *argv[1:]]
            environment = {**os.environ, CONFIG_ENV: str(target)}
            completed = subprocess.run(argv, env=environment, check=False)  # noqa: S603 - the operator's own command
            return completed.returncode
        finally:
            # Closing each listener also closes its recorder, which is what
            # writes the `end` row the assembled trace reads completeness from.
            for proxy in listeners.values():
                proxy.close()

    def _listen_for_http(self, config: dict[str, Any]) -> dict[str, HttpProxy]:
        """One loopback endpoint per remote server, bound before the rewrite.

        Design note D-265. This is the caller `http_port_for` never had: the
        argument existed, one test passed it, and production did not - so every
        remote MCP server in every real session was reached by the agent
        directly. Binding happens first because the rewritten URL has to name a
        port that already exists.

        A server whose listener will not bind is left unrewritten on purpose.
        The agent then reaches it directly, which keeps the agent working, and
        `_interposition` finds no record for it and declares the hole. Pointing
        the agent at a socket that is not there would break the run instead.
        """
        servers = config.get("mcpServers")
        if not isinstance(servers, dict):
            return {}
        listeners: dict[str, HttpProxy] = {}
        for name, entry in servers.items():
            if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
                continue
            recorder = Recorder(
                session_id=self.session_id,
                record_path=self.record_dir / f"{name}.jsonl",
                with_content=self.with_content,
                salt=self.salt,
                run_id=self.run_id,
            )
            proxy = HttpProxy(entry["url"], recorder, listen=True)
            if proxy.start():
                listeners[name] = proxy
            else:
                proxy.close()
        return listeners

    # -- assembling the trace ---------------------------------------------

    def _manifest(self) -> tuple[dict[str, Any] | None, str | None, str | None]:
        """`(servers, salt, run id)` as the rewriter recorded them, or Nones.

        The salt is read back rather than taken from `self` because a
        `WatchSession` built only to assemble a directory somebody else
        recorded holds a salt of its own that would reference the same files
        under different names.
        """
        manifest = self.record_dir / MANIFEST
        if not manifest.is_file():
            return None, None, None
        try:
            document = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None, None, None
        if not isinstance(document, dict):
            return None, None, None
        servers = document.get("servers")
        return (
            servers if isinstance(servers, dict) else {},
            document.get("redaction_salt") or None,
            document.get("run_id") or None,
        )

    def _interposition(self, declared: dict[str, Any] | None, salt: str | None) -> list[Gap]:
        """What the agent was configured with, against what was observed.

        Design note D-261, and it is the invariant of the phase-0.1 verifier
        moved to the capture side: the answer fails closed.

        The rewriter already wrote down every server it could not interpose
        on - and NOTHING READ IT BACK. A run in which the agent talked to an
        HTTP server directly produced an acta saying `complete: true`,
        `authenticity: established`, `gaps: []`. The hole was on disk, one
        directory away from the document that denied it.

        So the manifest is evidence like everything else: a server it says was
        not interposed is a hole, a server it says was interposed with no
        record file is a hole, and no manifest at all is the biggest of the
        three, because then this tool cannot show it observed anything the
        agent was configured with. `authenticity` and `complete` follow from
        the gaps, so this method is the whole of the fix.
        """
        if declared is None:
            return [
                Gap(
                    reason=GapReason.NOT_INTERPOSED,
                    detail=(
                        "nothing readable recorded which MCP servers this session was "
                        "configured with, so this tool cannot show that it observed all of them"
                    ),
                    unanchored=WHOLE_SESSION,
                )
            ]

        gaps: list[Gap] = []
        for name in sorted(declared):
            entry = declared[name] if isinstance(declared.get(name), dict) else {}
            ref = str(entry.get("ref") or label_ref(name, salt))
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
        declared, manifest_salt, manifest_run = self._manifest()
        salt = manifest_salt
        run_id = manifest_run
        parts = sorted(path for path in self.record_dir.glob("*.jsonl"))
        gaps: list[Gap] = []
        # `(timestamp, part, position within the part, event)`, so the order
        # the document is written in comes from what the records say about
        # themselves rather than from what the files happen to be called.
        placed: list[tuple[str, str, int, TraceEvent]] = []
        inventory: dict[str, dict[str, Any]] = {}
        ended: list[bool] = []
        read_any = False

        for part in parts:
            rows, unreadable, foreign = self._rows(part, run_id, salt)
            gaps.extend(unreadable)
            if foreign is not None:
                gaps.append(foreign)
                continue
            read_any = True
            by_name: dict[str, TraceEvent] = {}
            saw_end = False
            for position, row in enumerate(rows):
                kind = row.get("kind")
                if kind == "end":
                    saw_end = True
                elif kind == "discover":
                    entry = inventory.setdefault(part.stem, {"tools": [], "revisions": []})
                    entry["tools"] = sorted(set(entry["tools"]) | set(row.get("tools") or []))
                    if row.get("protocol_version"):
                        entry["revisions"] = sorted(
                            set(entry["revisions"]) | {row["protocol_version"]}
                        )
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
                    key = str(row["event"]["index"])
                    if key in by_name:
                        existing = by_name[key]
                        existing.result_sha256 = event.result_sha256
                        existing.error_type = event.error_type
                        existing.result = event.result
                        existing.result_type = event.result_type
                        existing.result_type_assumed = event.result_type_assumed
                        existing.request_state = event.request_state
                        existing.server = event.server
                        existing.protocol_version = (
                            existing.protocol_version or event.protocol_version
                        )
                        continue
                    by_name[key] = event
                    placed.append((event.timestamp or "", part.stem, position, event))
            ended.append(saw_end)

        events, order_gaps = self._ordered(placed)
        gaps.extend(order_gaps)
        gaps.extend(self._interposition(declared, salt))
        gaps.extend(self._inventory_gaps(declared, salt, inventory))

        moments = [event.timestamp for event in events if event.timestamp]
        trace = Trace(
            # Referenced, not written: the id may have come from whoever
            # invoked this, and D-268 does not make an exception for a field
            # because it is usually ours.
            session_id=value_ref(self.session_id, salt) or "",
            source="mcp-proxy",
            capture_level=CaptureLevel.L1,
            agent_name="mcp-proxy",
            started_at=min(moments) if moments else None,
            ended_at=max(moments) if moments else None,
            events=events,
            gaps=gaps,
            end_recorded=read_any and all(ended),
            child_returncode=child_returncode,
            mcp={
                "servers": [
                    {
                        "ref": self._ref_for(name, declared, salt),
                        "tools_advertised": entry["tools"],
                        "protocol_revisions_advertised": entry["revisions"],
                    }
                    for name, entry in sorted(inventory.items())
                ],
            },
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

    # -- order, identity and provenance of the records --------------------

    @staticmethod
    def _ref_for(name: str, declared: dict[str, Any] | None, salt: str | None) -> str:
        entry = (declared or {}).get(name)
        if isinstance(entry, dict) and entry.get("ref"):
            return str(entry["ref"])
        return label_ref(name, salt)

    def _ordered(
        self, placed: list[tuple[str, str, int, TraceEvent]]
    ) -> tuple[list[TraceEvent], list[Gap]]:
        """The events in the order the records claim, and a hole where they do not.

        Design note D-266, second half. The order used to come from
        `sorted(glob("*.jsonl"))`: a server called `alpha` came before one
        called `zeta` because of its NAME, and the document then published that
        as the order in which the agent did things. Identity, never position -
        the same rule as D-258, applied to the sequence rather than to one
        citation.

        So the key is the timestamp each record carries. The part name and the
        position within it break ties only so that the document is byte-stable
        for one input, never as a claim: whenever a tie is broken between two
        DIFFERENT parts, or an event carries no timestamp at all, the order
        between them was not observed and a hole says so.
        """
        ordered = sorted(placed, key=lambda row: (row[0], row[1], row[2]))
        gaps: list[Gap] = []
        undated = [row for row in ordered if not row[0]]
        if undated:
            gaps.append(
                Gap(
                    reason=GapReason.ORDER_NOT_OBSERVED,
                    detail=(
                        f"{len(undated)} of the records assembled here carry no moment of "
                        "their own, so where they sit among the rest is this tool's "
                        "arrangement and not an observation"
                    ),
                    unanchored=WHOLE_SESSION,
                )
            )
        for earlier, later in zip(ordered, ordered[1:], strict=False):
            if earlier[0] and earlier[0] == later[0] and earlier[1] != later[1]:
                gaps.append(
                    Gap(
                        reason=GapReason.ORDER_NOT_OBSERVED,
                        detail=(
                            "two calls observed through different servers carry the same "
                            "moment, so which of them happened first was not observed and "
                            "the order they appear in here is arbitrary"
                        ),
                        unanchored=WHOLE_SESSION,
                    )
                )
                break
        events = []
        for index, row in enumerate(ordered):
            row[3].index = index
            events.append(row[3])
        return events, gaps

    def _inventory_gaps(
        self,
        declared: dict[str, Any] | None,
        salt: str | None,
        inventory: dict[str, dict[str, Any]],
    ) -> list[Gap]:
        """A server whose tool inventory was never observed says so.

        SEP-2575 makes `server/discover` mandatory FOR THE SERVER, not for the
        client, so a run in which the agent never asked leaves this tool with
        no record of what existed at the time. That is the input the contract
        deriver needs, so its absence is a hole rather than an empty list.
        """
        gaps: list[Gap] = []
        for name in sorted(declared or {}):
            entry = (declared or {})[name]
            if not isinstance(entry, dict) or not entry.get("interposed"):
                continue
            if name in inventory:
                continue
            gaps.append(
                Gap(
                    reason=GapReason.DISCOVER_UNAVAILABLE,
                    detail=(
                        f"no server/discover result was observed for the MCP server "
                        f"{self._ref_for(name, declared, salt)}, so what tools it offered at "
                        f"the moment of this run was not observed. {WHICH_SERVER}"
                    ),
                    unanchored=THROUGH_THIS_SERVER,
                )
            )
        return gaps

    def _rows(
        self, part: Path, run_id: str | None, salt: str | None
    ) -> tuple[list[dict[str, Any]], list[Gap], Gap | None]:
        """Every readable row this run wrote into one part.

        The third member is set when the part belongs to somebody else's run.
        Design note D-266: `assemble` read whatever `*.jsonl` was in the
        directory, so a previous watch that left its records there contributed
        its calls to this session's acta as though the agent had just made
        them. A directory is not an identity; the run id each row carries is.
        """
        gaps: list[Gap] = []
        try:
            text = part.read_text(encoding="utf-8")
        except OSError as exc:
            return [], [
                Gap(
                    reason=GapReason.UNPARSABLE_RECORD,
                    detail=(
                        f"the record {part.stem} wrote ({file_ref(part, salt)}) could not be "
                        f"read ({failure_kind(exc)}), so nothing that proxy observed survived"
                    ),
                    unanchored="the record file could not be opened, so no event in it was observed",
                )
            ], None
        rows: list[dict[str, Any]] = []
        foreign = 0
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
            if not isinstance(row, dict):
                continue
            if run_id is not None and row.get("run") != run_id:
                foreign += 1
                continue
            rows.append(row)
        if foreign and not rows:
            return [], gaps, Gap(
                reason=GapReason.FOREIGN_RECORDS,
                detail=(
                    f"the record file {file_ref(part, salt)} holds {foreign} record(s) that "
                    "this run did not write, and none that it did. They were not read into "
                    "this trace: a directory is not an identity, and another run's calls are "
                    "not this session's evidence"
                ),
                unanchored=WHOLE_SESSION,
            )
        if foreign:
            gaps.append(
                Gap(
                    reason=GapReason.FOREIGN_RECORDS,
                    detail=(
                        f"the record file {file_ref(part, salt)} holds {foreign} record(s) "
                        "that this run did not write, mixed in with records that it did. The "
                        "foreign ones were not read into this trace"
                    ),
                    unanchored=WHOLE_SESSION,
                )
            )
        return rows, gaps, None
