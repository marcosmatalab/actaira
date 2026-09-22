"""Reading what Claude Code already wrote, and refusing to read more into it.

This is the L0 path: transcripts the audited agent produced about itself,
sitting on disk because it put them there. Nothing is installed, nothing is
intercepted, and nothing that comes out of here is evidence - which is a
statement the command has to make on the screen and not only in a document.

The reader is written against a real corpus and against the fact that the
format is Anthropic's internal one: eleven Claude Code versions appear in the
transcripts of a single machine. So every field is optional until proven
otherwise, a line that will not parse is a recorded gap rather than a crash,
and the versions the file was written by travel in the trace.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from seamark import cli
from seamark.trace import SOURCES, CaptureLevel, reader_for
from seamark.trace.claude_code import ClaudeCodeReader
from seamark.trace.model import GapReason

SESSION = "3fa85f64-5717-4562-b3fc-2c963f66afa6"


def _assistant(index: int, name: str, arguments: dict, version: str = "2.1.268") -> dict:
    return {
        "type": "assistant",
        "uuid": f"11111111-0000-4000-8000-{index:012d}",
        "parentUuid": None if index == 0 else f"22222222-0000-4000-8000-{index - 1:012d}",
        "sessionId": SESSION,
        "timestamp": f"2026-02-03T10:00:{index:02d}.000Z",
        "cwd": "/w/ledger",
        "gitBranch": "main",
        "version": version,
        "isSidechain": False,
        "message": {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "thinking about it"},
                {
                    "type": "tool_use",
                    "id": f"toolu_{index:016d}",
                    "name": name,
                    "input": arguments,
                    "caller": {"type": "direct"},
                },
            ],
        },
    }


def _result(index: int, content: str, is_error: bool = False) -> dict:
    return {
        "type": "user",
        "uuid": f"22222222-0000-4000-8000-{index:012d}",
        "parentUuid": f"11111111-0000-4000-8000-{index:012d}",
        "sessionId": SESSION,
        "timestamp": f"2026-02-03T10:00:{index:02d}.500Z",
        "cwd": "/w/ledger",
        "version": "2.1.268",
        "message": {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": f"toolu_{index:016d}",
                    "content": content,
                    "is_error": is_error,
                }
            ],
        },
        "toolUseResult": {"stdout": content, "stderr": "", "interrupted": False},
    }


def _write(home: Path, lines: list[dict], project: str = "-w-ledger") -> Path:
    directory = home / "projects" / project
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{SESSION}.jsonl"
    path.write_text(
        "\n".join(json.dumps(line, ensure_ascii=False) for line in lines) + "\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def home(tmp_path: Path) -> Path:
    _write(
        tmp_path / ".claude",
        [
            _assistant(0, "Bash", {"command": "git status", "description": "status"}),
            _result(0, "On branch main"),
            _assistant(1, "Read", {"file_path": "/w/ledger/pyproject.toml"}, version="2.1.252"),
            _result(1, "[project]"),
            _assistant(2, "Bash", {"command": "false", "description": "fail"}),
            _result(2, "exit 1", is_error=True),
        ],
    )
    return tmp_path / ".claude"


# ---------------------------------------------------------------------------
# Gate 1: the reader reads what is really on disk
# ---------------------------------------------------------------------------


def test_every_tool_call_becomes_one_event_in_file_order(home):
    reader = ClaudeCodeReader(home=home)
    (trace,) = reader.read_all()

    assert [event.tool_name for event in trace.events] == ["Bash", "Read", "Bash"]
    assert [event.index for event in trace.events] == [0, 1, 2]
    # The id the transcript declared is a string the audited agent wrote, so
    # the document carries a reference to it and the reader's own map resolves
    # it - D-268. The operator reads it out of `index.json`; here, off the
    # reader that minted it.
    assert trace.session_id != SESSION
    assert reader.refs.map[trace.session_id] == SESSION
    assert trace.capture_level is CaptureLevel.L0


def test_a_tool_result_is_matched_to_its_call_by_id(home):
    (trace,) = ClaudeCodeReader(home=home).read_all()

    assert all(event.result_sha256 is not None for event in trace.events)
    assert trace.events[2].error_type == "tool_error"
    assert trace.events[0].error_type is None


def test_the_claude_code_versions_the_file_was_written_by_travel_in_the_trace(home):
    """Anthropic says the format is internal and changes between versions, and
    a single machine's transcripts carry eleven of them. A trace that does not
    say which version wrote the bytes it was derived from cannot be re-read
    honestly later."""
    (trace,) = ClaudeCodeReader(home=home).read_all()

    assert trace.agent_versions == ("2.1.252", "2.1.268")


def test_the_reader_reports_the_sessions_it_found_and_their_date_range(home):
    summary = ClaudeCodeReader(home=home).summary()

    assert summary.sessions == 1
    assert summary.first == "2026-02-03T10:00:00.000Z"
    assert summary.last == "2026-02-03T10:00:02.500Z"


def test_the_config_directory_environment_variable_is_honoured(tmp_path, monkeypatch, home):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home))

    assert ClaudeCodeReader().home == home


# ---------------------------------------------------------------------------
# Tolerance: the format is somebody else's and it moves
# ---------------------------------------------------------------------------


def test_a_line_that_will_not_parse_is_a_recorded_gap_and_not_a_crash(tmp_path):
    home = tmp_path / ".claude"
    path = _write(home, [_assistant(0, "Bash", {"command": "ls"}), _result(0, "a")])
    path.write_text(path.read_text(encoding="utf-8") + "{not json\n", encoding="utf-8")

    (trace,) = ClaudeCodeReader(home=home).read_all()

    assert trace.gaps, "an unreadable line vanished instead of being declared"
    assert trace.gaps[0].reason is GapReason.UNPARSABLE_RECORD
    assert trace.to_dict()["complete"] is False


def test_the_older_top_level_tool_use_shape_is_read_too(tmp_path):
    """Two shapes, because the format is not ours. Older builds wrote the tool
    call as its own line; current ones nest it in `message.content`."""
    home = tmp_path / ".claude"
    _write(
        home,
        [
            {
                "type": "tool_use",
                "id": "toolu_0000000000000000",
                "name": "Bash",
                "input": {"command": "ls"},
                "sessionId": SESSION,
                "timestamp": "2026-02-03T10:00:00.000Z",
                "version": "2.0.1",
            }
        ],
    )

    (trace,) = ClaudeCodeReader(home=home).read_all()

    assert [event.tool_name for event in trace.events] == ["Bash"]


def test_a_call_whose_result_never_arrived_is_a_gap(tmp_path):
    home = tmp_path / ".claude"
    _write(home, [_assistant(0, "Bash", {"command": "sleep 900"})])

    (trace,) = ClaudeCodeReader(home=home).read_all()

    assert trace.events[0].result_sha256 is None
    assert any(gap.reason is GapReason.RESULT_NOT_RECORDED for gap in trace.gaps)
    assert trace.to_dict()["complete"] is False


def test_a_line_missing_every_optional_field_still_yields_an_event(tmp_path):
    home = tmp_path / ".claude"
    _write(
        home,
        [
            {
                "type": "assistant",
                "message": {"content": [{"type": "tool_use", "id": "t0", "name": "Glob"}]},
            }
        ],
    )

    (trace,) = ClaudeCodeReader(home=home).read_all()

    assert trace.events[0].tool_name == "Glob"
    assert trace.events[0].timestamp is None


def test_a_sidechain_turn_is_marked_as_one(tmp_path):
    """A subagent's calls are the agent's calls, and which they were is a fact
    the transcript records. Dropping it would make a trace claim a flatter
    execution than the one that happened."""
    home = tmp_path / ".claude"
    line = _assistant(0, "Bash", {"command": "ls"})
    line["isSidechain"] = True
    _write(home, [line, _result(0, "a")])

    (trace,) = ClaudeCodeReader(home=home).read_all()

    assert trace.events[0].sidechain is True


def test_a_subagents_calls_are_folded_into_the_session_that_launched_it(tmp_path):
    """The hole a real corpus found, and the reason this test exists.

    A sub-agent's calls are not in the session file. They go to
    `<session-id>/subagents/**/*.jsonl` beside it, and on the machine this was
    written on that is 388 files against 32. Reading only the session file
    produced a trace that said an agent had done a twentieth of what it did and
    was silent about the rest - a complete-looking trace of an incomplete read,
    which is the one outcome this phase exists to prevent.
    """
    home = tmp_path / ".claude"
    session = _write(home, [_assistant(0, "Task", {"prompt": "audit it"}), _result(0, "done")])
    nested = session.parent / session.stem / "subagents" / "workflows" / "wf_1"
    nested.mkdir(parents=True)
    child = _assistant(5, "Grep", {"pattern": "rate"})
    child["isSidechain"] = True
    child["timestamp"] = "2026-02-03T10:00:01.000Z"
    answer = _result(5, "src/rates.py:7")
    answer["timestamp"] = "2026-02-03T10:00:01.500Z"
    (nested / "agent-abc.jsonl").write_text(
        "\n".join(json.dumps(line) for line in (child, answer)) + "\n", encoding="utf-8"
    )

    (trace,) = ClaudeCodeReader(home=home).read_all()

    assert [event.tool_name for event in trace.events] == ["Task", "Grep"]
    assert trace.events[1].sidechain is True
    assert trace.events[1].result_sha256 is not None


def test_the_merged_events_are_ordered_by_when_they_happened(tmp_path):
    """Ordered by the execution rather than by the filesystem, and the same
    twice: the index is what a rule cites, so it cannot depend on a glob."""
    home = tmp_path / ".claude"
    session = _write(home, [_assistant(9, "Bash", {"command": "last"})])
    nested = session.parent / session.stem / "subagents"
    nested.mkdir(parents=True)
    early = _assistant(1, "Read", {"file_path": "/w/a"})
    early["isSidechain"] = True
    (nested / "agent-zzz.jsonl").write_text(json.dumps(early) + "\n", encoding="utf-8")

    first = [event.tool_name for event in ClaudeCodeReader(home=home).read_all()[0].events]
    second = [event.tool_name for event in ClaudeCodeReader(home=home).read_all()[0].events]

    assert first == ["Read", "Bash"], "the earlier call sorted after the later one"
    assert first == second


def test_a_sidecar_directory_that_is_not_a_transcript_is_left_alone(tmp_path):
    """`tool-results/` holds `.txt` and `memory/` holds `.md`. Reading those as
    transcripts would fill the trace with gaps that describe nothing that
    happened, which is its own kind of dishonesty."""
    home = tmp_path / ".claude"
    session = _write(home, [_assistant(0, "Bash", {"command": "ls"}), _result(0, "a")])
    sidecar = session.parent / session.stem / "tool-results"
    sidecar.mkdir(parents=True)
    (sidecar / "bzm1w2cs6.txt").write_text("not json at all\n", encoding="utf-8")

    (trace,) = ClaudeCodeReader(home=home).read_all()

    # No gap ABOUT THE SIDECAR, which is what this test is for. The trace is
    # still incomplete, because no L0 trace can be complete - see
    # `test_a_transcript_never_says_the_session_ended`.
    assert [gap["reason"] for gap in trace.to_dict()["gaps"]] == [
        GapReason.END_NOT_RECORDED.value
    ]


def test_what_the_transcript_does_not_record_is_declared_as_a_blind_spot(home):
    """Per-call permission decisions are not in the file - only the session's
    mode is. Never infer the unobserved: the trace says the question is not
    answerable at this level rather than leaving a reader to assume it was."""
    (trace,) = ClaudeCodeReader(home=home).read_all()

    spots = {spot["what"] for spot in trace.to_dict()["blind_spots"]}

    assert any("permission" in what for what in spots)


# ---------------------------------------------------------------------------
# The source interface the other two agents will arrive through
# ---------------------------------------------------------------------------


def test_the_registry_names_claude_code_and_declares_the_two_not_written_yet():
    assert reader_for("claude-code") is ClaudeCodeReader
    for name in ("cursor", "cline"):
        assert name in SOURCES, f"{name} is not even declared"
        with pytest.raises(NotImplementedError, match=name):
            reader_for(name)


# ---------------------------------------------------------------------------
# Gate 1 and 2, through the command
# ---------------------------------------------------------------------------


def test_scan_prints_the_session_count_and_the_date_range(home, capsys, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home))

    assert cli.main(["scan"]) == cli.EXIT_OK

    printed = capsys.readouterr().out
    assert "1" in printed
    assert "2026-02-03" in printed


def test_scan_says_on_screen_that_an_l0_trace_is_not_evidence(home, capsys, monkeypatch):
    """The honesty of the whole command is this sentence, and a sentence that
    only appears in the documentation is one nobody reading the output sees."""
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home))

    cli.main(["scan"])

    printed = capsys.readouterr().out.lower()
    assert "l0" in printed
    assert "not evidence" in printed or "diagnosis" in printed


def test_scan_demo_needs_no_agent_installed(tmp_path, capsys, monkeypatch):
    """Gate 2: a machine with nothing installed, which is what an empty home
    directory is."""
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "nothing-here"))

    assert cli.main(["scan", "--demo"]) == cli.EXIT_OK

    assert "demo" in capsys.readouterr().out.lower()


def test_scan_writes_the_traces_when_asked_where(home, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home))
    out = tmp_path / "traces"

    assert cli.main(["scan", "--out", str(out)]) == cli.EXIT_OK

    written = sorted(out.glob("*.json"))
    assert written
    document = json.loads(written[0].read_text(encoding="utf-8"))
    assert document["capture_level"] == "L0"
    assert document["authenticity"]["state"] == "not_evaluated"


def test_scan_on_a_machine_with_no_transcripts_says_so_and_does_not_fail(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "empty"))

    assert cli.main(["scan"]) == cli.EXIT_OK

    assert "0" in capsys.readouterr().out

# ---------------------------------------------------------------------------
# One call is one event, however many times the file records it
# ---------------------------------------------------------------------------


def _result_for(index: int, call_id: str, content: str) -> dict:
    """The matching result, when the call's id has been forced."""
    line = _result(index, content)
    line["message"]["content"][0]["tool_use_id"] = call_id
    return line


def _with_id(line: dict, call_id: str) -> dict:
    """The same turn, with its tool_use id forced - which is what compaction
    and resume do when they write a message back into the file."""
    copied = json.loads(json.dumps(line))
    for block in copied["message"]["content"]:
        if block.get("type") == "tool_use":
            block["id"] = call_id
    return copied


def test_a_call_the_transcript_records_twice_is_one_event(tmp_path):
    """Claude Code rewrites messages: compaction and resume put the same
    `tool_use` block back into the file with the same id, so a call that
    happened once was published twice - each copy fully resulted, and
    indistinguishable from a real repeat.

    The proportion this reached on a real corpus is in the commit that made
    the change and not here: it came from one person's private transcripts and
    no command in this repository can re-measure it.
    """
    home = tmp_path / ".claude"
    call = _with_id(_assistant(0, "Bash", {"command": "ls"}), "toolu_same")
    _write(home, [call, _result_for(0, "toolu_same", "a"), call, _result_for(1, "toolu_same", "a")])

    (trace,) = ClaudeCodeReader(home=home).read_all()
    document = trace.to_dict()

    assert [event["gen_ai.tool.name"] for event in document["events"]] == ["Bash"]
    assert document["events"][0]["result_sha256"] is not None
    assert document["duplicate_records_collapsed"] == 1


def test_the_collapsed_records_are_counted_in_the_trace(tmp_path):
    """The collapsed records are not in the document, so a reader cannot
    recover this from what is. It is a fact about the source, which is why it
    travels - and it is not a summary of anything the document already lists."""
    home = tmp_path / ".claude"
    call = _with_id(_assistant(0, "Bash", {"command": "ls"}), "toolu_same")
    _write(home, [call, call, call, _result_for(0, "toolu_same", "a")])

    (trace,) = ClaudeCodeReader(home=home).read_all()

    assert trace.to_dict()["duplicate_records_collapsed"] == 2


def test_a_transcript_with_no_repeats_says_so_rather_than_saying_nothing(tmp_path):
    """Zero is a measurement. Omitting the field would make "nobody counted"
    and "nothing to count" the same document."""
    home = tmp_path / ".claude"
    _write(home, [_assistant(0, "Bash", {"command": "ls"}), _result(0, "a")])

    (trace,) = ClaudeCodeReader(home=home).read_all()

    assert trace.to_dict()["duplicate_records_collapsed"] == 0


def test_two_records_of_one_call_that_disagree_are_a_hole_and_not_a_choice(tmp_path):
    """The source contradicting itself is not a repeat. Keeping either version
    silently would be this tool deciding what happened, which is the second
    negative: it compares what it observed against a norm somebody else wrote,
    and it does not have an opinion about which record is the true one."""
    home = tmp_path / ".claude"
    first = _with_id(_assistant(0, "Bash", {"command": "ls"}), "toolu_same")
    second = _with_id(_assistant(1, "Bash", {"command": "rm -rf /"}), "toolu_same")
    _write(home, [first, second, _result_for(0, "toolu_same", "a")])

    (trace,) = ClaudeCodeReader(home=home).read_all()
    document = trace.to_dict()

    contradictions = [
        gap for gap in document["gaps"]
        if gap["reason"] == GapReason.SOURCE_CONTRADICTION.value
    ]
    assert len(contradictions) == 1
    assert contradictions[0]["after_index"] == 0
    assert document["complete"] is False
    # Neither version's arguments were chosen over the other by being dropped:
    # one event, and the hole says the document does not decide between them.
    assert len(document["events"]) == 1
    assert "does not decide" in contradictions[0]["detail"]


def test_two_results_for_one_call_that_disagree_are_a_hole_too(tmp_path):
    home = tmp_path / ".claude"
    call = _with_id(_assistant(0, "Bash", {"command": "ls"}), "toolu_same")
    _write(home, [call, _result_for(0, "toolu_same", "first"), _result_for(1, "toolu_same", "second")])

    (trace,) = ClaudeCodeReader(home=home).read_all()

    assert any(
        gap["reason"] == GapReason.SOURCE_CONTRADICTION.value
        for gap in trace.to_dict()["gaps"]
    )


# ---------------------------------------------------------------------------
# A hole cites the event it follows, not a line number
# ---------------------------------------------------------------------------


def test_a_hole_cites_an_event_by_identity_and_the_index_follows_the_order(tmp_path):
    """`after_index` was filled with a count of lines parsed so far, and the
    events are re-sorted by timestamp afterwards - so even a correct line
    number would have gone stale. The anchor is the call id; the position is
    resolved against the ordered events when the document is written."""
    home = tmp_path / ".claude"
    _write(home, [
        _assistant(0, "Bash", {"command": "ls"}),
        _result(0, "a"),
        _assistant(1, "Read", {"path": "x"}),
        # no result for the second call: the hole anchors to it
    ])

    (trace,) = ClaudeCodeReader(home=home).read_all()
    document = trace.to_dict()

    (missing,) = [
        gap for gap in document["gaps"]
        if gap["reason"] == GapReason.RESULT_NOT_RECORDED.value
    ]
    assert missing["after_event"] == document["events"][1]["gen_ai.tool.call.id"]
    assert missing["after_index"] == 1


def test_a_hole_with_no_event_to_anchor_to_says_so_instead_of_inventing_one(tmp_path):
    """An unreadable record names no call. `-1` and `len(lines) - 1` both put
    a number there that a reader would follow to an unrelated event."""
    home = tmp_path / ".claude"
    project = home / "projects" / "-w-ledger"
    project.mkdir(parents=True)
    (project / f"{SESSION}.jsonl").write_text(
        "\n".join([
            json.dumps(_assistant(0, "Bash", {"command": "ls"})),
            json.dumps(_result(0, "a")),
            "{ this line is cut off",
        ]) + "\n",
        encoding="utf-8",
    )

    (trace,) = ClaudeCodeReader(home=home).read_all()
    document = trace.to_dict()

    (unparsable,) = [
        gap for gap in document["gaps"]
        if gap["reason"] == GapReason.UNPARSABLE_RECORD.value
    ]
    assert "after_index" not in unparsable
    assert len(unparsable["after_index_absent"]) > 10


@pytest.mark.parametrize("corpus", ["demo", "built"])
def test_no_hole_in_any_emitted_trace_points_outside_the_events(tmp_path, corpus):
    """The property, rather than the three examples above: a cited position
    is a position this document has."""
    from seamark.trace.claude_code import demo_trace

    if corpus == "demo":
        documents = [demo_trace().to_dict()]
    else:
        home = tmp_path / ".claude"
        project = home / "projects" / "-w-ledger"
        project.mkdir(parents=True)
        lines = [
            json.dumps(_assistant(0, "Bash", {"command": "ls"})),
            "not json",
            json.dumps(_result(0, "a")),
            json.dumps(_with_id(_assistant(1, "Read", {"path": "x"}), "toolu_dup")),
            json.dumps(_with_id(_assistant(2, "Read", {"path": "y"}), "toolu_dup")),
            "[]",
            json.dumps(_assistant(3, "Write", {"path": "z"})),
        ]
        (project / f"{SESSION}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
        documents = [trace.to_dict() for trace in ClaudeCodeReader(home=home).read_all()]

    for document in documents:
        assert document["gaps"], "a corpus with no holes proves nothing here"
        for gap in document["gaps"]:
            anchored = "after_index" in gap
            assert anchored != ("after_index_absent" in gap), gap
            if anchored:
                assert 0 <= gap["after_index"] < len(document["events"]), gap


# ---------------------------------------------------------------------------
# A transcript never says the session ended
# ---------------------------------------------------------------------------


def test_a_transcript_never_says_the_session_ended(home):
    """`scan` is built to run over `~/.claude` while the agent is using it, and
    the format has no end-of-session record: surveyed over one machine, the
    last line of a session is `last-prompt`, `mode`, `assistant` or
    `bridge-session` depending on where it stopped, and none of those means
    "ended". This passed `end_recorded=True` and called the files finished."""
    (trace,) = ClaudeCodeReader(home=home).read_all()
    document = trace.to_dict()

    assert document["complete"] is False
    (end,) = [
        gap for gap in document["gaps"]
        if gap["reason"] == GapReason.END_NOT_RECORDED.value
    ]
    assert "records no end of session" in end["detail"]


def test_a_session_the_agent_is_still_writing_to_is_not_a_finished_one(tmp_path):
    """The case the old default got wrong in the field rather than in theory:
    a live session read mid-run came out complete with no holes at all."""
    home = tmp_path / ".claude"
    _write(home, [_assistant(0, "Bash", {"command": "ls"}), _result(0, "a")])

    (trace,) = ClaudeCodeReader(home=home).read_all()

    assert trace.to_dict()["complete"] is False


# ---------------------------------------------------------------------------
# --out writes files, and the count it prints is of files
# ---------------------------------------------------------------------------


def _session_declaring(home: Path, filename: str, declared: str) -> None:
    project = home / "projects" / "-w-ledger"
    project.mkdir(parents=True, exist_ok=True)
    line = _assistant(0, "Bash", {"command": filename})
    line["sessionId"] = declared
    (project / filename).write_text(json.dumps(line) + "\n", encoding="utf-8")


def test_out_writes_one_file_per_session_however_the_transcripts_name_them(tmp_path, capsys, monkeypatch):
    """Three sessions in: two declaring the same id, one declaring a path that
    walks out of the directory. Before this, two files came out, one of them
    OUTSIDE `--out`, and the command said it had written three."""
    home = tmp_path / ".claude"
    _session_declaring(home, "aaaa.jsonl", "shared-id")
    _session_declaring(home, "bbbb.jsonl", "shared-id")
    _session_declaring(home, "cccc.jsonl", "../escaped")
    out = tmp_path / "out"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home))

    code = cli.main(["scan", "--out", str(out)])
    printed = capsys.readouterr().out

    assert code == 0
    traces = sorted(path.name for path in out.glob("*.json") if path.name != "index.json")
    assert len(traces) == 3, traces
    assert not list(tmp_path.glob("*.json")), "a session id walked out of --out"
    assert "3" in printed
    index = json.loads((out / "index.json").read_text(encoding="utf-8"))["sessions"]
    assert sorted(index.values()) == ["../escaped", "shared-id", "shared-id"]
    assert len(set(index)) == 3, "two sessions share a file, so one of them is not there"


def test_a_session_id_that_is_a_path_cannot_name_a_file_outside_the_directory(tmp_path):
    """The traversal on its own, because the test above would also pass if the
    escaping session had simply been dropped."""
    home = tmp_path / ".claude"
    _session_declaring(home, "cccc.jsonl", "../../../etc/passwd")
    out = tmp_path / "nested" / "out"

    written = cli._write_traces(ClaudeCodeReader(home=home).read_all(), out)

    assert len(written) == 1
    assert written[0].parent == out
