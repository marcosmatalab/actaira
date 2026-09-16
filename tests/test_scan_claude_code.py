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

from actaira import cli
from actaira.trace import SOURCES, CaptureLevel, reader_for
from actaira.trace.claude_code import ClaudeCodeReader
from actaira.trace.model import GapReason

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
    (trace,) = ClaudeCodeReader(home=home).read_all()

    assert [event.tool_name for event in trace.events] == ["Bash", "Read", "Bash"]
    assert [event.index for event in trace.events] == [0, 1, 2]
    assert trace.session_id == SESSION
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

    assert trace.gaps == []
    assert trace.to_dict()["complete"] is True


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
