"""The privacy boundary, as a property over a corpus rather than an example.

`actaira scan` reads files full of somebody's conversations, their home
directory and, sooner or later, their secrets. So the emitted trace carries
digests of arguments and results and not the arguments themselves, and the
guard on that is not "we remembered to hash it here": it is a corpus of
transcripts with secrets planted on purpose, and the assertion that none of
them survives into any emitted document by any route - not in an argument, not
in a result, not in an error message, not in a path, not in a gap's detail.

Gate 6 is the shape of it and gate 9 is the corpus. They are one file because
they are one property about one module; splitting them would let half of it go
green and read as the whole.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from actaira.trace import CaptureLevel
from actaira.trace.claude_code import ClaudeCodeReader

# Every seeded secret is a sentinel: it is planted in the input so the property
# below can assert it never comes out. `redact.py` digests everything and matches
# no patterns, so none of these has to be shaped like a real provider's
# credential, and none of them is. Do not restore a realistic prefix here to make
# the corpus look more lifelike: push protection reads a test fixture the same as
# a leak and refuses the whole repository, which is how this note came to be
# written. What the corpus does need is the separators - the newline, the `=`,
# the `/`, the backslash - because `fragments` splits on them and `forms`
# escapes them.
SECRETS = {
    "opaque api key": "FAKE-NOT-A-REAL-KEY-nor-was-this-one",
    "access key id": "FAKEACCESSKEYIDNOTREAL",
    "secret access key": "fakeSecretAccessKeyNotReal/alsoNotRealEither",
    "forge token": "fake_token_not_real_and_never_was",
    "postgres connection string": "postgresql://dbuser:hunter2@db.internal.example:5432/payroll",
    "dotenv body": "EXAMPLE_SECRET=fake-not-a-real-secret-value\nDEBUG=0",
    "private home path": "/home/aurelia.quintero/projects/ledger/.ssh/id_ed25519",
    "windows home path": "C:\\Users\\aurelia.quintero\\Desktop\\payroll\\.env",
    "bearer header": "Authorization: Bearer fake-not-a-real-bearer-token",
    "private key block": "-----BEGIN FAKE FIXTURE BLOCK-----\nbm90LWEtcmVhbC1rZXktZml4dHVyZQ==\n",
}


def _line(index: int, secret: str) -> dict:
    """One assistant turn calling a tool, with the secret in the arguments."""
    return {
        "type": "assistant",
        "uuid": f"11111111-0000-4000-8000-{index:012d}",
        "parentUuid": None,
        "sessionId": "aaaaaaaa-0000-4000-8000-000000000001",
        "timestamp": f"2026-01-01T00:00:{index:02d}.000Z",
        "cwd": "/home/aurelia.quintero/projects/ledger",
        "gitBranch": "main",
        "version": "2.1.268",
        "isSidechain": False,
        "message": {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": f"toolu_{index:016d}",
                    "name": "Bash",
                    "input": {"command": f"echo {secret}", "description": "leak it"},
                }
            ],
        },
    }


def _result_line(index: int, secret: str) -> dict:
    """The matching result, with the secret in the output too."""
    return {
        "type": "user",
        "uuid": f"22222222-0000-4000-8000-{index:012d}",
        "parentUuid": f"11111111-0000-4000-8000-{index:012d}",
        "sessionId": "aaaaaaaa-0000-4000-8000-000000000001",
        "timestamp": f"2026-01-01T00:00:{index:02d}.500Z",
        "cwd": "/home/aurelia.quintero/projects/ledger",
        "version": "2.1.268",
        "message": {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": f"toolu_{index:016d}",
                    "content": f"{secret}\n",
                    "is_error": False,
                }
            ],
        },
        "toolUseResult": {"stdout": secret, "stderr": "", "interrupted": False},
    }


def forms(secret: str) -> set[str]:
    """A secret as it can appear in text: literally, and JSON-escaped.

    A planted `.env` body travels through a JSONL file with its newline
    written as two characters, so searching for the literal string alone would
    pass over a reader that published the whole line. Both forms are searched
    for, which is also why the plant assertion below accepts either.
    """
    return {secret, json.dumps(secret)[1:-1]}


def fragments(secret: str) -> list[str]:
    """The parts of a secret long enough that finding one is finding it."""
    pieces: list[str] = []
    for form in forms(secret):
        for piece in re.split(r"[\s/\\=:@]+", form):
            if len(piece) >= 12:
                pieces.append(piece)
    return pieces


@pytest.fixture
def seeded_home(tmp_path: Path) -> Path:
    """A `~/.claude` holding one session per seeded secret."""
    projects = tmp_path / ".claude" / "projects" / "-home-aurelia-quintero-projects-ledger"
    projects.mkdir(parents=True)
    for position, (label, secret) in enumerate(sorted(SECRETS.items())):
        lines = [_line(position, secret), _result_line(position, secret)]
        path = projects / f"{position:08d}-0000-4000-8000-000000000001.jsonl"
        path.write_text(
            "\n".join(json.dumps(line, ensure_ascii=False) for line in lines) + "\n",
            encoding="utf-8",
        )
        written = path.read_text(encoding="utf-8")
        assert any(form in written for form in forms(secret)), f"{label} was not planted"
    return tmp_path / ".claude"


def _emitted(home: Path) -> str:
    """Every byte of every document `scan` would write for this home."""
    reader = ClaudeCodeReader(home=home)
    documents = [trace.to_dict() for trace in reader.read_all()]
    assert documents, "the reader found nothing; the corpus is not being read"
    return json.dumps(documents, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Gate 9: the property, over every planted secret
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label", sorted(SECRETS))
def test_no_emitted_trace_contains_a_seeded_secret(seeded_home, label):
    blob = _emitted(seeded_home)

    for form in forms(SECRETS[label]):
        assert form not in blob, f"{label} survived into an emitted trace"


@pytest.mark.parametrize("label", sorted(SECRETS))
def test_no_emitted_trace_contains_a_long_fragment_of_one(seeded_home, label):
    """The same statement against the pieces, because a secret cut in half by
    a path separator or an `=` is still a secret that was published."""
    blob = _emitted(seeded_home)

    for fragment in fragments(SECRETS[label]):
        assert fragment not in blob, f"{label}: the fragment {fragment!r} survived"


def test_the_corpus_would_catch_a_reader_that_published_everything(seeded_home):
    """The guard on the guard. If the assertions above could pass over an
    empty document they would prove nothing, so this proves the corpus is
    reachable: the raw transcripts do contain every secret, and every fragment
    the test above hunts for is really in there to be found."""
    raw = "".join(
        path.read_text(encoding="utf-8") for path in sorted(seeded_home.rglob("*.jsonl"))
    )

    for label, secret in SECRETS.items():
        assert any(form in raw for form in forms(secret)), label
        assert fragments(secret), f"{label} has no fragment long enough to search for"
        assert any(fragment in raw for fragment in fragments(secret)), label


# ---------------------------------------------------------------------------
# Gate 6: what the trace carries instead
# ---------------------------------------------------------------------------


def test_the_trace_carries_a_digest_of_the_arguments_and_not_the_arguments(seeded_home):
    reader = ClaudeCodeReader(home=seeded_home)
    traces = list(reader.read_all())

    for trace in traces:
        for event in trace.to_dict()["events"]:
            assert len(event["arguments_sha256"]) == 64
            assert "gen_ai.tool.call.arguments" not in event
            assert "gen_ai.tool.call.result" not in event


def test_the_tool_name_is_kept_because_a_verdict_has_to_name_something(seeded_home):
    """The line the boundary is drawn at, asserted rather than assumed: the
    name of the tool and the shape of the call are what a rule cites, and they
    are not the user's content. The content is what stays behind."""
    reader = ClaudeCodeReader(home=seeded_home)

    names = {
        event["gen_ai.tool.name"]
        for trace in reader.read_all()
        for event in trace.to_dict()["events"]
    }

    assert names == {"Bash"}


def test_content_travels_only_when_it_is_asked_for(seeded_home):
    """`--with-content` exists, so the claim is "digests by default" rather
    than "digests always", and this is what keeps that claim honest in both
    directions: without the flag nothing, with it the content the caller
    explicitly asked to keep."""
    kept = ClaudeCodeReader(home=seeded_home, with_content=True)

    documents = json.dumps([trace.to_dict() for trace in kept.read_all()], ensure_ascii=False)

    assert any(secret in documents for secret in SECRETS.values()), (
        "the flag does nothing, so the default it is contrasted with claims nothing"
    )


def test_scan_opens_no_socket(seeded_home, monkeypatch):
    """Local processing, stated as a refusal the test can observe. A reader
    that resolved a path over the network would fail here rather than in
    somebody's audit."""
    import socket

    def refuse(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("scan opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)

    assert list(ClaudeCodeReader(home=seeded_home).read_all())


# ---------------------------------------------------------------------------
# The shipped demo fixture, which is a public file forever
# ---------------------------------------------------------------------------


def test_the_demo_fixture_is_synthetic(monkeypatch):
    """It ships in the wheel and lives in a public repository for good, so it
    is written rather than harvested. A cleaned copy of a real session is still
    a real session, which is why this checks for the shapes rather than for a
    list of strings somebody remembered to scrub."""
    import re

    from actaira.trace.claude_code import DEMO_SESSION

    text = DEMO_SESSION.read_text(encoding="utf-8")

    assert "Usuario" not in text, "a real Windows user name reached the shipped fixture"
    assert not re.search(r"[A-Za-z]:\\\\Users\\\\", text), "a real Windows home path"
    assert "/home/usuario" not in text.lower(), "a real POSIX home path"
    assert not re.search(r"sk-[a-zA-Z0-9-]{16,}", text), "a key-shaped string"
    assert not re.search(r"gh[pousr]_[A-Za-z0-9]{20,}", text), "a token-shaped string"
    assert not re.search(r"\b[A-Z0-9]{20}\b", text), "an access-key-shaped string"
    assert "BEGIN" not in text, "a PEM block"


def test_the_demo_fixture_still_parses_into_a_trace():
    from actaira.trace.claude_code import demo_trace

    trace = demo_trace()

    assert trace.capture_level is CaptureLevel.L0
    assert len(trace.events) >= 3, "a demo with one call demonstrates nothing"
