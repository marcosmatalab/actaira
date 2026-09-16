"""The privacy boundary, as a property over a corpus rather than an example.

`actaira scan` reads files full of somebody's conversations, their home
directory and, sooner or later, their secrets. So the emitted trace carries
digests of arguments and results and not the arguments themselves, and the
guard on that is not "we remembered to hash it here": it is a corpus of
transcripts with secrets planted on purpose, and the assertion that none of
them survives into any emitted document by any route - not in an argument, not
in a result, not in an error message, not in a path, not in a gap's detail.

That last clause was in this docstring for a whole phase and was not tested.
The corpus fed the reader well-formed, readable files, so no failure path ever
ran, and every leak the phase-1 review found came out of one: the text of an
`OSError`, which carries the absolute path; the name of a directory under
`~/.claude/projects`, WHICH IS the user's working directory; and the upstream
URL of an MCP server, which is where the directories that hand them out put
the token. None of those is an argument or a result, which is why hashing
arguments and results did not cover any of them.

So the corpus now also contains files that cannot be read, directories whose
names are the secret, and servers whose URLs are, and the property below is
stated twice: once against the planted strings, and once against the SHAPES a
leak takes, so a secret nobody thought to plant is caught by the shape of the
sentence carrying it.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from actaira.proxy.session import WatchSession, rewrite_config
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


# ---------------------------------------------------------------------------
# The routes that are not an argument and not a result
# ---------------------------------------------------------------------------

# Absolute paths, URL query strings, and the text the operating system puts in
# an exception. A detail is built from `redact.file_ref`, `redact.endpoint` and
# `redact.failure_kind`, none of which can produce any of these - so this is a
# property about every emitted document rather than a list of call sites
# somebody has to keep finding.
LEAK_SHAPES = {
    "a POSIX absolute path": re.compile(r"(?<![\w/])/(?:home|Users|root|var|etc|tmp)/"),
    "a Windows absolute path": re.compile(r"[A-Za-z]:[\\/]{1,2}(?:Users|Windows|ProgramData)"),
    "a URL query string": re.compile(r"https?://[^\s\"]*\?"),
    "a URL with userinfo": re.compile(r"https?://[^\s/\"]*@"),
    "the text of an OS error": re.compile(r"\[Errno \d+\]|\[WinError \d+\]|Permission denied|"
                                         r"No such file or directory"),
}


def assert_no_leak_shape(blob: str, where: str) -> None:
    for name, pattern in LEAK_SHAPES.items():
        found = pattern.search(blob)
        assert not found, f"{where}: {name} reached an emitted document: {found.group(0)!r}"


@pytest.fixture
def unreadable_home(tmp_path: Path) -> Path:
    """A `~/.claude` whose directory name is a secret and one of whose session
    files cannot be read - a lock, a permission bit, a half-synced mount, or,
    as here, a directory where a file should be."""
    home = tmp_path / ".claude"
    # The sanitised cwd, which is how Claude Code names these directories, and
    # which is the "private home path" secret this file already plants.
    project = home / "projects" / "-home-aurelia-quintero-projects-payroll-dot-env"
    project.mkdir(parents=True)
    (project / "00000000-0000-4000-8000-000000000001.jsonl").write_text(
        json.dumps(_line(0, "harmless")) + "\n", encoding="utf-8"
    )
    (project / "00000000-0000-4000-8000-000000000002.jsonl").mkdir()
    (project / "00000000-0000-4000-8000-000000000003.jsonl").write_text(
        "{ this record is cut off\n", encoding="utf-8"
    )
    return home


def test_a_session_file_that_cannot_be_read_does_not_publish_where_it_lives(unreadable_home):
    """`str(OSError)` is `[Errno 13] Permission denied: '<absolute path>'`, and
    that sentence went into a gap's `detail` whole."""
    blob = _emitted(unreadable_home)

    assert_no_leak_shape(blob, "an unreadable session file")
    assert "aurelia-quintero" not in blob
    assert "aurelia.quintero" not in blob


def test_the_hole_is_still_declared_when_the_file_cannot_be_read(unreadable_home):
    """The guard on the guard above: saying nothing about the failure would
    also pass it, and that is the other way to be wrong here."""
    documents = [
        trace.to_dict() for trace in ClaudeCodeReader(home=unreadable_home).read_all()
    ]

    reasons = {gap["reason"] for document in documents for gap in document["gaps"]}
    assert "unparsable_record" in reasons
    assert all(document["complete"] is False for document in documents)


def test_a_record_that_will_not_parse_does_not_publish_the_file_it_was_in(unreadable_home):
    """A `json` ValueError carries a line and a column of somebody's
    conversation, and the sentence around it carried the file name."""
    documents = [
        trace.to_dict() for trace in ClaudeCodeReader(home=unreadable_home).read_all()
    ]
    details = " ".join(gap["detail"] for document in documents for gap in document["gaps"])

    assert_no_leak_shape(details, "an unparsable record")
    assert "Expecting" not in details, "the parser's own message names a column of the file"


@pytest.mark.parametrize("label", sorted(SECRETS))
def test_a_secret_in_a_directory_name_does_not_reach_an_emitted_trace(tmp_path, label):
    """The directory name under `projects/` is the user's working directory,
    so a secret in a path is a secret in a directory name."""
    secret = SECRETS[label]
    home = tmp_path / ".claude"
    safe = re.sub(r"[^A-Za-z0-9_.-]", "-", secret)[:80]
    project = home / "projects" / f"-w-{safe}"
    project.mkdir(parents=True)
    (project / "00000000-0000-4000-8000-000000000001.jsonl").mkdir()

    blob = _emitted_allowing_empty(home)

    for fragment in fragments(secret):
        assert fragment not in blob, f"{label}: a directory name reached the trace"
    assert reproducible_digest(str(project.resolve())) not in blob, (
        f"{label}: the directory is referenced by an unsalted digest of its path"
    )
    assert_no_leak_shape(blob, f"a directory named after {label}")


def _emitted_allowing_empty(home: Path) -> str:
    return json.dumps(
        [trace.to_dict() for trace in ClaudeCodeReader(home=home).read_all()],
        ensure_ascii=False,
    )


# ---------------------------------------------------------------------------
# The same boundary on the proxy side, which had no corpus at all
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def closed_port() -> int:
    """A loopback port nothing is listening on.

    The first version of this pointed at a hostname, so ten parametrised cases
    each did a DNS lookup: a test that reaches a third party and fails
    differently depending on whose resolver is answering. Loopback with no
    listener reaches the same code path in `http.request` - a refused
    connection - and leaves the machine alone.
    """
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.mark.parametrize("label", sorted(SECRETS))
def test_a_secret_in_a_server_url_does_not_reach_an_emitted_trace(label, closed_port):
    """MCP directories hand out endpoints with the credential in the query
    string. The transport published the URL entire when a connection failed."""
    from actaira.proxy import Recorder
    from actaira.proxy.http import HttpProxy

    secret = re.sub(r"[^A-Za-z0-9_.~-]", "-", SECRETS[label])
    recorder = Recorder(session_id="s")
    proxy = HttpProxy(f"http://127.0.0.1:{closed_port}/sse?api_key={secret}", recorder)

    proxy.request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "t", "arguments": {}}})
    blob = json.dumps(recorder.trace().to_dict(), ensure_ascii=False)

    assert recorder.gaps, "the connection has to have failed, or nothing was exercised"
    for fragment in fragments(SECRETS[label]):
        assert fragment not in blob, f"{label}: a server URL reached the trace"
    assert_no_leak_shape(blob, f"a server URL carrying {label}")
    assert f"127.0.0.1:{closed_port}" in blob, (
        "the host still travels, or a reader cannot tell which of their servers it was"
    )


def test_a_record_file_that_cannot_be_written_does_not_publish_its_path(tmp_path):
    """The recorder's own sidecar. Its failure gap interpolated the absolute
    path of the file it had just failed to write."""
    from actaira.proxy import Recorder

    recorder = Recorder(session_id="s", record_path=tmp_path / "deep" / "srv.jsonl")
    recorder.record_path.unlink()
    recorder.record_path.mkdir()  # every write from here on raises

    recorder.call("Bash", {"command": "ls"}, at="2026-01-01T00:00:00Z")
    blob = json.dumps(recorder.trace().to_dict(), ensure_ascii=False)

    assert_no_leak_shape(blob, "a record file that cannot be written")
    assert str(tmp_path) not in blob


def test_a_server_command_that_will_not_start_does_not_publish_its_path(tmp_path):
    """The operator's own server command is a path on their machine, and
    `str(OSError)` from `Popen` carries it a second time."""
    from actaira.proxy import Recorder
    from actaira.proxy.stdio import StdioProxy

    recorder = Recorder(session_id="s")
    missing = tmp_path / "Users" / "aurelia.quintero" / "bin" / "server-that-is-not-there"
    proxy = StdioProxy([str(missing)], recorder)

    assert proxy.start() is False
    blob = json.dumps(recorder.trace().to_dict(), ensure_ascii=False)

    assert_no_leak_shape(blob, "a server command that will not start")
    assert "aurelia.quintero" not in blob


def test_the_whole_watch_document_carries_no_leak_shape(tmp_path):
    """The property over an assembled `watch` trace rather than over one
    recorder, because `assemble` builds details of its own."""
    records = tmp_path / "records"
    rewrite_config(
        {"mcpServers": {"remote": {"url": "https://mcp.example/sse?token=FAKE-NOT-REAL-TOKEN"}}},
        record_dir=records,
        session_id="s",
    )
    (records / "remote.jsonl").write_text("{ cut off\n", encoding="utf-8")

    document = WatchSession(records, "s").assemble(child_returncode=0).to_dict()
    blob = json.dumps(document, ensure_ascii=False)

    assert_no_leak_shape(blob, "an assembled watch trace")
    assert "FAKE-NOT-REAL-TOKEN" not in blob
    assert document["complete"] is False


def test_the_shape_test_would_notice_a_leak(tmp_path):
    """The guard on the shapes. If `LEAK_SHAPES` matched nothing, every
    assertion above would pass over a document full of paths."""
    import pytest as _pytest

    for sample in (
        json.dumps({"detail": "could not read /home/aurelia.quintero/.ssh/id_ed25519"}),
        json.dumps({"detail": "could not read C:\\Users\\aurelia\\.env"}),
        json.dumps({"detail": "https://mcp.example/sse?api_key=abc"}),
        json.dumps({"detail": "https://user:pw@mcp.example/sse"}),
        json.dumps({"detail": "[Errno 13] Permission denied"}),
    ):
        with _pytest.raises(AssertionError):
            assert_no_leak_shape(sample, "the guard")


@pytest.mark.parametrize("label", sorted(SECRETS))
def test_a_secret_in_a_server_alias_does_not_reach_the_published_reason(tmp_path, label):
    """The third field, after the directory name and the URL query.

    `_interposition` names an uninterposed server in `authenticity.reason`,
    which is the most widely read sentence this tool emits - so the alias out
    of somebody's `.mcp.json` became publishable the moment that gap existed.
    It is a private string in a private file: a client name, a project code
    name, or a credential somebody pasted into a server name.
    """
    secret = SECRETS[label]
    alias = re.sub(r"[^A-Za-z0-9_.@:+-]", "-", secret)[:100]
    records = tmp_path / "records"
    rewrite_config(
        {"mcpServers": {alias: {"url": "http://127.0.0.1:1/mcp"}}},
        record_dir=records,
        session_id="s",
    )

    document = WatchSession(records, "s").assemble(child_returncode=0).to_dict()
    blob = json.dumps(document, ensure_ascii=False)

    assert document["authenticity"]["state"] == "not_established", (
        "the uninterposed server still has to make the trace refuse, "
        "or this test is passing on a document that says nothing"
    )
    for fragment in fragments(secret):
        assert fragment not in blob, f"{label}: a server alias reached the trace"
    assert reproducible_digest(alias) not in blob, (
        f"{label}: the alias is referenced by a digest anybody can recompute from a "
        "guess, which is an encoding of it rather than a redaction of it"
    )
    assert_no_leak_shape(blob, f"a server alias carrying {label}")


def test_the_alias_map_stays_beside_the_records_and_out_of_the_trace(tmp_path):
    """The other half: the operator can still read their own trace. The
    reference is in the acta, the alias it belongs to is in the manifest on
    their machine, and the gap says where to look."""
    records = tmp_path / "records"
    rewrite_config(
        {"mcpServers": {"payroll-prod": {"url": "http://127.0.0.1:1/mcp"}}},
        record_dir=records,
        session_id="s",
    )

    document = WatchSession(records, "s").assemble(child_returncode=0).to_dict()
    manifest = json.loads((records / "interposition.json").read_text(encoding="utf-8"))

    reference = manifest["servers"]["payroll-prod"]["ref"]
    assert "payroll-prod" not in json.dumps(document, ensure_ascii=False)
    assert reference in document["authenticity"]["reason"]
    assert "interposition.json" in json.dumps(document["gaps"], ensure_ascii=False)


# ---------------------------------------------------------------------------
# The other half of the boundary: a reference has to be one
# ---------------------------------------------------------------------------
#
# Every property above seeds a HIGH-entropy secret and asserts the literal
# string does not come out. A reference computed as an unsalted digest passes
# every one of them and protects nothing, because the thing being referenced
# comes from a small public set: the MCP server aliases people actually type.
# A reader with a list of eight words and one line of Python recovers the
# alias from `server:<digest>`, and the properties above cannot see it,
# because the leak is not the literal - it is a value anybody can recompute.
#
# So the corpus below is deliberately the opposite of `SECRETS`: eight words
# with no entropy at all, and the assertion is stated twice, against the
# literal AND against the digest a third party can reproduce from the word.

PUBLIC_ALIASES = (
    "github", "slack", "postgres", "filesystem",
    "sentry", "notion", "linear", "stripe",
)


def reproducible_digest(value: str) -> str:
    """What a third party computes from a guess, in one line, offline.

    This function is the attack. It takes no salt, because the attacker has
    none: it is the operator's, it never leaves their machine, and if this
    function can produce anything that appears in an emitted document then
    the reference in that document is a dictionary lookup away from its value.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


@pytest.mark.parametrize("alias", PUBLIC_ALIASES)
def test_a_guessable_server_alias_is_not_recoverable_from_the_published_reason(tmp_path, alias):
    records = tmp_path / "records"
    rewrite_config(
        {"mcpServers": {alias: {"url": "http://127.0.0.1:1/mcp"}}},
        record_dir=records,
        session_id="s",
    )

    document = WatchSession(records, "s").assemble(child_returncode=0).to_dict()
    blob = json.dumps(document, ensure_ascii=False)

    assert document["authenticity"]["state"] == "not_established", (
        "the uninterposed server still has to make the trace refuse, "
        "or this test is passing on a document that says nothing"
    )
    assert alias not in blob, f"the alias {alias!r} reached the trace literally"
    assert reproducible_digest(alias) not in blob, (
        f"the reference to {alias!r} is an unsalted digest of it, so anybody holding a "
        "list of the server names people use recovers the alias in one line"
    )


def test_a_guessable_path_is_not_recoverable_from_a_record_that_will_not_read(tmp_path):
    """The same argument for `file_ref`. A path has more entropy than a word
    and not enough of it: `/home/<user>/projects/<client>` is three guesses."""
    records = tmp_path / "records"
    rewrite_config(
        {"mcpServers": {"srv": {"command": "true"}}}, record_dir=records, session_id="s"
    )
    record = records / "srv.jsonl"
    record.unlink(missing_ok=True)
    record.mkdir()  # a directory where a file should be: every read raises

    document = WatchSession(records, "s").assemble(child_returncode=0).to_dict()
    blob = json.dumps(document, ensure_ascii=False)

    assert reproducible_digest(str(record.resolve())) not in blob, (
        "the reference to the record is an unsalted digest of its absolute path, so "
        "anybody who can guess the path confirms it from the document"
    )


def test_two_sessions_over_the_same_alias_publish_different_references(tmp_path):
    """The property a fixed salt would not have. Two actas from one machine
    must not be correlatable by a third party, so the salt is per session and
    the reference to one alias differs between them."""
    references = []
    for run in ("one", "two"):
        records = tmp_path / run
        rewrite_config(
            {"mcpServers": {"github": {"url": "http://127.0.0.1:1/mcp"}}},
            record_dir=records,
            session_id=run,
        )
        document = WatchSession(records, run).assemble(child_returncode=0).to_dict()
        references.append(document["authenticity"]["reason"])

    assert references[0] != references[1], (
        "the same alias produced the same reference in two sessions, so the salt is "
        "either absent or constant, and a constant salt is a constant"
    )


def test_the_operator_can_still_resolve_their_own_reference(tmp_path):
    """The cost of the salt, paid where it belongs. The operator holds the
    manifest, so the reference in their acta still names a server to them."""
    records = tmp_path / "records"
    rewrite_config(
        {"mcpServers": {"payroll-prod": {"url": "http://127.0.0.1:1/mcp"}}},
        record_dir=records,
        session_id="s",
    )

    document = WatchSession(records, "s").assemble(child_returncode=0).to_dict()
    manifest = json.loads((records / "interposition.json").read_text(encoding="utf-8"))

    reference = manifest["servers"]["payroll-prod"]["ref"]
    assert reference in document["authenticity"]["reason"]


def test_the_salt_never_travels_in_the_trace(tmp_path):
    """The one value that would undo all of the above."""
    records = tmp_path / "records"
    rewrite_config(
        {"mcpServers": {"github": {"url": "http://127.0.0.1:1/mcp"}}},
        record_dir=records,
        session_id="s",
    )
    manifest = json.loads((records / "interposition.json").read_text(encoding="utf-8"))
    salt = manifest["redaction_salt"]

    document = WatchSession(records, "s").assemble(child_returncode=0).to_dict()

    assert len(bytes.fromhex(salt)) >= 16, "a salt shorter than 128 bits is a speed bump"
    assert salt not in json.dumps(document, ensure_ascii=False)
