"""The invariant behind three fixes that were each made one at a time.

The MCP server alias, the absolute path in a gap's detail and `requestState`
are the same defect: a field of the published document whose value is chosen by
an agent, a server, or somebody else's configuration. Two were fixed with a
salt; the third was fixed by restricting its punctuation, which is not the same
fix, because the specification has servers encode their own identifier in it.

`src/actaira/trace/provenance.py` is the one place that classifies every
published field. This file is what makes that table an invariant rather than a
document: the first test walks the PUBLISHED CONTRACT and fails when it carries
a property the table does not name, so a fourth instance of this class cannot
arrive without somebody deciding, in writing, which way it travels.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from actaira import schemas
from actaira.proxy import Recorder
from actaira.proxy.session import MANIFEST, WatchSession, rewrite_config
from actaira.trace import provenance
from actaira.trace.model import SCHEMA_VERSION
from actaira.trace.provenance import PUBLISHED, REFUSED, Travel, Writer

CONTRACT = schemas.stem(SCHEMA_VERSION)


def properties_of(node, trail: str = "") -> set[str]:
    """Every property path a consumer can read off this contract.

    `$defs` are walked from their own root rather than under the property that
    `$ref`s them, because that is how they appear to a reader: an event's
    `mcp.client` is `mcp.client`, not `events.items.mcp.client`.
    """
    found: set[str] = set()
    if not isinstance(node, dict):
        return found
    for key, value in (node.get("properties") or {}).items():
        found.add(trail + key)
        found |= properties_of(value, trail + key + ".")
    if isinstance(node.get("items"), dict):
        found |= properties_of(node["items"], trail)
    return found


def contract_paths() -> set[str]:
    schema = schemas.load(CONTRACT)
    found = properties_of(schema)
    for definition in (schema.get("$defs") or {}).values():
        found |= properties_of(definition)
    return found


# ---------------------------------------------------------------------------
# The invariant: nothing published is unclassified
# ---------------------------------------------------------------------------


def test_every_field_of_the_published_contract_is_classified():
    """The test the fourth instance of this defect walks into.

    A field added to the trace without an entry in `provenance.PUBLISHED` fails
    here, and the entry cannot be written without deciding whether the value is
    ours or somebody else's - which is the decision that was not made three
    times in a row.
    """
    missing = sorted(contract_paths() - provenance.paths())

    assert not missing, (
        f"{CONTRACT} publishes field(s) that src/actaira/trace/provenance.py does not "
        f"classify: {', '.join(missing)}. Add an entry saying who writes the value and, "
        "if it is a third party, whether it is digested or why it travels literally. "
        "This is the check that stops the fourth version of the alias defect."
    )


def test_the_table_does_not_classify_fields_that_are_not_published():
    """The other direction. A stale entry is a reader being told a field is
    accounted for when it is not there at all, and it is also how a table stops
    being read: once one row is wrong, none of them is trusted."""
    stale = sorted(provenance.paths() - contract_paths())

    assert not stale, f"provenance entries for fields {CONTRACT} does not publish: {stale}"


def test_every_third_party_field_that_travels_literally_carries_its_argument():
    """A decision with no reason written down is a preference, and CLAUDE.md's
    fifth working rule is that a decision is written with its alternative."""
    unargued = [
        field.path
        for field in PUBLISHED + REFUSED
        if field.needs_an_argument() and len(field.why) < 40
    ]

    assert not unargued, (
        "third-party field(s) that travel literally, or are refused, with no argument "
        f"for it: {', '.join(unargued)}"
    )


def test_the_table_is_not_vacuous():
    """The guard on the two above. A table where nothing is third-party, or
    nothing is digested, would satisfy every assertion here and protect
    nothing - which is precisely the failure the old privacy property had."""
    third_party = [field for field in PUBLISHED if field.writer is Writer.THIRD_PARTY]
    digested = [field for field in PUBLISHED if field.travel is Travel.DIGESTED]

    assert len(third_party) >= 15, "a document this size has more foreign values than that"
    assert len(digested) >= 5
    assert {field.path for field in digested} >= {
        "session_id", "gen_ai.conversation.id", "gen_ai.tool.call.id",
        "after_event", "mcp.client", "mcp.server", "mcp.request.state",
    }


def keys_of(document, schema, trail: str = "") -> set[str]:
    """Every key an EMITTED document actually carries, as the table spells it.

    Walking the schema is not enough on its own and the adversarial pass for
    this phase is what found that: `additionalProperties` is true in every
    contract here, on purpose, so a writer can add a key without touching the
    schema and the classification test would never see it. That is the same
    shape as the defect this whole table exists to stop - a field arriving
    where nobody is looking - so the document is walked too.

    Which list flattens onto its parent's path and which does not is read off
    the schema rather than listed here: an array whose items are a `$ref` is a
    definition with paths of its own (an event's `mcp.client` is
    `mcp.client`), and an array with inline items is part of its parent
    (`mcp.servers.ref`). A list of those two kinds typed out by hand is a
    fourth place to record one fact.
    """
    found: set[str] = set()
    if not isinstance(document, dict) or not isinstance(schema, dict):
        return found
    properties = schema.get("properties") or {}
    for key, value in document.items():
        found.add(trail + key)
        below = properties.get(key)
        if not isinstance(below, dict):
            continue
        if isinstance(value, dict):
            found |= keys_of(value, resolved(below), trail + key + ".")
        elif isinstance(value, list):
            items = below.get("items")
            if not isinstance(items, dict):
                continue
            under = "" if "$ref" in items else trail + key + "."
            for entry in value:
                found |= keys_of(entry, resolved(items), under)
    return found


def resolved(node: dict) -> dict:
    """A `$ref` followed inside this one contract, or the node itself."""
    reference = node.get("$ref")
    if not isinstance(reference, str) or not reference.startswith("#/$defs/"):
        return node
    return (schemas.load(CONTRACT).get("$defs") or {}).get(
        reference.rsplit("/", 1)[-1], {}
    )


def test_every_key_an_emitted_document_carries_is_classified(tmp_path):
    """The other half of the invariant, against a document rather than a shape.

    `additionalProperties` is true in every contract this project publishes -
    that is what lets a field be added inside a version - and it means the
    schema is a floor, not a ceiling. So a real `watch` trace and the shipped
    demo are both walked, and a key in either of them that the table does not
    name fails here even though the schema would have accepted it silently.
    """
    from actaira.trace.claude_code import demo_trace

    session = WatchSession(tmp_path / "records", "s")
    rewrite_config(
        {"mcpServers": {"srv": {"command": "true"}, "odd": {"transport": "pigeon"}}},
        record_dir=session.record_dir,
        session_id=session.session_id,
        salt=session.salt,
        run_id=session.run_id,
    )
    recorder = Recorder(
        session_id=session.session_id,
        record_path=session.record_dir / "srv.jsonl",
        salt=session.salt,
        run_id=session.run_id,
    )
    recorder.call("read_file", {"path": "x"}, at="2026-01-01T00:00:00.000Z", call_id="1")
    recorder.close()

    schema = schemas.load(CONTRACT)
    watched = session.assemble(child_returncode=3).to_dict()
    scanned = demo_trace().to_dict()
    carried = keys_of(watched, schema) | keys_of(scanned, schema)

    assert carried, "no document was emitted, so nothing was walked"
    unclassified = sorted(carried - provenance.paths())
    assert not unclassified, (
        "emitted document(s) carry key(s) that src/actaira/trace/provenance.py does not "
        f"classify: {', '.join(unclassified)}. The schema would have accepted them - "
        "additionalProperties is true - which is exactly why this walks the document."
    )


def test_the_document_walk_would_notice_an_unclassified_key():
    """The guard on the guard above. If `keys_of` returned nothing, or missed
    everything nested, the assertion would pass over any document at all."""
    schema = schemas.load(CONTRACT)
    document = {
        "session_id": "x",
        "events": [{"index": 0, "mcp.client": "c", "a_key_nobody_declared": 1}],
        "mcp": {"servers": [{"ref": "r", "invented_here": 2}]},
    }

    carried = keys_of(document, schema)

    assert "mcp.client" in carried, "a $ref'd definition's keys did not flatten"
    assert "mcp.servers.ref" in carried, "an inline array's keys did not keep their path"
    assert carried - provenance.paths() == {"a_key_nobody_declared", "mcp.servers.invented_here"}


# ---------------------------------------------------------------------------
# And the table is true: what it says is digested, is
# ---------------------------------------------------------------------------

CURRENT = "2026-07-28"
TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

# One recognisable string per digested field, planted where a third party puts
# it. Each is low entropy on purpose - the point of the salt is that guessing
# the value does not confirm it - and each is checked BOTH as a literal and as
# the digest anybody could recompute from the guess.
PLANTED = {
    "session_id": "acme-payroll-migration",
    "gen_ai.tool.call.id": "req-acme-payroll-001",
    "mcp.client": "acme-internal-agent",
    "mcp.server": "acme-payroll-mcp",
    "mcp.request.state": "resume-acme-payroll-tenant-42",
}


def reproducible_digest(value: str) -> str:
    """What a third party computes from a guess, offline, in one line."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


SERVER = f"""
import json, sys
META = {{'io.modelcontextprotocol/protocolVersion': {CURRENT!r},
        'io.modelcontextprotocol/serverInfo':
            {{'name': {PLANTED["mcp.server"]!r}, 'version': '1'}}}}
for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    sys.stdout.write(json.dumps({{'jsonrpc': '2.0', 'id': message.get('id'), 'result': {{
        'content': [{{'type': 'text', 'text': 'ok'}}],
        'resultType': 'input_required',
        'requestState': {PLANTED["mcp.request.state"]!r},
        '_meta': META}}}}) + '\\n')
    sys.stdout.flush()
"""


@pytest.fixture
def planted(tmp_path):
    """One recorded session with every planted value in the place it belongs."""
    import sys as _sys

    script = tmp_path / "server.py"
    script.write_text(SERVER, encoding="utf-8")
    from actaira.proxy.stdio import StdioProxy

    recorder = Recorder(
        session_id=PLANTED["session_id"],
        record_path=tmp_path / "srv.jsonl",
        salt="a" * 32,
        run_id="r",
    )
    proxy = StdioProxy([_sys.executable, str(script)], recorder, timeout=5.0)
    assert proxy.start()
    proxy.request({
        "jsonrpc": "2.0",
        "id": PLANTED["gen_ai.tool.call.id"],
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": CURRENT,
                "io.modelcontextprotocol/clientInfo": {
                    "name": PLANTED["mcp.client"], "version": "1"
                },
                "traceparent": TRACEPARENT,
            },
        },
    })
    proxy.close()
    return recorder


@pytest.mark.parametrize("path", sorted(PLANTED))
def test_a_digested_field_publishes_neither_the_value_nor_a_guessable_digest(planted, path):
    value = PLANTED[path]
    blob = json.dumps(planted.trace().to_dict(), ensure_ascii=False)

    assert value not in blob, f"{path} published the value a third party chose"
    assert reproducible_digest(value) not in blob, (
        f"{path} published an unsalted digest of it, which is a dictionary lookup away "
        "from the value for anybody who can guess it"
    )


def test_the_planted_corpus_would_catch_a_reader_that_published_everything(planted):
    """The guard on the property above: if none of the planted values ever
    reached the recorder, every assertion would pass over an empty document."""
    document = planted.trace().to_dict()

    assert document["events"], "nothing was recorded, so nothing was tested"
    assert planted.refs.map, "no reference was minted, so nothing was digested"
    # `clientInfo` and `serverInfo` are referenced as `name@version`, so the
    # planted name is a prefix of what was minted rather than equal to it.
    minted = set(planted.refs.map.values())
    unreached = [
        value for value in PLANTED.values()
        if not any(held.startswith(value) for held in minted)
    ]
    assert not unreached, f"a planted value never reached the recorder: {unreached}"


def test_the_correlation_the_value_carried_survives_being_referenced(planted):
    """The cost the salt must NOT have. A reference is useless if two events
    that shared a value stop sharing anything."""
    from actaira.trace.model import GapReason

    # A hole recorded after the call, so the anchor is actually exercised: the
    # question is whether a REFERENCED identity still cites the event it names.
    planted.gap(GapReason.UPSTREAM_TIMEOUT, "the server stopped answering after this")
    document = planted.trace().to_dict()
    event = document["events"][0]

    assert event["gen_ai.conversation.id"] == document["session_id"], (
        "the session is one session, so its reference has to be one reference"
    )
    assert event["mcp.request.state"], "the handle that pairs a retry is gone entirely"
    gaps = [gap for gap in document["gaps"] if gap.get("after_event")]
    assert gaps, "no gap anchored to a call, so the anchor was not exercised"
    assert all(gap["after_event"] == event["gen_ai.tool.call.id"] for gap in gaps), (
        "a gap anchors to the identity of the call it follows (D-258), and a referenced "
        "identity has to anchor exactly as well as a literal one did"
    )


def test_the_operator_keeps_the_map_beside_their_records_and_out_of_the_trace(tmp_path):
    """The other half of every digest here: the operator can still read their
    own trace. The map is on their disk; the document holds none of it."""
    session = WatchSession(tmp_path / "records", "acme-payroll-migration")
    rewrite_config(
        {"mcpServers": {"payroll": {"command": "true"}}},
        record_dir=session.record_dir,
        session_id=session.session_id,
        salt=session.salt,
        run_id=session.run_id,
    )
    recorder = Recorder(
        session_id=session.session_id,
        record_path=session.record_dir / "payroll.jsonl",
        salt=session.salt,
        run_id=session.run_id,
    )
    recorder.call("read_file", {}, at="2026-01-01T00:00:00.000Z", call_id="req-acme-001")
    recorder.close()

    document = session.assemble(child_returncode=0).to_dict()
    manifest = json.loads((session.record_dir / MANIFEST).read_text(encoding="utf-8"))
    beside = json.loads(
        (session.record_dir / "payroll.refs.json").read_text(encoding="utf-8")
    )
    blob = json.dumps(document, ensure_ascii=False)

    assert manifest["servers"]["payroll"]["references"] == "payroll.refs.json"
    assert beside[document["events"][0]["gen_ai.tool.call.id"]] == "req-acme-001"
    assert manifest["references"][document["session_id"]] == "acme-payroll-migration"
    assert "acme-payroll-migration" not in blob
    assert "req-acme-001" not in blob
    assert manifest["redaction_salt"] not in blob


# ---------------------------------------------------------------------------
# The keys this reader refuses outright
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field", REFUSED, ids=lambda field: field.path)
def test_a_refused_key_reaches_no_emitted_document(tmp_path, field):
    """`tracestate` and `baggage` sit in `_meta` beside `traceparent` (SEP-414)
    and carry arbitrary key-value pairs written by whatever was upstream. They
    are not read, and "not read" is asserted here rather than left as an
    absence nobody went looking for."""
    planted = "acme-tenant-42-payroll"
    recorder = Recorder(session_id="s", salt="b" * 32)
    recorder.call(
        "read_file",
        {},
        at="2026-01-01T00:00:00.000Z",
        call_id="1",
        message={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": CURRENT,
                    "traceparent": TRACEPARENT,
                    field.path: f"acme={planted}",
                },
            },
        },
    )

    blob = json.dumps(recorder.trace().to_dict(), ensure_ascii=False)

    assert planted not in blob, f"{field.path} reached an emitted document"
    assert field.path not in blob


def test_the_refused_list_names_keys_the_protocol_module_knows_about():
    """A refusal about a key nobody has spelled anywhere is a refusal that
    stops meaning anything the moment the key is renamed upstream."""
    from actaira.proxy import protocol

    named = {protocol.TRACESTATE_KEY, protocol.BAGGAGE_KEY,
             protocol.CLIENT_CAPABILITIES_KEY}

    assert {field.path for field in REFUSED} == named


def test_the_provenance_table_is_the_only_place_this_is_written_down():
    """The table has to be findable from the contract it describes, or the next
    reader meets the schema and never learns there is a table."""
    schema = json.dumps(schemas.load(CONTRACT))

    assert "provenance.py" in schema


def test_no_reference_map_is_ever_written_into_a_trace_document(tmp_path):
    """The one file that would undo all of this if it were ever inlined."""
    reader_map = Path("src/actaira/trace/provenance.py")

    assert reader_map.is_file()
    assert "refs.json" not in json.dumps(schemas.load(CONTRACT)), (
        "the published contract names the operator's own map, which is an invitation "
        "to ship it beside the document it exists to keep out of"
    )
