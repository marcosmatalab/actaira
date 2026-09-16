"""Who writes each field of the published document, and what that costs.

Design note D-268. Three times now the same defect has been found and fixed
one instance at a time: the MCP server alias (D-263), the absolute path in a
gap's detail (D-263), and `requestState` (found in the 1.1b adversarial pass).
Each is a field of the PUBLISHED document whose value is chosen by somebody
else - an agent, a server, or a configuration this tool was handed. The first
two were fixed with a salt. The third was fixed by restricting which
CHARACTERS the value may contain, and that is not the same fix: the
specification says servers encode their own identifier in `requestState`, so a
server that puts something meaningful there still publishes it, through a gate
that was only ever looking at punctuation.

A fourth instance would have arrived on its own. So this file is the
invariant rather than a fourth patch:

    EVERY field of the published trace is classified here, with who writes its
    value; a third-party value is DIGESTED unless this table writes down why it
    travels literally; and `tests/test_trace_provenance.py` fails when the
    contract grows a field this table does not name.

That last clause is the half that matters. A rule about a class of field is
kept by whoever remembers the class exists, and the phase-1 review is a list of
things nobody remembered. A test that walks the published schema and demands an
entry for every property in it cannot be forgotten, because the schema is what
a consumer reads.

**What DIGESTED means.** `H(salt || domain || value)` with the session's own
salt, exactly as the alias already travels: the correlation survives - two
events carrying one server's identity carry one reference, a paused call and
its retry carry one handle - and nothing about the value itself is published.
The operator resolves theirs from the map beside their records; a third party,
including one holding a dictionary of likely values, resolves nothing.

**What CLEAR means.** The value travels as it is, and the `why` below is the
argument for it. Two kinds qualify and no others. Either the value space is
closed and this reader matches the whole of it - a revision date, an enum
member, a boolean, an integer, an instant - so the field cannot carry a
sentence somebody chose. Or there is a product reason written down elsewhere in
this repository, and then `why` names it: the tool NAME travels because a
non-conformance has to cite something, which is D-252 and is the line the
privacy boundary was drawn at in the first place.

**What REFUSED means.** A field the protocol defines, that this reader does not
read at all, and the reason. `tracestate` and `baggage` are here: SEP-414 puts
them in `_meta` beside `traceparent`, they carry arbitrary key-value pairs
written by whoever was upstream, and there is nothing this tool would do with
them. Naming them is not paperwork - it is what makes "we do not publish these"
a statement a test can check rather than an absence nobody looked for.

Rejected: classifying by field NAME with a pattern, so that anything ending in
`_ref` is assumed safe. That is a convention, and a convention is what the next
person breaks by writing a field that looks like the others. Rejected too:
digesting everything and publishing a document of opaque references. A document
in which nothing can be cited is a document no rule can be written against,
which is the product, not a side effect.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Writer(str, Enum):
    """Who chose the value that ends up in the document."""

    #: This tool computed it: a digest, a count, a verdict, a sentence of ours.
    ACTAIRA = "actaira"
    #: An agent, a server, or a configuration this tool was handed.
    THIRD_PARTY = "third_party"


class Travel(str, Enum):
    """How a third-party value reaches the published document."""

    #: `H(salt || domain || value)`. The map is beside the operator's records.
    DIGESTED = "digested"
    #: Literally, and `why` is the argument for it.
    CLEAR = "clear"
    #: Not at all. `why` says what it is and why this reader leaves it.
    REFUSED = "refused"


@dataclass(frozen=True)
class Field:
    """One property of the published contract, classified."""

    path: str
    writer: Writer
    travel: Travel
    why: str = ""

    def needs_an_argument(self) -> bool:
        """Whether this entry has to carry a written reason.

        A third-party value that travels literally, or one this reader refuses,
        is a decision somebody made. An Actaira-written field is not.
        """
        return self.writer is Writer.THIRD_PARTY and self.travel is not Travel.DIGESTED


# The reasons that recur, named once so that twelve entries cannot drift into
# twelve slightly different arguments for the same thing.
CLOSED_DATE = (
    "a protocol revision is a date, matched against `^\\d{4}-\\d{2}-\\d{2}$` before it "
    "is published, so the whole of its value space is known and it cannot carry a "
    "sentence somebody chose"
)
CLOSED_ENUM = "a member of a closed enumeration this reader matches against in full"
CLOSED_SCALAR = (
    "a boolean, an integer or an ISO instant: the value space is a shape, not a string "
    "somebody writes"
)
STRUCTURE = "a container, with no value of its own"
CITES_SOMETHING = (
    "D-252: what a rule cites is the tool NAME and the shape of the call. A document in "
    "which the tool cannot be named is a document no non-conformance can be written "
    "against, which is the product rather than a side effect of it. It is also not the "
    "user's content - that is what the digests are for"
)
OPERATOR_ASKED = (
    "present only under `--with-content`, which is the one explicit door through the "
    "privacy boundary and the only route by which literal content is written (D-252)"
)


PUBLISHED: tuple[Field, ...] = (
    # -- the document ------------------------------------------------------
    Field("schema_version", Writer.ACTAIRA, Travel.CLEAR),
    Field("session_id", Writer.THIRD_PARTY, Travel.DIGESTED),
    Field("source", Writer.ACTAIRA, Travel.CLEAR),
    Field("capture_level", Writer.ACTAIRA, Travel.CLEAR),
    Field("agent", Writer.ACTAIRA, Travel.CLEAR, STRUCTURE),
    Field("agent.name", Writer.ACTAIRA, Travel.CLEAR),
    Field(
        "agent.versions", Writer.THIRD_PARTY, Travel.CLEAR,
        "the released version of the agent that wrote the bytes this trace was derived "
        "from, as its publisher spells it. A public version of a public product, like a "
        "host name and unlike an alias, and without it the trace cannot say what produced "
        "what it read",
    ),
    Field("started_at", Writer.THIRD_PARTY, Travel.CLEAR, CLOSED_SCALAR),
    Field("ended_at", Writer.THIRD_PARTY, Travel.CLEAR, CLOSED_SCALAR),
    Field("authenticity", Writer.ACTAIRA, Travel.CLEAR, STRUCTURE),
    Field("authenticity.state", Writer.ACTAIRA, Travel.CLEAR),
    Field("authenticity.applies", Writer.ACTAIRA, Travel.CLEAR),
    Field("authenticity.reason", Writer.ACTAIRA, Travel.CLEAR),
    Field("complete", Writer.ACTAIRA, Travel.CLEAR),
    Field("child_returncode", Writer.THIRD_PARTY, Travel.CLEAR, CLOSED_SCALAR),
    Field("events", Writer.ACTAIRA, Travel.CLEAR, STRUCTURE),
    Field("gaps", Writer.ACTAIRA, Travel.CLEAR, STRUCTURE),
    Field("blind_spots", Writer.ACTAIRA, Travel.CLEAR, STRUCTURE),
    Field("blind_spots.what", Writer.ACTAIRA, Travel.CLEAR),
    Field("blind_spots.why", Writer.ACTAIRA, Travel.CLEAR),
    Field("duplicate_records_collapsed", Writer.ACTAIRA, Travel.CLEAR),
    Field("mcp", Writer.ACTAIRA, Travel.CLEAR, STRUCTURE),
    Field("mcp.protocol_revisions_observed", Writer.THIRD_PARTY, Travel.CLEAR, CLOSED_DATE),
    Field("mcp.servers", Writer.ACTAIRA, Travel.CLEAR, STRUCTURE),
    Field("mcp.servers.ref", Writer.ACTAIRA, Travel.CLEAR),
    Field("mcp.servers.tools_advertised", Writer.THIRD_PARTY, Travel.CLEAR, CITES_SOMETHING),
    Field(
        "mcp.servers.protocol_revisions_advertised",
        Writer.THIRD_PARTY, Travel.CLEAR, CLOSED_DATE,
    ),
    # -- one event ---------------------------------------------------------
    Field("index", Writer.ACTAIRA, Travel.CLEAR),
    Field("gen_ai.operation.name", Writer.ACTAIRA, Travel.CLEAR),
    Field("gen_ai.tool.name", Writer.THIRD_PARTY, Travel.CLEAR, CITES_SOMETHING),
    Field("gen_ai.tool.call.id", Writer.THIRD_PARTY, Travel.DIGESTED),
    Field("gen_ai.conversation.id", Writer.THIRD_PARTY, Travel.DIGESTED),
    Field("timestamp", Writer.THIRD_PARTY, Travel.CLEAR, CLOSED_SCALAR),
    Field("arguments_sha256", Writer.ACTAIRA, Travel.CLEAR),
    Field("result_sha256", Writer.ACTAIRA, Travel.CLEAR),
    Field("error.type", Writer.ACTAIRA, Travel.CLEAR),
    Field("sidechain", Writer.THIRD_PARTY, Travel.CLEAR, CLOSED_SCALAR),
    Field("gen_ai.tool.call.arguments", Writer.THIRD_PARTY, Travel.CLEAR, OPERATOR_ASKED),
    Field("gen_ai.tool.call.result", Writer.THIRD_PARTY, Travel.CLEAR, OPERATOR_ASKED),
    Field(
        "traceparent", Writer.THIRD_PARTY, Travel.CLEAR,
        "the W3C trace context, matched against its fixed hexadecimal shape before it is "
        "published, so it carries an identifier and no room for a sentence. It travels "
        "because its ONLY use is to line this trace up against the OpenTelemetry traces "
        "the operator's own systems already emit, and a reference nobody else holds the "
        "map to lines up against nothing. What that concedes - that a client could encode "
        "sixteen bytes of its own choosing in the trace id - is in docs/BACKLOG.md rather "
        "than unstated",
    ),
    Field("mcp.protocol.version", Writer.THIRD_PARTY, Travel.CLEAR, CLOSED_DATE),
    Field("mcp.client", Writer.THIRD_PARTY, Travel.DIGESTED),
    Field("mcp.server", Writer.THIRD_PARTY, Travel.DIGESTED),
    Field("mcp.result.type", Writer.THIRD_PARTY, Travel.CLEAR, CLOSED_ENUM),
    Field("mcp.result.type_assumed", Writer.ACTAIRA, Travel.CLEAR),
    Field("mcp.request.state", Writer.THIRD_PARTY, Travel.DIGESTED),
    # -- one gap -----------------------------------------------------------
    Field("reason", Writer.ACTAIRA, Travel.CLEAR),
    Field(
        "detail", Writer.ACTAIRA, Travel.CLEAR,
        "prose this tool writes, and it may be built only from `redact.failure_kind`, "
        "`redact.endpoint`, `redact.file_ref` and `redact.label_ref` - which is D-257, and "
        "is why this is an Actaira-written field and not a third-party one wearing a "
        "sentence",
    ),
    Field("after_event", Writer.THIRD_PARTY, Travel.DIGESTED),
    Field("after_index", Writer.ACTAIRA, Travel.CLEAR),
    Field("after_index_absent", Writer.ACTAIRA, Travel.CLEAR),
)


# Fields the protocol defines that this reader does not read. They are here so
# that "we do not publish these" is a statement a test checks rather than an
# absence nobody went looking for - `tests/test_trace_provenance.py` seeds each
# of them and asserts it reaches no emitted document.
REFUSED: tuple[Field, ...] = (
    Field(
        "tracestate", Writer.THIRD_PARTY, Travel.REFUSED,
        "SEP-414 puts it in `_meta` beside `traceparent`. It is a list of key-value pairs "
        "written by whatever tracing systems the request passed through, its keys and its "
        "values are both arbitrary, and there is nothing this tool would do with it that "
        "`traceparent` does not already do",
    ),
    Field(
        "baggage", Writer.THIRD_PARTY, Travel.REFUSED,
        "the same, and worse: baggage exists to carry application-defined key-value pairs "
        "across a call chain, which is to say it exists to carry exactly the kind of "
        "content this boundary is drawn against. A customer id put there by an unrelated "
        "system would travel into an acta",
    ),
    Field(
        "io.modelcontextprotocol/clientCapabilities", Writer.THIRD_PARTY, Travel.REFUSED,
        "SEP-2575 puts the client's capabilities on every request. It is a structure whose "
        "shape the client decides, no rule in this release is written against it, and a "
        "field read for no reason is a field whose value space nobody is watching",
    ),
)


def digested() -> tuple[str, ...]:
    """Every published path whose value is referenced rather than written."""
    return tuple(field.path for field in PUBLISHED if field.travel is Travel.DIGESTED)


def paths() -> frozenset[str]:
    """Every published path this table classifies."""
    return frozenset(field.path for field in PUBLISHED)
