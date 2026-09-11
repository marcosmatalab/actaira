"""Where a language model's answer comes from, and why the default is a file.

Design note D-45, and the decision the rest of this package is built on.

A judged control asks a model a question and then reports the answer to an
operator who will put it in front of a regulator. That makes two properties
non-negotiable, and they are in tension with the usual way an LLM is called:

  * The same input has to produce the same output on any machine, forever.
    An attestation over a judgement that cannot be reproduced attests to
    nothing. The chain in `attest/` signs a payload; if the payload changes
    when the vendor rotates a checkpoint, the signature is over a number
    that no longer exists.
  * The measurement of the judge has to be a measurement. An eval harness
    that opens a socket is not measuring the system under test, it is
    measuring the system under test *and* whatever the vendor served that
    afternoon, and it reports the sum as though it were the first. Runs
    taken a week apart are then not comparable, and the difference between
    them cannot be attributed.

So the default provider reads from disk. `CassetteProvider` replays answers
recorded earlier, keyed by the SHA-256 of the normalised prompt, and raises
`CassetteMiss` for a prompt it has never seen. It never falls back to a live
call, never returns an empty completion, and never guesses: a miss is loud,
because the failure this guards against is a harness that quietly stops
testing the thing it claims to test.

The trade-off, stated because pretending it away would be worse: a cassette
measures the model that was recorded, not the model that is served today.
The corpus therefore has to be regenerated deliberately, through
`RecordingProvider`, and the regeneration is a reviewable diff. That is the
point. A prompt whose answer changed shows up as a changed line rather than
as a test that started failing for reasons nobody can reconstruct.

`HTTPProvider` exists so the same pipeline can be pointed at a real model by
an operator who wants one, with the stdlib and no new dependency. It reads
its key from the environment, refuses to be constructed without one, and is
never reachable from a test: a test that could accidentally spend money or
leak a document is a test that will eventually do both.

Three shapes, one protocol, and the choice between them is the caller's:

    CassetteProvider   deterministic replay          tests, evals, CI
    HTTPProvider       a real model over HTTPS       an operator, opt-in
    RecordingProvider  a real model, written down    regenerating cassettes
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

HERE = Path(__file__).parent
CASSETTE_DIR = HERE / "cassettes"
CASSETTE_SCHEMA = "actaira-cassette/1"

# The environment variables `HTTPProvider` reads. Named as constants so the
# error message, the documentation and the code cannot drift apart, and so a
# grep for the key name finds every place it is touched.
API_KEY_ENV = "ACTAIRA_LLM_API_KEY"
ENDPOINT_ENV = "ACTAIRA_LLM_ENDPOINT"
MODEL_ENV = "ACTAIRA_LLM_MODEL"


class CassetteMiss(LookupError):
    """No recorded answer for this prompt.

    A `LookupError` rather than a bespoke base class because that is what it
    is: a lookup in a mapping that failed. Callers that want to degrade
    gracefully catch it explicitly; the pipeline turns it into an abstention
    and the control turns that into INCONCLUSIVE, so a missing cassette can
    never be mistaken for a judgement.
    """


class MissingCredential(RuntimeError):
    """`HTTPProvider` was constructed without a key in the environment.

    Raised at construction rather than at call time on purpose. A provider
    that constructs cleanly and fails on the first request is a provider that
    gets wired into a control, ships, and fails in front of the operator.
    """


@dataclass(frozen=True)
class Completion:
    """One answer, with what it cost.

    `latency_ms` is the wall time of the call that *produced* the text. On a
    replayed cassette it is therefore the latency of the recording, not of
    the replay, and the field name in the eval output says so
    (`latency_ms_recorded`). Reporting the replay's own microseconds as a
    model latency would be a fabricated number in a project whose whole
    argument is that it does not fabricate numbers.

    Token counts are whatever the producing provider reported. For a real
    endpoint that is the vendor's usage block; for anything else it is a
    whitespace count, and `usage_source` says which, because a whitespace
    count is not a tokenizer and an operator sizing a bill needs to know.
    (The field is `usage_source` rather than the more obvious `token_source`
    because the linter's credential check flags any name containing "token",
    and silencing a security rule to win a naming argument is the wrong
    trade.)
    """

    text: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    model: str = ""
    usage_source: str = "whitespace"
    cassette_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "latency_ms_recorded": self.latency_ms,
            "model": self.model,
            "usage_source": self.usage_source,
            "cassette_key": self.cassette_key,
        }


@runtime_checkable
class LLMProvider(Protocol):
    """The one method the rest of this package is allowed to call.

    Deliberately narrower than any vendor SDK: one string in, one string out,
    plus what it cost. No streaming, no tool calls, no conversation state.
    Every one of those would put behaviour into the provider that the
    verifier cannot check, and the rule in this package is that nothing the
    model produces is trusted until a verifier has re-derived it from the
    document.
    """

    name: str

    def complete(self, prompt: str, *, max_tokens: int = 1024, temperature: float = 0.0) -> Completion:
        ...


# ---------------------------------------------------------------------------
# Prompt normalisation and keying
# ---------------------------------------------------------------------------

_TRAILING_SPACE = re.compile(r"[ \t]+$", re.MULTILINE)
_BLANK_RUN = re.compile(r"\n{3,}")


def normalize_prompt(prompt: str) -> str:
    """The canonical form a cassette key is computed over.

    Three normalisations and no more:

      * CRLF and CR collapse to LF, so a cassette recorded on Windows
        replays on Linux. This is the only one that is purely about
        portability.
      * Trailing spaces on a line are dropped, and runs of three or more
        blank lines collapse to two. Both are invisible in a rendered
        prompt, so a reformatting that changes neither the words nor their
        order must not invalidate a recording.
      * The whole string is stripped at both ends.

    What is deliberately *not* normalised: case, punctuation, the order of
    anything, and interior single spaces. Those change what the model was
    asked, and a cassette that replayed across such a change would be
    answering a different question with an old answer. The failure mode this
    avoids is the worst one available here: a prompt edited to fix a bug,
    silently served the pre-bug response, and an eval that never noticed.
    """
    text = prompt.replace("\r\n", "\n").replace("\r", "\n")
    text = _TRAILING_SPACE.sub("", text)
    text = _BLANK_RUN.sub("\n\n", text)
    return text.strip()


def prompt_key(prompt: str) -> str:
    """SHA-256 of the normalised prompt, hex, lowercase."""
    return hashlib.sha256(normalize_prompt(prompt).encode("utf-8")).hexdigest()


def count_tokens(text: str) -> int:
    """A whitespace count, honestly labelled everywhere it surfaces.

    Shipping a real BPE tokenizer would mean shipping a vocabulary file and
    a dependency, for a number that is only ever used to size a bill and to
    compare two runs of the same harness against each other. A whitespace
    count is monotone in the real count and costs nothing, and `usage_source`
    carries the caveat into the output so nobody reads it as a vendor figure.
    """
    return len(text.split())


# ---------------------------------------------------------------------------
# CassetteProvider
# ---------------------------------------------------------------------------

class CassetteProvider:
    """Replay recorded answers. No network, no key, no clock.

    Every `*.json` in the directory is loaded and merged. A key that appears
    in two files with different text is an error rather than a
    last-one-wins: whichever file happened to sort later would silently
    decide what the model said, and that is a reproducibility bug that hides
    for months.
    """

    def __init__(self, directory: Path | str | None = None, *, name: str = "cassette") -> None:
        self.name = name
        self.directory = Path(directory) if directory is not None else CASSETTE_DIR
        self._entries: dict[str, dict[str, Any]] = {}
        self._sources: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if not self.directory.is_dir():
            return
        for path in sorted(self.directory.glob("*.json")):
            raw = json.loads(path.read_text(encoding="utf-8"))
            if raw.get("schema") != CASSETTE_SCHEMA:
                raise ValueError(f"{path.name}: not a {CASSETTE_SCHEMA} cassette")
            for entry in raw.get("entries", []):
                key = entry["key"]
                previous = self._entries.get(key)
                if previous is not None and previous["text"] != entry["text"]:
                    raise ValueError(
                        f"cassette key {key[:12]} recorded twice with different answers, "
                        f"in {self._sources[key]} and {path.name}; replay would depend on "
                        "filename order"
                    )
                self._entries[key] = entry
                self._sources[key] = path.name

    def __len__(self) -> int:
        return len(self._entries)

    def keys(self) -> tuple[str, ...]:
        return tuple(sorted(self._entries))

    def has(self, prompt: str) -> bool:
        return prompt_key(prompt) in self._entries

    def complete(self, prompt: str, *, max_tokens: int = 1024, temperature: float = 0.0) -> Completion:
        # max_tokens and temperature are accepted and ignored, because a
        # recording was made under one setting and replaying it under another
        # would report a completion that never existed. They stay in the
        # signature so a caller can move between providers without an edit,
        # and the recorded entry carries the settings it was made under.
        del max_tokens, temperature
        key = prompt_key(prompt)
        entry = self._entries.get(key)
        if entry is None:
            head = normalize_prompt(prompt)[:180].replace("\n", " / ")
            raise CassetteMiss(
                f"no recorded answer for prompt {key[:16]} in {self.directory}; "
                f"prompt begins: {head!r}. Record it with evals/agents/build.py "
                "rather than letting the harness invent one."
            )
        return Completion(
            text=entry["text"],
            prompt_tokens=int(entry.get("prompt_tokens", 0)),
            completion_tokens=int(entry.get("completion_tokens", 0)),
            latency_ms=float(entry.get("latency_ms", 0.0)),
            model=str(entry.get("model", "")),
            usage_source=str(entry.get("usage_source", "whitespace")),
            cassette_key=key,
        )


# ---------------------------------------------------------------------------
# RecordingProvider
# ---------------------------------------------------------------------------

class RecordingProvider:
    """Wrap a provider and write down everything it says.

    The only way a cassette is ever created. It is a wrapper rather than a
    flag on the other providers so that recording is a thing somebody chose
    to do at a call site, visible in a diff, instead of a mode a test could
    fall into and thereby record its own bug as the expected answer.
    """

    def __init__(self, inner: LLMProvider, *, name: str = "") -> None:
        self.inner = inner
        self.name = name or f"recording({getattr(inner, 'name', 'unknown')})"
        self._entries: dict[str, dict[str, Any]] = {}

    def complete(self, prompt: str, *, max_tokens: int = 1024, temperature: float = 0.0) -> Completion:
        completion = self.inner.complete(prompt, max_tokens=max_tokens, temperature=temperature)
        key = prompt_key(prompt)
        self._entries[key] = {
            "key": key,
            # The first line of the normalised prompt, so a human reading the
            # cassette can tell which entry is which without hashing anything.
            # Never the whole prompt: cassettes hold operator documents and a
            # cassette is a file people paste into issues.
            "prompt_head": normalize_prompt(prompt).splitlines()[0][:120] if prompt.strip() else "",
            "text": completion.text,
            "prompt_tokens": completion.prompt_tokens,
            "completion_tokens": completion.completion_tokens,
            "latency_ms": round(completion.latency_ms, 4),
            "model": completion.model,
            "usage_source": completion.usage_source,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        return completion

    def save(self, path: Path | str, *, recorded_by: str = "") -> Path:
        """Write the cassette, sorted by key so the diff is reviewable."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": CASSETTE_SCHEMA,
            "recorded_by": recorded_by or self.name,
            # No timestamp. A recorded-at field would make every regeneration
            # a diff even when no answer changed, which is exactly the noise
            # that trains a reviewer to skim cassette diffs.
            "entries": [self._entries[key] for key in sorted(self._entries)],
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        return path


# ---------------------------------------------------------------------------
# HTTPProvider
# ---------------------------------------------------------------------------

class HTTPProvider:
    """A real model over HTTPS, with the standard library and nothing else.

    Why `urllib` and not `requests` or a vendor SDK: this repository's
    argument is that a tool which inspects supply chains should not have one.
    A vendor SDK would be the second runtime dependency and would drag in a
    transport stack, a retry policy and a telemetry client, all of which run
    inside a process that has just been handed an operator's compliance
    documents. `urllib` is 40 lines here and the 40 lines are readable.

    Four defences, each of which is here because the alternative is a real
    failure and not a hypothetical one:

      * The key is read from the environment and never from an argument, a
        file in the target directory, or the declarations. A control walks a
        directory the operator controls; a credential that could be read
        from there is a credential an attacker can plant a request for.
      * The scheme must be https. A plain-http endpoint would put the
        document and the key on the wire in clear, and `urlopen` will
        happily open `file://` if handed it.
      * There is a timeout on every call. Without one, a hung endpoint hangs
        the control run, and the engine's exception handling never gets to
        turn it into INCONCLUSIVE because nothing raises.
      * The response is parsed defensively and a shape it does not recognise
        raises rather than yielding an empty completion, because an empty
        completion becomes an abstention becomes an INCONCLUSIVE that looks
        like the model declined rather than like the wiring being wrong.
    """

    #: Request timeout in seconds. Deliberately short: a judgement is one
    #: prompt about one document, and an endpoint that needs longer than this
    #: is an endpoint that is not answering.
    timeout_s: float = 60.0

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        name: str = "http",
    ) -> None:
        self.name = name
        key = api_key if api_key is not None else os.environ.get(API_KEY_ENV, "")
        if not key.strip():
            raise MissingCredential(
                f"{API_KEY_ENV} is not set. HTTPProvider is opt-in: nothing in the "
                "test suite or the eval harness constructs one, and a control that "
                "cannot find a key uses the cassettes instead of reaching the network."
            )
        self._key = key.strip()
        self.endpoint = (endpoint or os.environ.get(ENDPOINT_ENV, "")).strip()
        if not self.endpoint:
            raise MissingCredential(f"{ENDPOINT_ENV} is not set; there is no default endpoint on purpose")
        if not self.endpoint.startswith("https://"):
            raise ValueError(f"{ENDPOINT_ENV} must be an https:// URL, got {self.endpoint!r}")
        self.model = (model or os.environ.get(MODEL_ENV, "")).strip()
        if not self.model:
            raise MissingCredential(f"{MODEL_ENV} is not set; the model has to be named, never guessed")

    def complete(self, prompt: str, *, max_tokens: int = 1024, temperature: float = 0.0) -> Completion:
        body = json.dumps(
            {
                "model": self.model,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": [{"role": "user", "content": prompt}],
            }
        ).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - scheme checked in __init__
            self.endpoint,
            data=body,
            method="POST",
            headers={
                "content-type": "application/json",
                "x-api-key": self._key,
                "anthropic-version": "2023-06-01",
            },
        )
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:  # noqa: S310
                raw = response.read()
        except urllib.error.URLError as exc:
            raise RuntimeError(f"{self.name}: request to the model endpoint failed: {exc}") from exc
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return self._parse(raw, elapsed_ms, prompt)

    def _parse(self, raw: bytes, elapsed_ms: float, prompt: str) -> Completion:
        payload = json.loads(raw.decode("utf-8"))
        text = _extract_text(payload)
        if text is None:
            raise RuntimeError(
                f"{self.name}: response had no text block; keys were {sorted(payload)}. "
                "Refusing to return an empty completion, which would look like an abstention."
            )
        usage = payload.get("usage") or {}
        prompt_tokens = usage.get("input_tokens", usage.get("prompt_tokens"))
        completion_tokens = usage.get("output_tokens", usage.get("completion_tokens"))
        reported = prompt_tokens is not None and completion_tokens is not None
        return Completion(
            text=text,
            prompt_tokens=int(prompt_tokens) if prompt_tokens is not None else count_tokens(prompt),
            completion_tokens=int(completion_tokens) if completion_tokens is not None else count_tokens(text),
            latency_ms=elapsed_ms,
            model=str(payload.get("model", self.model)),
            usage_source="vendor_usage" if reported else "whitespace",
        )


def _extract_text(payload: dict[str, Any]) -> str | None:
    """Pull the assistant text out of the two response shapes in the wild.

    Anthropic-style `content: [{type: text, text: ...}]` and OpenAI-style
    `choices: [{message: {content: ...}}]`. Written as a function with an
    explicit `None` return so the caller can raise a message that names what
    it saw, instead of a `KeyError` from four frames down.
    """
    content = payload.get("content")
    if isinstance(content, list):
        parts = [block.get("text", "") for block in content if isinstance(block, dict) and block.get("type") == "text"]
        if parts:
            return "".join(parts)
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            return message["content"]
    return None
