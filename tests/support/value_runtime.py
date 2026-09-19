"""The SECOND view of point 1, derived a different way on purpose: the resolver
run over the corpus, recording every vendor key whose value it actually touched.

WHY A SECOND VIEW AT ALL, which is the whole argument for this file. The static
reader in `value_sites.py` read 10 keys, then 20, then 16, then 15, as it
learned four shapes it had been blind to. No version of it ever said it was
missing anything - each one returned a number and the number looked like an
answer. A guard that fails when the count DROPS would have passed at 10. The
only thing that can find a blindness is a view that was not derived the same
way, so this one is derived by RUNNING the resolver rather than by reading it.

  static MINUS runtime   the corpus does not exercise that site. A statement to
                         be declared, not a failure.
  runtime MINUS static   the static reader is blind to a shape. That is the
                         defect being hunted.

NOTHING IN `src/` IS TOUCHED, and that is not a convenience, it is the point.
`resolve()` is a pure function over a frozen `Reading` whose `data` is a plain
mapping, so the instrument is a mapping that records what is asked of it and a
string that records what it is compared against. Instrumenting the resolver by
editing the resolver would measure the edited resolver.

THE TRAP THAT WOULD MAKE THIS SILENT, named because it nearly happened: the
resolver is full of `isinstance(x, dict)` and `isinstance(x, str)`. A recorder
built on `collections.abc.Mapping` instead of `dict` fails every one of those
checks, the resolver sees nothing, and the runtime view comes back EMPTY -
which reads exactly like "the corpus exercises nothing" and would make the
comparison above pass over two empty sets. Both recorders are SUBCLASSES of the
built-in type for that reason, and `test_the_runtime_view_saw_the_corpus` is
what keeps an empty result from being mistaken for an answer.

WHAT IS RECORDED AND WHAT IS NOT, IN ONE LINE SO IT IS NOT DECIDED THREE TIMES.
A comparison that IDENTIFIES BOTH ITS OPERANDS is recorded: `==`, `!=`,
membership over a sequence, `startswith`, `endswith`, substring `in`. Anything
that only leaves a trace THAT THE VALUE WAS TOUCHED is not recorded, and is
declared instead. Three things fall on that side and the line settles all
three at once:

  hash        `x in frozenset` resolves by hashing and never calls `__eq__`.
              REJECTED: recording `__hash__`. What it yields is "this value was
              hashed somewhere", which does not say against what. Mixing
              evidence of two strengths in one output is the work rule 10
              failure; a declared hole beats a weak record filed among strong
              ones.
  length      `bool` cannot be subclassed, and a string in a boolean context
              goes through `__len__`. REJECTED for the same reason: `__len__`
              is called by formatting and joining too, so it says the value was
              touched and not that it was tested.
  truthiness  `entry.get("url") or entry.get("httpUrl")` picks a transport and
              never compares. Same rejection, same reason.

AND A LIMIT OF THE METHOD, NOT OF THE INSTRUMENT. `watched()` is applied to the
`Reading` that `read()` ALREADY RETURNED, so every decision a READER takes
while reading is outside this view. For those decisions THERE IS ONE VIEW AND
NOT TWO - the static one - which is the situation work rule 10 exists against.
What protects them is not agreement between views: it is the planted test of
gate point 3, which enters through the CLI and does not know or care where the
decision was taken. Nobody may read "the two views agree" as covering a
reader. Two sites are known to fall here, `type` at claude_code.py:186 in
`command_strings` and `notify` at codex.py:228.

EXTENDING THIS TO THE READERS IS MEASURED AND DEFERRED, with the number: a
parsed document is built at FIVE sites, not one - `disk.read_json`,
`vscode.read_jsonc` and `codex.read_toml`, which are shared helpers, plus two
inline ones at codex.py:177 and claude_code.py:355. `docs/BACKLOG.md` carries
the line with the argument and with the signal that would justify building it.
"""
from __future__ import annotations

import dataclasses
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from support.value_sites import ours

_THIS_FILE = Path(__file__).name

# WHOSE DOCUMENT A KEY BELONGS TO, taken from the one declaration of it. What
# is shared with the static view is this FACT and never the derivation: the two
# views must disagree about what the resolver does, and agree about which
# documents this tool wrote itself. Without it the runtime view reports
# `imports` - a key `instructions.py` synthesises because a CLAUDE.md has no
# keys - as a vendor key the static reader was blind to.
OURS = ours()


# How a key is spelled so the two views can be compared at all. The static
# reader sees `defaultMode` where this one walks `permissions` then
# `defaultMode`, and it sees the whole of `general.defaultApprovalMode` because
# `dig` takes a dotted path. Both are reduced the same way - the last segment -
# so the comparison is between two spellings of one thing rather than between
# two conventions.
def leaf(key: str) -> str:
    return key.rsplit(".", 1)[-1]


class Recorder:
    """What both instruments write into.

    `compared` holds PAIRS OF KEY AND LINE, never a bare set of keys, and that
    is the whole reason the misattribution in `_sandbox` is catchable: the
    static view claimed a site the runtime view never observes, and two sets of
    key names agree happily about that. `sites()` is what the guard compares.
    """

    def __init__(self) -> None:
        self.consulted: dict[str, set[str]] = defaultdict(set)
        self.compared: dict[str, set[tuple[str, int]]] = defaultdict(set)
        self.vendors: dict[str, set[str]] = defaultdict(set)

    def consult(self, path: str, vendor: str) -> None:
        if leaf(path) in OURS:
            return
        self.consulted[leaf(path)].add(vendor)

    def compare(self, path: str, vendor: str) -> None:
        key = leaf(path)
        if key in OURS:
            return
        self.compared[key].add(_caller())
        self.vendors[key].add(vendor)

    def sites(self) -> dict[str, set[tuple[str, int]]]:
        return {key: set(where) for key, where in self.compared.items()}


def _caller() -> tuple[str, int]:
    """The first frame outside this instrument: the line that decided.

    The stack and not a guess. It is the same capture that verified
    `allowedDomains` at resolve.py:1144 and `args` at resolve.py:1208 by hand,
    made part of the record instead of a thing somebody checks once.
    """
    frame = sys._getframe(1)
    while frame is not None and Path(frame.f_code.co_filename).name == _THIS_FILE:
        frame = frame.f_back
    if frame is None:  # pragma: no cover - there is always a caller
        return ("?", 0)
    return (Path(frame.f_code.co_filename).name, frame.f_lineno)


class WatchedStr(str):
    """A string that records being decided upon, and behaves as a string otherwise.

    FIVE METHODS, AND THE LINE BETWEEN THEM AND THE REST IS THE STRENGTH OF THE
    EVIDENCE. `==`, `!=`, `startswith`, `endswith` and substring `in` all say
    the same thing at the same strength: THIS VALUE WAS TESTED AGAINST THAT.
    `in` over a tuple compares elements and Python tries the subclass operand
    first, so membership over a sequence is recorded by `__eq__`.

    `startswith` and the other two are not padding: `_pinned` decides with
    `argument.startswith("-")` and `"@" in argument[1:]` and never with `==`,
    so `args` - which four corpus fixtures exercise - was invisible until they
    were added.

    `__hash__` is kept from `str` explicitly: defining `__eq__` would otherwise
    make it unhashable, and the resolver puts these in sets.
    """

    __slots__ = ("_recorder", "_path", "_vendor")

    def __new__(cls, value: str, recorder: Recorder, path: str, vendor: str):
        self = super().__new__(cls, value)
        self._recorder = recorder
        self._path = path
        self._vendor = vendor
        return self

    def _decided(self) -> None:
        self._recorder.compare(self._path, self._vendor)

    def __eq__(self, other: object) -> bool:
        self._decided()
        return str.__eq__(self, other)

    def __ne__(self, other: object) -> bool:
        self._decided()
        return str.__ne__(self, other)

    def startswith(self, *args, **kwargs) -> bool:  # noqa: D102 - str's own contract
        self._decided()
        return str.startswith(self, *args, **kwargs)

    def endswith(self, *args, **kwargs) -> bool:  # noqa: D102 - str's own contract
        self._decided()
        return str.endswith(self, *args, **kwargs)

    def __contains__(self, item: object) -> bool:
        self._decided()
        return str.__contains__(self, item)

    __hash__ = str.__hash__


class WatchedDict(dict):
    """A mapping that records which keys are asked for, and wraps what it hands back.

    A `dict` subclass, never a `Mapping`: see the trap in the module docstring.
    """

    def __init__(self, data: dict, recorder: Recorder, prefix: str, vendor: str):
        super().__init__(data)
        self._recorder = recorder
        self._prefix = prefix
        self._vendor = vendor

    def _path(self, key: Any) -> str:
        return f"{self._prefix}.{key}" if self._prefix else str(key)

    def _wrap(self, key: Any, value: Any) -> Any:
        path = self._path(key)
        if isinstance(value, WatchedDict | WatchedStr):
            return value
        if isinstance(value, dict):
            return WatchedDict(value, self._recorder, path, self._vendor)
        if isinstance(value, str):
            return WatchedStr(value, self._recorder, path, self._vendor)
        if isinstance(value, list):
            return [self._wrap(key, item) for item in value]
        return value

    def get(self, key: Any, default: Any = None) -> Any:
        if key in self:
            self._recorder.consult(self._path(key), self._vendor)
            return self._wrap(key, super().__getitem__(key))
        return default

    def __getitem__(self, key: Any) -> Any:
        self._recorder.consult(self._path(key), self._vendor)
        return self._wrap(key, super().__getitem__(key))

    def items(self):
        # The event of a hook is a KEY of this mapping, not a value read by
        # key, and `event in STARTUP_EVENTS` is a decision about it. Handing
        # back a watched key is how that decision is seen at all.
        for key, value in super().items():
            watched_key = WatchedStr(key, self._recorder, self._path("<event>"), self._vendor)
            yield watched_key, self._wrap(key, value)

    def values(self):
        return [self._wrap(key, value) for key, value in super().items()]


def watched(reading: Any, recorder: Recorder) -> Any:
    """`reading` with every parsed document replaced by a recording one.

    `dataclasses.replace`, because `Reading` and `SettingsFile` are frozen and
    a test that mutated them would be testing something the tool cannot build.
    """
    vendor = getattr(reading, "vendor", "?")

    def wrap_files(files: tuple) -> tuple:
        rebuilt = []
        for handle in files:
            if handle.data is None:
                rebuilt.append(handle)
                continue
            rebuilt.append(
                dataclasses.replace(
                    handle, data=WatchedDict(handle.data, recorder, "", vendor)
                )
            )
        return tuple(rebuilt)

    return dataclasses.replace(
        reading,
        settings=wrap_files(reading.settings),
        mcp_files=wrap_files(reading.mcp_files),
    )
