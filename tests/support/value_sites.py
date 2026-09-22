"""Point 1 of phase S3.1, the STATIC view: every vendor key whose value the
resolver reads in order to decide something, found by reading the resolver.

WHY IT IS DERIVED AND NOT TYPED. A typed inventory is satisfied by whoever
decides not to add a line, which is what work rule 11 forbids. This walks the
resolver and answers by reading it, so a key that starts being read to decide
appears on its own and one that stops disappears on its own.

THE CRITERION, AND IT IS ONE LINE. A value is READ TO DECIDE when it reaches a
comparison that IDENTIFIES BOTH ITS OPERANDS: `==`, `!=`, membership over a
sequence, `startswith`, `endswith`, substring `in`, or the test of an `if`.
Storing it in `facts`, digesting it or handing it on as evidence is not
deciding. The same line governs the runtime view in `value_runtime.py`, where
it is written once with the three things it excludes and why.

`X or []` IS NOT A DECISION. It is the guard against `None` before iterating,
and counting it reported three keys that decide nothing - `allow`,
`additionalDirectories` and `excludedCommands` all arrived through that idiom
alone. An `or` between two real values - `entry.get("url") or
entry.get("httpUrl")`, which picks a transport - is a decision and stays.

A MARK PER BINDING SITE, WHICH IS THE CORRECTION THAT MATTERS. Every binding of
a name opens a NEW mark, living from that binding until the next binding of the
same name in source order. The first version kept one mark per name per
function, last writer winning, and `_sandbox` binds `entry` twice - line 1130
for `excludedCommands`, line 1142 for `allowedDomains`. So `excludedCommands`
was LOST and its decision was credited to `allowedDomains`, which then showed a
site it never had.

A CORRECT TOTAL AND TWO AGREEING VIEWS CAN COEXIST WITH A LOST KEY AND A
PHANTOM SITE. Thirteen keys, both views agreeing, one key missing. That is the
finding of this phase and it is why the comparison between the views is over
PAIRS of key and line and never over sets of keys. A loop target is one case of
a binding and not a rule of its own: `x = data["a"]` and then `x = data["b"]`
further down is the same defect with no loop in it.

TWO LIMITS THIS LEAVES, declared rather than absorbed. A name bound in two
branches of an `if` and used after them keeps whichever binding comes later in
source order. A name bound inside a loop and used after it keeps that binding.
Neither is a guess about the corpus: the guard measures how many of each shape
the resolver actually contains and says so.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

from conftest import REPO_ROOT

RESOLVERS = Path(REPO_ROOT) / "src" / "actaira" / "surface"

# Not resolvers of a vendor's file, each with its reason. The parsers turn
# bytes into documents and decide nothing about what a value means; `diff` and
# `rules` read ACTAIRA'S OWN documents, so their comparisons are about this
# tool's vocabulary and belong to no vendor.
NOT_A_RESOLVER = {
    "jsonc.py": "a parser: every comparison in it is about syntax",
    "miniyaml.py": "a parser: every comparison in it is about syntax",
    "__init__.py": "re-exports",
    "diff.py": "reads Actaira's own capability documents, not a vendor's file",
    "rules.py": "evaluates rules over Actaira's own documents",
}

# WHERE THIS TOOL SYNTHESISES A DOCUMENT, and therefore where the key names are
# OURS. A key is ours when OUR CODE wrote its name while building the document,
# not when it came off the user's disk. A reader that parses - YAML, JSON,
# TOML - produces keys whose names came from the disk. A reader that
# SYNTHESISES produces keys whose names are literals in our source.
#
# THE DECLARATION IS OF SITES AND NEVER OF KEY NAMES; the names are derived
# from the literal at the site. Listing the names by hand would be a second
# definition of a fact the source already states - work rule 10 - and would go
# stale in silence the day a synthesiser grows a field. Excluding the whole
# FILE would be worse: the day that reader parses a real vendor key, a
# declaration made for something else swallows it, which is fail-open.
#
# WHAT HOLDS THE EXCLUSION IS THE ANCHOR TO THE SITE, NOT THE NAME. If a vendor
# ever publishes a key called `imports`, it arrives through a different piece
# of code and is not covered. `collisions()` below is a belt over those braces
# and MUST NOT be read as what makes this safe: its real value is catching the
# day somebody weakens the anchor back into a list of names.
SYNTHESISED_AT = (
    ("instructions.py", 181, "a CLAUDE.md has `@path` syntax, not keys"),
    ("resolve.py", 279, "the managed-sandbox mapping, when nothing is managed"),
    ("resolve.py", 296, "the managed-sandbox mapping handed to `_sandbox`"),
)

# Predicates that identify both operands, at the same strength as `==`.
PREDICATE_METHODS = ("startswith", "endswith")

MAX_DEPTH = 4


def _modules() -> dict[str, ast.Module]:
    found = {}
    for path in sorted(RESOLVERS.glob("*.py")):
        if path.name in NOT_A_RESOLVER:
            continue
        found[path.name] = ast.parse(path.read_text(encoding="utf-8"))
    return found


def ours() -> dict[str, str]:
    """{key name: the site that synthesised it}, derived from the sites."""
    found: dict[str, str] = {}
    for module, line, why in SYNTHESISED_AT:
        tree = ast.parse((RESOLVERS / module).read_text(encoding="utf-8"))
        literals = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Dict) and node.lineno == line
        ]
        if not literals:
            raise AssertionError(
                f"{module}:{line} is declared as a site that synthesises a document "
                f"({why}) and there is no dict literal there any more. The "
                "declaration is of SITES: move it to the line that builds the "
                "document. Do not replace it with a list of key names."
            )
        for literal in literals:
            for key in literal.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    found[key.value] = f"{module}:{line}"
    return found


def _is_none_guard(node: ast.BoolOp) -> bool:
    """`X or []`, `X or {}`, `X or ()` - the idiom for "or nothing to iterate"."""
    if not isinstance(node.op, ast.Or) or len(node.values) != 2:
        return False
    right = node.values[1]
    if isinstance(right, ast.List | ast.Tuple) and not right.elts:
        return True
    return bool(isinstance(right, ast.Dict) and not right.keys)


def _receiver(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - unparse handles every node built here
        return ""


def _key_read(
    node: ast.AST, constants: dict[str, str], owned: dict[str, str]
) -> str | None:
    """The vendor key this expression reads, when it reads one.

    FOUR SPELLINGS, each here because a version of this reader missed keys
    without it: a literal `x.get("k")` or `x["k"]`; `dig(data, "a.b")`, the
    dotted path; and `x.get(CONSTANT)`, which is how this repository names a
    key worth naming once.
    """
    key: str | None = None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "dig"
        and len(node.args) == 2
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
    ):
        key = node.args[1].value
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and node.args
    ):
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            key = first.value
        elif isinstance(first, ast.Name) and first.id in constants:
            key = constants[first.id]
        if key is not None and _receiver(node.func.value) in ("os.environ", "environ"):
            key = None
    elif (
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
    ):
        key = node.slice.value

    if key is not None and key in owned:
        return None
    return key


def _string_constants(modules: dict[str, ast.Module]) -> dict[str, dict[str, str]]:
    """{module: {NAME: value}} for module-level `NAME = "literal"` bindings."""
    return {
        name: {
            node.targets[0].id: node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id.isupper()
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        }
        for name, tree in modules.items()
    }


def _ordered(fn: ast.FunctionDef) -> list[ast.AST]:
    """Every node of the function IN SOURCE ORDER.

    `ast.walk` is breadth-first and says nothing about position, and a mark
    that lives from one binding to the next needs position.
    """
    return sorted(
        (node for node in ast.walk(fn) if hasattr(node, "lineno")),
        key=lambda node: (node.lineno, node.col_offset),
    )


class _Walk:
    def __init__(self) -> None:
        self.modules = _modules()
        self.constants = _string_constants(self.modules)
        self.owned = ours()
        self.functions: dict[str, tuple[str, ast.FunctionDef]] = {}
        for name, tree in self.modules.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    self.functions[node.name] = (name, node)
        # {function: {position: key}}; position -1 is a bare return.
        self.returns: dict[str, dict[int, str]] = {}
        self.sites: dict[str, set[tuple[str, int]]] = defaultdict(set)

    def run(self) -> dict[str, set[tuple[str, int]]]:
        for _ in range(MAX_DEPTH):
            before = {name: dict(table) for name, table in self.returns.items()}
            self.sites = defaultdict(set)
            for module, tree in self.modules.items():
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        self._function(node, module, {})
            if self.returns == before:
                break
        return dict(self.sites)

    def _function(
        self, fn: ast.FunctionDef, module: str, inherited: dict[str, str], depth: int = 0
    ) -> None:
        if depth > MAX_DEPTH:
            return
        marks = dict(inherited)
        for node in _ordered(fn):
            self._bind(node, module, marks)
            self._decision(node, module, marks)
            self._forward(node, module, marks, depth)
            if isinstance(node, ast.Return) and node.value is not None:
                self._record_return(fn.name, node.value, module, marks)

    def _bind(self, node: ast.AST, module: str, marks: dict[str, str]) -> None:
        """Every binding opens a new mark for that name, replacing the last."""
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if (
                isinstance(target, ast.Tuple)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
            ):
                by_position = self.returns.get(node.value.func.id, {})
                for position, element in enumerate(target.elts):
                    if isinstance(element, ast.Name):
                        if position in by_position:
                            marks[element.id] = by_position[position]
                        else:
                            marks.pop(element.id, None)
                return
            if not isinstance(target, ast.Name):
                return
            key = self._origin(node.value, marks, module)
            if key is None and isinstance(
                node.value, ast.ListComp | ast.SetComp | ast.GeneratorExp
            ):
                # A list built by a comprehension carries what its element
                # carried: `[item for item in (entry.get("args") or [])]`.
                for generator in node.value.generators:
                    self._bind_iteration(generator, module, marks)
                key = self._origin(node.value.elt, marks, module)
            if key:
                marks[target.id] = key
            else:
                # A binding to something untracked CLEARS the mark. Leaving the
                # old one is the last-writer-wins defect from the other side.
                marks.pop(target.id, None)
        elif isinstance(node, ast.For | ast.comprehension):
            self._bind_iteration(node, module, marks)

    def _bind_iteration(self, node: ast.AST, module: str, marks: dict[str, str]) -> None:
        iterated = node.iter
        if isinstance(iterated, ast.BoolOp) and iterated.values:
            iterated = iterated.values[0]
        key = self._origin(iterated, marks, module)
        target = node.target
        if isinstance(target, ast.Name):
            if key:
                marks[target.id] = key
            else:
                marks.pop(target.id, None)
        elif isinstance(target, ast.Tuple) and key:
            # `for event, matchers in hooks.items()`: the EVENT is a key of the
            # mapping, and `event in STARTUP_EVENTS` decides about it.
            if (
                isinstance(node.iter, ast.Call)
                and isinstance(node.iter.func, ast.Attribute)
                and node.iter.func.attr == "items"
            ):
                first = target.elts[0]
                if isinstance(first, ast.Name):
                    marks[first.id] = f"{key}.<event>"

    def _origin(self, node: ast.AST, marks: dict[str, str], module: str) -> str | None:
        if isinstance(node, ast.Name):
            return marks.get(node.id)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            returned = self.returns.get(node.func.id, {})
            if -1 in returned:
                return returned[-1]
        return _key_read(node, self.constants.get(module, {}), self.owned)

    def _decision(self, node: ast.AST, module: str, marks: dict[str, str]) -> None:
        where = (module, getattr(node, "lineno", 0))
        if isinstance(node, ast.Compare) and any(
            isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)) for op in node.ops
        ):
            for side in [node.left, *node.comparators]:
                key = self._origin(side, marks, module)
                if key:
                    self.sites[key].add(where)
        elif isinstance(node, ast.If):
            key = self._origin(node.test, marks, module)
            if key:
                self.sites[key].add(where)
        elif isinstance(node, ast.BoolOp) and not _is_none_guard(node):
            for value in node.values:
                key = self._origin(value, marks, module)
                if key:
                    self.sites[key].add(where)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in PREDICATE_METHODS
        ):
            key = self._origin(node.func.value, marks, module)
            if key:
                self.sites[key].add(where)
        elif isinstance(node, ast.Subscript) and not isinstance(node.slice, ast.Constant):
            # AN EIGHTH SHAPE, AND THE MOST CONSEQUENTIAL ONE: the value used
            # as the SUBSCRIPT into a mapping. `{"command": "hook.command",
            # "http": "hook.http", "mcp_tool": "hook.mcp_tool"}[kind]` picks
            # the capability's NAME from the handler type, which is the
            # strongest decision the resolver takes about any value, and this
            # reader was blind to it through five passes. The runtime view is
            # what found it: a successful lookup confirms the match with `==`,
            # so the instrument saw at resolve.py:938 what reading never did.
            key = self._origin(node.slice, marks, module)
            if key:
                self.sites[key].add(where)

    def _forward(
        self, node: ast.AST, module: str, marks: dict[str, str], depth: int
    ) -> None:
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            return
        if node.func.id not in self.functions:
            return
        callee_module, callee = self.functions[node.func.id]
        passed: dict[str, str] = {}
        for index, argument in enumerate(node.args):
            key = self._origin(argument, marks, module)
            if key and index < len(callee.args.args):
                passed[callee.args.args[index].arg] = key
        if passed:
            self._function(callee, callee_module, passed, depth + 1)

    def _record_return(
        self, name: str, value: ast.AST, module: str, marks: dict[str, str]
    ) -> None:
        if isinstance(value, ast.Tuple):
            for position, element in enumerate(value.elts):
                key = self._origin(element, marks, module)
                if key:
                    self.returns.setdefault(name, {})[position] = key
            return
        key = self._origin(value, marks, module)
        if key:
            self.returns.setdefault(name, {})[-1] = key


def inventory() -> dict[str, set[tuple[str, int]]]:
    """{vendor key: {(file, line), ...}} for every value read to decide."""
    return _Walk().run()


def rebound_names() -> list[tuple[str, str, int]]:
    """The two declared limits, MEASURED rather than assumed.

    A name bound more than once in one function is where a mark per binding
    site matters, and the two shapes that defeat source order - two branches of
    an `if`, and a binding inside a loop used after it - live among these. The
    guard prints what it found rather than claiming the corpus is clean.
    """
    found: list[tuple[str, str, int]] = []
    for module, tree in _modules().items():
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            seen: dict[str, int] = {}
            for node in _ordered(fn):
                targets: list[ast.AST] = []
                if isinstance(node, ast.Assign):
                    targets = list(node.targets)
                elif isinstance(node, ast.For | ast.comprehension):
                    targets = [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        if target.id in seen:
                            found.append((module, f"{fn.name}:{target.id}", node.lineno))
                        seen[target.id] = node.lineno
    return found
