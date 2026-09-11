"""Import policy for pickle-based artifacts.

Design note D-02, and the single most important decision in this project.

A pickle can execute arbitrary code at load time. Every tool in this space
has to decide how to judge the callables a pickle imports. There are two
possible policies:

  known-bad (denylist)  flag imports that appear on a list of dangerous
                        callables (os.system, subprocess.Popen, ...).
  strict   (allowlist)  flag every import that is NOT on a list of callables
                        known to be part of legitimate tensor
                        deserialisation.

A denylist can only ever recognise what its author already thought of, so it
fails open: an unknown gadget is silently accepted. An allowlist fails
closed: an unknown callable is reported, at the cost of false positives on
legitimate-but-unusual artifacts.

Actaira implements BOTH and defaults to `strict`, because in a supply-chain
tool a missed detection costs far more than a review. `known-bad` is kept
precisely so the eval harness can measure the difference between the two on
the same corpus; `evals/README` publishes that number rather than asserting
the argument. The cost of `strict` is also measured, as false positives on
the benign half of the corpus.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Allowlist: callables that legitimately appear when deserialising tensors.
#
# Entries are (module, name) pairs, or a module prefix ending in ".*" meaning
# "any name in this module". Prefix entries are deliberately rare and each
# one is a documented risk acceptance, because a prefix widens the hole.
# ---------------------------------------------------------------------------
ALLOWED_CALLABLES: frozenset[tuple[str, str]] = frozenset(
    {
        # numpy tensor reconstruction
        ("numpy", "ndarray"),
        ("numpy", "dtype"),
        ("numpy.core.multiarray", "_reconstruct"),
        ("numpy.core.multiarray", "scalar"),
        ("numpy._core.multiarray", "_reconstruct"),
        ("numpy._core.multiarray", "scalar"),
        ("numpy.core.numeric", "_frombuffer"),
        # torch tensor reconstruction
        ("torch", "Tensor"),
        ("torch", "Size"),
        ("torch", "device"),
        ("torch", "dtype"),
        ("torch._utils", "_rebuild_tensor"),
        ("torch._utils", "_rebuild_tensor_v2"),
        ("torch._utils", "_rebuild_parameter"),
        ("torch._utils", "_rebuild_sparse_tensor"),
        ("torch._utils", "_rebuild_meta_tensor_no_storage"),
        # ("torch.storage", "_load_from_bytes") was here, catalogued as tensor
        # reconstruction. Its body is torch.load(BytesIO(b), weights_only=False):
        # a full unpickler on attacker-supplied bytes with the safe mode off. An
        # adversarial review used it to carry a gadget past both policies to a
        # clean PASS. It is now handled as a nested loader, and the bytes it is
        # given are disassembled rather than trusted. See D-35.
        ("torch.serialization", "_get_layout"),
        # codecs used by pickle protocols 0-2 to carry numpy raw bytes.
        # Risk acceptance A-02: `_codecs.encode(str, codec)` decodes text, it
        # does not dispatch to arbitrary user code. It was added because the
        # benign half of the corpus proved it fires on every protocol 0-2
        # state_dict; the eval report shows the false positives it removed.
        ("_codecs", "encode"),
        ("_codecs", "decode"),
        # protocol 5 out-of-band buffer path for numpy arrays
        ("numpy._core.numeric", "_frombuffer"),
        ("numpy.core.numeric", "_frombuffer"),
        ("numpy._core.multiarray", "_frombuffer"),
        # ordered containers used by state_dicts
        ("collections", "OrderedDict"),
        ("collections", "defaultdict"),
        # scikit-learn model containers seen in the wild
        ("sklearn.preprocessing._label", "LabelEncoder"),
        ("sklearn.tree._tree", "Tree"),
    }
)

ALLOWED_MODULE_PREFIXES: tuple[str, ...] = ()
"""Deliberately empty.

This held `("torch.",)` until a hostile review pointed out what a prefix over
a namespace that large actually means: `torch.utils.cpp_extension.load` was
listed as an exception but its sibling `load_inline`, which compiles and runs
C++ at load time, was not, and neither were `torch._C.*`,
`torch.multiprocessing.spawn` or `torch.hub.*`. A prefix is allow-by-default
over a tree that changes every release, and a hand-maintained exception list
can never catch up with it. That is the same failure mode as a denylist, which
is the thing this policy exists to avoid, so the prefix is gone.

The cost of removing it is real and is priced in the eval: torch names storage
classes per dtype, so those are matched by the explicit shape rule below
instead. Anything else under `torch.` is now reported as ACT-PKL-001.
"""

PREFIX_EXCEPTIONS: frozenset[tuple[str, str]] = frozenset()
"""Empty for the same reason: there is no prefix left to except from."""


def _is_torch_storage_class(module: str, name: str) -> bool:
    """`torch.FloatStorage`, `torch.HalfStorage`, and the rest of the family.

    Enumerating them would rot with every torch release, and the shape is
    narrow: a name ending in `Storage` inside the `torch` module itself, never
    a submodule. This is a rule about one name shape in one module, not a
    prefix over a namespace.
    """
    return module in ("torch", "torch.storage") and name.endswith("Storage")


# ---------------------------------------------------------------------------
# Denylist: callables with a documented path to command or code execution.
# Used by policy `known-bad`, and used by policy `strict` to raise severity
# from HIGH (unknown import) to CRITICAL (known execution gadget).
# ---------------------------------------------------------------------------
DENIED_MODULES: frozenset[str] = frozenset(
    {
        "os",
        "nt",
        "posix",
        "subprocess",
        "commands",
        "popen2",
        "pty",
        "socket",
        "shutil",
        "importlib",
        "runpy",
        "sys",
        "ctypes",
        "multiprocessing",
        "asyncio",
        "code",
        "codeop",
        "pdb",
        "bdb",
        "timeit",
        "webbrowser",
        "platform",
        "pickle",
        "_pickle",
        "dill",
        "shelve",
        "base64",
        "zlib",
        "requests",
        "urllib",
        "urllib.request",
        "http.client",
        "ftplib",
        "smtplib",
        "telnetlib",
        "paramiko",
        "distutils.spawn",
        "setuptools",
        "pip",
    }
)

DENIED_CALLABLES: frozenset[tuple[str, str]] = frozenset(
    {
        ("builtins", "eval"),
        ("builtins", "exec"),
        ("builtins", "compile"),
        ("builtins", "open"),
        ("builtins", "__import__"),
        ("builtins", "getattr"),
        ("builtins", "setattr"),
        ("builtins", "globals"),
        ("builtins", "locals"),
        ("builtins", "input"),
        ("builtins", "breakpoint"),
        ("builtins", "memoryview"),
        ("__builtin__", "eval"),
        ("__builtin__", "exec"),
        ("__builtin__", "compile"),
        ("__builtin__", "open"),
        ("__builtin__", "__import__"),
        ("__builtin__", "getattr"),
        ("operator", "attrgetter"),
        ("operator", "methodcaller"),
        ("operator", "itemgetter"),
        ("functools", "partial"),
        ("functools", "reduce"),
        ("copyreg", "_reconstructor"),
        ("copyreg", "__newobj__"),
        ("types", "FunctionType"),
        ("types", "CodeType"),
        ("types", "ModuleType"),
        ("marshal", "loads"),
        ("json", "loads"),
        ("torch", "load"),
        ("torch.serialization", "load"),
        ("torch.hub", "load_state_dict_from_url"),
        ("numpy", "load"),
        ("numpy.lib.npyio", "load"),
        ("pandas", "read_pickle"),
        ("joblib", "load"),
    }
)


def _module_root(module: str) -> str:
    return module.split(".", 1)[0]


def is_denied(module: str, name: str) -> bool:
    """True when the import has a documented path to code execution."""
    if (module, name) in DENIED_CALLABLES:
        return True
    if module in DENIED_MODULES:
        return True
    if _module_root(module) in DENIED_MODULES:
        return True
    return False


def is_allowed(module: str, name: str) -> bool:
    """True when the import is a known tensor-reconstruction callable."""
    if is_denied(module, name):
        return False
    if (module, name) in ALLOWED_CALLABLES:
        return True
    if _is_torch_storage_class(module, name):
        return True
    for prefix in ALLOWED_MODULE_PREFIXES:
        if module == prefix.rstrip(".") or module.startswith(prefix):
            return True
    return False
