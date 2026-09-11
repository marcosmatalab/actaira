"""Artifacts produced by the real serialisers, not by this repository.

Design note D-23, and the answer to the sharpest criticism the synthetic
corpus attracts: "you wrote both the files and the parser, so of course they
agree."

Everything in `build.py` is crafted from raw bytes on purpose, so that the
eval is reproducible anywhere and no malware is committed. That buys
reproducibility and costs external validity. This module buys the external
validity back: when torch, onnx, h5py or safetensors are installed, it writes
artifacts with those libraries and the harness checks that Actaira reads
what the real writer wrote.

The dependency is one-way and stays that way. Actaira itself imports none of
these; they are dev extras, every generator degrades to a skip when its
library is missing, and CI runs the synthetic corpus with no ML stack at all
plus a separate job that installs one. If this module ever became required
to run the eval, the project's central claim, that you can inspect an
artifact without installing the ecosystem that loads it, would be false in
its own repository.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class RealCase:
    name: str
    writer: str  # which library produced it
    label: str  # benign | malicious
    expect_verdict: str
    expect_format: str
    expect_rules: list[str] = field(default_factory=list)
    forbid_rules: list[str] = field(default_factory=list)
    expect_tensors_at_least: int = 0
    note: str = ""


def _try(module: str) -> Any | None:
    try:
        return __import__(module)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# torch
# ---------------------------------------------------------------------------

class _TinyNetBase:
    """Placeholder replaced at import time when torch is available."""


def _make_tinynet_class():
    torch = _try("torch")
    if torch is None:
        return None
    import torch.nn as nn

    class TinyNet(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.fc = nn.Linear(8, 4)

        def forward(self, x):  # pragma: no cover - never executed here
            return self.fc(x)

    TinyNet.__module__ = __name__
    TinyNet.__qualname__ = "TinyNet"
    return TinyNet


TinyNet = _make_tinynet_class()
_TinyNet = TinyNet


class Exploit:
    """A benign-looking object whose __reduce__ runs a command on load.

    Module scope for the same reason as TinyNet. Nothing here ever executes:
    `__reduce__` only describes what a loader would do.
    """

    def __reduce__(self):
        import os

        return (os.system, ("id",))


def _build_torch(out_dir: Path) -> list[RealCase]:
    torch = _try("torch")
    if torch is None or TinyNet is None:
        return []

    cases: list[RealCase] = []

    state_dict = {
        "encoder.weight": torch.zeros(8, 8),
        "encoder.bias": torch.zeros(8),
        "decoder.weight": torch.ones(4, 8),
    }

    # 1. The modern default: a zip container holding data.pkl plus storages.
    torch.save(state_dict, out_dir / "real_state_dict.pt")
    cases.append(RealCase(
        # PASS, and the reason is the coverage model. ACT-ZIP-007 still fires
        # and still names the storage blobs, `version` and `byteorder` that
        # were never opened, but those belong to `raw_tensor_content`, a
        # surface this tool never undertook to read. A surface nobody
        # undertook to read cannot make a verdict inconclusive; one that was
        # in scope and failed still does.
        #
        # This said `inconclusive` until 2.2.0, where the boolean became a
        # per-surface matrix (D-104), because only the nightly runs it and the
        # nightly does not run on a machine without torch (DEF-102). The
        # identical object saved in the legacy format was PASS the whole time:
        # the same state_dict gave two different verdicts depending on which
        # serialisation flag was passed, which is exactly the confusion the
        # coverage model was built to end.
        name="real_state_dict.pt", writer=f"torch {torch.__version__}", label="benign",
        expect_verdict="pass", expect_format="pytorch-zip",
        expect_rules=["ACT-ZIP-007"],
        forbid_rules=["ACT-PKL-001", "ACT-PKL-002", "ACT-PKL-009"],
        note="torch.save default: the allowlist must admit every callable a real state_dict uses; "
             "the storage members are named as uninspected rather than passed over",
    ))

    # 2. The legacy format, still produced by older code and still loaded.
    torch.save(state_dict, out_dir / "real_state_dict_legacy.pt", _use_new_zipfile_serialization=False)
    cases.append(RealCase(
        name="real_state_dict_legacy.pt", writer=f"torch {torch.__version__}", label="benign",
        expect_verdict="pass", expect_format="pickle",
        forbid_rules=["ACT-PKL-001", "ACT-PKL-002"],
        note="pre-1.6 serialisation: a bare pickle, no zip container",
    ))

    # 3. A whole nn.Module. This pickles a reference to the class, which is
    #    why torch.save(model) is discouraged, and why it must not be a
    #    silent PASS: loading the artifact imports user code by name.
    #    `TinyNet` lives at module scope because pickle stores classes by
    #    qualified name and cannot reference a local one.
    torch.save(_TinyNet(), out_dir / "real_full_module.pt")
    cases.append(RealCase(
        name="real_full_module.pt", writer=f"torch {torch.__version__}", label="benign",
        expect_verdict="fail", expect_format="pytorch-zip",
        expect_rules=["ACT-PKL-001"],
        note="torch.save(model) pickles the class: reported, because loading it imports user code",
    ))

    # 4. A real malicious checkpoint, written by torch itself.
    torch.save({"state_dict": state_dict, "meta": Exploit()}, out_dir / "real_trojan.pt")
    cases.append(RealCase(
        name="real_trojan.pt", writer=f"torch {torch.__version__}", label="malicious",
        expect_verdict="fail", expect_format="pytorch-zip",
        expect_rules=["ACT-PKL-002"],
        note="the classic supply-chain attack, serialised by the real library",
    ))
    return cases


# ---------------------------------------------------------------------------
# safetensors
# ---------------------------------------------------------------------------

def _build_safetensors(out_dir: Path) -> list[RealCase]:
    safetensors = _try("safetensors")
    torch = _try("torch")
    if safetensors is None or torch is None:
        return []
    from safetensors.torch import save_file

    save_file(
        {"encoder.weight": torch.zeros(16, 16), "encoder.bias": torch.zeros(16)},
        str(out_dir / "real_model.safetensors"),
        metadata={"format": "pt", "producer": "actaira-eval"},
    )
    return [RealCase(
        name="real_model.safetensors", writer=f"safetensors {safetensors.__version__}",
        label="benign", expect_verdict="pass", expect_format="safetensors",
        forbid_rules=["ACT-STF-003", "ACT-STF-004", "ACT-STF-006", "ACT-STF-007"],
        expect_tensors_at_least=2,
        note="offsets, dtypes and shapes must agree with what the real writer emitted",
    )]


# ---------------------------------------------------------------------------
# onnx
# ---------------------------------------------------------------------------

def _build_onnx(out_dir: Path) -> list[RealCase]:
    onnx = _try("onnx")
    if onnx is None:
        return []
    import numpy as np
    from onnx import TensorProto, helper, numpy_helper

    weight = numpy_helper.from_array(np.zeros((4, 4), dtype=np.float32), name="W")
    node = helper.make_node("MatMul", ["X", "W"], ["Y"])
    graph = helper.make_graph(
        [node], "real_graph",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 4])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 4])],
        initializer=[weight],
    )
    model = helper.make_model(graph, producer_name="actaira-eval", opset_imports=[helper.make_opsetid("", 17)])
    onnx.save(model, str(out_dir / "real_model.onnx"))

    custom_node = helper.make_node("AcmeOp", ["X"], ["Y"], domain="com.acme.kernels")
    custom_graph = helper.make_graph(
        [custom_node], "custom_graph",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 4])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 4])],
    )
    custom = helper.make_model(
        custom_graph, producer_name="actaira-eval",
        opset_imports=[helper.make_opsetid("", 17), helper.make_opsetid("com.acme.kernels", 1)],
    )
    onnx.save(custom, str(out_dir / "real_custom_domain.onnx"))

    version = onnx.__version__
    return [
        RealCase(
            name="real_model.onnx", writer=f"onnx {version}", label="benign",
            expect_verdict="pass", expect_format="onnx",
            forbid_rules=["ACT-ONX-001", "ACT-ONX-002", "ACT-ONX-003"],
            expect_tensors_at_least=1,
            note="hand-written protobuf reader against a real ModelProto",
        ),
        RealCase(
            name="real_custom_domain.onnx", writer=f"onnx {version}", label="malicious",
            expect_verdict="fail", expect_format="onnx", expect_rules=["ACT-ONX-002"],
            note="custom operator domain, emitted by the real onnx helper",
        ),
    ]


# ---------------------------------------------------------------------------
# HDF5
# ---------------------------------------------------------------------------

def _build_hdf5(out_dir: Path) -> list[RealCase]:
    h5py = _try("h5py")
    if h5py is None:
        return []
    import numpy as np

    def write(path: Path, layers: list[dict[str, Any]]) -> None:
        with h5py.File(path, "w") as handle:
            handle.attrs["keras_version"] = "2.15.0"
            handle.attrs["backend"] = "tensorflow"
            handle.attrs["model_config"] = json.dumps(
                {"class_name": "Sequential", "config": {"name": "seq", "layers": layers}}
            )
            group = handle.create_group("model_weights")
            group.create_dataset("dense/kernel", data=np.zeros((4, 4), dtype=np.float32))

    write(out_dir / "real_keras.h5", [
        {"class_name": "Dense", "config": {"name": "dense", "units": 4}},
        {"class_name": "Dropout", "config": {"name": "drop", "rate": 0.1}},
    ])
    write(out_dir / "real_keras_lambda.h5", [
        {"class_name": "Dense", "config": {"name": "dense", "units": 4}},
        {"class_name": "Lambda", "config": {"name": "lam", "function": ["base64payload", None, None]}},
    ])
    version = h5py.__version__
    return [
        RealCase(
            name="real_keras.h5", writer=f"h5py {version}", label="benign",
            expect_verdict="pass", expect_format="hdf5",
            forbid_rules=["ACT-H5-001", "ACT-H5-002", "ACT-H5-003"],
            note="a genuine HDF5 container, not the synthetic byte blob: the byte scan must still locate the config",
        ),
        RealCase(
            name="real_keras_lambda.h5", writer=f"h5py {version}", label="malicious",
            expect_verdict="fail", expect_format="hdf5", expect_rules=["ACT-H5-001"],
            note="Lambda layer inside a real HDF5 file",
        ),
    ]


BUILDERS: tuple[Callable[[Path], list[RealCase]], ...] = (
    _build_torch, _build_safetensors, _build_onnx, _build_hdf5,
)


def build(out_dir: Path) -> list[RealCase]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cases: list[RealCase] = []
    for builder in BUILDERS:
        cases.extend(builder(out_dir))
    (out_dir / "real_cases.json").write_text(
        json.dumps([case.__dict__ for case in cases], indent=2), encoding="utf-8", newline="\n"
    )
    return cases


if __name__ == "__main__":
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("evals/real")
    built = build(target)
    print(f"{len(built)} real artifacts written to {target}")
    for case in built:
        print(f"  {case.name:34} {case.writer}")
