# Actaira in numbers

Every figure on this page was measured by `scripts/figures.py` from the
repository as it stood at the moment named below. Nothing here is typed by
hand, which is the point: the prose in this project has drifted from the
code twice, and a number nobody can regenerate is a number nobody can check.

```
make figures
```

Generated 2026-09-12T16:25:26+00:00 for actaira 2.3.0, at commit c439ee5.

## The package

- version **2.3.0**, Python >=3.11
- runtime dependencies: **1** (cryptography>=41)
- development dependencies: pytest>=8, numpy>=1.26, ruff>=0.6, jsonschema>=4.18, pillow>=10
- 3 commits, most recent 2026-09-12

## Tests

**3593** tests collected by pytest across 56 files.

| file | tests |
|---|---:|
| `tests/test_action_entrypoint.py` | 14 |
| `tests/test_agentgov.py` | 54 |
| `tests/test_agents.py` | 123 |
| `tests/test_attest_anchor.py` | 27 |
| `tests/test_benchmark.py` | 25 |
| `tests/test_bom.py` | 76 |
| `tests/test_bundle.py` | 23 |
| `tests/test_chain_and_signing.py` | 17 |
| `tests/test_cli.py` | 49 |
| `tests/test_cli_ui_parity.py` | 18 |
| `tests/test_connectors.py` | 118 |
| `tests/test_consistency.py` | 285 |
| `tests/test_controls.py` | 196 |
| `tests/test_controls_documentation.py` | 28 |
| `tests/test_controls_judged.py` | 26 |
| `tests/test_controls_records.py` | 27 |
| `tests/test_coverage.py` | 14 |
| `tests/test_defect_ledger.py` | 348 |
| `tests/test_design_notes.py` | 163 |
| `tests/test_dsse.py` | 31 |
| `tests/test_eval_harness.py` | 14 |
| `tests/test_formats.py` | 63 |
| `tests/test_formats_doc.py` | 82 |
| `tests/test_fuzz_regressions.py` | 44 |
| `tests/test_governance.py` | 201 |
| `tests/test_i18n.py` | 276 |
| `tests/test_io_budget.py` | 13 |
| `tests/test_junit.py` | 21 |
| `tests/test_keyring.py` | 34 |
| `tests/test_marking.py` | 43 |
| `tests/test_merkle.py` | 80 |
| `tests/test_miniyaml.py` | 22 |
| `tests/test_package_verify.py` | 27 |
| `tests/test_pickle_scan.py` | 20 |
| `tests/test_policy.py` | 180 |
| `tests/test_policy_engine.py` | 22 |
| `tests/test_readme_parity.py` | 33 |
| `tests/test_real_artifacts.py` | 27 |
| `tests/test_receipt.py` | 23 |
| `tests/test_release_check.py` | 12 |
| `tests/test_remote_receipt.py` | 27 |
| `tests/test_sarif.py` | 33 |
| `tests/test_schemas.py` | 59 |
| `tests/test_state.py` | 92 |
| `tests/test_state_change.py` | 48 |
| `tests/test_state_graph.py` | 29 |
| `tests/test_subjects.py` | 52 |
| `tests/test_timestamp.py` | 47 |
| `tests/test_trust.py` | 13 |
| `tests/test_trust_paths.py` | 39 |
| `tests/test_web_agents.py` | 50 |
| `tests/test_web_evidence.py` | 53 |
| `tests/test_web_frontend.py` | 18 |
| `tests/test_web_graph.py` | 69 |
| `tests/test_web_limits.py` | 31 |
| `tests/test_web_policy.py` | 34 |
| **total** | **3593** |

## The obligation catalogue

**21** obligations, from `src/actaira/governance/catalog.py`. **15** are marked as outside what this tool can show and **0** as fully supported, which is the number that matters: an obligation reaches that rating only if reading model files could carry it alone, and none can.

| coverage | obligations |
|---|---:|
| not_covered | 15 |
| partial | 6 |
| **total** | **21** |

| binds | obligations |
|---|---:|
| provider | 7 |
| provider_gpai | 6 |
| any | 4 |
| deployer | 3 |
| provider_gpai_systemic | 1 |

8 carry a transitional grace period. Dates of application run from 2025-02-02 to 2027-12-02.

## Defects found in this repository

**131** defects, from `docs/defects.json` (115 entries), found by **16** different mechanisms. **130** are pinned by a named regression test, across 205 tests. 86 were defects in the shipped tool; the rest were found the same way but lived in the measuring apparatus, and each says so.

| what found it | defects |
|---|---:|
| adversarial review of new code | 27 |
| adversarial engineering review | 21 |
| external adversarial audit | 19 |
| fuzzing | 14 |
| adversarial legal review | 8 |
| reading the tool's own output | 7 |
| test suite | 7 |
| product review against a roadmap | 6 |
| using the tool as a person would | 6 |
| real-serialiser corpus | 4 |
| running the gate | 4 |
| benchmark self-tests | 2 |
| running the harness | 2 |
| writing a test for an adjacent feature | 2 |
| benign corpus | 1 |
| exhaustive sweep | 1 |
| **total** | **131** |

Every test named in the ledger was checked against what pytest collects: all of them are collected.
Pinned by a note rather than by a test, with the reason stated in the ledger: DEF-58.

## Code

Docstrings are counted apart from code because this project keeps its
design notes in them: `docs/DESIGN.md` consolidates what the modules say,
and the modules are the source of truth.

| area | files | lines | code | docstrings | comments | blank |
|---|---:|---:|---:|---:|---:|---:|
| formats | 11 | 2490 | 1561 | 316 | 308 | 305 |
| attest | 10 | 4017 | 2523 | 709 | 252 | 533 |
| core | 5 | 2999 | 1978 | 331 | 303 | 387 |
| scan | 2 | 233 | 154 | 29 | 28 | 22 |
| agentgov | 6 | 2152 | 1300 | 444 | 101 | 307 |
| agents | 7 | 2401 | 1107 | 760 | 209 | 325 |
| controls | 7 | 2844 | 1765 | 585 | 142 | 352 |
| governance | 5 | 1135 | 717 | 249 | 45 | 124 |
| policy | 3 | 1226 | 779 | 172 | 100 | 175 |
| state | 9 | 3517 | 1970 | 820 | 231 | 496 |
| connectors | 10 | 2687 | 1562 | 639 | 141 | 345 |
| schemas | 1 | 111 | 41 | 36 | 14 | 20 |
| bom | 2 | 119 | 73 | 13 | 17 | 16 |
| report | 3 | 435 | 250 | 83 | 35 | 67 |
| i18n | 2 | 55 | 30 | 7 | 7 | 11 |
| web | 2 | 2323 | 1440 | 301 | 298 | 284 |
| rest | 13 | 4658 | 2839 | 868 | 333 | 618 |
| tests | 58 | 28901 | 16799 | 4042 | 1428 | 6632 |
| evals | 8 | 3619 | 2485 | 444 | 250 | 440 |
| fuzz | 1 | 1284 | 827 | 147 | 110 | 200 |
| scripts | 11 | 4586 | 3082 | 609 | 325 | 570 |
| **total** | 176 | 71792 | 43282 | 11604 | 4677 | 12229 |

Documentation, in lines of Markdown:

- `docs/DESIGN.md`: 1677
- `docs/FORMATS.md`: 679
- `docs/THREAT-MODEL.md`: 537
- `fuzz/README.md`: 251
- total: 3144

## Rules

**80** rule identifiers, each with text in 2 languages, 39 of them with an explanation of what to do about the finding.

| family | rules |
|---|---:|
| `ACT-AGT` | 10 |
| `ACT-BDL` | 9 |
| `ACT-CON` | 2 |
| `ACT-CTL` | 2 |
| `ACT-FMT` | 3 |
| `ACT-GGF` | 4 |
| `ACT-H5` | 4 |
| `ACT-MRK` | 5 |
| `ACT-NPY` | 2 |
| `ACT-ONX` | 4 |
| `ACT-PATH` | 5 |
| `ACT-PKL` | 14 |
| `ACT-STF` | 7 |
| `ACT-ZIP` | 9 |

Catalogue key sets identical in both languages: **yes** (asserted by `tests/test_i18n.py`).

## Corpus

**64** artifacts, built from code at measurement time and never committed: 16 benign, 1 hostile-but-inconclusive, 47 malicious.

| family | cases |
|---|---:|
| benign | 12 |
| format | 7 |
| gadget-known | 25 |
| gadget-unknown | 11 |
| structural | 9 |

## Evaluation

From `evals/results.json`, written by `make eval`.

- expectations met: **64/64**
- strict (allowlist): caught **47/47** malicious, **0** benign artifacts wrongly failed
- known-bad (denylist): caught **37/47** malicious, **0** benign artifacts wrongly failed
- caught only by the allowlist: **10**
- per artifact: median **0.765 ms**, max 16.275 ms
- identical output over two runs: **64/64**
- tampered packages rejected: **63/63**

## Against the other scanners

From `evals/benchmark.json`, written by `make benchmark` on Python 3.12.12, over 73 artifacts.

| tool | version |
|---|---|
| actaira (strict) | 2.2.0 |
| actaira (known-bad) | 2.2.0 |
| picklescan | 1.0.5 |
| modelscan | 0.8.8 |
| fickling | 0.1.12 |

### Head to head, on the artifacts every tool reads

pickle-bearing formats only, so nobody is scored on a format they never claimed

| tool | caught | false alarms | declined | median ms |
|---|---:|---:|---:|---:|
| actaira (strict) | 42/42 | 1 | 0 | 0.675 |
| actaira (known-bad) | 32/42 | 0 | 0 | 0.647 |
| picklescan | 26/42 | 0 | 1 | 0.172 |
| modelscan | 21/42 | 0 | 1 | 0.355 |
| fickling | 35/36 | 10 | 10 | 91.369 |

### The whole corpus

everything, with what each tool declined to read reported beside what it caught

| tool | caught | false alarms | declined | median ms |
|---|---:|---:|---:|---:|
| actaira (strict) | 50/50 | 1 | 0 | 0.624 |
| actaira (known-bad) | 40/50 | 0 | 0 | 0.621 |
| picklescan | 26/42 | 0 | 18 | 0.172 |
| modelscan | 21/44 | 0 | 14 | 0.351 |
| fickling | 35/36 | 10 | 27 | 91.369 |

Artifacts another tool catches and Actaira misses: **none**. The harness computes this every run and prints it either way, because "nobody beats us" is only information if you can see it was checked.

Caught, by corpus family:

| family | actaira (known-bad) | actaira (strict) | fickling | modelscan | picklescan |
|---|---|---|---|---|---|
| format | 5/5 | 5/5 | 2/2 | 0/3 | 1/2 |
| gadget-known | 25/25 | 25/25 | 21/22 | 19/25 | 19/25 |
| gadget-unknown | 1/11 | 11/11 | 11/11 | 1/11 | 4/11 |
| real | 3/3 | 3/3 | 1/1 | 1/2 | 1/1 |
| structural | 6/6 | 6/6 | 0/0 | 0/3 | 1/3 |

## Fuzzing

From `fuzz/runs/latest/summary.json`, written by `make fuzz`.

- **45000** cases over **9** targets, seed 1, 155.5 s
- findings: **0**, hard failures: **0**
- targets: archive, detect, gguf, inspect, keras_h5, npy, onnx, pickle, safetensors

**This run enforced 2 of the four promises.** The host it ran on does not provide what the other(s) are enforced with, so the finding count above is a weaker result than the same count from a POSIX run:

- (a) per-case termination: SIGALRM is POSIX-only, so a hang is caught by the parent watchdog after the whole worker stalls, not per case
- (c) bounded memory: RLIMIT_AS is POSIX-only, so an unbounded allocation surfaces as this machine swapping rather than as MemoryError
- (c) peak RSS: getrusage is POSIX-only, so an allocation that succeeds is not measured

---

The machine-readable form of this page is `figures.json`, written by the same
run. If a number here disagrees with one in a README, this page is the one
that was measured.
