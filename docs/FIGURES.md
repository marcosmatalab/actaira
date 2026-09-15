# Actaira in numbers

Every figure on this page was measured by `scripts/figures.py` from the
repository as it stood at the moment named below. Nothing here is typed by
hand, which is the point: the prose in this project has drifted from the
code twice, and a number nobody can regenerate is a number nobody can check.

```
make figures
```

Generated 2026-09-15T11:10:00+00:00 for actaira 3.0.0, at commit b61f634.

## The package

- version **3.0.0**, Python >=3.11
- runtime dependencies: **1** (cryptography>=41)
- development dependencies: pytest>=8, ruff>=0.6, jsonschema>=4.18
- 7 commits, most recent 2026-09-12

## Tests

**1643** tests collected by pytest across 32 files.

| file | tests |
|---|---:|
| `tests/test_action_entrypoint.py` | 14 |
| `tests/test_attest_anchor.py` | 25 |
| `tests/test_chain_and_signing.py` | 17 |
| `tests/test_chain_domain_separation.py` | 5 |
| `tests/test_cli.py` | 25 |
| `tests/test_conformance.py` | 54 |
| `tests/test_consistency.py` | 285 |
| `tests/test_coverage.py` | 12 |
| `tests/test_defect_ledger.py` | 348 |
| `tests/test_design_notes.py` | 74 |
| `tests/test_dsse.py` | 31 |
| `tests/test_i18n.py` | 139 |
| `tests/test_io_budget.py` | 9 |
| `tests/test_junit.py` | 19 |
| `tests/test_keyring.py` | 33 |
| `tests/test_merkle.py` | 80 |
| `tests/test_miniyaml.py` | 22 |
| `tests/test_package_verify.py` | 27 |
| `tests/test_policy_engine.py` | 22 |
| `tests/test_readme_parity.py` | 22 |
| `tests/test_receipt.py` | 23 |
| `tests/test_release_check.py` | 12 |
| `tests/test_sarif.py` | 29 |
| `tests/test_schemas.py` | 26 |
| `tests/test_signing_domain_separation.py` | 6 |
| `tests/test_state.py` | 88 |
| `tests/test_state_change.py` | 47 |
| `tests/test_state_graph.py` | 25 |
| `tests/test_subjects.py` | 40 |
| `tests/test_timestamp.py` | 47 |
| `tests/test_trust.py` | 13 |
| `tests/test_trust_paths.py` | 24 |
| **total** | **1643** |

## Defects found in this repository

**131** defects, from `docs/defects.json` (115 entries), found by **16** different mechanisms. **42** are pinned by a named regression test, across 73 tests. 86 were defects in the shipped tool; the rest were found the same way but lived in the measuring apparatus, and each says so.

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
Pinned by a note rather than by a test, with the reason stated in the ledger: DEF-01, DEF-03, DEF-04, DEF-05, DEF-06, DEF-07, DEF-08, DEF-09, DEF-10, DEF-13, DEF-15, DEF-16, DEF-17, DEF-18, DEF-19, DEF-20, DEF-21, DEF-22, DEF-23, DEF-24, DEF-25, DEF-26, DEF-27, DEF-28, DEF-29, DEF-30, DEF-31, DEF-32, DEF-33, DEF-34, DEF-35, DEF-36, DEF-37, DEF-40, DEF-43, DEF-44, DEF-45, DEF-46, DEF-47, DEF-48, DEF-49, DEF-51, DEF-52, DEF-54, DEF-55, DEF-56, DEF-57, DEF-58, DEF-59, DEF-60, DEF-61, DEF-65, DEF-67, DEF-68, DEF-76, DEF-77, DEF-78, DEF-80, DEF-85, DEF-86, DEF-87, DEF-93, DEF-97, DEF-98, DEF-99, DEF-101, DEF-102, DEF-103, DEF-105, DEF-107, DEF-108, DEF-109, DEF-111, DEF-115.

## Code

Docstrings are counted apart from code because this project keeps its
design notes in them: `docs/DESIGN.md` consolidates what the modules say,
and the modules are the source of truth.

| area | files | lines | code | docstrings | comments | blank |
|---|---:|---:|---:|---:|---:|---:|
| attest | 10 | 4059 | 2543 | 713 | 263 | 540 |
| core | 4 | 461 | 262 | 101 | 18 | 80 |
| conformance | 6 | 2152 | 1300 | 444 | 101 | 307 |
| policy | 3 | 1139 | 714 | 165 | 96 | 164 |
| state | 9 | 3527 | 1970 | 821 | 238 | 498 |
| schemas | 1 | 98 | 28 | 36 | 14 | 20 |
| report | 3 | 435 | 250 | 83 | 35 | 67 |
| i18n | 2 | 55 | 30 | 7 | 7 | 11 |
| rest | 6 | 1707 | 895 | 440 | 123 | 249 |
| tests | 36 | 13472 | 7933 | 1791 | 644 | 3104 |
| scripts | 9 | 2717 | 1744 | 412 | 187 | 374 |
| **total** | 89 | 29822 | 17669 | 5013 | 1726 | 5414 |

Documentation, in lines of Markdown:

- `docs/DESIGN.md`: 1588
- `docs/THREAT-MODEL.md`: 537
- total: 2125

## Rules

**41** rule identifiers, each with text in 2 languages, 22 of them with an explanation of what to do about the finding.

| family | rules |
|---|---:|
| `ACT-AGT` | 10 |
| `ACT-BDL` | 1 |
| `ACT-FMT` | 2 |
| `ACT-GGF` | 3 |
| `ACT-H5` | 2 |
| `ACT-NPY` | 1 |
| `ACT-ONX` | 2 |
| `ACT-PATH` | 5 |
| `ACT-PKL` | 6 |
| `ACT-STF` | 3 |
| `ACT-ZIP` | 6 |

Catalogue key sets identical in both languages: **yes** (asserted by `tests/test_i18n.py`).


---

The machine-readable form of this page is `figures.json`, written by the same
run. If a number here disagrees with one in a README, this page is the one
that was measured.
