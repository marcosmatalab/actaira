# Actaira in numbers

Every figure on this page was measured by `scripts/figures.py` from the
repository as it stood at the moment named below. Nothing here is typed by
hand, which is the point: the prose in this project has drifted from the
code twice, and a number nobody can regenerate is a number nobody can check.

```
make figures
```

Generated 2026-09-17T15:24:53+00:00 for actaira 3.0.0, at commit aef5206.

## The package

- version **3.0.0**, Python >=3.11
- runtime dependencies: **1** (cryptography>=41)
- development dependencies: pytest>=8, ruff>=0.6, jsonschema>=4.18
- 20 commits, most recent 2026-09-17

## Tests

**1566** tests collected by pytest across 31 files.

| file | tests |
|---|---:|
| `tests/test_attest_anchor.py` | 25 |
| `tests/test_chain_and_signing.py` | 17 |
| `tests/test_chain_domain_separation.py` | 14 |
| `tests/test_cli.py` | 35 |
| `tests/test_consistency.py` | 285 |
| `tests/test_defect_ledger.py` | 348 |
| `tests/test_design_notes.py` | 54 |
| `tests/test_dsse.py` | 25 |
| `tests/test_i18n.py` | 78 |
| `tests/test_keyring.py` | 33 |
| `tests/test_mcp.py` | 15 |
| `tests/test_merkle.py` | 146 |
| `tests/test_netguard.py` | 19 |
| `tests/test_no_aggregate.py` | 11 |
| `tests/test_package_verify.py` | 31 |
| `tests/test_proxy_completeness.py` | 48 |
| `tests/test_proxy_http_interposition.py` | 15 |
| `tests/test_proxy_protocol.py` | 17 |
| `tests/test_proxy_transports.py` | 28 |
| `tests/test_reachability.py` | 30 |
| `tests/test_readme_parity.py` | 25 |
| `tests/test_release_check.py` | 12 |
| `tests/test_scan_claude_code.py` | 33 |
| `tests/test_schemas.py` | 18 |
| `tests/test_signing_domain_separation.py` | 4 |
| `tests/test_timestamp.py` | 47 |
| `tests/test_trace_model.py` | 19 |
| `tests/test_trace_privacy.py` | 77 |
| `tests/test_trace_provenance.py` | 21 |
| `tests/test_trust.py` | 13 |
| `tests/test_verify_strictness.py` | 23 |
| **total** | **1566** |

## Defects found in this repository

**131** defects, from `docs/defects.json` (115 entries), found by **16** different mechanisms. **13** are pinned by a named regression test, across 23 tests. 86 were defects in the shipped tool; the rest were found the same way but lived in the measuring apparatus, and each says so.

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
Pinned by a note rather than by a test, with the reason stated in the ledger: DEF-01, DEF-03, DEF-04, DEF-05, DEF-06, DEF-07, DEF-08, DEF-09, DEF-10, DEF-13, DEF-15, DEF-16, DEF-17, DEF-18, DEF-19, DEF-20, DEF-21, DEF-22, DEF-23, DEF-24, DEF-25, DEF-26, DEF-27, DEF-28, DEF-29, DEF-30, DEF-31, DEF-32, DEF-33, DEF-34, DEF-35, DEF-36, DEF-37, DEF-40, DEF-43, DEF-44, DEF-45, DEF-46, DEF-47, DEF-48, DEF-49, DEF-50, DEF-51, DEF-52, DEF-54, DEF-55, DEF-56, DEF-57, DEF-58, DEF-59, DEF-60, DEF-61, DEF-62, DEF-65, DEF-66, DEF-67, DEF-68, DEF-69, DEF-70, DEF-71, DEF-72, DEF-73, DEF-74, DEF-75, DEF-76, DEF-77, DEF-78, DEF-79, DEF-80, DEF-81, DEF-82, DEF-83, DEF-84, DEF-85, DEF-86, DEF-87, DEF-88, DEF-89, DEF-90, DEF-91, DEF-92, DEF-93, DEF-94, DEF-95, DEF-97, DEF-98, DEF-99, DEF-101, DEF-102, DEF-103, DEF-104, DEF-105, DEF-106, DEF-107, DEF-108, DEF-109, DEF-110, DEF-111, DEF-112, DEF-113, DEF-114, DEF-115.

## Code

Docstrings are counted apart from code because this project keeps its
design notes in them: `docs/DESIGN.md` consolidates what the modules say,
and the modules are the source of truth.

| area | files | lines | code | docstrings | comments | blank |
|---|---:|---:|---:|---:|---:|---:|
| attest | 10 | 4018 | 2496 | 700 | 290 | 532 |
| trace | 5 | 1705 | 939 | 382 | 161 | 223 |
| proxy | 5 | 1929 | 1232 | 343 | 164 | 190 |
| core | 4 | 671 | 384 | 140 | 43 | 104 |
| schemas | 1 | 121 | 22 | 36 | 43 | 20 |
| i18n | 2 | 55 | 30 | 7 | 7 | 11 |
| rest | 1 | 179 | 111 | 30 | 10 | 28 |
| tests | 36 | 12443 | 6995 | 1931 | 754 | 2763 |
| scripts | 9 | 2819 | 1736 | 472 | 222 | 389 |
| **total** | 73 | 23940 | 13945 | 4041 | 1694 | 4260 |

Documentation, in lines of Markdown:

- `docs/DESIGN.md`: 817
- total: 817

## Rules

**0** rule identifiers, each with text in 2 languages, 0 of them with an explanation of what to do about the finding.

| family | rules |
|---|---:|

Catalogue key sets identical in both languages: **yes** (asserted by `tests/test_i18n.py`).


---

The machine-readable form of this page is `figures.json`, written by the same
run. If a number here disagrees with one in a README, this page is the one
that was measured.
