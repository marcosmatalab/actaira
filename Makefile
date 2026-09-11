# `lint`, `test`, `eval`, `fuzz`, `figures`, `contracts`, `design-notes`,
# `release-check` and `scan-self` run on a clean checkout with no arguments, no
# network and no ML framework installed.
#
# `all` is made of those plus `eval-marking` and `diagrams`, which need Pillow.
# Pillow is in the `dev` extra, so `make install` is enough and nothing here
# reaches the network, but it is worth naming because the header used to claim
# `all` needed nothing at all.
#
# Three targets need more than the dev extra, and say so where they are
# defined: `benchmark` needs the three tools it compares against, `real-corpus`
# needs torch, onnx, h5py and safetensors, and `screenshots` needs playwright
# with chromium. None of the three is a dependency of the package, because a
# comparison and a picture must not be able to break an install.
PY ?= python3

.PHONY: help install test eval eval-marking diagrams benchmark real-corpus nightly-real lint fuzz fuzz-long figures \
        release-check screenshots contracts design-notes scan-self discover-self serve package source-archive types clean all

help:
	@echo "install    install the package and dev extras"
	@echo "test       run the test suite"
	@echo "eval       rebuild the corpus and run the evaluation harness"
	@echo "benchmark  compare against picklescan, modelscan and fickling"
	@echo "eval-marking  measure whether an Art. 50(2) marking survives a real pipeline"
	@echo "diagrams   regenerate docs/img/*.svg from the code and the measurements"
	@echo "real-corpus generate artifacts with torch, onnx, h5py and safetensors"
	@echo "nightly-real  the same, then run the real-format tests with skipping disallowed"
	@echo "lint       run ruff"
	@echo "types      hold every mypy-clean module clean; needs the types extra"
	@echo "figures    measure the repository into docs/FIGURES.md and figures.json"
	@echo "contracts  regenerate docs/CONTRACTS.md from the shipped schemas"
	@echo "design-notes point every design-note row at the line that argues it"
	@echo "screenshots regenerate docs/img/*.png from the running interface"
	@echo "fuzz       fuzz every parser, CI budget (5 000 cases per target)"
	@echo "fuzz-long  fuzz every parser, full budget (50 000 cases per target)"
	@echo "scan-self  run actaira over its own eval corpus"
	@echo "discover-self  enumerate the eval corpus through the discovery layer, offline"
	@echo "serve      start the local web interface on 127.0.0.1:8765"
	@echo "release-check refuse a release whose parts disagree with each other"
	@echo "package    build the wheel and the sdist into dist/ and check what is in them"
	@echo "source-archive  zip the tracked source into dist/, from an allowlist"
	@echo "clean      remove every generated directory and build artifact"
	@echo "all        lint, test, fuzz, eval, eval-marking, diagrams, figures, release-check"

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest tests

eval:
	rm -rf evals/artifacts
	PYTHONPATH=src $(PY) evals/corpus/build.py evals/artifacts
	$(PY) evals/harness.py

# Every picture in the READMEs comes from here. The survival chart reads
# evals/marking/results.json and refuses to draw a figure the harness did not
# measure, so run `eval-marking` first; the coverage ladder reads the obligation
# catalogue, so it is always current. See design note D-70.
diagrams:
	$(PY) scripts/diagrams.py

# Needs Pillow (dev extra) to draw the corpus and to run the transformation
# battery. The corpus is generated, never committed: see evals/marking/build.py.
eval-marking:
	rm -rf evals/marking/artifacts
	$(PY) evals/marking/build.py evals/marking/artifacts
	$(PY) evals/marking/harness.py

# Needs picklescan, modelscan and fickling: `pip install picklescan modelscan
# fickling`. They are not in the dev extra, because a comparison against
# other people's tools must not be able to break an install of this one.
#
# And it needs a Python below 3.13, because modelscan declares
# `>=3.10,<3.13` and pip therefore finds no version at all on 3.13 - an error
# that reads like the package does not exist. Run it in a venv of its own:
#
#   python3.12 -m venv .venv-bench && .venv-bench/bin/pip install #       picklescan==1.0.5 modelscan==0.8.8 fickling==0.1.12 -e .
#   make benchmark PY=.venv-bench/bin/python
#
# Run `real-corpus` first if you have the ML stack. The recorded figures cover
# the real artifacts too, and a benchmark run without them is a different and
# slightly kinder corpus: `real_full_module.pt` is the one artifact this tool
# raises a false alarm on, and leaving it out removes that column.
benchmark:
	rm -rf evals/artifacts
	PYTHONPATH=src $(PY) evals/corpus/build.py evals/artifacts
	-PYTHONPATH=src $(PY) evals/corpus/real.py evals/real
	$(PY) evals/benchmark.py

# Needs torch, onnx, h5py and safetensors. Every generator degrades to a skip
# when its library is missing, which is why `benchmark` can call it with a
# `-` prefix and still be a check.
real-corpus:
	PYTHONPATH=src $(PY) evals/corpus/real.py evals/real

# What the nightly runs, runnable here. The variable turns every
# `importorskip` in that file into a failure naming the missing library, so
# this target answers "did the real-format tests actually execute" rather than
# "did the suite come back green".
nightly-real: real-corpus
	ACTAIRA_REQUIRE_REAL_STACK=1 $(PY) -m pytest tests/test_real_artifacts.py -rs

lint:
	$(PY) -m ruff check src tests evals fuzz scripts

# Design note D-242. A ratchet, not an ultimatum: the modules mypy already
# agrees with must stay that way, and a module that has been cleaned up but
# left on the known-unclean list fails just as loudly as a new error. Needs
# the `types` extra, which is separate from `dev` on purpose - `make all` must
# not be able to go red because a checker changed between two versions, which
# is also why this target is not in `all`.
types:
	$(PY) scripts/type_check.py

# The property: for ANY bytes, inspect_artifact terminates, does not raise,
# does not allocate without bound, and never answers PASS for an artifact it
# could not fully read. Deterministic: FUZZ_SEED and the case count decide the
# whole run, so a failure here reproduces from the command line alone. The CI
# budget is short on purpose; `fuzz-long` is the one that finds things.
FUZZ_SEED ?= 1
FUZZ_CASES ?= 5000
FUZZ_OUT ?= fuzz/runs/latest

fuzz:
	$(PY) fuzz/fuzz_targets.py run --target all --seed $(FUZZ_SEED) \
	    --iters $(FUZZ_CASES) --timeout 5 --memory-mb 1024 --out $(FUZZ_OUT)

fuzz-long:
	$(MAKE) fuzz FUZZ_CASES=50000 FUZZ_OUT=fuzz/runs/long

# Every number in docs/FIGURES.md comes from here, measured from the working
# tree. It reads evals/results.json, evals/benchmark.json and the fuzz summary
# rather than recomputing them, so run it after `eval`, `benchmark` or `fuzz`
# for those sections to be current; the sections whose source is missing say so
# instead of printing a zero.
figures:
	$(PY) scripts/figures.py
	$(PY) scripts/sync_readme_figures.py

# The index of published contracts, written from the schemas the package
# ships rather than by hand. An index typed by hand is a fourth place a
# contract is recorded, and the one nothing would notice going stale.
contracts:
	$(PY) scripts/contracts_doc.py

# The design-note table's line numbers, which drift on every edit above them.
# `--check` is what the release gate runs; without it the rows are rewritten.
design-notes:
	$(PY) scripts/design_notes.py

# The README shows pictures of this interface, and a picture of a version that
# no longer exists is worse than no picture: the reader believes it. Every
# capture also fails the target on a console error, a page error or a failed
# request, so the screenshot pass doubles as a smoke test of the front end and
# of its Content-Security-Policy.
screenshots:
	$(PY) scripts/screenshots.py

# Design note D-180. Not a linter and not a test: it compares facts recorded in
# two places and fails when they have come apart. The version against the
# changelog, the measured figures against the suite, every rule against both
# catalogues and the format table, every schema against the module that emits
# it, every design note against the table, the CLI's commands against the
# README, the two READMEs against each other, and the defect ledger against
# the tests it names. Each drift it checks for is one this repository has
# actually had.
release-check:
	$(PY) scripts/release_check.py

scan-self:
	PYTHONPATH=src $(PY) -m actaira scan evals/artifacts || true

# The discovery package against a source that needs no network: the corpus
# directory this repository generates. `--offline` is passed on purpose, so
# this target proves the local connector really does reach nothing, and so it
# stays runnable on a clean checkout with the network unplugged like every
# other target above `all`. Every remote connector is exercised instead by
# `tests/test_connectors.py`, against a TLS server the tests start themselves.
discover-self:
	PYTHONPATH=src $(PY) -m actaira discover --list
	PYTHONPATH=src $(PY) -m actaira discover evals/artifacts --offline || true

serve:
	PYTHONPATH=src $(PY) -m actaira serve

VERSION := $(shell $(PY) -c "import tomllib,pathlib; print(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['version'])")

# Design note D-239. Cleans first, builds into dist/ and nowhere else, then
# opens both artifacts and asserts what is inside them: every runtime resource
# present, and no tests, evals, fuzz corpus or gadget-pickle generator. Needs
# `pip install build`, which is not in the dev extra for the same reason
# nothing else optional is: a packaging tool must not be able to break an
# install of the package. `make package INSTALL=--install` additionally
# installs the wheel into a throwaway venv and runs the CLI out of it.
INSTALL ?=
package:
	$(PY) scripts/build_package.py $(INSTALL)

# The source archive, built from what git tracks rather than from whatever is
# in the directory. Zipping the folder as it stands is exactly how a wheel, an
# sdist and two screenshots of v1.0.0 ended up inside a delivered copy of this
# repository; `git archive` cannot pick up an ignored file.
#
# The guard is not paperwork. `git archive HEAD` archives the repository that
# CONTAINS this directory, and a snapshot of this tree unpacked inside some
# other checkout has one - so without the check, this target would silently
# write a zip of somebody else's project under Actaira's name. It refuses
# instead, and says what to do about it. `make package` builds an sdist from
# this tree's own manifest and needs no repository at all.
source-archive:
	@test "$$(git rev-parse --show-toplevel 2>/dev/null)" = "$$(pwd)" || { \
	  echo "refusing: this directory is not the root of its own git repository."; \
	  echo "  'git archive' would archive whatever repository contains it."; \
	  echo "  Run 'git init' here first, or use 'make package', which builds"; \
	  echo "  an sdist from MANIFEST.in and needs no repository."; \
	  exit 1; }
	mkdir -p dist
	git archive --format=zip --prefix=actaira-$(VERSION)/ -o dist/actaira-$(VERSION)-source.zip HEAD
	@echo "wrote dist/actaira-$(VERSION)-source.zip from tracked files only"

# The gate, in the order a failure is cheapest to read. CI runs these same
# steps as separate jobs rather than invoking `all`, so a red build names the
# stage that failed instead of the word "all".
#
# Every step here is allowed to fail the build. The three `-` and `|| true`
# escapes in this file are all outside it and all deliberate: `benchmark`
# tolerates a missing ML stack when regenerating the real corpus, `scan-self`
# is a demonstration whose whole point is to exit 1, and `discover-self` reads
# the generated corpus, which is not in the checkout until `make eval` has run.
all: lint test fuzz eval eval-marking diagrams figures release-check

clean:
	rm -rf evals/artifacts evals/marking/artifacts evals/_tamper evals/real .pytest_cache .ruff_cache
	rm -rf fuzz/runs .screenshots build dist models
	rm -rf *.egg-info src/*.egg-info
	rm -f *.whl *.tar.gz .coverage coverage.xml safety_results.json
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +
