# `lint`, `test`, `figures`, `contracts`, `design-notes` and `release-check` run
# on a clean checkout with no arguments and no network.
#
# `all` is made of `lint`, `test`, `figures` and `release-check`, in the order a
# failure is cheapest to read. Nothing in it needs anything beyond the dev extra.
#
# What went to archive/model-scanner at v2.3.0, and why no target here calls it:
# `eval`, `benchmark`, `eval-marking`, `real-corpus` and `nightly-real` all ran
# `evals/`, which read `actaira.inspect`; `fuzz` and `fuzz-long` ran `fuzz/`,
# which read `actaira.formats`; `diagrams` and `screenshots` drew pictures of
# the scanner and its web interface; `scan-self`, `discover-self` and `serve`
# were three of its commands. The trace-era equivalents arrive with the phases
# that give them something to measure.
PY ?= python3

.PHONY: help install test lint figures release-check contracts design-notes \
        package source-archive types clean all

help:
	@echo "install    install the package and dev extras"
	@echo "test       run the test suite"
	@echo "lint       run ruff"
	@echo "types      hold every mypy-clean module clean; needs the types extra"
	@echo "figures    measure the repository into docs/FIGURES.md and figures.json"
	@echo "contracts  regenerate docs/CONTRACTS.md from the shipped schemas"
	@echo "design-notes point every design-note row at the line that argues it"
	@echo "release-check refuse a release whose parts disagree with each other"
	@echo "package    build the wheel and the sdist into dist/ and check what is in them"
	@echo "source-archive  zip the tracked source into dist/, from an allowlist"
	@echo "clean      remove every generated directory and build artifact"
	@echo "all        lint, test, figures, release-check"

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest tests

lint:
	$(PY) -m ruff check src tests scripts

# Design note D-242. A ratchet, not an ultimatum: the modules mypy already
# agrees with must stay that way, and a module that has been cleaned up but
# left on the known-unclean list fails just as loudly as a new error. Needs
# the `types` extra, which is separate from `dev` on purpose - `make all` must
# not be able to go red because a checker changed between two versions, which
# is also why this target is not in `all`.
types:
	$(PY) scripts/type_check.py

# Every number in docs/FIGURES.md comes from here, measured from the working
# tree. The sections whose source is missing say so instead of printing a zero.
figures:
	$(PY) scripts/figures.py
	$(PY) scripts/sync_readme_figures.py

# The index of published contracts, written from the schemas the package
# ships rather than by hand. An index typed by hand is a fourth place a
# contract is recorded, and the one nothing would notice going stale.
contracts:
	$(PY) scripts/contracts_doc.py

# docs/RULES.md, written from the rule packs the package ships. Same argument as
# `contracts`: a rule's id, author, version and severity are recorded in the
# pack, and a page typed by hand is a second copy that nothing would notice
# going stale. `release-check` runs this with --check and fails on a difference.
rules:
	$(PY) scripts/rules_doc.py

# The design-note table's line numbers, which drift on every edit above them.
# `--check` is what the release gate runs; without it the rows are rewritten.
design-notes:
	$(PY) scripts/design_notes.py

# Design note D-180. Not a linter and not a test: it compares facts recorded in
# two places and fails when they have come apart. The version against the
# changelog, the measured figures against the suite, every schema against the
# module that emits it, every design note against the table, the CLI's commands
# against the README, the two READMEs against each other, and the defect ledger
# against the tests it names. Each drift it checks for is one this repository
# has actually had.
release-check:
	$(PY) scripts/release_check.py

VERSION := $(shell $(PY) -c "import tomllib,pathlib; print(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['version'])")

# Design note D-239. Cleans first, builds into dist/ and nowhere else, then
# opens both artifacts and asserts what is inside them: every runtime resource
# present, and no tests. Needs `pip install build`, which is not in the dev
# extra for the same reason nothing else optional is: a packaging tool must not
# be able to break an install of the package. `make package INSTALL=--install`
# additionally installs the wheel into a throwaway venv and runs the CLI out of
# it.
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
all: lint test figures release-check

clean:
	rm -rf .pytest_cache .ruff_cache build dist
	rm -rf *.egg-info src/*.egg-info
	rm -f *.whl *.tar.gz .coverage coverage.xml safety_results.json
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +
