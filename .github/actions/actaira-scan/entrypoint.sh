#!/usr/bin/env bash
# Actaira as a GitHub Action step.
#
# The exit code is the interface (0 clean, 1 a failure, 2 usage, 3 something
# could not be read), so this script does not reinterpret it. It records it,
# writes the SARIF report, and lets a later step turn a non-zero code into a
# failed job. Doing it in that order is what allows the alerts to be uploaded
# before the job stops.
#
# Inputs arrive as environment variables, never as interpolated template text.
set -euo pipefail

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
#
# `GITHUB_OUTPUT` is a `key=value` file, one line each, and a newline inside a
# value writes a line this script never emitted: an input carrying
# `x\nshould-fail=false` sets an output the action's own logic depends on. The
# defence is to strip CR and LF, and it used to be applied to exactly one
# input - `path` - while `sarif-file` reached `emit` untouched on both the
# normal and the early-exit path.
#
# So every input is flattened here, once, before anything reads it. Doing it
# per-input at the `emit` call site is how one gets missed.
flatten() { printf '%s' "$1" | tr -d '\r\n'; }

target="$(flatten "${ACTAIRA_PATH:-.}")"
policy="$(flatten "${ACTAIRA_POLICY:-strict}")"
fail_on="$(flatten "${ACTAIRA_FAIL_ON:-high}")"
sarif_file="$(flatten "${ACTAIRA_SARIF_FILE:-actaira.sarif}")"
allow_inconclusive="$(flatten "${ACTAIRA_ALLOW_INCONCLUSIVE:-false}")"
outputs="${GITHUB_OUTPUT:-/dev/null}"

emit() { printf '%s\n' "$1" >>"$outputs"; }

# One place that writes the whole output set, so a path that returns early
# cannot emit four of the six and leave a consumer reading a stale value for
# the other two.
emit_all() {
  emit "exit-code=$1"
  emit "verdict=$2"
  emit "should-fail=$3"
  emit "sarif-file=${sarif_file}"
  emit "sarif-written=$4"
  emit "summary=$5"
}

fail_usage() {
  # Exit code 2 is the CLI's word for "this invocation was wrong", and a scan
  # that never ran has proved nothing about the repository, so `should-fail`
  # is true. The script itself still exits 0: the verdict travels in the
  # outputs and the job is failed by a later step.
  echo "::error title=Actaira::$1"
  emit_all 2 usage true false "$1"
  exit 0
}

# The two inputs with a closed set of values, checked here rather than left to
# the CLI. The CLI would reject them too - with exit code 2, which this script
# maps to the same place - but a typo in a workflow is worth a message that
# names the allowed values instead of an argparse error inside a log.
case "$policy" in
  strict|known-bad) ;;
  *) fail_usage "policy must be 'strict' or 'known-bad', not '${policy}'" ;;
esac

case "$fail_on" in
  critical|high|medium|low) ;;
  *) fail_usage "fail-on must be critical, high, medium or low, not '${fail_on}'" ;;
esac

case "$allow_inconclusive" in
  true|false) ;;
  *) fail_usage "allow-inconclusive must be 'true' or 'false', not '${allow_inconclusive}'" ;;
esac

# An empty `sarif-file` would make `--out ""` and then `[ -s "" ]`, which is
# false, so the action would report `sarif-written=false` for a run that did
# produce findings.
if [ -z "$sarif_file" ]; then
  fail_usage "sarif-file cannot be empty"
fi

if [ ! -e "$target" ]; then
  fail_usage "nothing to scan at '${target}'"
fi

# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------

argv=(scan "$target" --policy "$policy" --fail-on "$fail_on" --format sarif --out "$sarif_file")
if [ "$allow_inconclusive" = "true" ]; then
  argv+=(--allow-inconclusive)
fi

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
status=0
actaira "${argv[@]}" >"$log" 2>&1 || status=$?
cat "$log"

case "$status" in
  0) verdict="pass" ;;
  1) verdict="fail" ;;
  2) verdict="usage" ;;
  3) verdict="inconclusive" ;;
  *) verdict="error" ;;
esac

# The summary line comes out of the log, and the log contains file names from
# the repository being scanned, which are attacker-controlled in this tool's
# threat model. Flattened for the same reason every input is.
summary="$(flatten "$(grep -E 'artifact\(s\)|artefacto\(s\)' "$log" | tail -n 1)")"
if [ -z "$summary" ]; then
  summary="actaira exited ${status} (${verdict})"
fi

sarif_written="false"
if [ -s "$sarif_file" ]; then
  sarif_written="true"
fi

should_fail="false"
if [ "$status" -ne 0 ]; then
  should_fail="true"
fi

emit_all "$status" "$verdict" "$should_fail" "$sarif_written" "$summary"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Actaira"
    echo
    echo "\`${summary}\`"
    echo
    echo "| | |"
    echo "|---|---|"
    echo "| path | \`${target}\` |"
    echo "| policy | \`${policy}\` |"
    echo "| fail-on | \`${fail_on}\` |"
    echo "| verdict | **${verdict}** (exit code ${status}) |"
    echo "| SARIF | \`${sarif_file}\` |"
    echo
    echo "<details><summary>Full report</summary>"
    echo
    echo '```'
    head -c 50000 "$log"
    echo '```'
    echo
    echo "</details>"
  } >>"$GITHUB_STEP_SUMMARY"
fi

# Always 0: the verdict travels in the outputs, and the action fails the job in
# a later step so that the SARIF upload is not skipped.
exit 0
