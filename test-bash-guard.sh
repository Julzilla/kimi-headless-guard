#!/usr/bin/env bash
# Offline test suite for bash-readonly-guard.sh. Zero LLM tokens: pipes
# synthetic PreToolUse payloads into the hook and asserts exit codes
# (0 = allow, 2 = deny). Any other exit code is reported as a LEAK, because
# that is the fail-open path and must never happen for these inputs.
#
# Cases come from cases.tsv, the same file Test-BashGuard.ps1 reads, so the
# POSIX and PowerShell guards cannot drift apart silently.
#
#   ./test-bash-guard.sh                          # guard next to this script
#   ./test-bash-guard.sh /path/to/guard.sh        # explicit path
#   ./test-bash-guard.sh /path/to/guard.sh cases.tsv

set -u

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
hook=${1:-$here/bash-readonly-guard.sh}
cases=${2:-$here/cases.tsv}

[ -f "$hook" ]  || { echo "hook not found: $hook"   >&2; exit 1; }
[ -f "$cases" ] || { echo "cases not found: $cases" >&2; exit 1; }

pass=0; fail=0; leak=0

json_escape() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

decode() {  # turn the TSV escapes back into real characters
  local s=$1 out="" i c n
  for ((i = 0; i < ${#s}; i++)); do
    c=${s:i:1}
    if [ "$c" = '\' ] && [ $((i + 1)) -lt ${#s} ]; then
      n=${s:i+1:1}
      case $n in
        n) out+=$'\n'; i=$((i + 1)); continue ;;
        r) out+=$'\r'; i=$((i + 1)); continue ;;
        t) out+=$'\t'; i=$((i + 1)); continue ;;
        '\') out+='\'; i=$((i + 1)); continue ;;
      esac
    fi
    out+=$c
  done
  printf '%s' "$out"
}

run_case() {
  local expect=$1 cmd=$2 payload code actual
  payload=$(printf '{"hook_event_name":"PreToolUse","session_id":"guard-offline-test","cwd":"%s","tool_input":{"command":"%s"}}' \
    "$(json_escape "$PWD")" "$(json_escape "$cmd")")
  printf '%s' "$payload" | bash "$hook" >/dev/null 2>&1
  code=$?
  case $code in
    0) actual=allow ;;
    2) actual=deny ;;
    *) actual="LEAK(exit=$code)" ;;
  esac
  local shown=${cmd//$'\n'/\\n}
  if [ "$actual" = "$expect" ]; then
    pass=$((pass + 1)); printf 'PASS [%s] %s\n' "$expect" "$shown"
  else
    fail=$((fail + 1))
    case $actual in LEAK*) leak=$((leak + 1)) ;; esac
    printf 'FAIL [expect=%s actual=%s] %s\n' "$expect" "$actual" "$shown"
  fi
}

while IFS=$'\t' read -r expect cmd; do
  case $expect in ''|\#*) continue ;; esac
  run_case "$expect" "$(decode "$cmd")"
done <"$cases"

echo
printf '%d passed, %d failed, %d total\n' "$pass" "$fail" "$((pass + fail))"
if [ $leak -gt 0 ]; then
  printf '%d LEAK(s): the guard exited with neither 0 nor 2. That is fail-open.\n' "$leak" >&2
fi
[ $fail -eq 0 ] || exit 1
