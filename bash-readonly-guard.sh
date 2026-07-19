#!/usr/bin/env bash
# PreToolUse Bash guard for a headless Kimi Code CLI reviewer.
#
# POSIX port of bash-readonly-guard.ps1. Same logic, same decisions: both are
# held to the identical 125 cases in cases.tsv, so a change to one that is not
# mirrored in the other shows up as a suite failure.
#
# Fail-closed allowlist. Only these may run:
#   * read-only git porcelain: status, diff, log, show, blame, annotate,
#     rev-parse, ls-files, ls-tree, grep, describe, shortlog, reflog,
#     whatchanged, count-objects, and listing-only branch/tag/remote/stash
#   * find, rg/grep, sort, and a set of plain inspection tools
#   * "<tool> --version" style checks
# Everything else is denied, including anything containing a shell
# metacharacter, because a reviewer never needs redirection or chaining.
#
# Exit codes: 0 permit, 2 block. Anything else is a LEAK (fail-open) and the
# suite reports it as such.
#
# Install: point a PreToolUse hook at it in $KIMI_CODE_HOME/config.toml:
#
#   [[hooks]]
#   event   = "PreToolUse"
#   matcher = "Bash"
#   command = '/bin/bash "/path/to/bash-readonly-guard.sh"'
#   timeout = 10
#
# KNOWN RESIDUAL RISK, same as the PowerShell original: Kimi hooks are
# fail-open by design. If this script cannot start, or the timeout fires, the
# Bash call is ALLOWED unconstrained. Static [[permission.rules]] denies on
# Write/Edit still hold in that window, but a shell command could still write.
# A Bash call with NO line in guard-log.jsonl is the signature. If that risk is
# unacceptable, deny Bash outright and lose read-only shell instead.

set -u

LOG_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/guard-log.jsonl"

# --- JSON helpers. No jq dependency: fall back to python3, then fail closed. --
json_escape() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

write_log() {
  local decision=$1 command=$2 why=$3 ts
  ts=$(date +%Y-%m-%dT%H:%M:%S%z 2>/dev/null || echo "")
  printf '{"ts":"%s","decision":"%s","reason":"%s","command":"%s"}\n' \
    "$ts" "$decision" "$(json_escape "$why")" "$(json_escape "$command")" \
    >>"$LOG_FILE" 2>/dev/null || true
}

block() {
  local why=$1 command=${2-}
  write_log deny "$command" "$why"
  printf 'Bash guard blocked this command: %s\n' "$why" >&2
  if [ -n "$command" ]; then
    local snip=$command
    [ ${#snip} -gt 140 ] && snip="${snip:0:140}..."
    printf 'Command was: %s\n' "$snip" >&2
  fi
  exit 2
}

permit() { write_log allow "$1" ""; exit 0; }

lower() { printf '%s' "${1,,}"; }

contains() {  # contains <needle> <haystack...>
  local needle=$1; shift
  local x
  for x in "$@"; do [ "$x" = "$needle" ] && return 0; done
  return 1
}

starts_with() { case "$1" in "$2"*) return 0;; *) return 1;; esac; }

# --- 1. Parse the hook payload. Fail closed. -------------------------------
# Pick a parser by PROBING it, not by checking it exists. On Windows,
# `command -v python3` resolves to a Microsoft Store stub that prints an
# install message and never runs Python, so an existence check picks a parser
# that cannot parse. Each candidate below is made to parse a known document
# and produce the expected answer before it is trusted.
PY_SNIPPET='import json,sys
try:
    sys.stdout.write(json.load(sys.stdin).get("tool_input",{}).get("command","") or "")
except Exception:
    sys.exit(9)'

parser=""
probe='{"tool_input":{"command":"__probe__"}}'
for cand in jq python3 python py; do
  command -v "$cand" >/dev/null 2>&1 || continue
  case $cand in
    jq) got=$(printf '%s' "$probe" | jq -er '.tool_input.command // ""' 2>/dev/null) ;;
    *)  got=$(printf '%s' "$probe" | "$cand" -c "$PY_SNIPPET" 2>/dev/null) ;;
  esac
  if [ "$got" = "__probe__" ]; then parser=$cand; break; fi
done
[ -z "$parser" ] && block 'no working JSON parser found (need jq or python3); refusing to guess at the payload' ''

raw=$(cat)
if [ "$parser" = jq ]; then
  command=$(printf '%s' "$raw" | jq -er '.tool_input.command // ""' 2>/dev/null) \
    || block 'hook payload missing or unparseable' ''
else
  command=$(printf '%s' "$raw" | "$parser" -c "$PY_SNIPPET" 2>/dev/null) \
    || block 'hook payload missing or unparseable' ''
fi

[ -z "${command//[[:space:]]/}" ] && block 'empty or missing command' "$command"
command="$(printf '%s' "$command" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

# --- 2. Global metacharacter screen ----------------------------------------
# Any of these ANYWHERE in the raw string (even inside quotes) = deny. Blocks
# redirection, pipes, chaining, substitution, subshells and multi-line input.
for ch in '>' '<' '|' '&' ';' '$' '`' '(' ')' $'\r' $'\n'; do
  case "$command" in
    *"$ch"*) block 'shell metacharacter detected: no redirection, pipes, chaining, substitution or subshells' "$command" ;;
  esac
done

# --- 3. Tokenize (quote-aware; quotes cannot smuggle metachars by now) -----
tokens=()
buf=""; quote=""; have=0
for ((i = 0; i < ${#command}; i++)); do
  c=${command:i:1}
  if [ -n "$quote" ]; then
    if [ "$c" = "$quote" ]; then quote=""; else buf+=$c; fi
    continue
  fi
  case $c in
    '"'|"'") quote=$c; have=1 ;;
    ' '|$'\t') if [ -n "$buf" ] || [ $have -eq 1 ]; then tokens+=("$buf"); buf=""; have=0; fi ;;
    *) buf+=$c ;;
  esac
done
if [ -n "$buf" ] || [ $have -eq 1 ]; then tokens+=("$buf"); fi
[ ${#tokens[@]} -eq 0 ] && block 'no command tokens' "$command"

prog=$(basename -- "${tokens[0]}")
prog=${prog%.*}
prog=$(lower "$prog")

# --- 4. Version checks: "<tool> --version" and friends ---------------------
version_tools=(node npm npx python python3 py pip pip3 uv dotnet go rustc cargo
               java javac ruby php perl deno bun tsc cmake gcc g++ clang jq rg
               bash sh git)
if [ ${#tokens[@]} -eq 2 ] && contains "$prog" "${version_tools[@]}"; then
  case "${tokens[1]}" in
    --version|-V|-v|version) permit "$command" ;;
  esac
fi

# --- Shared helper for branch/tag listing-only enforcement -----------------
# Every flag must be allowlisted. Positional args are permitted ONLY when a
# list-mode flag is present; without one, a positional would CREATE the ref.
test_branch_tag_args() {
  local -n _rest=$1 _allowed=$2 _listf=$3 _valuef=$4
  local listmode=0 expectvalue=0 t base
  for t in "${_rest[@]}"; do
    if [ $expectvalue -eq 1 ]; then expectvalue=0; continue; fi
    if starts_with "$t" '-'; then
      base=${t%%=*}
      contains "$base" "${_allowed[@]}" || return 1
      contains "$base" "${_listf[@]}" && listmode=1
      if contains "$base" "${_valuef[@]}" && [[ $t != *=* ]]; then expectvalue=1; fi
    fi
  done
  [ $listmode -eq 1 ] && return 0
  expectvalue=0
  for t in "${_rest[@]}"; do
    if [ $expectvalue -eq 1 ]; then expectvalue=0; continue; fi
    if starts_with "$t" '-'; then
      base=${t%%=*}
      if contains "$base" "${_valuef[@]}" && [[ $t != *=* ]]; then expectvalue=1; fi
    else
      return 1
    fi
  done
  return 0
}

# --- 5. git: read-only porcelain only --------------------------------------
if [ "$prog" = git ]; then
  git_read_sub=(status diff log show blame annotate rev-parse ls-files ls-tree
                grep describe shortlog reflog whatchanged count-objects branch
                tag remote stash)
  i=1; sub=""
  while [ $i -lt ${#tokens[@]} ]; do
    rawtok=${tokens[i]}
    tl=$(lower "$rawtok")
    # Case-sensitive: -C is chdir (benign), -c is a config override (not).
    if [ "$rawtok" = "-C" ]; then i=$((i + 2)); continue; fi
    starts_with "$tl" '-c'          && block "'git -c' config override can execute arbitrary shell aliases" "$command"
    starts_with "$tl" '--exec-path' && block "'git --exec-path' can run executables from inside the repo" "$command"
    if contains "$tl" -C --git-dir --work-tree --namespace; then i=$((i + 2)); continue; fi
    if starts_with "$tl" '--git-dir=' || starts_with "$tl" '--work-tree=' || starts_with "$tl" '--namespace='; then
      i=$((i + 1)); continue
    fi
    if starts_with "$tl" '-'; then i=$((i + 1)); continue; fi
    sub=$tl; break
  done
  [ -z "$sub" ] && permit "$command"           # bare 'git' prints usage
  contains "$sub" "${git_read_sub[@]}" || block "git subcommand '$sub' is not read-only" "$command"

  rest=()
  if [ $((i + 1)) -le $((${#tokens[@]} - 1)) ]; then rest=("${tokens[@]:$((i + 1))}"); fi

  # Flags that can write files or execute programs, for any subcommand.
  for t in ${rest[@]+"${rest[@]}"}; do
    tl=$(lower "$t")
    for bad in --output --exec --ext-diff --textconv --upload-pack --receive-pack --upload-archive --hook-path; do
      starts_with "$tl" "$bad" && block "git flag '$t' can write files or execute programs" "$command"
    done
  done

  case $sub in
    branch)
      _allowed=(-l --list -a --all -r --remotes -v -vv --verbose --show-current --sort --format --contains --no-contains --merged --no-merged --points-at --column --no-column --color --no-color -q --quiet --ignore-case -i)
      _listf=(-l --list -a --all -r --remotes -v -vv --verbose --show-current --contains --no-contains --merged --no-merged --points-at --sort --format)
      _valuef=(--sort --format --contains --no-contains --merged --no-merged --points-at --column --color)
      _r=(${rest[@]+"${rest[@]}"})
      test_branch_tag_args _r _allowed _listf _valuef \
        || block 'git branch is restricted to listing (-l/-a/-r/-v/--show-current/--contains etc.); no create/delete/rename' "$command"
      ;;
    tag)
      _allowed=(-l --list -n --sort --format --points-at --contains --no-contains --merged --no-merged --column --no-column --color --no-color -q --quiet --ignore-case -i --lines)
      _listf=(-l --list -n --sort --format --contains --no-contains --merged --no-merged --points-at)
      _valuef=(-n --lines --sort --format --points-at --contains --no-contains --merged --no-merged --column --color)
      _r=(${rest[@]+"${rest[@]}"})
      test_branch_tag_args _r _allowed _listf _valuef \
        || block 'git tag is restricted to listing (-l/--list etc.); no create/delete' "$command"
      ;;
    stash)
      if [ ${#rest[@]} -eq 0 ] || ! contains "$(lower "${rest[0]}")" list show; then
        block "only 'git stash list' and 'git stash show' are read-only" "$command"
      fi
      ;;
    remote)
      r=()
      for t in ${rest[@]+"${rest[@]}"}; do [ -n "$t" ] && r+=("$t"); done
      ok=1
      if [ ${#r[@]} -eq 0 ]; then ok=0
      elif [ ${#r[@]} -eq 1 ] && contains "$(lower "${r[0]}")" -v --verbose; then ok=0
      elif [ ${#r[@]} -eq 2 ] && [ "$(lower "${r[0]}")" = get-url ]; then ok=0
      fi
      [ $ok -eq 0 ] || block "only 'git remote', 'git remote -v' and 'git remote get-url <name>' are read-only" "$command"
      ;;
    reflog)
      if [ ${#rest[@]} -gt 0 ] && ! starts_with "${rest[0]}" '-' \
         && ! contains "$(lower "${rest[0]}")" show exists; then
        block "only 'git reflog [show|exists]' is read-only (expire/delete blocked)" "$command"
      fi
      ;;
  esac
  permit "$command"
fi

# --- 6. find: no -exec / -delete / -fprint ---------------------------------
if [ "$prog" = find ]; then
  for t in "${tokens[@]:1}"; do
    tl=$(lower "$t")
    if contains "$tl" -exec -execdir -ok -okdir -delete \
       || starts_with "$tl" '-fprint' || starts_with "$tl" '-fls'; then
      block "find action '$t' can execute commands or write files" "$command"
    fi
  done
  permit "$command"
fi

# --- 7. ripgrep / grep: no preprocessor or hostname execution --------------
if [ "$prog" = rg ] || [ "$prog" = grep ]; then
  for t in "${tokens[@]}"; do
    tl=$(lower "$t")
    if starts_with "$tl" '--pre' || starts_with "$tl" '--hostname-bin'; then
      block "flag '$t' can execute an external program" "$command"
    fi
  done
  permit "$command"
fi

# --- 8. sort: stdout only, -o writes a file --------------------------------
if [ "$prog" = sort ]; then
  for t in "${tokens[@]}"; do
    starts_with "$t" '-o' && block "'sort -o' writes to a file" "$command"
  done
  permit "$command"
fi

# --- 9. Plain read-only inspection tools -----------------------------------
simple_read_only=(ls pwd where which cat head tail wc file stat du df basename
                  dirname realpath readlink uname date hostname whoami id groups
                  uptime ps type cmp diff cksum md5sum sha1sum sha256sum
                  sha384sum sha512sum cut comm join column expand unexpand fold
                  fmt nl od xxd strings tr jq echo printf uniq)
contains "$prog" "${simple_read_only[@]}" && permit "$command"

# --- 10. Default: deny ------------------------------------------------------
block "'$prog' is not on the read-only allowlist" "$command"
