# Kimi Code headless guard

Making `kimi --prompt` safe to run unattended, and the findings that explain why
the obvious approaches don't work.

Tested against **Kimi Code CLI v0.27.0 on Windows 11**.

The findings apply to any platform. The guard ships twice, once in PowerShell
and once in bash:

| | Script | Suite |
|---|---|---|
| Windows | `bash-readonly-guard.ps1` | `Test-BashGuard.ps1` |
| macOS / Linux | `bash-readonly-guard.sh` | `test-bash-guard.sh` |

Both read the same 125 cases from `cases.tsv`, so they cannot drift apart
without a suite failing. Both pass 125/125, and they were differential-tested
against each other on a further 30 commands outside the suite, agreeing on
every decision.

One caveat I would rather state than paper over: **the bash guard was written
and tested on Windows**, under GNU bash 5.2 (Git for Windows) and against the
same synthetic payloads, not against a live Kimi Code CLI on Linux. The logic
is verified; what is unverified is a real Linux hook invocation end to end. If
you run it there, check that `hooks/guard-log.jsonl` gains a line when a
command is denied. A denial with no log line means the hook never ran, which
is the fail-open path described below.

The bash version needs `jq` or `python3` to read the hook payload. It probes
each candidate by parsing a known document before trusting it, rather than
checking the binary exists, because on Windows `python3` resolves to a Store
stub that exists and never runs. If no working parser is found it denies.

---

## The problem

`kimi --prompt` runs in **auto permission mode**. Tool calls are approved with no
human in the loop, because there is no human. That means an unattended run can
write files, and there is no flag to stop it: `--yolo`, `--auto` and `--plan` are
all rejected when combined with `--prompt`.

If you are running Kimi Code headlessly as a reviewer, a CI step, or behind an
MCP server, it can modify the repository it is reading. That surprised me, so
this documents it.

---

## Findings

Everything below was checked by looking at the filesystem afterwards, not by
reading the CLI's own denial messages. That distinction turned out to matter a
lot: see "Denial messages lie" at the bottom.

### 1. Auto mode really will write

Control test: `kimi -p "Create proof.txt containing X"` in an empty directory
with no permission rules. Exit 0, `proof.txt` on disk.

### 2. Permission rules DO apply in `--prompt` mode

Static `[[permission.rules]]` in `$KIMI_CODE_HOME/config.toml` are honoured. This
is the mechanism you have.

### 3. Precedence is NOT "first match wins"

The docs describe rules as matched in order with the first match winning. What
the v0.27.0 binary actually does is evaluate **all denies, then all asks, then
all allows**, taking the first non-undefined result.

So a `deny` is absolute regardless of where it sits in the file. Order only
matters *within* a decision class.

This is why a tiered design fails: put `allow Bash(git status*)` first and
`deny Bash` last as a catch-all, and the catch-all silently wins. Every allow is
dead. It looks like a working allowlist and is a blanket denial.

**Confirmed from source.** On
[kimi-code#1901](https://github.com/MoonshotAI/kimi-code/issues/1901) a reader
traced the same behaviour in the published source at commit `a41a09c`. The
policy chain is class-ordered and evaluation returns on the first defined
result, so precedence is fixed by class and never by position in `config.toml`:
`packages/agent-core/src/agent/permission/policies/index.ts` L38-47 (deny L39,
ask L45, allow L47, under the header comment at L27), with the same ordering in
`packages/agent-core-v2/src/agent/permissionPolicy/permissionPolicyService.ts`
L43-62 and its evaluate loop at L72-75.

**In headless mode it is worse than deny > ask > allow.**
`AutoModeApprovePermissionPolicy` sits between the deny and the ask, at
`index.ts` L40-41, commented "auto mode → approve (any auto-mode block must be a
deny rule above this)". Because `--prompt` runs in auto permission mode,
evaluation stops there and your `allow` and `ask` rules are never reached. For
an unattended run **`deny` is the only user-configured class that does
anything**, which is why layer 1 below is denies only.

### 4. Argument-pattern globs leak

`deny Bash(*>*)` looks like it blocks redirection. In testing it emitted a
denial message and the file was created anyway. Do not rely on `Bash(...)` arg
patterns for enforcement.

### 5. Denying `Write` while allowing `Bash` achieves nothing

The agent was denied `Write`, acknowledged the denial in its own output, and
created the file by another route. Verified on disk. If `Bash` is open, the
`Write` and `Edit` denials are decorative.

### 6. PreToolUse hooks DO fire in `--prompt` mode

This is undocumented and it is the finding this whole approach rests on. Hooks
are session-level, and print mode is a session. Verified: a `PreToolUse` hook on
`Bash` fired, wrote its audit entry, and the blocked command left nothing on
disk.

The source shows why it works. In `agent-core`,
`PreToolCallHookPermissionPolicy` is the **first** entry in the chain
(`policies/index.ts` L31 at commit `a41a09c`), ahead of the auto-mode approval
at L40-41. A hook is therefore the only user-controlled thing that runs before
auto mode approves a call.

**Caveat for a future version.** `agent-core-v2` has no equivalent policy in its
chain or in `permissionPolicy/policies/`, and it imports its hook context from
`#/agent/toolExecutor/toolHooks`, so the mechanism appears to have moved to the
executor layer. Whether PreToolUse still runs ahead of the auto-mode approval
under v2 is unverified. Combined with finding 7, a hook that stops being
consulted fails open silently. Re-run the suite and check `guard-log.jsonl`
after any CLI upgrade.

### 7. Hooks are fail-open

By design, and not configurable in v0.27.0. If the hook process fails to launch
or exceeds its timeout, the call is **allowed**. Any guard built on hooks is
mitigation, not a boundary. The only airtight answer is OS-level: run the CLI as
a restricted user with read-only filesystem permissions on the repo.

### 8. Token usage is not on stdout, but it is on disk

No output format emits usage. Every LLM step appends
`{"type":"usage.record","usage":{...}}` to
`$KIMI_CODE_HOME/sessions/<workspace>/<session_id>/agents/main/wire.jsonl`.
Fields are `inputOther`, `output`, `inputCacheRead`, `inputCacheCreation`.

The session id is in the `meta` line on stdout
(`{"role":"meta","type":"session.resume_hint","session_id":"..."}`) and is also
the directory name. Read usage by that id rather than picking the newest file by
timestamp, or concurrent runs will cross-attribute each other's tokens.

### 9. Quota is counted in requests, not tokens

Roughly 300 to 1,200 requests per rolling 5-hour window depending on tier, up to
30 concurrent, plus a weekly quota. Quota is **fully shared** across the CLI,
IDE extensions and API keys on one account, so headless testing competes with
your interactive sessions. Check with `/usage` or the Kimi Code Console; there is
no API endpoint or rate-limit response header.

---

## The guard

Given findings 3, 4 and 5, arg-pattern allowlisting is not usable. This uses two
layers instead.

**Layer 1, static denies.** `Write`, `Edit`, `Agent`, `AgentSwarm`, `CronCreate`.
Sub-agent tools are denied because hook coverage inside sub-agents is unverified.
`CronCreate` is denied so an unattended run cannot schedule future prompts.

**Layer 2, a PreToolUse hook on `Bash`.** `Bash` is deliberately *not* statically
denied. Every call goes to `bash-readonly-guard.ps1`, a fail-closed allowlist
doing real tokenisation rather than glob matching. It permits read-only git
porcelain, read-only inspection tools and `<tool> --version` checks, and denies
anything containing `> < | & ; $ ` ( )` or a newline anywhere in the raw command,
including inside quotes. Anything not explicitly allowed is denied, and any
internal error denies too.

Every decision is appended to `guard-log.jsonl`. **A `Bash` call that executed
with no corresponding log entry is the signature of the fail-open window in
finding 7.** That log is your only detection mechanism, so audit it.

---

## Install

1. Copy the guard for your platform to `$KIMI_CODE_HOME/hooks/`:
   `bash-readonly-guard.ps1` on Windows, `bash-readonly-guard.sh` elsewhere
   (`chmod +x` it).
2. Merge `config.example.toml` into `$KIMI_CODE_HOME/config.toml`, replacing the
   placeholder path in the hook `command` with your absolute path. On macOS or
   Linux the command is `/bin/bash "/path/to/bash-readonly-guard.sh"`.
3. Validate: `kimi doctor config <path to your config.toml>`
4. Run the test suite (below). It costs no tokens.

`kimi doctor config` reports OK for tables it does not recognise, so a passing
doctor is not evidence the hook is wired up. The suite is.

---

## Testing

Both suites run the same 125 cases from `cases.tsv` against the hook directly,
with no CLI and no API calls:

```
# Windows
powershell -NoProfile -ExecutionPolicy Bypass -File Test-BashGuard.ps1 -HookPath <path to bash-readonly-guard.ps1>

# macOS / Linux
./test-bash-guard.sh                       # guard next to the script
./test-bash-guard.sh /path/to/guard.sh     # or point at an installed copy
```

56 read-only commands expected to pass, 69 write or dangerous variants expected
to be denied, including `git -c alias.x=!cmd`, bare `git stash`, `git fetch` and
`git pull` (all of which modify `.git`), `find -exec`, `rg --pre` and `sort -o`.

An exit code that is neither 0 nor 2 is reported as a LEAK rather than a plain
failure, because that is the fail-open path: the hook crashed, and Kimi treats
a crashed hook as permission granted.

### Denial messages lie

Several tests during development looked like passes and were not:

- A canary write "passed" because the model declined on its own judgement. The
  rule never fired.
- A command "passed" because the binary wasn't installed, so nothing ran.
- A redirection "passed" on the denial message while the file was created.

If you change anything here, verify on the filesystem or in the guard log. Do not
trust the denial message alone.

---

## Licence

MIT. See LICENSE.
