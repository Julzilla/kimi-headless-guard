# Kimi Code headless guard

Making `kimi --prompt` safe to run unattended, and the findings that explain why
the obvious approaches don't work.

Tested against **Kimi Code CLI v0.27.0 on Windows 11**.

The findings apply to any platform. The guard itself is **PowerShell and Windows
only** — I don't have macOS or Linux to test on, so I'd rather say that plainly
than pretend otherwise. A port is welcome; the logic is a tokeniser, an
allowlist and a metacharacter screen, and the 125-case suite defines the
expected behaviour precisely enough to port against.

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

1. Copy `bash-readonly-guard.ps1` to `$KIMI_CODE_HOME/hooks/`.
2. Merge `config.example.toml` into `$KIMI_CODE_HOME/config.toml`, replacing the
   placeholder path in the hook `command` with your absolute path.
3. Validate: `kimi doctor config <path to your config.toml>`
4. Run the test suite (below). It costs no tokens.

---

## Testing

`Test-BashGuard.ps1` runs 125 cases against the hook directly, with no CLI and no
API calls:

```
powershell -NoProfile -ExecutionPolicy Bypass -File Test-BashGuard.ps1 -HookPath <path to bash-readonly-guard.ps1>
```

54 read-only commands expected to pass, 71 write or dangerous variants expected
to be denied, including `git -c alias.x=!cmd`, bare `git stash`, `git fetch` and
`git pull` (all of which modify `.git`), `find -exec`, `rg --pre` and `sort -o`.

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
