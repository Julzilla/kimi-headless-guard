### What version of Kimi Code CLI is running?

0.27.0

### Which open platform/subscription were you using?

Kimi Code membership, authenticated via API key using the `KIMI_MODEL_*` environment variables (no OAuth).

### Which model were you using?

k3

### What platform is your computer?

Windows 11 (win32 x64)

### What issue are you seeing?

The docs describe `[[permission.rules]]` as ordered, with the first matching rule winning. In practice a broad `deny` beats a more specific `allow` no matter where either sits in the file.

From [Configuration files](https://www.kimi.com/code/docs/en/kimi-code-cli/configuration/config-files.html):

> Rules are written as a `[[permission.rules]]` array of tables, matched in order — the first matching rule takes effect.

The practical consequence is that the natural "allowlist plus catch-all deny" pattern fails silently. It looks like a working allowlist and behaves as a blanket denial. Anyone who writes that config and tests only the cases they expect to be denied will conclude it works.

It also cannot be fixed by dropping the catch-all, because without it anything not explicitly denied is permitted, which makes the allow entries redundant. As far as I can tell there is no ordering of these primitives that expresses a working allowlist.

This matters most in `--prompt` mode, which runs in auto permission mode with no human in the loop. An unattended run under a misunderstood config can write to the repository it is reading.

### What steps can reproduce the bug?

Three configs in `$KIMI_CODE_HOME/config.toml`, same prompt each time:

```
kimi --prompt "Run exactly this bash command and nothing else, then stop: echo hi"
```

**A. Allow only**

```toml
[[permission.rules]]
decision = "allow"
pattern = "Bash(echo *)"
```

Result: allowed. (Expected.)

**B. Same allow, then a catch-all deny after it**

```toml
[[permission.rules]]
decision = "allow"
pattern = "Bash(echo *)"

[[permission.rules]]
decision = "deny"
pattern = "Bash"
```

Result: **denied.** Per the documented ordering, `allow Bash(echo *)` is the first matching rule and should take effect.

**C. Metacharacter deny first, then allow, then catch-all deny**

```toml
[[permission.rules]]
decision = "deny"
pattern = "Bash(*>*)"

[[permission.rules]]
decision = "allow"
pattern = "Bash(echo *)"

[[permission.rules]]
decision = "deny"
pattern = "Bash"
```

Result: **denied**, for a command containing no `>`.

### What is the expected behavior?

Per the documentation, the first rule whose pattern matches should determine the outcome, so B and C should both allow `echo hi`.

Observed behaviour is that any matching `deny` wins regardless of position. Ordering appears to apply only *within* a decision class, with classes evaluated deny → ask → allow.

Either resolution would be fine, but the current state is a trap:

1. **Docs fix.** State the actual precedence (all denies, then asks, then allows; ordering applies within a class) and note explicitly that a catch-all deny nullifies every allow for that tool.
2. **Behaviour fix.** Make matching genuinely first-match-wins as documented, so allowlists become expressible.

### Additional information

**Secondary observation, lower confidence.** I could not get `Bash(arg-pattern)` denies to behave consistently. With only:

```toml
[[permission.rules]]
decision = "deny"
pattern = "Bash(*>*)"
```

a redirection was blocked in one run and, in another, produced a denial message while the file was still created on disk. I could not reduce this to a reliable repro and cannot rule out the agent reaching the filesystem by another route, so I am reporting it as an observation rather than a confirmed bug. Given the documented example is `Bash(rm -rf*)`, it seems worth checking whether argument-pattern denies are reliably enforced.

**Testing notes.** `KIMI_CODE_HOME` pointed at an isolated data root throughout. All results were verified by checking the filesystem afterwards rather than by reading denial messages, after finding that a denial message and the actual on-disk outcome could disagree.

**Related, possibly useful context.** `--prompt` cannot be combined with `--yolo`, `--auto` or `--plan` (the CLI rejects the combination), so static permission rules are the only mechanism available for constraining an unattended run. That is why the precedence behaviour matters more here than it would interactively. `PreToolUse` hooks do fire in `--prompt` mode, which turned out to be a workable alternative, though hooks are fail-open by design.
