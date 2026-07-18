#Requires -Version 5.1
<#
.SYNOPSIS
  PreToolUse Bash guard for the PAL clink headless code reviewer (Kimi Code CLI).

.DESCRIPTION
  Fail-closed allowlist. Only these may run:
    * read-only git porcelain: status, diff, log, show, blame, annotate,
      rev-parse, ls-files, ls-tree, grep, describe, shortlog, reflog,
      whatchanged, count-objects, and strictly-limited branch/tag/remote/stash
    * read-only inspection tools: ls, cat, head, tail, wc, find (no -exec/-delete),
      rg/grep (no --pre), sort (no -o), sha*sum, jq, diff, stat, file, etc.
    * "<tool> --version" style version checks for common dev tools

  Redirection, pipes, chaining, substitution and subshells are denied
  unconditionally, anywhere in the raw command string, even inside quotes.

  Exit 0 = allow. Exit 2 = block (stderr becomes the reason shown to the model).
  ANY internal error also exits 2: fail-closed. The only residual fail-open
  window is powershell.exe failing to start or the configured hook timeout
  firing; Write/Edit/Agent/AgentSwarm/CronCreate remain statically denied in
  that window, but Bash would be unconstrained. See README for the mitigation.

  Every decision is appended as one JSON line to guard-log.jsonl next to this
  script. Denial messages lie; the log and on-disk checks do not.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$LogFile = Join-Path $PSScriptRoot 'guard-log.jsonl'

function Write-GuardLog {
    param([string]$Decision, [string]$Command, [string]$Why)
    try {
        $entry = [ordered]@{
            ts       = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffzzz')
            decision = $Decision
            reason   = $Why
            command  = $Command
        } | ConvertTo-Json -Compress
        Add-Content -Path $LogFile -Value $entry -Encoding UTF8
    } catch { }
}

function Block {
    param([string]$Why, [string]$Command)
    Write-GuardLog -Decision 'deny' -Command "$Command" -Why $Why
    $snippet = "$Command"
    if ($snippet.Length -gt 140) { $snippet = $snippet.Substring(0, 140) + '...' }
    [Console]::Error.WriteLine("Bash guard blocked this command: $Why")
    if ($snippet.Length -gt 0) { [Console]::Error.WriteLine("Command was: $snippet") }
    exit 2
}

function Permit {
    param([string]$Command)
    Write-GuardLog -Decision 'allow' -Command "$Command" -Why ''
    exit 0
}

function Test-BranchTagArgs {
    # Every flag must be whitelisted. Positional args (name/glob pattern) are
    # allowed only when a list-mode flag is present; without one, a positional
    # would CREATE the branch/tag.
    param(
        [string[]]$Rest,
        [string[]]$AllowedFlags,
        [string[]]$ListFlags,
        [string[]]$ValueTakingFlags
    )
    $listMode = $false
    $expectValue = $false
    foreach ($t in $Rest) {
        if ($expectValue) { $expectValue = $false; continue }
        if ($t.StartsWith('-')) {
            $base = ($t -split '=', 2)[0]
            if ($AllowedFlags -notcontains $base) { return $false }
            if ($ListFlags -contains $base) { $listMode = $true }
            if (($ValueTakingFlags -contains $base) -and (-not $t.Contains('='))) { $expectValue = $true }
        }
    }
    if ($listMode) { return $true }
    $expectValue = $false
    foreach ($t in $Rest) {
        if ($expectValue) { $expectValue = $false; continue }
        if ($t.StartsWith('-')) {
            $base = ($t -split '=', 2)[0]
            if (($ValueTakingFlags -contains $base) -and (-not $t.Contains('='))) { $expectValue = $true }
        } else {
            return $false
        }
    }
    return $true
}

# ---- 1. Parse the hook payload. Fail closed. ----
$raw = [Console]::In.ReadToEnd()
$command = ''
try {
    $payload = $raw | ConvertFrom-Json
    $command = [string]$payload.tool_input.command
} catch {
    Block -Why 'hook payload missing or unparseable' -Command ''
}
if ([string]::IsNullOrWhiteSpace($command)) {
    Block -Why 'empty or missing command' -Command "$command"
}
$command = "$command".Trim()

# ---- 2. Global metacharacter screen ----
# Any of these ANYWHERE in the raw string (even inside quotes) = deny.
# Blocks redirection, pipes, command chaining, variable/command substitution,
# subshells and multi-line input. A reviewer can issue two commands instead
# of a pipeline; it never needs any of these.
foreach ($ch in @('>', '<', '|', '&', ';', '$', '`', '(', ')', "`r", "`n")) {
    if ($command.Contains($ch)) {
        Block -Why 'shell metacharacter detected: no redirection, pipes, chaining, substitution or subshells' -Command $command
    }
}

# ---- 3. Tokenize (quote-aware; quotes already cannot smuggle metachars) ----
$tokens = @()
foreach ($m in [regex]::Matches($command, '"[^"]*"|''[^'']*''|[^\s]+')) {
    $tokens += ($m.Value.Trim('"', "'"))
}
if ($tokens.Count -eq 0) { Block -Why 'no command tokens' -Command $command }
$prog = [System.IO.Path]::GetFileNameWithoutExtension($tokens[0]).ToLowerInvariant()

# ---- 4. Version checks: "<tool> --version" and friends ----
$versionTools = @('node','npm','npx','python','python3','py','pip','pip3','uv',
                  'dotnet','go','rustc','cargo','java','javac','ruby','php',
                  'perl','deno','bun','tsc','cmake','gcc','g++','clang','jq',
                  'rg','bash','sh','git')
if (($tokens.Count -eq 2) -and ($versionTools -contains $prog) -and
    (@('--version','-V','-v','version') -contains $tokens[1])) {
    Permit -Command $command
}

# ---- 5. git: read-only porcelain only ----
if ($prog -eq 'git') {
    $gitReadSub = @('status','diff','log','show','blame','annotate','rev-parse',
                    'ls-files','ls-tree','grep','describe','shortlog','reflog',
                    'whatchanged','count-objects','branch','tag','remote','stash')
    $i = 1
    $sub = $null
    while ($i -lt $tokens.Count) {
        $rawTok = $tokens[$i]
        $tl = $rawTok.ToLowerInvariant()
        if ($rawTok -ceq '-C') { $i += 2; continue }   # case-sensitive: chdir, benign
        if ($tl.StartsWith('-c')) {
            Block -Why "'git -c' config override can execute arbitrary shell aliases" -Command $command
        }
        if ($tl.StartsWith('--exec-path')) {
            Block -Why "'git --exec-path' can run executables from inside the repo" -Command $command
        }
        if (@('-C','--git-dir','--work-tree','--namespace') -contains $tl) { $i += 2; continue }
        if ($tl.StartsWith('--git-dir=') -or $tl.StartsWith('--work-tree=') -or $tl.StartsWith('--namespace=')) { $i++; continue }
        if ($tl.StartsWith('-')) { $i++; continue }
        $sub = $tl
        break
    }
    if ($null -eq $sub) { Permit -Command $command }   # bare 'git' prints usage
    if ($gitReadSub -notcontains $sub) {
        Block -Why "git subcommand '$sub' is not read-only" -Command $command
    }
    $rest = @()
    if (($i + 1) -le ($tokens.Count - 1)) { $rest = @($tokens[($i + 1)..($tokens.Count - 1)]) }

    # Flags that can write files or execute programs, for any subcommand.
    foreach ($t in $rest) {
        $tl = $t.ToLowerInvariant()
        if ($tl.StartsWith('--output') -or $tl.StartsWith('--exec') -or
            $tl.StartsWith('--ext-diff') -or $tl.StartsWith('--textconv') -or
            $tl.StartsWith('--upload-pack') -or $tl.StartsWith('--receive-pack') -or
            $tl.StartsWith('--upload-archive') -or $tl.StartsWith('--hook-path')) {
            Block -Why "git flag '$t' can write files or execute programs" -Command $command
        }
    }

    switch ($sub) {
        'branch' {
            $ok = Test-BranchTagArgs -Rest $rest -AllowedFlags @('-l','--list','-a','--all','-r','--remotes','-v','-vv','--verbose','--show-current','--sort','--format','--contains','--no-contains','--merged','--no-merged','--points-at','--column','--no-column','--color','--no-color','-q','--quiet','--ignore-case','-i') -ListFlags @('-l','--list','-a','--all','-r','--remotes','-v','-vv','--verbose','--show-current','--contains','--no-contains','--merged','--no-merged','--points-at','--sort','--format') -ValueTakingFlags @('--sort','--format','--contains','--no-contains','--merged','--no-merged','--points-at','--column','--color')
            if (-not $ok) { Block -Why 'git branch is restricted to listing (-l/-a/-r/-v/--show-current/--contains etc.); no create/delete/rename' -Command $command }
        }
        'tag' {
            $ok = Test-BranchTagArgs -Rest $rest -AllowedFlags @('-l','--list','-n','--sort','--format','--points-at','--contains','--no-contains','--merged','--no-merged','--column','--no-column','--color','--no-color','-q','--quiet','--ignore-case','-i','--lines') -ListFlags @('-l','--list','-n','--sort','--format','--contains','--no-contains','--merged','--no-merged','--points-at') -ValueTakingFlags @('-n','--lines','--sort','--format','--points-at','--contains','--no-contains','--merged','--no-merged','--column','--color')
            if (-not $ok) { Block -Why 'git tag is restricted to listing (-l/--list etc.); no create/delete' -Command $command }
        }
        'stash' {
            if (($rest.Count -eq 0) -or (@('list','show') -notcontains $rest[0].ToLowerInvariant())) {
                Block -Why "only 'git stash list' and 'git stash show' are read-only" -Command $command
            }
        }
        'remote' {
            $r = @($rest | Where-Object { $_ -ne '' })
            $allowedRemote = ($r.Count -eq 0) -or
                (($r.Count -eq 1) -and (@('-v','--verbose') -contains $r[0].ToLowerInvariant())) -or
                (($r.Count -eq 2) -and ($r[0].ToLowerInvariant() -eq 'get-url'))
            if (-not $allowedRemote) {
                Block -Why "only 'git remote', 'git remote -v' and 'git remote get-url <name>' are read-only" -Command $command
            }
        }
        'reflog' {
            if (($rest.Count -gt 0) -and (-not $rest[0].StartsWith('-')) -and (@('show','exists') -notcontains $rest[0].ToLowerInvariant())) {
                Block -Why "only 'git reflog [show|exists]' is read-only (expire/delete blocked)" -Command $command
            }
        }
    }
    Permit -Command $command
}

# ---- 6. find: no -exec / -delete / -fprint ----
if ($prog -eq 'find') {
    if ($tokens.Count -gt 1) {
        foreach ($t in $tokens[1..($tokens.Count - 1)]) {
            $tl = $t.ToLowerInvariant()
            if ((@('-exec','-execdir','-ok','-okdir','-delete') -contains $tl) -or
                $tl.StartsWith('-fprint') -or $tl.StartsWith('-fls')) {
                Block -Why "find action '$t' can execute commands or write files" -Command $command
            }
        }
    }
    Permit -Command $command
}

# ---- 7. ripgrep / grep: no preprocessor or hostname execution ----
if (@('rg','grep') -contains $prog) {
    foreach ($t in $tokens) {
        $tl = $t.ToLowerInvariant()
        if ($tl.StartsWith('--pre') -or $tl.StartsWith('--hostname-bin')) {
            Block -Why "flag '$t' can execute an external program" -Command $command
        }
    }
    Permit -Command $command
}

# ---- 8. sort: stdout only, -o writes a file ----
if ($prog -eq 'sort') {
    foreach ($t in $tokens) {
        if ($t.StartsWith('-o')) { Block -Why "'sort -o' writes to a file" -Command $command }
    }
    Permit -Command $command
}

# ---- 9. Plain read-only inspection tools ----
$simpleReadOnly = @('ls','pwd','where','which','cat','head','tail','wc','file',
                    'stat','du','df','basename','dirname','realpath','readlink',
                    'uname','date','hostname','whoami','id','groups','uptime','ps',
                    'type','cmp','diff','cksum','md5sum','sha1sum','sha256sum',
                    'sha384sum','sha512sum','cut','comm','join','column','expand',
                    'unexpand','fold','fmt','nl','od','xxd','strings','tr',
                    'jq','echo','printf','uniq')
if ($simpleReadOnly -contains $prog) { Permit -Command $command }

# ---- 10. Default: deny ----
Block -Why "'$prog' is not on the read-only allowlist" -Command $command
