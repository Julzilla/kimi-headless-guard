#Requires -Version 5.1
<#
.SYNOPSIS
  Offline test suite for bash-readonly-guard.ps1. Zero LLM tokens: pipes
  synthetic PreToolUse payloads into the hook and asserts exit codes
  (0 = allow, 2 = deny). Any other exit code is reported as a LEAK —
  that is the fail-open path and must never happen for these inputs.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-BashGuard.ps1 `
      -HookPath <KIMI_CODE_HOME>\hooks\bash-readonly-guard.ps1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$HookPath
)
$ErrorActionPreference = 'Stop'

$script:pass = 0
$script:fail = 0

# Resolve the executable of the currently running engine; do not rely on PATH.
$PsExe = Join-Path $PSHOME 'powershell.exe'

function Invoke-Case {
    param([string]$Cmd, [string]$Expect)
    $payload = @{
        hook_event_name = 'PreToolUse'
        session_id      = 'guard-offline-test'
        cwd             = (Get-Location).Path
        tool_input      = @{ command = $Cmd }
    } | ConvertTo-Json -Compress -Depth 6
    # Pipe the payload via a temp file + Start-Process so we get the real exit
    # code. Native stdin piping in PS 5.1 loses the exit code (-1) when the
    # child writes stderr and exits early.
    $tmpIn = [System.IO.Path]::GetTempFileName()
    $tmpErr = "$tmpIn.err"
    $tmpOut = "$tmpIn.out"
    try {
        [System.IO.File]::WriteAllText($tmpIn, $payload)
        $proc = Start-Process -FilePath $PsExe `
            -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $HookPath) `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardInput $tmpIn -RedirectStandardError $tmpErr -RedirectStandardOutput $tmpOut
        $code = $proc.ExitCode
    } finally {
        Remove-Item $tmpIn, $tmpErr, $tmpOut -Force -ErrorAction SilentlyContinue
    }
    $actual = switch ($code) {
        0       { 'allow' }
        2       { 'deny' }
        default { "LEAK(exit=$code)" }
    }
    if ($actual -eq $Expect) {
        $script:pass++
        Write-Host "PASS [$Expect] $Cmd"
    } else {
        $script:fail++
        Write-Host "FAIL [expect=$Expect actual=$actual] $Cmd" -ForegroundColor Red
    }
}

# ---------------- must be ALLOWED ----------------
$allow = @(
    'git status',
    'git status --short',
    'git diff HEAD~1 --stat',
    'git diff --cached',
    'git log --oneline -10',
    'git log --pretty=format:%H -5',
    'git log -p --follow -- src/app.ts',
    'git show HEAD:src/main.py',
    'git show HEAD@{1} --stat',
    'git blame -L 10,20 -- file.py',
    'git ls-files',
    'git ls-tree -r HEAD --name-only',
    'git grep -n TODO -- src',
    'git branch -v',
    'git branch -a --list feat*',
    'git branch --show-current',
    'git branch --contains HEAD',
    'git tag -l',
    'git tag --list v1.* --sort=-creatordate',
    'git remote',
    'git remote -v',
    'git remote get-url origin',
    'git rev-parse HEAD',
    'git reflog show -10',
    'git stash list',
    'git stash show -p stash@{0}',
    'git describe --tags --always',
    'git shortlog -sn',
    'git count-objects -v',
    'git -C /path/to/repo status',
    'git --version',
    'ls -la',
    'pwd',
    'where python',
    'which git',
    'cat README.md',
    'head -20 Program.cs',
    'tail -n 50 app.log',
    'wc -l *.py',
    'find . -name *.cs -type f',
    'rg -n "class Foo" src',
    'grep -rn TODO src',
    'node --version',
    'npm --version',
    'python --version',
    'dotnet --version',
    'go version',
    'sha256sum setup.py',
    'jq . package.json',
    'sort -u ids.txt',
    'diff a.txt b.txt',
    'echo hello',
    'whoami',
    'uname -a',
    'du -sh .',
    'file README.md'
)

# ---------------- must be DENIED ----------------
$deny = @(
    'echo hi > out.txt',
    'git log | head',
    'ls && rm -rf x',
    'ls; rm x',
    'git push',
    'git push origin main',
    'git commit -m wip',
    'git checkout .',
    'git restore .',
    'git clean -fdx',
    'git reset --hard HEAD',
    'git merge feature',
    'git rebase main',
    'git branch new-feature',
    'git branch -d old',
    'git branch --unset-upstream',
    'git tag v1.0',
    'git stash',
    'git stash pop',
    'git fetch origin',
    'git pull',
    'git -c alias.st=!notepad st',
    'git --exec-path=. status',
    'git diff --output=patch.diff',
    'git log --ext-diff',
    'git show --textconv HEAD:file',
    'git config user.name x',
    'git submodule update --init',
    'git worktree add ../x',
    'git remote add origin https://example.com/x.git',
    'git reflog expire --expire=now --all',
    'rm -rf node_modules',
    'rm out.txt',
    'mv a b',
    'cp a b',
    'touch newfile',
    'mkdir subdir',
    'del foo.txt',
    'cmd /c del foo.txt',
    'powershell -Command Remove-Item x',
    'curl https://example.com -o f',
    'wget https://example.com',
    'python -c pass',
    'node -e pass',
    'sed -i s/a/b/ f',
    'sed -n "w out.txt" f',
    'find . -delete',
    'find . -exec rm',
    'rg --pre cat foo',
    'npm install',
    'npm run build',
    'pip install requests',
    'sort -o out.txt in.txt',
    'tee out.txt',
    'tar cf out.tgz dir',
    'env',
    'printenv',
    'kill 1234',
    'xargs rm',
    'FOO=bar git status',
    'ls $(pwd)',
    'echo `pwd`',
    'cat a > b',
    "ls`nrm x",
    'git svn dcommit',
    'git am',
    'git apply patch.diff',
    'git gc',
    'git update-index --refresh'
)

foreach ($c in $allow) { Invoke-Case -Cmd $c -Expect 'allow' }
foreach ($c in $deny)  { Invoke-Case -Cmd $c -Expect 'deny'  }

Write-Host ''
Write-Host ("{0} passed, {1} failed, {2} total" -f $script:pass, $script:fail, ($script:pass + $script:fail))
if ($script:fail -gt 0) { exit 1 }
exit 0
