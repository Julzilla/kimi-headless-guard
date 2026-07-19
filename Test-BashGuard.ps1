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
# Cases live in cases.tsv, which test-bash-guard.sh reads too, so the
# PowerShell and POSIX guards are held to identical inputs and cannot drift
# apart. Format: <expect><TAB><command>, with control characters escaped as
# \n, \r, \t and a doubled backslash.
$CasesPath = Join-Path $PSScriptRoot 'cases.tsv'
if (-not (Test-Path $CasesPath)) { throw "cases.tsv not found beside the suite: $CasesPath" }

function Expand-CaseEscapes {
    param([string]$Text)
    $sb = [System.Text.StringBuilder]::new()
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]
        if ($c -eq [char]92 -and $i + 1 -lt $Text.Length) {
            $n = $Text[$i + 1]
            switch ($n) {
                'n'     { [void]$sb.Append([char]10); $i++; continue }
                'r'     { [void]$sb.Append([char]13); $i++; continue }
                't'     { [void]$sb.Append([char]9);  $i++; continue }
                default {
                    if ($n -eq [char]92) { [void]$sb.Append([char]92); $i++; continue }
                }
            }
        }
        [void]$sb.Append($c)
    }
    $sb.ToString()
}

$cases = foreach ($line in (Get-Content $CasesPath -Encoding utf8)) {
    if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
    $parts = $line -split [char]9, 2
    if ($parts.Count -ne 2) { continue }
    [pscustomobject]@{ Expect = $parts[0]; Cmd = Expand-CaseEscapes $parts[1] }
}

foreach ($c in $cases) { Invoke-Case -Cmd $c.Cmd -Expect $c.Expect }

Write-Host ''
Write-Host ("{0} passed, {1} failed, {2} total" -f $script:pass, $script:fail, ($script:pass + $script:fail))
if ($script:fail -gt 0) { exit 1 }
exit 0
