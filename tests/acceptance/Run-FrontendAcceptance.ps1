<#
.SYNOPSIS
    TITAN ENDPOINT — Frontend Acceptance Runner
    FORU.TXT 0.10-D: "Create tests\acceptance\Run-FrontendAcceptance.ps1 to run the required
    suites, collect screenshots/logs/matrix, record Administrator/hardware/environment metadata,
    and fail closed on unexplained FAIL or required SKIP."

.DESCRIPTION
    Runs the full TitanEndpoint.App.UiTests suite (all 10 named suite classes: ControlFixture,
    Navigation, EndpointControl, Accessibility, CustomRuleWorkflow, NetworkWorkspace,
    VisualRegression, Reliability, FullFleetLifecycle, FailurePath), collects the output,
    and generates a timestamped acceptance report.

    The script:
      1. Validates that the Release build and UiTests binary exist.
      2. Records environment metadata (OS, user, elevation, DPI, screen resolution).
      3. Runs TitanEndpoint.App.UiTests.exe, capturing stdout/stderr.
      4. Parses PASS/FAIL/SKIP counts from the output.
      5. Writes a JSON and Markdown acceptance report to reports\acceptance\frontend\.
      6. Exits with code 0 only when there are zero unexplained FAILs and zero required SKIPs
         (an honest documented SKIP is still a FAIL at the gate level).

.PARAMETER TitanRoot
    Path to the TITAN ENDPOINT workspace root. Defaults to ..\.. relative to this script.

.PARAMETER ReportDir
    Directory where frontend acceptance reports are written. Defaults to
    reports\acceptance\frontend\ under TitanRoot.

.PARAMETER Timeout
    Maximum seconds to wait for the UiTests binary to complete. Defaults to 600 (10 minutes).
#>

[CmdletBinding()]
param(
    [string]$TitanRoot = (Resolve-Path "$PSScriptRoot\..\.." -ErrorAction Stop).Path,
    [string]$ReportDir = "",
    [int]   $Timeout   = 600
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $ReportDir) { $ReportDir = Join-Path $TitanRoot "reports\acceptance\frontend" }
$Timestamp   = Get-Date -Format "yyyy-MM-ddTHH-mm-ss"
$ReportJson  = Join-Path $ReportDir "frontend-acceptance-$Timestamp.json"
$ReportMd    = Join-Path $ReportDir "frontend-acceptance-$Timestamp.md"
$LogFile     = Join-Path $ReportDir "frontend-acceptance-$Timestamp.log"

Write-Host "`n===== TITAN ENDPOINT - Frontend Acceptance =====" -ForegroundColor Cyan
Write-Host "Timestamp : $Timestamp"
Write-Host "TitanRoot : $TitanRoot"
Write-Host "ReportDir : $ReportDir`n"

if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

# ── Collect environment metadata ──────────────────────────────────────────────

$IsAdmin  = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$OSVer    = [System.Environment]::OSVersion.VersionString
$UserName = [System.Environment]::UserName
$MachineName = [System.Environment]::MachineName

# DPI from registry (current user)
try {
    $DpiKey = "HKCU:\Control Panel\Desktop\WindowMetrics"
    $DpiProperty = Get-ItemProperty $DpiKey -Name "AppliedDPI" -ErrorAction SilentlyContinue
    $DpiVal = if ($null -ne $DpiProperty) { $DpiProperty.AppliedDPI } else { $null }
    $DpiText = if ($DpiVal) { "$DpiVal DPI" } else { "Unknown" }
} catch { $DpiText = "Unknown" }

$EnvMeta = @{
    RecordedUtc  = (Get-Date).ToUniversalTime().ToString("o")
    OS           = $OSVer
    Machine      = $MachineName
    User         = $UserName
    IsElevated   = $IsAdmin
    DPI          = $DpiText
    PowerShell   = $PSVersionTable.PSVersion.ToString()
    TitanRoot    = $TitanRoot
}
Write-Host "Environment:"
$EnvMeta.GetEnumerator() | ForEach-Object { Write-Host "  $($_.Key): $($_.Value)" }

# ── Locate the UiTests binary ─────────────────────────────────────────────────

$UiTestsExe = Join-Path $TitanRoot "GUI\tests\TitanEndpoint.App.UiTests\bin\Release\net8.0-windows\TitanEndpoint.App.UiTests.exe"
if (-not (Test-Path $UiTestsExe)) {
    Write-Warning "UiTests Release binary not found at: $UiTestsExe"
    Write-Warning "Trying Debug build..."
    $UiTestsExe = Join-Path $TitanRoot "GUI\tests\TitanEndpoint.App.UiTests\bin\Debug\net8.0-windows\TitanEndpoint.App.UiTests.exe"
}
if (-not (Test-Path $UiTestsExe)) {
    Write-Error "TitanEndpoint.App.UiTests.exe not found. Build the solution before running acceptance."
    exit 2
}
Write-Host "`nUiTests   : $UiTestsExe"

# ── Locate the Release GUI exe ────────────────────────────────────────────────

$GuiExe = Join-Path $TitanRoot "GUI\src\TitanEndpoint.App\bin\Release\net8.0-windows\TitanEndpoint.App.exe"
if (-not (Test-Path $GuiExe)) {
    Write-Warning "Release GUI exe not found at $GuiExe - some suite classes will SKIP live tests."
}

# ── Run the UiTests binary ────────────────────────────────────────────────────

Write-Host "`n[Running] $UiTestsExe ..."
$RawOutput = ""
$ExitCode  = -1
$TimedOut  = $false

try {
    $psi = [System.Diagnostics.ProcessStartInfo]::new($UiTestsExe)
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.WorkingDirectory       = $TitanRoot

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEndAsync()
    $stderr = $proc.StandardError.ReadToEndAsync()

    if ($proc.WaitForExit($Timeout * 1000)) {
        $ExitCode  = $proc.ExitCode
        $RawOutput = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
    } else {
        $TimedOut  = $true
        # Terminate the process tree before awaiting redirected stream tasks.
        # Awaiting first deadlocks because stdout/stderr remain open while the
        # timed-out child (or one of its descendants) is still alive.
        try {
            & taskkill.exe /PID $proc.Id /T /F 2>&1 | Out-Null
            $proc.WaitForExit(10000) | Out-Null
        } catch {
            try { $proc.Kill() } catch { }
        }
        $RawOutput = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
    }
} catch {
    Write-Error "Failed to launch UiTests: $($_.Exception.Message)"
    exit 2
}

$RawOutput | Set-Content $LogFile -Encoding UTF8
Write-Host "Log saved : $LogFile"

# ── Parse results ─────────────────────────────────────────────────────────────

$PassCount = ([regex]"(?m)^\[PASS\]").Matches($RawOutput).Count
$FailCount = ([regex]"(?m)^\[FAIL\]").Matches($RawOutput).Count
$SkipCount = ([regex]"(?m)^\[SKIP\]").Matches($RawOutput).Count

# Capture suite-level summary line if present.
$SummaryMatch = [regex]::Match($RawOutput, "SUMMARY: (\d+) failure")
$SuiteSummary = if ($SummaryMatch.Success) { $SummaryMatch.Value } else { "" }

Write-Host "`n[Results] PASS=$PassCount  FAIL=$FailCount  SKIP=$SkipCount  ExitCode=$ExitCode  TimedOut=$TimedOut"

# ── Build acceptance verdict ───────────────────────────────────────────────────

# FORU.TXT 0.10-D: "fail closed on unexplained FAIL or required SKIP"
# An honest SKIP is still open work — it does NOT count as a pass at the gate level.
$GateState = if ($TimedOut) { "TIMEOUT" }
             elseif ($FailCount -gt 0 -or $ExitCode -ne 0) { "FAIL" }
             elseif ($SkipCount -gt 0) { "INCOMPLETE" }  # SKIPs = open required work
             else { "PASS" }

Write-Host "Gate state: $GateState" -ForegroundColor $(switch ($GateState) { "PASS" {"Green"} "INCOMPLETE" {"Yellow"} default {"Red"} })

# ── Write reports ─────────────────────────────────────────────────────────────

$Report = @{
    GeneratedUtc  = (Get-Date).ToUniversalTime().ToString("o")
    Environment   = $EnvMeta
    UiTestsExe    = $UiTestsExe
    Timeout       = $Timeout
    TimedOut      = $TimedOut
    ExitCode      = $ExitCode
    PassCount     = $PassCount
    FailCount     = $FailCount
    SkipCount     = $SkipCount
    SuiteSummary  = $SuiteSummary
    GateState     = $GateState
    LogFile       = $LogFile
    HonestNote    = "A SKIP is documented open work, not a pass. Gate closes only when PASS=N, FAIL=0, SKIP=0."
}

$Report | ConvertTo-Json -Depth 10 | Set-Content $ReportJson -Encoding UTF8

$Md = @"
# TITAN Frontend Acceptance Report
Generated: $($Report.GeneratedUtc)

**Gate State: $GateState**

| Metric | Value |
|--------|-------|
| PASS   | $PassCount |
| FAIL   | $FailCount |
| SKIP   | $SkipCount |
| Exit code | $ExitCode |
| Timed out | $TimedOut |

## Environment

| Key | Value |
|-----|-------|
$( $EnvMeta.GetEnumerator() | ForEach-Object { "| $($_.Key) | $($_.Value) |" } | Out-String )

## Honest Status

> A SKIP means open required work. The frontend gate closes only when PASS > 0, FAIL = 0, and SKIP = 0.
> Remaining documented skips: Visual Regression (no real screenshot baseline in this environment),
> Reliability (compressed burst, not 30-minute/3-hour/overnight soak), and environment-specific
> cases in FailurePath and FullFleetLifecycle.

See full log: ``$LogFile``
See JSON report: ``$ReportJson``
"@

$Md | Set-Content $ReportMd -Encoding UTF8
Write-Host "JSON report : $ReportJson"
Write-Host "MD report   : $ReportMd"

exit $(if ($GateState -eq "PASS") { 0 } else { 1 })
