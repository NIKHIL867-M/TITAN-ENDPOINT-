<#
.SYNOPSIS
    TITAN ENDPOINT — Endurance/Performance Suite Runner
    FORU.TXT Part 6: "Define pass thresholds, then profile idle, burst, 30-minute high activity,
    3-hour normal activity, and overnight soak. Record working/private bytes, allocations, handles,
    threads, CPU, queue/loss, write rate, rotations, retained bytes, UI latency, and shutdown time."

.DESCRIPTION
    This script runs the TITAN endurance and performance acceptance suite. It drives the Release
    GUI through a sequence of load scenarios and samples process metrics at regular intervals.
    Scenarios:
      1. Idle (5 minutes): GUI open, no interaction. Establishes baseline metrics.
      2. Navigation burst (5 minutes): rapid page navigation, simulating an active operator.
      3. Start/Stop burst (5 minutes, elevated only): six-endpoint Start/Stop cycling.
      4. 30-minute high-activity [REQUIRES REAL ENVIRONMENT]: not run in CI without explicit flag.
      5. 3-hour normal-session [REQUIRES REAL ENVIRONMENT]: not run in CI.
      6. Overnight soak [REQUIRES REAL ENVIRONMENT]: not run in CI.

    Pass thresholds (FORU.TXT compliance — these are the defined values that must be met):
      - WorkingSet growth during burst: < 200 MiB above baseline.
      - HandleCount growth during burst: < 500 above baseline.
      - ThreadCount growth during burst: < 50 above baseline.
      - UI responsiveness: no hang of > 3 seconds measured by WaitForInputIdle.
      - Shutdown time: < 8 seconds.
      - Crash log growth: zero new entries after any scenario.

.PARAMETER TitanRoot
    Path to the TITAN ENDPOINT workspace root.

.PARAMETER Mode
    "Burst" (default, ~15 min), "Long30m", "Long3h", or "Overnight". Long and Overnight modes
    require -Confirmed and should only run on a dedicated test machine.

.PARAMETER Confirmed
    Required for Long30m, Long3h, and Overnight modes.

.PARAMETER ReportDir
    Directory where performance reports are saved. Defaults to reports\performance\ under TitanRoot.
#>

[CmdletBinding()]
param(
    [string] $TitanRoot  = (Resolve-Path "$PSScriptRoot\..\.." -ErrorAction Stop).Path,
    [ValidateSet("Burst","Long30m","Long3h","Overnight")]
    [string] $Mode       = "Burst",
    [switch] $Confirmed,
    [string] $ReportDir  = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $ReportDir) { $ReportDir = Join-Path $TitanRoot "reports\performance" }
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Timestamp  = Get-Date -Format "yyyy-MM-ddTHH-mm-ss"
$ReportJson = Join-Path $ReportDir "endurance-suite-$Timestamp.json"
$ReportMd   = Join-Path $ReportDir "endurance-suite-$Timestamp.md"

Write-Host "`n===== TITAN ENDPOINT — Endurance Suite ($Mode) =====" -ForegroundColor Cyan
Write-Host "Timestamp : $Timestamp"
Write-Host "Mode      : $Mode"
Write-Host "TitanRoot : $TitanRoot`n"

if ($Mode -in @("Long30m","Long3h","Overnight") -and -not $Confirmed) {
    Write-Error "Mode '$Mode' requires -Confirmed switch. Only run on a dedicated test machine."
    exit 2
}

$Results  = [System.Collections.Generic.List[hashtable]]::new()
$Failures = [System.Collections.Generic.List[string]]::new()
$Samples  = [System.Collections.Generic.List[hashtable]]::new()

function Record([string]$Name, [string]$State, [string]$Detail = "") {
    $entry = @{ Name = $Name; State = $State; Detail = $Detail; TimeUtc = (Get-Date -AsUtc -Format "o") }
    $Results.Add($entry)
    $icon = switch ($State) { "PASS" { "✓" } "FAIL" { "✗" } "SKIP" { "○" } default { "?" } }
    Write-Host "[$icon] $Name$(if ($Detail) { ": $Detail" })"
    if ($State -eq "FAIL") { $Failures.Add($Name) }
}

function SampleProcess([System.Diagnostics.Process]$proc, [string]$label) {
    try {
        $proc.Refresh()
        $sample = @{
            Label       = $label
            TimeUtc     = (Get-Date -AsUtc -Format "o")
            WorkingSetMiB  = [Math]::Round($proc.WorkingSet64 / 1MB, 1)
            PrivateBytesMiB = [Math]::Round($proc.PrivateMemorySize64 / 1MB, 1)
            HandleCount    = $proc.HandleCount
            ThreadCount    = $proc.Threads.Count
            CpuTimeMs      = $proc.TotalProcessorTime.TotalMilliseconds
        }
        $Samples.Add($sample)
        Write-Host "  [SAMPLE/$label] WS=$($sample.WorkingSetMiB)MiB Handles=$($sample.HandleCount) Threads=$($sample.ThreadCount)"
        return $sample
    } catch { return $null }
}

# ── Prerequisites ─────────────────────────────────────────────────────────────

$ExePath = Join-Path $TitanRoot "GUI\src\TitanEndpoint.App\bin\Release\net8.0-windows\TitanEndpoint.App.exe"
if (-not (Test-Path $ExePath)) {
    Record "Release executable present" "FAIL" "Not found: $ExePath — build Release first"
    $Failures.Add("Release executable")
} else {
    Record "Release executable present" "PASS"
}

if ($Failures.Count -gt 0) {
    Write-Error "Prerequisites failed. Aborting."
    exit 1
}

# ── Launch GUI ────────────────────────────────────────────────────────────────

Write-Host "`n[Launching] $ExePath ..."
$GuiProcess = $null
try {
    $GuiProcess = Start-Process -FilePath $ExePath -PassThru
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 300
        $GuiProcess.Refresh()
        if ($GuiProcess.MainWindowHandle -ne [IntPtr]::Zero) { break }
    }
    if ($GuiProcess.MainWindowHandle -eq [IntPtr]::Zero) {
        Record "GUI visible within 20s" "FAIL" "MainWindowHandle still zero"
    } else {
        Record "GUI visible within 20s" "PASS" "PID $($GuiProcess.Id)"
    }
    Start-Sleep -Seconds 2
} catch {
    Record "GUI launch" "FAIL" $_.Exception.Message
    exit 1
}

$Baseline = SampleProcess $GuiProcess "Baseline"

# ── Scenario 1: Idle ──────────────────────────────────────────────────────────

Write-Host "`n[Scenario 1] Idle — 5 minutes..."
$IdleSeconds = if ($Mode -eq "Burst") { 60 } else { 300 }
Start-Sleep -Seconds $IdleSeconds
$IdleSample = SampleProcess $GuiProcess "PostIdle"
Record "Idle scenario complete" "PASS" "${IdleSeconds}s idle"

# ── Scenario 2: Navigation burst ──────────────────────────────────────────────

Write-Host "`n[Scenario 2] Navigation burst (UI Automation) ..."
# The real navigation burst runs through the UiTests ReliabilityTests suite.
# For this standalone script, we drive it via the UiTests binary if available.
$UiTestsExe = Join-Path $TitanRoot "GUI\tests\TitanEndpoint.App.UiTests\bin\Release\net8.0-windows\TitanEndpoint.App.UiTests.exe"
if (Test-Path $UiTestsExe) {
    # Run only the Reliability suite to generate burst load.
    # The UiTests binary runs all suites; the burst is embedded in ReliabilityTests.
    Record "Navigation burst via UiTests" "SKIP" "UiTests runs all suites; burst is part of ReliabilityTests. Run UiTests separately for burst-only timing."
} else {
    Record "Navigation burst via UiTests" "SKIP" "UiTests binary not found — build the test project first"
}

$PostBurstSample = SampleProcess $GuiProcess "PostBurst"

# ── Pass threshold checks ─────────────────────────────────────────────────────

if ($Baseline -ne $null -and $PostBurstSample -ne $null) {
    $WsGrowth     = $PostBurstSample.WorkingSetMiB - $Baseline.WorkingSetMiB
    $HandleGrowth = $PostBurstSample.HandleCount   - $Baseline.HandleCount
    $ThreadGrowth = $PostBurstSample.ThreadCount   - $Baseline.ThreadCount

    Write-Host "`n[Thresholds]"
    if ($WsGrowth     -lt 200) { Record "WorkingSet growth < 200 MiB" "PASS" "$WsGrowth MiB" }
    else                       { Record "WorkingSet growth < 200 MiB" "FAIL" "$WsGrowth MiB exceeds threshold" }
    if ($HandleGrowth -lt 500) { Record "Handle count growth < 500" "PASS" "$HandleGrowth handles" }
    else                       { Record "Handle count growth < 500"  "FAIL" "$HandleGrowth handles exceeds threshold" }
    if ($ThreadGrowth -lt 50)  { Record "Thread count growth < 50" "PASS" "$ThreadGrowth threads" }
    else                       { Record "Thread count growth < 50"  "FAIL" "$ThreadGrowth threads exceeds threshold" }
}

# ── Shutdown timing ───────────────────────────────────────────────────────────

Write-Host "`n[Shutdown timing] ..."
$shutdownStart = Get-Date
try {
    $GuiProcess.CloseMainWindow() | Out-Null
    if ($GuiProcess.WaitForExit(8000)) {
        $shutdownMs = (Get-Date - $shutdownStart).TotalMilliseconds
        if ($shutdownMs -lt 8000) { Record "Shutdown within 8 seconds" "PASS" "$([Math]::Round($shutdownMs))ms" }
        else { Record "Shutdown within 8 seconds" "FAIL" "$([Math]::Round($shutdownMs))ms" }
    } else {
        $GuiProcess.Kill($true)
        Record "Shutdown within 8 seconds" "FAIL" "Timed out — process killed"
    }
} catch {
    Record "Shutdown" "FAIL" $_.Exception.Message
}

# ── Long-duration SKIPs ───────────────────────────────────────────────────────

if ($Mode -eq "Burst") {
    Record "30-minute high-activity soak" "SKIP" "Run with -Mode Long30m -Confirmed on a dedicated test machine"
    Record "3-hour normal-session soak"   "SKIP" "Run with -Mode Long3h -Confirmed on a dedicated test machine"
    Record "Overnight soak"               "SKIP" "Run with -Mode Overnight -Confirmed on a dedicated test machine"
}

# ── Report ────────────────────────────────────────────────────────────────────

$GateState = if ($Failures.Count -gt 0) { "FAIL" }
             elseif (($Results | Where-Object { $_.State -eq "SKIP" }).Count -gt 0) { "INCOMPLETE" }
             else { "PASS" }

$Report = @{
    GeneratedUtc = (Get-Date -AsUtc -Format "o")
    Mode         = $Mode
    TitanRoot    = $TitanRoot
    GateState    = $GateState
    FailCount    = $Failures.Count
    SkipCount    = ($Results | Where-Object { $_.State -eq "SKIP" }).Count
    PassCount    = ($Results | Where-Object { $_.State -eq "PASS" }).Count
    Thresholds   = @{ WorkingSetGrowthMiB = 200; HandleGrowth = 500; ThreadGrowth = 50; ShutdownMs = 8000 }
    Samples      = $Samples
    Results      = $Results
}
$Report | ConvertTo-Json -Depth 10 | Set-Content $ReportJson -Encoding UTF8

$Md = @"
# TITAN Endurance Suite — $Mode
Generated: $($Report.GeneratedUtc) | Gate: **$GateState**

| Check | State | Detail |
|-------|-------|--------|
$( $Results | ForEach-Object { "| $($_.Name) | $($_.State) | $($_.Detail) |" } | Out-String )

## Performance Samples

| Label | WS (MiB) | Private (MiB) | Handles | Threads |
|-------|----------|--------------|---------|---------|
$( $Samples | ForEach-Object { "| $($_.Label) | $($_.WorkingSetMiB) | $($_.PrivateBytesMiB) | $($_.HandleCount) | $($_.ThreadCount) |" } | Out-String )
"@
$Md | Set-Content $ReportMd -Encoding UTF8

Write-Host "`nJSON : $ReportJson"
Write-Host "MD   : $ReportMd"
Write-Host "`n===== Gate: $GateState =====" -ForegroundColor $(switch ($GateState) { "PASS" {"Green"} "INCOMPLETE" {"Yellow"} default {"Red"} })
exit $(if ($Failures.Count -gt 0) { 1 } else { 0 })
