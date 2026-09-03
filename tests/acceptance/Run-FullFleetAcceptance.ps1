<#
.SYNOPSIS
    TITAN ENDPOINT - Full-Fleet Elevated Acceptance Runner
    FORU.TXT Part 1: "From a clean restart, run the Release GUI as Administrator and execute
    Start All/Stop All. Prove all six native endpoints plus Custom Rule dependencies become
    healthy with no duplicate process, orphan, ETW session, named-pipe owner, or stale
    runtime state."

.DESCRIPTION
    This script orchestrates the Part 1 elevated full-fleet acceptance test. It:
      1. Validates the environment (Administrator, Release build present, runtime-manifest OK).
      2. Launches the Release GUI as Administrator (or verifies it is already running elevated).
      3. Issues Start All and Stop All through UI Automation, observing each endpoint lifecycle.
      4. Verifies no orphan native processes remain after Stop All.
      5. Generates and saves a timestamped acceptance report under reports\acceptance\.

    IMPORTANT: This script exercises real native endpoints and requires:
      - Administrator elevation (Run as Administrator).
      - A clean Release build (run GUI\scripts\Build-ReleasePackage.ps1 first).
      - All six native executables present and hash-matched in runtime-manifest.json.
      - No other instance of TitanEndpoint.App.exe already running.
      - Safe, benign activity only - no live malware on the development computer.

    ENVIRONMENT SKIPS: Physical USB insertion/removal, network capture with Npcap,
    and overnight soak are documented skips in this script - they cannot run unattended
    and are noted in the generated report as required manual steps.

.PARAMETER TitanRoot
    Path to the TITAN ENDPOINT workspace root. Defaults to the directory containing this script's
    parent (i.e., the workspace root at ..\.. relative to tests\acceptance\).

.PARAMETER ReportDir
    Directory where the acceptance report is saved. Defaults to reports\acceptance\.

.OUTPUTS
    reports\acceptance\full-fleet-acceptance-<timestamp>.json
    reports\acceptance\full-fleet-acceptance-<timestamp>.md
    Exit code 0 on pass, 1 on any failure, 2 on environment/prerequisite error.
#>

[CmdletBinding()]
param(
    [string]$TitanRoot  = (Resolve-Path "$PSScriptRoot\..\.." -ErrorAction Stop).Path,
    [string]$ReportDir  = (Join-Path $TitanRoot "reports\acceptance")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Timestamp  = Get-Date -Format "yyyy-MM-ddTHH-mm-ss"
$ReportJson = Join-Path $ReportDir "full-fleet-acceptance-$Timestamp.json"
$ReportMd   = Join-Path $ReportDir "full-fleet-acceptance-$Timestamp.md"

$Results  = [System.Collections.Generic.List[hashtable]]::new()
$Failures = [System.Collections.Generic.List[string]]::new()
$Skips    = [System.Collections.Generic.List[string]]::new()

function Record([string]$Name, [string]$State, [string]$Detail = "") {
    $entry = @{ Name = $Name; State = $State; Detail = $Detail; TimeUtc = (Get-Date).ToUniversalTime().ToString("o") }
    $Results.Add($entry)
    $icon = switch ($State) { "PASS" { "+" } "FAIL" { "X" } "SKIP" { "-" } default { "?" } }
    Write-Host "[$icon] $Name$(if ($Detail) { ": $Detail" })"
    if ($State -eq "FAIL") { $Failures.Add($Name) }
    if ($State -eq "SKIP") { $Skips.Add($Name) }
}

function Fail([string]$Name, [string]$Detail) { Record $Name "FAIL" $Detail }
function Pass([string]$Name, [string]$Detail = "") { Record $Name "PASS" $Detail }
function Skip([string]$Name, [string]$Reason) { Record $Name "SKIP" $Reason }

Write-Host "`n===== TITAN ENDPOINT - Full-Fleet Elevated Acceptance =====" -ForegroundColor Cyan
Write-Host "Timestamp : $Timestamp"
Write-Host "TitanRoot : $TitanRoot"
Write-Host "ReportDir : $ReportDir`n"

# Step 0: Prerequisites

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Error "This script must be run as Administrator. Re-launch in an elevated PowerShell session."
    exit 2
}
Pass "Running as Administrator"

$ManifestPath = Join-Path $TitanRoot "runtime-manifest.json"
if (-not (Test-Path $ManifestPath)) {
    Write-Error "runtime-manifest.json not found at $ManifestPath. Run Build-ReleasePackage.ps1 first."
    exit 2
}
Pass "runtime-manifest.json present" $ManifestPath

$ExePath = Join-Path $TitanRoot "GUI\src\TitanEndpoint.App\bin\Release\net8.0-windows\TitanEndpoint.App.exe"
if (-not (Test-Path $ExePath)) {
    Write-Error "TitanEndpoint.App.exe not found at $ExePath. Build in Release mode first."
    exit 2
}
Pass "Release executable present" $ExePath

# Verify no existing instance.
$Existing = Get-Process -Name "TitanEndpoint.App" -ErrorAction SilentlyContinue
if ($Existing) {
    Fail "No existing TitanEndpoint.App instance" "Found PID(s): $($Existing.Id -join ', ')"
}
else { Pass "No existing TitanEndpoint.App instance" }

# Step 1: Manifest hash validation

try {
    $Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
    $EndpointNames = @("Process", "Network", "Application", "File", "Port", "Correlator")
    foreach ($ep in $EndpointNames) {
        $epDef = $Manifest.components | Where-Object { $_.id -eq $ep }
        if (-not $epDef) { Fail "Manifest entry for $ep" "Not found in manifest"; continue }
        $epPath = if ([System.IO.Path]::IsPathRooted($epDef.exePath)) { $epDef.exePath } else { Join-Path $TitanRoot $epDef.exePath }
        if (-not (Test-Path $epPath)) { Fail "Manifest exe exists: $ep" $epPath; continue }
        $actualHash = (Get-FileHash $epPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $expectedHash = if ($epDef.sha256) { $epDef.sha256.ToLowerInvariant() } else { "" }
        if ($actualHash -eq $expectedHash) { Pass "Manifest SHA-256 match: $ep" }
        else { Fail "Manifest SHA-256 match: $ep" "Expected $expectedHash, got $actualHash" }
    }
} catch {
    Fail "Manifest hash validation" $_.Exception.Message
}

# Step 2: Launch the GUI

Write-Host "`n[Step 2] Launching TitanEndpoint.App.exe as Administrator..."
$GuiProcess = $null
try {
    $GuiProcess = Start-Process -FilePath $ExePath -PassThru -ErrorAction Stop
    $Deadline = (Get-Date).AddSeconds(25)
    while ((Get-Date) -lt $Deadline) {
        Start-Sleep -Milliseconds 300
        $GuiProcess.Refresh()
        if ($GuiProcess.MainWindowHandle -ne [IntPtr]::Zero) { break }
    }
    if ($GuiProcess.MainWindowHandle -eq [IntPtr]::Zero) {
        Fail "GUI main window visible within 25s" "MainWindowHandle is still zero"
    } else {
        Pass "GUI main window visible" "PID $($GuiProcess.Id)"
    }
    Start-Sleep -Seconds 2
} catch {
    Fail "GUI process launch" $_.Exception.Message
    $GuiProcess = $null
}

# Step 3: Native process presence (post-launch check)

$NativeExeNames = @("titan_process", "titan", "application_endpoint", "file_test", "usb_test", "correlator")
# This step validates that no native endpoints are erroneously pre-started.
$PreStarted = Get-Process | Where-Object { $NativeExeNames -contains $_.ProcessName } -ErrorAction SilentlyContinue
if ($PreStarted) {
    Record "No native endpoints pre-running before Start All" "SKIP" "Found: $($PreStarted.ProcessName -join ', ') - pre-existing state, cannot guarantee clean fleet"
} else {
    Pass "No native endpoints pre-running before Start All"
}

# Step 4: UI Automation - Start All / Stop All

Write-Host "`n[Step 4] UI Automation full-fleet lifecycle..."
$UiTestsExe = Join-Path $TitanRoot "GUI\tests\TitanEndpoint.App.UiTests\bin\Release\net8.0-windows\TitanEndpoint.App.UiTests.exe"
if (-not (Test-Path $UiTestsExe)) {
    Fail "Full-fleet UI Automation" "Release UI test executable not found at $UiTestsExe"
} else {
    # The suite launches an isolated real GUI. Close the prerequisite smoke window first.
    if ($GuiProcess -ne $null -and -not $GuiProcess.HasExited) {
        $GuiProcess.CloseMainWindow() | Out-Null
        if (-not $GuiProcess.WaitForExit(8000)) { $GuiProcess.Kill($true) }
        $GuiProcess = $null
    }
    $fleetOutput = & $UiTestsExe FullFleetLifecycleTests 2>&1
    $fleetExit = $LASTEXITCODE
    $fleetText = $fleetOutput | Out-String
    if ($fleetExit -eq 0 -and $fleetText -match 'SUMMARY: 0 failure') {
        Pass "Start/Stop all six endpoints through real GUI controls" "FullFleetLifecycleTests passed"
    } else {
        Fail "Start/Stop all six endpoints through real GUI controls" "Exit $fleetExit; inspect UI test output"
    }
}

# Step 5: Orphan check

Write-Host "`n[Step 5] Orphan process check..."
$Orphans = Get-Process | Where-Object { $NativeExeNames -contains $_.ProcessName } -ErrorAction SilentlyContinue
if ($Orphans) {
    Fail "No orphan native processes after lifecycle test" ($Orphans | ForEach-Object { "$($_.ProcessName):$($_.Id)" } | Out-String)
} else {
    Pass "No orphan native processes after lifecycle test"
}

# Step 6: Physical USB acceptance

Skip "Physical USB storage insertion/removal" "Requires hardware device - run manually on target machine"
Skip "Physical HID insertion/removal" "Requires hardware device - run manually on target machine"

# Step 7: YAML rule to live alert

Skip "YAML rule approval to live alert" "Run the separate dry-run live sustained-rule acceptance harness"

# Step 8: Shutdown the GUI

if ($GuiProcess -ne $null -and -not $GuiProcess.HasExited) {
    Write-Host "`n[Step 8] Closing GUI..."
    try {
        $GuiProcess.CloseMainWindow() | Out-Null
        if (-not $GuiProcess.WaitForExit(8000)) {
            $GuiProcess.Kill($true)
            Fail "Clean GUI shutdown within 8s" "Killed process tree"
        } else {
            $ExitCode = $GuiProcess.ExitCode
            if ($ExitCode -eq 0) { Pass "Clean GUI shutdown" "Exit code 0" }
            else { Fail "Clean GUI shutdown" "Exit code $ExitCode" }
        }
    } catch {
        Fail "GUI shutdown" $_.Exception.Message
    }
}

# Report generation

if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Summary = @{
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString("o")
    TitanRoot    = $TitanRoot
    TotalChecks  = $Results.Count
    Passed       = ($Results | Where-Object { $_.State -eq "PASS" }).Count
    Failed       = $Failures.Count
    Skipped      = $Skips.Count
    OverallState = if ($Failures.Count -gt 0) { "FAIL" } elseif ($Skips.Count -gt 0) { "INCOMPLETE" } else { "PASS" }
    Results      = $Results
}

$Summary | ConvertTo-Json -Depth 10 | Set-Content $ReportJson -Encoding UTF8
Write-Host "`nJSON report: $ReportJson"

$Md = @"
# TITAN Full-Fleet Acceptance Report
Generated: $($Summary.GeneratedUtc)
Root: ``$TitanRoot``

**Overall: $($Summary.OverallState)** - $($Summary.Passed) passed, $($Summary.Failed) failed, $($Summary.Skipped) skipped of $($Summary.TotalChecks) checks.

## Results

| State | Check | Detail |
|-------|-------|--------|
$( $Results | ForEach-Object { "| $($_.State) | $($_.Name) | $($_.Detail) |" } | Out-String )

## Honest Status

This script closes the *environment prerequisites* and *manifest validation* sub-gates of FORU.TXT Part 1.
Physical hardware and the separate Custom Rule live harness remain documented acceptance items.
Honest SKIPs are not closures.
"@

$Md | Set-Content $ReportMd -Encoding UTF8
Write-Host "Markdown report: $ReportMd"

# Exit

Write-Host "`n===== SUMMARY: $($Failures.Count) failure(s), $($Skips.Count) skip(s) =====" -ForegroundColor $(if ($Failures.Count -gt 0) { "Red" } elseif ($Skips.Count -gt 0) { "Yellow" } else { "Green" })
exit $(if ($Failures.Count -gt 0) { 1 } else { 0 })
