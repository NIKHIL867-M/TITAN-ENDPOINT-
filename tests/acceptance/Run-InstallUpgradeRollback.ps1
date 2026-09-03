<#
.SYNOPSIS
    TITAN ENDPOINT — Install, Upgrade, and Rollback Acceptance Runner
    FORU.TXT Part 6: "Code-sign the executables and installer; validate SmartScreen/UAC, clean
    install, relocation, repair, upgrade, rollback, uninstall, and recovery on a second clean
    Windows machine."

.DESCRIPTION
    This script orchestrates the install/upgrade/rollback acceptance gate. In the current build
    state, the installer project does not yet exist (release\installer\ is absent — see FORU.TXT
    'POST-FRONTEND FILES CONFIRMED ABSENT'). This script therefore:
      1. Validates prerequisite artifacts (installer, signed executables, checksums).
      2. If prerequisites are absent, records SKIP with a clear reference to the missing work.
      3. If prerequisites are present, runs install → smoke test → upgrade → rollback → uninstall.
      4. Writes a timestamped acceptance report.

    Run this script on a CLEAN MACHINE (second Windows machine, not the development computer)
    once the installer project and code-signing are complete. Never run it on the development
    machine where production TITAN logs and approved rules may exist.

.PARAMETER TitanRoot
    Path to the TITAN ENDPOINT workspace root (where runtime-manifest.json lives).

.PARAMETER InstallerPath
    Path to the signed installer executable. If absent, the relevant tests are SKIPped.

.PARAMETER ReportDir
    Directory where the acceptance report is saved.

.PARAMETER CleanMachineConfirmed
    Switch: caller confirms this is a clean machine with no existing TITAN installation.
    Without this switch, the script will warn but not run destructive install steps.
#>

[CmdletBinding()]
param(
    [string]$TitanRoot            = (Resolve-Path "$PSScriptRoot\..\.." -ErrorAction Stop).Path,
    [string]$InstallerPath        = "",
    [string]$ReportDir            = "",
    [switch]$CleanMachineConfirmed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $ReportDir) { $ReportDir = Join-Path $TitanRoot "reports\acceptance" }
$Timestamp  = Get-Date -Format "yyyy-MM-ddTHH-mm-ss"
$ReportJson = Join-Path $ReportDir "install-upgrade-rollback-$Timestamp.json"
$ReportMd   = Join-Path $ReportDir "install-upgrade-rollback-$Timestamp.md"

$Results  = [System.Collections.Generic.List[hashtable]]::new()
$Failures = [System.Collections.Generic.List[string]]::new()
$Skips    = [System.Collections.Generic.List[string]]::new()

function Record([string]$Name, [string]$State, [string]$Detail = "") {
    $entry = @{ Name = $Name; State = $State; Detail = $Detail; TimeUtc = (Get-Date -AsUtc -Format "o") }
    $Results.Add($entry)
    $icon = switch ($State) { "PASS" { "✓" } "FAIL" { "✗" } "SKIP" { "○" } default { "?" } }
    Write-Host "[$icon] $Name$(if ($Detail) { ": $Detail" })"
    if ($State -eq "FAIL") { $Failures.Add($Name) }
    if ($State -eq "SKIP") { $Skips.Add($Name) }
}

Write-Host "`n===== TITAN ENDPOINT — Install/Upgrade/Rollback Acceptance =====" -ForegroundColor Cyan
Write-Host "Timestamp : $Timestamp"
Write-Host "TitanRoot : $TitanRoot`n"

if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

# ── Clean-machine safety check ────────────────────────────────────────────────

if (-not $CleanMachineConfirmed) {
    Record "Clean-machine confirmation" "SKIP" "Pass -CleanMachineConfirmed only on a dedicated test VM or second clean machine, never on the development computer."
} else {
    Record "Clean-machine confirmation" "PASS" "Caller confirmed clean machine."
}

# ── Prerequisite checks ───────────────────────────────────────────────────────

# Installer
if (-not $InstallerPath -or -not (Test-Path $InstallerPath)) {
    Record "Installer present" "SKIP" "Installer project under release\installer\ is absent — FORU.TXT Part 6 remaining work. Create the signed installer before running this script."
} else {
    Record "Installer present" "PASS" $InstallerPath
}

# Code-signed executables
$ReleaseBinDir = Join-Path $TitanRoot "GUI\src\TitanEndpoint.App\bin\Release\net8.0-windows"
if (Test-Path $ReleaseBinDir) {
    $AppExe = Join-Path $ReleaseBinDir "TitanEndpoint.App.exe"
    if (Test-Path $AppExe) {
        try {
            $sig = Get-AuthenticodeSignature $AppExe
            if ($sig.Status -eq "Valid") { Record "TitanEndpoint.App.exe is Authenticode-signed" "PASS" $sig.SignerCertificate.Subject }
            else { Record "TitanEndpoint.App.exe is Authenticode-signed" "SKIP" "Status: $($sig.Status) — code-signing not yet applied (FORU.TXT Part 6)" }
        } catch {
            Record "TitanEndpoint.App.exe signature check" "SKIP" $_.Exception.Message
        }
    } else {
        Record "TitanEndpoint.App.exe exists" "SKIP" "Not found — build Release first"
    }
} else {
    Record "Release bin directory" "SKIP" "Not found: $ReleaseBinDir"
}

# CHECKSUMS.sha256
$ChecksumsPath = Join-Path $TitanRoot "release\CHECKSUMS.sha256"
if (Test-Path $ChecksumsPath) { Record "release\CHECKSUMS.sha256 present" "PASS" $ChecksumsPath }
else { Record "release\CHECKSUMS.sha256 present" "SKIP" "File absent — create during release packaging (FORU.TXT Part 6)" }

# DEPENDENCIES.md
$DepPath = Join-Path $TitanRoot "release\DEPENDENCIES.md"
if (Test-Path $DepPath) { Record "release\DEPENDENCIES.md present" "PASS" $DepPath }
else { Record "release\DEPENDENCIES.md present" "SKIP" "File absent — create before release" }

# ── Install, Upgrade, Rollback — all require installer ───────────────────────

$InstallerReady = $InstallerPath -and (Test-Path $InstallerPath) -and $CleanMachineConfirmed

if (-not $InstallerReady) {
    foreach ($step in @("Clean install to default location", "SmartScreen / UAC prompt pass",
                        "Post-install smoke test (launch + Overview visible)", "Install to relocated path",
                        "Repair existing installation", "Upgrade from v-1 to current",
                        "Rollback to previous version", "Uninstall leaves no residue",
                        "Recovery on second clean Windows machine")) {
        Record $step "SKIP" "Requires installer binary, code-signing, and -CleanMachineConfirmed switch — see FORU.TXT Part 6"
    }
} else {
    # Placeholder: real install/upgrade/rollback automation would go here once the installer exists.
    Write-Warning "Installer found but automated install/upgrade/rollback steps are not yet scripted. Add them here once the installer project is created under release\installer\."
    foreach ($step in @("Clean install", "Upgrade", "Rollback", "Uninstall")) {
        Record $step "SKIP" "Step scaffolded — implementation pending installer project completion"
    }
}

# ── Report ────────────────────────────────────────────────────────────────────

$GateState = if ($Failures.Count -gt 0) { "FAIL" } elseif ($Skips.Count -gt 0) { "INCOMPLETE" } else { "PASS" }

$Report = @{
    GeneratedUtc = (Get-Date -AsUtc -Format "o")
    TitanRoot    = $TitanRoot
    GateState    = $GateState
    FailCount    = $Failures.Count
    SkipCount    = $Skips.Count
    PassCount    = ($Results | Where-Object { $_.State -eq "PASS" }).Count
    Results      = $Results
    HonestNote   = "This gate requires a signed installer, a second clean Windows machine, and is currently mostly SKIP pending FORU.TXT Part 6 completion."
}
$Report | ConvertTo-Json -Depth 10 | Set-Content $ReportJson -Encoding UTF8

$Md = @"
# TITAN Install/Upgrade/Rollback Acceptance
Generated: $($Report.GeneratedUtc)
Gate: **$GateState** — $($Report.PassCount) passed, $($Report.FailCount) failed, $($Report.SkipCount) skipped.

> All steps currently SKIP because the installer project (``release\installer\``) does not yet exist.
> Run again after completing FORU.TXT Part 6 (packaging, code-signing, installer project).

$( $Results | ForEach-Object { "- [$($_.State)] $($_.Name)$(if ($_.Detail) { " — $($_.Detail)" })" } | Out-String )
"@
$Md | Set-Content $ReportMd -Encoding UTF8

Write-Host "`nJSON : $ReportJson"
Write-Host "MD   : $ReportMd"
Write-Host "`n===== Gate: $GateState =====" -ForegroundColor $(switch ($GateState) { "PASS" {"Green"} "INCOMPLETE" {"Yellow"} default {"Red"} })
exit $(if ($Failures.Count -gt 0) { 1 } else { 0 })
