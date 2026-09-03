<#
.SYNOPSIS
    TITAN ENDPOINT — Acceptance Report Generator
    FORU.TXT: "Must create tests\acceptance\Generate-AcceptanceReport.ps1 and place generated
    reports under reports\acceptance\; do not hand-write passing results or claim completion
    without the matching logs, screenshots, hashes, performance samples, and failure-path outputs."

.DESCRIPTION
    Aggregates results from all acceptance sub-reports (Frontend, Full-Fleet, Install/Upgrade/
    Rollback, Endurance) into a single overall acceptance report. Each sub-report is found by
    scanning reports\acceptance\ for its pattern. Missing sub-reports are recorded as ABSENT
    (open required work), not as passes.

    The overall gate state is:
      PASS       — all sub-reports are present and show PASS.
      INCOMPLETE — one or more sub-reports are INCOMPLETE (have honest SKIPs).
      FAIL       — one or more sub-reports show FAIL.
      ABSENT     — one or more required sub-reports have never been generated.

    This script must be run AFTER all sub-runners have been executed and their reports saved.
    It does not re-run any tests.

.PARAMETER TitanRoot
    Path to the TITAN ENDPOINT workspace root.

.PARAMETER ReportDir
    Root acceptance report directory. Defaults to reports\acceptance\ under TitanRoot.
#>

[CmdletBinding()]
param(
    [string]$TitanRoot = (Resolve-Path "$PSScriptRoot\..\.." -ErrorAction Stop).Path,
    [string]$ReportDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $ReportDir) { $ReportDir = Join-Path $TitanRoot "reports\acceptance" }
$Timestamp  = Get-Date -Format "yyyy-MM-ddTHH-mm-ss"
$ReportJson = Join-Path $ReportDir "acceptance-summary-$Timestamp.json"
$ReportMd   = Join-Path $ReportDir "acceptance-summary-$Timestamp.md"

Write-Host "`n===== TITAN ENDPOINT — Acceptance Report Aggregator =====" -ForegroundColor Cyan
Write-Host "Timestamp : $Timestamp"
Write-Host "ReportDir : $ReportDir`n"

if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

# ── Sub-report definitions ────────────────────────────────────────────────────

$SubReports = @(
    @{ Name = "Frontend Acceptance (0.4 / 0.8)";       Pattern = "frontend-acceptance-*.json";          Dir = (Join-Path $ReportDir "frontend") }
    @{ Name = "Full-Fleet Elevated Acceptance (Part 1)"; Pattern = "full-fleet-acceptance-*.json";       Dir = $ReportDir }
    @{ Name = "Frontend Control Matrix";               Pattern = "frontend-control-matrix.json";          Dir = $ReportDir }
    @{ Name = "Install/Upgrade/Rollback (Part 6)";     Pattern = "install-upgrade-rollback-*.json";     Dir = $ReportDir }
    @{ Name = "Endurance Suite (Part 6)";              Pattern = "endurance-suite-*.json";               Dir = (Join-Path $TitanRoot "reports\performance") }
)

$Results     = [System.Collections.Generic.List[hashtable]]::new()
$OverallFail = $false
$OverallIncomplete = $false

foreach ($sr in $SubReports) {
    $searchDir = $sr.Dir
    if (-not (Test-Path $searchDir)) {
        $entry = @{
            SubReport  = $sr.Name
            State      = "ABSENT"
            FoundFile  = ""
            GateState  = "ABSENT"
            Detail     = "Report directory does not exist: $searchDir"
            TimeUtc    = (Get-Date -AsUtc -Format "o")
        }
        $Results.Add($entry)
        Write-Host "[ABSENT] $($sr.Name): no report directory"
        $OverallFail = $true
        continue
    }

    $files = Get-ChildItem $searchDir -Filter $sr.Pattern -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTime -Descending
    if ($files.Count -eq 0) {
        $entry = @{
            SubReport = $sr.Name
            State     = "ABSENT"
            FoundFile = ""
            GateState = "ABSENT"
            Detail    = "No matching report found in $searchDir (pattern: $($sr.Pattern))"
            TimeUtc   = (Get-Date -AsUtc -Format "o")
        }
        $Results.Add($entry)
        Write-Host "[ABSENT] $($sr.Name): no report file found"
        $OverallFail = $true
        continue
    }

    $latest     = $files[0]
    $gateState  = "UNKNOWN"
    $detail     = ""
    try {
        $data       = Get-Content $latest.FullName -Raw | ConvertFrom-Json
        $gateState  = $data.GateState ?? $data.OverallState ?? "UNKNOWN"
        $detail     = "Latest: $($latest.Name) ($(($data.GeneratedUtc ?? $data.RecordedUtc) ?? ''))"
    } catch {
        $gateState = "PARSE_ERROR"
        $detail    = "Failed to parse JSON: $($_.Exception.Message)"
    }

    $entry = @{
        SubReport = $sr.Name
        State     = $gateState
        FoundFile = $latest.FullName
        GateState = $gateState
        Detail    = $detail
        TimeUtc   = (Get-Date -AsUtc -Format "o")
    }
    $Results.Add($entry)

    $icon = switch ($gateState) { "PASS" { "✓" } "FAIL" { "✗" } "INCOMPLETE" { "○" } "ABSENT" { "✗" } default { "?" } }
    Write-Host "[$icon] $($sr.Name): $gateState — $detail"

    if ($gateState -in @("FAIL", "ABSENT", "PARSE_ERROR", "UNKNOWN")) { $OverallFail = $true }
    elseif ($gateState -eq "INCOMPLETE") { $OverallIncomplete = $true }
}

# ── Overall verdict ───────────────────────────────────────────────────────────

$OverallState = if ($OverallFail) { "FAIL" } elseif ($OverallIncomplete) { "INCOMPLETE" } else { "PASS" }
Write-Host "`n===== Overall: $OverallState =====" -ForegroundColor $(switch ($OverallState) { "PASS" {"Green"} "INCOMPLETE" {"Yellow"} default {"Red"} })

# ── Write aggregate report ────────────────────────────────────────────────────

$Summary = @{
    GeneratedUtc = (Get-Date -AsUtc -Format "o")
    TitanRoot    = $TitanRoot
    OverallState = $OverallState
    SubReports   = $Results
    HonestNote   = @(
        "ABSENT = sub-report has never been generated = open required work.",
        "INCOMPLETE = sub-report exists but has required SKIPs = open required work.",
        "PASS = all sub-reports present and all checks passing.",
        "Production readiness requires PASS with zero SKIP, zero ABSENT, and no fabricated evidence."
    )
}

$Summary | ConvertTo-Json -Depth 10 | Set-Content $ReportJson -Encoding UTF8

$Md = @"
# TITAN Endpoint — Overall Acceptance Summary
Generated: $($Summary.GeneratedUtc)

**Overall State: $OverallState**

| Sub-Report | State | File / Note |
|-----------|-------|-------------|
$( $Results | ForEach-Object { "| $($_.SubReport) | $($_.State) | $($_.Detail) |" } | Out-String )

## Honest Status

- **ABSENT**: Required report has never been generated. This is open work, not a pass.
- **INCOMPLETE**: Report exists with documented SKIPs. Open work remains.
- **PASS**: All checks in this sub-report passed with no SKIPs.

Production readiness requires every row to show PASS, with real screenshots, hashes, performance
samples, and failure-path outputs — not hand-written claims. See FORU.TXT for the exact evidence
each gate requires before it can be called complete.

See JSON: ``$ReportJson``
"@

$Md | Set-Content $ReportMd -Encoding UTF8
Write-Host "JSON : $ReportJson"
Write-Host "MD   : $ReportMd"

exit $(if ($OverallFail) { 1 } else { 0 })
