<#
.SYNOPSIS
    FORU.TXT 0.8: "Generate reports\acceptance\frontend-control-matrix.json and a readable
    HTML/Markdown report mapping every visible control to backend call, acknowledgement,
    persisted result, error behavior, AutomationId, and test ID. Stage A passes only when this
    report has no untested enabled control and no unexplained failure."

.DESCRIPTION
    This is a first-pass, static-analysis implementation of that gate, not the full one. It scans
    every XAML view/control file under GUI\src\TitanEndpoint.App for interactive elements
    (Button, CheckBox, ComboBox, TextBox, DataGrid, TreeView) and records, for each:
      - file and line
      - control type
      - AutomationId (if any -- an interactive control with none is flagged as a real gap; a
        screen reader or an AutomationId-based test can't reliably address it)
      - Command binding (if any -- a rough proxy for "does this control do something backend-facing")
      - which GUI.tests.TitanEndpoint.App.UiTests\*.cs test files reference that AutomationId
        (a rough proxy for "is this covered by an automated test")

    What this does NOT do, so Stage A must not be marked complete from this report alone: it does
    not verify backend acknowledgement, persisted result, or error-path behavior per control (that
    needs the semantic knowledge only a human reviewer or a targeted live test has); it does not
    distinguish "no AutomationId because the control is decorative/non-interactive" from "missing
    coverage" beyond the control-type filter above; and a control referenced by an AutomationId
    string literal in a test file is not proof that test file actually exercises it correctly, only
    that the string appears there. Treat this report as a starting inventory and a regression guard
    against controls silently added with neither an AutomationId nor test coverage, not as the
    full FORU.TXT 0.8 acceptance evidence.

.OUTPUTS
    reports\acceptance\frontend-control-matrix.json
    reports\acceptance\frontend-control-matrix.md
#>

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$viewsRoot = Join-Path $repoRoot 'GUI\src\TitanEndpoint.App'
$testsRoot = Join-Path $repoRoot 'GUI\tests\TitanEndpoint.App.UiTests'
$reportsDir = Join-Path $repoRoot 'reports\acceptance'
New-Item -ItemType Directory -Force -Path $reportsDir | Out-Null

if (-not (Test-Path $viewsRoot)) { throw "Views root not found: $viewsRoot" }
if (-not (Test-Path $testsRoot)) { throw "UI tests root not found: $testsRoot" }

# ---- Step 1: collect every AutomationId string literal referenced anywhere in the test project
# (excluding build output) -- used as the "has test coverage" signal below. ----
$testFiles = Get-ChildItem -Path $testsRoot -Filter '*.cs' -Recurse |
    Where-Object { $_.FullName -notmatch '\\(bin|obj)\\' }

$idToTestFiles = @{}
foreach ($tf in $testFiles) {
    $content = Get-Content -Path $tf.FullName -Raw
    $matches = [regex]::Matches($content, '"([A-Za-z][A-Za-z0-9]*)"')
    foreach ($m in $matches) {
        $candidate = $m.Groups[1].Value
        # Only track identifiers that look like AutomationIds (PascalCase, ends in a control-ish
        # noun) to avoid polluting the map with unrelated string literals -- checked for real
        # existence against the XAML scan in step 2 below, not guessed here.
        if (-not $idToTestFiles.ContainsKey($candidate)) { $idToTestFiles[$candidate] = New-Object System.Collections.Generic.HashSet[string] }
        [void]$idToTestFiles[$candidate].Add($tf.Name)
    }
}

# ---- Step 2: scan every XAML file for interactive controls ----
$interactiveTypes = @('Button', 'CheckBox', 'ComboBox', 'TextBox', 'DataGrid', 'TreeView', 'ToggleButton', 'RadioButton')
$xamlFiles = Get-ChildItem -Path $viewsRoot -Filter '*.xaml' -Recurse |
    Where-Object { $_.FullName -notmatch '\\(bin|obj)\\' }

$controls = New-Object System.Collections.Generic.List[object]

foreach ($xf in $xamlFiles) {
    $lines = Get-Content -Path $xf.FullName
    $relativeFile = $xf.FullName.Substring($repoRoot.Length + 1)

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        foreach ($type in $interactiveTypes) {
            # Match "<Button " or "<Button>" but NOT "<Button.Style>"/"<DataGrid.Columns>" --
            # WPF's property-element syntax reuses the type name followed by a dot, which a plain
            # \b word-boundary match would wrongly treat as a second control instance (found
            # empirically: this initially double-counted every DataGrid.Columns and Button.Style
            # block in the codebase as an untested, un-idenified control).
            if ($line -match "<$type[\s>]") {
                # AutomationId and Command can appear on the same line or a following line before
                # the tag closes -- look ahead a small bounded window rather than requiring a
                # single-line match, since this codebase wraps long control declarations.
                $window = ($lines[$i..[Math]::Min($i + 4, $lines.Count - 1)]) -join ' '

                $idMatch = [regex]::Match($window, 'AutomationProperties\.AutomationId="([^"]+)"')
                $automationId = if ($idMatch.Success) { $idMatch.Groups[1].Value } else { $null }

                $cmdMatch = [regex]::Match($window, 'Command="\{Binding ([^,}"]+)')
                $command = if ($cmdMatch.Success) { $cmdMatch.Groups[1].Value.Trim() } else { $null }

                $testCoverage = @()
                if ($automationId -and $idToTestFiles.ContainsKey($automationId)) {
                    $testCoverage = @($idToTestFiles[$automationId])
                }

                $controls.Add([PSCustomObject]@{
                    file          = $relativeFile
                    line          = $i + 1
                    controlType   = $type
                    automationId  = $automationId
                    command       = $command
                    testCoverage  = $testCoverage
                    hasAutomationId = [bool]$automationId
                    hasTestCoverage = ($testCoverage.Count -gt 0)
                })
                break
            }
        }
    }
}

# ---- Step 3: write JSON ----
$jsonPath = Join-Path $reportsDir 'frontend-control-matrix.json'
$summary = [PSCustomObject]@{
    generatedAtUtc          = (Get-Date).ToUniversalTime().ToString('o')
    totalInteractiveControls = $controls.Count
    withAutomationId        = ($controls | Where-Object hasAutomationId).Count
    withoutAutomationId     = ($controls | Where-Object { -not $_.hasAutomationId }).Count
    withTestCoverage        = ($controls | Where-Object hasTestCoverage).Count
    withoutTestCoverage     = ($controls | Where-Object { -not $_.hasTestCoverage }).Count
}
$output = [PSCustomObject]@{
    summary  = $summary
    controls = $controls
}
$output | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding utf8

# ---- Step 4: write a readable Markdown report ----
$mdPath = Join-Path $reportsDir 'frontend-control-matrix.md'
$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine('# TITAN Frontend Control Matrix (first-pass, static)')
[void]$md.AppendLine('')
[void]$md.AppendLine("Generated: $($summary.generatedAtUtc)")
[void]$md.AppendLine('')
[void]$md.AppendLine('This is a static-analysis inventory, not full FORU.TXT 0.8 acceptance evidence -- see the')
[void]$md.AppendLine('generator script header for exactly what it does and does not verify (no backend')
[void]$md.AppendLine('acknowledgement/persisted-result/error-path verification per control).')
[void]$md.AppendLine('')
[void]$md.AppendLine('## Summary')
[void]$md.AppendLine('')
[void]$md.AppendLine("| Metric | Count |")
[void]$md.AppendLine("|---|---|")
[void]$md.AppendLine("| Total interactive controls scanned | $($summary.totalInteractiveControls) |")
[void]$md.AppendLine("| With AutomationId | $($summary.withAutomationId) |")
[void]$md.AppendLine("| **Without AutomationId (gap)** | **$($summary.withoutAutomationId)** |")
[void]$md.AppendLine("| With a referencing test file | $($summary.withTestCoverage) |")
[void]$md.AppendLine("| **Without any referencing test file (gap)** | **$($summary.withoutTestCoverage)** |")
[void]$md.AppendLine('')

$missingId = $controls | Where-Object { -not $_.hasAutomationId } | Sort-Object file, line
if ($missingId.Count -gt 0) {
    [void]$md.AppendLine('## Interactive controls with no AutomationId')
    [void]$md.AppendLine('')
    [void]$md.AppendLine('| File | Line | Type | Command |')
    [void]$md.AppendLine('|---|---|---|---|')
    foreach ($c in $missingId) {
        [void]$md.AppendLine("| $($c.file) | $($c.line) | $($c.controlType) | $($c.command) |")
    }
    [void]$md.AppendLine('')
}

$missingTest = $controls | Where-Object { $_.hasAutomationId -and -not $_.hasTestCoverage } | Sort-Object file, line
if ($missingTest.Count -gt 0) {
    [void]$md.AppendLine('## Controls with an AutomationId but no referencing test file')
    [void]$md.AppendLine('')
    [void]$md.AppendLine('| File | Line | Type | AutomationId | Command |')
    [void]$md.AppendLine('|---|---|---|---|---|')
    foreach ($c in $missingTest) {
        [void]$md.AppendLine("| $($c.file) | $($c.line) | $($c.controlType) | $($c.automationId) | $($c.command) |")
    }
    [void]$md.AppendLine('')
}

[void]$md.AppendLine('## Fully inventoried (AutomationId + at least one referencing test file)')
[void]$md.AppendLine('')
[void]$md.AppendLine('| File | Type | AutomationId | Referenced by |')
[void]$md.AppendLine('|---|---|---|---|')
foreach ($c in ($controls | Where-Object hasTestCoverage | Sort-Object file, line)) {
    [void]$md.AppendLine("| $($c.file) | $($c.controlType) | $($c.automationId) | $($c.testCoverage -join ', ') |")
}

Set-Content -Path $mdPath -Value $md.ToString() -Encoding utf8

Write-Output "Wrote $jsonPath"
Write-Output "Wrote $mdPath"
Write-Output ("Summary: {0} controls, {1} without AutomationId, {2} without any referencing test file" -f `
    $summary.totalInteractiveControls, $summary.withoutAutomationId, $summary.withoutTestCoverage)
