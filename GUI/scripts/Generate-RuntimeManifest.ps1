<#
.SYNOPSIS
    FORU.TXT section 3: reproducible runtime-manifest.json generation.

.DESCRIPTION
    Computes SHA-256 hashes for the 6 native TITAN executables from their
    actual built locations and writes TITAN root\runtime-manifest.json.
    Replaces the previous manual "run Get-FileHash by hand" process (Round 5)
    with a real, repeatable script -- run this after every native rebuild
    instead of hand-editing the manifest.

    Paths recorded are TITAN-root-relative (package-relative), not absolute --
    FORU.TXT section 3: "Use package-relative paths where possible; validate
    the package after copying it to a different path." The GUI resolves them
    against its own known TITAN root at load time (see RuntimeManifest.cs).

.PARAMETER TitanRoot
    Root of the TITAN ENDPOINT tree. Defaults to two levels up from this
    script's own location (GUI\scripts\..\..).

.EXAMPLE
    .\Generate-RuntimeManifest.ps1
    Regenerates runtime-manifest.json in place using each component's
    currently-built exe.
#>
[CmdletBinding()]
param(
    [string]$TitanRoot
)

if ([string]::IsNullOrWhiteSpace($TitanRoot)) {
    # $PSScriptRoot is sometimes empty depending on how the script is invoked
    # (observed via `powershell -File`) -- fall back to $MyInvocation, which
    # is reliable in every invocation style.
    $scriptDir = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($scriptDir)) {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    $TitanRoot = (Resolve-Path (Join-Path $scriptDir "..\..")).Path
}

$ErrorActionPreference = "Stop"

# Each component's exe path is relative to $TitanRoot -- this is the ONE
# place that needs updating if a build output directory ever moves.
$components = @(
    @{
        Id = "Process"; DisplayName = "Process"
        RelExePath = "PROCESS ENDPOINT\titan_fixed\out\build\release-manifest\bin\titan_process.exe"
        RelWorkingDirectory = "PROCESS ENDPOINT\titan_fixed\out\build\release-manifest\bin"
        RelLogDirectory = "PROCESS ENDPOINT\titan_fixed\out\build\release-manifest\bin\logs"
        RequiresElevation = $true
        ControlChannelName = "\\.\pipe\TitanEndpoint_Process_Control"
    },
    @{
        Id = "Network"; DisplayName = "Network"
        RelExePath = "NETOWRK ENDPOINT\out\build\release-manifest\titan.exe"
        RelWorkingDirectory = "NETOWRK ENDPOINT\out\build\release-manifest"
        RelLogDirectory = "NETOWRK ENDPOINT\out\build\release-manifest\logs"
        RequiresElevation = $true
        ControlChannelName = "\\.\pipe\TitanEndpoint_Network_Control"
    },
    @{
        Id = "Application"; DisplayName = "Applications"
        RelExePath = "APP\out\build\release-manifest\bin\application_endpoint.exe"
        RelWorkingDirectory = "APP\out\build\release-manifest\bin"
        RelLogDirectory = "APP\out\build\release-manifest\bin\logs"
        RequiresElevation = $true
        ControlChannelName = "\\.\pipe\TitanEndpoint_Application_Control"
    },
    @{
        Id = "File"; DisplayName = "Files"
        RelExePath = "FILEEE\out\build\release-manifest\bin\Release\file_test.exe"
        RelWorkingDirectory = "FILEEE\out\build\release-manifest\bin\Release"
        RelLogDirectory = "FILEEE\out\build\release-manifest\bin\Release\logs"
        RequiresElevation = $true
        ControlChannelName = "\\.\pipe\TitanEndpoint_File_Control"
    },
    @{
        Id = "Port"; DisplayName = "Port / USB"
        RelExePath = "PORT ENDPOINT\out\build\release-manifest\bin\usb_test.exe"
        RelWorkingDirectory = "PORT ENDPOINT\out\build\release-manifest\bin"
        RelLogDirectory = $null  # Port writes to a fixed C:\ProgramData\TitanUSB\logs, not package-relative
        AbsoluteLogDirectory = "C:\ProgramData\TitanUSB\logs"
        RequiresElevation = $true
        ControlChannelName = "\\.\pipe\TitanEndpoint_Port_Control"
    },
    @{
        Id = "Correlator"; DisplayName = "Correlator"
        RelExePath = "CORRELATOR\out\build\release-manifest\bin\correlator.exe"
        RelWorkingDirectory = "CORRELATOR\out\build\release-manifest\bin"
        RelLogDirectory = "CORRELATOR\out\build\release-manifest\bin\logs"
        RequiresElevation = $false
        ControlChannelName = "\\.\pipe\TitanEndpoint_Correlator_Control"
    }
)

$versionTag = "release-manifest-$(Get-Date -Format yyyy-MM-dd)-all-endpoints-hardened"
$manifestComponents = @()
$allOk = $true

foreach ($c in $components) {
    $absExePath = Join-Path $TitanRoot $c.RelExePath
    if (-not (Test-Path $absExePath)) {
        Write-Warning "[$($c.Id)] Executable not found at '$absExePath' -- skipping (won't be in manifest)."
        $allOk = $false
        continue
    }

    $hash = (Get-FileHash -Path $absExePath -Algorithm SHA256).Hash
    $logDir = if ($c.ContainsKey("AbsoluteLogDirectory")) { $c.AbsoluteLogDirectory } else { $c.RelLogDirectory }

    Write-Host "[$($c.Id)] $absExePath" -ForegroundColor Cyan
    Write-Host "    SHA-256: $hash"

    $manifestComponents += [ordered]@{
        id                        = $c.Id
        displayName               = $c.DisplayName
        exePath                   = $c.RelExePath
        sha256                    = $hash
        version                   = $versionTag
        requiresElevation         = $c.RequiresElevation
        commandArguments          = ""
        workingDirectory          = $c.RelWorkingDirectory
        logDirectory              = $logDir
        controlChannelName        = $c.ControlChannelName
        controlChannelImplemented = $true
        healthTimeoutSeconds      = 45
    }
}

$manifest = [ordered]@{
    schemaVersion = 2
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    generatedBy = "Generate-RuntimeManifest.ps1 (automated -- FORU.TXT section 3, replaces manual Get-FileHash)"
    pathsAreRelativeTo = "TITAN root (the directory containing this file)"
    components = $manifestComponents
}

$outPath = Join-Path $TitanRoot "runtime-manifest.json"
$manifest | ConvertTo-Json -Depth 6 | Out-File -FilePath $outPath -Encoding utf8 -NoNewline
Write-Host ""
Write-Host "Wrote $outPath" -ForegroundColor Green

if (-not $allOk) {
    Write-Warning "One or more components were skipped -- see warnings above. Manifest is PARTIAL."
    exit 1
}
exit 0
