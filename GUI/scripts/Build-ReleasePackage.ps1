<#
.SYNOPSIS
    TITAN ENDPOINT - Release Package Builder
    FORU.TXT Part 6: "Produce a reproducible clean-build script and dependency/license/
    checksum inventory."

.DESCRIPTION
    Builds the TITAN ENDPOINT Release package end-to-end:
      1. Validates all prerequisites (dotnet SDK, CMake, Python, native toolchain).
      2. Builds all six native C++ endpoints in Release configuration using CMake.
      3. Builds the .NET GUI solution in Release configuration.
      4. Runs TitanEndpoint.Core.RegressionTests to validate the build.
      5. Regenerates runtime-manifest.json (new SHA-256 hashes for the built executables).
      6. Generates release\CHECKSUMS.sha256 for every shipped binary.
      7. Validates that release\DEPENDENCIES.md and release\THIRD-PARTY-LICENSES.txt exist.
      8. Writes a build log to reports\builds\build-<timestamp>.log.

    This script produces a reproducible Release build from a clean working tree.
    It does NOT perform code-signing, installer packaging, or deployment - those are
    separate gates. Run Build-ReleasePackage.ps1 first, then the acceptance suite scripts.

.PARAMETER TitanRoot
    Path to the TITAN ENDPOINT workspace root.

.PARAMETER NoBuild
    Skip the actual build steps and only run validation/checksum generation.
    Useful when binaries are already built and you only need to refresh the manifest.

.PARAMETER SkipNative
    Skip native C++ endpoint builds (for environments without a C++ toolchain).
    The GUI will still build; manifest validation will warn for missing native executables.
#>

[CmdletBinding()]
param(
    [string]$TitanRoot  = (Resolve-Path "$PSScriptRoot\..\.." -ErrorAction Stop).Path,
    [switch]$NoBuild,
    [switch]$SkipNative
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Timestamp  = Get-Date -Format "yyyy-MM-ddTHH-mm-ss"
$ReportDir  = Join-Path $TitanRoot "reports\builds"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }
$LogFile    = Join-Path $ReportDir "build-$Timestamp.log"

$Results  = [System.Collections.Generic.List[hashtable]]::new()
$Failures = [System.Collections.Generic.List[string]]::new()

function Record([string]$Name, [string]$State, [string]$Detail = "") {
    $entry = @{ Name = $Name; State = $State; Detail = $Detail; TimeUtc = (Get-Date).ToUniversalTime().ToString("o") }
    $Results.Add($entry)
    $icon = switch ($State) { "PASS" { "+" } "FAIL" { "X" } "SKIP" { "-" } "WARN" { "!" } default { "?" } }
    $msg = "[$icon] $Name$(if ($Detail) { ": $Detail" })"
    Write-Host $msg
    Add-Content $LogFile $msg
    if ($State -eq "FAIL") { $Failures.Add($Name) }
}

function RunCmd([string]$Exe, [string[]]$CommandArgs, [string]$WorkDir = $TitanRoot, [string]$StepName = "") {
    # Do not call this parameter $Args: PowerShell reserves the case-insensitive
    # automatic variable $args.  Using that name caused external tools to be
    # invoked without their intended arguments and could produce false passes.
    $step = if ($StepName) { $StepName } else { "$Exe $($CommandArgs -join ' ')" }
    Write-Host "`n[Running] $step ..."
    Add-Content $LogFile "[Running] $step"
    try {
        $result = & $Exe @CommandArgs 2>&1
        $output = $result | Out-String
        Add-Content $LogFile $output
        if ($LASTEXITCODE -ne 0) {
            Record $step "FAIL" "Exit code $LASTEXITCODE"
            return $false
        }
        Record $step "PASS"
        return $true
    } catch {
        Record $step "FAIL" $_.Exception.Message
        return $false
    }
}

function Resolve-Tool([string]$Name, [string[]]$Fallbacks) {
    $command = Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command -and $command.Source -and (Test-Path $command.Source)) { return $command.Source }
    foreach ($candidate in $Fallbacks) {
        if ($candidate -and (Test-Path $candidate)) { return (Resolve-Path $candidate).Path }
    }
    return $null
}

$LocalDotnet = Join-Path $env:LOCALAPPDATA "Microsoft\dotnet\dotnet.exe"
$DotnetExe = if (Test-Path $LocalDotnet) { (Resolve-Path $LocalDotnet).Path } else {
    Resolve-Tool "dotnet" @((Join-Path $env:ProgramFiles "dotnet\dotnet.exe"))
}
$Vs18CMake = Join-Path $env:ProgramFiles "Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
$Vs17CMake = Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
$CMakeExe = if (Test-Path $Vs18CMake) { (Resolve-Path $Vs18CMake).Path } elseif (Test-Path $Vs17CMake) {
    (Resolve-Path $Vs17CMake).Path
} else { Resolve-Tool "cmake" @() }

# Ninja invokes cl.exe directly, so locating the Visual Studio copy of CMake is
# not sufficient: INCLUDE, LIB, PATH, and the Windows SDK variables must also
# be initialized. Import the same x64 developer environment that Visual Studio
# uses before configuring or building any native target.
$VsDevCmdCandidates = @(
    (Join-Path $env:ProgramFiles "Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"),
    (Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat")
)
$VsDevCmd = $VsDevCmdCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $SkipNative -and $VsDevCmd) {
    $devCommand = '"' + $VsDevCmd + '" -arch=x64 -host_arch=x64 >nul && set'
    & $env:COMSPEC /s /c $devCommand | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        }
    }
}

Write-Host "`n===== TITAN ENDPOINT - Build-ReleasePackage =====" -ForegroundColor Cyan
Write-Host "Timestamp : $Timestamp"
Write-Host "TitanRoot : $TitanRoot"
Write-Host "NoBuild   : $NoBuild"
Write-Host "LogFile   : $LogFile`n"

# Step 1: Prerequisites

# dotnet SDK
try {
    if (-not $DotnetExe) { throw "dotnet SDK not found" }
    $dotnetOutput = & $DotnetExe --version 2>&1
    $dotnetExit = $LASTEXITCODE
    $dotnetVer = $dotnetOutput | Select-Object -First 1
    if ($dotnetExit -eq 0) { Record "dotnet SDK" "PASS" $dotnetVer }
    else { Record "dotnet SDK" "FAIL" "dotnet exited with code $dotnetExit" }
} catch { Record "dotnet SDK" "FAIL" "dotnet not found" }

# CMake (for native endpoints)
if (-not $SkipNative) {
    try {
        if (-not $CMakeExe) { throw "CMake not found" }
        if (-not $VsDevCmd) { throw "Visual Studio developer environment not found" }
        if (-not $env:INCLUDE) { throw "Visual Studio developer environment did not initialize INCLUDE" }
        $cmakeOutput = & $CMakeExe --version 2>&1
        $cmakeExit = $LASTEXITCODE
        $cmakeVer = $cmakeOutput | Select-Object -First 1
        if ($cmakeExit -eq 0 -and $cmakeVer -match '^cmake version') { Record "CMake" "PASS" $cmakeVer }
        else { Record "CMake" "WARN" "cmake not found - native builds will fail" }
    } catch { Record "CMake" "WARN" "cmake not found - use -SkipNative to skip" }
}

# Python (for Custom Rule)
try {
    $pyOutput = & python --version 2>&1
    $pyExit = $LASTEXITCODE
    $pyVer = $pyOutput | Select-Object -First 1
    if ($pyExit -eq 0) { Record "Python" "PASS" $pyVer }
    else { Record "Python" "WARN" "Python not found - Custom Rule tests may fail" }
} catch { Record "Python" "WARN" "Python not found" }

if ($Failures.Count -gt 0 -and -not $NoBuild) {
    Write-Error "Critical prerequisites missing. Aborting build."
    exit 1
}

# Step 2: Native endpoints

if (-not $NoBuild -and -not $SkipNative) {
    $NativeDirs = @(
        "PROCESS ENDPOINT\titan_fixed",
        "NETOWRK ENDPOINT",
        "APP",
        "FILEEE",
        "PORT ENDPOINT",
        "CORRELATOR"
    )
    foreach ($nDir in $NativeDirs) {
        $fullDir = Join-Path $TitanRoot $nDir
        if (-not (Test-Path $fullDir)) { Record "Native build: $nDir" "SKIP" "Directory not found"; continue }
        $buildDir = Join-Path $fullDir "out\build\release-manifest"
        New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
        $cache = Join-Path $buildDir "CMakeCache.txt"
        if (Test-Path $cache) {
            $homeLine = Select-String -LiteralPath $cache -Pattern '^CMAKE_HOME_DIRECTORY:INTERNAL=' | Select-Object -First 1
            $cachedHome = if ($homeLine) { ($homeLine.Line -split '=', 2)[1].Replace('/', '\').TrimEnd('\') } else { "" }
            $expectedHome = $fullDir.Replace('/', '\').TrimEnd('\')
            if (-not [string]::Equals($cachedHome, $expectedHome, [StringComparison]::OrdinalIgnoreCase)) {
                # Delete only CMake's disposable cache metadata inside this validated endpoint build directory.
                Remove-Item -LiteralPath $cache -Force
                $cmakeFiles = Join-Path $buildDir "CMakeFiles"
                if (Test-Path $cmakeFiles) { Remove-Item -LiteralPath $cmakeFiles -Recurse -Force }
                Record "CMake cache relocation: $nDir" "PASS" "Removed stale source root '$cachedHome'"
            }
        }
        RunCmd $CMakeExe @("-S", $fullDir, "-B", $buildDir, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release") $TitanRoot "CMake configure: $nDir" | Out-Null
        RunCmd $CMakeExe @("--build", $buildDir, "--parallel") $TitanRoot "CMake build: $nDir" | Out-Null
    }
}

# Step 3: .NET GUI

if (-not $NoBuild) {
    $SlnPath = Join-Path $TitanRoot "GUI\TitanEndpoint.sln"
    if (Test-Path $SlnPath) {
        RunCmd $DotnetExe @("build", $SlnPath, "--configuration", "Release", "--no-incremental") $TitanRoot "dotnet build (Release)" | Out-Null
    } else {
        Record "GUI solution" "FAIL" "TitanEndpoint.sln not found at $SlnPath"
    }
}

# Step 4: Core regression tests

$RegressionExe = Join-Path $TitanRoot "GUI\tests\TitanEndpoint.Core.RegressionTests\bin\Release\net8.0\TitanEndpoint.Core.RegressionTests.exe"
if (Test-Path $RegressionExe) {
    RunCmd $RegressionExe @() $TitanRoot "TitanEndpoint.Core.RegressionTests" | Out-Null
} else {
    Record "Core regression tests" "SKIP" "Binary not found - build first"
}

# Step 5: Regenerate runtime-manifest.json

$ManifestScript = Join-Path $TitanRoot "GUI\scripts\Generate-RuntimeManifest.ps1"
if (Test-Path $ManifestScript) {
    try {
        & $ManifestScript -TitanRoot $TitanRoot
        if ($LASTEXITCODE -eq 0) { Record "Generate-RuntimeManifest.ps1" "PASS" }
        else { Record "Generate-RuntimeManifest.ps1" "FAIL" "Exit code $LASTEXITCODE" }
    } catch { Record "Generate-RuntimeManifest.ps1" "FAIL" $_.Exception.Message }
} else {
    Record "Generate-RuntimeManifest.ps1" "SKIP" "Script not found at $ManifestScript"
}

# Step 6: CHECKSUMS.sha256

$ChecksumsPath = Join-Path $TitanRoot "release\CHECKSUMS.sha256"
if (-not (Test-Path (Split-Path $ChecksumsPath))) { New-Item -ItemType Directory (Split-Path $ChecksumsPath) -Force | Out-Null }

$ShippedFiles = @(
    "GUI\src\TitanEndpoint.App\bin\Release\net8.0-windows\TitanEndpoint.App.exe"
    "GUI\src\TitanEndpoint.App\bin\Release\net8.0-windows\TitanEndpoint.Core.dll"
    "runtime-manifest.json"
)

try {
    $runtimeManifest = Get-Content (Join-Path $TitanRoot "runtime-manifest.json") -Raw | ConvertFrom-Json
    $ShippedFiles += @($runtimeManifest.components | ForEach-Object { [string]$_.exePath })
} catch {
    Record "Read native component paths for checksums" "FAIL" $_.Exception.Message
}
$ShippedFiles = @($ShippedFiles | Select-Object -Unique)

$checksumLines = @("# TITAN ENDPOINT - Release Checksums", "# Generated: $((Get-Date).ToUniversalTime().ToString("o"))", "")
foreach ($rel in $ShippedFiles) {
    $full = Join-Path $TitanRoot $rel
    if (Test-Path $full) {
        $hash = (Get-FileHash $full -Algorithm SHA256).Hash.ToLowerInvariant()
        $checksumLines += "$hash  $rel"
    } else {
        $checksumLines += "# MISSING: $rel"
        Record "CHECKSUMS: $rel" "WARN" "File not found - may not be built yet"
    }
}
$checksumLines | Set-Content $ChecksumsPath -Encoding UTF8
Record "release\CHECKSUMS.sha256 generated" "PASS" $ChecksumsPath

# Step 7: Validate release docs

foreach ($doc in @("release\DEPENDENCIES.md", "release\THIRD-PARTY-LICENSES.txt")) {
    $full = Join-Path $TitanRoot $doc
    if (Test-Path $full) { Record "$doc present" "PASS" }
    else { Record "$doc present" "WARN" "File absent - create before final release packaging" }
}

# Build summary

$GateState = if ($Failures.Count -gt 0) { "FAIL" } else { "PASS" }
Write-Host "`n===== Build: $GateState ($($Failures.Count) failures) =====" -ForegroundColor $(if ($GateState -eq "PASS") { "Green" } else { "Red" })
Write-Host "Log: $LogFile"

exit $(if ($Failures.Count -gt 0) { 1 } else { 0 })
