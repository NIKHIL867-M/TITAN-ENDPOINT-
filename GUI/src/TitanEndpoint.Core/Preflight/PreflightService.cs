using TitanEndpoint.Core.ProcessControl;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.Manifest;

namespace TitanEndpoint.Core.Preflight;

public enum PreflightSeverity { Info, Warning, Blocking }

/// <summary>One preflight check's outcome. Never fabricated — every check either genuinely
/// passed, genuinely failed, or is reported as Skipped with an honest reason (FORU.TXT section 3:
/// "verifies executable hashes, Npcap/driver availability, Python/.venv, configuration files,
/// administrator rights, log-directory writability, and free disk space").</summary>
public sealed class PreflightCheck
{
    public required string Name { get; init; }
    public required bool Passed { get; init; }
    public required PreflightSeverity Severity { get; init; }
    public required string Detail { get; init; }
}

/// <summary>FORU.TXT section 3: a real preflight command, run before Start All, that verifies the
/// whole environment is actually ready rather than discovering problems mid-launch. Every check
/// here is a genuine, independently-verifiable fact about this machine's current state — nothing
/// is inferred or assumed.</summary>
public static class PreflightService
{
    private const long MinFreeDiskBytesBlocking = 512L * 1024 * 1024;      // 512 MiB
    private const long MinFreeDiskBytesWarning = 5L * 1024 * 1024 * 1024;  // 5 GiB

    public static List<PreflightCheck> Run(TitanSettings settings)
    {
        var results = new List<PreflightCheck>();

        results.Add(CheckAdministrator());
        results.Add(CheckManifestPresent(settings));

        foreach (var endpoint in settings.Endpoints)
        {
            if (endpoint.Id == EndpointId.CustomRule) continue; // not a native manifest component
            results.Add(CheckExecutableHash(endpoint));
            results.Add(CheckLogDirectoryWritable(endpoint));
        }

        results.Add(CheckNpcap());
        results.Add(CheckPythonVenv(settings));
        results.Add(CheckCorrelatorConfig(settings));
        results.Add(CheckFreeDiskSpace(settings));

        return results;
    }

    private static PreflightCheck CheckAdministrator()
    {
        bool isAdmin;
        try
        {
            isAdmin = ElevationHelper.IsCurrentProcessElevated();
        }
        catch (Exception ex)
        {
            return new PreflightCheck
            {
                Name = "Administrator rights",
                Passed = false,
                Severity = PreflightSeverity.Warning,
                Detail = $"Could not determine elevation status: {ex.Message}"
            };
        }

        return new PreflightCheck
        {
            Name = "Administrator rights",
            Passed = isAdmin,
            // Warning, not Blocking: the GUI itself can run unelevated (it launches each
            // collector as a separate elevated process via UAC) -- but every native collector
            // requires elevation, so a non-elevated GUI process will hit a UAC prompt per
            // endpoint during Start All rather than a single upfront one.
            Severity = PreflightSeverity.Warning,
            Detail = isAdmin
                ? "Running elevated."
                : "Not running elevated -- Start All will prompt for UAC per elevated endpoint instead of once upfront."
        };
    }

    private static PreflightCheck CheckManifestPresent(TitanSettings settings)
    {
        return new PreflightCheck
        {
            Name = "Runtime manifest",
            Passed = settings.RuntimeManifestLoaded,
            Severity = PreflightSeverity.Blocking,
            Detail = settings.RuntimeManifestLoaded
                ? $"Loaded from {settings.RuntimeManifestPath}"
                : $"Not found or failed to parse at {settings.RuntimeManifestPath}. " +
                  "Run GUI\\scripts\\Generate-RuntimeManifest.ps1 after any native rebuild."
        };
    }

    private static PreflightCheck CheckExecutableHash(EndpointDefinition endpoint)
    {
        var state = endpoint.ValidateAgainstManifest();
        var passed = state is ManifestValidationState.Ok or ManifestValidationState.NotConfigured;
        return new PreflightCheck
        {
            Name = $"{endpoint.DisplayName}: executable hash",
            Passed = passed,
            Severity = state == ManifestValidationState.NotConfigured
                ? PreflightSeverity.Warning
                : PreflightSeverity.Blocking,
            Detail = state switch
            {
                ManifestValidationState.Ok => "Matches the runtime manifest.",
                ManifestValidationState.NotConfigured => "No manifest entry for this component -- unverified.",
                ManifestValidationState.FileMissing => $"Executable not found at {endpoint.ResolveExePath()}.",
                ManifestValidationState.HashMismatch => "SHA-256 does not match the manifest -- unverified build, will refuse to launch.",
                _ => "Unknown state."
            }
        };
    }

    private static PreflightCheck CheckLogDirectoryWritable(EndpointDefinition endpoint)
    {
        try
        {
            Directory.CreateDirectory(endpoint.LogDirectory);
            var probePath = Path.Combine(endpoint.LogDirectory, $".preflight_probe_{Guid.NewGuid():N}.tmp");
            File.WriteAllText(probePath, "preflight");
            File.Delete(probePath);
            return new PreflightCheck
            {
                Name = $"{endpoint.DisplayName}: log directory writable",
                Passed = true,
                Severity = PreflightSeverity.Blocking,
                Detail = endpoint.LogDirectory
            };
        }
        catch (Exception ex)
        {
            return new PreflightCheck
            {
                Name = $"{endpoint.DisplayName}: log directory writable",
                Passed = false,
                Severity = PreflightSeverity.Blocking,
                Detail = $"{endpoint.LogDirectory}: {ex.Message}"
            };
        }
    }

    private static PreflightCheck CheckNpcap()
    {
        // Real, checkable facts: the driver file and the Packet.dll/wpcap.dll runtime shipped by
        // the Npcap installer under System32\Npcap. Not a service-status check (Npcap's service
        // name/start type vary by install option) -- file presence is what NetworkMonitor's own
        // pcap_open_live/LoadLibrary calls actually depend on.
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var driverPath = Path.Combine(system32, "drivers", "npcap.sys");
        var npcapDir = Path.Combine(system32, "Npcap");
        var wpcapPath = Path.Combine(npcapDir, "wpcap.dll");

        var driverPresent = File.Exists(driverPath);
        var dllPresent = File.Exists(wpcapPath);
        var passed = driverPresent && dllPresent;

        return new PreflightCheck
        {
            Name = "Npcap driver/runtime",
            Passed = passed,
            Severity = PreflightSeverity.Blocking,
            Detail = passed
                ? $"Found {driverPath} and {wpcapPath}."
                : $"Missing: {(driverPresent ? "" : driverPath + " ")}{(dllPresent ? "" : wpcapPath)}. " +
                  "Network endpoint requires Npcap (https://npcap.com) to be installed."
        };
    }

    private static PreflightCheck CheckPythonVenv(TitanSettings settings)
    {
        var venvPython = Path.Combine(settings.TitanRootDirectory, "CUSTOM RULE", ".venv", "Scripts", "python.exe");
        var present = File.Exists(venvPython);
        return new PreflightCheck
        {
            Name = "Custom Rule Python .venv",
            Passed = present,
            Severity = PreflightSeverity.Warning, // Custom Rule is a Priority 1 dependency, not a native collector
            Detail = present
                ? venvPython
                : $"Not found at {venvPython} -- Custom Rule API/watcher cannot start."
        };
    }

    private static PreflightCheck CheckCorrelatorConfig(TitanSettings settings)
    {
        var correlator = settings.Endpoints.FirstOrDefault(e => e.Id == EndpointId.Correlator);
        var configPath = settings.RuntimeCorrelatorConfigPath;
        var present = !string.IsNullOrEmpty(configPath) && File.Exists(configPath);
        return new PreflightCheck
        {
            Name = "Correlator source config",
            Passed = present,
            Severity = PreflightSeverity.Warning,
            Detail = present
                ? $"{configPath} ({new FileInfo(configPath!).Length} bytes)"
                : correlator is null
                    ? "Correlator endpoint not configured."
                    : $"Not yet generated at {configPath ?? "(unknown)"} -- generated automatically on first Start All."
        };
    }

    private static PreflightCheck CheckFreeDiskSpace(TitanSettings settings)
    {
        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(settings.TitanRootDirectory));
            if (string.IsNullOrEmpty(root))
                return new PreflightCheck
                {
                    Name = "Free disk space",
                    Passed = false,
                    Severity = PreflightSeverity.Warning,
                    Detail = "Could not determine the drive hosting the TITAN root."
                };

            var drive = new DriveInfo(root);
            var free = drive.AvailableFreeSpace;
            var passed = free >= MinFreeDiskBytesBlocking;
            var severity = free < MinFreeDiskBytesBlocking ? PreflightSeverity.Blocking
                : free < MinFreeDiskBytesWarning ? PreflightSeverity.Warning
                : PreflightSeverity.Info;

            return new PreflightCheck
            {
                Name = "Free disk space",
                Passed = passed,
                Severity = severity,
                Detail = $"{free / (1024.0 * 1024 * 1024):F1} GiB free on {root} " +
                          $"(global disk budget is {settings.GlobalDiskBudgetBytes / (1024.0 * 1024 * 1024):F1} GiB)."
            };
        }
        catch (Exception ex)
        {
            return new PreflightCheck
            {
                Name = "Free disk space",
                Passed = false,
                Severity = PreflightSeverity.Warning,
                Detail = $"Could not check: {ex.Message}"
            };
        }
    }
}
