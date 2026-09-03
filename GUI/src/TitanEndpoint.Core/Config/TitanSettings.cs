using System.Text.Json;
using System.Text.Json.Serialization;
using TitanEndpoint.Core.Manifest;

namespace TitanEndpoint.Core.Config;

/// <summary>
/// Root of the persisted, user-editable configuration. Seeded with the paths
/// discovered on this machine (matching CORRELATOR\correlator_config.txt and
/// TITAN_MASTER_CONTEXT.md's build table) but every path can be changed from
/// the Settings page — nothing here is meant to stay hard-coded truth.
/// </summary>
public sealed class TitanSettings
{
    private const string RootDirEnvPlaceholder = "%TITAN_ROOT%";

    public string TitanRootDirectory { get; set; } = string.Empty;

    public List<EndpointDefinition> Endpoints { get; set; } = new();

    /// <summary>Matches CUSTOM RULE\desktop.py's HOST/PORT constants (8765), not FastAPI's
    /// common 8000 default — desktop.py embeds uvicorn on 8765 specifically to avoid clashing
    /// with other local dev servers.</summary>
    public string CustomRuleApiBaseUrl { get; set; } = "http://127.0.0.1:8765";
    public string CustomRuleDataDirectory { get; set; } = string.Empty;

    /// <summary>Hard coordinated budget distributed across the six native evidence producers.</summary>
    public long GlobalDiskBudgetBytes { get; set; } = 5L * 1024 * 1024 * 1024;
    public long MinimumFreeSpaceReserveBytes { get; set; } = 1L * 1024 * 1024 * 1024;

    public bool ReducedMotion { get; set; }

    /// <summary>Santosh, 2026-08-31: "add lightmode and darkmode option." False (dark) is the
    /// existing, unchanged default. Read once at startup (App.xaml.cs picks Palette.xaml vs
    /// PaletteLight.xaml before the first window is constructed) rather than live-swapped like
    /// ReducedMotion: nearly every color in this app is bound via StaticResource, not
    /// DynamicResource, so a live swap would only repaint newly-created elements and leave
    /// already-rendered ones on the old palette -- a restart is required for this one, by design,
    /// to guarantee the whole app is consistently on one palette rather than partially both.</summary>
    public bool UseLightTheme { get; set; }

    public int SettingsSchemaVersion { get; set; } = 2;

    /// <summary>Absolute path to runtime-manifest.json, computed at load time (not persisted).
    /// Null exePath resolution/mismatch is checked per-endpoint via EndpointDefinition.ValidateAgainstManifest —
    /// this is exposed only so the GUI can show "no manifest found at all" distinctly.</summary>
    [JsonIgnore] public string? RuntimeManifestPath { get; private set; }
    [JsonIgnore] public bool RuntimeManifestLoaded { get; private set; }
    [JsonIgnore] public string? RuntimeCorrelatorConfigPath { get; set; }

    public EndpointDefinition GetEndpoint(EndpointId id) =>
        Endpoints.First(e => e.Id == id);

    /// <summary>GUI\tests\TitanEndpoint.App.UiTests sets this so automated tests never read or
    /// overwrite the real operator's %LocalAppData%\TitanEndpoint\settings.json (FORU.TXT 0.8:
    /// "must never reuse or mutate production ... settings"). Unset in every normal launch.</summary>
    private const string TestSettingsPathEnvVar = "TITAN_ENDPOINT_TEST_SETTINGS_PATH";

    private static string SettingsPath =>
        Environment.GetEnvironmentVariable(TestSettingsPathEnvVar) is { Length: > 0 } testPath
            ? testPath
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "TitanEndpoint", "settings.json");

    public static TitanSettings LoadOrCreateDefault(string? knownTitanRoot = null)
    {
        var titanRoot = knownTitanRoot ?? GuessTitanRoot();

        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                var loaded = JsonSerializer.Deserialize<TitanSettings>(json, SerializerOptions);
                if (loaded is not null && loaded.Endpoints.Count > 0)
                {
                    ApplyRuntimeManifest(loaded, titanRoot);
                    return loaded;
                }
            }
        }
        catch
        {
            // Corrupt or unreadable settings file — fall through to a fresh default.
        }

        var fresh = CreateDefault(titanRoot);
        ApplyRuntimeManifest(fresh, titanRoot);
        return fresh;
    }

    /// <summary>
    /// Overlays runtime-manifest.json's authoritative {exePath, sha256, version} onto each
    /// matching EndpointDefinition (FORU.TXT section 1: "Make the GUI load this manifest and
    /// reject missing, mismatched or stale builds" — the actual rejection happens in
    /// EndpointProcessController.Start via EndpointDefinition.ValidateAgainstManifest; this just
    /// makes the manifest's path authoritative over ExeCandidatePaths's old "first path that
    /// happens to exist" behavior). Runs on every load — a manifest edited/regenerated between
    /// GUI launches takes effect without needing to touch settings.json.
    /// </summary>
    private static void ApplyRuntimeManifest(TitanSettings settings, string titanRoot)
    {
        var manifestPath = Path.Combine(titanRoot, "runtime-manifest.json");
        settings.RuntimeManifestPath = manifestPath;

        var manifest = RuntimeManifest.TryLoad(manifestPath);
        settings.RuntimeManifestLoaded = manifest is not null;
        if (manifest is null) return;

        foreach (var endpoint in settings.Endpoints)
        {
            var entry = manifest.Find(endpoint.Id.ToString());
            if (entry is null) continue;

            endpoint.ManifestExePath = ResolveManifestPath(entry.ExePath, titanRoot);
            endpoint.ManifestSha256 = entry.Sha256;
            endpoint.ManifestVersion = entry.Version;
            endpoint.ManifestCommandArguments = entry.CommandArguments;
            endpoint.ManifestWorkingDirectory = ResolveManifestPath(entry.WorkingDirectory, titanRoot);
            endpoint.ManifestControlChannelImplemented = entry.ControlChannelImplemented;
            endpoint.ManifestControlChannelName = entry.ControlChannelName;
            if (entry.HealthTimeoutSeconds > 0) endpoint.ManifestHealthTimeoutSeconds = entry.HealthTimeoutSeconds;
            var logDir = ResolveManifestPath(entry.LogDirectory, titanRoot);
            if (!string.IsNullOrEmpty(logDir)) endpoint.LogDirectory = logDir;
        }
    }

    /// <summary>FORU.TXT section 3: "Use package-relative paths where possible; validate the
    /// package after copying it to a different path." runtime-manifest.json (schema 2+) records
    /// exePath/workingDirectory/logDirectory relative to the TITAN root so the whole package can
    /// be relocated and still resolve correctly. A rooted (absolute, e.g. "C:\...") value is used
    /// as-is for backward compatibility with schema-1 manifests and Port's fixed
    /// C:\ProgramData\TitanUSB\logs (which is genuinely machine-global, not package-relative).</summary>
    private static string? ResolveManifestPath(string? value, string titanRoot)
    {
        if (string.IsNullOrEmpty(value)) return value;
        return Path.IsPathRooted(value) ? value : Path.GetFullPath(Path.Combine(titanRoot, value));
    }

    public void Save()
    {
        var dir = Path.GetDirectoryName(SettingsPath)!;
        Directory.CreateDirectory(dir);
        var json = JsonSerializer.Serialize(this, SerializerOptions);
        var temporary = SettingsPath + ".tmp";
        var backup = SettingsPath + ".bak";
        using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write,
                   FileShare.None, 16 * 1024, FileOptions.WriteThrough))
        using (var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false)))
        {
            writer.Write(json);
            writer.Flush();
            stream.Flush(flushToDisk: true);
        }

        if (File.Exists(SettingsPath))
            File.Replace(temporary, SettingsPath, backup, ignoreMetadataErrors: true);
        else
            File.Move(temporary, SettingsPath);
    }

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private static string GuessTitanRoot()
    {
        // The GUI project lives at <root>\GUI\src\TitanEndpoint.App\bin\... at runtime,
        // or <root>\GUI\src\TitanEndpoint.App during development. Walk up looking for
        // the marker file that only exists at the TITAN root.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "TITAN_MASTER_CONTEXT.md")))
                return dir.FullName;
            dir = dir.Parent;
        }
        return @"C:\Users\msant\OneDrive\Desktop\TITAN ENDPOINT";
    }

    public static TitanSettings CreateDefault(string titanRoot)
    {
        string R(string relative) => Path.Combine(titanRoot, relative);

        var settings = new TitanSettings
        {
            TitanRootDirectory = titanRoot,
            CustomRuleDataDirectory = R(@"CUSTOM RULE\data")
        };

        settings.Endpoints.Add(new EndpointDefinition
        {
            Id = EndpointId.Process,
            DisplayName = "Process",
            ShortDescription = "Process and thread lifecycle activity",
            ExeBaseName = "titan_process",
            ExeCandidatePaths = new()
            {
                R(@"PROCESS ENDPOINT\out\build\x64-Debug\bin\titan_process.exe"),
                R(@"PROCESS ENDPOINT\out\build\x64-Release\bin\titan_process.exe"),
            },
            LogDirectory = R(@"PROCESS ENDPOINT\out\build\x64-Debug\bin\logs"),
            LogFilePattern = "titan_*.jsonl",
            RequiresElevation = true,
            IconGlyph = "\u25A3"
        });

        settings.Endpoints.Add(new EndpointDefinition
        {
            Id = EndpointId.Network,
            DisplayName = "Network",
            ShortDescription = "Live packet and flow capture",
            ExeBaseName = "titan",
            ExeCandidatePaths = new()
            {
                R(@"NETOWRK ENDPOINT\out\build\x64-Release-2026\titan.exe"),
                R(@"NETOWRK ENDPOINT\out\build\x64-round3\titan.exe"),
                R(@"NETOWRK ENDPOINT\out\regression-20260730\titan.exe"),
            },
            LogDirectory = R(@"NETOWRK ENDPOINT\out\build\x64-Release-2026\logs"),
            LogFilePattern = "titan_*.jsonl",
            RequiresElevation = true,
            IconGlyph = "\u25C8"
        });

        settings.Endpoints.Add(new EndpointDefinition
        {
            Id = EndpointId.Application,
            DisplayName = "Applications",
            ShortDescription = "Installed and running application activity",
            ExeBaseName = "application_endpoint",
            ExeCandidatePaths = new()
            {
                R(@"APP\out\final-audit-2026\bin\application_endpoint.exe"),
                R(@"APP\out\regression-20260730\bin\application_endpoint.exe"),
            },
            LogDirectory = R(@"APP\out\final-audit-2026\bin\logs"),
            LogFilePattern = "application_events*.jsonl",
            RequiresElevation = true,
            IconGlyph = "\u25A2"
        });

        settings.Endpoints.Add(new EndpointDefinition
        {
            Id = EndpointId.File,
            DisplayName = "Files",
            ShortDescription = "Temporary activity and file integrity",
            ExeBaseName = "file_test",
            ExeCandidatePaths = new()
            {
                R(@"FILEEE\out\final-audit\bin\Release\file_test.exe"),
                R(@"FILEEE\out\regression-20260730\bin\Release\file_test.exe"),
            },
            LogDirectory = R(@"FILEEE\out\final-audit\bin\Release\logs"),
            LogFilePattern = "fim_events*.json",
            RequiresElevation = true,
            IconGlyph = "\u25A4"
        });

        settings.Endpoints.Add(new EndpointDefinition
        {
            Id = EndpointId.Port,
            DisplayName = "Port / USB",
            ShortDescription = "USB and physical port connections",
            ExeBaseName = "usb_test",
            ExeCandidatePaths = new()
            {
                R(@"PORT ENDPOINT\out\build\x64-Debug\bin\usb_test.exe"),
                R(@"PORT ENDPOINT\out\build\x64-Release\bin\usb_test.exe"),
            },
            LogDirectory = @"C:\ProgramData\TitanUSB\logs",
            LogFilePattern = "*.json*",
            RequiresElevation = true,
            IconGlyph = "\u25A0"
        });

        settings.Endpoints.Add(new EndpointDefinition
        {
            Id = EndpointId.Correlator,
            DisplayName = "Correlator",
            ShortDescription = "Cross-endpoint evidence correlation",
            ExeBaseName = "correlator",
            ExeCandidatePaths = new()
            {
                R(@"CORRELATOR\out\build\x64-Debug\bin\correlator.exe"),
                R(@"CORRELATOR\out\build\x64-Release\bin\correlator.exe"),
            },
            LogDirectory = R(@"CORRELATOR\out\build\x64-Debug\bin\logs"),
            LogFilePattern = "correlator_*.jsonl",
            RequiresElevation = false,
            IconGlyph = "\u25C9"
        });

        settings.Endpoints.Add(new EndpointDefinition
        {
            Id = EndpointId.CustomRule,
            DisplayName = "Custom Rule",
            ShortDescription = "Rule authoring, watcher and response",
            ExeBaseName = null,
            ExeCandidatePaths = new(),
            LogDirectory = R(@"CUSTOM RULE\data"),
            LogFilePattern = "alerts*.jsonl",
            RequiresElevation = false,
            IconGlyph = "\u25C6"
        });

        return settings;
    }
}
