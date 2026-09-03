using System.Text.Json.Serialization;
using TitanEndpoint.Core.Manifest;

namespace TitanEndpoint.Core.Config;

/// <summary>
/// Describes one of the six native collectors (or the Custom Rule Python
/// component) well enough for the GUI to find its executable, find its log
/// directory, launch/stop it, and tail its evidence. Exe resolution is
/// authoritative from the runtime manifest when one is configured (FORU.TXT
/// section 1) — ExeCandidatePaths is the fallback used only when no manifest
/// entry exists for this component, not a "try each until one exists" list to
/// paper over ambiguity between old build directories.
/// </summary>
public sealed class EndpointDefinition
{
    public required EndpointId Id { get; init; }
    public required string DisplayName { get; init; }
    public required string ShortDescription { get; init; }

    /// <summary>Process name without extension, e.g. "titan_process". Null for CustomRule (Python).</summary>
    public string? ExeBaseName { get; set; }

    /// <summary>Fallback path(s), used only when no runtime-manifest entry exists for this
    /// component. When a manifest entry is present, ManifestExePath is the sole authoritative
    /// path — see ResolveExePath.</summary>
    public List<string> ExeCandidatePaths { get; set; } = new();

    /// <summary>Directory this collector writes its JSONL evidence into.</summary>
    public string LogDirectory { get; set; } = string.Empty;

    /// <summary>Search pattern for evidence files inside LogDirectory, e.g. "titan_*.jsonl" or "*.json".</summary>
    public string LogFilePattern { get; set; } = "*.jsonl";

    public bool RequiresElevation { get; set; } = true;

    /// <summary>Single-glyph label used in the nav rail / cards (no image assets in this build).</summary>
    public string IconGlyph { get; set; } = "■";

    // ── Runtime manifest overlay (FORU.TXT section 1) — set by TitanSettings after loading
    // runtime-manifest.json, left null when no manifest entry exists for this component.
    // [JsonIgnore]: recomputed fresh from runtime-manifest.json on every load, never persisted
    // into settings.json — the manifest file is the single source of truth for these. ──
    [JsonIgnore] public string? ManifestExePath { get; set; }
    [JsonIgnore] public string? ManifestSha256 { get; set; }
    [JsonIgnore] public string? ManifestVersion { get; set; }
    [JsonIgnore] public string? ManifestCommandArguments { get; set; }
    [JsonIgnore] public string? ManifestWorkingDirectory { get; set; }
    [JsonIgnore] public bool ManifestControlChannelImplemented { get; set; }
    [JsonIgnore] public string? ManifestControlChannelName { get; set; }
    [JsonIgnore] public int ManifestHealthTimeoutSeconds { get; set; } = 45;

    /// <summary>Generated at application start when a component needs a runtime-specific
    /// configuration file. This takes precedence over the static manifest arguments without
    /// weakening manifest executable/hash validation.</summary>
    [JsonIgnore] public string? RuntimeCommandArguments { get; set; }

    public string ResolveExePath()
    {
        if (!string.IsNullOrEmpty(ManifestExePath)) return ManifestExePath;

        foreach (var candidate in ExeCandidatePaths)
        {
            if (System.IO.File.Exists(candidate))
                return candidate;
        }
        return ExeCandidatePaths.FirstOrDefault() ?? string.Empty;
    }

    public string ResolveCommandArguments() =>
        RuntimeCommandArguments ?? ManifestCommandArguments ?? string.Empty;

    public string ResolveWorkingDirectory()
    {
        if (!string.IsNullOrWhiteSpace(ManifestWorkingDirectory))
            return ManifestWorkingDirectory;
        var exe = ResolveExePath();
        return Path.GetDirectoryName(exe) ?? string.Empty;
    }

    /// <summary>Checked by EndpointProcessController.Start() before ever launching this
    /// component — a HashMismatch or FileMissing result blocks the start (FORU.TXT: "reject
    /// missing, mismatched or stale builds"). NotConfigured is not itself a failure (no manifest
    /// entry exists), but callers should surface it as a visibly degraded/unverified state rather
    /// than silent success.</summary>
    public ManifestValidationState ValidateAgainstManifest()
    {
        if (string.IsNullOrEmpty(ManifestSha256)) return ManifestValidationState.NotConfigured;

        var exePath = ResolveExePath();
        if (string.IsNullOrEmpty(exePath) || !System.IO.File.Exists(exePath))
            return ManifestValidationState.FileMissing;

        try
        {
            var actual = RuntimeManifest.ComputeSha256(exePath);
            return string.Equals(actual, ManifestSha256, StringComparison.OrdinalIgnoreCase)
                ? ManifestValidationState.Ok
                : ManifestValidationState.HashMismatch;
        }
        catch (IOException)
        {
            return ManifestValidationState.FileMissing;
        }
    }
}
