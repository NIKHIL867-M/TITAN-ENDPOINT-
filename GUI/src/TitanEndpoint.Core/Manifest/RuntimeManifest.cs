using System.Text.Json;
using System.Text.Json.Serialization;

namespace TitanEndpoint.Core.Manifest;

/// <summary>
/// One authoritative, versioned build record for a native component (FORU.TXT section 1: "one
/// versioned runtime manifest containing, for every component: component ID, executable path,
/// version, SHA-256, required privilege, command arguments, working directory, log directory,
/// control-channel name and health timeout"). Id matches TitanEndpoint.Core.Config.EndpointId's
/// string form.
/// </summary>
public sealed class RuntimeManifestEntry
{
    public required string Id { get; init; }
    public string DisplayName { get; init; } = "";
    public required string ExePath { get; init; }
    public required string Sha256 { get; init; }
    public string Version { get; init; } = "unknown";
    public bool RequiresElevation { get; init; } = true;
    public string CommandArguments { get; init; } = "";
    public string? WorkingDirectory { get; init; }
    public string? LogDirectory { get; init; }

    /// <summary>Reserved for the authenticated named-pipe control channel (FORU.TXT section 4) —
    /// null and ControlChannelImplemented=false until that exists. Present in the schema now so
    /// the manifest doesn't need a breaking format change once it's built.</summary>
    public string? ControlChannelName { get; init; }
    public bool ControlChannelImplemented { get; init; }

    public int HealthTimeoutSeconds { get; init; } = 45;
}

public enum ManifestValidationState
{
    /// <summary>No manifest entry exists for this component at all — not a failure by itself,
    /// but means path resolution falls back to the old candidate-list behavior and no
    /// build-integrity guarantee applies.</summary>
    NotConfigured,
    Ok,
    FileMissing,
    HashMismatch
}

public sealed class RuntimeManifest
{
    public int SchemaVersion { get; init; } = 1;
    public string GeneratedAtUtc { get; init; } = "";
    public List<RuntimeManifestEntry> Components { get; init; } = new();

    public RuntimeManifestEntry? Find(string id) =>
        Components.FirstOrDefault(c => string.Equals(c.Id, id, StringComparison.OrdinalIgnoreCase));

    private static readonly JsonSerializerOptions ReadOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>Returns null (never throws) if the file doesn't exist or fails to parse — callers
    /// must treat "no manifest" as an explicit, visible degraded state (FORU.TXT: "reject
    /// missing... builds"), not silently proceed as if everything were fine.</summary>
    public static RuntimeManifest? TryLoad(string path)
    {
        if (!File.Exists(path)) return null;
        try
        {
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<RuntimeManifest>(json, ReadOptions);
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            return null;
        }
    }

    public static string ComputeSha256(string exePath)
    {
        using var stream = File.OpenRead(exePath);
        using var sha = System.Security.Cryptography.SHA256.Create();
        var hash = sha.ComputeHash(stream);
        return Convert.ToHexString(hash);
    }
}
