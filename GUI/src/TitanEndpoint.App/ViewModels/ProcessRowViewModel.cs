using System.Text.Json;
using TitanEndpoint.Core.Json;

namespace TitanEndpoint.App.ViewModels;

public sealed class ProcessRowViewModel : IActionableRow
{
    public string Time { get; init; } = "";
    public string Action { get; init; } = "";
    public string ProcessName { get; init; } = "";
    public long Pid { get; init; }
    public long ParentPid { get; init; }
    public string User { get; init; } = "";
    public string Integrity { get; init; } = "";
    public string Elevation { get; init; } = "";
    public string Signer { get; init; } = "";
    public string Path { get; init; } = "";
    public string CommandLine { get; init; } = "";
    public string DisplayName => string.IsNullOrEmpty(ProcessName) ? $"pid {Pid}" : ProcessName;
    /// <summary>Santosh, Round 22: "what do you mean by unsigned and unverified -- at least show
    /// its location" -- the status alone isn't actionable without knowing which file it is.</summary>
    public string SignerDisplayText => Signer.StartsWith("Unsigned", StringComparison.Ordinal) && !string.IsNullOrEmpty(Path)
        ? $"{Signer} — {Path}" : Signer;

    /// <summary>FORU.TXT section 7.5: "Use stable evidence IDs instead of relying only on PID,
    /// because PIDs can be reused." Built from the tailer's own monotonic per-session
    /// SequenceId (unique within this GUI session/tailer, not a globally durable ID across
    /// restarts — that would need a native-side evidence ID, not attempted here) so cross-row
    /// lookups (parent/child, evidence linking) never collide on a recycled PID.</summary>
    public long EvidenceId { get; init; }
    public long TUnixMs { get; init; }
    public string RawJson { get; init; } = "";
    public string NativeRecordId { get; init; } = "";
    public string NativeSessionId { get; init; } = "";
    public string NativeSourceFile { get; init; } = "";
    public long NativeByteOffset { get; init; }
    public string NativeContentHash { get; init; } = "";

    /// <summary>From process_snapshot events only: the native collector's own count/names of this
    /// process's children at snapshot time. Used as a fallback in the Parent/Children detail panel
    /// when the counterpart row itself isn't retained in this GUI session's bounded window, so the
    /// panel still shows real data instead of appearing broken.</summary>
    public int ChildCount { get; init; }
    public IReadOnlyList<string> UniqueChildNames { get; init; } = Array.Empty<string>();

    public static ProcessRowViewModel From(JsonRecord r) => new()
    {
        Time = r.EventTimeUtc.ToLocalTime().ToString("HH:mm:ss.fff"),
        Action = r.GetString("event_subtype") ?? r.GetString("event_type") ?? "unknown",
        ProcessName = r.GetString("process_name") ?? "",
        Pid = r.GetLong("pid") ?? 0,
        ParentPid = r.GetLong("parent_pid") ?? 0,
        User = r.GetString("user_name") ?? "",
        Integrity = r.GetString("integrity") ?? "",
        Elevation = r.GetString("elevation") ?? "",
        Signer = (r.GetBool("signature_valid") ?? false) ? (r.GetString("signature_signer") ?? "Valid") : "Unsigned / unverified",
        Path = r.GetString("image_path_raw") ?? r.GetString("canonical_path") ?? "",
        CommandLine = r.GetString("cmdline_normalized") ?? r.GetString("command_line_raw") ?? "",
        EvidenceId = r.SequenceId,
        TUnixMs = r.GetLong("t_unix_ms") ?? r.EventTimeUtc.ToUnixTimeMilliseconds(),
        RawJson = SafePrettyJson(r),
        NativeRecordId = r.GetString("native_record_id") ?? "",
        NativeSessionId = r.GetString("native_session_id") ?? "",
        NativeSourceFile = r.GetString("native_source_file") ?? "",
        NativeByteOffset = r.GetLong("native_byte_offset") ?? 0,
        NativeContentHash = r.GetString("native_content_hash") ?? "",
        ChildCount = (int)(r.GetLong("child_count") ?? 0),
        UniqueChildNames = ReadStringArray(r, "unique_child_names")
    };

    private static IReadOnlyList<string> ReadStringArray(JsonRecord r, string key)
    {
        if (!r.Root.TryGetProperty(key, out var array) || array.ValueKind != JsonValueKind.Array) return Array.Empty<string>();
        var result = new List<string>();
        foreach (var value in array.EnumerateArray())
            if (value.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(value.GetString()))
                result.Add(value.GetString()!);
        return result;
    }

    private static string SafePrettyJson(JsonRecord r)
    {
        try { return JsonSerializer.Serialize(r.Root, new JsonSerializerOptions { WriteIndented = true }); }
        catch { return r.RawLine; }
    }
}
