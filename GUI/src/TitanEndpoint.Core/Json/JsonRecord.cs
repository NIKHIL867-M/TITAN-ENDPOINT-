using System.Text.Json;

namespace TitanEndpoint.Core.Json;

/// <summary>
/// One parsed JSONL evidence line from any of the six collectors. Deliberately
/// generic (raw JsonElement + typed accessors) rather than one C# class per
/// schema — the six producers hand-roll their own flat JSON independently
/// (see TITAN_MASTER_CONTEXT.md, "no shared library between the 6 programs")
/// and field sets differ per event type even within one collector.
/// </summary>
public sealed class JsonRecord
{
    public required string RawLine { get; init; }
    public required JsonElement Root { get; init; }
    public required DateTimeOffset ObservedAtUtc { get; init; }
    public DateTimeOffset EventTimeUtc { get; init; }

    /// <summary>Monotonically increasing per-tailer order, assigned by LogTailer. Lets the UI append
    /// only genuinely new rows each tick without rescanning the whole ring buffer.</summary>
    public long SequenceId { get; init; }

    /// <summary>True when this record was read as part of a tailer's initial seed-from-tail read
    /// (pre-existing content the file already had before this GUI session attached to it), false
    /// for a genuinely new line observed while actively tailing. Callers that report "current
    /// session" counts must exclude seed records — see FORU.TXT section 7: "Do not call historical
    /// seed records events from the current session."</summary>
    public bool IsSeedHistory { get; init; }

    public string? GetString(string key) =>
        Root.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    public long? GetLong(string key)
    {
        if (!Root.TryGetProperty(key, out var v)) return null;
        if (v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var l)) return l;
        if (v.ValueKind == JsonValueKind.String && long.TryParse(v.GetString(), out var ls)) return ls;
        return null;
    }

    public double? GetDouble(string key)
    {
        if (!Root.TryGetProperty(key, out var v)) return null;
        if (v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d)) return d;
        return null;
    }

    public bool? GetBool(string key) =>
        Root.TryGetProperty(key, out var v) &&
        (v.ValueKind == JsonValueKind.True || v.ValueKind == JsonValueKind.False)
            ? v.GetBoolean()
            : null;

    public bool Has(string key) => Root.TryGetProperty(key, out _);

    /// <summary>Reads root.parentKey.childKey for the nested sub-objects some collectors emit (e.g. Port's "device": {...}).</summary>
    public string? GetNestedString(string parentKey, string childKey)
    {
        if (!Root.TryGetProperty(parentKey, out var parent) || parent.ValueKind != JsonValueKind.Object) return null;
        return parent.TryGetProperty(childKey, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }

    public long? GetNestedLong(string parentKey, string childKey)
    {
        if (!Root.TryGetProperty(parentKey, out var parent) || parent.ValueKind != JsonValueKind.Object) return null;
        if (!parent.TryGetProperty(childKey, out var v) || v.ValueKind != JsonValueKind.Number) return null;
        return v.TryGetInt64(out var l) ? l : null;
    }

    public bool Is(string key, string value) =>
        string.Equals(GetString(key), value, StringComparison.Ordinal);

    /// <summary>True for the universal periodic/final health record every collector emits.</summary>
    public bool IsCollectorHealth => Is("type", "collector_health") || Is("record_type", "collector_health");

    public static JsonRecord? TryParse(string line, DateTimeOffset observedAtUtc, long sequenceId = 0, bool isSeedHistory = false)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement.Clone();
            return new JsonRecord
            {
                RawLine = line,
                Root = root,
                ObservedAtUtc = observedAtUtc,
                EventTimeUtc = ResolveEventTime(root, observedAtUtc),
                SequenceId = sequenceId,
                IsSeedHistory = isSeedHistory
            };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static DateTimeOffset ResolveEventTime(JsonElement root, DateTimeOffset fallback)
    {
        if (root.TryGetProperty("t_unix_ms", out var tms) && tms.ValueKind == JsonValueKind.Number &&
            tms.TryGetInt64(out var ms) && ms > 0)
        {
            return DateTimeOffset.FromUnixTimeMilliseconds(ms);
        }

        foreach (var key in TimestampKeys)
        {
            if (root.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String &&
                DateTimeOffset.TryParse(v.GetString(), null,
                    System.Globalization.DateTimeStyles.AssumeUniversal, out var parsed))
            {
                return parsed;
            }
        }

        return fallback;
    }

    private static readonly string[] TimestampKeys = { "timestamp", "ts", "heartbeat_at", "fired_at", "created_at" };
}
