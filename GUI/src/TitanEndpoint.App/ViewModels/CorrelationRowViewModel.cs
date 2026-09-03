using System.Collections.ObjectModel;
using System.Text.Json;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Json;

namespace TitanEndpoint.App.ViewModels;

/// <summary>One emitted unified activity story. Every accepted endpoint record is represented:
/// multi-source matches share a row, while unmatched evidence is an explicit single-source row.
/// Legacy session_timeline records remain readable so retained evidence does not disappear.</summary>
public sealed class CorrelationRowViewModel : ViewModelBase
{
    public long GroupId { get; }
    public CorrelationRowViewModel(long groupId) => GroupId = groupId;

    private string _time = "";
    public string Time { get => _time; private set => SetField(ref _time, value); }
    private int _revision;
    public int Revision { get => _revision; private set => SetField(ref _revision, value); }
    private bool _isFinal;
    public bool IsFinal { get => _isFinal; private set => SetField(ref _isFinal, value); }
    private int _memberCount;
    public int MemberCount { get => _memberCount; private set => SetField(ref _memberCount, value); }
    private long _recordCount;
    public long RecordCount { get => _recordCount; private set => SetField(ref _recordCount, value); }
    private long _repeatCount;
    public long RepeatCount { get => _repeatCount; private set => SetField(ref _repeatCount, value); }
    private string _endpoints = "";
    public string Endpoints { get => _endpoints; private set => SetField(ref _endpoints, value); }
    private string _timeSpanText = "";
    public string TimeSpanText { get => _timeSpanText; private set => SetField(ref _timeSpanText, value); }
    private string _missingEndpointsText = "";
    // Kept as a property name for binding compatibility; the value now reports
    // this row's actual connection, never a misleading "missing x of 5" claim.
    public string MissingEndpointsText { get => _missingEndpointsText; private set => SetField(ref _missingEndpointsText, value); }
    private string _rawJson = "";
    public string RawJson { get => _rawJson; private set => SetField(ref _rawJson, value); }
    private string _confidenceSummaryText = "";
    public string ConfidenceSummaryText { get => _confidenceSummaryText; private set => SetField(ref _confidenceSummaryText, value); }
    private string _primarySubjectText = "";
    /// <summary>Human-readable "what actually happened" for this row's anchor record (process/device
    /// name plus path, command, IP or file location), so the main grid shows real evidence at a
    /// glance instead of only IDs, counts and hashes.</summary>
    public string PrimarySubjectText { get => _primarySubjectText; private set => SetField(ref _primarySubjectText, value); }

    public ObservableCollection<CorrelationMemberViewModel> Members { get; } = new();
    public ObservableCollection<CorrelationConnectionViewModel> Connections { get; } = new();

    public static CorrelationRowViewModel? From(JsonRecord record, CorrelationRowViewModel? existing)
    {
        var unified = record.Is("type", "unified_event");
        var legacy = record.Is("type", "session_timeline");
        if (!unified && !legacy) return null;
        var memberKey = unified ? "events" : "members";
        if (!record.Root.TryGetProperty(memberKey, out var membersElement) ||
            membersElement.ValueKind != JsonValueKind.Array) return null;

        var groupId = record.GetLong("group_id") ?? 0;
        var row = existing ?? new CorrelationRowViewModel(groupId);
        var parsed = new List<ParsedMember>();
        foreach (var member in membersElement.EnumerateArray()) parsed.Add(ParseMember(member));
        if (legacy) parsed = parsed.OrderBy(x => x.TimeMs).ToList();

        var connections = ParseConnections(record, parsed, legacy);
        var incoming = connections.GroupBy(c => c.ToIndex).ToDictionary(g => g.Key, g => g.First());
        var minMs = parsed.Count == 0 ? 0 : parsed.Min(x => x.TimeMs);
        var maxMs = parsed.Count == 0 ? 0 : parsed.Max(x => x.LastSeenMs > 0 ? x.LastSeenMs : x.TimeMs);
        var present = parsed.Select(x => DisplayEndpoint(x.Endpoint)).Distinct().ToList();

        row.Time = record.EventTimeUtc.ToLocalTime().ToString("HH:mm:ss.fff");
        row.Revision = (int)(record.GetLong("revision") ?? 0);
        row.IsFinal = unified || record.GetBool("final") == true;
        row.MemberCount = parsed.Count;
        row.RecordCount = record.GetLong("event_count") ?? parsed.Sum(x => Math.Max(1, x.RepeatCount));
        row.RepeatCount = record.GetLong("repeat_count") ?? parsed.Sum(x => Math.Max(0, x.RepeatCount - 1));
        row.Endpoints = string.Join(" -> ", present);
        row.TimeSpanText = parsed.Count > 0 ? $"{Math.Max(0, maxMs - minMs)} ms span" : "Unavailable";
        row.MissingEndpointsText = present.Count > 1
            ? $"Connected {present.Count} sources in this record: {string.Join(", ", present)}."
            : present.Count == 1
                ? $"Single-source event from {present[0]}; retained because unmatched evidence is never hidden."
                : "No source member was readable.";
        row.RawJson = SafeSerialize(record);
        var anchor = parsed.FirstOrDefault(x => x.TimeMs == minMs) ?? parsed.FirstOrDefault();
        row.PrimarySubjectText = anchor is null || (anchor.Subject == "" && anchor.DetailText == "")
            ? "(no detail available)"
            : anchor.DetailText == "" ? anchor.Subject
            : anchor.Subject == "" ? anchor.DetailText
            : $"{anchor.Subject} — {anchor.DetailText}";

        row.Members.Clear();
        for (var i = 0; i < parsed.Count; i++)
        {
            var item = parsed[i];
            incoming.TryGetValue(i, out var edge);
            row.Members.Add(new CorrelationMemberViewModel
            {
                Endpoint = item.Endpoint,
                RecordType = item.RecordType,
                TUnixMs = item.TimeMs,
                DeltaMsFromFirst = item.TimeMs - minMs,
                Pid = item.Pid,
                ParentPid = item.ParentPid,
                RepeatCount = item.RepeatCount,
                SourceEvidenceId = item.SourceEvidenceId,
                RawSource = item.RawSource,
                JoinReason = edge?.Reason ?? item.JoinReason,
                MatchedFields = edge?.MatchedFields ?? item.MatchedFields,
                EdgeDeltaMs = edge?.DeltaMs ?? item.DeltaMs,
                WindowMs = edge?.WindowMs ?? item.WindowMs,
                Confidence = edge?.Confidence ?? item.Confidence,
                Caveat = edge?.Caveat ?? item.Caveat,
                ConfidenceScore = edge?.ConfidenceScore ?? item.ConfidenceScore,
                NativeRecordId = item.NativeRecordId,
                NativeSessionId = item.NativeSessionId,
                NativeSourceFile = item.NativeSourceFile,
                NativeByteOffset = item.NativeByteOffset,
                NativeContentHash = item.NativeContentHash,
                Subject = item.Subject,
                DetailText = item.DetailText
            });
        }

        row.Connections.Clear();
        foreach (var connection in connections) row.Connections.Add(connection);
        if (connections.Count == 0)
            row.ConfidenceSummaryText = $"No cross-source join. {row.RecordCount:N0} record(s) represented; {row.RepeatCount:N0} repeat(s) compacted.";
        else
        {
            var high = connections.Count(c => c.Confidence == "high");
            var medium = connections.Count(c => c.Confidence == "medium");
            var low = connections.Count(c => c.Confidence == "low");
            row.ConfidenceSummaryText = $"{connections.Count} evidence connection(s): {high} high, {medium} medium, {low} low confidence; {row.RepeatCount:N0} repeat(s) compacted.";
        }
        return row;
    }

    private static ParsedMember ParseMember(JsonElement member)
    {
        string Str(string key) => member.TryGetProperty(key, out var e) && e.ValueKind == JsonValueKind.String ? e.GetString() ?? "" : "";
        long Num(string key, long fallback = 0) => member.TryGetProperty(key, out var e) && e.ValueKind == JsonValueKind.Number && e.TryGetInt64(out var v) ? v : fallback;
        double Real(string key) => member.TryGetProperty(key, out var e) && e.ValueKind == JsonValueKind.Number && e.TryGetDouble(out var v) ? v : 0;
        var fields = Strings(member, "matched_fields");
        var time = Num("t_unix_ms");
        var endpoint = Str("endpoint");
        var rawSource = Str("raw_source");
        var (subject, detail) = ExtractDetails(endpoint, rawSource);
        return new ParsedMember(endpoint, Str("record_type"), time, Num("last_seen", time),
            Num("pid"), Num("parent_pid"), Math.Max(1, Num("repeat_count", 1)),
            Str("source_evidence_id"), rawSource, Str("join_reason"), fields,
            Num("delta_ms"), Num("window_ms"), Str("confidence"), Str("caveat"), Real("confidence_score"),
            Str("native_record_id"), Str("native_session_id"), Str("native_source_file"),
            Num("native_byte_offset", -1), Str("native_content_hash"), subject, detail);
    }

    /// <summary>The native Correlator only promotes pid/parent_pid/record_type/endpoint to
    /// first-class fields on each unified-event member; every other real detail (path, command
    /// line, remote IP, file action, USB device info) stays nested inside "raw_source", a
    /// JSON-escaped string of that endpoint's original line. Without parsing it, the correlation
    /// table only has IDs/hashes/counts to show -- which is exactly the "junk values" Santosh
    /// reported. This pulls the same human-meaningful fields the per-endpoint pages already show
    /// (see ProcessRowViewModel/NetworkRowViewModel/FileRowViewModel/ApplicationRowViewModel/
    /// PortRowViewModel for the proven key names per endpoint type) back out for display here.
    /// Shared with CorrelationGraphViewModel so the graph's per-connection event list uses the
    /// exact same extraction instead of a second drifting copy of the same per-endpoint keys.</summary>
    internal static (string Subject, string Detail) ExtractDetails(string endpoint, string rawSource)
    {
        if (string.IsNullOrWhiteSpace(rawSource)) return ("", "");
        try
        {
            using var doc = JsonDocument.Parse(rawSource);
            var root = doc.RootElement;
            string S(string key) => root.TryGetProperty(key, out var e) && e.ValueKind == JsonValueKind.String ? e.GetString() ?? "" : "";
            long N(string key) => root.TryGetProperty(key, out var e) && e.ValueKind == JsonValueKind.Number && e.TryGetInt64(out var v) ? v : 0;
            static string First(params string[] values) => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? "";
            static string Join(string sep, params string[] parts) => string.Join(sep, parts.Where(p => !string.IsNullOrWhiteSpace(p)));

            switch (endpoint)
            {
                case "process":
                {
                    var name = S("process_name");
                    var path = First(S("canonical_path"), S("image_path_raw"));
                    var cmd = First(S("cmdline_normalized"), S("command_line_raw"));
                    var user = S("user_name");
                    return (string.IsNullOrEmpty(name) ? "(unnamed process)" : name,
                        Join("  |  ", path, cmd != path ? cmd : "", user));
                }
                case "network":
                {
                    var proc = S("process_name");
                    var local = $"{S("local_ip")}:{N("local_port")}";
                    var remote = $"{S("remote_ip")}:{N("remote_port")}";
                    var proto = Join(" ", S("protocol"), S("direction"));
                    return (string.IsNullOrEmpty(proc) ? "(network)" : proc, $"{local} -> {remote}" + (proto != "" ? $" [{proto}]" : ""));
                }
                case "file_integrity":
                case "file":
                {
                    var action = First(S("action"), S("target_action"));
                    var path = First(S("path"), S("target_path"), S("temp_path"));
                    var proc = First(S("process"), S("creator"));
                    return (string.IsNullOrEmpty(proc) ? "(file)" : proc, Join(" ", action, path));
                }
                case "application":
                {
                    var app = S("application");
                    var action = S("action");
                    var path = S("path");
                    var local = S("local_endpoint");
                    var remote = S("remote_endpoint");
                    var proto = S("protocol");
                    var endpoints = (local != "" || remote != "") ? $"{local} -> {remote}" + (proto != "" ? $" [{proto}]" : "") : "";
                    return (string.IsNullOrEmpty(app) ? "(application)" : app, Join("  |  ", action, path, endpoints));
                }
                case "port":
                {
                    var evt = S("event_type");
                    var product = S("product");
                    var manufacturer = S("manufacturer");
                    var mount = S("mount_point");
                    return (string.IsNullOrEmpty(product) ? "(usb device)" : product, Join("  |  ", evt, manufacturer, mount));
                }
                default:
                    return ("", "");
            }
        }
        catch { return ("", ""); }
    }

    private static List<CorrelationConnectionViewModel> ParseConnections(JsonRecord record,
        List<ParsedMember> members, bool legacy)
    {
        var result = new List<CorrelationConnectionViewModel>();
        if (record.Root.TryGetProperty("connections", out var array) && array.ValueKind == JsonValueKind.Array)
        {
            foreach (var connection in array.EnumerateArray())
            {
                string Str(string key) => connection.TryGetProperty(key, out var e) && e.ValueKind == JsonValueKind.String ? e.GetString() ?? "" : "";
                long Num(string key) => connection.TryGetProperty(key, out var e) && e.ValueKind == JsonValueKind.Number && e.TryGetInt64(out var v) ? v : 0;
                double Real(string key) => connection.TryGetProperty(key, out var e) && e.ValueKind == JsonValueKind.Number && e.TryGetDouble(out var v) ? v : 0;
                result.Add(new CorrelationConnectionViewModel((int)Num("from"), (int)Num("to"), Str("reason"),
                    Strings(connection, "matched_fields"), Num("delta_ms"), Num("window_ms"),
                    Str("confidence"), Real("confidence_score"), Str("caveat")));
            }
        }
        else if (legacy)
        {
            for (var i = 1; i < members.Count; i++)
            {
                var m = members[i];
                if (!string.IsNullOrWhiteSpace(m.JoinReason))
                    result.Add(new CorrelationConnectionViewModel(i - 1, i, m.JoinReason, m.MatchedFields,
                        m.DeltaMs, m.WindowMs, m.Confidence, m.ConfidenceScore, m.Caveat));
            }
        }
        return result;
    }

    private static List<string> Strings(JsonElement element, string key)
    {
        var result = new List<string>();
        if (element.TryGetProperty(key, out var array) && array.ValueKind == JsonValueKind.Array)
            foreach (var value in array.EnumerateArray())
                if (value.ValueKind == JsonValueKind.String) result.Add(value.GetString() ?? "");
        return result;
    }

    private static string DisplayEndpoint(string value) => value switch
    {
        "file_integrity" or "file" => "File",
        "process" => "Process",
        "network" => "Network",
        "application" => "Application",
        "port" => "Port/USB",
        _ => value
    };

    private static string SafeSerialize(JsonRecord record)
    {
        try { return JsonSerializer.Serialize(record.Root, new JsonSerializerOptions { WriteIndented = true }); }
        catch { return record.RawLine; }
    }

    private sealed record ParsedMember(string Endpoint, string RecordType, long TimeMs, long LastSeenMs,
        long Pid, long ParentPid, long RepeatCount, string SourceEvidenceId, string RawSource,
        string JoinReason, List<string> MatchedFields, long DeltaMs, long WindowMs, string Confidence,
        string Caveat, double ConfidenceScore, string NativeRecordId, string NativeSessionId,
        string NativeSourceFile, long NativeByteOffset, string NativeContentHash,
        string Subject, string DetailText);
}

public sealed record CorrelationConnectionViewModel(int FromIndex, int ToIndex, string Reason,
    IReadOnlyList<string> MatchedFields, long DeltaMs, long WindowMs, string Confidence,
    double ConfidenceScore, string Caveat);
