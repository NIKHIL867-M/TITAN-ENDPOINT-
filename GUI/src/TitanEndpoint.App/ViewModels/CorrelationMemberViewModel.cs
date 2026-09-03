using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Evidence;

namespace TitanEndpoint.App.ViewModels;

public sealed class CorrelationMemberViewModel
{
    public string Endpoint { get; init; } = "";
    public string RecordType { get; init; } = "";
    public long TUnixMs { get; init; }
    public long DeltaMsFromFirst { get; init; }
    public long Pid { get; init; }
    public long ParentPid { get; init; }
    public long RepeatCount { get; init; } = 1;
    public string SourceEvidenceId { get; init; } = "";
    public string RawSource { get; init; } = "";
    public string NativeRecordId { get; init; } = "";
    public string NativeSessionId { get; init; } = "";
    public string NativeSourceFile { get; init; } = "";
    public long NativeByteOffset { get; init; }
    public string NativeContentHash { get; init; } = "";
    public string JoinReason { get; init; } = "";
    public IReadOnlyList<string> MatchedFields { get; init; } = Array.Empty<string>();
    public long EdgeDeltaMs { get; init; }
    public long WindowMs { get; init; }
    public string Confidence { get; init; } = "";
    public double ConfidenceScore { get; init; }
    public string Caveat { get; init; } = "";
    public string Subject { get; init; } = "";
    public string DetailText { get; init; } = "";

    public string DisplayEndpoint => Endpoint switch { "file_integrity" => "File", "process" => "Process", "network" => "Network", "application" => "Application", "port" => "Port/USB", _ => Endpoint };
    public string PidText => Pid > 0 ? $"pid {Pid}" + (ParentPid > 0 ? $" (parent {ParentPid})" : "") : "No PID";
    /// <summary>Human-readable identity + path/command/IP/location pulled out of the raw source
    /// event, so the correlation table shows real evidence instead of just IDs and hashes.</summary>
    public string SubjectDetailText => (Subject, DetailText) switch
    {
        ("", "") => "(no detail available)",
        (var s, "") => s,
        ("", var d) => d,
        (var s, var d) => $"{s} — {d}"
    };
    public string DeltaText => DeltaMsFromFirst == 0 ? "Anchor" : $"+{DeltaMsFromFirst} ms";
    public string RepeatText => RepeatCount > 1 ? $"{RepeatCount}x compacted" : "1 event";
    /// <summary>Short, real engine-reported confidence label for the evidence graph node -- "Anchor"
    /// for the group's first record (which has no join to score), otherwise the actual confidence
    /// bucket the correlator assigned, never a fabricated value.</summary>
    public string ConfidenceTag => JoinReason is "" or "anchor" ? "Anchor" : Confidence switch
    {
        "high" => "High confidence",
        "medium" => "Medium confidence",
        "low" => "Low confidence",
        _ => "Unscored join"
    };
    public string EvidenceIdentityText => string.IsNullOrWhiteSpace(NativeRecordId) ? "Legacy embedded evidence" : $"{NativeRecordId} | session {NativeSessionId} | {NativeSourceFile}@{NativeByteOffset:N0}";
    public string JoinReasonText
    {
        get
        {
            if (JoinReason == "" || JoinReason == "anchor") return "Anchor record for this group.";
            var fields = MatchedFields.Count > 0 ? $" (matched: {string.Join(", ", MatchedFields)})" : "";
            var score = ConfidenceScore > 0 ? $" {ConfidenceScore:P0}" : "";
            var basis = Confidence switch { "high" => "Confirmed", "medium" => "Likely", "low" => "Low-confidence", _ => "Unlabeled" };
            var text = $"{basis}{score}: {JoinReason}{fields} — Δ{EdgeDeltaMs} ms within {WindowMs} ms.";
            return string.IsNullOrEmpty(Caveat) ? text : $"{text} {Caveat}";
        }
    }
    public RelayCommand OpenEvidenceCommand => new(() =>
    {
        var result = EvidenceResolver.Resolve(new EvidenceReference(Endpoint, NativeRecordId, NativeSessionId,
            NativeSourceFile, NativeByteOffset, NativeContentHash, RawSource), App.Fleet.Settings.Endpoints);
        System.Windows.MessageBox.Show(System.Windows.Application.Current?.MainWindow,
            $"{result.Message}\n\n{result.Content}", $"{DisplayEndpoint} evidence — {result.State}",
            System.Windows.MessageBoxButton.OK, result.State == EvidenceResolutionState.Verified
                ? System.Windows.MessageBoxImage.Information : System.Windows.MessageBoxImage.Warning);
    });
}
