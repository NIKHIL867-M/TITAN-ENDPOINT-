using System.Text.Json;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Json;

namespace TitanEndpoint.App.ViewModels;

public sealed class AlertRowViewModel : ViewModelBase
{
    public string Time { get; init; } = "";
    public string Id { get; init; } = "";
    public string InstanceId { get; init; } = "";
    public string RuleId { get; init; } = "";
    public string Severity { get; init; } = "";
    public string EventType { get; init; } = "";
    public string RuleText { get; init; } = "";
    public string Summary { get; init; } = "";
    public string DryRun { get; init; } = "";
    public string EvidencePath { get; init; } = "";
    public string ActionResultsText { get; init; } = "";

    private string _integrityText = "Awaiting backend verification";
    public string IntegrityText { get => _integrityText; set => SetField(ref _integrityText, value); }

    public bool IsHistorical { get; init; }

    private bool _isAcknowledged;
    public bool IsAcknowledged { get => _isAcknowledged; set => SetField(ref _isAcknowledged, value); }

    public static AlertRowViewModel From(JsonRecord r)
    {
        var actionResultsText = "";
        if (r.Root.TryGetProperty("action_results", out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            var parts = new List<string>();
            foreach (var item in arr.EnumerateArray())
            {
                var action = item.TryGetProperty("action", out var a) ? a.GetString() : null;
                var result = item.TryGetProperty("result", out var res) ? res.GetString() : null;
                if (action is not null) parts.Add(result is not null ? $"{action}:{result}" : action);
            }
            actionResultsText = string.Join(", ", parts);
        }

        var integrityText = "Unverified - integrity record missing";
        if (r.Root.TryGetProperty("_integrity", out var integrity) && integrity.ValueKind == JsonValueKind.Object)
        {
            var algorithm = integrity.TryGetProperty("algorithm", out var alg) ? alg.GetString() : "unknown";
            integrityText = $"Awaiting backend verification ({algorithm})";
        }

        return new AlertRowViewModel
        {
            Time = r.EventTimeUtc.ToLocalTime().ToString("HH:mm:ss"),
            Id = r.GetString("id") ?? "",
            InstanceId = r.GetString("instance_id") ?? "",
            RuleId = r.GetString("rule_id") ?? "",
            Severity = r.GetString("severity") ?? "unknown",
            EventType = r.GetString("event_type") ?? "",
            RuleText = r.GetString("rule_text") ?? "",
            Summary = r.GetString("summary") ?? "",
            DryRun = (r.GetBool("dry_run") ?? true) ? "Dry run" : "Executed",
            EvidencePath = r.GetString("evidence_path") ?? "",
            ActionResultsText = actionResultsText,
            IntegrityText = integrityText,
            IsHistorical = r.IsSeedHistory
        };
    }
}
