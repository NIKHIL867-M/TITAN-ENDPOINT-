using System.Text.Json;
using TitanEndpoint.Core.Json;

namespace TitanEndpoint.App.ViewModels;

public sealed class RuleRowViewModel
{
    public string Id { get; init; } = "";
    /// <summary>Untruncated record ID -- Promote/Delete API calls need the exact value; Id above is
    /// shortened to 8 characters for the DataGrid and is not a valid API path segment on its own.</summary>
    public string FullId { get; init; } = "";
    public string RuleText { get; init; } = "";
    public string Status { get; init; } = "";
    public string Severity { get; init; } = "";
    public string TriggerEvent { get; init; } = "";
    public string ResponseActions { get; init; } = "";
    public string CreatedAt { get; init; } = "";
    public string RawJson { get; init; } = "";

    public static RuleRowViewModel From(JsonRecord r)
    {
        var id = r.GetString("id") ?? "";
        string severity = "", trigger = "", actions = "";

        if (r.Root.TryGetProperty("ir", out var ir) && ir.ValueKind == JsonValueKind.Object)
        {
            var inner = ir.TryGetProperty("ir", out var innerIr) && innerIr.ValueKind == JsonValueKind.Object ? innerIr : ir;
            if (inner.TryGetProperty("severity", out var sev) && sev.ValueKind == JsonValueKind.String)
                severity = sev.GetString() ?? "";
            if (inner.TryGetProperty("trigger_event", out var te) && te.ValueKind == JsonValueKind.String)
                trigger = te.GetString() ?? "";
            if (inner.TryGetProperty("response_actions", out var ra) && ra.ValueKind == JsonValueKind.Array)
            {
                var list = new List<string>();
                foreach (var a in ra.EnumerateArray())
                    if (a.TryGetProperty("type", out var t) && t.ValueKind == JsonValueKind.String)
                        list.Add(t.GetString() ?? "");
                actions = string.Join(", ", list);
            }
        }

        return new RuleRowViewModel
        {
            Id = id.Length >= 8 ? id[..8] : id,
            FullId = id,
            RuleText = r.GetString("rule_text") ?? "",
            Status = r.GetString("status") ?? "unknown",
            Severity = severity,
            TriggerEvent = trigger,
            ResponseActions = actions,
            CreatedAt = r.EventTimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm"),
            RawJson = System.Text.Json.JsonSerializer.Serialize(r.Root, new JsonSerializerOptions { WriteIndented = true })
        };
    }
}
