using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.CustomRule;

namespace TitanEndpoint.App.ViewModels;

public sealed class CoverageRowViewModel
{
    public required string Event { get; init; }
    public required bool Available { get; init; }
    public string StatusText => Available ? "AVAILABLE" : "UNAVAILABLE";
    public required string Collectors { get; init; }
    public required string Mode { get; init; }
    public required string Latency { get; init; }
    public required int FieldCount { get; init; }
    public required string Reason { get; init; }
    public required string DetailText { get; init; }
    /// <summary>Not shown directly -- rolled up into the page-level DISABLED summary.</summary>
    public List<string> DisabledCollectorsInternal { get; init; } = new();
}

/// <summary>FORU.TXT 0.5.B "WATCHER COVERAGE" -- the complete searchable capability map across
/// every supported Custom Rule collector (security, system, sysmon, wmi, registry_fim, inventory,
/// powershell, scheduled_tasks, usb, firewall, defender, titan_sensors), not only the five native
/// telemetry pages. Ported from native_gui.py's coverage tab (_build_coverage_tab/_coverage_loaded/
/// _show_coverage_item) against the existing, unchanged backend route GET /api/watcher-capabilities.</summary>
public sealed class WatcherCoverageViewModel : ViewModelBase
{
    private readonly CustomRuleApiClient _client;
    private readonly DispatcherTimer _timer;
    private List<CoverageRowViewModel> _allRows = new();
    private bool _refreshInFlight;

    public ObservableCollection<CoverageRowViewModel> Rows { get; } = new();

    private string _filterText = "";
    public string FilterText
    {
        get => _filterText;
        set { if (SetField(ref _filterText, value)) ApplyFilter(); }
    }

    private string _summaryText = "COLLECTORS: CHECKING";
    public string SummaryText { get => _summaryText; private set => SetField(ref _summaryText, value); }

    private string _storagePolicyText = "";
    public string StoragePolicyText { get => _storagePolicyText; private set => SetField(ref _storagePolicyText, value); }

    private CoverageRowViewModel? _selectedRow;
    public CoverageRowViewModel? SelectedRow
    {
        get => _selectedRow;
        set { if (SetField(ref _selectedRow, value)) OnPropertyChanged(nameof(DetailText)); }
    }

    public string DetailText => SelectedRow?.DetailText ?? "Select a row to see its full capability detail.";

    public RelayCommand RefreshCommand { get; }

    public WatcherCoverageViewModel(CustomRuleApiClient client)
    {
        _client = client;
        RefreshCommand = new RelayCommand(async () => await RefreshAsync());

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(6) };
        _timer.Tick += async (_, _) => await RefreshAsync();
        _timer.Start();
        _ = RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        if (_refreshInFlight) return;
        _refreshInFlight = true;
        try
        {
            var result = await _client.GetWatcherCapabilitiesAsync();
            if (!result.Reachable)
            {
                SummaryText = $"Custom Rule API unreachable: {result.TransportError}";
                return;
            }
            if (!result.Success || result.Body is not { } body || body.ValueKind != JsonValueKind.Object)
            {
                SummaryText = $"Custom Rule API returned an error (HTTP {result.StatusCode}).";
                return;
            }

            var rows = new List<CoverageRowViewModel>();
            if (body.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in events.EnumerateArray())
                    rows.Add(BuildRow(item));
            }
            _allRows = rows;
            ApplyFilter();

            var active = ReadStringArray(body, "active_collectors");
            var failedNames = body.TryGetProperty("failed_collectors", out var f) && f.ValueKind == JsonValueKind.Object
                ? f.EnumerateObject().Select(p => p.Name).ToList()
                : new List<string>();
            var disabled = rows.SelectMany(r => r.DisabledCollectorsInternal).Distinct().OrderBy(x => x).ToList();
            SummaryText = $"ACTIVE ({active.Count}): {(active.Count > 0 ? string.Join(", ", active) : "none")}    |    " +
                          $"FAILED: {(failedNames.Count > 0 ? string.Join(", ", failedNames) : "none")}    |    " +
                          $"DISABLED: {(disabled.Count > 0 ? string.Join(", ", disabled) : "none")}";

            if (body.TryGetProperty("storage_policy", out var policy) && policy.ValueKind == JsonValueKind.Object)
            {
                var evidenceDir = policy.TryGetProperty("evidence_directory", out var ed) ? ed.GetString() : "data/evidence";
                var alertsFile = policy.TryGetProperty("alerts_file", out var af) ? af.GetString() : "data/alerts.jsonl";
                StoragePolicyText = $"STORAGE POLICY: unmatched events are transient. Completed matches save normalized/raw " +
                                     $"contributing events and investigation evidence under {evidenceDir}, plus an alert summary in {alertsFile}.";
            }
        }
        finally
        {
            _refreshInFlight = false;
        }
    }

    private void ApplyFilter()
    {
        Rows.Clear();
        var filter = _filterText;
        var matches = string.IsNullOrWhiteSpace(filter)
            ? _allRows
            : _allRows.Where(r =>
                r.Event.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.Collectors.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.Reason.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.StatusText.Contains(filter, StringComparison.OrdinalIgnoreCase));
        foreach (var r in matches) Rows.Add(r);
        if (SelectedRow is null || !Rows.Contains(SelectedRow))
            SelectedRow = Rows.FirstOrDefault();
    }

    private static CoverageRowViewModel BuildRow(JsonElement item)
    {
        var eventName = item.TryGetProperty("event", out var e) ? e.GetString() ?? "" : "";
        var available = item.TryGetProperty("available", out var a) && a.ValueKind == JsonValueKind.True;
        var collectors = ReadStringArray(item, "collectors");
        var activeCollectors = ReadStringArray(item, "active_collectors");
        var disabledCollectors = ReadStringArray(item, "disabled_collectors");
        var failedCollectors = item.TryGetProperty("failed_collectors", out var fc) && fc.ValueKind == JsonValueKind.Object
            ? fc.EnumerateObject().ToDictionary(p => p.Name, p => ReadStringArray(p.Value))
            : new Dictionary<string, List<string>>();
        var fields = item.TryGetProperty("fields", out var flds) && flds.ValueKind == JsonValueKind.Array
            ? flds.EnumerateArray().Select(f => (
                Name: f.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "",
                Type: f.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "")).ToList()
            : new List<(string Name, string Type)>();
        var mode = item.TryGetProperty("collection_mode", out var m) ? (m.GetString() ?? "realtime") : "realtime";
        var pollIntervalS = item.TryGetProperty("poll_interval_s", out var p) && p.ValueKind == JsonValueKind.Number ? p.GetDouble() : (double?)null;

        string reason = available
            ? "Active: " + string.Join(", ", activeCollectors)
            : failedCollectors.Count > 0
                ? string.Join("; ", failedCollectors.Select(kv => $"{kv.Key}: {string.Join(", ", kv.Value)}"))
                : disabledCollectors.Count > 0
                    ? "Disabled in WATCHER_COLLECTORS: " + string.Join(", ", disabledCollectors)
                    : "No active telemetry provider";

        var detailLines = new List<string>
        {
            $"EVENT: {eventName}",
            $"STATUS: {(available ? "AVAILABLE" : "UNAVAILABLE")}",
            $"REQUIRED COLLECTORS: {(collectors.Count > 0 ? string.Join(", ", collectors) : "none")}",
            $"ACTIVE PROVIDERS: {(activeCollectors.Count > 0 ? string.Join(", ", activeCollectors) : "none")}",
            $"FAILED PROVIDERS: {(failedCollectors.Count > 0 ? string.Join(", ", failedCollectors.Keys) : "none")}",
            $"DISABLED PROVIDERS: {(disabledCollectors.Count > 0 ? string.Join(", ", disabledCollectors) : "none")}",
            $"COLLECTION: {mode.ToUpperInvariant()}" + (pollIntervalS is > 0 ? $" (up to ~{pollIntervalS:0}s latency)" : ""),
            "",
            "FIELDS:"
        };
        detailLines.AddRange(fields.Select(f => $"  - {f.Name} ({f.Type})"));
        if (failedCollectors.Count > 0)
        {
            detailLines.Add("");
            detailLines.Add("REQUIREMENTS TO ENABLE:");
            foreach (var (provider, messages) in failedCollectors)
                detailLines.AddRange(messages.Select(msg => $"  - {provider}: {msg}"));
        }

        return new CoverageRowViewModel
        {
            Event = eventName,
            Available = available,
            Collectors = string.Join(", ", collectors),
            Mode = mode.ToUpperInvariant(),
            Latency = pollIntervalS is > 0 ? $"~{pollIntervalS:0}s" : "LIVE",
            FieldCount = fields.Count,
            Reason = reason,
            DetailText = string.Join("\n", detailLines),
            DisabledCollectorsInternal = disabledCollectors
        };
    }

    private static List<string> ReadStringArray(JsonElement obj, string prop) =>
        obj.TryGetProperty(prop, out var arr) ? ReadStringArray(arr) : new List<string>();

    private static List<string> ReadStringArray(JsonElement arr) =>
        arr.ValueKind == JsonValueKind.Array
            ? arr.EnumerateArray().Select(x => x.GetString() ?? "").ToList()
            : new List<string>();
}
