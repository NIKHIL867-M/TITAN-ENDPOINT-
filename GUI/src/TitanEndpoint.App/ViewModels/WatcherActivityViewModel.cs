using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json;
using System.Windows.Media;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.CustomRule;

namespace TitanEndpoint.App.ViewModels;

public sealed class ActivityRowViewModel
{
    public required string Time { get; init; }
    public required string Kind { get; init; }
    public required string StatusLabel { get; init; }
    public required string EventType { get; init; }
    public required string Subject { get; init; }
    public required string RuleId { get; init; }
    public required string Outcome { get; init; }
    public required Brush Color { get; init; }
}

/// <summary>FORU.TXT 0.5.E "WATCHER ACTIVITY" -- live bounded activity with Search, Pause/Resume,
/// Refresh Once, autoscroll and export. Ported from native_gui.py's activity tab (_build_activity_tab
/// /load_activity/_activity_loaded) against the existing, unchanged backend route
/// GET /api/watcher-activity?limit=100&amp;compact=true. Deliberately not a raw-log archive:
/// unmatched events are transient by policy, matching the backend's own storage note.</summary>
public sealed class WatcherActivityViewModel : ViewModelBase
{
    private static readonly Dictionary<string, Color> KindColors = new()
    {
        ["event_observed"] = Color.FromRgb(0x6F, 0x9F, 0x7B),
        ["rule_matched"] = Color.FromRgb(0xFF, 0xE0, 0x66),
        ["alert_saved"] = Color.FromRgb(0x4C, 0xC9, 0xFF),
        ["event_deduplicated"] = Color.FromRgb(0x9B, 0x7E, 0xDE),
        ["rules_reloaded"] = Color.FromRgb(0xFF, 0x9F, 0x43),
        ["sustain_pending"] = Color.FromRgb(0xFF, 0xD1, 0x66),
        ["sustain_verified"] = Color.FromRgb(0x54, 0xFF, 0x87),
        ["sustain_not_met"] = Color.FromRgb(0x7F, 0x8C, 0x8D),
        ["rule_reload_degraded"] = Color.FromRgb(0xFF, 0x70, 0x70),
    };

    private static readonly Dictionary<string, string> KindLabels = new()
    {
        ["event_observed"] = "WATCHING",
        ["rule_matched"] = "MATCHED",
        ["alert_saved"] = "ALERT SAVED",
        ["event_deduplicated"] = "DEDUPED",
        ["rules_reloaded"] = "RULES RELOADED",
        ["sustain_pending"] = "TIMER STARTED",
        ["sustain_verified"] = "DURATION MET",
        ["sustain_not_met"] = "EXITED EARLY",
        ["rule_reload_degraded"] = "RULE FILE BLOCKED",
    };

    private static readonly Dictionary<string, string> KindOutcomes = new()
    {
        ["alert_saved"] = "Evidence stored",
        ["rule_matched"] = "Condition satisfied",
        ["rules_reloaded"] = "Active rule index updated",
        ["event_deduplicated"] = "Duplicate telemetry suppressed",
        ["sustain_pending"] = "Waiting to verify continued process liveness",
        ["sustain_verified"] = "Process remained alive for the required duration",
        ["sustain_not_met"] = "Process exited before the duration elapsed",
        ["rule_reload_degraded"] = "Invalid rule update blocked; last-known-good rules retained",
    };

    private readonly CustomRuleApiClient _client;
    private readonly DispatcherTimer _timer;
    private List<ActivityRowViewModel> _allRows = new();
    private bool _refreshInFlight;

    public ObservableCollection<ActivityRowViewModel> Rows { get; } = new();

    private string _filterText = "";
    public string FilterText
    {
        get => _filterText;
        set { if (SetField(ref _filterText, value)) ApplyFilter(); }
    }

    private bool _isLive = true;
    public bool IsLive
    {
        get => _isLive;
        set
        {
            if (!SetField(ref _isLive, value)) return;
            OnPropertyChanged(nameof(LiveButtonText));
            if (_isLive) { _timer.Start(); _ = RefreshAsync(); } else { _timer.Stop(); }
        }
    }

    public string LiveButtonText => IsLive ? "PAUSE LIVE VIEW" : "START LIVE VIEW";

    private string _infoText = "Bounded, sanitized watcher diagnostics. Proves whether a real event was observed, a rule matched, and an alert/evidence record was saved; unmatched raw logs are not retained.";
    public string InfoText { get => _infoText; private set => SetField(ref _infoText, value); }

    /// <summary>Santosh, 2026-08-06: "add option to save the logs ... keep it off until the user
    /// turns it on ... space/RAM limitation". Off by default (matches every native endpoint's own
    /// Monitoring-vs-Save-Logs split) -- this table above keeps showing live activity from the
    /// always-on bounded feed regardless of this toggle; the toggle only controls whether the
    /// watcher additionally writes a separate, larger, consolidated archive file to disk.</summary>
    private bool _saveLogsEnabled;
    public bool SaveLogsEnabled
    {
        get => _saveLogsEnabled;
        set
        {
            if (!SetField(ref _saveLogsEnabled, value)) return;
            if (_suppressSaveLogsPush) return;
            _ = PushSaveLogsAsync(value);
        }
    }

    private bool _suppressSaveLogsPush;
    private string _saveLogsStatusText = "";
    public string SaveLogsStatusText { get => _saveLogsStatusText; private set => SetField(ref _saveLogsStatusText, value); }

    public RelayCommand ToggleLiveCommand { get; }
    public RelayCommand RefreshCommand { get; }

    public WatcherActivityViewModel(CustomRuleApiClient client)
    {
        _client = client;
        ToggleLiveCommand = new RelayCommand(() => IsLive = !IsLive);
        RefreshCommand = new RelayCommand(async () => await RefreshAsync());

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(3) };
        _timer.Tick += async (_, _) => await RefreshAsync();
        _timer.Start();
        _ = RefreshAsync();
        _ = LoadSaveLogsStatusAsync();
    }

    private async Task LoadSaveLogsStatusAsync()
    {
        var result = await _client.GetSaveLogsStatusAsync();
        if (!result.Reachable || !result.Success || result.Body is not { } body || body.ValueKind != JsonValueKind.Object)
        {
            SaveLogsStatusText = "Save Logs state unavailable (Custom Rule API unreachable).";
            return;
        }
        var enabled = body.TryGetProperty("enabled", out var e) && e.ValueKind == JsonValueKind.True;
        _suppressSaveLogsPush = true;
        SaveLogsEnabled = enabled;
        _suppressSaveLogsPush = false;
        SaveLogsStatusText = enabled
            ? "Saving a consolidated archive of everything the watcher observes to one file on disk."
            : "Not writing to disk. Turn on to save a consolidated activity archive.";
    }

    private async Task PushSaveLogsAsync(bool enabled)
    {
        SaveLogsStatusText = "Updating...";
        var result = await _client.SetSaveLogsAsync(enabled);
        if (!result.Reachable || !result.Success)
        {
            SaveLogsStatusText = "Could not update Save Logs (Custom Rule API unreachable).";
            _suppressSaveLogsPush = true;
            SaveLogsEnabled = !enabled;
            _suppressSaveLogsPush = false;
            return;
        }
        SaveLogsStatusText = enabled
            ? "Saving a consolidated archive of everything the watcher observes to one file on disk."
            : "Not writing to disk. Turn on to save a consolidated activity archive.";
    }

    public void Stop() => _timer.Stop();

    private async Task RefreshAsync()
    {
        if (_refreshInFlight) return;
        _refreshInFlight = true;
        try
        {
            var result = await _client.GetWatcherActivityAsync(100);
            if (!result.Reachable || !result.Success || result.Body is not { } body || body.ValueKind != JsonValueKind.Object)
                return;
            if (!body.TryGetProperty("activity", out var activity) || activity.ValueKind != JsonValueKind.Array)
                return;

            var rows = new List<ActivityRowViewModel>();
            foreach (var row in activity.EnumerateArray())
                rows.Add(BuildRow(row));
            _allRows = rows;
            ApplyFilter();
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
                r.EventType.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.Subject.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.RuleId.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.StatusLabel.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.Outcome.Contains(filter, StringComparison.OrdinalIgnoreCase));
        foreach (var r in matches) Rows.Add(r);
    }

    private static ActivityRowViewModel BuildRow(JsonElement row)
    {
        var kind = row.TryGetProperty("kind", out var k) ? k.GetString() ?? "" : "";
        var at = row.TryGetProperty("at", out var a) ? a.GetString() ?? "" : "";
        var eventType = row.TryGetProperty("event_type", out var et) ? et.GetString() ?? "" : "";
        var ruleId = row.TryGetProperty("rule_id", out var ri) ? (ri.GetString() ?? "") : "";
        var repeatCount = row.TryGetProperty("repeat_count", out var rc) && rc.ValueKind == JsonValueKind.Number ? rc.GetInt32() : 1;

        var outcome = KindOutcomes.GetValueOrDefault(kind, "Observed only — no active rule matched");
        if (repeatCount > 1) outcome += $" ({repeatCount} similar events)";

        string subject;
        if (row.TryGetProperty("subject", out var subj) && subj.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(subj.GetString()))
        {
            subject = subj.GetString()!;
        }
        else
        {
            var processName = row.TryGetProperty("process_name", out var pn) ? pn.GetString() : null;
            var pid = row.TryGetProperty("pid", out var p) ? p.ToString() : null;
            var collector = row.TryGetProperty("collector", out var c) ? c.GetString() ?? "unknown" : "unknown";
            subject = !string.IsNullOrEmpty(processName) ? $"{processName} [{pid}]" : $"{(string.IsNullOrEmpty(eventType) ? "event" : eventType)} via {collector}";
        }

        return new ActivityRowViewModel
        {
            Time = FormatLocalTime(at),
            Kind = kind,
            StatusLabel = KindLabels.GetValueOrDefault(kind, kind.ToUpperInvariant()),
            EventType = eventType,
            Subject = subject,
            RuleId = ruleId.Length >= 8 ? ruleId[..8] : (string.IsNullOrEmpty(ruleId) ? "—" : ruleId),
            Outcome = outcome,
            Color = new SolidColorBrush(KindColors.GetValueOrDefault(kind, Color.FromRgb(0xB8, 0xFF, 0xD0)))
        };
    }

    private static string FormatLocalTime(string iso)
    {
        if (string.IsNullOrEmpty(iso)) return "";
        return DateTimeOffset.TryParse(iso, out var dto) ? dto.ToLocalTime().ToString("HH:mm:ss") : iso;
    }
}
