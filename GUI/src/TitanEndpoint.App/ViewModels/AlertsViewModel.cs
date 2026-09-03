using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text.Json;
using System.Windows.Data;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.CustomRule;

namespace TitanEndpoint.App.ViewModels;

public sealed class AlertsViewModel : ViewModelBase
{
    public ObservableCollection<AlertRowViewModel> Rows { get; } = new();
    public ICollectionView RowsView { get; }

    private string _filterText = "";
    public string FilterText
    {
        get => _filterText;
        set { if (SetField(ref _filterText, value)) RowsView.Refresh(); }
    }

    private string _summaryText = "Waiting for data...";
    public string SummaryText { get => _summaryText; private set => SetField(ref _summaryText, value); }

    private string _watcherStatusText = "Unavailable";
    public string WatcherStatusText { get => _watcherStatusText; private set => SetField(ref _watcherStatusText, value); }

    private string _dryRunText = "Unavailable";
    public string DryRunText { get => _dryRunText; private set => SetField(ref _dryRunText, value); }

    public RelayCommand AcknowledgeCommand { get; }
    public RelayCommand OpenEvidenceCommand { get; }
    public RelayCommand OpenRuleCommand { get; }
    public RelayCommand LoadOlderCommand { get; }

    private readonly IncrementalRowSync<AlertRowViewModel> _sync;
    private readonly DispatcherTimer _timer;
    private readonly string _watcherRuntimePath;
    private readonly AlertAckStore _ackStore = new();
    private readonly CustomRuleApiClient _api;
    private bool _integrityRefreshBusy;
    private bool _initialIntegrityLoaded;
    private int _integrityRefreshTicks;
    private int _archivePage;

    /// <summary>Above this age, a watcher_runtime.json heartbeat is stale (FORU.TXT 14.3:
    /// "Detect and label stale watcher_runtime.json instead of displaying Watching").</summary>
    private const double StaleHeartbeatSeconds = 60;

    public AlertsViewModel()
    {
        var state = App.Fleet.Get(EndpointId.CustomRule);
        _watcherRuntimePath = Path.Combine(App.Fleet.Settings.CustomRuleDataDirectory, "watcher_runtime.json");
        _api = new CustomRuleApiClient(App.Fleet.Settings.CustomRuleApiBaseUrl,
            App.Fleet.Settings.CustomRuleDataDirectory);
        state.BeginTailing();

        RowsView = CollectionViewSource.GetDefaultView(Rows);
        RowsView.Filter = FilterPredicate;

        AcknowledgeCommand = new RelayCommand(param =>
        {
            if (param is not AlertRowViewModel row || string.IsNullOrEmpty(row.Id)) return;
            _ackStore.Acknowledge(row.Id);
            row.IsAcknowledged = true;
        });
        OpenEvidenceCommand = new RelayCommand(OpenEvidence);
        OpenRuleCommand = new RelayCommand(OpenRule);
        LoadOlderCommand = new RelayCommand(LoadOlder);

        _sync = new IncrementalRowSync<AlertRowViewModel>(Rows, maxRows: 2000, MakeRow,
            filter: r => !r.IsCollectorHealth);

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        Tick();
    }

    private void OpenEvidence(object? parameter)
    {
        if (parameter is not AlertRowViewModel row) return;
        // Santosh, 2026-08-31: "clicked evidence... it is still not opening." Live-tested three ways
        // (UI Automation InvokePattern, a real physical mouse click at the button's exact screen
        // coordinates, and a file-based diagnostic trace inside this method): the command was always
        // firing correctly and MessageBox.Show was always actually creating a real window (confirmed
        // via raw Win32 EnumWindows) -- it just wasn't detected by AutomationElement-based tooling and,
        // for the row actually clicked, said nothing useful, since EvidencePath was genuinely empty
        // (a dry-run test rule whose action never ran the investigation/evidence-capture step -- real,
        // accurate data, not a bug). The one real, worthwhile fix: say that plainly instead of the
        // dialog's message being unhelpful, matching OpenRule's own "not retained" message just below.
        if (string.IsNullOrWhiteSpace(row.EvidencePath))
        {
            System.Windows.MessageBox.Show(System.Windows.Application.Current?.MainWindow,
                "This alert has no evidence_path recorded — the watcher did not capture investigation evidence for it " +
                "(common for a dry-run alert whose response action never actually ran).",
                $"Alert evidence — {row.InstanceId}", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            return;
        }
        var dataRoot = Path.GetFullPath(App.Fleet.Settings.CustomRuleDataDirectory);
        var candidate = row.EvidencePath;
        if (!Path.IsPathRooted(candidate))
        {
            candidate = candidate.StartsWith("data" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                ? Path.Combine(Directory.GetParent(dataRoot)?.FullName ?? dataRoot, candidate)
                : Path.Combine(dataRoot, candidate);
        }
        candidate = Path.GetFullPath(candidate);
        if (!candidate.StartsWith(dataRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            candidate = Path.Combine(dataRoot, "evidence", Path.GetFileName(row.EvidencePath));
        var message = File.Exists(candidate) ? File.ReadAllText(candidate) : "The evidence file has expired or is not present in the configured evidence store.";
        System.Windows.MessageBox.Show(System.Windows.Application.Current?.MainWindow, message, $"Alert evidence — {row.InstanceId}", System.Windows.MessageBoxButton.OK,
            File.Exists(candidate) ? System.Windows.MessageBoxImage.Information : System.Windows.MessageBoxImage.Warning);
    }

    private void OpenRule(object? parameter)
    {
        if (parameter is not AlertRowViewModel row || string.IsNullOrWhiteSpace(row.RuleId)) return;
        var path = Path.Combine(App.Fleet.Settings.CustomRuleDataDirectory, "rules.jsonl");
        if (!File.Exists(path)) { System.Windows.MessageBox.Show(System.Windows.Application.Current?.MainWindow, "The retained rule store is unavailable."); return; }
        string? matched = null;
        long? cursor = null;
        for (var page = 0; page < 20 && matched is null; page++)
        {
            var result = TitanEndpoint.Core.Logs.PagedLogReader.ReadPageBackward(path, cursor, 100);
            matched = result.Lines.FirstOrDefault(line => line.Contains(row.RuleId, StringComparison.OrdinalIgnoreCase));
            cursor = result.NextCursor;
            if (cursor is null) break;
        }
        System.Windows.MessageBox.Show(System.Windows.Application.Current?.MainWindow, matched ?? "The referenced rule is no longer retained.", $"Rule — {row.RuleId}");
    }

    private async void LoadOlder(object? _)
    {
        var response = await _api.GetAlertsAsync(_archivePage++, 100);
        if (!response.Success || response.Body is not { } body || !body.TryGetProperty("alerts", out var alerts) || alerts.ValueKind != JsonValueKind.Array)
        { SummaryText = "Could not load the next verified alert archive page."; return; }
        var existing = Rows.Select(row => row.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var added = 0;
        foreach (var alert in alerts.EnumerateArray())
        {
            var raw = alert.GetRawText();
            var record = Core.Json.JsonRecord.TryParse(raw, DateTimeOffset.UtcNow, isSeedHistory: true);
            if (record is null) continue;
            var row = MakeRow(record);
            if (string.IsNullOrWhiteSpace(row.Id) || !existing.Add(row.Id)) continue;
            Rows.Add(row); added++;
        }
        RowsView.Refresh();
        SummaryText = $"Loaded {added} older verified alert(s) from archive page {_archivePage}.";
    }

    private AlertRowViewModel MakeRow(Core.Json.JsonRecord r)
    {
        var row = AlertRowViewModel.From(r);
        if (!string.IsNullOrEmpty(row.Id)) row.IsAcknowledged = _ackStore.IsAcknowledged(row.Id);
        return row;
    }

    private bool FilterPredicate(object obj)
    {
        if (string.IsNullOrWhiteSpace(FilterText)) return true;
        if (obj is not AlertRowViewModel row) return true;
        var needle = FilterText.Trim();
        return row.RuleText.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.Severity.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.EventType.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.Summary.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    private void Tick()
    {
        var tailer = App.Fleet.Get(EndpointId.CustomRule).Tailer;
        _sync.Sync(tailer.Records.Snapshot());

        var bySeverity = Rows.GroupBy(r => r.Severity).ToDictionary(g => g.Key, g => g.Count());
        var currentSession = Rows.Count(r => !r.IsHistorical);
        SummaryText = Rows.Count == 0
            ? "No alerts recorded."
            : $"{Rows.Count:N0} alerts in view ({currentSession:N0} this session) — " +
              string.Join("  ", bySeverity.Select(kv => $"{kv.Key}: {kv.Value}"));

        RefreshWatcherStatus();
        if (!_initialIntegrityLoaded || ++_integrityRefreshTicks >= 5)
        {
            _integrityRefreshTicks = 0;
            _ = RefreshIntegrityAsync(!_initialIntegrityLoaded);
        }
    }

    private async Task RefreshIntegrityAsync(bool includeHistory)
    {
        if (_integrityRefreshBusy) return;
        _integrityRefreshBusy = true;
        try
        {
            var page = 0;
            var verified = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            while (page == 0 || includeHistory)
            {
                var response = await _api.GetAlertsAsync(page, 100);
                if (!response.Success || response.Body is not { } body ||
                    !body.TryGetProperty("alerts", out var alerts) || alerts.ValueKind != JsonValueKind.Array)
                {
                    // Santosh, 2026-08-31: "when i click on evidence button it is keep on loading" --
                    // _initialIntegrityLoaded was never set true on this path, so Tick() kept treating
                    // startup as still-in-progress forever whenever the Custom Rule API was simply not
                    // running: every 1s tick re-triggered a fresh RefreshIntegrityAsync call (now bounded
                    // to DefaultCallTimeout instead of the 100s the parse-rule fix introduced elsewhere,
                    // but still an endless, pointless retry loop and a permanently-"Awaiting" Evidence
                    // Integrity column). Marking startup complete here too -- a failed/unreachable first
                    // attempt is still a completed attempt, and Tick()'s existing every-5th-tick
                    // (~5s) retry already covers the API coming back up later.
                    if (!_initialIntegrityLoaded)
                        foreach (var row in Rows.Where(r => r.IntegrityText.StartsWith("Awaiting", StringComparison.Ordinal)))
                            row.IntegrityText = "Verification unavailable - Custom Rule API is offline or unauthorized";
                    _initialIntegrityLoaded = true;
                    return;
                }

                foreach (var alert in alerts.EnumerateArray())
                {
                    if (!alert.TryGetProperty("id", out var idElement) || idElement.ValueKind != JsonValueKind.String) continue;
                    var id = idElement.GetString();
                    var state = alert.TryGetProperty("integrity_status", out var stateElement)
                        ? stateElement.GetString() : null;
                    if (!string.IsNullOrEmpty(id)) verified[id] = state switch
                    {
                        "verified" => "Verified by backend HMAC check",
                        "invalid" => "INVALID - HMAC verification failed",
                        "missing" => "Unverified - integrity record missing",
                        _ => $"Unverified - backend status: {state ?? "unknown"}"
                    };
                }

                if (!includeHistory) break;
                var total = body.TryGetProperty("total", out var totalElement) && totalElement.TryGetInt32(out var value)
                    ? value : alerts.GetArrayLength();
                page++;
                if (page * 100 >= total || page >= 100) break;
            }

            foreach (var row in Rows)
                if (verified.TryGetValue(row.Id, out var status)) row.IntegrityText = status;
            _initialIntegrityLoaded = true;
        }
        finally { _integrityRefreshBusy = false; }
    }

    private void RefreshWatcherStatus()
    {
        if (!File.Exists(_watcherRuntimePath))
        {
            WatcherStatusText = "Unavailable — watcher_runtime.json not found";
            DryRunText = "Unavailable";
            return;
        }

        try
        {
            var json = File.ReadAllText(_watcherRuntimePath);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var state = root.TryGetProperty("state", out var s) ? s.GetString() : "unknown";
            var heartbeatRaw = root.TryGetProperty("heartbeat_at", out var h) ? h.GetString() : null;

            var stale = true;
            string ageText = "no heartbeat recorded";
            if (heartbeatRaw is not null && DateTimeOffset.TryParse(heartbeatRaw, out var heartbeatAt))
            {
                var age = DateTimeOffset.UtcNow - heartbeatAt;
                stale = age.TotalSeconds >= StaleHeartbeatSeconds;
                ageText = $"heartbeat {age.TotalSeconds:0}s ago";
            }

            WatcherStatusText = stale
                ? $"STALE — last reported '{state}' ({ageText}). Do not trust this as currently watching."
                : $"{state} ({ageText})";

            var dryRun = root.TryGetProperty("dry_run", out var d) && d.ValueKind == JsonValueKind.True;
            DryRunText = stale ? "Unavailable (watcher status is stale)"
                : dryRun ? "Dry run is ON — responses are recorded but not executed"
                : "Dry run is OFF — responses execute for real";
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            WatcherStatusText = "Unavailable — could not read watcher status";
            DryRunText = "Unavailable";
        }
    }
}
