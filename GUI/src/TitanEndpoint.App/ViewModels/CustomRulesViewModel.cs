using System.Collections.ObjectModel;
using System.Text.Json;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.CustomRule;
using TitanEndpoint.Core.Logs;

namespace TitanEndpoint.App.ViewModels;

public sealed class CustomRulesViewModel : ViewModelBase
{
    public ObservableCollection<RuleRowViewModel> Rules { get; } = new();
    public CustomRuleWizardViewModel Wizard { get; }
    public WatcherCoverageViewModel Coverage { get; }
    public WatcherActivityViewModel Activity { get; }
    private readonly CustomRuleApiClient _apiClient;

    private string _summaryText = "Waiting for data...";
    public string SummaryText { get => _summaryText; private set => SetField(ref _summaryText, value); }

    private string _watcherStatusText = "Unavailable";
    public string WatcherStatusText { get => _watcherStatusText; private set => SetField(ref _watcherStatusText, value); }

    private string _dryRunText = "Unavailable";
    public string DryRunText { get => _dryRunText; private set => SetField(ref _dryRunText, value); }

    // ── Approved Rules: search, selection, and mutation actions (FORU.TXT 0.5.C) ──────────────
    private string _filterText = "";
    public string FilterText
    {
        get => _filterText;
        set { if (SetField(ref _filterText, value)) ApplyRuleFilter(); }
    }

    private List<RuleRowViewModel> _allRuleRows = new();

    private RuleRowViewModel? _selectedRule;
    public RuleRowViewModel? SelectedRule
    {
        get => _selectedRule;
        set
        {
            if (!SetField(ref _selectedRule, value)) return;
            OnPropertyChanged(nameof(DetailText));
            RaiseSelectionCommands();
        }
    }

    public string DetailText => SelectedRule is null
        ? (Rules.Count == 0 ? "No approved rules." : "Select a rule to inspect or delete it.")
        : SelectedRule.RawJson;

    private string _actionStatusText = "";
    public string ActionStatusText { get => _actionStatusText; private set => SetField(ref _actionStatusText, value); }

    public RelayCommand RefreshRulesCommand { get; }
    public RelayCommand PromoteSelectedCommand { get; }
    public RelayCommand DeleteSelectedCommand { get; }
    public RelayCommand DeleteDuplicatesCommand { get; }
    public RelayCommand DeleteAllCommand { get; }
    public RelayCommand ToggleCustomRuleCommand { get; }

    /// <summary>Santosh, Round 22: "for the Custom Rule there is not specific option of start and
    /// stop" -- every native endpoint page has its own Start/Stop; Custom Rule only had the bundled
    /// global Start All/Stop All. Derived, not a separately-tracked flag, so it can never disagree
    /// with what WATCHER STATUS/RESPONSE MODE above already show.</summary>
    public bool IsCustomRuleRunning => Wizard.ApiReachable && !_watcherStatusText.StartsWith("STALE", StringComparison.Ordinal)
        && !_watcherStatusText.StartsWith("Unavailable", StringComparison.Ordinal);
    public string CustomRuleToggleLabel => _customRuleActionBusy ? "WORKING..." : IsCustomRuleRunning ? "STOP CUSTOM RULE" : "START CUSTOM RULE";

    private bool _customRuleActionBusy;
    private string _customRuleActionStatus = "";
    public string CustomRuleActionStatus { get => _customRuleActionStatus; private set => SetField(ref _customRuleActionStatus, value); }

    private readonly LogTailer _rulesTailer;
    private readonly IncrementalRowSync<RuleRowViewModel> _sync;
    private readonly DispatcherTimer _timer;
    private readonly string _watcherRuntimePath;

    public CustomRulesViewModel()
    {
        var dataDir = App.Fleet.Settings.CustomRuleDataDirectory;
        _watcherRuntimePath = System.IO.Path.Combine(dataDir, "watcher_runtime.json");

        var def = new EndpointDefinition
        {
            Id = EndpointId.CustomRule,
            DisplayName = "Custom Rule Library",
            ShortDescription = "Rule store",
            LogDirectory = dataDir,
            LogFilePattern = "rules.jsonl"
        };
        _rulesTailer = new LogTailer(def, capacity: 5000);
        _rulesTailer.Start();

        _apiClient = new CustomRuleApiClient(App.Fleet.Settings.CustomRuleApiBaseUrl, dataDir);
        Wizard = new CustomRuleWizardViewModel(_apiClient);
        Coverage = new WatcherCoverageViewModel(_apiClient);
        Activity = new WatcherActivityViewModel(_apiClient);

        RefreshRulesCommand = new RelayCommand(() => Tick());
        PromoteSelectedCommand = new RelayCommand(async () => await PromoteSelectedAsync(), () => SelectedRule is not null);
        DeleteSelectedCommand = new RelayCommand(async () => await DeleteSelectedAsync(), () => SelectedRule is not null);
        DeleteDuplicatesCommand = new RelayCommand(async () => await DeleteDuplicatesAsync());
        DeleteAllCommand = new RelayCommand(async () => await DeleteAllAsync(), () => Rules.Count > 0);
        ToggleCustomRuleCommand = new RelayCommand(async () => await ToggleCustomRuleAsync(), () => !_customRuleActionBusy);

        _sync = new IncrementalRowSync<RuleRowViewModel>(Rules, maxRows: 5000, RuleRowViewModel.From);

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        Tick();
    }

    private void RaiseSelectionCommands()
    {
        PromoteSelectedCommand.RaiseCanExecuteChanged();
        DeleteSelectedCommand.RaiseCanExecuteChanged();
    }

    private void ApplyRuleFilter()
    {
        var filter = _filterText;
        var matches = string.IsNullOrWhiteSpace(filter)
            ? _allRuleRows
            : _allRuleRows.Where(r =>
                r.RuleText.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.Status.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.Severity.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.TriggerEvent.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.ResponseActions.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.Id.Contains(filter, StringComparison.OrdinalIgnoreCase));
        Rules.Clear();
        foreach (var r in matches) Rules.Add(r);
        if (SelectedRule is null || !Rules.Contains(SelectedRule))
            SelectedRule = null;
        OnPropertyChanged(nameof(DetailText));
        DeleteAllCommand.RaiseCanExecuteChanged();
    }

    private async Task PromoteSelectedAsync()
    {
        if (SelectedRule is not { } rule) return;
        ActionStatusText = "Sanitizing and rebuilding the knowledge index...";
        var result = await _apiClient.PromoteRuleAsync(rule.FullId);
        ActionStatusText = result.Success
            ? $"Promoted sanitized knowledge document for rule {rule.Id}."
            : $"Promote failed: {(result.Reachable ? result.RawBody : result.TransportError)}";
    }

    private async Task DeleteSelectedAsync()
    {
        if (SelectedRule is not { } rule) return;
        ActionStatusText = "Deleting approved rule...";
        var result = await _apiClient.DeleteRuleAsync(rule.FullId);
        ActionStatusText = result.Success
            ? "Deleted 1 approved rule. Watcher hot-reload is automatic."
            : $"Delete failed: {(result.Reachable ? result.RawBody : result.TransportError)}";
        if (result.Success) SelectedRule = null;
    }

    private async Task DeleteDuplicatesAsync()
    {
        ActionStatusText = "Cleaning duplicate rule records...";
        var result = await _apiClient.DeleteDuplicateRulesAsync();
        ActionStatusText = result.Success
            ? "Deleted duplicate approved-rule records. Watcher hot-reload is automatic."
            : $"Delete duplicates failed: {(result.Reachable ? result.RawBody : result.TransportError)}";
    }

    private async Task DeleteAllAsync()
    {
        ActionStatusText = "Deleting all approved rules...";
        var result = await _apiClient.DeleteAllRulesAsync();
        ActionStatusText = result.Success
            ? "Deleted all approved rules. Watcher hot-reload is automatic."
            : $"Delete all failed: {(result.Reachable ? result.RawBody : result.TransportError)}";
        if (result.Success) SelectedRule = null;
    }

    private async Task ToggleCustomRuleAsync()
    {
        var mainVm = System.Windows.Application.Current?.MainWindow is MainWindow mw ? (MainViewModel)mw.DataContext : null;
        if (mainVm is null) { CustomRuleActionStatus = "Cannot reach the application's Custom Rule controller."; return; }

        _customRuleActionBusy = true;
        ToggleCustomRuleCommand.RaiseCanExecuteChanged();
        OnPropertyChanged(nameof(CustomRuleToggleLabel));
        try
        {
            if (IsCustomRuleRunning)
            {
                CustomRuleActionStatus = "Stopping Custom Rule...";
                var (wOk, wMsg) = await Task.Run(() => mainVm.CustomRuleController.StopWatcher());
                var (aOk, aMsg) = await Task.Run(() => mainVm.CustomRuleController.StopApi());
                CustomRuleActionStatus = wOk && aOk ? "Custom Rule stopped." : $"Stop finished with issues — watcher: {wMsg}; api: {aMsg}";
            }
            else
            {
                CustomRuleActionStatus = "Starting Custom Rule API...";
                var (aOk, aMsg) = await mainVm.CustomRuleController.StartApiAsync();
                if (!aOk) { CustomRuleActionStatus = $"API start failed: {aMsg}"; return; }

                var apiReady = false;
                for (var i = 0; i < 20 && !apiReady; i++)
                {
                    await Task.Delay(300);
                    apiReady = await mainVm.CustomRuleController.IsApiReadyAsync();
                }
                CustomRuleActionStatus = "Starting Custom Rule watcher...";
                var (wOk, wMsg) = mainVm.CustomRuleController.StartWatcher();
                CustomRuleActionStatus = apiReady && wOk ? "Custom Rule started." : $"Start finished with issues — api ready: {apiReady}; watcher: {wMsg}";
            }
        }
        finally
        {
            _customRuleActionBusy = false;
            ToggleCustomRuleCommand.RaiseCanExecuteChanged();
            Tick();
        }
    }

    private void Tick()
    {
        var snapshot = _rulesTailer.Records.Snapshot();
        _sync.Sync(snapshot);
        _allRuleRows = Rules.ToList();
        ApplyRuleFilter();

        var approved = _allRuleRows.Count(r => r.Status == "approved");
        SummaryText = _rulesTailer.ActiveFilePath is null
            ? "No rule store file found yet."
            : $"{_allRuleRows.Count:N0} rules — {approved:N0} approved.";

        if (System.IO.File.Exists(_watcherRuntimePath))
        {
            try
            {
                var json = System.IO.File.ReadAllText(_watcherRuntimePath);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                var state = root.TryGetProperty("state", out var s) ? s.GetString() : "unknown";
                var loaded = root.TryGetProperty("rules_loaded", out var rl) ? rl.GetInt32().ToString() : "?";
                var heartbeatRaw = root.TryGetProperty("heartbeat_at", out var h) ? h.GetString() : null;

                // FOUND LIVE, 2026-08-04: this page previously showed "watching — N rules loaded"
                // straight from the file with no freshness check at all -- unlike AlertsViewModel's
                // own RefreshWatcherStatus, which already implements FORU.TXT 14.3 ("Detect and
                // label stale watcher_runtime.json instead of displaying Watching") for the exact
                // same underlying file. Reproduced live: a watcher_runtime.json left over from a
                // watcher that exited hours earlier still read "watching" here with no warning,
                // while the Alerts & Evidence page correctly labelled the identical file STALE.
                // Mirrors AlertsViewModel's threshold/wording exactly so the two pages never disagree
                // about the same file again.
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
                    : $"{state} — {loaded} rules loaded ({ageText})";

                var dryRun = root.TryGetProperty("dry_run", out var d) && d.ValueKind == JsonValueKind.True;
                DryRunText = stale ? "Unavailable (watcher status is stale)"
                    : dryRun ? "Global Dry Run: ON"
                    : "Global Dry Run: OFF — responses execute for real";
            }
            catch
            {
                WatcherStatusText = "Unavailable";
                DryRunText = "Unavailable";
            }
        }
        else
        {
            WatcherStatusText = "Unavailable — watcher not detected";
            DryRunText = "Unavailable";
        }

        OnPropertyChanged(nameof(IsCustomRuleRunning));
        OnPropertyChanged(nameof(CustomRuleToggleLabel));
    }

    /// <summary>Same threshold as AlertsViewModel.StaleHeartbeatSeconds, kept in sync deliberately
    /// -- both pages read the exact same watcher_runtime.json file and must never disagree about
    /// whether it's fresh.</summary>
    private const double StaleHeartbeatSeconds = 60;
}
