using System.Collections.ObjectModel;
using System.Windows.Media;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.CustomRule;
using TitanEndpoint.Core.Health;
using TitanEndpoint.Core.Manifest;
using TitanEndpoint.Core.Models;
using TitanEndpoint.Core.Preflight;

namespace TitanEndpoint.App.ViewModels;

public sealed class MainViewModel : ViewModelBase
{
    private static readonly EndpointId[] CoreFive =
    {
        EndpointId.Process, EndpointId.Network, EndpointId.Application, EndpointId.File, EndpointId.Port
    };

    /// <summary>Dependency-ordered Start All sequence (FORU.TXT section 3.1) — Stop All runs
    /// this reversed, plus Custom Rule's two sub-processes stopped first.</summary>
    private static readonly (EndpointId Id, string Name)[] NativeStartOrder =
    {
        (EndpointId.Process, "Process"), (EndpointId.File, "Files"), (EndpointId.Network, "Network"),
        (EndpointId.Port, "Port / USB"), (EndpointId.Application, "Applications"),
        (EndpointId.Correlator, "Correlator")
    };

    private readonly CustomRuleServiceController _customRuleController;
    /// <summary>Santosh, Round 22: Custom Rule needs its own Start/Stop, not just the bundled
    /// global Start All/Stop All. Exposed so CustomRulesViewModel drives the exact same controller
    /// instance Start All/Stop All already use, instead of a second instance that would lose track
    /// of the real process (this codebase's documented history of duplicate-controller PID/token
    /// mismatches when Custom Rule is launched outside the one proven path).</summary>
    internal CustomRuleServiceController CustomRuleController => _customRuleController;

    public ObservableCollection<NavItemViewModel> NavItems { get; } = new();

    private NavItemViewModel? _selectedNavItem;
    public NavItemViewModel? SelectedNavItem
    {
        get => _selectedNavItem;
        set
        {
            if (_selectedNavItem == value) return;
            if (_selectedNavItem is not null) _selectedNavItem.IsSelected = false;
            _selectedNavItem = value;
            if (_selectedNavItem is not null) _selectedNavItem.IsSelected = true;
            OnPropertyChanged();
            if (value is not null) SetCurrentPage(value.Page);
        }
    }

    private AppPage _currentPage;
    public AppPage CurrentPage
    {
        get => _currentPage;
        private set => SetField(ref _currentPage, value);
    }

    public event Action<AppPage>? NavigateRequested;

    private void SetCurrentPage(AppPage page)
    {
        CurrentPage = page;
        var (title, desc) = PageMeta(page);
        PageTitle = title;
        PageDescription = desc;
        BottomContextEndpoint = page switch
        {
            AppPage.Process => EndpointId.Process,
            AppPage.Network => EndpointId.Network,
            AppPage.Applications => EndpointId.Application,
            AppPage.Files => EndpointId.File,
            AppPage.PortUsb => EndpointId.Port,
            AppPage.Correlation => EndpointId.Correlator,
            AppPage.CorrelationGraph => EndpointId.Correlator,
            AppPage.IncidentGraph => EndpointId.Correlator,
            AppPage.StixExport => EndpointId.Correlator,
            _ => null
        };
        NavigateRequested?.Invoke(page);
    }

    private static (string title, string desc) PageMeta(AppPage page) => page switch
    {
        AppPage.Overview => ("Overview", "Command centre for all TITAN endpoints"),
        AppPage.Process => ("Process", "Process and thread lifecycle activity"),
        AppPage.Network => ("Network", "Live packet and flow capture"),
        AppPage.Applications => ("Applications", "Installed and running application activity"),
        AppPage.Files => ("Files", "Temporary activity and file integrity"),
        AppPage.PortUsb => ("Port / USB", "Physical port and USB device activity"),
        AppPage.Correlation => ("Correlation", "Cross-endpoint evidence graph"),
        AppPage.CorrelationGraph => ("Correlation Graph", "Live endpoint-to-endpoint connection flow"),
        AppPage.IncidentGraph => ("Incident Graph", "Every real correlated incident, one full page"),
        AppPage.StixExport => ("STIX Export", "Convert correlated incidents into STIX 2.1 for OpenCTI"),
        AppPage.CustomRules => ("Custom Rules", "Rule authoring, dry-run and response"),
        AppPage.Alerts => ("Alerts and Evidence", "Matched rules and recorded evidence"),
        AppPage.UnifiedLogs => ("Unified Logs", "Every collector's evidence in one catalogue"),
        AppPage.SystemHealth => ("System Health", "Stage-by-stage pipeline health"),
        AppPage.Settings => ("Settings", "Endpoint paths, retention and privacy"),
        _ => (page.ToString(), string.Empty)
    };

    private string _pageTitle = "Overview";
    public string PageTitle { get => _pageTitle; private set => SetField(ref _pageTitle, value); }

    private string _pageDescription = string.Empty;
    public string PageDescription { get => _pageDescription; private set => SetField(ref _pageDescription, value); }

    // ---- Top command bar ----
    private string _systemStateText = "Detecting...";
    public string SystemStateText { get => _systemStateText; private set => SetField(ref _systemStateText, value); }

    private Brush _systemStateBrush = ThemeBrushes.Disabled;
    public Brush SystemStateBrush { get => _systemStateBrush; private set => SetField(ref _systemStateBrush, value); }

    private string _activeEndpointsText = "0/5";
    public string ActiveEndpointsText { get => _activeEndpointsText; private set => SetField(ref _activeEndpointsText, value); }

    private string _loggingText = "0 endpoints writing logs";
    public string LoggingText { get => _loggingText; private set => SetField(ref _loggingText, value); }

    private string _clockText = string.Empty;
    public string ClockText { get => _clockText; private set => SetField(ref _clockText, value); }

    private string _diskBudgetText = "";
    /// <summary>Moved here from the Overview-only Resource Usage panel so it is visible on every
    /// page, in the same top bar as Start All/Stop All -- GUI-upgrade ask. Refreshed on its own
    /// slower timer (directory-size scanning is real I/O, not worth doing every 1s).</summary>
    public string DiskBudgetText { get => _diskBudgetText; private set => SetField(ref _diskBudgetText, value); }

    // ---- Bottom status bar (contextual to the selected endpoint page, if any) ----
    private EndpointId? BottomContextEndpoint;

    private string _bottomRateText = "Unavailable";
    public string BottomRateText { get => _bottomRateText; private set => SetField(ref _bottomRateText, value); }

    private string _bottomDroppedText = "Unavailable";
    public string BottomDroppedText { get => _bottomDroppedText; private set => SetField(ref _bottomDroppedText, value); }

    private string _bottomLogPathText = "Unavailable";
    public string BottomLogPathText { get => _bottomLogPathText; private set => SetField(ref _bottomLogPathText, value); }

    private string _bottomLogSizeText = "Unavailable";
    public string BottomLogSizeText { get => _bottomLogSizeText; private set => SetField(ref _bottomLogSizeText, value); }

    private string _bottomLastWriteText = "Unavailable";
    public string BottomLastWriteText { get => _bottomLastWriteText; private set => SetField(ref _bottomLastWriteText, value); }

    // ---- Start All / Stop All ----
    public ObservableCollection<StartAllRowViewModel> StartAllRows { get; } = new();

    private bool _isStartAllOverlayVisible;
    public bool IsStartAllOverlayVisible { get => _isStartAllOverlayVisible; set => SetField(ref _isStartAllOverlayVisible, value); }

    public RelayCommand StartAllCommand { get; }
    public RelayCommand StopAllCommand { get; }
    public RelayCommand CloseOverlayCommand { get; }

    // ---- Preflight (FORU.TXT section 3) ----
    public ObservableCollection<PreflightRowViewModel> PreflightResults { get; } = new();

    private bool _isPreflightOverlayVisible;
    public bool IsPreflightOverlayVisible { get => _isPreflightOverlayVisible; set => SetField(ref _isPreflightOverlayVisible, value); }

    private string _preflightSummaryText = "";
    public string PreflightSummaryText { get => _preflightSummaryText; private set => SetField(ref _preflightSummaryText, value); }

    public RelayCommand RunPreflightCommand { get; }
    public RelayCommand ClosePreflightOverlayCommand { get; }

    // ---- Santosh, 2026-08-31: "just add button on dark and light... no restart for that." A
    // one-click top-bar toggle -- App.RestartWithTheme saves the flip and relaunches TITAN itself
    // (see that method's own doc comment for why a true live, no-relaunch swap is not safe to do
    // here), so nothing is required of the user beyond this single click. ----
    public string ThemeToggleLabel => App.Fleet.Settings.UseLightTheme ? "Switch to Dark Mode" : "Switch to Light Mode";
    public RelayCommand ToggleThemeCommand { get; }

    private readonly DispatcherTimer _timer;

    public MainViewModel()
    {
        NavItems.Add(new NavItemViewModel(AppPage.Overview, "Overview", "▦"));
        NavItems.Add(new NavItemViewModel(AppPage.Process, "Process", "▣", EndpointId.Process));
        NavItems.Add(new NavItemViewModel(AppPage.Network, "Network", "◈", EndpointId.Network));
        NavItems.Add(new NavItemViewModel(AppPage.Applications, "Applications", "▢", EndpointId.Application));
        NavItems.Add(new NavItemViewModel(AppPage.Files, "Files", "▤", EndpointId.File));
        NavItems.Add(new NavItemViewModel(AppPage.PortUsb, "Port / USB", "■", EndpointId.Port));
        // Santosh, 2026-08-31: "there are 2 pages, correlation and correlation graph... merge these
        // 2 into 1." The standalone "Correlation" nav item is gone -- its grid+investigation-tabs
        // content now lives embedded (compact, collapsible) inside CorrelationGraphView itself. The
        // AppPage.Correlation enum value and its view-switch case are left in place, unused but
        // harmless, rather than torn out along with every place that references it.
        NavItems.Add(new NavItemViewModel(AppPage.CorrelationGraph, "Correlation Graph", "⬡", EndpointId.Correlator));
        NavItems.Add(new NavItemViewModel(AppPage.IncidentGraph, "Incident Graph", "❖", EndpointId.Correlator));
        NavItems.Add(new NavItemViewModel(AppPage.StixExport, "STIX Export", "⇄", EndpointId.Correlator));
        NavItems.Add(new NavItemViewModel(AppPage.CustomRules, "Custom Rules", "◆"));
        NavItems.Add(new NavItemViewModel(AppPage.Alerts, "Alerts & Evidence", "▲"));
        NavItems.Add(new NavItemViewModel(AppPage.UnifiedLogs, "Unified Logs", "≡"));
        NavItems.Add(new NavItemViewModel(AppPage.SystemHealth, "System Health", "♥"));
        NavItems.Add(new NavItemViewModel(AppPage.Settings, "Settings", "⚙"));

        var customRuleRoot = System.IO.Path.GetDirectoryName(App.Fleet.Settings.CustomRuleDataDirectory) ?? "";
        var apiClient = new CustomRuleApiClient(App.Fleet.Settings.CustomRuleApiBaseUrl, App.Fleet.Settings.CustomRuleDataDirectory);
        _customRuleController = new CustomRuleServiceController(
            customRuleRoot, apiClient, App.Fleet.Settings.RuntimeCorrelatorConfigPath,
            App.Fleet.Get(EndpointId.Correlator).Definition.LogDirectory);

        StartAllCommand = new RelayCommand(async () => await RunStartAllAsync());
        StopAllCommand = new RelayCommand(async () => await RunStopAllAsync());
        CloseOverlayCommand = new RelayCommand(() => IsStartAllOverlayVisible = false);

        RunPreflightCommand = new RelayCommand(RunPreflight);
        ClosePreflightOverlayCommand = new RelayCommand(() => IsPreflightOverlayVisible = false);
        ToggleThemeCommand = new RelayCommand(() => App.RestartWithTheme(!App.Fleet.Settings.UseLightTheme));

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        Tick();

        _diskBudgetTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(5) };
        _diskBudgetTimer.Tick += (_, _) => RefreshDiskBudget();
        _diskBudgetTimer.Start();
        RefreshDiskBudget();

        SelectedNavItem = NavItems[0];
    }

    private void Tick()
    {
        App.Fleet.RefreshAllProcessStates();
        foreach (var item in NavItems) item.RefreshStatus();

        var fleetStatus = FleetStatus.Compute(CoreFive, App.Fleet);
        ActiveEndpointsText = $"{fleetStatus.RunningCount}/{CoreFive.Length}";
        LoggingText = fleetStatus.RunningCount == 1 ? "1 endpoint writing logs" : $"{fleetStatus.RunningCount} endpoints writing logs";
        SystemStateText = fleetStatus.Text;
        SystemStateBrush = fleetStatus.Brush;

        ClockText = $"{DateTime.Now:HH:mm:ss} local  •  {DateTime.UtcNow:HH:mm:ss} UTC";

        RefreshBottomBar();
    }

    private readonly DispatcherTimer _diskBudgetTimer;

    private void RefreshDiskBudget()
    {
        long total = 0;
        foreach (var id in CoreFive.Append(EndpointId.Correlator))
            total += OverviewViewModel.SafeDirectorySize(App.Fleet.Get(id).Definition.LogDirectory);

        var budget = App.Fleet.Settings.GlobalDiskBudgetBytes;
        DiskBudgetText = $"Disk: {FormatBytes(total)} of {FormatBytes(budget)} budget";
    }

    private void RefreshBottomBar()
    {
        if (BottomContextEndpoint is null)
        {
            BottomRateText = "Unavailable";
            BottomDroppedText = "Unavailable";
            BottomLogPathText = "Unavailable";
            BottomLogSizeText = "Unavailable";
            BottomLastWriteText = "Unavailable";
            return;
        }

        var state = App.Fleet.Get(BottomContextEndpoint.Value);
        var t = state.Tailer;

        BottomRateText = t.ActiveFilePath is null ? "Unavailable" : $"{t.EventsPerSecond:0.0} events/sec";
        BottomLogPathText = string.IsNullOrEmpty(t.Definition.LogDirectory) ? "Unavailable" : t.Definition.LogDirectory;
        BottomLogSizeText = t.ActiveFilePath is null ? "Unavailable" : FormatBytes(t.ActiveFileSizeBytes);
        BottomLastWriteText = t.ActiveFileLastWriteUtc is null
            ? "Unavailable"
            : $"{t.ActiveFileLastWriteUtc.Value.ToLocalTime():HH:mm:ss}";

        if (t.LastHealth is not null)
        {
            var snap = HealthSnapshot.FromRecord(t.LastHealth);
            var dropped = snap.Counters.TryGetValue("queue_dropped", out var qd) ? qd : (long?)null;
            BottomDroppedText = dropped is null ? "Unavailable" : dropped.Value.ToString("N0");
        }
        else
        {
            BottomDroppedText = "Unavailable";
        }
    }

    private static string FormatBytes(long bytes)
    {
        double b = bytes;
        string[] units = { "B", "KB", "MB", "GB" };
        var i = 0;
        while (b >= 1024 && i < units.Length - 1) { b /= 1024; i++; }
        return $"{b:0.#} {units[i]}";
    }

    /// <summary>FORU.TXT section 3: "Add a preflight command that verifies executable hashes,
    /// Npcap/driver availability, Python/.venv, configuration files, administrator rights,
    /// log-directory writability, and free disk space." Every result is a real, independently
    /// re-checkable fact about this machine right now (see PreflightService) -- never a cached
    /// or assumed value.</summary>
    private void RunPreflight()
    {
        PreflightResults.Clear();
        var results = PreflightService.Run(App.Fleet.Settings);
        foreach (var r in results) PreflightResults.Add(new PreflightRowViewModel(r));

        var blocking = results.Count(r => !r.Passed && r.Severity == PreflightSeverity.Blocking);
        var warnings = results.Count(r => !r.Passed && r.Severity == PreflightSeverity.Warning);
        PreflightSummaryText = blocking > 0
            ? $"{blocking} blocking issue(s), {warnings} warning(s) -- resolve blocking issues before Start All."
            : warnings > 0
                ? $"No blocking issues. {warnings} warning(s) -- review before Start All."
                : "All preflight checks passed.";

        IsPreflightOverlayVisible = true;
    }

    private async Task RunStartAllAsync()
    {
        StartAllRows.Clear();
        var rows = new List<StartAllRowViewModel>();

        foreach (var (id, name) in NativeStartOrder)
        {
            StartAllRowViewModel row = null!;
            row = new StartAllRowViewModel(name, () => StartNativeStepAsync(id, row));
            rows.Add(row);
        }
        StartAllRowViewModel apiRow = null!;
        apiRow = new StartAllRowViewModel("Custom Rule API", () => StartCustomRuleApiStepAsync(apiRow));
        StartAllRowViewModel watcherRow = null!;
        watcherRow = new StartAllRowViewModel("Custom Rule Watcher", () => StartCustomRuleWatcherStepAsync(watcherRow));
        rows.Add(apiRow);
        rows.Add(watcherRow);

        foreach (var r in rows) StartAllRows.Add(r);
        IsStartAllOverlayVisible = true;

        // Sequential and dependency-ordered. StartNativeStepAsync applies a hard readiness
        // gate for Correlator, so Failed/Degraded is never treated as source readiness.
        for (var i = 0; i < NativeStartOrder.Length; i++)
            await StartNativeStepAsync(NativeStartOrder[i].Id, rows[i]);

        await StartCustomRuleApiStepAsync(apiRow);
        await StartCustomRuleWatcherStepAsync(watcherRow);
    }

    private async Task StartNativeStepAsync(EndpointId id, StartAllRowViewModel row)
    {
        // Santosh: found live -- RequiredSourcesReady used to be a single
        // instantaneous check. Under real load (e.g. File endpoint briefly
        // degraded/backlogged right as Correlator's turn came up), a sensor's
        // very first health record can legitimately land a few seconds late
        // -- and since this ran exactly once, that transient timing miss
        // permanently skipped starting the Correlator for the whole Start
        // All cycle, with no retry, even though every source became ready
        // moments later. Poll for the same real condition instead of
        // checking it once, same pattern WaitForRunning/WaitForFreshHealth
        // already use below for the analogous per-endpoint waits.
        if (id == EndpointId.Correlator)
        {
            row.Status = "Waiting for sensor sources";
            // Santosh, 2026-08-31: "when i click start all the endpoints are started and correlation
            // and then custom rule are failed... when i went to correlation page and clicked it then
            // it start" -- the textbook signature of a timeout budget just slightly too tight, not a
            // logic bug: all 5 sensors DO come up, Correlator's own real process starts fine too, but
            // this outer gate requires EVERY sensor's health to be simultaneously fresh (see
            // RequiredSourcesReady) at the moment it checks, and by the time the 5th sensor
            // (elevation-dependent, e.g. Port/USB enumerating devices, or Npcap init on Network) has
            // JUST become healthy, 45s of real wall-clock time had often already elapsed waiting for
            // the earlier sensors' own 20s-process + up-to-45s-heartbeat sequential steps ahead of it.
            // DependentPipelineReady (Custom Rule's own gate) checks RequiredSourcesReady too, so this
            // single race cascades into both rows failing together, exactly as reported. 90s gives
            // real cold-start variance (ETW/Npcap driver init, disk contention) enough margin without
            // masking a genuinely dead sensor forever.
            var sourcesReady = await Task.Run(() => WaitForRequiredSources(TimeSpan.FromSeconds(90)));
            if (!sourcesReady)
            {
                RequiredSourcesReady(out var dependencyError);
                row.Status = "Failed — required sensor sources are not ready";
                row.DetailText = dependencyError;
                return;
            }
        }

        var state = App.Fleet.Get(id);
        var requestedAtUtc = DateTime.UtcNow;

        row.Status = "Validating";
        row.DetailText = "";
        await Task.Delay(100);

        var manifestState = state.Definition.ValidateAgainstManifest();
        if (manifestState is ManifestValidationState.HashMismatch or ManifestValidationState.FileMissing)
        {
            row.Status = "Failed — build validation";
            row.DetailText = manifestState == ManifestValidationState.HashMismatch
                ? $"Executable at {state.Definition.ResolveExePath()} does not match runtime-manifest.json's recorded SHA-256."
                : $"Manifest-configured executable was not found at {state.Definition.ResolveExePath()}.";
            return;
        }

        if (!state.IsRunning)
        {
            row.Status = "Starting";
            var (ok, message) = await Task.Run(() => state.Controller.Start());
            if (!ok)
            {
                row.Status = "Failed — start error";
                row.DetailText = message;
                return;
            }

            row.Status = "Waiting for process";
            var becameRunning = await Task.Run(() => WaitForRunning(state, TimeSpan.FromSeconds(20)));
            if (!becameRunning)
            {
                row.Status = "Failed — no process detected within 20s";
                row.DetailText = "The process never appeared after launch. Check Endpoint Details for the resolved executable path and elevation prompt.";
                return;
            }
        }

        // Process detection is not a heartbeat (3.4) — wait for a genuinely new, live (not
        // seeded/historical) collector_health record before calling this endpoint ready.
        row.Status = "Waiting for heartbeat";
        var healthTimeout = TimeSpan.FromSeconds(Math.Max(10, state.Definition.ManifestHealthTimeoutSeconds));
        var becameHealthy = await Task.Run(() => WaitForFreshHealth(state, requestedAtUtc, healthTimeout));
        if (!becameHealthy)
        {
            row.Status = $"Degraded — running, no fresh heartbeat within {healthTimeout.TotalSeconds:0}s";
            row.DetailText = "The process is running but has not produced a current-session collector_health record yet.";
            return;
        }

        row.Status = id == EndpointId.Correlator
            ? $"Active ({NativeStartOrder.Take(NativeStartOrder.Length - 1).Count(o => App.Fleet.Get(o.Id).Tailer.LastHealth is { IsSeedHistory: false })}/{NativeStartOrder.Length - 1} sensor sources confirmed ready)"
            : "Active";
    }

    private async Task StartCustomRuleApiStepAsync(StartAllRowViewModel row)
    {
        if (!DependentPipelineReady(out var dependencyError))
        {
            row.Status = "Failed — evidence pipeline is not ready";
            row.DetailText = dependencyError;
            return;
        }

        row.Status = "Starting";
        row.DetailText = "";
        var (ok, message) = await _customRuleController.StartApiAsync();
        if (!ok)
        {
            row.Status = "Failed — start error";
            row.DetailText = message;
            return;
        }

        row.Status = "Waiting for readiness";
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(20);
        var ready = false;
        while (DateTime.UtcNow < deadline)
        {
            if (await _customRuleController.IsApiReadyAsync()) { ready = true; break; }
            await Task.Delay(500);
        }
        row.Status = ready ? "Active" : "Failed — API did not become reachable within 20s";
        if (!ready) row.DetailText = "Check CUSTOM RULE\\logs\\backend.log and whether GROQ_API_KEY is configured.";
    }

    private async Task StartCustomRuleWatcherStepAsync(StartAllRowViewModel row)
    {
        if (!DependentPipelineReady(out var dependencyError))
        {
            row.Status = "Failed — evidence pipeline is not ready";
            row.DetailText = dependencyError;
            return;
        }

        var requestedAtUtc = DateTime.UtcNow;
        row.Status = "Starting";
        row.DetailText = "";
        var (ok, message) = _customRuleController.StartWatcher();
        if (!ok)
        {
            row.Status = "Failed — start error";
            row.DetailText = message;
            return;
        }

        row.Status = "Waiting for readiness";
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(20);
        var ready = false;
        while (DateTime.UtcNow < deadline)
        {
            if (_customRuleController.IsWatcherReady(requestedAtUtc)) { ready = true; break; }
            await Task.Delay(500);
        }

        if (!ready)
        {
            row.Status = "Failed — watcher did not report readiness within 20s";
            row.DetailText = "Check CUSTOM RULE\\data\\watcher_runtime.json and the watcher process output.";
            return;
        }

        var dryRun = _customRuleController.IsDryRun();
        row.Status = dryRun ? "Active — Dry Run ON" : "Active — DRY RUN OFF (responses execute for real)";
    }

    private static bool WaitForRequiredSources(TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (RequiredSourcesReady(out _)) return true;
            Thread.Sleep(500);
        }
        return RequiredSourcesReady(out _);
    }

    private static bool WaitForRunning(EndpointRuntimeState state, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            state.RefreshProcessState();
            if (state.IsRunning) return true;
            Thread.Sleep(500);
        }
        return false;
    }

    private static bool WaitForFreshHealth(EndpointRuntimeState state, DateTime requestedAtUtc, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            var health = state.Tailer.LastHealth;
            if (health is not null && !health.IsSeedHistory && health.ObservedAtUtc.UtcDateTime >= requestedAtUtc)
                return true;
            Thread.Sleep(500);
        }
        return false;
    }

    private static bool RequiredSourcesReady(out string detail)
    {
        var failures = new List<string>();
        foreach (var id in CoreFive)
        {
            var state = App.Fleet.Get(id);
            state.RefreshProcessState();
            var health = state.Tailer.LastHealth;
            var timeout = Math.Max(10, state.Definition.ManifestHealthTimeoutSeconds);
            if (!state.IsRunning)
                failures.Add($"{state.Definition.DisplayName}: process is not running");
            else if (health is null || health.IsSeedHistory)
                failures.Add($"{state.Definition.DisplayName}: no current-session health record");
            else if ((DateTimeOffset.UtcNow - health.ObservedAtUtc).TotalSeconds > timeout)
                failures.Add($"{state.Definition.DisplayName}: heartbeat is stale");
        }

        detail = failures.Count == 0
            ? string.Empty
            : "Correlator was not started because required evidence sources are not ready:\n- " +
              string.Join("\n- ", failures);
        return failures.Count == 0;
    }

    private static bool DependentPipelineReady(out string detail)
    {
        if (!RequiredSourcesReady(out detail)) return false;
        var correlator = App.Fleet.Get(EndpointId.Correlator);
        correlator.RefreshProcessState();
        var health = correlator.Tailer.LastHealth;
        var timeout = Math.Max(10, correlator.Definition.ManifestHealthTimeoutSeconds);
        if (!correlator.IsRunning || health is null || health.IsSeedHistory ||
            (DateTimeOffset.UtcNow - health.ObservedAtUtc).TotalSeconds > timeout)
        {
            detail = "Custom Rule was not started because Correlator is not running with a fresh current-session heartbeat.";
            return false;
        }
        return true;
    }

    private async Task RunStopAllAsync()
    {
        StartAllRows.Clear();

        var watcherRow = new StartAllRowViewModel("Custom Rule Watcher");
        var apiRow = new StartAllRowViewModel("Custom Rule API");
        var reverseNative = NativeStartOrder.Reverse().ToArray();
        var nativeRows = reverseNative.Select(o => new StartAllRowViewModel(o.Name)).ToList();

        var rows = new List<StartAllRowViewModel> { watcherRow, apiRow };
        rows.AddRange(nativeRows);
        foreach (var r in rows) StartAllRows.Add(r);
        IsStartAllOverlayVisible = true;

        watcherRow.Status = "Stopping";
        var (wOk, wMsg) = await Task.Run(() => _customRuleController.StopWatcher());
        watcherRow.Status = wOk ? wMsg : "Failed — stop error";
        if (!wOk) watcherRow.DetailText = wMsg;

        apiRow.Status = "Stopping";
        var (aOk, aMsg) = await Task.Run(() => _customRuleController.StopApi());
        apiRow.Status = aOk ? aMsg : "Failed — stop error";
        if (!aOk) apiRow.DetailText = aMsg;

        for (var i = 0; i < reverseNative.Length; i++)
        {
            var (id, _) = reverseNative[i];
            var row = nativeRows[i];
            row.Status = "Stopping";
            var state = App.Fleet.Get(id);
            var (ok, message) = await Task.Run(() => state.Controller.Stop());
            row.Status = ok ? message : "Failed — stop error";
            if (!ok) row.DetailText = message;
        }

        // Santosh, 2026-08-27: reverted the Round 22 "Stop All also closes the GUI" behavior --
        // stopping the fleet should leave the window open with final per-row status visible (same
        // as Start All already does), not exit the application. The window's own close button
        // remains the only way to actually quit.
    }
}
