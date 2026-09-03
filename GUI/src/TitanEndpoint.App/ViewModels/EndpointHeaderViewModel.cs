using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows.Media;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.Health;
using TitanEndpoint.Core.Models;
using TitanEndpoint.Core.ProcessControl;
using TitanEndpoint.App.Views;

namespace TitanEndpoint.App.ViewModels;

/// <summary>
/// The shared control-header pattern every endpoint page uses (spec section 5):
/// status badge, Monitoring/Save Logs, log path, session, rate, loss counters,
/// compact resource use. Self-ticking so pages just embed one of these.
/// </summary>
public sealed class EndpointHeaderViewModel : ViewModelBase
{
    public EndpointRuntimeState State { get; }
    public string DisplayName => State.Definition.DisplayName;
    public string ScopeDescription { get; }

    private string _statusBadgeText = "Detecting...";
    public string StatusBadgeText { get => _statusBadgeText; private set => SetField(ref _statusBadgeText, value); }

    private Brush _statusBadgeBrush = ThemeBrushes.Disabled;
    public Brush StatusBadgeBrush { get => _statusBadgeBrush; private set => SetField(ref _statusBadgeBrush, value); }

    /// <summary>FORU.TXT section 5's formal 9-state vocabulary, computed from the exact same
    /// inputs as StatusBadgeText/StatusBadgeBrush above (see HealthSnapshot.ClassifyLifecycle) --
    /// exposed so other views (System Health) can use one consistent classification instead of
    /// re-deriving their own text.</summary>
    private EndpointLifecycleState _lifecycleState = EndpointLifecycleState.Unavailable;
    public EndpointLifecycleState LifecycleState { get => _lifecycleState; private set => SetField(ref _lifecycleState, value); }

    private bool _wasRunningLastObserved;

    // FORU.TXT 0.2: "Replace the confusing single Monitoring toggle with three clearly named and
    // separately stateful controls: (1) START/STOP ENDPOINT controls the native process lifetime,
    // (2) MONITORING ON/PAUSE controls collection while the process remains alive, (3) SAVE LOGS
    // controls persistence without stopping live collection. Never use one toggle position to
    // represent both 'process exists' and 'collector is monitoring.'" MonitoringIsOn below now
    // ONLY ever calls the native StartMonitoring/StopMonitoring IPC command -- it never starts or
    // stops the OS process. StartStopCommand (new, below) is the only thing that does that.
    private bool _monitoringIsOn;
    public bool MonitoringIsOn
    {
        get => _monitoringIsOn;
        set
        {
            if (_monitoringIsOn == value) return;
            if (!CanToggleMonitoring) { OnPropertyChanged(); return; } // snap back — see CanToggleMonitoring
            _monitoringIsOn = value;
            OnPropertyChanged();
            ApplyMonitoringToggle(value);
        }
    }

    /// <summary>Monitoring can only be paused/resumed while the process is actually alive and
    /// reachable over its control channel — there is nothing to pause otherwise. Bound to the
    /// control's IsEnabled so the reason a control is greyed out is always structural, never a
    /// silent no-op (FORU.TXT 0.2: "Disable Monitoring and Save Logs only when the endpoint
    /// process is stopped/unreachable, and explain why").</summary>
    public bool CanToggleMonitoring => IsRunning && HasControlChannel && !IsBusy;

    public string MonitoringDisabledReason =>
        !IsRunning ? "Start the endpoint first — there is nothing to monitor while it is stopped."
        : !HasControlChannel ? "This endpoint has no authenticated control channel configured."
        : "";

    private bool _isRunning;
    public bool IsRunning { get => _isRunning; private set => SetField(ref _isRunning, value); }

    /// <summary>FORU.TXT 0.2 control #1: process lifetime only. One button whose label/action
    /// flips with IsRunning, so there is exactly one place that starts or stops the OS process —
    /// MonitoringIsOn's setter above deliberately never does.</summary>
    public RelayCommand StartStopCommand { get; }
    public string StartStopButtonText => IsBusy
        ? (_pendingAction == "stop" ? "STOPPING…" : "STARTING…")
        : IsRunning ? "STOP ENDPOINT" : "START ENDPOINT";

    private bool _isBusy;
    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (!SetField(ref _isBusy, value)) return;
            OnPropertyChanged(nameof(StartStopButtonText));
            OnPropertyChanged(nameof(CanToggleMonitoring));
            OnPropertyChanged(nameof(MonitoringDisabledReason));
            // WPF ties Button.IsEnabled to ICommand.CanExecute via CommandManager.RequerySuggested,
            // which only fires implicitly on standard input events (keypress/mouseclick/focus
            // change) -- NOT on an arbitrary property change delivered through
            // Dispatcher.Invoke from a background Task.Run, which is exactly how StartStop()
            // clears IsBusy after Start()/Stop() returns. Without this explicit call, the Stop
            // button can be left stuck disabled indefinitely after a real state change with no
            // subsequent real input event to coincidentally trigger a global requery -- found
            // empirically 2026-08-03 live-testing Port/USB (Start succeeded, IsRunning/IsBusy were
            // both already correct, but the button stayed disabled). This affects every endpoint's
            // Start/Stop button equally; it happened to reproduce first on Port/USB purely because
            // of which background thread won the race in that run.
            StartStopCommand.RaiseCanExecuteChanged();
        }
    }

    /// <summary>Genuinely independent of Monitoring only when this endpoint's runtime manifest
    /// marks a real control channel implemented -- as of the FORU.TXT section 4 hardening pass,
    /// all 6 native endpoints have one (see each program's ipc_control_server.cpp) — otherwise
    /// falls back to the previous honest placeholder (mirrors Monitoring, since the collector has
    /// no way to persist-vs-not independently).</summary>
    private bool _saveLogsIsOn;
    public bool SaveLogsIsOn
    {
        get => HasControlChannel ? _saveLogsIsOn : _monitoringIsOn;
        set
        {
            if (!HasControlChannel || _saveLogsIsOn == value) return;
            _saveLogsIsOn = value;
            OnPropertyChanged();
            ApplySaveLogsToggle(value);
        }
    }

    private bool _saveLogsBusy;
    public bool SaveLogsBusy
    {
        get => _saveLogsBusy;
        private set
        {
            if (!SetField(ref _saveLogsBusy, value)) return;
            OnPropertyChanged(nameof(CanToggleSaveLogs));
        }
    }

    /// <summary>FORU.TXT 0.2: "Save Logs must be an enabled interactive control when native IPC is
    /// reachable. It must never be rendered disabled while the GUI simultaneously claims that
    /// independent persistence is supported." -- enabled whenever the process is running and has a
    /// control channel, exactly the same structural condition as Monitoring (both need a live IPC
    /// connection to mean anything), never additionally gated on Monitoring's own on/off state.</summary>
    public bool CanToggleSaveLogs => IsRunning && HasControlChannel && !SaveLogsBusy;

    public string SaveLogsNote => HasControlChannel
        ? "Independent of Monitoring via this endpoint's control channel — turning Save Logs off keeps live collection running but stops future disk writes. Retained evidence is never deleted."
        : "This collector writes evidence unconditionally while active. An independent Save Logs toggle is not implemented in the collector yet.";

    private bool HasControlChannel => State.Definition.ManifestControlChannelImplemented &&
        !string.IsNullOrEmpty(State.Definition.ManifestControlChannelName);

    private EndpointControlClient? _controlClient;
    private bool _controlStatusRefreshInFlight;

    private string _logPathText = "Unavailable";
    public string LogPathText { get => _logPathText; private set => SetField(ref _logPathText, value); }

    private string _sessionText = "Not running";
    public string SessionText { get => _sessionText; private set => SetField(ref _sessionText, value); }

    private string _eventsPerSecText = "Unavailable";
    public string EventsPerSecText { get => _eventsPerSecText; private set => SetField(ref _eventsPerSecText, value); }

    private string _queueText = "Unavailable";
    public string QueueText { get => _queueText; private set => SetField(ref _queueText, value); }

    private string _lossText = "Unavailable";
    public string LossText { get => _lossText; private set => SetField(ref _lossText, value); }

    private string _cpuText = "Unavailable";
    public string CpuText { get => _cpuText; private set => SetField(ref _cpuText, value); }

    private string _workingSetText = "Unavailable";
    public string WorkingSetText { get => _workingSetText; private set => SetField(ref _workingSetText, value); }

    public RelayCommand OpenFolderCommand { get; }
    public RelayCommand DetailsCommand { get; }
    public RelayCommand ShowDiagnosticsCommand { get; }

    private readonly DispatcherTimer _timer;
    private TimeSpan _lastCpuTime;
    private DateTime _lastCpuSampleUtc;
    private DiagnosticsWindow? _diagnosticsWindow;

    public event Action<string>? DetailsRequested;

    public EndpointHeaderViewModel(EndpointId id, string scopeDescription)
    {
        State = App.Fleet.Get(id);
        ScopeDescription = scopeDescription;

        OpenFolderCommand = new RelayCommand(OpenFolder, () => Directory.Exists(State.Definition.LogDirectory));
        DetailsCommand = new RelayCommand(ShowDetails);
        StartStopCommand = new RelayCommand(StartStop, () => !IsBusy);
        ShowDiagnosticsCommand = new RelayCommand(ShowDiagnostics);

        // Reuse the one EndpointControlClient EndpointRuntimeState already constructed for this
        // endpoint (also used by LogTailer's GetRecentEvents fallback) rather than opening a
        // second, redundant client pointed at the same pipe.
        if (HasControlChannel)
            _controlClient = State.ControlClient;

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => Refresh();
        _timer.Start();
        Refresh();
    }

    /// <summary>Threshold above which a last-seen health record is treated as stale rather than
    /// currently trustworthy (FORU.TXT section 6.5: "Never display an old watcher_runtime.json
    /// state as currently watching" — generalized here to every endpoint's health record, not
    /// just Custom Rule's watcher state).</summary>
    private const double StaleHealthThresholdSeconds = 45;

    /// <summary>"start" | "stop" | null — set while ApplyMonitoringToggle has an operation in
    /// flight, so Refresh() can show a real Requested/Stopping state instead of jumping straight
    /// to a guessed terminal state (FORU.TXT section 2.6: distinguish Requested/Starting/
    /// Stopping, not just Active/Stopped).</summary>
    private string? _pendingAction;

    /// <summary>FORU.TXT 6.6: "Associate health with the exact process session. Ignore health
    /// from a previous process or historical file when determining current runtime state."
    /// Latched to the first fresh health's session_id seen for the CURRENT tracked OS process
    /// instance (identified by Pid+StartTimeUtc, reset whenever that identity changes) — if a
    /// later health record shows a DIFFERENT session_id while still believed to be the same
    /// process, the file no longer describes the process the GUI is tracking (e.g. it restarted
    /// and reused the PID without the controller noticing), so it must not count as fresh.</summary>
    private string? _trackedSessionId;
    private int _trackedPid;
    private DateTime _trackedStartTimeUtc;

    private void Refresh()
    {
        State.RefreshProcessState();
        var running = State.IsRunning;
        var tailer = State.Tailer;
        HealthSnapshot? health = tailer.LastHealth is null ? null : HealthSnapshot.FromRecord(tailer.LastHealth);
        var healthAgeSeconds = health is null ? double.MaxValue : (DateTimeOffset.UtcNow - health.ObservedAtUtc).TotalSeconds;
        var healthIsFresh = healthAgeSeconds < StaleHealthThresholdSeconds;

        var sessionMismatch = false;
        if (running && State.Running is not null)
        {
            if (_trackedPid != State.Running.Pid || _trackedStartTimeUtc != State.Running.StartTimeUtc)
            {
                // A genuinely different process instance is now being tracked (fresh start, or a
                // restart the controller did notice) -- start over rather than comparing against
                // a session_id that belonged to whatever was tracked before.
                _trackedPid = State.Running.Pid;
                _trackedStartTimeUtc = State.Running.StartTimeUtc;
                _trackedSessionId = null;
            }

            if (healthIsFresh && !string.IsNullOrEmpty(health!.SessionId))
            {
                if (_trackedSessionId is null)
                {
                    _trackedSessionId = health.SessionId;
                }
                else if (_trackedSessionId != health.SessionId)
                {
                    // Health belongs to a session the GUI never started tracking as "current" --
                    // a previous process or a historical file, per 6.6. Never trust it as fresh.
                    healthIsFresh = false;
                    sessionMismatch = true;
                }
            }
        }
        else
        {
            _trackedPid = 0;
            _trackedStartTimeUtc = default;
            _trackedSessionId = null;
        }

        IsRunning = running;
        OnPropertyChanged(nameof(CanToggleMonitoring));
        OnPropertyChanged(nameof(CanToggleSaveLogs));
        OnPropertyChanged(nameof(MonitoringDisabledReason));
        OnPropertyChanged(nameof(StartStopButtonText));

        // For endpoints with authenticated IPC, process-running and collection-enabled are
        // deliberately different states. The next GetStatus refresh (RefreshControlChannelStatus)
        // supplies the native truth for a running+reachable endpoint; without a control channel,
        // or while stopped, there is nothing to poll, so this is display-only (the control itself
        // is disabled by CanToggleMonitoring in that case, never interactive).
        if (!HasControlChannel || !running)
        {
            _monitoringIsOn = running;
            OnPropertyChanged(nameof(MonitoringIsOn));
        }
        OnPropertyChanged(nameof(SaveLogsIsOn));

        StatusBadgeText = IsBusy && _pendingAction == "stop" ? "Stopping"
            : IsBusy && _pendingAction == "start" ? "Requested"
            : !running ? "Stopped"
            : health is null ? "Starting"
            : sessionMismatch ? "Degraded (health from a different process session)"
            : !healthIsFresh ? $"Degraded (heartbeat {healthAgeSeconds:0}s old)"
            : health.Status switch
            {
                HealthStatus.Healthy => "Active",
                HealthStatus.Degraded => "Degraded",
                HealthStatus.Failed => "Failed",
                _ => "Starting"
            };

        StatusBadgeBrush = !running ? ThemeBrushes.Disabled
            : health is null ? ThemeBrushes.Warning
            : !healthIsFresh ? ThemeBrushes.Warning
            : ThemeBrushes.ForHealth(health.Status);

        var isStopRequested = IsBusy && _pendingAction == "stop";
        LifecycleState = HealthSnapshot.ClassifyLifecycle(
            health, running, isStopRequested, _wasRunningLastObserved, healthAgeSeconds, StaleHealthThresholdSeconds);
        _wasRunningLastObserved = running;

        LogPathText = string.IsNullOrEmpty(State.Definition.LogDirectory) ? "Unavailable" : State.Definition.LogDirectory;

        if (running && State.Running is not null)
        {
            var duration = DateTime.UtcNow - State.Running.StartTimeUtc;
            SessionText = $"Started {State.Running.StartTimeUtc.ToLocalTime():HH:mm:ss} — running {Humanize(duration)}";
        }
        else
        {
            SessionText = "Not running";
        }

        EventsPerSecText = tailer.ActiveFilePath is null ? "Unavailable" : $"{tailer.EventsPerSecond:0.0} events/sec";
        QueueText = health is not null && health.Counters.TryGetValue("queue_depth", out var depth)
            ? health.Counters.TryGetValue("queue_capacity", out var cap)
                ? $"{depth:N0} / {cap:N0}"
                : $"{depth:N0}"
            : "Unavailable";

        if (health is not null)
        {
            var parts = new List<string>();
            foreach (var (key, label) in LossCounterLabels)
            {
                if (health.Counters.TryGetValue(key, out var v) && v > 0)
                    parts.Add($"{label}: {v:N0}");
            }
            LossText = parts.Count == 0 ? "No loss reported" : string.Join("  ", parts);
        }
        else
        {
            LossText = "Unavailable";
        }

        RefreshResourceUse(running);

        if (HasControlChannel && running) RefreshControlChannelStatus();
    }

    /// <summary>Fire-and-forget poll of the native control channel's real SetPersistence state
    /// (source of truth), rather than optimistically trusting the GUI's last toggle succeeded —
    /// FORU.TXT 4.6: "Show a pending state until the endpoint acknowledges each change."</summary>
    private void RefreshControlChannelStatus()
    {
        if (_controlStatusRefreshInFlight || _controlClient is null) return;
        _controlStatusRefreshInFlight = true;

        _ = Task.Run(async () =>
        {
            var response = await _controlClient.SendAsync("GetStatus", timeout: TimeSpan.FromSeconds(2));
            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                _controlStatusRefreshInFlight = false;
                if (!response.Reachable || !response.Ok) return;
                if (response.Root.TryGetProperty("monitoring_enabled", out var monitoring) &&
                    monitoring.ValueKind is JsonValueKind.True or JsonValueKind.False)
                {
                    var actualMonitoring = monitoring.ValueKind == JsonValueKind.True;
                    if (_monitoringIsOn != actualMonitoring)
                    {
                        _monitoringIsOn = actualMonitoring;
                        OnPropertyChanged(nameof(MonitoringIsOn));
                    }
                }
                if (response.Root.TryGetProperty("save_logs_enabled", out var sle) &&
                    (sle.ValueKind == JsonValueKind.True || sle.ValueKind == JsonValueKind.False))
                {
                    var actual = sle.ValueKind == JsonValueKind.True;
                    if (_saveLogsIsOn != actual)
                    {
                        _saveLogsIsOn = actual;
                        OnPropertyChanged(nameof(SaveLogsIsOn));
                    }
                    // Tell the tailer the real native truth so it knows when to fall back to
                    // polling GetRecentEvents instead of the (in that state, non-growing) JSONL
                    // file -- see LogTailer.SaveLogsIsOff.
                    State.Tailer.SaveLogsIsOff = !actual;
                }
            });
        });
    }

    private void ApplySaveLogsToggle(bool turnOn)
    {
        if (_controlClient is null || SaveLogsBusy) return;
        SaveLogsBusy = true;
        Task.Run(async () =>
        {
            var response = await _controlClient.SendRevisionedAsync("SetPersistence", new { enabled = turnOn });
            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                SaveLogsBusy = false;
                if (!response.Ok)
                {
                    // Roll back — the endpoint didn't acknowledge the change (FORU.TXT 4.6).
                    _saveLogsIsOn = !turnOn;
                    OnPropertyChanged(nameof(SaveLogsIsOn));
                    DetailsRequested?.Invoke(response.Reachable
                        ? $"Save Logs change was not acknowledged: {response.Error ?? "unknown error"}"
                        : $"Could not reach the control channel: {response.TransportError}");
                }
            });
        });
    }

    private static readonly (string Key, string Label)[] LossCounterLabels =
    {
        ("queue_dropped", "Queue loss"), ("etw_events_lost", "Source loss"),
        ("etw_realtime_buffers_lost", "Buffer loss"), ("realtime_buffers_lost", "Buffer loss"),
        ("processing_errors", "Write failures"), ("watcher_buffer_overflow_count", "Overflow"),
        ("write_failures", "Write failures"), ("etw_buffers_lost", "Buffer loss"),
        ("capture_drops", "Capture loss"), ("interface_drops", "Interface loss"),
        ("logger_drops", "Logger loss"), ("logger_failures", "Logger failures"),
        ("storage_failures", "Storage failures"), ("raw_capture_failures", "Raw capture failures"),
        ("subscription_errors", "Subscription errors")
    };

    private void RefreshResourceUse(bool running)
    {
        if (!running || State.Running is null)
        {
            CpuText = "Unavailable";
            WorkingSetText = "Unavailable";
            _lastCpuTime = TimeSpan.Zero;
            return;
        }

        try
        {
            using var p = Process.GetProcessById(State.Running.Pid);
            WorkingSetText = FormatBytes(p.WorkingSet64);

            var now = DateTime.UtcNow;
            var cpuTime = p.TotalProcessorTime;
            if (_lastCpuTime != TimeSpan.Zero)
            {
                var cpuDelta = (cpuTime - _lastCpuTime).TotalMilliseconds;
                var wallDelta = (now - _lastCpuSampleUtc).TotalMilliseconds;
                if (wallDelta > 0)
                {
                    var pct = cpuDelta / wallDelta / Environment.ProcessorCount * 100.0;
                    CpuText = $"{pct:0.0}%";
                }
            }
            else
            {
                CpuText = "Sampling...";
            }
            _lastCpuTime = cpuTime;
            _lastCpuSampleUtc = now;
        }
        catch
        {
            CpuText = "Unavailable";
            WorkingSetText = "Unavailable";
        }
    }

    /// <summary>FORU.TXT 0.2 control #2: Monitoring pause/resume ONLY -- this method must never
    /// start or stop the OS process. It requires the process to already be running and reachable
    /// (CanToggleMonitoring gates the control itself, but this is checked again here since a
    /// command can still be in flight when the process state changes underneath it).</summary>
    private void ApplyMonitoringToggle(bool turnOn)
    {
        if (IsBusy || _controlClient is null) return;
        IsBusy = true;
        Task.Run(async () =>
        {
            State.RefreshProcessState();
            bool ok;
            string message;
            if (State.IsRunning)
            {
                var response = await _controlClient.SendRevisionedAsync(
                    turnOn ? "StartMonitoring" : "StopMonitoring");
                ok = response.Ok;
                message = response.Ok
                    ? (turnOn ? "Native collection resumed." : "Native collection paused; the endpoint process remains available for control and health.")
                    : response.Reachable
                        ? response.Error ?? "The endpoint rejected the monitoring change."
                        : response.TransportError ?? "The endpoint control channel is unreachable.";
            }
            else
            {
                ok = false;
                message = "The endpoint stopped before this change could be applied.";
            }
            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                IsBusy = false;
                if (!ok)
                {
                    // Roll back — the endpoint didn't acknowledge the change, matching
                    // ApplySaveLogsToggle's own rollback-on-rejection behavior.
                    _monitoringIsOn = !turnOn;
                    OnPropertyChanged(nameof(MonitoringIsOn));
                    DetailsRequested?.Invoke(message);
                }
                Refresh();
            });
        });
    }

    /// <summary>FORU.TXT 0.2 control #1: process lifetime only -- the ONLY place in this
    /// view-model that calls EndpointProcessController.Start()/Stop(). Never touches Monitoring
    /// or Save Logs state directly; RefreshControlChannelStatus() naturally picks up whatever the
    /// freshly-started native process reports once it's reachable (every collector defaults to
    /// monitoring_enabled=true at startup).</summary>
    private void StartStop()
    {
        if (IsBusy) return;
        var startingNow = !IsRunning;
        IsBusy = true;
        _pendingAction = startingNow ? "start" : "stop";
        Refresh(); // show Starting/Stopping immediately rather than waiting for Start()/Stop() to return
        Task.Run(() =>
        {
            var (ok, message) = startingNow ? State.Controller.Start() : State.Controller.Stop();
            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                IsBusy = false;
                _pendingAction = null;
                Refresh();
                if (!ok) DetailsRequested?.Invoke(message);
            });
        });
    }

    private void OpenFolder()
    {
        if (!Directory.Exists(State.Definition.LogDirectory)) return;
        Process.Start(new ProcessStartInfo { FileName = State.Definition.LogDirectory, UseShellExecute = true });
    }

    private void ShowDetails()
    {
        var def = State.Definition;
        var exe = def.ResolveExePath();
        var exists = File.Exists(exe);
        string version = "Unavailable";
        if (exists)
        {
            try { version = FileVersionInfo.GetVersionInfo(exe).FileVersion ?? "Unavailable"; }
            catch { /* leave Unavailable */ }
        }

        var manifestState = def.ValidateAgainstManifest();
        var manifestLine = manifestState switch
        {
            TitanEndpoint.Core.Manifest.ManifestValidationState.NotConfigured =>
                "No runtime-manifest.json entry for this component — path/build integrity is not verified.",
            TitanEndpoint.Core.Manifest.ManifestValidationState.Ok =>
                $"Verified against runtime-manifest.json — SHA-256 matches (manifest version: {def.ManifestVersion}).",
            TitanEndpoint.Core.Manifest.ManifestValidationState.HashMismatch =>
                $"MISMATCH: this executable's SHA-256 does not match runtime-manifest.json (expected {def.ManifestSha256}). This build will be refused on start.",
            TitanEndpoint.Core.Manifest.ManifestValidationState.FileMissing =>
                "The manifest-configured executable was not found on disk. This build will be refused on start.",
            _ => "Unavailable"
        };

        var text = $"Executable: {exe}\nFound: {exists}\nVersion: {version}\n" +
                   $"Requires elevation: {def.RequiresElevation}\nLog directory: {def.LogDirectory}\n" +
                   $"\nBuild manifest: {manifestLine}";
        DetailsRequested?.Invoke(text);
    }

    /// <summary>FORU.TXT 0.3: opens the bounded per-endpoint stdout/stderr Diagnostics panel. One
    /// live window per endpoint header — a second click while it's already open just brings the
    /// existing window forward rather than spawning a duplicate view over the same ring buffer.</summary>
    private void ShowDiagnostics()
    {
        if (_diagnosticsWindow is not null)
        {
            if (_diagnosticsWindow.WindowState == System.Windows.WindowState.Minimized)
                _diagnosticsWindow.WindowState = System.Windows.WindowState.Normal;
            _diagnosticsWindow.Activate();
            return;
        }

        var vm = new EndpointDiagnosticsViewModel(State.Definition.DisplayName, State.Diagnostics);
        _diagnosticsWindow = new DiagnosticsWindow(vm)
        {
            Owner = System.Windows.Application.Current.MainWindow
        };
        _diagnosticsWindow.Closed += (_, _) => _diagnosticsWindow = null;
        _diagnosticsWindow.Show();
    }

    private static string Humanize(TimeSpan t) =>
        t.TotalHours >= 1 ? $"{(int)t.TotalHours}h {t.Minutes}m" : $"{t.Minutes}m {t.Seconds}s";

    private static string FormatBytes(long bytes)
    {
        double b = bytes;
        string[] units = { "B", "KB", "MB", "GB" };
        var i = 0;
        while (b >= 1024 && i < units.Length - 1) { b /= 1024; i++; }
        return $"{b:0.#} {units[i]}";
    }
}
