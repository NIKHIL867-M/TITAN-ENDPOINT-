using System.Windows.Media;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Health;
using TitanEndpoint.Core.Models;

namespace TitanEndpoint.App.ViewModels;

/// <summary>One normalized health-schema-v2 row. Endpoint-specific legacy counters are used only
/// as a compatibility fallback; they are never added to v2 counters and double-counted.</summary>
public sealed class SystemHealthRowViewModel : ViewModelBase
{
    private const double StaleSeconds = 45;
    private readonly EndpointRuntimeState _state;
    private bool _wasRunning;
    public string Name => _state.Definition.DisplayName;

    private string _stateText = "Unavailable";
    public string State { get => _stateText; private set => SetField(ref _stateText, value); }
    private Brush _stateBrush = ThemeBrushes.Disabled;
    public Brush StateBrush { get => _stateBrush; private set => SetField(ref _stateBrush, value); }
    private string _heartbeat = "Unavailable";
    public string Heartbeat { get => _heartbeat; private set => SetField(ref _heartbeat, value); }
    private string _session = "Unavailable";
    public string Session { get => _session; private set => SetField(ref _session, value); }
    private string _received = "Unavailable";
    public string Received { get => _received; private set => SetField(ref _received, value); }
    private string _written = "Unavailable";
    public string Written { get => _written; private set => SetField(ref _written, value); }
    /// <summary>Same figure as <see cref="Written"/>, kept as a real number (not a formatted
    /// string) so the fleet-wide activity graph can sum it across components each tick.</summary>
    public long? WrittenCount { get; private set; }
    private string _queue = "Unavailable";
    public string Queue { get => _queue; private set => SetField(ref _queue, value); }
    private string _dropped = "Unavailable";
    public string Dropped { get => _dropped; private set => SetField(ref _dropped, value); }
    private string _retained = "Unavailable";
    public string Retained { get => _retained; private set => SetField(ref _retained, value); }
    private string _pressure = "Unavailable";
    public string Pressure { get => _pressure; private set => SetField(ref _pressure, value); }
    private string _evidenceGap = "Unavailable";
    public string EvidenceGap { get => _evidenceGap; private set => SetField(ref _evidenceGap, value); }
    private string _restartCount = "Unavailable";
    public string RestartCount { get => _restartCount; private set => SetField(ref _restartCount, value); }
    private string _lastErrorSummary = "Unavailable";
    public string LastErrorSummary { get => _lastErrorSummary; private set => SetField(ref _lastErrorSummary, value); }

    public SystemHealthRowViewModel(EndpointRuntimeState state) => _state = state;

    public string DiagnosticLine =>
        $"{Name}: state={State}, heartbeat={Heartbeat}, session={Session}, seen={Received}, written={Written}, " +
        $"queue={Queue}, dropped={Dropped}, retained={Retained}, pressure={Pressure}, " +
        $"evidence_gap={EvidenceGap}, restarts={RestartCount}, errors={LastErrorSummary}";

    public void Refresh()
    {
        _state.RefreshProcessState();
        var running = _state.IsRunning;
        var record = _state.Tailer.LastHealth;
        var snapshot = record is null ? null : HealthSnapshot.FromRecord(record);
        var age = snapshot is null ? double.MaxValue :
            Math.Max(0, (DateTimeOffset.UtcNow - snapshot.ObservedAtUtc).TotalSeconds);
        var lifecycle = HealthSnapshot.ClassifyLifecycle(snapshot, running, false, _wasRunning, age, StaleSeconds);
        _wasRunning = running;

        State = lifecycle.ToString();
        StateBrush = lifecycle switch
        {
            EndpointLifecycleState.Healthy => ThemeBrushes.Healthy,
            EndpointLifecycleState.Degraded or EndpointLifecycleState.Stale or
                EndpointLifecycleState.Starting or EndpointLifecycleState.Stopping => ThemeBrushes.Warning,
            EndpointLifecycleState.Crashed or EndpointLifecycleState.IncompatibleSchema => ThemeBrushes.Critical,
            _ => ThemeBrushes.Disabled
        };

        if (snapshot is null)
        {
            Heartbeat = running ? "Waiting for first heartbeat" : "Unavailable";
            Session = running && _state.Running is not null ? $"pid {_state.Running.Pid}" : "Unavailable";
            Received = Written = Queue = Dropped = Retained = Pressure = EvidenceGap = RestartCount = LastErrorSummary = "Unavailable";
            WrittenCount = null;
            return;
        }

        Heartbeat = $"{age:0}s ago";
        Session = string.IsNullOrWhiteSpace(snapshot.SessionId)
            ? (snapshot.Pid is > 0 ? $"pid {snapshot.Pid}" : "Not reported")
            : $"{Shorten(snapshot.SessionId, 24)} / pid {snapshot.Pid?.ToString() ?? "?"}";
        var legacySeen = FirstCounter(snapshot, "events_processed", "submitted_events", "logged");
        Received = FormatCount(snapshot.RecordsSeen ?? legacySeen);
        Written = FormatCount(snapshot.RecordsWritten);
        WrittenCount = snapshot.RecordsWritten;
        Queue = snapshot.QueueDepth is null ? "Unavailable" : snapshot.QueueCapacity is > 0
            ? $"{snapshot.QueueDepth:N0}/{snapshot.QueueCapacity:N0} (peak {snapshot.QueuePeak?.ToString("N0") ?? "?"})"
            : snapshot.QueueDepth.Value.ToString("N0");

        var normalizedLoss = SumNullable(snapshot.RecordsDropped, snapshot.SourceLoss,
            snapshot.ParseFailures, snapshot.WriterFailures);
        Dropped = normalizedLoss is null ? FormatCount(LegacyLoss(snapshot)) : normalizedLoss.Value.ToString("N0");
        Retained = snapshot.RetainedBytes is null ? "Unavailable" :
            $"{FormatBytes(snapshot.RetainedBytes.Value)} / {snapshot.RetainedFiles?.ToString("N0") ?? "?"} files";
        Pressure = snapshot.ResourcePressure ?? "Not reported";
        EvidenceGap = snapshot.EvidenceGap || normalizedLoss is > 0 ? "Yes" : "No";
        RestartCount = snapshot.Counters.TryGetValue("restart_count", out var restarts)
            ? restarts.ToString("N0") : "Not reported";

        var failures = new List<string>();
        if (!string.IsNullOrWhiteSpace(snapshot.LastError)) failures.Add(snapshot.LastError);
        if (snapshot.SourceLoss is > 0) failures.Add($"source loss {snapshot.SourceLoss:N0}");
        if (snapshot.ParseFailures is > 0) failures.Add($"parse failures {snapshot.ParseFailures:N0}");
        if (snapshot.WriterFailures is > 0) failures.Add($"writer failures {snapshot.WriterFailures:N0}");
        LastErrorSummary = failures.Count == 0 ? "No error reported" : string.Join("; ", failures);
    }

    private static long? FirstCounter(HealthSnapshot snapshot, params string[] names)
    {
        foreach (var name in names)
            if (snapshot.Counters.TryGetValue(name, out var value)) return value;
        return null;
    }

    private static long LegacyLoss(HealthSnapshot snapshot)
    {
        foreach (var name in new[] { "queue_dropped", "etw_events_lost", "capture_drops", "logger_drops" })
            if (snapshot.Counters.TryGetValue(name, out var value) && value > 0) return value;
        return 0;
    }

    private static long? SumNullable(params long?[] values) => values.All(value => value is null)
        ? null : values.Sum(value => value ?? 0);
    private static string FormatCount(long? value) => value?.ToString("N0") ?? "Unavailable";
    private static string Shorten(string value, int max) => value.Length <= max ? value : value[..max] + "...";
    private static string FormatBytes(long bytes)
    {
        double value = bytes;
        string[] units = { "B", "KiB", "MiB", "GiB", "TiB" };
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1) { value /= 1024; unit++; }
        return $"{value:0.#} {units[unit]}";
    }
}
