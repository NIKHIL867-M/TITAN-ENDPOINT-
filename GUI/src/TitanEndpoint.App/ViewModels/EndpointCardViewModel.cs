using System.Windows.Media;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.Health;
using TitanEndpoint.Core.Models;

namespace TitanEndpoint.App.ViewModels;

/// <summary>One card in the Overview's endpoint status grid — always reads live state, never cached fakes.</summary>
public sealed class EndpointCardViewModel : ViewModelBase
{
    private readonly EndpointRuntimeState _state;
    public string DisplayName => _state.Definition.DisplayName;
    public string IconGlyph { get; }
    public AppPage TargetPage { get; }

    private string _statusText = "Detecting...";
    public string StatusText { get => _statusText; private set => SetField(ref _statusText, value); }

    private Brush _statusBrush = ThemeBrushes.Disabled;
    public Brush StatusBrush { get => _statusBrush; private set => SetField(ref _statusBrush, value); }

    private string _loggingText = "Unavailable";
    public string LoggingText { get => _loggingText; private set => SetField(ref _loggingText, value); }

    private string _lastHeartbeatText = "Unavailable";
    public string LastHeartbeatText { get => _lastHeartbeatText; private set => SetField(ref _lastHeartbeatText, value); }

    private string _eventRateText = "Unavailable";
    public string EventRateText { get => _eventRateText; private set => SetField(ref _eventRateText, value); }

    private string _keyMetricText = string.Empty;
    public string KeyMetricText { get => _keyMetricText; private set => SetField(ref _keyMetricText, value); }

    private string _degradedReasonText = string.Empty;
    public string DegradedReasonText { get => _degradedReasonText; private set => SetField(ref _degradedReasonText, value); }

    public bool HasDegradedReason => !string.IsNullOrEmpty(DegradedReasonText);

    public EndpointCardViewModel(EndpointId id, AppPage targetPage)
    {
        _state = App.Fleet.Get(id);
        IconGlyph = _state.Definition.IconGlyph;
        TargetPage = targetPage;
    }

    public void Refresh()
    {
        _state.RefreshProcessState();
        var running = _state.IsRunning;
        var tailer = _state.Tailer;
        HealthSnapshot? health = tailer.LastHealth is null ? null : HealthSnapshot.FromRecord(tailer.LastHealth);

        if (!running)
        {
            StatusText = "Stopped";
            StatusBrush = ThemeBrushes.Disabled;
            LoggingText = "Off";
            LastHeartbeatText = "Unavailable";
            EventRateText = "Unavailable";
            DegradedReasonText = string.Empty;
        }
        else
        {
            StatusText = health?.Status switch
            {
                HealthStatus.Healthy => "Active",
                HealthStatus.Degraded => "Degraded",
                HealthStatus.Failed => "Failed",
                _ => "Starting"
            };
            StatusBrush = ThemeBrushes.ForEndpointDot(true, health?.Status ?? HealthStatus.Unknown);
            LoggingText = tailer.ActiveFilePath is null ? "Starting" : "On";
            LastHeartbeatText = health is null ? "Waiting for first heartbeat" : Humanize(health.ObservedAtUtc);
            EventRateText = tailer.ActiveFilePath is null ? "Unavailable" : $"{tailer.EventsPerSecond:0.0} events/sec";

            DegradedReasonText = health is { EvidenceGap: true }
                ? "Evidence gap reported by the collector"
                : health?.Status == HealthStatus.Degraded
                    ? "Collector reports degraded status"
                    : string.Empty;
        }

        OnPropertyChanged(nameof(HasDegradedReason));
    }

    private static string Humanize(DateTimeOffset t)
    {
        var age = DateTimeOffset.UtcNow - t;
        if (age.TotalSeconds < 60) return $"{(int)age.TotalSeconds}s ago";
        if (age.TotalMinutes < 60) return $"{(int)age.TotalMinutes}m ago";
        return $"{(int)age.TotalHours}h ago";
    }
}
