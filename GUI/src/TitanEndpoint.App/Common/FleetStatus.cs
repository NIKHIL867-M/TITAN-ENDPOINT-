using System.Windows.Media;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.Health;

namespace TitanEndpoint.App.Common;

/// <summary>
/// Single shared "is the fleet Protected?" computation (FORU.TXT section 6.7 — "Protected"
/// requires every required endpoint running, FRESH and healthy; process detection is not a
/// heartbeat). Previously duplicated slightly differently between MainViewModel (top bar) and
/// OverviewViewModel (Overview page) — the two could disagree about the same fleet state. Now
/// both call this.
/// </summary>
public static class FleetStatus
{
    public const double StaleHealthThresholdSeconds = 45;

    public readonly struct Result
    {
        public string Text { get; init; }
        public Brush Brush { get; init; }
        public int RunningCount { get; init; }
        public int TotalCount { get; init; }
        public bool AnyStaleOrMissing { get; init; }
        public bool AnyDegraded { get; init; }
    }

    public static Result Compute(IReadOnlyList<EndpointId> ids, Core.Models.TitanFleet fleet)
    {
        var runningCount = ids.Count(id => fleet.Get(id).IsRunning);
        var staleOrMissing = false;
        var degraded = false;

        foreach (var id in ids)
        {
            var t = fleet.Get(id).Tailer;
            if (t.LastHealth is null) { staleOrMissing = true; continue; }
            var ageSeconds = (DateTimeOffset.UtcNow - t.LastHealth.ObservedAtUtc).TotalSeconds;
            if (t.LastHealth.IsSeedHistory || ageSeconds >= StaleHealthThresholdSeconds) { staleOrMissing = true; continue; }
            var status = HealthSnapshot.FromRecord(t.LastHealth).Status;
            if (status is HealthStatus.Degraded or HealthStatus.Failed) degraded = true;
        }

        var (text, brush) = runningCount switch
        {
            0 => ("Stopped", ThemeBrushes.Disabled),
            _ when runningCount < ids.Count => ("Partially Active", ThemeBrushes.Warning),
            _ when degraded => ("Degraded", ThemeBrushes.Warning),
            _ when staleOrMissing => ("Starting", ThemeBrushes.Warning),
            _ => ("Protected", ThemeBrushes.Healthy)
        };

        return new Result
        {
            Text = text,
            Brush = brush,
            RunningCount = runningCount,
            TotalCount = ids.Count,
            AnyStaleOrMissing = staleOrMissing,
            AnyDegraded = degraded
        };
    }
}
