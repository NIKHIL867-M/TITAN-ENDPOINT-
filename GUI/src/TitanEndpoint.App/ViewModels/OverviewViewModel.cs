using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.Json;

namespace TitanEndpoint.App.ViewModels;

public sealed class OverviewViewModel : ViewModelBase
{
    private static readonly EndpointId[] CoreFive =
    {
        EndpointId.Process, EndpointId.Network, EndpointId.Application, EndpointId.File, EndpointId.Port
    };

    public ObservableCollection<EndpointCardViewModel> Cards { get; } = new();
    public ObservableCollection<ActivityItemViewModel> RecentActivity { get; } = new();

    private string _overallStateText = "Detecting...";
    public string OverallStateText { get => _overallStateText; private set => SetField(ref _overallStateText, value); }

    private string _activeEndpointsText = "0/5";
    public string ActiveEndpointsText { get => _activeEndpointsText; private set => SetField(ref _activeEndpointsText, value); }

    private string _eventsThisSessionText = "0";
    public string EventsThisSessionText { get => _eventsThisSessionText; private set => SetField(ref _eventsThisSessionText, value); }

    private string _alertsSummaryText = "0 alerts";
    public string AlertsSummaryText { get => _alertsSummaryText; private set => SetField(ref _alertsSummaryText, value); }

    private string _totalRamText = "Unavailable";
    public string TotalRamText { get => _totalRamText; private set => SetField(ref _totalRamText, value); }

    private double _ramFraction;
    /// <summary>Real fraction of this machine's total physical RAM that TITAN's own running
    /// processes are using -- drives the Overview page's animated RAM radial gauge (Santosh,
    /// 2026-08-04: "animated live pie graph that should be indicating that RAM number"). Denominator
    /// is <see cref="GC.GetGCMemoryInfo"/>'s TotalAvailableMemoryBytes -- the real installed physical
    /// memory, already exposed by the BCL, no P/Invoke or new dependency needed.</summary>
    public double RamFraction { get => _ramFraction; private set => SetField(ref _ramFraction, value); }

    private static readonly long TotalSystemRamBytes = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;

    private string _diskUsageText = "Unavailable";
    public string DiskUsageText { get => _diskUsageText; private set => SetField(ref _diskUsageText, value); }

    private double _diskBudgetFraction;
    /// <summary>Real disk-usage-of-budget fraction (can exceed 1.0 if over budget) -- drives the
    /// Resource Usage panel's radial gauge. GUI-upgrade ask: "circle graph ... anything that fits".</summary>
    public double DiskBudgetFraction { get => _diskBudgetFraction; private set => SetField(ref _diskBudgetFraction, value); }

    private string _droppedEventsText = "0";
    public string DroppedEventsText { get => _droppedEventsText; private set => SetField(ref _droppedEventsText, value); }

    public ObservableCollection<double> DiskSamples { get; } = new();

    /// <summary>FORU.TXT section 7.2: "Label sparklines and counters by their real sampling
    /// window and source" — describes exactly what DiskSamples actually is.</summary>
    public string DiskSampleWindowText => "Disk: last 60 samples @ 5s — sum of Process/Network/Application/File/Port/Correlator log directories";

    private readonly DispatcherTimer _fastTimer;
    private readonly DispatcherTimer _slowTimer;
    private long _diskUsageBytes;

    public OverviewViewModel()
    {
        Cards.Add(new EndpointCardViewModel(EndpointId.Process, AppPage.Process));
        Cards.Add(new EndpointCardViewModel(EndpointId.Network, AppPage.Network));
        Cards.Add(new EndpointCardViewModel(EndpointId.Application, AppPage.Applications));
        Cards.Add(new EndpointCardViewModel(EndpointId.File, AppPage.Files));
        Cards.Add(new EndpointCardViewModel(EndpointId.Port, AppPage.PortUsb));

        _fastTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(1) };
        _fastTimer.Tick += (_, _) => FastTick();
        _fastTimer.Start();

        _slowTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(5) };
        _slowTimer.Tick += (_, _) => SlowTick();
        _slowTimer.Start();

        FastTick();
        SlowTick();
    }

    private string _overallStateNote = "";
    public string OverallStateNote { get => _overallStateNote; private set => SetField(ref _overallStateNote, value); }

    private void FastTick()
    {
        foreach (var card in Cards) card.Refresh();

        // Shared with MainViewModel's top-bar state (Common.FleetStatus) so the two can never
        // disagree about the same fleet — FORU.TXT 6.7: "Protected" needs fresh health, not
        // just process detection.
        var fleetStatus = Common.FleetStatus.Compute(CoreFive, App.Fleet);
        ActiveEndpointsText = $"{fleetStatus.RunningCount}/{CoreFive.Length}";
        OverallStateText = fleetStatus.Text;
        OverallStateNote = fleetStatus.AnyStaleOrMissing
            ? "One or more endpoints has no fresh heartbeat yet."
            : fleetStatus.AnyDegraded ? "One or more endpoints reports degraded health." : "";

        // "Current session" only — TotalLinesRead already excludes the seed-from-tail read of
        // pre-existing content (FORU.TXT 7.1/7.6: never let historical records affect
        // current-session counters; see LogTailer.IsSeedHistory).
        var totalEvents = CoreFive.Sum(id => App.Fleet.Get(id).Tailer.TotalLinesRead);
        EventsThisSessionText = totalEvents.ToString("N0");

        long dropped = 0;
        foreach (var id in CoreFive)
        {
            var health = App.Fleet.Get(id).Tailer.LastHealth;
            if (health is null) continue;
            dropped += health.GetLong("queue_dropped") ?? 0;
        }
        DroppedEventsText = dropped.ToString("N0");

        RefreshAlertsSummary();
        RefreshTimeline();
        RefreshRam();
    }

    private void RefreshAlertsSummary()
    {
        var alertsTailer = App.Fleet.Get(EndpointId.CustomRule).Tailer;
        var snapshot = alertsTailer.Records.Snapshot();
        if (snapshot.Length == 0)
        {
            AlertsSummaryText = alertsTailer.DirectoryExists ? "0 alerts (recent)" : "Unavailable";
            return;
        }

        var bySeverity = snapshot
            .GroupBy(r => r.GetString("severity") ?? "unknown")
            .ToDictionary(g => g.Key, g => g.Count());

        AlertsSummaryText = string.Join("  ", bySeverity.Select(kv => $"{kv.Key}: {kv.Value}"));
    }

    private void RefreshTimeline()
    {
        var items = new List<ActivityItemViewModel>();
        foreach (var id in CoreFive)
        {
            var state = App.Fleet.Get(id);
            var recent = state.Tailer.Records.Snapshot();
            var take = recent.Length > 12 ? recent[^12..] : recent;
            foreach (var r in take)
            {
                if (r.IsCollectorHealth) continue;
                var (type, entity) = Summarize(id, r);
                items.Add(new ActivityItemViewModel
                {
                    TimeUtc = r.EventTimeUtc,
                    EndpointIcon = state.Definition.IconGlyph,
                    EndpointName = state.Definition.DisplayName,
                    EventType = type,
                    MainEntity = entity,
                    RawJson = r.RawLine
                });
            }
        }

        var ordered = items.OrderByDescending(i => i.TimeUtc).Take(40).ToList();
        RecentActivity.Clear();
        foreach (var item in ordered) RecentActivity.Add(item);
    }

    private static (string type, string entity) Summarize(EndpointId id, JsonRecord r) => id switch
    {
        EndpointId.Process => (
            r.GetString("event_type") ?? "event",
            r.GetString("process_name") is { } pn ? $"{pn} (pid {r.GetLong("pid")})" : "unknown process"),
        EndpointId.Network => (
            r.GetString("protocol") ?? "packet",
            $"{r.GetString("process_name")} → {r.GetString("remote_ip")}:{r.GetLong("remote_port")}"),
        EndpointId.Application => (
            r.GetString("type") ?? r.GetString("action") ?? "event",
            r.GetString("application") ?? Path.GetFileName(r.GetString("path") ?? string.Empty)),
        EndpointId.File => (
            r.GetString("action") ?? "file event",
            Path.GetFileName(r.GetString("path") ?? "unknown")),
        EndpointId.Port => (
            r.GetString("type") ?? "usb event",
            r.GetString("device") ?? r.GetString("endpoint") ?? "device"),
        _ => ("event", string.Empty)
    };

    private void RefreshRam()
    {
        long totalWorkingSet = 0;
        foreach (var id in CoreFive.Append(EndpointId.Correlator))
        {
            var running = App.Fleet.Get(id).Running;
            if (running is null) continue;
            try
            {
                using var p = Process.GetProcessById(running.Pid);
                totalWorkingSet += p.WorkingSet64;
            }
            catch { /* process exited between check and read */ }
        }

        TotalRamText = totalWorkingSet == 0 ? "Unavailable" : FormatBytes(totalWorkingSet);
        RamFraction = TotalSystemRamBytes > 0 ? totalWorkingSet / (double)TotalSystemRamBytes : 0;
    }

    private void SlowTick()
    {
        long total = 0;
        foreach (var id in CoreFive.Append(EndpointId.Correlator))
        {
            var dir = App.Fleet.Get(id).Definition.LogDirectory;
            total += SafeDirectorySize(dir);
        }
        _diskUsageBytes = total;

        var budget = App.Fleet.Settings.GlobalDiskBudgetBytes;
        DiskUsageText = $"{FormatBytes(total)} of {FormatBytes(budget)} budget";
        DiskBudgetFraction = budget > 0 ? total / (double)budget : 0;
        PushSample(DiskSamples, total / (1024.0 * 1024.0));
    }

    /// <summary>Internal (not private) so MainViewModel's top-bar budget readout can reuse the exact
    /// same real directory-size computation instead of duplicating it -- the top bar needs this
    /// figure globally (every page), not just while the Overview page instance happens to exist.</summary>
    internal static long SafeDirectorySize(string dir)
    {
        if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return 0;
        try
        {
            return Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly)
                .Sum(f => { try { return new FileInfo(f).Length; } catch { return 0L; } });
        }
        catch { return 0; }
    }

    private static void PushSample(ObservableCollection<double> samples, double value)
    {
        samples.Add(value);
        while (samples.Count > 60) samples.RemoveAt(0);
    }

    private static string FormatBytes(long bytes)
    {
        double b = bytes;
        string[] units = { "B", "KB", "MB", "GB" };
        var i = 0;
        while (b >= 1024 && i < units.Length - 1) { b /= 1024; i++; }
        return $"{b:0.#} {units[i]}";
    }
}
