using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows.Data;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;

namespace TitanEndpoint.App.ViewModels;

public sealed class ApplicationsViewModel : ViewModelBase
{
    public EndpointHeaderViewModel Header { get; }
    public ObservableCollection<ApplicationRowViewModel> Rows { get; } = new();
    public ICollectionView RowsView { get; }
    public ObservableCollection<ApplicationSummaryRowViewModel> ObservedApplications { get; } = new();
    public ApplicationWatchlistViewModel Watchlist { get; }
    public ApplicationCatalogViewModel Catalog { get; }
    public RowActionsViewModel RowActions { get; } = new();

    private string _filterText = "";
    public string FilterText
    {
        get => _filterText;
        set { if (SetField(ref _filterText, value)) RowsView.Refresh(); }
    }

    private string _summaryText = "Waiting for data...";
    public string SummaryText { get => _summaryText; private set => SetField(ref _summaryText, value); }

    private readonly IncrementalRowSync<ApplicationRowViewModel> _sync;
    private readonly DispatcherTimer _timer;

    public ApplicationsViewModel()
    {
        Header = new EndpointHeaderViewModel(EndpointId.Application, "Installed and running application activity");
        Watchlist = new ApplicationWatchlistViewModel(Header.State.Definition);
        Catalog = new ApplicationCatalogViewModel(Watchlist, Header.State.Definition);
        RowsView = CollectionViewSource.GetDefaultView(Rows);
        RowsView.Filter = FilterPredicate;

        _sync = new IncrementalRowSync<ApplicationRowViewModel>(Rows, maxRows: 4000, ApplicationRowViewModel.From,
            filter: r => !r.IsCollectorHealth);

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(700) };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        Tick();
    }

    private bool FilterPredicate(object obj)
    {
        if (string.IsNullOrWhiteSpace(FilterText)) return true;
        if (obj is not ApplicationRowViewModel row) return true;
        var needle = FilterText.Trim();
        return row.Application.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.Path.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.Action.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    private void Tick()
    {
        var snapshot = Header.State.Tailer.Records.Snapshot();
        _sync.Sync(snapshot);

        var distinctApps = Rows.Select(r => r.Application).Where(a => !string.IsNullOrEmpty(a)).Distinct().Count();
        SummaryText = Header.State.Tailer.ActiveFilePath is null
            ? "No active log file found for this endpoint yet."
            : $"{distinctApps:N0} applications observed, {Rows.Count:N0} events in view (bounded).";

        // One syscall-backed process enumeration per tick, shared by every app below, rather than
        // calling Process.GetProcessesByName per app (up to 30x more expensive per tick for no
        // benefit) -- Santosh, 2026-08-04: "it even has to show ... which are currently running."
        var runningNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Process.GetProcesses())
        {
            try { runningNames.Add(p.ProcessName); } finally { p.Dispose(); }
        }

        // Real cross-reference against the Network endpoint's own tailer, joined by pid -- same
        // GUI-side correlation approach ProcessDetailViewModel already uses for "Related Evidence",
        // applied here to give genuine per-application inbound/outbound bytes and remote-endpoint
        // counts from the Network collector's real packet-derived counters, complementing the
        // Application collector's own coarser point-in-time socket-table snapshot.
        var networkRecords = App.Fleet.Get(EndpointId.Network).Tailer.Records.Snapshot();

        var grouped = Rows.Where(r => !string.IsNullOrEmpty(r.Application))
            .GroupBy(r => r.Application)
            .Select(g =>
            {
                var pids = g.Select(r => r.Pid).Where(p => p > 0).ToHashSet();
                var netMatches = pids.Count == 0
                    ? Array.Empty<TitanEndpoint.Core.Json.JsonRecord>()
                    : networkRecords.Where(n => !n.IsCollectorHealth &&
                        n.GetLong("pid") is { } p && pids.Contains(p)).ToArray();

                var exeBase = System.IO.Path.GetFileNameWithoutExtension(g.Key);
                return new ApplicationSummaryRowViewModel
                {
                    Application = g.Key!,
                    EventCount = g.Count(),
                    LastSeen = g.Max(r => r.Time) ?? "",
                    IsCurrentlyRunning = !string.IsNullOrEmpty(exeBase) && runningNames.Contains(exeBase),
                    NetworkBytesSent = netMatches.Sum(n => n.GetLong("bytes_sent") ?? 0),
                    NetworkBytesRecv = netMatches.Sum(n => n.GetLong("bytes_recv") ?? 0),
                    DistinctRemoteEndpoints = netMatches
                        .Select(n => $"{n.GetString("remote_ip")}:{n.GetLong("remote_port")}")
                        .Where(s => s != ":0" && s != ":" && !string.IsNullOrWhiteSpace(s))
                        .Distinct().Count()
                };
            })
            .OrderByDescending(a => a.EventCount)
            .Take(30)
            .ToList();

        ObservedApplications.Clear();
        foreach (var g in grouped) ObservedApplications.Add(g);
    }
}
