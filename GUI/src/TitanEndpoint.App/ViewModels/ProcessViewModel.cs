using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;

namespace TitanEndpoint.App.ViewModels;

public sealed class ProcessViewModel : ViewModelBase
{
    public EndpointHeaderViewModel Header { get; }
    public ObservableCollection<ProcessRowViewModel> Rows { get; } = new();
    public ICollectionView RowsView { get; }
    public ProcessDetailViewModel Detail { get; }
    public RowActionsViewModel RowActions { get; } = new();

    private ProcessRowViewModel? _selectedRow;
    public ProcessRowViewModel? SelectedRow
    {
        get => _selectedRow;
        set
        {
            // Santosh, Round 22: "the new ones come and goes but still that thing should [stay] --
            // if I click on that specific I should need to see that specific detail." IncrementalRowSync
            // evicts the oldest row once the bounded window (maxRows) is exceeded; if that happens to
            // be the selected row, WPF's DataGrid resets its own SelectedItem to null, which flows back
            // here through the TwoWay binding and used to wipe the detail panel even though the user
            // never clicked away. Only a genuine new selection (non-null) should ever change it.
            if (value is null) return;
            if (SetField(ref _selectedRow, value)) Detail.Selected = value;
        }
    }

    private string _filterText = "";
    public string FilterText
    {
        get => _filterText;
        set { if (SetField(ref _filterText, value)) RowsView.Refresh(); }
    }

    private string _summaryText = "Waiting for data...";
    public string SummaryText { get => _summaryText; private set => SetField(ref _summaryText, value); }

    private readonly IncrementalRowSync<ProcessRowViewModel> _sync;
    private readonly DispatcherTimer _timer;

    public ProcessViewModel()
    {
        Header = new EndpointHeaderViewModel(EndpointId.Process, "Process and thread lifecycle activity");
        RowsView = CollectionViewSource.GetDefaultView(Rows);
        RowsView.Filter = FilterPredicate;
        Detail = new ProcessDetailViewModel(Rows);

        _sync = new IncrementalRowSync<ProcessRowViewModel>(Rows, maxRows: 3000, ProcessRowViewModel.From,
            filter: r => !r.IsCollectorHealth);

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(700) };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        Tick();
    }

    private bool FilterPredicate(object obj)
    {
        if (string.IsNullOrWhiteSpace(FilterText)) return true;
        if (obj is not ProcessRowViewModel row) return true;
        var needle = FilterText.Trim();
        return row.ProcessName.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.Path.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.User.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.Pid.ToString().Contains(needle)
            || row.CommandLine.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    private void Tick()
    {
        var snapshot = Header.State.Tailer.Records.Snapshot();
        _sync.Sync(snapshot);
        if (Detail.Selected is not null) Detail.Rebuild();

        // The native collector emits periodic point-in-time process_snapshot records, not discrete
        // process_start/process_stop lifecycle events -- "Action" (event_subtype) is always
        // "process_snapshot" in every real record observed, so counting "process_start"/"process_stop"
        // here was permanently stuck at zero regardless of real activity (confirmed live via
        // ProcessLiveTests: 305 real events, still "0 starts, 0 stops"). Distinct PID count is real,
        // always-populated data that actually reflects genuine session activity.
        var distinctProcesses = Rows.Select(r => r.Pid).Distinct().Count();
        SummaryText = Header.State.Tailer.ActiveFilePath is null
            ? "No active log file found for this endpoint yet."
            : $"{Rows.Count:N0} events in view (bounded) — {distinctProcesses:N0} distinct process(es) observed this session.";
    }
}
