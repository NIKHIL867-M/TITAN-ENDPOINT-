using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Threading;
using TitanEndpoint.App.Common;

namespace TitanEndpoint.App.ViewModels;

public sealed class SystemHealthViewModel : ViewModelBase
{
    public ObservableCollection<SystemHealthRowViewModel> Rows { get; } = new();
    /// <summary>FORU.TXT 0.6 search. Refreshed every tick since rows are mutated in place by
    /// Refresh() rather than replaced -- ICollectionView's filter does not auto-rerun on property
    /// changes to existing items.</summary>
    public ICollectionView RowsView { get; }
    public RelayCommand CopyDiagnosticSummaryCommand { get; }

    private string _filterText = "";
    public string FilterText
    {
        get => _filterText;
        set { if (SetField(ref _filterText, value)) RowsView.Refresh(); }
    }

    private string _copyStatusText = "";
    public string CopyStatusText { get => _copyStatusText; private set => SetField(ref _copyStatusText, value); }

    /// <summary>Real fleet-wide events/sec (sum of every component's genuine RecordsWritten delta
    /// since the previous tick), 60 samples @ 1s -- the "Task Manager Performance tab" style live
    /// moving graph asked for in the GUI upgrade. Not a fabricated series: it is silent (flat at 0)
    /// whenever nothing is actually running, exactly like the real number would be.</summary>
    public ObservableCollection<double> ActivitySamples { get; } = new();

    private readonly DispatcherTimer _timer;
    private long? _lastTotalWritten;

    public SystemHealthViewModel()
    {
        foreach (var state in App.Fleet.Endpoints.Values)
            Rows.Add(new SystemHealthRowViewModel(state));

        RowsView = CollectionViewSource.GetDefaultView(Rows);
        RowsView.Filter = FilterPredicate;

        CopyDiagnosticSummaryCommand = new RelayCommand(CopyDiagnosticSummary);

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) =>
        {
            foreach (var r in Rows) r.Refresh();
            if (!string.IsNullOrWhiteSpace(FilterText)) RowsView.Refresh();
            RefreshActivitySample();
        };
        _timer.Start();
        foreach (var r in Rows) r.Refresh();
        // Seed two samples immediately (both honestly 0 -- no delta is knowable yet) rather than
        // leaving the graph completely blank for the ~2s it would otherwise take two real 1s ticks
        // to accumulate enough points to draw a line at all. Found live: VisualRegressionTests
        // captured this page ~900ms after navigating and the Fleet Activity panel was empty.
        RefreshActivitySample();
        RefreshActivitySample();
    }

    private void RefreshActivitySample()
    {
        long? total = null;
        foreach (var r in Rows)
        {
            if (r.WrittenCount is not { } written) continue;
            total = (total ?? 0) + written;
        }

        var rate = total is null || _lastTotalWritten is null || total < _lastTotalWritten
            ? 0.0 // no data yet, or a component restarted and its counter reset -- 0, not a bogus negative spike
            : total.Value - _lastTotalWritten.Value;
        _lastTotalWritten = total;

        ActivitySamples.Add(rate);
        while (ActivitySamples.Count > 60) ActivitySamples.RemoveAt(0);
    }

    private bool FilterPredicate(object obj)
    {
        if (string.IsNullOrWhiteSpace(FilterText)) return true;
        if (obj is not SystemHealthRowViewModel row) return true;
        var needle = FilterText.Trim();
        return row.Name.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.State.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.LastErrorSummary.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    private void CopyDiagnosticSummary()
    {
        var text = string.Join(Environment.NewLine, Rows.Select(r => r.DiagnosticLine));
        try
        {
            System.Windows.Clipboard.SetText(text);
            CopyStatusText = $"Copied {Rows.Count} rows to clipboard at {DateTime.Now:HH:mm:ss}.";
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            CopyStatusText = "Could not access the clipboard — try again.";
        }
    }
}
