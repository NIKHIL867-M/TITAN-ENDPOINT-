using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;

namespace TitanEndpoint.App.ViewModels;

public sealed class FilesViewModel : ViewModelBase
{
    public EndpointHeaderViewModel Header { get; }
    public HashToolViewModel HashTool { get; } = new();
    public ObservableCollection<FileRowViewModel> Rows { get; } = new();
    public ICollectionView RowsView { get; }
    public RowActionsViewModel RowActions { get; } = new();

    private string _filterText = "";
    public string FilterText
    {
        get => _filterText;
        set { if (SetField(ref _filterText, value)) RowsView.Refresh(); }
    }

    private string _summaryText = "Waiting for data...";
    public string SummaryText { get => _summaryText; private set => SetField(ref _summaryText, value); }

    private readonly IncrementalRowSync<FileRowViewModel> _sync;
    private readonly DispatcherTimer _timer;

    public FilesViewModel()
    {
        Header = new EndpointHeaderViewModel(EndpointId.File, "Temporary activity and file integrity");
        RowsView = CollectionViewSource.GetDefaultView(Rows);
        RowsView.Filter = FilterPredicate;

        _sync = new IncrementalRowSync<FileRowViewModel>(Rows, maxRows: 4000, FileRowViewModel.From,
            filter: r => !r.IsCollectorHealth);

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(700) };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        Tick();
    }

    private bool FilterPredicate(object obj)
    {
        if (string.IsNullOrWhiteSpace(FilterText)) return true;
        if (obj is not FileRowViewModel row) return true;
        var needle = FilterText.Trim();
        return row.Path.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.Process.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.Operation.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    private void Tick()
    {
        var snapshot = Header.State.Tailer.Records.Snapshot();
        _sync.Sync(snapshot);

        var temp = Rows.Count(r => r.Category == "Temporary");
        var normal = Rows.Count - temp;
        SummaryText = Header.State.Tailer.ActiveFilePath is null
            ? "No active log file found for this endpoint yet."
            : $"{Rows.Count:N0} events in view — {normal:N0} normal, {temp:N0} temporary (bounded).";
    }
}
