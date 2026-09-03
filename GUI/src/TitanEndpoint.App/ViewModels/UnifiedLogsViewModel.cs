using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows.Data;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Logs;

namespace TitanEndpoint.App.ViewModels;

public sealed class UnifiedLogsViewModel : ViewModelBase
{
    public ObservableCollection<LogCatalogRowViewModel> Rows { get; } = new();
    public ICollectionView RowsView { get; }
    public RelayCommand OpenFolderCommand { get; }
    public RelayCommand LoadNewestCommand { get; }
    public RelayCommand LoadOlderCommand { get; }
    public RelayCommand SearchQueryCommand { get; }
    public RelayCommand ExportLogsCommand { get; }
    public RelayCommand CancelQueryCommand { get; }
    public ObservableCollection<string> HistoryLines { get; } = new();

    private LogCatalogRowViewModel? _selectedEndpoint;
    public LogCatalogRowViewModel? SelectedEndpoint { get => _selectedEndpoint; set { if (SetField(ref _selectedEndpoint, value)) LoadNewest(); } }
    private string _historyStatus = "Select an endpoint to inspect bounded historical evidence.";
    public string HistoryStatus { get => _historyStatus; private set => SetField(ref _historyStatus, value); }
    private List<string> _archiveFiles = new();
    private int _archiveIndex;
    private long? _archiveCursor;
    private CancellationTokenSource? _queryCancellation;

    private string _querySearchText = "";
    public string QuerySearchText { get => _querySearchText; set => SetField(ref _querySearchText, value); }
    private string _queryEventType = "";
    public string QueryEventType { get => _queryEventType; set => SetField(ref _queryEventType, value); }
    private DateTime? _queryFromDate;
    public DateTime? QueryFromDate { get => _queryFromDate; set => SetField(ref _queryFromDate, value); }
    private DateTime? _queryToDate;
    public DateTime? QueryToDate { get => _queryToDate; set => SetField(ref _queryToDate, value); }
    private bool _queryAllEndpoints;
    public bool QueryAllEndpoints { get => _queryAllEndpoints; set => SetField(ref _queryAllEndpoints, value); }
    private string _queryMaxResults = "500";
    public string QueryMaxResults { get => _queryMaxResults; set => SetField(ref _queryMaxResults, value); }
    private bool _isQueryRunning;
    public bool IsQueryRunning
    {
        get => _isQueryRunning;
        private set
        {
            if (SetField(ref _isQueryRunning, value))
            {
                SearchQueryCommand.RaiseCanExecuteChanged();
                ExportLogsCommand.RaiseCanExecuteChanged();
                CancelQueryCommand.RaiseCanExecuteChanged();
            }
        }
    }

    private string _filterText = "";
    public string FilterText
    {
        get => _filterText;
        set { if (SetField(ref _filterText, value)) RowsView.Refresh(); }
    }

    private string _diskPressureText = "Unavailable";
    public string DiskPressureText { get => _diskPressureText; private set => SetField(ref _diskPressureText, value); }

    private readonly DispatcherTimer _timer;
    private readonly long _globalDiskBudgetBytes;

    public UnifiedLogsViewModel()
    {
        foreach (var state in App.Fleet.Endpoints.Values)
            Rows.Add(new LogCatalogRowViewModel(state));

        RowsView = CollectionViewSource.GetDefaultView(Rows);
        RowsView.Filter = FilterPredicate;
        _globalDiskBudgetBytes = App.Fleet.Settings.GlobalDiskBudgetBytes;

        OpenFolderCommand = new RelayCommand(param =>
        {
            if (param is not LogCatalogRowViewModel row) return;
            if (!Directory.Exists(row.LogDirectoryPath)) return;
            Process.Start(new ProcessStartInfo { FileName = row.LogDirectoryPath, UseShellExecute = true });
        });
        LoadNewestCommand = new RelayCommand(LoadNewest);
        LoadOlderCommand = new RelayCommand(LoadOlder);
        SearchQueryCommand = new RelayCommand(() => _ = SearchHistoricalAsync(), () => !IsQueryRunning);
        ExportLogsCommand = new RelayCommand(() => _ = ExportHistoricalAsync(), () => !IsQueryRunning);
        CancelQueryCommand = new RelayCommand(() => _queryCancellation?.Cancel(), () => IsQueryRunning);

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(2) };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        Tick();
    }

    private void LoadNewest(object? _ = null)
    {
        HistoryLines.Clear(); _archiveFiles.Clear(); _archiveIndex = 0; _archiveCursor = null;
        if (SelectedEndpoint is null || !Directory.Exists(SelectedEndpoint.LogDirectoryPath))
        { HistoryStatus = "No readable log directory is selected."; return; }
        try
        {
            foreach (var pattern in SelectedEndpoint.LogFilePattern.Split(';', StringSplitOptions.RemoveEmptyEntries))
                _archiveFiles.AddRange(Directory.EnumerateFiles(SelectedEndpoint.LogDirectoryPath, pattern));
            _archiveFiles = _archiveFiles.Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(File.GetLastWriteTimeUtc).ToList();
            LoadOlder();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { HistoryStatus = $"Archive enumeration failed: {ex.Message}"; }
    }

    private void LoadOlder(object? _ = null)
    {
        while (_archiveIndex < _archiveFiles.Count)
        {
            try
            {
                var path = _archiveFiles[_archiveIndex];
                var page = TitanEndpoint.Core.Logs.PagedLogReader.ReadPageBackward(path, _archiveCursor, 100);
                foreach (var line in page.Lines) HistoryLines.Add(line);
                _archiveCursor = page.NextCursor;
                HistoryStatus = $"{HistoryLines.Count:N0} bounded record(s) loaded; source {Path.GetFileName(path)}. Newest-first, 100 records per page.";
                if (_archiveCursor is null) { _archiveIndex++; _archiveCursor = null; }
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { _archiveIndex++; _archiveCursor = null; HistoryStatus = $"Skipped unreadable archive: {ex.Message}"; }
        }
        HistoryStatus = _archiveFiles.Count == 0 ? "No retained archives match this endpoint's configured pattern." : "Reached the oldest retained evidence.";
    }

    private bool FilterPredicate(object obj)
    {
        if (string.IsNullOrWhiteSpace(FilterText)) return true;
        return obj is LogCatalogRowViewModel row &&
            row.EndpointName.Contains(FilterText.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    private IReadOnlyList<string> QueryDirectories()
    {
        var candidates = QueryAllEndpoints
            ? Rows.Select(row => row.LogDirectoryPath)
            : SelectedEndpoint is null ? Array.Empty<string>() : new[] { SelectedEndpoint.LogDirectoryPath };
        return candidates.Where(Directory.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private (DateTimeOffset? From, DateTimeOffset? To) QueryRange()
    {
        static DateTimeOffset LocalMidnight(DateTime value)
        {
            var local = DateTime.SpecifyKind(value.Date, DateTimeKind.Unspecified);
            return new DateTimeOffset(local, TimeZoneInfo.Local.GetUtcOffset(local)).ToUniversalTime();
        }
        return (QueryFromDate is null ? null : LocalMidnight(QueryFromDate.Value),
            QueryToDate is null ? null : LocalMidnight(QueryToDate.Value.AddDays(1)));
    }

    private int ResultLimit() => int.TryParse(QueryMaxResults, out var parsed)
        ? Math.Clamp(parsed, 1, 10_000) : 500;

    private async Task SearchHistoricalAsync()
    {
        var directories = QueryDirectories();
        if (directories.Count == 0)
        {
            HistoryStatus = QueryAllEndpoints
                ? "No readable endpoint log directories are available."
                : "Select an endpoint, or enable All endpoints, before searching.";
            return;
        }

        _queryCancellation?.Dispose();
        _queryCancellation = new CancellationTokenSource();
        var ct = _queryCancellation.Token;
        IsQueryRunning = true;
        HistoryStatus = $"Searching {directories.Count} endpoint log director{(directories.Count == 1 ? "y" : "ies")}...";
        try
        {
            var range = QueryRange();
            var query = new LogQuery
            {
                From = range.From,
                To = range.To,
                SearchTerm = string.IsNullOrWhiteSpace(QuerySearchText) ? null : QuerySearchText.Trim(),
                EventType = string.IsNullOrWhiteSpace(QueryEventType) ? null : QueryEventType.Trim(),
                MaxResults = ResultLimit()
            };
            var result = await Task.Run(() => query.Execute(directories, ct), ct);
            HistoryLines.Clear();
            foreach (var record in result.Records) HistoryLines.Add(record.RawJson);
            HistoryStatus = $"{result.Records.Count:N0} result(s), {result.ArchivesScanned:N0} archive(s) scanned" +
                (result.Truncated ? $"; stopped at the {ResultLimit():N0}-record UI bound" : "") +
                $". Skipped: {result.MalformedLineCount:N0} malformed, {result.PartialWriteCount:N0} partial/blank, {result.ParseFailureCount:N0} unreadable.";
        }
        catch (OperationCanceledException)
        {
            HistoryStatus = "Historical search cancelled.";
        }
        finally
        {
            IsQueryRunning = false;
        }
    }

    private async Task ExportHistoricalAsync()
    {
        var directories = QueryDirectories();
        if (directories.Count == 0)
        {
            HistoryStatus = "Select a readable endpoint scope before exporting.";
            return;
        }
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Export bounded TITAN evidence",
            Filter = "JSON Lines (*.jsonl)|*.jsonl|JSON array (*.json)|*.json",
            FileName = $"titan-evidence-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl"
        };
        if (dialog.ShowDialog() != true) return;

        _queryCancellation?.Dispose();
        _queryCancellation = new CancellationTokenSource();
        var ct = _queryCancellation.Token;
        IsQueryRunning = true;
        HistoryStatus = "Exporting with a 10,000-record / 50 MiB safety bound...";
        try
        {
            var range = QueryRange();
            var options = new BoundedLogExporter.ExportOptions
            {
                From = range.From,
                To = range.To,
                SearchTerm = string.IsNullOrWhiteSpace(QuerySearchText) ? null : QuerySearchText.Trim(),
                EventType = string.IsNullOrWhiteSpace(QueryEventType) ? null : QueryEventType.Trim(),
                MaxRecords = 10_000,
                MaxBytes = 50L * 1024 * 1024,
                Format = Path.GetExtension(dialog.FileName).Equals(".json", StringComparison.OrdinalIgnoreCase)
                    ? BoundedLogExporter.ExportFormat.JsonArray
                    : BoundedLogExporter.ExportFormat.Jsonl
            };
            var result = await BoundedLogExporter.ExportToFileAsync(directories, dialog.FileName, options, ct);
            HistoryStatus = $"{result.Summary} Saved to {dialog.FileName}";
        }
        catch (OperationCanceledException)
        {
            HistoryStatus = "Export cancelled; the partial output file is retained and clearly bounded.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            HistoryStatus = $"Export failed: {ex.Message}";
        }
        finally
        {
            IsQueryRunning = false;
        }
    }

    /// <summary>Fixed track width for the "retained bytes by endpoint" bar graph -- keeps the bar
    /// math simple (no converter/MultiBinding needed) since this is a compact summary strip, not a
    /// full responsive chart; the numeric label next to each bar carries the exact real value.</summary>
    private const double BarTrackWidthPixels = 160;

    private void Tick()
    {
        foreach (var row in Rows) row.Refresh();

        var maxBytes = Rows.Count == 0 ? 0 : Rows.Max(r => r.TotalSizeBytes);
        foreach (var row in Rows)
            row.BarWidthPixels = maxBytes > 0 ? row.TotalSizeBytes / (double)maxBytes * BarTrackWidthPixels : 0;

        var totalBytes = Rows.Sum(r => r.TotalSizeBytes);
        if (_globalDiskBudgetBytes <= 0)
        {
            DiskPressureText = $"Total retained: {FormatBytes(totalBytes)} (no global disk budget configured).";
            return;
        }
        var fraction = (double)totalBytes / _globalDiskBudgetBytes;
        var tier = fraction >= 1.0 ? "Over budget" : fraction >= 0.8 ? "Approaching budget" : "Normal";
        DiskPressureText = $"Total retained: {FormatBytes(totalBytes)} of {FormatBytes(_globalDiskBudgetBytes)} budget — {tier} ({fraction:P0}).";
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
