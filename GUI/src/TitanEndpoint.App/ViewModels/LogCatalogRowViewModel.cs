using System.Windows.Media;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.Health;
using TitanEndpoint.Core.Models;

namespace TitanEndpoint.App.ViewModels;

public sealed class LogCatalogRowViewModel : ViewModelBase
{
    private readonly EndpointRuntimeState _state;
    public string EndpointName => _state.Definition.DisplayName;

    private string _activeFile = "Unavailable";
    public string ActiveFile { get => _activeFile; private set => SetField(ref _activeFile, value); }

    private string _directory = "Unavailable";
    public string Directory { get => _directory; private set => SetField(ref _directory, value); }

    private string _currentSize = "Unavailable";
    public string CurrentSize { get => _currentSize; private set => SetField(ref _currentSize, value); }

    private string _totalSize = "Unavailable";
    public string TotalSize { get => _totalSize; private set => SetField(ref _totalSize, value); }

    private string _recordCount = "Unavailable";
    public string RecordCount { get => _recordCount; private set => SetField(ref _recordCount, value); }

    private string _lastWrite = "Unavailable";
    public string LastWrite { get => _lastWrite; private set => SetField(ref _lastWrite, value); }

    private string _writeState = "Unavailable";
    public string WriteState { get => _writeState; private set => SetField(ref _writeState, value); }

    private Brush _writeStateBrush = ThemeBrushes.Disabled;
    public Brush WriteStateBrush { get => _writeStateBrush; private set => SetField(ref _writeStateBrush, value); }

    public string LogDirectoryPath => _state.Definition.LogDirectory;
    public string LogFilePattern => _state.Definition.LogFilePattern;

    private string _lastWriteError = "Unavailable";
    public string LastWriteError { get => _lastWriteError; private set => SetField(ref _lastWriteError, value); }

    public long TotalSizeBytes { get; private set; }

    private double _barWidthPixels;
    /// <summary>Computed by UnifiedLogsViewModel.Tick() (needs every row's TotalSizeBytes to find
    /// the fleet max, which a single row can't know about itself) -- drives the real "retained
    /// bytes by endpoint" bar graph, GUI-upgrade ask for Unified Logs.</summary>
    public double BarWidthPixels { get => _barWidthPixels; set => SetField(ref _barWidthPixels, value); }

    public LogCatalogRowViewModel(EndpointRuntimeState state) => _state = state;

    private static readonly string[] FailureCounterKeys =
        { "queue_dropped", "etw_events_lost", "processing_errors", "watcher_buffer_overflow_count" };

    public void Refresh()
    {
        var t = _state.Tailer;
        Directory = string.IsNullOrEmpty(t.Definition.LogDirectory) ? "Unavailable" : t.Definition.LogDirectory;
        ActiveFile = t.ActiveFilePath is null ? "None" : System.IO.Path.GetFileName(t.ActiveFilePath);
        CurrentSize = t.ActiveFilePath is null ? "Unavailable" : FormatBytes(t.ActiveFileSizeBytes);
        RecordCount = t.TotalLinesRead.ToString("N0");
        LastWrite = t.ActiveFileLastWriteUtc is null ? "Unavailable" : t.ActiveFileLastWriteUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

        long total = 0;
        var haveTotal = false;
        if (System.IO.Directory.Exists(t.Definition.LogDirectory))
        {
            try
            {
                foreach (var pattern in t.Definition.LogFilePattern.Split(';', StringSplitOptions.RemoveEmptyEntries))
                foreach (var f in System.IO.Directory.EnumerateFiles(t.Definition.LogDirectory, pattern))
                {
                    total += new System.IO.FileInfo(f).Length;
                }
                haveTotal = true;
            }
            catch { /* leave Unavailable */ }
        }
        TotalSize = haveTotal ? FormatBytes(total) : "Unavailable";
        TotalSizeBytes = haveTotal ? total : 0;

        var parts = new List<string>();
        if (t.LastHealth is not null)
        {
            var snap = HealthSnapshot.FromRecord(t.LastHealth);
            long failures = 0;
            foreach (var key in FailureCounterKeys)
                if (snap.Counters.TryGetValue(key, out var v)) failures += v;
            if (failures > 0) parts.Add($"{failures:N0} loss/failure events reported by collector");
        }
        if (t.ReadFailureCount > 0)
            parts.Add($"{t.ReadFailureCount:N0} local read failures" + (t.LastErrorMessage is null ? "" : $" (last: {t.LastErrorMessage})"));
        if (t.ParseErrorCount > 0)
            parts.Add($"{t.ParseErrorCount:N0} malformed JSON lines skipped");
        LastWriteError = parts.Count == 0 ? "No error reported" : string.Join("; ", parts);

        if (!t.DirectoryExists)
        {
            WriteState = "Directory not found";
            WriteStateBrush = ThemeBrushes.Critical;
        }
        else if (t.ActiveFilePath is null)
        {
            WriteState = _state.IsRunning ? "Waiting for first write" : "Not writing (collector stopped)";
            WriteStateBrush = ThemeBrushes.Disabled;
        }
        else if (t.LastPollUtc is not null && (DateTimeOffset.UtcNow - t.ActiveFileLastWriteUtc!.Value).TotalSeconds < 60)
        {
            WriteState = "Writing";
            WriteStateBrush = ThemeBrushes.Healthy;
        }
        else
        {
            WriteState = _state.IsRunning ? "Idle (no recent writes)" : "Not writing (collector stopped)";
            WriteStateBrush = ThemeBrushes.Disabled;
        }
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
