using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows.Threading;
using Microsoft.Win32;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Diagnostics;

namespace TitanEndpoint.App.ViewModels;

/// <summary>FORU.TXT 0.3: bounded per-endpoint stdout/stderr panel -- diagnostic output only, never
/// the forensic JSONL evidence log, which the native writer produces independently of whether this
/// panel is open. Polls EndpointDiagnostics' snapshot on a DispatcherTimer (the same self-ticking
/// pattern EndpointHeaderViewModel uses) instead of subscribing to LineAppended directly, since that
/// event fires from the process's redirected-output I/O thread -- polling keeps all ObservableCollection
/// mutation safely on the UI thread.</summary>
public sealed class EndpointDiagnosticsViewModel : ViewModelBase
{
    private readonly EndpointDiagnostics _diagnostics;
    private readonly DispatcherTimer _timer;
    private int _lastRenderedCount = -1;
    private string _lastFilterText = "";
    private bool _lastErrorsOnly;

    public string EndpointName { get; }
    public ObservableCollection<DiagnosticLine> Lines { get; } = new();

    private string _filterText = "";
    public string FilterText { get => _filterText; set => SetField(ref _filterText, value); }

    private bool _errorsOnly;
    public bool ErrorsOnly { get => _errorsOnly; set => SetField(ref _errorsOnly, value); }

    /// <summary>"pause autoscroll" (FORU.TXT 0.3) -- capture into the underlying ring buffer never
    /// stops, only this view's re-render does, so nothing is lost while paused.</summary>
    public bool IsPaused
    {
        get => _diagnostics.IsPaused;
        set
        {
            if (_diagnostics.IsPaused == value) return;
            _diagnostics.IsPaused = value;
            OnPropertyChanged();
        }
    }

    private string _countText = "0 lines";
    public string CountText { get => _countText; private set => SetField(ref _countText, value); }

    public RelayCommand ClearCommand { get; }
    public RelayCommand ExportCommand { get; }

    public EndpointDiagnosticsViewModel(string endpointName, EndpointDiagnostics diagnostics)
    {
        EndpointName = endpointName;
        _diagnostics = diagnostics;

        ClearCommand = new RelayCommand(() => { _diagnostics.ClearView(); Render(force: true); });
        ExportCommand = new RelayCommand(Export);

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(500) };
        _timer.Tick += (_, _) => Render(force: false);
        _timer.Start();
        Render(force: true);
    }

    /// <summary>Called when the hosting window closes -- stops the timer so it doesn't keep ticking
    /// (and keeping this view-model alive) after nothing is displaying it.</summary>
    public void Stop() => _timer.Stop();

    private void Render(bool force)
    {
        var snapshot = _diagnostics.Snapshot();
        // Skip the rebuild when nothing that could change the visible list has changed -- avoids
        // needlessly reallocating/rebinding the ListView on every idle tick.
        if (!force && snapshot.Count == _lastRenderedCount && _filterText == _lastFilterText && _errorsOnly == _lastErrorsOnly)
            return;

        _lastRenderedCount = snapshot.Count;
        _lastFilterText = _filterText;
        _lastErrorsOnly = _errorsOnly;

        var filtered = snapshot.Where(l =>
                (!_errorsOnly || l.Level == DiagnosticLevel.Error) &&
                (string.IsNullOrEmpty(_filterText) || l.Text.Contains(_filterText, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        Lines.Clear();
        foreach (var line in filtered) Lines.Add(line);
        CountText = $"{filtered.Count:N0} of {snapshot.Count:N0} lines";
    }

    private void Export()
    {
        var dialog = new SaveFileDialog
        {
            Title = $"Export {EndpointName} Diagnostics",
            FileName = $"{EndpointName}_diagnostics_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
            Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
        };
        if (dialog.ShowDialog() != true) return;
        File.WriteAllText(dialog.FileName, _diagnostics.ExportText(_filterText, _errorsOnly));
    }
}
