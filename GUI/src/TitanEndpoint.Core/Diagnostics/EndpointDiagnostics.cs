using System.Collections.Concurrent;

namespace TitanEndpoint.Core.Diagnostics;

public enum DiagnosticLevel { Info, Warning, Error }

/// <summary>One captured stdout/stderr line from a native endpoint process. This is diagnostic
/// output only -- never the forensic JSONL evidence log, which the native writers produce
/// independently of whether anyone is watching this panel (FORU.TXT 0.3).</summary>
public sealed class DiagnosticLine
{
    public required DateTimeOffset TimestampUtc { get; init; }
    public required string Endpoint { get; init; }
    public required DiagnosticLevel Level { get; init; }
    public required string Text { get; init; }
}

/// <summary>FORU.TXT 0.3: "Native stdout/stderr must be redirected to a bounded per-endpoint
/// Diagnostics panel inside the GUI... bounded line retention." One instance per endpoint, owned
/// by EndpointRuntimeState; EndpointProcessController.Start() wires a process's redirected output
/// streams into Append() when it can (see EndpointProcessController's hidden-window launch path).
/// Thread-safe: process output arrives on the .NET process I/O thread pool, read by the UI thread.</summary>
public sealed class EndpointDiagnostics
{
    private const int MaxLines = 4000;
    private readonly ConcurrentQueue<DiagnosticLine> _lines = new();
    private readonly string _endpointName;
    private volatile bool _paused;

    public EndpointDiagnostics(string endpointName) => _endpointName = endpointName;

    public event Action? LineAppended;

    /// <summary>Pause/Resume autoscroll in the panel -- capture itself never stops, only the
    /// "notify the UI a new line arrived" signal does, so nothing is lost while paused (FORU.TXT
    /// 0.3: "pause autoscroll").</summary>
    public bool IsPaused { get => _paused; set => _paused = value; }

    public void Append(DiagnosticLevel level, string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        _lines.Enqueue(new DiagnosticLine
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            Endpoint = _endpointName,
            Level = level,
            Text = text
        });
        while (_lines.Count > MaxLines) _lines.TryDequeue(out _);
        if (!_paused) LineAppended?.Invoke();
    }

    public void AppendSystem(string text) => Append(DiagnosticLevel.Info, text);

    public IReadOnlyList<DiagnosticLine> Snapshot() => _lines.ToArray();

    /// <summary>"clear-view (not delete evidence)" -- this only clears the in-memory diagnostics
    /// ring, never touches the endpoint's real JSONL evidence log.</summary>
    public void ClearView()
    {
        while (_lines.TryDequeue(out _)) { }
        LineAppended?.Invoke();
    }

    public string ExportText(string filterText, bool errorsOnly)
    {
        var lines = Snapshot().Where(l =>
            (!errorsOnly || l.Level == DiagnosticLevel.Error) &&
            (string.IsNullOrEmpty(filterText) || l.Text.Contains(filterText, StringComparison.OrdinalIgnoreCase)));
        return string.Join(Environment.NewLine,
            lines.Select(l => $"{l.TimestampUtc:yyyy-MM-dd HH:mm:ss.fff}Z [{l.Level}] {l.Text}"));
    }
}
