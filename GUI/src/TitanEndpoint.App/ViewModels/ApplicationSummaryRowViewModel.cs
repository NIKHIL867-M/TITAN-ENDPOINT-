namespace TitanEndpoint.App.ViewModels;

public sealed class ApplicationSummaryRowViewModel
{
    public string Application { get; init; } = "";
    public int EventCount { get; init; }
    public string LastSeen { get; init; } = "";

    /// <summary>Live OS check (Process.GetProcessesByName), not derived from log activity --
    /// Santosh, 2026-08-04: "it even has to show ... which are currently running." A watched app
    /// with recent log rows may have already exited since its last event.</summary>
    public bool IsCurrentlyRunning { get; init; }

    /// <summary>Real cross-reference against the Network endpoint's own tailer, joined by pid
    /// (same GUI-side correlation pattern ProcessDetailViewModel already uses for "Related
    /// Evidence", just applied here per-application) -- gives genuine inbound/outbound network
    /// activity per app using the Network collector's actual byte counters and direction, rather
    /// than the coarser point-in-time socket-table snapshot the Application collector itself has.</summary>
    public long NetworkBytesSent { get; init; }
    public long NetworkBytesRecv { get; init; }
    public int DistinctRemoteEndpoints { get; init; }

    public string NetworkSummary => NetworkBytesSent == 0 && NetworkBytesRecv == 0 && DistinctRemoteEndpoints == 0
        ? "No retained network evidence for this app"
        : $"↑{FormatBytes(NetworkBytesSent)} ↓{FormatBytes(NetworkBytesRecv)} — {DistinctRemoteEndpoints} remote endpoint(s)";

    private static string FormatBytes(long bytes)
    {
        double b = bytes;
        string[] units = { "B", "KB", "MB", "GB" };
        var i = 0;
        while (b >= 1024 && i < units.Length - 1) { b /= 1024; i++; }
        return $"{b:0.#}{units[i]}";
    }
}
