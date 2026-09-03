namespace TitanEndpoint.App.ViewModels;

/// <summary>
/// One rotating raw-PCAP segment written by the native Network endpoint into
/// "&lt;LogDirectory&gt;\raw_pcap\adapter_&lt;hash&gt;_&lt;slot&gt;.pcap" (see
/// NETOWRK ENDPOINT\network_monitor.cpp, NetworkMonitor::OpenRawDumper). These bytes are
/// real and retained, but the native endpoint does not currently write a byte offset back
/// onto the JSONL record, so a selected packet cannot be matched to an exact byte range yet
/// (spec section 8 bytes pane — see NetworkViewModel.BytesPaneMessage for the honest state
/// this produces instead of fabricating a match).
/// </summary>
public sealed class RawCaptureFileViewModel
{
    public string FileName { get; init; } = "";
    public string FullPath { get; init; } = "";
    public long SizeBytes { get; init; }
    public DateTime LastWriteUtc { get; init; }

    public string SizeText => FormatBytes(SizeBytes);
    public string LastWriteText => LastWriteUtc == default ? "Unavailable" : LastWriteUtc.ToLocalTime().ToString("HH:mm:ss");

    private static string FormatBytes(long bytes)
    {
        double b = bytes;
        string[] units = { "B", "KB", "MB", "GB" };
        var i = 0;
        while (b >= 1024 && i < units.Length - 1) { b /= 1024; i++; }
        return $"{b:0.#} {units[i]}";
    }
}
