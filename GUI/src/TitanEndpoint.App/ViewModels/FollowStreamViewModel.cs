using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Buffers.Binary;
using TitanEndpoint.App.Common;

namespace TitanEndpoint.App.ViewModels;

/// <summary>
/// FORU.TXT section C — "Follow TCP Stream: provide a focused dialog/drawer with client/server
/// direction colours plus text, ASCII, hex, and raw views; search next/previous; direction filter;
/// save/export; packet backlinks; gap, overlap, and retransmission markers; 4,096-record and 1 MiB
/// bounds; and explicit ciphertext/privacy/expired notices."
///
/// FollowStreamViewModel is the backing model for the Follow TCP Stream focused window
/// (FollowStreamWindow.xaml). It is constructed from a set of matching NetworkRowViewModels and
/// the raw PCAP directory path, then reconstructs retained TCP payloads on demand in a background
/// task. The caller (NetworkViewModel or the window code-behind) passes rows and awaits Load().
/// This deliberately does NOT inherit ViewModelBase so it is testable without a WPF dispatcher;
/// property-change notifications use the standard INotifyPropertyChanged pattern.
/// </summary>
public sealed class FollowStreamViewModel : ViewModelBase
{
    // ---- Bounds (FORU.TXT explicit) ----
    public const int MaxInputRecords  = 4096;
    public const int MaxPayloadBytes  = 1024 * 1024; // 1 MiB

    // ---- View mode ----

    public enum StreamViewMode { Text, Hex, Raw, Ascii }

    private StreamViewMode _viewMode = StreamViewMode.Text;
    public StreamViewMode ViewMode
    {
        get => _viewMode;
        set { if (SetField(ref _viewMode, value)) RenderActiveView(); }
    }

    // ---- Direction filter ----

    public enum DirectionFilter { Both, AToB, BToA }

    private DirectionFilter _directionFilter = DirectionFilter.Both;
    public DirectionFilter ActiveDirectionFilter
    {
        get => _directionFilter;
        set { if (SetField(ref _directionFilter, value)) RenderActiveView(); }
    }

    // ---- Load state ----

    private bool _isLoading;
    public bool IsLoading
    {
        get => _isLoading;
        private set => SetField(ref _isLoading, value);
    }

    private string _statusText = "Select a conversation to reconstruct retained TCP payloads.";
    public string StatusText
    {
        get => _statusText;
        private set => SetField(ref _statusText, value);
    }

    // ---- Conversation identity ----

    private string _conversationTitle = "";
    public string ConversationTitle
    {
        get => _conversationTitle;
        private set => SetField(ref _conversationTitle, value);
    }

    private bool _isEncrypted;
    /// <summary>True when any record in the conversation carries TLS/port-443 evidence.</summary>
    public bool IsEncrypted
    {
        get => _isEncrypted;
        private set => SetField(ref _isEncrypted, value);
    }

    public string EncryptionNotice =>
        "TLS/encrypted conversation: TITAN does not decrypt TLS. Ciphertext is shown as hex. " +
        "Application content is not available.";

    // ---- Stream segments (raw data for rendering) ----

    private readonly List<StreamSegment> _segments = new();

    // ---- Rendered output ----

    private string _renderedText = "";
    public string RenderedText
    {
        get => _renderedText;
        private set => SetField(ref _renderedText, value);
    }

    public ObservableCollection<StreamSegment> Segments { get; } = new();

    // ---- Search ----

    private string _searchTerm = "";
    public string SearchTerm
    {
        get => _searchTerm;
        set
        {
            if (SetField(ref _searchTerm, value))
            {
                SearchNextCommand.RaiseCanExecuteChanged();
                SearchPreviousCommand.RaiseCanExecuteChanged();
            }
        }
    }

    private int _searchResultIndex = -1;
    private readonly List<int> _searchHits = new();

    public string SearchResultText => _searchHits.Count == 0 ? "" :
        $"{(_searchResultIndex >= 0 ? _searchResultIndex + 1 : 0)} / {_searchHits.Count} match(es)";

    // ---- Statistics ----

    private int _packetCount;
    public int PacketCount
    {
        get => _packetCount;
        private set => SetField(ref _packetCount, value);
    }

    private int _gapCount;
    public int GapCount
    {
        get => _gapCount;
        private set => SetField(ref _gapCount, value);
    }

    private int _retransmissionCount;
    public int RetransmissionCount
    {
        get => _retransmissionCount;
        private set => SetField(ref _retransmissionCount, value);
    }

    private int _expiredCount;
    public int ExpiredCount
    {
        get => _expiredCount;
        private set => SetField(ref _expiredCount, value);
    }

    private bool _truncated;
    public bool Truncated
    {
        get => _truncated;
        private set => SetField(ref _truncated, value);
    }

    // ---- Commands ----

    public RelayCommand SearchNextCommand     { get; }
    public RelayCommand SearchPreviousCommand { get; }
    public RelayCommand SaveCommand           { get; }
    public RelayCommand CopyCommand           { get; }

    public FollowStreamViewModel()
    {
        // CanExecute must not depend on _searchHits.Count: that field is populated only inside
        // SearchNext()/SearchPrevious() themselves (via RunSearch()), so gating on it made the
        // buttons permanently disabled -- there was no way to ever run the first search. Found live
        // via NetworkLiveCaptureTests (a real Invoke() on Next threw ElementNotEnabledException).
        SearchNextCommand     = new RelayCommand(SearchNext,     () => !string.IsNullOrEmpty(SearchTerm) && _segments.Count > 0);
        SearchPreviousCommand = new RelayCommand(SearchPrevious, () => !string.IsNullOrEmpty(SearchTerm) && _segments.Count > 0);
        SaveCommand           = new RelayCommand(Save,           () => _segments.Count > 0 && !IsLoading);
        CopyCommand           = new RelayCommand(CopyToClipboard, () => _segments.Count > 0);
    }

    // ---- Load ----

    /// <summary>
    /// Reconstructs the TCP stream for the given conversation from up to MaxInputRecords retained
    /// PCAP records. Runs on a background thread; progress is reported back on the calling thread
    /// via SetField / RaisePropertyChanged (safe from background because ViewModelBase does not
    /// marshal to UI thread — callers are responsible for UI updates if required by WPF bindings).
    /// </summary>
    public async Task LoadAsync(
        string conversationKey,
        string endpointA,
        string endpointB,
        string protocol,
        IEnumerable<NetworkRowViewModel> rows,
        string rawCaptureDirectory,
        CancellationToken ct = default)
    {
        IsLoading  = true;
        StatusText = "Reconstructing retained packets…";
        _segments.Clear();
        Segments.Clear();
        _gapCount = _retransmissionCount = _expiredCount = 0;
        Truncated  = false;

        ConversationTitle = $"{endpointA} ↔ {endpointB}  [{protocol}]";

        var workRows = rows
            .OrderBy(r => r.CaptureEpochUs)
            .Take(MaxInputRecords)
            .ToList();

        var isEncrypted = workRows.Any(r =>
            r.Protocol.Contains("TLS", StringComparison.OrdinalIgnoreCase) ||
            r.LocalPort == 443 || r.RemotePort == 443);
        IsEncrypted = isEncrypted;

        var result = await Task.Run(() =>
            ReconstructStream(workRows, rawCaptureDirectory, endpointA, protocol, isEncrypted, ct), ct);

        _segments.AddRange(result.Segments);
        foreach (var seg in _segments) Segments.Add(seg);

        PacketCount         = result.PacketCount;
        GapCount            = result.GapCount;
        RetransmissionCount = result.RetransmissionCount;
        ExpiredCount        = result.ExpiredCount;
        Truncated           = result.Truncated;

        var summary = new StringBuilder();
        summary.Append($"{PacketCount} packet(s)");
        if (GapCount > 0)            summary.Append($", {GapCount} gap(s)");
        if (RetransmissionCount > 0) summary.Append($", {RetransmissionCount} retransmission(s)");
        if (ExpiredCount > 0)        summary.Append($", {ExpiredCount} expired/unavailable");
        if (Truncated)               summary.Append(" — output stopped at 1 MiB limit");
        StatusText = summary.ToString();

        IsLoading = false;
        RenderActiveView();

        // The command predicates depend on _segments/IsLoading, which are updated
        // asynchronously and are not observable properties themselves. Force WPF
        // to re-evaluate every affected command after reconstruction completes;
        // otherwise Copy/Save (and the first search) can remain stuck in the
        // disabled state captured when the window initially opened.
        SaveCommand.RaiseCanExecuteChanged();
        CopyCommand.RaiseCanExecuteChanged();
        SearchNextCommand.RaiseCanExecuteChanged();
        SearchPreviousCommand.RaiseCanExecuteChanged();
    }

    // ---- Rendering ----

    private void RenderActiveView()
    {
        if (_segments.Count == 0) { RenderedText = StatusText; return; }

        var sb = new StringBuilder();
        if (IsEncrypted) sb.AppendLine(EncryptionNotice).AppendLine();

        foreach (var seg in _segments)
        {
            if (ActiveDirectionFilter == DirectionFilter.AToB && seg.Direction != StreamSegmentDirection.AToB) continue;
            if (ActiveDirectionFilter == DirectionFilter.BToA && seg.Direction != StreamSegmentDirection.BToA) continue;

            switch (seg.Kind)
            {
                case StreamSegmentKind.Annotation:
                    sb.AppendLine(seg.Text);
                    break;
                case StreamSegmentKind.Payload:
                    if (seg.Payload is null) break;
                    switch (ViewMode)
                    {
                        case StreamViewMode.Hex:   sb.Append(FormatHex(seg.Payload)); break;
                        case StreamViewMode.Raw:   sb.Append(Encoding.Latin1.GetString(seg.Payload)); break;
                        case StreamViewMode.Ascii:
                        case StreamViewMode.Text:
                            sb.Append(FormatText(seg.Payload)); break;
                    }
                    sb.AppendLine();
                    break;
            }
        }

        RenderedText = sb.ToString();
    }

    // ---- Stream reconstruction ----

    private sealed class ReconstructResult
    {
        public List<StreamSegment> Segments        { get; } = new();
        public int PacketCount                     { get; set; }
        public int GapCount                        { get; set; }
        public int RetransmissionCount             { get; set; }
        public int ExpiredCount                    { get; set; }
        public bool Truncated                      { get; set; }
    }

    private static ReconstructResult ReconstructStream(
        IReadOnlyList<NetworkRowViewModel> rows,
        string rawCaptureDirectory,
        string endpointA,
        string protocol,
        bool isEncrypted,
        CancellationToken ct)
    {
        var result    = new ReconstructResult();
        var nextSeq   = new Dictionary<StreamSegmentDirection, uint>();
        var retained  = 0;

        foreach (var row in rows)
        {
            ct.ThrowIfCancellationRequested();
            result.PacketCount++;

            if (!row.RawCaptureMapped || string.IsNullOrEmpty(row.RawCaptureSegment))
            {
                result.Segments.Add(StreamSegment.Annotation($"[seq? — packet not retained in raw PCAP]"));
                result.ExpiredCount++;
                continue;
            }

            var safeName = Path.GetFileName(row.RawCaptureSegment);
            var path     = Path.Combine(rawCaptureDirectory, safeName);
            byte[]? packetBytes = null;
            try
            {
                packetBytes = ReadMappedPacketBytes(path, row);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Santosh, 2026-08-31: "I'm not sure that mean" -- the raw exception message (a bare
                // .NET "Could not find file '...'.") is correct and honest (the referenced raw_pcap
                // segment really is gone -- retention rotation deletes older segments under disk
                // pressure, same as every other endpoint's log retention), but it reads like an error
                // rather than the expected, explained state it actually is. FileNotFoundException is
                // itself an IOException, so it was already being caught correctly here; only the
                // message shown to the analyst needed to say what this actually means.
                var message = ex is FileNotFoundException
                    ? "this packet's raw capture segment has been rotated out by disk retention and is no longer on disk (normal for older captures)"
                    : ex.Message;
                result.Segments.Add(StreamSegment.Annotation($"[Unavailable: {message}]"));
                result.ExpiredCount++;
                continue;
            }

            if (!TryGetTcpPayload(packetBytes, out var sequence, out var flags, out var payload))
                continue;

            var dir = string.Equals(row.LocalAddress, endpointA, StringComparison.Ordinal)
                ? StreamSegmentDirection.AToB
                : StreamSegmentDirection.BToA;

            string? annotation = null;
            if (nextSeq.TryGetValue(dir, out var expected))
            {
                if (sequence < expected)
                {
                    annotation = $" [retransmission/overlap seq={sequence}]";
                    result.RetransmissionCount++;
                }
                else if (sequence > expected)
                {
                    annotation = $" [GAP {sequence - expected} byte(s) missing]";
                    result.GapCount++;
                }
            }

            var end = sequence + (uint)payload.Length;
            if (!nextSeq.TryGetValue(dir, out var cur) || end > cur) nextSeq[dir] = end;

            var dirLabel = dir == StreamSegmentDirection.AToB ? "→" : "←";
            result.Segments.Add(StreamSegment.Annotation(
                $"[{dirLabel} seq={sequence} flags={flags} {payload.Length} byte(s){annotation}]"));

            if (payload.Length > 0)
            {
                if (retained + payload.Length > MaxPayloadBytes)
                {
                    result.Segments.Add(StreamSegment.Annotation("[Output stopped at the 1 MiB investigation limit.]"));
                    result.Truncated = true;
                    break;
                }
                retained += payload.Length;
                result.Segments.Add(StreamSegment.Data(dir, payload));
            }
        }

        return result;
    }

    private static byte[] ReadMappedPacketBytes(string path, NetworkRowViewModel row)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite, 64 * 1024, FileOptions.RandomAccess);
        if (row.RawRecordOffset < 24 || row.RawRecordOffset > stream.Length - 16)
            throw new IOException("PCAP record offset is unavailable or out of bounds.");
        stream.Position = row.RawRecordOffset;
        Span<byte> header = stackalloc byte[16];
        stream.ReadExactly(header);
        var captured = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(8, 4));
        if (captured > 1024 * 1024 || stream.Position + captured > stream.Length)
            throw new IOException("PCAP record is incomplete or exceeds 1 MiB.");
        var bytes = new byte[captured];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private static bool TryGetTcpPayload(byte[] packet, out uint sequence, out string flags, out byte[] payload)
    {
        sequence = 0; flags = ""; payload = Array.Empty<byte>();
        if (packet.Length < 34) return false;
        var network   = 14;
        var etherType = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(12, 2));
        while ((etherType is 0x8100 or 0x88A8) && packet.Length >= network + 4)
        { etherType = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(network + 2, 2)); network += 4; }
        int tcp;
        if (etherType == 0x0800)
        {
            var ihl = (packet[network] & 0x0F) * 4;
            if (packet.Length < network + ihl || packet[network + 9] != 6) return false;
            tcp = network + ihl;
        }
        else if (etherType == 0x86DD)
        {
            if (packet.Length < network + 40 || packet[network + 6] != 6) return false;
            tcp = network + 40;
        }
        else return false;
        if (packet.Length < tcp + 20) return false;
        sequence = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(tcp + 4, 4));
        var headerLength = (packet[tcp + 12] >> 4) * 4;
        if (headerLength < 20 || packet.Length < tcp + headerLength) return false;
        flags   = $"0x{packet[tcp + 13]:x2}";
        payload = packet[(tcp + headerLength)..];
        return true;
    }

    // ---- Formatting ----

    private static string FormatHex(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 4);
        for (var offset = 0; offset < bytes.Length; offset += 16)
        {
            sb.Append(offset.ToString("x6")).Append("  ");
            var count = Math.Min(16, bytes.Length - offset);
            for (var i = 0; i < 16; i++)
                sb.Append(i < count ? bytes[offset + i].ToString("x2") + " " : "   ");
            sb.Append(" ");
            for (var i = 0; i < count; i++)
            {
                var b = bytes[offset + i];
                sb.Append(b is >= 32 and <= 126 ? (char)b : '.');
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }

    private static string FormatText(byte[] bytes)
    {
        if (bytes.All(b => b is 9 or 10 or 13 || b is >= 32 and <= 126))
            return Encoding.UTF8.GetString(bytes);
        return FormatHex(bytes);
    }

    // ---- Search ----

    private void SearchNext()
    {
        RunSearch();
        if (_searchHits.Count == 0) return;
        _searchResultIndex = (_searchResultIndex + 1) % _searchHits.Count;
        OnPropertyChanged(nameof(SearchResultText));
    }

    private void SearchPrevious()
    {
        RunSearch();
        if (_searchHits.Count == 0) return;
        _searchResultIndex = (_searchResultIndex - 1 + _searchHits.Count) % _searchHits.Count;
        OnPropertyChanged(nameof(SearchResultText));
    }

    private void RunSearch()
    {
        _searchHits.Clear();
        if (string.IsNullOrEmpty(SearchTerm) || string.IsNullOrEmpty(RenderedText)) return;
        var text  = RenderedText;
        var term  = SearchTerm;
        var start = 0;
        while (true)
        {
            var idx = text.IndexOf(term, start, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) break;
            _searchHits.Add(idx);
            start = idx + 1;
        }
        _searchResultIndex = _searchHits.Count > 0 ? 0 : -1;
        OnPropertyChanged(nameof(SearchResultText));
        SearchNextCommand.RaiseCanExecuteChanged();
        SearchPreviousCommand.RaiseCanExecuteChanged();
    }

    // ---- Save / Copy ----

    private void Save()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title  = "Save Follow Stream",
            Filter = "Text (*.txt)|*.txt|Hex dump (*.txt)|*.txt",
            FileName = "follow-stream"
        };
        if (dialog.ShowDialog() != true) return;
        try { File.WriteAllText(dialog.FileName, RenderedText, new UTF8Encoding(false)); }
        catch (Exception ex) { StatusText = $"Save failed: {ex.Message}"; }
    }

    private void CopyToClipboard()
    {
        try { System.Windows.Clipboard.SetText(RenderedText); }
        catch { /* clipboard may be unavailable in headless environments */ }
    }
}

public sealed class StreamSegment
{
    public StreamSegmentKind       Kind      { get; private init; }
    public StreamSegmentDirection  Direction { get; private init; }
    public string                  Text      { get; private init; } = "";
    public byte[]?                 Payload   { get; private init; }

    public static StreamSegment Annotation(string text) => new()
        { Kind = StreamSegmentKind.Annotation, Text = text };

    public static StreamSegment Data(StreamSegmentDirection direction, byte[] payload) => new()
        { Kind = StreamSegmentKind.Payload, Direction = direction, Payload = payload };
}

public enum StreamSegmentKind      { Annotation, Payload }
public enum StreamSegmentDirection { AToB, BToA }
