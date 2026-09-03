using System.Collections.ObjectModel;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.App.Views;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.Health;

namespace TitanEndpoint.App.ViewModels;

public sealed class ProtocolCountViewModel
{
    public string Protocol { get; init; } = "";
    public int Count { get; init; }
}

public sealed class TopTalkerViewModel
{
    public string RemoteAddress { get; init; } = "";
    public long TotalBytes { get; init; }
    public int PacketCount { get; init; }
}

/// <summary>Mutable/notifying by design (unlike most row view-models in this file): NetworkViewModel.
/// Tick() reconciles Conversations by Key every 700ms and must be able to update Protocol/Process/
/// Packets/Bytes/*EpochUs on the SAME object instance rather than replacing it, so a live-updating,
/// currently-selected conversation never loses ConversationsGrid's TwoWay-bound SelectedItem
/// identity. Key/EndpointA/EndpointB stay init-only because they define the conversation's identity
/// and never change once a group exists.</summary>
public sealed class NetworkConversationViewModel : ViewModelBase
{
    public required string Key { get; init; }
    public required string EndpointA { get; init; }
    public required string EndpointB { get; init; }

    private string _protocol = "";
    public string Protocol { get => _protocol; set => SetField(ref _protocol, value); }

    private long _transportProtocolNumber;
    public long TransportProtocolNumber
    {
        get => _transportProtocolNumber;
        set
        {
            if (SetField(ref _transportProtocolNumber, value))
                OnPropertyChanged(nameof(Transport));
        }
    }
    public string Transport => TransportProtocolNumber switch
    {
        6 => "TCP", 17 => "UDP", 1 => "ICMP", 58 => "ICMPv6", _ => "Other"
    };

    private string _process = "";
    public string Process { get => _process; set => SetField(ref _process, value); }

    private int _packets;
    public int Packets { get => _packets; set => SetField(ref _packets, value); }

    private long _bytes;
    public long Bytes { get => _bytes; set => SetField(ref _bytes, value); }

    private ulong _firstEpochUs;
    public ulong FirstEpochUs { get => _firstEpochUs; set { if (SetField(ref _firstEpochUs, value)) OnPropertyChanged(nameof(DurationText)); } }

    private ulong _lastEpochUs;
    public ulong LastEpochUs { get => _lastEpochUs; set { if (SetField(ref _lastEpochUs, value)) OnPropertyChanged(nameof(DurationText)); } }

    public string DurationText => FirstEpochUs == 0 ? "Unavailable" : $"{(LastEpochUs - FirstEpochUs) / 1000.0:N1} ms";
}

public sealed class NetworkViewModel : ViewModelBase
{
    public EndpointHeaderViewModel Header { get; }
    public ObservableCollection<NetworkRowViewModel> Rows { get; } = new();
    public ICollectionView RowsView { get; }
    public ObservableCollection<ProtocolCountViewModel> ProtocolHierarchy { get; } = new();
    public ObservableCollection<TopTalkerViewModel> TopTalkers { get; } = new();
    public ObservableCollection<ProtocolTreeNode> ProtocolTree { get; } = new();
    public ObservableCollection<RawCaptureFileViewModel> RawCaptureFiles { get; } = new();
    public ObservableCollection<NetworkConversationViewModel> Conversations { get; } = new();
    public NetworkCaptureBarViewModel CaptureBar { get; } = new();
    public PacketBytesViewModel PacketBytes { get; } = new();
    public ObservableCollection<string> Adapters { get; } = new() { "All captured adapters" };
    private string _selectedAdapter = "All captured adapters";
    public string SelectedAdapter { get => _selectedAdapter; set { if (SetField(ref _selectedAdapter, value)) RowsView.Refresh(); } }

    private string _filterText = "";
    public string FilterText
    {
        get => _filterText;
        set { if (SetField(ref _filterText, value)) { RowsView.Refresh(); OnPropertyChanged(nameof(FilterHelpText)); } }
    }
    public string FilterHelpText => "Filters: protocol:, ip:, port:, process:, adapter:, direction:. Plain text searches all common fields.";

    private NetworkConversationViewModel? _selectedConversation;
    public NetworkConversationViewModel? SelectedConversation
    {
        get => _selectedConversation;
        set
        {
            if (SetField(ref _selectedConversation, value))
            {
                _ = BuildFollowStreamAsync(value);
                FollowStreamCommand.RaiseCanExecuteChanged();
                ExportConversationCommand.RaiseCanExecuteChanged();
            }
        }
    }
    private string _followStreamText = "Select a conversation to reconstruct retained TCP payloads.";
    public string FollowStreamText { get => _followStreamText; private set => SetField(ref _followStreamText, value); }

    private string _summaryText = "Waiting for data...";
    public string SummaryText { get => _summaryText; private set => SetField(ref _summaryText, value); }

    private NetworkRowViewModel? _selectedRow;
    public NetworkRowViewModel? SelectedRow
    {
        get => _selectedRow;
        set
        {
            // Santosh, Round 22: same eviction-vs-real-deselect fix as ProcessViewModel.SelectedRow /
            // CorrelationViewModel.SelectedGroup -- a live sync evicting the selected row from the
            // bounded window must not silently wipe this page's detail panels either.
            if (value is null) return;
            if (SetField(ref _selectedRow, value))
            {
                RebuildProtocolTree();
                OnPropertyChanged(nameof(RawJsonText));
                _ = LoadSelectedPacketBytesAsync(value);
            }
        }
    }

    public string RawJsonText => _selectedRow?.RawJson ?? "Select a packet to view its raw JSON record.";

    /// <summary>Honest bytes-pane state (spec section 8: "If raw payload was not retained,
    /// display a clear privacy-mode explanation") — see RawCaptureFileViewModel for why this
    /// can't yet name an exact byte range for the selected packet.</summary>
    private string _bytesPaneMessage = "Select a packet to view raw capture availability.";
    public string BytesPaneMessage { get => _bytesPaneMessage; private set => SetField(ref _bytesPaneMessage, value); }

    private string _rawBytesText = "";
    public string RawBytesText { get => _rawBytesText; private set => SetField(ref _rawBytesText, value); }
    private string _selectedFieldBytesText = "Select a protocol field to map it to retained packet bytes.";
    public string SelectedFieldBytesText { get => _selectedFieldBytesText; private set => SetField(ref _selectedFieldBytesText, value); }
    private byte[]? _selectedPacketBytes;

    public RelayCommand OpenRawCaptureFolderCommand { get; }
    public RelayCommand ExportConversationCommand { get; }
    public RelayCommand FollowStreamCommand { get; }

    private readonly IncrementalRowSync<NetworkRowViewModel> _sync;
    private readonly DispatcherTimer _timer;
    private readonly string _rawCaptureDirectory;
    private DateTime _lastRawScanUtc = DateTime.MinValue;
    private int _byteLoadGeneration;
    private long _lastCaptureCount;
    private DateTimeOffset _lastCaptureStatsUtc = DateTimeOffset.UtcNow;

    public NetworkViewModel()
    {
        Header = new EndpointHeaderViewModel(EndpointId.Network, "Live packet and flow capture");
        RowsView = CollectionViewSource.GetDefaultView(Rows);
        RowsView.Filter = FilterPredicate;
        _rawCaptureDirectory = Path.Combine(Header.State.Definition.LogDirectory, "raw_pcap");

        _sync = new IncrementalRowSync<NetworkRowViewModel>(Rows, maxRows: 4000, NetworkRowViewModel.From,
            filter: r => !r.IsCollectorHealth);

        OpenRawCaptureFolderCommand = new RelayCommand(
            () => Process.Start(new ProcessStartInfo { FileName = _rawCaptureDirectory, UseShellExecute = true }),
            () => Directory.Exists(_rawCaptureDirectory));
        ExportConversationCommand = new RelayCommand(ExportSelectedConversation,
            () => SelectedConversation is not null);
        FollowStreamCommand = new RelayCommand(() => _ = OpenFollowStreamWindowAsync(),
            () => IsTcpConversation(SelectedConversation));

        CaptureBar.DisplayFilterApplied += (_, filter) => FilterText = filter;
        CaptureBar.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(NetworkCaptureBarViewModel.SelectedAdapter))
                SelectedAdapter = CaptureBar.SelectedAdapter;
        };

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(700) };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        Tick();
    }

    private void RebuildProtocolTree()
    {
        ProtocolTree.Clear();
        if (_selectedRow is null) return;
        foreach (var node in ProtocolTreeNode.Build(_selectedRow)) ProtocolTree.Add(node);
    }

    private void RescanRawCaptureFiles()
    {
        var now = DateTime.UtcNow;
        if ((now - _lastRawScanUtc).TotalSeconds < 3) return;
        _lastRawScanUtc = now;

        RawCaptureFiles.Clear();
        if (!Directory.Exists(_rawCaptureDirectory)) return;

        foreach (var path in Directory.EnumerateFiles(_rawCaptureDirectory, "*.pcap").OrderByDescending(File.GetLastWriteTimeUtc).Take(20))
        {
            var info = new FileInfo(path);
            RawCaptureFiles.Add(new RawCaptureFileViewModel
            {
                FileName = info.Name,
                FullPath = path,
                SizeBytes = info.Length,
                LastWriteUtc = info.LastWriteTimeUtc
            });
        }
    }

    private async Task LoadSelectedPacketBytesAsync(NetworkRowViewModel? row)
    {
        var generation = ++_byteLoadGeneration;
        RawBytesText = "";
        _selectedPacketBytes = null;
        PacketBytes.Clear();
        if (row is null)
        {
            BytesPaneMessage = "Select a packet to view raw capture availability.";
            return;
        }
        if (!row.RawCaptureMapped || string.IsNullOrWhiteSpace(row.RawCaptureSegment))
        {
            BytesPaneMessage = "This record has no exact raw-capture mapping. It may come from an older collector build, or raw capture was unavailable when the packet was observed.";
            PacketBytes.ShowValidationError(BytesPaneMessage);
            return;
        }

        var safeName = Path.GetFileName(row.RawCaptureSegment);
        if (!string.Equals(safeName, row.RawCaptureSegment, StringComparison.Ordinal))
        {
            BytesPaneMessage = "The raw-capture reference was rejected because it is not a safe segment filename.";
            PacketBytes.ShowValidationError(BytesPaneMessage);
            return;
        }
        var path = Path.Combine(_rawCaptureDirectory, safeName);
        BytesPaneMessage = $"Loading exact bytes from {safeName} at PCAP record offset {row.RawRecordOffset:N0}...";
        try
        {
            var loaded = await Task.Run(() => ReadMappedPacket(path, row));
            if (generation != _byteLoadGeneration) return;
            BytesPaneMessage = loaded.Message;
            RawBytesText = loaded.Hex;
            _selectedPacketBytes = loaded.Bytes;
            PacketBytes.LoadBytes(loaded.Bytes, loaded.Message);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentOutOfRangeException)
        {
            if (generation != _byteLoadGeneration) return;
            BytesPaneMessage = File.Exists(path)
                ? $"Exact byte lookup failed: {ex.Message}"
                : "The mapped PCAP segment has expired under bounded raw-capture retention; the JSON evidence remains, but those packet bytes are no longer retained.";
            PacketBytes.ShowValidationError(BytesPaneMessage);
        }
    }

    private static (string Message, string Hex, byte[] Bytes) ReadMappedPacket(string path, NetworkRowViewModel row)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
            64 * 1024, FileOptions.RandomAccess);
        if (row.RawRecordOffset < 24 || row.RawRecordOffset > stream.Length - 16)
            throw new IOException("The stored PCAP record offset is outside the retained segment.");
        stream.Position = row.RawRecordOffset;
        Span<byte> recordHeader = stackalloc byte[16];
        stream.ReadExactly(recordHeader);
        var seconds = BinaryPrimitives.ReadUInt32LittleEndian(recordHeader[..4]);
        var microseconds = BinaryPrimitives.ReadUInt32LittleEndian(recordHeader.Slice(4, 4));
        var capturedLength = BinaryPrimitives.ReadUInt32LittleEndian(recordHeader.Slice(8, 4));
        var wireLength = BinaryPrimitives.ReadUInt32LittleEndian(recordHeader.Slice(12, 4));
        if (capturedLength > 1024 * 1024 || stream.Position + capturedLength > stream.Length)
            throw new IOException("The mapped PCAP record length is invalid or incomplete.");
        if (row.Length > 0 && capturedLength != row.Length)
            throw new IOException($"PCAP length mismatch (mapped {capturedLength}, JSON {row.Length}); refusing to show possibly wrong bytes.");
        var captureEpochUs = (ulong)seconds * 1_000_000UL + microseconds;
        if (row.CaptureEpochUs != 0 && captureEpochUs != row.CaptureEpochUs)
            throw new IOException("PCAP timestamp does not match the JSON record; the segment may have been replaced.");

        var bytes = new byte[capturedLength];
        stream.ReadExactly(bytes);
        return ($"Exact mapping verified: {Path.GetFileName(path)}, data offset {row.RawDataOffset:N0}, captured {capturedLength:N0} of {wireLength:N0} wire bytes.", FormatHex(bytes), bytes);
    }

    public void SelectProtocolField(ProtocolTreeNode? node)
    {
        if (node is null || string.IsNullOrWhiteSpace(node.FieldKey)) return;
        if (_selectedPacketBytes is null) { SelectedFieldBytesText = "Exact packet bytes are not retained for this field."; return; }
        if (!TryResolveFieldRange(_selectedPacketBytes, node.FieldKey, _selectedRow, out var offset, out var length))
        { SelectedFieldBytesText = $"{node.Label}: a safe exact byte range could not be established for this frame."; return; }
        SelectedFieldBytesText = $"{node.Label}: byte offset {offset}, length {length}\n{FormatHex(_selectedPacketBytes.Skip(offset).Take(length).ToArray())}";
        PacketBytes.HighlightFieldRange(offset, length, node.Label);
    }

    private static bool TryResolveFieldRange(byte[] packet, string field, NetworkRowViewModel? row, out int offset, out int length)
    {
        offset = 0; length = 0;
        if (field == "frame") { length = packet.Length; return true; }
        if (packet.Length < 14) return false;
        if (field == "ether_type") { offset = 12; length = 2; return true; }
        var network = 14;
        var etherType = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(12, 2));
        while ((etherType is 0x8100 or 0x88A8) && packet.Length >= network + 4)
        { etherType = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(network + 2, 2)); network += 4; }
        int transport;
        if (etherType == 0x0800)
        {
            var ihl = (packet[network] & 0x0F) * 4;
            if (packet.Length < network + ihl) return false;
            if (field == "ip_protocol") { offset = network + 9; length = 1; return true; }
            if (field == "ip_source") { offset = network + 12; length = 4; return true; }
            if (field == "ip_destination") { offset = network + 16; length = 4; return true; }
            transport = network + ihl;
        }
        else if (etherType == 0x86DD)
        {
            if (packet.Length < network + 40) return false;
            if (field == "ip_protocol") { offset = network + 6; length = 1; return true; }
            if (field == "ip_source") { offset = network + 8; length = 16; return true; }
            if (field == "ip_destination") { offset = network + 24; length = 16; return true; }
            transport = network + 40;
        }
        else return false;
        if (field is "local_port" or "remote_port" && packet.Length >= transport + 4 && row is not null)
        {
            var sourcePort = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(transport, 2));
            var localIsSource = sourcePort == row.LocalPort;
            offset = transport + (field == "local_port" ? (localIsSource ? 0 : 2) : (localIsSource ? 2 : 0));
            length = 2; return true;
        }
        return false;
    }

    private static string FormatHex(byte[] bytes)
    {
        var output = new StringBuilder(bytes.Length * 4);
        for (var offset = 0; offset < bytes.Length; offset += 16)
        {
            output.Append(offset.ToString("x6")).Append("  ");
            var count = Math.Min(16, bytes.Length - offset);
            for (var i = 0; i < 16; i++)
                output.Append(i < count ? bytes[offset + i].ToString("x2") + " " : "   ");
            output.Append(" ");
            for (var i = 0; i < count; i++)
            {
                var value = bytes[offset + i];
                output.Append(value is >= 32 and <= 126 ? (char)value : '.');
            }
            output.AppendLine();
        }
        return output.ToString();
    }

    private bool FilterPredicate(object obj)
    {
        if (obj is not NetworkRowViewModel row) return true;
        if (SelectedAdapter != "All captured adapters" && !string.Equals(row.Adapter, SelectedAdapter, StringComparison.OrdinalIgnoreCase)) return false;
        if (string.IsNullOrWhiteSpace(FilterText)) return true;
        var needle = FilterText.Trim();
        var colon = needle.IndexOf(':');
        if (colon > 0)
        {
            var field = needle[..colon].Trim().ToLowerInvariant();
            var value = needle[(colon + 1)..].Trim();
            return field switch
            {
                "protocol" => row.Protocol.Contains(value, StringComparison.OrdinalIgnoreCase),
                "ip" => row.LocalIp.Contains(value, StringComparison.OrdinalIgnoreCase) || row.RemoteIp.Contains(value, StringComparison.OrdinalIgnoreCase),
                "port" => row.LocalPort.ToString() == value || row.RemotePort.ToString() == value,
                "process" => row.Process.Contains(value, StringComparison.OrdinalIgnoreCase),
                "adapter" => row.Adapter.Contains(value, StringComparison.OrdinalIgnoreCase),
                "direction" => row.Direction.Contains(value, StringComparison.OrdinalIgnoreCase),
                _ => false
            };
        }
        return row.RemoteAddress.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.LocalAddress.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.Process.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.Protocol.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    private void Tick()
    {
        var snapshot = Header.State.Tailer.Records.Snapshot();
        _sync.Sync(snapshot);
        RescanRawCaptureFiles();
        var selectedAdapter = SelectedAdapter;
        var adapters = Rows.Select(row => row.Adapter).Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(value => value).ToList();
        if (adapters.Count + 1 != Adapters.Count || !adapters.SequenceEqual(Adapters.Skip(1), StringComparer.OrdinalIgnoreCase))
        {
            Adapters.Clear(); Adapters.Add("All captured adapters"); foreach (var adapter in adapters) Adapters.Add(adapter);
            SelectedAdapter = Adapters.Contains(selectedAdapter) ? selectedAdapter : "All captured adapters";

            var captureSelection = CaptureBar.SelectedAdapter;
            CaptureBar.AvailableAdapters.Clear();
            foreach (var adapter in Adapters) CaptureBar.AvailableAdapters.Add(adapter);
            CaptureBar.SelectedAdapter = CaptureBar.AvailableAdapters.Contains(captureSelection)
                ? captureSelection : "All captured adapters";
        }

        SummaryText = Header.State.Tailer.ActiveFilePath is null
            ? "No active log file found for this endpoint yet."
            : $"{Rows.Count:N0} packets in view (bounded).";

        var now = DateTimeOffset.UtcNow;
        var elapsedSeconds = Math.Max(0.001, (now - _lastCaptureStatsUtc).TotalSeconds);
        var health = Header.State.Tailer.LastHealth is null
            ? null : HealthSnapshot.FromRecord(Header.State.Tailer.LastHealth);
        var captured = health?.RecordsSeen ?? Rows.Count;
        var dropped = health?.RecordsDropped ??
            Counter(health, "capture_drops") + Counter(health, "interface_drops") +
            Counter(health, "logger_drops");
        var rate = Math.Max(0, captured - _lastCaptureCount) / elapsedSeconds;
        _lastCaptureCount = captured;
        _lastCaptureStatsUtc = now;
        var retained = RawCaptureFiles.Sum(file => file.SizeBytes);
        var newestSegment = RawCaptureFiles.FirstOrDefault()?.FileName ?? "";
        var state = Header.State.IsRunning
            ? health?.Collecting == false ? "Paused" : "Live"
            : "Stopped";
        if (CaptureBar.CaptureStartedUtc is null && health?.StartedAtUnixMs is > 0)
            CaptureBar.CaptureStartedUtc = DateTimeOffset.FromUnixTimeMilliseconds(health.StartedAtUnixMs.Value);
        CaptureBar.UpdateStats(captured, dropped, health?.SourceLoss ?? 0, rate,
            state, newestSegment, retained);

        var byProtocol = Rows.GroupBy(r => string.IsNullOrEmpty(r.Protocol) ? "UNKNOWN" : r.Protocol)
            .Select(g => new ProtocolCountViewModel { Protocol = g.Key, Count = g.Count() })
            .OrderByDescending(p => p.Count)
            .Take(10)
            .ToList();
        ProtocolHierarchy.Clear();
        foreach (var p in byProtocol) ProtocolHierarchy.Add(p);

        var byRemote = Rows.GroupBy(r => r.RemoteAddress)
            .Select(g => new TopTalkerViewModel
            {
                RemoteAddress = g.Key,
                TotalBytes = g.Sum(r => r.BytesSent + r.BytesRecv),
                PacketCount = g.Count()
            })
            .OrderByDescending(t => t.TotalBytes)
            .Take(10)
            .ToList();
        TopTalkers.Clear();
        foreach (var t in byRemote) TopTalkers.Add(t);

        var grouped = Rows.Where(row => row.LocalPort > 0 || row.RemotePort > 0)
            .GroupBy(ConversationKey)
            .Select(group =>
            {
                var first = group.First();
                var endpoints = new[] { first.LocalAddress, first.RemoteAddress }.OrderBy(value => value, StringComparer.Ordinal).ToArray();
                return (Key: group.Key, EndpointA: endpoints[0], EndpointB: endpoints[1], Protocol: first.Protocol,
                    TransportProtocolNumber: group.Select(row => row.TransportProtocolNumber).FirstOrDefault(number => number > 0),
                    Process: first.Process, Packets: group.Count(),
                    Bytes: group.Sum(row => Math.Max(row.Length, row.BytesSent + row.BytesRecv)),
                    FirstEpochUs: group.Min(row => row.CaptureEpochUs), LastEpochUs: group.Max(row => row.CaptureEpochUs));
            }).OrderByDescending(item => item.LastEpochUs).Take(500).ToList();

        // Key-based upsert into stable object identities, then position with Move -- never Clear()
        // or index-based Replace. ConversationsGrid's SelectedItem is TwoWay-bound; Clear() raises a
        // Reset notification (WPF's Selector always unselects on Reset), and replacing the object
        // reference at the selected index has the same effect. Every tick previously rebuilt this
        // whole collection from scratch, so a real Follow TCP Stream/Export click landing during
        // that window was silently dropped -- no exception, no window, no feedback (ButtonBase
        // re-checks Command.CanExecute immediately before Execute). Found live via
        // NetworkLiveCaptureTests. A conversation that persists across ticks now keeps the exact
        // same NetworkConversationViewModel instance (its properties are mutated in place instead),
        // so SelectedConversation's identity survives regardless of how its stats change or where it
        // re-sorts to; Move only changes position, never identity, and WPF's Selector does not lose
        // selection on Move.
        var existingByKey = Conversations.ToDictionary(c => c.Key);
        var desired = new List<NetworkConversationViewModel>(grouped.Count);
        foreach (var src in grouped)
        {
            if (!existingByKey.TryGetValue(src.Key, out var vm))
                vm = new NetworkConversationViewModel { Key = src.Key, EndpointA = src.EndpointA, EndpointB = src.EndpointB };
            vm.Protocol = src.Protocol;
            vm.TransportProtocolNumber = src.TransportProtocolNumber;
            vm.Process = src.Process;
            vm.Packets = src.Packets;
            vm.Bytes = src.Bytes;
            vm.FirstEpochUs = src.FirstEpochUs;
            vm.LastEpochUs = src.LastEpochUs;
            desired.Add(vm);
        }
        for (var i = 0; i < desired.Count; i++)
        {
            if (i < Conversations.Count && ReferenceEquals(Conversations[i], desired[i])) continue;
            var existingIndex = Conversations.IndexOf(desired[i]);
            if (existingIndex >= 0) Conversations.Move(existingIndex, i);
            else Conversations.Insert(i, desired[i]);
        }
        while (Conversations.Count > desired.Count) Conversations.RemoveAt(Conversations.Count - 1);
    }

    private static string ConversationKey(NetworkRowViewModel row)
    {
        var endpoints = new[] { row.LocalAddress, row.RemoteAddress }.OrderBy(value => value, StringComparer.Ordinal).ToArray();
        return $"{row.TransportProtocolNumber}|{row.Protocol.ToUpperInvariant()}|{endpoints[0]}|{endpoints[1]}";
    }

    private static bool IsTcpConversation(NetworkConversationViewModel? conversation)
    {
        if (conversation is null) return false;
        if (conversation.TransportProtocolNumber == 6) return true;
        var protocol = conversation.Protocol;
        return protocol.Contains("TCP", StringComparison.OrdinalIgnoreCase) ||
               protocol.Contains("HTTP", StringComparison.OrdinalIgnoreCase) ||
               protocol.Contains("TLS", StringComparison.OrdinalIgnoreCase);
    }

    private static long Counter(HealthSnapshot? health, string name) =>
        health?.Counters.TryGetValue(name, out var value) == true ? value : 0;

    private async Task OpenFollowStreamWindowAsync()
    {
        var conversation = SelectedConversation;
        if (conversation is null) return;

        // FollowStreamCommand invokes this fire-and-forget (`_ = OpenFollowStreamWindowAsync()`) --
        // without this try/catch, any exception here (including one thrown before window.Show())
        // becomes an unobserved Task exception: no crash log entry, no window, and no feedback to
        // the operator that their click did nothing. Found live via NetworkLiveCaptureTests.
        try
        {
            var rows = Rows.Where(row => ConversationKey(row) == conversation.Key)
                .OrderBy(row => row.CaptureEpochUs)
                .Take(FollowStreamViewModel.MaxInputRecords)
                .ToList();
            var viewModel = new FollowStreamViewModel();
            var window = new FollowStreamWindow(viewModel)
            {
                Owner = Application.Current?.MainWindow
            };
            window.Show();
            await viewModel.LoadAsync(conversation.Key, conversation.EndpointA,
                conversation.EndpointB, conversation.Protocol, rows, _rawCaptureDirectory);
        }
        catch (Exception ex)
        {
            FollowStreamText = $"Could not open the Follow TCP Stream window: {ex}";
        }
    }

    private async Task BuildFollowStreamAsync(NetworkConversationViewModel? conversation)
    {
        if (conversation is null) { FollowStreamText = "Select a conversation to reconstruct retained TCP payloads."; return; }
        FollowStreamText = "Reconstructing retained packets...";
        var rows = Rows.Where(row => ConversationKey(row) == conversation.Key && row.RawCaptureMapped)
            .OrderBy(row => row.CaptureEpochUs).Take(4096).ToList();
        var result = await Task.Run(() =>
        {
            var output = new StringBuilder();
            var nextSequence = new Dictionary<string, uint>();
            var retained = 0;
            var encrypted = rows.Any(row => row.Protocol.Contains("TLS", StringComparison.OrdinalIgnoreCase) ||
                                             row.LocalPort == 443 || row.RemotePort == 443);
            foreach (var row in rows)
            {
                try
                {
                    var path = Path.Combine(_rawCaptureDirectory, Path.GetFileName(row.RawCaptureSegment));
                    var bytes = ReadMappedPacketBytes(path, row);
                    if (!TryGetTcpPayload(bytes, out var sequence, out var flags, out var payload)) continue;
                    var direction = row.LocalAddress == conversation.EndpointA ? "A → B" : "B → A";
                    var status = "";
                    if (nextSequence.TryGetValue(direction, out var expected))
                    {
                        if (sequence < expected) status = " retransmission/overlap";
                        else if (sequence > expected) status = $" GAP {sequence - expected} byte(s)";
                    }
                    var end = sequence + (uint)payload.Length;
                    if (!nextSequence.TryGetValue(direction, out var current) || end > current) nextSequence[direction] = end;
                    if (payload.Length == 0) continue;
                    if (retained + payload.Length > 1024 * 1024) { output.AppendLine("[Output stopped at the 1 MiB investigation limit.]"); break; }
                    retained += payload.Length;
                    output.AppendLine($"[{direction}] seq={sequence} flags={flags}{status} payload={payload.Length} bytes");
                    output.AppendLine(encrypted ? FormatHex(payload) : FormatPayload(payload));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { output.AppendLine($"[Unavailable packet: {ex.Message}]"); }
            }
            if (output.Length == 0) output.AppendLine("No retained TCP payload was available for this conversation.");
            if (encrypted) output.Insert(0, "TLS/encrypted conversation: ciphertext is shown as hex; TITAN does not claim decrypted application content.\n\n");
            return output.ToString();
        });
        FollowStreamText = result;
    }

    private void ExportSelectedConversation()
    {
        if (SelectedConversation is null) return;
        var dialog = new Microsoft.Win32.SaveFileDialog { Filter = "JSON (*.json)|*.json|Text (*.txt)|*.txt", FileName = "titan-conversation" };
        if (dialog.ShowDialog() != true) return;
        var content = Path.GetExtension(dialog.FileName).Equals(".json", StringComparison.OrdinalIgnoreCase)
            ? JsonSerializer.Serialize(new { conversation = SelectedConversation, packets = Rows.Where(row => ConversationKey(row) == SelectedConversation.Key).Select(row => JsonDocument.Parse(row.RawJson).RootElement.Clone()).ToArray() }, new JsonSerializerOptions { WriteIndented = true })
            : FollowStreamText;
        File.WriteAllText(dialog.FileName, content, new UTF8Encoding(false));
    }

    private static byte[] ReadMappedPacketBytes(string path, NetworkRowViewModel row)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 64 * 1024, FileOptions.RandomAccess);
        if (row.RawRecordOffset < 24 || row.RawRecordOffset > stream.Length - 16) throw new IOException("PCAP record offset is unavailable.");
        stream.Position = row.RawRecordOffset;
        Span<byte> header = stackalloc byte[16]; stream.ReadExactly(header);
        var captured = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(8, 4));
        if (captured > 1024 * 1024 || stream.Position + captured > stream.Length) throw new IOException("PCAP record is incomplete.");
        var bytes = new byte[captured]; stream.ReadExactly(bytes); return bytes;
    }

    private static bool TryGetTcpPayload(byte[] packet, out uint sequence, out string flags, out byte[] payload)
    {
        sequence = 0; flags = ""; payload = Array.Empty<byte>();
        if (packet.Length < 34) return false;
        var network = 14;
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
        flags = $"0x{packet[tcp + 13]:x2}";
        payload = packet[(tcp + headerLength)..];
        return true;
    }

    private static string FormatPayload(byte[] payload)
    {
        if (payload.All(value => value is 9 or 10 or 13 || value is >= 32 and <= 126)) return Encoding.UTF8.GetString(payload);
        return FormatHex(payload);
    }
}
