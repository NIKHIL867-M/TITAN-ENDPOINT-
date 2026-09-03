using System.Collections.ObjectModel;
using System.Text;
using TitanEndpoint.App.Common;

namespace TitanEndpoint.App.ViewModels;

/// <summary>
/// FORU.TXT section C — "Packet bytes: place a synchronized offset + hexadecimal + ASCII pane
/// beside/below the protocol tree. Keep scroll position and selection stable; highlight field
/// bytes in both hex and ASCII; support copy as hex, escaped bytes, or text. If the PCAP
/// segment/offset/hash fails validation, show Expired/Mismatch and do not substitute unrelated
/// bytes. TLS payload remains ciphertext unless a future, explicit decryptor exists."
///
/// PacketBytesViewModel is the backing model for the offset/hex/ASCII pane. It is constructed
/// once and kept alive alongside NetworkViewModel; the packet list calls LoadPacket() when
/// the selected row changes. This keeps byte-pane concerns (chunked display, field highlight,
/// copy format) separate from the packet list and protocol tree.
/// </summary>
public sealed class PacketBytesViewModel : ViewModelBase
{
    private const int BytesPerRow = 16;
    private const int MaxDisplayBytes = 64 * 1024; // 64 KiB display limit

    // ---- State ----

    private byte[]? _packetBytes;

    private string _statusMessage = "Select a packet to view raw capture bytes.";
    /// <summary>Human-readable load/validation/error state shown above the hex pane.</summary>
    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetField(ref _statusMessage, value);
    }

    private bool _hasBytes;
    public bool HasBytes
    {
        get => _hasBytes;
        private set => SetField(ref _hasBytes, value);
    }

    // ---- Hex/ASCII display lines ----

    public ObservableCollection<HexLine> Lines { get; } = new();

    // ---- Field highlight ----

    private int _highlightOffset = -1;
    private int _highlightLength;

    // ---- Copy format ----

    private CopyFormat _activeCopyFormat = CopyFormat.HexDump;
    public CopyFormat ActiveCopyFormat
    {
        get => _activeCopyFormat;
        set => SetField(ref _activeCopyFormat, value);
    }

    // ---- Commands ----

    public RelayCommand CopyAllCommand        { get; }
    public RelayCommand CopyAsHexCommand      { get; }
    public RelayCommand CopyAsEscapedCommand  { get; }
    public RelayCommand CopyAsTextCommand     { get; }

    public PacketBytesViewModel()
    {
        CopyAllCommand       = new RelayCommand(CopyAll,       () => HasBytes);
        CopyAsHexCommand     = new RelayCommand(CopyAsHex,     () => HasBytes);
        CopyAsEscapedCommand = new RelayCommand(CopyAsEscaped, () => HasBytes);
        CopyAsTextCommand    = new RelayCommand(CopyAsText,    () => HasBytes);
    }

    // ---- Public API called by NetworkViewModel ----

    /// <summary>Clears the pane and shows an appropriate status message.</summary>
    public void Clear(string message = "Select a packet to view raw capture bytes.")
    {
        _packetBytes = null;
        HasBytes     = false;
        StatusMessage = message;
        Lines.Clear();
        ClearHighlight();
        RaiseAllCopyCommands();
    }

    /// <summary>
    /// Loads validated packet bytes into the pane, rebuilding the hex/ASCII line list.
    /// </summary>
    public void LoadBytes(byte[] bytes, string statusMessage)
    {
        _packetBytes = bytes;
        HasBytes     = true;
        StatusMessage = statusMessage;
        ClearHighlight();
        RebuildLines(bytes);
        RaiseAllCopyCommands();
    }

    /// <summary>
    /// Shows an error/validation state without any bytes (expired PCAP, hash mismatch, etc.).
    /// FORU.TXT: "If the PCAP segment/offset/hash fails validation, show Expired/Mismatch
    /// and do not substitute unrelated bytes."
    /// </summary>
    public void ShowValidationError(string reason)
    {
        _packetBytes  = null;
        HasBytes      = false;
        StatusMessage = reason;
        Lines.Clear();
        ClearHighlight();
        RaiseAllCopyCommands();
    }

    /// <summary>
    /// Highlights the byte range [offset, offset+length) in both the hex and ASCII columns.
    /// Called when the operator selects a protocol-tree field.
    /// </summary>
    public void HighlightFieldRange(int offset, int length, string fieldLabel)
    {
        if (_packetBytes is null || offset < 0 || length <= 0 || offset + length > _packetBytes.Length)
        {
            ClearHighlight();
            return;
        }

        _highlightOffset = offset;
        _highlightLength = length;
        RebuildLines(_packetBytes);

        var sliceHex  = string.Join(" ", _packetBytes.Skip(offset).Take(length).Select(b => b.ToString("x2")));
        StatusMessage = $"{fieldLabel}: offset {offset}, length {length}  |  {sliceHex}";
    }

    private void ClearHighlight()
    {
        _highlightOffset = -1;
        _highlightLength = 0;
    }

    // ---- Display line building ----

    private void RebuildLines(byte[] bytes)
    {
        Lines.Clear();
        var displayBytes = bytes.Length > MaxDisplayBytes ? bytes.AsSpan(0, MaxDisplayBytes) : bytes.AsSpan();
        var rowCount = (displayBytes.Length + BytesPerRow - 1) / BytesPerRow;
        for (var row = 0; row < rowCount; row++)
        {
            var start = row * BytesPerRow;
            var count = Math.Min(BytesPerRow, displayBytes.Length - start);
            var slice = displayBytes.Slice(start, count);

            // Build hex column (16 groups of "xx " padded to fixed width).
            var hexSb = new StringBuilder(BytesPerRow * 3);
            for (var i = 0; i < BytesPerRow; i++)
            {
                if (i < count) hexSb.Append(slice[i].ToString("x2") + " ");
                else           hexSb.Append("   ");
                if (i == 7)    hexSb.Append(' '); // mid-group gap
            }

            // Build ASCII column.
            var asciiSb = new StringBuilder(BytesPerRow);
            for (var i = 0; i < count; i++)
            {
                var b = slice[i];
                asciiSb.Append(b is >= 32 and <= 126 ? (char)b : '.');
            }

            // Determine highlight state for this row.
            var rowHighlight = HighlightKind.None;
            if (_highlightOffset >= 0)
            {
                var rowEnd = start + count;
                var hEnd   = _highlightOffset + _highlightLength;
                if (_highlightOffset < rowEnd && hEnd > start)
                    rowHighlight = HighlightKind.Highlighted;
            }

            Lines.Add(new HexLine
            {
                Offset    = start.ToString("x6"),
                HexText   = hexSb.ToString(),
                AsciiText = asciiSb.ToString(),
                Highlight = rowHighlight
            });
        }

        if (bytes.Length > MaxDisplayBytes)
        {
            Lines.Add(new HexLine
            {
                Offset    = "",
                HexText   = $"... {bytes.Length - MaxDisplayBytes:N0} more bytes not displayed (64 KiB display limit).",
                AsciiText = "",
                Highlight = HighlightKind.None
            });
        }
    }

    // ---- Copy operations ----

    private void CopyAll()
    {
        if (_packetBytes is null) return;
        SetClipboard(ActiveCopyFormat == CopyFormat.HexDump ? BuildHexDump(_packetBytes)
                   : ActiveCopyFormat == CopyFormat.Escaped  ? BuildEscaped(_packetBytes)
                   :                                           Encoding.UTF8.GetString(_packetBytes.Where(b => b < 128).ToArray()));
    }

    private void CopyAsHex()     { if (_packetBytes is not null) SetClipboard(BuildHexDump(_packetBytes)); }
    private void CopyAsEscaped() { if (_packetBytes is not null) SetClipboard(BuildEscaped(_packetBytes)); }
    private void CopyAsText()    { if (_packetBytes is not null) SetClipboard(Encoding.UTF8.GetString(_packetBytes.Where(b => b < 128).ToArray())); }

    private static void SetClipboard(string text)
    {
        try { System.Windows.Clipboard.SetText(text); }
        catch { /* clipboard may be unavailable in headless test environments */ }
    }

    private static string BuildHexDump(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 4);
        for (var offset = 0; offset < bytes.Length; offset += 16)
        {
            sb.Append(offset.ToString("x6")).Append("  ");
            var count = Math.Min(16, bytes.Length - offset);
            for (var i = 0; i < 16; i++)
                sb.Append(i < count ? bytes[offset + i].ToString("x2") + " " : "   ");
            sb.Append("  ");
            for (var i = 0; i < count; i++)
            {
                var b = bytes[offset + i];
                sb.Append(b is >= 32 and <= 126 ? (char)b : '.');
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }

    private static string BuildEscaped(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 4);
        foreach (var b in bytes) sb.Append($"\\x{b:x2}");
        return sb.ToString();
    }

    private void RaiseAllCopyCommands()
    {
        CopyAllCommand.RaiseCanExecuteChanged();
        CopyAsHexCommand.RaiseCanExecuteChanged();
        CopyAsEscapedCommand.RaiseCanExecuteChanged();
        CopyAsTextCommand.RaiseCanExecuteChanged();
    }
}

public sealed class HexLine
{
    public string     Offset    { get; init; } = "";
    public string     HexText   { get; init; } = "";
    public string     AsciiText { get; init; } = "";
    public HighlightKind Highlight { get; init; }
}

public enum HighlightKind { None, Highlighted }
public enum CopyFormat    { HexDump, Escaped, Text }
