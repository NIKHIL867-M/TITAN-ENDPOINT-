using System.Collections.ObjectModel;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;

namespace TitanEndpoint.App.ViewModels;

/// <summary>
/// FORU.TXT section C — "Build the capture toolbar": native capture state, selected adapter(s),
/// capture profile/filter, display filter, Start/Pause/Stop, Apply, Clear, recent/saved filters,
/// validation result, packet rate, captured/dropped/source-loss counts, retained PCAP segment,
/// and elapsed time. Visually distinguishes native capture filters from GUI display filters.
///
/// This ViewModel is deliberately separate from NetworkViewModel (which owns the packet list,
/// protocol tree, conversations and Follow Stream) so neither class becomes an unbounded god-object,
/// matching the FORU.TXT instruction: "Create these focused GUI files rather than turning
/// NetworkViewModel into one unbounded class."
///
/// Adapter/capture reconfiguration is NOT yet enabled through authenticated native IPC — the
/// current adapter selector is a GUI display filter. This class tracks that honest state and
/// exposes it to the UI so the distinction is always visible, never hidden.
/// </summary>
public sealed class NetworkCaptureBarViewModel : ViewModelBase
{
    // ---- Capture state (read from native health / status IPC) ----

    private string _captureState = "Unknown";
    /// <summary>Human-readable native capture state: Live, Paused, Stopped, Error, etc.</summary>
    public string CaptureState
    {
        get => _captureState;
        set => SetField(ref _captureState, value);
    }

    private bool _isCapturing;
    public bool IsCapturing
    {
        get => _isCapturing;
        set { if (SetField(ref _isCapturing, value)) { OnPropertyChanged(nameof(CaptureStatusText)); } }
    }

    public string CaptureStatusText => IsCapturing ? "● LIVE" : "○ Not capturing";

    // ---- Adapter selection (GUI display filter only, NOT native capture reconfiguration) ----

    public ObservableCollection<string> AvailableAdapters { get; } = new() { "All captured adapters" };

    private string _selectedAdapter = "All captured adapters";
    public string SelectedAdapter
    {
        get => _selectedAdapter;
        set => SetField(ref _selectedAdapter, value);
    }

    /// <summary>
    /// Honest label: adapter selection is a GUI display filter over retained evidence, not native
    /// capture reconfiguration. FORU.TXT: "Never label GUI filtering as capture control."
    /// </summary>
    public string AdapterFilterNote =>
        "Adapter selection filters retained evidence. It does not reconfigure the native capture.";

    // ---- Display filter (GUI-side, applied to the already-captured packet collection) ----

    private string _displayFilter = "";
    public string DisplayFilter
    {
        get => _displayFilter;
        set { if (SetField(ref _displayFilter, value)) ValidateDisplayFilter(); }
    }

    private string _displayFilterValidation = "";
    public string DisplayFilterValidation
    {
        get => _displayFilterValidation;
        private set => SetField(ref _displayFilterValidation, value);
    }

    private bool _displayFilterValid = true;
    public bool DisplayFilterValid
    {
        get => _displayFilterValid;
        private set => SetField(ref _displayFilterValid, value);
    }

    // ---- Native capture filter (placeholder — requires authenticated native IPC to apply) ----

    private string _nativeCaptureFilter = "";
    /// <summary>
    /// BPF-style capture filter string. Currently display-only.
    /// Applying it to the native producer requires authenticated revision-bound IPC which is
    /// not yet implemented in this build (FORU.TXT: "Never enable an adapter/filter mutation
    /// until native authenticated acknowledgement exists").
    /// </summary>
    public string NativeCaptureFilter
    {
        get => _nativeCaptureFilter;
        set => SetField(ref _nativeCaptureFilter, value);
    }

    public bool CanApplyNativeFilter => false; // Not yet backed by authenticated IPC.
    public string NativeFilterNote =>
        "Native capture-filter reconfiguration is not yet enabled. It requires authenticated IPC with the native endpoint.";

    // ---- Statistics (refreshed from native health / LogTailer summary) ----

    private long _capturedPackets;
    public long CapturedPackets
    {
        get => _capturedPackets;
        set { if (SetField(ref _capturedPackets, value)) OnPropertyChanged(nameof(StatsText)); }
    }

    private long _droppedPackets;
    public long DroppedPackets
    {
        get => _droppedPackets;
        set { if (SetField(ref _droppedPackets, value)) OnPropertyChanged(nameof(StatsText)); }
    }

    private long _sourceLoss;
    public long SourceLoss
    {
        get => _sourceLoss;
        set { if (SetField(ref _sourceLoss, value)) OnPropertyChanged(nameof(StatsText)); }
    }

    private double _packetsPerSecond;
    public double PacketsPerSecond
    {
        get => _packetsPerSecond;
        set { if (SetField(ref _packetsPerSecond, value)) OnPropertyChanged(nameof(StatsText)); }
    }

    public string StatsText =>
        $"Captured: {CapturedPackets:N0}  Dropped: {DroppedPackets:N0}  Source loss: {SourceLoss:N0}  Rate: {PacketsPerSecond:N1}/s";

    // ---- Retained PCAP segment ----

    private string _retainedPcapSegment = "";
    public string RetainedPcapSegment
    {
        get => _retainedPcapSegment;
        set => SetField(ref _retainedPcapSegment, value);
    }

    private long _retainedPcapBytes;
    public long RetainedPcapBytes
    {
        get => _retainedPcapBytes;
        set { if (SetField(ref _retainedPcapBytes, value)) OnPropertyChanged(nameof(RetainedSizeText)); }
    }

    public string RetainedSizeText => RetainedPcapBytes > 0
        ? $"PCAP: {RetainedPcapBytes / 1024.0 / 1024.0:N2} MiB retained"
        : "No PCAP data retained";

    // ---- Elapsed time ----

    private DateTimeOffset? _captureStartedUtc;
    public DateTimeOffset? CaptureStartedUtc
    {
        get => _captureStartedUtc;
        set { if (SetField(ref _captureStartedUtc, value)) OnPropertyChanged(nameof(ElapsedText)); }
    }

    public string ElapsedText
    {
        get
        {
            if (CaptureStartedUtc is null) return "";
            var elapsed = DateTimeOffset.UtcNow - CaptureStartedUtc.Value;
            return elapsed.TotalHours >= 1
                ? $"{(int)elapsed.TotalHours:D2}:{elapsed.Minutes:D2}:{elapsed.Seconds:D2}"
                : $"{elapsed.Minutes:D2}:{elapsed.Seconds:D2}";
        }
    }

    // ---- Recent / saved display filters ----

    public ObservableCollection<string> RecentDisplayFilters { get; } = new();
    private const int MaxRecentFilters = 10;

    public RelayCommand ApplyDisplayFilterCommand  { get; }
    public RelayCommand ClearDisplayFilterCommand  { get; }
    public RelayCommand SaveFilterCommand          { get; }

    public NetworkCaptureBarViewModel()
    {
        ApplyDisplayFilterCommand = new RelayCommand(ApplyDisplayFilter, () => DisplayFilterValid);
        ClearDisplayFilterCommand = new RelayCommand(ClearDisplayFilter);
        SaveFilterCommand         = new RelayCommand(SaveCurrentFilter, () => !string.IsNullOrWhiteSpace(DisplayFilter));
    }

    private void ValidateDisplayFilter()
    {
        if (string.IsNullOrWhiteSpace(DisplayFilter))
        {
            DisplayFilterValid      = true;
            DisplayFilterValidation = "";
            return;
        }

        // Validate known prefix-colon syntax.
        var known = new[] { "protocol:", "ip:", "port:", "process:", "adapter:", "direction:" };
        var term  = DisplayFilter.Trim();
        var colon = term.IndexOf(':');
        if (colon > 0)
        {
            var prefix = term[..(colon + 1)].ToLowerInvariant();
            if (!known.Contains(prefix))
            {
                DisplayFilterValid      = false;
                DisplayFilterValidation = $"Unknown filter prefix '{prefix}'. Valid: protocol:, ip:, port:, process:, adapter:, direction:, or plain text.";
                return;
            }
            if (term.Length <= colon + 1)
            {
                DisplayFilterValid      = false;
                DisplayFilterValidation = "Filter value is empty after the colon.";
                return;
            }
        }

        DisplayFilterValid      = true;
        DisplayFilterValidation = $"Filter OK — plain-text search across all fields or prefixed by {string.Join(", ", known)}.";
        ApplyDisplayFilterCommand.RaiseCanExecuteChanged();
    }

    private void ApplyDisplayFilter()
    {
        // Signal to NetworkViewModel (which owns the CollectionView) to refresh.
        // NetworkViewModel subscribes to this event to avoid circular VM coupling.
        DisplayFilterApplied?.Invoke(this, DisplayFilter);
        AddToRecentFilters(DisplayFilter);
    }

    private void ClearDisplayFilter()
    {
        DisplayFilter = "";
        DisplayFilterApplied?.Invoke(this, "");
    }

    private void SaveCurrentFilter()
    {
        if (string.IsNullOrWhiteSpace(DisplayFilter)) return;
        AddToRecentFilters(DisplayFilter);
    }

    private void AddToRecentFilters(string filter)
    {
        if (string.IsNullOrWhiteSpace(filter)) return;
        RecentDisplayFilters.Remove(filter);
        RecentDisplayFilters.Insert(0, filter);
        while (RecentDisplayFilters.Count > MaxRecentFilters)
            RecentDisplayFilters.RemoveAt(RecentDisplayFilters.Count - 1);
    }

    /// <summary>
    /// Raised when the operator applies a display filter. NetworkViewModel subscribes and
    /// refreshes its CollectionView. Parameter is the new filter text (empty = clear).
    /// </summary>
    public event EventHandler<string>? DisplayFilterApplied;

    /// <summary>Updates statistics from a native health/status snapshot.</summary>
    public void UpdateStats(long captured, long dropped, long sourceLoss, double rate,
        string captureState, string retainedSegment, long retainedBytes)
    {
        CapturedPackets    = captured;
        DroppedPackets     = dropped;
        SourceLoss         = sourceLoss;
        PacketsPerSecond   = rate;
        CaptureState       = captureState;
        RetainedPcapSegment = retainedSegment;
        RetainedPcapBytes  = retainedBytes;
        IsCapturing        = captureState.Equals("Live", StringComparison.OrdinalIgnoreCase) ||
                             captureState.Equals("Capturing", StringComparison.OrdinalIgnoreCase);
        OnPropertyChanged(nameof(ElapsedText));
    }
}
