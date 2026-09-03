using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.Json;

namespace TitanEndpoint.App.ViewModels;

public sealed class CorrelationViewModel : ViewModelBase
{
    private const int MaxGroups = 1000;

    public EndpointHeaderViewModel Header { get; }
    public ObservableCollection<CorrelationRowViewModel> Rows { get; } = new();
    /// <summary>FORU.TXT 0.6 search. Refreshed explicitly after every sync tick (not just on
    /// FilterText change) since groups are mutated in place as revisions grow — ICollectionView's
    /// filter predicate does not automatically re-run on property changes to existing items.</summary>
    public ICollectionView RowsView { get; }
    public ObservableCollection<CorrelationGraphNodeViewModel> GraphNodes { get; } = new();
    public ObservableCollection<CorrelationGraphEdgeViewModel> GraphEdges { get; } = new();

    private string _filterText = "";
    public string FilterText
    {
        get => _filterText;
        set { if (SetField(ref _filterText, value)) RowsView.Refresh(); }
    }

    private string _summaryText = "Waiting for data...";
    public string SummaryText { get => _summaryText; private set => SetField(ref _summaryText, value); }

    private CorrelationRowViewModel? _selectedGroup;
    public CorrelationRowViewModel? SelectedGroup
    {
        get => _selectedGroup;
        set
        {
            // Santosh, Round 22: same "new ones come and go but the clicked thing should stay" ask as
            // ProcessViewModel.SelectedRow. SyncGroups' Rows.RemoveAt(0) can evict the selected group
            // once MaxGroups is exceeded, which resets the DataGrid's own SelectedItem to null and used
            // to blank the Timeline/Chain View/Evidence Graph/Raw JSON panel with no user action at all.
            // Only a genuine new selection (non-null) should ever change what's shown.
            if (value is null) return;
            if (SetField(ref _selectedGroup, value)) RebuildGraph();
        }
    }

    private double _graphZoom = 1;
    public double GraphZoom { get => _graphZoom; set => SetField(ref _graphZoom, Math.Clamp(value, 0.5, 2.0)); }

    private double _graphCanvasWidth = 600;
    /// <summary>Sized from the selected group's real member count instead of a fixed width, so a
    /// 2-member group isn't stranded in a mostly-empty 2200px canvas and a large group still gets
    /// enough room for every node -- an honest "neat regardless of size" bound, not a magic
    /// constant.</summary>
    public double GraphCanvasWidth { get => _graphCanvasWidth; private set => SetField(ref _graphCanvasWidth, value); }

    private readonly Dictionary<long, CorrelationRowViewModel> _byGroupId = new();
    private long _lastSeq = -1;
    private readonly DispatcherTimer _timer;

    public CorrelationViewModel()
    {
        Header = new EndpointHeaderViewModel(EndpointId.Correlator, "Cross-endpoint evidence correlation");
        RowsView = CollectionViewSource.GetDefaultView(Rows);
        RowsView.Filter = FilterPredicate;

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(700) };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        Tick();
    }

    private void Tick()
    {
        var tailer = Header.State.Tailer;
        var snapshot = tailer.Records.Snapshot();
        SyncGroups(snapshot);
        if (!string.IsNullOrWhiteSpace(FilterText)) RowsView.Refresh();

        var health = snapshot.LastOrDefault(r => r.IsCollectorHealth);
        var activeSources = health?.GetLong("active_sources");
        var configuredSources = health?.GetLong("configured_sources");
        var repeats = health?.GetLong("semantic_repeats_compacted") ?? 0;
        var connected = health?.GetLong("connected_events_emitted") ?? Rows.Count(r => r.Connections.Count > 0);
        var single = health?.GetLong("single_source_events_emitted") ?? Rows.Count(r => r.Connections.Count == 0);
        SummaryText = tailer.ActiveFilePath is null
            ? "No active log file found for this endpoint yet."
            : Rows.Count == 0
                ? "Live unified stream is waiting for new endpoint records. Existing history is not replayed."
                : $"Feeds {activeSources ?? 0}/{configuredSources ?? 0} active | {Rows.Count:N0} unified events in view | {connected:N0} connected | {single:N0} single-source | {repeats:N0} repeats compacted.";
    }

    private bool FilterPredicate(object obj)
    {
        if (string.IsNullOrWhiteSpace(FilterText)) return true;
        if (obj is not CorrelationRowViewModel row) return true;
        var needle = FilterText.Trim();
        return row.GroupId.ToString().Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.Endpoints.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.TimeSpanText.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.MissingEndpointsText.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// FORU.TXT 12.6: the engine emits one session_timeline JSONL line per REVISION as a group
    /// grows, plus one final "closed" revision at expiry — not one line per unique group. This
    /// upserts by group_id into a stable CorrelationRowViewModel instance (mutating it in
    /// place) instead of appending a new row per line, so Rows.Count is always the true unique
    /// group count and a live SelectedGroup selection survives further updates to that same
    /// group.
    /// </summary>
    private void SyncGroups(JsonRecord[] snapshot)
    {
        if (snapshot.Length == 0) return;

        if (_lastSeq >= 0 && snapshot[0].SequenceId > _lastSeq + 1 && snapshot[^1].SequenceId - snapshot.Length + 1 > _lastSeq)
        {
            Rows.Clear();
            _byGroupId.Clear();
            _lastSeq = -1;
        }

        foreach (var record in snapshot)
        {
            if (record.SequenceId <= _lastSeq) continue;
            _lastSeq = record.SequenceId;
            if (!record.Is("type", "session_timeline") && !record.Is("type", "unified_event")) continue;

            var groupId = record.GetLong("group_id") ?? 0;
            _byGroupId.TryGetValue(groupId, out var existing);
            var updated = CorrelationRowViewModel.From(record, existing);
            if (updated is null) continue;

            if (existing is null)
            {
                _byGroupId[groupId] = updated;
                Rows.Add(updated);
                while (Rows.Count > MaxGroups)
                {
                    _byGroupId.Remove(Rows[0].GroupId);
                    Rows.RemoveAt(0);
                }
            }
            // else: updated IS existing, mutated in place -- already reflected via INotifyPropertyChanged.
            if (ReferenceEquals(existing, SelectedGroup)) RebuildGraph();
        }
    }

    private void RebuildGraph()
    {
        GraphNodes.Clear();
        GraphEdges.Clear();
        if (SelectedGroup is null) { GraphCanvasWidth = 600; return; }
        const double startX = 30, startY = 45, width = 210, gap = 70, minWidth = 600;
        for (var i = 0; i < SelectedGroup.Members.Count; i++)
        {
            var member = SelectedGroup.Members[i];
            var x = startX + i * (width + gap);
            GraphNodes.Add(new CorrelationGraphNodeViewModel(x, startY, width, member));
        }
        foreach (var connection in SelectedGroup.Connections)
        {
            if (connection.FromIndex < 0 || connection.ToIndex < 0 ||
                connection.FromIndex >= SelectedGroup.Members.Count || connection.ToIndex >= SelectedGroup.Members.Count) continue;
            var from = SelectedGroup.Members[connection.FromIndex];
            var to = SelectedGroup.Members[connection.ToIndex];
            GraphEdges.Add(new CorrelationGraphEdgeViewModel(
                startX + connection.FromIndex * (width + gap) + width, startY + 42,
                startX + connection.ToIndex * (width + gap), startY + 42,
                connection.Confidence, connection.ConfidenceScore, connection.Reason,
                connection.DeltaMs, from.NativeRecordId, to.NativeRecordId));
        }
        GraphCanvasWidth = Math.Max(minWidth, startX * 2 + SelectedGroup.Members.Count * (width + gap));
    }
}

public sealed record CorrelationGraphNodeViewModel(double X, double Y, double Width, CorrelationMemberViewModel Member)
{
    public string Label => $"{Member.DisplayEndpoint}\n{Member.RecordType}\n{Member.DeltaText} | {Member.RepeatText}\n{Member.ConfidenceTag}";
    public RelayCommand OpenEvidenceCommand => Member.OpenEvidenceCommand;
}

public sealed record CorrelationGraphEdgeViewModel(double X1, double Y1, double X2, double Y2,
    string Confidence, double Score, string Reason, long DeltaMs, string FromRecordId, string ToRecordId)
{
    public string ToolTip => $"{Confidence} {(Score > 0 ? Score.ToString("P0") : "unscored")} — {Reason}; Δ{DeltaMs} ms\n{FromRecordId} → {ToRecordId}";

    /// <summary>Real-data-driven visual weight for the join edge: a stronger, more opaque accent
    /// stroke for a higher-confidence join, a fainter one for a lower/unscored one. Deliberately an
    /// opacity variation on the existing accent brush, not a new color -- FORU.TXT 0.4 reserves
    /// green/amber/red exclusively for acknowledged health state, not data classification.</summary>
    public double StrokeOpacity => Score > 0 ? Math.Clamp(0.35 + Score * 0.65, 0.35, 1.0) : Confidence switch
    {
        "high" => 0.95,
        "medium" => 0.7,
        "low" => 0.45,
        _ => 0.55
    };
}
