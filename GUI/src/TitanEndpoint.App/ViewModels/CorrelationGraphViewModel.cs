using System.Collections.ObjectModel;
using System.Text.Json;
using System.Windows.Media;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.Json;

namespace TitanEndpoint.App.ViewModels;

/// <summary>Live aggregate view of how the Correlator's real unified stream connects the five
/// sensor endpoints to each other over time. GUI-only: reads the same Correlator tailer every
/// other Correlation view already reads, adds no new native/backend logic, and never fabricates a
/// causal "flows into" direction the underlying data does not support -- an edge means "these two
/// endpoints have been joined by the Correlator N times", not "A always happens before B". Pairs
/// and per-endpoint totals only ever grow while this page is open (matching the live, cumulative
/// view Santosh asked for) and reset only when the app restarts, never silently.
///
/// This page used to ALSO persist its own "incident_graph.jsonl" (VISHNU.TXT: "write the incident
/// graph as logs itself"). That was removed once the native Correlator gained an equivalent,
/// strictly more detailed "endpoint_graph" section (endpoint-pair connection_count/reasons/
/// confidence) inside its own correlated_events.json (see CORRELATOR\correlated_snapshot_writer.cpp)
/// -- Santosh: "both the correlation and incident graph logs should be combined". Two independently
/// -written files that merely happened to agree was not that; one authoritative, always-on file
/// (the Correlator runs and logs regardless of whether this GUI page is ever opened) written by the
/// single process that actually owns the join logic is. This page still computes and DISPLAYS the
/// same live pentagon/incidents -- it just no longer writes a second copy to disk.</summary>
public sealed class CorrelationGraphViewModel : ViewModelBase
{
    private const int MaxTrackedGroups = 2000;

    private static readonly (string Key, string Label)[] EndpointDefs =
    {
        ("process", "Process"), ("network", "Network"), ("application", "Application"),
        ("file_integrity", "File"), ("port", "Port / USB")
    };

    private const int MaxTrackedChains = 300;
    private const int MaxDisplayedChains = 60;
    /// <summary>RAM/space bound, per Santosh's explicit "consider other aspects of design, RAM,
    /// space" instruction -- a pathological incident (hundreds of repeat_summary members) still gets
    /// fully counted and its common-fields summary still reflects every member, but the rendered
    /// card list is capped so one huge incident can't make the page heavy to scroll or render.</summary>
    private const int MaxDisplayedSegmentsPerIncident = 40;

    public EndpointHeaderViewModel Header { get; }
    public ObservableCollection<FlowNodeViewModel> Nodes { get; } = new();
    public ObservableCollection<FlowEdgeViewModel> Edges { get; } = new();
    public ObservableCollection<EndpointFlowSummaryViewModel> SummaryRows { get; } = new();
    /// <summary>Santosh, Round 22 (three passes): (1) "if I click on that number, I wanted to see
    /// those events"; (2) "not only 3, in the 5 endpoints... the way you portray the graph should
    /// change"; (3) "we have 5 endpoints, each has its own data -- take the common things out and
    /// link them... 16 chains keep coming, 10 chains containing 30 or 50 of the 5 endpoints... call
    /// it Incident Graph." Each entry is one real correlated group treated as an INCIDENT: every
    /// member actually involved (not flattened to a pair), plus the common fields extracted across
    /// them (PIDs, processes, time span) the way the old reference format's top-level arrays did.
    /// Populated continuously as real incidents happen -- clicking a pentagon edge narrows this to
    /// incidents touching that pair, it does not gate visibility of incidents in the first place.</summary>
    public ObservableCollection<IncidentViewModel> Incidents { get; } = new();

    private string _selectedPairText = "Showing all live incidents. Click a node to focus on that endpoint, or a connection line's count badge to focus on that pair -- click it again to clear.";
    public string SelectedPairText { get => _selectedPairText; private set => SetField(ref _selectedPairText, value); }

    /// <summary>Santosh, 2026-08-31: "when we run the whole application it will just keep on moving...
    /// if I wanted to select one particular incident I was not able to select even though if I click
    /// on it, it will just keep on going up." New incidents insert at index 0 continuously (Ingest
    /// below) -- there was no way to hold the list still to read or click a specific card before it
    /// got pushed down/replaced. New incidents keep accumulating in _allIncidents either way (nothing
    /// is lost while paused); only the visible Incidents collection stops changing, and catches up in
    /// one shot the moment this is turned back off.</summary>
    private bool _isPaused;
    public bool IsPaused
    {
        get => _isPaused;
        set
        {
            if (_isPaused == value) return;
            _isPaused = value;
            if (!_isPaused) RefreshDisplayedIncidents();
            OnPropertyChanged(nameof(IsPaused));
        }
    }

    private string _summaryText = "Waiting for correlated data...";
    public string SummaryText { get => _summaryText; private set => SetField(ref _summaryText, value); }

    public RelayCommand ShowAllIncidentsCommand { get; }

    /// <summary>Round 23 ("make it more interactable"): matches CorrelationView's proven Evidence
    /// Graph tab zoom slider exactly (same Minimum/Maximum order of magnitude, same ScaleTransform
    /// wiring) so this page's pentagon can be zoomed in after the layout was shrunk to fit its row
    /// without scrolling by default -- zooming back out to see detail no longer requires the
    /// ScrollViewer for the common case, only for zoom levels above 1.0.</summary>
    private double _graphZoom = 1.0;
    public double GraphZoom { get => _graphZoom; set => SetField(ref _graphZoom, Math.Clamp(value, 0.7, 1.8)); }

    private readonly Dictionary<string, EndpointFlowSummaryViewModel> _summaryByKey = new();
    private readonly Dictionary<string, FlowEdgeViewModel> _edgeByPairKey = new();
    /// <summary>Every real incident seen this session, newest first, bounded -- the single source of
    /// truth the pair filter narrows instead of maintaining a separate flattened list per pair
    /// (which is what made an earlier version lose the rest of a 3+ endpoint chain).</summary>
    private readonly List<IncidentViewModel> _allIncidents = new();
    private readonly Dictionary<long, int> _groupConnectionsSeen = new();
    private readonly Queue<long> _groupEvictionOrder = new();
    private string? _pairFilter;
    /// <summary>Round 23: a single clicked node narrows the incident list the same way a clicked
    /// pair already did -- mutually exclusive with _pairFilter, never both set at once.</summary>
    private string? _endpointFilter;
    private long _lastSeq = -1;
    private long _totalConnections;
    private readonly DispatcherTimer _timer;

    private static string PairKeyOf(string a, string b) => string.CompareOrdinal(a, b) <= 0 ? $"{a}|{b}" : $"{b}|{a}";

    /// <summary>Bound to each edge's SelectCommand -- narrows the always-visible incident list to
    /// ones that include this pair, without hiding incidents that don't. Clicking the same pair
    /// again clears the filter (Round 23 toggle -- previously the only way to clear was the separate
    /// "Show All Incidents" button).</summary>
    public void SelectPair(string pairKey)
    {
        _pairFilter = _pairFilter == pairKey ? null : pairKey;
        _endpointFilter = null;
        RefreshDisplayedIncidents();
        ApplyFilterVisuals();
    }

    /// <summary>Round 23 ("it still needs some GUI fixes... make it more interactable"): pentagon
    /// nodes had no interaction at all before this -- clicking one now does for a single endpoint
    /// what clicking an edge's count badge already did for a pair. Same toggle-to-clear behavior.</summary>
    public void SelectEndpoint(string endpointKey)
    {
        _endpointFilter = _endpointFilter == endpointKey ? null : endpointKey;
        _pairFilter = null;
        RefreshDisplayedIncidents();
        ApplyFilterVisuals();
    }

    private void RefreshDisplayedIncidents()
    {
        Incidents.Clear();
        List<IncidentViewModel> matches;
        if (_pairFilter is null && _endpointFilter is null)
        {
            matches = _allIncidents.Take(MaxDisplayedChains).ToList();
            SelectedPairText = matches.Count == 0
                ? "No connected incidents observed yet -- waiting for the Correlator to join real cross-endpoint activity."
                : $"Showing the {matches.Count} most recent live incidents (of {_allIncidents.Count} tracked this session), newest first.";
        }
        else if (_pairFilter is not null && _edgeByPairKey.TryGetValue(_pairFilter, out var edge))
        {
            matches = _allIncidents.Where(c => c.PairKeys.Contains(_pairFilter)).Take(MaxDisplayedChains).ToList();
            SelectedPairText = $"Filtered to {edge.PairLabel}: {edge.Count:N0} connection(s) so far. Showing the {matches.Count} most recent incidents that include this pair -- click the badge again to clear. An incident may involve more endpoints than just these two.";
        }
        else if (_endpointFilter is not null && _summaryByKey.TryGetValue(_endpointFilter, out var summaryRow))
        {
            matches = _allIncidents.Where(c => c.EndpointKeys.Contains(_endpointFilter)).Take(MaxDisplayedChains).ToList();
            SelectedPairText = $"Filtered to {summaryRow.Label}: {summaryRow.CrossLinks:N0} cross-endpoint connection(s) so far. Showing the {matches.Count} most recent incidents that touch this endpoint -- click the node again to clear.";
        }
        else
        {
            matches = new List<IncidentViewModel>();
            SelectedPairText = "No connections recorded for this selection yet.";
        }
        foreach (var incident in matches) Incidents.Add(incident);
    }

    /// <summary>Round 23: pushes the current node/pair filter (if any) onto every node and edge's
    /// own IsSelected/IsDimmed so the clicked thing and its immediate neighborhood stay at full
    /// opacity while everything unrelated visibly recedes -- previously every edge/node looked
    /// identical whether or not a filter was active, so a click's effect was only visible in the
    /// text below the pentagon, never in the pentagon itself. Cheap (at most 5 nodes/10 edges) so
    /// it just runs every Tick rather than needing to be threaded into every mutation site.</summary>
    private void ApplyFilterVisuals()
    {
        var filterActive = _pairFilter is not null || _endpointFilter is not null;
        var directTargets = new HashSet<string>();
        if (_pairFilter is not null) foreach (var k in _pairFilter.Split('|')) directTargets.Add(k);
        if (_endpointFilter is not null) directTargets.Add(_endpointFilter);

        var neighborhood = new HashSet<string>(directTargets);
        foreach (var edge in Edges)
        {
            var edgeKeys = edge.PairKey.Split('|');
            var matches = _pairFilter is not null ? edge.PairKey == _pairFilter
                : _endpointFilter is not null && edgeKeys.Contains(_endpointFilter);
            edge.IsDimmed = filterActive && !matches;
            if (matches) foreach (var k in edgeKeys) neighborhood.Add(k);
        }
        foreach (var node in Nodes)
        {
            node.IsSelected = directTargets.Contains(node.Key);
            node.IsDimmed = filterActive && !neighborhood.Contains(node.Key);
        }
    }

    public CorrelationGraphViewModel()
    {
        Header = new EndpointHeaderViewModel(EndpointId.Correlator,
            "Live endpoint-to-endpoint connection flow, built only from the Correlator's own unified stream");
        BuildNodesAndSummaryRows();
        ShowAllIncidentsCommand = new RelayCommand(() =>
        {
            _pairFilter = null;
            _endpointFilter = null;
            RefreshDisplayedIncidents();
            ApplyFilterVisuals();
        });

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(700) };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        Tick();
    }

    /// <summary>Round 23: pentagon shrunk from a 520x440 canvas (radius 165, 96px nodes) to fit
    /// inside its card's row without needing the ScrollViewer at default zoom -- the old geometry
    /// needed ~440px of vertical room but the row below the incident panel's 1.4-star weighting
    /// (see CorrelationGraphView.xaml's Round 22 comment on why incidents outweigh the graph) only
    /// ever actually rendered at ~230-260px even maximized, confirmed by direct screenshot: only the
    /// top node was ever visible without manually scrolling. This keeps that same deliberate
    /// incident-first weighting untouched and instead makes the graph itself small enough to earn
    /// its keep at the height it actually gets, with GraphZoom available to see it larger on demand.</summary>
    private void BuildNodesAndSummaryRows()
    {
        const double centerX = 185, centerY = 148, radius = 104;
        for (var i = 0; i < EndpointDefs.Length; i++)
        {
            var angle = -Math.PI / 2 + i * (2 * Math.PI / EndpointDefs.Length);
            var x = centerX + radius * Math.Cos(angle);
            var y = centerY + radius * Math.Sin(angle);
            var (key, label) = EndpointDefs[i];
            Nodes.Add(new FlowNodeViewModel(key, label, x, y, SelectEndpoint));

            var summary = new EndpointFlowSummaryViewModel(label);
            SummaryRows.Add(summary);
            _summaryByKey[key] = summary;
        }
    }

    private void Tick()
    {
        var tailer = Header.State.Tailer;
        var snapshot = tailer.Records.Snapshot();
        Ingest(snapshot);

        var health = snapshot.LastOrDefault(r => r.IsCollectorHealth);
        ApplySourceStatus(health);
        ApplyFilterVisuals();

        SummaryText = tailer.ActiveFilePath is null
            ? "No active log file found for the Correlator yet."
            : _totalConnections == 0
                ? "Live flow graph is waiting for the first connected multi-source event. Existing history is not replayed."
                : $"{_totalConnections:N0} cross-endpoint connection(s) observed across {Edges.Count} endpoint pair(s) since this page started watching. Never reset while open.";
    }

    /// <summary>Processes each new unified/session_timeline record exactly once (sequence-gated,
    /// same guarantee CorrelationViewModel.SyncGroups relies on) so a group's revisions are never
    /// double-counted -- only genuinely new connection entries beyond what was already counted for
    /// that group_id are added to the running totals.</summary>
    private void Ingest(JsonRecord[] snapshot)
    {
        foreach (var record in snapshot)
        {
            if (record.SequenceId <= _lastSeq) continue;
            _lastSeq = record.SequenceId;
            if (!record.Is("type", "unified_event") && !record.Is("type", "session_timeline")) continue;

            var memberKey = record.Is("type", "unified_event") ? "events" : "members";
            if (!record.Root.TryGetProperty(memberKey, out var membersEl) || membersEl.ValueKind != JsonValueKind.Array) continue;

            var memberEndpoints = new List<string>();
            var memberRawSources = new List<string>();
            var memberRecordTypes = new List<string>();
            var memberPids = new List<long>();
            var memberTimes = new List<long>();
            var memberRepeats = new List<long>();
            // Santosh, 2026-08-27: "evidence is showing or not in the evidence button" -- it never
            // was, for any incident on this page. The Correlator already emits these five fields per
            // member (unified_stream_engine.cpp, right next to raw_source above), but this loop only
            // ever read raw_source, so EvidenceResolver's very first check ("does this reference have
            // a record ID and source file at all?") failed unconditionally, every single click,
            // regardless of the actual incident -- not a rare case, not a display bug, a 100% miss.
            var memberNativeRecordIds = new List<string>();
            var memberNativeSessionIds = new List<string>();
            var memberNativeSourceFiles = new List<string>();
            var memberNativeByteOffsets = new List<long>();
            var memberNativeContentHashes = new List<string>();
            foreach (var member in membersEl.EnumerateArray())
            {
                var raw = member.TryGetProperty("endpoint", out var e) && e.ValueKind == JsonValueKind.String
                    ? e.GetString() ?? "" : "";
                memberEndpoints.Add(raw);
                memberRawSources.Add(member.TryGetProperty("raw_source", out var rs) && rs.ValueKind == JsonValueKind.String
                    ? rs.GetString() ?? "" : "");
                memberRecordTypes.Add(member.TryGetProperty("record_type", out var rt) && rt.ValueKind == JsonValueKind.String
                    ? rt.GetString() ?? "" : "");
                memberPids.Add(member.TryGetProperty("pid", out var pe) && pe.ValueKind == JsonValueKind.Number && pe.TryGetInt64(out var pv) ? pv : 0);
                memberTimes.Add(member.TryGetProperty("t_unix_ms", out var tm) && tm.ValueKind == JsonValueKind.Number && tm.TryGetInt64(out var tv) ? tv : 0);
                memberRepeats.Add(member.TryGetProperty("repeat_count", out var rc) && rc.ValueKind == JsonValueKind.Number && rc.TryGetInt64(out var rcv) ? Math.Max(1, rcv) : 1);
                memberNativeRecordIds.Add(member.TryGetProperty("native_record_id", out var nri) && nri.ValueKind == JsonValueKind.String ? nri.GetString() ?? "" : "");
                memberNativeSessionIds.Add(member.TryGetProperty("native_session_id", out var nsi) && nsi.ValueKind == JsonValueKind.String ? nsi.GetString() ?? "" : "");
                memberNativeSourceFiles.Add(member.TryGetProperty("native_source_file", out var nsf) && nsf.ValueKind == JsonValueKind.String ? nsf.GetString() ?? "" : "");
                memberNativeByteOffsets.Add(member.TryGetProperty("native_byte_offset", out var nbo) && nbo.ValueKind == JsonValueKind.Number && nbo.TryGetInt64(out var nbov) ? nbov : -1);
                memberNativeContentHashes.Add(member.TryGetProperty("native_content_hash", out var nch) && nch.ValueKind == JsonValueKind.String ? nch.GetString() ?? "" : "");
            }
            if (memberEndpoints.Count == 0) continue;

            if (!record.Root.TryGetProperty("connections", out var connArray) || connArray.ValueKind != JsonValueKind.Array)
                continue; // honest single-source event -- no cross-endpoint pair to draw

            var connections = new List<(int From, int To, string Reason)>();
            foreach (var c in connArray.EnumerateArray())
            {
                var from = c.TryGetProperty("from", out var fe) && fe.ValueKind == JsonValueKind.Number && fe.TryGetInt32(out var fv) ? fv : -1;
                var to = c.TryGetProperty("to", out var te) && te.ValueKind == JsonValueKind.Number && te.TryGetInt32(out var tv) ? tv : -1;
                var reason = c.TryGetProperty("reason", out var re) && re.ValueKind == JsonValueKind.String ? re.GetString() ?? "" : "";
                if (from < 0 || to < 0 || from >= memberEndpoints.Count || to >= memberEndpoints.Count) continue;
                connections.Add((from, to, reason));
            }
            if (connections.Count == 0) continue;

            var groupId = record.GetLong("group_id") ?? 0;

            // Update the aggregate pentagon edges/counts. Only genuinely new connections beyond what
            // a prior revision of this same group already contributed are counted, so totals never
            // double when a group's record is re-emitted as it grows.
            var alreadySeen = _groupConnectionsSeen.GetValueOrDefault(groupId, 0);
            for (var i = alreadySeen; i < connections.Count; i++)
            {
                var (from, to, reason) = connections[i];
                var a = memberEndpoints[from];
                var b = memberEndpoints[to];
                if (a == b) continue; // a same-endpoint join is not a cross-endpoint edge
                UpdateEdgeAggregate(a, b, reason);
            }
            if (connections.Count > alreadySeen)
            {
                if (!_groupConnectionsSeen.ContainsKey(groupId))
                {
                    _groupEvictionOrder.Enqueue(groupId);
                    while (_groupConnectionsSeen.Count > MaxTrackedGroups && _groupEvictionOrder.Count > 0)
                        _groupConnectionsSeen.Remove(_groupEvictionOrder.Dequeue());
                }
                _groupConnectionsSeen[groupId] = connections.Count;
            }

            // Santosh, Round 22 (third pass): "take all the endpoints' data and check which one is
            // connected to which one, take the common things out and link them -- PID, number, time,
            // location, filepath -- put all the logs from each connected endpoint together." Build
            // the real INCIDENT for this record -- every member actually involved, in order (not
            // flattened to the two endpoints of whichever pairwise edge was clicked), plus the common
            // fields extracted across all of them.
            var incidentMembers = new List<CorrelationMemberViewModel>(memberEndpoints.Count);
            for (var i = 0; i < memberEndpoints.Count; i++)
            {
                var (subject, detail) = CorrelationRowViewModel.ExtractDetails(memberEndpoints[i], memberRawSources[i]);
                incidentMembers.Add(new CorrelationMemberViewModel
                {
                    Endpoint = memberEndpoints[i],
                    RecordType = memberRecordTypes[i],
                    Pid = memberPids[i],
                    TUnixMs = memberTimes[i],
                    RepeatCount = memberRepeats[i],
                    Subject = subject,
                    DetailText = detail,
                    RawSource = memberRawSources[i],
                    NativeRecordId = memberNativeRecordIds[i],
                    NativeSessionId = memberNativeSessionIds[i],
                    NativeSourceFile = memberNativeSourceFiles[i],
                    NativeByteOffset = memberNativeByteOffsets[i],
                    NativeContentHash = memberNativeContentHashes[i]
                });
            }
            var edgeLabels = new List<string>();
            for (var i = 0; i < incidentMembers.Count - 1; i++)
            {
                var reason = connections.Where(c => (c.From == i && c.To == i + 1) || (c.From == i + 1 && c.To == i))
                    .Select(c => c.Reason).FirstOrDefault() ?? "";
                edgeLabels.Add(reason);
            }
            var pairKeys = new HashSet<string>();
            foreach (var (from, to, _) in connections)
            {
                var a = memberEndpoints[from];
                var b = memberEndpoints[to];
                if (a == b || !_summaryByKey.ContainsKey(a) || !_summaryByKey.ContainsKey(b)) continue;
                pairKeys.Add(PairKeyOf(a, b));
            }
            if (pairKeys.Count == 0) continue;

            var endpointKeys = new HashSet<string>(memberEndpoints.Where(e => _summaryByKey.ContainsKey(e)));
            var incident = new IncidentViewModel(groupId, record.EventTimeUtc.ToLocalTime().ToString("HH:mm:ss.fff"),
                incidentMembers, edgeLabels, pairKeys, endpointKeys, MaxDisplayedSegmentsPerIncident);
            _allIncidents.Insert(0, incident);
            if (_allIncidents.Count > MaxTrackedChains) _allIncidents.RemoveAt(_allIncidents.Count - 1);
            if (!_isPaused && (_pairFilter is null || pairKeys.Contains(_pairFilter)))
            {
                Incidents.Insert(0, incident);
                while (Incidents.Count > MaxDisplayedChains) Incidents.RemoveAt(Incidents.Count - 1);
            }
        }
    }

    private void UpdateEdgeAggregate(string rawA, string rawB, string reason)
    {
        if (!_summaryByKey.TryGetValue(rawA, out var summaryA) || !_summaryByKey.TryGetValue(rawB, out var summaryB)) return;

        var ordered = string.CompareOrdinal(rawA, rawB) <= 0;
        var (labelA, labelB) = ordered ? (summaryA.Label, summaryB.Label) : (summaryB.Label, summaryA.Label);
        var pairKey = PairKeyOf(rawA, rawB);

        _totalConnections++;
        summaryA.CrossLinks++;
        summaryB.CrossLinks++;

        if (!_edgeByPairKey.TryGetValue(pairKey, out var edge))
        {
            var nodeA = Nodes.First(n => n.Key == (ordered ? rawA : rawB));
            var nodeB = Nodes.First(n => n.Key == (ordered ? rawB : rawA));
            edge = new FlowEdgeViewModel(nodeA.X, nodeA.Y, nodeB.X, nodeB.Y, labelA, labelB, pairKey, SelectPair);
            _edgeByPairKey[pairKey] = edge;
            Edges.Add(edge);
        }
        edge.Count++;
        edge.LastReason = reason;
    }

    /// <summary>Per-endpoint "records seen" and "last seen" are pulled directly from the
    /// Correlator's own authoritative collector_health source_status array (the same live field
    /// verified during Round 14's live GUI run) instead of re-derived here, so this table never
    /// disagrees with what the Correlator itself reports. CrossLinks is the one number that field
    /// does not already expose, so it stays as this page's own running total.</summary>
    /// <summary>Santosh, 2026-08-31: "in that table the info it is showing it is not proper... in
    /// that status tab" -- live-confirmed via screenshot: Network/Application/File/Port/USB all read
    /// "Live" here while the app's own top-bar fleet status said "1/5" active and each endpoint's own
    /// header said "Stopped -- Not running". Root cause: IsLive trusted whatever the LAST
    /// collector_health record ever said, with no check on whether that record itself was fresh --
    /// once the Correlator (which is what emits this record) stops, its last-ever "active: true"
    /// just sits there forever, correctly aging (LastSeenText already computed real seconds-ago
    /// honestly) while the Status column kept contradicting it. Same StaleHeartbeatSeconds threshold
    /// AlertsViewModel already uses for the analogous watcher_runtime.json freshness check.</summary>
    private const double StaleHealthSeconds = 60;

    private void ApplySourceStatus(JsonRecord? health)
    {
        if (health is null) return;
        if (!health.Root.TryGetProperty("source_status", out var arr) || arr.ValueKind != JsonValueKind.Array) return;

        var healthIsStale = health.IsSeedHistory || (DateTimeOffset.UtcNow - health.EventTimeUtc).TotalSeconds > StaleHealthSeconds;

        foreach (var entry in arr.EnumerateArray())
        {
            var endpoint = entry.TryGetProperty("endpoint", out var e) && e.ValueKind == JsonValueKind.String ? e.GetString() ?? "" : "";
            if (!_summaryByKey.TryGetValue(endpoint, out var row)) continue;

            row.IsLive = !healthIsStale && entry.TryGetProperty("active", out var a) && a.ValueKind == JsonValueKind.True;
            row.RecordsSeen = entry.TryGetProperty("records_seen", out var rs) && rs.ValueKind == JsonValueKind.Number && rs.TryGetInt64(out var rv) ? rv : row.RecordsSeen;

            if (entry.TryGetProperty("last_observed_ms", out var lo) && lo.ValueKind == JsonValueKind.Number && lo.TryGetInt64(out var loMs) && loMs > 0)
            {
                var age = DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeMilliseconds(loMs);
                row.LastSeenText = age.TotalSeconds < 1 ? "just now" : $"{age.TotalSeconds:N0}s ago";
            }

            if (Nodes.FirstOrDefault(n => n.Key == endpoint) is { } node)
            {
                node.IsLive = row.IsLive;
                node.RecordsSeen = row.RecordsSeen;
            }
        }
    }
}

/// <summary>A fixed node position on the pentagon layout -- always one of the five real sensor
/// endpoints, never the Correlator itself, since the Correlator is what draws the edges, not a
/// source in the data flow it describes.</summary>
public sealed class FlowNodeViewModel : ViewModelBase
{
    private const double VisualSize = 72;

    public string Key { get; }
    public string Label { get; }
    public double X { get; }
    public double Y { get; }
    /// <summary>Canvas.Left/Top for a <see cref="VisualSize"/>-square node visual centered on X,Y.</summary>
    public double Left => X - VisualSize / 2;
    public double Top => Y - VisualSize / 2;
    public double Size => VisualSize;

    /// <summary>Round 23: clicking a node now filters the incident list to that single endpoint,
    /// mirroring the click-to-filter an edge's count badge already offered for pairs -- "make it
    /// more interactable" -- previously nodes were purely decorative.</summary>
    public RelayCommand SelectCommand { get; }

    private bool _isLive;
    public bool IsLive
    {
        get => _isLive;
        set { if (SetField(ref _isLive, value)) OnPropertyChanged(nameof(DotBrush)); }
    }
    public Brush DotBrush => IsLive ? ThemeBrushes.Healthy : ThemeBrushes.Disabled;

    private long _recordsSeen;
    /// <summary>Round 23: the small live counter under each node's dot -- previously this number
    /// only existed in the separate Per-Endpoint Summary table to the right, so the pentagon itself
    /// gave no sense of which endpoint was actually busy versus idle at a glance.</summary>
    public long RecordsSeen
    {
        get => _recordsSeen;
        set { if (SetField(ref _recordsSeen, value)) OnPropertyChanged(nameof(RecordsSeenText)); }
    }
    public string RecordsSeenText => RecordsSeen > 0 ? RecordsSeen.ToString("N0") : "—";

    private bool _isSelected;
    /// <summary>True only for a node that was directly clicked (not merely a neighbor of one).</summary>
    public bool IsSelected { get => _isSelected; set => SetField(ref _isSelected, value); }

    private bool _isDimmed;
    /// <summary>True while a filter is active and this node is neither the selected endpoint/pair
    /// nor directly connected to it -- see CorrelationGraphViewModel.ApplyFilterVisuals.</summary>
    public bool IsDimmed
    {
        get => _isDimmed;
        set { if (SetField(ref _isDimmed, value)) OnPropertyChanged(nameof(DisplayOpacity)); }
    }
    public double DisplayOpacity => IsDimmed ? 0.3 : 1.0;

    public FlowNodeViewModel(string key, string label, double x, double y, Action<string> onSelect)
    {
        Key = key; Label = label; X = x; Y = y;
        SelectCommand = new RelayCommand(() => onSelect(key));
    }
}

/// <summary>One growing edge between two endpoints. Deliberately undirected -- the Correlator's
/// own join reasons (same_pid, same file, USB mount-path, etc.) describe an association, not a
/// proven causal direction, so this graph never draws an arrowhead implying one endpoint's
/// activity caused the other's.</summary>
public sealed class FlowEdgeViewModel : ViewModelBase
{
    public double X1 { get; }
    public double Y1 { get; }
    public double X2 { get; }
    public double Y2 { get; }
    public string LabelA { get; }
    public string LabelB { get; }
    public string PairKey { get; }
    public string PairLabel => $"{LabelA} ↔ {LabelB}";
    /// <summary>Bound from FlowEdgeControl's click handler -- "if I click on that number, I wanted
    /// to see those events" -- fills CorrelationGraphViewModel.SelectedPairEvents with this pair's
    /// real correlated events instead of leaving the count as a dead-end number.</summary>
    public RelayCommand SelectCommand { get; }

    public double MidX => (X1 + X2) / 2;
    public double MidY => (Y1 + Y2) / 2;

    private long _count;
    public long Count
    {
        get => _count;
        set
        {
            if (!SetField(ref _count, value)) return;
            OnPropertyChanged(nameof(StrokeThickness));
            OnPropertyChanged(nameof(Opacity));
            OnPropertyChanged(nameof(CountText));
            OnPropertyChanged(nameof(ToolTipText));
        }
    }

    private string _lastReason = "";
    public string LastReason
    {
        get => _lastReason;
        set { if (SetField(ref _lastReason, value)) OnPropertyChanged(nameof(ToolTipText)); }
    }

    /// <summary>Round 23: true while a node/pair filter is active and this edge is not part of it --
    /// bound to FlowEdgeControl.Dimmed so the selected pair (or a selected node's edges) visibly
    /// stand out instead of every line looking the same regardless of what is clicked.</summary>
    private bool _isDimmed;
    public bool IsDimmed { get => _isDimmed; set => SetField(ref _isDimmed, value); }

    public string CountText => $"{Count:N0}";

    /// <summary>Log-scaled so one endpoint pair that dominates activity (e.g. Process&#8596;File)
    /// cannot visually blot out a rarer but still real pair -- every edge that has ever connected
    /// stays visible and clickable-looking, matching "no junk" without ever hiding a real link.</summary>
    public double StrokeThickness => Math.Clamp(1.75 + Math.Log(Count + 1) * 2.1, 1.75, 13);
    public double Opacity => Math.Clamp(0.32 + Math.Log(Count + 1) * 0.11, 0.32, 1.0);

    public string ToolTipText => $"{PairLabel}\n{Count:N0} connection(s) since this page started watching\nMost recent join reason: {(string.IsNullOrWhiteSpace(LastReason) ? "unavailable" : LastReason)}";

    public FlowEdgeViewModel(double x1, double y1, double x2, double y2, string labelA, string labelB,
        string pairKey, Action<string> onSelect)
    {
        X1 = x1; Y1 = y1; X2 = x2; Y2 = y2; LabelA = labelA; LabelB = labelB; PairKey = pairKey;
        SelectCommand = new RelayCommand(() => onSelect(pairKey));
    }
}

/// <summary>One real correlated group treated as an INCIDENT (Santosh's own term, Round 22 third
/// pass): every endpoint actually involved, in real member order -- not flattened to the two
/// endpoints of whichever pairwise edge was clicked -- plus the common fields extracted across all
/// of them (which processes, which PIDs, what time span, how many real events), matching what the
/// old reference correlator format's top-level arrays (processes/pids/dest_ips/protocols) already
/// did for a correlated group. Rendered as a horizontal row of cards joined by arrows, the same
/// visual language as the main Correlation page's proven Chain View tab. DisplaySegments is capped
/// (RAM/rendering bound) but every summary field below is computed from the FULL member set, never
/// just the capped/displayed subset -- a huge incident never under-reports its own real scope.</summary>
public sealed class IncidentViewModel
{
    public long GroupId { get; }
    public string IncidentText => $"INC-{GroupId}";
    public string Time { get; }
    public IReadOnlyList<ChainSegmentViewModel> Segments { get; }
    public int TotalMemberCount { get; }
    public int HiddenMemberCount => Math.Max(0, TotalMemberCount - Segments.Count);
    public string MoreSegmentsText => HiddenMemberCount > 0
        ? $"+ {HiddenMemberCount} more endpoint record(s) in this incident (not rendered, to keep this page light -- included in the summary above)"
        : "";
    public HashSet<string> PairKeys { get; }
    /// <summary>Round 23: raw endpoint keys this incident actually touched -- lets a clicked pentagon
    /// node filter incidents by single endpoint, the same way PairKeys already let a clicked edge
    /// filter by pair.</summary>
    public HashSet<string> EndpointKeys { get; }

    /// <summary>"From which to which endpoint it went" -- the real member sequence, e.g.
    /// "Application -> File -> Network", however many endpoints (not capped at any fixed number).</summary>
    public string EndpointPathText { get; }
    public string CommonProcessesText { get; }
    public string CommonPidsText { get; }
    public string TimeSpanText { get; }
    public string TotalEventsText { get; }

    public string HeaderText => $"{Time}  {IncidentText}  —  {EndpointPathText}";
    public string CommonSummaryText => $"{CommonProcessesText}  |  PID(s): {CommonPidsText}  |  {TimeSpanText}  |  {TotalEventsText} real event(s) across {TotalMemberCount} endpoint record(s)";

    public IncidentViewModel(long groupId, string time, IReadOnlyList<CorrelationMemberViewModel> allMembers,
        IReadOnlyList<string> edgeLabelsToNext, HashSet<string> pairKeys, HashSet<string> endpointKeys, int maxDisplayedSegments)
    {
        GroupId = groupId;
        Time = time;
        PairKeys = pairKeys;
        EndpointKeys = endpointKeys;
        TotalMemberCount = allMembers.Count;

        EndpointPathText = string.Join(" → ", allMembers.Select(m => m.DisplayEndpoint));

        var processes = allMembers.Select(m => m.Subject).Where(s => !string.IsNullOrWhiteSpace(s) && !s.StartsWith('(')).Distinct().ToList();
        CommonProcessesText = processes.Count == 0 ? "no named process/device"
            : string.Join(", ", processes.Take(6)) + (processes.Count > 6 ? $" (+{processes.Count - 6} more)" : "");

        var pids = allMembers.Select(m => m.Pid).Where(p => p > 0).Distinct().ToList();
        CommonPidsText = pids.Count == 0 ? "none reported"
            : string.Join(", ", pids.Take(8)) + (pids.Count > 8 ? $" (+{pids.Count - 8} more)" : "");

        var times = allMembers.Select(m => m.TUnixMs).Where(t => t > 0).ToList();
        TimeSpanText = times.Count == 0 ? "time unavailable"
            : times.Min() == times.Max() ? "single point in time"
            : $"{times.Max() - times.Min():N0} ms span";

        TotalEventsText = allMembers.Sum(m => Math.Max(1, m.RepeatCount)).ToString("N0");

        var shown = Math.Min(allMembers.Count, maxDisplayedSegments);
        var segments = new List<ChainSegmentViewModel>(shown);
        for (var i = 0; i < shown; i++)
        {
            var isLast = i == shown - 1;
            var edgeLabel = i < edgeLabelsToNext.Count ? edgeLabelsToNext[i] : "";
            segments.Add(new ChainSegmentViewModel(allMembers[i], isLast ? "" : edgeLabel, isLast));
        }
        Segments = segments;
    }
}

/// <summary>One card in a chain row plus the label on the arrow to the next card (blank/no arrow
/// on the last card).</summary>
public sealed record ChainSegmentViewModel(CorrelationMemberViewModel Member, string EdgeLabelToNext, bool IsLast)
{
    public string ArrowText => IsLast ? "" : "→";
}

/// <summary>One row of the live summary table -- the "check the below table" ask. RecordsSeen and
/// LastSeenText mirror the Correlator's own authoritative per-source health, not a re-derived
/// guess; CrossLinks is this page's own running participation count.</summary>
public sealed class EndpointFlowSummaryViewModel : ViewModelBase
{
    public string Label { get; }

    private bool _isLive;
    public bool IsLive { get => _isLive; set { if (SetField(ref _isLive, value)) OnPropertyChanged(nameof(LiveText)); } }
    public string LiveText => IsLive ? "Live" : "Not running";

    private long _recordsSeen;
    public long RecordsSeen { get => _recordsSeen; set => SetField(ref _recordsSeen, value); }

    private long _crossLinks;
    public long CrossLinks { get => _crossLinks; set => SetField(ref _crossLinks, value); }

    private string _lastSeenText = "Unavailable";
    public string LastSeenText { get => _lastSeenText; set => SetField(ref _lastSeenText, value); }

    public EndpointFlowSummaryViewModel(string label) => Label = label;
}
