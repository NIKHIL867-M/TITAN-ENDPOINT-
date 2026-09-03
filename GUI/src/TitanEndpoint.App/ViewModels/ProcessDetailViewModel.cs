using System.Collections.ObjectModel;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.Json;

namespace TitanEndpoint.App.ViewModels;

public sealed class RelatedEvidenceRowViewModel
{
    public string Endpoint { get; init; } = "";
    public string Time { get; init; } = "";
    public string Summary { get; init; } = "";
    public string Confidence { get; init; } = "";
}

/// <summary>
/// Selected-event detail panel for the Process page (FORU.TXT section 7.4): raw record,
/// parent/child relationships, signer details, command line, and associated Application/File/
/// Network evidence. Cross-endpoint matches are found by pid + time proximity across each
/// endpoint's currently-loaded bounded row window — this is a GUI-side heuristic, not something
/// the Correlator confirmed, so every match is explicitly labeled "Inferred" (same honesty
/// convention as the Correlation page) rather than presented as a confirmed relationship.
/// </summary>
public sealed class ProcessDetailViewModel : ViewModelBase
{
    private const long CrossEndpointWindowMs = 5000;

    private ProcessRowViewModel? _selected;
    public ProcessRowViewModel? Selected
    {
        get => _selected;
        set { if (SetField(ref _selected, value)) Rebuild(); }
    }

    public ObservableCollection<ProcessRowViewModel> ChildEvents { get; } = new();
    public ObservableCollection<ProcessRowViewModel> ParentEvents { get; } = new();
    public ObservableCollection<RelatedEvidenceRowViewModel> RelatedEvidence { get; } = new();

    private string _relatedEvidenceNote = "";
    public string RelatedEvidenceNote { get => _relatedEvidenceNote; private set => SetField(ref _relatedEvidenceNote, value); }
    private string _parentFallbackText = "";
    public string ParentFallbackText { get => _parentFallbackText; private set => SetField(ref _parentFallbackText, value); }
    private string _childFallbackText = "";
    public string ChildFallbackText { get => _childFallbackText; private set => SetField(ref _childFallbackText, value); }

    private readonly IReadOnlyCollection<ProcessRowViewModel> _allRows;

    public ProcessDetailViewModel(IReadOnlyCollection<ProcessRowViewModel> allRows)
    {
        _allRows = allRows;
    }

    public void Rebuild()
    {
        ChildEvents.Clear();
        ParentEvents.Clear();
        RelatedEvidence.Clear();

        if (Selected is null)
        {
            RelatedEvidenceNote = "Select a process event to see related evidence.";
            return;
        }

        foreach (var row in _allRows.Where(r => r.ParentPid == Selected.Pid && r.EvidenceId != Selected.EvidenceId))
            ChildEvents.Add(row);
        foreach (var row in _allRows.Where(r => r.Pid == Selected.ParentPid && Selected.ParentPid > 0))
            ParentEvents.Add(row);

        // The counterpart process's own event often isn't retained in this GUI session's bounded
        // row window (it may have started before this session, or been trimmed already), which
        // used to leave the panel blank even though the selected event itself reports a parent PID
        // / child count. Fall back to that self-reported data so the tab always shows something real.
        ParentFallbackText = ParentEvents.Count > 0 ? "" : Selected.ParentPid > 0
            ? $"Parent PID {Selected.ParentPid} (no separate event for that process retained in the current bounded view)."
            : "This event reports no parent PID.";
        ChildFallbackText = ChildEvents.Count > 0 ? "" : Selected.ChildCount > 0
            ? $"This snapshot reports {Selected.ChildCount} child process(es)"
              + (Selected.UniqueChildNames.Count > 0 ? ": " + string.Join(", ", Selected.UniqueChildNames) : "")
              + " — not individually retained as separate rows in the current bounded view."
            : "No child events retained in the current bounded view.";

        BuildRelatedEvidence();
    }

    private void BuildRelatedEvidence()
    {
        if (Selected is null) return;
        var confirmed = BuildCorrelatorConfirmedEvidence();
        var pid = Selected.Pid;
        if (pid <= 0)
        {
            RelatedEvidenceNote = "This event has no PID to cross-reference against other endpoints.";
            return;
        }

        var found = 0;
        foreach (var (id, label) in new[] { (EndpointId.Application, "Application"), (EndpointId.File, "File"), (EndpointId.Network, "Network") })
        {
            var tailer = App.Fleet.Get(id).Tailer;
            foreach (var record in tailer.Records.Snapshot())
            {
                if (record.IsCollectorHealth) continue;
                var recordPid = record.GetLong("pid");
                if (recordPid != pid) continue;

                var deltaMs = Math.Abs((record.EventTimeUtc.ToUnixTimeMilliseconds()) - Selected.TUnixMs);
                if (deltaMs > CrossEndpointWindowMs) continue;

                RelatedEvidence.Add(new RelatedEvidenceRowViewModel
                {
                    Endpoint = label,
                    Time = record.EventTimeUtc.ToLocalTime().ToString("HH:mm:ss.fff"),
                    Summary = Summarize(id, record),
                    Confidence = $"Inferred — matched by pid {pid} within {deltaMs} ms"
                });
                found++;
                if (found >= 20) break;
            }
            if (found >= 20) break;
        }

        RelatedEvidenceNote = found == 0 && confirmed == 0
            ? "No related Application/File/Network evidence was retained within the selected time window."
            : $"{confirmed} Correlator-confirmed and {found} explicitly inferred match(es). Inferred rows use shared PID within {CrossEndpointWindowMs} ms and are never promoted to confirmed.";
    }

    private int BuildCorrelatorConfirmedEvidence()
    {
        if (Selected is null || string.IsNullOrWhiteSpace(Selected.NativeRecordId)) return 0;
        var found = 0;
        foreach (var record in App.Fleet.Get(EndpointId.Correlator).Tailer.Records.Snapshot())
        {
            // Supports both the legacy "session_timeline"/"members" schema and the current native
            // Correlator's "unified_event"/"events" schema -- checking only the legacy type/key here
            // meant this count silently stayed 0 forever against real, current Correlator output.
            var legacy = record.Is("type", "session_timeline");
            var unified = record.Is("type", "unified_event");
            if (!legacy && !unified) continue;
            var memberKey = unified ? "events" : "members";
            if (!record.Root.TryGetProperty(memberKey, out var members) || members.ValueKind != System.Text.Json.JsonValueKind.Array) continue;
            var all = members.EnumerateArray().ToList();
            if (!all.Any(member => member.TryGetProperty("native_record_id", out var id) &&
                    id.ValueKind == System.Text.Json.JsonValueKind.String && id.GetString() == Selected.NativeRecordId)) continue;
            foreach (var member in all)
            {
                var endpoint = member.TryGetProperty("endpoint", out var ep) ? ep.GetString() ?? "" : "";
                if (endpoint == "process") continue;
                var recordType = member.TryGetProperty("record_type", out var type) ? type.GetString() ?? "event" : "event";
                var nativeId = member.TryGetProperty("native_record_id", out var id) ? id.GetString() ?? "" : "";
                var confidence = member.TryGetProperty("confidence", out var quality) ? quality.GetString() ?? "confirmed" : "confirmed";
                RelatedEvidence.Add(new RelatedEvidenceRowViewModel
                {
                    Endpoint = endpoint, Time = record.EventTimeUtc.ToLocalTime().ToString("HH:mm:ss.fff"),
                    Summary = $"{recordType} — durable record {nativeId}",
                    Confidence = $"Correlator {confidence}; group {record.GetLong("group_id") ?? 0}"
                });
                if (++found >= 20) return found;
            }
        }
        return found;
    }

    private static string Summarize(EndpointId id, JsonRecord r) => id switch
    {
        EndpointId.Application => r.GetString("type") ?? r.GetString("action") ?? "application event",
        EndpointId.File => $"{r.GetString("action") ?? "file event"}: {System.IO.Path.GetFileName(r.GetString("path") ?? "")}",
        EndpointId.Network => $"{r.GetString("protocol") ?? "packet"} → {r.GetString("remote_ip")}:{r.GetLong("remote_port")}",
        _ => "event"
    };
}
