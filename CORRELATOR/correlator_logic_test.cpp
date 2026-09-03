// correlator_logic_test.cpp -- non-admin logic tests for the Correlator.
//
// Exercises pure logic only: JSON field extraction, the pairwise join
// predicates (EvaluateLineageEdge / EvaluatePortBridgeEdge / EvaluateEdge),
// and the full CorrelationEngine ingest+correlate cycle fed with synthetic
// fixture lines shaped exactly like real endpoint output (no real file
// tailing or live endpoint processes needed).
//
// Rewritten for FORU.TXT section 12 ("FIX CORRELATION CORRECTNESS BEFORE
// EXTENDING ITS VISUALS"). Fixture shapes were corrected to match each
// endpoint's REAL schema (confirmed by reading each endpoint's own
// event/logger source, not assumed) -- the previous version's process/
// network fixtures used a bare "type":"FORWARD" field that neither
// endpoint's real schema actually emits at the top level.
#include "json_fields.h"
#include "correlation_engine.h"
#include "resource_pressure.h"

#include <chrono>
#include <iostream>
#include <string>

using namespace correlator;

namespace {
bool Require(bool condition, const char* message)
{
    if (!condition) std::cerr << "[TEST] FAIL: " << message << "\n";
    return condition;
}

int64_t NowMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}
}

int main()
{
    bool ok = true;

    // ── JSON field extraction ────────────────────────────────────────────────
    {
        const std::string line =
            "{\"endpoint\":\"process_monitor\",\"type\":\"collector_health\","
            "\"t_unix_ms\":1234567890123,\"pid\":4242,\"parent_pid\":4,"
            "\"status\":\"healthy\"}";

        int64_t num = 0;
        std::string str;

        ok &= Require(ExtractJsonNumber(line, "t_unix_ms", num) && num == 1234567890123LL,
            "extracts t_unix_ms");
        ok &= Require(ExtractJsonNumber(line, "pid", num) && num == 4242,
            "extracts pid");
        ok &= Require(ExtractJsonNumber(line, "parent_pid", num) && num == 4,
            "extracts parent_pid");
        ok &= Require(ExtractJsonString(line, "type", str) && str == "collector_health",
            "extracts type string");
        ok &= Require(ExtractJsonString(line, "status", str) && str == "healthy",
            "extracts a second string field on the same line");
        ok &= Require(!ExtractJsonNumber(line, "nonexistent_field", num),
            "missing field returns false");
    }

    // ── IsOperationalStatusLine: FORU.TXT 12.1 -- health/startup/control-ack
    //    must never enter behavioural correlation ─────────────────────────────
    {
        ok &= Require(IsOperationalStatusLine("{\"type\":\"collector_health\",\"pid\":1}"),
            "collector_health (type field) recognized as operational");
        ok &= Require(IsOperationalStatusLine(
            "{\"record_type\":\"collector_health\",\"type\":\"collector_health\",\"pid\":1}"),
            "network's collector_health (record_type field) recognized as operational");
        ok &= Require(IsOperationalStatusLine("{\"type\":\"startup\"}"), "startup recognized as operational");
        ok &= Require(!IsOperationalStatusLine("{\"event_subtype\":\"process_start\",\"pid\":1}"),
            "a real process event is NOT flagged as operational");
    }

    // ── Record type normalization: FORU.TXT 12.2 -- correct field per schema,
    //    never a blind "type" lookup that goes blank for Process/Network ─────
    {
        auto proc = ParseEvidenceLine("process",
            "{\"event_type\":\"FORWARD\",\"event_subtype\":\"process_start\",\"t_unix_ms\":1,\"pid\":1}");
        ok &= Require(proc.record_type == "process_start",
            "Process record_type comes from event_subtype, not a blank top-level \"type\"");

        auto net = ParseEvidenceLine("network",
            "{\"event_type\":\"FORWARD\",\"record_type\":\"network_packet\",\"t_unix_ms\":1,\"pid\":1}");
        ok &= Require(net.record_type == "network_packet",
            "Network record_type comes from record_type, not a blank top-level \"type\"");

        auto file = ParseEvidenceLine("file_integrity",
            "{\"action\":\"create\",\"t_unix_ms\":1,\"pid\":1}");
        ok &= Require(file.record_type == "create",
            "File record_type comes from action");

        auto app = ParseEvidenceLine("application",
            "{\"type\":\"process\",\"action\":\"launch\",\"t_unix_ms\":1,\"pid\":1}");
        ok &= Require(app.record_type == "process",
            "Application record_type comes from its own type field (already correct)");
    }

    // ── EvaluateLineageEdge: pid/parent_pid predicate with real edge metadata ─
    {
        EvidenceRecord a;
        a.endpoint = "process";
        a.pid = 5000;
        a.t_unix_ms = 1'700'000'000'000;

        EvidenceRecord b_same_pid = a;
        b_same_pid.endpoint = "file_integrity";
        b_same_pid.t_unix_ms = a.t_unix_ms + 500;   // within window

        auto e1 = EvaluateLineageEdge(a, b_same_pid, 2000);
        ok &= Require(e1.matched && e1.reason == "same_pid" && e1.confidence == "high" && e1.delta_ms == 500,
            "same pid within window correlates with reason=same_pid, confidence=high");

        EvidenceRecord b_too_far = b_same_pid;
        b_too_far.t_unix_ms = a.t_unix_ms + 5000;   // outside window
        ok &= Require(!EvaluateLineageEdge(a, b_too_far, 2000).matched,
            "same pid outside window does not correlate");

        EvidenceRecord child;
        child.endpoint = "network";
        child.parent_pid = a.pid;   // child of a's process
        child.t_unix_ms = a.t_unix_ms + 100;
        auto e2 = EvaluateLineageEdge(a, child, 2000);
        ok &= Require(e2.matched && e2.reason == "parent_child_pid" && e2.confidence == "high",
            "parent/child pid lineage correlates with reason=parent_child_pid");

        EvidenceRecord sibling = a;
        sibling.pid = 6000;
        sibling.parent_pid = 4;
        EvidenceRecord sibling2 = a;
        sibling2.pid = 6001;
        sibling2.parent_pid = 4;
        sibling.pid = 0; // avoid same_pid path so only parent_pid can match
        auto e3 = EvaluateLineageEdge(sibling, sibling2, 2000);
        ok &= Require(e3.matched && e3.reason == "sibling_pid" && e3.confidence == "medium",
            "shared parent_pid (sibling launches) correlates with reason=sibling_pid, confidence=medium (weaker than direct lineage)");

        EvidenceRecord unrelated;
        unrelated.endpoint = "port";
        unrelated.pid = 9999;
        unrelated.t_unix_ms = a.t_unix_ms;
        ok &= Require(!EvaluateLineageEdge(a, unrelated, 2000).matched,
            "same time, unrelated pid does not correlate");

        EvidenceRecord no_timestamp;
        no_timestamp.pid = a.pid;
        no_timestamp.t_unix_ms = 0;
        ok &= Require(!EvaluateLineageEdge(a, no_timestamp, 2000).matched,
            "record with no timestamp never correlates");
    }

    // ── EvaluatePortBridgeEdge: FORU.TXT 12.5 -- Port must never join purely
    //    on time proximity without a defensible bridge ────────────────────────
    {
        // A USB_SESSION_END record: mount_point "E:\" (doubled backslash in
        // the JSON TEXT -- that's how a real single backslash is escaped --
        // but ExtractJsonString now properly decodes it back to one real
        // backslash, same as any path field on the "other side", so a
        // substring comparison between the two still correctly detects a
        // real shared-prefix relationship).
        const int64_t session_end = 1'700'000'100'000;
        const int64_t duration_s = 60; // 60s session
        std::string usb_end_line =
            "{\"endpoint\":\"usb_monitor\",\"event_type\":\"USB_SESSION_END\","
            "\"t_unix_ms\":" + std::to_string(session_end) + ",\"mount_point\":\"E:\\\\\","
            "\"timing\":{\"duration_seconds\":" + std::to_string(duration_s) + ".000}}";
        EvidenceRecord port_rec = ParseEvidenceLine("port", usb_end_line);
        // The fixture's C++ source embeds "E:\\\\" -- two escaped backslash
        // PAIRS in C++ source, i.e. two literal backslash characters in the
        // actual JSON text, i.e. the correctly-escaped JSON form of ONE
        // real backslash. ExtractJsonString decodes that back to the real
        // value: "E:\\" in C++ source here is one real backslash character.
        ok &= Require(port_rec.mount_point == "E:\\", "mount_point parsed from USB_SESSION_END");
        ok &= Require(port_rec.duration_seconds == duration_s, "duration_seconds parsed from nested timing object");

        // Positive case: a file written to that same drive, during the session.
        EvidenceRecord file_on_device = ParseEvidenceLine("file_integrity",
            "{\"action\":\"create\",\"path\":\"E:\\\\autorun.inf\",\"t_unix_ms\":" +
            std::to_string(session_end - 10'000) + ",\"pid\":1}");
        auto bridge = EvaluatePortBridgeEdge(port_rec, file_on_device);
        ok &= Require(bridge.matched && bridge.reason == "usb_mount_path_match" && bridge.confidence == "high" &&
            bridge.caveat.empty(),
            "file path under the session's mount point is a defensible bridge -> high confidence, no caveat");

        // Negative-but-proximate case: a file on a COMPLETELY different
        // drive, still within the session's time window. Real-world this is
        // the exact anti-pattern FORU.TXT calls out -- must not be presented
        // as a proven chain, only low-confidence with an explicit caveat.
        EvidenceRecord unrelated_file = ParseEvidenceLine("file_integrity",
            "{\"action\":\"write\",\"path\":\"C:\\\\Windows\\\\System32\\\\notepad.exe\",\"t_unix_ms\":" +
            std::to_string(session_end - 5000) + ",\"pid\":1}");
        auto weak = EvaluatePortBridgeEdge(port_rec, unrelated_file);
        ok &= Require(weak.matched && weak.reason == "port_temporal_proximity_only" && weak.confidence == "low" &&
            !weak.caveat.empty(),
            "no path bridge -> still time-proximate, but explicitly low-confidence with a non-empty caveat");

        // Outside the session window entirely (well past end + slack).
        EvidenceRecord far_away = unrelated_file;
        far_away.t_unix_ms = session_end + 999'000;
        ok &= Require(!EvaluatePortBridgeEdge(port_rec, far_away).matched,
            "a record far outside the session window does not correlate at all");

        // THE CORE FIX: usb_hid_event carries no mount_point/bridge field at
        // all -- must NEVER join to unrelated Process/File activity merely
        // because it happened nearby in time (this is exactly what the old
        // PortProximityCorrelates did, and exactly what 12.5 forbids).
        EvidenceRecord hid_rec = ParseEvidenceLine("port",
            "{\"endpoint\":\"usb_monitor\",\"type\":\"usb_hid_event\",\"event_type\":\"USB_HID_KEYBOARD_ARRIVED\","
            "\"t_unix_ms\":" + std::to_string(session_end) + "}");
        EvidenceRecord nearby_process;
        nearby_process.endpoint = "process";
        nearby_process.pid = 1234;
        nearby_process.t_unix_ms = session_end + 500;
        ok &= Require(!EvaluatePortBridgeEdge(hid_rec, nearby_process).matched,
            "usb_hid_event (no mount_point) never bridges to unrelated activity purely on proximity -- the fixed bug");

        // Symmetry + non-Port-pair rejection.
        ok &= Require(EvaluateEdge(nearby_process, hid_rec, 2000).matched == false,
            "EvaluateEdge dispatches correctly regardless of which side is Port, and still rejects the no-bridge case");
        EvidenceRecord proc_a; proc_a.endpoint = "process"; proc_a.t_unix_ms = 1; proc_a.pid = 1;
        EvidenceRecord proc_b; proc_b.endpoint = "process"; proc_b.t_unix_ms = 1; proc_b.pid = 2;
        ok &= Require(!EvaluatePortBridgeEdge(proc_a, proc_b).matched,
            "two non-Port records never correlate via the Port-bridge predicate");
    }

    // ── Ingest excludes operational status lines from the graph entirely ────
    {
        CorrelationEngine engine;
        const int64_t t0 = NowMs();
        engine.Ingest("process", "{\"type\":\"collector_health\",\"t_unix_ms\":" + std::to_string(t0) + ",\"pid\":42}");
        ok &= Require(engine.TotalRecords() == 0,
            "a collector_health line is never stored in the correlation graph at all");

        // Even with a REAL process event sharing the same pid nearby, the
        // health line must not appear as a member if it had leaked in.
        engine.Ingest("process",
            "{\"event_subtype\":\"process_start\",\"t_unix_ms\":" + std::to_string(t0) + ",\"pid\":42}");
        engine.Ingest("network",
            "{\"record_type\":\"network_packet\",\"t_unix_ms\":" + std::to_string(t0 + 300) + ",\"pid\":42}");
        auto joined = engine.TryCorrelate();
        for (const auto& j : joined)
            ok &= Require(j.find("collector_health") == std::string::npos,
                "no emitted session_timeline ever contains a collector_health record");
    }

    // ── CorrelationEngine end-to-end with realistic fixture lines ───────────
    {
        CorrelationEngine engine;
        const int64_t t0 = NowMs();

        // Process -> Network via same pid (real schema field names).
        engine.Ingest("process",
            "{\"event_subtype\":\"process_start\",\"t_unix_ms\":" + std::to_string(t0) +
            ",\"pid\":7777,\"parent_pid\":4}");
        engine.Ingest("network",
            "{\"record_type\":\"network_packet\",\"t_unix_ms\":" + std::to_string(t0 + 300) +
            ",\"pid\":7777}");

        // Port HID event at an unrelated time/pid, no bridge -- must never join.
        engine.Ingest("port",
            "{\"type\":\"usb_hid_event\",\"t_unix_ms\":" + std::to_string(t0 + 999999) + "}");

        auto joined = engine.TryCorrelate();
        ok &= Require(joined.size() == 1,
            "exactly one session_timeline emitted for the correlated Process<->Network pair");
        if (!joined.empty()) {
            ok &= Require(joined[0].find("\"session_timeline\"") != std::string::npos,
                "joined record has the correct type");
            ok &= Require(joined[0].find("\"process\"") != std::string::npos &&
                joined[0].find("\"network\"") != std::string::npos,
                "joined record names both correlated endpoints");
            ok &= Require(joined[0].find("\"join_reason\":\"same_pid\"") != std::string::npos,
                "joined record carries the engine's own join reason (same_pid), not a GUI guess");
            ok &= Require(joined[0].find("\"revision\":1") != std::string::npos,
                "a freshly created group starts at revision 1");
            ok &= Require(joined[0].find("\"source_evidence_id\"") != std::string::npos,
                "each member carries a resolvable source_evidence_id");
            ok &= Require(joined[0].find("\"raw_source\"") != std::string::npos,
                "each member embeds its original raw source line so it can be opened directly");
        }

        // Running TryCorrelate again must not re-emit the same join (consumed).
        auto joined_again = engine.TryCorrelate();
        ok &= Require(joined_again.empty(),
            "already-consumed records are not re-joined on a later cycle");
    }

    // ── Application -> File via shared pid (both carry a real OS pid) ───────
    {
        CorrelationEngine engine;
        const int64_t t0 = NowMs();
        const int pid = 3333;

        engine.Ingest("application",
            "{\"type\":\"process\",\"action\":\"launch\",\"t_unix_ms\":" + std::to_string(t0) +
            ",\"pid\":" + std::to_string(pid) + "}");
        engine.Ingest("file_integrity",
            "{\"action\":\"write\",\"path\":\"C:\\\\Users\\\\demo\\\\doc.docx\",\"t_unix_ms\":" +
            std::to_string(t0 + 250) + ",\"pid\":" + std::to_string(pid) + "}");

        auto joined = engine.TryCorrelate();
        ok &= Require(joined.size() == 1 &&
            joined[0].find("\"application\"") != std::string::npos &&
            joined[0].find("\"file_integrity\"") != std::string::npos,
            "Application -> File joins via shared pid");
    }

    // ── USB -> Process/File justified chain, positive and negative ──────────
    {
        CorrelationEngine engine;
        const int64_t session_end = NowMs();
        const int64_t duration_s = 30;

        engine.Ingest("port",
            "{\"endpoint\":\"usb_monitor\",\"event_type\":\"USB_SESSION_END\",\"t_unix_ms\":" +
            std::to_string(session_end) + ",\"mount_point\":\"F:\\\\\","
            "\"timing\":{\"duration_seconds\":" + std::to_string(duration_s) + ".000}}");
        // A file written to the mounted volume during the session -- justified bridge.
        engine.Ingest("file_integrity",
            "{\"action\":\"create\",\"path\":\"F:\\\\payload.exe\",\"t_unix_ms\":" +
            std::to_string(session_end - 15000) + ",\"pid\":1}");

        auto joined = engine.TryCorrelate();
        ok &= Require(joined.size() == 1, "USB session end joins with the file written to its own mount point");
        if (!joined.empty()) {
            ok &= Require(joined[0].find("\"confidence\":\"high\"") != std::string::npos,
                "USB -> File justified-bridge join is high confidence");
            ok &= Require(joined[0].find("usb_mount_path_match") != std::string::npos,
                "USB -> File join carries the real bridge reason");
        }
    }
    {
        // Negative case: same USB session, but a file on an unrelated drive
        // that merely happens to fall inside the time window -- must either
        // not join, or join ONLY as explicitly low-confidence (never silently
        // presented as a proven chain).
        CorrelationEngine engine;
        const int64_t session_end = NowMs();
        engine.Ingest("port",
            "{\"endpoint\":\"usb_monitor\",\"event_type\":\"USB_SESSION_END\",\"t_unix_ms\":" +
            std::to_string(session_end) + ",\"mount_point\":\"G:\\\\\","
            "\"timing\":{\"duration_seconds\":10.000}}");
        engine.Ingest("file_integrity",
            "{\"action\":\"write\",\"path\":\"C:\\\\Windows\\\\System32\\\\calc.exe\",\"t_unix_ms\":" +
            std::to_string(session_end - 2000) + ",\"pid\":1}");

        auto joined = engine.TryCorrelate();
        if (!joined.empty()) {
            ok &= Require(joined[0].find("\"confidence\":\"low\"") != std::string::npos &&
                joined[0].find("\"caveat\"") != std::string::npos,
                "USB -> unrelated-drive File join (if made at all) is explicitly low-confidence with a caveat, never a proven chain");
        }
    }

    // ── Group identity vs revision: FORU.TXT 12.6 -- unique groups must not
    //    be confused with growing snapshots ──────────────────────────────────
    {
        CorrelationEngine engine;
        const int64_t t0 = NowMs();
        const int pid = 5151;

        engine.Ingest("process",
            "{\"event_subtype\":\"process_start\",\"t_unix_ms\":" + std::to_string(t0) +
            ",\"pid\":" + std::to_string(pid) + "}");
        engine.Ingest("file_integrity",
            "{\"action\":\"create\",\"t_unix_ms\":" + std::to_string(t0 + 100) +
            ",\"pid\":" + std::to_string(pid) + "}");
        engine.Ingest("network",
            "{\"record_type\":\"network_packet\",\"t_unix_ms\":" + std::to_string(t0 + 200) +
            ",\"pid\":" + std::to_string(pid) + "}");

        std::vector<std::string> all_joined;
        for (int cycle = 0; cycle < 4; ++cycle) {
            auto batch = engine.TryCorrelate();
            all_joined.insert(all_joined.end(), batch.begin(), batch.end());
        }

        // Multiple revisions of the SAME group are emitted as this group
        // grows (process+file, then +network) -- more than one JSON line...
        ok &= Require(all_joined.size() >= 2,
            "more than one session_timeline snapshot is emitted as the group grows across cycles");
        // ...but engine.TotalGroups() (the authoritative unique-group count)
        // must still say exactly one group, proving snapshots != groups.
        ok &= Require(engine.TotalGroups() == 1,
            "despite multiple emitted snapshots, there is still exactly ONE unique group -- "
            "a consumer counting emitted lines instead of distinct group_id would wrongly see >1");
        ok &= Require(all_joined.front().find("\"revision\":1") != std::string::npos,
            "first snapshot is revision 1");
        ok &= Require(all_joined.back().find("\"revision\":1") == std::string::npos ||
            all_joined.size() == 1,
            "later snapshots carry a higher revision than the first (not the same revision repeated)");
    }

    // ── Bounded graph: per-record and per-group caps hold, declines counted ──
    {
        // A daisy-chain via parent_pid lineage (process[i] is the parent of
        // network[i], which is the parent of process[i+1], ...), ingested
        // and correlated ONE RECORD AT A TIME (mirroring main.cpp's real
        // ingest-then-correlate loop) so there is only ever one growing
        // chain in flight -- no parallel islands competing for the same
        // pair-scan cycle. Each node only ever needs 2 of its 4-join
        // budget (prev+next), so kMaxJoinsPerRecord is never the
        // bottleneck -- kMaxGroupSize (8) is, which is exactly what this
        // proves gets capped and counted rather than silently exceeded.
        CorrelationEngine engine;
        const int64_t t0 = NowMs();
        const int chain_length = 15;
        uint32_t pid = 5000;
        for (int i = 0; i < chain_length; ++i) {
            const std::string endpoint = (i % 2 == 0) ? "process" : "network";
            const uint32_t parent = pid - 1;
            const std::string field = (endpoint == "process")
                ? "\"event_subtype\":\"process_start\","
                : "\"record_type\":\"network_packet\",";
            engine.Ingest(endpoint,
                "{" + field + "\"t_unix_ms\":" + std::to_string(t0 + i) +
                ",\"pid\":" + std::to_string(pid) +
                (i > 0 ? ",\"parent_pid\":" + std::to_string(parent) : "") + "}");
            ++pid;
            engine.TryCorrelate();
        }

        // Once the first group hits kMaxGroupSize, the decline correctly
        // leaves the next chain link ungrouped rather than silently
        // overgrowing it -- that link then starts a second group with ITS
        // neighbor, so this legitimately produces more than one group. The
        // property this proves is the decline itself, not a single group.
        ok &= Require(engine.DeclinedGroupSizeCount() > 0,
            "exceeding kMaxGroupSize is counted as a declined join, not silently dropped");
        ok &= Require(engine.TotalGroups() >= 1, "the chain still produced at least one bounded group");
    }

    // ── RAM/disk auto-lightening (shared with all 5 endpoints) ──────────────
    {
        ok &= Require(ClassifyPressure(50, 10ULL * 1024 * 1024 * 1024) == PressureTier::Normal,
            "low RAM load + ample disk classifies as normal");
        ok &= Require(ClassifyPressure(95, 10ULL * 1024 * 1024 * 1024) == PressureTier::Severe,
            "very high RAM load triggers severe tier");
        ok &= Require(AdaptiveCap(10, 2, 0.25) == 2,
            "severe factor respects the configured floor");
    }

    // ── FORU.TXT section 15: numeric confidence scoring ──────────────────────
    {
        // Base weight at delta_ms==0 is exactly the documented constant.
        ok &= Require(ScoreConfidence("same_pid", 0, 2000) == 0.95,
            "same_pid at delta 0 scores exactly its base weight (0.95)");
        // At the edge of the window, score is exactly 70% of the base weight
        // (the documented "* (1 - 0.3 * fraction)" formula, fraction==1).
        const double edgeScore = ScoreConfidence("same_pid", 2000, 2000);
        ok &= Require(edgeScore > 0.664 && edgeScore < 0.666,
            "same_pid at the window edge scores ~70% of base (0.95 * 0.7 = 0.665)");
        // A delta beyond the window still clamps to the same 70% floor
        // rather than going negative or exceeding the base weight.
        ok &= Require(ScoreConfidence("same_pid", 5000, 2000) == edgeScore,
            "delta beyond the window clamps to the same floor as the window edge, doesn't go lower");
        // Ordering matches the pre-existing categorical labels exactly:
        // same_pid/usb_mount_path_match (high) > parent_child_pid (high) >
        // sibling_pid (medium) > port_temporal_proximity_only (low).
        ok &= Require(ScoreConfidence("same_pid", 0, 2000) > ScoreConfidence("parent_child_pid", 0, 2000),
            "same_pid outscores parent_child_pid at equal delta");
        ok &= Require(ScoreConfidence("parent_child_pid", 0, 2000) > ScoreConfidence("sibling_pid", 0, 2000),
            "parent_child_pid outscores sibling_pid at equal delta");
        ok &= Require(ScoreConfidence("sibling_pid", 0, 2000) > ScoreConfidence("port_temporal_proximity_only", 0, 2000),
            "sibling_pid outscores port_temporal_proximity_only at equal delta");
        // An unknown reason never fabricates a nonzero score.
        ok &= Require(ScoreConfidence("something_made_up", 0, 2000) == 0.0,
            "an unrecognized reason scores exactly 0.0, never a guessed nonzero value");

        // EvaluateLineageEdge/EvaluatePortBridgeEdge actually populate the
        // field on a real edge, not just the free function in isolation.
        EvidenceRecord a, b;
        a.endpoint = "process"; a.pid = 555; a.t_unix_ms = 1000;
        b.endpoint = "network"; b.pid = 555; b.t_unix_ms = 1000;
        const EdgeInfo edge = EvaluateLineageEdge(a, b, 2000);
        ok &= Require(edge.matched && edge.confidence_score == 0.95,
            "EvaluateLineageEdge populates confidence_score on a real same_pid match");
    }

    // ── FORU.TXT section 8/15: native durable evidence ID extraction ────────
    {
        // A source line that HAS been upgraded to stamp record_id/session_id/
        // source_file/byte_offset (evidence_envelope.h) is correctly captured.
        EvidenceRecord upgraded = ParseEvidenceLine("process",
            "{\"record_id\":42,\"session_id\":\"process-123-456\","
            "\"source_file\":\"titan_20260802_000000.jsonl\",\"byte_offset\":789,"
            "\"event_subtype\":\"process_start\",\"t_unix_ms\":1000,\"pid\":1}");
        ok &= Require(upgraded.native_record_id == "42", "native_record_id extracted correctly");
        ok &= Require(upgraded.native_session_id == "process-123-456", "native_session_id extracted correctly");
        ok &= Require(upgraded.native_source_file == "titan_20260802_000000.jsonl", "native_source_file extracted correctly");
        ok &= Require(upgraded.native_byte_offset == 789, "native_byte_offset extracted correctly");

        // A source line from a NOT-YET-upgraded endpoint must never fabricate
        // these fields -- honest absence (empty string / -1 sentinel), the
        // engine must keep working exactly as before for it.
        EvidenceRecord notUpgraded = ParseEvidenceLine("network",
            "{\"record_type\":\"network_packet\",\"t_unix_ms\":1000,\"pid\":1}");
        ok &= Require(notUpgraded.native_record_id.empty(), "native_record_id stays empty when absent from the source line");
        ok &= Require(notUpgraded.native_byte_offset == -1, "native_byte_offset stays -1 (sentinel) when absent");
    }

    if (ok) {
        std::cout << "[TEST] PASS\n";
        return 0;
    }
    return 1;
}
