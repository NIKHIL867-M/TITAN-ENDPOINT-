// correlation_engine.cpp
#include "correlation_engine.h"
#include "json_fields.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <sstream>

namespace correlator {

namespace {

// FORU.TXT 12.2: normalize using the correct field per endpoint schema --
// never a blind "type" lookup for every endpoint. Confirmed by reading each
// endpoint's actual JSON emission (event.cpp / file_processor.cpp /
// applog_monitor.cpp / usb_monitor.cpp / usb_session.cpp), not assumed:
//   process:        event_subtype   (process_start|process_stop|process_snapshot) -- has no top-level "type" at all
//   network:        record_type     (network_packet)                              -- has no top-level "type" at all
//   application:    type            (process|file|application_state|selection|network|module) -- already correct
//   file_integrity: action          (create|write|delete|rename|close|set_info)   -- has no top-level "type" for its main record;
//                                                                                     falls back to "type" for its temp_* derived records
//   port:           type            (usb_hid_event|usb_injection_alert) if present, else event_type (USB_SESSION_END)
std::string NormalizeRecordType(const std::string& endpoint, const std::string& raw_line, const std::string& top_level_type)
{
    std::string value;
    if (endpoint == "process") {
        if (ExtractJsonString(raw_line, "event_subtype", value)) return value;
    } else if (endpoint == "network") {
        if (ExtractJsonString(raw_line, "record_type", value)) return value;
    } else if (endpoint == "application") {
        if (!top_level_type.empty()) return top_level_type;
    } else if (endpoint == "file_integrity") {
        if (ExtractJsonString(raw_line, "action", value)) return value;
        if (!top_level_type.empty()) return top_level_type;
    } else if (endpoint == "port") {
        if (!top_level_type.empty()) return top_level_type;
        if (ExtractJsonString(raw_line, "event_type", value)) return value;
    }
    return top_level_type;   // best-effort fallback -- better than silently blank
}

// FORU.TXT 12.5's bridging path: the generic "this record touched this
// filesystem path" field, wherever the schema carries one.
std::string ExtractBridgePath(const std::string& endpoint, const std::string& raw_line)
{
    std::string value;
    if (endpoint == "process") {
        if (ExtractJsonString(raw_line, "canonical_path", value)) return value;
    } else if (endpoint == "file_integrity" || endpoint == "application") {
        if (ExtractJsonString(raw_line, "path", value)) return value;
    }
    return "";
}

bool CaseInsensitiveStartsWith(const std::string& haystack, const std::string& prefix)
{
    if (prefix.empty() || haystack.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(haystack[i])) !=
            std::tolower(static_cast<unsigned char>(prefix[i])))
            return false;
    }
    return true;
}

int64_t NowUnixMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string EscapeJson(const std::string& s)
{
    std::ostringstream o;
    for (unsigned char c : s) {
        switch (c) {
        case '"':  o << "\\\""; break;
        case '\\': o << "\\\\"; break;
        case '\n': o << "\\n";  break;
        case '\r': o << "\\r";  break;
        case '\t': o << "\\t";  break;
        default:
            if (c < 0x20u) { /* drop other control chars -- display-only field */ }
            else o << c;
        }
    }
    return o.str();
}

bool AlreadyJoined(const EvidenceRecord& r, uint64_t partner_id)
{
    return std::find(r.joined_partner_ids.begin(), r.joined_partner_ids.end(), partner_id)
        != r.joined_partner_ids.end();
}

// Base weight per match reason -- the ordering mirrors the existing
// "high"/"medium"/"low" categorical labels exactly (same_pid and
// usb_mount_path_match are the two strongest possible signals this engine
// can observe; sibling_pid and port_temporal_proximity_only are the
// weakest), just expressed numerically instead of three buckets.
double BaseConfidenceWeight(const std::string& reason)
{
    if (reason == "same_pid") return 0.95;
    if (reason == "usb_mount_path_match") return 0.90;
    if (reason == "parent_child_pid") return 0.85;
    if (reason == "sibling_pid") return 0.55;
    if (reason == "port_temporal_proximity_only") return 0.30;
    return 0.0; // unknown reason -- never fabricate a nonzero score for it
}

} // namespace

// FORU.TXT section 15: numeric confidence, not just a category. Formula:
// score = base(reason) * (1 - 0.3 * min(1, |deltaMs| / max(1, windowMs)))
// i.e. a match at delta_ms==0 scores exactly the base weight; a match right
// at the edge of the window it was evaluated against scores 70% of it. This
// is a deliberately simple, fully-documented, auditable function of actual
// measured evidence (which reason matched + how much of the allowed window
// the timing actually used) -- not a machine-learned or otherwise opaque
// score.
double ScoreConfidence(const std::string& reason, int64_t deltaMs, int64_t windowMs)
{
    const double base = BaseConfidenceWeight(reason);
    if (base <= 0.0) return 0.0;
    const int64_t safeWindow = windowMs > 0 ? windowMs : 1;
    double fraction = static_cast<double>(deltaMs < 0 ? -deltaMs : deltaMs) / static_cast<double>(safeWindow);
    if (fraction > 1.0) fraction = 1.0;
    return base * (1.0 - 0.3 * fraction);
}

bool IsOperationalStatusLine(const std::string& raw_line)
{
    std::string type;
    if (ExtractJsonString(raw_line, "type", type) &&
        (type == "collector_health" || type == "startup" || type == "control_ack"))
        return true;
    std::string recordType;
    if (ExtractJsonString(raw_line, "record_type", recordType) && recordType == "collector_health")
        return true;
    return false;
}

EvidenceRecord ParseEvidenceLine(const std::string& endpoint, const std::string& raw_line)
{
    EvidenceRecord record;
    record.endpoint = endpoint;
    record.raw_line = raw_line;

    std::string top_level_type;
    ExtractJsonString(raw_line, "type", top_level_type);
    record.record_type = NormalizeRecordType(endpoint, raw_line, top_level_type);
    record.path = ExtractBridgePath(endpoint, raw_line);

    if (endpoint == "port") {
        ExtractJsonString(raw_line, "mount_point", record.mount_point);
        ExtractJsonNumber(raw_line, "duration_seconds", record.duration_seconds);
    }

    int64_t value = 0;
    if (ExtractJsonNumber(raw_line, "t_unix_ms", value)) record.t_unix_ms = value;
    if (ExtractJsonNumber(raw_line, "pid", value)) record.pid = static_cast<uint32_t>(value);
    if (ExtractJsonNumber(raw_line, "parent_pid", value))
        record.parent_pid = static_cast<uint32_t>(value);

    // FORU.TXT section 8/15: the native writer's own durable identity, when
    // present (evidence_envelope.h's stamped fields) -- absent entirely on a
    // source endpoint that hasn't been upgraded yet, which is fine: these
    // stay at their empty/-1 defaults and callers must treat that as
    // "unavailable", never assume presence.
    int64_t recordIdValue = 0;
    if (ExtractJsonNumber(raw_line, "record_id", recordIdValue))
        record.native_record_id = std::to_string(recordIdValue);
    ExtractJsonString(raw_line, "session_id", record.native_session_id);
    ExtractJsonString(raw_line, "source_file", record.native_source_file);
    int64_t byteOffsetValue = 0;
    if (ExtractJsonNumber(raw_line, "byte_offset", byteOffsetValue))
        record.native_byte_offset = byteOffsetValue;
    ExtractJsonString(raw_line, "content_hash", record.native_content_hash);

    return record;
}

EdgeInfo EvaluateLineageEdge(const EvidenceRecord& a, const EvidenceRecord& b, int64_t windowMs)
{
    EdgeInfo edge;
    if (a.t_unix_ms == 0 || b.t_unix_ms == 0) return edge;   // no usable timestamp
    const int64_t delta = a.t_unix_ms > b.t_unix_ms ? a.t_unix_ms - b.t_unix_ms : b.t_unix_ms - a.t_unix_ms;
    if (delta > windowMs) return edge;

    if (a.pid != 0 && a.pid == b.pid) {
        edge.matched = true;
        edge.reason = "same_pid";
        edge.matched_fields = { "pid" };
        edge.confidence = "high";
    } else if ((a.pid != 0 && a.pid == b.parent_pid) || (b.pid != 0 && b.pid == a.parent_pid)) {
        edge.matched = true;
        edge.reason = "parent_child_pid";
        edge.matched_fields = { "pid", "parent_pid" };
        edge.confidence = "high";
    } else if (a.parent_pid != 0 && a.parent_pid == b.parent_pid) {
        edge.matched = true;
        edge.reason = "sibling_pid";
        edge.matched_fields = { "parent_pid" };
        edge.confidence = "medium";   // two children of the same parent, not the same actor -- weaker inference
    } else {
        return edge;
    }

    edge.delta_ms = delta;
    edge.confidence_score = ScoreConfidence(edge.reason, delta, windowMs);
    return edge;
}

EdgeInfo EvaluatePortBridgeEdge(const EvidenceRecord& port_rec, const EvidenceRecord& other_rec)
{
    EdgeInfo edge;
    if (port_rec.endpoint != "port" || other_rec.endpoint == "port") return edge;
    if (other_rec.t_unix_ms == 0 || port_rec.t_unix_ms == 0) return edge;

    // Only a USB_SESSION_END record carries mount_point + duration_seconds
    // -- USB_HID_* telemetry has no bridge-relevant field, so it never
    // joins unrelated activity (FORU.TXT 12.5: never join Port purely on
    // proximity when no defensible bridge exists).
    if (port_rec.mount_point.empty()) return edge;

    const int64_t session_end_ms = port_rec.t_unix_ms;
    const int64_t session_start_ms = session_end_ms - port_rec.duration_seconds * 1000;
    const int64_t window_lo = session_start_ms - CorrelationEngine::kUsbSessionSlackMs;
    const int64_t window_hi = session_end_ms + CorrelationEngine::kUsbSessionSlackMs;
    if (other_rec.t_unix_ms < window_lo || other_rec.t_unix_ms > window_hi) return edge;   // not even proximate to this session

    const int64_t delta_ms = other_rec.t_unix_ms > session_end_ms
        ? other_rec.t_unix_ms - session_end_ms
        : (other_rec.t_unix_ms < session_start_ms ? session_start_ms - other_rec.t_unix_ms : 0);

    if (!other_rec.path.empty() && CaseInsensitiveStartsWith(other_rec.path, port_rec.mount_point)) {
        edge.matched = true;
        edge.reason = "usb_mount_path_match";
        edge.matched_fields = { "mount_point", "path" };
        edge.confidence = "high";
    } else {
        edge.matched = true;
        edge.reason = "port_temporal_proximity_only";
        edge.matched_fields = {};
        edge.confidence = "low";
        edge.caveat = "Port evidence has no OS pid; this edge is based only on temporal proximity to the "
                      "USB session window, not a path or process-lineage bridge -- not a proven causal chain.";
    }
    edge.delta_ms = delta_ms;
    edge.confidence_score = ScoreConfidence(edge.reason, delta_ms,
        CorrelationEngine::kUsbSessionSlackMs);
    return edge;
}

EdgeInfo EvaluateEdge(const EvidenceRecord& a, const EvidenceRecord& b, int64_t windowMs)
{
    if (a.endpoint == "port") return EvaluatePortBridgeEdge(a, b);
    if (b.endpoint == "port") return EvaluatePortBridgeEdge(b, a);
    return EvaluateLineageEdge(a, b, windowMs);
}

void CorrelationEngine::Ingest(const std::string& endpoint, const std::string& raw_line)
{
    if (raw_line.empty()) return;
    // FORU.TXT 12.1/12.7: operational status records never enter
    // behavioural correlation or contaminate a group's member list.
    if (IsOperationalStatusLine(raw_line)) return;

    EvidenceRecord record = ParseEvidenceLine(endpoint, raw_line);
    // Cap the raw_line copy kept in RAM/output -- evidence lines from a
    // pathological source shouldn't blow up this process's own memory.
    if (record.raw_line.size() > 4096) record.raw_line.resize(4096);
    record.id = next_record_id_++;

    auto& ring = by_endpoint_[endpoint];
    ring.push_back(std::move(record));
    if (ring.size() > kMaxPerEndpoint) {
        ring.pop_front();
        ++evicted_by_capacity_;
    }
}

void CorrelationEngine::PruneStale(int64_t now_ms)
{
    for (auto& [endpoint, ring] : by_endpoint_) {
        (void)endpoint;
        while (!ring.empty() &&
            ring.front().t_unix_ms != 0 &&
            now_ms - ring.front().t_unix_ms > kMaxAgeMs) {
            ring.pop_front();
            ++evicted_by_age_;
        }
    }
}

void CorrelationEngine::PruneStaleGroups(int64_t now_ms, std::vector<std::string>& out)
{
    // A group with no new member in kMaxAgeMs is done growing -- its story
    // is complete (or abandoned). Emit one final "closed" revision so a
    // consumer knows this group_id will never change again, then free it
    // rather than holding it forever.
    for (auto it = group_last_updated_ms_.begin(); it != group_last_updated_ms_.end(); ) {
        if (now_ms - it->second > kMaxAgeMs) {
            out.push_back(RenderGroupJson(it->first, /*final_revision=*/true));
            ++expired_group_count_;
            groups_.erase(it->first);
            group_revision_.erase(it->first);
            it = group_last_updated_ms_.erase(it);
        } else {
            ++it;
        }
    }
}

uint32_t CorrelationEngine::AssignOrExtendGroup(EvidenceRecord& a, EvidenceRecord& b, const EdgeInfo& edge, int64_t now_ms)
{
    auto make_anchor = [](const EvidenceRecord& r) {
        GroupMember m;
        m.endpoint = r.endpoint;
        m.record_type = r.record_type;
        m.t_unix_ms = r.t_unix_ms;
        m.pid = r.pid;
        m.parent_pid = r.parent_pid;
        m.source_evidence_id = r.endpoint + ":" + std::to_string(r.id);
        m.raw_line = r.raw_line;
        m.native_record_id = r.native_record_id;
        m.native_session_id = r.native_session_id;
        m.native_source_file = r.native_source_file;
        m.native_byte_offset = r.native_byte_offset;
        m.native_content_hash = r.native_content_hash;
        m.join_reason = "anchor";
        return m;
        };
    auto make_joined = [&](const EvidenceRecord& r) {
        GroupMember m = make_anchor(r);
        m.join_reason = edge.reason;
        m.matched_fields = edge.matched_fields;
        m.delta_ms = edge.delta_ms;
        m.confidence = edge.confidence;
        m.confidence_score = edge.confidence_score;
        m.window_ms = CorrelationEngine::kJoinWindowMs;
        m.caveat = edge.caveat;
        return m;
        };

    if (a.group_id != 0 && a.group_id == b.group_id) {
        // Already transitively linked via a prior edge -- nothing new to
        // add or emit for this specific pair.
        return 0;
    }

    if (a.group_id == 0 && b.group_id == 0) {
        if (groups_.size() >= kMaxActiveGroups) { ++declined_active_groups_; return 0; }
        const uint32_t gid = next_group_id_++;
        groups_[gid] = { make_anchor(a), make_joined(b) };
        group_last_updated_ms_[gid] = now_ms;
        group_revision_[gid] = 1;
        a.group_id = gid;
        b.group_id = gid;
        return gid;
    }

    if (a.group_id != 0 && b.group_id == 0) {
        auto& members = groups_[a.group_id];
        if (members.size() >= kMaxGroupSize) { ++declined_group_size_; return 0; }
        members.push_back(make_joined(b));
        group_last_updated_ms_[a.group_id] = now_ms;
        ++group_revision_[a.group_id];
        b.group_id = a.group_id;
        return a.group_id;
    }

    if (b.group_id != 0 && a.group_id == 0) {
        auto& members = groups_[b.group_id];
        if (members.size() >= kMaxGroupSize) { ++declined_group_size_; return 0; }
        members.push_back(make_joined(a));
        group_last_updated_ms_[b.group_id] = now_ms;
        ++group_revision_[b.group_id];
        a.group_id = b.group_id;
        return b.group_id;
    }

    // Both already belong to different, established groups. Merging two
    // independently-grown chains adds real complexity (renumbering,
    // unbounded merge cascades) for a rare case; declining is a deliberate,
    // documented bound -- the two groups still separately carry real
    // evidence, just not combined into one.
    ++declined_cross_merge_;
    return 0;
}

std::string CorrelationEngine::RenderGroupJson(uint32_t group_id, bool final_revision) const
{
    auto it = groups_.find(group_id);
    if (it == groups_.end()) return {};
    auto rev_it = group_revision_.find(group_id);
    const uint32_t revision = rev_it != group_revision_.end() ? rev_it->second : 1;

    std::ostringstream j;
    j << "{\"type\":\"session_timeline\","
        << "\"t_unix_ms\":" << NowUnixMs() << ","
        << "\"group_id\":" << group_id << ","
        << "\"revision\":" << revision << ","
        << "\"final\":" << (final_revision ? "true" : "false") << ","
        << "\"member_count\":" << it->second.size() << ","
        << "\"members\":[";
    bool first = true;
    for (const auto& m : it->second) {
        if (!first) j << ",";
        first = false;
        j << "{\"endpoint\":\"" << EscapeJson(m.endpoint) << "\","
            << "\"record_type\":\"" << EscapeJson(m.record_type) << "\","
            << "\"source_evidence_id\":\"" << EscapeJson(m.source_evidence_id) << "\","
            << "\"t_unix_ms\":" << m.t_unix_ms << ","
            << "\"pid\":" << m.pid << ","
            << "\"parent_pid\":" << m.parent_pid << ","
            << "\"join_reason\":\"" << EscapeJson(m.join_reason) << "\",";
        j << "\"matched_fields\":[";
        for (size_t i = 0; i < m.matched_fields.size(); ++i) {
            if (i) j << ",";
            j << "\"" << EscapeJson(m.matched_fields[i]) << "\"";
        }
        j << "],";
        j << "\"delta_ms\":" << m.delta_ms << ","
            << "\"window_ms\":" << m.window_ms << ",";
        if (!m.confidence.empty()) j << "\"confidence\":\"" << EscapeJson(m.confidence) << "\",";
        j << "\"confidence_score\":" << m.confidence_score << ",";
        if (!m.caveat.empty()) j << "\"caveat\":\"" << EscapeJson(m.caveat) << "\",";
        // FORU.TXT section 8/15: exact durable reference to the native
        // record, when the source endpoint has been upgraded to stamp one --
        // null fields (not omitted) so a consumer can tell "not available
        // from this producer yet" apart from "field never existed".
        if (!m.native_record_id.empty()) {
            j << "\"native_record_id\":\"" << EscapeJson(m.native_record_id) << "\","
              << "\"native_session_id\":\"" << EscapeJson(m.native_session_id) << "\","
              << "\"native_source_file\":\"" << EscapeJson(m.native_source_file) << "\","
              << "\"native_byte_offset\":" << m.native_byte_offset << ","
              << "\"native_content_hash\":" << (m.native_content_hash.empty() ? "null" : "\"" + EscapeJson(m.native_content_hash) + "\"") << ",";
        } else {
            j << "\"native_record_id\":null,\"native_session_id\":null,"
              << "\"native_source_file\":null,\"native_byte_offset\":null,\"native_content_hash\":null,";
        }
        j << "\"raw_source\":\"" << EscapeJson(m.raw_line) << "\"}";
    }
    j << "]}";
    return j.str();
}

std::vector<std::string> CorrelationEngine::TryCorrelate()
{
    std::vector<std::string> joined;
    const int64_t now_ms = NowUnixMs();
    PruneStale(now_ms);
    PruneStaleGroups(now_ms, joined);

    // Collect endpoint names once so the pairwise loop below has stable
    // iteration order and can index by name.
    std::vector<std::string> endpoints;
    endpoints.reserve(by_endpoint_.size());
    for (auto& [name, ring] : by_endpoint_) {
        (void)ring;
        endpoints.push_back(name);
    }

    size_t joins = 0;
    for (size_t ea = 0; ea < endpoints.size() && joins < kMaxJoinsPerCycle; ++ea) {
        for (size_t eb = ea + 1; eb < endpoints.size() && joins < kMaxJoinsPerCycle; ++eb) {
            auto& a_ring = by_endpoint_[endpoints[ea]];
            auto& b_ring = by_endpoint_[endpoints[eb]];

            // Port's justified bridge (USB session mount-path match) can
            // legitimately span far more than the generic lineage join
            // window -- a file written 30s into a session is still inside
            // it. Widen the prefilter for any pair involving Port so
            // EvaluatePortBridgeEdge (which does the real, precise window
            // check against the session's own duration) actually gets a
            // chance to see those candidates.
            const bool involves_port = (endpoints[ea] == "port" || endpoints[eb] == "port");
            const int64_t prefilter_window_ms = involves_port
                ? CorrelationEngine::kPortPrefilterWindowMs
                : CorrelationEngine::kJoinWindowMs;

            // Two-pointer scan: both rings are time-ordered (endpoints
            // append new lines in real-time order, and Ingest() only ever
            // pushes to the back), so for each 'a' record we only need to
            // slide 'b's window forward, not rescan from the start.
            size_t bj = 0;
            for (size_t ai = 0; ai < a_ring.size() && joins < kMaxJoinsPerCycle; ++ai) {
                EvidenceRecord& a_rec = a_ring[ai];
                if (a_rec.t_unix_ms == 0) continue;
                if (a_rec.joined_partner_ids.size() >= CorrelationEngine::kMaxJoinsPerRecord) continue;

                // A record with no usable timestamp can never correlate by
                // time, so treat it the same as "too old" here -- advance
                // past it rather than letting it permanently stall bj.
                while (bj < b_ring.size() &&
                    (b_ring[bj].t_unix_ms == 0 ||
                        b_ring[bj].t_unix_ms < a_rec.t_unix_ms - prefilter_window_ms))
                    ++bj;

                for (size_t bk = bj;
                    bk < b_ring.size() &&
                    b_ring[bk].t_unix_ms <= a_rec.t_unix_ms + prefilter_window_ms;
                    ++bk)
                {
                    EvidenceRecord& b_rec = b_ring[bk];
                    if (b_rec.joined_partner_ids.size() >= CorrelationEngine::kMaxJoinsPerRecord) continue;
                    if (AlreadyJoined(a_rec, b_rec.id)) continue;   // don't re-evaluate the exact same pair every cycle

                    const EdgeInfo edge = EvaluateEdge(a_rec, b_rec, CorrelationEngine::kJoinWindowMs);
                    if (!edge.matched) continue;

                    // Record the pair as evaluated regardless of whether a
                    // group actually changed (e.g. already-same-group), so
                    // it is never re-scanned every single cycle for the
                    // rest of its time in the ring.
                    a_rec.joined_partner_ids.push_back(b_rec.id);
                    b_rec.joined_partner_ids.push_back(a_rec.id);

                    // The engine's edge is expressed as "the second-seen
                    // side joins via this reason" -- pass a/b as encountered
                    // (a_rec is the earlier-or-equal ring in iteration order).
                    const uint32_t gid = AssignOrExtendGroup(a_rec, b_rec, edge, now_ms);
                    if (gid != 0) {
                        joined.push_back(RenderGroupJson(gid, /*final_revision=*/false));
                        ++joins;
                    }
                    break;   // one match is enough for this a_rec this cycle -- more edges can form on later cycles within its ring lifetime
                }
            }
        }
    }

    return joined;
}

size_t CorrelationEngine::TotalRecords() const
{
    size_t total = 0;
    for (auto& [name, ring] : by_endpoint_) {
        (void)name;
        total += ring.size();
    }
    return total;
}

} // namespace correlator
