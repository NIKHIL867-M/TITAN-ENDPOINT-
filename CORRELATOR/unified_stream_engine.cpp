#include "unified_stream_engine.h"
#include "json_fields.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <set>
#include <sstream>

namespace correlator {
namespace {

std::string EscapeJson(const std::string& value)
{
    std::ostringstream out;
    for (const unsigned char c : value) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) {
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<unsigned int>(c) << std::dec << std::setfill(' ');
            } else {
                out << static_cast<char>(c);
            }
        }
    }
    return out.str();
}

uint64_t Fnv1a64(const std::string& value)
{
    uint64_t hash = 1469598103934665603ULL;
    for (const unsigned char c : value) {
        hash ^= c;
        hash *= 1099511628211ULL;
    }
    return hash;
}

std::string HexHash(const std::string& value)
{
    std::ostringstream out;
    out << std::hex << std::setw(16) << std::setfill('0') << Fnv1a64(value);
    return out.str();
}

void AppendStringField(std::ostringstream& out, const std::string& line, const char* key)
{
    std::string value;
    if (ExtractJsonString(line, key, value)) out << '|' << key << '=' << value;
}

void AppendNumberField(std::ostringstream& out, const std::string& line, const char* key)
{
    int64_t value = 0;
    if (ExtractJsonNumber(line, key, value)) out << '|' << key << '=' << value;
}

void RenderNullableString(std::ostringstream& out, const char* name, const std::string& value)
{
    out << "\"" << name << "\":";
    if (value.empty()) out << "null";
    else out << "\"" << EscapeJson(value) << "\"";
}

std::string SourceLabel(const std::string& source)
{
    return source == "file_integrity" ? "file" : source;
}

} // namespace

int64_t UnifiedStreamEngine::NowUnixMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string UnifiedStreamEngine::ExactIdentity(const EvidenceRecord& record)
{
    if (!record.native_session_id.empty() && !record.native_record_id.empty())
        return record.endpoint + "|native|" + record.native_session_id + '|' + record.native_record_id;
    if (!record.native_content_hash.empty())
        return record.endpoint + "|content|" + record.native_content_hash;
    return record.endpoint + "|raw|" + HexHash(record.raw_line);
}

std::string UnifiedStreamEngine::SemanticFingerprint(const EvidenceRecord& record, bool operational)
{
    if (operational) return ExactIdentity(record);

    std::ostringstream key;
    key << record.endpoint << '|' << record.record_type << "|pid=" << record.pid
        << "|ppid=" << record.parent_pid << "|path=" << record.path;

    // Stable activity identity across all five real schemas. Timestamps,
    // record IDs and cumulative health counters are intentionally excluded.
    for (const char* field : { "process_name", "image", "exe", "action", "event_type",
            "local_ip", "remote_ip", "src_ip", "dst_ip", "protocol", "direction",
            "module_path", "mount_point", "device_id", "command_line" })
        AppendStringField(key, record.raw_line, field);
    for (const char* field : { "local_port", "remote_port", "src_port", "dst_port",
            "transport_protocol", "creator_pid", "target_pid" })
        AppendNumberField(key, record.raw_line, field);
    return HexHash(key.str());
}

bool UnifiedStreamEngine::IsUsableConnection(const EvidenceRecord& a,
    const EvidenceRecord& b, const EdgeInfo& edge)
{
    if (!edge.matched || a.endpoint == b.endpoint) return false;
    // System/Idle PIDs and children of the System process are shared by huge
    // amounts of unrelated activity. PID alone is not evidence there.
    if (edge.reason == "same_pid" && (a.pid <= 4 || b.pid <= 4))
        return !a.path.empty() && !b.path.empty() && a.path == b.path;
    if (edge.reason == "sibling_pid" && (a.parent_pid <= 4 || b.parent_pid <= 4))
        return false;
    return true;
}

void UnifiedStreamEngine::RememberIdentity(std::string identity)
{
    recent_identities_.insert(identity);
    identity_order_.push_back(std::move(identity));
    while (identity_order_.size() > kMaxDedupIdentities) {
        recent_identities_.erase(identity_order_.front());
        identity_order_.pop_front();
    }
}

bool UnifiedStreamEngine::Ingest(const std::string& endpoint,
    const std::string& rawLine, int64_t observedAtUnixMs)
{
    if (rawLine.empty()) return false;
    const auto first = rawLine.find_first_not_of(" \t\r\n");
    const auto last = rawLine.find_last_not_of(" \t\r\n");
    if (first == std::string::npos || rawLine[first] != '{' || rawLine[last] != '}') {
        ++parse_failures_;
        return false;
    }
    if (observedAtUnixMs <= 0) observedAtUnixMs = NowUnixMs();

    EvidenceRecord record = ParseEvidenceLine(endpoint, rawLine);
    if (record.record_type.empty()) record.record_type = "unknown";
    if (record.raw_line.size() > 4096) record.raw_line.resize(4096);
    const bool operational = IsOperationalStatusLine(rawLine);
    const std::string exact = ExactIdentity(record);
    if (recent_identities_.contains(exact)) {
        ++exact_duplicates_suppressed_;
        return false;
    }
    RememberIdentity(exact);
    ++records_accepted_;
    ++records_represented_;

    const std::string fingerprint = SemanticFingerprint(record, operational);
    const int64_t eventMs = record.t_unix_ms > 0 ? record.t_unix_ms : observedAtUnixMs;

    // Compact a rapid semantic repeat into its existing member. The latest
    // durable evidence reference remains available alongside the first.
    if (!operational) {
        for (auto& [id, group] : groups_) {
            (void)id;
            for (auto& member : group.members) {
                const int64_t delta = std::llabs(eventMs - member.last_seen_ms);
                if (member.first.endpoint == endpoint && member.fingerprint == fingerprint &&
                    delta <= kRepeatWindowMs) {
                    member.last = std::move(record);
                    member.last_seen_ms = eventMs;
                    ++member.repeat_count;
                    ++group.records_observed;
                    group.last_seen_ms = std::max(group.last_seen_ms, eventMs);
                    group.last_activity_wall_ms = observedAtUnixMs;
                    ++semantic_repeats_compacted_;
                    return true;
                }
            }
        }
    }

    std::vector<Candidate> candidates;
    if (!operational) {
        for (const auto& [groupId, group] : groups_) {
            if (group.operational_only) continue;
            Candidate best;
            for (size_t i = 0; i < group.members.size(); ++i) {
                const auto& existing = group.members[i].last;
                EdgeInfo edge = EvaluateEdge(existing, record, kCorrelationWindowMs);
                if (!IsUsableConnection(existing, record, edge)) continue;
                if (best.group_id == 0 || edge.confidence_score > best.edge.confidence_score)
                    best = Candidate{groupId, i, std::move(edge)};
            }
            if (best.group_id != 0) candidates.push_back(std::move(best));
        }
    }

    if (candidates.empty()) {
        if (groups_.size() >= kMaxPendingGroups) FlushOldestForCapacity();
        Group group;
        group.id = next_group_id_++;
        group.records_observed = 1;
        group.first_seen_ms = eventMs;
        group.last_seen_ms = eventMs;
        group.created_wall_ms = observedAtUnixMs;
        group.last_activity_wall_ms = observedAtUnixMs;
        group.operational_only = operational;
        group.members.push_back(Member{record, record, fingerprint, 1, eventMs, eventMs, {}});
        groups_.emplace(group.id, std::move(group));
        return true;
    }

    std::sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) {
        return a.edge.confidence_score > b.edge.confidence_score;
    });
    uint64_t targetId = candidates.front().group_id;
    auto targetIt = groups_.find(targetId);
    if (targetIt == groups_.end()) return false;

    // Merge every independently matched pending story that fits. This is the
    // crucial graph-union behavior missing from the previous implementation.
    struct Bridge { size_t from; EdgeInfo edge; };
    std::vector<Bridge> bridges;
    bridges.push_back({candidates.front().member_index, candidates.front().edge});
    std::set<uint64_t> mergedIds;
    for (size_t c = 1; c < candidates.size(); ++c) {
        const auto& candidate = candidates[c];
        if (candidate.group_id == targetId || mergedIds.contains(candidate.group_id)) continue;
        auto otherIt = groups_.find(candidate.group_id);
        if (otherIt == groups_.end()) continue;
        auto& target = targetIt->second;
        auto& other = otherIt->second;
        if (target.members.size() + other.members.size() + 1 > kMaxMembersPerGroup) {
            ++connection_limit_count_;
            continue;
        }
        const size_t offset = target.members.size();
        target.members.insert(target.members.end(), other.members.begin(), other.members.end());
        for (const auto& connection : other.connections)
            target.connections.push_back(Connection{connection.from + offset, connection.to + offset, connection.edge});
        bridges.push_back({offset + candidate.member_index, candidate.edge});
        target.records_observed += other.records_observed;
        target.first_seen_ms = std::min(target.first_seen_ms, other.first_seen_ms);
        target.last_seen_ms = std::max(target.last_seen_ms, other.last_seen_ms);
        mergedIds.insert(candidate.group_id);
        groups_.erase(otherIt);
    }

    auto& target = targetIt->second;
    if (target.members.size() >= kMaxMembersPerGroup) {
        forced_ready_.push_back(Render(target));
        forced_ready_groups_.push_back(target);
        ++events_emitted_;
        if (target.connections.empty()) ++single_source_emitted_; else ++connected_emitted_;
        groups_.erase(targetIt);
        ++capacity_flushes_;
        Group replacement;
        replacement.id = next_group_id_++;
        replacement.records_observed = 1;
        replacement.first_seen_ms = eventMs;
        replacement.last_seen_ms = eventMs;
        replacement.created_wall_ms = observedAtUnixMs;
        replacement.last_activity_wall_ms = observedAtUnixMs;
        replacement.operational_only = operational;
        replacement.members.push_back(Member{record, record, fingerprint, 1, eventMs, eventMs, {}});
        groups_.emplace(replacement.id, std::move(replacement));
        return true;
    }

    const size_t newIndex = target.members.size();
    target.members.push_back(Member{record, record, fingerprint, 1, eventMs, eventMs, candidates.front().edge});
    for (const auto& bridge : bridges)
        target.connections.push_back(Connection{bridge.from, newIndex, bridge.edge});
    ++target.records_observed;
    target.first_seen_ms = std::min(target.first_seen_ms, eventMs);
    target.last_seen_ms = std::max(target.last_seen_ms, eventMs);
    target.last_activity_wall_ms = observedAtUnixMs;
    target.operational_only = false;
    return true;
}

void UnifiedStreamEngine::FlushOldestForCapacity()
{
    if (groups_.empty()) return;
    auto oldest = std::min_element(groups_.begin(), groups_.end(), [](const auto& a, const auto& b) {
        return a.second.last_activity_wall_ms < b.second.last_activity_wall_ms;
    });
    forced_ready_.push_back(Render(oldest->second));
    forced_ready_groups_.push_back(oldest->second);
    ++events_emitted_;
    if (oldest->second.connections.empty()) ++single_source_emitted_; else ++connected_emitted_;
    groups_.erase(oldest);
    ++capacity_flushes_;
}

std::vector<std::string> UnifiedStreamEngine::DrainReady(int64_t nowUnixMs, bool force,
    std::vector<GroupSnapshot>* readyGroupsOut)
{
    if (nowUnixMs <= 0) nowUnixMs = NowUnixMs();
    std::vector<std::string> output;
    output.swap(forced_ready_);
    if (readyGroupsOut) {
        for (auto& group : forced_ready_groups_) readyGroupsOut->push_back(ToSnapshot(group));
        forced_ready_groups_.clear();
    } else {
        forced_ready_groups_.clear();
    }

    for (auto it = groups_.begin(); it != groups_.end();) {
        const auto& group = it->second;
        const bool settled = nowUnixMs - group.last_activity_wall_ms >= kSettleDelayMs;
        const bool lifetimeCap = nowUnixMs - group.created_wall_ms >= kMaxPendingLifetimeMs;
        if (!force && !settled && !lifetimeCap) { ++it; continue; }
        output.push_back(Render(group));
        if (readyGroupsOut) readyGroupsOut->push_back(ToSnapshot(group));
        ++events_emitted_;
        if (group.connections.empty()) ++single_source_emitted_; else ++connected_emitted_;
        it = groups_.erase(it);
    }
    return output;
}

GroupSnapshot UnifiedStreamEngine::ToSnapshot(const Group& group)
{
    GroupSnapshot snapshot;
    snapshot.id = group.id;
    snapshot.first_seen_ms = group.first_seen_ms;
    snapshot.last_seen_ms = group.last_seen_ms;
    snapshot.records_observed = group.records_observed;
    snapshot.operational_only = group.operational_only;
    snapshot.connected = !group.connections.empty();
    snapshot.members.reserve(group.members.size());
    for (const auto& member : group.members) {
        MemberSnapshot m;
        m.endpoint = member.first.endpoint;
        m.record_type = member.first.record_type;
        m.first_seen_ms = member.first_seen_ms;
        m.last_seen_ms = member.last_seen_ms;
        m.repeat_count = member.repeat_count;
        m.pid = member.first.pid;
        m.parent_pid = member.first.parent_pid;
        m.native_source_file = member.first.native_source_file;
        m.native_record_id = member.first.native_record_id;
        m.raw_line = member.first.raw_line;
        snapshot.members.push_back(std::move(m));
    }
    snapshot.connections.reserve(group.connections.size());
    for (const auto& connection : group.connections) {
        ConnectionSnapshot c;
        c.from = connection.from;
        c.to = connection.to;
        c.reason = connection.edge.reason;
        c.matched_fields = connection.edge.matched_fields;
        c.delta_ms = connection.edge.delta_ms;
        c.confidence = connection.edge.confidence;
        c.confidence_score = connection.edge.confidence_score;
        c.caveat = connection.edge.caveat;
        snapshot.connections.push_back(std::move(c));
    }
    return snapshot;
}

size_t UnifiedStreamEngine::PendingMemberCount() const noexcept
{
    size_t count = 0;
    for (const auto& [id, group] : groups_) { (void)id; count += group.members.size(); }
    return count;
}

std::string UnifiedStreamEngine::Render(const Group& group)
{
    std::set<std::string> sources;
    uint64_t repeats = 0;
    for (const auto& member : group.members) {
        sources.insert(SourceLabel(member.first.endpoint));
        repeats += member.repeat_count > 0 ? member.repeat_count - 1 : 0;
    }

    std::ostringstream out;
    out << "{\"type\":\"unified_event\",\"schema_version\":1,"
        << "\"t_unix_ms\":" << group.last_seen_ms << ','
        << "\"correlation_id\":\"corr-" << group.id << "\"," 
        << "\"group_id\":" << group.id << ','
        << "\"first_seen\":" << group.first_seen_ms << ','
        << "\"last_seen\":" << group.last_seen_ms << ','
        << "\"event_count\":" << group.records_observed << ','
        << "\"unique_event_count\":" << group.members.size() << ','
        << "\"repeat_count\":" << repeats << ','
        << "\"source_count\":" << sources.size() << ",\"sources\":[";
    bool firstSource = true;
    for (const auto& source : sources) {
        if (!firstSource) out << ',';
        firstSource = false;
        out << '"' << EscapeJson(source) << '"';
    }
    out << "],\"classification\":\"" << (group.operational_only ? "operational" : "activity") << "\",";
    if (group.connections.empty()) {
        out << "\"correlation\":{\"connected\":false,\"reason\":\"single_source\",\"connection_count\":0},";
    } else {
        const auto strongest = std::max_element(group.connections.begin(), group.connections.end(),
            [](const Connection& a, const Connection& b) { return a.edge.confidence_score < b.edge.confidence_score; });
        out << "\"correlation\":{\"connected\":true,\"reason\":\""
            << EscapeJson(strongest->edge.reason) << "\",\"confidence\":\""
            << EscapeJson(strongest->edge.confidence) << "\",\"confidence_score\":"
            << strongest->edge.confidence_score << ",\"connection_count\":" << group.connections.size() << "},";
    }

    out << "\"events\":[";
    for (size_t i = 0; i < group.members.size(); ++i) {
        if (i) out << ',';
        const auto& member = group.members[i];
        out << "{\"endpoint\":\"" << EscapeJson(member.first.endpoint) << "\","
            << "\"record_type\":\"" << EscapeJson(member.first.record_type) << "\","
            << "\"t_unix_ms\":" << member.first_seen_ms << ','
            << "\"first_seen\":" << member.first_seen_ms << ','
            << "\"last_seen\":" << member.last_seen_ms << ','
            << "\"repeat_count\":" << member.repeat_count << ','
            << "\"pid\":" << member.first.pid << ",\"parent_pid\":" << member.first.parent_pid << ',';
        RenderNullableString(out, "native_record_id", member.first.native_record_id); out << ',';
        RenderNullableString(out, "native_session_id", member.first.native_session_id); out << ',';
        RenderNullableString(out, "native_source_file", member.first.native_source_file); out << ',';
        out << "\"native_byte_offset\":";
        if (member.first.native_byte_offset < 0) out << "null"; else out << member.first.native_byte_offset;
        out << ',';
        RenderNullableString(out, "native_content_hash", member.first.native_content_hash); out << ',';
        RenderNullableString(out, "last_native_record_id", member.last.native_record_id); out << ',';
        out << "\"raw_source\":\"" << EscapeJson(member.first.raw_line) << "\"}";
    }
    out << "],\"connections\":[";
    for (size_t i = 0; i < group.connections.size(); ++i) {
        if (i) out << ',';
        const auto& connection = group.connections[i];
        out << "{\"from\":" << connection.from << ",\"to\":" << connection.to
            << ",\"reason\":\"" << EscapeJson(connection.edge.reason) << "\",\"matched_fields\":[";
        for (size_t f = 0; f < connection.edge.matched_fields.size(); ++f) {
            if (f) out << ',';
            out << '"' << EscapeJson(connection.edge.matched_fields[f]) << '"';
        }
        out << "],\"delta_ms\":" << connection.edge.delta_ms
            << ",\"window_ms\":" << kCorrelationWindowMs
            << ",\"confidence\":\"" << EscapeJson(connection.edge.confidence)
            << "\",\"confidence_score\":" << connection.edge.confidence_score;
        if (!connection.edge.caveat.empty())
            out << ",\"caveat\":\"" << EscapeJson(connection.edge.caveat) << '"';
        out << '}';
    }
    out << "]}";
    return out.str();
}

} // namespace correlator
