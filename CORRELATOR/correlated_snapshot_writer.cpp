// correlated_snapshot_writer.cpp
#include "correlated_snapshot_writer.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <set>
#include <sstream>

#include "evidence_envelope.h"
#include "json_fields.h"

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

void WriteStringArray(std::ostringstream& out, const char* key, const std::set<std::string>& values)
{
    out << '"' << key << "\":[";
    bool first = true;
    for (const auto& v : values) {
        if (!first) out << ',';
        first = false;
        out << '"' << EscapeJson(v) << '"';
    }
    out << ']';
}

// Best-effort, dependency-free extraction of the handful of descriptive
// fields real endpoints put under different names depending on schema
// version (FORU.TXT's own established pattern -- see
// UnifiedStreamEngine::SemanticFingerprint's identical field-list
// approach). A member missing a given field simply omits it below; nothing
// here is ever invented when the source record doesn't carry it.
struct ExtractedFields {
    std::string process_name;
    std::string user_name;
    std::string user_sid;
    std::string src_ip;
    std::string dst_ip;
    std::string protocol;
    std::string direction;
    std::string action;
    std::string path;
    std::string command_line;
    std::string expected_protocol;
    int64_t src_port = -1;
    int64_t dst_port = -1;
    // Tri-state: has_signature_valid=false means the source record carried
    // no such field at all (most endpoints besides Process), never
    // defaulted to true/false -- absence must stay visibly absent.
    bool has_signature_valid = false;
    bool signature_valid = false;
    // Same tri-state reasoning as has_signature_valid -- expected_protocol
    // (and therefore protocol_mismatch) is only present on Network events
    // whose port had a well-known-port hint at all; absence must stay
    // visibly absent rather than defaulting to false.
    bool has_protocol_mismatch = false;
    bool protocol_mismatch = false;
};

ExtractedFields ExtractFields(const std::string& raw_line)
{
    ExtractedFields f;
    std::string tmp;
    if (ExtractJsonString(raw_line, "process_name", tmp)) f.process_name = tmp;
    else if (ExtractJsonString(raw_line, "image", tmp)) f.process_name = tmp;
    else if (ExtractJsonString(raw_line, "exe", tmp)) f.process_name = tmp;
    else if (ExtractJsonString(raw_line, "application", tmp)) f.process_name = tmp;

    if (ExtractJsonString(raw_line, "user_name", tmp)) f.user_name = tmp;
    if (ExtractJsonString(raw_line, "user_sid", tmp)) f.user_sid = tmp;

    if (ExtractJsonString(raw_line, "dst_ip", tmp)) f.dst_ip = tmp;
    else if (ExtractJsonString(raw_line, "remote_ip", tmp)) f.dst_ip = tmp;
    else if (ExtractJsonString(raw_line, "packet_dst_ip", tmp)) f.dst_ip = tmp;

    if (ExtractJsonString(raw_line, "src_ip", tmp)) f.src_ip = tmp;
    else if (ExtractJsonString(raw_line, "local_ip", tmp)) f.src_ip = tmp;

    if (ExtractJsonString(raw_line, "protocol", tmp)) f.protocol = tmp;
    if (ExtractJsonString(raw_line, "expected_protocol", tmp)) f.expected_protocol = tmp;
    if (ExtractJsonString(raw_line, "direction", tmp)) f.direction = tmp;
    if (ExtractJsonString(raw_line, "action", tmp)) f.action = tmp;
    if (ExtractJsonString(raw_line, "path", tmp)) f.path = tmp;
    else if (ExtractJsonString(raw_line, "canonical_path", tmp)) f.path = tmp;
    if (ExtractJsonString(raw_line, "command_line", tmp)) f.command_line = tmp;
    else if (ExtractJsonString(raw_line, "command_line_raw", tmp)) f.command_line = tmp;

    int64_t num = 0;
    if (ExtractJsonNumber(raw_line, "dst_port", num)) f.dst_port = num;
    else if (ExtractJsonNumber(raw_line, "remote_port", num)) f.dst_port = num;
    if (ExtractJsonNumber(raw_line, "src_port", num)) f.src_port = num;
    else if (ExtractJsonNumber(raw_line, "local_port", num)) f.src_port = num;

    bool boolValue = false;
    if (ExtractJsonBool(raw_line, "signature_valid", boolValue)) {
        f.has_signature_valid = true;
        f.signature_valid = boolValue;
    }
    if (ExtractJsonBool(raw_line, "protocol_mismatch", boolValue)) {
        f.has_protocol_mismatch = true;
        f.protocol_mismatch = boolValue;
    }

    return f;
}

int64_t NowUnixMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

} // namespace

CorrelatedSnapshotWriter::CorrelatedSnapshotWriter(std::wstring log_dir)
    : log_dir_(std::move(log_dir))
{
    output_path_ = log_dir_ + L"\\correlated_events.json";
}

void CorrelatedSnapshotWriter::AddGroups(const std::vector<GroupSnapshot>& groups)
{
    if (groups.empty()) return;
    std::lock_guard<std::mutex> lock(mutex_);
    bool addedAny = false;
    for (const auto& group : groups) {
        // Mirrors Render()'s own "operational" classification (FORU.TXT
        // 12.1: collector_health/startup/control-ack records must never
        // enter behavioural correlation) -- a lone health heartbeat is not
        // an "incident", and must never be handed to ClassifyCorrType(),
        // which has no operational category and would otherwise mislabel
        // it as real behavioural activity (caught live: a Port collector_health
        // record was coming out as corr_type "usb_activity").
        if (group.operational_only) { ++operational_groups_excluded_; continue; }
        ++total_groups_all_time_;
        total_events_all_time_ += group.records_observed;
        for (const auto& member : group.members)
            if (!member.endpoint.empty()) known_endpoints_.insert(member.endpoint);
        UpdateEndpointGraph(group);
        UpdateEndpointCombinations(group);
        groups_.push_back(group);
        addedAny = true;
    }
    while (groups_.size() > kMaxHeldGroups) groups_.pop_front();
    if (addedAny) dirty_ = true;
}

void CorrelatedSnapshotWriter::UpdateEndpointGraph(const GroupSnapshot& group)
{
    // Caller (AddGroups) already holds mutex_.
    for (const auto& connection : group.connections) {
        if (connection.from >= group.members.size() || connection.to >= group.members.size()) continue;
        const std::string& a = group.members[connection.from].endpoint;
        const std::string& b = group.members[connection.to].endpoint;
        if (a.empty() || b.empty() || a == b) continue;

        const bool ordered = a <= b;
        const std::string& endpointA = ordered ? a : b;
        const std::string& endpointB = ordered ? b : a;
        auto& aggregate = edge_aggregates_[endpointA + "|" + endpointB];
        aggregate.endpoint_a = endpointA;
        aggregate.endpoint_b = endpointB;
        ++aggregate.connection_count;
        ++aggregate.reason_counts[connection.reason];
        aggregate.last_reason = connection.reason;
        if (connection.confidence_score >= aggregate.strongest_confidence_score) {
            aggregate.strongest_confidence_score = connection.confidence_score;
            aggregate.strongest_confidence = connection.confidence;
        }
    }
}

void CorrelatedSnapshotWriter::UpdateEndpointCombinations(const GroupSnapshot& group)
{
    // Caller (AddGroups) already holds mutex_.
    std::set<std::string> endpoints;
    for (const auto& member : group.members)
        if (!member.endpoint.empty()) endpoints.insert(member.endpoint);
    if (endpoints.empty()) return;

    std::string key;
    for (const auto& endpoint : endpoints) {
        if (!key.empty()) key += '|';
        key += endpoint;
    }

    auto& aggregate = endpoint_combinations_[key];
    if (aggregate.endpoints.empty())
        aggregate.endpoints.assign(endpoints.begin(), endpoints.end());
    ++aggregate.incident_count;
    if (aggregate.example_corr_ids.size() < kMaxExampleCorrIdsPerCombination)
        aggregate.example_corr_ids.push_back(CorrIdFor(group.id));
}

std::string CorrelatedSnapshotWriter::RenderEndpointCombinations() const
{
    // Caller (RenderDocument) already holds mutex_. Sorted by how many
    // endpoints are in the combination (descending) so the richest,
    // most-connected combinations -- exactly what "1 to 2,3,4" /
    // "3 to 1,4,3,5" was asking to see, not just simple pairs -- appear
    // first, then by how often that exact combination occurred.
    std::vector<const EndpointCombinationAggregate*> ordered;
    ordered.reserve(endpoint_combinations_.size());
    for (const auto& [key, aggregate] : endpoint_combinations_) {
        (void)key;
        ordered.push_back(&aggregate);
    }
    std::sort(ordered.begin(), ordered.end(), [](const auto* a, const auto* b) {
        if (a->endpoints.size() != b->endpoints.size()) return a->endpoints.size() > b->endpoints.size();
        return a->incident_count > b->incident_count;
    });

    std::ostringstream out;
    out << '[';
    bool first = true;
    for (const auto* aggregate : ordered) {
        if (!first) out << ',';
        first = false;
        out << "{\"endpoints\":[";
        bool firstEp = true;
        for (const auto& endpoint : aggregate->endpoints) {
            if (!firstEp) out << ',';
            firstEp = false;
            out << '"' << EscapeJson(endpoint) << '"';
        }
        out << "],\"endpoint_count\":" << aggregate->endpoints.size() << ','
            << "\"incident_count\":" << aggregate->incident_count << ','
            << "\"example_corr_ids\":[";
        for (size_t i = 0; i < aggregate->example_corr_ids.size(); ++i) {
            if (i) out << ',';
            out << '"' << EscapeJson(aggregate->example_corr_ids[i]) << '"';
        }
        out << "]}";
    }
    out << ']';
    return out.str();
}

std::string CorrelatedSnapshotWriter::RenderEndpointGraph() const
{
    // Caller (RenderDocument) already holds mutex_.
    std::ostringstream out;
    out << "{\"description\":\"Endpoint-to-endpoint connection graph -- nodes are the real sensor "
           "endpoints seen; edges are all-time cumulative connection counts between endpoint pairs, "
           "with the strongest join reason/confidence observed for each.\",\"nodes\":[";
    bool firstNode = true;
    for (const auto& endpoint : known_endpoints_) {
        if (!firstNode) out << ',';
        firstNode = false;
        out << '"' << EscapeJson(endpoint) << '"';
    }
    out << "],\"edges\":[";
    bool firstEdge = true;
    for (const auto& [key, aggregate] : edge_aggregates_) {
        (void)key;
        if (!firstEdge) out << ',';
        firstEdge = false;
        out << "{\"endpoint_a\":\"" << EscapeJson(aggregate.endpoint_a) << "\","
            << "\"endpoint_b\":\"" << EscapeJson(aggregate.endpoint_b) << "\","
            << "\"connection_count\":" << aggregate.connection_count << ','
            << "\"last_reason\":\"" << EscapeJson(aggregate.last_reason) << "\","
            << "\"strongest_confidence\":\"" << EscapeJson(aggregate.strongest_confidence) << "\","
            << "\"strongest_confidence_score\":" << aggregate.strongest_confidence_score << ','
            << "\"reasons\":{";
        bool firstReason = true;
        for (const auto& [reason, count] : aggregate.reason_counts) {
            if (!firstReason) out << ',';
            firstReason = false;
            out << '"' << EscapeJson(reason) << "\":" << count;
        }
        out << "}}";
    }
    out << "]}";
    return out.str();
}

size_t CorrelatedSnapshotWriter::GroupsInSnapshot() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return groups_.size();
}

std::string CorrelatedSnapshotWriter::GetLastError() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return last_error_;
}

std::string CorrelatedSnapshotWriter::FormatIso8601(int64_t unix_ms)
{
    if (unix_ms <= 0) return "";
    const std::time_t tt = static_cast<std::time_t>(unix_ms / 1000);
    std::tm tm{};
    gmtime_s(&tm, &tt);
    std::ostringstream out;
    out << (tm.tm_year + 1900) << '-'
        << std::setfill('0') << std::setw(2) << (tm.tm_mon + 1) << '-'
        << std::setw(2) << tm.tm_mday << 'T'
        << std::setw(2) << tm.tm_hour << ':'
        << std::setw(2) << tm.tm_min << ':'
        << std::setw(2) << tm.tm_sec << '.'
        << std::setw(3) << static_cast<int>(unix_ms % 1000) << 'Z';
    return out.str();
}

std::string CorrelatedSnapshotWriter::CorrIdFor(uint64_t group_id)
{
    const std::string hash = Fnv1a64Hex("group:" + std::to_string(group_id));
    std::string top8 = hash.substr(0, 8);
    for (auto& c : top8) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return "CG-" + top8;
}

std::string CorrelatedSnapshotWriter::ClassifyCorrType(const GroupSnapshot& group)
{
    std::set<std::string> endpoints;
    std::set<std::string> record_types;
    for (const auto& member : group.members) {
        endpoints.insert(member.endpoint);
        record_types.insert(member.record_type);
    }

    const bool onlyNetwork = endpoints.size() == 1 && endpoints.count("network") != 0;
    const bool onlyProcess = endpoints.size() == 1 && endpoints.count("process") != 0;
    const bool onlyApplication = endpoints.size() == 1 && endpoints.count("application") != 0;
    const bool onlyFile = endpoints.size() == 1 &&
        (endpoints.count("file_integrity") != 0 || endpoints.count("file") != 0);
    const bool onlyPort = endpoints.size() == 1 && endpoints.count("port") != 0;
    const bool hasProcess = endpoints.count("process") != 0;
    const bool hasNetwork = endpoints.count("network") != 0;

    if (onlyNetwork) return "network_flow";
    if (onlyProcess) return "process_session";
    if (onlyApplication)
        return record_types.count("script_execution") != 0 ? "script_session" : "application_activity";
    if (onlyFile) return "file_activity";
    if (onlyPort) return "usb_activity";
    if (hasProcess && hasNetwork) return "process_with_network";
    return "mixed_activity";
}

std::string CorrelatedSnapshotWriter::RenderEventObject(const MemberSnapshot& member)
{
    const ExtractedFields ef = ExtractFields(member.raw_line);
    std::ostringstream out;
    out << "{\"endpoint\":\"" << EscapeJson(member.endpoint) << "\","
        << "\"record_type\":\"" << EscapeJson(member.record_type) << "\","
        << "\"pid\":" << member.pid << ",\"parent_pid\":" << member.parent_pid << ','
        << "\"first_ts\":\"" << FormatIso8601(member.first_seen_ms) << "\","
        << "\"last_ts\":\"" << FormatIso8601(member.last_seen_ms) << "\","
        << "\"count\":" << member.repeat_count << ',';
    if (!ef.process_name.empty()) out << "\"process_name\":\"" << EscapeJson(ef.process_name) << "\",";
    if (!ef.user_name.empty())    out << "\"user_name\":\""    << EscapeJson(ef.user_name)    << "\",";
    if (!ef.user_sid.empty())     out << "\"user_sid\":\""     << EscapeJson(ef.user_sid)     << "\",";
    if (!ef.src_ip.empty())       out << "\"src_ip\":\""       << EscapeJson(ef.src_ip)       << "\",";
    if (!ef.dst_ip.empty())       out << "\"dst_ip\":\""       << EscapeJson(ef.dst_ip)       << "\",";
    if (ef.src_port >= 0)         out << "\"src_port\":" << ef.src_port << ',';
    if (ef.dst_port >= 0)         out << "\"dst_port\":" << ef.dst_port << ',';
    if (!ef.protocol.empty())     out << "\"protocol\":\""     << EscapeJson(ef.protocol)     << "\",";
    if (!ef.expected_protocol.empty())
        out << "\"expected_protocol\":\"" << EscapeJson(ef.expected_protocol) << "\",";
    if (!ef.direction.empty())    out << "\"direction\":\""    << EscapeJson(ef.direction)    << "\",";
    if (!ef.action.empty())       out << "\"action\":\""       << EscapeJson(ef.action)       << "\",";
    if (!ef.path.empty())         out << "\"path\":\""         << EscapeJson(ef.path)         << "\",";
    if (!ef.command_line.empty()) out << "\"command_line\":\"" << EscapeJson(ef.command_line) << "\",";
    if (ef.has_signature_valid)   out << "\"signature_valid\":" << (ef.signature_valid ? "true" : "false") << ',';
    if (ef.has_protocol_mismatch) out << "\"protocol_mismatch\":" << (ef.protocol_mismatch ? "true" : "false") << ',';
    if (!member.native_source_file.empty())
        out << "\"native_source_file\":\"" << EscapeJson(member.native_source_file) << "\",";
    if (!member.native_record_id.empty())
        out << "\"native_record_id\":\"" << EscapeJson(member.native_record_id) << "\",";
    out << "\"raw_source\":\"" << EscapeJson(member.raw_line) << "\"}";
    return out.str();
}

std::string CorrelatedSnapshotWriter::BuildSummary(const std::string& corr_type,
    const std::set<std::string>& processes, const std::set<std::string>& protocols,
    const std::set<std::string>& dest_ips, const std::set<std::string>& record_types)
{
    auto joinSet = [](const std::set<std::string>& values, size_t max_items) -> std::string {
        std::ostringstream out;
        size_t i = 0;
        for (const auto& value : values) {
            if (i >= max_items) { out << ", +" << (values.size() - max_items) << " more"; break; }
            if (i) out << ", ";
            out << value;
            ++i;
        }
        return out.str();
    };

    const std::string procList = processes.empty() ? "" : joinSet(processes, 4);
    const std::string protoList = protocols.empty() ? "" : joinSet(protocols, 3);
    const std::string ipList = dest_ips.empty() ? "" : joinSet(dest_ips, 3);

    std::ostringstream out;
    if (corr_type == "process_with_network") {
        out << (procList.empty() ? "a process" : procList) << " connected over network";
        if (!protoList.empty()) out << " (" << protoList << ")";
        if (!ipList.empty()) out << " to " << ipList;
    } else if (corr_type == "network_flow") {
        out << "network activity";
        if (!protoList.empty()) out << " (" << protoList << ")";
        if (!ipList.empty()) out << " to " << ipList;
    } else if (corr_type == "process_session") {
        out << (procList.empty() ? "a process" : procList) << " ran";
    } else if (corr_type == "script_session") {
        out << (procList.empty() ? "a script host" : procList) << " executed a script";
    } else if (corr_type == "file_activity") {
        out << (procList.empty() ? "a process" : procList) << " touched file(s)";
    } else if (corr_type == "application_activity") {
        out << (procList.empty() ? "an application" : procList) << " -- activity";
    } else if (corr_type == "usb_activity") {
        out << "USB / port device activity";
    } else {
        out << (procList.empty() ? "mixed activity" : procList + " -- mixed activity");
    }
    if (!record_types.empty()) out << " [" << joinSet(record_types, 4) << "]";
    return out.str();
}

std::string CorrelatedSnapshotWriter::BuildConfidenceSummary(const GroupSnapshot& group)
{
    if (group.connections.empty())
        return group.members.size() <= 1 ? "single event -- no join" : "anchor-only group (no scored joins)";

    size_t high = 0, medium = 0, low = 0;
    for (const auto& connection : group.connections) {
        if (connection.confidence == "high") ++high;
        else if (connection.confidence == "medium") ++medium;
        else ++low;
    }
    std::ostringstream out;
    out << group.connections.size() << " scored join(s): " << high << " high, "
        << medium << " medium, " << low << " low confidence";
    return out.str();
}

std::string CorrelatedSnapshotWriter::RenderDocument() const
{
    // Caller (WriteIfDue) already holds mutex_.
    uint64_t events_in_snapshot = 0;
    std::set<std::string> input_files;
    for (const auto& group : groups_) {
        events_in_snapshot += group.records_observed;
        for (const auto& member : group.members)
            if (!member.native_source_file.empty()) input_files.insert(member.native_source_file);
    }

    std::ostringstream out;
    out << "{\"meta\":{"
        << "\"generated_at\":\"" << FormatIso8601(NowUnixMs()) << "\","
        << "\"correlator_version\":\"unified-stream-v1\","
        // Santosh: "even though it writes both incident and the correlation
        // in the same file, the data should be properly and neatly
        // mentioned that which is which" -- this file combines two
        // genuinely different views of the same underlying evidence
        // (VISHNU.TXT: "make sure that u also adding the incident graph
        // data also into the correlator logs"). sections below is the
        // self-contained answer to "which top-level key is which", so a
        // reader never has to guess or go find external documentation.
        << "\"description\":\"Combined Correlator output: the endpoint-to-endpoint connection GRAPH (both pairwise edges and full N-way combinations), and the individual correlated event INCIDENTS, all live in this one file. See meta.sections for exactly which top-level key holds which.\","
        << "\"sections\":{"
            << "\"endpoint_graph\":\"PAIRWISE graph view -- for every PAIR of real sensor endpoints (process/network/application/file_integrity/port), how many times the Correlator has linked them (connection_count) and the strongest join reason/confidence. All-time cumulative, never reset. A single incident touching 3+ endpoints contributes to every pair within it, so this view alone cannot show which endpoints occurred TOGETHER as one incident -- see endpoint_combinations for that.\","
            << "\"endpoint_combinations\":\"N-WAY graph view -- every exact SET of endpoints that has occurred together in one real incident (2-way, 3-way, up to all 5), how many times that exact combination occurred, and example corr_ids. This is what shows a genuine 3+, 4+, or 5-endpoint incident as the single combined fact it is, not just as separate pairs.\","
            << "\"correlated_incidents\":\"INCIDENT view -- one entry per real correlated group: which events are connected, why (connections[]), a plain-English summary, and every underlying event (events[]).\""
        << "},"
        << "\"groups_in_snapshot\":" << groups_.size() << ','
        << "\"events_in_snapshot\":" << events_in_snapshot << ','
        << "\"total_groups_all_time\":" << total_groups_all_time_ << ','
        << "\"total_events_all_time\":" << total_events_all_time_ << ','
        << "\"operational_groups_excluded\":" << operational_groups_excluded_ << ',';
    WriteStringArray(out, "input_files", input_files);
    out << ",\"config\":{"
        << "\"correlation_window_ms\":" << UnifiedStreamEngine::kCorrelationWindowMs << ','
        << "\"repeat_window_ms\":" << UnifiedStreamEngine::kRepeatWindowMs << ','
        << "\"settle_delay_ms\":" << UnifiedStreamEngine::kSettleDelayMs << ','
        << "\"max_members_per_group\":" << UnifiedStreamEngine::kMaxMembersPerGroup << ','
        << "\"max_held_groups_in_snapshot\":" << kMaxHeldGroups
        << "}},";

    out << "\"endpoint_graph\":" << RenderEndpointGraph() << ',';
    out << "\"endpoint_combinations\":" << RenderEndpointCombinations() << ',';

    out << "\"correlated_incidents\":[";
    for (size_t gi = 0; gi < groups_.size(); ++gi) {
        if (gi) out << ',';
        const auto& group = groups_[gi];

        std::set<std::string> record_types, processes, users, dest_ips, protocols, source_files;
        std::set<uint32_t> pids;
        std::set<int64_t> dest_ports;
        for (const auto& member : group.members) {
            if (!member.record_type.empty()) record_types.insert(member.record_type);
            if (!member.native_source_file.empty()) source_files.insert(member.native_source_file);
            if (member.pid != 0) pids.insert(member.pid);
            const ExtractedFields ef = ExtractFields(member.raw_line);
            if (!ef.process_name.empty()) processes.insert(ef.process_name);
            if (!ef.user_name.empty()) users.insert(ef.user_name);
            if (!ef.dst_ip.empty()) dest_ips.insert(ef.dst_ip);
            if (!ef.protocol.empty()) protocols.insert(ef.protocol);
            if (ef.dst_port >= 0) dest_ports.insert(ef.dst_port);
        }
        const std::string corr_type = ClassifyCorrType(group);
        const double duration_seconds = group.members.empty() ? 0.0 :
            static_cast<double>(group.last_seen_ms - group.first_seen_ms) / 1000.0;

        out << "{\"corr_id\":\"" << CorrIdFor(group.id) << "\","
            << "\"corr_type\":\"" << corr_type << "\","
            << "\"summary\":\"" << EscapeJson(BuildSummary(corr_type, processes, protocols, dest_ips, record_types)) << "\","
            << "\"unique_events\":" << group.members.size() << ','
            << "\"total_occurrences\":" << group.records_observed << ','
            << "\"connected\":" << (group.connected ? "true" : "false") << ','
            << "\"confidence_summary\":\"" << EscapeJson(BuildConfidenceSummary(group)) << "\","
            << "\"start_ts\":\"" << FormatIso8601(group.first_seen_ms) << "\","
            << "\"end_ts\":\"" << FormatIso8601(group.last_seen_ms) << "\","
            << "\"duration_seconds\":" << duration_seconds << ',';
        WriteStringArray(out, "source_files", source_files); out << ',';
        WriteStringArray(out, "record_types", record_types); out << ',';
        WriteStringArray(out, "processes", processes); out << ',';
        WriteStringArray(out, "users", users); out << ',';
        out << "\"pids\":[";
        bool firstPid = true;
        for (const auto pid : pids) { if (!firstPid) out << ','; firstPid = false; out << pid; }
        out << "],";
        WriteStringArray(out, "dest_ips", dest_ips); out << ',';
        out << "\"dest_ports\":[";
        bool firstPort = true;
        for (const auto port : dest_ports) { if (!firstPort) out << ','; firstPort = false; out << port; }
        out << "],";
        WriteStringArray(out, "protocols", protocols); out << ',';

        out << "\"connections\":[";
        for (size_t ci = 0; ci < group.connections.size(); ++ci) {
            if (ci) out << ',';
            const auto& connection = group.connections[ci];
            out << "{\"from_event_index\":" << connection.from << ",\"to_event_index\":" << connection.to << ','
                << "\"reason\":\"" << EscapeJson(connection.reason) << "\","
                << "\"confidence\":\"" << EscapeJson(connection.confidence) << "\","
                << "\"confidence_score\":" << connection.confidence_score << ','
                << "\"delta_ms\":" << connection.delta_ms << ','
                << "\"matched_fields\":[";
            for (size_t f = 0; f < connection.matched_fields.size(); ++f) {
                if (f) out << ',';
                out << '"' << EscapeJson(connection.matched_fields[f]) << '"';
            }
            out << ']';
            if (!connection.caveat.empty()) out << ",\"caveat\":\"" << EscapeJson(connection.caveat) << '"';
            out << '}';
        }
        out << "],";

        out << "\"events\":[";
        for (size_t mi = 0; mi < group.members.size(); ++mi) {
            if (mi) out << ',';
            out << RenderEventObject(group.members[mi]);
        }
        out << "]}";
    }
    out << "]}";
    return out.str();
}

bool CorrelatedSnapshotWriter::WriteIfDue(bool force)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!dirty_ && !force) return true;

    std::error_code dir_ec;
    std::filesystem::create_directories(log_dir_, dir_ec);

    const std::wstring temp_path = output_path_ + L".tmp";
    std::ofstream out;
    out.open(temp_path, std::ios::out | std::ios::trunc);
    if (!out.is_open()) {
        last_error_ = "Failed to open temp file for correlated_events.json";
        return false;
    }
    out << RenderDocument();
    out.close();
    if (out.fail()) {
        last_error_ = "Write failed while rendering correlated_events.json";
        return false;
    }

    std::error_code rename_ec;
    std::filesystem::rename(temp_path, output_path_, rename_ec);
    if (rename_ec) {
        last_error_ = "Atomic rename failed: " + rename_ec.message();
        return false;
    }
    dirty_ = false;
    return true;
}

} // namespace correlator
