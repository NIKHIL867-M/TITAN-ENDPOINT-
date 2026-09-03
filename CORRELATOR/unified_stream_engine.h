#pragma once

#include "correlation_engine.h"

#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>

namespace correlator {

// A bounded, loss-visible unifier for the five endpoint streams. Unlike the
// legacy session-only engine, every valid source record reaches one output:
// either a connected multi-source event or an honest single-source event.
// One member of a drained group, exported by value (not the private Member
// struct itself) so a consumer outside this engine -- the grouped
// correlated_events.json snapshot writer -- can build an aggregated report
// straight from real structured fields instead of re-parsing Render()'s
// rendered JSON string. raw_line is the ORIGINAL source endpoint's JSONL
// object, unmodified, so a consumer can pull whatever fields it needs via
// json_fields.h's ExtractJsonString/ExtractJsonNumber the same way this
// engine's own SemanticFingerprint() already does -- never a re-guessed
// field name.
struct MemberSnapshot {
    std::string endpoint;
    std::string record_type;
    int64_t     first_seen_ms = 0;
    int64_t     last_seen_ms = 0;
    uint64_t    repeat_count = 1;
    uint32_t    pid = 0;
    uint32_t    parent_pid = 0;
    std::string native_source_file;
    std::string native_record_id;
    std::string raw_line;
};

// One join edge between two members of a drained group -- the engine's own
// account of WHY they were considered connected (EdgeInfo, see
// correlation_engine.h), exported by value alongside GroupSnapshot so a
// consumer can show the actual join evidence (reason/confidence/matched
// fields), not just the resulting member list.
struct ConnectionSnapshot {
    size_t from = 0;   // index into GroupSnapshot::members
    size_t to = 0;
    std::string reason;
    std::vector<std::string> matched_fields;
    int64_t delta_ms = 0;
    std::string confidence;
    double confidence_score = 0.0;
    std::string caveat;
};

// One drained group, exported by value. Mirrors exactly what Render()
// serializes for the live per-event JSONL log, plus nothing more -- no
// snapshot-only field is ever fabricated beyond what the engine itself
// already tracked.
struct GroupSnapshot {
    uint64_t id = 0;
    int64_t  first_seen_ms = 0;
    int64_t  last_seen_ms = 0;
    uint64_t records_observed = 0;
    bool     operational_only = false;
    bool     connected = false;
    std::vector<MemberSnapshot> members;
    std::vector<ConnectionSnapshot> connections;
};

class UnifiedStreamEngine {
public:
    static constexpr int64_t kCorrelationWindowMs = 2000;
    static constexpr int64_t kRepeatWindowMs = 5000;
    static constexpr int64_t kSettleDelayMs = 3000;
    static constexpr int64_t kMaxPendingLifetimeMs = 30000;
    static constexpr size_t kMaxPendingGroups = 512;
    static constexpr size_t kMaxMembersPerGroup = 16;
    static constexpr size_t kMaxDedupIdentities = 8192;

    // Returns true when the line was accepted. Exact replays are suppressed;
    // semantically repeated activity is represented by repeat_count.
    bool Ingest(const std::string& endpoint, const std::string& rawLine,
        int64_t observedAtUnixMs = 0);

    // Emits settled records. force=true is used only during clean shutdown so
    // no accepted record remains stranded in memory. When readyGroupsOut is
    // non-null, every group drained this call (via the normal settle path,
    // the lifetime cap, or either capacity-flush path) is ALSO appended there
    // as a GroupSnapshot -- same set of groups as the returned strings, just
    // structured instead of pre-rendered. Existing callers that omit this
    // parameter are unaffected.
    std::vector<std::string> DrainReady(int64_t nowUnixMs = 0, bool force = false,
        std::vector<GroupSnapshot>* readyGroupsOut = nullptr);

    size_t PendingGroupCount() const noexcept { return groups_.size(); }
    size_t PendingMemberCount() const noexcept;
    uint64_t RecordsAccepted() const noexcept { return records_accepted_; }
    uint64_t RecordsRepresented() const noexcept { return records_represented_; }
    uint64_t UnifiedEventsEmitted() const noexcept { return events_emitted_; }
    uint64_t ConnectedEventsEmitted() const noexcept { return connected_emitted_; }
    uint64_t SingleSourceEventsEmitted() const noexcept { return single_source_emitted_; }
    uint64_t ExactDuplicatesSuppressed() const noexcept { return exact_duplicates_suppressed_; }
    uint64_t SemanticRepeatsCompacted() const noexcept { return semantic_repeats_compacted_; }
    uint64_t ParseFailures() const noexcept { return parse_failures_; }
    uint64_t CapacityFlushes() const noexcept { return capacity_flushes_; }
    uint64_t ConnectionLimitCount() const noexcept { return connection_limit_count_; }

private:
    struct Member {
        EvidenceRecord first;
        EvidenceRecord last;
        std::string fingerprint;
        uint64_t repeat_count = 1;
        int64_t first_seen_ms = 0;
        int64_t last_seen_ms = 0;
        EdgeInfo incoming_edge;
    };

    struct Connection {
        size_t from = 0;
        size_t to = 0;
        EdgeInfo edge;
    };

    struct Group {
        uint64_t id = 0;
        std::vector<Member> members;
        std::vector<Connection> connections;
        uint64_t records_observed = 0;
        int64_t first_seen_ms = 0;
        int64_t last_seen_ms = 0;
        int64_t created_wall_ms = 0;
        int64_t last_activity_wall_ms = 0;
        bool operational_only = false;
    };

    struct Candidate {
        uint64_t group_id = 0;
        size_t member_index = 0;
        EdgeInfo edge;
    };

    static int64_t NowUnixMs();
    static std::string ExactIdentity(const EvidenceRecord& record);
    static std::string SemanticFingerprint(const EvidenceRecord& record, bool operational);
    static std::string Render(const Group& group);
    static GroupSnapshot ToSnapshot(const Group& group);
    static bool IsUsableConnection(const EvidenceRecord& a, const EvidenceRecord& b,
        const EdgeInfo& edge);
    void RememberIdentity(std::string identity);
    void FlushOldestForCapacity();

    std::map<uint64_t, Group> groups_;
    std::vector<std::string> forced_ready_;
    // Parallel to forced_ready_ (same two producers: the kMaxMembersPerGroup
    // force-flush branch in Ingest() and FlushOldestForCapacity()) -- carries
    // the structured Group so DrainReady's readyGroupsOut param can report
    // these forced flushes too, not only the ones drained via the normal
    // settle/lifetime-cap loop.
    std::vector<Group> forced_ready_groups_;
    std::unordered_set<std::string> recent_identities_;
    std::deque<std::string> identity_order_;
    uint64_t next_group_id_ = 1;

    uint64_t records_accepted_ = 0;
    uint64_t records_represented_ = 0;
    uint64_t events_emitted_ = 0;
    uint64_t connected_emitted_ = 0;
    uint64_t single_source_emitted_ = 0;
    uint64_t exact_duplicates_suppressed_ = 0;
    uint64_t semantic_repeats_compacted_ = 0;
    uint64_t parse_failures_ = 0;
    uint64_t capacity_flushes_ = 0;
    uint64_t connection_limit_count_ = 0;
};

} // namespace correlator
