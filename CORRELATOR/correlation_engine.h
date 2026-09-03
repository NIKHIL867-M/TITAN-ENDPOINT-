// correlation_engine.h
//
// Implements TITAN_CORRELATION_DESIGN.md Section 3, rewritten per FORU.TXT
// section 12 ("FIX CORRELATION CORRECTNESS BEFORE EXTENDING ITS VISUALS").
// Joins evidence records from the 5 independent endpoints on t_unix_ms
// (bucketed) + pid/parent_pid lineage -- OR, for Port (which carries no OS
// pid), a defensible non-temporal bridge (USB session mount path prefix
// match against a candidate record's own path) -- into a bounded evidence
// GRAPH rather than isolated 2-record pairs. One record can have several
// justified edges, and a group can grow multi-hop as new correlating
// records arrive, all bounded by explicit size/count caps below so this
// remains a fixed-RAM structure regardless of ingest rate.
//
// This engine never modifies or replaces any source endpoint's own log --
// it only reads already-written JSONL lines (via LogTailer) and emits new,
// additive session_timeline evidence.
#pragma once

#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

namespace correlator {

struct EvidenceRecord {
    std::string endpoint;    // "port", "process", "file_integrity", "network", "application"

    // record_type is the NORMALIZED behavioural kind, extracted from the
    // correct field per endpoint schema (FORU.TXT 12.2) -- never the same
    // blind "type" lookup for every endpoint, which is blank for real
    // Process (uses event_subtype) and Network (uses record_type) events.
    std::string record_type;
    std::string path;        // generic bridging path, when this endpoint's schema carries one
    std::string mount_point; // Port USB_SESSION_END only
    int64_t     duration_seconds = 0;   // Port USB_SESSION_END only -- whole seconds is enough for bridging

    int64_t     t_unix_ms = 0;
    uint32_t    pid = 0;
    uint32_t    parent_pid = 0;
    std::string raw_line;    // bounded-length copy, embedded in joined output so a member always resolves to its source record

    // FORU.TXT section 8/15: the NATIVE writer's own durable identity, when
    // the source endpoint has been upgraded to stamp it (evidence_envelope.h
    // -- record_id/session_id/source_file/byte_offset). Empty/-1 for a
    // producer that hasn't been upgraded yet -- never fabricated, and never
    // required for correlation to still work (falls back to the engine-local
    // id below), only for exact original-line navigation once present.
    std::string native_record_id;   // decimal string form of the native uint64 record_id, empty if absent
    std::string native_session_id;
    std::string native_source_file;
    int64_t     native_byte_offset = -1;   // -1 = not present on this record
    std::string native_content_hash;       // Fnv1a64Hex of the pre-envelope body, empty if absent

    uint64_t id = 0;                          // engine-wide monotonic identity -- forms source_evidence_id with endpoint
    uint32_t group_id = 0;                    // 0 = not yet part of any group
    std::vector<uint64_t> joined_partner_ids;  // bounded to kMaxJoinsPerRecord -- prevents re-joining the exact same partner every cycle
};

// Parses the fields the engine needs out of one JSONL line, including the
// endpoint-correct normalized record_type and bridging path. Returns a
// record with t_unix_ms == 0 if the line has no usable timestamp (still
// ingested for completeness, but can never participate in a time-bucketed
// join).
EvidenceRecord ParseEvidenceLine(const std::string& endpoint, const std::string& raw_line);

// True if this raw line is an operational status record (collector_health,
// startup, control-ack) that must never enter behavioural correlation
// (FORU.TXT 12.1) -- health belongs only in System Health.
bool IsOperationalStatusLine(const std::string& raw_line);

// One evaluated join candidate between two records -- the engine's own
// authoritative account of WHY (or whether) they correlate, replacing any
// GUI-side guess (FORU.TXT 12.4, 12.9).
struct EdgeInfo {
    bool matched = false;
    std::string reason;                    // e.g. "same_pid", "parent_child_pid", "sibling_pid", "usb_mount_path_match", "port_temporal_proximity_only"
    std::vector<std::string> matched_fields; // e.g. {"pid"}, {"mount_point","path"}
    int64_t delta_ms = 0;
    std::string confidence;                // "high" | "medium" | "low" -- kept for human readability/back-compat
    // FORU.TXT section 15: "typed, confidence-scored edges" -- a numeric
    // 0.0-1.0 score alongside the categorical label above, computed by
    // ScoreConfidence() from a documented, deterministic formula (base score
    // per match reason, decayed by how much of the join window the time
    // delta actually used) rather than a fixed constant per category, so it's
    // a genuine function of the measured evidence, not just a re-labeled
    // enum. See ScoreConfidence()'s own comment for the exact formula.
    double confidence_score = 0.0;
    std::string caveat;                    // non-empty only when the join is NOT a proven causal chain
};

// Computes EdgeInfo::confidence_score for a matched edge. windowMs is the
// window the match was evaluated against (kJoinWindowMs for lineage edges,
// kUsbSessionSlackMs-based for Port bridge edges) -- 0 delta scores the base
// weight for `reason`; a delta at the edge of the window scores 70% of it.
// Exposed (not file-local) so it's independently unit-testable.
double ScoreConfidence(const std::string& reason, int64_t deltaMs, int64_t windowMs);

// Pure predicate: do two records belong to the same real-world activity via
// pid/parent_pid lineage, within windowMs of each other? No OS/file access
// here, so this is directly unit-testable. Does NOT cover Port -- see
// EvaluatePortBridgeEdge for that.
EdgeInfo EvaluateLineageEdge(const EvidenceRecord& a, const EvidenceRecord& b, int64_t windowMs);

// Port carries no OS pid, so lineage is never available. FORU.TXT 12.5:
// do not join Port to arbitrary activity only because it happened nearby
// in time -- require a defensible bridge (here: the candidate record's own
// path falling under the USB session's mount point). Only a
// "usb_monitor"/"USB_SESSION_END" record (the one record type that carries
// mount_point + duration_seconds) can ever produce a match; USB_HID_*
// telemetry has no bridge-relevant field at all and is intentionally never
// joined to unrelated Process/File/Application activity. When no path
// bridge is found but the two records are genuinely time-proximate within
// the session's own [start,end] window, the edge is still returned but
// explicitly labeled low-confidence with a caveat -- never presented as a
// proven chain.
EdgeInfo EvaluatePortBridgeEdge(const EvidenceRecord& port_rec, const EvidenceRecord& other_rec);

// Dispatches to EvaluateLineageEdge or EvaluatePortBridgeEdge depending on
// whether either side is a "port" record.
EdgeInfo EvaluateEdge(const EvidenceRecord& a, const EvidenceRecord& b, int64_t windowMs);

// A member of an evolving session_timeline group, snapshotted BY VALUE at
// join time -- never a pointer/reference into by_endpoint_'s rings, which
// reallocate and evict members as records age out. Carries the engine's own
// edge metadata (FORU.TXT 12.4) and a resolvable source_evidence_id +
// embedded raw source line (FORU.TXT 12.3, 12.10) so a GUI can always open
// the exact original record without depending on the source log still
// being present.
struct GroupMember {
    std::string endpoint;
    std::string record_type;
    int64_t     t_unix_ms = 0;
    uint32_t    pid = 0;
    uint32_t    parent_pid = 0;
    std::string source_evidence_id;   // "<endpoint>:<engine-wide id>" -- stable for this process's lifetime
    std::string raw_line;             // bounded copy of the original JSONL line this member came from

    // FORU.TXT section 8/15: exact, durable reference to the native writer's
    // own record, when available (see EvidenceRecord above) -- lets a
    // consumer open the UNTRUNCATED original line directly by
    // (native_session_id, native_byte_offset) in native_source_file even if
    // raw_line above was truncated for display/RAM reasons. Empty/-1 when
    // the source endpoint hasn't been upgraded to stamp it yet.
    std::string native_record_id;
    std::string native_session_id;
    std::string native_source_file;
    int64_t     native_byte_offset = -1;
    std::string native_content_hash;

    // Edge metadata describing WHY this member joined the group (empty/zero
    // for the group's anchor member, which has no incoming edge).
    std::string join_reason;
    std::vector<std::string> matched_fields;
    int64_t delta_ms = 0;
    std::string confidence;
    double confidence_score = 0.0;   // see EdgeInfo::confidence_score
    int64_t window_ms = 0;
    std::string caveat;
};

// ─────────────────────────────────────────────────────────────────────────────
// CorrelationEngine
//
// Owns one bounded ring (by count AND by age) per source endpoint, plus a
// bounded set of evidence GROUPS (multi-member chains). Ingest() parses and
// stores a line (dropping operational status lines entirely -- FORU.TXT
// 12.1/12.7); TryCorrelate() scans for cross-endpoint matches, extends
// existing groups or starts new ones, and returns freshly-updated
// session_timeline JSON lines for every group that changed this cycle.
// Each group carries a stable group_id plus a monotonically increasing
// revision (FORU.TXT 12.6) -- a consumer must count DISTINCT group_id
// values as "groups", not every revision line, and a "final":true revision
// is emitted once when a group expires so consumers know its story is over.
// ─────────────────────────────────────────────────────────────────────────────
class CorrelationEngine {
public:
    // kMaxPerEndpoint bounds RAM regardless of ingest rate (independent of
    // kMaxAgeMs below -- whichever bound is hit first evicts). kMaxAgeMs
    // serves two roles, both driven by the same "how long can a real-world
    // activity go quiet before we stop treating it as ongoing" question:
    //   1. PruneStale(): how long an ingested record stays eligible to be a
    //      NEW join partner before it's evicted from by_endpoint_.
    //   2. PruneStaleGroups(): how long a group can go without a NEW member
    //      joining before it's force-closed ("final":true).
    // FORU.TXT section 15: "long-running activity is not separated by the
    // short in-memory window" -- the original 60-second value meant any real
    // session with a >60s gap between related events (e.g. a browser tab
    // idle for two minutes, then resuming network activity) got split into
    // two unrelated-looking groups instead of one continuous chain. Widened
    // to 30 minutes: still fully bounded (RAM is independently capped by
    // kMaxPerEndpoint/kMaxActiveGroups regardless of this value, so widening
    // it costs nothing but staleness latency), and a defensible upper bound
    // for "still plausibly the same real-world session."
    static constexpr size_t kMaxPerEndpoint = 2000;
    static constexpr int64_t kMaxAgeMs = 30 * 60 * 1000;   // 30 minutes (was 60s)
    static constexpr int64_t kJoinWindowMs = 2000;    // +/-2s bucket
    static constexpr size_t kMaxJoinsPerCycle = 100;  // defensive cap

    // Bounds on the evidence GRAPH itself:
    static constexpr size_t kMaxJoinsPerRecord = 4;   // one record can justify at most this many edges
    static constexpr size_t kMaxGroupSize = 8;        // one session_timeline chain caps at this many members
    static constexpr size_t kMaxActiveGroups = 500;   // total concurrent groups; new-group creation declines beyond this

    // Port USB_SESSION_END bridging: how much slack either side of the
    // session's own [start,end] window before a candidate record is
    // considered "during this session" at all (covers filesystem write
    // buffering flushed right around unmount, and clock/logging jitter).
    static constexpr int64_t kUsbSessionSlackMs = 5000;

    // The two-pointer scan in TryCorrelate() prefilters candidate pairs to
    // within a window before ever calling EvaluateEdge, purely to keep the
    // scan cheap. For any pair involving Port, that prefilter must be wide
    // enough to admit a candidate anywhere inside a real USB session's
    // [start,end] span (EvaluatePortBridgeEdge itself does the precise
    // window check) -- kJoinWindowMs's 2s would silently exclude a file
    // written 30s into a session before the bridge logic ever saw it.
    static constexpr int64_t kPortPrefilterWindowMs = 6 * 60 * 60 * 1000;   // 6 hours -- generous, realistic USB session upper bound

    void Ingest(const std::string& endpoint, const std::string& raw_line);

    // Scans all endpoint pairs for new/extended correlations, emits an
    // updated session_timeline JSON line for every group that changed this
    // cycle (plus one final "closed" revision per group that expires this
    // cycle), and records each successfully-matched pair so it isn't
    // re-evaluated forever.
    std::vector<std::string> TryCorrelate();

    size_t TotalRecords() const;
    size_t TotalGroups() const { return groups_.size(); }

    // Evidence-gap counters (FORU.TXT 12.8) -- declined joins, evictions and
    // backlog reported honestly rather than silently dropped.
    uint64_t DeclinedGroupSizeCount() const { return declined_group_size_; }
    uint64_t DeclinedActiveGroupsCount() const { return declined_active_groups_; }
    uint64_t DeclinedCrossMergeCount() const { return declined_cross_merge_; }
    uint64_t EvictedByAgeCount() const { return evicted_by_age_; }
    uint64_t EvictedByCapacityCount() const { return evicted_by_capacity_; }
    uint64_t ExpiredGroupCount() const { return expired_group_count_; }

private:
    void PruneStale(int64_t now_ms);
    // Emits a final "closed" revision for every group that expires this
    // cycle (appended to 'out') before erasing its state.
    void PruneStaleGroups(int64_t now_ms, std::vector<std::string>& out);
    // Returns the group id to use for this new edge (a<->b), creating,
    // extending, or declining (0, e.g. at a bound) per the rules above. On
    // a nonzero return, the new member(s) have already been appended to
    // groups_[gid] and group_last_updated_ms_ has been refreshed.
    uint32_t AssignOrExtendGroup(EvidenceRecord& a, EvidenceRecord& b, const EdgeInfo& edge, int64_t now_ms);
    std::string RenderGroupJson(uint32_t group_id, bool final_revision) const;

    std::unordered_map<std::string, std::deque<EvidenceRecord>> by_endpoint_;
    std::unordered_map<uint32_t, std::vector<GroupMember>> groups_;
    std::unordered_map<uint32_t, int64_t> group_last_updated_ms_;
    std::unordered_map<uint32_t, uint32_t> group_revision_;
    uint64_t next_record_id_ = 1;
    uint32_t next_group_id_ = 1;

    uint64_t declined_group_size_ = 0;
    uint64_t declined_active_groups_ = 0;
    uint64_t declined_cross_merge_ = 0;
    uint64_t evicted_by_age_ = 0;
    uint64_t evicted_by_capacity_ = 0;
    uint64_t expired_group_count_ = 0;
};

} // namespace correlator
