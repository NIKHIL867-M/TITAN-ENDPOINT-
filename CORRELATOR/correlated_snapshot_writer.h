// correlated_snapshot_writer.h
//
// VISHNU.TXT task 1: "in correlation u have to give the logs as proper group
// of events -- which and all are connected -- ... in [OLDEST LOGS\]
// correlated_events new.json the proper format is there -- that format I
// wanted u to write the logs of the correlator."
//
// The Correlator already writes a live, per-group JSONL log
// (correlator_*.jsonl via CorrelatorLogger) -- one line per group revision,
// wrapped with an evidence envelope. That format is correct for tailing/
// live GUI display but is not the human-reviewable "one document, grouped,
// with aggregated processes/users/pids/dest_ips/protocols arrays plus a
// nested events[] array" shape the prior offline analysis format used.
//
// CorrelatedSnapshotWriter builds exactly that second shape, purely
// additively: it never reads or modifies correlator_*.jsonl, and every
// field it emits is either read verbatim from a real GroupSnapshot/
// MemberSnapshot (see unified_stream_engine.h) or extracted from a member's
// own real raw_line via json_fields.h -- nothing here is fabricated or
// guessed. Output is a single bounded JSON document, rewritten atomically
// (temp file + rename) on the same cadence the Correlator already emits
// collector_health, plus once more, forced, at clean shutdown.
#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "unified_stream_engine.h"

namespace correlator {

// Cumulative, all-time tally for one unordered pair of endpoints (e.g.
// "process"+"network") -- the native, correlator-side equivalent of the
// GUI's Correlation Graph "pentagon" edges, computed from the SAME
// connections the engine itself found (never re-derived/guessed), so the
// two can never disagree. Only ever grows in COUNT (a connection_count
// increment), never in number of distinct pairs beyond the small fixed set
// of real endpoints (at most 10 pairs for 5 endpoints) -- no eviction
// needed.
struct EndpointEdgeAggregate {
    std::string endpoint_a;
    std::string endpoint_b;
    uint64_t connection_count = 0;
    std::map<std::string, uint64_t> reason_counts;
    std::string last_reason;
    std::string strongest_confidence;
    double strongest_confidence_score = 0.0;
};

// Cumulative, all-time tally for one exact SET of endpoints seen together
// in a single real incident -- e.g. {application, file_integrity, process}
// all three, not just each pair of them separately. EndpointEdgeAggregate
// above answers "how often are A and B linked" (loses the fact that a
// single real incident may have involved C and D too); this answers
// "which exact combinations of endpoints actually occur together, and how
// often" -- 2-way, 3-way, up to all 5, plus the (informational) 1-way case
// of an endpoint that only ever shows up alone. Never evicted -- bounded by
// construction, since there are at most 2^5-1=31 possible non-empty subsets
// of 5 real endpoints.
struct EndpointCombinationAggregate {
    std::vector<std::string> endpoints;   // sorted, stable ordering
    uint64_t incident_count = 0;
    std::vector<std::string> example_corr_ids;   // bounded, most recent first
};

class CorrelatedSnapshotWriter {
public:
    // log_dir: same directory CorrelatorLogger writes correlator_*.jsonl
    // into (".\\logs\\" from main.cpp) -- the new file sits alongside it as
    // "correlated_events.json".
    explicit CorrelatedSnapshotWriter(std::wstring log_dir);

    // Folds newly-drained groups into the bounded accumulator (oldest
    // evicted first once kMaxHeldGroups is exceeded -- same fixed-RAM
    // philosophy as every other bound in this program). Pure in-memory
    // bookkeeping; does no file I/O by itself.
    void AddGroups(const std::vector<GroupSnapshot>& groups);

    // Rewrites the consolidated JSON document to disk if at least one group
    // was added since the last successful write, or if force is true.
    // Returns true on a successful write (or a no-op skip because nothing
    // was dirty), false only on an actual I/O failure.
    bool WriteIfDue(bool force = false);

    size_t GroupsInSnapshot() const;
    uint64_t TotalGroupsAllTime() const { return total_groups_all_time_; }
    uint64_t TotalEventsAllTime() const { return total_events_all_time_; }
    uint64_t OperationalGroupsExcluded() const { return operational_groups_excluded_; }
    std::string GetLastError() const;

private:
    std::string RenderDocument() const;   // caller must hold mutex_
    static std::string ClassifyCorrType(const GroupSnapshot& group);
    static std::string FormatIso8601(int64_t unix_ms);
    static std::string CorrIdFor(uint64_t group_id);
    static std::string RenderEventObject(const MemberSnapshot& member);
    // Plain-English one-liner ("clean and clear" read-at-a-glance summary)
    // built only from the group's own real aggregated fields -- never a
    // fabricated narrative, just those fields joined into a sentence.
    static std::string BuildSummary(const std::string& corr_type,
        const std::set<std::string>& processes, const std::set<std::string>& protocols,
        const std::set<std::string>& dest_ips, const std::set<std::string>& record_types);
    // Mirrors the GUI's own established confidence-rollup phrasing
    // (CorrelationRowViewModel's "N scored join(s): X high, Y medium, Z low
    // confidence") so the same wording means the same thing everywhere in
    // this app.
    static std::string BuildConfidenceSummary(const GroupSnapshot& group);
    // VISHNU.TXT: "make sure that u also adding the incident graph data
    // also into the correlator logs" -- folds one group's real connections
    // into the running per-endpoint-pair tallies. Caller (AddGroups) already
    // holds mutex_.
    void UpdateEndpointGraph(const GroupSnapshot& group);
    std::string RenderEndpointGraph() const;   // caller must hold mutex_
    // Santosh: "how come u only seen from 1 endpoint the other endpoint...
    // it has to properly [show] which are really connected and combined" --
    // the pairwise edges above cannot show a real 3-, 4-, or 5-way incident
    // as a single fact; this can. Caller (AddGroups) already holds mutex_.
    void UpdateEndpointCombinations(const GroupSnapshot& group);
    std::string RenderEndpointCombinations() const;   // caller must hold mutex_

    std::wstring log_dir_;
    std::wstring output_path_;
    mutable std::mutex mutex_;
    std::deque<GroupSnapshot> groups_;   // bounded, oldest evicted first
    bool dirty_ = false;
    uint64_t total_groups_all_time_ = 0;
    uint64_t total_events_all_time_ = 0;
    // Santosh: "are we really utilizing all the logs info that we are
    // getting or not... make sure that nothing is lost." Every group the
    // engine ever hands to AddGroups() is accounted for one of two ways:
    // folded into total_groups_all_time_ (real behavioural evidence), or
    // counted here (a collector_health/startup/control-ack heartbeat,
    // correctly excluded from the INCIDENT/GRAPH views because it isn't
    // behavioural evidence -- see FORU.TXT 12.1 -- but never silently
    // dropped: this counter, exposed in meta, is the proof).
    uint64_t operational_groups_excluded_ = 0;
    std::string last_error_;

    // All-time endpoint-flow graph (never evicted -- see EndpointEdgeAggregate
    // doc comment). known_endpoints_ tracks every endpoint seen as a member
    // of any non-operational group, even ones with no edge yet, so the
    // "nodes" list is never narrower than the real sensor set actually seen.
    std::set<std::string> known_endpoints_;
    std::map<std::string, EndpointEdgeAggregate> edge_aggregates_;   // key: "endpointA|endpointB", sorted
    std::map<std::string, EndpointCombinationAggregate> endpoint_combinations_;   // key: sorted endpoints joined by '|'

    // Bounded RAM regardless of run length -- the per-line correlator_*.jsonl
    // log remains the complete, unbounded-by-design history; this rollup is
    // a bounded, always-current supplementary view, not the sole record.
    static constexpr size_t kMaxHeldGroups = 2000;
    static constexpr size_t kMaxExampleCorrIdsPerCombination = 5;
};

} // namespace correlator
