#ifndef TITAN_PROCESS_MONITOR_H
#define TITAN_PROCESS_MONITOR_H

// ============================================================================
// process_monitor.h  —  TITAN V3  Enriched Sensor
//
// Responsibilities:
//   1. Open an ETW real-time session on the Kernel-Process provider.
//   2. For every process-start event, resolve the TRUE binary path via
//      QueryFullProcessImageNameW (kernel path, not ETW-reported string).
//   3. Resolve the PARENT's canonical path via the same API so the filter
//      can evaluate parent-child relationships (Rule 10, bloom filter).
//   4. Populate fork/thread summary fields in V3ProcessInfo:
//        child_count, unique_child_names, thread_count,
//        duplicate_instances, new_child_flag
//   5. Pass the enriched Event to FilterEngine::Process().
//   6. If decision == FORWARD  → logger_.LogEvent()
//      If decision == COMPRESS → counter only (ticker handles the summary)
//
// V3 changes vs V2:
//   REMOVED: FilterAction::Drop path, events_dropped_ counter, Evaluate()
//   ADDED:   EnrichV3Fields(), parent path resolution, fork/thread tracking,
//            GetEventsForwarded(), GetEventsCompressed()
// ============================================================================

#include "event.h"
#include "evidence_envelope.h"
#include "filter.h"
#include "logger.h"
#include "resource_pressure.h"

#include <atomic>
#include <evntcons.h>
#include <evntrace.h>
#include <mutex>
#include <string>
#include <thread>
#include <set>
#include <unordered_map>
#include <windows.h>

namespace titan {

    class ProcessMonitor;

    // ETW callback context
    struct EtwSessionContext {
        ProcessMonitor* monitor;
        TRACEHANDLE session_handle;
        std::wstring session_name;
    };

    // Per-PID fork/thread accumulator — updated on every child-spawn /
    // thread-create event. Cleared when the parent process terminates.
    //
    // FIX: unique_child_names was unbounded, contradicting the agent's own
    // "fixed ~1.3MB RAM" claim -- a long-lived parent (svchost, explorer,
    // System) that spawns many distinct children over the agent's uptime
    // would grow this set without limit. Capped at kMaxUniqueChildNames with
    // an overflow counter (same pattern as the other endpoints' bounded
    // detail-path caps) so accounting stays honest instead of silently
    // truncating.
    struct ProcessAccumulator {
        static constexpr size_t kMaxUniqueChildNames = 256;

        uint32_t child_count{ 0 };
        std::set<std::wstring> unique_child_names;   // capped at kMaxUniqueChildNames
        uint32_t unique_child_names_overflow{ 0 };    // count dropped once cap hit
        uint32_t thread_count{ 0 };
        uint32_t duplicate_instances{ 0 };
        bool new_child_flag{ false };

        // FIX: Cache the last known image path so HandleProcessStop can emit a
        // useful process_name even after the process has already exited and
        // ResolveImagePath(pid) returns empty.
        std::wstring last_image_path;
        std::wstring last_parent_image_path;
        DWORD        last_parent_pid{ 0 };

        // Records a child name, honoring kMaxUniqueChildNames. An
        // already-seen name is always re-counted for free (no overflow
        // charge); a genuinely new name beyond the cap increments
        // unique_child_names_overflow instead of growing the set further.
        void AddChildName(const std::wstring& name) {
            if (unique_child_names.count(name) ||
                unique_child_names.size() < kMaxUniqueChildNames) {
                unique_child_names.insert(name);
            }
            else {
                ++unique_child_names_overflow;
            }
        }
    };

    // ============================================================================
    // PROCESS MONITOR
    // ============================================================================

    class ProcessMonitor {
    public:
        explicit ProcessMonitor(AsyncLogger& logger, FilterEngine& filter);
        ~ProcessMonitor();

        ProcessMonitor(const ProcessMonitor&) = delete;
        ProcessMonitor& operator=(const ProcessMonitor&) = delete;

        bool Start();
        void Stop();
        bool IsRunning() const noexcept { return running_.load(); }

        // V3 pipeline counters (replaces events_dropped_)
        uint64_t GetEventsProcessed() const noexcept {
            return events_processed_.load();
        }
        uint64_t GetEventsForwarded() const noexcept {
            return events_forwarded_.load();
        }
        uint64_t GetEventsCompressed() const noexcept {
            return events_compressed_.load();
        }

        // Queries live ETW loss counters (EventsLost / RealTimeBuffersLost)
        // via ControlTraceW(...QUERY...) -- does not stop the session -- and
        // emits a collector_health JSONL record via the logger. Safe to call
        // periodically while running (e.g. from Agent's status loop).
        void ReportHealth();

        // FORU.TXT section 4: Monitoring toggle via the IPC control channel —
        // independent of whether the ETW session itself is open. When false,
        // OnProcessEvent discards events immediately (no enrichment, no
        // filtering, no logging) rather than tearing down/recreating the ETW
        // subscription, so toggling is instant and reversible.
        void SetMonitoringEnabled(bool enabled) noexcept { monitoring_enabled_.store(enabled); }
        bool IsMonitoringEnabled() const noexcept { return monitoring_enabled_.load(); }
        void SetRetentionBudgetBytes(uint64_t budget_bytes) noexcept;

    private:
        // Emits the actual collector_health JSON record. Called by
        // ReportHealth() (periodic, final=false) and by StopEtwSession()
        // (final=true, using the stats returned by the STOP call itself).
        void EmitHealthRecord(bool final_record, uint64_t events_lost,
            uint64_t realtime_buffers_lost);
        // ETW session lifecycle
        bool StartEtwSession();
        void StopEtwSession();

        // ETW callback (static, routes to instance method)
        static void WINAPI EtwEventCallback(PEVENT_RECORD record);

        // Event dispatch
        void OnProcessEvent(PEVENT_RECORD record);

        // Per-event-type handlers
        void HandleProcessStart(const BYTE* data, ULONG len, uint64_t ts);
        void HandleProcessStop(const BYTE* data, ULONG len, uint64_t ts);
        void HandleProcessDCStart(const BYTE* data, ULONG len, uint64_t ts);
        void HandleThreadCreate(const BYTE* data, ULONG len, uint64_t ts);

        // Enrichment: resolve parent canonical path and populate V3ProcessInfo
        // fork/thread summary fields from the per-PID accumulator.
        // NOTE: not const — consumes new_child_flag after reading it.
        void EnrichV3Fields(DWORD pid, DWORD parent_pid, Event& event);

        // Resolve real binary path from kernel via QueryFullProcessImageNameW.
        // Returns empty string on failure.
        static std::wstring ResolveImagePath(DWORD pid);

        // Helpers
        static IntegrityLevel QueryIntegrity(HANDLE hToken);
        static TokenElevation QueryElevation(HANDLE hToken);
        static DWORD QueryRealParent(HANDLE hProcess);
        static std::wstring ReadUnicodeString(const BYTE* data, ULONG& offset,
            ULONG len);
        static std::string ReadSidString(const BYTE* data, ULONG& offset, ULONG len);

        // Members
        AsyncLogger& logger_;
        FilterEngine& filter_;

        TRACEHANDLE session_handle_{ 0 };
        // FIX: atomic + INVALID_PROCESSTRACE_HANDLE sentinel so StartEtwSession
        // can poll for "consumer thread has actually attached via OpenTraceW"
        // instead of a fixed sleep -- see StartEtwSession for the ordering fix.
        std::atomic<TRACEHANDLE> consumer_handle_{ INVALID_PROCESSTRACE_HANDLE };
        std::wstring session_name_{ L"TitanProcessSession" };
        std::thread consumer_thread_;

        std::atomic<bool> running_{ false };
        std::atomic<bool> stop_requested_{ false };
        std::atomic<bool> monitoring_enabled_{ true };

        // FORU.TXT section 6.6: "Associate health with the exact process
        // session. Ignore health from a previous process or historical file."
        // Reused from logger_ (not independently generated) so this process
        // launch has exactly one session_id everywhere -- the health record's
        // own "session_id" field and every evidence record's envelope
        // session_id (see evidence_envelope.h) are now guaranteed identical,
        // which also means EmitHealthRecord must NOT also hand-write
        // "session_id" itself: WriteJsonLine's envelope already adds it, and
        // a second occurrence of the same JSON key would be an honest-but-
        // sloppy duplicate.
        const std::string &session_id_;

        // Computed once (the running image doesn't change during this
        // process's lifetime) rather than re-hashed on every health tick.
        const std::string executable_sha256_{ComputeSelfExecutableSha256()};

        // Per-PID fork/thread accumulators (guarded by accum_mutex_)
        mutable std::mutex accum_mutex_;
        std::unordered_map<DWORD, ProcessAccumulator> accumulators_;

        // V3 counters
        std::atomic<uint64_t> events_processed_{ 0 };
        std::atomic<uint64_t> events_forwarded_{ 0 };
        std::atomic<uint64_t> events_compressed_{ 0 };

        // Health / loss counters -- surfaced via collector_health records.
        std::atomic<uint64_t> events_lost_{ 0 };
        std::atomic<uint64_t> realtime_buffers_lost_{ 0 };

        // RAM/disk auto-lightening -- shrinks logger_'s pack-retention cap
        // under system pressure. Never touches WHAT is captured (ETW
        // subscriptions, accumulator caps) -- only how much evidence
        // history stays on disk.
        ResourcePressureMonitor pressure_monitor_;
        // FORU.TXT section 7: "Make Process retention consistent with the
        // product budget instead of allowing approximately 2 GiB." 20 packs *
        // AsyncLogger's 100MB/pack was exactly that hardcoded ~2GiB. Now a
        // runtime default, overridable by LoadRetentionBudgetOverride() below
        // -- unchanged (still 20/3) unless something has actually configured
        // a coordinated budget, so behavior is identical until the GUI-side
        // disk-budget work writes a real override file.
        std::atomic<size_t> base_max_packs_{20};
        std::atomic<size_t> floor_max_packs_{3};
        // Reads "<log_dir>.retention_budget_mb" (one plain integer, written by
        // the GUI's coordinated disk-budget allocation) if present and valid;
        // silently keeps the defaults above otherwise -- a missing or
        // malformed override file must never crash or block startup.
        void LoadRetentionBudgetOverride();

        // ETW provider GUID: Microsoft-Windows-Kernel-Process
        static constexpr GUID kKernelProcessGuid = {
            0x22FB2CD6,
            0x0E7B,
            0x422B,
            {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16} };

        // ETW event IDs
        static constexpr uint16_t kEvtProcessStart = 1;
        static constexpr uint16_t kEvtProcessStop = 2;
        static constexpr uint16_t kEvtProcessDCStart = 3;
        static constexpr uint16_t kEvtThreadCreate = 5;
    };

} // namespace titan

#endif // TITAN_PROCESS_MONITOR_H
