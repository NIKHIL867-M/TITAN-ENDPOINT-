#ifndef TITAN_LOGGER_H
#define TITAN_LOGGER_H

// ============================================================================
// Bounded asynchronous JSONL logger for the Network Endpoint.
// Queue, disk rotation, archive pruning, and all failure/loss paths are
// explicitly bounded and counted.
// ============================================================================

#include "event.h"
#include "evidence_envelope.h"
#include "resource_pressure.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace titan {

    // ============================================================================
    // ASYNC LOGGER
    // Thread-safe. Single worker thread drains the queue and writes .jsonl packs.
    // A full queue rejects an event and increments an observable drop counter.
    // ============================================================================

    class AsyncLogger {
    public:
        explicit AsyncLogger(const std::wstring& log_dir);
        ~AsyncLogger();

        AsyncLogger(const AsyncLogger&) = delete;
        AsyncLogger& operator=(const AsyncLogger&) = delete;

        // Initialise: create log directory, open first pack, start worker threads.
        bool Initialize();

        // Drain queue, close file, stop threads. Safe to call multiple times.
        void Shutdown();

        // Enqueue a packet/flow event. Thread-safe. If the queue is full, wait
        // up to 50 ms; if it is still full, reject and count the event.
        // Every rejected event is counted and reported in collector health.
        void LogEvent(Event&& event);

        // Append a raw pre-built JSON line directly (control_audit records
        // from ipc_control_server.cpp) -- bypasses the event queue, writes
        // and flushes immediately, same pattern as Process's AsyncLogger.
        void LogRaw(const std::string& json);

        // Publish capture, aggregation, logger, and storage health.
        // monitoring_enabled surfaces NetworkMonitor's own collecting toggle
        // (FORU.TXT section 4/5) -- AsyncLogger has no other way to know it.
        // final_record=true marks the shutdown-time call (schema v2's
        // shutdown_state/shutdown_ack) vs a periodic call.
        void LogHealthRecord(uint64_t capture_drops,
            uint64_t interface_drops, uint64_t raw_capture_failures,
            uint64_t structured_unparsed_packets,
            uint64_t suppressed_packets, bool monitoring_enabled, bool final_record);

        // FORU.TXT section 4.3-4.5: Save Logs is independent of Monitoring.
        void SetSaveLogsEnabled(bool enabled) noexcept { save_logs_enabled_.store(enabled); }
        bool IsSaveLogsEnabled() const noexcept { return save_logs_enabled_.load(); }
        std::vector<std::string> GetRecentLines() const;
        void SetMaxPacks(size_t maxPacks) noexcept {
            const size_t value = maxPacks < 1 ? 1 : maxPacks;
            configured_max_log_packs_.store(value, std::memory_order_relaxed);
            max_log_packs_.store(value, std::memory_order_relaxed);
        }
        size_t GetMaxPacks() const noexcept { return max_log_packs_.load(std::memory_order_relaxed); }
        static constexpr uint64_t GetMaxPackFileBytes() noexcept { return kMaxFileBytes; }

        const std::string& GetSessionId() const noexcept { return session_id_; }
        int64_t GetStartedAtUnixMs() const noexcept { return started_at_unix_ms_; }
        uint64_t GetRotationCount() const noexcept { return rotation_count_.load(); }
        std::pair<uint64_t, uint64_t> GetRetainedBytesAndFiles() const;

        // Wait until the queue is fully drained.
        void Flush();

        // Runtime counters
        uint64_t GetWrittenCount() const noexcept { return written_count_.load(); }
        uint64_t GetQueuedCount() const noexcept { return queued_count_.load(); }
        uint64_t GetDroppedCount() const noexcept { return dropped_count_.load(); }
        uint64_t GetStorageFailureCount() const noexcept {
            return storage_failures_.load();
        }
        uint64_t GetForwardedCount() const noexcept {
            return forwarded_count_.load();
        }

        // RAM/disk auto-lightening: samples system pressure and shrinks
        // (or restores) the JSON pack retention cap accordingly. Call
        // periodically (e.g. from Agent::PrintStatus's existing 10s loop).
        // Never touches WHAT is captured -- only how much history is kept.
        void UpdateResourcePressure() {
            pressure_monitor_.Update();
            max_log_packs_.store(
                AdaptiveCap(configured_max_log_packs_.load(std::memory_order_relaxed),
                    kMinLogPacks, pressure_monitor_.GetFactor()),
                std::memory_order_relaxed);
        }
        PressureTier GetResourcePressureTier() const noexcept {
            return pressure_monitor_.GetTier();
        }

    private:
        void WorkerThread();   // drains event_queue_, writes JSON lines

        void WriteJsonLine(const std::string& json);
        void RotateIfNeeded();
        void PruneOldPacks();
        std::wstring NewPackPath() const;

        // ---- state ----
        std::wstring log_dir_;
        std::wstring current_pack_path_;
        std::ofstream pack_file_;
        std::string pending_health_record_;

        std::thread worker_;
        std::mutex mutex_;
        std::condition_variable cv_;
        std::queue<Event> event_queue_;
        std::atomic<bool> running_{ false };

        // Runtime counters
        std::atomic<uint64_t> queued_count_{ 0 };
        std::atomic<uint64_t> in_flight_count_{ 0 };
        std::atomic<uint64_t> dropped_count_{ 0 };
        std::atomic<uint64_t> written_count_{ 0 };
        std::atomic<uint64_t> forwarded_count_{ 0 };
        std::atomic<uint64_t> current_file_bytes_{ 0 };
        std::atomic<uint64_t> storage_failures_{ 0 };
        std::atomic<uint64_t> rotation_count_{ 0 };

        // FORU.TXT section 8: durable evidence identity, stamped on every
        // record at the WriteJsonLine choke point -- see evidence_envelope.h.
        const std::string session_id_{MakeSessionId("network")};
        std::atomic<uint64_t> next_record_id_{1};
        const int64_t started_at_unix_ms_{
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()};
        static std::string NarrowFileName(const std::wstring& path);

        // FORU.TXT section 4.3-4.5: Save Logs toggle + bounded live-view ring
        // (same pattern as Process's AsyncLogger).
        std::atomic<bool> save_logs_enabled_{true};
        mutable std::mutex recent_lines_mutex_;
        std::deque<std::string> recent_lines_;
        static constexpr size_t kRecentLinesCap = 500;

        // Config
        static constexpr size_t kMaxQueue = 1'024;
        static constexpr uint64_t kMaxFileBytes =
            2ULL * 1024 * 1024;
        static constexpr size_t kMaxLogPacksBase = 3;
        static constexpr size_t kMinLogPacks = 1;
        std::atomic<size_t> max_log_packs_{ kMaxLogPacksBase };
        std::atomic<size_t> configured_max_log_packs_{ kMaxLogPacksBase };
        ResourcePressureMonitor pressure_monitor_;
    };

    // ============================================================================
    // CONSOLE LOGGER  —  lightweight, sync, for status/debug output only
    // ============================================================================

    class ConsoleLogger {
    public:
        static void LogInfo(const std::string& msg);
        static void LogWarning(const std::string& msg);
        static void LogError(const std::string& msg);
    };

} // namespace titan

#endif // TITAN_LOGGER_H
