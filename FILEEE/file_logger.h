#pragma once

// =============================================================================
// TITAN - File Integrity Monitor
// file_logger.h
//
// FIX (Circular Dependency):
//   Previously included file_processor.h to get LogSeverity. That created a
//   circular include because file_processor.cpp includes file_logger.h which
//   included file_processor.h again.
//   Fix: LogSeverity is now in _file_scope.h. Include that instead.
// =============================================================================

#include "_file_scope.h"    // LogSeverity
#include "evidence_envelope.h"

#include <string>
#include <fstream>
#include <mutex>
#include <cstdint>
#include <filesystem>
#include <atomic>
#include <chrono>
#include <deque>
#include <unordered_map>
#include <utility>
#include <vector>

namespace titan::fim
{

    class FileLogger
    {
    public:

        FileLogger();
        ~FileLogger();

        // Santosh: "upgrade them ... close all the gaps, not delete or
        // destroy what is there." Found live: the old 256 KiB-per-pack
        // default meant total retained evidence (2 archives + the active
        // pack) was under 1 MiB -- enough for only a few SECONDS of a real
        // burst (e.g. Windows Defender's own scan sweeping thousands of
        // System32 files in direct response to detecting a real threat).
        // The very create/close/delete records for the file that TRIGGERED
        // that scan were rotated away and pruned before the Correlator (or
        // a human) ever got a chance to read them -- self-defeating: the
        // remediation's own noise erased the signal. 2 MiB per pack matches
        // every other endpoint's own established convention (Correlator/
        // Process/Network all already use 2 MiB packs).
        bool Initialize(
            const std::wstring& log_path,
            uint64_t max_file_bytes = 2ULL * 1024 * 1024
        );

        void Log(const std::string& json);
        void Log(const std::string& json, LogSeverity severity);
        void LogAggregated(const std::string& key, const std::string& json,
            LogSeverity severity);
        void Flush();

        // RAM/disk auto-lightening: shrinks (or restores) the archive-
        // retention cap at runtime, e.g. driven by ResourcePressureMonitor.
        // Takes effect on the next rotation's prune pass.
        void SetMaxArchives(size_t maxArchives) noexcept {
            const auto budget = budget_max_archives_.load(std::memory_order_relaxed);
            max_archives_.store(maxArchives < budget ? maxArchives : budget, std::memory_order_relaxed);
        }
        void SetRetentionMaxArchives(size_t maxArchives) noexcept {
            budget_max_archives_.store(maxArchives, std::memory_order_relaxed);
            max_archives_.store(maxArchives, std::memory_order_relaxed);
        }
        uint64_t GetMaxFileBytes() const noexcept { return max_file_bytes_; }
        size_t GetMaxArchives() const noexcept { return max_archives_.load(std::memory_order_relaxed); }

        // FORU.TXT section 4.3-4.5: Save Logs is independent of Monitoring.
        void SetSaveLogsEnabled(bool enabled) noexcept { save_logs_enabled_.store(enabled); }
        bool IsSaveLogsEnabled() const noexcept { return save_logs_enabled_.load(); }
        std::vector<std::string> GetRecentLines() const;

        const std::string& GetSessionId() const noexcept { return session_id_; }
        int64_t GetStartedAtUnixMs() const noexcept { return started_at_unix_ms_; }
        std::pair<uint64_t, uint64_t> GetRetainedBytesAndFiles() const;
        uint64_t GetWriteFailureCount() const noexcept { return write_failures_.load(); }
        uint64_t GetRotationCount() const noexcept { return rotation_count_.load(); }

    private:

        std::ofstream log_stream_;
        std::mutex    log_mutex_;
        std::wstring  log_path_;
        uint64_t      max_file_bytes_;
        uint64_t      bytes_written_;
        bool          initialized_;
        // Base 10 (was 2): ten 2 MiB archives give real burst headroom --
        // the old 2x256KiB combination could be entirely consumed and
        // pruned within seconds of a genuine burst (see Initialize's
        // max_file_bytes comment for the live incident that exposed this).
        // budget_max_archives_ is the hard ceiling SetMaxArchives() (the
        // resource-pressure adaptive path) can never exceed -- must move
        // together with max_archives_'s own default, or the adaptive path
        // silently clamps back down to the OLD budget regardless of what
        // file_monitor.cpp's kBaseMaxArchives requests.
        std::atomic<size_t> max_archives_{ 10 };
        std::atomic<size_t> budget_max_archives_{ 10 };
        std::chrono::steady_clock::time_point rotation_started_;

        // FORU.TXT section 8: durable evidence identity, stamped on every
        // record at the WriteUnlocked() choke point -- see evidence_envelope.h.
        // NOTE: like Application's AppLogLogger, this program's rotation
        // RENAMES the live file rather than opening a new timestamped one,
        // so source_file reflects the filename as of the write and becomes
        // stale after a LATER rotation renames that file out from under it
        // -- same documented, unfixed limitation, not introduced here.
        const std::string session_id_{MakeSessionId("file_integrity")};
        std::atomic<uint64_t> next_record_id_{1};
        std::atomic<bool> save_logs_enabled_{true};
        mutable std::mutex recent_lines_mutex_;
        std::deque<std::string> recent_lines_;
        static constexpr size_t kRecentLinesCap = 500;
        std::atomic<uint64_t> write_failures_{0};
        std::atomic<uint64_t> rotation_count_{0};
        const int64_t started_at_unix_ms_{
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()};

        struct PendingRecord
        {
            std::string json;
            LogSeverity severity = LogSeverity::INFO;
            uint64_t repeat_count = 1;
            std::chrono::steady_clock::time_point last_seen;
        };
        std::unordered_map<std::string, PendingRecord> pending_;

        bool RotateIfNeeded();
        void PruneOldArchives(const std::filesystem::path& current);
        static void EnableDirectoryCompression(
            const std::filesystem::path& directory);
        bool WriteUnlocked(const std::string& json, LogSeverity severity,
            uint64_t repeat_count);
        void FlushExpiredAggregatesUnlocked(
            std::chrono::steady_clock::time_point now, bool all);
        static const char* SeverityString(LogSeverity s);
    };

} // namespace titan::fim
