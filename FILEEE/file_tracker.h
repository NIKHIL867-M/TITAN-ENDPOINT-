#pragma once


#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <functional>
#include <deque>

#include "_file_scope.h"
#include "file_processor.h"   // FileEvent, FileAction

namespace titan::fim
{
    class FileLogger;

    // =========================================================================
    // Lifecycle state of a single tracked temp file
    // =========================================================================
    enum class TempFileState
    {
        WATCHING,       // just arrived, observing
        TRUSTED_AGING,  // no anomaly, within normal lifespan
        ELEVATED,       // anomaly detected, treat as Bucket A
        DROPPED,        // confirmed clean, removed from tracking
    };

    // =========================================================================
    // Single file entry inside a TempBucket
    // =========================================================================
    struct TempFileEntry
    {
        std::wstring  path;
        uint64_t      file_key = 0;
        uint32_t      creator_pid = 0;
        std::wstring  creator_name;
        std::chrono::steady_clock::time_point born_at;
        std::chrono::steady_clock::time_point last_seen;
        TempFileState state = TempFileState::WATCHING;
        bool          was_renamed = false;
        bool          cross_pid = false;
        uint32_t      write_count = 0;
        std::vector<std::pair<uint32_t, std::wstring>> other_pids; // {pid, name}
    };

    // =========================================================================
    // A batch of temp files grouped by {directory + creator_pid}
    //
    // FIX (RAM Bomb): files map is capped at TEMP_BUCKET_DETAIL_LIMIT.
    //   mass_file_count counts files beyond that limit (no path stored).
    // =========================================================================
    struct TempBucket
    {
        std::wstring  directory;
        uint32_t      creator_pid = 0;
        std::wstring  creator_name;
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;
        uint32_t      total_created = 0;
        uint32_t      total_deleted = 0;
        uint32_t      total_alive = 0;
        bool          has_anomaly = false;

        // Detailed per-file entries — capped at TEMP_BUCKET_DETAIL_LIMIT
        std::unordered_map<std::wstring, TempFileEntry> files;

        // Count of files beyond TEMP_BUCKET_DETAIL_LIMIT (no path stored)
        uint32_t      mass_file_count = 0;
        uint64_t      mass_event_count = 0;
    };

    // =========================================================================
    // Per-directory churn tracker
    // =========================================================================
    struct DirChurnEntry
    {
        uint32_t      count_this_second = 0;
        std::chrono::steady_clock::time_point window_start;
        bool          is_high_churn = false;
        std::chrono::steady_clock::time_point last_seen;
        double        lifetime_avg_seconds = 0.0;
        uint64_t      lifetime_samples = 0;
    };

    // =========================================================================
    // TempTracker
    // =========================================================================
    class TempTracker
    {
    public:

        explicit TempTracker(FileLogger* logger,
            uint32_t minimum_lifetime_seconds = TEMP_SHORT_LIFE_SECONDS,
            FileProcessor* processor = nullptr);
        ~TempTracker() = default;

        // Called by FileMonitor for every Bucket B event.
        // Returns true if the event was elevated to Bucket A treatment.
        bool TrackEvent(const FileEvent& event);

        // Called periodically from the monitor maintenance loop.
        void Maintenance();

        // Called by FileMonitor for every event (all buckets) so per-directory
        // churn counts are accurate for dynamic zone detection.
        void RecordDirectoryEvent(const std::wstring& path);

        // Is this directory currently classified as high-churn?
        bool IsHighChurnDirectory(const std::wstring& dir) const;
        void ObserveRelatedEvent(const FileEvent& event);
        void ObservePathTransition(const FileEvent& event);

    private:

        FileLogger* logger_;
        FileProcessor* processor_;
        uint32_t minimum_lifetime_seconds_;
        mutable std::mutex mutex_;

        std::unordered_map<std::wstring, TempBucket>   buckets_;
        std::unordered_map<std::wstring, DirChurnEntry> dir_churn_;
        struct RecentTempActivity
        {
            std::wstring identity;
            std::wstring path;
            std::wstring process_name;
            uint64_t file_key = 0;
            uint32_t creator_pid = 0;
            uint32_t creator_tid = 0;
            uint32_t last_tid = 0;
            uint32_t create_count = 0;
            uint32_t write_count = 0;
            uint32_t rename_count = 0;
            uint32_t delete_count = 0;
            std::chrono::steady_clock::time_point born_at;
            std::chrono::steady_clock::time_point last_seen;
            bool active = true;
        };
        std::unordered_map<std::wstring, RecentTempActivity> recent_temp_files_;
        std::unordered_map<uint32_t, std::deque<std::wstring>>
            recent_temp_ids_by_pid_;

        std::wstring BucketKey(const std::wstring& dir, uint32_t pid) const;
        std::wstring TempIdentity(const FileEvent& event) const;
        void RememberTempFile(const FileEvent& event, uint32_t effective_pid);
        void RemoveRecentTemp(const std::wstring& identity);
        std::wstring ExtractDir(const std::wstring& path) const;
        void         UpdateChurn(const std::wstring& dir);
        bool         CheckAnomalies(TempBucket& bucket, TempFileEntry& entry,
            const FileEvent& event);
        void         ElevateToBucketA(TempBucket& bucket, TempFileEntry& entry,
            const std::string& reason);
        void         CompressAndLogBucket(TempBucket& bucket);
        void         EvictCleanBuckets();
        uint32_t     LifetimeThresholdSeconds(const std::wstring& dir) const;

        std::string  BuildSummaryJson(const TempBucket& bucket,
            uint32_t elevated_count) const;
        std::string  BuildElevatedJson(const TempBucket& bucket,
            const TempFileEntry& entry,
            const std::string& reason) const;

        static std::string WstrToUtf8(const std::wstring& ws);
    };

} // namespace titan::fim
