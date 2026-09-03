#pragma once
#include <atomic>
#include <thread>
#include <memory>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <chrono>

#include "file_processor.h"
#include "file_logger.h"
#include "file_tracker.h"
#include "_file_scope.h"
#include "resource_pressure.h"

namespace titan::fim
{

    // Santosh: "upgrade them in a way so that we [close] all the gaps, not
    // delete or destroy what is there." Found live: a real burst (repeated
    // fleet test cycles plus ordinary desktop activity) submitted 71,752
    // events in one session and the queue -- at the old 8192 depth --
    // dropped 3,206 of them (~4.5%) by evicting the OLDEST still-unprocessed
    // event to make room for each new one, regardless of that event's real
    // value. The existing low-value-temp-churn coalescing pre-filter above
    // this queue already diverts the highest-volume noise before it ever
    // reaches here (unchanged, still the first line of defense) -- this is
    // the second: 4x more headroom for the consumer thread (MonitorLoop,
    // draining every ~500ms) to catch up under a real burst before FIFO
    // eviction of genuine, not-yet-processed evidence ever has to happen.
    static constexpr size_t MAX_EVENT_QUEUE_DEPTH = 32768;
    static constexpr size_t MAX_EVENT_QUEUE_CHARS = 4 * 1024 * 1024;
    static constexpr size_t TEMP_COALESCE_QUEUE_DEPTH = 24576;
    static constexpr size_t TEMP_COALESCE_QUEUE_CHARS = 3 * 1024 * 1024;

    class FileMonitor
    {
    public:

        FileMonitor();
        ~FileMonitor();

        bool Start(const std::wstring& log_path = L"logs\\fim_events.json");
        void Stop();

        // Called by ETW collector — thread safe, non-blocking
        void SubmitEvent(const FileEvent& event);

        // FORU.TXT section 4: Monitoring toggle via the IPC control channel,
        // independent of whether the ETW subscription is open.
        void SetMonitoringEnabled(bool enabled) noexcept { monitoring_enabled_.store(enabled); }
        bool IsMonitoringEnabled() const noexcept { return monitoring_enabled_.load(); }

        FileLogger* GetLogger() { return logger_.get(); }
        std::string HashFile(const std::wstring& path);
        uint64_t SubmittedEvents() const { return submitted_events_.load(); }
        uint64_t DroppedEvents() const { return dropped_events_.load(); }
        uint64_t CoalescedTempEvents() const
        {
            return coalesced_temp_events_.load();
        }
        void ReportEtwLoss(uint64_t events_lost,
            uint64_t realtime_buffers_lost);

    private:

        std::unique_ptr<FileLogger>    logger_;
        std::unique_ptr<FileProcessor> processor_;
        std::unique_ptr<TempTracker>   tracker_;

        std::queue<FileEvent>          event_queue_;
        std::mutex                     queue_mutex_;
        std::condition_variable        queue_cv_;
        size_t                         queued_event_chars_ = 0;

        std::atomic<bool>              running_;
        std::atomic<bool>              monitoring_enabled_{ true };
        std::atomic<uint64_t>          submitted_events_{ 0 };
        std::atomic<uint64_t>          dropped_events_{ 0 };
        std::atomic<uint64_t>          coalesced_temp_events_{ 0 };
        std::atomic<uint64_t>          etw_events_lost_{ 0 };
        std::atomic<uint64_t>          etw_buffers_lost_{ 0 };
        std::atomic<uint64_t>          processing_errors_{ 0 };
        uint64_t                       logged_queue_drops_ = 0;
        uint64_t                       logged_etw_events_lost_ = 0;
        uint64_t                       logged_etw_buffers_lost_ = 0;
        std::chrono::steady_clock::time_point last_health_log_;
        std::thread                    monitor_thread_;

        void MonitorLoop();
        void DispatchEvent(const FileEvent& event);

        std::chrono::steady_clock::time_point last_maintenance_;
        std::wstring internal_log_path_;
        std::wstring internal_log_directory_;
        std::wstring internal_log_stem_;
        std::wstring internal_baseline_path_;

        bool IsInternalLogPath(const std::wstring& path) const;
        void PersistCollectorHealth(bool final);

        // RAM/disk auto-lightening -- shrinks logger_'s archive-retention
        // cap under system pressure. Never touches WHAT is captured. Base
        // 10 / floor 3 (was 2 / 1) -- matches FileLogger's own raised
        // defaults (see file_logger.h); real pressure can still shrink
        // retention, but never back down to the single ~2 MiB pack that let
        // a genuine burst outrun retention entirely.
        ResourcePressureMonitor pressure_monitor_;
        static constexpr size_t kBaseMaxArchives = 10;
        static constexpr size_t kFloorMaxArchives = 3;
    };

} // namespace titan::fim
