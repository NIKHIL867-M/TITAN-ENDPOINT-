#include "file_monitor.h"
#include "_file_scope.h"
#include "evidence_envelope.h"
#include <iostream>
#include <sstream>
#include <filesystem>
#include <chrono>
#include <psapi.h>

namespace titan::fim
{

    FileMonitor::FileMonitor()
        : running_(false)
        , last_maintenance_(std::chrono::steady_clock::now())
    {
        logger_ = std::make_unique<FileLogger>();
        processor_ = std::make_unique<FileProcessor>();
    }

    FileMonitor::~FileMonitor()
    {
        Stop();
    }

    // =========================================================================
    // ResolveLogPath
    // If log_path is already absolute use it verbatim.
    // If relative, anchor it to the exe's own directory so logs always land
    // next to the binary regardless of Visual Studio's working directory setting.
    // =========================================================================
    static std::wstring ResolveLogPath(const std::wstring& log_path)
    {
        std::filesystem::path p(log_path);

        if (p.is_absolute())
            return log_path;

        wchar_t exe_buf[MAX_PATH * 2] = {};
        DWORD   exe_len = GetModuleFileNameW(nullptr, exe_buf, MAX_PATH * 2);

        if (exe_len == 0 || exe_len >= MAX_PATH * 2)
        {
            std::wcerr << L"[FIM][Monitor] Warning: cannot resolve exe path, "
                L"using log_path as-is\n";
            return log_path;
        }

        std::filesystem::path exe_dir =
            std::filesystem::path(exe_buf).parent_path();

        return (exe_dir / p).wstring();
    }

    // =========================================================================
    // Start
    // =========================================================================
    bool FileMonitor::Start(const std::wstring& log_path)
    {
        if (running_) return false;
        submitted_events_.store(0);
        dropped_events_.store(0);
        coalesced_temp_events_.store(0);
        etw_events_lost_.store(0);
        etw_buffers_lost_.store(0);
        processing_errors_.store(0);
        logged_queue_drops_ = 0;
        logged_etw_events_lost_ = 0;
        logged_etw_buffers_lost_ = 0;
        last_health_log_ = std::chrono::steady_clock::now();

        std::wstring abs_log_path = ResolveLogPath(log_path);
        const std::filesystem::path normalized_log =
            std::filesystem::path(abs_log_path).lexically_normal();
        internal_log_path_ = ToLower(normalized_log.wstring());
        internal_log_directory_ = ToLower(normalized_log.parent_path().wstring());
        internal_log_stem_ = ToLower(normalized_log.stem().wstring());
        internal_baseline_path_ = ToLower(
            (normalized_log.parent_path() / L"fim_hash_baseline.dat").wstring());
        pressure_monitor_.SetPath(internal_log_directory_);

        std::wcout << L"[FIM][Monitor] Log: " << abs_log_path << L"\n";

        if (!logger_->Initialize(abs_log_path))
        {
            std::cerr << "[FIM][Monitor] Failed to initialize logger\n";
            return false;
        }

        if (!processor_->Initialize(logger_.get(), internal_baseline_path_))
        {
            std::cerr << "[FIM][Monitor] Failed to initialize processor\n";
            return false;
        }

        tracker_ = std::make_unique<TempTracker>(
            logger_.get(), TEMP_SHORT_LIFE_SECONDS, processor_.get());

        // Startup entry — proves logger + flush are working
        std::string startup =
            std::string("{\"endpoint\":\"file_integrity\"")
            + ",\"action\":\"startup\""
            + ",\"path\":\"TITAN_FIM_started\""
            + ",\"pid\":0,\"tid\":0"
            + ",\"process\":\"file_test.exe\""
            + ",\"timestamp\":\"startup\""
            + ",\"protected\":false"
            + ",\"executable\":false"
            + ",\"document\":false"
            + "}";
        logger_->Log(startup, LogSeverity::INFO);

        running_ = true;
        monitor_thread_ = std::thread(&FileMonitor::MonitorLoop, this);

        std::cout << "[FIM][Monitor] Started — watching all file activity\n";
        return true;
    }

    // =========================================================================
    // Stop
    // =========================================================================
    void FileMonitor::Stop()
    {
        if (!running_) return;

        running_ = false;
        queue_cv_.notify_all();

        if (monitor_thread_.joinable())
            monitor_thread_.join();

        PersistCollectorHealth(true);
        if (processor_) processor_->SaveHashBaselines();
        if (logger_) logger_->Flush();

        std::cout << "[FIM][Monitor] Stopped (submitted="
            << submitted_events_.load() << ", queue_dropped="
            << dropped_events_.load() << ", temp_coalesced="
            << coalesced_temp_events_.load() << ")\n";
    }

    void FileMonitor::ReportEtwLoss(uint64_t events_lost,
        uint64_t realtime_buffers_lost)
    {
        auto update_max = [](std::atomic<uint64_t>& target, uint64_t value)
        {
            uint64_t current = target.load(std::memory_order_relaxed);
            while (current < value && !target.compare_exchange_weak(
                current, value, std::memory_order_relaxed)) {}
        };
        update_max(etw_events_lost_, events_lost);
        update_max(etw_buffers_lost_, realtime_buffers_lost);
        queue_cv_.notify_one();
    }

    void FileMonitor::PersistCollectorHealth(bool final)
    {
        if (!logger_) return;
        const uint64_t queue_drops = dropped_events_.load();
        const uint64_t events_lost = etw_events_lost_.load();
        const uint64_t buffers_lost = etw_buffers_lost_.load();
        const auto now = std::chrono::steady_clock::now();
        // A health record is a heartbeat, not merely a loss-counter change notification.
        // Start All launches the sensors sequentially; suppressing unchanged health made an idle,
        // healthy File collector look stale before Correlator/Custom Rule dependency checks ran.
        // Keep the five-second bound below even when every counter is unchanged.
        if (!final && now - last_health_log_ < std::chrono::seconds(5))
            return;

        const bool degraded = queue_drops != 0 || events_lost != 0 ||
            buffers_lost != 0 || processing_errors_.load() != 0;
        std::ostringstream json;
        const auto health_now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const auto [retainedBytes, retainedFiles] = logger_->GetRetainedBytesAndFiles();
        static const std::string executableHash = ComputeSelfExecutableSha256();
        json << "{\"t_unix_ms\":" << health_now_ms << ","
            << "\"endpoint\":\"file_integrity\","
            << "\"type\":\"collector_health\","
            << "\"schema_version\":2,"
            << "\"endpoint_id\":\"file_integrity\","
            << "\"pid\":" << GetCurrentProcessId() << ","
            << "\"executable_version\":\"release-manifest-2026-08-02-schema-v2\","
            << "\"executable_hash\":\"" << executableHash << "\","
            << "\"started_at\":" << logger_->GetStartedAtUnixMs() << ","
            << "\"updated_at\":" << health_now_ms << ","
            << "\"collecting\":" << (monitoring_enabled_.load() ? "true" : "false") << ","
            << "\"persistence_enabled\":" << (logger_->IsSaveLogsEnabled() ? "true" : "false") << ","
            << "\"status\":\"" << (degraded ? "degraded" : "healthy") << "\","
            << "\"final\":" << (final ? "true" : "false") << ","
            << "\"submitted_events\":" << submitted_events_.load() << ","
            << "\"queue_dropped\":" << queue_drops << ","
            << "\"temp_events_coalesced\":"
            << coalesced_temp_events_.load() << ","
            << "\"etw_events_lost\":" << events_lost << ","
            << "\"realtime_buffers_lost\":" << buffers_lost << ","
            << "\"processing_errors\":" << processing_errors_.load() << ","
            // Standardized cross-endpoint names (additive).
            << "\"records_seen\":" << submitted_events_.load() << ","
            << "\"records_written\":" << (submitted_events_.load() - queue_drops) << ","
            << "\"records_dropped\":" << queue_drops << ","
            << "\"parse_failures\":0," // this program parses no untrusted external input
            << "\"source_loss\":" << (events_lost + buffers_lost) << ","
            << "\"writer_failures\":" << logger_->GetWriteFailureCount() << ","
            << "\"rotations\":" << logger_->GetRotationCount() << ","
            << "\"retained_bytes\":" << retainedBytes << ","
            << "\"retained_files\":" << retainedFiles << ","
            << "\"evidence_gap\":" << (degraded ? "true" : "false") << ","
            << "\"reconciliation_required\":"
            << (degraded ? "true" : "false") << ","
            << "\"resource_pressure\":\"" << PressureTierToString(pressure_monitor_.GetTier()) << "\","
            << "\"shutdown_state\":\"" << (final ? "stopped" : "running") << "\","
            << "\"shutdown_ack\":" << (final ? "true" : "false") << ","
            << "\"last_error\":\"\""
            << "}";
        logger_->Log(json.str(), degraded
            ? LogSeverity::WARNING : LogSeverity::INFO);
        if (final) logger_->Flush();
        logged_queue_drops_ = queue_drops;
        logged_etw_events_lost_ = events_lost;
        logged_etw_buffers_lost_ = buffers_lost;
        last_health_log_ = now;
    }

    // =========================================================================
    // SubmitEvent — called from ETW thread (must be fast, non-blocking)
    // =========================================================================
    void FileMonitor::SubmitEvent(const FileEvent& event)
    {
        if (!running_) return;
        // FORU.TXT section 4.3/4.4: Monitoring OFF stops new collection entirely.
        if (!monitoring_enabled_.load(std::memory_order_relaxed)) return;
        submitted_events_.fetch_add(1, std::memory_order_relaxed);

        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            const size_t event_chars = event.path.size() +
                event.old_path.size() + event.process_name.size();
            const bool low_value_temp = IsKnownTempPath(event.path) &&
                !IsExecutableExtension(event.path) &&
                (event.action == FileAction::CREATE ||
                    event.action == FileAction::WRITE ||
                    event.action == FileAction::DELETE_F);
            if (low_value_temp &&
                (event_queue_.size() >= TEMP_COALESCE_QUEUE_DEPTH ||
                    queued_event_chars_ + event_chars >
                    TEMP_COALESCE_QUEUE_CHARS))
            {
                coalesced_temp_events_.fetch_add(1,
                    std::memory_order_relaxed);
                return;
            }
            while (!event_queue_.empty() &&
                (event_queue_.size() >= MAX_EVENT_QUEUE_DEPTH ||
                    queued_event_chars_ + event_chars >
                    MAX_EVENT_QUEUE_CHARS))
            {
                const FileEvent& discarded = event_queue_.front();
                const size_t discarded_chars = discarded.path.size() +
                    discarded.old_path.size() +
                    discarded.process_name.size();
                queued_event_chars_ = discarded_chars <= queued_event_chars_
                    ? queued_event_chars_ - discarded_chars : 0;
                event_queue_.pop();
                dropped_events_.fetch_add(1, std::memory_order_relaxed);
            }
            if (event_chars > MAX_EVENT_QUEUE_CHARS)
            {
                dropped_events_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            event_queue_.push(event);
            queued_event_chars_ += event_chars;
        }

        queue_cv_.notify_one();
    }

    std::string FileMonitor::HashFile(const std::wstring& path)
    {
        return processor_ ? processor_->HashFileNow(path) : std::string{};
    }

    // =========================================================================
    // DispatchEvent
    //
    // FIX A: Normalise empty / "unknown" paths to L"unresolved" BEFORE calling
    // ClassifyEvent. ClassifyEvent drops empty paths, so without this fix every
    // WRITE/CLOSE event whose FileKey→path cache lookup missed was silently
    // discarded. Now those events reach FileProcessor as Bucket C and are
    // logged with path="unresolved".
    // =========================================================================
    void FileMonitor::DispatchEvent(const FileEvent& event)
    {
        // FIX A: work on a local copy so the original queue entry is unchanged
        FileEvent ev = event;
        if (ev.path.empty() || ev.path == L"unknown")
            ev.path = L"unresolved";
        else
            ev.path = NtPathToDosPath(ev.path);
        if (!ev.old_path.empty())
            ev.old_path = NtPathToDosPath(ev.old_path);

        // Never ingest the active JSONL output or its rotated archives. Without
        // this guard, writing a log record can produce another ETW file event
        // and create a self-sustaining feedback loop.
        if (IsInternalLogPath(ev.path))
            return;

        if (tracker_)
            tracker_->ObservePathTransition(ev);

        // BUG 3 FIX: Update churn for every event, regardless of which bucket
        // it will land in. Previously UpdateChurn was only called from
        // TempTracker::TrackEvent (Bucket B), so non-temp directories never
        // accumulated churn counts and IsHighChurnDirectory always returned
        // false — making the dynamic reclassification dead code.
        if (tracker_ && ev.path != L"unresolved")
            tracker_->RecordDirectoryEvent(ev.path);

        EventBucket bucket = ClassifyEvent(ev.path);

        if (tracker_ && bucket != EventBucket::B)
            tracker_->ObserveRelatedEvent(ev);

        // Dynamic high-churn rerouting (Bucket C → B when dir is churning)
        if (bucket == EventBucket::C && tracker_)
        {
            std::filesystem::path fp(ev.path);
            std::wstring dir = fp.has_parent_path()
                ? fp.parent_path().wstring()
                : ev.path;
            if (tracker_->IsHighChurnDirectory(dir))
                bucket = EventBucket::B;
        }

        switch (bucket)
        {
        case EventBucket::DROP:
            return; // only truly unresolvable events

        case EventBucket::A:
            if (processor_) processor_->ProcessEvent(ev);
            break;

        case EventBucket::B:
            if (tracker_)
            {
                bool elevated = tracker_->TrackEvent(ev);
                if (elevated && processor_)
                    processor_->ProcessEvent(ev);
            }
            break;

        case EventBucket::C:
            if (processor_) processor_->ProcessEvent(ev);
            break;
        }
    }

    bool FileMonitor::IsInternalLogPath(const std::wstring& path) const
    {
        if (path.empty() || path == L"unresolved") return false;
        const std::filesystem::path normalized =
            std::filesystem::path(path).lexically_normal();
        const std::wstring full = ToLower(normalized.wstring());
        if (full == internal_log_path_ || full == internal_baseline_path_ ||
            full == internal_baseline_path_ + L".tmp")
            return true;
        if (ToLower(normalized.parent_path().wstring()) != internal_log_directory_)
            return false;

        const std::wstring stem = ToLower(normalized.stem().wstring());
        return stem.rfind(internal_log_stem_ + L"_", 0) == 0 &&
            ToLower(normalized.extension().wstring()) ==
            ToLower(std::filesystem::path(internal_log_path_).extension().wstring());
    }

    // =========================================================================
    // MonitorLoop
    //
    // FIX B: Batch drain — each wakeup takes ALL pending events out of the
    // queue in a single lock acquisition, then processes them outside the lock.
    //
    // Previous behaviour: dequeue ONE event per wakeup, sleep up to 500ms,
    // repeat. With ETW firing hundreds of events per second the queue would
    // grow to 8192 and start dropping events. Consumer latency was up to 500ms
    // per event.
    //
    // New behaviour: wake up when any event arrives, grab everything in the
    // queue at once, release the lock, process the batch. Queue depth stays
    // near zero under normal load. Processing is still single-threaded
    // (no lock contention on map_mutex_ inside FileProcessor).
    // =========================================================================
    void FileMonitor::MonitorLoop()
    {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
        while (running_.load())
        {
            // ---------------------------------------------------------------
            // FIX B: Drain the entire queue under one lock acquisition.
            // ---------------------------------------------------------------
            std::vector<FileEvent> batch;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                queue_cv_.wait_for(
                    lock,
                    std::chrono::milliseconds(500),
                    [this]() -> bool {
                        return !event_queue_.empty() || !running_.load();
                    }
                );

                // Take everything that arrived while we were waiting
                batch.reserve(event_queue_.size());
                while (!event_queue_.empty())
                {
                    const FileEvent& queued = event_queue_.front();
                    const size_t chars = queued.path.size() +
                        queued.old_path.size() + queued.process_name.size();
                    queued_event_chars_ = chars <= queued_event_chars_
                        ? queued_event_chars_ - chars : 0;
                    batch.push_back(event_queue_.front());
                    event_queue_.pop();
                }
            } // lock released — ETW thread can keep submitting

            // Process the batch outside the lock
            for (const auto& ev : batch)
            {
                try { DispatchEvent(ev); }
                catch (...) {
                    processing_errors_.fetch_add(1,
                        std::memory_order_relaxed);
                }
            }

            PersistCollectorHealth(false);

            // Periodic maintenance (every 30 s)
            auto now = std::chrono::steady_clock::now();
            if (now - last_maintenance_ >= std::chrono::seconds(30))
            {
                last_maintenance_ = now;
                try
                {
                    if (processor_) processor_->CleanupStaleEntries();
                    if (processor_) processor_->SaveHashBaselines();
                    if (tracker_)   tracker_->Maintenance();
                    if (logger_)    logger_->Flush();

                    // RAM/disk auto-lightening.
                    pressure_monitor_.Update();
                    if (logger_)
                        logger_->SetMaxArchives(AdaptiveCap(
                            kBaseMaxArchives, kFloorMaxArchives, pressure_monitor_.GetFactor()));
                }
                catch (...) {
                    processing_errors_.fetch_add(1,
                        std::memory_order_relaxed);
                }
            }
        }

        // Final drain — process everything left in the queue on shutdown
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            while (!event_queue_.empty())
            {
                try { DispatchEvent(event_queue_.front()); }
                catch (...) {
                    processing_errors_.fetch_add(1,
                        std::memory_order_relaxed);
                }
                const FileEvent& queued = event_queue_.front();
                const size_t chars = queued.path.size() +
                    queued.old_path.size() + queued.process_name.size();
                queued_event_chars_ = chars <= queued_event_chars_
                    ? queued_event_chars_ - chars : 0;
                event_queue_.pop();
            }
        }

        // Santosh: "make sure that it is able to watch literally everything" --
        // active_writes_ is in-memory only; without this, any write whose
        // CLOSE event hadn't arrived yet (or that hadn't reached
        // MAX_WRITE_ENTRY_AGE_SECONDS via the periodic sweep above) was
        // silently lost the moment this process stopped. Unconditional, not
        // age-filtered -- shutdown is exactly the one moment nothing should
        // be left "waiting for later" that will never come.
        if (processor_) processor_->FlushAllActiveWrites();

        if (logger_) logger_->Flush();
    }

} // namespace titan::fim
