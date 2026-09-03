#include "logger.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <vector>

namespace titan {
    namespace {
        // FIX C4244: wstring->UTF-8 string without narrowing char<-wchar_t
        static std::string WstrToUtf8Log(const std::wstring& ws) {
            if (ws.empty()) return {};
            int n = WideCharToMultiByte(CP_UTF8, 0, ws.data(),
                static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
            if (n <= 0) return {};
            std::string s(static_cast<size_t>(n), '\0');
            WideCharToMultiByte(CP_UTF8, 0, ws.data(),
                static_cast<int>(ws.size()), s.data(), n, nullptr, nullptr);
            return s;
        }
    } // anonymous namespace


        // ============================================================================
        // CONSTRUCTOR / DESTRUCTOR
        // ============================================================================

    AsyncLogger::AsyncLogger(const std::wstring& log_dir)
        : log_dir_(log_dir), pressure_monitor_(log_dir) {
    }

    AsyncLogger::~AsyncLogger() { Shutdown(); }

    // ============================================================================
    // INITIALIZE
    // Creates the log directory, opens the first pack file, starts both threads.
    // ============================================================================

    bool AsyncLogger::Initialize() {
        std::lock_guard<std::mutex> lock(mutex_);

        std::error_code directory_error;
        std::filesystem::create_directories(
            std::filesystem::path(log_dir_), directory_error);
        if (directory_error) {
            storage_failures_.fetch_add(1, std::memory_order_relaxed);
            ConsoleLogger::LogError(
                "Failed to create log directory: " +
                directory_error.message());
            return false;
        }

        current_pack_path_ = NewPackPath();
        pack_file_.open(std::filesystem::path(current_pack_path_),
            std::ios::out | std::ios::trunc);

        if (!pack_file_.is_open()) {
            storage_failures_.fetch_add(1, std::memory_order_relaxed);
            ConsoleLogger::LogError(
                "Failed to open log pack: " +
                WstrToUtf8Log(current_pack_path_));
            return false;
        }

        running_ = true;
        worker_ = std::thread(&AsyncLogger::WorkerThread, this);

        ConsoleLogger::LogInfo(
            "Logger V4 started: " +
            WstrToUtf8Log(current_pack_path_));
        return true;
    }

    // ============================================================================
    // SHUTDOWN
    // Drains the queue completely before closing — no events lost on exit.
    // ============================================================================

    void AsyncLogger::Shutdown() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!running_)
                return;
            running_ = false;
        }

        cv_.notify_all();

        if (worker_.joinable())
            worker_.join();

        if (pack_file_.is_open()) {
            if (!pending_health_record_.empty())
                WriteJsonLine(pending_health_record_);
            pack_file_.flush();
            pack_file_.close();
        }
    }

    // ============================================================================
    // LOG EVENT
    // Waits up to 50 ms for queue capacity, then rejects and counts the event
    // if the fixed queue remains full.
    // ============================================================================

    void AsyncLogger::LogEvent(Event&& event) {
        {
            std::unique_lock<std::mutex> lock(mutex_);

            // Back-pressure: wait up to 50ms if queue is at capacity.
            // This keeps the pipeline honest — no silent loss.
            if (event_queue_.size() >= kMaxQueue) {
                cv_.wait_for(lock, std::chrono::milliseconds(50), [this] {
                    return event_queue_.size() < kMaxQueue || !running_;
                    });
            }

            if (!running_)
                return;
            if (event_queue_.size() >= kMaxQueue) {
                dropped_count_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            event_queue_.push(std::move(event));
            queued_count_.fetch_add(1, std::memory_order_relaxed);
        }
        cv_.notify_one();
    }

    // ============================================================================
    // LOG RAW (control_audit-style pre-built JSON lines)
    // ============================================================================

    void AsyncLogger::LogRaw(const std::string& json) {
        // Deliberately does NOT call RotateIfNeeded() -- that function takes
        // mutex_ itself (see below), and this is already inside the lock.
        // Same tradeoff Process's AsyncLogger::LogRaw already accepts: a
        // pack could grow slightly past kMaxFileBytes if only health/audit
        // records are written for a stretch with no regular events, and
        // rotation catches up on the next one -- harmless, not worth a
        // second lock-ordering path for.
        std::lock_guard<std::mutex> lock(mutex_);
        if (!pack_file_.is_open()) return;
        WriteJsonLine(json);
        written_count_.fetch_add(1, std::memory_order_relaxed);
        pack_file_.flush();
    }

    // ============================================================================
    // WORKER THREAD
    // Drains event_queue_ in batches, serialises each event as a JSON line.
    // ============================================================================

    void AsyncLogger::WorkerThread() {
        std::vector<Event> batch;
        batch.reserve(128);

        while (true) {
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this] { return !event_queue_.empty() || !running_; });

                if (!running_ && event_queue_.empty())
                    break;

                while (!event_queue_.empty() && batch.size() < 128) {
                    batch.push_back(std::move(event_queue_.front()));
                    event_queue_.pop();
                    queued_count_.fetch_sub(1, std::memory_order_relaxed);
                }
                in_flight_count_.fetch_add(
                    static_cast<uint64_t>(batch.size()),
                    std::memory_order_relaxed);
            }
            cv_.notify_all(); // wake Flush() after a batch leaves the queue

            for (auto& evt : batch) {
                RotateIfNeeded();
                std::string line = evt.ToJson();

                {
                    std::lock_guard<std::mutex> recentLock(recent_lines_mutex_);
                    recent_lines_.push_back(line);
                    if (recent_lines_.size() > kRecentLinesCap) recent_lines_.pop_front();
                }

                std::lock_guard<std::mutex> lock(mutex_);
                if (save_logs_enabled_.load()) {
                    WriteJsonLine(line);
                    written_count_.fetch_add(1, std::memory_order_relaxed);
                }

                forwarded_count_.fetch_add(1, std::memory_order_relaxed);
            }

            const uint64_t completed =
                static_cast<uint64_t>(batch.size());
            batch.clear();
            pack_file_.flush();
            in_flight_count_.fetch_sub(completed,
                std::memory_order_relaxed);
            cv_.notify_all();
        }
    }

    // ============================================================================
    // ============================================================================

    // ============================================================================
    // WRITE JSON LINE
    // Writes one JSONL line (newline-delimited JSON — no wrapping array).
    // Must be called with mutex_ held.
    // ============================================================================

    void AsyncLogger::WriteJsonLine(const std::string& json) {
        // FORU.TXT section 8: durable evidence identity stamped at this
        // single choke point -- see evidence_envelope.h.
        const uint64_t record_id = next_record_id_.fetch_add(1, std::memory_order_relaxed);
        const uint64_t offset_before = current_file_bytes_.load(std::memory_order_relaxed);
        const std::string wrapped = WrapWithEvidenceEnvelope(
            json, record_id, session_id_, NarrowFileName(current_pack_path_), offset_before);

        pack_file_ << wrapped << '\n';
        if (!pack_file_) {
            storage_failures_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        const uint64_t bytes_written = static_cast<uint64_t>(wrapped.size()) + 1ULL;
        current_file_bytes_.fetch_add(bytes_written, std::memory_order_relaxed);
    }

    std::string AsyncLogger::NarrowFileName(const std::wstring& path) {
        const auto slash = path.find_last_of(L"/\\");
        const std::wstring wide_name = (slash == std::wstring::npos) ? path : path.substr(slash + 1);
        std::string out;
        out.reserve(wide_name.size());
        for (wchar_t wc : wide_name) out.push_back(static_cast<char>(wc));
        return out;
    }

    std::vector<std::string> AsyncLogger::GetRecentLines() const {
        std::lock_guard<std::mutex> lock(recent_lines_mutex_);
        return std::vector<std::string>(recent_lines_.begin(), recent_lines_.end());
    }

    std::pair<uint64_t, uint64_t> AsyncLogger::GetRetainedBytesAndFiles() const {
        std::error_code ec;
        if (!std::filesystem::exists(log_dir_, ec)) return {0, 0};

        uint64_t total_bytes = 0;
        uint64_t total_files = 0;
        for (const auto& entry : std::filesystem::directory_iterator(log_dir_, ec)) {
            if (ec) break;
            if (!entry.is_regular_file()) continue;
            const auto& name = entry.path().filename().wstring();
            if (name.rfind(L"titan_", 0) != 0 || entry.path().extension() != L".jsonl") continue;
            std::error_code size_ec;
            const auto size = entry.file_size(size_ec);
            if (!size_ec) total_bytes += size;
            ++total_files;
        }
        return {total_bytes, total_files};
    }

    // ============================================================================
    // ROTATE IF NEEDED
    // Rolls to a new pack file when the current one exceeds kMaxFileBytes.
    // ============================================================================

    void AsyncLogger::RotateIfNeeded() {
        if (current_file_bytes_.load() < kMaxFileBytes)
            return;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            pack_file_.close();
            current_pack_path_ = NewPackPath();
            pack_file_.open(std::filesystem::path(current_pack_path_),
                std::ios::out | std::ios::trunc);
            if (!pack_file_.is_open()) {
                storage_failures_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            current_file_bytes_.store(0);
            rotation_count_.fetch_add(1, std::memory_order_relaxed);
            PruneOldPacks();
        }

        ConsoleLogger::LogInfo(
            "Log pack rotated: " +
            WstrToUtf8Log(current_pack_path_));
    }

    void AsyncLogger::LogHealthRecord(uint64_t capture_drops,
        uint64_t interface_drops, uint64_t raw_capture_failures,
        uint64_t structured_unparsed_packets,
        uint64_t suppressed_packets, bool monitoring_enabled, bool final_record) {
        // FIX (Round 3): this used to only ever be called once, at clean
        // shutdown, and stashed its result in pending_health_record_ --
        // written to disk ONLY by Shutdown()'s own explicit check. Now also
        // called periodically (agent.cpp's PrintStatus(), ~10s cadence)
        // while the agent is still running, so it writes immediately here
        // instead of deferring; Shutdown()'s pending_health_record_ check
        // is retained as a harmless no-op safety net (pending_health_record_
        // is simply never set now).
        //
        // Capture storage failures from every queued event before freezing
        // this health snapshot.
        Flush();
        const uint64_t logger_drops = dropped_count_.load();
        const uint64_t storage_failures = storage_failures_.load();
        const bool degraded = capture_drops != 0 ||
            interface_drops != 0 || logger_drops != 0 ||
            storage_failures != 0 || raw_capture_failures != 0;
        const auto health_now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const auto [retained_bytes, retained_files] = GetRetainedBytesAndFiles();
        static const std::string kExecutableHash = ComputeSelfExecutableSha256();
        std::ostringstream json;
        json << "{\"t_unix_ms\":" << health_now_ms
            // FIX: this endpoint's health record used only "record_type",
            // while the other 5 programs (and the Correlator's own
            // json_fields.h ExtractJsonString(..., "type", ...) parser) all
            // key on "type". Additive -- "record_type" kept unchanged for
            // anything already reading it -- so the Correlator can finally
            // recognize this endpoint's health records as collector_health.
            << ",\"type\":\"collector_health\","
            << "\"record_type\":\"collector_health\","
            << "\"schema_version\":2,"
            << "\"endpoint_id\":\"network\","
            << "\"pid\":" << GetCurrentProcessId() << ","
            << "\"executable_version\":\"release-manifest-2026-08-02-schema-v2\","
            << "\"executable_hash\":\"" << kExecutableHash << "\","
            << "\"started_at\":" << started_at_unix_ms_ << ","
            << "\"updated_at\":" << health_now_ms << ","
            << "\"collecting\":" << (monitoring_enabled ? "true" : "false") << ","
            << "\"persistence_enabled\":" << (save_logs_enabled_.load() ? "true" : "false") << ","
            << "\"final\":" << (final_record ? "true" : "false") << ","
            << "\"status\":\"" << (degraded ? "degraded" : "healthy")
            << "\",\"capture_drops\":" << capture_drops
            << ",\"interface_drops\":" << interface_drops
            << ",\"raw_capture_failures\":" << raw_capture_failures
            << ",\"structured_unparsed_packets\":"
            << structured_unparsed_packets
            << ",\"logger_drops\":" << logger_drops
            << ",\"storage_failures\":" << storage_failures
            << ",\"suppressed_packets\":" << suppressed_packets
            // Standardized cross-endpoint names (additive).
            << ",\"records_seen\":" << forwarded_count_.load()
            << ",\"records_written\":" << written_count_.load()
            << ",\"records_dropped\":" << logger_drops
            << ",\"parse_failures\":" << structured_unparsed_packets
            << ",\"source_loss\":" << (capture_drops + interface_drops)
            << ",\"writer_failures\":" << storage_failures
            << ",\"rotations\":" << rotation_count_.load()
            << ",\"retained_bytes\":" << retained_bytes
            << ",\"retained_files\":" << retained_files
            << ",\"evidence_gap\":" << (degraded ? "true" : "false")
            << ",\"resource_pressure\":\""
            << PressureTierToString(pressure_monitor_.GetTier()) << "\","
            << "\"shutdown_state\":\"" << (final_record ? "stopped" : "running") << "\","
            << "\"shutdown_ack\":" << (final_record ? "true" : "false") << ","
            << "\"last_error\":\"\""
            << "}";
        std::lock_guard<std::mutex> lock(mutex_);
        if (pack_file_.is_open())
            WriteJsonLine(json.str());
    }

    void AsyncLogger::PruneOldPacks() {
        std::vector<std::filesystem::directory_entry> packs;
        std::error_code error;
        for (const auto& entry :
            std::filesystem::directory_iterator(log_dir_, error)) {
            if (error || !entry.is_regular_file()) continue;
            const auto& path = entry.path();
            if (path.extension() == L".jsonl" &&
                path.filename().wstring().rfind(L"titan_", 0) == 0)
                packs.push_back(entry);
        }
        const size_t max_log_packs = max_log_packs_.load(std::memory_order_relaxed);
        if (packs.size() <= max_log_packs) return;
        std::sort(packs.begin(), packs.end(),
            [](const auto& left, const auto& right) {
                return left.last_write_time() < right.last_write_time();
            });
        for (size_t index = 0;
            index < packs.size() - max_log_packs; ++index) {
            if (packs[index].path() == current_pack_path_) continue;
            std::filesystem::remove(packs[index].path(), error);
            if (error) {
                storage_failures_.fetch_add(1,
                    std::memory_order_relaxed);
                error.clear();
            }
        }
    }

    // ============================================================================
    // NEW PACK PATH
    // Generates: <log_dir>\titan_YYYYMMDD_HHMMSS.jsonl
    // ============================================================================

    std::wstring AsyncLogger::NewPackPath() const {
        auto now = std::chrono::system_clock::now();
        auto tt = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
        localtime_s(&tm, &tt);

        wchar_t buf[64]{};
        wcsftime(buf, std::size(buf), L"%Y%m%d_%H%M%S", &tm);
        const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count() % 1000;
        return log_dir_ + L"titan_" + buf + L"_" +
            std::to_wstring(millis) + L".jsonl";
    }

    // ============================================================================
    // FLUSH  —  wait until queue is empty
    // ============================================================================

    void AsyncLogger::Flush() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] {
            return event_queue_.empty() &&
                in_flight_count_.load(std::memory_order_relaxed) == 0;
        });
    }

    // ============================================================================
    // CONSOLE LOGGER
    // ============================================================================

    void ConsoleLogger::LogInfo(const std::string& msg) {
        std::cout << "[INFO]  " << msg << '\n';
    }
    void ConsoleLogger::LogWarning(const std::string& msg) {
        std::cout << "[WARN]  " << msg << '\n';
    }
    void ConsoleLogger::LogError(const std::string& msg) {
        std::cerr << "[ERROR] " << msg << '\n';
    }

} // namespace titan
