#include "file_logger.h"

// =============================================================================
// TITAN - File Integrity Monitor
// file_logger.cpp
//
// FIX: Removed std::ios::binary. Binary mode buffers writes internally and
// only flushes when the 8KB buffer fills or flush() is called. If the process
// is killed (VS Stop button) before that, the file stays 0 KB.
// Text mode + explicit flush() after every write = every line hits disk
// immediately, no matter how the process ends.
// =============================================================================

#include <filesystem>
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <algorithm>
#include <vector>
#include <winioctl.h>

namespace titan::fim
{

    FileLogger::FileLogger()
        : max_file_bytes_(256ULL * 1024)
        , bytes_written_(0)
        , initialized_(false)
    {
    }

    FileLogger::~FileLogger()
    {
        std::lock_guard<std::mutex> lock(log_mutex_);
        FlushExpiredAggregatesUnlocked(std::chrono::steady_clock::now(), true);
        if (log_stream_.is_open())
        {
            log_stream_.flush();
            log_stream_.close();
        }
    }

    bool FileLogger::Initialize(const std::wstring& log_path, uint64_t max_file_bytes)
    {
        std::lock_guard<std::mutex> lock(log_mutex_);

        try
        {
            if (log_stream_.is_open())
                log_stream_.close();
            initialized_ = false;
            log_path_ = log_path;
            max_file_bytes_ = max_file_bytes;
            if (max_file_bytes_ == 0)
            {
                std::cerr << "[FIM][Logger] max_file_bytes must be greater than zero\n";
                return false;
            }

            std::filesystem::path path(log_path);

            if (path.has_parent_path())
            {
                std::filesystem::create_directories(path.parent_path());
                EnableDirectoryCompression(path.parent_path());
            }

            // TEXT mode — no binary, so writes hit disk on flush() not on buffer fill
            log_stream_.open(path, std::ios::out | std::ios::app);

            if (!log_stream_.is_open())
            {
                std::cerr << "[FIM][Logger] Failed to open: " << path.string() << "\n";
                return false;
            }

            bytes_written_ = static_cast<uint64_t>(
                std::filesystem::exists(path) ? std::filesystem::file_size(path) : 0);

            initialized_ = true;
            rotation_started_ = std::chrono::steady_clock::now();

            std::cout << "[FIM][Logger] Initialized: " << path.string() << "\n";
            return true;
        }
        catch (const std::exception& ex)
        {
            std::cerr << "[FIM][Logger] Init error: " << ex.what() << "\n";
            return false;
        }
    }

    void FileLogger::Log(const std::string& json)
    {
        std::lock_guard<std::mutex> lock(log_mutex_);
        if (!initialized_ || json.empty()) return;
        try
        {
            if (!RotateIfNeeded()) return;
            log_stream_ << json << "\n";
            log_stream_.flush();  // hit disk immediately
            if (!log_stream_)
            {
                std::cerr << "[FIM][Logger] Write failed\n";
                log_stream_.clear();
                return;
            }
            bytes_written_ += json.size() + 1;
        }
        catch (const std::exception& ex)
        {
            std::cerr << "[FIM][Logger] Write error: " << ex.what() << "\n";
        }
    }

    void FileLogger::Log(const std::string& json, LogSeverity severity)
    {
        std::lock_guard<std::mutex> lock(log_mutex_);
        if (!initialized_ || json.empty()) return;
        WriteUnlocked(json, severity, 1);
    }

    void FileLogger::LogAggregated(const std::string& key,
        const std::string& json, LogSeverity severity)
    {
        if (key.empty())
        {
            Log(json, severity);
            return;
        }

        std::lock_guard<std::mutex> lock(log_mutex_);
        if (!initialized_ || json.empty()) return;
        const auto now = std::chrono::steady_clock::now();
        FlushExpiredAggregatesUnlocked(now, false);

        auto it = pending_.find(key);
        if (it != pending_.end())
        {
            if (now - it->second.last_seen <= std::chrono::seconds(2))
            {
                ++it->second.repeat_count;
                it->second.last_seen = now;
                return;
            }
            WriteUnlocked(it->second.json, it->second.severity,
                it->second.repeat_count);
            pending_.erase(it);
        }

        if (pending_.size() >= MAX_PENDING_LOG_AGGREGATES)
        {
            auto oldest = pending_.begin();
            for (auto candidate = pending_.begin();
                candidate != pending_.end(); ++candidate)
            {
                if (candidate->second.last_seen < oldest->second.last_seen)
                    oldest = candidate;
            }
            WriteUnlocked(oldest->second.json, oldest->second.severity,
                oldest->second.repeat_count);
            pending_.erase(oldest);
        }
        pending_.emplace(key, PendingRecord{ json, severity, 1, now });
    }

    void FileLogger::Flush()
    {
        std::lock_guard<std::mutex> lock(log_mutex_);
        FlushExpiredAggregatesUnlocked(std::chrono::steady_clock::now(), true);
        if (log_stream_.is_open()) log_stream_.flush();
    }

    bool FileLogger::WriteUnlocked(const std::string& json,
        LogSeverity severity, uint64_t repeat_count)
    {
        try
        {
            std::string enriched;
            enriched.reserve(json.size() + 64);
            if (!json.empty() && json.front() == '{')
            {
                enriched = "{\"severity\":\"";
                enriched += SeverityString(severity);
                enriched += "\",";
                enriched += json.substr(1);
                if (repeat_count > 1 && !enriched.empty() &&
                    enriched.back() == '}')
                {
                    enriched.pop_back();
                    enriched += ",\"repeat_count\":";
                    enriched += std::to_string(repeat_count);
                    enriched += "}";
                }
            }
            else
            {
                enriched = json;
            }

            {
                std::lock_guard<std::mutex> recentLock(recent_lines_mutex_);
                recent_lines_.push_back(enriched);
                if (recent_lines_.size() > kRecentLinesCap) recent_lines_.pop_front();
            }
            if (!save_logs_enabled_.load()) return true; // FORU.TXT 4.3-4.5

            if (!RotateIfNeeded()) return false;

            // FORU.TXT section 8: durable evidence identity, stamped at this
            // single choke point -- see evidence_envelope.h.
            const uint64_t recordId = next_record_id_.fetch_add(1, std::memory_order_relaxed);
            const std::string wrapped = WrapWithEvidenceEnvelope(enriched, recordId,
                session_id_, std::filesystem::path(log_path_).filename().string(), bytes_written_);

            log_stream_ << wrapped << "\n";
            log_stream_.flush();
            if (!log_stream_)
            {
                std::cerr << "[FIM][Logger] Write failed\n";
                log_stream_.clear();
                write_failures_.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
            bytes_written_ += wrapped.size() + 1;
            return true;
        }
        catch (const std::exception& ex)
        {
            std::cerr << "[FIM][Logger] Write error: " << ex.what() << "\n";
            write_failures_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }

    std::vector<std::string> FileLogger::GetRecentLines() const
    {
        std::lock_guard<std::mutex> lock(recent_lines_mutex_);
        return std::vector<std::string>(recent_lines_.begin(), recent_lines_.end());
    }

    std::pair<uint64_t, uint64_t> FileLogger::GetRetainedBytesAndFiles() const
    {
        std::error_code ec;
        std::filesystem::path dir = std::filesystem::path(log_path_).parent_path();
        if (!std::filesystem::exists(dir, ec)) return {0, 0};

        const std::string stem = std::filesystem::path(log_path_).stem().string();
        const std::string ext = std::filesystem::path(log_path_).extension().string();
        uint64_t totalBytes = 0;
        uint64_t totalFiles = 0;
        for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
            if (ec) break;
            if (!entry.is_regular_file()) continue;
            const auto& path = entry.path();
            if (path.extension().string() != ext) continue;
            if (path.filename().string() != (stem + ext) &&
                path.filename().string().rfind(stem + "_", 0) != 0) continue;
            std::error_code sizeEc;
            const auto size = entry.file_size(sizeEc);
            if (!sizeEc) totalBytes += size;
            ++totalFiles;
        }
        return {totalBytes, totalFiles};
    }

    void FileLogger::FlushExpiredAggregatesUnlocked(
        std::chrono::steady_clock::time_point now, bool all)
    {
        for (auto it = pending_.begin(); it != pending_.end(); )
        {
            if (all || now - it->second.last_seen > std::chrono::seconds(2))
            {
                WriteUnlocked(it->second.json, it->second.severity,
                    it->second.repeat_count);
                it = pending_.erase(it);
            }
            else
                ++it;
        }
    }

    bool FileLogger::RotateIfNeeded()
    {
        const bool size_due = bytes_written_ >= max_file_bytes_;
        const bool time_due = std::chrono::steady_clock::now() -
            rotation_started_ >= std::chrono::minutes(5);
        if (!size_due && !time_due) return log_stream_.is_open();

        if (log_stream_.is_open())
        {
            log_stream_.flush();
            log_stream_.close();
        }

        bool rotated_ok = false;
        try
        {
            std::filesystem::path current(log_path_);
            auto now = std::chrono::system_clock::now();
            auto now_t = std::chrono::system_clock::to_time_t(now);
            std::tm tm_info{};
            localtime_s(&tm_info, &now_t);

            std::ostringstream ts;
            const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()).count() % 1000;
            ts << std::put_time(&tm_info, "%Y%m%d_%H%M%S")
                << "_" << std::setw(3) << std::setfill('0') << millis;

            std::filesystem::path rotated =
                current.parent_path() /
                (current.stem().string() + "_" + ts.str() + current.extension().string());
            for (uint32_t suffix = 1; std::filesystem::exists(rotated); ++suffix)
            {
                rotated = current.parent_path() /
                    (current.stem().string() + "_" + ts.str() + "_" +
                        std::to_string(suffix) + current.extension().string());
            }

            std::filesystem::rename(current, rotated);
            rotated_ok = true;
            rotation_count_.fetch_add(1, std::memory_order_relaxed);
            std::cout << "[FIM][Logger] Rotated to: " << rotated.string() << "\n";
            PruneOldArchives(current);
        }
        catch (const std::exception& ex)
        {
            std::cerr << "[FIM][Logger] Rotation failed: " << ex.what() << "\n";
        }

        log_stream_.clear();
        log_stream_.open(log_path_, std::ios::out |
            (rotated_ok ? std::ios::trunc : std::ios::app));
        if (!log_stream_.is_open())
        {
            initialized_ = false;
            std::cerr << "[FIM][Logger] Could not reopen active log\n";
            return false;
        }
        bytes_written_ = rotated_ok ? 0 : static_cast<uint64_t>(
            std::filesystem::file_size(std::filesystem::path(log_path_)));
        rotation_started_ = std::chrono::steady_clock::now();
        return true;
    }

    void FileLogger::PruneOldArchives(const std::filesystem::path& current)
    {
        // Base 2 archives keep roughly 10 minutes / 768 KiB of recent
        // evidence during high-volume runs, which prevents an early event
        // in a two-minute investigation from being rotated away before
        // review. Adjustable at runtime -- see SetMaxArchives().
        const size_t MAX_ARCHIVES = max_archives_.load(std::memory_order_relaxed);
        std::vector<std::filesystem::directory_entry> archives;
        const std::string prefix = current.stem().string() + "_";
        for (const auto& entry : std::filesystem::directory_iterator(current.parent_path()))
        {
            if (!entry.is_regular_file()) continue;
            const auto& p = entry.path();
            const std::string name = p.filename().string();
            if (p.extension() == current.extension() && name.rfind(prefix, 0) == 0)
                archives.push_back(entry);
        }
        if (archives.size() <= MAX_ARCHIVES) return;
        std::sort(archives.begin(), archives.end(),
            [](const auto& a, const auto& b) {
                return a.last_write_time() < b.last_write_time();
            });
        for (size_t i = 0; i < archives.size() - MAX_ARCHIVES; ++i)
        {
            std::error_code ec;
            std::filesystem::remove(archives[i].path(), ec);
            if (ec)
                std::cerr << "[FIM][Logger] Archive cleanup failed: "
                    << ec.message() << "\n";
        }
    }

    const char* FileLogger::SeverityString(LogSeverity s)
    {
        switch (s)
        {
        case LogSeverity::INFO:     return "info";
        case LogSeverity::ALERT:    return "alert";
        case LogSeverity::WARNING:  return "warning";
        case LogSeverity::CRITICAL: return "critical";
        default:                    return "info";
        }
    }

    void FileLogger::EnableDirectoryCompression(
        const std::filesystem::path& directory)
    {
        HANDLE handle = CreateFileW(directory.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (handle == INVALID_HANDLE_VALUE) return;

        USHORT format = COMPRESSION_FORMAT_DEFAULT;
        DWORD returned = 0;
        if (!DeviceIoControl(handle, FSCTL_SET_COMPRESSION,
            &format, sizeof(format), nullptr, 0, &returned, nullptr))
        {
            const DWORD error = GetLastError();
            if (error != ERROR_INVALID_FUNCTION &&
                error != ERROR_NOT_SUPPORTED)
            {
                std::cerr << "[FIM][Logger] Directory compression unavailable: "
                    << error << "\n";
            }
        }
        CloseHandle(handle);
    }

} // namespace titan::fim
