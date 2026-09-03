#pragma once
#include "titan_pch.h"
#include "evidence_envelope.h"
#include <chrono>
#include <deque>
#include <filesystem>
#include <fstream>
#include <utility>

class AppLogLogger {
public:
    static AppLogLogger& Instance()
    {
        static AppLogLogger instance;
        return instance;
    }

    bool Init(const std::filesystem::path& filePath,
        uint64_t maxFileBytes = 256ULL * 1024ULL);
    void Shutdown();
    bool Write(const std::string& jsonEvent);
    void Flush();
    std::vector<std::string> ReadRecent(
        const std::string& filter, size_t limit);
    const std::filesystem::path& Path() const { return m_path; }
    uint64_t WriteFailures() const { return m_writeFailures.load(); }
    uint64_t RecoveredMalformedRecords() const
    {
        return m_recoveredMalformedRecords.load();
    }

    // FORU.TXT section 4.3-4.5: Save Logs is independent of Monitoring.
    void SetSaveLogsEnabled(bool enabled) noexcept { m_saveLogsEnabled.store(enabled); }
    bool IsSaveLogsEnabled() const noexcept { return m_saveLogsEnabled.load(); }
    std::vector<std::string> GetRecentLines() const;

    const std::string& GetSessionId() const noexcept { return m_sessionId; }
    int64_t GetStartedAtUnixMs() const noexcept { return m_startedAtUnixMs; }
    // Walks the archive directory the same way PruneArchives() does and sums
    // size/count of every retained pack -- FORU.TXT section 5's
    // retained_bytes/retained_files.
    std::pair<uint64_t, uint64_t> GetRetainedBytesAndFiles() const;

    // RAM/disk auto-lightening: shrinks (or restores) the archive-retention
    // cap at runtime. Takes effect on the next rotation's prune pass.
    void SetMaxArchives(size_t maxArchives) noexcept
    {
        const auto budget = m_budgetMaxArchives.load(std::memory_order_relaxed);
        m_maxArchives.store(maxArchives < budget ? maxArchives : budget, std::memory_order_relaxed);
    }
    void SetRetentionMaxArchives(size_t maxArchives) noexcept
    {
        m_budgetMaxArchives.store(maxArchives, std::memory_order_relaxed);
        m_maxArchives.store(maxArchives, std::memory_order_relaxed);
    }
    uint64_t GetMaxFileBytes() const noexcept { return m_maxFileBytes; }
    size_t GetMaxArchives() const noexcept { return m_maxArchives.load(std::memory_order_relaxed); }

private:
    AppLogLogger() = default;
    ~AppLogLogger() { Shutdown(); }
    AppLogLogger(const AppLogLogger&) = delete;
    AppLogLogger& operator=(const AppLogLogger&) = delete;

    bool Open(bool append);
    bool RotateIfNeeded(size_t incomingBytes);
    void PruneArchives();
    void EnableCompression() const;
    bool RepairExistingJsonl();

    mutable std::mutex       m_mutex;
    std::ofstream            m_file;
    std::filesystem::path    m_path;
    uint64_t                 m_maxFileBytes = 256ULL * 1024ULL;
    uint64_t                 m_bytesWritten = 0;
    uint32_t                 m_unflushedRecords = 0;
    bool                     m_initialized = false;
    std::atomic<uint64_t>    m_writeFailures{ 0 };
    std::atomic<uint64_t>    m_recoveredMalformedRecords{ 0 };
    std::atomic<size_t>      m_maxArchives{ 2 };
    std::atomic<size_t>      m_budgetMaxArchives{ 2 };

    // FORU.TXT section 8: durable evidence identity, stamped on every record
    // at the single Write() choke point -- see evidence_envelope.h. NOTE:
    // this program's rotation scheme RENAMES the live file to a timestamped
    // archive name (rather than opening a new timestamped file each
    // rotation, like the other 5 endpoints) -- source_file below reflects
    // the filename AS OF the write; a record's source_file becomes stale
    // (points at the pre-rotation live name) once a LATER rotation renames
    // that file out from under it. Documented limitation, not fixed here --
    // matches this program's own pre-existing rotation design, unchanged.
    const std::string m_sessionId{MakeSessionId("application")};
    std::atomic<uint64_t> m_nextRecordId{1};
    std::atomic<bool> m_saveLogsEnabled{true};
    mutable std::mutex m_recentLinesMutex;
    std::deque<std::string> m_recentLines;
    static constexpr size_t kRecentLinesCap = 500;
    const int64_t m_startedAtUnixMs{
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()};
};
