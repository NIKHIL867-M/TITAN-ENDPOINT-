// usb_logger.h
#pragma once

#include "evidence_envelope.h"

#include <deque>
#include <fstream>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// UsbLogger
//
// Thread-safe append-only logger for USB session JSON summaries.
// Writes one JSON object per line (NDJSON / JSON-Lines format).
// Rotates the file by renaming it when it exceeds maxSizeBytes, then
// reopens a fresh file at the same path.
//
// Usage:
//   UsbLogger::Initialize("logs/usb.json");  // once at startup
//   UsbLogger::Log(jsonString);              // any thread
//   UsbLogger::Shutdown();                   // once at exit
//
// Thread-safety notes:
//   All public methods are mutex-guarded so they may be called concurrently.
//   FIX: s_initialized is now only checked and modified while holding s_mutex,
//        eliminating the previous TOCTOU race between the atomic load in Log()
//        and the file operations inside the same mutex scope.
// ─────────────────────────────────────────────────────────────────────────────
class UsbLogger {
public:
    // Open (or create) the log file at logPath.  Creates parent directories.
    // Returns true on success.  Returns false (no-op) if already initialized.
    // maxArchives bounds how many rotated (timestamped) archive files are
    // kept alongside the active log; the oldest are pruned on each rotation.
    static bool Initialize(const std::string& logPath,
        size_t             maxSizeBytes = 2ULL * 1024 * 1024,
        size_t             maxArchives = 20);

    // Adjusts the archive-retention cap at runtime (e.g. shrunk under
    // system RAM/disk pressure by ResourcePressureMonitor). Takes effect on
    // the next rotation's prune pass.
    static void SetMaxArchives(size_t maxArchives);
    static void SetRetentionMaxArchives(size_t maxArchives);
    static size_t GetMaxFileBytes();
    static size_t GetMaxArchives();

    // Flush and close the log file.
    static void Shutdown();

    // Append a JSON string as one line.  No-op if not initialized.
    static void Log(const std::string& json);

    // Returns the active log file path, or empty string if not initialized.
    static std::string GetLogPath();

    // FORU.TXT section 4.3-4.5: Save Logs is independent of Monitoring.
    static void SetSaveLogsEnabled(bool enabled);
    static bool IsSaveLogsEnabled();
    static std::vector<std::string> GetRecentLines();

    static const std::string& GetSessionId();
    static int64_t GetStartedAtUnixMs();
    static std::pair<uint64_t, uint64_t> GetRetainedBytesAndFiles();
    static uint64_t GetWriteFailureCount();
    static uint64_t GetRotationCount();

private:
    // Must be called with s_mutex held.
    static void RotateIfNeeded();
    static void WriteLine(const std::string& line);
    static void PruneOldArchives();

    static std::mutex    s_mutex;
    static std::ofstream s_file;
    static std::string   s_logPath;
    static size_t        s_maxSize;
    static size_t        s_maxArchives;
    static size_t        s_budgetMaxArchives;
    static bool          s_initialized;  // FIX: plain bool — always accessed under s_mutex

    // FORU.TXT section 8: durable evidence identity, stamped on every record
    // at the WriteLine() choke point -- see evidence_envelope.h. Rotation
    // here appends ".<timestamp>" to s_logPath rather than renaming it away
    // from a stable stem, so source_file (the live s_logPath's filename)
    // never goes stale the way Application's/File's do -- the live file
    // truly keeps its name across rotations here.
    static const std::string s_sessionId;
    static uint64_t s_nextRecordId;
    static bool s_saveLogsEnabled;
    static std::deque<std::string> s_recentLines;
    static constexpr size_t kRecentLinesCap = 500;
    static uint64_t s_writeFailures;
    static uint64_t s_rotationCount;
    static const int64_t s_startedAtUnixMs;
};
