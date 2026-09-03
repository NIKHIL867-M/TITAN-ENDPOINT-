// usb_logger.cpp
#include "usb_logger.h"

#include <iostream>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <vector>

// ── Static member definitions ─────────────────────────────────────────────────
std::mutex    UsbLogger::s_mutex;
std::ofstream UsbLogger::s_file;
std::string   UsbLogger::s_logPath;
size_t        UsbLogger::s_maxSize = 2ULL * 1024 * 1024;   // 2 MB — rotate frequently, keep RAM low
size_t        UsbLogger::s_maxArchives = 20;                // cap rotated-archive count -- bounded disk use
size_t        UsbLogger::s_budgetMaxArchives = 20;
// FIX: was std::atomic<bool> — but s_initialized was only *read* atomically in
//      Log() before acquiring the mutex, then *written* inside the mutex in
//      Shutdown().  That creates a TOCTOU window: Log() could pass the atomic
//      check, then Shutdown() could close s_file before Log() re-acquires the
//      mutex and calls WriteLine().  Replacing with a plain bool and always
//      checking it inside the mutex eliminates the race entirely.
bool          UsbLogger::s_initialized = false;
const std::string UsbLogger::s_sessionId = MakeSessionId("port");
uint64_t      UsbLogger::s_nextRecordId = 1;
bool          UsbLogger::s_saveLogsEnabled = true;
std::deque<std::string> UsbLogger::s_recentLines;
uint64_t      UsbLogger::s_writeFailures = 0;
uint64_t      UsbLogger::s_rotationCount = 0;
const int64_t UsbLogger::s_startedAtUnixMs =
    std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

// ─────────────────────────────────────────────────────────────────────────────
static std::string TimestampForFilename()
{
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y%m%d_%H%M%S");
    return ss.str();
}

// ─────────────────────────────────────────────────────────────────────────────
bool UsbLogger::Initialize(const std::string& logPath, size_t maxSizeBytes, size_t maxArchives)
{
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return false;   // already open — caller error, not fatal

    s_logPath = logPath;
    s_maxSize = maxSizeBytes;
    s_maxArchives = maxArchives;

    // Create parent directory tree if absent.
    auto dir = std::filesystem::path(s_logPath).parent_path();
    if (!dir.empty() && !std::filesystem::exists(dir)) {
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        if (ec) {
            std::cerr << "[UsbLogger] Cannot create directory '"
                << dir.string() << "': " << ec.message() << '\n';
            return false;
        }
    }

    s_file.open(s_logPath, std::ios::app);
    if (!s_file.is_open()) {
        std::cerr << "[UsbLogger] Cannot open log file: " << s_logPath << '\n';
        return false;
    }

    s_initialized = true;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
void UsbLogger::Shutdown()
{
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    s_file.flush();
    s_file.close();
    s_initialized = false;
}

// ─────────────────────────────────────────────────────────────────────────────
void UsbLogger::Log(const std::string& json)
{
    if (json.empty()) return;

    std::lock_guard<std::mutex> lock(s_mutex);

    // Recorded regardless of s_initialized/save_logs so GetRecentLines()
    // still has something even with persistence off -- same bounded
    // live-view ring pattern as every other endpoint.
    s_recentLines.push_back(json);
    if (s_recentLines.size() > kRecentLinesCap) s_recentLines.pop_front();

    // FIX: s_initialized checked inside the mutex — no race with Shutdown().
    if (!s_initialized) {
        std::cerr << "[UsbLogger] Log() called before Initialize().\n";
        return;
    }
    if (!s_saveLogsEnabled) return; // FORU.TXT 4.3-4.5
    RotateIfNeeded();
    WriteLine(json);
}

// ─────────────────────────────────────────────────────────────────────────────
void UsbLogger::SetMaxArchives(size_t maxArchives)
{
    std::lock_guard<std::mutex> lock(s_mutex);
    s_maxArchives = maxArchives < s_budgetMaxArchives ? maxArchives : s_budgetMaxArchives;
}

void UsbLogger::SetRetentionMaxArchives(size_t maxArchives)
{
    std::lock_guard<std::mutex> lock(s_mutex);
    s_budgetMaxArchives = maxArchives;
    s_maxArchives = maxArchives;
}

// ─────────────────────────────────────────────────────────────────────────────
std::string UsbLogger::GetLogPath()
{
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_logPath;
}

// ─────────────────────────────────────────────────────────────────────────────
// RotateIfNeeded  — mutex must be held by caller
// ─────────────────────────────────────────────────────────────────────────────
void UsbLogger::RotateIfNeeded()
{
    if (!s_file.is_open()) return;
    s_file.flush();

    std::error_code ec;
    auto fileSize = std::filesystem::file_size(s_logPath, ec);
    if (ec || fileSize < s_maxSize) return;

    s_file.close();

    std::string rotated = s_logPath + '.' + TimestampForFilename();
    std::error_code renameEc;
    std::filesystem::rename(s_logPath, rotated, renameEc);
    if (renameEc) {
        std::cerr << "[UsbLogger] Rotation rename failed: "
            << renameEc.message() << '\n';
    }

    s_file.open(s_logPath, std::ios::app);
    if (!s_file.is_open()) {
        std::cerr << "[UsbLogger] Failed to reopen log after rotation.\n";
        s_initialized = false;  // mark as broken so callers get the error message
        s_writeFailures++;
    } else {
        s_rotationCount++;
    }

    PruneOldArchives();
}

// ─────────────────────────────────────────────────────────────────────────────
// PruneOldArchives  — mutex must be held by caller
//
// FIX: RotateIfNeeded previously rotated the active file at s_maxSize but
// never removed old archives -- unbounded disk growth via accumulating
// "usb_events.json.<timestamp>" files (the same problem the other endpoints
// were fixed for, just shifted from "one huge file" to "many files").
//
// Archive filenames embed a "%Y%m%d_%H%M%S" timestamp suffix, so lexical
// (string) sort order is identical to chronological order -- no need to
// parse timestamps back out.
// ─────────────────────────────────────────────────────────────────────────────
void UsbLogger::PruneOldArchives()
{
    std::error_code ec;
    auto logFile = std::filesystem::path(s_logPath);
    auto dir = logFile.parent_path();
    if (dir.empty()) dir = ".";
    if (!std::filesystem::exists(dir, ec)) return;

    const std::string prefix = logFile.filename().string() + ".";
    std::vector<std::filesystem::path> archives;

    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;
        const std::string name = entry.path().filename().string();
        if (name.rfind(prefix, 0) == 0)   // starts_with prefix
            archives.push_back(entry.path());
    }
    if (archives.size() <= s_maxArchives) return;

    std::sort(archives.begin(), archives.end());   // lexical == chronological
    size_t toRemove = archives.size() - s_maxArchives;
    for (size_t i = 0; i < toRemove; ++i) {
        std::error_code removeEc;
        std::filesystem::remove(archives[i], removeEc);
        if (removeEc) {
            std::cerr << "[UsbLogger] Failed to prune archive '"
                << archives[i].string() << "': " << removeEc.message() << '\n';
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WriteLine  — mutex must be held by caller
// ─────────────────────────────────────────────────────────────────────────────
void UsbLogger::WriteLine(const std::string& line)
{
    if (!s_file.is_open()) return;

    // FORU.TXT section 8: durable evidence identity, stamped at this single
    // choke point -- see evidence_envelope.h.
    std::error_code sizeEc;
    const uint64_t offsetBefore = std::filesystem::file_size(s_logPath, sizeEc);
    const std::string wrapped = WrapWithEvidenceEnvelope(line, s_nextRecordId++,
        s_sessionId, std::filesystem::path(s_logPath).filename().string(),
        sizeEc ? 0 : offsetBefore);

    s_file << wrapped << '\n';
    s_file.flush();
    if (!s_file) s_writeFailures++;
}

void UsbLogger::SetSaveLogsEnabled(bool enabled)
{
    std::lock_guard<std::mutex> lock(s_mutex);
    s_saveLogsEnabled = enabled;
}

bool UsbLogger::IsSaveLogsEnabled()
{
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_saveLogsEnabled;
}

std::vector<std::string> UsbLogger::GetRecentLines()
{
    std::lock_guard<std::mutex> lock(s_mutex);
    return std::vector<std::string>(s_recentLines.begin(), s_recentLines.end());
}

const std::string& UsbLogger::GetSessionId()
{
    return s_sessionId;
}

int64_t UsbLogger::GetStartedAtUnixMs()
{
    return s_startedAtUnixMs;
}

uint64_t UsbLogger::GetWriteFailureCount()
{
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_writeFailures;
}

uint64_t UsbLogger::GetRotationCount()
{
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_rotationCount;
}

std::pair<uint64_t, uint64_t> UsbLogger::GetRetainedBytesAndFiles()
{
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_logPath.empty()) return {0, 0};

    std::error_code ec;
    auto logFile = std::filesystem::path(s_logPath);
    auto dir = logFile.parent_path();
    if (dir.empty()) dir = ".";
    if (!std::filesystem::exists(dir, ec)) return {0, 0};

    const std::string prefix = logFile.filename().string();
    uint64_t totalBytes = 0;
    uint64_t totalFiles = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;
        const std::string name = entry.path().filename().string();
        if (name != prefix && name.rfind(prefix + ".", 0) != 0) continue;
        std::error_code sizeEc;
        const auto size = entry.file_size(sizeEc);
        if (!sizeEc) totalBytes += size;
        ++totalFiles;
    }
    return {totalBytes, totalFiles};
}

size_t UsbLogger::GetMaxFileBytes()
{
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_maxSize;
}

size_t UsbLogger::GetMaxArchives()
{
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_maxArchives;
}
