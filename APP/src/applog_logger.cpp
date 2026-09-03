#include "titan_pch.h"
#include "applog_logger.h"

#include <deque>
#include <winioctl.h>

namespace {
constexpr uint32_t FLUSH_EVERY_RECORDS = 32;

bool IsStructurallyValidJsonObject(const std::string& line)
{
    if (line.size() < 2 || line.front() != '{' || line.back() != '}')
        return false;
    bool inString = false;
    bool escaped = false;
    int objectDepth = 0;
    int arrayDepth = 0;
    for (unsigned char character : line) {
        if (inString) {
            if (escaped) escaped = false;
            else if (character == '\\') escaped = true;
            else if (character == '"') inString = false;
            else if (character < 0x20) return false;
            continue;
        }
        if (character == '"') inString = true;
        else if (character == '{') ++objectDepth;
        else if (character == '}' && --objectDepth < 0) return false;
        else if (character == '[') ++arrayDepth;
        else if (character == ']' && --arrayDepth < 0) return false;
    }
    return !inString && !escaped && objectDepth == 0 && arrayDepth == 0;
}
}

bool AppLogLogger::Init(const std::filesystem::path& filePath,
    uint64_t maxFileBytes)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_initialized) return true;
    m_path = filePath;
    m_maxFileBytes = maxFileBytes;
    m_writeFailures.store(0);
    m_recoveredMalformedRecords.store(0);
    try {
        if (!m_path.parent_path().empty())
            std::filesystem::create_directories(m_path.parent_path());
    }
    catch (const std::exception& ex) {
        std::cerr << "[Logger] Directory creation failed: " << ex.what() << "\n";
        return false;
    }
    if (!RepairExistingJsonl() || !Open(true)) return false;
    EnableCompression();
    m_initialized = true;
    std::cout << "[Logger] JSONL: " << m_path.string() << "\n";
    return true;
}

bool AppLogLogger::RepairExistingJsonl()
{
    std::error_code error;
    if (!std::filesystem::exists(m_path, error) || error) return !error;
    std::ifstream input(m_path, std::ios::binary);
    if (!input) return false;
    const auto temporary = m_path.wstring() + L".repair";
    std::ofstream output(std::filesystem::path(temporary),
        std::ios::binary | std::ios::trunc);
    if (!output) return false;
    uint64_t invalid = 0;
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (IsStructurallyValidJsonObject(line))
            output << line << '\n';
        else if (!line.empty())
            ++invalid;
    }
    input.close();
    output.flush();
    output.close();
    if (invalid == 0) {
        DeleteFileW(temporary.c_str());
        return true;
    }
    if (!MoveFileExW(temporary.c_str(), m_path.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
        return false;
    }
    m_recoveredMalformedRecords.store(invalid);
    std::cerr << "[Logger] Recovered JSONL by removing " << invalid
        << " malformed record(s).\n";
    return true;
}

bool AppLogLogger::Open(bool append)
{
    m_file.clear();
    m_file.open(m_path, std::ios::out | std::ios::binary |
        (append ? std::ios::app : std::ios::trunc));
    if (!m_file.is_open()) {
        std::cerr << "[Logger] Failed to open: " << m_path.string() << "\n";
        return false;
    }
    std::error_code ec;
    m_bytesWritten = append && std::filesystem::exists(m_path, ec)
        ? std::filesystem::file_size(m_path, ec) : 0;
    m_unflushedRecords = 0;
    return true;
}

bool AppLogLogger::Write(const std::string& jsonEvent)
{
    {
        std::lock_guard<std::mutex> recentLock(m_recentLinesMutex);
        m_recentLines.push_back(jsonEvent);
        if (m_recentLines.size() > kRecentLinesCap) m_recentLines.pop_front();
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_saveLogsEnabled.load()) return true; // FORU.TXT 4.3-4.5: persistence off, not a failure
    if (!m_initialized || !m_file.is_open()) {
        m_writeFailures.fetch_add(1);
        return false;
    }
    if (!RotateIfNeeded(jsonEvent.size() + 1)) {
        m_writeFailures.fetch_add(1);
        return false;
    }

    // FORU.TXT section 8: durable evidence identity, stamped at this single
    // choke point -- see evidence_envelope.h.
    const uint64_t recordId = m_nextRecordId.fetch_add(1, std::memory_order_relaxed);
    const std::string wrapped = WrapWithEvidenceEnvelope(
        jsonEvent, recordId, m_sessionId, m_path.filename().string(), m_bytesWritten);

    m_file.write(wrapped.data(),
        static_cast<std::streamsize>(wrapped.size()));
    m_file.put('\n');
    if (!m_file.good()) {
        m_writeFailures.fetch_add(1);
        return false;
    }
    m_bytesWritten += wrapped.size() + 1;
    if (++m_unflushedRecords >= FLUSH_EVERY_RECORDS) {
        m_file.flush();
        m_unflushedRecords = 0;
    }
    return true;
}

std::vector<std::string> AppLogLogger::GetRecentLines() const
{
    std::lock_guard<std::mutex> lock(m_recentLinesMutex);
    return std::vector<std::string>(m_recentLines.begin(), m_recentLines.end());
}

std::pair<uint64_t, uint64_t> AppLogLogger::GetRetainedBytesAndFiles() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    uint64_t totalBytes = 0;
    uint64_t totalFiles = 0;
    const std::string prefix = m_path.stem().string() + "_";
    std::error_code ec;
    if (m_file.is_open()) {
        totalBytes += m_bytesWritten;
        ++totalFiles;
    }
    for (const auto& entry : std::filesystem::directory_iterator(m_path.parent_path(), ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;
        const auto& path = entry.path();
        if (path.extension() != m_path.extension() ||
            path.filename().string().rfind(prefix, 0) != 0) continue;
        std::error_code sizeEc;
        const auto size = entry.file_size(sizeEc);
        if (!sizeEc) totalBytes += size;
        ++totalFiles;
    }
    return {totalBytes, totalFiles};
}

void AppLogLogger::Flush()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_file.is_open()) m_file.flush();
    m_unflushedRecords = 0;
}

std::vector<std::string> AppLogLogger::ReadRecent(
    const std::string& filter, size_t limit)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_file.is_open()) m_file.flush();
    std::string loweredFilter = filter;
    std::transform(loweredFilter.begin(), loweredFilter.end(),
        loweredFilter.begin(), [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    std::deque<std::string> matches;
    std::vector<std::filesystem::directory_entry> files;
    const std::string prefix = m_path.stem().string() + "_";
    try {
        for (const auto& entry :
            std::filesystem::directory_iterator(m_path.parent_path())) {
            if (!entry.is_regular_file()) continue;
            const auto& path = entry.path();
            if (path == m_path ||
                (path.extension() == m_path.extension() &&
                    path.filename().string().rfind(prefix, 0) == 0))
                files.push_back(entry);
        }
    } catch (...) {
        return {};
    }
    std::sort(files.begin(), files.end(),
        [](const auto& left, const auto& right) {
            return left.last_write_time() < right.last_write_time();
        });
    for (const auto& file : files) {
        std::ifstream input(file.path(), std::ios::binary);
        std::string line;
        while (std::getline(input, line)) {
            std::string searchable = line;
            std::transform(searchable.begin(), searchable.end(),
                searchable.begin(), [](unsigned char character) {
                    return static_cast<char>(std::tolower(character));
                });
            if (!loweredFilter.empty() &&
                searchable.find(loweredFilter) == std::string::npos)
                continue;
            matches.push_back(std::move(line));
            if (matches.size() > limit) matches.pop_front();
        }
    }
    return { matches.begin(), matches.end() };
}

void AppLogLogger::Shutdown()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_file.is_open()) {
        m_file.flush();
        m_file.close();
    }
    m_initialized = false;
}

bool AppLogLogger::RotateIfNeeded(size_t incomingBytes)
{
    if (m_bytesWritten + incomingBytes <= m_maxFileBytes)
        return true;
    m_file.flush();
    m_file.close();
    try {
        const auto now = std::chrono::system_clock::now();
        const auto stamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        const auto archive = m_path.parent_path() /
            (m_path.stem().string() + "_" + std::to_string(stamp) +
                m_path.extension().string());
        std::filesystem::rename(m_path, archive);
        PruneArchives();
    }
    catch (const std::exception& ex) {
        std::cerr << "[Logger] Rotation failed: " << ex.what() << "\n";
        return Open(true);
    }
    return Open(false);
}

void AppLogLogger::PruneArchives()
{
    std::vector<std::filesystem::directory_entry> archives;
    const std::string prefix = m_path.stem().string() + "_";
    for (const auto& entry :
        std::filesystem::directory_iterator(m_path.parent_path())) {
        if (!entry.is_regular_file()) continue;
        const auto& path = entry.path();
        if (path.extension() == m_path.extension() &&
            path.filename().string().rfind(prefix, 0) == 0)
            archives.push_back(entry);
    }
    const size_t maxArchives = m_maxArchives.load(std::memory_order_relaxed);
    if (archives.size() <= maxArchives) return;
    std::sort(archives.begin(), archives.end(),
        [](const auto& a, const auto& b) {
            return a.last_write_time() < b.last_write_time();
        });
    for (size_t index = 0;
        index < archives.size() - maxArchives; ++index) {
        std::error_code ec;
        std::filesystem::remove(archives[index].path(), ec);
    }
}

void AppLogLogger::EnableCompression() const
{
    HANDLE handle = CreateFileW(m_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return;
    USHORT format = COMPRESSION_FORMAT_DEFAULT;
    DWORD returned = 0;
    DeviceIoControl(handle, FSCTL_SET_COMPRESSION,
        &format, sizeof(format), nullptr, 0, &returned, nullptr);
    CloseHandle(handle);
}
