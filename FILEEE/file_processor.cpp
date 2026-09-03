
#include "file_logger.h"
#include "file_processor.h"
#include "_file_scope.h"

#include <windows.h>
#include <psapi.h>
#include <bcrypt.h>

#include <filesystem>
#include <sstream>
#include <iomanip>
#include <vector>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")

namespace titan::fim
{

    // =========================================================================
    // LRU PID cache
    //
    // Eliminates repeated OpenProcess calls for the same PID.
    // TTL of 5 seconds guards against PID recycling.
    // =========================================================================
    namespace
    {
        struct PidEntry
        {
            std::wstring name;
            std::chrono::steady_clock::time_point touched;
        };

        static constexpr size_t PID_CACHE_MAX = 512;
        static constexpr int    PID_CACHE_TTL_SECONDS = 5;

        static std::unordered_map<uint32_t, PidEntry> s_pid_cache;
        static std::mutex                              s_pid_mutex;

        void TraceEvent(const char* label, const std::string& json)
        {
#ifdef TITAN_FIM_VERBOSE_EVENTS
            std::cout << "[FIM][LOG] " << label << " -> "
                << json.substr(0, 120) << "\n";
#else
            (void)label;
            (void)json;
#endif
        }
    }

    // =========================================================================
    // Constructor / Destructor
    // =========================================================================

    FileProcessor::FileProcessor() : logger_(nullptr) {}
    FileProcessor::~FileProcessor() {}

    bool FileProcessor::Initialize(FileLogger* logger,
        const std::wstring& baseline_path)
    {
        if (!logger) return false;
        logger_ = logger;
        hash_baseline_path_ = baseline_path;
        LoadHashBaselines();
        return true;
    }

    // =========================================================================
    // ProcessEvent
    //
    // FIX 4: Normalise empty / "unknown" paths to "unresolved".
    // =========================================================================

    void FileProcessor::ProcessEvent(const FileEvent& event)
    {
        if (!logger_) return;

        try
        {
            FileEvent ev = event;
            if (ev.path.empty() || ev.path == L"unknown")
                ev.path = L"unresolved";

            switch (ev.action)
            {
            case FileAction::CREATE:   HandleCreate(ev);   break;
            case FileAction::WRITE:    HandleWrite(ev);    break;
            case FileAction::CLOSE:    HandleClose(ev);    break;
            case FileAction::DELETE_F: HandleDelete(ev);   break;
            case FileAction::RENAME:   HandleRename(ev);   break;
            case FileAction::SET_INFO: HandleSetInfo(ev);  break;
            default: break;
            }
        }
        catch (const std::exception& ex)
        {
            std::cerr << "[FIM][Processor] Exception: " << ex.what() << "\n";
        }
        catch (...) {}
    }

    // =========================================================================
    // Handlers
    // =========================================================================

    void FileProcessor::HandleCreate(const FileEvent& event)
    {
        FileEvent ev = event;
        if (ev.process_name.empty() || ev.process_name == L"unknown")
            ev.process_name = ResolveProcessName(ev.pid);

        bool is_protected = IsProtectedPath(ev.path);
        bool is_executable = IsExecutableExtension(ev.path);
        bool is_document = IsDocumentExtension(ev.path);
        ApplyHashEvidence(ev, true);

        LogSeverity sev = ScoreSeverity(FileAction::CREATE, ev.path, ev.process_name);
        std::string json = BuildJsonLog(ev, "", is_protected, is_executable, is_document, 0);

        TraceEvent("CREATE", json);
        logger_->LogAggregated("create|" + EscapeJsonString(ToLower(ev.path)) +
            "|" + ev.hash_status + "|" + ev.current_sha256,
            json, sev);
    }

    // =========================================================================
    // HandleWrite
    //
    // FIX (Bug C): ResolveProcessName called BEFORE acquiring map_mutex_.
    // =========================================================================
    void FileProcessor::HandleWrite(const FileEvent& event)
    {
        uint64_t key = WriteKey(event);

        // Resolve name before the lock — Win32 call outside of map_mutex_.
        std::wstring resolved_name = event.process_name;
        if (resolved_name.empty() || resolved_name == L"unknown")
            resolved_name = ResolveProcessName(event.pid);

        std::lock_guard<std::mutex> lock(map_mutex_);

        auto it = active_writes_.find(key);
        if (it != active_writes_.end())
        {
            it->second.last_write_time = std::chrono::steady_clock::now();
            it->second.write_count++;
            if ((it->second.process_name.empty() ||
                it->second.process_name == L"unknown") &&
                !resolved_name.empty() && resolved_name != L"unknown")
            {
                it->second.process_name = resolved_name;
            }
        }
        else
        {
            if (active_writes_.size() >= MAX_ACTIVE_WRITE_ENTRIES)
            {
                // Constant-time emergency eviction. Normal age-based cleanup
                // handles ordering; this branch exists only under overload.
                active_writes_.erase(active_writes_.begin());
                ++forced_write_evictions_;
                if (forced_write_evictions_ == 1 ||
                    forced_write_evictions_ % 1024 == 0)
                {
                    std::cerr << "[FIM][Processor] Active-write cap reached; "
                        "evicted oldest entry (total=" << forced_write_evictions_
                        << ")\n";
                }
            }
            ActiveWriteEntry entry;
            entry.path = event.path;
            entry.pid = event.pid;
            entry.tid = event.tid;
            entry.file_key = event.file_key;
            entry.is_protected = IsProtectedPath(event.path);
            entry.is_executable = IsExecutableExtension(event.path);
            entry.is_document = IsDocumentExtension(event.path);
            entry.last_write_time = std::chrono::steady_clock::now();
            entry.write_count = 1;
            entry.process_name = resolved_name;
            active_writes_[key] = std::move(entry);
        }
    }

    void FileProcessor::HandleClose(const FileEvent& event)
    {
        uint64_t         key = WriteKey(event);
        ActiveWriteEntry entry;
        bool             found = false;

        {
            std::lock_guard<std::mutex> lock(map_mutex_);
            auto it = active_writes_.find(key);
            if (it != active_writes_.end())
            {
                found = true;
                entry = it->second;
                active_writes_.erase(it);
            }
        }

        if (!found)
        {
            // Santosh: "watch literally everything" -- a CLOSE with no
            // matching WRITE entry used to be silently dropped, no record
            // at all. Real cause found live: ETW's real-time callback can
            // deliver Write/Close out of order for a very fast create-
            // write-close sequence (the exact shape of writing a small
            // file and closing it immediately), so the Close can arrive
            // before HandleWrite ever created the active_writes_ entry it
            // was expecting to find. This is still real, useful evidence
            // (a file WAS closed) even without the write-count/timing detail
            // a normally-paired record would have -- log it as a best-effort
            // CLOSE rather than discarding it outright.
            if (event.path == L"unresolved" || !logger_) return;

            FileEvent ev = event;
            if (ev.process_name.empty() || ev.process_name == L"unknown")
                ev.process_name = ResolveProcessName(ev.pid);
            const bool is_protected = IsProtectedPath(ev.path);
            const bool is_executable = IsExecutableExtension(ev.path);
            const bool is_document = IsDocumentExtension(ev.path);

            LogSeverity sev = ScoreSeverity(FileAction::CLOSE, ev.path, ev.process_name);
            std::string json = BuildJsonLog(ev, "", is_protected, is_executable, is_document, 0);

            TraceEvent("CLOSE(unpaired)", json);
            logger_->LogAggregated("close_unpaired|" + EscapeJsonString(ToLower(ev.path)),
                json, sev);
            return;
        }

        if (entry.path == L"unresolved" && event.path != L"unresolved")
            entry.path = event.path;

        std::string hash;
        if (entry.path != L"unresolved" &&
            (entry.is_executable || entry.is_document || entry.is_protected))
        {
            hash = ComputeSHA256(entry.path);
        }

        FileEvent final_event;
        final_event.action = FileAction::WRITE;
        final_event.path = entry.path;
        final_event.pid = entry.pid;
        final_event.tid = entry.tid;
        final_event.process_name = entry.process_name;
        final_event.file_key = entry.file_key;
        final_event.timestamp = std::chrono::system_clock::now();
        ApplyHashEvidence(final_event, false);
        if (!final_event.current_sha256.empty())
            hash = final_event.current_sha256;

        LogSeverity sev = ScoreSeverity(FileAction::WRITE, entry.path, entry.process_name);
        std::string json = BuildJsonLog(final_event, hash,
            entry.is_protected, entry.is_executable,
            entry.is_document, entry.write_count);

        TraceEvent("WRITE(close)", json);
        logger_->LogAggregated("write|" + EscapeJsonString(ToLower(entry.path)) +
            "|" + final_event.hash_status + "|" + final_event.current_sha256,
            json, sev);
    }

    void FileProcessor::HandleDelete(const FileEvent& event)
    {
        {
            uint64_t key = WriteKey(event);
            std::lock_guard<std::mutex> lock(map_mutex_);
            active_writes_.erase(key);
        }

        FileEvent ev = event;
        if (ev.process_name.empty() || ev.process_name == L"unknown")
            ev.process_name = ResolveProcessName(ev.pid);

        bool is_protected = IsProtectedPath(ev.path);
        bool is_executable = IsExecutableExtension(ev.path);
        bool is_document = IsDocumentExtension(ev.path);

        LogSeverity sev = ScoreSeverity(FileAction::DELETE_F, ev.path, ev.process_name);
        std::string json = BuildJsonLog(ev, "", is_protected, is_executable, is_document, 0);

        TraceEvent("DELETE", json);
        logger_->LogAggregated("delete|" + EscapeJsonString(ToLower(ev.path)),
            json, sev);

        {
            std::lock_guard<std::mutex> lock(map_mutex_);
            if (hash_baselines_.erase(ToLower(ev.path)) > 0)
                hash_baselines_dirty_ = true;
        }
    }

    void FileProcessor::HandleRename(const FileEvent& event)
    {
        FileEvent ev = event;
        if (ev.process_name.empty() || ev.process_name == L"unknown")
            ev.process_name = ResolveProcessName(ev.pid);

        bool dest_protected = IsProtectedPath(ev.path);
        bool dest_executable = IsExecutableExtension(ev.path);
        bool dest_document = IsDocumentExtension(ev.path);
        bool src_protected = !ev.old_path.empty() && IsProtectedPath(ev.old_path);
        if (!ev.old_path.empty())
        {
            std::lock_guard<std::mutex> lock(map_mutex_);
            auto old = hash_baselines_.find(ToLower(ev.old_path));
            if (old != hash_baselines_.end())
            {
                hash_baselines_[ToLower(ev.path)] = old->second;
                hash_baselines_.erase(old);
                hash_baselines_dirty_ = true;
            }
        }
        ApplyHashEvidence(ev, false);

        std::string hash;
        if (ev.path != L"unresolved" && (dest_executable || dest_document))
            hash = ComputeSHA256(ev.path);

        LogSeverity sev = ScoreSeverity(FileAction::RENAME, ev.path, ev.process_name);
        if (dest_protected && !src_protected && sev < LogSeverity::WARNING)
            sev = LogSeverity::WARNING;

        std::string json = BuildJsonLog(ev, hash, dest_protected, dest_executable,
            dest_document, 0);

        TraceEvent("RENAME", json);
        logger_->LogAggregated("rename|" + EscapeJsonString(ToLower(ev.path)) +
            "|" + ev.hash_status + "|" + ev.current_sha256,
            json, sev);

        if (!ev.old_path.empty())
        {
            std::lock_guard<std::mutex> lock(map_mutex_);
            if (hash_baselines_.erase(ToLower(ev.old_path)) > 0)
                hash_baselines_dirty_ = true;
        }
    }

    // =========================================================================
    // HandleSetInfo — FIX 3: logs all SET_INFO events
    // =========================================================================
    void FileProcessor::HandleSetInfo(const FileEvent& event)
    {
        if (event.path == L"unresolved") return;

        FileEvent ev = event;
        if (ev.process_name.empty() || ev.process_name == L"unknown")
            ev.process_name = ResolveProcessName(ev.pid);

        bool is_protected = IsProtectedPath(ev.path);
        bool is_startup = IsStartupPath(ev.path);
        bool is_executable = IsExecutableExtension(ev.path);
        bool is_document = IsDocumentExtension(ev.path);

        LogSeverity sev;
        if (is_startup)   sev = LogSeverity::CRITICAL;
        else if (is_protected) sev = LogSeverity::ALERT;
        else                   sev = LogSeverity::INFO;

        std::string json = BuildJsonLog(ev, "", is_protected || is_startup,
            is_executable, is_document, 0);

        TraceEvent("SETINFO", json);
        logger_->LogAggregated("set_info|" + EscapeJsonString(ToLower(ev.path)),
            json, sev);
    }

    // =========================================================================
    // CleanupStaleEntries
    // =========================================================================

    void FileProcessor::CleanupStaleEntries()
    {
        auto now = std::chrono::steady_clock::now();

        std::vector<ActiveWriteEntry> stale;
        {
            std::lock_guard<std::mutex> lock(map_mutex_);
            for (auto it = active_writes_.begin(); it != active_writes_.end(); )
            {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second.last_write_time).count();
                if (age > static_cast<long long>(MAX_WRITE_ENTRY_AGE_SECONDS))
                {
                    stale.push_back(it->second);
                    it = active_writes_.erase(it);
                }
                else ++it;
            }
        }

        FlushEntries(stale);
    }

    void FileProcessor::FlushAllActiveWrites()
    {
        std::vector<ActiveWriteEntry> all;
        {
            std::lock_guard<std::mutex> lock(map_mutex_);
            all.reserve(active_writes_.size());
            for (auto& [key, entry] : active_writes_) { (void)key; all.push_back(entry); }
            active_writes_.clear();
        }

        FlushEntries(all);
    }

    void FileProcessor::FlushEntries(const std::vector<ActiveWriteEntry>& entries)
    {
        for (const auto& entry : entries)
        {
            if (!logger_) continue;

            std::string hash;
            if (entry.path != L"unresolved" &&
                (entry.is_executable || entry.is_document || entry.is_protected))
            {
                hash = ComputeSHA256(entry.path);
            }

            FileEvent ev;
            ev.action = FileAction::WRITE;
            ev.path = entry.path;
            ev.pid = entry.pid;
            ev.tid = entry.tid;
            ev.process_name = entry.process_name;
            ev.file_key = entry.file_key;
            ev.timestamp = std::chrono::system_clock::now();

            LogSeverity sev = ScoreSeverity(FileAction::WRITE,
                entry.path, entry.process_name);
            logger_->Log(BuildJsonLog(ev, hash,
                entry.is_protected, entry.is_executable,
                entry.is_document, entry.write_count), sev);
        }
    }

    // =========================================================================
    // SHA-256 via BCrypt
    // =========================================================================

    std::string FileProcessor::ComputeSHA256(const std::wstring& path)
    {
        HANDLE file = CreateFileW(
            path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (file == INVALID_HANDLE_VALUE) return "";

        BCRYPT_ALG_HANDLE  alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;

        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        {
            CloseHandle(file); return "";
        }

        DWORD obj_size = 0, data_size = 0;
        if (!BCRYPT_SUCCESS(BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&obj_size), sizeof(DWORD), &data_size, 0))
            || obj_size == 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0); CloseHandle(file); return "";
        }

        std::vector<BYTE> obj_buf(obj_size);
        if (!BCRYPT_SUCCESS(BCryptCreateHash(
            alg, &hash, obj_buf.data(), obj_size, nullptr, 0, 0)))
        {
            BCryptCloseAlgorithmProvider(alg, 0); CloseHandle(file); return "";
        }

        std::vector<BYTE> buf(65536);
        DWORD bytes_read = 0;
        while (ReadFile(file, buf.data(), 65536, &bytes_read, nullptr) && bytes_read > 0)
            BCryptHashData(hash, buf.data(), bytes_read, 0);

        DWORD hash_len = 0;
        BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hash_len), sizeof(DWORD), &data_size, 0);

        std::vector<BYTE> hash_bytes(hash_len);
        BCryptFinishHash(hash, hash_bytes.data(), hash_len, 0);
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        CloseHandle(file);

        std::ostringstream ss;
        for (BYTE b : hash_bytes)
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        return ss.str();
    }

    void FileProcessor::ApplyHashEvidence(FileEvent& event,
        bool establish_baseline)
    {
        if (event.path.empty() || event.path == L"unresolved") return;
        const std::string current = ComputeSHA256(event.path);
        if (current.empty())
        {
            event.hash_status = "unavailable";
            return;
        }

        const std::wstring key = ToLower(event.path);
        const auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lock(map_mutex_);
        auto it = hash_baselines_.find(key);
        event.current_sha256 = current;
        event.hash_checked = true;

        if (it == hash_baselines_.end())
        {
            if (hash_baselines_.size() >= MAX_HASH_BASELINE_ENTRIES)
                hash_baselines_.erase(hash_baselines_.begin());
            hash_baselines_[key] = { current, now };
            hash_baselines_dirty_ = true;
            event.hash_status = establish_baseline
                ? "baseline_created" : "baseline_missing_created";
            return;
        }

        event.previous_sha256 = it->second.sha256;
        event.content_changed = event.previous_sha256 != current;
        event.hash_status = event.content_changed ? "changed" : "unchanged";
        it->second.sha256 = current;
        it->second.touched = now;
        hash_baselines_dirty_ = true;
    }

    std::string FileProcessor::HashFileNow(const std::wstring& path)
    {
        return ComputeSHA256(path);
    }

    void FileProcessor::LoadHashBaselines()
    {
        if (hash_baseline_path_.empty()) return;
        std::ifstream input(std::filesystem::path(hash_baseline_path_),
            std::ios::binary);
        if (!input) return;

        char magic[8] = {};
        uint32_t count = 0;
        input.read(magic, sizeof(magic));
        input.read(reinterpret_cast<char*>(&count), sizeof(count));
        if (!input || memcmp(magic, "TFIMH1", 6) != 0 ||
            count > MAX_HASH_BASELINE_ENTRIES)
            return;

        const auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lock(map_mutex_);
        for (uint32_t i = 0; i < count; ++i)
        {
            uint32_t units = 0;
            char hash[64] = {};
            input.read(reinterpret_cast<char*>(&units), sizeof(units));
            if (!input || units == 0 || units > 32768) break;
            std::wstring path(units, L'\0');
            input.read(reinterpret_cast<char*>(path.data()),
                static_cast<std::streamsize>(units * sizeof(wchar_t)));
            input.read(hash, sizeof(hash));
            if (!input) break;
            hash_baselines_[std::move(path)] =
                { std::string(hash, sizeof(hash)), now };
        }
        hash_baselines_dirty_ = false;
    }

    void FileProcessor::SaveHashBaselines()
    {
        if (hash_baseline_path_.empty()) return;
        std::vector<std::pair<std::wstring, std::string>> snapshot;
        {
            std::lock_guard<std::mutex> lock(map_mutex_);
            if (!hash_baselines_dirty_) return;
            snapshot.reserve(hash_baselines_.size());
            for (const auto& [path, entry] : hash_baselines_)
                snapshot.emplace_back(path, entry.sha256);
        }

        const std::filesystem::path target(hash_baseline_path_);
        const std::filesystem::path temporary =
            target.wstring() + L".tmp";
        try
        {
            std::filesystem::create_directories(target.parent_path());
            std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
            if (!output) return;
            char magic[8] = { 'T','F','I','M','H','1','\0','\0' };
            const uint32_t count = static_cast<uint32_t>(snapshot.size());
            output.write(magic, sizeof(magic));
            output.write(reinterpret_cast<const char*>(&count), sizeof(count));
            for (const auto& [path, hash] : snapshot)
            {
                const uint32_t units = static_cast<uint32_t>(path.size());
                output.write(reinterpret_cast<const char*>(&units), sizeof(units));
                output.write(reinterpret_cast<const char*>(path.data()),
                    static_cast<std::streamsize>(units * sizeof(wchar_t)));
                output.write(hash.data(), 64);
            }
            output.flush();
            output.close();
            if (MoveFileExW(temporary.c_str(), target.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            {
                std::lock_guard<std::mutex> lock(map_mutex_);
                hash_baselines_dirty_ = false;
            }
        }
        catch (const std::exception& ex)
        {
            std::cerr << "[FIM][Processor] Baseline save error: "
                << ex.what() << "\n";
        }
    }

    // =========================================================================
    // ScoreSeverity
    // =========================================================================

    LogSeverity FileProcessor::ScoreSeverity(
        FileAction          action,
        const std::wstring& path,
        const std::wstring& process_name) const
    {
        if (IsStartupPath(path))
            return LogSeverity::CRITICAL;

        bool is_protected = IsProtectedPath(path);
        bool is_executable = IsExecutableExtension(path);
        bool is_document = IsDocumentExtension(path);

        if (is_executable && is_protected &&
            (action == FileAction::CREATE ||
                action == FileAction::WRITE ||
                action == FileAction::RENAME ||
                action == FileAction::DELETE_F))
            return LogSeverity::CRITICAL;

        if (is_protected)
        {
            std::wstring p = ToLower(process_name);
            if (p.find(L"powershell") != std::wstring::npos ||
                p.find(L"cmd.exe") != std::wstring::npos ||
                p.find(L"wscript") != std::wstring::npos ||
                p.find(L"cscript") != std::wstring::npos ||
                p.find(L"mshta") != std::wstring::npos ||
                p.find(L"rundll32") != std::wstring::npos ||
                p.find(L"regsvr32") != std::wstring::npos ||
                p.find(L"certutil") != std::wstring::npos ||
                p.find(L"bitsadmin") != std::wstring::npos)
                return LogSeverity::CRITICAL;
        }

        if (is_executable &&
            (action == FileAction::CREATE ||
                action == FileAction::WRITE ||
                action == FileAction::RENAME))
            return LogSeverity::WARNING;

        if (is_protected) return LogSeverity::WARNING;

        if (is_document &&
            (action == FileAction::WRITE || action == FileAction::DELETE_F))
        {
            std::wstring p = ToLower(process_name);
            if (p.find(L"powershell") != std::wstring::npos ||
                p.find(L"cmd.exe") != std::wstring::npos ||
                p.find(L"wscript") != std::wstring::npos ||
                p.find(L"cscript") != std::wstring::npos)
                return LogSeverity::ALERT;
        }

        {
            std::wstring ext = GetExtension(path);
            if (ext == L".ps1" || ext == L".psm1" || ext == L".vbs" ||
                ext == L".vbe" || ext == L".js" || ext == L".jse" ||
                ext == L".hta" || ext == L".wsf" || ext == L".sct" ||
                ext == L".xsl" || ext == L".wsc")
                return LogSeverity::ALERT;
        }

        return LogSeverity::INFO;
    }

    // =========================================================================
    // ResolveProcessName — with LRU cache
    //
    // FIX (Win32 Bottleneck): Cache hit → return immediately with no Win32 call.
    // Cache miss → call OpenProcess once, store result.
    // TTL (5s) prevents stale names from PID recycling.
    // =========================================================================

    std::wstring FileProcessor::ResolveProcessName(uint32_t pid) const
    {
        if (pid == 0 || pid == 4) return L"System";

        auto now = std::chrono::steady_clock::now();

        // Check cache
        {
            std::lock_guard<std::mutex> lock(s_pid_mutex);
            auto it = s_pid_cache.find(pid);
            if (it != s_pid_cache.end())
            {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second.touched).count();
                if (age < PID_CACHE_TTL_SECONDS)
                {
                    it->second.touched = now; // refresh LRU timestamp
                    return it->second.name;
                }
                s_pid_cache.erase(it); // TTL expired, re-resolve below
            }
        }

        // Cache miss — call Win32
        std::wstring name = L"unknown";

        HANDLE proc = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
        if (proc)
        {
            wchar_t buf[MAX_PATH] = {};
            DWORD   sz = MAX_PATH;
            if (QueryFullProcessImageNameW(proc, 0, buf, &sz))
                name = std::filesystem::path(buf).filename().wstring();
            else if (GetModuleFileNameExW(proc, nullptr, buf, MAX_PATH))
                name = std::filesystem::path(buf).filename().wstring();
            CloseHandle(proc);
        }

        // Store in cache; evict LRU entry if full
        {
            std::lock_guard<std::mutex> lock(s_pid_mutex);
            if (s_pid_cache.size() >= PID_CACHE_MAX)
            {
                auto oldest = s_pid_cache.begin();
                for (auto it = s_pid_cache.begin(); it != s_pid_cache.end(); ++it)
                    if (it->second.touched < oldest->second.touched)
                        oldest = it;
                s_pid_cache.erase(oldest);
            }
            s_pid_cache[pid] = { name, now };
        }

        return name;
    }

    // =========================================================================
    // WriteKey
    // =========================================================================

    uint64_t FileProcessor::WriteKey(const FileEvent& ev)
    {
        if (ev.file_key != 0) return ev.file_key;
        return std::hash<std::wstring>{}(ev.path);
    }

    // =========================================================================
    // EscapeJsonString — UTF-16 → UTF-8 with JSON escaping
    // =========================================================================

    std::string FileProcessor::EscapeJsonString(const std::wstring& ws)
    {
        std::string out;
        out.reserve(ws.size() * 2);

        for (size_t i = 0; i < ws.size(); ++i)
        {
            uint32_t cp = static_cast<uint16_t>(ws[i]);

            if (cp >= 0xD800u && cp <= 0xDBFFu)
            {
                if (i + 1 < ws.size())
                {
                    uint32_t low = static_cast<uint16_t>(ws[i + 1]);
                    if (low >= 0xDC00u && low <= 0xDFFFu)
                    {
                        cp = 0x10000u + ((cp - 0xD800u) << 10) + (low - 0xDC00u);
                        ++i;
                    }
                    else cp = 0xFFFDu;
                }
                else cp = 0xFFFDu;
            }
            else if (cp >= 0xDC00u && cp <= 0xDFFFu)
                cp = 0xFFFDu;

            if (cp < 0x80u)
            {
                char c = static_cast<char>(cp);
                if (c == '"')  out += "\\\"";
                else if (c == '\\') out += "\\\\";
                else if (c == '\n') out += "\\n";
                else if (c == '\r') out += "\\r";
                else if (c == '\t') out += "\\t";
                else if (cp < 0x20u)
                {
                    char escaped[7] = {};
                    sprintf_s(escaped, "\\u%04X", static_cast<unsigned>(cp));
                    out += escaped;
                }
                else                out += c;
            }
            else if (cp < 0x800u)
            {
                out += static_cast<char>(0xC0u | (cp >> 6));
                out += static_cast<char>(0x80u | (cp & 0x3Fu));
            }
            else if (cp < 0x10000u)
            {
                out += static_cast<char>(0xE0u | (cp >> 12));
                out += static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu));
                out += static_cast<char>(0x80u | (cp & 0x3Fu));
            }
            else
            {
                out += static_cast<char>(0xF0u | (cp >> 18));
                out += static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu));
                out += static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu));
                out += static_cast<char>(0x80u | (cp & 0x3Fu));
            }
        }
        return out;
    }

    // =========================================================================
    // BuildJsonLog
    // =========================================================================

    std::string FileProcessor::BuildJsonLog(
        const FileEvent& event,
        const std::string& sha256,
        bool               is_protected,
        bool               is_executable,
        bool               is_document,
        uint32_t           write_count)
    {
        const char* action_str = "unknown";
        switch (event.action)
        {
        case FileAction::CREATE:   action_str = "create";   break;
        case FileAction::WRITE:    action_str = "write";    break;
        case FileAction::DELETE_F: action_str = "delete";   break;
        case FileAction::RENAME:   action_str = "rename";   break;
        case FileAction::CLOSE:    action_str = "close";    break;
        case FileAction::SET_INFO: action_str = "set_info"; break;
        default: break;
        }

        auto now_t = std::chrono::system_clock::to_time_t(event.timestamp);
        std::tm tm_info{};
        gmtime_s(&tm_info, &now_t);
        std::ostringstream ts;
        ts << std::put_time(&tm_info, "%Y-%m-%dT%H:%M:%SZ");

        std::ostringstream json;
        json << "{";
        json << "\"endpoint\":\"file_integrity\",";
        json << "\"action\":\"" << action_str << "\",";
        json << "\"path\":\"" << EscapeJsonString(event.path) << "\",";
        if (!event.old_path.empty())
            json << "\"old_path\":\"" << EscapeJsonString(event.old_path) << "\",";
        json << "\"pid\":" << event.pid << ",";
        json << "\"tid\":" << event.tid << ",";
        json << "\"process\":\"" << EscapeJsonString(event.process_name) << "\",";
        json << "\"timestamp\":\"" << ts.str() << "\",";
        // Shared, precision-normalized join key for a future cross-endpoint
        // Correlator -- this endpoint's own "timestamp" is whole-seconds
        // only (see ts above), so this carries the real millisecond value.
        json << "\"t_unix_ms\":"
            << std::chrono::duration_cast<std::chrono::milliseconds>(
                event.timestamp.time_since_epoch()).count() << ",";
        json << "\"protected\":" << (is_protected ? "true" : "false") << ",";
        json << "\"executable\":" << (is_executable ? "true" : "false") << ",";
        json << "\"document\":" << (is_document ? "true" : "false");
        if (write_count > 0)
            json << ",\"write_count\":" << write_count;
        if (!sha256.empty() && !event.hash_checked)
            json << ",\"sha256\":\"" << sha256 << "\"";
        if (event.hash_checked)
        {
            if (!event.previous_sha256.empty())
                json << ",\"previous_sha256\":\"" << event.previous_sha256 << "\"";
            json << ",\"current_sha256\":\"" << event.current_sha256 << "\"";
            json << ",\"hash_status\":\"" << event.hash_status << "\"";
            json << ",\"content_changed\":"
                << (event.content_changed ? "true" : "false");
        }
        else if (!event.hash_status.empty())
        {
            json << ",\"hash_status\":\"" << event.hash_status << "\"";
        }
        json << "}";
        return json.str();
    }

} // namespace titan::fim
