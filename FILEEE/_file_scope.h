#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <filesystem>
#include <windows.h>
#include <algorithm>
#include <cwctype>

namespace titan::fim
{

    // =========================================================================
    // LogSeverity
    //
    // Moved here from file_processor.h to break the circular dependency:
    //   file_logger.h → file_processor.h (old)
    //   file_logger.h → _file_scope.h    (new, no cycle)
    // =========================================================================
    enum class LogSeverity
    {
        INFO = 0,
        ALERT = 1,
        WARNING = 2,
        CRITICAL = 3
    };

    // =========================================================================
    // String helpers
    // =========================================================================

    inline std::wstring ToLower(const std::wstring& s)
    {
        std::wstring r = s;
        std::transform(r.begin(), r.end(), r.begin(), ::towlower);
        return r;
    }

    inline std::wstring ExpandEnvPath(const std::wstring& path)
    {
        DWORD len = ExpandEnvironmentStringsW(path.c_str(), nullptr, 0);
        if (len == 0) return path;
        std::vector<wchar_t> buf(len);
        DWORD written = ExpandEnvironmentStringsW(path.c_str(), buf.data(), len);
        if (written == 0 || written > len) return path;
        return std::wstring(buf.data());
    }

    // Returns lowercased extension including dot, e.g. L".exe"
    inline std::wstring GetExtension(const std::wstring& path)
    {
        std::filesystem::path p(path);
        return ToLower(p.extension().wstring());
    }

    // =========================================================================
    // NT → DOS path translation
    //
    // ETW delivers NT device paths: \Device\HarddiskVolume3\Windows\System32\...
    // All classification and protection checks use DOS paths:  C:\Windows\System32\...
    //
    // GetDeviceToDosMap() — built once at first call (thread-safe since C++11).
    //   Maps lowercase device path → drive letter  e.g.
    //   L"\\device\\harddiskvolume3" → L"C:"
    //
    // NtPathToDosPath() — translates a path if needed, otherwise returns as-is.
    //   Already-DOS paths (L"C:\...") are returned immediately (fast path).
    //   \??\ prefix (Object Manager redirect) is stripped first.
    //   \Device\... prefix is translated via the map.
    //   Unrecognised formats are returned unchanged (safe fallback).
    // =========================================================================

    inline const std::unordered_map<std::wstring, std::wstring>& GetDeviceToDosMap()
    {
        static const std::unordered_map<std::wstring, std::wstring> map = []()
            {
                std::unordered_map<std::wstring, std::wstring> m;
                wchar_t buf[512] = {};
                DWORD   len = GetLogicalDriveStringsW(511, buf);

                for (const wchar_t* p = buf; p < buf + len && *p; p += wcslen(p) + 1)
                {
                    if (p[1] != L':') continue;

                    wchar_t drive[3] = { p[0], L':', L'\0' };
                    wchar_t dev[512] = {};

                    if (QueryDosDeviceW(drive, dev, 511) > 0)
                        m[ToLower(dev)] = std::wstring(drive); // lowercase key
                }
                return m;
            }();
        return map;
    }

    inline std::wstring NtPathToDosPath(const std::wstring& path)
    {
        if (path.empty()) return path;

        // Fast path — already a DOS path (e.g. C:\Windows\...)
        if (path.size() >= 2 && path[1] == L':') return path;

        std::wstring lo = ToLower(path);

        // Strip Object Manager redirect prefix \??\  (e.g. \??\C:\...)
        if (lo.rfind(L"\\??\\", 0) == 0)
        {
            std::wstring inner = path.substr(4);
            if (inner.size() >= 2 && inner[1] == L':') return inner;
            return NtPathToDosPath(inner); // recurse once for \??\\Device\...
        }

        // Translate \Device\HarddiskVolumeX\...
        if (lo.rfind(L"\\device\\", 0) != 0) return path; // unknown format, leave as-is

        for (const auto& [dev_lower, letter] : GetDeviceToDosMap())
        {
            if (lo.rfind(dev_lower, 0) == 0 &&
                (lo.size() == dev_lower.size() || lo[dev_lower.size()] == L'\\'))
                return letter + path.substr(dev_lower.size()); // e.g. C: + \Windows\...
        }

        return path; // no matching drive found, return unchanged
    }

    // =========================================================================
    // Path lists — built once, returned by const reference (Bug D fix)
    // =========================================================================

    inline const std::vector<std::wstring>& GetProtectedPaths()
    {
        static const std::vector<std::wstring> paths = {
            ExpandEnvPath(L"%SystemRoot%\\System32"),
            ExpandEnvPath(L"%SystemRoot%\\System32\\drivers"),
            ExpandEnvPath(L"%SystemRoot%\\System32\\drivers\\etc"),
            ExpandEnvPath(L"%SystemRoot%\\SysWOW64"),
            ExpandEnvPath(L"%SystemRoot%\\System"),
            ExpandEnvPath(L"%SystemRoot%\\Boot"),
            ExpandEnvPath(L"%SystemRoot%\\Fonts"),
            ExpandEnvPath(L"%ProgramFiles%"),
            ExpandEnvPath(L"%ProgramFiles(x86)%"),
            ExpandEnvPath(L"%ProgramW6432%"),
            ExpandEnvPath(L"%USERPROFILE%\\Desktop"),
            ExpandEnvPath(L"%USERPROFILE%\\Documents"),
            ExpandEnvPath(L"%USERPROFILE%\\AppData\\Roaming"),
        };
        return paths;
    }

    inline const std::vector<std::wstring>& GetStartupPaths()
    {
        static const std::vector<std::wstring> paths = {
            ExpandEnvPath(L"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            ExpandEnvPath(L"%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            ExpandEnvPath(L"%SystemRoot%\\System32\\Tasks"),
            ExpandEnvPath(L"%SystemRoot%\\SysWOW64\\Tasks"),
            ExpandEnvPath(L"%SystemRoot%\\System32\\wbem\\Repository"),
            ExpandEnvPath(L"%SystemRoot%\\System32\\GroupPolicy\\Machine\\Scripts"),
            ExpandEnvPath(L"%SystemRoot%\\System32\\GroupPolicy\\User\\Scripts"),
        };
        return paths;
    }

    inline const std::vector<std::wstring>& GetKnownTempPaths()
    {
        static const std::vector<std::wstring> paths = {
            ExpandEnvPath(L"%SystemRoot%\\Temp"),
            ExpandEnvPath(L"%TEMP%"),
            ExpandEnvPath(L"%TMP%"),
            ExpandEnvPath(L"%USERPROFILE%\\AppData\\Local\\Temp"),
            ExpandEnvPath(L"%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\INetCache"),
            ExpandEnvPath(L"%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\WebCache"),
            ExpandEnvPath(L"%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache"),
            ExpandEnvPath(L"%USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache"),
            ExpandEnvPath(L"%SystemRoot%\\Prefetch"),
        };
        return paths;
    }

    // =========================================================================
    // Extension sets
    // =========================================================================

    inline const std::unordered_set<std::wstring> EXECUTABLE_EXTENSIONS = {
        L".exe", L".dll", L".sys", L".drv", L".ocx",
        L".bat", L".cmd", L".ps1", L".psm1",
        L".vbs", L".vbe", L".js",  L".jse", L".wsf",
        L".hta", L".scr", L".cpl", L".msi", L".com",
        L".pif", L".reg", L".inf", L".lnk",
        L".xsl", L".xslt", L".sct", L".wsc", L".application",
        L".jar", L".py", L".pyc", L".rb", L".pl",
    };

    inline const std::unordered_set<std::wstring> DOCUMENT_EXTENSIONS = {
        L".doc",  L".docx", L".xls",  L".xlsx", L".ppt",  L".pptx",
        L".odt",  L".ods",  L".odp",
        L".pdf",
        L".txt",  L".csv",  L".xml",  L".json", L".yaml", L".yml",
        L".conf", L".cfg",  L".toml",
        L".zip",  L".rar",  L".7z",   L".gz",   L".tar",  L".cab",
        L".iso",  L".img",
        L".pfx",  L".cer",  L".crt",  L".pem",  L".key",
        L".jpg",  L".jpeg", L".png",  L".gif",  L".bmp",  L".tiff",
    };

    // Low-priority extensions — routed to Bucket C, not dropped.
    inline const std::unordered_set<std::wstring> LOW_PRIORITY_EXTENSIONS = {
        L".etl",    // ETW trace log
        L".evtx",   // Event log
        L".pf",     // Prefetch
        L".mui",    // Multilingual UI resource
        L".db-shm", L".db-wal",
        L".msc",
        L".nls",
    };

    // =========================================================================
    // Thresholds
    // =========================================================================

    static constexpr uint64_t MIN_FILE_SIZE_BYTES = 512;
    static constexpr uint32_t WRITE_SETTLE_MS = 500;
    // Was 120s: a completed write with no observed CLOSE event (see
    // file_processor.cpp HandleClose/CleanupStaleEntries) sat invisible in
    // memory for up to two full minutes before this periodic sweep would
    // ever promote it to a real log record -- far longer than useful for a
    // live-monitored system, and long enough that a short monitoring
    // session could plausibly stop before it ever fires (that specific gap
    // is now separately closed by FlushAllActiveWrites() on shutdown, but
    // this value still governs how promptly a NORMAL, still-running session
    // surfaces evidence for a write it never saw a close for).
    static constexpr uint32_t MAX_WRITE_ENTRY_AGE_SECONDS = 10;
    static constexpr size_t   MAX_ACTIVE_WRITE_ENTRIES = 1024;
    static constexpr size_t   MAX_HASH_BASELINE_ENTRIES = 1024;
    static constexpr size_t   MAX_PENDING_LOG_AGGREGATES = 256;

    // TempTracker
    static constexpr uint32_t HIGH_CHURN_THRESHOLD = 500;
    static constexpr uint32_t TEMP_SHORT_LIFE_SECONDS = 60;
    static constexpr uint32_t TEMP_DEEP_WATCH_SECONDS = 300;
    static constexpr uint32_t TEMP_TRACKER_MAX_ENTRIES = 128;
    static constexpr uint32_t TEMP_OTHER_PID_LIMIT = 16;
    static constexpr size_t   DIR_CHURN_MAX_ENTRIES = 512;
    static constexpr uint32_t DIR_CHURN_IDLE_SECONDS = 300;

    // RAM Bomb fix: per-bucket files map is capped at this many detailed entries.
    // Files beyond this limit are counted in TempBucket::mass_file_count only.
    // Summary logs report: "N detailed + M aggregated".
    static constexpr uint32_t TEMP_BUCKET_DETAIL_LIMIT = 10;
    static constexpr size_t   RECENT_TEMP_FILE_LIMIT = 512;
    static constexpr size_t   RECENT_TEMP_FILES_PER_PID = 4;
    static constexpr uint32_t TEMP_RELATION_WINDOW_SECONDS = 10;

    // =========================================================================
    // Path helpers
    // =========================================================================

    inline bool PathStartsWith(const std::wstring& path, const std::wstring& base)
    {
        if (base.empty()) return false;
        std::wstring normalized_path = ToLower(path);
        std::wstring normalized_base = ToLower(base);
        while (normalized_base.size() > 3 &&
            (normalized_base.back() == L'\\' || normalized_base.back() == L'/'))
            normalized_base.pop_back();

        if (normalized_path.rfind(normalized_base, 0) != 0) return false;
        if (normalized_path.size() == normalized_base.size()) return true;
        return normalized_path[normalized_base.size()] == L'\\' ||
            normalized_path[normalized_base.size()] == L'/';
    }

    inline bool IsProtectedPath(const std::wstring& path)
    {
        for (const auto& base : GetProtectedPaths())
            if (!base.empty() && PathStartsWith(path, base)) return true;
        return false;
    }

    inline bool IsStartupPath(const std::wstring& path)
    {
        for (const auto& base : GetStartupPaths())
            if (!base.empty() && PathStartsWith(path, base)) return true;
        return false;
    }

    inline bool IsKnownTempPath(const std::wstring& path)
    {
        for (const auto& base : GetKnownTempPaths())
            if (!base.empty() && PathStartsWith(path, base)) return true;

        // Kernel ETW can report the same file as an NT device path
        // (\Device\HarddiskVolumeN\...) instead of a DOS drive path.  Match
        // well-known temp directory components as a representation-independent
        // fallback so rename transitions are not lost.
        const std::wstring normalized = ToLower(path);
        static constexpr const wchar_t* TEMP_COMPONENTS[] = {
            L"\\appdata\\local\\temp\\",
            L"\\windows\\temp\\",
            L"\\inetcache\\",
            L"\\temporary internet files\\"
        };
        for (const wchar_t* component : TEMP_COMPONENTS)
            if (normalized.find(component) != std::wstring::npos) return true;
        return false;
    }

    inline bool IsExecutableExtension(const std::wstring& path)
    {
        return EXECUTABLE_EXTENSIONS.count(GetExtension(path)) > 0;
    }

    inline bool IsDocumentExtension(const std::wstring& path)
    {
        return DOCUMENT_EXTENSIONS.count(GetExtension(path)) > 0;
    }

    inline bool IsLowPriorityExtension(const std::wstring& path)
    {
        return LOW_PRIORITY_EXTENSIONS.count(GetExtension(path)) > 0;
    }

    // Backward-compat alias
    inline bool IsIgnoredExtension(const std::wstring& path)
    {
        return IsLowPriorityExtension(path);
    }

    inline bool HasNoExtension(const std::wstring& path)
    {
        return std::filesystem::path(path).extension().empty();
    }

    // =========================================================================
    // EventBucket
    //
    //   DROP — only for truly unresolvable events (empty path).
    //   A    — protected path, startup path, or executable extension.
    //   B    — known temp/churn path OR dynamic churn zone.
    //   C    — everything else.
    //
    // NOTE: paths passed here must already be DOS paths. Normalisation from
    //       NT device paths is done once in FileMonitor::DispatchEvent before
    //       any path is touched by classification or processing logic.
    // =========================================================================

    enum class EventBucket { DROP, A, B, C };

    inline EventBucket ClassifyEvent(const std::wstring& path)
    {
        if (path.empty())
            return EventBucket::DROP;

        if (IsStartupPath(path))         return EventBucket::A;
        if (IsProtectedPath(path))       return EventBucket::A;
        if (IsExecutableExtension(path)) return EventBucket::A;
        if (IsKnownTempPath(path))       return EventBucket::B;

        return EventBucket::C;
    }

} // namespace titan::fim
