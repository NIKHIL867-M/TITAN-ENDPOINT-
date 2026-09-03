#pragma once
#include "titan_pch.h"

#include <tlhelp32.h>

struct WatchlistEntry {
    std::string               appName;
    std::unordered_set<DWORD> pids;
    bool                      active{ false };
};

class AppLogWatchlist {
public:
    AppLogWatchlist();
    ~AppLogWatchlist() = default;

    void Add(const std::string& appName);
    void Remove(const std::string& appName);
    bool Contains(const std::string& appName) const;

    std::vector<WatchlistEntry> GetAll() const;
    void RefreshPIDs();
    std::vector<DWORD> GetActivePIDs() const;
    bool IsWatchedPID(DWORD pid) const;
    bool IsWatchedName(const std::string& appName) const;
    std::string NameForPID(DWORD pid) const;
    bool ObserveProcessStart(DWORD pid, const std::string& appName,
        DWORD parentPid = 0);
    bool ObserveRelatedProcessStart(
        DWORD pid, DWORD parentPid, const std::string& executableName);
    bool ObserveProcessStop(DWORD pid);
    std::string ProcessNameForPID(DWORD pid) const;
    DWORD ParentPIDForPID(DWORD pid) const;
    DWORD RootPIDForPID(DWORD pid) const;

    static constexpr size_t MAX_WATCHLIST_SIZE = 20;

private:
    std::unordered_map<std::string, std::unordered_set<DWORD>>
        SnapshotProcesses() const;

    static std::string ToLower(std::string s);

    std::unordered_map<std::string, WatchlistEntry> m_entries;
    std::unordered_map<DWORD, std::string>           m_pidToName;
    std::unordered_map<DWORD, std::string>           m_pidToProcessName;
    std::unordered_map<DWORD, DWORD>                 m_pidToParent;
    std::unordered_map<DWORD, DWORD>                 m_pidToRoot;
    mutable std::shared_mutex                        m_mutex;
};
