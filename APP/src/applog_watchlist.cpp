#include "titan_pch.h"
#include "applog_watchlist.h"
#include <filesystem>
#include <tlhelp32.h>

namespace {
std::string NormalizeExecutableName(std::string value)
{
    while (!value.empty() &&
        std::isspace(static_cast<unsigned char>(value.front())))
        value.erase(value.begin());
    while (!value.empty() &&
        std::isspace(static_cast<unsigned char>(value.back())))
        value.pop_back();
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
        value = value.substr(1, value.size() - 2);
    value = std::filesystem::path(value).filename().string();
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    if (value.size() < 5 || value.substr(value.size() - 4) != ".exe")
        return {};
    return value;
}
}

// ─── Constructor ─────────────────────────────────────────────────────────────

AppLogWatchlist::AppLogWatchlist() {
    std::cout << "[Watchlist] Initialized. Max: "
        << MAX_WATCHLIST_SIZE << " apps.\n";
}

// ─── Add ─────────────────────────────────────────────────────────────────────

void AppLogWatchlist::Add(const std::string& appName) {
    const std::string key = NormalizeExecutableName(appName);
    if (key.empty()) {
        std::cerr << "[Watchlist] Invalid executable name: "
            << appName << "\n";
        return;
    }
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    if (m_entries.count(key)) {
        std::cout << "[Watchlist] Already watching: " << key << "\n";
        return;
    }
    if (m_entries.size() >= MAX_WATCHLIST_SIZE) {
        std::cerr << "[Watchlist] Capacity full. Cannot add: "
            << key << "\n";
        return;
    }

    WatchlistEntry entry;
    entry.appName = key;
    entry.active = false;
    m_entries[key] = std::move(entry);

    std::cout << "[Watchlist] Added: " << key
        << " (" << m_entries.size()
        << "/" << MAX_WATCHLIST_SIZE << ")\n";
}

// ─── Remove ──────────────────────────────────────────────────────────────────

void AppLogWatchlist::Remove(const std::string& appName) {
    const std::string key = NormalizeExecutableName(appName);
    if (key.empty()) {
        std::cout << "[Watchlist] Not found: " << appName << "\n";
        return;
    }
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    auto it = m_entries.find(key);
    if (it == m_entries.end()) {
        std::cout << "[Watchlist] Not found: " << appName << "\n";
        return;
    }
    for (DWORD pid : it->second.pids)
    {
        m_pidToName.erase(pid);
        m_pidToProcessName.erase(pid);
        m_pidToParent.erase(pid);
        m_pidToRoot.erase(pid);
    }
    m_entries.erase(it);
    std::cout << "[Watchlist] Removed: " << appName << "\n";
}

// ─── Contains ────────────────────────────────────────────────────────────────

bool AppLogWatchlist::Contains(const std::string& appName) const {
    const std::string key = NormalizeExecutableName(appName);
    if (key.empty()) return false;
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_entries.count(key) > 0;
}

// ─── GetAll ──────────────────────────────────────────────────────────────────

std::vector<WatchlistEntry> AppLogWatchlist::GetAll() const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    std::vector<WatchlistEntry> result;
    result.reserve(m_entries.size());
    for (const auto& kv : m_entries)
        result.push_back(kv.second);
    return result;
}

// ─── RefreshPIDs ─────────────────────────────────────────────────────────────

void AppLogWatchlist::RefreshPIDs() {
    auto snapshot = SnapshotProcesses();
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    std::unordered_set<DWORD> currentPids;
    for (const auto& [name, pids] : snapshot) {
        (void)name;
        currentPids.insert(pids.begin(), pids.end());
    }
    std::vector<std::pair<DWORD, std::string>> related;
    for (const auto& [pid, rootName] : m_pidToName) {
        const auto direct = snapshot.find(rootName);
        const bool isDirect = direct != snapshot.end() &&
            direct->second.contains(pid);
        if (!isDirect && currentPids.contains(pid))
            related.emplace_back(pid, rootName);
    }
    const auto previousProcessNames = m_pidToProcessName;
    const auto previousParents = m_pidToParent;
    const auto previousRoots = m_pidToRoot;
    m_pidToName.clear();
    m_pidToProcessName.clear();
    m_pidToParent.clear();
    m_pidToRoot.clear();

    for (auto& kv : m_entries) {
        auto it = snapshot.find(kv.first);
        if (it != snapshot.end()) {
            kv.second.pids = it->second;
            kv.second.active = !kv.second.pids.empty();
            for (DWORD pid : kv.second.pids) {
                m_pidToName[pid] = kv.first;
                m_pidToProcessName[pid] = kv.first;
                const auto previousRoot = previousRoots.find(pid);
                m_pidToRoot[pid] = previousRoot == previousRoots.end()
                    ? pid : previousRoot->second;
                const auto previousParent = previousParents.find(pid);
                if (previousParent != previousParents.end())
                    m_pidToParent[pid] = previousParent->second;
            }
        }
        else {
            kv.second.pids.clear();
            kv.second.active = false;
        }
    }
    for (const auto& [pid, rootName] : related) {
        const auto entry = m_entries.find(rootName);
        if (entry == m_entries.end()) continue;
        entry->second.pids.insert(pid);
        entry->second.active = true;
        m_pidToName[pid] = rootName;
        const auto processName = previousProcessNames.find(pid);
        m_pidToProcessName[pid] = processName == previousProcessNames.end()
            ? std::string{} : processName->second;
        const auto parent = previousParents.find(pid);
        if (parent != previousParents.end()) m_pidToParent[pid] = parent->second;
        const auto rootPid = previousRoots.find(pid);
        m_pidToRoot[pid] = rootPid == previousRoots.end() ? pid : rootPid->second;
    }
}

// ─── GetActivePIDs ───────────────────────────────────────────────────────────

std::vector<DWORD> AppLogWatchlist::GetActivePIDs() const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    std::vector<DWORD> pids;
    for (const auto& kv : m_entries)
        for (DWORD pid : kv.second.pids)
            pids.push_back(pid);
    return pids;
}

// ─── SnapshotProcesses ───────────────────────────────────────────────────────

std::unordered_map<std::string, std::unordered_set<DWORD>>
AppLogWatchlist::SnapshotProcesses() const
{
    std::unordered_map<std::string, std::unordered_set<DWORD>> result;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "[Watchlist] Snapshot failed: "
            << GetLastError() << "\n";
        return result;
    }

    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            std::string name;
            for (int i = 0; pe.szExeFile[i] != L'\0'; ++i)
                name += static_cast<char>(pe.szExeFile[i]);
            name = ToLower(name);
            result[name].insert(pe.th32ProcessID);
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return result;
}

// ─── ToLower ─────────────────────────────────────────────────────────────────

std::string AppLogWatchlist::ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
    return s;
}

bool AppLogWatchlist::IsWatchedPID(DWORD pid) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_pidToName.count(pid) != 0;
}

bool AppLogWatchlist::IsWatchedName(const std::string& appName) const {
    const std::string key = NormalizeExecutableName(appName);
    if (key.empty()) return false;
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_entries.count(key) != 0;
}

std::string AppLogWatchlist::NameForPID(DWORD pid) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    const auto it = m_pidToName.find(pid);
    return it == m_pidToName.end() ? std::string{} : it->second;
}

bool AppLogWatchlist::ObserveProcessStart(
    DWORD pid, const std::string& appName, DWORD parentPid) {
    const std::string key = ToLower(appName);
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    const auto it = m_entries.find(key);
    if (it == m_entries.end()) return false;
    it->second.pids.insert(pid);
    it->second.active = true;
    const auto parentApplication = m_pidToName.find(parentPid);
    const bool inheritsRoot = parentApplication != m_pidToName.end() &&
        parentApplication->second == key;
    DWORD inheritedRootPid = parentPid;
    if (inheritsRoot) {
        const auto inheritedRoot = m_pidToRoot.find(parentPid);
        if (inheritedRoot != m_pidToRoot.end())
            inheritedRootPid = inheritedRoot->second;
    }
    m_pidToName[pid] = key;
    m_pidToProcessName[pid] = key;
    if (parentPid != 0) m_pidToParent[pid] = parentPid;
    if (inheritsRoot) {
        m_pidToRoot[pid] = inheritedRootPid;
    }
    else {
        m_pidToRoot[pid] = pid;
    }
    return true;
}

bool AppLogWatchlist::ObserveRelatedProcessStart(
    DWORD pid, DWORD parentPid, const std::string& executableName)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    const auto parent = m_pidToName.find(parentPid);
    if (parent == m_pidToName.end()) return false;
    const auto root = m_entries.find(parent->second);
    if (root == m_entries.end()) return false;
    root->second.pids.insert(pid);
    root->second.active = true;
    m_pidToName[pid] = root->first;
    m_pidToProcessName[pid] = ToLower(executableName);
    m_pidToParent[pid] = parentPid;
    const auto rootPid = m_pidToRoot.find(parentPid);
    m_pidToRoot[pid] = rootPid == m_pidToRoot.end()
        ? parentPid : rootPid->second;
    return true;
}

bool AppLogWatchlist::ObserveProcessStop(DWORD pid) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    const auto found = m_pidToName.find(pid);
    if (found == m_pidToName.end()) return false;
    const std::string name = found->second;
    m_pidToName.erase(found);
    m_pidToProcessName.erase(pid);
    m_pidToParent.erase(pid);
    m_pidToRoot.erase(pid);
    const auto entry = m_entries.find(name);
    if (entry != m_entries.end()) {
        entry->second.pids.erase(pid);
        entry->second.active = !entry->second.pids.empty();
    }
    return true;
}

std::string AppLogWatchlist::ProcessNameForPID(DWORD pid) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    const auto it = m_pidToProcessName.find(pid);
    return it == m_pidToProcessName.end() ? std::string{} : it->second;
}

DWORD AppLogWatchlist::ParentPIDForPID(DWORD pid) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    const auto it = m_pidToParent.find(pid);
    return it == m_pidToParent.end() ? 0 : it->second;
}

DWORD AppLogWatchlist::RootPIDForPID(DWORD pid) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    const auto it = m_pidToRoot.find(pid);
    return it == m_pidToRoot.end() ? 0 : it->second;
}
