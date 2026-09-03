#include <sdkddkver.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>

#include "applog_monitor.h"
#include "application_discovery.h"
#include "ipc_control_server.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <numeric>
#include <optional>
#include <string>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <atomic>

// ─── Graceful shutdown ────────────────────────────────────────────────────────

static std::atomic<bool> g_shutdown{ false };

static BOOL WINAPI ConsoleCtrlHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        std::cout << "\n[main] Shutdown signal received...\n";
        g_shutdown.store(true);
        return TRUE;
    }
    return FALSE;
}

// ─── Admin check ─────────────────────────────────────────────────────────────

static bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(
        &ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup))
    {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

// ─── Banner — ASCII only, no UTF-8 box chars (MSVC without /utf-8 safe) ──────

static void PrintBanner() {
    std::cout << "\n";
    std::cout << "============================================================\n";
    std::cout << "   TITAN -- Application Endpoint                            \n";
    std::cout << "   Selected Apps | PowerShell | WMI | Defender | Security   \n";
    std::cout << "   Press Ctrl+C to stop cleanly                              \n";
    std::cout << "============================================================\n";
    std::cout << "\n";
}

// ─── Menu ─────────────────────────────────────────────────────────────────────

static void PrintMenu() {
    std::cout << "\n";
    std::cout << "+--------------------------------------------------+\n";
    std::cout << "|  apps [search]   -- show/refresh applications    |\n";
    std::cout << "|  next            -- show next application page   |\n";
    std::cout << "|  watch <name/#>  -- monitor app (typos accepted) |\n";
    std::cout << "|  unwatch <name/#>-- stop monitoring app          |\n";
    std::cout << "|  add/rem <name>  -- aliases for watch/unwatch    |\n";
    std::cout << "|  activity [app]  -- show recent behavior JSON    |\n";
    std::cout << "|  list | status   -- watchlist / collector status |\n";
    std::cout << "|  help | quit     -- commands / clean shutdown    |\n";
    std::cout << "+--------------------------------------------------+\n";
    std::cout << "> ";
}

static std::filesystem::path ConfigurationPath()
{
    wchar_t executable[32768]{};
    const DWORD length = GetModuleFileNameW(nullptr, executable,
        static_cast<DWORD>(std::size(executable)));
    if (length == 0 || length >= std::size(executable)) return {};
    return std::filesystem::path(executable).parent_path() /
        L"config" / L"watchlist.txt";
}

static std::vector<std::string> LoadSelection()
{
    std::vector<std::string> names;
    std::ifstream input(ConfigurationPath());
    std::string name;
    while (std::getline(input, name)) {
        if (!name.empty() && name.front() != '#') names.push_back(name);
    }
    return names;
}

static void SaveSelection(const AppLogMonitor& monitor)
{
    const auto path = ConfigurationPath();
    if (path.empty()) return;
    std::error_code error;
    std::filesystem::create_directories(path.parent_path(), error);
    if (error) {
        std::cerr << "[Config] Cannot create directory: "
            << error.message() << "\n";
        return;
    }
    const auto temporary = path.wstring() + L".tmp";
    {
        std::ofstream output(std::filesystem::path(temporary),
            std::ios::trunc);
        if (!output) {
            std::cerr << "[Config] Cannot save watchlist.\n";
            return;
        }
        output << "# One executable filename per line. Maximum 20.\n";
        for (const auto& name : monitor.WatchlistNames())
            output << name << "\n";
    }
    if (!MoveFileExW(temporary.c_str(), path.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::cerr << "[Config] Cannot replace watchlist: "
            << GetLastError() << "\n";
        DeleteFileW(temporary.c_str());
    }
}

static void PrintApplications(
    const std::vector<DiscoveredApplication>& applications, size_t offset = 0)
{
    constexpr size_t pageSize = 25;
    if (offset >= applications.size() && !applications.empty()) offset = 0;
    const size_t end = std::min(applications.size(), offset + pageSize);
    std::cout << "[Applications] " << applications.size()
        << " matching executable(s)";
    if (!applications.empty())
        std::cout << "; showing " << (offset + 1) << "-" << end;
    std::cout << "\n";
    for (size_t index = offset; index < end; ++index) {
        const auto& app = applications[index];
        std::cout << "  " << (index + 1) << ") " << app.display_name
            << " [" << app.executable << "] "
            << (app.IsRunning() ? "RUNNING" : "installed");
        if (app.IsRunning())
            std::cout << " (" << app.pids.size()
                << (app.pids.size() == 1 ? " process)" : " processes)");
        std::cout << "\n";
    }
    std::cout << "[Applications] Use: watch <name/number>";
    if (end < applications.size()) std::cout << " | next for more";
    std::cout << "\n";
}

static bool ParseIndex(const std::string& value, size_t& index)
{
    try {
        size_t consumed = 0;
        const unsigned long long parsed = std::stoull(value, &consumed);
        if (consumed != value.size() || parsed == 0) return false;
        index = static_cast<size_t>(parsed - 1);
        return true;
    } catch (...) {
        return false;
    }
}

static std::string Lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value;
}

static size_t EditDistance(const std::string& left, const std::string& right)
{
    std::vector<size_t> previous(right.size() + 1);
    std::vector<size_t> current(right.size() + 1);
    std::iota(previous.begin(), previous.end(), size_t{ 0 });
    for (size_t row = 1; row <= left.size(); ++row) {
        current[0] = row;
        for (size_t column = 1; column <= right.size(); ++column) {
            const size_t substitution = previous[column - 1] +
                (left[row - 1] == right[column - 1] ? 0U : 1U);
            current[column] = std::min({
                previous[column] + 1,
                current[column - 1] + 1,
                substitution });
        }
        previous.swap(current);
    }
    return previous.back();
}

static std::optional<std::string> ResolveDiscoveredApplication(
    const std::string& input,
    const std::vector<DiscoveredApplication>& applications,
    bool& corrected)
{
    corrected = false;
    const std::string query = Lower(input);
    if (query.empty()) return std::nullopt;
    for (const auto& application : applications) {
        const std::string executable = Lower(application.executable);
        const std::string stem = Lower(std::filesystem::path(
            application.executable).stem().string());
        const std::string display = Lower(application.display_name);
        if (query == executable || query == stem || query == display)
            return application.executable;
    }
    std::vector<const DiscoveredApplication*> substringMatches;
    for (const auto& application : applications) {
        const std::string searchable = Lower(application.display_name + " " +
            application.executable);
        if (searchable.find(query) != std::string::npos)
            substringMatches.push_back(&application);
    }
    if (substringMatches.size() == 1)
        return substringMatches.front()->executable;

    size_t bestDistance = std::numeric_limits<size_t>::max();
    const DiscoveredApplication* best = nullptr;
    bool tied = false;
    for (const auto& application : applications) {
        const std::string stem = Lower(std::filesystem::path(
            application.executable).stem().string());
        const size_t distance = EditDistance(query, stem);
        if (distance < bestDistance) {
            bestDistance = distance;
            best = &application;
            tied = false;
        } else if (distance == bestDistance) {
            tied = true;
        }
    }
    const size_t threshold = std::max<size_t>(2, query.size() / 4);
    if (best && !tied && bestDistance <= threshold) {
        corrected = true;
        return best->executable;
    }
    return std::nullopt;
}

static std::optional<std::string> ResolveSelectedApplication(
    const std::string& input, const std::vector<std::string>& selected)
{
    const std::string query = Lower(input);
    for (const auto& name : selected) {
        const std::string stem = Lower(
            std::filesystem::path(name).stem().string());
        if (query == Lower(name) || query == stem) return name;
    }
    size_t bestDistance = std::numeric_limits<size_t>::max();
    std::optional<std::string> best;
    for (const auto& name : selected) {
        const size_t distance = EditDistance(query, Lower(
            std::filesystem::path(name).stem().string()));
        if (distance < bestDistance) {
            bestDistance = distance;
            best = name;
        }
    }
    return bestDistance <= std::max<size_t>(2, query.size() / 4)
        ? best : std::nullopt;
}

static void RunInteractiveMenu(AppLogMonitor& monitor) {
    std::string line;
    std::vector<DiscoveredApplication> discovered =
        ApplicationDiscovery::Discover();
    size_t applicationPage = 0;
    PrintApplications(discovered, applicationPage);
    PrintMenu();

    while (!g_shutdown.load()) {
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) {
            std::cout << "> ";
            continue;
        }

        // Split into command + optional argument
        std::string cmd;
        std::string arg;
        auto space = line.find(' ');
        if (space != std::string::npos) {
            cmd = line.substr(0, space);
            arg = line.substr(space + 1);
            auto start = arg.find_first_not_of(' ');
            arg = (start == std::string::npos) ? "" : arg.substr(start);
        }
        else {
            cmd = line;
        }

        // Lowercase command
        for (char& c : cmd)
            c = static_cast<char>(
                std::tolower(static_cast<unsigned char>(c)));

        if (cmd == "quit" || cmd == "exit" || cmd == "q") {
            g_shutdown.store(true);
            break;
        }
        else if (cmd == "add" || cmd == "watch") {
            if (arg.empty()) {
                std::cout << "[!] Usage: watch <application name or number>\n";
            } else {
                size_t index = 0;
                std::optional<std::string> resolved;
                bool corrected = false;
                if (ParseIndex(arg, index) && index < discovered.size())
                    resolved = discovered[index].executable;
                else
                    resolved = ResolveDiscoveredApplication(
                        arg, discovered, corrected);
                if (!resolved) {
                    const auto matches = ApplicationDiscovery::Discover(arg);
                    if (matches.size() == 1) {
                        resolved = matches.front().executable;
                        std::cout << "[Applications] Matched '" << arg
                            << "' to " << *resolved << ".\n";
                    } else if (!matches.empty()) {
                        discovered = matches;
                        applicationPage = 0;
                        PrintApplications(discovered, applicationPage);
                    } else {
                        std::cout << "[!] No application matched '" << arg
                            << "'. Run 'apps' to see all choices.\n";
                    }
                    if (!resolved) {
                        std::cout << "> ";
                        continue;
                    }
                }
                if (corrected)
                    std::cout << "[Applications] Interpreting '" << arg
                        << "' as " << *resolved << ".\n";
                monitor.AddToWatchlist(*resolved);
                SaveSelection(monitor);
            }
        }
        else if (cmd == "rem" || cmd == "remove" ||
            cmd == "unwatch" || cmd == "unselect") {
            const auto selected = monitor.WatchlistNames();
            size_t index = 0;
            std::optional<std::string> resolved;
            if (ParseIndex(arg, index) && index < selected.size())
                resolved = selected[index];
            else
                resolved = ResolveSelectedApplication(arg, selected);
            if (!resolved) {
                std::cout << "[!] No selected application matched '" << arg
                    << "'. Run 'list' to see selected apps.\n";
            } else {
                monitor.RemoveFromWatchlist(*resolved);
                SaveSelection(monitor);
            }
        }
        else if (cmd == "apps" || cmd == "discover" || cmd == "refresh") {
            discovered = ApplicationDiscovery::Discover(arg);
            applicationPage = 0;
            PrintApplications(discovered, applicationPage);
        }
        else if (cmd == "next") {
            constexpr size_t pageSize = 25;
            if (applicationPage + pageSize < discovered.size())
                applicationPage += pageSize;
            else
                applicationPage = 0;
            PrintApplications(discovered, applicationPage);
        }
        else if (cmd == "select") {
            size_t index = 0;
            bool corrected = false;
            std::optional<std::string> resolved;
            if (ParseIndex(arg, index) && index < discovered.size())
                resolved = discovered[index].executable;
            else
                resolved = ResolveDiscoveredApplication(
                    arg, discovered, corrected);
            if (!resolved) {
                std::cout << "[!] No application matched '" << arg << "'.\n";
            } else {
                if (corrected)
                    std::cout << "[Applications] Interpreting '" << arg
                        << "' as " << *resolved << ".\n";
                monitor.AddToWatchlist(*resolved);
                SaveSelection(monitor);
            }
        }
        else if (cmd == "list") {
            monitor.PrintWatchlist();
        }
        else if (cmd == "status") {
            monitor.PrintStatus();
        }
        else if (cmd == "activity" || cmd == "logs") {
            monitor.PrintRecentActivity(arg);
        }
        else if (cmd == "help" || cmd == "?") {
            PrintMenu();
            continue;
        }
        else {
            std::cout << "[!] Unknown command: " << cmd << "\n";
        }
        std::cout << "> ";
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    PrintBanner();

    if (!IsRunningAsAdmin()) {
        std::cerr << "[FATAL] TITAN requires Administrator privileges.\n"
            << "        Right-click terminal -> Run as administrator.\n";
        return 1;
    }
    std::cout << "[OK] Running as Administrator.\n";

    const HANDLE instanceMutex = CreateMutexW(nullptr, FALSE,
        L"Global\\TITAN_Application_Endpoint_Instance");
    if (!instanceMutex) {
        std::cerr << "[FATAL] Cannot create instance lock: "
            << GetLastError() << "\n";
        return 3;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cerr << "[FATAL] Application Endpoint is already running.\n";
        CloseHandle(instanceMutex);
        return 4;
    }

    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    AppLogMonitor monitor;

    auto selected = LoadSelection();
    if (selected.empty()) {
        // FIX: default watchlist previously covered only LOLBin script
        // hosts -- no browsers, no chat/mail apps every Windows user
        // actually has running day to day. Expanded to cover the common
        // defaults (browsers get depth via the existing child-process
        // following, since they're multi-process); still well under the
        // 20-app watchlist cap (see AppLogWatchlist), leaving room for
        // manual additions.
        selected = {
            // LOLBin / script hosts (original defaults)
            "powershell.exe", "cmd.exe", "mshta.exe",
            "wscript.exe", "cscript.exe",
            // Browsers
            "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
            // Chat / mail
            "whatsapp.exe", "discord.exe", "telegram.exe",
            "slack.exe", "teams.exe", "outlook.exe",
        };
    }
    for (const auto& name : selected) monitor.AddToWatchlist(name);
    SaveSelection(monitor);

    if (!monitor.Start()) {
        std::cerr << "[FATAL] Monitor failed to start.\n";
        CloseHandle(instanceMutex);
        return 2;
    }
    std::cout << "[OK] Monitor started. Listening for events...\n";

    // FORU.TXT section 4/12: authenticated local control channel, including
    // the revisioned SetWatchlist command.
    IpcControlServer ipcServer(monitor, [] { g_shutdown.store(true); });
    if (!ipcServer.Start()) {
        std::cerr << "[WARN] Failed to start IPC control channel -- remote control will be "
            "unavailable, monitoring continues normally.\n";
    }
    std::cout << "[TIP] Run 'apps' to discover running and installed "
        "desktop applications.\n";

    uint32_t durationSeconds = 0;
    for (int index = 1; index + 1 < argc; ++index) {
        if (std::string(argv[index]) == "--duration-seconds")
            durationSeconds = static_cast<uint32_t>(
                std::strtoul(argv[++index], nullptr, 10));
    }
    if (durationSeconds != 0) {
        for (uint32_t elapsed = 0;
            elapsed < durationSeconds && !g_shutdown.load(); ++elapsed)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        g_shutdown.store(true);
    }
    else {
        RunInteractiveMenu(monitor);
    }

    std::cout << "[main] Stopping monitor...\n";
    ipcServer.Stop();
    monitor.Stop();
    CloseHandle(instanceMutex);
    std::cout << "[main] Clean exit.\n";
    return 0;
} 
