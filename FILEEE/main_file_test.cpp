#include <atomic>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <string>
#include <io.h>
#include <conio.h>
#include <fcntl.h>

#include <windows.h>

#include "file_monitor.h"
#include "file_etw_collector.h"
#include "ipc_control_server.h"

// =============================================================================
// TITAN - File Integrity Monitor
// main_file_test.cpp
//
// FIX 1 — Banner mojibake: std::cout on Windows does not print UTF-8
//          box-drawing characters correctly unless SetConsoleOutputCP(CP_UTF8)
//          is called first. Replaced box-drawing with plain ASCII so the
//          banner works in every terminal regardless of code page.
//
// FIX 2 — Log path visibility: After monitor.Start() the resolved absolute
//          log path is now printed so the user always knows exactly which
//          file to open. Previously it was easy to look at the wrong copy
//          (e.g. the src3 sample file while real logs went to the build dir).
// =============================================================================

using namespace titan::fim;

static bool IsRunningAsAdmin()
{
    BOOL is_admin = FALSE;
    PSID admin_group = nullptr;

    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(
        &nt_authority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &admin_group))
    {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }

    return is_admin == TRUE;
}

// FIX 1: Plain ASCII banner — no UTF-8 box-drawing, works in every terminal.
static void PrintBanner()
{
    // FIX 1: Enable UTF-8 output so any remaining non-ASCII text (process
    // names, paths) doesn't corrupt the console.
    SetConsoleOutputCP(CP_UTF8);

    std::cout << "\n";
    std::cout << "  +-------------------------------------------------+\n";
    std::cout << "  |                                                 |\n";
    std::cout << "  |   TITAN  -  File Integrity Monitor              |\n";
    std::cout << "  |   Endpoint 04                                   |\n";
    std::cout << "  |                                                 |\n";
    std::cout << "  +-------------------------------------------------+\n";
    std::cout << "\n";
}

int main(int argc, char* argv[])
{
    PrintBanner();

    if (!IsRunningAsAdmin())
    {
        std::cerr << "[FIM] ERROR: Must run as Administrator\n";
        std::cerr << "[FIM] ETW kernel file provider requires elevated privileges\n";
        std::cerr << "[FIM] Right-click the executable and choose 'Run as administrator'\n\n";
        return -1;
    }

    std::cout << "[FIM] Running as Administrator: OK\n\n";

    // FORU.TXT section 6: "Each endpoint must reject a second independent
    // native instance." Same pattern as the other elevated endpoints.
    const HANDLE instanceMutex = CreateMutexW(nullptr, FALSE,
        L"Global\\TitanEndpoint_File_Instance");
    if (!instanceMutex) {
        std::cerr << "[FATAL] Cannot create instance lock: " << GetLastError() << "\n";
        return 3;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cerr << "[FATAL] TITAN File endpoint is already running (single-instance lock held).\n";
        CloseHandle(instanceMutex);
        return 4;
    }

    // -------------------------------------------------------------------------
    // Start file monitor (owns logger + processor + event queue).
    //
    // The path passed here is relative — FileMonitor::ResolveLogPath anchors
    // it to the directory of the running exe automatically. The resolved
    // absolute path is printed by the monitor on startup so you always know
    // exactly which file to open in VS or a text editor.
    // -------------------------------------------------------------------------
    FileMonitor monitor;

    if (!monitor.Start(L"logs\\fim_events.json"))
    {
        std::cerr << "[FIM] Failed to start FileMonitor\n";
        return -1;
    }

    // -------------------------------------------------------------------------
    // Start ETW collector (owns ETW session + provider + collection thread).
    // -------------------------------------------------------------------------
    FileEtwCollector collector(&monitor);

    if (!collector.Start())
    {
        std::cerr << "[FIM] Failed to start ETW collector\n";
        monitor.Stop();
        CloseHandle(instanceMutex);
        return -1;
    }

    // FORU.TXT section 4: authenticated local control channel.
    static std::atomic<bool> s_shutdownRequested{false};
    IpcControlServer ipcServer(monitor, [] { s_shutdownRequested.store(true); });
    if (!ipcServer.Start()) {
        std::cerr << "[WARN] Failed to start IPC control channel -- remote control will be "
            "unavailable, monitoring continues normally.\n";
    }

    std::cout << "\n[FIM] Monitoring active — all file events are being captured\n";
    std::cout << "[FIM] Commands: Q = stop, HASH <full-path> = SHA-256\n\n";

    uint32_t duration_seconds = 0;
    for (int index = 1; index + 1 < argc; ++index)
    {
        if (std::string(argv[index]) == "--duration-seconds")
            duration_seconds = static_cast<uint32_t>(
                std::strtoul(argv[++index], nullptr, 10));
    }

    if (duration_seconds != 0)
    {
        // Interruptible so an IPC Shutdown command (FORU.TXT section 4)
        // during a bounded/headless run doesn't have to wait out the full
        // duration.
        for (uint32_t elapsed = 0;
            elapsed < duration_seconds && !s_shutdownRequested.load(); ++elapsed)
            std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    else if (_isatty(_fileno(stdin)))
    {
        // A real terminal keeps the small HASH/Q command surface. Poll stdin
        // before reading it so an IPC shutdown can also stop an interactive
        // session without waiting for another Enter key.
        while (!s_shutdownRequested.load())
        {
            if (!_kbhit())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            std::string line;
            if (!std::getline(std::cin, line))
                break;

            if (!line.empty() && (line[0] == 'q' || line[0] == 'Q'))
                break;

            if (line.size() > 5 &&
                (_strnicmp(line.c_str(), "hash ", 5) == 0))
            {
                const std::string utf8_path = line.substr(5);
                const int required = MultiByteToWideChar(CP_UTF8, 0,
                    utf8_path.c_str(), -1, nullptr, 0);
                std::wstring path;
                if (required > 1)
                {
                    path.resize(static_cast<size_t>(required));
                    MultiByteToWideChar(CP_UTF8, 0, utf8_path.c_str(), -1,
                        path.data(), required);
                    path.resize(static_cast<size_t>(required - 1));
                }
                const std::string hash = monitor.HashFile(path);
                if (hash.empty())
                    std::cout << "[FIM][HASH] Unable to read file\n";
                else
                    std::cout << "[FIM][HASH] SHA-256 " << hash << "\n";
            }
        }
    }
    else
    {
        // GUI/service launches intentionally redirect or omit stdin. An EOF
        // on that pipe is not a stop request: remain alive until the
        // authenticated control channel asks the endpoint to shut down.
        while (!s_shutdownRequested.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "\n[FIM] Stopping...\n";

    // Stop in order: IPC server, collector (no new events), then monitor (drains queue)
    ipcServer.Stop();
    collector.Stop();
    monitor.Stop();
    CloseHandle(instanceMutex);

    std::cout << "[FIM] Clean shutdown — all queued events flushed to disk\n\n";
    return 0;
}
