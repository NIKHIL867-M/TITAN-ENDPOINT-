// test_main.cpp  (production entry point -- real USB monitoring, no fake data)
//
// TitanUSB -- real-time USB storage monitoring agent.
// Runs until Ctrl+C or the console window is closed.
// Logs one JSON line per session to:
//   C:\ProgramData\TitanUSB\logs\usb_events.json
//
#ifndef WIN32_LEAN_AND_MEAN
#   define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#   define NOMINMAX
#endif
#include <windows.h>

#include "usb_monitor.h"
#include "usb_logger.h"
#include "ipc_control_server.h"

#include <iostream>
#include <string>
#include <atomic>

// ── Shutdown state ────────────────────────────────────────────────────────────
static std::atomic<bool>  g_running{ true };
static UsbMonitor* g_monitor = nullptr;

// ── Ctrl+C / console-close handler ───────────────────────────────────────────
static BOOL WINAPI ConsoleHandler(DWORD signal)
{
    if (signal == CTRL_C_EVENT ||
        signal == CTRL_BREAK_EVENT ||
        signal == CTRL_CLOSE_EVENT ||
        signal == CTRL_SHUTDOWN_EVENT)
    {
        std::cout << "\n[TitanUSB] Shutdown signal -- stopping...\n";
        g_running.store(false, std::memory_order_release);
        if (g_monitor) g_monitor->Stop();
        return TRUE;
    }
    return FALSE;
}

// ─────────────────────────────────────────────────────────────────────────────
int main()
{
    // Set console to UTF-8 so all output renders correctly.
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // FORU.TXT section 6: "Each endpoint must reject a second independent
    // native instance." Same pattern as the other elevated endpoints.
    const HANDLE instanceMutex = CreateMutexW(nullptr, FALSE,
        L"Global\\TitanEndpoint_Port_Instance");
    if (!instanceMutex) {
        std::cerr << "[FATAL] Cannot create instance lock: " << GetLastError() << "\n";
        return 3;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cerr << "[FATAL] TitanUSB is already running (single-instance lock held).\n";
        CloseHandle(instanceMutex);
        return 4;
    }

    std::cout << "============================================================\n"
        "  TitanUSB -- USB Storage Monitor\n"
        "  Press Ctrl+C to stop.\n"
        "============================================================\n\n";

    // ── 1. Open log file ─────────────────────────────────────────────────
    const std::string logPath =
        "C:\\ProgramData\\TitanUSB\\logs\\usb_events.json";

    if (!UsbLogger::Initialize(logPath)) {
        std::cerr << "[TitanUSB] FATAL: Cannot open log file: " << logPath << "\n"
            "           Run as Administrator if the directory does not exist.\n";
        return 1;
    }
    std::cout << "[TitanUSB] Logging to: " << logPath << "\n\n";

    // ── 2. Start monitor ─────────────────────────────────────────────────
    // Start() blocks until the kernel listener is fully registered.
    UsbMonitor monitor;
    g_monitor = &monitor;

    if (!monitor.Start()) {
        std::cerr << "[TitanUSB] FATAL: Failed to start USB monitor.\n"
            "           Try running as Administrator.\n";
        UsbLogger::Shutdown();
        CloseHandle(instanceMutex);
        return 1;
    }

    // Start() returns only after the listener is ready -- safe to print now.
    std::cout << "[TitanUSB] Listening for USB storage devices.\n"
        "[TitanUSB] Plug in a USB drive to start a session.\n\n";

    // FORU.TXT section 4: authenticated local control channel.
    IpcControlServer ipcServer(monitor, [] { g_running.store(false, std::memory_order_release); });
    if (!ipcServer.Start()) {
        std::cerr << "[WARN] Failed to start IPC control channel -- remote control will be "
            "unavailable, monitoring continues normally.\n";
    }

    // ── 3. Register signal handler ───────────────────────────────────────
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    // ── 4. Idle loop ─────────────────────────────────────────────────────
    while (g_running.load(std::memory_order_acquire)) {
        Sleep(200);
    }

    // ── 5. Clean shutdown ────────────────────────────────────────────────
    std::cout << "[TitanUSB] Stopping...\n";
    ipcServer.Stop();
    monitor.Stop();
    UsbLogger::Shutdown();
    g_monitor = nullptr;
    CloseHandle(instanceMutex);

    std::cout << "[TitanUSB] Done. Log: " << logPath << "\n";
    return 0;
}