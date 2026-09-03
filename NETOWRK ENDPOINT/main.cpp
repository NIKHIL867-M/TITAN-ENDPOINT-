#include "agent.h"

#include <iostream>
// windows.h pulled in via agent.h -> event.h (with winsock2 first)

// ============================================================================
// ELEVATION CHECK
// ============================================================================

static bool IsElevated() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;

    TOKEN_ELEVATION elev{};
    DWORD len = 0;
    bool result =
        GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &len) &&
        elev.TokenIsElevated != 0;
    CloseHandle(hToken);
    return result;
}

// ============================================================================
// SINGLE INSTANCE GUARD — FORU.TXT section 6. Same pattern as the Process
// endpoint's main.cpp; see that file's comment for the full rationale.
// ============================================================================

static void AcquireSingleInstanceMutexOrExit() {
    HANDLE mutex = CreateMutexW(nullptr, TRUE, L"Global\\TitanEndpoint_Network_Instance");
    const DWORD err = GetLastError();
    if (mutex && err == ERROR_ALREADY_EXISTS) {
        std::cerr << "[FATAL] TITAN Network endpoint is already running (single-instance "
                     "lock held). Refusing to start a second instance.\n";
        CloseHandle(mutex);
        std::exit(4);
    }
    if (!mutex) {
        std::cerr << "[WARN]  Could not create single-instance mutex (error " << err
                  << ") -- single-instance protection is NOT active this run.\n";
    }
}

// ============================================================================
// BANNER
// ============================================================================

static void PrintBanner() {
    std::cout << "\n"
        "  _______ _____ _____ ___  _   _ \n"
        " |__   __|_   _|_   _/ _ \\| \\ | |\n"
        "    | |    | |   | || | | |  \\| |\n"
        "    | |    | |   | || |_| | . ` |\n"
        "    | |   _| |_ _| | \\__/| |\\  |\n"
        "    |_|  |_____|_____\\___/|_| \\_|\n"
        "\n"
        "  TITAN V4  —  Signal Amplifier + Noise Suppressor\n"
        "  Npcap full-packet Network Capture\n"
        "  Protocols: TCP/UDP/ICMP/TLS-SNI/HTTP/DNS/QUIC/RDP/SMB/SSH\n"
        "  Bounded state | Explicit capture/log loss accounting\n"
        "  Output: first observation + periodic flow deltas + raw PCAP\n"
        "  Compiler: MSVC | Standard: C++20 | Target: Windows 10+\n"
        "\n";
}

// ============================================================================
// ENTRY POINT
// ============================================================================

int wmain(int argc, wchar_t* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    AcquireSingleInstanceMutexOrExit();
    PrintBanner();

    if (!IsElevated()) {
        std::cerr << "[ERROR] TITAN requires Administrator privileges.\n"
            << "        Right-click -> Run as Administrator\n";
        return 1;
    }

    // Log directory — AsyncLogger creates it if it doesn't exist.
    // Pass a directory path ending in '\\'; the logger appends the filename.
    std::wstring log_dir = L".\\logs\\";
    uint32_t duration_seconds = 0;
    for (int index = 1; index < argc; ++index) {
        if (std::wstring(argv[index]) == L"--duration-seconds" &&
            index + 1 < argc) {
            duration_seconds = static_cast<uint32_t>(
                std::wcstoul(argv[++index], nullptr, 10));
        }
        else {
            log_dir = argv[index];
        }
    }

    // Ensure trailing backslash
    if (!log_dir.empty() && log_dir.back() != L'\\')
        log_dir += L'\\';

    std::wcout << L"[INFO]  Log directory: " << log_dir << L'\n';

    titan::Agent agent;

    if (!agent.Initialize(log_dir)) {
        std::cerr << "[ERROR] Failed to initialize TITAN V4.\n";
        return 1;
    }

    if (!agent.Start(duration_seconds)) {
        std::cerr << "[ERROR] Failed to start TITAN V4.\n";
        return 1;
    }

    return 0;
}
