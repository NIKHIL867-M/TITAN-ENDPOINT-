#include "agent.h"

#include <iostream>
#include <windows.h>

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
// SINGLE INSTANCE GUARD — FORU.TXT section 6: "Each endpoint must reject a
// second independent native instance." Checked before anything else (even
// the elevation check) so a second launch fails fast and obviously instead
// of partially initializing (opening an ETW session, etc.) first. The
// returned handle is deliberately leaked for the process's whole lifetime —
// Windows releases mutex ownership automatically on process exit, and
// there's no earlier point where it's safe to close it.
// ============================================================================

static void AcquireSingleInstanceMutexOrExit() {
  HANDLE mutex = CreateMutexW(nullptr, TRUE, L"Global\\TITAN_Process_Endpoint_Instance");
  const DWORD err = GetLastError();
  if (mutex && err == ERROR_ALREADY_EXISTS) {
    std::cerr << "[FATAL] TITAN Process endpoint is already running (single-instance "
                 "lock held). Refusing to start a second instance.\n";
    CloseHandle(mutex);
    std::exit(4);
  }
  if (!mutex) {
    // Genuinely can't tell whether another instance holds it -- don't block
    // startup on this alone, but say so loudly rather than silently
    // pretending single-instance protection is active when it isn't.
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
               "  TITAN V3  —  Signal Amplifier + Noise Suppressor\n"
               "  ETW Kernel-Process | Fixed RAM ~1.3 MB\n"
               "  No scoring. No detection. No drop path.\n"
               "  Output: FORWARD (novel) | COMPRESS (redundant)\n"
               "\n";
}

// ============================================================================
// ENTRY POINT
// ============================================================================

int wmain(int argc, wchar_t *argv[]) {
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
  if (argc > 1)
    log_dir = argv[1];

  // Ensure trailing backslash
  if (!log_dir.empty() && log_dir.back() != L'\\')
    log_dir += L'\\';

  std::wcout << L"[INFO]  Log directory: " << log_dir << L'\n';

  titan::Agent agent;

  if (!agent.Initialize(log_dir)) {
    std::cerr << "[ERROR] Failed to initialize TITAN V3.\n";
    return 1;
  }

  if (!agent.Start()) {
    std::cerr << "[ERROR] Failed to start TITAN V3.\n";
    return 1;
  }

  return 0;
}