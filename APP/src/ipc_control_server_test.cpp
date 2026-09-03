// Non-admin integration test for Application's ipc_control_server.cpp,
// mirroring PROCESS ENDPOINT\titan_fixed\ipc_control_server_test.cpp.
// AppLogMonitor's constructor doesn't open any ETW/WEL subscription --
// that happens in Start(), which is deliberately never called here -- so
// this needs no Administrator privileges.
#include "applog_monitor.h"
#include "applog_logger.h"
#include "ipc_control_server.h"

#include <windows.h>
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>
#include <filesystem>
#include <thread>
#include <chrono>

namespace {
bool g_ok = true;
bool Require(bool condition, const char* message) {
    if (!condition) { std::cerr << "[TEST] FAIL: " << message << "\n"; g_ok = false; }
    return condition;
}

std::string SendRequest(const std::string& command, const std::string& extraJson = "") {
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 20 && pipe == INVALID_HANDLE_VALUE; ++attempt) {
        pipe = CreateFileW(IpcControlServer::kPipeName, GENERIC_READ | GENERIC_WRITE, 0,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (pipe == INVALID_HANDLE_VALUE) return "";

    std::string request = "{\"proto_version\":1,\"request_id\":\"test-1\",\"command\":\"" + command + "\"" + extraJson + "}";
    DWORD written = 0;
    WriteFile(pipe, request.data(), static_cast<DWORD>(request.size()), &written, nullptr);

    char buffer[8192]{};
    DWORD read = 0;
    ReadFile(pipe, buffer, sizeof(buffer) - 1, &read, nullptr);
    CloseHandle(pipe);
    return std::string(buffer, read);
}

bool ResponseHasTrue(const std::string& response, const std::string& key) {
    return response.find("\"" + key + "\":true") != std::string::npos;
}
uint64_t ExtractUint(const std::string& response, const std::string& key) {
    auto needle = "\"" + key + "\":";
    auto pos = response.find(needle);
    if (pos == std::string::npos) return 0;
    pos += needle.size();
    return std::strtoull(response.c_str() + pos, nullptr, 10);
}
std::string ExtractString(const std::string& response, const std::string& key) {
    auto needle = "\"" + key + "\":\"";
    auto pos = response.find(needle);
    if (pos == std::string::npos) return "";
    pos += needle.size();
    auto end = response.find('"', pos);
    if (end == std::string::npos) return "";
    return response.substr(pos, end - pos);
}
} // namespace

int main() {
    AppLogMonitor monitor; // constructor only -- Start() never called, no ETW/admin needed

    IpcControlServer server(monitor, [] { /* no-op */ });
    Require(server.Start(), "IpcControlServer starts");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto status1 = SendRequest("GetStatus");
    Require(ResponseHasTrue(status1, "ok"), "GetStatus: ok:true");
    Require(ExtractString(status1, "endpoint_id") == "application", "GetStatus: endpoint_id is \"application\"");
    const std::string sessionId = ExtractString(status1, "session_id");
    Require(!sessionId.empty(), "GetStatus: session_id is non-empty");
    Require(ResponseHasTrue(status1, "monitoring_enabled"), "GetStatus: monitoring_enabled defaults true");

    auto stopResp = SendRequest("StopMonitoring");
    Require(ResponseHasTrue(stopResp, "ok"), "StopMonitoring: ok:true");
    Require(!monitor.IsMonitoringEnabled(), "AppLogMonitor::IsMonitoringEnabled() is now false");

    auto staleResp = SendRequest("StartMonitoring", ",\"expected_session_id\":\"not-real\"");
    Require(!ResponseHasTrue(staleResp, "ok"), "StartMonitoring with wrong session is rejected");
    Require(!monitor.IsMonitoringEnabled(), "monitoring remains off after a stale-session rejection");

    auto okResp = SendRequest("StartMonitoring", ",\"expected_session_id\":\"" + sessionId + "\"");
    Require(ResponseHasTrue(okResp, "ok"), "StartMonitoring with correct session succeeds");
    Require(monitor.IsMonitoringEnabled(), "monitoring is back on");

    // FORU.TXT section 12: revisioned watchlist -- accepted_watchlist_revision
    // must be present and must actually apply the requested list.
    Require(monitor.CurrentWatchlistRevision() == 0, "watchlist revision starts at 0");
    auto watchlistResp = SendRequest("SetWatchlist", ",\"applications\":[\"chrome.exe\",\"code.exe\"]");
    Require(ResponseHasTrue(watchlistResp, "ok"), "SetWatchlist: ok:true");
    const uint64_t acceptedRev = ExtractUint(watchlistResp, "accepted_watchlist_revision");
    Require(acceptedRev == 1, "first real watchlist change advances accepted_watchlist_revision to 1");
    Require(monitor.CurrentWatchlistRevision() == 1, "AppLogMonitor's own revision counter agrees");
    auto names = monitor.WatchlistNames();
    Require(std::find(names.begin(), names.end(), "chrome.exe") != names.end(),
        "chrome.exe was actually applied to the live watchlist");

    // Re-applying the SAME list is a no-op -- revision must NOT advance for
    // a request that changes nothing (only real changes count).
    auto watchlistResp2 = SendRequest("SetWatchlist", ",\"applications\":[\"chrome.exe\",\"code.exe\"]");
    Require(ExtractUint(watchlistResp2, "accepted_watchlist_revision") == 1,
        "re-applying an unchanged watchlist does not advance the revision");

    server.Stop();
    std::cout << (g_ok ? "[TEST] PASS: all Application ipc_control_server checks passed\n"
                        : "[TEST] one or more checks FAILED\n");
    return g_ok ? 0 : 1;
}
