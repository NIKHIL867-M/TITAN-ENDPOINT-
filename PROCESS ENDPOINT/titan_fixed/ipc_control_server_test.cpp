// Non-admin integration test for ipc_control_server.cpp's real named-pipe protocol.
// Constructs real AsyncLogger + FilterEngine + ProcessMonitor instances (no ETW session is
// ever started -- ProcessMonitor::Start() is deliberately never called, so this needs no
// Administrator privileges) and runs the real IpcControlServer against them, then drives it
// with a real named-pipe client exercising every command exactly as the GUI would. Prints
// [TEST] PASS/FAIL lines matching this project's existing logic-test convention.
#include "agent.h" // pulls in filter.h/logger.h/process_monitor.h/ipc_control_server.h together
#include <windows.h>
#include <cstdlib>
#include <iostream>
#include <string>
#include <filesystem>
#include <thread>
#include <chrono>

using namespace titan;

namespace {
bool g_ok = true;
bool Require(bool condition, const char* message) {
    if (!condition) { std::cerr << "[TEST] FAIL: " << message << "\n"; g_ok = false; }
    return condition;
}

// Minimal client matching the GUI's EndpointControlClient wire format exactly.
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
bool ResponseHasFalse(const std::string& response, const std::string& key) {
    return response.find("\"" + key + "\":false") != std::string::npos;
}
// Minimal same-style numeric field extraction, matching this test's existing
// "no JSON library" convention.
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

// All real object lifetimes (AsyncLogger in particular holds an open file handle until its
// destructor/Shutdown runs) are confined to this function so they're guaranteed to unwind
// -- and release the log file -- before main() tries to delete the temp directory.
void RunTest(const std::wstring& logDir) {
    FilterEngine filter;
    Require(filter.Initialize(logDir + L"bloom\\"), "FilterEngine initializes without admin");

    AsyncLogger logger(logDir);
    Require(logger.Initialize(), "AsyncLogger initializes without admin");
    logger.SetFilter(&filter);

    ProcessMonitor monitor(logger, filter); // constructor only -- Start() never called, no ETW/admin needed

    IpcControlServer server(monitor, logger, [] { /* Shutdown callback: no-op for this test */ });
    Require(server.Start(), "IpcControlServer starts");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // 1. GetStatus — defaults should reflect monitoring/save-logs both ON.
    auto status1 = SendRequest("GetStatus");
    Require(ResponseHasTrue(status1, "ok"), "GetStatus: ok:true");
    Require(ResponseHasTrue(status1, "monitoring_enabled"), "GetStatus: monitoring_enabled defaults true");
    Require(ResponseHasTrue(status1, "save_logs_enabled"), "GetStatus: save_logs_enabled defaults true");

    // 2. StopMonitoring, then GetStatus reflects it — and ProcessMonitor's own getter agrees.
    auto stopResp = SendRequest("StopMonitoring");
    Require(ResponseHasTrue(stopResp, "ok"), "StopMonitoring: ok:true");
    Require(!monitor.IsMonitoringEnabled(), "ProcessMonitor::IsMonitoringEnabled() is now false");
    auto status2 = SendRequest("GetStatus");
    Require(ResponseHasFalse(status2, "monitoring_enabled"), "GetStatus reflects monitoring_enabled:false after StopMonitoring");

    // 3. StartMonitoring re-enables it.
    SendRequest("StartMonitoring");
    Require(monitor.IsMonitoringEnabled(), "StartMonitoring re-enables ProcessMonitor::IsMonitoringEnabled()");

    // 4. SetPersistence(false) — independent of monitoring (FORU.TXT 4.3/4.5).
    auto persistResp = SendRequest("SetPersistence", ",\"enabled\":false");
    Require(ResponseHasTrue(persistResp, "ok"), "SetPersistence(false): ok:true");
    Require(!logger.IsSaveLogsEnabled(), "AsyncLogger::IsSaveLogsEnabled() is now false");
    Require(monitor.IsMonitoringEnabled(), "Monitoring remains ON while Save Logs is OFF -- the two are independent");

    // 5. SetPersistence with a missing 'enabled' field must fail cleanly, not crash.
    auto badResp = SendRequest("SetPersistence");
    Require(!ResponseHasTrue(badResp, "ok"), "SetPersistence with no 'enabled' field correctly reports ok:false");

    // 6. Restore persistence, then Flush must succeed without hanging.
    SendRequest("SetPersistence", ",\"enabled\":true");
    auto flushResp = SendRequest("Flush");
    Require(ResponseHasTrue(flushResp, "ok"), "Flush: ok:true");

    // 7. Unknown command handled gracefully.
    auto unknownResp = SendRequest("NotARealCommand");
    Require(!ResponseHasTrue(unknownResp, "ok"), "Unknown command correctly reports ok:false, not a crash");

    // 8. GetRecentEvents returns a well-formed (possibly empty) array field.
    auto recentResp = SendRequest("GetRecentEvents");
    Require(recentResp.find("\"recent_events\":[") != std::string::npos, "GetRecentEvents includes a recent_events array field");

    // 9. GetStatus exposes endpoint_id/session_id/revision (FORU.TXT 4, 2026-08-02 revision).
    auto status3 = SendRequest("GetStatus");
    Require(ExtractString(status3, "endpoint_id") == "process", "GetStatus: endpoint_id is \"process\"");
    const std::string realSessionId = ExtractString(status3, "session_id");
    Require(!realSessionId.empty(), "GetStatus: session_id is non-empty");
    const uint64_t currentRevision = ExtractUint(status3, "revision");
    Require(currentRevision > 0, "GetStatus: revision has advanced past 0 from the mutations above");

    // 10. A mutating command carrying the WRONG expected_session_id must be
    // rejected outright, and must NOT change state.
    const bool monitoringBefore = monitor.IsMonitoringEnabled();
    auto staleSessionResp = SendRequest("StopMonitoring", ",\"expected_session_id\":\"not-the-real-session\"");
    Require(!ResponseHasTrue(staleSessionResp, "ok"), "StopMonitoring with wrong expected_session_id is rejected");
    Require(staleSessionResp.find("stale_session") != std::string::npos, "Rejection reason names stale_session");
    Require(monitor.IsMonitoringEnabled() == monitoringBefore, "Monitoring state is unchanged after a stale-session rejection");

    // 11. A mutating command carrying an expected_revision LOWER than current
    // must also be rejected (someone else already changed state since the
    // caller last read it).
    auto staleRevResp = SendRequest("StopMonitoring",
        ",\"expected_session_id\":\"" + realSessionId + "\",\"expected_revision\":0");
    Require(!ResponseHasTrue(staleRevResp, "ok"), "StopMonitoring with stale expected_revision:0 is rejected");
    Require(staleRevResp.find("stale_revision") != std::string::npos, "Rejection reason names stale_revision");
    Require(monitor.IsMonitoringEnabled() == monitoringBefore, "Monitoring state is unchanged after a stale-revision rejection");

    // 12. The SAME command with the CORRECT current session/revision succeeds
    // and the revision advances by exactly one.
    auto okResp = SendRequest("StopMonitoring",
        ",\"expected_session_id\":\"" + realSessionId + "\",\"expected_revision\":" + std::to_string(currentRevision));
    Require(ResponseHasTrue(okResp, "ok"), "StopMonitoring with correct session/revision succeeds");
    Require(ExtractUint(okResp, "revision") == currentRevision + 1, "Revision advances by exactly one on an accepted mutation");
    SendRequest("StartMonitoring"); // restore for cleanliness (no session/revision -- omitting them stays backward compatible)
    Require(monitor.IsMonitoringEnabled(), "Omitting expected_session_id/expected_revision still works (backward compatible)");

    server.Stop();
    // logger/filter/monitor/server destruct here, at the end of this function's scope --
    // AsyncLogger's Shutdown() (called from its destructor) closes the log file before
    // RunTest returns, so the caller can safely delete the temp directory afterward.
}
}

int main() {
    auto tempDir = std::filesystem::temp_directory_path() / L"titan_ipc_test";
    std::error_code ec;
    std::filesystem::remove_all(tempDir, ec);
    std::filesystem::create_directories(tempDir, ec);

    RunTest(tempDir.wstring() + L"\\");

    std::filesystem::remove_all(tempDir, ec); // best-effort; ec intentionally ignored

    std::cout << (g_ok ? "[TEST] PASS: all ipc_control_server checks passed\n" : "[TEST] one or more checks FAILED\n");
    return g_ok ? 0 : 1;
}
