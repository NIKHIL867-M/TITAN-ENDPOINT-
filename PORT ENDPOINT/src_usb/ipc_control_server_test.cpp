// Non-admin integration test for Port's ipc_control_server.cpp, mirroring
// PROCESS ENDPOINT\titan_fixed\ipc_control_server_test.cpp. UsbMonitor's
// constructor doesn't touch the kernel listener (that's Start(), never
// called here), so this needs no Administrator privileges.
#include "usb_monitor.h"
#include "usb_logger.h"
#include "ipc_control_server.h"

#include <windows.h>
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
    auto tempDir = std::filesystem::temp_directory_path() / L"titan_port_ipc_test";
    std::error_code ec;
    std::filesystem::remove_all(tempDir, ec);
    std::filesystem::create_directories(tempDir, ec);

    {
        const std::string logPath = (tempDir / L"usb_events.json").string();
        Require(UsbLogger::Initialize(logPath), "UsbLogger initializes without admin");

        UsbMonitor monitor; // constructor only -- Start() never called, no kernel/admin needed

        IpcControlServer server(monitor, [] { /* no-op */ });
        Require(server.Start(), "IpcControlServer starts");
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        auto status1 = SendRequest("GetStatus");
        Require(ResponseHasTrue(status1, "ok"), "GetStatus: ok:true");
        Require(ExtractString(status1, "endpoint_id") == "port", "GetStatus: endpoint_id is \"port\"");
        const std::string sessionId = ExtractString(status1, "session_id");
        Require(!sessionId.empty(), "GetStatus: session_id is non-empty");
        Require(ResponseHasTrue(status1, "monitoring_enabled"), "GetStatus: monitoring_enabled defaults true");

        auto stopResp = SendRequest("StopMonitoring");
        Require(ResponseHasTrue(stopResp, "ok"), "StopMonitoring: ok:true");
        Require(!monitor.IsMonitoringEnabled(), "UsbMonitor::IsMonitoringEnabled() is now false");

        auto staleResp = SendRequest("StartMonitoring", ",\"expected_session_id\":\"not-real\"");
        Require(!ResponseHasTrue(staleResp, "ok"), "StartMonitoring with wrong session is rejected");
        Require(!monitor.IsMonitoringEnabled(), "monitoring remains off after a stale-session rejection");

        auto okResp = SendRequest("StartMonitoring", ",\"expected_session_id\":\"" + sessionId + "\"");
        Require(ResponseHasTrue(okResp, "ok"), "StartMonitoring with correct session succeeds");
        Require(monitor.IsMonitoringEnabled(), "monitoring is back on");

        auto persistResp = SendRequest("SetPersistence", ",\"enabled\":false");
        Require(ResponseHasTrue(persistResp, "ok"), "SetPersistence(false): ok:true");
        Require(!UsbLogger::IsSaveLogsEnabled(), "UsbLogger::IsSaveLogsEnabled() is now false");

        server.Stop();
        UsbLogger::Shutdown();
    }

    std::filesystem::remove_all(tempDir, ec);
    std::cout << (g_ok ? "[TEST] PASS: all Port ipc_control_server checks passed\n"
                        : "[TEST] one or more checks FAILED\n");
    return g_ok ? 0 : 1;
}
