#include "ipc_control_server.h"
#include "correlator_logger.h"

#include <windows.h>
#include <sddl.h>
#include <cstdlib>
#include <sstream>
#include <chrono>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace correlator {

namespace {

bool ExtractJsonStringField(const std::string& line, const std::string& key, std::string& out) {
    auto needle = "\"" + key + "\"";
    auto pos = line.find(needle);
    if (pos == std::string::npos) return false;
    pos = line.find(':', pos + needle.size());
    if (pos == std::string::npos) return false;
    pos = line.find('"', pos);
    if (pos == std::string::npos) return false;
    auto end = line.find('"', pos + 1);
    if (end == std::string::npos) return false;
    out = line.substr(pos + 1, end - pos - 1);
    return true;
}

bool ExtractJsonBoolField(const std::string& line, const std::string& key, bool& out) {
    auto needle = "\"" + key + "\"";
    auto pos = line.find(needle);
    if (pos == std::string::npos) return false;
    pos = line.find(':', pos + needle.size());
    if (pos == std::string::npos) return false;
    pos++;
    while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) pos++;
    if (line.compare(pos, 4, "true") == 0) { out = true; return true; }
    if (line.compare(pos, 5, "false") == 0) { out = false; return true; }
    return false;
}

bool ExtractJsonUint64Field(const std::string& line, const std::string& key, uint64_t& out) {
    auto needle = "\"" + key + "\"";
    auto pos = line.find(needle);
    if (pos == std::string::npos) return false;
    pos = line.find(':', pos + needle.size());
    if (pos == std::string::npos) return false;
    pos++;
    while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) pos++;
    const auto start = pos;
    while (pos < line.size() && line[pos] >= '0' && line[pos] <= '9') pos++;
    if (pos == start) return false;
    out = std::strtoull(line.substr(start, pos - start).c_str(), nullptr, 10);
    return true;
}

std::string JsonEscape(const std::string& value) {
    std::string output;
    output.reserve(value.size() + 8);
    for (unsigned char c : value) {
        switch (c) {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        default:
            if (c < 0x20) { char buf[8]; sprintf_s(buf, "\\u%04x", c); output += buf; }
            else output += static_cast<char>(c);
        }
    }
    return output;
}

} // namespace

IpcControlServer::IpcControlServer(std::atomic<bool>& collectingEnabled, CorrelatorLogger& logger,
    std::function<void()> shutdownCallback)
    : collecting_enabled_(collectingEnabled), logger_(logger), shutdown_callback_(std::move(shutdownCallback)) {
}

IpcControlServer::~IpcControlServer() {
    Stop();
}

bool IpcControlServer::Start() {
    if (running_.exchange(true)) return true;
    server_thread_ = std::thread(&IpcControlServer::ServerLoop, this);
    return true;
}

void IpcControlServer::Stop() {
    if (!running_.exchange(false)) return;

    // Close the Stop/CreateNamedPipe race: the server may be between closing
    // the previous client and creating its next blocking pipe instance. A
    // single wake attempt can miss that interval and leave join() blocked in
    // ConnectNamedPipe forever (observed in repeated CTest runs). Retry for a
    // short bounded interval until either the new instance is reached or the
    // server thread observes running_=false and exits by itself.
    for (int attempt = 0; attempt < 50; ++attempt) {
        HANDLE h = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (server_thread_.joinable()) server_thread_.join();
}

void IpcControlServer::ServerLoop() {
    // Same DACL as every other endpoint's control channel: Administrators,
    // SYSTEM, and the pipe's own creator/owner (OW) -- OW alone is already
    // sufficient for Correlator's normal non-elevated same-user scenario; BA/
    // SY additionally cover a caller running at a different privilege level.
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:(A;;GRGW;;;BA)(A;;GRGW;;;SY)(A;;GRGW;;;OW)",
        SDDL_REVISION_1, &sd, nullptr)) {
        return;
    }
    SECURITY_ATTRIBUTES sa{ sizeof(SECURITY_ATTRIBUTES), sd, FALSE };

    while (running_.load()) {
        HANDLE pipe = CreateNamedPipeW(
            kPipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            8192, 8192, 0, &sa);

        if (pipe == INVALID_HANDLE_VALUE) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        BOOL connected = ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!running_.load()) {
            CloseHandle(pipe);
            break;
        }
        if (connected) {
            HandleOneConnection(pipe);
        }
        CloseHandle(pipe);
    }

    LocalFree(sd);
}

void IpcControlServer::HandleOneConnection(void* pipeHandleVoid) {
    HANDLE pipe = static_cast<HANDLE>(pipeHandleVoid);
    char buffer[8192]{};
    DWORD bytesRead = 0;
    if (!ReadFile(pipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)) return;
    buffer[bytesRead] = '\0';

    std::string response = Dispatch(std::string(buffer, bytesRead), pipeHandleVoid);

    DWORD bytesWritten = 0;
    WriteFile(pipe, response.data(), static_cast<DWORD>(response.size()), &bytesWritten, nullptr);
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
}

std::string IpcControlServer::CaptureCallerIdentity(void* pipeHandleVoid) {
    HANDLE pipe = static_cast<HANDLE>(pipeHandleVoid);
    std::string identity = "unknown";

    if (!ImpersonateNamedPipeClient(pipe)) return identity;

    HANDLE token = nullptr;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        DWORD needed = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
        if (needed > 0) {
            std::vector<BYTE> buf(needed);
            if (GetTokenInformation(token, TokenUser, buf.data(), needed, &needed)) {
                auto* tokenUser = reinterpret_cast<TOKEN_USER*>(buf.data());
                wchar_t name[256]{};
                wchar_t domain[256]{};
                DWORD nameLen = 256, domainLen = 256;
                SID_NAME_USE use;
                if (LookupAccountSidW(nullptr, tokenUser->User.Sid, name, &nameLen,
                    domain, &domainLen, &use)) {
                    std::wstring wide = std::wstring(domain) + L"\\" + std::wstring(name);
                    // Account names are ASCII-safe in practice -- explicit
                    // per-char cast rather than the iterator-range assign so
                    // this doesn't trip C4244 under /WX (no /wd4244 here).
                    identity.clear();
                    identity.reserve(wide.size());
                    for (wchar_t wc : wide) identity.push_back(static_cast<char>(wc));
                }
            }
        }
        CloseHandle(token);
    }

    RevertToSelf();
    return identity;
}

std::string IpcControlServer::Dispatch(const std::string& requestJson, void* pipeHandle) {
    std::string command;
    ExtractJsonStringField(requestJson, "command", command);
    std::string requestId;
    ExtractJsonStringField(requestJson, "request_id", requestId);

    bool ok = true;
    std::string error;
    std::string extra;

    const bool isMutating = (command == "StartMonitoring" || command == "StopMonitoring" ||
        command == "SetPersistence" || command == "SetRetentionBudget" || command == "Shutdown");
    bool staleRejected = false;
    if (isMutating) {
        std::string expectedSession;
        if (ExtractJsonStringField(requestJson, "expected_session_id", expectedSession) &&
            expectedSession != logger_.GetSessionId()) {
            ok = false;
            error = "stale_session: caller's expected_session_id does not match the current process session.";
            staleRejected = true;
        }
        uint64_t expectedRevision = 0;
        if (!staleRejected && ExtractJsonUint64Field(requestJson, "expected_revision", expectedRevision) &&
            expectedRevision != revision_.load()) {
            ok = false;
            error = "stale_revision: state has changed since the caller last read status (expected " +
                std::to_string(expectedRevision) + ", current " + std::to_string(revision_.load()) + ").";
            staleRejected = true;
        }
    }

    if (staleRejected) {
        // fall through to audit below, command not executed
    }
    else if (command == "GetStatus") {
        // no-op
    }
    else if (command == "StartMonitoring") {
        collecting_enabled_.store(true);
        revision_.fetch_add(1, std::memory_order_relaxed);
    }
    else if (command == "StopMonitoring") {
        collecting_enabled_.store(false);
        revision_.fetch_add(1, std::memory_order_relaxed);
    }
    else if (command == "SetPersistence") {
        bool enabled = true;
        if (!ExtractJsonBoolField(requestJson, "enabled", enabled)) {
            ok = false;
            error = "Missing or invalid 'enabled' boolean.";
        } else {
            logger_.SetPersistenceEnabled(enabled);
            revision_.fetch_add(1, std::memory_order_relaxed);
        }
    }
    else if (command == "SetRetentionBudget") {
        uint64_t budgetBytes = 0;
        if (!ExtractJsonUint64Field(requestJson, "budget_bytes", budgetBytes) || budgetBytes == 0) {
            ok = false;
            error = "Missing or invalid positive 'budget_bytes' integer.";
        } else {
            const uint64_t packBytes = CorrelatorLogger::GetMaxPackFileBytes();
            size_t packs = static_cast<size_t>((budgetBytes + packBytes - 1) / packBytes);
            if (packs < 1) packs = 1;
            if (packs > 4096) packs = 4096;
            logger_.SetMaxPacks(packs);
            revision_.fetch_add(1, std::memory_order_relaxed);
            extra = ",\"retention_budget_bytes\":" + std::to_string(budgetBytes) +
                ",\"retention_pack_limit\":" + std::to_string(packs);
        }
    }
    else if (command == "Flush") {
        logger_.Flush();
    }
    else if (command == "GetRecentEvents") {
        // Correlator has no in-memory recent-lines ring (its own output is
        // low-volume session_timeline/health, not a high-rate event stream
        // like Process) -- honestly reports an empty array rather than
        // fabricating a buffer that doesn't exist.
        extra = ",\"recent_events\":[]";
    }
    else if (command == "Shutdown") {
        revision_.fetch_add(1, std::memory_order_relaxed);
        if (shutdown_callback_) {
            auto callback = shutdown_callback_;
            std::thread([callback] {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                callback();
            }).detach();
        }
    }
    else {
        ok = false;
        error = "Unknown command: " + command;
    }

    if (isMutating) {
        const std::string caller = CaptureCallerIdentity(pipeHandle);
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::ostringstream audit;
        audit << "{\"t_unix_ms\":" << now_ms << ",\"endpoint\":\"correlator\","
              << "\"type\":\"control_audit\",\"command\":\"" << JsonEscape(command) << "\","
              << "\"request_id\":\"" << JsonEscape(requestId) << "\","
              << "\"caller\":\"" << JsonEscape(caller) << "\","
              << "\"accepted\":" << (ok ? "true" : "false") << ","
              << "\"reason\":" << (error.empty() ? "null" : ("\"" + JsonEscape(error) + "\"")) << ","
              << "\"revision_after\":" << revision_.load() << "}";
        logger_.Log(audit.str());
    }

    std::ostringstream out;
    out << "{\"proto_version\":1,\"request_id\":\"" << JsonEscape(requestId) << "\","
        << "\"ok\":" << (ok ? "true" : "false") << ","
        << "\"error\":" << (error.empty() ? "null" : ("\"" + JsonEscape(error) + "\"")) << ","
        << "\"endpoint_id\":\"correlator\","
        << "\"session_id\":\"" << logger_.GetSessionId() << "\","
        << "\"revision\":" << revision_.load() << ","
        << "\"monitoring_enabled\":" << (collecting_enabled_.load() ? "true" : "false") << ","
        << "\"save_logs_enabled\":" << (logger_.IsPersistenceEnabled() ? "true" : "false") << ","
        << "\"queue_dropped\":" << 0
        << extra
        << "}";
    return out.str();
}

} // namespace correlator
