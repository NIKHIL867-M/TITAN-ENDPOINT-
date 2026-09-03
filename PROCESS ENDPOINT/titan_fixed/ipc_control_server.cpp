#include "ipc_control_server.h"
#include "process_monitor.h"
#include "logger.h"

#include <windows.h>
#include <sddl.h>
#include <cstdlib>
#include <sstream>
#include <chrono>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace titan {

namespace {

// Same minimal, dependency-free named-key extraction convention as
// CORRELATOR\json_fields.h — duplicated rather than shared, per this
// project's "no shared library between programs" rule.
bool ExtractJsonString(const std::string& line, const std::string& key, std::string& out) {
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

bool ExtractJsonBool(const std::string& line, const std::string& key, bool& out) {
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

// Unsigned integer extraction for expected_revision -- deliberately rejects
// (returns false) anything that isn't a plain run of digits, rather than
// guessing at a partial number.
bool ExtractJsonUint64(const std::string& line, const std::string& key, uint64_t& out) {
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

IpcControlServer::IpcControlServer(ProcessMonitor& monitor, AsyncLogger& logger,
    std::function<void()> shutdownCallback)
    : monitor_(monitor), logger_(logger), shutdown_callback_(std::move(shutdownCallback)) {
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

    // Unblock a pending ConnectNamedPipe() call in ServerLoop by connecting to
    // ourselves once — its next check of running_ (right after that connection
    // completes) will see false and exit cleanly instead of blocking forever.
    HANDLE h = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

    if (server_thread_.joinable()) server_thread_.join();
}

void IpcControlServer::ServerLoop() {
    // Explicit DACL: Administrators (BA), Local System (SY) and the pipe's own
    // creator/owner (OW) get full duplex access; every other principal is
    // implicitly denied since no other ACE grants access (FORU.TXT 4.1:
    // "restrictive ACL for Administrators, SYSTEM and the current authorized
    // user").
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
                    identity.assign(wide.begin(), wide.end()); // account names are ASCII-safe
                }
            }
        }
        CloseHandle(token);
    }

    RevertToSelf(); // MUST run regardless of the outcome above -- never stay impersonated.
    return identity;
}

std::string IpcControlServer::Dispatch(const std::string& requestJson, void* pipeHandle) {
    std::string command;
    ExtractJsonString(requestJson, "command", command);
    std::string requestId;
    ExtractJsonString(requestJson, "request_id", requestId);

    bool ok = true;
    std::string error;
    std::string extra; // command-specific extra fields appended to the common status block

    // FORU.TXT section 4 (2026-08-02): bind state-changing commands to the
    // session/revision the caller last observed, and reject stale ones. Only
    // commands that actually mutate state are gated -- GetStatus/Flush/
    // GetRecentEvents are always safe to serve regardless of staleness.
    const bool isMutating = (command == "StartMonitoring" || command == "StopMonitoring" ||
        command == "SetPersistence" || command == "SetRetentionBudget" || command == "Shutdown");
    bool staleRejected = false;
    if (isMutating) {
        std::string expectedSession;
        if (ExtractJsonString(requestJson, "expected_session_id", expectedSession) &&
            expectedSession != logger_.GetSessionId()) {
            ok = false;
            error = "stale_session: caller's expected_session_id does not match the current "
                    "process session -- this endpoint restarted since the caller last read status.";
            staleRejected = true;
        }
        uint64_t expectedRevision = 0;
        if (!staleRejected && ExtractJsonUint64(requestJson, "expected_revision", expectedRevision) &&
            expectedRevision != revision_.load()) {
            ok = false;
            error = "stale_revision: state has changed since the caller last read status "
                    "(expected " + std::to_string(expectedRevision) + ", current " +
                    std::to_string(revision_.load()) + ").";
            staleRejected = true;
        }
    }

    if (staleRejected) {
        // Fall through to the audit log below without executing the command.
    }
    else if (command == "GetStatus") {
        // no-op — common status block below is the whole point
    }
    else if (command == "StartMonitoring") {
        monitor_.SetMonitoringEnabled(true);
        revision_.fetch_add(1, std::memory_order_relaxed);
    }
    else if (command == "StopMonitoring") {
        monitor_.SetMonitoringEnabled(false);
        revision_.fetch_add(1, std::memory_order_relaxed);
    }
    else if (command == "SetPersistence") {
        bool enabled = true;
        if (!ExtractJsonBool(requestJson, "enabled", enabled)) {
            ok = false;
            error = "Missing or invalid 'enabled' boolean.";
        }
        else {
            logger_.SetSaveLogsEnabled(enabled);
            revision_.fetch_add(1, std::memory_order_relaxed);
        }
    }
    else if (command == "SetRetentionBudget") {
        uint64_t budgetBytes = 0;
        if (!ExtractJsonUint64(requestJson, "budget_bytes", budgetBytes) || budgetBytes == 0) {
            ok = false;
            error = "Missing or invalid positive 'budget_bytes' integer.";
        } else {
            const uint64_t packBytes = AsyncLogger::GetMaxPackFileBytes();
            size_t packs = static_cast<size_t>((budgetBytes + packBytes - 1) / packBytes);
            if (packs < 1) packs = 1;
            if (packs > 4096) packs = 4096;
            monitor_.SetRetentionBudgetBytes(budgetBytes);
            revision_.fetch_add(1, std::memory_order_relaxed);
            extra = ",\"retention_budget_bytes\":" + std::to_string(budgetBytes) +
                ",\"retention_pack_limit\":" + std::to_string(packs);
        }
    }
    else if (command == "Flush") {
        logger_.Flush();
    }
    else if (command == "GetRecentEvents") {
        // Bounded in-memory transport for "Monitoring ON, Save Logs OFF" live
        // viewing (FORU.TXT 4.4) — polled by the GUI the same way it already
        // polls the JSONL file, just via this command instead when Save Logs
        // is off and there's nothing new on disk to tail.
        auto lines = logger_.GetRecentLines();
        std::ostringstream events;
        events << "[";
        for (size_t i = 0; i < lines.size(); ++i) {
            if (i) events << ",";
            events << lines[i];
        }
        events << "]";
        extra = ",\"recent_events\":" + events.str();
    }
    else if (command == "Shutdown") {
        revision_.fetch_add(1, std::memory_order_relaxed);
        // Must not call shutdown_callback_() synchronously here: it ultimately
        // calls Agent::Stop(), which calls this server's own Stop() and joins
        // server_thread_ — and this Dispatch() call is already running ON
        // server_thread_ (inside HandleOneConnection), so that join would
        // deadlock a thread against itself. Detach a one-shot thread instead,
        // giving HandleOneConnection time to flush this response back to the
        // client first.
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

    // FORU.TXT section 4: audit every accepted or rejected state change. Only
    // mutating commands are audited (GetStatus/Flush/GetRecentEvents are
    // read-only/idempotent noise, not state changes) -- routed through
    // logger_.LogRaw so it gets a real record_id/session_id/content_hash via
    // the same evidence envelope as everything else this endpoint writes.
    if (isMutating) {
        const std::string caller = CaptureCallerIdentity(pipeHandle);
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::ostringstream audit;
        audit << "{\"t_unix_ms\":" << now_ms << ",\"endpoint\":\"process_monitor\","
              << "\"type\":\"control_audit\",\"command\":\"" << JsonEscape(command) << "\","
              << "\"request_id\":\"" << JsonEscape(requestId) << "\","
              << "\"caller\":\"" << JsonEscape(caller) << "\","
              << "\"accepted\":" << (ok ? "true" : "false") << ","
              << "\"reason\":" << (error.empty() ? "null" : ("\"" + JsonEscape(error) + "\"")) << ","
              << "\"revision_after\":" << revision_.load() << "}";
        logger_.LogRaw(audit.str());
    }

    std::ostringstream out;
    out << "{\"proto_version\":1,\"request_id\":\"" << JsonEscape(requestId) << "\","
        << "\"ok\":" << (ok ? "true" : "false") << ","
        << "\"error\":" << (error.empty() ? "null" : ("\"" + JsonEscape(error) + "\"")) << ","
        << "\"endpoint_id\":\"process\","
        << "\"session_id\":\"" << logger_.GetSessionId() << "\","
        << "\"revision\":" << revision_.load() << ","
        << "\"monitoring_enabled\":" << (monitor_.IsMonitoringEnabled() ? "true" : "false") << ","
        << "\"save_logs_enabled\":" << (logger_.IsSaveLogsEnabled() ? "true" : "false") << ","
        << "\"events_processed\":" << monitor_.GetEventsProcessed() << ","
        << "\"events_forwarded\":" << monitor_.GetEventsForwarded() << ","
        << "\"events_compressed\":" << monitor_.GetEventsCompressed() << ","
        << "\"queue_dropped\":" << logger_.GetQueueDroppedCount()
        << extra
        << "}";
    return out.str();
}

} // namespace titan
