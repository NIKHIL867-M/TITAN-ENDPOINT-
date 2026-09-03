#ifndef TITAN_IPC_CONTROL_SERVER_H
#define TITAN_IPC_CONTROL_SERVER_H

// ============================================================================
// ipc_control_server.h — FORU.TXT section 4: authenticated local control
// channel for Monitoring/Save Logs, independent of process start/stop.
//
// Windows named pipe, restricted via an explicit security descriptor to
// Administrators, SYSTEM and the pipe's own creating user (Owner) only —
// every other principal is implicitly denied since the DACL we supply has no
// other ACEs. One client at a time (the GUI); each connection handles exactly
// one request/response JSON line, then disconnects, matching the project's
// existing hand-rolled single-line-JSON convention (no library).
//
// Commands: GetStatus, StartMonitoring, StopMonitoring, SetPersistence,
// Flush, Shutdown (FORU.TXT 4.2). Monitoring controls whether ProcessMonitor
// processes/forwards ETW events at all; Save Logs controls only whether
// AsyncLogger persists forwarded events to disk — turning Save Logs off never
// deletes retained evidence and does not stop live processing, matching
// FORU.TXT 4.3-4.5.
//
// FORU.TXT section 4 (2026-08-02 revision) additionally requires binding
// requests to endpoint/session/revision, rejecting stale acknowledgements,
// and auditing every accepted or rejected state change:
//   - GetStatus returns endpoint_id/session_id/revision. State-changing
//     commands (StartMonitoring/StopMonitoring/SetPersistence/Shutdown) may
//     include "expected_session_id"/"expected_revision"; if present and
//     stale (a different process launch, or someone else already changed
//     state since the caller last read it), the command is REJECTED rather
//     than blindly applied. Omitting them is still accepted (backward
//     compatible with a caller that hasn't read status yet), but the GUI
//     always has a fresh GetStatus before it acts, so it always sends both.
//   - Every dispatch (accepted or rejected) is written as a real
//     "control_audit" record through the SAME evidence pipeline as
//     everything else (logger_.LogRaw), including the caller's Windows
//     identity (captured via ImpersonateNamedPipeClient — the DACL above
//     already restricts WHO can connect at all; this records WHO specifically
//     did, for after-the-fact audit). That also means every audit entry gets
//     a durable record_id/content_hash for free via evidence_envelope.h.
// ============================================================================

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <functional>

namespace titan {

class ProcessMonitor;
class AsyncLogger;

class IpcControlServer {
public:
    IpcControlServer(ProcessMonitor& monitor, AsyncLogger& logger,
        std::function<void()> shutdownCallback);
    ~IpcControlServer();

    IpcControlServer(const IpcControlServer&) = delete;
    IpcControlServer& operator=(const IpcControlServer&) = delete;

    bool Start();
    void Stop();

    static constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\TitanEndpoint_Process_Control";

private:
    void ServerLoop();
    // Handles exactly one connect/read/dispatch/write/disconnect cycle. Never
    // throws -- any failure just ends that one connection attempt.
    void HandleOneConnection(void* pipeHandle);
    std::string Dispatch(const std::string& requestJson, void* pipeHandle);

    // Captures the connected client's Windows account name via
    // ImpersonateNamedPipeClient/GetTokenInformation/LookupAccountSidW, always
    // calling RevertToSelf before returning (even on failure). Returns
    // "unknown" rather than throwing/crashing if any step fails -- an audit
    // trail that's sometimes "unknown" is still far better than one that
    // takes the server down.
    static std::string CaptureCallerIdentity(void* pipeHandle);

    ProcessMonitor& monitor_;
    AsyncLogger& logger_;
    std::function<void()> shutdown_callback_;

    std::atomic<bool> running_{ false };
    std::atomic<uint64_t> revision_{ 0 };
    std::thread server_thread_;
};

} // namespace titan

#endif // TITAN_IPC_CONTROL_SERVER_H
