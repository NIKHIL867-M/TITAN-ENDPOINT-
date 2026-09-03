#ifndef TITAN_IPC_CONTROL_SERVER_H
#define TITAN_IPC_CONTROL_SERVER_H

// ============================================================================
// ipc_control_server.h — FORU.TXT section 4, extended to the Correlator.
// Same authenticated named-pipe pattern as
// PROCESS ENDPOINT\titan_fixed\ipc_control_server.h (session/revision-bound
// mutating commands, per-request audit trail with caller identity) --
// see that file's header comment for the full rationale, not repeated here.
//
// Correlator-specific command mapping: "Monitoring" controls whether the main
// loop ingests+correlates at all (StartMonitoring/StopMonitoring); "Save
// Logs"/persistence controls whether CorrelatorLogger actually writes
// session_timeline/health output to disk (SetPersistence) -- same
// independence guarantee as every other endpoint (4.3-4.5).
// ============================================================================

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <functional>

namespace correlator {

class CorrelatorLogger;

class IpcControlServer {
public:
    IpcControlServer(std::atomic<bool>& collectingEnabled, CorrelatorLogger& logger,
        std::function<void()> shutdownCallback);
    ~IpcControlServer();

    IpcControlServer(const IpcControlServer&) = delete;
    IpcControlServer& operator=(const IpcControlServer&) = delete;

    bool Start();
    void Stop();

    static constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\TitanEndpoint_Correlator_Control";

private:
    void ServerLoop();
    void HandleOneConnection(void* pipeHandle);
    std::string Dispatch(const std::string& requestJson, void* pipeHandle);
    static std::string CaptureCallerIdentity(void* pipeHandle);

    std::atomic<bool>& collecting_enabled_;
    CorrelatorLogger& logger_;
    std::function<void()> shutdown_callback_;

    std::atomic<bool> running_{ false };
    std::atomic<uint64_t> revision_{ 0 };
    std::thread server_thread_;
};

} // namespace correlator

#endif // TITAN_IPC_CONTROL_SERVER_H
