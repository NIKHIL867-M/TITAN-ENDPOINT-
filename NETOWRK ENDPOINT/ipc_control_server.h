#ifndef TITAN_IPC_CONTROL_SERVER_H
#define TITAN_IPC_CONTROL_SERVER_H

// ============================================================================
// ipc_control_server.h — FORU.TXT section 4, extended to the Network endpoint.
// Same authenticated named-pipe pattern as
// PROCESS ENDPOINT\titan_fixed\ipc_control_server.h (session/revision-bound
// mutating commands, per-request audit trail with caller identity) -- see
// that file's header comment for the full rationale, not repeated here.
// ============================================================================

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <functional>

namespace titan {

class NetworkMonitor;
class AsyncLogger;

class IpcControlServer {
public:
    IpcControlServer(NetworkMonitor& monitor, AsyncLogger& logger,
        std::function<void()> shutdownCallback);
    ~IpcControlServer();

    IpcControlServer(const IpcControlServer&) = delete;
    IpcControlServer& operator=(const IpcControlServer&) = delete;

    bool Start();
    void Stop();

    static constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\TitanEndpoint_Network_Control";

private:
    void ServerLoop();
    void HandleOneConnection(void* pipeHandle);
    std::string Dispatch(const std::string& requestJson, void* pipeHandle);
    static std::string CaptureCallerIdentity(void* pipeHandle);

    NetworkMonitor& monitor_;
    AsyncLogger& logger_;
    std::function<void()> shutdown_callback_;

    std::atomic<bool> running_{ false };
    std::atomic<uint64_t> revision_{ 0 };
    std::thread server_thread_;
};

} // namespace titan

#endif // TITAN_IPC_CONTROL_SERVER_H
