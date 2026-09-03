#pragma once

// ============================================================================
// ipc_control_server.h — FORU.TXT section 4, extended to the File endpoint.
// Same authenticated named-pipe pattern as
// PROCESS ENDPOINT\titan_fixed\ipc_control_server.h -- see that file's
// header comment for the full rationale, not repeated here.
// ============================================================================

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <functional>

namespace titan::fim {

class FileMonitor;

class IpcControlServer {
public:
    IpcControlServer(FileMonitor& monitor, std::function<void()> shutdownCallback);
    ~IpcControlServer();

    IpcControlServer(const IpcControlServer&) = delete;
    IpcControlServer& operator=(const IpcControlServer&) = delete;

    bool Start();
    void Stop();

    static constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\TitanEndpoint_File_Control";

private:
    void ServerLoop();
    void HandleOneConnection(void* pipeHandle);
    std::string Dispatch(const std::string& requestJson, void* pipeHandle);
    static std::string CaptureCallerIdentity(void* pipeHandle);

    FileMonitor& monitor_;
    std::function<void()> shutdown_callback_;

    std::atomic<bool> running_{ false };
    std::atomic<uint64_t> revision_{ 0 };
    std::thread server_thread_;
};

} // namespace titan::fim
