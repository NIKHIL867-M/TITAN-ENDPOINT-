#ifndef TITAN_AGENT_H
#define TITAN_AGENT_H

#include "ipc_control_server.h"
#include "logger.h"
#include "network_monitor.h"

#include <atomic>
#include <memory>
#include <string>

namespace titan {

    // ============================================================================
    // Agent  —  TITAN V4  Network Endpoint
    // Boots and owns all components.
    // Responsibilities:
    //   - Initialize the bounded asynchronous JSONL logger
    //   - Initialize NetworkMonitor (Npcap deep-packet capture)
    //   - Run the main loop and emit capture/flow health every 10s
    //   - Clean shutdown on SIGINT / SIGTERM
    // ============================================================================

    class Agent {
    public:
        Agent();
        ~Agent();

        Agent(const Agent&) = delete;
        Agent& operator=(const Agent&) = delete;

        // Initialize all sub-components.
        // log_path: directory where .jsonl log packs are written.
        bool Initialize(const std::wstring& log_path);

        // Start monitoring. Blocks until Stop() is called.
        bool Start(uint32_t duration_seconds = 0);

        // Signal-safe stop. Can be called from signal handler.
        void Stop();

        // Print capture, aggregation, loss, and storage status to stdout.
        void PrintStatus() const;

    private:
        bool CheckAdminPrivileges();

        std::atomic<bool> initialized_{ false };
        std::atomic<bool> running_{ false };
        std::wstring log_path_;

        std::unique_ptr<AsyncLogger>    logger_;
        std::unique_ptr<NetworkMonitor> network_monitor_;
        std::unique_ptr<IpcControlServer> ipc_control_server_;
    };

} // namespace titan

#endif // TITAN_AGENT_H
