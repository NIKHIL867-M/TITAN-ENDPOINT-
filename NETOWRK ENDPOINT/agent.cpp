#include "agent.h"
#include "ipc_control_server.h"

#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

namespace titan {

    // ============================================================================
    // GLOBAL SIGNAL HANDLER
    // ============================================================================

    static volatile std::sig_atomic_t g_stop_requested = 0;

    static void SignalHandler(int) {
        g_stop_requested = 1;
    }

    // ============================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ============================================================================

    Agent::Agent() = default;
    Agent::~Agent() { Stop(); }

    // ============================================================================
    // ADMIN PRIVILEGE CHECK
    // ============================================================================

    bool Agent::CheckAdminPrivileges() {
        BOOL is_admin = FALSE;
        PSID administrators_group = nullptr;
        SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
            &administrators_group)) {
            CheckTokenMembership(nullptr, administrators_group, &is_admin);
            FreeSid(administrators_group);
        }
        return is_admin == TRUE;
    }

    // ============================================================================
    // INITIALIZE
    // ============================================================================

    bool Agent::Initialize(const std::wstring& log_path) {
        if (initialized_)
            return true;

        log_path_ = log_path;

        ConsoleLogger::LogInfo("Initializing TITAN V4 Network Agent...");
        ConsoleLogger::LogInfo("Signal Amplifier + Noise Suppressor");
        ConsoleLogger::LogInfo(
            "Bounded state with explicit capture/log loss accounting");

        if (!CheckAdminPrivileges()) {
            ConsoleLogger::LogError("Administrator privileges required");
            ConsoleLogger::LogError("Please run as Administrator");
            return false;
        }
        ConsoleLogger::LogInfo("Administrator privileges confirmed");

        // Logger
        logger_ = std::make_unique<AsyncLogger>(log_path_);
        if (!logger_->Initialize()) {
            ConsoleLogger::LogError("Failed to initialize logger");
            return false;
        }

        // Network Monitor (Npcap — required)
        network_monitor_ = std::make_unique<NetworkMonitor>(
            *logger_, log_path_);

        // FORU.TXT section 4: authenticated local control channel.
        ipc_control_server_ = std::make_unique<IpcControlServer>(
            *network_monitor_, *logger_, [this] { Stop(); });

        initialized_ = true;
        ConsoleLogger::LogInfo("TITAN V4 Network Agent initialized successfully");
        ConsoleLogger::LogInfo("Ready: Npcap deep-packet capture active");
        return true;
    }

    // ============================================================================
    // START
    // ============================================================================

    bool Agent::Start(uint32_t duration_seconds) {
        if (!initialized_) {
            ConsoleLogger::LogError("Agent not initialized");
            return false;
        }
        if (running_)
            return true;

        ConsoleLogger::LogInfo("Starting TITAN V4 Network Agent...");

        if (!network_monitor_->Start()) {
            ConsoleLogger::LogError("Failed to start network monitor — is Npcap installed?");
            return false;
        }

        if (ipc_control_server_ && !ipc_control_server_->Start()) {
            ConsoleLogger::LogWarning("Failed to start IPC control channel — remote control will be "
                "unavailable, capture continues normally.");
        }

        running_ = true;
        g_stop_requested = 0;

        std::signal(SIGINT, SignalHandler);
        std::signal(SIGTERM, SignalHandler);

        ConsoleLogger::LogInfo("TITAN V4 running. Press Ctrl+C to stop.");
        ConsoleLogger::LogInfo(
            "Output: first observation + 30-second flow deltas + raw PCAP");

        int counter = 0;
        uint32_t elapsed = 0;
        while (running_ && g_stop_requested == 0) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            ++elapsed;
            if (++counter >= 10) {
                PrintStatus();
                counter = 0;
            }
            if (duration_seconds != 0 && elapsed >= duration_seconds) {
                g_stop_requested = 1;
                break;
            }
        }
        Stop();
        return true;
    }

    // ============================================================================
    // STOP
    // ============================================================================

    void Agent::Stop() {
        if (!running_)
            return;

        ConsoleLogger::LogInfo("Stopping TITAN V4 Network Agent...");
        running_ = false;

        if (ipc_control_server_)
            ipc_control_server_->Stop();

        if (network_monitor_)
            network_monitor_->Stop();

        if (logger_ && network_monitor_) {
            logger_->LogHealthRecord(
                network_monitor_->GetCaptureDrops(),
                network_monitor_->GetInterfaceDrops(),
                network_monitor_->GetRawCaptureFailures(),
                network_monitor_->GetStructuredUnparsedPackets(),
                network_monitor_->GetSuppressedPackets(),
                network_monitor_->IsMonitoringEnabled(),
                /*final_record=*/true);
        }
        if (logger_)
            logger_->Shutdown();

        ConsoleLogger::LogInfo("TITAN V4 Network Agent stopped");
    }

    // ============================================================================
    // STATUS
    // ============================================================================

    void Agent::PrintStatus() const {
        if (!network_monitor_ || !logger_)
            return;

        // RAM/disk auto-lightening -- sampled on this existing ~10s cadence.
        logger_->UpdateResourcePressure();

        // FIX (Round 3 live testing): collector_health was previously only
        // ever emitted once, at clean shutdown (Agent::Stop()) -- meaning a
        // long-running, perfectly healthy agent wrote zero health evidence
        // the entire time it ran. An operator (or the Correlator) had no
        // way to distinguish "healthy and quiet" from "silently hung" for
        // this endpoint. PrintStatus() already gathers every metric
        // LogHealthRecord() needs on this same ~10s cadence -- just also
        // persist it, not only print it.
        logger_->LogHealthRecord(
            network_monitor_->GetCaptureDrops(),
            network_monitor_->GetInterfaceDrops(),
            network_monitor_->GetRawCaptureFailures(),
            network_monitor_->GetStructuredUnparsedPackets(),
            network_monitor_->GetSuppressedPackets(),
            network_monitor_->IsMonitoringEnabled(),
            /*final_record=*/false);

        const uint64_t packets = network_monitor_->GetPacketsCaptured();
        const uint64_t forwarded = network_monitor_->GetFlowsForwarded();
        const uint64_t suppressed =
            network_monitor_->GetSuppressedPackets();
        const uint64_t ratio = packets > 0
            ? (suppressed * 100) / packets : 0;

        std::cout << "[STATUS]"
            << " Packets: " << packets
            << " | FlowLogs: " << forwarded
            << " | Suppressed: " << suppressed
            << " | Suppression: " << ratio << "%"
            << " | Q: " << logger_->GetQueuedCount()
            << " | LogDrop: " << logger_->GetDroppedCount()
            << " | LogFail: " << logger_->GetStorageFailureCount()
            << " | CapDrop: " << network_monitor_->GetCaptureDrops()
            << " | IfDrop: " << network_monitor_->GetInterfaceDrops()
            << " | RawFail: " << network_monitor_->GetRawCaptureFailures()
            << " | Unparsed: "
            << network_monitor_->GetStructuredUnparsedPackets()
            << std::endl;
    }

} // namespace titan
