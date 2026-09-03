#ifndef TITAN_NETWORK_MONITOR_H
#define TITAN_NETWORK_MONITOR_H

// ============================================================================
// network_monitor.h  —  TITAN V4  Npcap Deep-Packet Network Monitor
//
// Responsibilities:
//   1. Load Npcap DLLs from System32\Npcap.
//   2. Enumerate all non-loopback adapters.
//   3. Per-adapter pcap_loop capture thread.
//   4. Parse Ethernet -> IPv4/IPv6 -> TCP/UDP/ICMP.
//   5. Application-layer identification (HTTP, TLS-SNI, DNS, QUIC, RDP, SMB, SSH, SMTP).
//   6. PID resolution via GetExtendedTcpTable / GetExtendedUdpTable (refreshed every 500ms).
//   7. Best-effort local PID and process-name correlation.
//   8. Flow state tracking in a bounded table.
//   9. Write first observations and periodic flow deltas to bounded JSONL.
//  10. Preserve retained packet bytes in bounded rotating PCAP files.
//
// V4 -- replaces the old ETW-network path entirely.
// ============================================================================

// Winsock2 must precede windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

#include "event.h"
#include "logger.h"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Npcap
#include <pcap.h>
#include <deque>

namespace titan {

    // ============================================================================
    // FLOW KEY -- 5-tuple used as hash map key
    // ============================================================================

    struct FlowKey {
        std::string local_addr;
        std::string remote_addr;
        uint16_t    local_port{ 0 };
        uint16_t    remote_port{ 0 };
        uint8_t     protocol{ 0 };

        bool operator==(const FlowKey& o) const noexcept {
            return local_addr == o.local_addr && remote_addr == o.remote_addr
                && local_port == o.local_port && remote_port == o.remote_port
                && protocol == o.protocol;
        }
    };

    struct FlowKeyHash {
        size_t operator()(const FlowKey& k) const noexcept {
            size_t h = std::hash<std::string>{}(k.local_addr);
            h ^= std::hash<std::string>{}(k.remote_addr) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<uint32_t>{}(
                (static_cast<uint32_t>(k.local_port) << 16) | k.remote_port)
                + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<uint8_t>{}(k.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };

    // ============================================================================
    // FLOW STATE -- per-flow accumulator
    // ============================================================================

    struct FlowState {
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;
        NetworkDirection direction{ NetworkDirection::UNKNOWN };
        TcpState         tcp_state{ TcpState::UNKNOWN };
        uint32_t         pid{ 0 };
        uint64_t         bytes_sent{ 0 };
        uint64_t         bytes_recv{ 0 };
        uint32_t         packet_count{ 0 };
        uint32_t         last_emitted_packet_count{ 0 };
        std::chrono::steady_clock::time_point last_emitted;
    };

    // ============================================================================
    // SOCKET->PID CACHE KEY
    // ============================================================================

    struct SocketPidKey {
        std::string local_ip;
        uint16_t    local_port{ 0 };
        uint8_t     proto{ 0 };

        bool operator==(const SocketPidKey& o) const noexcept {
            return local_ip == o.local_ip && local_port == o.local_port
                && proto == o.proto;
        }
    };

    struct SocketPidKeyHash {
        size_t operator()(const SocketPidKey& k) const noexcept {
            size_t h = std::hash<std::string>{}(k.local_ip);
            h ^= std::hash<uint32_t>{}(
                (static_cast<uint32_t>(k.local_port) << 8) | k.proto)
                + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };

    // ============================================================================
    // ADAPTER CONTEXT
    // ============================================================================

    struct AdapterCtx {
        std::string  name;
        pcap_t* handle{ nullptr };
        pcap_dumper_t* dumper{ nullptr };
        uint64_t raw_bytes{ 0 };
        unsigned raw_slot{ 0 };
        std::filesystem::path raw_base;
        std::string raw_session;
        uint64_t raw_generation{ 0 };
        std::filesystem::path raw_current_path;
        std::deque<std::filesystem::path> raw_retained_paths;
        std::thread  thread;
    };

    // ============================================================================
    // NETWORK MONITOR
    // ============================================================================

    class NetworkMonitor {
    public:
        explicit NetworkMonitor(AsyncLogger& logger,
            const std::wstring& log_directory);
        ~NetworkMonitor();

        NetworkMonitor(const NetworkMonitor&) = delete;
        NetworkMonitor& operator=(const NetworkMonitor&) = delete;

        bool Start();
        void Stop();
        bool IsRunning() const noexcept { return running_.load(); }

        // FORU.TXT section 4: Monitoring toggle via the IPC control channel,
        // independent of whether capture threads are actually running --
        // mirrors Process's ProcessMonitor::SetMonitoringEnabled exactly.
        // When false, HandlePacket discards immediately (no parsing,
        // enrichment, or logging) rather than tearing down pcap_loop.
        void SetMonitoringEnabled(bool enabled) noexcept { monitoring_enabled_.store(enabled); }
        bool IsMonitoringEnabled() const noexcept { return monitoring_enabled_.load(); }

        // Capture and aggregation counters.
        uint64_t GetPacketsCaptured()  const noexcept { return pkts_captured_.load(); }
        uint64_t GetCaptureDrops() const noexcept { return capture_drops_.load(); }
        uint64_t GetInterfaceDrops() const noexcept { return interface_drops_.load(); }
        uint64_t GetRawCaptureFailures() const noexcept {
            return raw_capture_failures_.load();
        }
        uint64_t GetStructuredUnparsedPackets() const noexcept {
            return structured_unparsed_packets_.load();
        }
        uint64_t GetFlowsForwarded()   const noexcept { return flows_forwarded_.load(); }
        uint64_t GetSuppressedPackets() const noexcept {
            return suppressed_packets_.load();
        }

    private:
        // Startup helpers
        bool LoadNpcapDlls();
        void EnumerateAdapters();
        void BuildLocalIpSet();
        void BuildPortAppMap();
        bool IsLocalIp(const std::string& ip) const;

        // Per-adapter capture thread entry point
        void CaptureThread(AdapterCtx* adapter);

        // Packet pipeline
        void HandlePacket(const struct pcap_pkthdr* header,
            const uint8_t* data,
            AdapterCtx& adapter);
        bool OpenRawDumper(AdapterCtx& adapter);
        void RotateRawDumperIfNeeded(AdapterCtx& adapter,
            uint32_t incoming_bytes);

        // Parsers
        bool ParseEthernet(const uint8_t* data, uint32_t len, NetworkInfo& out);
        bool ParseArp(const uint8_t* data, uint32_t len, NetworkInfo& out);
        bool ParseIPv4(const uint8_t* data, uint32_t len, NetworkInfo& out);
        bool ParseIPv6(const uint8_t* data, uint32_t len, NetworkInfo& out);
        bool ParseTCP(const uint8_t* data, uint32_t len, NetworkInfo& out, bool is_src_local);
        bool ParseUDP(const uint8_t* data, uint32_t len, NetworkInfo& out, bool is_src_local);
        bool ParseICMP(const uint8_t* data, uint32_t len, NetworkInfo& out);

        // Application-layer identification
        void IdentifyAppLayer(const uint8_t* payload, uint32_t len, NetworkInfo& out);
        void ParseDnsQuery(const uint8_t* payload, uint32_t len,
            bool tcp, NetworkInfo& out);
        void ParseDnsResponse(const uint8_t* payload, uint32_t len,
            bool tcp, NetworkInfo& out);
        void ParseTlsClientHello(const uint8_t* payload, uint32_t len,
            NetworkInfo& out);
        void ParseHttpMessage(const uint8_t* payload, uint32_t len,
            NetworkInfo& out);

        // Flow state
        bool UpdateFlowState(NetworkInfo& info);

        // PID resolution
        void  RefreshPidCache();
        DWORD LookupPid(const std::string& local_ip, uint16_t local_port,
            uint8_t proto) const;

        // Process enrichment
        // Lightweight process name resolution (short name only)
        void ResolveProcessName(DWORD pid, NetworkInfo& out);

        // ---- members ----
        AsyncLogger& logger_;
        std::filesystem::path raw_capture_directory_;
        static constexpr uint64_t kRawPcapBytes = 4ULL * 1024 * 1024;

        std::vector<AdapterCtx> adapters_;

        // Local IP set for direction detection
        mutable std::mutex                  local_ip_mutex_;
        std::unordered_set<std::string>     local_ips_;

        // Flow table
        static constexpr size_t kMaxFlows = 8192;
        mutable std::mutex                                          flow_mutex_;
        std::unordered_map<FlowKey, FlowState, FlowKeyHash>        flow_table_;
        uint64_t flow_insertions_{ 0 };

        // Port -> AppLayer hint map
        std::unordered_map<uint16_t, AppLayer> port_app_map_;

        // PID cache (refreshed every kPidRefreshMs)
        static constexpr uint32_t kPidRefreshMs = 500;
        static constexpr size_t kMaxPidEntries = 32768;
        mutable std::mutex  pid_mutex_;
        std::unordered_map<SocketPidKey, DWORD, SocketPidKeyHash>  pid_cache_;
        std::thread         pid_refresh_thread_;

        std::atomic<bool>     running_{ false };
        std::atomic<bool>     stop_requested_{ false };
        std::atomic<bool>     monitoring_enabled_{ true };

        // Capture and aggregation counters.
        std::atomic<uint64_t> pkts_captured_{ 0 };
        std::atomic<uint64_t> capture_drops_{ 0 };
        std::atomic<uint64_t> interface_drops_{ 0 };
        std::atomic<uint64_t> raw_capture_failures_{ 0 };
        std::atomic<uint64_t> structured_unparsed_packets_{ 0 };
        std::atomic<uint64_t> flows_forwarded_{ 0 };
        std::atomic<uint64_t> suppressed_packets_{ 0 };
    };

} // namespace titan

#endif // TITAN_NETWORK_MONITOR_H
