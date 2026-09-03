#ifndef TITAN_EVENT_H
#define TITAN_EVENT_H

// Network-only event model. The File and Application endpoints own their own
// schemas; no process, file, registry, signature, or hash model is compiled
// into this endpoint.

// Winsock2 must precede windows.h.
#include <winsock2.h>
#include <windows.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace titan {

    enum class EventSource {
        NpcapLive
    };

    enum class NetworkDirection {
        INBOUND,
        OUTBOUND,
        UNKNOWN
    };

    enum class TcpState {
        SYN_SENT,
        SYN_RECEIVED,
        ESTABLISHED,
        FIN_WAIT,
        CLOSE_WAIT,
        CLOSED,
        UNKNOWN
    };

    enum class AppLayer {
        HTTP,
        HTTPS_TLS,
        DNS,
        RDP,
        SMB,
        QUIC,
        ICMP,
        NTP,
        DHCP,
        FTP,
        SSH,
        SMTP,
        ARP,
        IP_FRAGMENT,
        IPSEC,
        UNKNOWN
    };

    struct NetworkInfo {
        DWORD pid{ 0 };
        std::wstring process_name;

        std::string local_addr;
        USHORT local_port{ 0 };
        std::string remote_addr;
        USHORT remote_port{ 0 };
        bool is_tcp{ true };
        bool is_ipv6{ false };
        uint8_t transport_protocol{ 0 };
        std::string packet_src_addr;
        std::string packet_dst_addr;
        std::string adapter_name;
        uint64_t capture_epoch_us{ 0 };
        uint16_t ether_type{ 0 };
        std::vector<uint16_t> vlan_ids;

        NetworkDirection direction{ NetworkDirection::UNKNOWN };
        TcpState tcp_state{ TcpState::UNKNOWN };
        AppLayer app_layer{ AppLayer::UNKNOWN };
        // What the well-known port implied the protocol would be, before
        // payload inspection ran (UNKNOWN if neither port had an entry in
        // port_app_map_). protocol_mismatch is set when payload inspection
        // actually identified a protocol and it disagrees with this hint --
        // e.g. non-TLS traffic on 443, or a tunnel dressed up as DNS on 53.
        AppLayer port_hint{ AppLayer::UNKNOWN };
        bool protocol_mismatch{ false };

        uint64_t bytes_sent{ 0 };
        uint64_t bytes_recv{ 0 };
        uint32_t packet_count{ 0 };
        uint32_t packets_since_last_log{ 0 };
        uint64_t flow_duration_ms{ 0 };
        uint32_t captured_length{ 0 };
        uint32_t wire_length{ 0 };
        std::string raw_capture_segment;
        uint64_t raw_record_offset{ 0 };
        uint64_t raw_data_offset{ 0 };
        bool raw_capture_mapped{ false };
        uint32_t payload_length{ 0 };

        bool fragmented{ false };
        uint16_t fragment_offset{ 0 };
        bool more_fragments{ false };
        std::string dns_query;
        uint16_t dns_query_type{ 0 };
        // Semicolon-joined "type:value" answer records (e.g.
        // "A:93.184.216.34;A:93.184.216.35"), populated for DNS responses --
        // previously only queries were decoded, never responses.
        std::string dns_answers;
        std::string tls_sni;

        // Best-effort single-packet HTTP parsing (no TCP reassembly, so
        // only requests/responses that fit in one captured segment are
        // decoded -- matches this endpoint's existing honest-limitations
        // style for TLS/QUIC decryption and stream reassembly).
        bool http_is_request{ false };
        std::string http_method;
        std::string http_target;
        uint16_t http_status_code{ 0 };
        std::string http_reason;
        std::string http_host;

        bool is_broadcast{ false };
        bool is_loopback{ false };
    };

    class Event {
    public:
        Event() = default;
        ~Event() = default;

        Event(const Event&) = delete;
        Event& operator=(const Event&) = delete;
        Event(Event&&) noexcept = default;
        Event& operator=(Event&&) noexcept = default;

        static Event CreateNetworkEvent(
            const NetworkInfo& info, EventSource source);

        const NetworkInfo& GetNetworkInfo() const noexcept {
            return network_;
        }
        EventSource GetSource() const noexcept {
            return source_;
        }
        const std::chrono::system_clock::time_point& GetTimestamp() const noexcept {
            return timestamp_;
        }

        std::string ToJson() const;

    private:
        EventSource source_{ EventSource::NpcapLive };
        std::chrono::system_clock::time_point timestamp_{
            std::chrono::system_clock::now() };
        NetworkInfo network_;
    };

} // namespace titan

#endif // TITAN_EVENT_H
