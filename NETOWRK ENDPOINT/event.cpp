#include "event.h"

#include <ctime>
#include <iomanip>
#include <sstream>

namespace titan {
    namespace {
        std::string WideToUtf8(const std::wstring& value)
        {
            if (value.empty()) return {};
            const int input_size = static_cast<int>(value.size());
            const int required = WideCharToMultiByte(CP_UTF8,
                WC_ERR_INVALID_CHARS, value.data(), input_size,
                nullptr, 0, nullptr, nullptr);
            if (required <= 0) return {};
            std::string output(static_cast<size_t>(required), '\0');
            if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                value.data(), input_size, output.data(), required,
                nullptr, nullptr) != required)
                return {};
            return output;
        }

        std::string EscapeJson(const std::string& value)
        {
            std::ostringstream output;
            for (const unsigned char character : value) {
                switch (character) {
                case '"': output << "\\\""; break;
                case '\\': output << "\\\\"; break;
                case '\b': output << "\\b"; break;
                case '\f': output << "\\f"; break;
                case '\n': output << "\\n"; break;
                case '\r': output << "\\r"; break;
                case '\t': output << "\\t"; break;
                default:
                    if (character < 0x20) {
                        output << "\\u" << std::hex << std::setw(4)
                            << std::setfill('0')
                            << static_cast<unsigned>(character)
                            << std::dec;
                    }
                    else {
                        output << static_cast<char>(character);
                    }
                    break;
                }
            }
            return output.str();
        }

        std::string FormatTimestamp(
            const std::chrono::system_clock::time_point& timestamp)
        {
            const auto seconds =
                std::chrono::time_point_cast<std::chrono::seconds>(timestamp);
            const auto microseconds =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    timestamp - seconds).count();
            const std::time_t time = std::chrono::system_clock::to_time_t(seconds);
            std::tm utc{};
            if (gmtime_s(&utc, &time) != 0) return {};
            std::ostringstream output;
            output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S")
                << '.' << std::setw(6) << std::setfill('0')
                << microseconds << 'Z';
            return output.str();
        }

        // UTC epoch milliseconds -- shared join key for a future
        // cross-endpoint Correlator, named consistently with the other
        // 4 endpoints (capture_epoch_us above is microsecond-precision
        // but specific to this endpoint's own capture-clock convention).
        int64_t ToUnixMs(const std::chrono::system_clock::time_point& timestamp)
        {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                timestamp.time_since_epoch()).count();
        }

        const char* DirectionName(NetworkDirection direction) noexcept
        {
            switch (direction) {
            case NetworkDirection::INBOUND: return "INBOUND";
            case NetworkDirection::OUTBOUND: return "OUTBOUND";
            default: return "UNKNOWN";
            }
        }

        const char* TcpStateName(TcpState state) noexcept
        {
            switch (state) {
            case TcpState::SYN_SENT: return "SYN_SENT";
            case TcpState::SYN_RECEIVED: return "SYN_RECEIVED";
            case TcpState::ESTABLISHED: return "ESTABLISHED";
            case TcpState::FIN_WAIT: return "FIN_WAIT";
            case TcpState::CLOSE_WAIT: return "CLOSE_WAIT";
            case TcpState::CLOSED: return "CLOSED";
            default: return "UNKNOWN";
            }
        }

        const char* AppLayerName(AppLayer layer) noexcept
        {
            switch (layer) {
            case AppLayer::HTTP: return "HTTP";
            case AppLayer::HTTPS_TLS: return "HTTPS_TLS";
            case AppLayer::DNS: return "DNS";
            case AppLayer::RDP: return "RDP";
            case AppLayer::SMB: return "SMB";
            case AppLayer::QUIC: return "QUIC";
            case AppLayer::ICMP: return "ICMP";
            case AppLayer::NTP: return "NTP";
            case AppLayer::DHCP: return "DHCP";
            case AppLayer::FTP: return "FTP";
            case AppLayer::SSH: return "SSH";
            case AppLayer::SMTP: return "SMTP";
            case AppLayer::ARP: return "ARP";
            case AppLayer::IP_FRAGMENT: return "IP_FRAGMENT";
            case AppLayer::IPSEC: return "IPSEC";
            default: return "UNKNOWN";
            }
        }
    }

    Event Event::CreateNetworkEvent(
        const NetworkInfo& info, EventSource source)
    {
        Event event;
        event.source_ = source;
        event.timestamp_ = std::chrono::system_clock::now();
        event.network_ = info;
        return event;
    }

    std::string Event::ToJson() const
    {
        const NetworkInfo& network = network_;
        std::ostringstream json;
        json << '{'
            << "\"ts\":\"" << FormatTimestamp(timestamp_) << "\","
            << "\"t_unix_ms\":" << ToUnixMs(timestamp_) << ","
            << "\"event_type\":\"FORWARD\","
            << "\"source\":\"npcap_live\","
            << "\"record_type\":\"network_packet\","
            << "\"pid\":" << network.pid << ','
            << "\"process_name\":\""
            << EscapeJson(WideToUtf8(network.process_name)) << "\","
            << "\"local_ip\":\"" << EscapeJson(network.local_addr) << "\","
            << "\"local_port\":" << network.local_port << ','
            << "\"remote_ip\":\"" << EscapeJson(network.remote_addr) << "\","
            << "\"remote_port\":" << network.remote_port << ','
            << "\"packet_src_ip\":\""
            << EscapeJson(network.packet_src_addr) << "\","
            << "\"packet_dst_ip\":\""
            << EscapeJson(network.packet_dst_addr) << "\","
            << "\"adapter\":\"" << EscapeJson(network.adapter_name) << "\","
            << "\"capture_epoch_us\":" << network.capture_epoch_us << ','
            << "\"ether_type\":" << network.ether_type << ','
            << "\"transport_protocol\":"
            << static_cast<unsigned>(network.transport_protocol) << ','
            << "\"protocol\":\"" << AppLayerName(network.app_layer) << "\","
            << "\"ipv6\":" << (network.is_ipv6 ? "true" : "false") << ','
            << "\"direction\":\"" << DirectionName(network.direction) << "\","
            << "\"state\":\"" << TcpStateName(network.tcp_state) << "\","
            << "\"bytes_sent\":" << network.bytes_sent << ','
            << "\"bytes_recv\":" << network.bytes_recv << ','
            << "\"packet_count\":" << network.packet_count << ','
            << "\"packets_since_last_log\":"
            << network.packets_since_last_log << ','
            << "\"flow_duration_ms\":" << network.flow_duration_ms << ','
            << "\"captured_length\":" << network.captured_length << ','
            << "\"wire_length\":" << network.wire_length << ','
            << "\"raw_capture_mapped\":" << (network.raw_capture_mapped ? "true" : "false") << ',';
        if (network.raw_capture_mapped) {
            json << "\"raw_capture_segment\":\"" << EscapeJson(network.raw_capture_segment) << "\","
                << "\"raw_record_offset\":" << network.raw_record_offset << ','
                << "\"raw_data_offset\":" << network.raw_data_offset << ',';
        }
        json
            << "\"payload_length\":" << network.payload_length << ','
            << "\"fragmented\":"
            << (network.fragmented ? "true" : "false") << ','
            << "\"fragment_offset\":" << network.fragment_offset << ','
            << "\"more_fragments\":"
            << (network.more_fragments ? "true" : "false") << ','
            << "\"vlan_ids\":[";
        for (size_t index = 0; index < network.vlan_ids.size(); ++index) {
            if (index != 0) json << ',';
            json << network.vlan_ids[index];
        }
        json << "],";
        if (!network.dns_query.empty()) {
            json << "\"dns_query\":\""
                << EscapeJson(network.dns_query) << "\","
                << "\"dns_query_type\":" << network.dns_query_type << ',';
        }
        if (!network.dns_answers.empty()) {
            json << "\"dns_answers\":\""
                << EscapeJson(network.dns_answers) << "\",";
        }
        if (!network.tls_sni.empty()) {
            json << "\"tls_sni\":\""
                << EscapeJson(network.tls_sni) << "\",";
        }
        if (network.port_hint != AppLayer::UNKNOWN) {
            json << "\"expected_protocol\":\"" << AppLayerName(network.port_hint) << "\","
                << "\"protocol_mismatch\":"
                << (network.protocol_mismatch ? "true" : "false") << ',';
        }
        if (network.http_is_request) {
            json << "\"http_method\":\"" << EscapeJson(network.http_method) << "\",";
            if (!network.http_target.empty())
                json << "\"http_target\":\"" << EscapeJson(network.http_target) << "\",";
            if (!network.http_host.empty())
                json << "\"http_host\":\"" << EscapeJson(network.http_host) << "\",";
        }
        else if (network.http_status_code != 0) {
            json << "\"http_status_code\":" << network.http_status_code << ',';
            if (!network.http_reason.empty())
                json << "\"http_reason\":\"" << EscapeJson(network.http_reason) << "\",";
        }
        json << "\"is_broadcast\":"
            << (network.is_broadcast ? "true" : "false") << ','
            << "\"is_loopback\":"
            << (network.is_loopback ? "true" : "false")
            << '}';
        return json.str();
    }

} // namespace titan
