#include "protocol_decoder.h"
#include "resource_pressure.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {
void Push16(std::vector<uint8_t>& bytes, uint16_t value)
{
    bytes.push_back(static_cast<uint8_t>(value >> 8));
    bytes.push_back(static_cast<uint8_t>(value));
}

void Push24(std::vector<uint8_t>& bytes, uint32_t value)
{
    bytes.push_back(static_cast<uint8_t>(value >> 16));
    bytes.push_back(static_cast<uint8_t>(value >> 8));
    bytes.push_back(static_cast<uint8_t>(value));
}
}

int main()
{
    const std::vector<uint8_t> dns{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    std::string query;
    uint16_t query_type = 0;
    if (!titan::protocol::DecodeDnsQuery(
        dns.data(), static_cast<uint32_t>(dns.size()), false,
        query, query_type) ||
        query != "example.com" || query_type != 1) {
        std::cerr << "DNS decode failed\n";
        return 1;
    }

    const std::string host = "example.com";
    std::vector<uint8_t> extensions;
    Push16(extensions, 0);
    Push16(extensions, static_cast<uint16_t>(5 + host.size()));
    Push16(extensions, static_cast<uint16_t>(3 + host.size()));
    extensions.push_back(0);
    Push16(extensions, static_cast<uint16_t>(host.size()));
    extensions.insert(extensions.end(), host.begin(), host.end());

    std::vector<uint8_t> hello_body{ 0x03, 0x03 };
    hello_body.insert(hello_body.end(), 32, 0);
    hello_body.push_back(0);
    Push16(hello_body, 2);
    Push16(hello_body, 0x1301);
    hello_body.push_back(1);
    hello_body.push_back(0);
    Push16(hello_body, static_cast<uint16_t>(extensions.size()));
    hello_body.insert(hello_body.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> handshake{ 0x01 };
    Push24(handshake, static_cast<uint32_t>(hello_body.size()));
    handshake.insert(handshake.end(), hello_body.begin(), hello_body.end());
    std::vector<uint8_t> record{ 0x16, 0x03, 0x01 };
    Push16(record, static_cast<uint16_t>(handshake.size()));
    record.insert(record.end(), handshake.begin(), handshake.end());

    std::string sni;
    if (!titan::protocol::DecodeTlsSni(
        record.data(), static_cast<uint32_t>(record.size()), sni) ||
        sni != host) {
        std::cerr << "TLS SNI decode failed\n";
        return 2;
    }
    if (titan::protocol::DecodeTlsSni(dns.data(),
        static_cast<uint32_t>(dns.size()), sni)) {
        std::cerr << "Malformed TLS accepted\n";
        return 3;
    }

    // DNS response: one question (example.com A) + one A-record answer
    // whose NAME uses a compression pointer back to the question name.
    std::vector<uint8_t> dns_response{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m', 0x00,
        0x00, 0x01, 0x00, 0x01,               // QTYPE=A, QCLASS=IN
        0xC0, 0x0C,                            // answer NAME: pointer to offset 12
        0x00, 0x01, 0x00, 0x01,               // TYPE=A, CLASS=IN
        0x00, 0x00, 0x01, 0x2C,               // TTL=300
        0x00, 0x04,                            // RDLENGTH=4
        93, 184, 216, 34
    };
    std::string answers;
    if (!titan::protocol::DecodeDnsResponse(dns_response.data(),
        static_cast<uint32_t>(dns_response.size()), false, answers) ||
        answers != "A:93.184.216.34") {
        std::cerr << "DNS response decode failed: '" << answers << "'\n";
        return 4;
    }
    // A query message must not be accepted as a response (QR bit unset).
    if (titan::protocol::DecodeDnsResponse(dns.data(),
        static_cast<uint32_t>(dns.size()), false, answers)) {
        std::cerr << "DNS query accepted as response\n";
        return 5;
    }

    // HTTP request line + Host header (single packet).
    const std::string http_request =
        "GET /path HTTP/1.1\r\nHost: example.invalid\r\nUser-Agent: t\r\n\r\n";
    bool is_request = false;
    uint16_t status_code = 0;
    std::string method, target, reason, http_host;
    if (!titan::protocol::DecodeHttpMessage(
        reinterpret_cast<const uint8_t*>(http_request.data()),
        static_cast<uint32_t>(http_request.size()),
        is_request, method, target, status_code, reason, http_host) ||
        !is_request || method != "GET" || target != "/path" ||
        http_host != "example.invalid") {
        std::cerr << "HTTP request decode failed\n";
        return 6;
    }

    // HTTP status line (single packet).
    const std::string http_response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
    if (!titan::protocol::DecodeHttpMessage(
        reinterpret_cast<const uint8_t*>(http_response.data()),
        static_cast<uint32_t>(http_response.size()),
        is_request, method, target, status_code, reason, http_host) ||
        is_request || status_code != 200 || reason != "OK") {
        std::cerr << "HTTP response decode failed\n";
        return 7;
    }

    // RAM/disk auto-lightening.
    if (ClassifyPressure(50, 10ULL * 1024 * 1024 * 1024) != PressureTier::Normal) {
        std::cerr << "pressure classification: expected normal\n";
        return 8;
    }
    if (ClassifyPressure(95, 10ULL * 1024 * 1024 * 1024) != PressureTier::Severe) {
        std::cerr << "pressure classification: expected severe\n";
        return 9;
    }
    if (AdaptiveCap(3, 1, 0.5) != 1) {
        std::cerr << "adaptive cap floor not respected\n";
        return 10;
    }

    std::cout << "protocol_decoder_test passed\n";
    return 0;
}
