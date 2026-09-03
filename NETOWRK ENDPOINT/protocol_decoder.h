#pragma once

#include <cstdint>
#include <string>

namespace titan::protocol {

bool DecodeDnsQuery(const uint8_t* payload, uint32_t length, bool tcp,
    std::string& query, uint16_t& query_type);

// Decodes a DNS RESPONSE message (QR bit set): skips the question section,
// then decodes up to 16 answer records into a single semicolon-joined
// "type:value" string (e.g. "A:93.184.216.34;CNAME:example.invalid").
// Answer name-compression pointers are followed (bounded). Only A, AAAA and
// CNAME record types are rendered; other types are counted but not
// expanded. Returns false if the message isn't a well-formed DNS response.
bool DecodeDnsResponse(const uint8_t* payload, uint32_t length, bool tcp,
    std::string& answers);

bool DecodeTlsSni(const uint8_t* payload, uint32_t length,
    std::string& server_name);

// Best-effort, single-packet-only HTTP request/response line + Host header
// parsing (no TCP stream reassembly -- only catches messages whose
// request/status line and headers fit in one captured segment). Returns
// false if the payload isn't a recognizable HTTP/1.x request or response.
bool DecodeHttpMessage(const uint8_t* payload, uint32_t length,
    bool& is_request, std::string& method, std::string& target,
    uint16_t& status_code, std::string& reason, std::string& host);

}
