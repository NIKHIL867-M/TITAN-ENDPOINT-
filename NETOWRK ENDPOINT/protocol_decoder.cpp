#include "protocol_decoder.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace titan::protocol {

namespace {
bool Read16(const uint8_t* data, uint32_t length,
    uint32_t offset, uint16_t& value)
{
    if (!data || offset + 2 > length) return false;
    value = static_cast<uint16_t>(
        (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1]);
    return true;
}

bool Read32(const uint8_t* data, uint32_t length,
    uint32_t offset, uint32_t& value)
{
    if (!data || offset + 4 > length) return false;
    value = (static_cast<uint32_t>(data[offset]) << 24) |
        (static_cast<uint32_t>(data[offset + 1]) << 16) |
        (static_cast<uint32_t>(data[offset + 2]) << 8) |
        static_cast<uint32_t>(data[offset + 3]);
    return true;
}

// Reads a (possibly compressed) DNS name starting at `offset`. Follows
// 0xC0xx compression pointers, bounded against infinite loops. `consumed`
// is set to the number of bytes occupied by the name AT `offset` in the
// original record stream (i.e. up to and including the first pointer, or
// the terminating zero label if uncompressed) -- NOT how far a followed
// pointer's target extends, since that lives elsewhere in the message.
bool ReadDnsName(const uint8_t* data, uint32_t length, uint32_t offset,
    std::string& name, uint32_t& consumed)
{
    name.clear();
    uint32_t cursor = offset;
    bool jumped = false;
    unsigned steps = 0;

    for (;;) {
        if (++steps > 128) return false;
        if (cursor >= length) return false;
        const uint8_t label_length = data[cursor];

        if ((label_length & 0xC0) == 0xC0) {
            uint16_t pointer_bits = 0;
            if (!Read16(data, length, cursor, pointer_bits)) return false;
            if (!jumped) consumed = cursor + 2 - offset;
            jumped = true;
            cursor = pointer_bits & 0x3FFF;
            continue;
        }
        if (label_length == 0) {
            if (!jumped) consumed = cursor + 1 - offset;
            return true;
        }
        if (label_length > 63 || cursor + 1u + label_length > length)
            return false;
        if (!name.empty()) name.push_back('.');
        for (uint32_t index = 0; index < label_length; ++index) {
            const unsigned char character = data[cursor + 1 + index];
            if (character < 0x21 || character > 0x7E) return false;
            name.push_back(static_cast<char>(character));
        }
        if (name.size() > 253) return false;
        cursor += 1u + label_length;
    }
}

std::string FormatIPv4(const uint8_t* bytes)
{
    std::string out;
    out.reserve(15);
    for (int i = 0; i < 4; ++i) {
        if (i) out.push_back('.');
        out += std::to_string(static_cast<unsigned>(bytes[i]));
    }
    return out;
}

std::string FormatIPv6(const uint8_t* bytes)
{
    char buf[40];
    std::snprintf(buf, sizeof(buf),
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
        bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15]);
    return std::string(buf);
}
}

bool DecodeDnsQuery(const uint8_t* data, uint32_t length, bool tcp,
    std::string& query, uint16_t& query_type)
{
    query.clear();
    query_type = 0;
    uint32_t offset = tcp ? 2U : 0U;
    if (tcp) {
        uint16_t message_length = 0;
        if (!Read16(data, length, 0, message_length) ||
            message_length > length - 2)
            return false;
    }
    if (!data || offset + 12 > length) return false;
    uint16_t flags = 0;
    uint16_t questions = 0;
    if (!Read16(data, length, offset + 2, flags) ||
        !Read16(data, length, offset + 4, questions) ||
        (flags & 0x8000) != 0 || questions == 0)
        return false;
    offset += 12;
    for (unsigned labels = 0; labels < 128 && offset < length; ++labels) {
        const uint8_t label_length = data[offset++];
        if (label_length == 0) break;
        if ((label_length & 0xC0) != 0 || label_length > 63 ||
            offset + label_length > length)
            return false;
        if (!query.empty()) query.push_back('.');
        for (uint8_t index = 0; index < label_length; ++index) {
            const unsigned char character = data[offset++];
            if (character < 0x21 || character > 0x7E) return false;
            query.push_back(static_cast<char>(character));
        }
        if (query.size() > 253) return false;
    }
    if (query.empty() || offset + 4 > length ||
        !Read16(data, length, offset, query_type))
        return false;
    return true;
}

// FIX: previously only DNS queries were decoded (DecodeDnsQuery rejects any
// message with the QR bit set) -- DNS responses, the half of the exchange
// that actually carries resolved IPs, were never parsed at all.
bool DecodeDnsResponse(const uint8_t* data, uint32_t length, bool tcp,
    std::string& answers)
{
    answers.clear();
    uint32_t offset = tcp ? 2U : 0U;
    if (tcp) {
        uint16_t message_length = 0;
        if (!Read16(data, length, 0, message_length) ||
            message_length > length - 2)
            return false;
    }
    if (!data || offset + 12 > length) return false;

    uint16_t flags = 0, questions = 0, answer_count = 0;
    if (!Read16(data, length, offset + 2, flags) ||
        !Read16(data, length, offset + 4, questions) ||
        !Read16(data, length, offset + 6, answer_count) ||
        (flags & 0x8000) == 0 || questions == 0 || answer_count == 0)
        return false;
    offset += 12;

    // Skip the question section (name + qtype(2) + qclass(2)) for each
    // question -- responses normally carry exactly one.
    for (uint16_t q = 0; q < questions; ++q) {
        std::string discard_name;
        uint32_t name_len = 0;
        if (!ReadDnsName(data, length, offset, discard_name, name_len))
            return false;
        offset += name_len;
        if (offset + 4 > length) return false;
        offset += 4;
    }

    constexpr uint16_t kMaxAnswersRendered = 16;
    unsigned rendered = 0;
    for (uint16_t a = 0; a < answer_count && rendered < kMaxAnswersRendered; ++a) {
        std::string name;
        uint32_t name_len = 0;
        if (!ReadDnsName(data, length, offset, name, name_len)) break;
        offset += name_len;

        uint16_t rr_type = 0, rr_class = 0, rdlength = 0;
        uint32_t ttl = 0;
        if (!Read16(data, length, offset, rr_type)) break;
        if (!Read16(data, length, offset + 2, rr_class)) break;
        if (!Read32(data, length, offset + 4, ttl)) break;
        if (!Read16(data, length, offset + 8, rdlength)) break;
        offset += 10;
        if (offset + rdlength > length) break;

        std::string rendered_value;
        if (rr_type == 1 && rdlength == 4) {                  // A
            rendered_value = "A:" + FormatIPv4(data + offset);
        }
        else if (rr_type == 28 && rdlength == 16) {           // AAAA
            rendered_value = "AAAA:" + FormatIPv6(data + offset);
        }
        else if (rr_type == 5) {                              // CNAME
            std::string cname;
            uint32_t cname_len = 0;
            if (ReadDnsName(data, length, offset, cname, cname_len))
                rendered_value = "CNAME:" + cname;
        }

        if (!rendered_value.empty()) {
            if (!answers.empty()) answers.push_back(';');
            answers += rendered_value;
            ++rendered;
        }
        offset += rdlength;
        if (answers.size() > 2048) break;   // bounded output regardless of answer_count
    }

    return !answers.empty();
}

bool DecodeTlsSni(const uint8_t* data, uint32_t length,
    std::string& server_name)
{
    server_name.clear();
    if (!data || length < 9 || data[0] != 0x16 || data[5] != 0x01)
        return false;
    uint32_t offset = 9;
    if (offset + 34 > length) return false;
    offset += 34;
    if (offset >= length) return false;
    const uint8_t session_length = data[offset++];
    if (offset + session_length > length) return false;
    offset += session_length;
    uint16_t cipher_length = 0;
    if (!Read16(data, length, offset, cipher_length)) return false;
    offset += 2;
    if (offset + cipher_length > length) return false;
    offset += cipher_length;
    if (offset >= length) return false;
    const uint8_t compression_length = data[offset++];
    if (offset + compression_length > length) return false;
    offset += compression_length;
    uint16_t extensions_length = 0;
    if (!Read16(data, length, offset, extensions_length)) return false;
    offset += 2;
    const uint32_t extensions_end =
        (std::min)(length, offset + extensions_length);
    while (offset + 4 <= extensions_end) {
        uint16_t type = 0;
        uint16_t extension_length = 0;
        if (!Read16(data, length, offset, type) ||
            !Read16(data, length, offset + 2, extension_length))
            return false;
        offset += 4;
        if (offset + extension_length > extensions_end) return false;
        if (type == 0 && extension_length >= 5) {
            uint16_t list_length = 0;
            if (!Read16(data, length, offset, list_length) ||
                list_length + 2 > extension_length)
                return false;
            uint32_t name_offset = offset + 2;
            const uint32_t list_end = (std::min)(
                offset + extension_length, name_offset + list_length);
            while (name_offset + 3 <= list_end) {
                const uint8_t name_type = data[name_offset++];
                uint16_t name_length = 0;
                if (!Read16(data, length, name_offset, name_length))
                    return false;
                name_offset += 2;
                if (name_offset + name_length > list_end) return false;
                if (name_type == 0 && name_length != 0) {
                    server_name.assign(
                        reinterpret_cast<const char*>(data + name_offset),
                        name_length);
                    return true;
                }
                name_offset += name_length;
            }
        }
        offset += extension_length;
    }
    return false;
}

namespace {
// Finds the next CRLF (or bare LF) at or after `start`, within `length`.
// Returns the offset of the line-ending character, or `length` if none.
uint32_t FindLineEnd(const uint8_t* data, uint32_t length, uint32_t start)
{
    for (uint32_t i = start; i < length; ++i) {
        if (data[i] == '\n' || data[i] == '\r') return i;
    }
    return length;
}

std::string TrimAscii(const uint8_t* data, uint32_t begin, uint32_t end)
{
    while (begin < end && std::isspace(data[begin])) ++begin;
    while (end > begin && std::isspace(data[end - 1])) --end;
    return std::string(reinterpret_cast<const char*>(data + begin), end - begin);
}

bool StartsWithCI(const uint8_t* data, uint32_t length, uint32_t offset,
    const char* needle)
{
    const size_t needle_len = std::strlen(needle);
    if (offset + needle_len > length) return false;
    for (size_t i = 0; i < needle_len; ++i) {
        if (std::tolower(data[offset + i]) != std::tolower(
            static_cast<unsigned char>(needle[i])))
            return false;
    }
    return true;
}
}

// FIX: HTTP was only ever classified by its request/status line prefix
// (network_monitor.cpp's IdentifyAppLayer) -- nothing extracted the actual
// method/target/status/Host. Best-effort, single-packet only (no TCP
// stream reassembly): a request or response whose start line + headers
// span more than one captured segment will not be fully decoded here.
bool DecodeHttpMessage(const uint8_t* data, uint32_t length,
    bool& is_request, std::string& method, std::string& target,
    uint16_t& status_code, std::string& reason, std::string& host)
{
    is_request = false;
    method.clear();
    target.clear();
    status_code = 0;
    reason.clear();
    host.clear();

    if (!data || length < 8) return false;
    const uint32_t line_end = FindLineEnd(data, length, 0);
    if (line_end == length || line_end == 0) return false;

    if (StartsWithCI(data, length, 0, "HTTP/")) {
        // Status line: "HTTP/1.1 200 OK"
        uint32_t cursor = 5;
        while (cursor < line_end && data[cursor] != ' ') ++cursor;
        if (cursor >= line_end) return false;
        ++cursor;   // skip space
        const uint32_t code_start = cursor;
        while (cursor < line_end && std::isdigit(data[cursor])) ++cursor;
        // Bound the digit run so a malformed/hostile status line can't
        // overflow a numeric parse -- real HTTP status codes are 3 digits.
        if (cursor == code_start || cursor - code_start > 5) return false;
        uint32_t parsed_code = 0;
        for (uint32_t i = code_start; i < cursor; ++i)
            parsed_code = parsed_code * 10 + (data[i] - '0');
        if (parsed_code > 0xFFFF) return false;
        status_code = static_cast<uint16_t>(parsed_code);
        if (cursor < line_end && data[cursor] == ' ') ++cursor;
        reason = TrimAscii(data, cursor, line_end);
        is_request = false;
        return true;
    }

    // Request line: "METHOD target HTTP/1.x"
    uint32_t cursor = 0;
    while (cursor < line_end && data[cursor] != ' ') ++cursor;
    if (cursor == 0 || cursor >= line_end) return false;
    method = TrimAscii(data, 0, cursor);

    static const char* const kKnownMethods[] = {
        "GET", "POST", "PUT", "HEAD", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"
    };
    bool known = false;
    for (const char* candidate : kKnownMethods)
        if (method == candidate) { known = true; break; }
    if (!known) return false;

    ++cursor;   // skip space
    const uint32_t target_start = cursor;
    while (cursor < line_end && data[cursor] != ' ') ++cursor;
    if (cursor == target_start) return false;
    target = TrimAscii(data, target_start, cursor);
    is_request = true;

    // Best-effort Host header scan, bounded to this single packet and a
    // sane number of header lines so a malformed/huge payload can't spin.
    uint32_t header_offset = line_end;
    while (header_offset < length && (data[header_offset] == '\r' ||
        data[header_offset] == '\n'))
        ++header_offset;

    for (unsigned lines = 0; lines < 64 && header_offset < length; ++lines) {
        const uint32_t next_end = FindLineEnd(data, length, header_offset);
        if (next_end == header_offset) break;   // blank line -- end of headers
        if (StartsWithCI(data, length, header_offset, "Host:")) {
            uint32_t value_start = header_offset + 5;
            host = TrimAscii(data, value_start, next_end);
            break;
        }
        header_offset = next_end;
        while (header_offset < length && (data[header_offset] == '\r' ||
            data[header_offset] == '\n'))
            ++header_offset;
    }

    return true;
}

}
