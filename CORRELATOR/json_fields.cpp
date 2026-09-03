// json_fields.cpp
#include "json_fields.h"

#include <cctype>

namespace correlator {

bool ExtractJsonNumber(const std::string& line, const std::string& key, int64_t& out)
{
    const std::string needle = "\"" + key + "\":";
    const size_t pos = line.find(needle);
    if (pos == std::string::npos) return false;

    size_t cursor = pos + needle.size();
    bool negative = false;
    if (cursor < line.size() && line[cursor] == '-') {
        negative = true;
        ++cursor;
    }
    const size_t digits_start = cursor;
    int64_t value = 0;
    while (cursor < line.size() && std::isdigit(static_cast<unsigned char>(line[cursor]))) {
        // Bound the digit run so a malformed/oversized field can't overflow.
        if (cursor - digits_start >= 18) return false;
        value = value * 10 + (line[cursor] - '0');
        ++cursor;
    }
    if (cursor == digits_start) return false;   // no digits at all

    out = negative ? -value : value;
    return true;
}

bool ExtractJsonString(const std::string& line, const std::string& key, std::string& out)
{
    const std::string needle = "\"" + key + "\":\"";
    const size_t pos = line.find(needle);
    if (pos == std::string::npos) return false;

    // Proper escape decode, not just an escape-aware boundary scan. Found
    // live, two compounding bugs from the earlier "raw substring, don't
    // un-escape" approach: (1) a naive line.find('"', ...) for the closing
    // quote stops at the FIRST raw '"' byte -- wrong the moment a value
    // contains an escaped quote before its real end, e.g. a Windows
    // command_line that itself starts with a quoted path ("C:\Program
    // Files\..." is JSON-encoded starting \"C:\\Program Files\\...) came
    // out as a lone "\\" instead of the real value; (2) every caller that
    // then re-embeds the "raw, still-escaped" substring through EscapeJson
    // (correlated_snapshot_writer.cpp) DOUBLE-escaped it -- a real single
    // backslash in a path came out as two in the final JSON. Decoding once,
    // here, at the single source of truth, fixes both: every caller either
    // only needs the decoded value for comparison/hashing (fingerprints,
    // bridge-path matching -- unaffected either way, both sides always
    // decoded the same way) or re-embeds it through exactly one EscapeJson
    // pass (now correct).
    size_t cursor = pos + needle.size();
    std::string decoded;
    while (cursor < line.size()) {
        const char c = line[cursor];
        if (c == '"') { out = std::move(decoded); return true; }
        if (c != '\\' || cursor + 1 >= line.size()) { decoded += c; ++cursor; continue; }

        const char next = line[cursor + 1];
        switch (next) {
        case '"':  decoded += '"';  cursor += 2; break;
        case '\\': decoded += '\\'; cursor += 2; break;
        case '/':  decoded += '/';  cursor += 2; break;
        case 'b':  decoded += '\b'; cursor += 2; break;
        case 'f':  decoded += '\f'; cursor += 2; break;
        case 'n':  decoded += '\n'; cursor += 2; break;
        case 'r':  decoded += '\r'; cursor += 2; break;
        case 't':  decoded += '\t'; cursor += 2; break;
        case 'u': {
            // BMP-only (no UTF-16 surrogate-pair combining): every real
            // value from these endpoints (process/user/path/IP names) is
            // plain ASCII, so this covers the rest without the added
            // complexity of a case that does not occur in practice.
            if (cursor + 6 > line.size()) { decoded += next; cursor += 2; break; }
            unsigned int code = 0;
            bool validHex = true;
            for (size_t i = 0; i < 4; ++i) {
                const char h = line[cursor + 2 + i];
                code <<= 4;
                if (h >= '0' && h <= '9') code |= static_cast<unsigned int>(h - '0');
                else if (h >= 'a' && h <= 'f') code |= static_cast<unsigned int>(h - 'a' + 10);
                else if (h >= 'A' && h <= 'F') code |= static_cast<unsigned int>(h - 'A' + 10);
                else { validHex = false; break; }
            }
            if (!validHex) { decoded += next; cursor += 2; break; }
            if (code < 0x80u) {
                decoded += static_cast<char>(code);
            } else if (code < 0x800u) {
                decoded += static_cast<char>(0xC0u | (code >> 6));
                decoded += static_cast<char>(0x80u | (code & 0x3Fu));
            } else {
                decoded += static_cast<char>(0xE0u | (code >> 12));
                decoded += static_cast<char>(0x80u | ((code >> 6) & 0x3Fu));
                decoded += static_cast<char>(0x80u | (code & 0x3Fu));
            }
            cursor += 6;
            break;
        }
        default:
            decoded += next;   // unknown escape -- keep the literal character
            cursor += 2;
            break;
        }
    }
    return false;   // unterminated value
}

bool ExtractJsonBool(const std::string& line, const std::string& key, bool& out)
{
    const std::string needle = "\"" + key + "\":";
    const size_t pos = line.find(needle);
    if (pos == std::string::npos) return false;

    const size_t cursor = pos + needle.size();
    if (line.compare(cursor, 4, "true") == 0) { out = true; return true; }
    if (line.compare(cursor, 5, "false") == 0) { out = false; return true; }
    return false;
}

} // namespace correlator
