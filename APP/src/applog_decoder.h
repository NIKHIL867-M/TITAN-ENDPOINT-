#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct DecodedEvent {
    std::string source;
    std::string event_id;
    std::string timestamp;
    std::string summary;
    std::string script_content;
    std::string script_path;
    std::string encoded_decoded;
    std::string network_activity;
    int         pattern_hits = 0;
    bool        credential_access = false;
    bool        amsi_bypass = false;
    bool        process_injection = false;
    bool        content_truncated = false;
    // FIX: pid/tid were captured upstream (AppLogEvent) but never carried
    // into application_log records -- dropped before this struct even
    // existed. Stamped in Decode(), emitted in BuildJson() when nonzero.
    uint32_t    pid = 0;
    uint32_t    tid = 0;
};

class AppLogDecoder {
public:
    AppLogDecoder();
    ~AppLogDecoder() = default;

    // timestamp now passed in — appears in every JSON output
    // pid/tid now passed in too — see DecodedEvent's pid/tid fields.
    std::string Decode(
        const std::string& source,
        const std::string& rawData,
        const std::string& timestamp = "",
        uint32_t            pid = 0,
        uint32_t            tid = 0);

private:
    DecodedEvent DecodePowerShell(const std::string& raw);
    DecodedEvent DecodeWmi(const std::string& raw);
    DecodedEvent DecodeDefender(const std::string& raw);
    DecodedEvent DecodeSecurity(const std::string& raw);
    DecodedEvent DecodeWatchlist(const std::string& source,
        const std::string& raw);

    int         CountPatternHits(const std::string& lower) const;
    std::string DetectEncodedCommand(const std::string& script) const;
    std::string ExtractUrls(const std::string& script) const;
    std::string StripObfuscation(const std::string& script);
    std::string ExtractXmlField(const std::string& xml, const std::string& tag);
    std::string ExtractXmlData(const std::string& xml, const std::string& name);
    std::string BuildJson(const DecodedEvent& evt);

    static std::string JsonEscape(const std::string& s);
    static std::string XmlUnescape(const std::string& s);
    static std::string ToLower(const std::string& s);

    std::vector<std::string> m_suspiciousPatterns;
};
