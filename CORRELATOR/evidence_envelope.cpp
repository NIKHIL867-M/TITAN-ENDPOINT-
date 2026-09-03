#include "evidence_envelope.h"

#include <windows.h>
#include <bcrypt.h>

#include <chrono>
#include <sstream>

#pragma comment(lib, "bcrypt.lib")

namespace correlator {

std::string Fnv1a64Hex(const std::string& data) {
    uint64_t hash = 1469598103934665603ULL;
    constexpr uint64_t kPrime = 1099511628211ULL;
    for (unsigned char c : data) {
        hash ^= c;
        hash *= kPrime;
    }
    char buf[17];
    sprintf_s(buf, "%016llx", static_cast<unsigned long long>(hash));
    return std::string(buf, 16);
}

std::string MakeSessionId(const char* componentId) {
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::ostringstream s;
    s << componentId << "-" << GetCurrentProcessId() << "-" << now_ms;
    return s.str();
}

std::string ComputeSelfExecutableSha256() {
    wchar_t path[MAX_PATH]{};
    DWORD len = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (len == 0 || len == MAX_PATH) return {};

    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        CloseHandle(file);
        return {};
    }

    std::string result;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
        BYTE buffer[65536];
        DWORD bytesRead = 0;
        bool ok = true;
        while (ok && ReadFile(file, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
            ok = (BCryptHashData(hash, buffer, bytesRead, 0) == 0);
        }
        if (ok) {
            BYTE digest[32];
            if (BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0) {
                char hex[65]{};
                for (int i = 0; i < 32; ++i) sprintf_s(hex + i * 2, 3, "%02x", digest[i]);
                result.assign(hex, 64);
            }
        }
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(file);
    return result;
}

std::string WrapWithEvidenceEnvelope(const std::string& json, uint64_t recordId,
    const std::string& sessionId, const std::string& sourceFileName,
    uint64_t byteOffset) {
    if (json.empty() || json.front() != '{') return json;

    std::ostringstream out;
    out << "{\"record_id\":" << recordId
        << ",\"session_id\":\"" << sessionId << "\""
        << ",\"source_file\":\"" << sourceFileName << "\""
        << ",\"byte_offset\":" << byteOffset
        << ",\"content_hash\":\"" << Fnv1a64Hex(json) << "\","
        << json.substr(1);
    return out.str();
}

} // namespace correlator
