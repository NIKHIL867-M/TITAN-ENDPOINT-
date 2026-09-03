#pragma once

// ============================================================================
// evidence_envelope.h — FORU.TXT section 8: durable evidence identity.
// Duplicated per-program (this project's established convention). Namespace
// titan::fim, matching this program's own convention -- see
// PROCESS ENDPOINT\titan_fixed\evidence_envelope.h for the full rationale.
// ============================================================================

#include <cstdint>
#include <string>

namespace titan::fim {

std::string Fnv1a64Hex(const std::string& data);
std::string MakeSessionId(const char* componentId);
std::string ComputeSelfExecutableSha256();
std::string WrapWithEvidenceEnvelope(const std::string& json, uint64_t recordId,
    const std::string& sessionId, const std::string& sourceFileName,
    uint64_t byteOffset);

} // namespace titan::fim
