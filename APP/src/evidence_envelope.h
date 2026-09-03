#pragma once

// ============================================================================
// evidence_envelope.h — FORU.TXT section 8: durable evidence identity.
//
// Duplicated per-program (this project's established convention). Global
// namespace (not wrapped in `namespace titan`), matching this program's own
// existing style (AppLogMonitor/AppLogLogger etc. are not namespaced either)
// -- see PROCESS ENDPOINT\titan_fixed\evidence_envelope.h for the full
// field-by-field rationale, identical logic here.
// ============================================================================

#include <cstdint>
#include <string>

std::string Fnv1a64Hex(const std::string& data);
std::string MakeSessionId(const char* componentId);
std::string ComputeSelfExecutableSha256();
std::string WrapWithEvidenceEnvelope(const std::string& json, uint64_t recordId,
    const std::string& sessionId, const std::string& sourceFileName,
    uint64_t byteOffset);
