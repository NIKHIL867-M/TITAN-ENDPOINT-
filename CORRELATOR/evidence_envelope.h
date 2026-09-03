#ifndef TITAN_EVIDENCE_ENVELOPE_H
#define TITAN_EVIDENCE_ENVELOPE_H

// ============================================================================
// evidence_envelope.h — FORU.TXT section 8: durable evidence identity.
//
// Duplicated per-program (this project's established convention: no shared
// library between the native components). Every JSONL record this endpoint
// writes (session_timeline joins, collector_health, control_audit) gets
// wrapped with record_id/session_id/source_file/byte_offset/content_hash --
// see PROCESS ENDPOINT\titan_fixed\evidence_envelope.h for the full field-by-
// field rationale (identical here, just in the `correlator` namespace to
// match this program's existing convention).
// ============================================================================

#include <cstdint>
#include <string>

namespace correlator {

// Fowler-Noll-Vo 1a, 64-bit. Non-cryptographic -- corruption/tamper evidence
// for one line, not a security signature.
std::string Fnv1a64Hex(const std::string& data);

// "<component>-<pid>-<start_epoch_ms>".
std::string MakeSessionId(const char* componentId);

// SHA-256 (hex, lowercase) of this process's own currently-running executable
// image, via BCrypt (Windows-native). Empty string on any failure.
std::string ComputeSelfExecutableSha256();

// Wraps an already-built, single-line JSON object (must start with '{') with
// the durable-evidence envelope fields. Returns the input unchanged if it
// doesn't start with '{'.
std::string WrapWithEvidenceEnvelope(const std::string& json, uint64_t recordId,
    const std::string& sessionId, const std::string& sourceFileName,
    uint64_t byteOffset);

} // namespace correlator

#endif // TITAN_EVIDENCE_ENVELOPE_H
