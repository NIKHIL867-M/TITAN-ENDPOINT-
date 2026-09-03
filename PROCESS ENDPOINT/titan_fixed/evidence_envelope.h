#ifndef TITAN_EVIDENCE_ENVELOPE_H
#define TITAN_EVIDENCE_ENVELOPE_H

// ============================================================================
// evidence_envelope.h — FORU.TXT section 8: durable evidence identity.
//
// Duplicated per-program (this project's established convention: no shared
// library between the native components — see resource_pressure.h for the
// same pattern). Every JSONL record this endpoint writes gets wrapped with:
//   record_id     — monotonically increasing, unique for this process's
//                    lifetime (NOT persisted across restarts by itself —
//                    paired with session_id it forms a durable composite key,
//                    same convention as ProcessMonitor's pre-existing
//                    session_id).
//   session_id    — this process launch's identity ("<pid>-<start_epoch_ms>"),
//                    shared by every subsystem in this program so a single
//                    process run has exactly one session_id everywhere.
//   source_file   — the pack filename (not full path — stays meaningful after
//                    the file rotates/archives/moves) this record was written
//                    into.
//   byte_offset   — this record's starting byte offset within source_file, so
//                    a consumer can seek directly to it without a full scan.
//   content_hash  — Fnv1a64Hex of the ORIGINAL (pre-envelope) record body.
//                    Non-cryptographic — cheap corruption/tamper *evidence*
//                    for a single line, not a security signature. Computed
//                    over the body only (not record_id/offset/etc.) so it
//                    stays stable regardless of which envelope it's wrapped
//                    with.
// ============================================================================

#include <cstdint>
#include <string>

namespace titan {

// Fowler-Noll-Vo 1a, 64-bit.
std::string Fnv1a64Hex(const std::string& data);

// "<component>-<pid>-<start_epoch_ms>" — generated once by the logger at
// construction and reused by every subsystem in the same process (see
// AsyncLogger::GetSessionId) so one process launch has exactly one
// session_id everywhere in its output.
std::string MakeSessionId(const char* componentId);

// SHA-256 (hex, lowercase) of this process's own currently-running executable
// image, computed once via BCrypt (Windows-native — already linked via
// bcrypt.lib in every program's CMakeLists.txt, no new dependency). Directly
// comparable (case-insensitively) against runtime-manifest.json's sha256 for
// the same component. Returns an empty string on any failure — never
// fabricates a placeholder hash.
std::string ComputeSelfExecutableSha256();

// Wraps an already-built, single-line JSON object (must start with '{') with
// the durable-evidence envelope fields above. Returns the input completely
// unchanged if it doesn't start with '{' — never corrupts a malformed caller
// rather than guessing.
std::string WrapWithEvidenceEnvelope(const std::string& json, uint64_t recordId,
    const std::string& sessionId, const std::string& sourceFileName,
    uint64_t byteOffset);

} // namespace titan

#endif // TITAN_EVIDENCE_ENVELOPE_H
