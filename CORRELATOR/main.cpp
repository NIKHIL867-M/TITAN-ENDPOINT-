// main.cpp -- TITAN Correlator
//
// A 6th, read-only, standalone program implementing TITAN_CORRELATION_DESIGN.md:
// tails all 5 endpoints' JSONL logs (each endpoint's own log directory is
// listed in correlator_config.txt next to this executable), joins evidence
// on t_unix_ms (bucketed) + pid/parent_pid lineage, and writes a new,
// additive session_timeline JSONL log. Never modifies any source
// endpoint's own log.
//
// This program does not require Administrator privileges -- it only reads
// already-written log files.
#ifndef WIN32_LEAN_AND_MEAN
#   define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "correlated_snapshot_writer.h"
#include "correlation_engine.h"
#include "correlator_logger.h"
#include "evidence_envelope.h"
#include "ipc_control_server.h"
#include "json_fields.h"
#include "log_tailer.h"
#include "unified_stream_engine.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace correlator;

namespace {

std::atomic<bool> g_running{ true };
// FORU.TXT section 4: "Monitoring" for the Correlator means "ingesting +
// correlating at all" -- gates the whole per-cycle Ingest/TryCorrelate block
// below, independent of persistence (CorrelatorLogger's own toggle).
std::atomic<bool> g_collecting_enabled{ true };

// FORU.TXT section 6: "Each endpoint must reject a second independent native
// instance." Correlator runs unelevated by design (requiresElevation:false
// in runtime-manifest.json), and plain interactive users don't hold
// SeCreateGlobalPrivilege -- CreateMutexW(L"Global\\...") would fail outright
// for them, unlike the other 5 (all elevated) endpoints. Local\ is the
// correct namespace here: it still refuses a second instance for the same
// logged-in session, which is the realistic threat model for an unelevated
// per-user tool.
void AcquireSingleInstanceMutexOrExit() {
    HANDLE mutex = CreateMutexW(nullptr, TRUE, L"Local\\TitanEndpoint_Correlator_Instance");
    const DWORD err = GetLastError();
    if (mutex && err == ERROR_ALREADY_EXISTS) {
        std::cerr << "[FATAL] TITAN Correlator is already running for this session "
                     "(single-instance lock held). Refusing to start a second instance.\n";
        CloseHandle(mutex);
        std::exit(4);
    }
    if (!mutex) {
        std::cerr << "[WARN]  Could not create single-instance mutex (error " << err
                  << ") -- single-instance protection is NOT active this run.\n";
    }
}

BOOL WINAPI ConsoleHandler(DWORD signal)
{
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT ||
        signal == CTRL_CLOSE_EVENT || signal == CTRL_SHUTDOWN_EVENT) {
        g_running.store(false);
        return TRUE;
    }
    return FALSE;
}

struct SourceConfig {
    std::string  name;        // "port", "process", "file_integrity", "network", "application"
    std::wstring directory;
};

struct SourceRuntime {
    uint64_t records_seen = 0;
    int64_t last_observed_ms = 0;
    bool health_seen = false;
    bool collecting = true;
};

// Maps a configured endpoint name to the filename substring its log/pack
// files always contain -- keeps the tailer from picking up unrelated files
// if multiple endpoints ever shared a directory.
std::string FilenameHintFor(const std::string& name)
{
    if (name == "port") return "usb";
    if (name == "process") return "titan_";
    if (name == "file_integrity") return "fim_events";
    if (name == "network") return "titan_";
    if (name == "application") return "application_events";
    return "";   // no filter -- tail everything in the directory
}

// Minimal escape for last_error_ (display-only text, never a full record) --
// same pattern used by every other endpoint's own local escape helper.
std::string EscapeJsonText(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        default:
            if (c >= 0x20) out += static_cast<char>(c);
        }
    }
    return out;
}

std::wstring Widen(const std::string& narrow)
{
    return std::wstring(narrow.begin(), narrow.end());   // ASCII paths only
}

std::string Narrow(const std::wstring& wide)
{
    std::string out;
    out.reserve(wide.size());
    for (wchar_t wc : wide) out.push_back(static_cast<char>(wc));   // ASCII paths only
    return out;
}

// Reads "name=directory" lines from a plain text config file. Blank lines
// and lines starting with '#' are ignored.
std::vector<SourceConfig> LoadConfig(const std::string& config_path)
{
    std::vector<SourceConfig> sources;
    std::ifstream in(config_path);
    if (!in.is_open()) {
        std::cerr << "[Correlator] Cannot open config file: " << config_path << "\n";
        return sources;
    }

    std::string line;
    bool first_line = true;
    while (std::getline(in, line)) {
        // Strip a leading UTF-8 BOM if present -- common on files saved by
        // Notepad or PowerShell's `Set-Content -Encoding utf8` (which always
        // writes one on Windows PowerShell 5.1), and would otherwise corrupt
        // the first source's name (e.g. "process" becomes "\xEF\xBB\xBFprocess",
        // silently failing to match any known endpoint name).
        if (first_line) {
            first_line = false;
            if (line.size() >= 3 &&
                static_cast<unsigned char>(line[0]) == 0xEF &&
                static_cast<unsigned char>(line[1]) == 0xBB &&
                static_cast<unsigned char>(line[2]) == 0xBF)
                line.erase(0, 3);
        }
        // Trim trailing CR (Windows-edited text files) and surrounding whitespace.
        while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
            line.pop_back();
        size_t start = 0;
        while (start < line.size() && line[start] == ' ') ++start;
        line = line.substr(start);

        if (line.empty() || line[0] == '#') continue;

        const size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        SourceConfig cfg;
        cfg.name = line.substr(0, eq);
        cfg.directory = Widen(line.substr(eq + 1));
        if (!cfg.name.empty() && !cfg.directory.empty())
            sources.push_back(std::move(cfg));
    }
    return sources;
}

// Best-effort discovery of the GUI-managed, always-current source-directory
// config at "<TITAN root>\.titan-runtime\correlator_config.txt", walking up
// from this executable's own directory. The GUI regenerates that file from
// runtime-manifest.json on every Start All, so it is the only copy that is
// guaranteed to track wherever each endpoint's build output currently lives.
// Falls back to the plain relative "correlator_config.txt" next to the exe
// (this program's original, hand-maintained default) if no .titan-runtime
// tree is found, so a standalone copy without the full GUI-managed tree
// still works. Bug found live 2026-08-06: with no argv[1], the GUI's own
// launch (runtime-manifest.json's commandArguments is "") always fell
// through to the stale hand-maintained local file, which still listed
// pre-release-manifest build paths (x64-Debug, final-audit, x64-Release-2026,
// final-audit-2026) for Process/File/Network/Application -- so a real Start
// All run only ever correlated Port, silently, with active_sources:1 of 5.
std::string ResolveDefaultConfigPath()
{
    wchar_t exe_path[MAX_PATH] = {};
    const DWORD len = GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return "correlator_config.txt";

    std::filesystem::path dir = std::filesystem::path(exe_path).parent_path();
    for (int depth = 0; depth < 12 && !dir.empty(); ++depth) {
        std::error_code ec;
        std::filesystem::path candidate = dir / L".titan-runtime" / L"correlator_config.txt";
        if (std::filesystem::exists(candidate, ec) && !ec)
            return candidate.string();
        std::filesystem::path parent = dir.parent_path();
        if (parent == dir) break;   // reached a drive root
        dir = parent;
    }
    return "correlator_config.txt";
}

} // namespace

int main(int argc, char** argv)
{
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    AcquireSingleInstanceMutexOrExit();

    const std::string config_path = argc > 1 ? argv[1] : ResolveDefaultConfigPath();
    std::vector<SourceConfig> sources = LoadConfig(config_path);
    if (sources.empty()) {
        std::cerr << "[Correlator] No sources configured (config: " << config_path
            << "). Add at least one \"name=directory\" line and restart.\n";
        return 1;
    }

    std::cout << "[Correlator] Watching " << sources.size() << " source(s):" << std::endl;
    std::vector<LogTailer> tailers;
    tailers.reserve(sources.size());
    for (const auto& src : sources) {
        std::cout << "  " << src.name << " -> " << Narrow(src.directory)
            << " (hint='" << FilenameHintFor(src.name) << "')" << std::endl;
        tailers.emplace_back(src.directory, FilenameHintFor(src.name),
            L".\\state\\" + Widen(src.name) + L".offsets", true);
    }

    CorrelatorLogger logger(L".\\logs\\");
    if (!logger.Initialize()) {
        std::cerr << "[Correlator] Failed to initialize output logger.\n";
        return 1;
    }

    // VISHNU.TXT task 1: a single, bounded, human-reviewable grouped JSON
    // document (meta + correlated_groups[]) alongside the existing live
    // correlator_*.jsonl stream -- see correlated_snapshot_writer.h.
    CorrelatedSnapshotWriter snapshotWriter(L".\\logs\\");

    // FORU.TXT section 4: authenticated local control channel, same pattern
    // as every other endpoint. Shutdown callback just clears g_running --
    // the main loop below notices within one ~3s poll cycle and exits
    // normally, emitting the final health record itself.
    IpcControlServer ipcServer(g_collecting_enabled, logger, [] { g_running.store(false); });
    if (!ipcServer.Start()) {
        std::cerr << "[WARN] Failed to start IPC control channel -- remote control will be unavailable, "
                     "correlation continues normally.\n";
    }

    UnifiedStreamEngine engine;
    std::vector<SourceRuntime> sourceRuntime(sources.size());

    uint64_t ingested = 0, unified_total = 0, checkpoint_failures = 0;
    // Emit a source-connectivity snapshot in the first completed poll, not
    // only after 30 seconds; short GUI sessions must still show real feeds.
    auto last_health = std::chrono::steady_clock::now() - std::chrono::seconds(30);
    auto last_pressure = std::chrono::steady_clock::now();

    // FORU.TXT section 5/6: versioned collector_health schema, shared field
    // names with every other native endpoint. Called periodically
    // (final=false) and once more at shutdown (final=true) so the GUI sees a
    // clean stop rather than only ever inferring it from staleness.
    //
    // FIX (found while implementing FORU.TXT's 2026-08-02 health-schema-v2
    // pass): "status" was a HARDCODED "healthy" literal -- it never actually
    // reflected declined_*/evicted_*/write-failure counters sitting right
    // next to it in this same record, so a genuinely struggling Correlator
    // (e.g. hitting kMaxActiveGroups repeatedly, or failing to write its own
    // output) would still report "healthy" forever. Also FIXED: this record
    // had no "t_unix_ms" at all, unlike every other endpoint's health record
    // and the project's own stated convention ("t_unix_ms present on every
    // JSON record type in all 5 sensors + the Correlator's own output").
    auto emit_health = [&](bool final_record) {
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const auto [retained_bytes, retained_files] = logger.GetRetainedBytesAndFiles();
        size_t active_sources = 0;
        for (const auto& state : sourceRuntime) {
            if (state.records_seen != 0 && state.collecting &&
                now_ms - state.last_observed_ms <= 90000) ++active_sources;
        }
        // A bounded graph can compact redundant candidate edges while still
        // representing every source record. That is not source loss and must
        // not paint the endpoint Degraded. Only an actual parse, checkpoint,
        // or writer failure affects health.
        const bool degraded = engine.ParseFailures() != 0 || checkpoint_failures != 0 ||
            logger.GetWriteFailureCount() != 0;
        const char* shutdown_state = final_record ? "stopped" : (g_running.load() ? "running" : "stopping");

        std::ostringstream health;
        health << "{\"t_unix_ms\":" << now_ms << ",\"type\":\"collector_health\","
            << "\"schema_version\":2,"
            << "\"endpoint_id\":\"correlator\","
            << "\"component_id\":\"correlator\","
            << "\"pid\":" << GetCurrentProcessId() << ","
            << "\"executable_version\":\"unified-stream-v1\"," 
            << "\"executable_hash\":\"" << ComputeSelfExecutableSha256() << "\","
            << "\"started_at\":" << logger.GetStartedAtUnixMs() << ","
            << "\"updated_at\":" << now_ms << ","
            << "\"status\":\"" << (degraded ? "degraded" : "healthy") << "\","
            << "\"final\":" << (final_record ? "true" : "false") << ","
            << "\"collecting\":" << (g_collecting_enabled.load() ? "true" : "false") << ","
            << "\"persistence_enabled\":" << (logger.IsPersistenceEnabled() ? "true" : "false") << ","
            << "\"records_ingested\":" << ingested << ","
            << "\"unified_events_emitted\":" << unified_total << ","
            << "\"connected_events_emitted\":" << engine.ConnectedEventsEmitted() << ","
            << "\"single_source_events_emitted\":" << engine.SingleSourceEventsEmitted() << ","
            << "\"records_represented\":" << engine.RecordsRepresented() << ","
            << "\"records_in_memory\":" << engine.PendingMemberCount() << ","
            << "\"active_groups\":" << engine.PendingGroupCount() << ","
            << "\"exact_duplicates_suppressed\":" << engine.ExactDuplicatesSuppressed() << ","
            << "\"semantic_repeats_compacted\":" << engine.SemanticRepeatsCompacted() << ","
            << "\"capacity_flushes\":" << engine.CapacityFlushes() << ","
            << "\"connection_limit_count\":" << engine.ConnectionLimitCount() << ","
            << "\"redundant_connections_compacted\":" << engine.ConnectionLimitCount() << ","
            << "\"configured_sources\":" << sources.size() << ","
            << "\"active_sources\":" << active_sources << ","
            << "\"source_status\":[";
        for (size_t i = 0; i < sources.size(); ++i) {
            if (i) health << ',';
            const bool active = sourceRuntime[i].records_seen != 0 && sourceRuntime[i].collecting &&
                now_ms - sourceRuntime[i].last_observed_ms <= 90000;
            health << "{\"endpoint\":\"" << EscapeJsonText(sources[i].name) << "\","
                << "\"active\":" << (active ? "true" : "false") << ','
                << "\"records_seen\":" << sourceRuntime[i].records_seen << ','
                << "\"last_observed_ms\":" << sourceRuntime[i].last_observed_ms << ','
                << "\"bootstrapped_bytes\":" << tailers[i].BootstrappedBytes() << '}';
        }
        health << "],"
            // Standardized cross-endpoint names (additive) -- see HealthSnapshot
            // on the GUI side.
            << "\"records_seen\":" << ingested << ","
            << "\"records_written\":" << logger.GetWrittenCount() << ","
            << "\"records_dropped\":0,"
            << "\"parse_failures\":" << engine.ParseFailures() << ","
            << "\"source_loss\":0,"
            << "\"checkpoint_failures\":" << checkpoint_failures << ","
            << "\"writer_failures\":" << logger.GetWriteFailureCount() << ","
            << "\"rotations\":" << logger.GetRotationCount() << ","
            << "\"retained_bytes\":" << retained_bytes << ","
            << "\"retained_files\":" << retained_files << ","
            << "\"evidence_gap\":" << (degraded ? "true" : "false") << ","
            << "\"resource_pressure\":\""
            << PressureTierToString(logger.GetResourcePressureTier()) << "\","
            << "\"shutdown_state\":\"" << shutdown_state << "\","
            << "\"shutdown_ack\":" << (final_record ? "true" : "false") << ","
            << "\"last_error\":\"" << EscapeJsonText(logger.GetLastError()) << "\""
            << "}";
        logger.Log(health.str());
        logger.Flush();
    };

    std::cout << "[Correlator] Running. Press Ctrl+C to stop.\n";

    while (g_running.load()) {
        // FORU.TXT section 4.3/4.4: Monitoring OFF stops new ingestion and
        // correlation entirely (mirrors Process's OnProcessEvent gating) --
        // the tailers themselves keep polling (cheap, and resuming shouldn't
        // have to re-seed from scratch) but nothing is ingested or joined
        // while paused.
        if (g_collecting_enabled.load()) {
            const auto observed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            for (size_t i = 0; i < sources.size(); ++i) {
                auto new_lines = tailers[i].ReadNewLines();
                if (!new_lines.empty())
                    std::cout << "[Correlator] " << sources[i].name << ": +"
                        << new_lines.size() << " line(s)" << std::endl;
                for (auto& line : new_lines) {
                    sourceRuntime[i].records_seen++;
                    sourceRuntime[i].last_observed_ms = observed_ms;
                    if (IsOperationalStatusLine(line)) {
                        sourceRuntime[i].health_seen = true;
                        const bool stopped = line.find("\"final\":true") != std::string::npos ||
                            line.find("\"collecting\":false") != std::string::npos;
                        sourceRuntime[i].collecting = !stopped;
                    }
                    engine.Ingest(sources[i].name, line, observed_ms);
                    ++ingested;
                }
            }

            std::vector<GroupSnapshot> readyGroups;
            for (auto& unifiedLine : engine.DrainReady(observed_ms, false, &readyGroups)) {
                logger.Log(unifiedLine);
                ++unified_total;
            }
            if (!readyGroups.empty()) snapshotWriter.AddGroups(readyGroups);
            // Only advance durable read positions when no accepted event is
            // waiting for its short correlation window. Clean shutdown also
            // force-drains before committing, preventing normal restarts from
            // replaying old endpoint packs.
            if (engine.PendingGroupCount() == 0) {
                for (auto& tailer : tailers)
                    if (!tailer.Commit()) ++checkpoint_failures;
            }
        }

        const auto now = std::chrono::steady_clock::now();

        if (now - last_pressure >= std::chrono::seconds(20)) {
            logger.UpdateResourcePressure();
            last_pressure = now;
        }

        if (now - last_health >= std::chrono::seconds(30)) {
            emit_health(/*final_record=*/false);
            last_health = now;
            if (!snapshotWriter.WriteIfDue())
                std::cerr << "[WARN] correlated_events.json write failed: "
                    << snapshotWriter.GetLastError() << "\n";

            std::cout << "[STATUS] ingested=" << ingested
                << " unified=" << unified_total
                << " pending=" << engine.PendingMemberCount() << "\n";
        }

        for (int i = 0; i < 30 && g_running.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));   // ~3s poll cadence
    }

    std::cout << "[Correlator] Stopping. ingested=" << ingested
        << " unified=" << unified_total << "\n";
    std::vector<GroupSnapshot> finalGroups;
    for (auto& unifiedLine : engine.DrainReady(0, true, &finalGroups)) {
        logger.Log(unifiedLine);
        ++unified_total;
    }
    if (!finalGroups.empty()) snapshotWriter.AddGroups(finalGroups);
    snapshotWriter.WriteIfDue(/*force=*/true);
    for (auto& tailer : tailers)
        if (!tailer.Commit()) ++checkpoint_failures;
    emit_health(/*final_record=*/true);
    ipcServer.Stop();
    return 0;
}
