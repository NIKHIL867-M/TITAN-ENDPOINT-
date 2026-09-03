// log_tailer.h
//
// Poll-tails a directory of JSONL/append-only log files: on each call,
// re-scans the directory, reads any bytes appended since the last check for
// every tracked file, and naturally picks up newly-rotated-to files. Files
// that disappear (pruned by the source endpoint's own retention logic) are
// simply dropped from tracking -- never an error, since every endpoint's
// rotation/pruning is expected and already exercised by their own test
// suites this session.
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace correlator {

class LogTailer {
public:
    // directory: where this endpoint's log files live.
    // filename_hint: substring every relevant file's name must contain
    // (e.g. "usb_events", "titan_", "fim_events") -- keeps the tailer from
    // picking up unrelated files that might share the directory.
    LogTailer(std::wstring directory, std::string filename_hint,
        std::wstring checkpoint_path = {}, bool start_at_end_on_first_run = true);

    // Scans for new/changed files and returns every complete new line
    // appended since the last call, across all tracked files. A partial
    // (not yet newline-terminated) trailing line is held back until it is
    // completed on a later call.
    // max_bytes is shared across all packs in this call, preventing a large
    // retained history from becoming one unbounded allocation.
    std::vector<std::string> ReadNewLines(size_t max_bytes = 256 * 1024);

    // Persist only after the caller has successfully handled every returned
    // line. This gives at-least-once crash semantics instead of silently
    // checkpointing data before it reaches the unified output.
    bool Commit();

    const std::wstring& Directory() const { return directory_; }
    uint64_t BootstrappedBytes() const noexcept { return bootstrapped_bytes_; }

private:
    struct FileState {
        uint64_t last_offset = 0;
        uint64_t safe_offset = 0;
        std::string pending_partial_line;   // bytes read but not yet newline-terminated
    };

    void LoadCheckpoint();
    bool SaveCheckpoint() const;

    std::wstring directory_;
    std::string filename_hint_;
    std::wstring checkpoint_path_;
    std::unordered_map<std::wstring, FileState> files_;
    bool bootstrap_pending_ = false;
    uint64_t bootstrapped_bytes_ = 0;
};

} // namespace correlator
