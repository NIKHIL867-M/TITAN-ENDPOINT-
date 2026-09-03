// log_tailer.cpp
#include "log_tailer.h"

#include <filesystem>
#include <fstream>
#include <algorithm>
#include <iomanip>

namespace correlator {

namespace {
bool NameMatches(const std::wstring& filename, const std::string& hint)
{
    if (hint.empty()) return true;
    std::wstring wide_hint(hint.begin(), hint.end());   // ASCII hints only -- safe widen
    return filename.find(wide_hint) != std::wstring::npos;
}
}

LogTailer::LogTailer(std::wstring directory, std::string filename_hint,
    std::wstring checkpoint_path, bool start_at_end_on_first_run)
    : directory_(std::move(directory)), filename_hint_(std::move(filename_hint)),
      checkpoint_path_(std::move(checkpoint_path))
{
    const bool checkpoint_exists = !checkpoint_path_.empty() &&
        std::filesystem::exists(checkpoint_path_);
    LoadCheckpoint();
    bootstrap_pending_ = start_at_end_on_first_run && !checkpoint_exists;
}

std::vector<std::string> LogTailer::ReadNewLines(size_t max_bytes)
{
    std::vector<std::string> lines;
    if (max_bytes == 0) return lines;

    std::error_code ec;
    if (!std::filesystem::exists(directory_, ec) || ec) return lines;

    // Track which files we saw this pass so vanished (pruned/rotated-away)
    // ones can be dropped from files_ afterward.
    std::vector<std::wstring> seen_this_pass;

    std::vector<std::filesystem::directory_entry> entries;
    for (const auto& entry : std::filesystem::directory_iterator(directory_, ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;
        const std::wstring name = entry.path().filename().wstring();
        if (!NameMatches(name, filename_hint_)) continue;
        entries.push_back(entry);
        seen_this_pass.push_back(entry.path().wstring());
    }
    // Santosh, 2026-08-13: "if anything related to the process then fix it" -- found live via a
    // controlled test (one process, one file write, matching pid and a well-within-window
    // timestamp) that the Correlator never even ingested the correct-pid evidence at all. Two
    // compounding root causes, both here:
    // (1) Entries used to be read in a fixed ALPHABETICAL order. For File endpoint that alone was
    //     enough to starve everything else outright ("fim_events.json" sorts before every
    //     "fim_events_<timestamp>.json" rotation, since '.' < '_' in ASCII, and it is also always
    //     the currently-live file -- if it had more unread backlog than one call's budget, every
    //     later-sorting file got zero bytes, every call, for as long as the backlog persisted).
    // (2) For Process endpoint specifically, alphabetical happens to equal chronological (the
    //     "titan_YYYYMMDD_HHMMSS.jsonl" naming sorts oldest-first) -- confirmed live: 24 files
    //     spanning back six real days were all still present and matched, meaning even splitting
    //     the budget evenly across all of them (the first fix, alone) still processed six days of
    //     history before ever reaching today's live tail. A live process can never wait behind
    //     that.
    // Fix: sort newest-write-time-first instead, so whichever file is actually growing right now
    // always gets read on every single call regardless of how much older backlog exists elsewhere
    // -- see the budget split below for how the newest file gets first claim on the call's budget
    // while older files still make steady, fair, non-starved progress with whatever is left over.
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
        std::error_code ec_a, ec_b;
        const auto time_a = a.last_write_time(ec_a);
        const auto time_b = b.last_write_time(ec_b);
        if (ec_a || ec_b) return a.path().wstring() < b.path().wstring();   // fall back to a stable order if either stat fails
        if (time_a != time_b) return time_a > time_b;   // newest first
        return a.path().wstring() < b.path().wstring();   // stable tiebreak for same-instant writes
    });

    size_t bytes_read_this_call = 0;
    for (size_t entry_index = 0; entry_index < entries.size(); ++entry_index) {
        if (bytes_read_this_call >= max_bytes) break;
        const auto& entry = entries[entry_index];

        const std::wstring full_path = entry.path().wstring();

        std::error_code size_ec;
        const uint64_t current_size = std::filesystem::file_size(entry.path(), size_ec);
        if (size_ec) continue;

        const auto existing = files_.find(full_path);
        if (existing == files_.end() && bootstrap_pending_) {
            files_.emplace(full_path, FileState{current_size, current_size, {}});
            bootstrapped_bytes_ += current_size;
            continue;
        }
        auto& state = files_[full_path];

        if (current_size < state.last_offset) {
            // File was truncated or replaced (e.g. a rotation reused the
            // same name) -- restart from the beginning rather than trying
            // to seek past the new, shorter end.
            state.last_offset = 0;
            state.safe_offset = 0;
        state.pending_partial_line.clear();
        }
        if (current_size == state.last_offset) continue;   // nothing new

        std::ifstream in(entry.path(), std::ios::binary);
        if (!in.is_open()) continue;
        in.seekg(static_cast<std::streamoff>(state.last_offset));

        const uint64_t available = current_size - state.last_offset;
        const uint64_t remaining_total = static_cast<uint64_t>(max_bytes - bytes_read_this_call);
        // The single newest (entries[0], per the newest-first sort above) file takes as much of
        // the remaining budget as it needs, uncapped by file count -- it is always the currently-
        // live file, so it must never be throttled down to an N-way split just because old backlog
        // also exists elsewhere. Every other (older) file splits only what is left over after that,
        // still bounded to a fair per-file floor so no single old file can hog the whole remainder
        // either -- old backlog keeps draining in the background, it just never competes with live
        // data for priority.
        uint64_t budget;
        if (entry_index == 0) {
            budget = remaining_total;
        } else {
            const size_t older_files_remaining = entries.size() - entry_index;
            budget = std::min<uint64_t>(remaining_total,
                std::max<uint64_t>(remaining_total / older_files_remaining, 4096));
        }
        const size_t requested = static_cast<size_t>(std::min(available, budget));
        std::string chunk(requested, '\0');
        in.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        const std::streamsize got = in.gcount();
        if (got <= 0) continue;
        chunk.resize(static_cast<size_t>(got));
        state.last_offset += static_cast<uint64_t>(got);
        bytes_read_this_call += static_cast<size_t>(got);

        std::string buffer = std::move(state.pending_partial_line);
        buffer += chunk;
            state.pending_partial_line.clear();

        size_t start = 0;
        for (;;) {
            const size_t newline = buffer.find('\n', start);
            if (newline == std::string::npos) {
                state.pending_partial_line = buffer.substr(start);
                break;
            }
            std::string line = buffer.substr(start, newline - start);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty()) lines.push_back(std::move(line));
            start = newline + 1;
        }
        state.safe_offset = state.last_offset -
            static_cast<uint64_t>(state.pending_partial_line.size());
    }

    if (bootstrap_pending_) {
        bootstrap_pending_ = false;
        SaveCheckpoint();
    }

    // Drop tracking for files that no longer exist (pruned or rotated away).
    for (auto it = files_.begin(); it != files_.end(); ) {
        if (std::find(seen_this_pass.begin(), seen_this_pass.end(), it->first) ==
            seen_this_pass.end())
            it = files_.erase(it);
        else
            ++it;
    }

    return lines;
}

void LogTailer::LoadCheckpoint()
{
    if (checkpoint_path_.empty()) return;
    std::wifstream in(checkpoint_path_);
    if (!in.is_open()) return;
    std::wstring path;
    uint64_t offset = 0;
    while (in >> std::quoted(path) >> offset)
        files_[path] = FileState{offset, offset, {}};
}

bool LogTailer::SaveCheckpoint() const
{
    if (checkpoint_path_.empty()) return true;
    const std::filesystem::path target(checkpoint_path_);
    std::error_code ec;
    if (target.has_parent_path()) std::filesystem::create_directories(target.parent_path(), ec);
    const std::filesystem::path temporary = target.wstring() + L".tmp";
    std::wofstream out(temporary, std::ios::out | std::ios::trunc);
    if (!out.is_open()) return false;
    for (const auto& [path, state] : files_)
        out << std::quoted(path) << L' ' << state.safe_offset << L'\n';
    out.flush();
    if (out.fail()) return false;
    out.close();
    std::filesystem::remove(target, ec);
    ec.clear();
    std::filesystem::rename(temporary, target, ec);
    return !ec;
}

bool LogTailer::Commit()
{
    return SaveCheckpoint();
}

} // namespace correlator
