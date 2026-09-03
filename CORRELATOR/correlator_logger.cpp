// correlator_logger.cpp
#include "correlator_logger.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <vector>

namespace correlator {

CorrelatorLogger::CorrelatorLogger(std::wstring log_dir)
    : log_dir_(std::move(log_dir)), pressure_monitor_(log_dir_)
{
}

bool CorrelatorLogger::Initialize()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ec;
    std::filesystem::create_directories(log_dir_, ec);

    current_pack_path_ = NewPackPath();
    pack_file_.open(current_pack_path_, std::ios::out | std::ios::trunc);
    if (!pack_file_.is_open()) {
        std::wcerr << L"[Correlator] Failed to open log pack: " << current_pack_path_ << L'\n';
        return false;
    }
    // Enforce the existing retention budget at startup too. Previously old
    // packs were pruned only after the new pack reached 2 MiB, so dozens of
    // stale sessions could remain indefinitely during short runs.
    PruneOldPacks();
    return true;
}

void CorrelatorLogger::Log(const std::string& json_line)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!pack_file_.is_open()) return;
    // FORU.TXT section 4.3-4.5: persistence toggle skips the disk write but
    // never blocks the caller or deletes anything already retained.
    if (!persistence_enabled_.load()) return;

    RotateIfNeeded();

    // FORU.TXT section 8: durable evidence identity, stamped at this single
    // choke point so every record type this program writes (session_timeline,
    // collector_health, control_audit) gets one, unconditionally.
    const uint64_t record_id = next_record_id_.fetch_add(1, std::memory_order_relaxed);
    const std::string wrapped = WrapWithEvidenceEnvelope(
        json_line, record_id, session_id_, NarrowFileName(current_pack_path_), current_file_bytes_);

    pack_file_ << wrapped << '\n';
    if (pack_file_.fail()) {
        write_failures_.fetch_add(1, std::memory_order_relaxed);
        SetLastError("Write to log pack failed (stream error state)");
        pack_file_.clear();
        return;
    }
    current_file_bytes_ += wrapped.size() + 1;
    written_count_.fetch_add(1, std::memory_order_relaxed);
    pack_file_.flush();
}

std::string CorrelatorLogger::NarrowFileName(const std::wstring& path) {
    const auto slash = path.find_last_of(L"/\\");
    const std::wstring wide_name = (slash == std::wstring::npos) ? path : path.substr(slash + 1);
    // Pack filenames are always ASCII (see NewPackPath) -- explicit per-char
    // cast rather than the iterator-range constructor so this doesn't trip
    // C4244 under /WX (this program's CMakeLists.txt has no /wd4244).
    std::string out;
    out.reserve(wide_name.size());
    for (wchar_t wc : wide_name) out.push_back(static_cast<char>(wc));
    return out;
}

std::pair<uint64_t, uint64_t> CorrelatorLogger::GetRetainedBytesAndFiles() const {
    std::error_code ec;
    if (!std::filesystem::exists(log_dir_, ec)) return {0, 0};

    uint64_t total_bytes = 0;
    uint64_t total_files = 0;
    for (const auto& entry : std::filesystem::directory_iterator(log_dir_, ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;
        const auto& name = entry.path().filename().wstring();
        if (name.rfind(L"correlator_", 0) != 0 || entry.path().extension() != L".jsonl") continue;
        std::error_code size_ec;
        const auto size = entry.file_size(size_ec);
        if (!size_ec) total_bytes += size;
        ++total_files;
    }
    return {total_bytes, total_files};
}

void CorrelatorLogger::Flush()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (pack_file_.is_open()) pack_file_.flush();
}

void CorrelatorLogger::UpdateResourcePressure()
{
    pressure_monitor_.Update();
    max_packs_.store(
        AdaptiveCap(configured_max_packs_.load(std::memory_order_relaxed),
            static_cast<size_t>(1), pressure_monitor_.GetFactor()),
        std::memory_order_relaxed);
}

void CorrelatorLogger::RotateIfNeeded()
{
    // Caller (Log()) already holds mutex_.
    if (current_file_bytes_ < kMaxFileBytes) return;

    pack_file_.close();
    current_pack_path_ = NewPackPath();
    pack_file_.open(current_pack_path_, std::ios::out | std::ios::trunc);
    current_file_bytes_ = 0;
    if (!pack_file_.is_open()) {
        write_failures_.fetch_add(1, std::memory_order_relaxed);
        SetLastError("Failed to reopen log pack after rotation");
    } else {
        rotation_count_.fetch_add(1, std::memory_order_relaxed);
    }

    PruneOldPacks();
}

void CorrelatorLogger::PruneOldPacks()
{
    // Caller (RotateIfNeeded, via Log()) already holds mutex_.
    std::error_code ec;
    std::vector<std::filesystem::path> packs;
    for (const auto& entry : std::filesystem::directory_iterator(log_dir_, ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;
        const auto& name = entry.path().filename().wstring();
        if (name.rfind(L"correlator_", 0) == 0 && entry.path().extension() == L".jsonl")
            packs.push_back(entry.path());
    }

    const size_t max_packs = max_packs_.load(std::memory_order_relaxed);
    if (packs.size() <= max_packs) return;

    std::sort(packs.begin(), packs.end());   // lexical == chronological (timestamped names)
    const size_t to_remove = packs.size() - max_packs;
    for (size_t i = 0; i < to_remove; ++i) {
        if (packs[i] == std::filesystem::path(current_pack_path_)) continue;
        std::error_code remove_ec;
        std::filesystem::remove(packs[i], remove_ec);
    }
}

std::wstring CorrelatorLogger::NewPackPath() const
{
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_s(&tm, &tt);

    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count() % 1000;
    wchar_t buf[64]{};
    wcsftime(buf, std::size(buf), L"%Y%m%d_%H%M%S", &tm);

    return log_dir_ + L"\\correlator_" + buf + L"_" + std::to_wstring(millis) +
        L"_" + std::to_wstring(GetCurrentProcessId()) + L".jsonl";
}

} // namespace correlator
