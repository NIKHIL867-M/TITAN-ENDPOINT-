// correlator_logger.h
//
// Bounded JSONL output for the Correlator's own session_timeline evidence
// and collector_health records -- same rotate-at-size + prune-oldest-
// archives pattern as every other endpoint's logger this session.
#pragma once

#include <atomic>
#include <chrono>
#include <fstream>
#include <mutex>
#include <string>
#include <utility>

#include "evidence_envelope.h"
#include "resource_pressure.h"

namespace correlator {

class CorrelatorLogger {
public:
    explicit CorrelatorLogger(std::wstring log_dir);

    bool Initialize();
    void Log(const std::string& json_line);
    void Flush();

    // RAM/disk auto-lightening.
    void UpdateResourcePressure();
    PressureTier GetResourcePressureTier() const { return pressure_monitor_.GetTier(); }

    // FORU.TXT section 4.3-4.5: Persistence is independent of collection --
    // when disabled, Log() still runs (revision bookkeeping etc.) but skips
    // the actual disk write. Never deletes anything already retained.
    void SetPersistenceEnabled(bool enabled) noexcept { persistence_enabled_.store(enabled); }
    bool IsPersistenceEnabled() const noexcept { return persistence_enabled_.load(); }
    void SetMaxPacks(size_t maxPacks) noexcept {
        const size_t value = maxPacks < 1 ? 1 : maxPacks;
        configured_max_packs_.store(value, std::memory_order_relaxed);
        max_packs_.store(value, std::memory_order_relaxed);
    }
    size_t GetMaxPacks() const noexcept { return max_packs_.load(std::memory_order_relaxed); }
    static constexpr uint64_t GetMaxPackFileBytes() noexcept { return kMaxFileBytes; }

    const std::string& GetSessionId() const noexcept { return session_id_; }
    int64_t GetStartedAtUnixMs() const noexcept { return started_at_unix_ms_; }
    uint64_t GetWriteFailureCount() const noexcept { return write_failures_.load(); }
    uint64_t GetRotationCount() const noexcept { return rotation_count_.load(); }
    uint64_t GetWrittenCount() const noexcept { return written_count_.load(); }
    std::string GetLastError() const {
        std::lock_guard<std::mutex> lock(last_error_mutex_);
        return last_error_;
    }
    // Walks log_dir_ the same way PruneOldPacks() does and sums size/count of
    // every retained pack -- FORU.TXT section 5's retained_bytes/files.
    std::pair<uint64_t, uint64_t> GetRetainedBytesAndFiles() const;

private:
    void RotateIfNeeded();
    void PruneOldPacks();
    std::wstring NewPackPath() const;
    static std::string NarrowFileName(const std::wstring& path);
    void SetLastError(const std::string& err) {
        std::lock_guard<std::mutex> lock(last_error_mutex_);
        last_error_ = err;
    }

    std::wstring log_dir_;
    std::wstring current_pack_path_;
    std::ofstream pack_file_;
    std::mutex mutex_;
    uint64_t current_file_bytes_ = 0;

    ResourcePressureMonitor pressure_monitor_;
    static constexpr uint64_t kMaxFileBytes = 2ULL * 1024 * 1024;   // 2 MB per pack
    static constexpr size_t   kMaxPacksBase = 10;
    static constexpr size_t   kMinPacks = 2;
    std::atomic<size_t> max_packs_{ kMaxPacksBase };
    std::atomic<size_t> configured_max_packs_{ kMaxPacksBase };

    std::atomic<bool> persistence_enabled_{ true };
    const std::string session_id_{MakeSessionId("correlator")};
    std::atomic<uint64_t> next_record_id_{1};
    std::atomic<uint64_t> write_failures_{0};
    std::atomic<uint64_t> rotation_count_{0};
    std::atomic<uint64_t> written_count_{0};
    mutable std::mutex last_error_mutex_;
    std::string last_error_;
    const int64_t started_at_unix_ms_{
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()};
};

} // namespace correlator
