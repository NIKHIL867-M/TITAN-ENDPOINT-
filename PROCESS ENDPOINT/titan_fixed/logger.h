#ifndef TITAN_LOGGER_H
#define TITAN_LOGGER_H

// ============================================================================
// logger.h  —  TITAN V3
//
// V3 changes:
//   REMOVED: dropped_count_ / drop-on-full logic — no silent event loss
//   ADDED:   LogCompressSummary()  — writes lightweight COMPRESS JSON lines
//            GetForwardedCount() / GetCompressedCount() — V3 pipeline counters
//            compress_ticker_ thread — calls
//            FilterEngine::FlushCompressSummaries() every 60 seconds and writes
//            the summaries to the log pack
//   CHANGED: Queue back-pressure instead of drop (block caller briefly if full)
//            Log files are .jsonl (newline-delimited JSON) — one event per
//            line, no wrapping array — easier for streaming parsers
// ============================================================================

#include "event.h"
#include "evidence_envelope.h"
#include "filter.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace titan {

// ============================================================================
// ASYNC LOGGER  —  V3
// Thread-safe. Single worker thread drains the queue and writes .jsonl packs.
// A second ticker thread calls FlushCompressSummaries() every 60 seconds.
// NO events are ever silently dropped — back-pressure is applied instead.
// ============================================================================

class AsyncLogger {
public:
  explicit AsyncLogger(const std::wstring &log_dir);
  ~AsyncLogger();

  AsyncLogger(const AsyncLogger &) = delete;
  AsyncLogger &operator=(const AsyncLogger &) = delete;

  // Initialise: create log directory, open first pack, start worker threads.
  bool Initialize();

  // Drain queue, close file, stop threads. Safe to call multiple times.
  void Shutdown();

  // Enqueue a FORWARD event. Thread-safe, non-blocking under normal load.
  // If the queue is at capacity, caller blocks briefly (back-pressure).
  // Events are NEVER silently dropped.
  void LogEvent(Event &&event);

  // Enqueue a pre-built COMPRESS summary (called by compress ticker).
  void LogCompressSummary(const CompressSummary &summary);

  // Append a raw pre-built JSON line directly (used for collector_health-style
  // records that aren't full Event objects). Thread-safe; writes and flushes
  // immediately, bypassing the queue -- same pattern as LogCompressSummary().
  void LogRaw(const std::string &json);

  // Wait until the queue is fully drained.
  void Flush();

  // FORU.TXT section 4.3-4.5: Save Logs is independent of Monitoring. When
  // disabled, forwarded events are still processed and counted (Monitoring
  // controls that) but the disk write is skipped — turning Save Logs off
  // never deletes retained evidence, it only stops future persistence.
  // "Monitoring ON + Save Logs OFF" still needs bounded live viewing without
  // relying on the JSONL file (4.4) — recent forwarded lines are kept in a
  // small in-memory ring regardless of this flag, retrievable via
  // GetRecentLines(), so a live view has something to read from even with
  // disk writes off.
  void SetSaveLogsEnabled(bool enabled) noexcept {
    save_logs_enabled_.store(enabled);
  }
  bool IsSaveLogsEnabled() const noexcept { return save_logs_enabled_.load(); }

  // Newest-last snapshot of the last kRecentLinesCap forwarded/compressed
  // JSON lines, safe to call from the IPC server thread.
  std::vector<std::string> GetRecentLines() const;

  // Wire the filter so the compress ticker can call FlushCompressSummaries().
  void SetFilter(FilterEngine *filter) noexcept { filter_ = filter; }

  // RAM/disk auto-lightening: shrinks (or restores) the pack-retention cap
  // at runtime, e.g. driven by ResourcePressureMonitor. Takes effect on the
  // next rotation's prune pass.
  void SetMaxPacks(size_t maxPacks) noexcept {
    max_packs_.store(maxPacks, std::memory_order_relaxed);
  }
  size_t GetMaxPacks() const noexcept { return max_packs_.load(std::memory_order_relaxed); }
  const std::wstring &GetLogDir() const noexcept { return log_dir_; }

  // V3 counters
  uint64_t GetWrittenCount() const noexcept { return written_count_.load(); }
  uint64_t GetQueuedCount() const noexcept { return queued_count_.load(); }
  uint64_t GetForwardedCount() const noexcept {
    return forwarded_count_.load();
  }
  uint64_t GetCompressedCount() const noexcept {
    return compressed_count_.load();
  }
  // Events dropped because the queue hit its hard ceiling under sustained
  // overload (e.g. a stalled disk) -- never silent, always counted.
  uint64_t GetQueueDroppedCount() const noexcept {
    return queue_dropped_.load();
  }

  // FORU.TXT section 6: normalized collector_health schema fields.
  // GetQueueDepth() is the CURRENT backlog (unlike GetQueuedCount(), which is
  // a cumulative lifetime total) -- what health needs to show actual queue
  // pressure right now. Tracked as its own atomic (rather than locking
  // mutex_ to call event_queue_.size()) so this stays lock-free.
  int64_t GetQueueDepth() const noexcept { return queue_depth_.load(); }
  static constexpr size_t GetQueueCapacity() noexcept { return kHardMaxQueue; }
  // FORU.TXT section 7: lets a caller (ProcessMonitor's retention-budget
  // override) convert a byte/MB budget into an equivalent pack count without
  // duplicating this constant.
  static constexpr uint64_t GetMaxPackFileBytes() noexcept { return kMaxFileBytes; }
  uint64_t GetRotationCount() const noexcept { return rotation_count_.load(); }
  uint64_t GetWriteFailureCount() const noexcept {
    return write_failures_.load();
  }
  std::string GetLastError() const {
    std::lock_guard<std::mutex> lock(last_error_mutex_);
    return last_error_;
  }

  // FORU.TXT section 5/8: this process launch's identity, shared by every
  // subsystem in this program (ProcessMonitor reuses this exact value rather
  // than generating its own) so a single run has exactly one session_id
  // everywhere, and by evidence-envelope stamping on every record written.
  const std::string &GetSessionId() const noexcept { return session_id_; }

  // Highest queue_depth_ observed since startup -- queue_depth_ itself is
  // point-in-time, this is what health's "queue_peak" needs.
  int64_t GetQueueDepthPeak() const noexcept { return queue_depth_peak_.load(); }

  int64_t GetStartedAtUnixMs() const noexcept { return started_at_unix_ms_; }

  // Walks log_dir_ the same way PruneOldPacks() does and sums size/count of
  // every retained pack -- FORU.TXT section 5's retained_bytes/retained_files.
  std::pair<uint64_t, uint64_t> GetRetainedBytesAndFiles() const;

private:
  void WorkerThread();   // drains event_queue_, writes JSON lines
  void CompressTicker(); // every 60s: flush compress summaries from filter

  void WriteJsonLine(const std::string &json);
  void RotateIfNeeded();
  std::wstring NewPackPath() const;
  // FIX: each rotation creates a uniquely-timestamped pack file and nothing
  // ever removed old ones -- unbounded disk growth over agent uptime. Prunes
  // the oldest packs beyond kMaxPacks after each rotation.
  void PruneOldPacks() const;

  // ---- state ----
  std::wstring log_dir_;
  std::wstring current_pack_path_;
  std::ofstream pack_file_;
  FilterEngine *filter_{nullptr};

  std::thread worker_;
  std::thread ticker_;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::queue<Event> event_queue_;
  std::atomic<bool> running_{false};

  // V3 counters
  std::atomic<uint64_t> queued_count_{0};
  std::atomic<uint64_t> written_count_{0};
  std::atomic<uint64_t> forwarded_count_{0};
  std::atomic<uint64_t> compressed_count_{0};
  std::atomic<uint64_t> current_file_bytes_{0};
  std::atomic<uint64_t> queue_dropped_{0};
  std::atomic<int64_t> queue_depth_{0};
  std::atomic<uint64_t> rotation_count_{0};
  std::atomic<uint64_t> write_failures_{0};
  std::atomic<int64_t> queue_depth_peak_{0};
  mutable std::mutex last_error_mutex_;
  std::string last_error_;
  void SetLastError(const std::string &err) {
    std::lock_guard<std::mutex> lock(last_error_mutex_);
    last_error_ = err;
  }

  // FORU.TXT section 8: durable evidence identity, stamped on every record at
  // the single WriteJsonLine choke point -- see evidence_envelope.h.
  const std::string session_id_{MakeSessionId("process")};
  std::atomic<uint64_t> next_record_id_{1};
  const int64_t started_at_unix_ms_{
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count()};
  // Narrow (single-byte) filename-only view of a pack path, for embedding
  // directly into JSON as source_file -- pack filenames are ASCII
  // ("titan_YYYYMMDD_HHMMSS.jsonl", see NewPackPath), so this is a plain
  // narrow-cast, not a real Unicode transcode.
  static std::string NarrowFileName(const std::wstring &path);

  // Save Logs toggle + bounded live-view ring (see SetSaveLogsEnabled/GetRecentLines above).
  std::atomic<bool> save_logs_enabled_{true};
  mutable std::mutex recent_lines_mutex_;
  std::deque<std::string> recent_lines_;
  static constexpr size_t kRecentLinesCap = 500;

  // Config
  static constexpr size_t kMaxQueue = 10'000; // back-pressure threshold
  // FIX: kMaxQueue above only triggers a 50ms wait, not a hard stop -- under
  // a genuinely stalled disk (worker thread never catches up), LogEvent()
  // used to push past kMaxQueue every single call, growing the queue (and
  // RAM) without bound. kHardMaxQueue is the real ceiling: 5x kMaxQueue so
  // it only engages under sustained overload, past which new events are
  // dropped and counted (never silently) rather than accumulated forever.
  static constexpr size_t kHardMaxQueue = 50'000;
  static constexpr uint64_t kMaxFileBytes =
      100ULL * 1024 * 1024; // 100 MB per pack
  static constexpr uint32_t kCompressWindowSec = 60;
  static constexpr size_t kMaxPacksBase = 20; // base retention cap -- bounded disk use
  // Runtime, pressure-adjustable retention cap (starts at kMaxPacksBase,
  // shrunk under RAM/disk pressure via SetMaxPacks()).
  std::atomic<size_t> max_packs_{kMaxPacksBase};
};

// ============================================================================
// CONSOLE LOGGER  —  lightweight, sync, for status/debug output only
// ============================================================================

class ConsoleLogger {
public:
  static void LogInfo(const std::string &msg);
  static void LogWarning(const std::string &msg);
  static void LogError(const std::string &msg);
};

} // namespace titan

#endif // TITAN_LOGGER_H
