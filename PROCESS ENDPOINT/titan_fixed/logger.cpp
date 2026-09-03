#include "logger.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <vector>

namespace titan {

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

AsyncLogger::AsyncLogger(const std::wstring &log_dir) : log_dir_(log_dir) {}

AsyncLogger::~AsyncLogger() { Shutdown(); }

// ============================================================================
// INITIALIZE
// Creates the log directory, opens the first pack file, starts both threads.
// ============================================================================

bool AsyncLogger::Initialize() {
  std::lock_guard<std::mutex> lock(mutex_);

  std::filesystem::create_directories(std::filesystem::path(log_dir_));

  current_pack_path_ = NewPackPath();
  pack_file_.open(std::filesystem::path(current_pack_path_),
                  std::ios::out | std::ios::trunc);

  if (!pack_file_.is_open()) {
    const std::string err =
        "Failed to open log pack: " +
        std::string(current_pack_path_.begin(), current_pack_path_.end());
    ConsoleLogger::LogError(err);
    write_failures_.fetch_add(1, std::memory_order_relaxed);
    SetLastError(err);
    return false;
  }

  running_ = true;
  worker_ = std::thread(&AsyncLogger::WorkerThread, this);
  ticker_ = std::thread(&AsyncLogger::CompressTicker, this);

  ConsoleLogger::LogInfo(
      "Logger V3 started: " +
      std::string(current_pack_path_.begin(), current_pack_path_.end()));
  return true;
}

// ============================================================================
// SHUTDOWN
// Drains the queue completely before closing — no events lost on exit.
// ============================================================================

void AsyncLogger::Shutdown() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!running_)
      return;
    running_ = false;
  }

  cv_.notify_all();

  if (worker_.joinable())
    worker_.join();
  if (ticker_.joinable())
    ticker_.join();

  if (pack_file_.is_open())
    pack_file_.close();
}

// ============================================================================
// LOG EVENT  (FORWARD path)
// Non-blocking under normal load. Applies back-pressure if queue is full
// (waits briefly) rather than dropping the event silently.
// ============================================================================

void AsyncLogger::LogEvent(Event &&event) {
  {
    std::unique_lock<std::mutex> lock(mutex_);

    // Back-pressure: wait up to 50ms if queue is at capacity.
    // This keeps the pipeline honest — no silent loss under a transient stall.
    if (event_queue_.size() >= kMaxQueue) {
      cv_.wait_for(lock, std::chrono::milliseconds(50), [this] {
        return event_queue_.size() < kMaxQueue || !running_;
      });
    }

    if (!running_)
      return;

    // FIX: the wait above does not guarantee space freed up -- under a
    // genuinely stalled disk the worker thread never drains, and every call
    // used to push anyway after its 50ms wait, growing the queue (and RAM)
    // without bound. Re-check against the hard ceiling and drop-and-count
    // rather than grow forever; GetQueueDroppedCount() surfaces this in
    // collector_health so a real overload is visible, not silent.
    if (event_queue_.size() >= kHardMaxQueue) {
      queue_dropped_.fetch_add(1, std::memory_order_relaxed);
      return;
    }

    event_queue_.push(std::move(event));
    queued_count_.fetch_add(1, std::memory_order_relaxed);
    const int64_t depth_now = queue_depth_.fetch_add(1, std::memory_order_relaxed) + 1;
    // Racy read-then-maybe-write is fine for a peak gauge -- worst case under
    // concurrent LogEvent() calls is under-reporting the peak by one bump,
    // never a wrong/negative value, and never worth a CAS loop for a
    // monitoring-only counter.
    if (depth_now > queue_depth_peak_.load(std::memory_order_relaxed))
      queue_depth_peak_.store(depth_now, std::memory_order_relaxed);
  }
  cv_.notify_one();
}

// ============================================================================
// LOG COMPRESS SUMMARY  (COMPRESS path)
// Builds a CompressSummary into a COMPRESS event and writes it directly.
// Called from CompressTicker — already on the ticker thread, not queued.
// ============================================================================

void AsyncLogger::LogCompressSummary(const CompressSummary &summary) {
  Event evt = Event::CreateCompressEvent(summary);
  std::string line = evt.CompressJson();

  std::lock_guard<std::mutex> lock(mutex_);
  WriteJsonLine(line);
  compressed_count_.fetch_add(1, std::memory_order_relaxed);
  written_count_.fetch_add(1, std::memory_order_relaxed);
  pack_file_.flush();
}

// ============================================================================
// LOG RAW  (collector_health-style pre-built JSON lines)
// ============================================================================

void AsyncLogger::LogRaw(const std::string &json) {
  std::lock_guard<std::mutex> lock(mutex_);
  WriteJsonLine(json);
  written_count_.fetch_add(1, std::memory_order_relaxed);
  pack_file_.flush();
}

// ============================================================================
// WORKER THREAD
// Drains event_queue_ in batches, serialises each event as a JSON line.
// ============================================================================

void AsyncLogger::WorkerThread() {
  std::vector<Event> batch;
  batch.reserve(128);

  while (true) {
    {
      std::unique_lock<std::mutex> lock(mutex_);
      cv_.wait(lock, [this] { return !event_queue_.empty() || !running_; });

      if (!running_ && event_queue_.empty())
        break;

      while (!event_queue_.empty() && batch.size() < 128) {
        batch.push_back(std::move(event_queue_.front()));
        event_queue_.pop();
        queue_depth_.fetch_sub(1, std::memory_order_relaxed);
      }
    }
    cv_.notify_all(); // unblock any back-pressured callers

    for (auto &evt : batch) {
      RotateIfNeeded();
      const bool is_compress = evt.IsV3Enriched() &&
                               evt.GetV3().decision == FilterDecision::COMPRESS;

      std::string line = evt.ToJson();

      // Kept regardless of save_logs_enabled_ so "Monitoring ON, Save Logs
      // OFF" still has bounded live-view data available over the IPC control
      // channel (FORU.TXT 4.4) even though nothing new is being written to
      // the JSONL file below.
      {
        std::lock_guard<std::mutex> recentLock(recent_lines_mutex_);
        recent_lines_.push_back(line);
        if (recent_lines_.size() > kRecentLinesCap) recent_lines_.pop_front();
      }

      {
        std::lock_guard<std::mutex> lock(mutex_);
        if (save_logs_enabled_.load()) {
          WriteJsonLine(line);
          written_count_.fetch_add(1, std::memory_order_relaxed);
        }

        if (is_compress)
          compressed_count_.fetch_add(1, std::memory_order_relaxed);
        else
          forwarded_count_.fetch_add(1, std::memory_order_relaxed);
      }
    }

    batch.clear();

    // FIX: flush must be done under the mutex — pack_file_ is shared with
    // CompressTicker via LogCompressSummary().  Calling flush() concurrently
    // without the lock was a data race that corrupted the stream state.
    {
      std::lock_guard<std::mutex> lock(mutex_);
      pack_file_.flush();
    }
  }
}

// ============================================================================
// COMPRESS TICKER
// Every 60 seconds, asks the FilterEngine to flush compress summaries and
// writes each one to the log pack via LogCompressSummary().
// ============================================================================

void AsyncLogger::CompressTicker() {
  // FIX: previously an uninterruptible sleep_for(60s) -- Shutdown()'s ticker_.join()
  // could then block for up to a full 60 seconds waiting for this thread to wake up
  // and notice running_ was cleared, even though Shutdown() already calls
  // cv_.notify_all() immediately. Confirmed live: a full IPC-driven start/stop cycle
  // in ipc_control_server_test took 60+ seconds end to end purely from this wait,
  // meaning every graceful stop (Ctrl+C, IPC Shutdown, or EndpointProcessController's
  // 5-second graceful-stop window from the GUI) was almost certainly hitting the
  // force-kill fallback in practice rather than actually shutting down cleanly.
  // Waiting on the same cv_/mutex_ the queue already uses lets Shutdown()'s existing
  // notify_all() wake this immediately while still capping the wait at 60s normally.
  while (running_.load(std::memory_order_relaxed)) {
    {
      std::unique_lock<std::mutex> lock(mutex_);
      cv_.wait_for(lock, std::chrono::seconds(kCompressWindowSec),
                   [this] { return !running_.load(std::memory_order_relaxed); });
    }

    if (!running_.load(std::memory_order_relaxed))
      break;
    if (!filter_)
      continue;

    auto summaries = filter_->FlushCompressSummaries();
    for (const auto &s : summaries)
      LogCompressSummary(s);
  }
}

// ============================================================================
// WRITE JSON LINE
// Writes one JSONL line (newline-delimited JSON — no wrapping array).
// Must be called with mutex_ held.
// ============================================================================

void AsyncLogger::WriteJsonLine(const std::string &json) {
  // FORU.TXT section 8: stamp durable evidence identity on every record at
  // this single choke point -- every LogEvent/LogCompressSummary/LogRaw call
  // funnels through here, so this is the one place that guarantees no record
  // type is missed.
  const uint64_t record_id = next_record_id_.fetch_add(1, std::memory_order_relaxed);
  const uint64_t offset_before = current_file_bytes_.load(std::memory_order_relaxed);
  const std::string wrapped = WrapWithEvidenceEnvelope(
      json, record_id, session_id_, NarrowFileName(current_pack_path_), offset_before);

  pack_file_ << wrapped << '\n';
  if (pack_file_.fail()) {
    write_failures_.fetch_add(1, std::memory_order_relaxed);
    SetLastError("Write to log pack failed (stream error state)");
    pack_file_.clear();   // allow subsequent attempts rather than staying permanently failed
    return;
  }
  current_file_bytes_.fetch_add(wrapped.size() + 1, std::memory_order_relaxed);
}

std::string AsyncLogger::NarrowFileName(const std::wstring &path) {
  const auto slash = path.find_last_of(L"/\\");
  const std::wstring wide_name = (slash == std::wstring::npos) ? path : path.substr(slash + 1);
  // Pack filenames are always ASCII (see NewPackPath), so a plain narrow-cast
  // is correct here -- not a general Unicode transcode.
  return std::string(wide_name.begin(), wide_name.end());
}

std::pair<uint64_t, uint64_t> AsyncLogger::GetRetainedBytesAndFiles() const {
  std::error_code ec;
  std::filesystem::path dir(log_dir_);
  if (!std::filesystem::exists(dir, ec)) return {0, 0};

  uint64_t total_bytes = 0;
  uint64_t total_files = 0;
  for (const auto &entry : std::filesystem::directory_iterator(dir, ec)) {
    if (ec) break;
    if (!entry.is_regular_file()) continue;
    const auto &name = entry.path().filename().wstring();
    if (name.rfind(L"titan_", 0) != 0 || entry.path().extension() != L".jsonl") continue;
    std::error_code size_ec;
    const auto size = entry.file_size(size_ec);
    if (!size_ec) total_bytes += size;
    ++total_files;
  }
  return {total_bytes, total_files};
}

// ============================================================================
// ROTATE IF NEEDED
// Rolls to a new pack file when the current one exceeds kMaxFileBytes.
// ============================================================================

void AsyncLogger::RotateIfNeeded() {
  if (current_file_bytes_.load() < kMaxFileBytes)
    return;

  bool reopened_ok = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    pack_file_.close();
    current_pack_path_ = NewPackPath();
    pack_file_.open(std::filesystem::path(current_pack_path_),
                    std::ios::out | std::ios::trunc);
    current_file_bytes_.store(0);
    reopened_ok = pack_file_.is_open();
  }

  if (!reopened_ok) {
    const std::string err =
        "Failed to reopen log pack after rotation: " +
        std::string(current_pack_path_.begin(), current_pack_path_.end());
    ConsoleLogger::LogError(err);
    write_failures_.fetch_add(1, std::memory_order_relaxed);
    SetLastError(err);
    return;
  }

  rotation_count_.fetch_add(1, std::memory_order_relaxed);
  ConsoleLogger::LogInfo(
      "Log pack rotated: " +
      std::string(current_pack_path_.begin(), current_pack_path_.end()));

  PruneOldPacks();
}

// ============================================================================
// PRUNE OLD PACKS
//
// Pack filenames embed a "%Y%m%d_%H%M%S" timestamp (see NewPackPath), so
// lexical (string) sort order is identical to chronological order -- no need
// to parse timestamps back out. Never removes the currently-open pack.
// ============================================================================

void AsyncLogger::PruneOldPacks() const {
  std::error_code ec;
  std::filesystem::path dir(log_dir_);
  if (!std::filesystem::exists(dir, ec))
    return;

  std::vector<std::filesystem::path> packs;
  for (const auto &entry : std::filesystem::directory_iterator(dir, ec)) {
    if (ec) break;
    if (!entry.is_regular_file()) continue;
    const auto &name = entry.path().filename().wstring();
    if (name.rfind(L"titan_", 0) == 0 && entry.path().extension() == L".jsonl")
      packs.push_back(entry.path());
  }
  const size_t max_packs = max_packs_.load(std::memory_order_relaxed);
  if (packs.size() <= max_packs)
    return;

  std::sort(packs.begin(), packs.end()); // lexical == chronological
  size_t to_remove = packs.size() - max_packs;
  for (size_t i = 0; i < to_remove; ++i) {
    if (packs[i] == std::filesystem::path(current_pack_path_))
      continue; // never remove the pack we're actively writing to
    std::error_code remove_ec;
    std::filesystem::remove(packs[i], remove_ec);
    if (remove_ec) {
      ConsoleLogger::LogError("Failed to prune old log pack: " +
                              packs[i].string());
    }
  }
}

// ============================================================================
// NEW PACK PATH
// Generates: <log_dir>\titan_YYYYMMDD_HHMMSS.jsonl
// ============================================================================

std::wstring AsyncLogger::NewPackPath() const {
  auto now = std::chrono::system_clock::now();
  auto tt = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
  localtime_s(&tm, &tt);

  wchar_t buf[64]{};
  wcsftime(buf, std::size(buf), L"%Y%m%d_%H%M%S", &tm);

  return log_dir_ + L"titan_" + buf + L".jsonl";
}

// ============================================================================
// FLUSH  —  wait until queue is empty
// ============================================================================

void AsyncLogger::Flush() {
  std::unique_lock<std::mutex> lock(mutex_);
  cv_.wait(lock, [this] { return event_queue_.empty(); });
}

std::vector<std::string> AsyncLogger::GetRecentLines() const {
  std::lock_guard<std::mutex> lock(recent_lines_mutex_);
  return std::vector<std::string>(recent_lines_.begin(), recent_lines_.end());
}

// ============================================================================
// CONSOLE LOGGER
// ============================================================================

void ConsoleLogger::LogInfo(const std::string &msg) {
  std::cout << "[INFO]  " << msg << '\n';
}
void ConsoleLogger::LogWarning(const std::string &msg) {
  std::cout << "[WARN]  " << msg << '\n';
}
void ConsoleLogger::LogError(const std::string &msg) {
  std::cerr << "[ERROR] " << msg << '\n';
}

} // namespace titan
