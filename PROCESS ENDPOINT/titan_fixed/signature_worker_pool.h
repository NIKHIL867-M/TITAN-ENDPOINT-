#ifndef TITAN_SIGNATURE_WORKER_POOL_H
#define TITAN_SIGNATURE_WORKER_POOL_H

// ============================================================================
// signature_worker_pool.h  —  TITAN V3
//
// Replaces filter.cpp Stage3_VerifySignature's previous pattern: on every
// uncached-path timeout it spawned a brand new std::async(launch::async)
// thread PLUS a detached std::thread to wait on it -- two new OS threads per
// call, with no cap on how many could be in flight at once. A burst of
// never-before-seen binaries (e.g. software install, archive extraction)
// could accumulate an unbounded number of live threads/handles until the
// process's own natural pacing caught up, if it ever did.
//
// This header-only pool replaces that with:
//   - A fixed, owned set of worker threads (kDefaultWorkers), started once
//     and cleanly joined on Shutdown()/destruction -- never detached.
//   - Duplicate-path coalescing: if a second caller asks to verify a path
//     that's already in flight, it gets the SAME std::shared_future instead
//     of triggering a second WinVerifyTrust call for the same binary.
//   - A bounded work queue (kDefaultMaxQueue): once full, Submit() returns
///    a future that resolves to an "unverified" entry immediately rather
//     than growing the queue without bound. This is counted via
//     GetQueueDroppedCount(), never silent.
// ============================================================================

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace titan {

template <typename Entry>
class SignatureWorkerPool {
public:
    using VerifyFn = std::function<Entry(const std::wstring&)>;

    explicit SignatureWorkerPool(VerifyFn verify,
        size_t worker_count = kDefaultWorkers,
        size_t max_queue = kDefaultMaxQueue)
        : verify_(std::move(verify)), max_queue_(max_queue) {
        running_.store(true, std::memory_order_relaxed);
        workers_.reserve(worker_count);
        for (size_t i = 0; i < worker_count; ++i)
            workers_.emplace_back(&SignatureWorkerPool::WorkerThread, this);
    }

    ~SignatureWorkerPool() { Shutdown(); }

    SignatureWorkerPool(const SignatureWorkerPool&) = delete;
    SignatureWorkerPool& operator=(const SignatureWorkerPool&) = delete;

    // Returns a shared_future so multiple callers for the same path in
    // flight at once share one underlying verification. Never blocks the
    // caller -- queuing and coalescing happen under a short-held mutex only.
    std::shared_future<Entry> Submit(const std::wstring& canonical_path) {
        std::unique_lock<std::mutex> lock(mutex_);

        auto existing = in_flight_.find(canonical_path);
        if (existing != in_flight_.end())
            return existing->second;   // coalesced -- no new WinVerifyTrust call

        if (queue_.size() >= max_queue_) {
            queue_dropped_.fetch_add(1, std::memory_order_relaxed);
            std::promise<Entry> promise;
            std::shared_future<Entry> fut = promise.get_future().share();
            promise.set_value(Entry{});   // default-constructed => "unverified"
            return fut;
        }

        auto promise = std::make_shared<std::promise<Entry>>();
        std::shared_future<Entry> fut = promise->get_future().share();
        in_flight_[canonical_path] = fut;
        queue_.push_back(Job{ canonical_path, promise });
        lock.unlock();
        cv_.notify_one();
        return fut;
    }

    // Drains no further work, joins every worker thread. Safe to call more
    // than once (subsequent calls are a no-op).
    void Shutdown() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!running_.exchange(false, std::memory_order_relaxed))
                return;
        }
        cv_.notify_all();
        for (auto& t : workers_) {
            if (t.joinable()) t.join();
        }
        workers_.clear();
    }

    uint64_t GetQueueDroppedCount() const noexcept {
        return queue_dropped_.load(std::memory_order_relaxed);
    }

    static constexpr size_t kDefaultWorkers = 2;
    static constexpr size_t kDefaultMaxQueue = 256;

private:
    struct Job {
        std::wstring path;
        std::shared_ptr<std::promise<Entry>> promise;
    };

    void WorkerThread() {
        for (;;) {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return !queue_.empty() || !running_.load(std::memory_order_relaxed); });
            if (!running_.load(std::memory_order_relaxed) && queue_.empty())
                return;
            if (queue_.empty())
                continue;

            Job job = std::move(queue_.front());
            queue_.pop_front();
            lock.unlock();

            Entry result = verify_(job.path);
            job.promise->set_value(result);

            std::lock_guard<std::mutex> erase_lock(mutex_);
            in_flight_.erase(job.path);
        }
    }

    VerifyFn verify_;
    size_t max_queue_;

    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<Job> queue_;
    std::unordered_map<std::wstring, std::shared_future<Entry>> in_flight_;
    std::vector<std::thread> workers_;
    std::atomic<bool> running_{ false };
    std::atomic<uint64_t> queue_dropped_{ 0 };
};

} // namespace titan

#endif // TITAN_SIGNATURE_WORKER_POOL_H
