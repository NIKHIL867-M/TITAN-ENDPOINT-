// process_logic_test.cpp -- non-admin logic tests for the Process endpoint.
//
// Exercises pure logic that does not require Administrator privileges or a
// live ETW session: JSON escaping, the FilterEngine 7-stage pipeline
// (classification, signature caching, dedup/compress, persistence
// touchpoints), bloom filter persistence, and the ProcessAccumulator
// unique-child-name cap. No ETW session is started -- that is covered by the
// elevated live smoke test.
#include "event.h"
#include "filter.h"
#include "process_monitor.h"
#include "resource_pressure.h"
#include "signature_worker_pool.h"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <future>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>

using namespace titan;

namespace {
    bool Require(bool condition, const char* message) {
        if (!condition)
            std::cerr << "[TEST] FAIL: " << message << "\n";
        return condition;
    }

    std::wstring EnvVar(const wchar_t* name) {
        wchar_t buf[MAX_PATH]{};
        if (!GetEnvironmentVariableW(name, buf, MAX_PATH)) return {};
        return buf;
    }
}

int main() {
    bool ok = true;
    const auto root = std::filesystem::temp_directory_path() /
        ("titan_process_logic_" + std::to_string(GetCurrentProcessId()));
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root);

    // ── BloomFilter: insert/novel + save/load round trip ────────────────────
    {
        BloomFilter bf;
        ok &= Require(bf.IsNovel("alpha"), "fresh bloom filter reports novel");
        bf.Insert("alpha");
        ok &= Require(!bf.IsNovel("alpha"), "inserted key is no longer novel");
        ok &= Require(bf.IsNovel("beta"), "distinct key still novel");

        const auto bloomPath = (root / "test.bin").wstring();
        ok &= Require(bf.SaveToFile(bloomPath), "bloom filter saves to file");

        BloomFilter reloaded;
        ok &= Require(reloaded.LoadFromFile(bloomPath), "bloom filter loads from file");
        ok &= Require(!reloaded.IsNovel("alpha"), "reloaded filter retains inserted key");
        ok &= Require(reloaded.IsNovel("beta"), "reloaded filter has no false positive here");
    }

    // ── ProcessAccumulator: unique-child-name cap + overflow counter ────────
    {
        ProcessAccumulator acc;
        for (size_t i = 0; i < ProcessAccumulator::kMaxUniqueChildNames; ++i)
            acc.AddChildName(L"child_" + std::to_wstring(i));
        ok &= Require(acc.unique_child_names.size() == ProcessAccumulator::kMaxUniqueChildNames,
            "accumulator fills up to the cap");
        ok &= Require(acc.unique_child_names_overflow == 0,
            "no overflow while under the cap");

        acc.AddChildName(L"one_more_new_child");
        ok &= Require(acc.unique_child_names.size() == ProcessAccumulator::kMaxUniqueChildNames,
            "set does not grow past the cap");
        ok &= Require(acc.unique_child_names_overflow == 1,
            "overflow counter increments for a new name past the cap");

        // Re-seeing an already-tracked name must not charge the overflow
        // counter -- it's a repeat, not new growth.
        acc.AddChildName(L"child_0");
        ok &= Require(acc.unique_child_names_overflow == 1,
            "re-seeing a known child name does not charge overflow");
    }

    // ── Event JSON escaping (adversarial process_name / canonical_path) ─────
    {
        ProcessInfo info;
        info.pid = 4242;
        info.image_path = LR"(C:\Fake\App.exe)";
        Event event = Event::CreateProcessEvent(info, EventSource::EtwKernelProcess);

        V3ProcessInfo& v3 = event.GetV3();
        v3.pid = 4242;
        v3.process_name = LR"(evil"quote\backslash)";
        v3.canonical_path = LR"(C:\Fake\App.exe)";
        v3.location_type = LocationType::UNKNOWN;

        std::string json = event.ForwardJson();
        ok &= Require(json.find(R"(evil\"quote\\backslash)") != std::string::npos,
            "adversarial process_name is JSON-escaped in ForwardJson output");
    }

    // ── FilterEngine: classification + persistence + dedup/compress ─────────
    {
        FilterEngine filter;
        const auto bloomDir = (root / "bloom").wstring() + L"\\";
        ok &= Require(filter.Initialize(bloomDir), "filter initializes");

        const std::wstring sysRoot = EnvVar(L"SystemRoot");
        ok &= Require(!sysRoot.empty(), "SystemRoot environment variable is set");
        const std::wstring notepadPath = sysRoot + L"\\System32\\notepad.exe";

        auto makeEvent = [&]() {
            ProcessInfo info;
            info.pid = 9001;
            info.parent_pid = 4;
            info.image_path = notepadPath;
            return Event::CreateProcessEvent(info, EventSource::EtwKernelProcess);
            };

        // 1st occurrence: novel process/relationship -> always FORWARD.
        Event e1 = makeEvent();
        FilterResult r1 = filter.Process(e1);
        ok &= Require(r1.decision == FilterDecision::FORWARD,
            "first occurrence of a process forwards (novelty)");
        ok &= Require(e1.GetV3().location_type == LocationType::SYSTEM,
            "notepad.exe under SystemRoot classifies as SYSTEM");

        // NOTE: The ring/dedup COMPRESS path (Stage7) is only reachable when
        // ShouldAlwaysForward's rule 2 does NOT fire, which requires
        // signature_valid == true. That depends on WinVerifyTrust actually
        // chaining to a trusted root in the environment this test runs in --
        // a sandboxed/minimal Windows image can have an incomplete trust
        // store and fail verification even for a genuine Microsoft system
        // binary. Rather than assert on that environment-dependent outcome
        // here, we test the one thing that IS deterministic regardless of
        // trust-store state: an unverified-or-invalid-signature binary in a
        // known location must ALWAYS forward, never compress (rule 2). The
        // COMPRESS path itself is exercised by the elevated live smoke test,
        // where the real agent runs against real repeated process launches.
        Event e2 = makeEvent();
        FilterResult r2 = filter.Process(e2);
        Event e3 = makeEvent();
        FilterResult r3 = filter.Process(e3);
        if (!e1.GetV3().signature_valid) {
            ok &= Require(r2.decision == FilterDecision::FORWARD &&
                r3.decision == FilterDecision::FORWARD,
                "unverified-signature system binary always forwards, never compresses");
        }
        else {
            // Trust store in this environment does validate the binary --
            // the ring/dedup path is reachable; 3rd identical occurrence
            // should compress.
            ok &= Require(r3.decision == FilterDecision::COMPRESS,
                "third occurrence of a verified, repeated process is compressed (dedup)");
        }

        // Persistence touchpoint: a synthetic process launched from the
        // per-user Startup folder must always forward, never compress.
        const std::wstring appdata = EnvVar(L"APPDATA");
        if (!appdata.empty()) {
            const std::wstring startupExe = appdata +
                L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.exe";
            auto makeStartupEvent = [&]() {
                ProcessInfo info;
                info.pid = 9002;
                info.parent_pid = 4;
                info.image_path = startupExe;
                return Event::CreateProcessEvent(info, EventSource::EtwKernelProcess);
                };
            // Forward it three times -- persistence_touched must force
            // FORWARD every time, never falling through to COMPRESS.
            for (int i = 0; i < 3; ++i) {
                Event se = makeStartupEvent();
                FilterResult sr = filter.Process(se);
                ok &= Require(sr.decision == FilterDecision::FORWARD,
                    "Startup-folder process always forwards (persistence touchpoint)");
                ok &= Require(se.GetV3().persistence_touched,
                    "Startup-folder process is flagged persistence_touched");
            }
        }
    }

    // ── RAM/disk auto-lightening ─────────────────────────────────────────────
    {
        ok &= Require(ClassifyPressure(50, 10ULL * 1024 * 1024 * 1024) == PressureTier::Normal,
            "low RAM load + ample disk classifies as normal");
        ok &= Require(ClassifyPressure(87, 10ULL * 1024 * 1024 * 1024) == PressureTier::Lightened,
            "high RAM load alone triggers lightened tier");
        ok &= Require(ClassifyPressure(95, 10ULL * 1024 * 1024 * 1024) == PressureTier::Severe,
            "very high RAM load triggers severe tier");
        ok &= Require(AdaptiveCap(20, 3, 0.5) == 10, "lightened factor halves the base cap");
        ok &= Require(AdaptiveCap(4, 3, 0.25) == 3,
            "adaptive cap never drops below the configured floor");
    }

    // ── SignatureWorkerPool: coalescing + bounded queue ──────────────────────
    {
        std::atomic<int> verify_calls{ 0 };
        std::atomic<int> in_flight_now{ 0 };
        std::atomic<int> max_concurrent{ 0 };

        // A slow, call-counting stand-in for WinVerifyTrust so the test can
        // (a) prove two Submit()s for the SAME path share one underlying
        // call (coalescing), and (b) prove a saturated queue drops-and-counts
        // instead of blocking or growing forever.
        auto slow_verify = [&](const std::wstring&) -> SignatureCacheEntry {
            int now = in_flight_now.fetch_add(1, std::memory_order_relaxed) + 1;
            int prev_max = max_concurrent.load(std::memory_order_relaxed);
            while (now > prev_max && !max_concurrent.compare_exchange_weak(prev_max, now)) {}
            verify_calls.fetch_add(1, std::memory_order_relaxed);
            std::this_thread::sleep_for(std::chrono::milliseconds(60));
            in_flight_now.fetch_sub(1, std::memory_order_relaxed);
            SignatureCacheEntry entry;
            entry.valid = true;
            entry.signer = L"test-signer";
            return entry;
            };

        {
            // 1 worker so coalescing is unambiguous: if the pool DIDN'T
            // coalesce, 5 submits for the same path would need 5 sequential
            // ~60ms calls (~300ms); coalesced, they share 1 call (~60ms).
            SignatureWorkerPool<SignatureCacheEntry> pool(slow_verify, /*worker_count=*/1, /*max_queue=*/4);

            std::vector<std::shared_future<SignatureCacheEntry>> futures;
            for (int i = 0; i < 5; ++i)
                futures.push_back(pool.Submit(L"C:\\same\\path.exe"));
            for (auto& f : futures) {
                ok &= Require(f.get().valid, "coalesced submit resolves to a valid entry");
            }
            ok &= Require(verify_calls.load() == 1,
                "5 submits for the identical path coalesce into exactly 1 verify call");
        }

        {
            verify_calls.store(0);
            max_concurrent.store(0);
            in_flight_now.store(0);
            // 1 worker, tiny queue: submit more distinct paths than the
            // queue can hold. Excess submits must resolve immediately
            // (never block the caller) and be counted as dropped, not
            // silently queued without bound.
            SignatureWorkerPool<SignatureCacheEntry> pool(slow_verify, /*worker_count=*/1, /*max_queue=*/2);

            std::vector<std::shared_future<SignatureCacheEntry>> futures;
            for (int i = 0; i < 10; ++i)
                futures.push_back(pool.Submit(L"C:\\distinct\\path" + std::to_wstring(i) + L".exe"));
            for (auto& f : futures) f.wait();

            ok &= Require(pool.GetQueueDroppedCount() > 0,
                "submits past the bounded queue are counted as dropped, not grown without bound");
            ok &= Require(max_concurrent.load() <= 1,
                "exactly 1 worker thread means at most 1 concurrent verify call ever runs");
        }
    }

    std::filesystem::remove_all(root, ec);
    if (ok) {
        std::cout << "[TEST] PASS\n";
        return 0;
    }
    return 1;
}
