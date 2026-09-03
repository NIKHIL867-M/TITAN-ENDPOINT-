// usb_logic_test.cpp -- non-admin logic tests for the USB (Port) endpoint.
//
// Exercises pure logic that does not require Administrator privileges or
// real USB hardware: JSON escaping + anomaly accounting (UsbSession), log
// rotation + archive retention (UsbLogger), and the keystroke-injection
// timing heuristic (EvaluateKeystrokeTiming). No kernel listener, no real
// device enumeration -- those are covered by the elevated live smoke test.
#include "usb_identity.h"
#include "usb_session.h"
#include "usb_logger.h"
#include "usb_hid_guard.h"
#include "resource_pressure.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <windows.h>

namespace {
    bool Require(bool condition, const char* message)
    {
        if (!condition)
            std::cerr << "[TEST] FAIL: " << message << "\n";
        return condition;
    }

    std::string ReadAll(const std::filesystem::path& path)
    {
        std::ifstream input(path);
        return std::string(std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>());
    }
}

int main()
{
    bool ok = true;
    const auto root = std::filesystem::temp_directory_path() /
        ("titan_usb_logic_" + std::to_string(GetCurrentProcessId()));
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root);

    // ── UsbSession: JSON escaping + anomaly thresholds ───────────────────────
    {
        UsbIdentity id;
        id.vid = "0781";
        id.pid = "5567";
        id.serialNumber = "AA00112233";
        id.manufacturer = "SanDisk";
        id.product = "Cruzer\"Blade\\Evil\nInjector";  // adversarial product string
        id.instanceId = "USB\\VID_0781&PID_5567\\AA00112233";

        UsbSession session(id, "E:\\");

        // Executable write anomaly.
        session.AddFileEvent("write", "E:\\payload.exe", 1024);
        // Mass deletion anomaly.
        for (int i = 0; i < 50; ++i)
            session.AddFileEvent("delete", "E:\\f" + std::to_string(i) + ".txt", 0);
        // High-volume read anomaly (>= 500 MB cumulative).
        session.AddFileEvent("read", "E:\\big.bin", 600ULL * 1024 * 1024);

        std::string json = session.Finalize();
        ok &= Require(!json.empty(), "session Finalize produces JSON");
        ok &= Require(json.find("Cruzer\\\"Blade\\\\Evil\\nInjector") != std::string::npos,
            "device-supplied product string is JSON-escaped");
        ok &= Require(json.find("executable_written") != std::string::npos,
            "executable-write anomaly detected");
        ok &= Require(json.find("mass_deletion") != std::string::npos,
            "mass-deletion anomaly detected");
        ok &= Require(json.find("high_read_volume") != std::string::npos,
            "high-read-volume anomaly detected");
        ok &= Require(session.Finalize().empty(),
            "double Finalize() returns empty (no double-emit)");
    }

    // ── UsbLogger: rotation + bounded archive retention ──────────────────────
    {
        const auto logPath = root / "usb_events.json";
        // Tiny size cap forces frequent rotation; small archive cap so the
        // test completes quickly while still proving the prune logic runs.
        ok &= Require(UsbLogger::Initialize(logPath.string(), /*maxSizeBytes=*/200,
            /*maxArchives=*/3),
            "logger initialization");

        for (int i = 0; i < 60; ++i) {
            UsbLogger::Log("{\"sequence\":" + std::to_string(i) +
                ",\"payload\":\"0123456789abcdefghijklmnopqrstuvwxyz\"}");
        }
        UsbLogger::Shutdown();

        size_t archives = 0;
        const std::string prefix = logPath.filename().string() + ".";
        for (const auto& entry : std::filesystem::directory_iterator(root)) {
            if (entry.path().filename().string().rfind(prefix, 0) == 0)
                ++archives;
        }
        ok &= Require(archives > 0, "rotation actually produced archive files");
        ok &= Require(archives <= 3, "rotated-archive retention cap enforced");
        ok &= Require(std::filesystem::exists(logPath),
            "active log file exists after rotation");
    }

    // ── Keystroke-injection timing heuristic ─────────────────────────────────
    {
        // Synthetic "BadUSB" series: fast, near-metronomic (typical of
        // DuckyScript / firmware-driven injection).
        std::vector<double> botIntervals = { 8.0, 9.0, 8.5, 9.5, 8.0, 9.0, 8.5, 8.0 };
        auto botResult = EvaluateKeystrokeTiming(botIntervals);
        ok &= Require(botResult.suspected,
            "fast + regular keystroke timing is flagged as suspected injection");
        ok &= Require(botResult.sampleCount == botIntervals.size(),
            "bot sample count matches input");

        // Synthetic human series: slower, irregular.
        std::vector<double> humanIntervals = { 120.0, 340.0, 95.0, 410.0, 180.0, 260.0, 90.0, 500.0 };
        auto humanResult = EvaluateKeystrokeTiming(humanIntervals);
        ok &= Require(!humanResult.suspected,
            "slow + irregular keystroke timing is not flagged");

        // Too few samples: must not flag regardless of speed (avoid false
        // positives on brief key taps, e.g. a single hotkey).
        std::vector<double> tooFew = { 5.0, 5.0 };
        auto fewResult = EvaluateKeystrokeTiming(tooFew);
        ok &= Require(!fewResult.suspected,
            "below minimum sample count is never flagged");

        // Empty input is handled without crashing.
        auto emptyResult = EvaluateKeystrokeTiming({});
        ok &= Require(!emptyResult.suspected && emptyResult.sampleCount == 0,
            "empty interval list yields a safe not-suspected result");
    }

    // ── RAM/disk auto-lightening: pressure classification + adaptive cap ────
    {
        ok &= Require(ClassifyPressure(50, 10ULL * 1024 * 1024 * 1024) == PressureTier::Normal,
            "low RAM load + ample disk classifies as normal");
        ok &= Require(ClassifyPressure(87, 10ULL * 1024 * 1024 * 1024) == PressureTier::Lightened,
            "high RAM load alone triggers lightened tier");
        ok &= Require(ClassifyPressure(50, 1ULL * 1024 * 1024 * 1024) == PressureTier::Lightened,
            "low free disk alone triggers lightened tier");
        ok &= Require(ClassifyPressure(95, 10ULL * 1024 * 1024 * 1024) == PressureTier::Severe,
            "very high RAM load triggers severe tier");
        ok &= Require(ClassifyPressure(50, 100ULL * 1024 * 1024) == PressureTier::Severe,
            "very low free disk triggers severe tier regardless of RAM");

        ok &= Require(AdaptiveCap(20, 3, 1.0) == 20, "normal factor keeps base cap");
        ok &= Require(AdaptiveCap(20, 3, 0.5) == 10, "lightened factor halves the cap");
        ok &= Require(AdaptiveCap(20, 3, 0.25) == 5, "severe factor quarters the cap");
        ok &= Require(AdaptiveCap(4, 3, 0.25) == 3,
            "adaptive cap never drops below the configured floor");
    }

    std::filesystem::remove_all(root, ec);
    if (ok) {
        std::cout << "[TEST] PASS\n";
        return 0;
    }
    return 1;
}
