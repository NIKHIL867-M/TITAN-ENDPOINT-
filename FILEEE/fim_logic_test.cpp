#include "file_logger.h"
#include "file_monitor.h"
#include "_file_scope.h"
#include "resource_pressure.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

using namespace titan::fim;

namespace
{
    bool Require(bool condition, const char* message)
    {
        if (!condition)
            std::cerr << "[TEST] FAIL: " << message << "\n";
        return condition;
    }

    size_t CountLines(const std::filesystem::path& path)
    {
        std::ifstream input(path);
        size_t count = 0;
        std::string line;
        while (std::getline(input, line)) ++count;
        return count;
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
        ("titan_fim_logic_" + std::to_string(GetCurrentProcessId()));
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root);

    ok &= Require(PathStartsWith(L"C:\\Windows\\System32\\a.dll",
        L"C:\\Windows\\System32"), "path child boundary");
    ok &= Require(!PathStartsWith(L"C:\\Windows\\System32evil\\a.dll",
        L"C:\\Windows\\System32"), "path sibling boundary");
    ok &= Require(ClassifyEvent(L"C:\\Temp\\ordinary.bin") != EventBucket::DROP,
        "ordinary file must not be dropped");

    {
        FileLogger logger;
        const auto rotation_log = root / L"rotation.jsonl";
        ok &= Require(logger.Initialize(rotation_log.wstring(), 96),
            "logger initialization");
        for (int i = 0; i < 30; ++i)
            logger.Log("{\"sequence\":" + std::to_string(i) +
                ",\"payload\":\"abcdefghijklmnopqrstuvwxyz\"}",
                LogSeverity::INFO);
        logger.Flush();

        size_t archives = 0;
        for (const auto& entry : std::filesystem::directory_iterator(root))
            if (entry.path().filename().wstring().rfind(L"rotation_", 0) == 0)
                ++archives;
        ok &= Require(archives <= 10, "rotated log retention cap");
        ok &= Require(std::filesystem::exists(rotation_log),
            "active log exists after rotation");
    }

    {
        const auto integrity_file = root / L"integrity.txt";
        const auto integrity_log = root / L"integrity.jsonl";
        const auto baseline_db = root / L"baseline.dat";
        {
            std::ofstream output(integrity_file);
            output << "baseline";
        }

        {
            FileLogger logger;
            ok &= Require(logger.Initialize(integrity_log.wstring()),
                "integrity logger initialization");
            FileProcessor processor;
            ok &= Require(processor.Initialize(&logger, baseline_db.wstring()),
                "integrity processor initialization");

            FileEvent event;
            event.action = FileAction::CREATE;
            event.path = integrity_file.wstring();
            event.pid = GetCurrentProcessId();
            event.timestamp = std::chrono::system_clock::now();
            processor.ProcessEvent(event);

            {
                std::ofstream output(integrity_file, std::ios::trunc);
                output << "changed-content";
            }
            event.action = FileAction::WRITE;
            event.file_key = 0xABCDEF;
            processor.ProcessEvent(event);
            event.action = FileAction::CLOSE;
            processor.ProcessEvent(event);
            processor.SaveHashBaselines();

            for (int i = 0; i < 10; ++i)
                logger.LogAggregated("duplicate-test", "{\"kind\":\"duplicate\"}",
                    LogSeverity::INFO);
            logger.Flush();
        }

        {
            std::ofstream output(integrity_file, std::ios::trunc);
            output << "changed-while-stopped";
        }
        {
            FileLogger logger;
            ok &= Require(logger.Initialize(integrity_log.wstring()),
                "restart logger initialization");
            FileProcessor processor;
            ok &= Require(processor.Initialize(&logger, baseline_db.wstring()),
                "persistent baseline reload");
            FileEvent event;
            event.action = FileAction::CREATE;
            event.path = integrity_file.wstring();
            event.pid = GetCurrentProcessId();
            event.timestamp = std::chrono::system_clock::now();
            processor.ProcessEvent(event);
            logger.Flush();
        }

        const std::string content = ReadAll(integrity_log);
        ok &= Require(content.find("\"hash_status\":\"baseline_created\"") !=
            std::string::npos, "hash baseline record");
        ok &= Require(content.find("\"hash_status\":\"changed\"") !=
            std::string::npos, "changed hash record");
        ok &= Require(content.find("\"content_changed\":true") !=
            std::string::npos, "content changed flag");
        ok &= Require(content.find("\"repeat_count\":10") !=
            std::string::npos, "duplicate aggregation count");
        ok &= Require(std::filesystem::exists(baseline_db),
            "persistent baseline database");
    }

    {
        FileLogger logger;
        const auto stress_log = root / L"stress.jsonl";
        ok &= Require(logger.Initialize(stress_log.wstring(), 8ULL * 1024 * 1024),
            "stress logger initialization");

        TempTracker tracker(&logger);
        FileEvent temp;
        temp.action = FileAction::WRITE;
        temp.pid = GetCurrentProcessId();
        temp.creator_pid = temp.pid;
        temp.timestamp = std::chrono::system_clock::now();
        for (uint32_t i = 0; i < 100000; ++i)
        {
            temp.path = L"C:\\Windows\\Temp\\stress_" + std::to_wstring(i) + L".tmp";
            temp.file_key = i + 1;
            tracker.TrackEvent(temp);
        }

        FileProcessor processor;
        ok &= Require(processor.Initialize(&logger), "processor initialization");
        FileEvent write = temp;
        write.path = L"C:\\Users\\Public\\ordinary.bin";
        for (uint32_t i = 0; i < 20000; ++i)
        {
            write.file_key = 0x100000ULL + i;
            processor.ProcessEvent(write);
        }
        logger.Flush();
        ok &= Require(std::filesystem::file_size(stress_log) < 1024 * 1024,
            "stress tracking remains aggregated");
    }

    {
        const auto temp_log = root / L"temp_lifetime.jsonl";
        FileLogger logger;
        ok &= Require(logger.Initialize(temp_log.wstring()),
            "temp lifetime logger initialization");
        FileProcessor processor;
        ok &= Require(processor.Initialize(&logger),
            "temp hash processor initialization");
        TempTracker tracker(&logger, 1, &processor);

        FileEvent short_lived;
        short_lived.action = FileAction::CREATE;
        short_lived.path = L"C:\\Windows\\Temp\\short_lived.tmp";
        short_lived.pid = GetCurrentProcessId();
        short_lived.creator_pid = short_lived.pid;
        tracker.TrackEvent(short_lived);
        short_lived.action = FileAction::DELETE_F;
        tracker.TrackEvent(short_lived);

        FileEvent long_lived = short_lived;
        long_lived.action = FileAction::CREATE;
        const auto long_temp_path = root / L"long_lived.tmp";
        {
            std::ofstream output(long_temp_path);
            output << "long-lived-temp-content";
        }
        long_lived.path = long_temp_path.wstring();
        tracker.TrackEvent(long_lived);
        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        tracker.Maintenance();
        logger.Flush();

        const std::string content = ReadAll(temp_log);
        ok &= Require(content.find("short_lived.tmp") == std::string::npos,
            "short-lived temp suppressed");
        ok &= Require(content.find("long_lived.tmp") != std::string::npos,
            "long-lived temp persisted");
        ok &= Require(content.find("\"type\":\"temp_lifecycle\"") !=
            std::string::npos, "temp lifecycle evidence type");
        ok &= Require(content.find("\"lifetime_threshold_seconds\":1") !=
            std::string::npos, "temp lifetime threshold field");
        ok &= Require(content.find("\"sha256\":\"") != std::string::npos,
            "long-lived temp hash");

        FileEvent concurrent_a;
        concurrent_a.action = FileAction::CREATE;
        concurrent_a.path = L"C:\\Windows\\Temp\\concurrent_a.tmp";
        concurrent_a.pid = short_lived.pid;
        concurrent_a.creator_pid = concurrent_a.pid;
        concurrent_a.tid = GetCurrentThreadId();
        concurrent_a.file_key = 0xA001;
        tracker.TrackEvent(concurrent_a);
        concurrent_a.action = FileAction::WRITE;
        tracker.TrackEvent(concurrent_a);

        FileEvent concurrent_b = concurrent_a;
        concurrent_b.action = FileAction::CREATE;
        concurrent_b.path = L"C:\\Windows\\Temp\\concurrent_b.tmp";
        concurrent_b.file_key = 0xB002;
        tracker.TrackEvent(concurrent_b);
        concurrent_b.action = FileAction::WRITE;
        tracker.TrackEvent(concurrent_b);

        FileEvent related;
        related.action = FileAction::WRITE;
        related.path = L"C:\\Program Files\\Example\\target.dll";
        related.pid = short_lived.pid;
        related.tid = GetCurrentThreadId();
        related.file_key = 0xC003;
        related.process_name = L"example.exe";
        tracker.ObserveRelatedEvent(related);
        FileEvent key_only_transition = related;
        key_only_transition.action = FileAction::RENAME;
        key_only_transition.old_path.clear();
        key_only_transition.path =
            L"C:\\Program Files\\Example\\concurrent_a.dll";
        key_only_transition.file_key = concurrent_a.file_key;
        tracker.ObservePathTransition(key_only_transition);
        related.action = FileAction::RENAME;
        related.old_path = L"C:\\Windows\\Temp\\stage.tmp";
        related.path = L"C:\\Program Files\\Example\\stage.dll";
        tracker.ObservePathTransition(related);
        logger.Flush();
        const std::string related_content = ReadAll(temp_log);
        ok &= Require(related_content.find("\"type\":\"temp_related_activity\"")
            != std::string::npos, "temp related activity evidence");
        ok &= Require(related_content.find(
            "\"reason\":\"temp_process_touched_executable_target\"")
            != std::string::npos, "temp to DLL relationship");
        ok &= Require(related_content.find("concurrent_a.tmp") !=
            std::string::npos && related_content.find("concurrent_b.tmp") !=
            std::string::npos, "overlapping temp files retained independently");
        ok &= Require(related_content.find(
            "\"correlation_basis\":\"same_actor_thread\"") !=
            std::string::npos, "thread-strength relationship evidence");
        ok &= Require(related_content.find("\"temp_file_key\":40961") !=
            std::string::npos && related_content.find(
                "\"temp_file_key\":45058") != std::string::npos,
            "kernel file identities retained");
        ok &= Require(related_content.find("\"temp_write_count\":1") !=
            std::string::npos, "file-centric history retained");
        ok &= Require(related_content.find("\"type\":\"temp_path_transition\"")
            != std::string::npos, "temp path transition evidence");
        ok &= Require(related_content.find(
            "\"old_path\":\"C:\\\\Windows\\\\Temp\\\\concurrent_a.tmp\"")
            != std::string::npos, "missing rename source recovered by file key");
        ok &= Require(related_content.find("\"new_extension\":\".dll\"")
            != std::string::npos, "temp extension transition");
    }

    {
        const auto monitor_log = root / L"monitor.jsonl";
        FileMonitor monitor;
        ok &= Require(monitor.Start(monitor_log.wstring()), "monitor start");

        FileEvent create;
        create.action = FileAction::CREATE;
        create.path = L"C:\\Users\\Public\\Documents\\titan_test.txt";
        create.pid = GetCurrentProcessId();
        create.tid = GetCurrentThreadId();
        create.creator_pid = create.pid;
        create.timestamp = std::chrono::system_clock::now();
        monitor.SubmitEvent(create);

        FileEvent write = create;
        write.action = FileAction::WRITE;
        write.file_key = 0x12345678;
        monitor.SubmitEvent(write);

        FileEvent close = write;
        close.action = FileAction::CLOSE;
        monitor.SubmitEvent(close);

        for (uint32_t i = 0; i < 2000; ++i)
        {
            FileEvent temp = create;
            temp.action = FileAction::CREATE;
            temp.path = L"C:\\Windows\\Temp\\titan_" + std::to_wstring(i) + L".tmp";
            temp.file_key = i + 1;
            monitor.SubmitEvent(temp);
        }

        monitor.ReportEtwLoss(7, 2);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        monitor.Stop();
        ok &= Require(std::filesystem::exists(monitor_log), "monitor log exists");
        ok &= Require(CountLines(monitor_log) >= 3, "monitor persisted events");
        const std::string monitor_content = ReadAll(monitor_log);
        ok &= Require(monitor_content.find("\"type\":\"collector_health\"") !=
            std::string::npos, "collector health persisted");
        ok &= Require(monitor_content.find("\"etw_events_lost\":7") !=
            std::string::npos &&
            monitor_content.find("\"realtime_buffers_lost\":2") !=
            std::string::npos, "ETW loss counters persisted");
        ok &= Require(monitor_content.find("\"evidence_gap\":true") !=
            std::string::npos, "loss produces explicit evidence gap");
    }

    // ── RAM/disk auto-lightening ─────────────────────────────────────────────
    {
        ok &= Require(ClassifyPressure(50, 10ULL * 1024 * 1024 * 1024) == PressureTier::Normal,
            "low RAM load + ample disk classifies as normal");
        ok &= Require(ClassifyPressure(87, 10ULL * 1024 * 1024 * 1024) == PressureTier::Lightened,
            "high RAM load alone triggers lightened tier");
        ok &= Require(ClassifyPressure(95, 10ULL * 1024 * 1024 * 1024) == PressureTier::Severe,
            "very high RAM load triggers severe tier");
        ok &= Require(AdaptiveCap(2, 1, 0.5) == 1,
            "adaptive cap on a tight base (2 archives) still respects the floor (1)");
    }

    std::filesystem::remove_all(root, ec);
    if (ok)
    {
        std::cout << "[TEST] PASS\n";
        return 0;
    }
    return 1;
}
