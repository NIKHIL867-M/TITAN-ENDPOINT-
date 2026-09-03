#include "titan_pch.h"
#include "applog_decoder.h"
#include "applog_logger.h"
#include "applog_watchlist.h"
#include "application_discovery.h"
#include "resource_pressure.h"
#include "evidence_envelope.h"

#include <filesystem>
#include <fstream>

namespace {
bool Require(bool condition, const char* message)
{
    if (!condition) std::cerr << "[TEST] FAIL: " << message << "\n";
    return condition;
}
}

int main()
{
    bool ok = true;
    AppLogDecoder decoder;
    const std::string decoded = decoder.Decode("PowerShell",
        "<Event><EventID>4104</EventID><EventData>"
        "<Data Name=\"ScriptBlockText\">Invoke-WebRequest "
        "https://example.invalid/a</Data>"
        "<Data Name=\"Path\">C:\\test.ps1</Data>"
        "</EventData></Event>", "2026-07-28T00:00:00.000Z");
    ok &= Require(decoded.find('\n') == std::string::npos,
        "decoder emits one-line JSONL");
    ok &= Require(decoded.find("\"pattern_hits\":0") == std::string::npos,
        "PowerShell pattern detected");
    ok &= Require(decoded.find("https://example.invalid/a") !=
        std::string::npos, "URL extracted");
    const std::string channelDecoded = decoder.Decode("PowerShell",
        "<Event><EventID>4104</EventID><EventData>"
        "<Data Name='ScriptBlockText'>Set-Content sample.txt</Data>"
        "</EventData></Event>", "2026-07-28T00:00:00.000Z");
    ok &= Require(channelDecoded.find("Set-Content sample.txt") !=
        std::string::npos, "single-quoted channel XML decoded");

    // FIX coverage: application_log records previously always dropped
    // pid/tid even though the caller had them (see AppLogMonitor::
    // ProcessEvent / AppLogEventSubscriber::ExtractPidTidFromXml).
    const std::string withIdentity = decoder.Decode("Security",
        "<Event><EventID>4688</EventID></Event>",
        "2026-07-28T00:00:00.000Z", /*pid=*/4321, /*tid=*/8765);
    ok &= Require(withIdentity.find("\"pid\":4321") != std::string::npos,
        "application_log record carries pid when supplied");
    ok &= Require(withIdentity.find("\"tid\":8765") != std::string::npos,
        "application_log record carries tid when supplied");

    const std::string withoutIdentity = decoder.Decode("Security",
        "<Event><EventID>4688</EventID></Event>",
        "2026-07-28T00:00:00.000Z");
    ok &= Require(withoutIdentity.find("\"pid\"") == std::string::npos &&
        withoutIdentity.find("\"tid\"") == std::string::npos,
        "pid/tid omitted (not zero-emitted) when not supplied");

    AppLogWatchlist watchlist;
    watchlist.Add("C:\\Program Files\\Example\\EXAMPLE.EXE");
    ok &= Require(watchlist.Contains("example.exe"),
        "watchlist normalizes full executable path");
    watchlist.Add("not-an-executable");
    ok &= Require(watchlist.GetAll().size() == 1,
        "invalid watchlist entry rejected");
    ok &= Require(watchlist.ObserveProcessStart(4242, "EXAMPLE.EXE", 4000),
        "watched process start accepted");
    ok &= Require(watchlist.IsWatchedPID(4242),
        "PID associated with watched application");
    ok &= Require(watchlist.NameForPID(4242) == "example.exe",
        "PID resolves to application name");
    ok &= Require(watchlist.ObserveRelatedProcessStart(
        4343, 4242, "child-helper.exe"),
        "child process is correlated to selected parent");
    ok &= Require(watchlist.NameForPID(4343) == "example.exe",
        "child PID resolves to selected root application");
    ok &= Require(watchlist.ProcessNameForPID(4343) == "child-helper.exe",
        "child PID retains its actual executable name");
    ok &= Require(watchlist.ParentPIDForPID(4343) == 4242 &&
        watchlist.RootPIDForPID(4343) == 4242,
        "child PID retains parent/root application family identity");
    ok &= Require(watchlist.ObserveProcessStop(4343),
        "related child process stop accepted");
    ok &= Require(watchlist.ObserveProcessStop(4242),
        "watched process stop accepted");
    ok &= Require(!watchlist.IsWatchedPID(4242),
        "stopped PID removed");

    const std::string wrapped = WrapWithEvidenceEnvelope(
        "{\"endpoint\":\"application\",\"action\":\"open\"}", 7,
        "session-test", "events.jsonl", 42);
    ok &= Require(wrapped.rfind("{\"endpoint\":\"application\"", 0) == 0,
        "behavior fields precede evidence bookkeeping for human-readable logs");
    ok &= Require(wrapped.find("\"record_id\":7") != std::string::npos &&
        wrapped.find("\"content_hash\":") != std::string::npos,
        "human-readable ordering preserves durable evidence identity");

    const auto discovered = ApplicationDiscovery::Discover();
    ok &= Require(!discovered.empty(),
        "application discovery returns desktop executables");
    if (!discovered.empty()) {
        ok &= Require(discovered.front().executable.size() >= 5 &&
            discovered.front().executable.ends_with(".exe"),
            "discovered application has executable filename");
    }
    ok &= Require(std::none_of(discovered.begin(), discovered.end(),
        [](const auto& application) {
            return application.executable == "application_logic_test.exe";
        }), "discovery excludes the endpoint/test process itself");

    const auto root = std::filesystem::temp_directory_path() /
        (L"titan_application_test_" +
            std::to_wstring(GetCurrentProcessId()));
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);
    const auto log = root / L"events.jsonl";
    {
        std::ofstream damaged(log, std::ios::binary);
        damaged << "{\"valid\":true}\n"
            << "{\"broken\":{\"record\":\n";
    }
    ok &= Require(AppLogLogger::Instance().Init(log, 1024),
        "logger initialized");
    ok &= Require(
        AppLogLogger::Instance().RecoveredMalformedRecords() == 1,
        "logger repairs malformed record from interrupted run");
    for (int index = 0; index < 300; ++index)
        AppLogLogger::Instance().Write(
            "{\"endpoint\":\"application\",\"sequence\":" +
            std::to_string(index) + "}");
    AppLogLogger::Instance().Write(
        "{\"application\":\"brave.exe\",\"type\":\"module\"}");
    AppLogLogger::Instance().Write(
        "{\"application\":\"code.exe\",\"type\":\"module\"}");
    const auto braveRecent = AppLogLogger::Instance().ReadRecent(
        "\"application\":\"brave.exe\"", 20);
    ok &= Require(braveRecent.size() == 1 &&
        braveRecent.front().find("\"application\":\"brave.exe\"") !=
        std::string::npos,
        "recent activity filter uses attributed application field");
    AppLogLogger::Instance().Shutdown();
    size_t archives = 0;
    for (const auto& entry : std::filesystem::directory_iterator(root))
        if (entry.path().filename().wstring().rfind(L"events_", 0) == 0)
            ++archives;
    ok &= Require(archives <= 2, "archive retention bounded");
    ok &= Require(std::filesystem::exists(log), "active log retained");
    std::filesystem::remove_all(root, ec);

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

    if (ok) {
        std::cout << "[TEST] PASS\n";
        return 0;
    }
    return 1;
}
