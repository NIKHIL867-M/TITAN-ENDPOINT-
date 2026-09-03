#include "unified_stream_engine.h"
#include "log_tailer.h"

#include <windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

using correlator::LogTailer;
using correlator::UnifiedStreamEngine;

namespace {
int failures = 0;

void Check(bool condition, const char* name)
{
    if (condition) std::cout << "[PASS] " << name << '\n';
    else { std::cerr << "[FAIL] " << name << '\n'; ++failures; }
}

std::string Event(const std::string& kind, int64_t ms, int pid,
    const std::string& extra = {})
{
    return "{\"t_unix_ms\":" + std::to_string(ms) +
        ",\"type\":\"" + kind + "\",\"event_subtype\":\"" + kind +
        "\",\"record_type\":\"" + kind + "\",\"pid\":" + std::to_string(pid) +
        (extra.empty() ? "" : "," + extra) + "}";
}

void TestSingleSourcePreserved()
{
    UnifiedStreamEngine e;
    Check(e.Ingest("process", Event("process_start", 1000, 100), 10000), "single source accepted");
    const auto out = e.DrainReady(14000);
    Check(out.size() == 1, "single source emitted");
    Check(out[0].find("\"connected\":false") != std::string::npos, "single source labeled honestly");
    Check(out[0].find("\"endpoint\":\"process\"") != std::string::npos, "single source raw member retained");
}

void TestCrossEndpointConnection()
{
    UnifiedStreamEngine e;
    e.Ingest("process", Event("process_start", 2000, 222), 20000);
    e.Ingest("network", Event("network_packet", 2100, 222,
        "\"remote_ip\":\"1.1.1.1\",\"remote_port\":443"), 20001);
    const auto out = e.DrainReady(24000);
    Check(out.size() == 1, "matched records become one output");
    Check(out[0].find("\"connected\":true") != std::string::npos, "match marked connected");
    Check(out[0].find("\"source_count\":2") != std::string::npos, "two real sources reported");
    Check(out[0].find("\"reason\":\"same_pid\"") != std::string::npos, "match reason retained");
}

void TestDedupAndRepeatCompaction()
{
    UnifiedStreamEngine e;
    const auto a = Event("write", 3000, 333, "\"path\":\"C:\\\\Temp\\\\a.tmp\",\"action\":\"write\"");
    const auto b = Event("write", 3200, 333, "\"path\":\"C:\\\\Temp\\\\a.tmp\",\"action\":\"write\"");
    Check(e.Ingest("file_integrity", a, 30000), "first repeat candidate accepted");
    Check(!e.Ingest("file_integrity", a, 30001), "exact duplicate suppressed");
    Check(e.Ingest("file_integrity", b, 30002), "semantic repeat represented");
    const auto out = e.DrainReady(34000);
    Check(out.size() == 1, "repeat compaction emits one logical event");
    Check(out[0].find("\"event_count\":2") != std::string::npos, "repeat event count accurate");
    Check(out[0].find("\"repeat_count\":1") != std::string::npos, "repeat count exposed");
    Check(e.ExactDuplicatesSuppressed() == 1, "duplicate counter accurate");
    Check(e.SemanticRepeatsCompacted() == 1, "compaction counter accurate");
}

void TestSystemPidDoesNotFabricateConnection()
{
    UnifiedStreamEngine e;
    e.Ingest("process", Event("process_snapshot", 4000, 4), 40000);
    e.Ingest("file_integrity", Event("write", 4050, 4,
        "\"path\":\"C:\\\\Windows\\\\x.log\",\"action\":\"write\""), 40001);
    const auto out = e.DrainReady(44000);
    Check(out.size() == 2, "PID 4 alone does not connect unrelated evidence");
}

void TestAllFiveSourcesCanConnect()
{
    UnifiedStreamEngine e;
    e.Ingest("port", Event("USB_SESSION_END", 10000, 0,
        "\"event_type\":\"USB_SESSION_END\",\"mount_point\":\"E:\\\\\",\"duration_seconds\":5"), 50000);
    e.Ingest("file_integrity", Event("write", 9900, 777,
        "\"path\":\"E:\\\\report.docx\",\"action\":\"write\""), 50001);
    e.Ingest("process", Event("process_start", 9950, 777), 50002);
    e.Ingest("network", Event("network_packet", 10050, 777,
        "\"remote_ip\":\"8.8.8.8\",\"remote_port\":53"), 50003);
    e.Ingest("application", Event("file", 10100, 777,
        "\"path\":\"E:\\\\report.docx\""), 50004);
    const auto out = e.DrainReady(54000);
    Check(out.size() == 1, "all five matched sources become one story");
    Check(out[0].find("\"source_count\":5") != std::string::npos, "five-source coverage is data-driven");
}

void TestBoundedPendingMemory()
{
    UnifiedStreamEngine e;
    for (int i = 0; i < 700; ++i)
        e.Ingest("process", Event("unique_" + std::to_string(i), 100000 + i, 1000 + i), 60000 + i);
    Check(e.PendingGroupCount() <= UnifiedStreamEngine::kMaxPendingGroups, "pending groups hard bounded");
    Check(e.CapacityFlushes() > 0, "capacity pressure is lossless and visible");
    const auto output = e.DrainReady(1000000, true);
    Check(output.size() + e.UnifiedEventsEmitted() >= 700, "capacity flush preserves every unique record");
}

void TestDurableTailCheckpoint()
{
    const auto root = std::filesystem::temp_directory_path() /
        ("titan_correlator_test_" + std::to_string(GetCurrentProcessId()));
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    const auto log = root / "titan_test.jsonl";
    const auto state = root / "tail.state";
    { std::ofstream out(log); out << "{\"old\":true}\n"; }
    {
        LogTailer tail(root.wstring(), "titan_", state.wstring(), true);
        Check(tail.ReadNewLines().empty(), "first live bootstrap does not replay retained history");
        { std::ofstream out(log, std::ios::app); out << "{\"new\":1}\n"; }
        const auto lines = tail.ReadNewLines();
        Check(lines.size() == 1 && lines[0].find("\"new\":1") != std::string::npos,
            "new append read exactly once");
        Check(tail.Commit(), "tail checkpoint committed");
    }
    {
        LogTailer restarted(root.wstring(), "titan_", state.wstring(), true);
        Check(restarted.ReadNewLines().empty(), "clean restart does not replay committed logs");
    }
    std::filesystem::remove_all(root, ec);
}
}

int main()
{
    TestSingleSourcePreserved();
    TestCrossEndpointConnection();
    TestDedupAndRepeatCompaction();
    TestSystemPidDoesNotFabricateConnection();
    TestAllFiveSourcesCanConnect();
    TestBoundedPendingMemory();
    TestDurableTailCheckpoint();
    if (failures == 0) std::cout << "All unified correlator tests passed.\n";
    return failures == 0 ? 0 : 1;
}
