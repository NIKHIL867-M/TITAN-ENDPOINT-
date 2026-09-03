#include "titan_pch.h"
#include "applog_monitor.h"
#include "applog_etw_collector.h"
#include "applog_event_subscriber.h"
#include "applog_watchlist.h"
#include "applog_decoder.h"
#include "applog_logger.h"
#include "application_discovery.h"
#include "evidence_envelope.h"

#include <filesystem>
#include <fstream>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>

namespace {
std::filesystem::path WatchlistConfigPath()
{
    wchar_t executable[32768]{};
    const DWORD length = GetModuleFileNameW(nullptr, executable,
        static_cast<DWORD>(std::size(executable)));
    if (length == 0 || length >= std::size(executable)) return {};
    return std::filesystem::path(executable).parent_path() /
        L"config" / L"watchlist.txt";
}

std::filesystem::path ApplicationCatalogPath()
{
    wchar_t executable[32768]{};
    const DWORD length = GetModuleFileNameW(nullptr, executable,
        static_cast<DWORD>(std::size(executable)));
    if (length == 0 || length >= std::size(executable)) return {};
    return std::filesystem::path(executable).parent_path() /
        L"config" / L"application_catalog.json";
}

// Mirrors applog_watchlist.cpp's NormalizeExecutableName (duplicated per this
// project's own "no shared library between programs" convention) -- used only
// to compare the file's contents against the already-normalized names
// WatchlistNames() returns, so an unchanged file (different casing/whitespace)
// doesn't get diffed as a spurious remove+add every poll.
std::string NormalizeForDiff(std::string value)
{
    while (!value.empty() &&
        std::isspace(static_cast<unsigned char>(value.front())))
        value.erase(value.begin());
    while (!value.empty() &&
        std::isspace(static_cast<unsigned char>(value.back())))
        value.pop_back();
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
        value = value.substr(1, value.size() - 2);
    value = std::filesystem::path(value).filename().string();
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    if (value.size() < 5 || value.substr(value.size() - 4) != ".exe")
        return {};
    return value;
}

uint64_t Fnv1a(const std::string& value)
{
    uint64_t hash = 1469598103934665603ULL;
    for (unsigned char byte : value) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return hash;
}

std::string CurrentTimestamp()
{
    SYSTEMTIME system{};
    GetSystemTime(&system);
    char value[40]{};
    sprintf_s(value, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        system.wYear, system.wMonth, system.wDay,
        system.wHour, system.wMinute, system.wSecond,
        system.wMilliseconds);
    return value;
}

std::string WideToUtf8(const std::wstring& value)
{
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(CP_UTF8, 0, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string result(static_cast<size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(),
        static_cast<int>(value.size()), result.data(), required,
        nullptr, nullptr);
    return result;
}

std::string Ipv4Address(DWORD address)
{
    IN_ADDR value{};
    value.S_un.S_addr = address;
    char text[INET_ADDRSTRLEN]{};
    return InetNtopA(AF_INET, &value, text,
        static_cast<DWORD>(std::size(text))) ? text : std::string{};
}

std::string Ipv6Address(const UCHAR address[16], DWORD scope)
{
    IN6_ADDR value{};
    memcpy(value.u.Byte, address, 16);
    char text[INET6_ADDRSTRLEN]{};
    std::string result = InetNtopA(AF_INET6, &value, text,
        static_cast<DWORD>(std::size(text))) ? text : std::string{};
    if (scope != 0 && !result.empty()) result += "%" + std::to_string(scope);
    return result;
}

const char* TcpStateName(DWORD state)
{
    switch (state) {
    case MIB_TCP_STATE_CLOSED: return "closed";
    case MIB_TCP_STATE_LISTEN: return "listen";
    case MIB_TCP_STATE_SYN_SENT: return "syn_sent";
    case MIB_TCP_STATE_SYN_RCVD: return "syn_received";
    case MIB_TCP_STATE_ESTAB: return "established";
    case MIB_TCP_STATE_FIN_WAIT1: return "fin_wait_1";
    case MIB_TCP_STATE_FIN_WAIT2: return "fin_wait_2";
    case MIB_TCP_STATE_CLOSE_WAIT: return "close_wait";
    case MIB_TCP_STATE_CLOSING: return "closing";
    case MIB_TCP_STATE_LAST_ACK: return "last_ack";
    case MIB_TCP_STATE_DELETE_TCB: return "delete_tcb";
    default: return "unknown";
    }
}
}

AppLogMonitor::AppLogMonitor()
{
    m_decoder = std::make_unique<AppLogDecoder>();
    m_watchlist = std::make_unique<AppLogWatchlist>();
    m_etwCollector = std::make_unique<AppLogEtwCollector>(
        this, m_watchlist.get());
    m_eventSubscriber = std::make_unique<AppLogEventSubscriber>(this);
}

AppLogMonitor::~AppLogMonitor() { Stop(); }

bool AppLogMonitor::Start()
{
    if (m_running.load()) return true;
    m_eventCount.store(0);
    m_deduplicatedCount.store(0);
    m_queueDroppedCount.store(0);
    m_etwEventsLost.store(0);
    m_etwBuffersLost.store(0);
    m_subscriptionErrors.store(0);
    m_processingErrors.store(0);
    m_behaviorScanErrors.store(0);
    m_queuedBytes = 0;
    m_recentKeys.clear();
    m_networkKeys.clear();
    m_moduleKeys.clear();

    wchar_t executable[MAX_PATH * 4]{};
    const DWORD length = GetModuleFileNameW(nullptr, executable,
        static_cast<DWORD>(std::size(executable)));
    if (length == 0 || length >= std::size(executable)) {
        std::cerr << "[ApplicationEndpoint] Cannot resolve executable path.\n";
        return false;
    }
    const auto logPath = std::filesystem::path(executable).parent_path() /
        L"logs" / L"application_events.jsonl";
    if (!AppLogLogger::Instance().Init(logPath)) return false;
    m_pressureMonitor.SetPath(AppLogLogger::Instance().Path().parent_path().wstring());

    m_watchlist->RefreshPIDs();
    m_etwCollector->UpdatePIDFilter(m_watchlist->GetActivePIDs());
    m_running.store(true);
    m_workerThread = std::thread(&AppLogMonitor::WorkerThreadFunc, this);

    const bool etwStarted = m_etwCollector->Start();
    const bool welStarted = m_eventSubscriber->Start();
    if (!etwStarted && !welStarted) {
        std::cerr << "[ApplicationEndpoint] No collection source started.\n";
        m_running.store(false);
        m_queueCv.notify_all();
        if (m_workerThread.joinable()) m_workerThread.join();
        AppLogLogger::Instance().Shutdown();
        return false;
    }
    m_monitorThread = std::thread(&AppLogMonitor::MonitorThreadFunc, this);

    AppLogLogger::Instance().Write(
        "{\"endpoint\":\"application\",\"type\":\"startup\","
        "\"status\":\"running\",\"etw_active\":" +
        std::string(etwStarted ? "true" : "false") +
        ",\"eventlog_active\":" +
        std::string(welStarted ? "true" : "false") + "}");
    std::cout << "[ApplicationEndpoint] Started. Log: "
        << logPath.string() << "\n";
    EmitApplicationSnapshot();
    return true;
}

void AppLogMonitor::Stop()
{
    if (!m_running.exchange(false)) return;
    m_etwCollector->Stop();
    m_eventSubscriber->Stop();
    m_queueCv.notify_all();
    if (m_workerThread.joinable()) m_workerThread.join();
    if (m_monitorThread.joinable()) m_monitorThread.join();
    WriteHealthRecord(true);
    AppLogLogger::Instance().Shutdown();
    std::cout << "[ApplicationEndpoint] Stopped. logged="
        << m_eventCount.load() << " deduplicated="
        << m_deduplicatedCount.load() << " queue_dropped="
        << m_queueDroppedCount.load() << "\n";
}

void AppLogMonitor::OnEventReceived(AppLogEvent event)
{
    if (!m_running.load()) return;
    // FORU.TXT section 4.3/4.4: Monitoring OFF stops new collection entirely.
    if (!m_monitoringEnabled.load(std::memory_order_relaxed)) return;
    const size_t eventBytes = event.raw_data.size() + event.path.size() +
        event.old_path.size() + event.application.size() +
        event.process_name.size() + event.command_line.size() +
        event.protocol.size() + event.connection_state.size() +
        event.local_endpoint.size() +
        event.remote_endpoint.size() + 192;
    const auto now = std::chrono::steady_clock::now();
    const uint64_t contentHash = Fnv1a(event.source + "|" + event.event_id +
        "|" + event.raw_data + "|" + event.application + "|" +
        event.process_name + "|" + event.action + "|" + event.path + "|" +
        event.protocol + "|" +
        event.local_endpoint + "|" + event.remote_endpoint + "|" +
        event.connection_state + "|" + event.direction + "|" +
        std::to_string(event.application_root_pid) + "|" +
        std::to_string(event.pid) + "|" +
        std::to_string(event.tid));
    const std::string dedupKey = std::to_string(contentHash);

    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        if (!event.bypass_dedup) {
            const auto duplicate = m_recentKeys.find(dedupKey);
            if (duplicate != m_recentKeys.end() &&
                now - duplicate->second.last_seen < std::chrono::seconds(2)) {
                duplicate->second.last_seen = now;
                duplicate->second.representative.last_seen = event.timestamp;
                ++duplicate->second.repeat_count;
                m_deduplicatedCount.fetch_add(1);
                return;
            }
            if (m_recentKeys.size() >= MAX_DEDUP_KEYS)
                m_recentKeys.erase(m_recentKeys.begin());
            AppLogDedupEntry entry;
            entry.first_seen = now;
            entry.last_seen = now;
            entry.representative = event;
            entry.representative.first_seen = event.timestamp;
            entry.representative.last_seen = event.timestamp;
            m_recentKeys[dedupKey] = std::move(entry);
        }

        if (eventBytes > MAX_QUEUE_BYTES) {
            m_queueDroppedCount.fetch_add(1);
            return;
        }
        while (!m_eventQueue.empty() &&
            (m_eventQueue.size() >= MAX_QUEUE_DEPTH ||
                m_queuedBytes + eventBytes > MAX_QUEUE_BYTES)) {
            const auto& oldest = m_eventQueue.front();
            const size_t oldBytes = oldest.raw_data.size() +
                oldest.path.size() + oldest.old_path.size() +
                oldest.application.size() + oldest.command_line.size() +
                oldest.process_name.size() +
                oldest.protocol.size() + oldest.connection_state.size() +
                oldest.local_endpoint.size() +
                oldest.remote_endpoint.size() + 192;
            m_queuedBytes = oldBytes <= m_queuedBytes
                ? m_queuedBytes - oldBytes : 0;
            m_eventQueue.pop();
            m_queueDroppedCount.fetch_add(1);
        }
        m_eventQueue.push(std::move(event));
        m_queuedBytes += eventBytes;
    }
    m_queueCv.notify_one();
}

void AppLogMonitor::WorkerThreadFunc()
{
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    while (true) {
        std::vector<AppLogEvent> batch;
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            m_queueCv.wait(lock, [this] {
                return !m_eventQueue.empty() || !m_running.load();
            });
            if (!m_running.load() && m_eventQueue.empty()) break;
            batch.reserve(m_eventQueue.size());
            while (!m_eventQueue.empty()) {
                auto& queued = m_eventQueue.front();
                const size_t bytes = queued.raw_data.size() +
                    queued.path.size() + queued.old_path.size() +
                    queued.application.size() +
                    queued.process_name.size() +
                    queued.protocol.size() + queued.connection_state.size() +
                    queued.command_line.size() +
                    queued.local_endpoint.size() +
                    queued.remote_endpoint.size() + 192;
                m_queuedBytes = bytes <= m_queuedBytes
                    ? m_queuedBytes - bytes : 0;
                batch.push_back(std::move(queued));
                m_eventQueue.pop();
            }
        }
        for (auto& event : batch) {
            try { ProcessEvent(event); }
            catch (const std::exception& ex) {
                m_processingErrors.fetch_add(1);
                std::cerr << "[ApplicationEndpoint] Decode failure: "
                    << ex.what() << "\n";
            }
            catch (...) {
                m_processingErrors.fetch_add(1);
                std::cerr << "[ApplicationEndpoint] Unknown processing failure.\n";
            }
        }
    }
    AppLogLogger::Instance().Flush();
}

void AppLogMonitor::MonitorThreadFunc()
{
    auto lastHealth = std::chrono::steady_clock::now();
    auto lastModules = std::chrono::steady_clock::time_point{};
    // Start at time_point{} (not now) so the very first catalog write happens promptly on
    // startup rather than waiting a full 20s for the GUI's first paint of this page.
    auto lastCatalog = std::chrono::steady_clock::time_point{};
    while (m_running.load()) {
        SyncWatchlistFromFile();
        m_watchlist->RefreshPIDs();
        m_etwCollector->UpdatePIDFilter(m_watchlist->GetActivePIDs());
        CollectNetworkBehavior();
        const auto now = std::chrono::steady_clock::now();
        if (now - lastModules >= std::chrono::seconds(10)) {
            CollectModuleBehavior();
            lastModules = now;
        }
        if (now - lastCatalog >= std::chrono::seconds(20)) {
            WriteApplicationCatalog();
            lastCatalog = now;
        }
        CleanupDedupCache();
        CleanupBehaviorCaches();
        // Bound live-log latency without forcing a disk flush per event.
        AppLogLogger::Instance().Flush();
        if (now - lastHealth >= std::chrono::seconds(30)) {
            // RAM/disk auto-lightening.
            m_pressureMonitor.Update();
            AppLogLogger::Instance().SetMaxArchives(
                AdaptiveCap(kBaseMaxArchives, kFloorMaxArchives, m_pressureMonitor.GetFactor()));
            WriteHealthRecord(false);
            lastHealth = now;
        }
        for (int i = 0; i < 10 && m_running.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

void AppLogMonitor::ProcessEvent(AppLogEvent& event)
{
    if (event.kind == "process" || event.kind == "file" ||
        event.kind == "application_state" || event.kind == "selection" ||
        event.kind == "network" || event.kind == "network_summary" ||
        event.kind == "module" || event.kind == "repeat_summary") {
        std::ostringstream json;
        const auto t_unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        json << "{\"endpoint\":\"application\"," 
            << "\"schema_version\":2,"
            << "\"type\":\"" << JsonEscape(event.kind) << "\","
            << "\"timestamp\":\"" << JsonEscape(event.timestamp) << "\","
            << "\"t_unix_ms\":" << t_unix_ms << ","
            << "\"source\":\"" << JsonEscape(event.source) << "\","
            << "\"event_id\":\"" << JsonEscape(event.event_id) << "\","
            << "\"application\":\"" << JsonEscape(event.application) << "\","
            << "\"action\":\"" << JsonEscape(event.action) << "\","
            << "\"pid\":" << event.pid << ","
            << "\"tid\":" << event.tid;
        if (!event.path.empty())
            json << ",\"path\":\"" << JsonEscape(event.path) << "\"";
        if (!event.process_name.empty())
            json << ",\"process_name\":\""
                << JsonEscape(event.process_name) << "\"";
        if (!event.command_line.empty())
            json << ",\"command_line\":\""
                << JsonEscape(event.command_line) << "\"";
        if (!event.process_role.empty())
            json << ",\"process_role\":\""
                << JsonEscape(event.process_role) << "\"";
        if (event.parent_pid != 0)
            json << ",\"parent_pid\":" << event.parent_pid;
        if (event.application_root_pid != 0)
            json << ",\"application_root_pid\":"
                << event.application_root_pid;
        if (!event.protocol.empty())
            json << ",\"protocol\":\"" << JsonEscape(event.protocol) << "\"";
        if (!event.local_endpoint.empty())
            json << ",\"local_endpoint\":\""
                << JsonEscape(event.local_endpoint) << "\"";
        if (!event.remote_endpoint.empty())
            json << ",\"remote_endpoint\":\""
                << JsonEscape(event.remote_endpoint) << "\"";
        if (!event.connection_state.empty())
            json << ",\"connection_state\":\""
                << JsonEscape(event.connection_state) << "\"";
        if (!event.direction.empty())
            json << ",\"direction\":\"" << JsonEscape(event.direction) << "\"";
        if (!event.direction_basis.empty())
            json << ",\"direction_basis\":\""
                << JsonEscape(event.direction_basis) << "\"";
        if (!event.direction_confidence.empty())
            json << ",\"direction_confidence\":\""
                << JsonEscape(event.direction_confidence) << "\"";
        if (!event.local_ip.empty())
            json << ",\"local_ip\":\"" << JsonEscape(event.local_ip) << "\"";
        if (event.local_port != 0)
            json << ",\"local_port\":" << event.local_port;
        if (!event.remote_ip.empty())
            json << ",\"remote_ip\":\"" << JsonEscape(event.remote_ip) << "\"";
        if (event.remote_port != 0)
            json << ",\"remote_port\":" << event.remote_port;
        if (!event.protocol.empty())
            json << ",\"ipv6\":" << (event.ipv6 ? "true" : "false");
        if (!event.first_seen.empty())
            json << ",\"first_seen\":\"" << JsonEscape(event.first_seen) << "\"";
        if (!event.last_seen.empty())
            json << ",\"last_seen\":\"" << JsonEscape(event.last_seen) << "\"";
        if (event.repeat_count > 1)
            json << ",\"repeat_count\":" << event.repeat_count;
        if (event.additional_observations > 0)
            json << ",\"additional_observations\":"
                << event.additional_observations;
        if (!event.repeat_of_kind.empty())
            json << ",\"repeat_of_type\":\""
                << JsonEscape(event.repeat_of_kind) << "\"";
        if (!event.repeat_of_action.empty())
            json << ",\"repeat_of_action\":\""
                << JsonEscape(event.repeat_of_action) << "\"";
        if (!event.old_path.empty())
            json << ",\"old_path\":\"" << JsonEscape(event.old_path) << "\"";
        if (event.file_key != 0)
            json << ",\"file_key\":" << event.file_key;
        json << "}";
        event.decoded_json = json.str();
    }
    else {
        // FIX: pid/tid were already captured on `event` (upstream ETW/WEL
        // collection) but never forwarded into application_log records.
        event.decoded_json = m_decoder->Decode(
            event.source, event.raw_data, event.timestamp,
            event.pid, event.tid);
    }
    if (LogEvent(event))
        m_eventCount.fetch_add(1);
}

bool AppLogMonitor::LogEvent(const AppLogEvent& event) const
{
    return AppLogLogger::Instance().Write(event.decoded_json);
}

void AppLogMonitor::CleanupDedupCache()
{
    std::vector<AppLogEvent> summaries;
    const auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        for (auto it = m_recentKeys.begin(); it != m_recentKeys.end();) {
            auto& entry = it->second;
            if (entry.repeat_count > 0 &&
                now - entry.last_seen > std::chrono::seconds(2)) {
                AppLogEvent summary = entry.representative;
                summary.kind = "repeat_summary";
                summary.action = "compacted_repetitions";
                summary.repeat_of_kind = entry.representative.kind;
                summary.repeat_of_action = entry.representative.action;
                summary.repeat_count = entry.repeat_count + 1;
                summary.additional_observations = entry.repeat_count;
                summary.bypass_dedup = true;
                summaries.push_back(std::move(summary));
                entry.repeat_count = 0;
            }
            if (entry.repeat_count == 0 &&
                now - entry.last_seen > std::chrono::seconds(10))
                it = m_recentKeys.erase(it);
            else
                ++it;
        }
    }
    for (auto& summary : summaries)
        OnEventReceived(std::move(summary));
}

void AppLogMonitor::CollectNetworkBehavior()
{
    std::lock_guard<std::mutex> behaviorLock(m_behaviorMutex);
    const auto entries = m_watchlist->GetAll();
    std::unordered_map<DWORD, std::string> applications;
    for (const auto& entry : entries)
        for (DWORD pid : entry.pids) applications.emplace(pid, entry.appName);
    if (applications.empty()) return;

    struct Observation {
        DWORD pid = 0;
        std::string protocol;
        std::string local_ip;
        std::string remote_ip;
        uint16_t local_port = 0;
        uint16_t remote_port = 0;
        std::string state;
        bool ipv6 = false;
    };
    std::vector<Observation> observations;
    const auto now = std::chrono::steady_clock::now();

    auto tcp4 = [&] {
        DWORD bytes = 0;
        DWORD status = GetExtendedTcpTable(nullptr, &bytes, FALSE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0);
        if (status != ERROR_INSUFFICIENT_BUFFER) {
            m_behaviorScanErrors.fetch_add(1);
            return;
        }
        std::vector<BYTE> buffer(bytes);
        status = GetExtendedTcpTable(buffer.data(), &bytes, FALSE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0);
        if (status != NO_ERROR) {
            m_behaviorScanErrors.fetch_add(1);
            return;
        }
        const auto* table =
            reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD index = 0; index < table->dwNumEntries; ++index) {
            const auto& row = table->table[index];
            if (!applications.contains(row.dwOwningPid)) continue;
            observations.push_back({ row.dwOwningPid, "tcp4",
                Ipv4Address(row.dwLocalAddr),
                row.dwState == MIB_TCP_STATE_LISTEN ? std::string{} :
                    Ipv4Address(row.dwRemoteAddr),
                ntohs(static_cast<unsigned short>(row.dwLocalPort)),
                row.dwState == MIB_TCP_STATE_LISTEN ? uint16_t{ 0 } :
                    ntohs(static_cast<unsigned short>(row.dwRemotePort)),
                TcpStateName(row.dwState), false });
        }
    };
    auto tcp6 = [&] {
        DWORD bytes = 0;
        DWORD status = GetExtendedTcpTable(nullptr, &bytes, FALSE, AF_INET6,
            TCP_TABLE_OWNER_PID_ALL, 0);
        if (status != ERROR_INSUFFICIENT_BUFFER) {
            m_behaviorScanErrors.fetch_add(1);
            return;
        }
        std::vector<BYTE> buffer(bytes);
        status = GetExtendedTcpTable(buffer.data(), &bytes, FALSE, AF_INET6,
            TCP_TABLE_OWNER_PID_ALL, 0);
        if (status != NO_ERROR) {
            m_behaviorScanErrors.fetch_add(1);
            return;
        }
        const auto* table =
            reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
        for (DWORD index = 0; index < table->dwNumEntries; ++index) {
            const auto& row = table->table[index];
            if (!applications.contains(row.dwOwningPid)) continue;
            observations.push_back({ row.dwOwningPid, "tcp6",
                Ipv6Address(row.ucLocalAddr, row.dwLocalScopeId),
                row.dwState == MIB_TCP_STATE_LISTEN ? std::string{} :
                    Ipv6Address(row.ucRemoteAddr, row.dwRemoteScopeId),
                ntohs(static_cast<unsigned short>(row.dwLocalPort)),
                row.dwState == MIB_TCP_STATE_LISTEN ? uint16_t{ 0 } :
                    ntohs(static_cast<unsigned short>(row.dwRemotePort)),
                TcpStateName(row.dwState), true });
        }
    };
    auto udp4 = [&] {
        DWORD bytes = 0;
        DWORD status = GetExtendedUdpTable(nullptr, &bytes, FALSE, AF_INET,
            UDP_TABLE_OWNER_PID, 0);
        if (status != ERROR_INSUFFICIENT_BUFFER) {
            m_behaviorScanErrors.fetch_add(1);
            return;
        }
        std::vector<BYTE> buffer(bytes);
        status = GetExtendedUdpTable(buffer.data(), &bytes, FALSE, AF_INET,
            UDP_TABLE_OWNER_PID, 0);
        if (status != NO_ERROR) {
            m_behaviorScanErrors.fetch_add(1);
            return;
        }
        const auto* table =
            reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD index = 0; index < table->dwNumEntries; ++index) {
            const auto& row = table->table[index];
            if (!applications.contains(row.dwOwningPid)) continue;
            observations.push_back({ row.dwOwningPid, "udp4",
                Ipv4Address(row.dwLocalAddr), {},
                ntohs(static_cast<unsigned short>(row.dwLocalPort)), 0,
                "bound", false });
        }
    };
    auto udp6 = [&] {
        DWORD bytes = 0;
        DWORD status = GetExtendedUdpTable(nullptr, &bytes, FALSE, AF_INET6,
            UDP_TABLE_OWNER_PID, 0);
        if (status != ERROR_INSUFFICIENT_BUFFER) {
            m_behaviorScanErrors.fetch_add(1);
            return;
        }
        std::vector<BYTE> buffer(bytes);
        status = GetExtendedUdpTable(buffer.data(), &bytes, FALSE, AF_INET6,
            UDP_TABLE_OWNER_PID, 0);
        if (status != NO_ERROR) {
            m_behaviorScanErrors.fetch_add(1);
            return;
        }
        const auto* table =
            reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
        for (DWORD index = 0; index < table->dwNumEntries; ++index) {
            const auto& row = table->table[index];
            if (!applications.contains(row.dwOwningPid)) continue;
            observations.push_back({ row.dwOwningPid, "udp6",
                Ipv6Address(row.ucLocalAddr, row.dwLocalScopeId), {},
                ntohs(static_cast<unsigned short>(row.dwLocalPort)), 0,
                "bound", true });
        }
    };
    tcp4();
    tcp6();
    udp4();
    udp6();

    // The owner-PID tables do not directly expose connection direction.  A TCP
    // connection whose local port is also owned by a listening socket in the
    // same process is inbound.  SYN-SENT is kernel-confirmed outbound.  For an
    // established connection without a matching listener, OUTBOUND is a
    // labelled inference rather than a false claim of packet-level proof.
    std::unordered_set<std::string> listeners;
    for (const auto& observation : observations) {
        if (observation.state == "listen") {
            listeners.insert(std::to_string(observation.pid) + "|" +
                observation.protocol + "|" +
                std::to_string(observation.local_port));
        }
    }

    for (const auto& observation : observations) {
        const auto application = applications.find(observation.pid);
        if (application == applications.end()) continue;
        const std::string listenerKey = std::to_string(observation.pid) + "|" +
            observation.protocol + "|" +
            std::to_string(observation.local_port);
        std::string direction;
        std::string directionBasis;
        std::string directionConfidence;
        if (observation.protocol.rfind("udp", 0) == 0) {
            direction = "BOUND";
            directionBasis = "owner_pid_udp_binding";
            directionConfidence = "observed";
        }
        else if (observation.state == "listen") {
            direction = "LISTENING";
            directionBasis = "tcp_listen_state";
            directionConfidence = "observed";
        }
        else if (listeners.contains(listenerKey) ||
            observation.state == "syn_received") {
            direction = "INBOUND";
            directionBasis = "matching_process_listener";
            directionConfidence = "inferred";
        }
        else if (observation.state == "syn_sent") {
            direction = "OUTBOUND";
            directionBasis = "tcp_syn_sent_state";
            directionConfidence = "observed";
        }
        else {
            direction = "OUTBOUND";
            directionBasis = "no_matching_process_listener";
            directionConfidence = "inferred";
        }

        const std::string local = observation.ipv6
            ? "[" + observation.local_ip + "]:" +
                std::to_string(observation.local_port)
            : observation.local_ip + ":" +
                std::to_string(observation.local_port);
        const std::string remote = observation.remote_ip.empty()
            ? std::string{}
            : (observation.ipv6
                ? "[" + observation.remote_ip + "]:" +
                    std::to_string(observation.remote_port)
                : observation.remote_ip + ":" +
                    std::to_string(observation.remote_port));
        const std::string key = application->second + "|" +
            std::to_string(observation.pid) + "|" + observation.protocol +
            "|" + local + "|" + remote + "|" + observation.state +
            "|" + direction;
        const std::string timestamp = CurrentTimestamp();
        const auto found = m_networkKeys.find(key);
        if (found != m_networkKeys.end()) {
            found->second.last_seen = now;
            found->second.representative.last_seen = timestamp;
            ++found->second.observation_count;
            continue;
        }
        if (m_networkKeys.size() >= MAX_NETWORK_KEYS)
            m_networkKeys.erase(m_networkKeys.begin());

        AppLogEvent event;
        event.kind = "network";
        event.source = "ip_helper_owner_pid_tables";
        event.event_id = "connection_observation";
        event.timestamp = timestamp;
        event.first_seen = timestamp;
        event.last_seen = timestamp;
        event.application = application->second;
        event.process_name = m_watchlist->ProcessNameForPID(observation.pid);
        event.process_role = event.process_name == event.application
            ? "main_process" : "related_subprocess";
        event.action = observation.remote_ip.empty()
            ? "local_endpoint_bound" : "remote_endpoint_accessed";
        event.pid = observation.pid;
        event.parent_pid = m_watchlist->ParentPIDForPID(observation.pid);
        event.application_root_pid =
            m_watchlist->RootPIDForPID(observation.pid);
        event.protocol = observation.protocol;
        event.local_endpoint = local;
        event.remote_endpoint = remote;
        event.local_ip = observation.local_ip;
        event.remote_ip = observation.remote_ip;
        event.local_port = observation.local_port;
        event.remote_port = observation.remote_port;
        event.connection_state = observation.state;
        event.direction = direction;
        event.direction_basis = directionBasis;
        event.direction_confidence = directionConfidence;
        event.ipv6 = observation.ipv6;

        AppLogNetworkAggregate aggregate;
        aggregate.first_seen = now;
        aggregate.last_seen = now;
        aggregate.representative = event;
        m_networkKeys.emplace(key, std::move(aggregate));
        OnEventReceived(std::move(event));
    }
}

void AppLogMonitor::CollectModuleBehavior()
{
    std::lock_guard<std::mutex> behaviorLock(m_behaviorMutex);
    for (const auto& entry : m_watchlist->GetAll()) {
        for (DWORD pid : entry.pids) {
            HANDLE snapshot = INVALID_HANDLE_VALUE;
            for (unsigned attempt = 0; attempt < 3; ++attempt) {
                snapshot = CreateToolhelp32Snapshot(
                    TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
                if (snapshot != INVALID_HANDLE_VALUE ||
                    GetLastError() != ERROR_BAD_LENGTH)
                    break;
            }
            if (snapshot == INVALID_HANDLE_VALUE) continue;
            MODULEENTRY32W module{};
            module.dwSize = sizeof(module);
            if (Module32FirstW(snapshot, &module)) {
                do {
                    const std::string path = WideToUtf8(module.szExePath);
                    const std::string key = entry.appName + "|" + path;
                    if (!path.empty() && !m_moduleKeys.contains(key)) {
                        if (m_moduleKeys.size() >= MAX_MODULE_KEYS)
                            m_moduleKeys.erase(m_moduleKeys.begin());
                        m_moduleKeys.insert(key);
                        AppLogEvent event;
                        event.kind = "module";
                        event.timestamp = CurrentTimestamp();
                        event.application = entry.appName;
                        event.action = "loaded";
                        event.pid = pid;
                        event.process_name =
                            m_watchlist->ProcessNameForPID(pid);
                        event.process_role = event.process_name == event.application
                            ? "main_process" : "related_subprocess";
                        event.parent_pid = m_watchlist->ParentPIDForPID(pid);
                        event.application_root_pid =
                            m_watchlist->RootPIDForPID(pid);
                        event.path = path;
                        OnEventReceived(std::move(event));
                    }
                } while (Module32NextW(snapshot, &module));
            }
            CloseHandle(snapshot);
        }
    }
}

void AppLogMonitor::CleanupBehaviorCaches()
{
    std::lock_guard<std::mutex> behaviorLock(m_behaviorMutex);
    const auto now = std::chrono::steady_clock::now();
    for (auto it = m_networkKeys.begin(); it != m_networkKeys.end();) {
        auto& aggregate = it->second;
        const bool stale =
            now - aggregate.last_seen > std::chrono::seconds(6);
        const bool periodic =
            now - aggregate.first_seen > std::chrono::seconds(30);
        if ((stale || periodic) && aggregate.observation_count > 1) {
            AppLogEvent summary = aggregate.representative;
            summary.kind = "network_summary";
            summary.action = "connection_observations_compacted";
            summary.repeat_of_kind = "network";
            summary.repeat_of_action = aggregate.representative.action;
            summary.repeat_count = aggregate.observation_count;
            summary.additional_observations =
                aggregate.observation_count - 1;
            summary.bypass_dedup = true;
            OnEventReceived(std::move(summary));
        }
        if (stale) {
            it = m_networkKeys.erase(it);
        }
        else {
            if (periodic) {
                aggregate.first_seen = now;
                aggregate.observation_count = 0;
                aggregate.representative.first_seen =
                    aggregate.representative.last_seen;
            }
            ++it;
        }
    }
}

void AppLogMonitor::AddToWatchlist(const std::string& appName)
{
    const bool existed = m_watchlist->Contains(appName);
    m_watchlist->Add(appName);
    m_watchlist->RefreshPIDs();
    m_etwCollector->UpdatePIDFilter(m_watchlist->GetActivePIDs());
    if (m_running.load() && !existed && m_watchlist->Contains(appName)) {
        const auto names = WatchlistNames();
        const auto found = std::find_if(names.begin(), names.end(),
            [&appName](const std::string& value) {
                std::string input = appName;
                if (input.size() >= 2 && input.front() == '"' &&
                    input.back() == '"')
                    input = input.substr(1, input.size() - 2);
                return _stricmp(value.c_str(), std::filesystem::path(input)
                    .filename().string().c_str()) == 0;
            });
        if (found != names.end()) {
            EmitSelectionChange(*found, "add");
            EmitApplicationSnapshot(*found);
        }
    }
}

void AppLogMonitor::RemoveFromWatchlist(const std::string& appName)
{
    std::string normalized = std::filesystem::path(appName).filename().string();
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    const bool existed = m_watchlist->Contains(normalized);
    m_watchlist->Remove(appName);
    m_watchlist->RefreshPIDs();
    m_etwCollector->UpdatePIDFilter(m_watchlist->GetActivePIDs());
    if (m_running.load() && existed &&
        !m_watchlist->Contains(normalized))
        EmitSelectionChange(normalized, "remove");
}

void AppLogMonitor::EmitApplicationSnapshot(
    const std::string& onlyApplication)
{
    std::unordered_map<DWORD, DWORD> parents;
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W process{};
        process.dwSize = sizeof(process);
        if (Process32FirstW(snapshot, &process)) {
            do {
                parents.emplace(process.th32ProcessID,
                    process.th32ParentProcessID);
            } while (Process32NextW(snapshot, &process));
        }
        CloseHandle(snapshot);
    }
    for (const auto& entry : m_watchlist->GetAll()) {
        if (!onlyApplication.empty() &&
            _stricmp(entry.appName.c_str(), onlyApplication.c_str()) != 0)
            continue;
        for (DWORD pid : entry.pids) {
            AppLogEvent event;
            event.kind = "application_state";
            event.timestamp = CurrentTimestamp();
            event.application = entry.appName;
            event.action = "observed_running";
            event.pid = pid;
            const auto parent = parents.find(pid);
            event.parent_pid =
                parent == parents.end() ? 0 : parent->second;
            event.process_role =
                event.parent_pid != 0 &&
                    m_watchlist->NameForPID(event.parent_pid) == entry.appName
                ? "related_subprocess" : "main_process";
            OnEventReceived(std::move(event));
        }
    }
}

void AppLogMonitor::EmitSelectionChange(
    const std::string& application, const std::string& action)
{
    AppLogEvent event;
    event.kind = "selection";
    event.timestamp = CurrentTimestamp();
    event.application = application;
    event.action = action;
    OnEventReceived(std::move(event));
}

void AppLogMonitor::PrintWatchlist() const
{
    auto entries = m_watchlist->GetAll();
    std::sort(entries.begin(), entries.end(),
        [](const auto& left, const auto& right) {
            return left.appName < right.appName;
        });
    std::cout << "[Watchlist] " << entries.size() << " application(s)\n";
    for (size_t index = 0; index < entries.size(); ++index) {
        const auto& entry = entries[index];
        std::cout << "  " << (index + 1) << ") " << entry.appName << " ["
            << (entry.active ? "running" : "stopped") << "]";
        for (DWORD pid : entry.pids) std::cout << " " << pid;
        std::cout << "\n";
    }
}

void AppLogMonitor::PrintStatus() const
{
    const auto entries = m_watchlist->GetAll();
    size_t activeApplications = 0;
    size_t activePids = 0;
    for (const auto& entry : entries) {
        if (entry.active) ++activeApplications;
        activePids += entry.pids.size();
    }
    std::lock_guard<std::mutex> behaviorLock(m_behaviorMutex);
    std::cout << "[Status] Collector: "
        << (m_running.load() ? "RUNNING" : "STOPPED") << "\n"
        << "[Status] Selected: " << entries.size()
        << " | active apps: " << activeApplications
        << " | active PIDs: " << activePids << "\n"
        << "[Status] Logged: " << m_eventCount.load()
        << " | deduplicated: " << m_deduplicatedCount.load()
        << " | queue dropped: " << m_queueDroppedCount.load() << "\n"
        << "[Status] ETW lost: " << m_etwEventsLost.load()
        << " | buffers lost: " << m_etwBuffersLost.load()
        << " | subscription errors: " << m_subscriptionErrors.load() << "\n"
        << "[Status] Network identities: " << m_networkKeys.size()
        << " | module identities: " << m_moduleKeys.size()
        << " | behavior scan errors: " << m_behaviorScanErrors.load() << "\n"
        << "[Status] Log: " << AppLogLogger::Instance().Path().string()
        << "\n";
}

void AppLogMonitor::PrintRecentActivity(
    const std::string& filter, size_t limit) const
{
    std::string recordFilter;
    if (!filter.empty()) {
        std::string application = filter;
        std::transform(application.begin(), application.end(),
            application.begin(), [](unsigned char character) {
                return static_cast<char>(std::tolower(character));
            });
        if (!application.ends_with(".exe")) application += ".exe";
        recordFilter = "\"application\":\"" + application + "\"";
    }
    const auto matches = AppLogLogger::Instance().ReadRecent(
        recordFilter, limit);
    std::cout << "[Activity] Last " << matches.size();
    if (!filter.empty()) std::cout << " matching '" << filter << "'";
    std::cout << "\n";
    for (const auto& record : matches) std::cout << record << "\n";
}

std::vector<std::string> AppLogMonitor::WatchlistNames() const
{
    std::vector<std::string> names;
    for (const auto& entry : m_watchlist->GetAll())
        names.push_back(entry.appName);
    std::sort(names.begin(), names.end());
    return names;
}

uint64_t AppLogMonitor::ApplyWatchlistRevisioned(const std::vector<std::string>& desiredApps)
{
    // FORU.TXT section 12: shared apply path for both the IPC SetWatchlist
    // command and the legacy file-poll SyncWatchlistFromFile -- one
    // consistent revision counter regardless of which path made the change.
    std::vector<std::string> desired;
    desired.reserve(desiredApps.size());
    for (const auto& raw : desiredApps) {
        auto normalized = NormalizeForDiff(raw);
        if (!normalized.empty()) desired.push_back(std::move(normalized));
    }

    const auto current = WatchlistNames();
    const std::unordered_set<std::string> desiredSet(desired.begin(), desired.end());
    const std::unordered_set<std::string> currentSet(current.begin(), current.end());

    bool changed = false;
    for (const auto& name : current)
        if (!desiredSet.count(name)) { RemoveFromWatchlist(name); changed = true; }
    for (const auto& name : desired)
        if (!currentSet.count(name)) { AddToWatchlist(name); changed = true; }

    if (changed) m_watchlistRevision.fetch_add(1, std::memory_order_relaxed);
    WriteWatchlistAck();
    return m_watchlistRevision.load();
}

void AppLogMonitor::SyncWatchlistFromFile()
{
    const auto path = WatchlistConfigPath();
    if (path.empty()) return;

    std::error_code error;
    const auto lastWrite = std::filesystem::last_write_time(path, error);
    if (error) return; // no file yet -- nothing external to apply
    if (lastWrite == m_watchlistFileLastWrite) return; // unchanged since last poll
    m_watchlistFileLastWrite = lastWrite;

    std::vector<std::string> desired;
    {
        std::ifstream input(path);
        std::string line;
        while (std::getline(input, line)) {
            if (line.empty() || line.front() == '#') continue;
            desired.push_back(line); // ApplyWatchlistRevisioned normalizes
        }
    }

    ApplyWatchlistRevisioned(desired);
}

void AppLogMonitor::WriteWatchlistAck()
{
    const auto path = WatchlistConfigPath();
    if (path.empty()) return;
    const auto ackPath = path.parent_path() / L"watchlist_state.json";
    const auto temporary = ackPath.wstring() + L".tmp";

    const auto names = WatchlistNames();
    const auto t_unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // FORU.TXT section 12: "Native acknowledgement must include the endpoint
    // session ID and exact accepted revision so an old acknowledgement
    // cannot satisfy a new request." session_id comes from AppLogLogger
    // (this process's one shared session identity), matching every other
    // endpoint's convention.
    std::ostringstream json;
    json << "{\"applied_at_ms\":" << t_unix_ms
        << ",\"session_id\":\"" << AppLogLogger::Instance().GetSessionId() << "\""
        << ",\"accepted_revision\":" << m_watchlistRevision.load()
        << ",\"capacity\":" << AppLogWatchlist::MAX_WATCHLIST_SIZE
        << ",\"count\":" << names.size()
        << ",\"watchlist\":[";
    for (size_t i = 0; i < names.size(); ++i) {
        if (i != 0) json << ",";
        json << "\"" << JsonEscape(names[i]) << "\"";
    }
    json << "]}";

    {
        std::ofstream output(std::filesystem::path(temporary), std::ios::trunc);
        if (!output) return;
        output << json.str();
    }
    if (!MoveFileExW(temporary.c_str(), ackPath.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
    }
}

void AppLogMonitor::WriteApplicationCatalog()
{
    const auto path = ApplicationCatalogPath();
    if (path.empty()) return;

    // Discover() only reads the registry uninstall keys and takes a running-process
    // snapshot -- it never launches anything, matching FORU.TXT 9.2/9.9 ("never open
    // an application merely to discover or select it").
    const auto discovered = ApplicationDiscovery::Discover();

    const auto t_unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    size_t runningCount = 0;
    size_t monitoredCount = 0;

    std::ostringstream json;
    json << "{\"generated_at_ms\":" << t_unix_ms
        << ",\"total_discovered\":" << discovered.size()
        << ",\"applications\":[";
    for (size_t i = 0; i < discovered.size(); ++i) {
        const auto& app = discovered[i];
        const bool running = app.IsRunning();
        const bool monitored = m_watchlist->IsWatchedName(app.executable);
        if (running) ++runningCount;
        if (monitored) ++monitoredCount;

        if (i != 0) json << ",";
        json << "{\"executable\":\"" << JsonEscape(app.executable) << "\","
            << "\"display_name\":\"" << JsonEscape(app.display_name) << "\","
            << "\"publisher\":\"" << JsonEscape(app.publisher) << "\","
            << "\"signature_status\":\"" << JsonEscape(app.signature_status) << "\","
            << "\"path\":\"" << JsonEscape(WideToUtf8(app.path)) << "\","
            << "\"installed\":" << (app.installed ? "true" : "false") << ","
            << "\"running\":" << (running ? "true" : "false") << ","
            << "\"pid_count\":" << app.pids.size() << ","
            << "\"monitored\":" << (monitored ? "true" : "false")
            << "}";
    }
    json << "],\"total_running\":" << runningCount
        << ",\"total_monitored\":" << monitoredCount
        << "}";

    const auto temporary = path.wstring() + L".tmp";
    std::error_code createError;
    std::filesystem::create_directories(path.parent_path(), createError);
    {
        std::ofstream output(std::filesystem::path(temporary), std::ios::trunc);
        if (!output) return;
        output << json.str();
    }
    if (!MoveFileExW(temporary.c_str(), path.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
    }
}

void AppLogMonitor::ReportTransportLoss(uint64_t etwEventsLost,
    uint64_t etwBuffersLost, uint64_t subscriptionErrors)
{
    auto updateMax = [](std::atomic<uint64_t>& target, uint64_t value) {
        uint64_t current = target.load();
        while (current < value &&
            !target.compare_exchange_weak(current, value)) {}
    };
    updateMax(m_etwEventsLost, etwEventsLost);
    updateMax(m_etwBuffersLost, etwBuffersLost);
    m_subscriptionErrors.fetch_add(subscriptionErrors);
}

void AppLogMonitor::WriteHealthRecord(bool final)
{
    const bool degraded = m_queueDroppedCount.load() != 0 ||
        m_etwEventsLost.load() != 0 || m_etwBuffersLost.load() != 0 ||
        m_subscriptionErrors.load() != 0 ||
        m_processingErrors.load() != 0 ||
        AppLogLogger::Instance().WriteFailures() != 0 ||
        AppLogLogger::Instance().RecoveredMalformedRecords() != 0 ||
        m_behaviorScanErrors.load() != 0;
    std::ostringstream json;
    const auto health_t_unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const auto [retainedBytes, retainedFiles] = AppLogLogger::Instance().GetRetainedBytesAndFiles();
    static const std::string executableHash = ComputeSelfExecutableSha256();
    json << "{\"t_unix_ms\":" << health_t_unix_ms << ","
        << "\"endpoint\":\"application\","
        << "\"type\":\"collector_health\","
        << "\"schema_version\":2,"
        << "\"endpoint_id\":\"application\","
        << "\"pid\":" << GetCurrentProcessId() << ","
        << "\"executable_version\":\"release-manifest-2026-08-02-schema-v2\","
        << "\"executable_hash\":\"" << executableHash << "\","
        << "\"started_at\":" << AppLogLogger::Instance().GetStartedAtUnixMs() << ","
        << "\"updated_at\":" << health_t_unix_ms << ","
        << "\"collecting\":" << (m_monitoringEnabled.load() ? "true" : "false") << ","
        << "\"persistence_enabled\":" << (AppLogLogger::Instance().IsSaveLogsEnabled() ? "true" : "false") << ","
        << "\"status\":\"" << (degraded ? "degraded" : "healthy") << "\","
        << "\"final\":" << (final ? "true" : "false") << ","
        << "\"logged\":" << m_eventCount.load() << ","
        << "\"deduplicated\":" << m_deduplicatedCount.load() << ","
        << "\"queue_dropped\":" << m_queueDroppedCount.load() << ","
        << "\"etw_events_lost\":" << m_etwEventsLost.load() << ","
        << "\"etw_buffers_lost\":" << m_etwBuffersLost.load() << ","
        << "\"subscription_errors\":" << m_subscriptionErrors.load() << ","
        << "\"processing_errors\":" << m_processingErrors.load() << ","
        << "\"logger_failures\":"
        << AppLogLogger::Instance().WriteFailures() << ","
        << "\"recovered_malformed_records\":"
        << AppLogLogger::Instance().RecoveredMalformedRecords() << ","
        << "\"behavior_scan_errors\":"
        << m_behaviorScanErrors.load() << ","
        // Standardized cross-endpoint names (additive).
        << "\"records_seen\":" << m_eventCount.load() << ","
        << "\"records_written\":" << m_eventCount.load() << ","
        << "\"records_dropped\":" << m_queueDroppedCount.load() << ","
        << "\"parse_failures\":" << AppLogLogger::Instance().RecoveredMalformedRecords() << ","
        << "\"source_loss\":" << (m_etwEventsLost.load() + m_etwBuffersLost.load()) << ","
        << "\"writer_failures\":" << AppLogLogger::Instance().WriteFailures() << ","
        << "\"rotations\":0," // AppLogLogger doesn't currently count rotations as its own metric
        << "\"retained_bytes\":" << retainedBytes << ","
        << "\"retained_files\":" << retainedFiles << ","
        << "\"evidence_gap\":" << (degraded ? "true" : "false") << ","
        << "\"resource_pressure\":\""
        << PressureTierToString(m_pressureMonitor.GetTier()) << "\","
        << "\"shutdown_state\":\"" << (final ? "stopped" : "running") << "\","
        << "\"shutdown_ack\":" << (final ? "true" : "false") << ","
        << "\"last_error\":\"\""
        << "}";
    AppLogLogger::Instance().Write(json.str());
    if (final) AppLogLogger::Instance().Flush();
}

std::string AppLogMonitor::JsonEscape(const std::string& value)
{
    std::string output;
    output.reserve(value.size() + 16);
    for (unsigned char character : value) {
        switch (character) {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (character < 0x20) {
                char escaped[8]{};
                sprintf_s(escaped, "\\u%04x", character);
                output += escaped;
            }
            else output += static_cast<char>(character);
        }
    }
    return output;
}
