#pragma once
#include "titan_pch.h"
#include "resource_pressure.h"
#include <queue>
#include <condition_variable>
#include <unordered_map>
#include <filesystem>

class AppLogEtwCollector;
class AppLogEventSubscriber;
class AppLogWatchlist;
class AppLogDecoder;

struct AppLogEvent {
    std::string kind;
    std::string source;
    std::string event_id;
    std::string timestamp;
    std::string raw_data;
    std::string decoded_json;
    std::string application;
    std::string process_name;
    std::string action;
    std::string path;
    std::string old_path;
    std::string command_line;
    std::string process_role;
    std::string protocol;
    std::string local_endpoint;
    std::string remote_endpoint;
    std::string connection_state;
    std::string direction;
    std::string direction_basis;
    std::string direction_confidence;
    std::string local_ip;
    std::string remote_ip;
    std::string first_seen;
    std::string last_seen;
    std::string repeat_of_kind;
    std::string repeat_of_action;
    uint32_t    pid = 0;
    uint32_t    tid = 0;
    uint32_t    parent_pid = 0;
    uint32_t    application_root_pid = 0;
    uint16_t    local_port = 0;
    uint16_t    remote_port = 0;
    uint64_t    file_key = 0;
    uint64_t    repeat_count = 1;
    uint64_t    additional_observations = 0;
    bool        ipv6 = false;
    bool        bypass_dedup = false;
};

struct AppLogDedupEntry {
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    AppLogEvent representative;
    uint64_t repeat_count = 0;
};

struct AppLogNetworkAggregate {
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    AppLogEvent representative;
    uint64_t observation_count = 1;
};

class AppLogMonitor {
public:
    AppLogMonitor();
    ~AppLogMonitor();

    bool Start();
    void Stop();
    bool IsRunning() const { return m_running.load(); }

    // Called from ETW/WEL threads — thread safe, non-blocking
    void OnEventReceived(AppLogEvent event);

    // FORU.TXT section 4: Monitoring toggle via the IPC control channel,
    // independent of whether ETW/WEL subscriptions are open. When false,
    // OnEventReceived discards immediately (mirrors ProcessMonitor's
    // SetMonitoringEnabled exactly).
    void SetMonitoringEnabled(bool enabled) noexcept { m_monitoringEnabled.store(enabled); }
    bool IsMonitoringEnabled() const noexcept { return m_monitoringEnabled.load(); }

    void AddToWatchlist(const std::string& appName);
    void RemoveFromWatchlist(const std::string& appName);
    void PrintWatchlist() const;
    void PrintStatus() const;
    void PrintRecentActivity(
        const std::string& filter = {}, size_t limit = 20) const;
    std::vector<std::string> WatchlistNames() const;
    void ReportTransportLoss(uint64_t etwEventsLost,
        uint64_t etwBuffersLost, uint64_t subscriptionErrors = 0);

private:
    void WorkerThreadFunc();
    void MonitorThreadFunc();
    void ProcessEvent(AppLogEvent& event);
    bool LogEvent(const AppLogEvent& event) const;
    void CleanupDedupCache();
    void EmitApplicationSnapshot(const std::string& onlyApplication = {});
    void EmitSelectionChange(
        const std::string& application, const std::string& action);
    void CollectNetworkBehavior();
    void CollectModuleBehavior();
    void CleanupBehaviorCaches();

    // FORU.TXT section 9.2: "Enumerate all discoverable installed and currently
    // running desktop applications without launching them." ApplicationDiscovery::Discover()
    // already does exactly this (registry uninstall keys + running process snapshot,
    // merged by canonical executable identity) but was previously only reachable via
    // this program's own interactive stdin commands. Periodically dumped to
    // config\application_catalog.json so the GUI can show the full catalogue rather
    // than only whatever this session's log activity happened to mention.
    void WriteApplicationCatalog();

    // Live external control: config\watchlist.txt is written once at startup
    // (main_test.cpp's LoadSelection/SaveSelection) but was never re-read while
    // running -- the GUI's Application Monitor add/remove control needs the
    // running collector to notice edits made to that file externally. Polled
    // from MonitorThreadFunc's existing ~2s loop via last_write_time, so it costs
    // one stat() call when nothing changed. WriteWatchlistAck persists the
    // effective watchlist to config\watchlist_state.json after every sync so an
    // external caller (the GUI) can confirm what was actually applied rather than
    // assuming its own write took effect.
    void SyncWatchlistFromFile();
    void WriteWatchlistAck();
    std::filesystem::file_time_type m_watchlistFileLastWrite{};

    std::atomic<bool> m_running{ false };
    std::atomic<bool> m_monitoringEnabled{ true };
    std::thread       m_monitorThread;
    std::thread       m_workerThread;

public:
    // FORU.TXT section 12: revisioned watchlist IPC (SetWatchlist command in
    // ipc_control_server.cpp) -- applies the requested list via the existing
    // Add/RemoveFromWatchlist and returns the accepted revision, so a stale
    // acknowledgement can never satisfy a newer request. Incremented on
    // every actually-applied change from EITHER path (IPC SetWatchlist or
    // the legacy file-poll SyncWatchlistFromFile), so both paths share one
    // consistent revision counter.
    uint64_t ApplyWatchlistRevisioned(const std::vector<std::string>& desiredApps);
    uint64_t CurrentWatchlistRevision() const noexcept { return m_watchlistRevision.load(); }

private:
    std::atomic<uint64_t> m_watchlistRevision{ 0 };

    // Event queue
    std::queue<AppLogEvent>  m_eventQueue;
    std::mutex               m_queueMutex;
    std::condition_variable  m_queueCv;

    // Deduplication
    std::unordered_map<std::string, AppLogDedupEntry> m_recentKeys;

    // Stats
    std::atomic<uint64_t> m_eventCount{ 0 };
    std::atomic<uint64_t> m_deduplicatedCount{ 0 };
    std::atomic<uint64_t> m_queueDroppedCount{ 0 };
    std::atomic<uint64_t> m_etwEventsLost{ 0 };
    std::atomic<uint64_t> m_etwBuffersLost{ 0 };
    std::atomic<uint64_t> m_subscriptionErrors{ 0 };
    std::atomic<uint64_t> m_processingErrors{ 0 };
    size_t                m_queuedBytes = 0;
    static constexpr size_t MAX_QUEUE_DEPTH = 4096;
    static constexpr size_t MAX_QUEUE_BYTES = 2 * 1024 * 1024;
    static constexpr size_t MAX_DEDUP_KEYS = 1024;
    static constexpr size_t MAX_NETWORK_KEYS = 8192;
    static constexpr size_t MAX_MODULE_KEYS = 4096;
    std::unordered_map<std::string, AppLogNetworkAggregate> m_networkKeys;
    std::unordered_set<std::string> m_moduleKeys;
    mutable std::mutex m_behaviorMutex;
    std::atomic<uint64_t> m_behaviorScanErrors{ 0 };

    std::unique_ptr<AppLogEtwCollector>    m_etwCollector;
    std::unique_ptr<AppLogEventSubscriber> m_eventSubscriber;
    std::unique_ptr<AppLogWatchlist>       m_watchlist;
    std::unique_ptr<AppLogDecoder>         m_decoder;

    // RAM/disk auto-lightening -- shrinks AppLogLogger's archive-retention
    // cap under system pressure. Never touches the watchlist (WHAT is
    // monitored stays the same regardless of pressure).
    ResourcePressureMonitor m_pressureMonitor;
    static constexpr size_t kBaseMaxArchives = 2;
    static constexpr size_t kFloorMaxArchives = 1;

    void WriteHealthRecord(bool final);
    static std::string JsonEscape(const std::string& value);
};
