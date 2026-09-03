#pragma once
#include "titan_pch.h"
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

class AppLogMonitor;
class AppLogWatchlist;

inline constexpr GUID POWERSHELL_PROVIDER_GUID = {
    0xA0C1853B, 0x5C40, 0x4B15,
    { 0x87, 0x66, 0x3C, 0xF1, 0xC5, 0x8F, 0x98, 0x5A }
};
inline constexpr GUID WMI_ACTIVITY_PROVIDER_GUID = {
    0x1418EF04, 0xB0B4, 0x4623,
    { 0xBF, 0x7E, 0xD7, 0x4A, 0xB4, 0x7B, 0xBD, 0xAA }
};
inline constexpr GUID KERNEL_PROCESS_PROVIDER_GUID = {
    0x22FB2CD6, 0x0E7B, 0x422B,
    { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 }
};
inline constexpr GUID KERNEL_FILE_PROVIDER_GUID = {
    0xEDD08927, 0x9CC4, 0x4E65,
    { 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89 }
};

class AppLogEtwCollector {
public:
    AppLogEtwCollector(AppLogMonitor* monitor, AppLogWatchlist* watchlist);
    ~AppLogEtwCollector();

    bool Start();
    void Stop();
    void UpdatePIDFilter(const std::vector<DWORD>& activePIDs);

private:
    bool StartEtwSession();
    bool EnableProviders();
    void ProcessingThreadFunc();
    void HandleEvent(PEVENT_RECORD event);
    void HandlePowerShellEvent(PEVENT_RECORD event);
    void HandleWmiEvent(PEVENT_RECORD event);
    void HandleProcessEvent(PEVENT_RECORD event);
    void HandleFileEvent(PEVENT_RECORD event);
    bool IsPIDWatched(DWORD pid) const;
    DWORD WatchedPIDForEvent(DWORD headerPID, DWORD headerTID) const;

    static VOID WINAPI StaticEventCallback(PEVENT_RECORD event);
    static ULONG WINAPI StaticBufferCallback(PEVENT_TRACE_LOGFILEW logfile);
    static std::string TimestampFromFiletime(const LARGE_INTEGER& timestamp);

    AppLogMonitor*   m_monitor;
    AppLogWatchlist* m_watchlist;
    TRACEHANDLE      m_sessionHandle = 0;
    std::atomic<TRACEHANDLE> m_traceHandle{ INVALID_PROCESSTRACE_HANDLE };
    std::thread       m_processingThread;
    std::atomic<bool> m_running{ false };
    mutable SRWLOCK   m_pidLock = SRWLOCK_INIT;
    std::unordered_set<DWORD> m_watchedPIDs;
    std::unordered_map<DWORD, DWORD> m_watchedThreads;

    inline static constexpr wchar_t SESSION_NAME[] =
        L"TITAN_Application_Endpoint";
    static std::atomic<AppLogEtwCollector*> s_instance;
};
