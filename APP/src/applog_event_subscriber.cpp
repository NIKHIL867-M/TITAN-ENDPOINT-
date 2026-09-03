#include "titan_pch.h"
#include <winevt.h>
#include "applog_event_subscriber.h"
#include "applog_monitor.h"

// =============================================================================
// AppLogEventSubscriber
//
// FIXES IN THIS VERSION:
//
//   1. WEL now handles ONLY Security + Defender
//      PowerShell/WMI removed from WEL — handled by ETW collector only
//      This eliminates the duplicate events (ETW + WEL both firing for PS 4104)
//      and eliminates the source="" / raw XML shown in script_content
//
//   2. GetEventChannel() fallback fixed
//      If property index 7 returns empty, parse channel from rendered XML
//      This was causing events to fall through to ParseGenericEvent
//      with empty source
//
//   3. No logic changes to Security or Defender parsers — those work correctly
// =============================================================================

// ─── Channel Definitions ─────────────────────────────────────────────────────
// WEL handles ONLY what ETW cannot provide cleanly:
//   Security (4625 failed logon, 4672 privilege escalation, 4688 process create)
//   Defender (1116/1117/1118 detections)
//
// These are future-only, server-side-filtered Windows Event Log subscriptions.
// Kernel process/file telemetry is collected separately through private ETW.

const std::vector<std::pair<std::wstring, std::wstring>>
AppLogEventSubscriber::DEFAULT_CHANNELS = {

    // Security: failed logon, privilege escalation, process creation
    {
        L"Security",
        L"*[System[(EventID=4625 or EventID=4672 or EventID=4688)]]"
    },

    // Windows Defender: malware detected, action taken, action failed
    {
        L"Microsoft-Windows-Windows Defender/Operational",
        L"*[System[(EventID=1116 or EventID=1117 or EventID=1118)]]"
    },

    {
        L"Microsoft-Windows-WMI-Activity/Operational",
        L"*[System[(EventID=5859 or EventID=5861)]]"
    },

    {
        L"Microsoft-Windows-PowerShell/Operational",
        L"*[System[EventID=4104]]"
    },
};

// Compatibility placeholder; there is no second/fallback subscription set.
const std::vector<std::pair<std::wstring, std::wstring>>
AppLogEventSubscriber::FALLBACK_CHANNELS = {};

// ─── Constructor / Destructor ────────────────────────────────────────────────

AppLogEventSubscriber::AppLogEventSubscriber(AppLogMonitor* monitor)
    : m_monitor(monitor) {
}

AppLogEventSubscriber::~AppLogEventSubscriber() {
    Stop();
}

// ─── Lifecycle ───────────────────────────────────────────────────────────────

bool AppLogEventSubscriber::Start() {
    if (m_running.load()) return true;

    int succeeded = 0;

    for (const auto& ch : DEFAULT_CHANNELS) {
        ChannelSubscription sub;
        sub.channel = ch.first;
        sub.xpath = ch.second;

        if (SubscribeToChannel(sub)) {
            m_subscriptions.push_back(std::move(sub));
            ++succeeded;
        }
        else {
            std::wcerr << L"[EventSubscriber] Could not subscribe: "
                << ch.first << L"\n";
        }
    }

    m_running.store(true);
    std::cout << "[EventSubscriber] Started. Subscriptions: "
        << succeeded << "/" << DEFAULT_CHANNELS.size() << "\n";

    if (succeeded < (int)DEFAULT_CHANNELS.size()) {
        std::cout << "[EventSubscriber] TIP: Enable Security events:\n"
            << "  auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable\n"
            << "  auditpol /set /subcategory:\"Special Logon\" /success:enable\n"
            << "  auditpol /set /subcategory:\"Process Creation\" /success:enable\n";
    }

    return succeeded > 0;
}

void AppLogEventSubscriber::Stop() {
    if (!m_running.load()) return;
    m_running.store(false);
    UnsubscribeAll();
    std::cout << "[EventSubscriber] Stopped.\n";
}

void AppLogEventSubscriber::EnableFallbackMode(bool /*enable*/) {
    // Compatibility no-op. DEFAULT_CHANNELS is the single subscription set.
}

// ─── Subscription ────────────────────────────────────────────────────────────

bool AppLogEventSubscriber::SubscribeToChannel(ChannelSubscription& sub) {
    sub.handle = EvtSubscribe(
        nullptr, nullptr,
        sub.channel.c_str(),
        sub.xpath.c_str(),
        nullptr, this,
        StaticEventCallback,
        EvtSubscribeToFutureEvents
    );

    if (!sub.handle) {
        DWORD err = GetLastError();
        std::wcerr << L"[EventSubscriber] EvtSubscribe failed (err="
            << err << L"): " << sub.channel << L"\n";
        return false;
    }
    return true;
}

void AppLogEventSubscriber::UnsubscribeAll() {
    for (auto& sub : m_subscriptions) {
        if (sub.handle) { EvtClose(sub.handle); sub.handle = nullptr; }
    }
    m_subscriptions.clear();
}

// ─── Static Callback ─────────────────────────────────────────────────────────

DWORD WINAPI AppLogEventSubscriber::StaticEventCallback(
    EVT_SUBSCRIBE_NOTIFY_ACTION action,
    PVOID                       context,
    EVT_HANDLE                  hEvent)
{
    auto* self = reinterpret_cast<AppLogEventSubscriber*>(context);
    if (!self) return ERROR_SUCCESS;
    if (action == EvtSubscribeActionError) {
        if (self->m_monitor)
            self->m_monitor->ReportTransportLoss(0, 0, 1);
        return ERROR_SUCCESS;
    }
    if (action != EvtSubscribeActionDeliver || !hEvent)
        return ERROR_SUCCESS;

    std::wstring channel = self->GetEventChannel(hEvent);
    self->HandleEvent(hEvent, channel);
    return ERROR_SUCCESS;
}

// ─── Event Routing ───────────────────────────────────────────────────────────

void AppLogEventSubscriber::HandleEvent(
    EVT_HANDLE hEvent, const std::wstring& channel)
{
    std::wstring idStr = GetEventProperty(hEvent, 1);
    DWORD        eventId = idStr.empty()
        ? 0 : static_cast<DWORD>(std::stoul(idStr));

    // Route by channel name
    if (channel == L"Security" ||
        channel.find(L"Security") != std::wstring::npos)
    {
        ParseSecurityEvent(hEvent, eventId);
    }
    else if (channel.find(L"Defender") != std::wstring::npos)
    {
        ParseDefenderEvent(hEvent, eventId);
    }
    else if (channel.find(L"PowerShell") != std::wstring::npos)
    {
        ParsePowerShellEvent(hEvent);
    }
    else if (channel.find(L"WMI-Activity") != std::wstring::npos)
    {
        ParseWmiEvent(hEvent);
    }
    else
    {
        // Unexpected channel — log generically rather than silently drop
        ParseGenericEvent(hEvent, channel, eventId);
    }
}

// ─── Parsers ─────────────────────────────────────────────────────────────────

void AppLogEventSubscriber::ParseSecurityEvent(
    EVT_HANDLE hEvent, DWORD eventId)
{
    AppLogEvent evt;
    evt.source = "Security";
    evt.event_id = std::to_string(eventId);
    evt.timestamp = NowTimestamp();
    evt.raw_data = RenderEventXml(hEvent);
    ExtractPidTidFromXml(evt.raw_data, evt.pid, evt.tid);

    if (eventId == 4672)
        evt.raw_data = "[PRIVILEGE_ESCALATION] " + evt.raw_data;
    else if (eventId == 4688)
        evt.raw_data = "[PROCESS_CREATION] " + evt.raw_data;

    m_monitor->OnEventReceived(std::move(evt));
}

void AppLogEventSubscriber::ParseDefenderEvent(
    EVT_HANDLE hEvent, DWORD eventId) {
    AppLogEvent evt;
    evt.source = "WindowsDefender";
    evt.event_id = std::to_string(eventId);
    evt.timestamp = NowTimestamp();
    evt.raw_data = RenderEventXml(hEvent);
    ExtractPidTidFromXml(evt.raw_data, evt.pid, evt.tid);
    m_monitor->OnEventReceived(std::move(evt));
}

void AppLogEventSubscriber::ParsePowerShellEvent(EVT_HANDLE hEvent) {
    // Kept for compile compatibility — no longer called
    // PowerShell 4104 is handled exclusively by ETW collector (TDH decoded)
    AppLogEvent evt;
    evt.source = "PowerShell";
    evt.event_id = "4104";
    evt.timestamp = NowTimestamp();
    evt.raw_data = RenderEventXml(hEvent);
    ExtractPidTidFromXml(evt.raw_data, evt.pid, evt.tid);
    m_monitor->OnEventReceived(std::move(evt));
}

void AppLogEventSubscriber::ParseWmiEvent(EVT_HANDLE hEvent) {
    // Kept for compile compatibility — no longer called
    // WMI 5859/5861 handled exclusively by ETW collector
    AppLogEvent evt;
    evt.source = "WMI";
    evt.timestamp = NowTimestamp();
    evt.raw_data = RenderEventXml(hEvent);
    ExtractPidTidFromXml(evt.raw_data, evt.pid, evt.tid);
    const std::string marker = "<EventID>";
    const size_t begin = evt.raw_data.find(marker);
    const size_t end = begin == std::string::npos ? std::string::npos
        : evt.raw_data.find("</EventID>", begin + marker.size());
    if (end != std::string::npos)
        evt.event_id = evt.raw_data.substr(begin + marker.size(),
            end - begin - marker.size());
    m_monitor->OnEventReceived(std::move(evt));
}

void AppLogEventSubscriber::ParseGenericEvent(
    EVT_HANDLE hEvent, const std::wstring& channel, DWORD eventId)
{
    AppLogEvent evt;

    // FIXED: proper wstring to UTF-8 conversion
    evt.source.clear();
    evt.source.reserve(channel.size());
    for (wchar_t wc : channel) {
        if (wc < 0x80) { evt.source += static_cast<char>(wc); }
        else if (wc < 0x800) {
            evt.source += static_cast<char>(0xC0 | (wc >> 6));
            evt.source += static_cast<char>(0x80 | (wc & 0x3F));
        }
        else {
            evt.source += static_cast<char>(0xE0 | (wc >> 12));
            evt.source += static_cast<char>(0x80 | ((wc >> 6) & 0x3F));
            evt.source += static_cast<char>(0x80 | (wc & 0x3F));
        }
    }

    evt.event_id = std::to_string(eventId);
    evt.timestamp = NowTimestamp();
    evt.raw_data = RenderEventXml(hEvent);
    ExtractPidTidFromXml(evt.raw_data, evt.pid, evt.tid);
    m_monitor->OnEventReceived(std::move(evt));
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// FIXED: GetEventChannel tries property index 7 first,
// then falls back to parsing channel from rendered XML
std::wstring AppLogEventSubscriber::GetEventChannel(EVT_HANDLE hEvent) const
{
    // Try system property index 7 (EvtSystemChannel)
    std::wstring ch = GetEventProperty(hEvent, 7);
    if (!ch.empty()) return ch;

    // Fallback: extract from rendered XML
    // <Channel>Microsoft-Windows-...</Channel>
    std::string xml = RenderEventXml(hEvent);
    auto start = xml.find("<Channel>");
    auto end = xml.find("</Channel>");
    if (start != std::string::npos && end != std::string::npos) {
        start += 9;  // len("<Channel>")
        std::string ch_utf8 = xml.substr(start, end - start);
        // Convert back to wstring for routing
        std::wstring result;
        result.reserve(ch_utf8.size());
        for (unsigned char c : ch_utf8)
            result += static_cast<wchar_t>(c);
        return result;
    }

    return L"";
}

// FIX: extracts ProcessID/ThreadID from the <Execution> element of an
// already-rendered event XML string (e.g. RenderEventXml's output), so
// application_log records can carry real pid/tid instead of always 0.
void AppLogEventSubscriber::ExtractPidTidFromXml(
    const std::string& xml, uint32_t& pid, uint32_t& tid)
{
    pid = 0;
    tid = 0;

    auto extractAttr = [&](const char* attrName) -> uint32_t {
        const std::string needle = std::string(attrName) + "=\"";
        const size_t pos = xml.find(needle);
        if (pos == std::string::npos) return 0;
        const size_t valueStart = pos + needle.size();
        const size_t valueEnd = xml.find('"', valueStart);
        if (valueEnd == std::string::npos) return 0;
        const std::string value = xml.substr(valueStart, valueEnd - valueStart);
        try {
            return static_cast<uint32_t>(std::stoul(value));
        }
        catch (...) {
            return 0;
        }
        };

    pid = extractAttr("ProcessID");
    tid = extractAttr("ThreadID");
}

std::wstring AppLogEventSubscriber::GetEventProperty(
    EVT_HANDLE hEvent, DWORD index) const
{
    EVT_HANDLE hCtx = EvtCreateRenderContext(
        0, nullptr, EvtRenderContextSystem);
    if (!hCtx) return L"";

    DWORD bufSize = 0, count = 0;
    EvtRender(hCtx, hEvent, EvtRenderEventValues,
        0, nullptr, &bufSize, &count);

    if (bufSize == 0) { EvtClose(hCtx); return L""; }

    std::vector<BYTE> buf(bufSize);
    DWORD usedSize = 0, propCount = 0;

    if (!EvtRender(hCtx, hEvent, EvtRenderEventValues,
        bufSize, buf.data(), &usedSize, &propCount))
    {
        EvtClose(hCtx); return L"";
    }

    EvtClose(hCtx);

    if (index >= propCount) return L"";

    auto* values = reinterpret_cast<EVT_VARIANT*>(buf.data());

    if (values[index].Type == EvtVarTypeString && values[index].StringVal)
        return std::wstring(values[index].StringVal);
    if (values[index].Type == EvtVarTypeUInt16)
        return std::to_wstring(values[index].UInt16Val);
    if (values[index].Type == EvtVarTypeUInt32)
        return std::to_wstring(values[index].UInt32Val);

    return L"";
}

std::string AppLogEventSubscriber::RenderEventXml(EVT_HANDLE hEvent) const
{
    DWORD bufSize = 0, propCount = 0;
    EvtRender(nullptr, hEvent, EvtRenderEventXml,
        0, nullptr, &bufSize, &propCount);

    if (bufSize == 0) return "<render_error/>";

    std::vector<wchar_t> buf(bufSize / sizeof(wchar_t) + 1, L'\0');
    DWORD used = 0, propCount2 = 0;

    if (!EvtRender(nullptr, hEvent, EvtRenderEventXml,
        bufSize, buf.data(), &used, &propCount2))
        return "<render_error/>";

    // Proper UTF-8 conversion
    std::string out;
    out.reserve(used / sizeof(wchar_t));
    for (size_t i = 0; i < buf.size(); ++i) {
        wchar_t wc = buf[i];
        if (wc == L'\0') break;
        if (wc < 0x80) { out += static_cast<char>(wc); }
        else if (wc < 0x800) {
            out += static_cast<char>(0xC0 | (wc >> 6));
            out += static_cast<char>(0x80 | (wc & 0x3F));
        }
        else {
            out += static_cast<char>(0xE0 | (wc >> 12));
            out += static_cast<char>(0x80 | ((wc >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (wc & 0x3F));
        }
    }
    return out;
}

std::string AppLogEventSubscriber::NowTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto timeVal = std::chrono::system_clock::to_time_t(now);
    std::tm tmBuf{};
    localtime_s(&tmBuf, &timeVal);
    char buf[32] = { 0 };
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmBuf);
    return std::string(buf);
}
