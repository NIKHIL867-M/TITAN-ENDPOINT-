#include "titan_pch.h"
#include "applog_etw_collector.h"
#include "applog_monitor.h"
#include "applog_watchlist.h"

#include <deque>
#include <filesystem>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

std::atomic<AppLogEtwCollector*> AppLogEtwCollector::s_instance{ nullptr };

namespace {
constexpr ULONGLONG PROCESS_KEYWORD = 0x10;
constexpr size_t MAX_FILE_PATH_CACHE = 2048;

std::unordered_map<uint64_t, std::wstring> g_filePaths;
std::deque<uint64_t> g_filePathOrder;

enum FileTask : USHORT {
    KFT_NAME_CREATE = 10,
    KFT_NAME_DELETE = 11,
    KFT_CREATE = 12,
    KFT_CLOSE = 14,
    KFT_WRITE = 16,
    KFT_SET_INFO = 17,
    KFT_RENAME = 19,
    KFT_DELETE_PATH = 26,
    KFT_RENAME_PATH = 27,
    KFT_CREATE_NEW = 30
};

struct PropertySchema {
    std::vector<BYTE> storage;
    PTRACE_EVENT_INFO info = nullptr;
};

bool GetSchema(PEVENT_RECORD event, PropertySchema& schema)
{
    ULONG size = 0;
    const ULONG first = TdhGetEventInformation(
        event, 0, nullptr, nullptr, &size);
    if (first != ERROR_INSUFFICIENT_BUFFER || size == 0) return false;
    schema.storage.resize(size);
    schema.info = reinterpret_cast<PTRACE_EVENT_INFO>(schema.storage.data());
    return TdhGetEventInformation(event, 0, nullptr, schema.info, &size)
        == ERROR_SUCCESS;
}

bool GetRawProperty(PEVENT_RECORD event, PTRACE_EVENT_INFO info,
    const wchar_t* requested, std::vector<BYTE>& value, USHORT& inType)
{
    if (!info) return false;
    for (ULONG index = 0; index < info->TopLevelPropertyCount; ++index) {
        const auto& property = info->EventPropertyInfoArray[index];
        const auto* name = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const BYTE*>(info) + property.NameOffset);
        if (_wcsicmp(name, requested) != 0) continue;
        PROPERTY_DATA_DESCRIPTOR descriptor{};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
        descriptor.ArrayIndex = ULONG_MAX;
        ULONG size = 0;
        if (TdhGetPropertySize(event, 0, nullptr, 1, &descriptor, &size)
            != ERROR_SUCCESS || size == 0)
            return false;
        value.assign(static_cast<size_t>(size) + sizeof(wchar_t), BYTE{});
        if (TdhGetProperty(event, 0, nullptr, 1, &descriptor,
            size, value.data()) != ERROR_SUCCESS)
            return false;
        inType = property.nonStructType.InType;
        return true;
    }
    return false;
}

std::string WideToUtf8(const std::wstring& value)
{
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        value.data(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string output(static_cast<size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        value.data(), static_cast<int>(value.size()),
        output.data(), required, nullptr, nullptr);
    return output;
}

std::string PropertyString(PEVENT_RECORD event, PTRACE_EVENT_INFO info,
    const wchar_t* name)
{
    std::vector<BYTE> raw;
    USHORT type = 0;
    if (!GetRawProperty(event, info, name, raw, type)) return {};
    if (type == TDH_INTYPE_UNICODESTRING) {
        const auto* text = reinterpret_cast<const wchar_t*>(raw.data());
        return WideToUtf8(std::wstring(text));
    }
    if (type == TDH_INTYPE_ANSISTRING)
        return std::string(reinterpret_cast<const char*>(raw.data()));
    return {};
}

uint64_t PropertyUInt(PEVENT_RECORD event, PTRACE_EVENT_INFO info,
    const wchar_t* name)
{
    std::vector<BYTE> raw;
    USHORT type = 0;
    if (!GetRawProperty(event, info, name, raw, type)) return 0;
    uint64_t value = 0;
    if (type == TDH_INTYPE_UINT32 || type == TDH_INTYPE_HEXINT32) {
        uint32_t small = 0;
        memcpy(&small, raw.data(), sizeof(small));
        return small;
    }
    if (type == TDH_INTYPE_UINT64 || type == TDH_INTYPE_HEXINT64 ||
        type == TDH_INTYPE_POINTER) {
        memcpy(&value, raw.data(),
            (std::min)(sizeof(value), raw.size()));
    }
    return value;
}

std::string XmlEscape(const std::string& value)
{
    std::string output;
    output.reserve(value.size() + 16);
    for (char character : value) {
        switch (character) {
        case '&': output += "&amp;"; break;
        case '<': output += "&lt;"; break;
        case '>': output += "&gt;"; break;
        case '"': output += "&quot;"; break;
        case '\'': output += "&apos;"; break;
        default: output += character; break;
        }
    }
    return output;
}

std::string BaseName(const std::string& path)
{
    const auto slash = path.find_last_of("\\/");
    std::string name = slash == std::string::npos
        ? path : path.substr(slash + 1);
    std::transform(name.begin(), name.end(), name.begin(),
        [](unsigned char value) {
            return static_cast<char>(std::tolower(value));
        });
    return name;
}

void CachePath(uint64_t key, const std::wstring& path)
{
    if (key == 0 || path.empty()) return;
    const auto found = g_filePaths.find(key);
    if (found != g_filePaths.end()) {
        found->second = path;
        return;
    }
    while (g_filePaths.size() >= MAX_FILE_PATH_CACHE &&
        !g_filePathOrder.empty()) {
        g_filePaths.erase(g_filePathOrder.front());
        g_filePathOrder.pop_front();
    }
    g_filePaths[key] = path;
    g_filePathOrder.push_back(key);
}

std::wstring LookupPath(uint64_t key)
{
    const auto found = g_filePaths.find(key);
    return found == g_filePaths.end() ? std::wstring{} : found->second;
}

void RemovePath(uint64_t key)
{
    g_filePaths.erase(key);
    const auto found = std::find(
        g_filePathOrder.begin(), g_filePathOrder.end(), key);
    if (found != g_filePathOrder.end()) g_filePathOrder.erase(found);
}

std::wstring NtPathToDos(std::wstring path)
{
    if (path.rfind(L"\\Device\\", 0) != 0) return path;
    wchar_t drives[512]{};
    const DWORD length = GetLogicalDriveStringsW(
        static_cast<DWORD>(std::size(drives)), drives);
    if (length == 0) return path;
    for (const wchar_t* drive = drives; *drive;
        drive += wcslen(drive) + 1) {
        wchar_t device[1024]{};
        wchar_t name[3]{ drive[0], L':', L'\0' };
        if (!QueryDosDeviceW(name, device,
            static_cast<DWORD>(std::size(device))))
            continue;
        const size_t prefix = wcslen(device);
        if (_wcsnicmp(path.c_str(), device, prefix) == 0)
            return std::wstring(name) + path.substr(prefix);
    }
    return path;
}
}

AppLogEtwCollector::AppLogEtwCollector(
    AppLogMonitor* monitor, AppLogWatchlist* watchlist)
    : m_monitor(monitor), m_watchlist(watchlist)
{
    s_instance.store(this);
}

AppLogEtwCollector::~AppLogEtwCollector()
{
    Stop();
    AppLogEtwCollector* expected = this;
    s_instance.compare_exchange_strong(expected, nullptr);
}

bool AppLogEtwCollector::Start()
{
    if (m_running.load()) return true;
    if (!StartEtwSession()) {
        Stop();
        return false;
    }
    m_running.store(true);
    m_processingThread = std::thread(
        &AppLogEtwCollector::ProcessingThreadFunc, this);
    // Open the real-time consumer before enabling high-volume providers.
    // Otherwise the finite ETW buffers can overflow during thread startup.
    for (unsigned attempt = 0; attempt < 200 &&
        m_traceHandle.load() == INVALID_PROCESSTRACE_HANDLE; ++attempt)
        Sleep(5);
    if (m_traceHandle.load() == INVALID_PROCESSTRACE_HANDLE ||
        !EnableProviders()) {
        Stop();
        return false;
    }
    std::cout << "[ETW] Kernel process lifecycle provider active.\n";
    return true;
}

void AppLogEtwCollector::Stop()
{
    const bool wasRunning = m_running.exchange(false);
    if (!wasRunning && m_sessionHandle == 0) return;

    // Stop provider production before closing the real-time consumer.  Closing
    // the consumer while Kernel-File was still producing events caused the huge
    // shutdown-only loss count observed in live testing.
    if (m_sessionHandle != 0) {
        EnableTraceEx2(m_sessionHandle, &KERNEL_FILE_PROVIDER_GUID,
            EVENT_CONTROL_CODE_DISABLE_PROVIDER, TRACE_LEVEL_NONE,
            0, 0, 0, nullptr);
        EnableTraceEx2(m_sessionHandle, &KERNEL_PROCESS_PROVIDER_GUID,
            EVENT_CONTROL_CODE_DISABLE_PROVIDER, TRACE_LEVEL_NONE,
            0, 0, 0, nullptr);
        const ULONG nameBytes = static_cast<ULONG>(
            (wcslen(SESSION_NAME) + 1) * sizeof(wchar_t));
        const ULONG total = sizeof(EVENT_TRACE_PROPERTIES) + nameBytes;
        std::vector<BYTE> buffer(total);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(
            buffer.data());
        properties->Wnode.BufferSize = total;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        if (ControlTraceW(m_sessionHandle, SESSION_NAME, properties,
            EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS && m_monitor) {
            m_monitor->ReportTransportLoss(properties->EventsLost,
                properties->RealTimeBuffersLost);
            std::cout << "[ETW] events_lost=" << properties->EventsLost
                << " buffers_lost=" << properties->RealTimeBuffersLost << "\n";
        }
    }

    const TRACEHANDLE trace = m_traceHandle.exchange(
        INVALID_PROCESSTRACE_HANDLE);
    if (trace != INVALID_PROCESSTRACE_HANDLE) CloseTrace(trace);
    if (m_processingThread.joinable()) m_processingThread.join();

    if (m_sessionHandle != 0) {
        const ULONG nameBytes = static_cast<ULONG>(
            (wcslen(SESSION_NAME) + 1) * sizeof(wchar_t));
        const ULONG total = sizeof(EVENT_TRACE_PROPERTIES) + nameBytes;
        std::vector<BYTE> buffer(total);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(
            buffer.data());
        properties->Wnode.BufferSize = total;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        if (ControlTraceW(m_sessionHandle, SESSION_NAME, properties,
            EVENT_TRACE_CONTROL_STOP) == ERROR_SUCCESS && m_monitor) {
            m_monitor->ReportTransportLoss(properties->EventsLost,
                properties->RealTimeBuffersLost);
        }
        m_sessionHandle = 0;
    }
}

bool AppLogEtwCollector::StartEtwSession()
{
    const ULONG nameBytes = static_cast<ULONG>(
        (wcslen(SESSION_NAME) + 1) * sizeof(wchar_t));
    const ULONG total = sizeof(EVENT_TRACE_PROPERTIES) + nameBytes;
    auto makeProperties = [total, nameBytes](std::vector<BYTE>& buffer) {
        std::fill(buffer.begin(), buffer.end(), BYTE{});
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(
            buffer.data());
        properties->Wnode.BufferSize = total;
        properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        // TimestampFromFiletime consumes EventHeader.TimeStamp as FILETIME.
        properties->Wnode.ClientContext = 2;
        // Kernel-File is system-wide even though the callback immediately
        // discards non-watchlisted PIDs.  A 2 MiB ceiling (32 x 64 KiB) proved
        // too small during a normal browser workload and produced a real,
        // visible evidence gap.  Keep the pool bounded, but allow 2-16 MiB so
        // short bursts are absorbed without turning RAM growth unbounded.
        properties->BufferSize = 64;
        properties->MinimumBuffers = 32;
        properties->MaximumBuffers = 256;
        properties->FlushTimer = 1;
        properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        memcpy(buffer.data() + properties->LoggerNameOffset,
            SESSION_NAME, nameBytes);
        return properties;
    };
    std::vector<BYTE> buffer(total);
    auto* properties = makeProperties(buffer);
    ULONG status = StartTraceW(&m_sessionHandle, SESSION_NAME, properties);
    if (status == ERROR_ALREADY_EXISTS) {
        ControlTraceW(0, SESSION_NAME, properties, EVENT_TRACE_CONTROL_STOP);
        properties = makeProperties(buffer);
        status = StartTraceW(&m_sessionHandle, SESSION_NAME, properties);
    }
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] StartTrace failed: " << status << "\n";
        m_sessionHandle = 0;
        return false;
    }
    return true;
}

bool AppLogEtwCollector::EnableProviders()
{
    const auto enable = [this](const GUID& provider, UCHAR level,
        ULONGLONG keywords, const char* name, bool required) {
        const ULONG status = EnableTraceEx2(m_sessionHandle, &provider,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER, level, keywords,
            0, 0, nullptr);
        if (status != ERROR_SUCCESS)
            std::cerr << "[ETW] " << name << " enable failed: "
                << status << "\n";
        return !required || status == ERROR_SUCCESS;
    };
    bool success = true;
    success &= enable(KERNEL_PROCESS_PROVIDER_GUID,
        TRACE_LEVEL_INFORMATION, PROCESS_KEYWORD,
        "Kernel-Process", true);
    success &= enable(KERNEL_FILE_PROVIDER_GUID,
        TRACE_LEVEL_VERBOSE, 0xFEFF,
        "Kernel-File", true);
    return success;
}

void AppLogEtwCollector::ProcessingThreadFunc()
{
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = const_cast<LPWSTR>(SESSION_NAME);
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
        PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = StaticEventCallback;
    logfile.BufferCallback = StaticBufferCallback;
    TRACEHANDLE trace = OpenTraceW(&logfile);
    if (trace == INVALID_PROCESSTRACE_HANDLE) {
        std::cerr << "[ETW] OpenTrace failed: " << GetLastError() << "\n";
        return;
    }
    m_traceHandle.store(trace);
    const ULONG status = ProcessTrace(&trace, 1, nullptr, nullptr);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
        std::cerr << "[ETW] ProcessTrace ended: " << status << "\n";
}

VOID WINAPI AppLogEtwCollector::StaticEventCallback(PEVENT_RECORD event)
{
    auto* instance = s_instance.load();
    if (instance && instance->m_running.load())
        instance->HandleEvent(event);
}

ULONG WINAPI AppLogEtwCollector::StaticBufferCallback(
    PEVENT_TRACE_LOGFILEW logfile)
{
    auto* instance = s_instance.load();
    if (!instance) return FALSE;
    if (logfile && instance->m_monitor)
        instance->m_monitor->ReportTransportLoss(logfile->EventsLost, 0);
    // Stop() disables both providers before closing the consumer.  Returning
    // FALSE merely because the public running flag was cleared makes ETW drop
    // every buffer that was already queued at that instant, inflating the final
    // EventsLost counter by hundreds of thousands.  CloseTrace is the explicit
    // termination signal for this real-time consumer.
    return TRUE;
}

void AppLogEtwCollector::HandleEvent(PEVENT_RECORD event)
{
    if (!event) return;
    const GUID& provider = event->EventHeader.ProviderId;
    if (IsEqualGUID(provider, KERNEL_PROCESS_PROVIDER_GUID))
        HandleProcessEvent(event);
    else if (IsEqualGUID(provider, KERNEL_FILE_PROVIDER_GUID))
        HandleFileEvent(event);
    else if (IsEqualGUID(provider, POWERSHELL_PROVIDER_GUID))
        HandlePowerShellEvent(event);
    else if (IsEqualGUID(provider, WMI_ACTIVITY_PROVIDER_GUID))
        HandleWmiEvent(event);
}

void AppLogEtwCollector::HandleProcessEvent(PEVENT_RECORD event)
{
    const USHORT id = event->EventHeader.EventDescriptor.Id;
    if (id != 1 && id != 2) return;
    PropertySchema schema;
    if (!GetSchema(event, schema)) return;
    uint32_t pid = static_cast<uint32_t>(
        PropertyUInt(event, schema.info, L"ProcessId"));
    if (pid == 0)
        pid = static_cast<uint32_t>(
            PropertyUInt(event, schema.info, L"ProcessID"));
    if (pid == 0) return;
    std::string image = PropertyString(event, schema.info, L"ImageName");
    if (image.empty())
        image = PropertyString(event, schema.info, L"ImageFileName");
    const std::string name = BaseName(image);
    uint32_t parentPid = static_cast<uint32_t>(
        PropertyUInt(event, schema.info, L"ParentId"));
    if (parentPid == 0)
        parentPid = static_cast<uint32_t>(
            PropertyUInt(event, schema.info, L"ParentProcessId"));

    bool watched = false;
    bool relatedProcess = false;
    std::string watchedName;
    std::string actualProcessName = name;
    uint32_t rootPid = 0;
    uint32_t savedParentPid = parentPid;
    if (id == 1) {
        const std::string parentApplication =
            m_watchlist->NameForPID(parentPid);
        watched = m_watchlist->ObserveProcessStart(pid, name, parentPid);
        relatedProcess = !parentApplication.empty();
        if (!watched) {
            watched = m_watchlist->ObserveRelatedProcessStart(
                pid, parentPid, name);
            relatedProcess = watched;
        }
        watchedName = m_watchlist->NameForPID(pid);
        rootPid = m_watchlist->RootPIDForPID(pid);
    }
    else {
        watchedName = m_watchlist->NameForPID(pid);
        const std::string cachedName = m_watchlist->ProcessNameForPID(pid);
        if (!cachedName.empty()) actualProcessName = cachedName;
        savedParentPid = m_watchlist->ParentPIDForPID(pid);
        rootPid = m_watchlist->RootPIDForPID(pid);
        watched = m_watchlist->ObserveProcessStop(pid);
    }
    if (!watched) return;
    if (id == 1)
        UpdatePIDFilter(m_watchlist->GetActivePIDs());

    AppLogEvent output;
    output.kind = "process";
    output.source = "Kernel-Process";
    output.event_id = std::to_string(id);
    output.timestamp = TimestampFromFiletime(event->EventHeader.TimeStamp);
    output.application = !watchedName.empty() ? watchedName : name;
    output.process_name = actualProcessName;
    output.action = id == 1 ? "start" : "stop";
    output.path = image;
    output.command_line = PropertyString(
        event, schema.info, L"CommandLine");
    output.process_role = id == 1
        ? (relatedProcess ? "related_subprocess" : "main_process")
        : "monitored_process";
    output.parent_pid = savedParentPid;
    output.application_root_pid = rootPid;
    output.pid = pid;
    output.tid = event->EventHeader.ThreadId;
    m_monitor->OnEventReceived(std::move(output));
}

void AppLogEtwCollector::HandleFileEvent(PEVENT_RECORD event)
{
    // Kernel-File is system-wide and extremely busy. Discard events from
    // applications outside the watchlist before any TDH allocation/decoding.
    // This keeps the real-time consumer from falling behind under normal I/O.
    const DWORD pid = WatchedPIDForEvent(event->EventHeader.ProcessId,
        event->EventHeader.ThreadId);
    if (pid == 0) return;

    const USHORT task = event->EventHeader.EventDescriptor.Task;
    if (task == 0) return;
    PropertySchema schema;
    if (!GetSchema(event, schema)) return;
    uint64_t key = PropertyUInt(event, schema.info, L"FileKey");
    if (key == 0) key = PropertyUInt(event, schema.info, L"FileObject");
    std::string utf8Path = PropertyString(event, schema.info, L"FileName");
    if (utf8Path.empty())
        utf8Path = PropertyString(event, schema.info, L"OpenPath");
    std::wstring path;
    if (!utf8Path.empty()) {
        const int needed = MultiByteToWideChar(CP_UTF8, 0, utf8Path.data(),
            static_cast<int>(utf8Path.size()), nullptr, 0);
        path.resize(static_cast<size_t>(needed));
        MultiByteToWideChar(CP_UTF8, 0, utf8Path.data(),
            static_cast<int>(utf8Path.size()), path.data(), needed);
        path = NtPathToDos(path);
    }
    const std::wstring cachedBefore = LookupPath(key);
    if (!path.empty()) CachePath(key, path);
    if (path.empty()) path = cachedBefore;
    if (task == KFT_NAME_CREATE) {
        if (!path.empty()) CachePath(key, path);
        return;
    }
    if (task == KFT_NAME_DELETE) {
        RemovePath(key);
        return;
    }

    std::string action;
    // Task 12 is a create/open-handle request and does not prove that a new
    // file was created. Task 30 is the provider's explicit create-new event.
    if (task == KFT_CREATE) action = "open";
    else if (task == KFT_CREATE_NEW) action = "create";
    else if (task == KFT_WRITE) action = "write";
    else if (task == KFT_DELETE_PATH) action = "delete";
    else if (task == KFT_RENAME_PATH || task == KFT_RENAME) action = "rename";
    else if (task == KFT_SET_INFO) action = "set_info";
    else if (task == KFT_CLOSE) action = "close";
    else return;

    std::wstring oldPath;
    if (action == "rename" && !cachedBefore.empty() &&
        _wcsicmp(cachedBefore.c_str(), path.c_str()) != 0)
        oldPath = NtPathToDos(cachedBefore);

    AppLogEvent output;
    output.kind = "file";
    output.source = "Kernel-File";
    output.event_id = std::to_string(task);
    output.timestamp = TimestampFromFiletime(event->EventHeader.TimeStamp);
    output.application = m_watchlist->NameForPID(pid);
    output.process_name = m_watchlist->ProcessNameForPID(pid);
    output.process_role = output.process_name == output.application
        ? "main_process" : "related_subprocess";
    output.parent_pid = m_watchlist->ParentPIDForPID(pid);
    output.application_root_pid = m_watchlist->RootPIDForPID(pid);
    output.action = action;
    output.path = WideToUtf8(path.empty() ? L"unresolved" : path);
    output.old_path = WideToUtf8(oldPath);
    output.pid = pid;
    output.tid = event->EventHeader.ThreadId;
    output.file_key = key;
    m_monitor->OnEventReceived(std::move(output));
    if (action == "delete") RemovePath(key);
}

void AppLogEtwCollector::HandlePowerShellEvent(PEVENT_RECORD event)
{
    if (event->EventHeader.EventDescriptor.Id != 4104 ||
        !IsPIDWatched(event->EventHeader.ProcessId))
        return;
    PropertySchema schema;
    if (!GetSchema(event, schema)) return;
    const std::string script = PropertyString(
        event, schema.info, L"ScriptBlockText");
    if (script.empty()) return;
    const std::string path = PropertyString(event, schema.info, L"Path");
    std::ostringstream xml;
    xml << "<Event><EventID>4104</EventID><EventData>"
        << "<Data Name=\"ScriptBlockText\">" << XmlEscape(script) << "</Data>"
        << "<Data Name=\"Path\">" << XmlEscape(path) << "</Data>"
        << "</EventData></Event>";
    AppLogEvent output;
    output.kind = "application_log";
    output.source = "PowerShell";
    output.event_id = "4104";
    output.timestamp = TimestampFromFiletime(event->EventHeader.TimeStamp);
    output.raw_data = xml.str();
    output.pid = event->EventHeader.ProcessId;
    output.tid = event->EventHeader.ThreadId;
    m_monitor->OnEventReceived(std::move(output));
}

void AppLogEtwCollector::HandleWmiEvent(PEVENT_RECORD event)
{
    const USHORT id = event->EventHeader.EventDescriptor.Id;
    if (id != 5859 && id != 5861) return;
    PropertySchema schema;
    if (!GetSchema(event, schema)) return;
    const std::string consumer = PropertyString(
        event, schema.info, L"CONSUMER");
    const std::string filter = PropertyString(event, schema.info, L"FILTER");
    const std::string operation = PropertyString(
        event, schema.info, L"Operation");
    const std::string query = PropertyString(event, schema.info, L"Query");
    std::ostringstream xml;
    xml << "<Event><EventID>" << id << "</EventID><EventData>"
        << "<Data Name=\"CONSUMER\">" << XmlEscape(consumer) << "</Data>"
        << "<Data Name=\"FILTER\">" << XmlEscape(filter) << "</Data>"
        << "<Data Name=\"Operation\">" << XmlEscape(operation) << "</Data>"
        << "<Data Name=\"Query\">" << XmlEscape(query) << "</Data>"
        << "</EventData></Event>";
    AppLogEvent output;
    output.kind = "application_log";
    output.source = "WMI";
    output.event_id = std::to_string(id);
    output.timestamp = TimestampFromFiletime(event->EventHeader.TimeStamp);
    output.raw_data = xml.str();
    output.pid = event->EventHeader.ProcessId;
    output.tid = event->EventHeader.ThreadId;
    m_monitor->OnEventReceived(std::move(output));
}

void AppLogEtwCollector::UpdatePIDFilter(
    const std::vector<DWORD>& activePIDs)
{
    std::unordered_set<DWORD> pids(activePIDs.begin(), activePIDs.end());
    std::unordered_map<DWORD, DWORD> threads;
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (Thread32First(snapshot, &entry)) {
            do {
                if (pids.contains(entry.th32OwnerProcessID))
                    threads.emplace(entry.th32ThreadID,
                        entry.th32OwnerProcessID);
            } while (Thread32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    AcquireSRWLockExclusive(&m_pidLock);
    m_watchedPIDs.swap(pids);
    m_watchedThreads.swap(threads);
    ReleaseSRWLockExclusive(&m_pidLock);
}

bool AppLogEtwCollector::IsPIDWatched(DWORD pid) const
{
    AcquireSRWLockShared(&m_pidLock);
    const bool watched = m_watchedPIDs.count(pid) != 0;
    ReleaseSRWLockShared(&m_pidLock);
    return watched;
}

DWORD AppLogEtwCollector::WatchedPIDForEvent(
    DWORD headerPID, DWORD headerTID) const
{
    AcquireSRWLockShared(&m_pidLock);
    DWORD pid = 0;
    if (m_watchedPIDs.contains(headerPID)) {
        pid = headerPID;
    } else {
        const auto found = m_watchedThreads.find(headerTID);
        if (found != m_watchedThreads.end()) pid = found->second;
    }
    ReleaseSRWLockShared(&m_pidLock);
    return pid;
}

std::string AppLogEtwCollector::TimestampFromFiletime(
    const LARGE_INTEGER& timestamp)
{
    FILETIME filetime{};
    filetime.dwLowDateTime = timestamp.LowPart;
    filetime.dwHighDateTime = static_cast<DWORD>(timestamp.HighPart);
    SYSTEMTIME system{};
    FileTimeToSystemTime(&filetime, &system);
    char value[40]{};
    sprintf_s(value, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        system.wYear, system.wMonth, system.wDay,
        system.wHour, system.wMinute, system.wSecond,
        system.wMilliseconds);
    return value;
}
