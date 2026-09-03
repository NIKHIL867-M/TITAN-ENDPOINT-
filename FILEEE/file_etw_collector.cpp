#include "file_etw_collector.h"

#include <tdh.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <deque>
#include <sstream>
#include <filesystem>
#include <unordered_map>
#include <mutex>
#include <cstring>  // memcpy

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

namespace titan::fim
{

    std::atomic<FileEtwCollector*> FileEtwCollector::instance_{ nullptr };

    static std::unordered_map<uint64_t, std::wstring> s_fileKeyCache;
    static std::deque<uint64_t>                        s_cacheOrder;
    static std::mutex                                  s_cacheMutex;
    // Busy systems can produce tens of thousands of Kernel-File callbacks per
    // second. Keep enough bounded FileKey history to join open/write/close.
    static constexpr size_t                            MAX_CACHE = 8192;

    static void CacheFilePath(uint64_t key, const std::wstring& path)
    {
        if (key == 0 || path.empty()) return;
        std::lock_guard<std::mutex> lock(s_cacheMutex);

        if (s_fileKeyCache.size() >= MAX_CACHE)
        {
            if (!s_cacheOrder.empty())
            {
                s_fileKeyCache.erase(s_cacheOrder.front());
                s_cacheOrder.pop_front();
            }
        }

        auto it = s_fileKeyCache.find(key);
        if (it != s_fileKeyCache.end())
        {
            it->second = path;
        }
        else
        {
            s_fileKeyCache[key] = path;
            s_cacheOrder.push_back(key);
        }
    }

    static std::wstring LookupFilePath(uint64_t key)
    {
        if (key == 0) return L"";
        std::lock_guard<std::mutex> lock(s_cacheMutex);
        auto it = s_fileKeyCache.find(key);
        return (it != s_fileKeyCache.end()) ? it->second : L"";
    }

    static void RemoveCachedPath(uint64_t key)
    {
        if (key == 0) return;
        std::lock_guard<std::mutex> lock(s_cacheMutex);

        auto dit = std::find(s_cacheOrder.begin(), s_cacheOrder.end(), key);
        if (dit != s_cacheOrder.end())
            s_cacheOrder.erase(dit);

        s_fileKeyCache.erase(key);
    }

    // =========================================================================
    // Constructor / Destructor
    // =========================================================================

    FileEtwCollector::FileEtwCollector(FileMonitor* monitor)
        : monitor_(monitor)
        , session_handle_(0)
        , trace_handle_(INVALID_PROCESSTRACE_HANDLE)
        , running_(false)
    {
        instance_.store(this, std::memory_order_release);
    }

    FileEtwCollector::~FileEtwCollector()
    {
        Stop();
        FileEtwCollector* expected = this;
        instance_.compare_exchange_strong(expected, nullptr, std::memory_order_acq_rel);
    }

    // =========================================================================
    // Start
    // =========================================================================
    bool FileEtwCollector::Start()
    {
        if (running_) return false;

        if (!CreateSession())
        {
            std::cerr << "[FIM][ETW] CreateSession failed\n";
            return false;
        }
        running_ = true;
        collector_thread_ = std::thread(&FileEtwCollector::CollectorThread, this);
        for (unsigned attempt = 0; attempt < 200 &&
            trace_handle_.load(std::memory_order_acquire) ==
            INVALID_PROCESSTRACE_HANDLE; ++attempt)
            Sleep(5);
        if (trace_handle_.load(std::memory_order_acquire) ==
            INVALID_PROCESSTRACE_HANDLE)
        {
            std::cerr << "[FIM][ETW] Consumer failed to open\n";
            Stop();
            return false;
        }
        if (!EnableProvider())
        {
            std::cerr << "[FIM][ETW] EnableProvider failed\n";
            Stop();
            return false;
        }
        std::cout << "[FIM][ETW] Collector started\n";
        return true;
    }

    // =========================================================================
    // Stop
    //
    // FIX 4: Correct shutdown order:
    //   1. running_ = false
    //   2. DisableProvider
    //   3. CloseTrace  (unblocks ProcessTrace)
    //   4. join()
    //   5. DestroySession
    // =========================================================================
    void FileEtwCollector::Stop()
    {
        if (!running_.exchange(false))
            return;

        if (session_handle_)
        {
            const ULONG name_size = static_cast<ULONG>(
                (wcslen(ETW_SESSION_NAME) + 1) * sizeof(wchar_t));
            const ULONG props_size =
                static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES)) + name_size;
            std::vector<BYTE> stats_buffer(props_size);
            auto* stats = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(
                stats_buffer.data());
            stats->Wnode.BufferSize = props_size;
            stats->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            if (ControlTraceW(session_handle_, ETW_SESSION_NAME, stats,
                EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS)
            {
                std::cout << "[FIM][ETW] Stats: buffers="
                    << stats->NumberOfBuffers << ", events_lost="
                    << stats->EventsLost << ", realtime_buffers_lost="
                    << stats->RealTimeBuffersLost << "\n";
                if (monitor_)
                    monitor_->ReportEtwLoss(stats->EventsLost,
                        stats->RealTimeBuffersLost);
            }
        }

        DisableProvider();

        TRACEHANDLE th = trace_handle_.exchange(INVALID_PROCESSTRACE_HANDLE);
        if (th != INVALID_PROCESSTRACE_HANDLE)
            CloseTrace(th);

        if (collector_thread_.joinable())
            collector_thread_.join();

        DestroySession();

        std::cout << "[FIM][ETW] Collector stopped (provider_events="
            << provider_events_received_.load() << ", callback_events="
            << callback_events_received_.load() << ", decoded_events="
            << events_decoded_.load() << ")\n";
    }

    // =========================================================================
    // CreateSession
    //
    // FIX 10: std::vector<BYTE>(props_size) — default zero-init, no int→BYTE
    //         narrowing. std::fill uses BYTE{} instead of 0 for the same reason.
    // =========================================================================
    bool FileEtwCollector::CreateSession()
    {
        const ULONG name_size = static_cast<ULONG>((wcslen(ETW_SESSION_NAME) + 1) * sizeof(wchar_t));
        const ULONG props_size = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES)) + name_size;

        // FIX 10: no fill value → default zero-init (trivial type, always zeros)
        auto MakeProps = [&](std::vector<BYTE>& buf) -> PEVENT_TRACE_PROPERTIES
            {
                // FIX 10: BYTE{} instead of 0 — avoids int → unsigned char narrowing
                std::fill(buf.begin(), buf.end(), BYTE{});
                auto* p = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buf.data());
                p->Wnode.BufferSize = props_size;
                p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
                p->Wnode.ClientContext = 1;   // QPC timestamps

                // Production-sized ETW pool: 64 KiB x 8-64. The previous
                // 1 MiB x 32-128 configuration could reserve excessive
                // kernel memory during a long-running endpoint session.
                p->BufferSize = 64;
                p->MinimumBuffers = 8;
                p->MaximumBuffers = 64;
                p->FlushTimer = 1;
                p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;

                p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
                memcpy(reinterpret_cast<BYTE*>(p) + p->LoggerNameOffset,
                    ETW_SESSION_NAME, name_size);
                return p;
            };

        // FIX 10: default-init → zero-filled without narrowing
        std::vector<BYTE> buf(props_size);
        auto* props = MakeProps(buf);
        ULONG status = StartTraceW(&session_handle_, ETW_SESSION_NAME, props);

        if (status == ERROR_ALREADY_EXISTS)
        {
            std::cout << "[FIM][ETW] Stopping stale session...\n";
            ControlTraceW(0, ETW_SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
            props = MakeProps(buf);
            status = StartTraceW(&session_handle_, ETW_SESSION_NAME, props);
        }

        if (status != ERROR_SUCCESS)
        {
            std::cerr << "[FIM][ETW] StartTrace failed: " << status << "\n";
            if (status == ERROR_ACCESS_DENIED)
                std::cerr << "[FIM][ETW] Run as Administrator!\n";
            return false;
        }

        std::cout << "[FIM][ETW] Session created (real-time, 64 KiB x 8-64 buffers)\n";
        return true;
    }

    // =========================================================================
    // DestroySession
    //
    // FIX 5: Zero session_handle_ before calling ControlTraceW.
    // FIX 10: std::vector<BYTE>(props_size) — default zero-init.
    // =========================================================================
    void FileEtwCollector::DestroySession()
    {
        TRACEHANDLE h = session_handle_;
        session_handle_ = 0;
        if (h == 0) return;

        const ULONG name_size = static_cast<ULONG>((wcslen(ETW_SESSION_NAME) + 1) * sizeof(wchar_t));
        const ULONG props_size = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES)) + name_size;

        // FIX 10: default zero-init — no narrowing warning
        std::vector<BYTE> buf(props_size);
        auto* props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buf.data());
        props->Wnode.BufferSize = props_size;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ControlTraceW(h, ETW_SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
    }

    // =========================================================================
    // EnableProvider — keywords = all except READ (0xFEFF)
    // =========================================================================
    bool FileEtwCollector::EnableProvider()
    {
        const ULONGLONG keywords = 0xFEFF;   // bit 8 = Read, excluded

        ENABLE_TRACE_PARAMETERS params = {};
        params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

        ULONG status = EnableTraceEx2(
            session_handle_,
            &KERNEL_FILE_PROVIDER_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE,
            keywords, 0, 0,
            &params
        );

        if (status != ERROR_SUCCESS)
        {
            std::cerr << "[FIM][ETW] EnableTraceEx2 failed: " << status << "\n";
            return false;
        }

        std::cout << "[FIM][ETW] Kernel-File provider enabled (keywords=0xFEFF, READ excluded)\n";
        return true;
    }

    void FileEtwCollector::DisableProvider()
    {
        if (!session_handle_) return;
        EnableTraceEx2(
            session_handle_,
            &KERNEL_FILE_PROVIDER_GUID,
            EVENT_CONTROL_CODE_DISABLE_PROVIDER,
            0, 0, 0, 0, nullptr
        );
    }

    // =========================================================================
    // CollectorThread
    //
    // FIX 9: Write trace_handle_ atomically so Stop() can read it safely.
    // =========================================================================
    void FileEtwCollector::CollectorThread()
    {
        // Keep the real-time consumer responsive during CPU pressure. This is
        // deliberately ABOVE_NORMAL, not a real-time priority class.
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

        EVENT_TRACE_LOGFILEW trace = {};
        trace.LoggerName = const_cast<LPWSTR>(ETW_SESSION_NAME);
        trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD
            | PROCESS_TRACE_MODE_REAL_TIME;
        trace.EventRecordCallback = EventRecordCallback;
        trace.BufferCallback = BufferCallback;

        TRACEHANDLE th = OpenTraceW(&trace);
        if (th == INVALID_PROCESSTRACE_HANDLE)
        {
            std::cerr << "[FIM][ETW] OpenTrace failed: " << GetLastError() << "\n";
            return;
        }

        trace_handle_.store(th, std::memory_order_release);

        std::cout << "[FIM][ETW] ProcessTrace running\n";
        ULONG status = ProcessTrace(&th, 1, nullptr, nullptr);

        if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
            std::cerr << "[FIM][ETW] ProcessTrace ended: " << status << "\n";
        else
            std::cout << "[FIM][ETW] ProcessTrace ended: " << status << "\n";
    }

    // =========================================================================
    // BufferCallback
    // =========================================================================
    ULONG WINAPI FileEtwCollector::BufferCallback(PEVENT_TRACE_LOGFILEW logfile)
    {
        FileEtwCollector* inst = instance_.load(std::memory_order_acquire);
        if (!inst) return FALSE;
        if (logfile && inst->monitor_)
            inst->monitor_->ReportEtwLoss(logfile->EventsLost, 0);
        return inst->running_.load() ? TRUE : FALSE;
    }

    // =========================================================================
    // EventRecordCallback
    //
    // FIX 8: Filter by provider GUID first to avoid TDH decode on noise.
    // =========================================================================
    VOID WINAPI FileEtwCollector::EventRecordCallback(PEVENT_RECORD event_record)
    {
        if (!event_record) return;

        FileEtwCollector* inst = instance_.load(std::memory_order_acquire);
        if (!inst || !inst->monitor_ || !inst->running_.load()) return;

        inst->callback_events_received_.fetch_add(1,
            std::memory_order_relaxed);
        if (!IsEqualGUID(event_record->EventHeader.ProviderId, KERNEL_FILE_PROVIDER_GUID))
            return;

        inst->provider_events_received_.fetch_add(1,
            std::memory_order_relaxed);
        try
        {
            FileEvent event;
            if (!DecodeEvent(event_record, event)) return;
            inst->events_decoded_.fetch_add(1,
                std::memory_order_relaxed);
            inst->monitor_->SubmitEvent(event);
        }
        catch (...) {}
    }

    // =========================================================================
    // DecodeEvent
    // =========================================================================
    bool FileEtwCollector::DecodeEvent(
        PEVENT_RECORD event_record,
        FileEvent& out_event)
    {
        if (!event_record) return false;

        out_event.pid = event_record->EventHeader.ProcessId;
        out_event.tid = event_record->EventHeader.ThreadId;
        out_event.creator_pid = out_event.pid;
        out_event.timestamp = std::chrono::system_clock::now();
        out_event.process_name = L"";

        const USHORT task = event_record->EventHeader.EventDescriptor.Task;
        out_event.action = TaskToAction(task);

        if (out_event.action == FileAction::READ &&
            task != KFT_NAME_CREATE && task != KFT_NAME_DELETE &&
            task != KFT_CREATE)
            return false;

        // ===== TDH: GET EVENT SCHEMA =====
        ULONG size = 0;
        ULONG tdh_ret = TdhGetEventInformation(event_record, 0, nullptr, nullptr, &size);

        if (tdh_ret != ERROR_INSUFFICIENT_BUFFER || size == 0)
        {
            out_event.path = L"unresolved";
            return true;
        }

        // FIX 10: default zero-init — no narrowing
        std::vector<BYTE> buffer(size);
        auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.data());

        if (TdhGetEventInformation(event_record, 0, nullptr, info, &size) != ERROR_SUCCESS)
        {
            out_event.path = L"unresolved";
            return true;
        }

        // ===== EXTRACT PATH =====
        std::wstring path;
        std::wstring tmp;

        if (GetEventPropertyString(event_record, info, L"FileName", tmp)) path = tmp;
        else if (GetEventPropertyString(event_record, info, L"OpenPath", tmp)) path = tmp;
        else if (GetEventPropertyString(event_record, info, L"FilePath", tmp)) path = tmp;

        // ===== FILE KEY =====
        ULONGLONG key = 0;
        if (!GetEventPropertyUlonglong(event_record, info, L"FileKey", key))
            GetEventPropertyUlonglong(event_record, info, L"FileObject", key);

        out_event.file_key = key;
        const std::wstring cached_before = LookupFilePath(key);

        // ===== PATH RESOLUTION =====
        if (!path.empty())
        {
            out_event.path = path;
            CacheFilePath(key, path);
        }
        else
        {
            out_event.path = !cached_before.empty()
                ? cached_before : L"unresolved";
        }

        // NameCreate/NameDelete are provider bookkeeping events used only to
        // maintain FileKey -> path resolution. They are not file operations.
        if (task == KFT_NAME_CREATE)
        {
            CacheFilePath(key, path);
            return false;
        }
        if (task == KFT_NAME_DELETE)
        {
            RemoveCachedPath(key);
            return false;
        }
        if (task == KFT_CREATE)
            return false;

        // ===== RENAME SUPPORT (FIX 2) =====
        if (out_event.action == FileAction::RENAME)
        {
            if (!cached_before.empty() &&
                ToLower(cached_before) != ToLower(out_event.path))
                out_event.old_path = cached_before;

            std::wstring new_name;
            if (GetEventPropertyString(event_record, info, L"NewFileName", new_name)
                && !new_name.empty())
            {
                if (out_event.old_path.empty())
                    out_event.old_path = out_event.path;
                out_event.path = new_name;
                CacheFilePath(key, new_name);
            }
        }

        // ===== CACHE EVICTION (FIX 3) =====
        if (out_event.action == FileAction::DELETE_F && key != 0)
            RemoveCachedPath(key);

        return true;
    }

    // =========================================================================
    // GetEventPropertyString
    //
    // FIX 6:  memcpy into aligned wchar_t buffer instead of reinterpret_cast.
    // FIX 10: std::vector<BYTE> raw(prop_size + sizeof(wchar_t)) — no narrowing.
    // =========================================================================
    bool FileEtwCollector::GetEventPropertyString(
        PEVENT_RECORD     event_record,
        PTRACE_EVENT_INFO info,
        const wchar_t* property_name,
        std::wstring& out_value)
    {
        if (!info || !property_name) return false;

        for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
        {
            const auto& prop = info->EventPropertyInfoArray[i];
            const wchar_t* actual_name =
                reinterpret_cast<const wchar_t*>(
                    reinterpret_cast<const BYTE*>(info) + prop.NameOffset);

            if (_wcsicmp(actual_name, property_name) != 0) continue;

            PROPERTY_DATA_DESCRIPTOR desc{};
            desc.PropertyName = reinterpret_cast<ULONGLONG>(actual_name);
            desc.ArrayIndex = ULONG_MAX;

            ULONG prop_size = 0;
            if (TdhGetPropertySize(event_record, 0, nullptr, 1, &desc, &prop_size)
                != ERROR_SUCCESS || prop_size == 0)
                return false;

            // FIX 10: default zero-init — no int→BYTE narrowing
            std::vector<BYTE> raw(static_cast<size_t>(prop_size) + sizeof(wchar_t));

            if (TdhGetProperty(event_record, 0, nullptr, 1, &desc,
                prop_size, raw.data()) != ERROR_SUCCESS)
                return false;

            // FIX 6: properly aligned wchar_t copy via memcpy
            size_t wchar_count = prop_size / sizeof(wchar_t);
            std::vector<wchar_t> wbuf(wchar_count + 1, L'\0');
            memcpy(wbuf.data(), raw.data(), prop_size);

            out_value = std::wstring(wbuf.data());
            return !out_value.empty();
        }

        return false;
    }

    // =========================================================================
    // GetEventPropertyUlonglong
    //
    // FIX 7:  memcpy instead of pointer cast.
    // FIX 10: std::vector<BYTE> raw(prop_size) — no int→BYTE narrowing.
    // =========================================================================
    bool FileEtwCollector::GetEventPropertyUlonglong(
        PEVENT_RECORD     event_record,
        PTRACE_EVENT_INFO info,
        const wchar_t* property_name,
        ULONGLONG& out_value)
    {
        if (!info || !property_name) return false;

        for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
        {
            const auto& prop = info->EventPropertyInfoArray[i];
            const wchar_t* actual_name =
                reinterpret_cast<const wchar_t*>(
                    reinterpret_cast<const BYTE*>(info) + prop.NameOffset);

            if (_wcsicmp(actual_name, property_name) != 0) continue;

            PROPERTY_DATA_DESCRIPTOR desc{};
            desc.PropertyName = reinterpret_cast<ULONGLONG>(actual_name);
            desc.ArrayIndex = ULONG_MAX;

            ULONG prop_size = 0;
            if (TdhGetPropertySize(event_record, 0, nullptr, 1, &desc, &prop_size)
                != ERROR_SUCCESS || prop_size < sizeof(ULONGLONG))
                return false;

            // FIX 10: default zero-init — no int→BYTE narrowing
            std::vector<BYTE> raw(prop_size);
            if (TdhGetProperty(event_record, 0, nullptr, 1, &desc,
                prop_size, raw.data()) != ERROR_SUCCESS)
                return false;

            // FIX 7: memcpy instead of pointer cast
            ULONGLONG value = 0;
            memcpy(&value, raw.data(), sizeof(ULONGLONG));
            out_value = value;
            return true;
        }

        return false;
    }

    // =========================================================================
    // TaskToAction
    // This provider emits opcode 0 and identifies operations by Task.
    // =========================================================================
    FileAction FileEtwCollector::TaskToAction(USHORT task)
    {
        switch (task)
        {
        case KFT_CREATE_NEW:  return FileAction::CREATE;
        case KFT_WRITE:       return FileAction::WRITE;
        case KFT_CLOSE:
        case KFT_CLEANUP:     return FileAction::CLOSE;
        case KFT_DELETE_PATH: return FileAction::DELETE_F;
        case KFT_RENAME_PATH: return FileAction::RENAME;
        case KFT_SET_INFO:    return FileAction::SET_INFO;
        case KFT_READ:
        default:              return FileAction::READ;
        }
    }

} // namespace titan::fim
