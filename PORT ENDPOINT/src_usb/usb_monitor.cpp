// usb_monitor.cpp
#include "usb_monitor.h"
#include "usb_kernel_listener.h"
#include "usb_session_manager.h"
#include "usb_identity.h"
#include "usb_logger.h"
#include "usb_watcher.h"
#include "usb_hid_guard.h"
#include "evidence_envelope.h"

#ifndef WIN32_LEAN_AND_MEAN
#   define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <thread>

static void LogErrorToConsole(const std::string& msg) {
    std::cerr << "[UsbMonitor] ERROR: " << msg << '\n';
}

// RFC 8259 JSON string escaping -- device-supplied strings (manufacturer,
// product, instance ID) come straight from USB descriptors, which a
// malicious/spoofed device fully controls. Without escaping, a device could
// inject '"' or control characters to corrupt or forge JSON log entries.
static std::string EscapeJsonString(const std::string& s)
{
    std::ostringstream o;
    for (unsigned char c : s) {
        switch (c) {
        case '"':  o << "\\\""; break;
        case '\\': o << "\\\\"; break;
        case '\b': o << "\\b";  break;
        case '\f': o << "\\f";  break;
        case '\n': o << "\\n";  break;
        case '\r': o << "\\r";  break;
        case '\t': o << "\\t";  break;
        default:
            if (c < 0x20u) {
                o << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<unsigned>(c) << std::dec;
            }
            else {
                o << c;
            }
        }
    }
    return o.str();
}

// UTC ISO-8601 timestamp with millisecond precision -- matches the format
// UsbSession::Finalize() uses, so all usb_monitor JSON record types share
// one timestamp convention.
static std::string GetCurrentTimeISO()
{
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &tt);
#else
    gmtime_r(&tt, &utc);
#endif
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    std::ostringstream ss;
    ss << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S")
        << '.' << std::setw(3) << std::setfill('0') << ms.count() << 'Z';
    return ss.str();
}

// UTC epoch milliseconds -- shared join key for a future cross-endpoint
// Correlator (see usb_session.cpp's CurrentUnixMs() for the same helper).
static int64_t CurrentUnixMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// ─────────────────────────────────────────────────────────────────────────────
// SessionKeyFor
//
// Computes the same key that UsbSessionManager::CreateSession() will store
// internally so that OnDeviceRemoved can look up the right session.
//
// Rules (must stay in sync with UsbSessionManager::CreateSession):
//   1. If the device has a non-empty serial number, use the serial.
//   2. Otherwise use "VID:PID:suffix" where suffix is the last segment of
//      the instance ID (unique per USB port, stable across plug cycles on the
//      same port).  This avoids collisions when multiple identical no-serial
//      devices are plugged into different ports simultaneously.
// ─────────────────────────────────────────────────────────────────────────────
static std::string SessionKeyFor(const UsbIdentity& identity)
{
    if (!identity.serialNumber.empty())
        return identity.serialNumber;

    // Derive a port-unique suffix from the instance ID tail.
    // e.g. "USB\VID_1BCF&PID_08A0\5&2AD35BE9&0&1" → suffix "5&2AD35BE9&0&1"
    std::string suffix;
    size_t lastSlash = identity.instanceId.find_last_of('\\');
    if (lastSlash != std::string::npos && lastSlash + 1 < identity.instanceId.size())
        suffix = identity.instanceId.substr(lastSlash + 1);

    return identity.vid + ":" + identity.pid + ":" + suffix;
}

// ─────────────────────────────────────────────────────────────────────────────
UsbMonitor::UsbMonitor()
    : m_listener(std::make_unique<UsbKernelListener>(this))
    , m_sessionManager(std::make_unique<UsbSessionManager>())
{
}

UsbMonitor::~UsbMonitor() {
    Stop();
}

bool UsbMonitor::Start() {
    if (!m_listener->Start()) {
        LogError("Failed to start USB kernel listener.");
        return false;
    }
    m_pressureThreadRunning.store(true);
    m_pressureThread = std::thread(&UsbMonitor::PressureTickerLoop, this);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stop
//
// Join all live arrival threads first.  Those threads may be in the middle of
// the drive-letter retry loop when Stop() is called; we must wait for them to
// finish before destroying m_sessionManager and m_listener, otherwise they
// would access freed objects.
// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::Stop() {
    // 0. Stop the pressure ticker first -- cheap, independent of everything else.
    if (m_pressureThreadRunning.exchange(false) && m_pressureThread.joinable())
        m_pressureThread.join();

    // 1. Collect all joinable arrival threads under the lock, then release
    //    the lock before joining so the threads can still acquire it if needed.
    std::vector<std::thread> toJoin;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& t : m_arrivalThreads)
            if (t.joinable()) toJoin.push_back(std::move(t));
        m_arrivalThreads.clear();
    }
    for (auto& t : toJoin)
        t.join();

    // 2. Stop all active file watchers.
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& [serial, watcher] : m_watchers)
            watcher->Stop();
        m_watchers.clear();
    }

    // 3. Stop the kernel listener last.
    if (m_listener) m_listener->Stop();

    // 4. Emit a final collector_health record so a clean shutdown always
    //    leaves an unambiguous evidence trail (matches the pattern already
    //    proven in the File/Network endpoints).
    EmitHealthRecord(/*final=*/true);
}

// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::OnFileEvent(const std::string& deviceSerial,
    const std::string& operation,
    const std::string& filePath,
    uint64_t           size)
{
    // FORU.TXT section 4.3/4.4: Monitoring OFF stops new collection entirely.
    if (!m_monitoringEnabled.load(std::memory_order_relaxed)) return;
    if (m_sessionManager)
        m_sessionManager->OnFileEvent(deviceSerial, operation, filePath, size);
}

// ─────────────────────────────────────────────────────────────────────────────
// OnDeviceArrived  (called on the Win32 message thread)
//
// FIX: Previously this function ran the entire drive-letter retry loop
// (up to 10 × 500 ms = 5 seconds) directly on the Win32 message thread.
// While blocked there, no other WM_DEVICECHANGE messages could be dispatched
// — meaning a second device arriving simultaneously would be invisible until
// the first device's retry loop completed.
//
// Fix: Immediately spawn a worker thread (HandleArrival) and return.  The
// message loop stays responsive.  The worker thread is stored in
// m_arrivalThreads and joined in Stop() to prevent use-after-free.
// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::OnDeviceArrived(const std::string& devicePath) {
    // FORU.TXT section 4.3/4.4: Monitoring OFF stops new collection entirely.
    if (!m_monitoringEnabled.load(std::memory_order_relaxed)) return;
    std::cout << "[UsbMonitor] Device arrival detected: " << devicePath << '\n';

    std::lock_guard<std::mutex> lock(m_mutex);

    // Prune any already-finished arrival threads before adding a new one.
    m_arrivalThreads.erase(
        std::remove_if(m_arrivalThreads.begin(), m_arrivalThreads.end(),
            [](std::thread& t) { return !t.joinable(); }),
        m_arrivalThreads.end());

    m_arrivalThreads.emplace_back(&UsbMonitor::HandleArrival, this, devicePath);
}

// ─────────────────────────────────────────────────────────────────────────────
// HandleArrival  (runs on a dedicated worker thread per arrival event)
//
// All the work that was previously done inline in OnDeviceArrived now lives
// here.  The drive-letter retry loop blocking is harmless on this thread.
// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::HandleArrival(std::string devicePath)
{
    // 1. Resolve identity.
    UsbIdentity identity;
    if (!ResolveDeviceIdentity(devicePath, identity)) {
        // Non-storage interfaces (HID, audio) often fail here — not an error.
        std::cout << "[UsbMonitor] Skipping (cannot resolve identity): "
            << devicePath << '\n';
        return;
    }

    std::cout << "[UsbMonitor] Identity resolved:"
        << " VID=" << identity.vid
        << " PID=" << identity.pid
        << " Serial=" << identity.serialNumber
        << " InstanceId=" << identity.instanceId << '\n';

    // 2. Quick sanity check — must be a USB bus device.
    if (identity.instanceId.find("USB") == std::string::npos) {
        std::cout << "[UsbMonitor] Skipping (not USB): "
            << identity.instanceId << '\n';
        return;
    }

    // 3. Check whether this is a storage device by walking PnP children.
    //    IsStorageDevice() now correctly walks the child chain of the USB
    //    interface node instead of checking the node itself (which is class
    //    "USB", not "DiskDrive").
    //
    //    FIX: Previously every non-storage device (webcams, keyboards, audio
    //    dongles) was discarded here without further inspection — meaning a
    //    BadUSB / Rubber-Ducky-style keystroke-injection device, which
    //    enumerates as a HID keyboard, was invisible to this agent entirely.
    //    We now branch: HID-keyboard-capable devices get routed into the
    //    keystroke-timing observation path instead of being dropped.
    if (!IsStorageDevice(identity)) {
        if (IsHidKeyboardDevice(identity)) {
            std::cout << "[UsbMonitor] HID keyboard device detected -- routing to "
                "keystroke-timing observation: " << identity.instanceId << '\n';
            HandleHidArrival(devicePath, identity);
        }
        else {
            // FIX (Round 22): previously every non-storage, non-HID-keyboard device (mouse, webcam,
            // audio dongle, etc.) was dropped here with only a console line -- invisible to the GUI
            // entirely, even though a real device genuinely connected. Santosh: "connected the mouse
            // but it is not showing anything in that." No session/mount-point tracking makes sense
            // for these (nothing to watch), but a real connect/disconnect record does.
            std::cout << "[UsbMonitor] Non-storage, non-keyboard device detected (logging only): "
                << identity.instanceId << '\n';
            std::ostringstream j;
            j << "{\"timestamp\":\"" << GetCurrentTimeISO()
                << "\",\"t_unix_ms\":" << CurrentUnixMs()
                << ",\"endpoint\":\"usb_monitor\",\"type\":\"usb_device_detected\","
                << "\"event_type\":\"USB_DEVICE_ARRIVED\","
                << "\"device\":{\"vid\":\"" << EscapeJsonString(identity.vid)
                << "\",\"pid\":\"" << EscapeJsonString(identity.pid)
                << "\",\"serial\":\"" << EscapeJsonString(identity.serialNumber)
                << "\",\"manufacturer\":\"" << EscapeJsonString(identity.manufacturer)
                << "\",\"product\":\"" << EscapeJsonString(identity.product)
                << "\",\"instance_id\":\"" << EscapeJsonString(identity.instanceId)
                << "\"}}";
            UsbLogger::Log(j.str());
        }
        return;
    }

    // 4. Find mount point — retry loop because Windows assigns the drive
    //    letter asynchronously after the USB interface arrives.
    //    Running on a worker thread so this delay is harmless.
    std::vector<std::string> mountPoints;
    constexpr int   kMaxRetries = 10;
    constexpr DWORD kRetryMs = 500;

    for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
        if (attempt > 0) {
            std::cout << "[UsbMonitor] Waiting for drive letter... (attempt "
                << (attempt + 1) << "/" << kMaxRetries << ")\n";
            Sleep(kRetryMs);
        }
        GetMountPointsForDevice(devicePath, mountPoints);
        if (!mountPoints.empty()) break;
    }

    if (mountPoints.empty()) {
        std::cout << "[UsbMonitor] No drive letter found after retries -- skipping.\n";
        return;
    }

    const std::string& mountPoint = mountPoints[0];
    std::cout << "[UsbMonitor] Mount point: " << mountPoint << '\n';

    // 5. Compute the session key — MUST use the same logic as
    //    UsbSessionManager::CreateSession() so OnDeviceRemoved can find the
    //    session by looking up the key stored in m_deviceSerialMap.
    //
    //    FIX: Previously we stored identity.serialNumber (which is "" when the
    //    device has no serial) in m_deviceSerialMap, but CreateSession used a
    //    "VID:PID" fallback key.  EndSession("") then found no session.
    const std::string sessionKey = SessionKeyFor(identity);

    // 6. Cache devicePath -> session key for OnDeviceRemoved.
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Guard: if the device arrived twice (e.g. hot-plug race), skip.
        if (m_deviceSerialMap.count(devicePath)) {
            std::cout << "[UsbMonitor] Session already exists for: "
                << devicePath << " -- skipping duplicate arrival.\n";
            return;
        }
        EvictOldestDeviceMappingIfFull();
        m_deviceSerialMap[devicePath] = sessionKey;
        m_deviceSerialOrder.push_back(devicePath);
    }

    // 7. Create session.
    std::string createdSessionId;
    if (!m_sessionManager->CreateSession(identity, mountPoint, &createdSessionId)) {
        LogError("Failed to create session for device: " + devicePath);
        std::lock_guard<std::mutex> lock(m_mutex);
        m_deviceSerialMap.erase(devicePath);
        m_deviceSerialOrder.erase(
            std::remove(m_deviceSerialOrder.begin(), m_deviceSerialOrder.end(), devicePath),
            m_deviceSerialOrder.end());
        return;
    }

    // Emit an immediate lifecycle record after the unique session has been created.
    // Previously storage devices were invisible in JSON until removal/finalization,
    // which prevented the operator UI from truthfully showing a live connection.
    {
        std::ostringstream j;
        j << "{\"timestamp\":\"" << GetCurrentTimeISO()
            << "\",\"t_unix_ms\":" << CurrentUnixMs()
            << ",\"endpoint\":\"usb_monitor\",\"type\":\"usb_session_start\"," 
            << "\"event_type\":\"USB_DEVICE_ARRIVED\"," 
            << "\"session_id\":\"" << EscapeJsonString(createdSessionId) << "\"," 
            << "\"mount_point\":\"" << EscapeJsonString(mountPoint) << "\"," 
            << "\"device\":{\"vid\":\"" << EscapeJsonString(identity.vid)
            << "\",\"pid\":\"" << EscapeJsonString(identity.pid)
            << "\",\"serial\":\"" << EscapeJsonString(identity.serialNumber)
            << "\",\"manufacturer\":\"" << EscapeJsonString(identity.manufacturer)
            << "\",\"product\":\"" << EscapeJsonString(identity.product)
            << "\",\"instance_id\":\"" << EscapeJsonString(identity.instanceId)
            << "\"}}";
        UsbLogger::Log(j.str());
    }

    // 8. Start file watcher.
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto watcher = std::make_unique<UsbWatcher>(
            mountPoint, sessionKey, this);
        watcher->Start();
        m_watchers[sessionKey] = std::move(watcher);
    }

    std::cout << "[UsbMonitor] Session started:"
        << " VID=" << identity.vid
        << " PID=" << identity.pid
        << " Key=" << sessionKey
        << " Mount=" << mountPoint << '\n';
}

// ─────────────────────────────────────────────────────────────────────────────
// OnDeviceRemoved  (called on the Win32 message thread)
//
// Removal processing is fast (no blocking I/O, no retry loop) so it is safe
// to run directly on the message thread.
// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::OnDeviceRemoved(const std::string& devicePath) {

    std::cout << "[UsbMonitor] Device removal detected: " << devicePath << '\n';

    std::string sessionKey;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_deviceSerialMap.find(devicePath);
        if (it == m_deviceSerialMap.end()) {
            // Was never a tracked storage device (webcam, keyboard, etc.)
            // or HandleArrival is still in the retry loop — ignore silently.
            return;
        }
        sessionKey = it->second;
        m_deviceSerialMap.erase(it);
        m_deviceSerialOrder.erase(
            std::remove(m_deviceSerialOrder.begin(), m_deviceSerialOrder.end(), devicePath),
            m_deviceSerialOrder.end());

        // Stop watcher BEFORE ending session — prevents use-after-free.
        auto wit = m_watchers.find(sessionKey);
        if (wit != m_watchers.end()) {
            wit->second->Stop();
            m_watchers.erase(wit);
        }
    }

    if (!m_sessionManager->EndSession(sessionKey)) {
        LogError("Failed to end session for key: " + sessionKey);
        return;
    }

    std::cout << "[UsbMonitor] Session ended and logged: Key=" << sessionKey << '\n';
}

// ─────────────────────────────────────────────────────────────────────────────
// HandleHidArrival  (runs on the same per-arrival worker thread as
// HandleArrival -- already off the Win32 message thread, so blocking here
// for the observation window is harmless, exactly like the storage
// drive-letter retry loop above.)
//
// Resolves the raw-input device handle for this specific arrival, then
// blocks (in short polling increments so Stop() ordering stays simple) until
// either the observation window elapses or the sample cap is hit. Emits:
//   usb_hid_event      -- always, on arrival (telemetry: a HID keyboard-
//                          capable device was seen).
//   usb_injection_alert -- always, after the observation window, carrying
//                          full timing evidence (hid_injection_suspected is
//                          never reported as a bare boolean).
// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::HandleHidArrival(std::string devicePath, UsbIdentity identity)
{
    auto guard = std::make_shared<HidInjectionGuard>(
        identity.vid, identity.pid, identity.instanceId);
    bool resolved = guard->ResolveDeviceHandle();

    {
        std::lock_guard<std::mutex> lock(m_hidMutex);
        m_hidGuards[devicePath] = guard;
    }

    // -- usb_hid_event: arrival telemetry, emitted immediately.
    {
        std::ostringstream j;
        j << "{\"timestamp\":\"" << GetCurrentTimeISO()
            << "\",\"t_unix_ms\":" << CurrentUnixMs()
            << ",\"endpoint\":\"usb_monitor\",\"type\":\"usb_hid_event\","
            << "\"event_type\":\"USB_HID_KEYBOARD_ARRIVED\","
            << "\"vid\":\"" << EscapeJsonString(identity.vid) << "\","
            << "\"pid\":\"" << EscapeJsonString(identity.pid) << "\","
            << "\"manufacturer\":\"" << EscapeJsonString(identity.manufacturer) << "\","
            << "\"product\":\"" << EscapeJsonString(identity.product) << "\","
            << "\"instance_id\":\"" << EscapeJsonString(identity.instanceId) << "\","
            << "\"raw_input_resolved\":" << (resolved ? "true" : "false") << "}";
        UsbLogger::Log(j.str());
    }

    if (!resolved) {
        std::cout << "[UsbMonitor] Could not resolve raw-input handle for HID device "
            "(no keystroke evidence collected): " << identity.instanceId << '\n';
    }
    else {
        // Poll until the window elapses or the sample cap is hit. 100ms
        // granularity is more than enough for a 5-second window and keeps
        // this worker thread cheap.
        while (!guard->IsDone()) {
            Sleep(100);
        }
    }

    KeystrokeTimingResult result = guard->Evaluate();

    {
        std::ostringstream j;
        j << "{\"timestamp\":\"" << GetCurrentTimeISO()
            << "\",\"t_unix_ms\":" << CurrentUnixMs()
            << ",\"endpoint\":\"usb_monitor\",\"type\":\"usb_injection_alert\","
            << "\"vid\":\"" << EscapeJsonString(identity.vid) << "\","
            << "\"pid\":\"" << EscapeJsonString(identity.pid) << "\","
            << "\"instance_id\":\"" << EscapeJsonString(identity.instanceId) << "\","
            << "\"hid_injection_suspected\":" << (result.suspected ? "true" : "false") << ","
            << "\"sample_count\":" << result.sampleCount << ","
            << "\"mean_interval_ms\":" << result.meanIntervalMs << ","
            << "\"stddev_interval_ms\":" << result.stddevIntervalMs << ","
            << "\"min_interval_ms\":" << result.minIntervalMs << "}";
        UsbLogger::Log(j.str());
    }

    if (result.suspected) {
        std::cout << "[UsbMonitor] *** HID KEYSTROKE-INJECTION SUSPECTED *** VID="
            << identity.vid << " PID=" << identity.pid
            << " mean=" << result.meanIntervalMs << "ms stddev="
            << result.stddevIntervalMs << "ms (n=" << result.sampleCount << ")\n";
    }

    // Clean up -- guard's observation window is over.
    {
        std::lock_guard<std::mutex> lock(m_hidMutex);
        m_hidGuards.erase(devicePath);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::OnHidKeyEvent(void* hDeviceHandle)
{
    // FORU.TXT section 4.3/4.4: Monitoring OFF stops new collection entirely.
    if (!m_monitoringEnabled.load(std::memory_order_relaxed)) return;
    HANDLE hDevice = static_cast<HANDLE>(hDeviceHandle);

    // Snapshot the active guards under the lock, then call out to them
    // without holding it -- OnKeyDown() only takes the guard's own mutex.
    std::vector<std::shared_ptr<HidInjectionGuard>> guards;
    {
        std::lock_guard<std::mutex> lock(m_hidMutex);
        guards.reserve(m_hidGuards.size());
        for (auto& kv : m_hidGuards) guards.push_back(kv.second);
    }
    for (auto& g : guards) g->OnKeyDown(hDevice);
}

// ─────────────────────────────────────────────────────────────────────────────
// EvictOldestDeviceMappingIfFull  -- mutex must be held by caller
//
// Backstop against unbounded growth of m_deviceSerialMap: under normal
// operation every arrival is matched by a removal that erases its entry, but
// a missed WM_DEVICECHANGE removal notification (rare, but possible under
// driver/OS quirks) would otherwise leak the mapping for the lifetime of the
// agent. This caps worst-case growth at kMaxTrackedDevices regardless.
// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::EvictOldestDeviceMappingIfFull()
{
    while (m_deviceSerialOrder.size() >= kMaxTrackedDevices) {
        const std::string& oldest = m_deviceSerialOrder.front();
        m_deviceSerialMap.erase(oldest);
        m_deviceSerialOrder.pop_front();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::ReportWatcherOverflow(const std::string& mountPoint)
{
    m_watcherOverflowCount.fetch_add(1, std::memory_order_relaxed);
    std::cerr << "[UsbMonitor] ReadDirectoryChangesW buffer overflow on '"
        << mountPoint << "' -- events dropped (total overflow count="
        << m_watcherOverflowCount.load() << ")\n";
    EmitHealthRecord(/*final=*/false);
}

// ─────────────────────────────────────────────────────────────────────────────
// EmitHealthRecord
//
// Rate-limited to once per 5 seconds for non-final records (mirrors the
// throttling pattern already proven in the File endpoint) so a sustained
// burst of overflows cannot spam the log. final=true always emits, exactly
// once (guarded by m_healthFinalEmitted).
// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::EmitHealthRecord(bool final)
{
    std::lock_guard<std::mutex> lock(m_healthMutex);

    if (final && m_healthFinalEmitted) return;

    auto now = std::chrono::steady_clock::now();
    if (!final && m_lastHealthLog.time_since_epoch().count() != 0 &&
        now - m_lastHealthLog < std::chrono::seconds(5))
        return;

    uint64_t overflowCount = m_watcherOverflowCount.load();
    bool degraded = overflowCount != 0;

    const auto [retainedBytes, retainedFiles] = UsbLogger::GetRetainedBytesAndFiles();
    static const std::string executableHash = ComputeSelfExecutableSha256();
    const int64_t nowMs = CurrentUnixMs();

    std::ostringstream j;
    j << "{\"timestamp\":\"" << GetCurrentTimeISO() << "\","
        << "\"t_unix_ms\":" << nowMs << ","
        << "\"endpoint\":\"usb_monitor\",\"type\":\"collector_health\","
        << "\"schema_version\":2,"
        << "\"endpoint_id\":\"port\","
        << "\"pid\":" << GetCurrentProcessId() << ","
        << "\"executable_version\":\"release-manifest-2026-08-02-schema-v2\","
        << "\"executable_hash\":\"" << executableHash << "\","
        << "\"started_at\":" << UsbLogger::GetStartedAtUnixMs() << ","
        << "\"updated_at\":" << nowMs << ","
        << "\"collecting\":" << (m_monitoringEnabled.load() ? "true" : "false") << ","
        << "\"persistence_enabled\":" << (UsbLogger::IsSaveLogsEnabled() ? "true" : "false") << ","
        << "\"status\":\"" << (degraded ? "degraded" : "healthy") << "\","
        << "\"final\":" << (final ? "true" : "false") << ","
        << "\"watcher_buffer_overflow_count\":" << overflowCount << ","
        << "\"active_sessions\":" << (m_sessionManager ? m_sessionManager->GetActiveSessionCount() : 0) << ","
        // Standardized cross-endpoint names (additive).
        << "\"records_dropped\":" << overflowCount << ","
        << "\"parse_failures\":0," // this program parses no untrusted external input
        << "\"source_loss\":" << overflowCount << ","
        << "\"writer_failures\":" << UsbLogger::GetWriteFailureCount() << ","
        << "\"rotations\":" << UsbLogger::GetRotationCount() << ","
        << "\"retained_bytes\":" << retainedBytes << ","
        << "\"retained_files\":" << retainedFiles << ","
        << "\"resource_pressure\":\"" << PressureTierToString(m_pressureMonitor.GetTier()) << "\","
        << "\"shutdown_state\":\"" << (final ? "stopped" : "running") << "\","
        << "\"shutdown_ack\":" << (final ? "true" : "false") << ","
        << "\"last_error\":\"\""
        << "}";
    UsbLogger::Log(j.str());

    m_lastHealthLog = now;
    if (final) m_healthFinalEmitted = true;
}

// ─────────────────────────────────────────────────────────────────────────────
// PressureTickerLoop
//
// RAM/disk auto-lightening: every ~20s, samples system-wide memory load and
// free disk space on the log volume, then shrinks (or restores) the log
// archive-retention cap accordingly. Never touches m_hidGuards/m_watchers/
// m_deviceSerialMap caps -- those bound live monitoring state, not evidence
// history, and per the current stage's "monitor everything possible"
// directive, coverage itself must never shrink under pressure.
// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::PressureTickerLoop()
{
    while (m_pressureThreadRunning.load(std::memory_order_acquire)) {
        m_pressureMonitor.Update();
        UsbLogger::SetMaxArchives(
            AdaptiveCap(kBaseMaxArchives, kFloorMaxArchives, m_pressureMonitor.GetFactor()));

        // FIX (Round 3 live testing): EmitHealthRecord() was previously only
        // ever called on a ReadDirectoryChangesW buffer overflow, or once at
        // clean shutdown -- a perfectly healthy, quiet run (no USB activity)
        // wrote zero health evidence its entire lifetime, indistinguishable
        // in the log from a silently hung process. EmitHealthRecord() is
        // already internally rate-limited (5s floor for non-final calls),
        // so piggybacking it on this existing ~20s pressure tick is safe.
        EmitHealthRecord(/*final=*/false);

        for (int i = 0; i < 200 && m_pressureThreadRunning.load(std::memory_order_acquire); ++i)
            Sleep(100);   // ~20s total, but responsive to shutdown
    }
}

// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::LogError(const std::string& message) {
    LogErrorToConsole(message);
}
