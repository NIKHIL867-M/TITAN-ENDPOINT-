// usb_monitor.h
#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <deque>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <cstdint>

#include "usb_identity.h"
#include "resource_pressure.h"

class UsbKernelListener;
class UsbSessionManager;
class UsbWatcher;
class HidInjectionGuard;

// ─────────────────────────────────────────────────────────────────────────────
// IUsbMonitorCallbacks
// ─────────────────────────────────────────────────────────────────────────────
class IUsbMonitorCallbacks {
public:
    virtual ~IUsbMonitorCallbacks() = default;
    virtual void OnDeviceArrived(const std::string& devicePath) = 0;
    virtual void OnDeviceRemoved(const std::string& devicePath) = 0;

    // Called from the Win32 message thread for every WM_INPUT keyboard
    // key-down. hDeviceHandle is really a Win32 HANDLE (raw-input device
    // handle); typed as void* so this header stays free of <windows.h>.
    virtual void OnHidKeyEvent(void* hDeviceHandle) = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
// UsbMonitor
//
// Top-level coordinator.  Owns:
//   UsbKernelListener   -- Win32 message window watching WM_DEVICECHANGE
//   UsbSessionManager   -- per-device session lifecycle
//   UsbWatcher map      -- one ReadDirectoryChangesW thread per active drive
//   m_arrivalThreads    -- detached worker threads, one per arrival event
//
// Thread safety:
//   m_mutex guards m_deviceSerialMap, m_watchers, and m_arrivalThreads.
//
//   UsbKernelListener calls OnDeviceArrived/Removed from its Win32 message
//   thread.  OnDeviceArrived immediately spawns a worker thread so the
//   5-second drive-letter retry loop does NOT block the message thread — if
//   it did, no other WM_DEVICECHANGE messages (e.g. a second device arriving)
//   could be processed until the loop finished.
//
//   UsbWatcher calls OnFileEvent from its own thread.  This is safe: it only
//   acquires m_mutex briefly then delegates to UsbSessionManager which has
//   its own independent mutex.
//
//   Stop() joins all live arrival threads before tearing down sessions and
//   the kernel listener, ensuring a clean, race-free shutdown.
// ─────────────────────────────────────────────────────────────────────────────
class UsbMonitor : public IUsbMonitorCallbacks {
public:
    UsbMonitor();
    ~UsbMonitor();

    bool Start();
    void Stop();

    // FORU.TXT section 4: Monitoring toggle via the IPC control channel,
    // independent of whether the kernel listener/watcher threads are
    // running. When false, the callback methods below discard immediately.
    void SetMonitoringEnabled(bool enabled) noexcept { m_monitoringEnabled.store(enabled); }
    bool IsMonitoringEnabled() const noexcept { return m_monitoringEnabled.load(); }

    // Called by UsbWatcher threads to record a file-system event.
    void OnFileEvent(const std::string& deviceSerial,
        const std::string& operation,
        const std::string& filePath,
        uint64_t           size);

    // IUsbMonitorCallbacks — called from the kernel listener thread.
    void OnDeviceArrived(const std::string& devicePath) override;
    void OnDeviceRemoved(const std::string& devicePath) override;
    void OnHidKeyEvent(void* hDeviceHandle) override;

    // Called by UsbWatcher when ReadDirectoryChangesW reports a buffer
    // overflow (events dropped). Surfaces the loss as a counted,
    // persisted collector_health record instead of a stderr-only print.
    void ReportWatcherOverflow(const std::string& mountPoint);

private:
    // Actual arrival work — runs on a dedicated thread per arrival so the
    // Win32 message loop is never blocked by the drive-letter retry delay.
    void HandleArrival(std::string devicePath);

    // HID-keyboard-capable (non-storage) arrival: runs the bounded keystroke-
    // timing observation window on its own worker thread, then emits
    // usb_hid_event / usb_injection_alert JSON and cleans itself up.
    void HandleHidArrival(std::string devicePath, UsbIdentity identity);

    // Defensive cap on m_deviceSerialMap -- backstop against unbounded growth
    // if a removal notification is ever missed (mutex must be held by caller).
    static constexpr size_t kMaxTrackedDevices = 512;
    void EvictOldestDeviceMappingIfFull();   // mutex must be held by caller

    // Emits a collector_health JSON record via UsbLogger. Rate-limited to
    // once per 5 seconds except when final=true (always emitted).
    void EmitHealthRecord(bool final);

    // RAM/disk auto-lightening: periodically samples system pressure and
    // shrinks log-archive retention under load. Never touches WHAT is
    // monitored -- only how much evidence history is kept on disk.
    void PressureTickerLoop();

    std::unique_ptr<UsbKernelListener> m_listener;
    std::unique_ptr<UsbSessionManager> m_sessionManager;

    // devicePath -> session key  (so OnDeviceRemoved works after device gone)
    // The session key is the device serial number when present, or
    // "VID:PID:instanceId-suffix" when the device has no serial.
    // It MUST match the key used by UsbSessionManager::CreateSession().
    std::unordered_map<std::string, std::string> m_deviceSerialMap;
    std::deque<std::string> m_deviceSerialOrder;   // insertion order, for eviction

    // serial -> watcher  (one ReadDirectoryChangesW thread per active drive)
    std::unordered_map<std::string, std::unique_ptr<UsbWatcher>> m_watchers;

    // One worker thread per arrival event (storage or HID).  Collected here
    // so Stop() can join them all, preventing use-after-free of UsbMonitor
    // members.
    std::vector<std::thread> m_arrivalThreads;

    std::mutex m_mutex;   // guards all containers above

    // devicePath -> active keystroke-timing guard for HID-keyboard arrivals.
    std::unordered_map<std::string, std::shared_ptr<HidInjectionGuard>> m_hidGuards;
    std::mutex m_hidMutex;   // guards m_hidGuards independently of m_mutex

    // Health / loss counters -- surfaced via collector_health records.
    std::atomic<uint64_t> m_watcherOverflowCount{ 0 };
    std::atomic<bool>     m_monitoringEnabled{ true };
    std::chrono::steady_clock::time_point m_lastHealthLog{};
    std::mutex m_healthMutex;
    bool m_healthFinalEmitted = false;   // guards against duplicate final records on repeated Stop()

    // RAM/disk auto-lightening.
    ResourcePressureMonitor m_pressureMonitor{ "C:\\ProgramData\\TitanUSB\\logs\\" };
    std::thread             m_pressureThread;
    std::atomic<bool>       m_pressureThreadRunning{ false };
    static constexpr size_t kBaseMaxArchives = 20;
    static constexpr size_t kFloorMaxArchives = 3;

    void LogError(const std::string& message);
};