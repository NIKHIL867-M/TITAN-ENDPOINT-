// usb_hid_guard.cpp
#include "usb_hid_guard.h"

#include <cmath>
#include <algorithm>
#include <iostream>
#include <cctype>

// ─────────────────────────────────────────────────────────────────────────────
// EvaluateKeystrokeTiming — pure function, no Win32 dependency.
// ─────────────────────────────────────────────────────────────────────────────
KeystrokeTimingResult EvaluateKeystrokeTiming(const std::vector<double>& intervalsMs)
{
    KeystrokeTimingResult result;
    result.sampleCount = intervalsMs.size();
    if (intervalsMs.empty()) return result;

    double sum = 0.0;
    double minVal = intervalsMs[0];
    for (double v : intervalsMs) {
        sum += v;
        if (v < minVal) minVal = v;
    }
    double mean = sum / static_cast<double>(intervalsMs.size());

    double sqDiffSum = 0.0;
    for (double v : intervalsMs) {
        double d = v - mean;
        sqDiffSum += d * d;
    }
    double stddev = std::sqrt(sqDiffSum / static_cast<double>(intervalsMs.size()));

    result.meanIntervalMs = mean;
    result.stddevIntervalMs = stddev;
    result.minIntervalMs = minVal;

    if (intervalsMs.size() >= KeystrokeTimingThresholds::kMinSamples
        && mean < KeystrokeTimingThresholds::kSuspiciousMeanMs
        && stddev < KeystrokeTimingThresholds::kSuspiciousStddevMs)
    {
        result.suspected = true;
    }

    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// HidInjectionGuard
// ─────────────────────────────────────────────────────────────────────────────
HidInjectionGuard::HidInjectionGuard(std::string vid, std::string pid, std::string instanceId)
    : m_vid(std::move(vid))
    , m_pid(std::move(pid))
    , m_instanceId(std::move(instanceId))
    , m_startTime(std::chrono::steady_clock::now())
{
}

namespace {
    std::string ToUpperCopy(const std::string& s) {
        std::string out = s;
        for (char& c : out) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        return out;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolveDeviceHandle
//
// Enumerates the OS-wide raw-input device list, finds keyboard-type entries,
// and matches by VID/PID against the device path string (which looks like
// "\\?\HID#VID_1234&PID_5678&...").  This is a best-effort match: if the
// device does not (yet) appear in the raw-input list -- e.g. driver binding
// still in progress -- we simply return false and the caller proceeds
// without keystroke evidence for this arrival.
// ─────────────────────────────────────────────────────────────────────────────
bool HidInjectionGuard::ResolveDeviceHandle()
{
    UINT numDevices = 0;
    if (GetRawInputDeviceList(nullptr, &numDevices, sizeof(RAWINPUTDEVICELIST)) != 0)
        return false;
    if (numDevices == 0) return false;

    std::vector<RAWINPUTDEVICELIST> devices(numDevices);
    UINT got = GetRawInputDeviceList(devices.data(), &numDevices, sizeof(RAWINPUTDEVICELIST));
    if (got == static_cast<UINT>(-1)) return false;

    const std::string vidTag = "VID_" + ToUpperCopy(m_vid);
    const std::string pidTag = "PID_" + ToUpperCopy(m_pid);

    for (UINT i = 0; i < got; ++i) {
        if (devices[i].dwType != RIM_TYPEKEYBOARD) continue;

        char nameBuf[512] = {};
        UINT nameSize = sizeof(nameBuf);
        UINT r = GetRawInputDeviceInfoA(devices[i].hDevice, RIDI_DEVICENAME,
            nameBuf, &nameSize);
        if (r == static_cast<UINT>(-1) || r == 0) continue;

        std::string name = ToUpperCopy(nameBuf);
        if (name.find(vidTag) != std::string::npos &&
            name.find(pidTag) != std::string::npos)
        {
            m_matchedDevice = devices[i].hDevice;
            return true;
        }
    }
    return false;
}

void HidInjectionGuard::OnKeyDown(HANDLE hDevice)
{
    if (!m_matchedDevice || hDevice != m_matchedDevice) return;

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_timestamps.size() >= kMaxSamples) return;   // bounded -- backstop
    m_timestamps.push_back(std::chrono::steady_clock::now());
}

bool HidInjectionGuard::IsDone() const
{
    auto elapsed = std::chrono::steady_clock::now() - m_startTime;
    if (elapsed >= std::chrono::seconds(kWindowSeconds)) return true;

    std::lock_guard<std::mutex> lock(m_mutex);
    return m_timestamps.size() >= kMaxSamples;
}

size_t HidInjectionGuard::SampleCount() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_timestamps.size();
}

KeystrokeTimingResult HidInjectionGuard::Evaluate() const
{
    std::vector<std::chrono::steady_clock::time_point> snapshot;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        snapshot = m_timestamps;
    }

    std::vector<double> intervalsMs;
    intervalsMs.reserve(snapshot.size());
    for (size_t i = 1; i < snapshot.size(); ++i) {
        auto d = std::chrono::duration_cast<std::chrono::microseconds>(
            snapshot[i] - snapshot[i - 1]).count();
        intervalsMs.push_back(static_cast<double>(d) / 1000.0);
    }
    return EvaluateKeystrokeTiming(intervalsMs);
}

// ─────────────────────────────────────────────────────────────────────────────
// EnsureRawInputRegistered
// ─────────────────────────────────────────────────────────────────────────────
bool EnsureRawInputRegistered(HWND targetWindow)
{
    static bool s_registered = false;
    if (s_registered) return true;

    RAWINPUTDEVICE rid{};
    rid.usUsagePage = 0x01;   // Generic Desktop
    rid.usUsage = 0x06;   // Keyboard
    rid.dwFlags = RIDEV_INPUTSINK;  // receive input even when not foreground/focused
    rid.hwndTarget = targetWindow;

    if (!RegisterRawInputDevices(&rid, 1, sizeof(RAWINPUTDEVICE))) {
        std::cerr << "[HidInjectionGuard] RegisterRawInputDevices failed (err="
            << GetLastError() << ")\n";
        return false;
    }
    s_registered = true;
    return true;
}
